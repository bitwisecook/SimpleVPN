// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
//  SSHLiveIntegrationTests.swift
//  The libssh engine against a REAL SSH server. Everything else about the SSH
//  kinds is contract-tested (SSHNetworkTunnelTests, SSHSettingDescriptorTests);
//  this file is the only place the code actually talks SSH, because three of its
//  claims cannot be proven any other way:
//
//    • the HOST-KEY GATE fails closed — a wrong or truncated pin must refuse a
//      server that is otherwise perfectly willing to let us in;
//    • the IN-MEMORY PEM auth path works. It is the ONLY key auth the packet-tunnel
//      extension can do (root, no ~/.ssh), so a defect there is a tunnel kind that
//      never connects for anyone;
//    • the EVENT LOOP does not starve writers. `ssh_event_dopoll` blocks the one
//      serial queue every libssh call funnels through, so a session carrying N
//      flows would add up to the poll ceiling (200 ms) of latency to every write —
//      which is why SSHBridge has a self-pipe in the poll set. That is a claim
//      about a race, and a race is only ever proven by measurement.
//
//  NO PRIVILEGE, NO NETWORK. `/usr/sbin/sshd` runs as an ordinary user on a high
//  port bound to loopback; each test starts its OWN instance from the fixture that
//  Tools/ssh-live-test-fixture.sh lays down, and stops it again. The direct-tcpip
//  target is an in-process echo listener, also on loopback. Nothing leaves the
//  machine and nothing survives the run.
//
//  WITHOUT THE FIXTURE EVERY TEST HERE SKIPS. `liveSSHFixtureMode` always runs and
//  prints which mode the run was in, so a green suite can never be mistaken for a
//  proven one. To create it:
//
//      ./Tools/ssh-live-test-fixture.sh
//      TEST_RUNNER_SIMPLEVPN_SSH_TEST_DIR=/tmp/simplevpn-ssh-live \
//        xcodebuild -project SimpleVPN.xcodeproj -scheme SimpleVPN \
//        -destination 'platform=macOS' test -only-testing:SimpleVPNTests
//

import Testing
import Foundation
import CryptoKit
@testable import SimpleVPN

// MARK: - Fixture discovery

/// The keys and sshd_config the live tests need on disk, plus the two host-key
/// fingerprints derived from them (the right one and a real-but-wrong one).
nonisolated struct LiveSSHFixture: Sendable {
    static let sshdPath = "/usr/sbin/sshd"
    static let sshKeygenPath = "/usr/bin/ssh-keygen"
    static let defaultDirectory = "/tmp/simplevpn-ssh-live"

    let directory: URL
    /// The login the server will accept — the account that owns authorized_keys.
    let user: String
    /// SHA-256 of the host key's wire blob, lowercase hex: the form SSHBridge reports.
    let hostKeyFingerprintHex: String
    /// The same digest as unpadded base64 — the form `ssh-keygen -lf` prints.
    let hostKeyFingerprintBase64: String
    /// A well-formed fingerprint belonging to a DIFFERENT key. Not gibberish on
    /// purpose: a pin check that only rejects malformed input is no check at all.
    let wrongFingerprintHex: String

    var configPath: String { directory.appendingPathComponent("sshd_config").path }
    var hostKeyPublicPath: String { directory.appendingPathComponent("hostkey.pub").path }
    var clientKeyPath: String { directory.appendingPathComponent("clientkey").path }
    var lockedKeyPath: String { directory.appendingPathComponent("lockedkey").path }
    var unauthorizedKeyPath: String { directory.appendingPathComponent("otherkey").path }
    static let lockedKeyPassphrase = "correct horse"

    static let shared: LiveSSHFixture? = discover()
    static var isAvailable: Bool { shared != nil }

    /// Printed by `liveSSHFixtureMode` so a skipped run says why.
    static var status: String {
        if let f = shared { return "ENABLED — fixture \(f.directory.path), login \(f.user)" }
        let where_ = ProcessInfo.processInfo.environment["SIMPLEVPN_SSH_TEST_DIR"] ?? defaultDirectory
        if !FileManager.default.isExecutableFile(atPath: sshdPath) {
            return "SKIPPED — no \(sshdPath) on this machine"
        }
        return "SKIPPED — no fixture at \(where_) (run ./Tools/ssh-live-test-fixture.sh)"
    }

    private static func discover() -> LiveSSHFixture? {
        let fm = FileManager.default
        guard fm.isExecutableFile(atPath: sshdPath) else { return nil }
        let path = ProcessInfo.processInfo.environment["SIMPLEVPN_SSH_TEST_DIR"] ?? defaultDirectory
        let dir = URL(fileURLWithPath: path)
        for name in ["sshd_config", "hostkey", "hostkey.pub", "clientkey",
                     "lockedkey", "otherkey", "otherkey.pub", "authorized_keys"] {
            guard fm.fileExists(atPath: dir.appendingPathComponent(name).path) else { return nil }
        }
        guard let host = digest(ofOpenSSHPublicKeyAt: dir.appendingPathComponent("hostkey.pub")),
              let other = digest(ofOpenSSHPublicKeyAt: dir.appendingPathComponent("otherkey.pub"))
        else { return nil }
        return LiveSSHFixture(directory: dir, user: NSUserName(),
                              hostKeyFingerprintHex: host.hex,
                              hostKeyFingerprintBase64: host.base64,
                              wrongFingerprintHex: other.hex)
    }

    /// SHA-256 of the base64 blob in an OpenSSH ".pub" line — the same bytes
    /// `ssh_get_publickey_hash` hashes, so the two forms are directly comparable.
    private static func digest(ofOpenSSHPublicKeyAt url: URL) -> (hex: String, base64: String)? {
        guard let text = try? String(contentsOf: url, encoding: .utf8) else { return nil }
        let fields = text.split(whereSeparator: \.isWhitespace)
        guard fields.count >= 2, let blob = Data(base64Encoded: String(fields[1])) else { return nil }
        let d = SHA256.hash(data: blob)
        let hex = d.map { String(format: "%02x", $0) }.joined()
        let b64 = Data(d).base64EncodedString().replacingOccurrences(of: "=", with: "")
        return (hex, b64)
    }

    /// What `ssh-keygen -lf` says about the host key, straight from the tool.
    func sshKeygenFingerprintLine() -> String? {
        Self.run(Self.sshKeygenPath, ["-lf", hostKeyPublicPath])
    }

    static func run(_ tool: String, _ arguments: [String]) -> String? {
        let p = Process()
        p.executableURL = URL(fileURLWithPath: tool)
        p.arguments = arguments
        let out = Pipe()
        p.standardOutput = out
        p.standardError = FileHandle.nullDevice
        guard (try? p.run()) != nil else { return nil }
        let data = out.fileHandleForReading.readDataToEndOfFile()
        p.waitUntilExit()
        return String(data: data, encoding: .utf8)
    }
}

// MARK: - Loopback helpers

nonisolated enum Loopback {
    /// A port nothing is listening on right now, obtained the only reliable way:
    /// bind :0 and read back what the kernel chose.
    static func freePort() -> UInt16? {
        let fd = socket(AF_INET, SOCK_STREAM, 0)
        guard fd >= 0 else { return nil }
        defer { close(fd) }
        var addr = sockaddr_in()
        addr.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
        addr.sin_family = sa_family_t(AF_INET)
        addr.sin_port = 0
        addr.sin_addr.s_addr = inet_addr("127.0.0.1")
        let size = socklen_t(MemoryLayout<sockaddr_in>.size)
        let bound = withUnsafePointer(to: &addr) { raw in
            raw.withMemoryRebound(to: sockaddr.self, capacity: 1) { bind(fd, $0, size) }
        }
        guard bound == 0 else { return nil }
        var back = sockaddr_in()
        var len = size
        let named = withUnsafeMutablePointer(to: &back) { raw in
            raw.withMemoryRebound(to: sockaddr.self, capacity: 1) { getsockname(fd, $0, &len) }
        }
        guard named == 0 else { return nil }
        return UInt16(bigEndian: back.sin_port)
    }

    /// True once something accepts a TCP connection on the port.
    static func accepts(port: UInt16) -> Bool {
        let fd = socket(AF_INET, SOCK_STREAM, 0)
        guard fd >= 0 else { return false }
        defer { close(fd) }
        var addr = sockaddr_in()
        addr.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
        addr.sin_family = sa_family_t(AF_INET)
        addr.sin_port = port.bigEndian
        addr.sin_addr.s_addr = inet_addr("127.0.0.1")
        let size = socklen_t(MemoryLayout<sockaddr_in>.size)
        return withUnsafePointer(to: &addr) { raw in
            raw.withMemoryRebound(to: sockaddr.self, capacity: 1) { connect(fd, $0, size) == 0 }
        }
    }

    /// Spin until `condition` holds. Returns false on timeout. Used instead of a
    /// fixed sleep so a fast machine isn't punished and a slow one isn't flaky.
    @discardableResult
    static func wait(upTo seconds: Double, step: Double = 0.02,
                     for condition: () -> Bool) -> Bool {
        let deadline = Date().addingTimeInterval(seconds)
        while Date() < deadline {
            if condition() { return true }
            Thread.sleep(forTimeInterval: step)
        }
        return condition()
    }

    /// SIGPIPE would kill the whole test host; every socket here opts out.
    static func suppressSIGPIPE(_ fd: Int32) {
        var on: Int32 = 1
        setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &on, socklen_t(MemoryLayout<Int32>.size))
    }
}

// MARK: - A real sshd, owned by the test

/// One user-space `sshd` on a free loopback port, from the fixture's config.
/// Stopping it kills the listener AND the per-connection children — sshd forks
/// per session, so signalling only the parent would leave the live session up and
/// the session-loss test proving nothing.
nonisolated final class LiveSSHServer: @unchecked Sendable {
    enum Failure: Error, CustomStringConvertible {
        case noFreePort
        case launchFailed(String)
        case neverListened(String)
        var description: String {
            switch self {
            case .noFreePort: "couldn't find a free loopback port"
            case .launchFailed(let s): "sshd wouldn't launch: \(s)"
            case .neverListened(let s): "sshd never listened:\n\(s)"
            }
        }
    }

    let port: UInt16
    private let process = Process()
    private let logURL: URL
    private let lock = NSLock()
    private var reaped = false

    /// A write to a socket whose peer has gone would otherwise raise SIGPIPE and
    /// take the whole test host down with it — and this suite kills servers on
    /// purpose. Done once, only when a live server is actually started.
    private static let sigpipeIgnored: Bool = {
        signal(SIGPIPE, SIG_IGN)
        return true
    }()

    /// Starts sshd and returns only once the port accepts connections.
    init(fixture: LiveSSHFixture, extraOptions: [String] = []) throws {
        _ = Self.sigpipeIgnored
        guard let port = Loopback.freePort() else { throw Failure.noFreePort }
        self.port = port
        logURL = URL(fileURLWithPath: NSTemporaryDirectory())
            .appendingPathComponent("simplevpn-sshd-\(port)-\(UUID().uuidString).log")
        _ = FileManager.default.createFile(atPath: logURL.path, contents: nil)

        process.executableURL = URL(fileURLWithPath: LiveSSHFixture.sshdPath)
        var args = ["-f", fixture.configPath, "-o", "Port=\(port)", "-D", "-e"]
        for option in extraOptions { args += ["-o", option] }
        process.arguments = args
        guard let handle = try? FileHandle(forWritingTo: logURL) else {
            throw Failure.launchFailed("couldn't open \(logURL.path)")
        }
        process.standardOutput = handle
        process.standardError = handle
        do { try process.run() } catch { throw Failure.launchFailed("\(error)") }

        guard Loopback.wait(upTo: 10, for: { Loopback.accepts(port: port) }) else {
            stop()
            throw Failure.neverListened(log())
        }
    }

    func log() -> String { (try? String(contentsOf: logURL, encoding: .utf8)) ?? "" }

    /// SIGKILL the listener and every child it forked, so an established session
    /// dies with it. `ps` rather than libproc: this is a test, and the parent pid
    /// is ours, so there is nothing to race with.
    func killEverything() {
        let pid = process.processIdentifier
        guard pid > 0 else { return }
        for victim in Self.descendants(of: pid).reversed() { kill(victim, SIGKILL) }
        kill(pid, SIGKILL)
        reap()
    }

    func stop() {
        let pid = process.processIdentifier
        guard pid > 0 else { return }
        for victim in Self.descendants(of: pid).reversed() { kill(victim, SIGTERM) }
        kill(pid, SIGTERM)
        reap()
    }

    private func reap() {
        lock.lock(); defer { lock.unlock() }
        guard !reaped else { return }
        reaped = true
        process.waitUntilExit()
        try? FileManager.default.removeItem(at: logURL)
    }

    /// Every process descended from `root`, parents before children.
    private static func descendants(of root: Int32) -> [Int32] {
        guard let text = LiveSSHFixture.run("/bin/ps", ["-A", "-o", "pid=,ppid="]) else { return [] }
        var children: [Int32: [Int32]] = [:]
        for line in text.split(separator: "\n") {
            let f = line.split(whereSeparator: \.isWhitespace)
            guard f.count == 2, let pid = Int32(f[0]), let ppid = Int32(f[1]) else { continue }
            children[ppid, default: []].append(pid)
        }
        var out: [Int32] = []
        var frontier = children[root] ?? []
        while let next = frontier.popLast() {
            out.append(next)
            frontier.append(contentsOf: children[next] ?? [])
        }
        return out
    }
}

// MARK: - The direct-tcpip target

/// A plain TCP echo server on loopback — what the SSH server forwards to. POSIX
/// sockets rather than Network.framework so half-close is exact: `SHUT_WR` is what
/// makes the SSH channel report EOF, and that is the behaviour under test.
nonisolated final class EchoTarget: @unchecked Sendable {
    /// `immediate` echoes each chunk as it lands. `afterEOF` answers only once the
    /// peer has half-closed — the shape of every request/response protocol that
    /// signals "request over" with a FIN, and the one a flow that closes both
    /// halves at once silently truncates.
    enum Mode { case immediate, afterEOF }

    let port: UInt16
    private let listenFD: Int32
    private let mode: Mode
    private let lock = NSLock()
    private var running = true
    private var accepted = 0

    var connectionCount: Int { lock.lock(); defer { lock.unlock() }; return accepted }

    init(mode: Mode = .immediate) throws {
        self.mode = mode
        // A LOCAL fd through the whole of the setup: the pointer-rebinding closures
        // below would otherwise capture `self` before `port` exists.
        let fd = socket(AF_INET, SOCK_STREAM, 0)
        guard fd >= 0 else { throw POSIXError(.EBADF) }
        var yes: Int32 = 1
        setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &yes, socklen_t(MemoryLayout<Int32>.size))
        Loopback.suppressSIGPIPE(fd)
        var addr = sockaddr_in()
        addr.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
        addr.sin_family = sa_family_t(AF_INET)
        addr.sin_port = 0
        addr.sin_addr.s_addr = inet_addr("127.0.0.1")
        let size = socklen_t(MemoryLayout<sockaddr_in>.size)
        let bound = withUnsafePointer(to: &addr) { raw in
            raw.withMemoryRebound(to: sockaddr.self, capacity: 1) { bind(fd, $0, size) }
        }
        guard bound == 0, listen(fd, 64) == 0 else {
            close(fd)
            throw POSIXError(.EADDRINUSE)
        }
        var back = sockaddr_in()
        var len = size
        _ = withUnsafeMutablePointer(to: &back) { raw in
            raw.withMemoryRebound(to: sockaddr.self, capacity: 1) { getsockname(fd, $0, &len) }
        }
        listenFD = fd
        port = UInt16(bigEndian: back.sin_port)

        let accept = Thread { [self] in acceptLoop() }
        accept.name = "echo-accept"
        accept.start()
    }

    func shutdownTarget() {
        lock.lock()
        let wasRunning = running
        running = false
        lock.unlock()
        if wasRunning { close(listenFD) }   // unblocks accept()
    }

    private var isRunning: Bool { lock.lock(); defer { lock.unlock() }; return running }

    private func acceptLoop() {
        while isRunning {
            let fd = accept(listenFD, nil, nil)
            if fd < 0 {
                if errno == EINTR { continue }
                return   // the listener was closed
            }
            Loopback.suppressSIGPIPE(fd)
            lock.lock(); accepted += 1; lock.unlock()
            let worker = Thread { [self] in serve(fd) }
            worker.name = "echo-conn"
            worker.start()
        }
    }

    private func serve(_ fd: Int32) {
        var buf = [UInt8](repeating: 0, count: 64 * 1024)
        var held = [UInt8]()
        while true {
            let n = buf.withUnsafeMutableBytes { raw -> Int in
                recv(fd, raw.baseAddress!, raw.count, 0)
            }
            if n < 0 && errno == EINTR { continue }
            if n <= 0 { break }
            switch mode {
            case .immediate:
                if !sendAll(fd, buf, n) { close(fd); return }
            case .afterEOF:
                held.append(contentsOf: buf[0..<n])
            }
        }
        if mode == .afterEOF, !held.isEmpty { _ = sendAll(fd, held, held.count) }
        // FIN, not a reset: the SSH channel must see a clean EOF.
        shutdown(fd, SHUT_WR)
        close(fd)
    }

    private func sendAll(_ fd: Int32, _ bytes: [UInt8], _ count: Int) -> Bool {
        var offset = 0
        while offset < count {
            let sent = bytes.withUnsafeBytes { raw -> Int in
                send(fd, raw.baseAddress!.advanced(by: offset), count - offset, 0)
            }
            if sent <= 0 {
                if sent < 0 && errno == EINTR { continue }
                return false
            }
            offset += sent
        }
        return true
    }
}

// MARK: - The session harness

/// The SSH Network Tunnel's data pump, reduced to what a test can drive: one
/// serial queue owning the libssh session, a self-rescheduling reader step that
/// drains every channel and then blocks in `ssh_event_dopoll`, and writers that
/// arrive from other threads. It is deliberately the SAME SHAPE as
/// `SSHNetworkTunnelEngine.readerStep`/`writeAll` — including the poll ceiling —
/// because the property under test is a property of that shape.
nonisolated final class LiveSessionHarness: @unchecked Sendable {
    /// Matches SSHNetworkTunnelEngine.pollCeilingMs. If the wake pipe fails, this
    /// is exactly the latency a writer inherits.
    static let pollCeilingMs: Int32 = 200

    private let session: SSHSession
    private let sshQueue = DispatchQueue(label: "test.simplevpn.sshnet.session")
    private let lock = NSLock()
    private var sinks: [ObjectIdentifier: Sink] = [:]
    private var running = false
    private var lost = false
    private var pollCount = 0

    /// When false, writers skip `wakeActivityWait()` — the control experiment that
    /// says whether the self-pipe is load-bearing or decoration.
    let usesWakePipe: Bool

    /// One channel and what has come back on it. Stands in for the extension's
    /// `Flow` (which owns a socketpair instead of a buffer).
    private final class Sink {
        let channel: SSHChannel
        var received = Data()
        var sawEOF = false
        var failed = false
        init(channel: SSHChannel) { self.channel = channel }
    }

    init(session: SSHSession, usesWakePipe: Bool = true) {
        self.session = session
        self.usesWakePipe = usesWakePipe
    }

    var sessionLost: Bool { lock.lock(); defer { lock.unlock() }; return lost }
    var polls: Int { lock.lock(); defer { lock.unlock() }; return pollCount }

    func start() {
        lock.lock()
        guard !running else { lock.unlock(); return }
        running = true
        lock.unlock()
        sshQueue.async { [weak self] in self?.readerStep() }
    }

    /// Stop the reader loop and wait for the step in flight to finish, so nothing is
    /// inside libssh when the caller disconnects the session.
    func stop() {
        lock.lock(); running = false; lock.unlock()
        session.wakeActivityWait()
        sshQueue.sync { }
    }

    private func readerStep() {
        lock.lock(); let go = running; lock.unlock()
        guard go else { return }
        drain()
        lock.lock(); pollCount += 1; lock.unlock()
        let rc = session.waitForActivity(withTimeoutMs: Self.pollCeilingMs)
        if rc < 0 {
            lock.lock(); lost = true; running = false; lock.unlock()
            return
        }
        sshQueue.async { [weak self] in self?.readerStep() }
    }

    /// Exactly `SSHNetworkTunnelEngine.drainChannels` minus the socketpair: read
    /// every open channel until it says "nothing more right now".
    private func drain() {
        lock.lock(); let live = Array(sinks.values); lock.unlock()
        guard !live.isEmpty else { return }
        var buf = [UInt8](repeating: 0, count: 16 * 1024)
        for sink in live {
            if sink.channel.isClosed() { continue }
            while true {
                let n = buf.withUnsafeMutableBytes { raw -> Int in
                    sink.channel.read(raw.baseAddress!, maxLength: raw.count)
                }
                if n < 0 { lock.lock(); sink.failed = true; lock.unlock(); break }
                if n == 0 {
                    if sink.channel.isEOF() { lock.lock(); sink.sawEOF = true; lock.unlock() }
                    break
                }
                lock.lock(); sink.received.append(contentsOf: buf[0..<n]); lock.unlock()
            }
        }
    }

    /// Open a direct-tcpip channel on the session queue, like every other libssh call.
    func openChannel(toHost host: String, port: UInt16) throws -> SSHChannel {
        var result: Result<SSHChannel, any Error>!
        session.wakeActivityWait()
        sshQueue.sync {
            do { result = .success(try session.openDirectTCPIP(toHost: host, port: Int32(port))) }
            catch { result = .failure(error) }
        }
        let channel = try result.get()
        lock.lock(); sinks[ObjectIdentifier(channel)] = Sink(channel: channel); lock.unlock()
        return channel
    }

    /// One write, the way `SSHNetworkTunnelEngine.writeAll` does it: wake the poll,
    /// then take the session queue. The returned latency is the time to ACQUIRE the
    /// queue — the number the self-pipe exists to keep small.
    func write(_ channel: SSHChannel, _ bytes: [UInt8]) -> (latency: Double, written: Int) {
        let started = DispatchTime.now()
        if usesWakePipe { session.wakeActivityWait() }
        var acquired = started
        var written = 0
        sshQueue.sync {
            acquired = DispatchTime.now()
            written = bytes.withUnsafeBytes { raw -> Int in
                channel.write(raw.baseAddress!, length: raw.count)
            }
        }
        let seconds = Double(acquired.uptimeNanoseconds - started.uptimeNanoseconds) / 1e9
        return (seconds, written)
    }

    /// Write every byte, retrying the tail on a short write or EAGAIN.
    func writeAll(_ channel: SSHChannel, _ bytes: [UInt8]) -> Bool {
        var offset = 0
        while offset < bytes.count {
            let slice = Array(bytes[offset...])
            let (_, n) = write(channel, slice)
            if n < 0 { return false }
            if n == 0 {
                if usesWakePipe { session.wakeActivityWait() }
                Thread.sleep(forTimeInterval: 0.002)
                continue
            }
            offset += n
        }
        return true
    }

    /// Half-close, retrying a would-block (the bridge reports it as NO by design).
    func sendEOF(_ channel: SSHChannel) -> Bool {
        for _ in 0..<50 {
            var ok = false
            session.wakeActivityWait()
            sshQueue.sync { ok = channel.sendEOF() }
            if ok { return true }
            Thread.sleep(forTimeInterval: 0.01)
        }
        return false
    }

    func received(_ channel: SSHChannel) -> Data {
        lock.lock(); defer { lock.unlock() }
        return sinks[ObjectIdentifier(channel)]?.received ?? Data()
    }

    func sawEOF(_ channel: SSHChannel) -> Bool {
        lock.lock(); defer { lock.unlock() }
        return sinks[ObjectIdentifier(channel)]?.sawEOF ?? false
    }

    func sawFailure(_ channel: SSHChannel) -> Bool {
        lock.lock(); defer { lock.unlock() }
        return sinks[ObjectIdentifier(channel)]?.failed ?? false
    }

    /// Free every channel on the session queue (never from a dealloc — libssh state
    /// is single-threaded), then let the reader loop finish.
    func closeChannels() {
        lock.lock()
        let live = Array(sinks.values)
        sinks.removeAll()
        lock.unlock()
        session.wakeActivityWait()
        sshQueue.sync {
            for sink in live where !sink.channel.isClosed() { sink.channel.close() }
        }
    }

    /// Send one keepalive from the session queue and report what libssh said.
    func sendKeepalive() -> Bool {
        var ok = false
        session.wakeActivityWait()
        sshQueue.sync { ok = session.sendKeepalive() }
        return ok
    }
}

// MARK: - A minimal SOCKS5 client

/// Just enough SOCKS5 to prove the app engine's proxy works: no-auth greeting,
/// CONNECT to an IPv4 literal, then bytes. POSIX sockets with a receive timeout, so
/// a stalled proxy fails the test instead of hanging it.
nonisolated enum SOCKS5Client {
    enum Failure: Error, CustomStringConvertible {
        case connect(Int32)
        case handshake(String)
        case short(String, Int)
        var description: String {
            switch self {
            case .connect(let e): "couldn't reach the proxy (errno \(e))"
            case .handshake(let s): "SOCKS5 handshake: \(s)"
            case .short(let what, let n): "short read of \(what): \(n) bytes"
            }
        }
    }

    /// CONNECT through `proxyPort` to `host:port`, send `payload`, read back the same
    /// number of bytes.
    static func roundTrip(proxyPort: UInt16, host: String, port: UInt16,
                          payload: [UInt8], timeout: Double = 20) throws -> [UInt8] {
        let fd = try connect(port: proxyPort, timeout: timeout)
        defer { close(fd) }

        try send(fd, [0x05, 0x01, 0x00])                        // VER, NMETHODS, no-auth
        let choice = try receive(fd, 2, "method choice")
        guard choice == [0x05, 0x00] else { throw Failure.handshake("chose \(choice)") }

        var request: [UInt8] = [0x05, 0x01, 0x00, 0x01]          // CONNECT, IPv4
        let octets = host.split(separator: ".").compactMap { UInt8($0) }
        guard octets.count == 4 else { throw Failure.handshake("\(host) is not an IPv4 literal") }
        request += octets
        request += [UInt8(port >> 8), UInt8(port & 0xff)]
        try send(fd, request)
        let reply = try receive(fd, 10, "CONNECT reply")
        guard reply.count == 10, reply[0] == 0x05, reply[1] == 0x00 else {
            throw Failure.handshake("CONNECT was refused with \(reply)")
        }

        try send(fd, payload)
        return try receive(fd, payload.count, "echo")
    }

    private static func connect(port: UInt16, timeout: Double) throws -> Int32 {
        let fd = socket(AF_INET, SOCK_STREAM, 0)
        guard fd >= 0 else { throw Failure.connect(errno) }
        Loopback.suppressSIGPIPE(fd)
        var tv = timeval(tv_sec: Int(timeout), tv_usec: 0)
        setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, socklen_t(MemoryLayout<timeval>.size))
        setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, socklen_t(MemoryLayout<timeval>.size))
        var addr = sockaddr_in()
        addr.sin_len = UInt8(MemoryLayout<sockaddr_in>.size)
        addr.sin_family = sa_family_t(AF_INET)
        addr.sin_port = port.bigEndian
        addr.sin_addr.s_addr = inet_addr("127.0.0.1")
        let size = socklen_t(MemoryLayout<sockaddr_in>.size)
        let rc = withUnsafePointer(to: &addr) { raw in
            raw.withMemoryRebound(to: sockaddr.self, capacity: 1) { Darwin.connect(fd, $0, size) }
        }
        guard rc == 0 else {
            let err = errno
            close(fd)
            throw Failure.connect(err)
        }
        return fd
    }

    private static func send(_ fd: Int32, _ bytes: [UInt8]) throws {
        var offset = 0
        while offset < bytes.count {
            let n = bytes.withUnsafeBytes { raw -> Int in
                Darwin.send(fd, raw.baseAddress!.advanced(by: offset), bytes.count - offset, 0)
            }
            if n <= 0 {
                if n < 0 && errno == EINTR { continue }
                throw Failure.short("send", offset)
            }
            offset += n
        }
    }

    private static func receive(_ fd: Int32, _ want: Int, _ what: String) throws -> [UInt8] {
        var out = [UInt8]()
        var buf = [UInt8](repeating: 0, count: 65536)
        while out.count < want {
            let n = buf.withUnsafeMutableBytes { raw -> Int in
                recv(fd, raw.baseAddress!, min(raw.count, want - out.count), 0)
            }
            if n <= 0 {
                if n < 0 && errno == EINTR { continue }
                throw Failure.short(what, out.count)
            }
            out.append(contentsOf: buf[0..<n])
        }
        return out
    }
}

/// A session handed to another queue. `SSHSession` is deliberately NOT Sendable in
/// the app module (the packet tunnel declares its own conformance), so tests that
/// dispatch a libssh call carry it in this box — under exactly the engine's rule:
/// every call happens on one queue, whichever queue that is.
nonisolated final class SessionBox: @unchecked Sendable {
    let session: SSHSession
    init(_ session: SSHSession) { self.session = session }
}

// MARK: - Latency summary

nonisolated struct Latencies: Sendable {
    var samples: [Double] = []

    mutating func add(_ seconds: Double) { samples.append(seconds) }

    func percentile(_ p: Double) -> Double {
        guard !samples.isEmpty else { return 0 }
        let sorted = samples.sorted()
        let index = Int((Double(sorted.count - 1) * p).rounded())
        return sorted[index]
    }
    var max: Double { samples.max() ?? 0 }
    var count: Int { samples.count }

    func summary(_ label: String) -> String {
        let ms = { (v: Double) in String(format: "%.2f", v * 1000) }
        return "\(label): n=\(count) p50=\(ms(percentile(0.5)))ms "
            + "p90=\(ms(percentile(0.9)))ms p99=\(ms(percentile(0.99)))ms max=\(ms(max))ms"
    }
}

// MARK: - The tests

@Suite(.serialized)
nonisolated struct SSHLiveIntegrationTests {

    /// ALWAYS RUNS. Without it a fixture-less run looks identical to a proven one.
    @Test func liveSSHFixtureMode() {
        print("── SSH LIVE INTEGRATION: \(LiveSSHFixture.status)")
    }

    private func fixture() throws -> LiveSSHFixture {
        try #require(LiveSSHFixture.shared, "the live SSH fixture vanished mid-run")
    }

    /// Connect + verify + authenticate with the key file, the common preamble.
    private func connected(to server: LiveSSHServer, _ fixture: LiveSSHFixture,
                           compression: Bool = false) throws -> SSHSession {
        let session = SSHSession()
        try session.connect(toHost: "127.0.0.1", port: Int32(server.port), timeout: 10,
                            kexAlgorithms: nil, compression: compression)
        try session.verifyHostKey(withKnownHosts: nil, pin: fixture.hostKeyFingerprintHex,
                                  strict: "yes")
        try session.authKey(forUser: fixture.user, privateKeyPath: fixture.clientKeyPath,
                            certificatePath: nil, passphrase: nil)
        session.enterDataMode()
        return session
    }

    // MARK: 1 — the host-key gate

    @Test(.enabled(if: LiveSSHFixture.isAvailable))
    func hostKeyFingerprintMatchesSSHKeygenAndAMatchingPinConnects() throws {
        let fixture = try fixture()
        let server = try LiveSSHServer(fixture: fixture)
        defer { server.stop() }

        let session = SSHSession()
        defer { session.disconnect() }
        try session.connect(toHost: "127.0.0.1", port: Int32(server.port), timeout: 10,
                            kexAlgorithms: nil, compression: false)

        // The fingerprint the bridge reports IS the one ssh-keygen computes — via
        // the fixture's independently-derived digest, so a normalisation bug in
        // either the bridge or the test can't hide behind the other.
        let reported = try #require(session.hostKeyFingerprintSHA256)
        #expect(reported == fixture.hostKeyFingerprintHex)
        let keygen = try #require(fixture.sshKeygenFingerprintLine())
        #expect(keygen.contains("SHA256:\(fixture.hostKeyFingerprintBase64)"),
                "ssh-keygen said \(keygen), we derived SHA256:\(fixture.hostKeyFingerprintBase64)")
        #expect(session.hostKeyType == "ssh-ed25519")
        #expect(session.hostKeyLength > 0)

        // A matching pin is a match, and verification passes at the STRICTEST
        // setting (nothing may be written or trusted on first use).
        #expect(session.checkHostKey(withKnownHosts: nil, pin: fixture.hostKeyFingerprintHex) == .match)
        try session.verifyHostKey(withKnownHosts: nil, pin: fixture.hostKeyFingerprintHex,
                                  strict: "yes")
        #expect(session.acceptedNewHostKey == false, "a pinned host must never be treated as first use")

        // The handshake facts the diagnostics report are really there.
        let negotiated = session.negotiatedMethods
        #expect(negotiated["hostkey"] == "ssh-ed25519")
        #expect(!(negotiated["kex"] ?? "").isEmpty)
        #expect(!(negotiated["cipher"] ?? "").isEmpty)
        print("   negotiated: \(negotiated)")
    }

    @Test(.enabled(if: LiveSSHFixture.isAvailable))
    func aWrongOrTruncatedHostKeyPinIsRefusedByAServerThatWouldOtherwiseLetUsIn() throws {
        let fixture = try fixture()
        let server = try LiveSSHServer(fixture: fixture)
        defer { server.stop() }

        // The control: this server WILL authenticate us (proven above), so every
        // refusal below is the pin's doing and nothing else.
        let truncated = String(fixture.hostKeyFingerprintHex.prefix(32))
        let cases: [(label: String, pin: String)] = [
            ("a different key's fingerprint", fixture.wrongFingerprintHex),
            ("a TRUNCATED prefix of the right one", truncated),
            ("the right digest with one nibble changed",
             Self.flippedNibble(fixture.hostKeyFingerprintHex)),
        ]
        for (label, pin) in cases {
            let session = SSHSession()
            defer { session.disconnect() }
            try session.connect(toHost: "127.0.0.1", port: Int32(server.port), timeout: 10,
                                kexAlgorithms: nil, compression: false)
            #expect(session.checkHostKey(withKnownHosts: nil, pin: pin) == .mismatch,
                    "\(label) must read as a mismatch")
            // FAIL CLOSED AT EVERY STRICTNESS. "no" is the most permissive setting
            // the app offers, and it must still refuse a pin that doesn't match —
            // a pin is a statement about identity, not a preference.
            for strict in ["yes", "accept-new", "no"] {
                #expect(throws: (any Error).self, "\(label) was accepted at strict=\(strict)") {
                    try session.verifyHostKey(withKnownHosts: nil, pin: pin, strict: strict)
                }
            }
        }
    }

    private static func flippedNibble(_ hex: String) -> String {
        guard let last = hex.last else { return hex }
        let replacement: Character = last == "0" ? "1" : "0"
        return String(hex.dropLast()) + String(replacement)
    }

    // MARK: 2 — authentication, including the extension's in-memory path

    @Test(.enabled(if: LiveSSHFixture.isAvailable))
    func authenticationFromAKeyFileAndFromAnInMemoryPEM() throws {
        let fixture = try fixture()
        let server = try LiveSSHServer(fixture: fixture)
        defer { server.stop() }

        // What the server offers. The fixture allows publickey ONLY, so a live test
        // can never pass by falling back to something the app wouldn't choose.
        do {
            let session = SSHSession()
            defer { session.disconnect() }
            try session.connect(toHost: "127.0.0.1", port: Int32(server.port), timeout: 10,
                                kexAlgorithms: nil, compression: false)
            let methods = try session.authMethods(forUser: fixture.user)
            #expect(methods == ["publickey"], "server offered \(methods)")
        }

        // (a) the app's path: a key FILE.
        do {
            let session = SSHSession()
            defer { session.disconnect() }
            try session.connect(toHost: "127.0.0.1", port: Int32(server.port), timeout: 10,
                                kexAlgorithms: nil, compression: false)
            try session.verifyHostKey(withKnownHosts: nil, pin: fixture.hostKeyFingerprintHex,
                                      strict: "yes")
            try session.authKey(forUser: fixture.user, privateKeyPath: fixture.clientKeyPath,
                                certificatePath: nil, passphrase: nil)
        }

        // (b) THE EXTENSION'S ONLY PATH: the same key as an in-memory PEM blob.
        // It runs as root with no access to ~/.ssh, so if this is broken the SSH
        // Network Tunnel cannot connect for anybody.
        do {
            let pem = try String(contentsOfFile: fixture.clientKeyPath, encoding: .utf8)
            let session = SSHSession()
            defer { session.disconnect() }
            try session.connect(toHost: "127.0.0.1", port: Int32(server.port), timeout: 10,
                                kexAlgorithms: nil, compression: false)
            #expect(session.checkHostKey(withKnownHosts: nil,
                                         pin: fixture.hostKeyFingerprintHex) == .match)
            try session.authKey(forUser: fixture.user, privateKeyPEM: pem,
                                certificatePEM: nil, passphrase: nil)
        }

        // (c) an ENCRYPTED in-memory PEM: the passphrase actually unlocks it…
        do {
            let pem = try String(contentsOfFile: fixture.lockedKeyPath, encoding: .utf8)
            let session = SSHSession()
            defer { session.disconnect() }
            try session.connect(toHost: "127.0.0.1", port: Int32(server.port), timeout: 10,
                                kexAlgorithms: nil, compression: false)
            try session.authKey(forUser: fixture.user, privateKeyPEM: pem,
                                certificatePEM: nil,
                                passphrase: LiveSSHFixture.lockedKeyPassphrase)
        }
        // …and the WRONG passphrase fails rather than falling through to something else.
        do {
            let pem = try String(contentsOfFile: fixture.lockedKeyPath, encoding: .utf8)
            let session = SSHSession()
            defer { session.disconnect() }
            try session.connect(toHost: "127.0.0.1", port: Int32(server.port), timeout: 10,
                                kexAlgorithms: nil, compression: false)
            #expect(throws: (any Error).self) {
                try session.authKey(forUser: fixture.user, privateKeyPEM: pem,
                                    certificatePEM: nil, passphrase: "wrong")
            }
        }

        // (d) a valid key the server has never heard of is REJECTED. Without this
        // the tests above only prove that authentication returns YES a lot.
        do {
            let pem = try String(contentsOfFile: fixture.unauthorizedKeyPath, encoding: .utf8)
            let session = SSHSession()
            defer { session.disconnect() }
            try session.connect(toHost: "127.0.0.1", port: Int32(server.port), timeout: 10,
                                kexAlgorithms: nil, compression: false)
            #expect(throws: (any Error).self) {
                try session.authKey(forUser: fixture.user, privateKeyPEM: pem,
                                    certificatePEM: nil, passphrase: nil)
            }
        }
    }

    // MARK: 3 — direct-tcpip: round trip, half-close, teardown

    @Test(.enabled(if: LiveSSHFixture.isAvailable))
    func directTCPIPRoundTripsBytesAndHalfCloses() throws {
        let fixture = try fixture()
        let server = try LiveSSHServer(fixture: fixture)
        defer { server.stop() }
        let session = try connected(to: server, fixture)
        defer { session.disconnect() }

        // (a) plain round trip through an echo target, 128 KiB so partial writes
        // and multi-window reads are real rather than theoretical.
        let echo = try EchoTarget(mode: .immediate)
        defer { echo.shutdownTarget() }
        let harness = LiveSessionHarness(session: session)
        harness.start()
        defer { harness.stop() }

        let channel = try harness.openChannel(toHost: "127.0.0.1", port: echo.port)
        let payload: [UInt8] = (0..<(128 * 1024)).map { index in UInt8((index &* 31 &+ 7) & 0xff) }
        #expect(harness.writeAll(channel, payload))
        #expect(Loopback.wait(upTo: 20) { harness.received(channel).count >= payload.count },
                "echoed \(harness.received(channel).count) of \(payload.count) bytes")
        #expect(Array(harness.received(channel)) == payload, "the echo came back altered")
        #expect(echo.connectionCount == 1, "the server opened \(echo.connectionCount) connections")

        // (b) HALF-CLOSE. The target answers only after seeing our FIN, which is
        // what a flow that closes both halves at once truncates. `sendEOF` is the
        // primitive that keeps the answer reachable.
        let lateEcho = try EchoTarget(mode: .afterEOF)
        defer { lateEcho.shutdownTarget() }
        let request = Array("GET /late HTTP/1.0\r\n\r\n".utf8)
        let late = try harness.openChannel(toHost: "127.0.0.1", port: lateEcho.port)
        #expect(harness.writeAll(late, request))
        #expect(harness.received(late).isEmpty, "the target answered before the half-close")
        #expect(harness.sendEOF(late), "the channel refused to send EOF")
        #expect(Loopback.wait(upTo: 10) { harness.received(late).count >= request.count },
                "the answer after half-close never arrived (\(harness.received(late).count) bytes)")
        #expect(Array(harness.received(late)) == request)
        // …and the target's own FIN reaches us as channel EOF, which is how a flow
        // knows to retire rather than hang.
        #expect(Loopback.wait(upTo: 10) { harness.sawEOF(late) },
                "the target's FIN never surfaced as channel EOF")
        #expect(!harness.sawFailure(late))

        // (c) clean teardown: the channels close on the session queue and the
        // session survives to serve another one.
        harness.closeChannels()
        let after = try harness.openChannel(toHost: "127.0.0.1", port: echo.port)
        #expect(harness.writeAll(after, Array("still here".utf8)))
        #expect(Loopback.wait(upTo: 10) { harness.received(after).count == 10 })
        harness.closeChannels()
    }

    // MARK: 3b — the app's own engine, end to end

    /// `SSHTunnelEngine` is what the app runs for `-D`/`-L`, and until now nothing had
    /// ever driven it against a server: connect, pinned host key, key sign-in, the
    /// SOCKS5 listener, a direct-tcpip channel per accepted connection, and the pump.
    /// A real SOCKS client goes through all of it.
    @Test(.enabled(if: LiveSSHFixture.isAvailable))
    func theAppEngineServesSOCKSOverARealSession() async throws {
        let fixture = try fixture()
        let server = try LiveSSHServer(fixture: fixture)
        defer { server.stop() }
        let echo = try EchoTarget(mode: .immediate)
        defer { echo.shutdownTarget() }
        let socksPort = try #require(Loopback.freePort())

        var config = SSHTunnelEngine.Config(host: "127.0.0.1", port: Int(server.port),
                                            username: fixture.user, password: nil,
                                            identityFile: fixture.clientKeyPath,
                                            socksPort: Int(socksPort))
        // NEVER the user's real known_hosts: the pin decides, at the strictest setting.
        config.knownHostsPath = nil
        config.pinnedHostKeySHA256 = fixture.hostKeyFingerprintHex
        config.strictHostKey = "yes"
        config.authMethod = "key"
        config.keepaliveInterval = 1

        let engine = SSHTunnelEngine()
        defer { engine.stop() }
        try await engine.startSOCKS(config)
        #expect(Loopback.wait(upTo: 5) { engine.state == .connected },
                "engine state is \(engine.state), not connected")

        // 64 KiB through the proxy and back, unaltered.
        let payload: [UInt8] = (0..<(64 * 1024)).map { index in UInt8((index &* 17 &+ 3) & 0xff) }
        let echoed = try SOCKS5Client.roundTrip(proxyPort: socksPort, host: "127.0.0.1",
                                                port: echo.port, payload: payload)
        #expect(echoed == payload, "the proxy returned \(echoed.count) altered bytes")

        // A SECOND connection on the same session: each accepted connection gets its
        // own channel, and the first one's teardown must not have taken the session
        // (or the listener) with it.
        let again = try SOCKS5Client.roundTrip(proxyPort: socksPort, host: "127.0.0.1",
                                               port: echo.port, payload: Array("second".utf8))
        #expect(again == Array("second".utf8))
        #expect(echo.connectionCount == 2, "the echo target saw \(echo.connectionCount) connections")

        // The keepalive timer (1 s here) has had time to fire; the session must still
        // be serving. This is the app-side half of the keepalive proof.
        try await Task.sleep(for: .seconds(2.5))
        let third = try SOCKS5Client.roundTrip(proxyPort: socksPort, host: "127.0.0.1",
                                               port: echo.port, payload: Array("third".utf8))
        #expect(third == Array("third".utf8), "the session died while idle under keepalive")
        #expect(server.log().contains("keepalive@openssh.com"),
                "the engine's keepalive timer never reached the server")

        engine.stop()
        #expect(Loopback.wait(upTo: 5) { engine.state == .idle })
        // …and the listener is really gone, not just marked idle.
        #expect(Loopback.wait(upTo: 5) { !Loopback.accepts(port: socksPort) },
                "the SOCKS listener is still accepting after stop()")
    }

    // MARK: 4 — the event loop: does the wake actually interrupt the poll?

    /// The narrowest possible statement of the design claim in SSHBridge.h: a poll
    /// in progress on the session queue must END when another thread wakes it.
    /// Nothing else is running — no reader loop, no channels — so a failure here is
    /// the self-pipe and nothing but the self-pipe.
    @Test(.enabled(if: LiveSSHFixture.isAvailable))
    func theWakePipeInterruptsAPollInProgress() throws {
        let fixture = try fixture()
        let server = try LiveSSHServer(fixture: fixture)
        defer { server.stop() }
        let session = try connected(to: server, fixture)
        defer { session.disconnect() }

        let queue = DispatchQueue(label: "test.simplevpn.wake")
        let ceiling: Int32 = 3000        // far longer than the wake delay below
        let wakeAfter = 0.15

        // Let the session settle first: the waits immediately after sign-in return
        // early for honest reasons — the server's own post-auth traffic, and the
        // POLLOUT libssh re-arms after the auth writes.
        for _ in 0..<3 { queue.sync { _ = session.waitForActivity(withTimeoutMs: 50) } }

        // THE POLL MUST ACTUALLY WAIT. This is the defect this suite was written to
        // find: `ssh_event_dopoll` returns instantly on a connected session (libssh
        // re-arms POLLOUT after every write, and a connected socket is always
        // writable), so the "event loop" was a 100%-CPU spin and the wake pipe below
        // could never matter — nothing was ever waiting to be woken.
        for attempt in 1...2 {
            var idle = 0.0
            queue.sync {
                let t0 = DispatchTime.now()
                _ = session.waitForActivity(withTimeoutMs: 300)
                idle = Double(DispatchTime.now().uptimeNanoseconds - t0.uptimeNanoseconds) / 1e9
            }
            #expect(idle >= 0.25, """
                    idle wait \(attempt) returned after \(idle * 1000) ms instead of its \
                    300 ms ceiling — the reader loop is spinning, not waiting
                    """)
        }

        let box = SessionBox(session)
        for attempt in 1...5 {
            let done = DispatchSemaphore(value: 0)
            let elapsed = LatencyCollector()
            queue.async {
                let t0 = DispatchTime.now()
                _ = box.session.waitForActivity(withTimeoutMs: ceiling)
                let seconds = Double(DispatchTime.now().uptimeNanoseconds - t0.uptimeNanoseconds) / 1e9
                elapsed.add(latency: seconds, wrote: 0, wanted: 0)
                done.signal()
            }
            Thread.sleep(forTimeInterval: wakeAfter)
            session.wakeActivityWait()
            #expect(done.wait(timeout: .now() + 3.0) == .success,
                    "attempt \(attempt): the poll never returned after being woken")
            let seconds = elapsed.latencies.max
            print(String(format: "   wake %d: poll returned after %.1f ms (woken at %.0f ms)",
                         attempt, seconds * 1000, wakeAfter * 1000))
            #expect(seconds < wakeAfter + 0.050, """
                    attempt \(attempt): the poll ran \(seconds * 1000) ms despite being woken \
                    at \(wakeAfter * 1000) ms — wakeActivityWait did not interrupt \
                    ssh_event_dopoll
                    """)
        }
    }

    // MARK: 5 — the big one: many channels, and whether writers starve

    @Test(.enabled(if: LiveSSHFixture.isAvailable))
    func manyConcurrentChannelsAndNoWriterStarvation() throws {
        let fixture = try fixture()
        let server = try LiveSSHServer(fixture: fixture,
                                       extraOptions: ["MaxSessions=64", "MaxStartups=64"])
        defer { server.stop() }
        let echo = try EchoTarget(mode: .immediate)
        defer { echo.shutdownTarget() }

        let channelCount = 24
        let rounds = 40
        let chunk = 512

        let measured = try Self.measureWriteLatency(
            fixture: fixture, server: server, echo: echo,
            channels: channelCount, rounds: rounds, chunk: chunk, usesWakePipe: true)
        print("   \(measured.latencies.summary("wake pipe ON  (\(channelCount) channels)"))")

        // (a) every flow carried every byte, unmixed. 24 channels on one session
        // with a per-channel payload only that channel could produce.
        for (index, bytes) in measured.received.enumerated() {
            #expect(bytes.count == rounds * chunk,
                    "channel \(index) received \(bytes.count) of \(rounds * chunk) bytes")
            #expect(bytes == measured.expected[index],
                    "channel \(index)'s echo does not match what was sent to it")
        }
        #expect(echo.connectionCount == channelCount)

        // (b) THE CLAIM. A writer must not wait behind the reader loop's poll.
        // 50 ms is the budget; the poll ceiling is 200 ms, so a failure here is
        // unambiguous — it means the wake did not interrupt the poll.
        #expect(measured.latencies.percentile(0.99) < 0.050,
                "p99 write latency \(measured.latencies.percentile(0.99) * 1000) ms")
        #expect(measured.latencies.max < 0.050, """
                worst write latency \(measured.latencies.max * 1000) ms — a writer waited \
                behind ssh_event_dopoll
                """)
    }

    /// The control experiment: the SAME loop with the wake suppressed. If the
    /// self-pipe were decoration this would be just as fast — and the design note
    /// in SSHBridge.h would be wrong.
    @Test(.enabled(if: LiveSSHFixture.isAvailable))
    func withoutTheWakePipeWritersDoStarveBehindThePoll() throws {
        let fixture = try fixture()
        let server = try LiveSSHServer(fixture: fixture,
                                       extraOptions: ["MaxSessions=64", "MaxStartups=64"])
        defer { server.stop() }
        let echo = try EchoTarget(mode: .immediate)
        defer { echo.shutdownTarget() }

        let measured = try Self.measureWriteLatency(
            fixture: fixture, server: server, echo: echo,
            channels: 8, rounds: 10, chunk: 512, usesWakePipe: false)
        print("   \(measured.latencies.summary("wake pipe OFF (8 channels)"))")

        // Not an assertion about a number we control — an assertion that the
        // problem the self-pipe solves is REAL. Without the wake, at least one
        // writer must have waited a poll ceiling's worth.
        #expect(measured.latencies.max >= 0.050, """
                no writer starved without the wake pipe \
                (max \(measured.latencies.max * 1000) ms) — the self-pipe may no longer be \
                load-bearing
                """)
    }

    private struct Measured {
        var latencies = Latencies()
        var received: [[UInt8]] = []
        var expected: [[UInt8]] = []
    }

    /// Open `channels` direct-tcpip channels on ONE session, then in each round go
    /// idle long enough that the reader loop is parked in `ssh_event_dopoll` and
    /// have every channel write at once from a different thread. The latency
    /// measured is the time to acquire the session queue — the starvation itself.
    private static func measureWriteLatency(
        fixture: LiveSSHFixture, server: LiveSSHServer, echo: EchoTarget,
        channels channelCount: Int, rounds: Int, chunk: Int, usesWakePipe: Bool
    ) throws -> Measured {
        let session = SSHSession()
        defer { session.disconnect() }
        try session.connect(toHost: "127.0.0.1", port: Int32(server.port), timeout: 10,
                            kexAlgorithms: nil, compression: false)
        try session.verifyHostKey(withKnownHosts: nil, pin: fixture.hostKeyFingerprintHex,
                                  strict: "yes")
        try session.authKey(forUser: fixture.user, privateKeyPath: fixture.clientKeyPath,
                            certificatePath: nil, passphrase: nil)
        session.enterDataMode()

        let harness = LiveSessionHarness(session: session, usesWakePipe: usesWakePipe)
        harness.start()
        defer { harness.stop() }

        var opened: [SSHChannel] = []
        for _ in 0..<channelCount {
            opened.append(try harness.openChannel(toHost: "127.0.0.1", port: echo.port))
        }
        let openChannels = opened   // immutable: the writers below run concurrently
        defer { harness.closeChannels() }

        var expected = [[UInt8]](repeating: [], count: channelCount)
        let collector = LatencyCollector()

        for round in 0..<rounds {
            // Go quiet, so the reader loop really is blocked in the poll rather
            // than churning on echo traffic. Without this the test measures a busy
            // loop and would pass even if the wake pipe were removed.
            Thread.sleep(forTimeInterval: 0.05)
            let payloads: [[UInt8]] = (0..<channelCount).map { index in
                let seed = Int(UInt8((round * channelCount + index) & 0xff))
                return (0..<chunk).map { UInt8(($0 &+ seed &* 7) & 0xff) }
            }
            for index in 0..<channelCount { expected[index].append(contentsOf: payloads[index]) }
            // Every channel writes AT ONCE, from a different thread — the exact
            // arrangement the per-flow pumps produce in the extension.
            DispatchQueue.concurrentPerform(iterations: channelCount) { index in
                let (latency, written) = harness.write(openChannels[index], payloads[index])
                collector.add(latency: latency, wrote: written, wanted: chunk)
            }
        }

        var out = Measured()
        out.latencies = collector.latencies
        out.expected = expected
        #expect(collector.shortWrites == 0,
                "\(collector.shortWrites) write(s) did not take the whole chunk")

        let want = rounds * chunk
        _ = Loopback.wait(upTo: 30) {
            openChannels.allSatisfy { harness.received($0).count >= want }
        }
        out.received = openChannels.map { Array(harness.received($0)) }
        return out
    }

    /// Latency samples from many threads at once.
    private final class LatencyCollector: @unchecked Sendable {
        private let lock = NSLock()
        private var store = Latencies()
        private var short = 0
        func add(latency: Double, wrote: Int, wanted: Int) {
            lock.lock(); defer { lock.unlock() }
            store.add(latency)
            if wrote != wanted { short += 1 }
        }
        var latencies: Latencies { lock.lock(); defer { lock.unlock() }; return store }
        var shortWrites: Int { lock.lock(); defer { lock.unlock() }; return short }
    }

    // MARK: 5 — keepalive

    @Test(.enabled(if: LiveSSHFixture.isAvailable))
    func theInProcessKeepaliveFiresAndAnIdleSessionSurvives() throws {
        let fixture = try fixture()
        let server = try LiveSSHServer(fixture: fixture)
        defer { server.stop() }
        let echo = try EchoTarget(mode: .immediate)
        defer { echo.shutdownTarget() }
        let session = try connected(to: server, fixture)
        defer { session.disconnect() }

        let harness = LiveSessionHarness(session: session)
        harness.start()
        defer { harness.stop() }
        let channel = try harness.openChannel(toHost: "127.0.0.1", port: echo.port)

        // The engine's timer interval is shortened to a test's patience: what is
        // under test is that the request is accepted and answered, not the clock.
        for _ in 0..<5 {
            #expect(harness.sendKeepalive(), "libssh could not send keepalive@openssh.com")
            Thread.sleep(forTimeInterval: 0.2)
        }
        #expect(!harness.sessionLost, "the session died while being kept alive")

        // The server ANSWERED (reply requested), which is the half that detects a
        // peer that has gone away — and it is visible in sshd's own log.
        let log = server.log()
        #expect(log.contains("keepalive@openssh.com"),
                "sshd never logged the keepalive global request")

        // And the session is still usable afterwards — a keepalive that corrupted
        // the session state would show up exactly here.
        #expect(harness.writeAll(channel, Array("after-idle".utf8)))
        #expect(Loopback.wait(upTo: 10) { harness.received(channel).count == 10 })
        harness.closeChannels()
    }

    // MARK: 6 — compression

    @Test(.enabled(if: LiveSSHFixture.isAvailable))
    func compressionNegotiatesInProcessAndStillCarriesBytes() throws {
        let fixture = try fixture()
        let server = try LiveSSHServer(fixture: fixture)
        defer { server.stop() }
        let echo = try EchoTarget(mode: .immediate)
        defer { echo.shutdownTarget() }

        let session = try connected(to: server, fixture, compression: true)
        defer { session.disconnect() }
        let harness = LiveSessionHarness(session: session)
        harness.start()
        defer { harness.stop() }

        // A very compressible payload: if zlib is on the wire this is where it
        // would show, and if it is broken this is where it would corrupt.
        let channel = try harness.openChannel(toHost: "127.0.0.1", port: echo.port)
        let payload = [UInt8](repeating: 0x41, count: 256 * 1024)
        #expect(harness.writeAll(channel, payload))
        #expect(Loopback.wait(upTo: 30) { harness.received(channel).count >= payload.count },
                "compressed round trip stalled at \(harness.received(channel).count) bytes")
        #expect(Array(harness.received(channel)) == payload)
        harness.closeChannels()

        // libssh exposes no compression getter, so the server's own kex line is the
        // evidence. Only asserted when sshd actually logged one, so a quieter
        // OpenSSH can't turn this into a phantom failure.
        let log = server.log()
        let compressionLines = log.split(separator: "\n").filter { $0.contains("compression") }
        if compressionLines.isEmpty {
            print("   compression: sshd logged no kex compression line — round trip only")
        } else {
            print("   compression: \(compressionLines.prefix(2).joined(separator: " | "))")
            #expect(compressionLines.contains { $0.contains("zlib") },
                    "compression was asked for but sshd negotiated: \(compressionLines.joined(separator: " | "))")
        }
    }

    // MARK: 7 — the server goes away

    @Test(.enabled(if: LiveSSHFixture.isAvailable))
    func aDeadServerIsNoticedRatherThanHangingAndTheSessionCanBeRebuilt() throws {
        let fixture = try fixture()
        let echo = try EchoTarget(mode: .immediate)
        defer { echo.shutdownTarget() }

        let server = try LiveSSHServer(fixture: fixture)
        let session = try connected(to: server, fixture)
        let harness = LiveSessionHarness(session: session)
        harness.start()
        let channel = try harness.openChannel(toHost: "127.0.0.1", port: echo.port)
        #expect(harness.writeAll(channel, Array("alive".utf8)))
        #expect(Loopback.wait(upTo: 10) { harness.received(channel).count == 5 })
        #expect(!harness.sessionLost)

        // Kill the listener AND the forked child that owns our session — sshd forks
        // per connection, so signalling only the parent would prove nothing.
        server.killEverything()

        // THE POINT: the loop must NOTICE, not hang and not spin. `waitForActivity`
        // returning -1 is the only signal the engine gets, and it is what drives
        // reconnect. A generous window because it must be detected at all; the
        // poll-count check below is what says it wasn't a busy spin.
        let pollsBefore = harness.polls
        #expect(Loopback.wait(upTo: 15, step: 0.05) { harness.sessionLost },
                "the engine never noticed the SSH server had died")
        let spins = harness.polls - pollsBefore
        #expect(spins < 200, """
                the loop spun \(spins) times noticing session loss — a dead socket must \
                report loss, not poll hot
                """)
        print("   session loss noticed after \(spins) poll iteration(s)")
        harness.stop()
        session.disconnect()

        // Restore: a fresh server from the same fixture, and a session must come up
        // again — which is what the engine's reconnect path does after a backoff.
        let restored = try LiveSSHServer(fixture: fixture)
        defer { restored.stop() }
        let second = try connected(to: restored, fixture)
        defer { second.disconnect() }
        let again = LiveSessionHarness(session: second)
        again.start()
        defer { again.stop() }
        let reopened = try again.openChannel(toHost: "127.0.0.1", port: echo.port)
        #expect(again.writeAll(reopened, Array("reconnected".utf8)))
        #expect(Loopback.wait(upTo: 10) { again.received(reopened).count == 11 },
                "the rebuilt session could not carry a flow")
        again.closeChannels()
    }
}
