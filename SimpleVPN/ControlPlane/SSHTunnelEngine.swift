// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
//  SSHTunnelEngine.swift
//  In-process SSH tunnels over libssh (SSHBridge) — no /usr/bin/ssh subprocess.
//  A single serial queue owns the libssh session (it's single-threaded); local
//  listeners run on Network.framework and hand each accepted connection a
//  direct-tcpip channel:
//    • SOCKS proxy (-D)   — a SOCKS5 server on socksPort
//    • port-forward (-L)  — a fixed local→remote mapping
//  The net-tunnel (-w) mode is NOT served here — it still runs through /usr/bin/ssh
//  (`SubprocessTunnelManager`, `-o Tunnel=point-to-point -w any:any`). The bridge's
//  tun@openssh.com channel (`openTunChannelMode:`) is built but has no caller yet;
//  the SSH Network Tunnel kind uses per-flow direct-tcpip instead (see
//  PacketTunnel/Engines/SSHNetworkTunnelEngine.swift), which needs no server-side
//  root or PermitTunnel.
//  Auth honours the PINNED method when one is set (password / key / certificate /
//  agent / kerberos); unpinned it tries key, then agent, then password.
//
//  Concurrency model: the session runs BLOCKING through handshake/host-key/auth,
//  then switches to NON-BLOCKING (`enterDataMode`) for the data pump. Every libssh
//  call — reads, writes, channel open, channel close — is dispatched on the single
//  `ssh` serial queue, and channels are freed there too (never in dealloc, which
//  runs on an arbitrary thread). Non-blocking reads mean one idle channel can't
//  stall the others (no head-of-line blocking).
//

import Foundation
import Network
import os

// Safe to pass across the Network.framework callback queues and the `ssh` serial
// queue: every libssh call on an SSHChannel is funnelled onto the `ssh` queue, so
// it is never touched concurrently despite being handed between executors.
extension SSHChannel: @unchecked Sendable {}

/// A live-forward request the in-process engine couldn't satisfy — the message is
/// shown verbatim as the row's failure reason.
nonisolated struct SSHForwardError: LocalizedError {
    let message: String
    init(_ message: String) { self.message = message }
    var errorDescription: String? { message }
}

/// Nonisolated: the whole engine lives on background queues (libssh serial queue +
/// Network.framework). `state` is observable for UI but published on the main queue.
@Observable
nonisolated final class SSHTunnelEngine: @unchecked Sendable {
    enum State: Equatable { case idle, connecting, connected, failed(String) }
    private(set) var state: State = .idle

    private static let log = Logger(subsystem: "com.bragi0.SimpleVPN", category: "ssh-engine")

    private let ssh = DispatchQueue(label: "com.bragi0.SimpleVPN.ssh.session")
    private var session: SSHSession?      // touched only on `ssh`
    private var listener: NWListener?

    // Live forwards added while connected ("-L"/"-D" listeners keyed by their
    // normalized "FLAG spec" line). Guarded by a lock: add/remove arrive from
    // MainActor tasks while stop() may race them.
    private let forwardLock = NSLock()
    private var _forwards: [String: NWListener] = [:]

    // Stop signal, readable from both the MainActor (`stop`) and the `ssh` queue
    // (the in-flight connect), so a disconnect during connect can't leave a live
    // listener/session behind.
    private let stopLock = NSLock()
    private var _stopped = false
    private var stopped: Bool { stopLock.lock(); defer { stopLock.unlock() }; return _stopped }
    private func markStopped() { stopLock.lock(); _stopped = true; stopLock.unlock() }

    struct Config: Sendable {
        var host: String
        var port: Int
        var username: String
        var password: String?
        var identityFile: String?
        /// OpenSSH certificate (…-cert.pub) presented alongside the identity key.
        var certificateFile: String? = nil
        var socksPort: Int
        /// OpenSSH known_hosts file consulted when no explicit pin is set.
        var knownHostsPath: String? = (("~/.ssh/known_hosts") as NSString).expandingTildeInPath
        /// Exact SHA-256 host-key pin; wins over known_hosts when present.
        var pinnedHostKeySHA256: String? = nil
        /// "yes" | "accept-new" | "no" — a changed key is always refused regardless.
        var strictHostKey: String = "accept-new"
        /// TCP connect timeout in seconds (ssh's ConnectTimeout).
        var connectTimeout: Int = 15
        /// How to sign in: nil/"" = automatic (key → agent → password);
        /// "password" | "key" | "certificate" | "agent" | "kerberos" pin ONE
        /// method — that method is used and nothing else, so what the user
        /// chose is what actually authenticates. Kerberos is opt-in only.
        var authMethod: String? = nil
        /// Key-exchange preference (OpenSSH KexAlgorithms syntax); nil = libssh default.
        var kexAlgorithms: String? = nil
        /// Session keepalive interval in seconds (`ssh -o ServerAliveInterval`);
        /// 0 turns it off. The in-process engine used to send NONE while the
        /// descriptor promised the setting was honoured — the timer below is that
        /// promise kept.
        var keepaliveInterval: Int = 30
        /// Transport compression (`ssh -C`). Negotiated at kex, so it is passed to
        /// `connect`, not applied afterwards.
        var compression: Bool = false
    }

    /// A sign-in that can't proceed as configured — the message is user-facing.
    nonisolated struct AuthError: LocalizedError {
        let message: String
        init(_ message: String) { self.message = message }
        var errorDescription: String? { message }
    }

    /// Publish `state` on the main queue so the `@Observable` bookkeeping and any
    /// SwiftUI reads are serialized on one thread (writes arrive from several).
    private func publish(_ s: State) {
        if Thread.isMainThread { state = s }
        else { DispatchQueue.main.async { self.state = s } }
    }

    /// Establish the SSH session and start the SOCKS5 listener. Returns once the
    /// session is up (or throws). Channels are opened lazily per connection.
    func startSOCKS(_ config: Config) async throws {
        publish(.connecting)
        try await withCheckedThrowingContinuation { (cont: CheckedContinuation<Void, Error>) in
            ssh.async {
                let s = SSHSession()
                do {
                    try s.connect(toHost: config.host, port: Int32(config.port),
                                  timeout: Int32(max(1, config.connectTimeout)),
                                  kexAlgorithms: config.kexAlgorithms,
                                  compression: config.compression)
                    // Verify the host key BEFORE auth — otherwise we'd hand
                    // credentials to whoever answered (MITM).
                    try s.verifyHostKey(withKnownHosts: config.knownHostsPath,
                                        pin: config.pinnedHostKeySHA256,
                                        strict: config.strictHostKey)
                    // TOFU is a trust decision — say out loud exactly what key
                    // was just pinned, so a surprise entry is attributable.
                    if s.acceptedNewHostKey, let fp = s.hostKeyFingerprintSHA256 {
                        Self.log.notice("Trusted new SSH host key on first use for \(config.host, privacy: .public):\(config.port): \(s.hostKeyType ?? "key", privacy: .public) SHA256:\(fp, privacy: .public) — appended to known_hosts")
                    }
                    try Self.authenticate(s, config)
                    s.enterDataMode()   // non-blocking from here on
                } catch {
                    self.publish(.failed(error.localizedDescription))
                    cont.resume(throwing: error); return
                }
                // A disconnect may have arrived while we were connecting; if so,
                // don't publish a live session (the listener isn't started yet).
                if self.stopped { s.disconnect(); cont.resume(throwing: CancellationError()); return }
                self.session = s
                self.startKeepalive(every: config.keepaliveInterval)
                cont.resume(returning: ())
            }
        }
        // Re-check after the await: a disconnect could have landed between the
        // continuation resuming and here.
        if stopped {
            ssh.async { self.session?.disconnect(); self.session = nil }
            throw CancellationError()
        }
        do {
            try await startListener(port: config.socksPort)
        } catch {
            // Publish the real reason (typically EADDRINUSE) and rethrow so the
            // caller can fall back — never report Connected over a dead listener.
            publish(.failed("SOCKS listener failed: \(error.localizedDescription)"))
            throw error
        }
        if stopped { throw CancellationError() }   // stop() during listener startup
        publish(.connected)
    }

    /// An explicit method is used alone — a config that says "password" must
    /// never quietly succeed with a key (or vice versa); the chosen method's
    /// real failure surfaces instead. Automatic keeps the historical chain.
    private static func authenticate(_ s: SSHSession, _ c: Config) throws {
        switch c.authMethod ?? "" {
        case "password":
            guard let pw = c.password, !pw.isEmpty else {
                throw AuthError("Password sign-in is selected but no password was provided.")
            }
            try s.authPassword(forUser: c.username, password: pw)
        case "key":
            guard let key = c.identityFile, !key.isEmpty else {
                throw AuthError("Key sign-in is selected but no identity file is set.")
            }
            try s.authKey(forUser: c.username, privateKeyPath: key,
                          certificatePath: nil, passphrase: c.password)
        case "certificate":
            guard let key = c.identityFile, !key.isEmpty,
                  let cert = c.certificateFile, !cert.isEmpty else {
                throw AuthError("Certificate sign-in is selected but the identity file or certificate file is missing.")
            }
            try s.authKey(forUser: c.username, privateKeyPath: key,
                          certificatePath: cert, passphrase: c.password)
        case "agent":
            try s.authAgent(forUser: c.username)
        case "kerberos":
            try s.authGSSAPI(forUser: c.username)
        default:
            // Automatic: key file, then agent, then password.
            if let key = c.identityFile, !key.isEmpty {
                if (try? s.authKey(forUser: c.username, privateKeyPath: key,
                                   certificatePath: nil,
                                   passphrase: c.password)) != nil { return }
            }
            if (try? s.authAgent(forUser: c.username)) != nil { return }
            if let pw = c.password, !pw.isEmpty {
                try s.authPassword(forUser: c.username, password: pw)
                return
            }
            // authKey/authAgent throw on failure; reaching here with no
            // password means nothing worked.
            try s.authAgent(forUser: c.username)
        }
    }

    /// Start the main SOCKS listener and return only once it is actually
    /// `.ready` — bind errors (EADDRINUSE when the port is taken) arrive
    /// asynchronously via `stateUpdateHandler`, so returning at `start()` would
    /// report a proxy that can never accept a connection.
    private func startListener(port: Int) async throws {
        let listener = try NWListener(using: .tcp,
                                      on: NWEndpoint.Port(rawValue: UInt16(port)) ?? .any)
        listener.newConnectionHandler = { [weak self] conn in self?.handleSOCKS(conn) }
        self.listener = listener   // published before start so stop() can cancel it mid-await
        try await Self.startAndAwaitReady(listener)
    }

    /// Start a listener and wait for `.ready`; `.failed`/`.waiting` throw the
    /// underlying error (a fixed local port that can't bind never becomes ready).
    private static func startAndAwaitReady(_ listener: NWListener) async throws {
        try await withCheckedThrowingContinuation { (cont: CheckedContinuation<Void, Error>) in
            // The handler fires for every state change; resume exactly once.
            let resumed = OSAllocatedUnfairLock(initialState: false)
            @Sendable func resumeOnce(_ result: Result<Void, Error>) {
                let first = resumed.withLock { done -> Bool in
                    if done { return false }
                    done = true
                    return true
                }
                guard first else { return }
                cont.resume(with: result)
            }
            // weak: a strong capture in the listener's own handler is a cycle.
            listener.stateUpdateHandler = { [weak listener] state in
                switch state {
                case .ready:
                    resumeOnce(.success(()))
                case .failed(let error):
                    listener?.cancel()
                    resumeOnce(.failure(error))
                case .waiting(let error):
                    listener?.cancel()
                    resumeOnce(.failure(error))
                case .cancelled:
                    resumeOnce(.failure(CancellationError()))
                default:
                    break
                }
            }
            listener.start(queue: .global(qos: .userInitiated))
        }
    }

    // MARK: Live forwards (add/remove while connected — no reconnect)

    /// Add a forward to the running session. "D" opens another SOCKS listener,
    /// "L" a fixed local→remote listener; both reuse the direct-tcpip pump.
    /// "R" would need a `ssh_channel_listen_forward` accept loop the data
    /// pump doesn't run — refused honestly so the caller can say "reconnect
    /// required" (the subprocess path supports it live).
    func addForward(flag: String, spec: String) async throws {
        let key = "\(flag) \(spec)"
        switch flag {
        case "D":
            guard let port = Self.dynamicPort(spec), (1...65535).contains(port) else {
                throw SSHForwardError("Couldn't parse a SOCKS port out of “\(spec)”.")
            }
            try await startForwardListener(key: key, port: port) { [weak self] conn in
                self?.handleSOCKS(conn)
            }
        case "L":
            guard let (localPort, host, remotePort) = Self.localForwardParts(spec) else {
                throw SSHForwardError("Couldn't parse “\(spec)” — expected [bind:]port:host:hostport (bracketed IPv6 binds aren't supported in-process).")
            }
            try await startForwardListener(key: key, port: localPort) { [weak self] conn in
                self?.handleLocalForward(conn, host: host, port: remotePort)
            }
        default:
            throw SSHForwardError("Reverse forwards (-R) need a reconnect on the in-process engine.")
        }
    }

    /// Tear down a live forward added with `addForward`. Keyed by the same
    /// normalized "FLAG spec" line.
    func removeForward(key: String) {
        forwardLock.lock()
        let listener = _forwards.removeValue(forKey: key)
        forwardLock.unlock()
        listener?.cancel()
    }

    /// Register the listener under its key BEFORE starting it, so stop()/remove
    /// can cancel it even mid-startup; deregister again if it never got ready.
    private func startForwardListener(key: String, port: Int,
                                      onConnection: @escaping @Sendable (NWConnection) -> Void) async throws {
        guard !stopped else { throw CancellationError() }
        let listener = try NWListener(using: .tcp,
                                      on: NWEndpoint.Port(rawValue: UInt16(port)) ?? .any)
        listener.newConnectionHandler = onConnection
        forwardLock.withLock {
            _forwards[key]?.cancel()   // replacing an edited spec under the same key
            _forwards[key] = listener
        }
        do {
            try await Self.startAndAwaitReady(listener)
        } catch {
            forwardLock.withLock {
                if _forwards[key] === listener { _forwards[key] = nil }
            }
            throw error
        }
    }

    /// A fixed -L forward: no SOCKS handshake — every accepted connection goes
    /// straight to a direct-tcpip channel to the configured host:port.
    private func handleLocalForward(_ conn: NWConnection, host: String, port: Int) {
        conn.start(queue: .global(qos: .userInitiated))
        ssh.async {
            guard !self.stopped, let s = self.session,
                  let channel = try? s.openDirectTCPIP(toHost: host, port: Int32(port)) else {
                conn.cancel(); return
            }
            self.pump(conn, channel)
        }
    }

    /// "[bind:]port" → port (the -D spec).
    private static func dynamicPort(_ spec: String) -> Int? {
        Int(spec.split(separator: ":").last.map(String.init) ?? spec)
    }

    /// "[bind:]port:host:hostport" → (localPort, host, remotePort). Bracketed
    /// IPv6 fields break the colon split and return nil (surfaced as an error).
    private static func localForwardParts(_ spec: String) -> (Int, String, Int)? {
        let parts = spec.split(separator: ":").map(String.init)
        guard parts.count == 3 || parts.count == 4 else { return nil }
        let p = parts.count == 4 ? Array(parts.dropFirst()) : parts   // drop the bind address
        guard let localPort = Int(p[0]), (1...65535).contains(localPort),
              let remotePort = Int(p[2]), (1...65535).contains(remotePort),
              !p[1].isEmpty else { return nil }
        return (localPort, p[1], remotePort)
    }

    // MARK: SOCKS5 (RFC 1928, CONNECT + no-auth only)

    private func handleSOCKS(_ conn: NWConnection) {
        conn.start(queue: .global(qos: .userInitiated))
        readGreeting(conn, Data())
    }

    /// Accumulate until the full greeting (VER NMETHODS METHODS…) has arrived —
    /// NWConnection.receive may deliver fewer bytes than a full message.
    private func readGreeting(_ conn: NWConnection, _ acc: Data) {
        conn.receive(minimumIncompleteLength: 1, maximumLength: 262) { data, _, isDone, err in
            var buf = acc
            if let d = data { buf.append(d) }
            if let first = buf.first, first != 0x05 { conn.cancel(); return }   // not SOCKS5
            guard buf.count >= 2 else {
                if isDone || err != nil { conn.cancel(); return }
                self.readGreeting(conn, buf); return
            }
            let nmethods = Int(buf[1])
            guard buf.count >= 2 + nmethods else {
                if isDone || err != nil { conn.cancel(); return }
                self.readGreeting(conn, buf); return
            }
            // Any bytes past the greeting are the start of the request (pipelined).
            let rest = buf.count > 2 + nmethods ? buf.subdata(in: (2 + nmethods)..<buf.count) : Data()
            conn.send(content: Data([0x05, 0x00]), completion: .contentProcessed { _ in
                self.readRequest(conn, rest)
            })
        }
    }

    /// Accumulate until the full request (VER CMD RSV ATYP DST.ADDR DST.PORT) is in.
    private func readRequest(_ conn: NWConnection, _ acc: Data) {
        // CONNECT only; reject other commands as soon as CMD is known.
        if acc.count >= 2, acc[1] != 0x01 {
            conn.send(content: Data([0x05, 0x07, 0x00, 0x01, 0,0,0,0, 0,0]), completion: .idempotent)
            conn.cancel(); return
        }
        if let (host, port) = Self.parseSOCKSAddr(acc) {
            openChannelAndPump(conn, host: host, port: port); return
        }
        conn.receive(minimumIncompleteLength: 1, maximumLength: 262) { data, _, isDone, err in
            var buf = acc
            if let d = data { buf.append(d) }
            if buf.count >= 2, buf[1] != 0x01 {
                conn.send(content: Data([0x05, 0x07, 0x00, 0x01, 0,0,0,0, 0,0]), completion: .idempotent)
                conn.cancel(); return
            }
            if let (host, port) = Self.parseSOCKSAddr(buf) {
                self.openChannelAndPump(conn, host: host, port: port); return
            }
            if isDone || err != nil { conn.cancel(); return }
            self.readRequest(conn, buf)
        }
    }

    /// Parse a (possibly still-incomplete) SOCKS5 request. Returns nil when more
    /// bytes are needed, so the caller keeps accumulating.
    private static func parseSOCKSAddr(_ r: Data) -> (String, Int)? {
        guard r.count >= 4, r[0] == 0x05 else { return nil }
        let atyp = r[3]
        switch atyp {
        case 0x01:   // IPv4
            guard r.count >= 10 else { return nil }
            let host = "\(r[4]).\(r[5]).\(r[6]).\(r[7])"
            let port = Int(r[8]) << 8 | Int(r[9])
            return (host, port)
        case 0x03:   // domain
            guard r.count >= 5 else { return nil }
            let len = Int(r[4]); guard r.count >= 5 + len + 2 else { return nil }
            let host = String(data: r.subdata(in: 5..<5+len), encoding: .utf8) ?? ""
            let port = Int(r[5+len]) << 8 | Int(r[5+len+1])
            return host.isEmpty ? nil : (host, port)
        case 0x04:   // IPv6
            guard r.count >= 22 else { return nil }
            var parts: [String] = []
            for i in stride(from: 4, to: 20, by: 2) { parts.append(String(format: "%02x%02x", r[i], r[i+1])) }
            let port = Int(r[20]) << 8 | Int(r[21])
            return (parts.joined(separator: ":"), port)
        default: return nil
        }
    }

    private func openChannelAndPump(_ conn: NWConnection, host: String, port: Int) {
        ssh.async {
            guard !self.stopped, let s = self.session,
                  let channel = try? s.openDirectTCPIP(toHost: host, port: Int32(port)) else {
                conn.send(content: Data([0x05, 0x05, 0x00, 0x01, 0,0,0,0, 0,0]), completion: .idempotent)
                conn.cancel(); return
            }
            // Success reply (bound addr 0.0.0.0:0 is acceptable for CONNECT).
            conn.send(content: Data([0x05, 0x00, 0x00, 0x01, 0,0,0,0, 0,0]), completion: .idempotent)
            self.pump(conn, channel)
        }
    }

    /// Free a channel. MUST be invoked on the `ssh` queue.
    private func closeChannel(_ channel: SSHChannel) {
        if !channel.isClosed() { channel.close() }
    }

    /// Bridge an NWConnection to an SSH channel. Client→channel is event-driven
    /// (with full-write retry); channel→client is polled on the non-blocking ssh
    /// queue. Both directions free the channel on the ssh queue at end/error.
    private func pump(_ conn: NWConnection, _ channel: SSHChannel) {
        // Write every byte, retrying the unwritten tail on partial writes / EAGAIN.
        // @Sendable throughout: these three hand themselves between the `ssh` queue
        // and Network.framework's callback queue, and only touch queue-confined state.
        @Sendable func writeAll(_ d: Data, _ from: Int) {
            self.ssh.async {
                if channel.isClosed() { return }
                let remaining = d.count - from
                let n: Int = d.withUnsafeBytes { raw in
                    channel.write(raw.baseAddress!.advanced(by: from), length: remaining)
                }
                if n < 0 { self.closeChannel(channel); conn.cancel(); return }   // hard error
                let wrote = from + n
                if wrote < d.count {
                    // Partial write or EAGAIN(0): flush the remainder shortly.
                    self.ssh.asyncAfter(deadline: .now() + 0.003) { writeAll(d, wrote) }
                }
            }
        }
        @Sendable func clientToChannel() {
            conn.receive(minimumIncompleteLength: 1, maximumLength: 32768) { data, _, isDone, _ in
                if let d = data, !d.isEmpty { writeAll(d, 0) }
                if isDone { self.ssh.async { self.closeChannel(channel) }; return }
                clientToChannel()
            }
        }
        @Sendable func channelToClient() {
            self.ssh.async {
                if channel.isClosed() { return }
                var buf = [UInt8](repeating: 0, count: 32768)
                let cap = buf.count
                let n = buf.withUnsafeMutableBytes { channel.read($0.baseAddress!, maxLength: cap) }
                if n > 0 {
                    conn.send(content: Data(buf[0..<Int(n)]), completion: .contentProcessed { _ in })
                    self.ssh.async { channelToClient() }   // drain promptly; more may be buffered
                    return
                }
                if n < 0 || channel.isEOF() {   // hard error or clean EOF → done
                    self.closeChannel(channel); conn.cancel(); return
                }
                // n == 0: EAGAIN — nothing available yet, poll again shortly.
                self.ssh.asyncAfter(deadline: .now() + 0.02) { channelToClient() }
            }
        }
        clientToChannel()
        channelToClient()
    }

    func stop() {
        markStopped()
        listener?.cancel(); listener = nil
        forwardLock.lock()
        let extras = _forwards; _forwards = [:]
        forwardLock.unlock()
        for l in extras.values { l.cancel() }
        ssh.async {
            self.keepaliveTimer?.cancel(); self.keepaliveTimer = nil
            self.session?.disconnect(); self.session = nil
        }
        publish(.idle)
    }

    // MARK: - Keepalive (ssh.keepalive · ServerAliveInterval)

    /// Send a `keepalive@openssh.com` global request every `seconds` on the SESSION
    /// queue — the same queue every other libssh call funnels through, because a
    /// libssh session is single-threaded and a keepalive racing a channel read would
    /// corrupt the session state. 0 (or less) means off, exactly like
    /// `ServerAliveInterval 0`.
    ///
    /// This is what an idle in-process tunnel needs: without it a NAT or firewall
    /// silently forgets the flow and the tunnel is dead long before anything notices.
    /// The request wants a reply, so a peer that has gone away is detected too — the
    /// write then fails and the session is torn down by the next channel operation.
    /// MUST be called on `ssh`.
    private func startKeepalive(every seconds: Int) {
        keepaliveTimer?.cancel(); keepaliveTimer = nil
        guard seconds > 0 else { return }
        let t = DispatchSource.makeTimerSource(queue: ssh)
        t.schedule(deadline: .now() + .seconds(seconds), repeating: .seconds(seconds), leeway: .seconds(1))
        t.setEventHandler { [weak self] in
            guard let self, let s = self.session else { return }
            if !s.sendKeepalive() {
                // Not fatal on its own: the data path reports the real failure. Worth
                // one line, because "the tunnel died after N minutes idle" is exactly
                // the story this timer exists to change.
                Self.log.notice("SSH keepalive could not be sent — the session may be gone")
            }
        }
        t.resume()
        keepaliveTimer = t
        Self.log.log("SSH keepalive every \(seconds)s")
    }

    /// Touched only on the `ssh` queue (armed at connect, cancelled in `stop`).
    private var keepaliveTimer: DispatchSourceTimer?
}
