// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
//  SSHTunnelEngine.swift
//  In-process SSH tunnels over libssh2 (SSHBridge) — no /usr/bin/ssh subprocess.
//  A single serial queue owns the libssh2 session (it's single-threaded); local
//  listeners run on Network.framework and hand each accepted connection a
//  direct-tcpip channel:
//    • SOCKS proxy (-D)   — a SOCKS5 server on socksPort
//    • port-forward (-L)  — a fixed local→remote mapping
//  The net-tunnel (-w) mode uses the bridge's tun@openssh.com channel and is wired
//  where a utun is available. Auth tries key, then agent, then password.
//
//  Concurrency model: the session runs BLOCKING through handshake/host-key/auth,
//  then switches to NON-BLOCKING (`enterDataMode`) for the data pump. Every libssh2
//  call — reads, writes, channel open, channel close — is dispatched on the single
//  `ssh` serial queue, and channels are freed there too (never in dealloc, which
//  runs on an arbitrary thread). Non-blocking reads mean one idle channel can't
//  stall the others (no head-of-line blocking).
//

import Foundation
import Network

// Safe to pass across the Network.framework callback queues and the `ssh` serial
// queue: every libssh2 call on an SSHChannel is funnelled onto the `ssh` queue, so
// it is never touched concurrently despite being handed between executors.
extension SSHChannel: @unchecked Sendable {}

/// Nonisolated: the whole engine lives on background queues (libssh2 serial queue +
/// Network.framework). `state` is observable for UI but published on the main queue.
@Observable
nonisolated final class SSHTunnelEngine: @unchecked Sendable {
    enum State: Equatable { case idle, connecting, connected, failed(String) }
    private(set) var state: State = .idle

    private let ssh = DispatchQueue(label: "com.bragi0.SimpleVPN.ssh.session")
    private var session: SSHSession?      // touched only on `ssh`
    private var listener: NWListener?

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
        var socksPort: Int
        /// OpenSSH known_hosts file consulted when no explicit pin is set.
        var knownHostsPath: String? = (("~/.ssh/known_hosts") as NSString).expandingTildeInPath
        /// Exact SHA-256 host-key pin; wins over known_hosts when present.
        var pinnedHostKeySHA256: String? = nil
        /// "yes" | "accept-new" | "no" — a changed key is always refused regardless.
        var strictHostKey: String = "accept-new"
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
                    try s.connect(toHost: config.host, port: Int32(config.port), timeout: 15)
                    // Verify the host key BEFORE auth — otherwise we'd hand
                    // credentials to whoever answered (MITM).
                    try s.verifyHostKey(withKnownHosts: config.knownHostsPath,
                                        pin: config.pinnedHostKeySHA256,
                                        strict: config.strictHostKey)
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
                cont.resume(returning: ())
            }
        }
        // Re-check after the await: a disconnect could have landed between the
        // continuation resuming and here.
        if stopped {
            ssh.async { self.session?.disconnect(); self.session = nil }
            throw CancellationError()
        }
        try startListener(port: config.socksPort)
        publish(.connected)
    }

    private static func authenticate(_ s: SSHSession, _ c: Config) throws {
        if let key = c.identityFile, !key.isEmpty {
            if (try? s.authKey(forUser: c.username, privateKeyPath: key, passphrase: c.password)) != nil { return }
        }
        if (try? s.authAgent(forUser: c.username)) != nil { return }
        if let pw = c.password, !pw.isEmpty {
            try s.authPassword(forUser: c.username, password: pw)
            return
        }
        // authKey/authAgent throw on failure; reaching here with no password means
        // nothing worked.
        try s.authAgent(forUser: c.username)
    }

    private func startListener(port: Int) throws {
        let params = NWParameters.tcp
        let listener = try NWListener(using: params,
                                      on: NWEndpoint.Port(rawValue: UInt16(port)) ?? .any)
        listener.newConnectionHandler = { [weak self] conn in self?.handleSOCKS(conn) }
        listener.start(queue: .global(qos: .userInitiated))
        self.listener = listener
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
        ssh.async { self.session?.disconnect(); self.session = nil }
        publish(.idle)
    }
}
