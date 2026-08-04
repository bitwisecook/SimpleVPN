// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
//  SSHNetworkTunnelEngine.swift
//  The SSH Network Tunnel: a utun with routes, the gVisor netstack behind it, and
//  ONE SSH `direct-tcpip` channel per flow. The netstack half is the same Go
//  engine the Proxy Tunnel uses (Vendor/proxy-engine/src) — this file supplies
//  the other half, the libssh session that dials each flow.
//
//  ┌ NEPacketTunnelFlow ┐   raw IP    ┌ gVisor netstack ┐  per flow  ┌ libssh ┐
//  │  (this file pumps) │ ─────────── │  PXPacketIn /   │ ────────── │ direct │
//  └────────────────────┘   packets   │  packetOut      │  socketpair│ -tcpip │
//                                     └─────────────────┘   fd       └────────┘
//
//  WHY A SOCKETPAIR PER FLOW. The Go side asks for a flow and gets back a socket
//  descriptor (see flowdial.go for the full argument). That means Go holds a real
//  net.Conn — its existing pipe/copy/half-close/counters all work untouched — and
//  the backpressure between the guest and the SSH session is the kernel's socket
//  buffer rather than a queue we would have to invent, size and debug.
//
//  THREADING. libssh sessions are single-threaded, so `sshQueue` (serial) is the
//  ONLY thing that touches one, with exactly one documented exception:
//  `wakeActivityWait`. Per-flow socketpair reads run on `pumpQueue` (concurrent)
//  and re-enter `sshQueue` synchronously to write — which is where the
//  backpressure comes from, and also why the reader loop's poll must be
//  interruptible: a `sync` write must never wait behind a 200 ms poll. That is
//  what the wake pipe in SSHBridge is for.
//
//  NO POLLING. The reader loop blocks in `ssh_event_dopoll` on the session's own
//  socket. Idle costs nothing; a packet is processed when it lands. The 200 ms
//  ceiling is a liveness backstop, not a poll interval.
//
//  ISOLATION. This target is `nonisolated` by default, which is what this file
//  needs: the dial callback arrives on a Go goroutine and must not hop to another
//  executor to answer. The retroactive `@unchecked Sendable` conformances for
//  SSHChannel/SSHSession live HERE and not in Shared/ on purpose — the app target
//  compiles the same bridge, and a second retroactive conformance there would
//  clash.
//
//  KILL-SWITCH SHAPE, DELIBERATE: when the session drops, the tunnel's network
//  settings are NOT torn down. The utun keeps its routes, so traffic destined for
//  the tunnel is REFUSED (every dial answers -3) instead of falling back to the
//  physical path. A VPN that leaks while reconnecting is worse than one that
//  stalls, so this is a stall on purpose. Flows fail fast and are never queued.
//

import Foundation
import NetworkExtension
import os

// The bridge types cross queues by reference. They are `@unchecked` because the
// invariant that makes them safe is a DISCIPLINE (every call on `sshQueue`), not
// something the type system can see — see the file header.
extension SSHChannel: @retroactive @unchecked Sendable {}
extension SSHSession: @retroactive @unchecked Sendable {}

protocol SSHNetworkTunnelEngineDelegate: AnyObject {
    /// A failure the session cannot recover from (bad settings, refused sign-in,
    /// a host key that doesn't match). NOT a transport drop — those reconnect.
    func sshNetworkTunnelEngine(_ engine: SSHNetworkTunnelEngine, didFailWithError error: Error)
    /// Engine diagnostics for os_log.
    func sshNetworkTunnelEngine(_ engine: SSHNetworkTunnelEngine, didLog line: String)
}

final class SSHNetworkTunnelEngine: @unchecked Sendable {

    private static let log = Logger(subsystem: "com.bragi0.SimpleVPN.PacketTunnel", category: "sshnet")

    // MARK: - Tunables

    /// A flow's whole budget for getting a channel open, INCLUDING its wait behind
    /// other work on the session queue. Deliberately under the Go engine's own
    /// 30 s dial timeout so the reset the guest sees is ours, attributed to the
    /// SSH server, rather than the netstack's anonymous one.
    private static let dialBudget: DispatchTimeInterval = .seconds(15)

    /// The reader loop's idle ceiling. Not a poll interval — the wake pipe returns
    /// the poll the instant anything needs the queue — just a backstop so a
    /// silently-dead socket is noticed.
    private static let pollCeilingMs: Int32 = 200

    /// Per-flow copy chunk. Small enough that one chunk's write can never hold the
    /// session queue for long (head-of-line fairness between flows), large enough
    /// not to pay the queue hop per kilobyte.
    private static let chunkSize = 16 * 1024

    /// Socketpair buffer, each direction, each end. Generous because it IS the
    /// window between the guest's TCP and the SSH channel: too small and a fast
    /// download stalls on queue hops rather than on bandwidth.
    private static let socketBufferBytes: Int32 = 256 * 1024

    /// Reconnect backoff, then jittered ±20% and repeated indefinitely at the cap.
    /// Indefinite because the alternative — giving up — drops the tunnel, and a
    /// dropped tunnel is a leak (see the kill-switch note in the file header).
    private static let backoffSeconds: [Double] = [1, 2, 4, 8, 15, 30]

    /// Refusal codes handed back to the Go dialler. MUST match the constants in
    /// Vendor/proxy-engine/src/flowdial.go.
    enum FlowRefusal: Int32 {
        case generic = -1
        case noSession = -2
        case sessionDown = -3
        case serverRefused = -4
        case timedOut = -5
    }

    // MARK: - State

    private weak var provider: NEPacketTunnelProvider?
    private weak var delegate: (any SSHNetworkTunnelEngineDelegate)?

    /// Every libssh call. Serial, and the only toucher of `session`.
    private let sshQueue = DispatchQueue(label: "com.bragi0.SimpleVPN.sshnet.session")
    /// Per-flow socketpair reads. Concurrent: one blocking read per live flow.
    private let pumpQueue = DispatchQueue(label: "com.bragi0.SimpleVPN.sshnet.pumps",
                                          attributes: .concurrent)

    private let lock = NSLock()
    private var start: SSHNetworkTunnelStartConfig?
    private var session: SSHSession?          // touched ONLY on sshQueue
    private var sessionUp = false             // guarded by `lock`
    private var stopping = false              // guarded by `lock`
    private var pumpRunning = false           // guarded by `lock`
    private var reconnectCount = 0            // guarded by `lock`
    private var lastKeepalive = Date.distantPast
    private var flows: [ObjectIdentifier: Flow] = [:]   // guarded by `lock`
    private var refusedFlows: Int64 = 0       // guarded by `lock`
    private var openedFlows: Int64 = 0        // guarded by `lock`
    private var lastSessionError = ""         // guarded by `lock`

    /// The engine currently wired to the C callbacks. Same single-static pattern
    /// as the other in-process engines: a C function pointer cannot capture, and
    /// exactly one tunnel runs per provider process.
    private static let currentLock = NSLock()
    nonisolated(unsafe) private static var current: SSHNetworkTunnelEngine?

    private static func active() -> SSHNetworkTunnelEngine? {
        currentLock.lock(); defer { currentLock.unlock() }
        return current
    }

    init(provider: NEPacketTunnelProvider, delegate: any SSHNetworkTunnelEngineDelegate) {
        self.provider = provider
        self.delegate = delegate
    }

    // MARK: - One live flow

    /// One netstack flow: our end of the socketpair, and the SSH channel it is
    /// spliced to. `id` keys the table; the channel is only ever used on sshQueue.
    private final class Flow: @unchecked Sendable {
        let id: ObjectIdentifier
        let channel: SSHChannel
        /// OUR end of the socketpair. Go holds a dup of the other end.
        let fd: Int32
        let target: String
        /// Bytes the channel produced that the socketpair would not take yet. The
        /// reader loop stops reading this channel until it drains, which is the
        /// server→guest direction's backpressure.
        var pending = Data()
        /// The guest has finished sending and the channel's EOF still has to go out
        /// (the first attempt would have blocked). Retried by the reader sweep.
        /// Touched only on sshQueue, like `pending`.
        var needsEOF = false
        private let closed = NSLock()
        private var isClosed = false

        init(channel: SSHChannel, fd: Int32, target: String) {
            self.channel = channel
            self.fd = fd
            self.target = target
            self.id = ObjectIdentifier(channel)
        }

        /// Close our socketpair end exactly once. The CHANNEL is closed separately,
        /// on sshQueue — never from here, which can run on a pump thread.
        func closeSocket() {
            closed.lock(); defer { closed.unlock() }
            guard !isClosed else { return }
            isClosed = true
            close(fd)
        }
    }

    // MARK: - Lifecycle

    /// Open the session and register the flow dialler, then hand the netstack up.
    ///
    /// Returns an error only for failures that are the USER'S to fix: bad settings,
    /// a refused sign-in, a host key that doesn't match. A transport problem
    /// reconnects instead, because the tunnel is already established by then and
    /// tearing it down would be the leak.
    func start(config: SSHNetworkTunnelStartConfig) -> Error? {
        if let problem = config.problem {
            return SSHNetworkTunnelEngineError.engine(kind: "badRequest", message: problem)
        }
        lock.lock(); start = config; stopping = false; lock.unlock()

        Self.log.log("sshnet start: \(config.redactedDescription(), privacy: .public)")

        // The session FIRST: a sign-in or host-key failure must be reported as a
        // start failure, before any netstack exists to be torn down again.
        var openError: Error?
        sshQueue.sync {
            openError = openSession(config)
        }
        if let openError {
            Self.log.error("sshnet session failed: \(openError.localizedDescription, privacy: .public)")
            return openError
        }
        lock.lock(); sessionUp = true; lock.unlock()

        // Register the dialler BEFORE PXStart — PXStart refuses an ssh:// upstream
        // without one, which is the guard that turns "every flow refuses and
        // nobody knows why" into one settings error.
        Self.currentLock.lock(); Self.current = self; Self.currentLock.unlock()
        PXSetFlowDialCallback(Self.flowDial)
        PXSetCallbacks(Self.packetOut, Self.stateChanged, Self.logLine)

        let reply = config.engineJSONString().withCString { PXStart($0) }
        if let error = Self.engineError(from: Self.takeString(reply),
                                       fallback: "The SSH tunnel's network stack could not start.") {
            teardownSession(reason: "netstack failed to start")
            return error
        }

        startReaderLoop()
        return nil
    }

    /// Tear everything down. Safe to call more than once, and safe after a failed
    /// start.
    func stop() {
        lock.lock()
        if stopping { lock.unlock(); return }
        stopping = true
        lock.unlock()

        _ = Self.takeString(PXStop())
        teardownSession(reason: "stopping")

        Self.currentLock.lock()
        if Self.current === self { Self.current = nil }
        Self.currentLock.unlock()
        // Callbacks last: a packet already inside the Go writer would otherwise
        // land on a torn-down flow.
        PXSetFlowDialCallback(nil)
        PXSetCallbacks(nil, nil, nil)
        Self.log.log("sshnet stopped")
    }

    /// Open and authenticate. MUST run on sshQueue.
    private func openSession(_ config: SSHNetworkTunnelStartConfig) -> Error? {
        let s = SSHSession()
        guard let (host, port) = Self.hostAndPort(from: config.upstream) else {
            return SSHNetworkTunnelEngineError.engine(
                kind: "badRequest", message: "This tunnel's server address can't be used.")
        }
        // The bridge's BOOL+NSError** methods import as `throws`, so libssh's own
        // reason arrives as the thrown error's description — which is the only
        // useful thing in a failed handshake.
        do {
            try s.connect(toHost: host, port: port,
                          timeout: Int32(config.connectTimeoutSeconds),
                          kexAlgorithms: config.keyExchange.isEmpty ? nil : config.keyExchange,
                          compression: false)
        } catch {
            return SSHNetworkTunnelEngineError.engine(kind: "network",
                                                      message: error.localizedDescription)
        }

        // ── HOST KEY BEFORE AUTH, AND PIN ONLY ──
        // Before, because a host key checked after authentication is a host key
        // checked after the credential has already been handed to whoever
        // answered. Pin only, because this process cannot prompt (no UI, no user
        // session) and cannot read or write known_hosts (root, sandboxed, and the
        // bridge points libssh's known-hosts options at /dev/null). The app
        // resolved trust and passed the ONE fingerprint we accept.
        let status = s.checkHostKey(withKnownHosts: nil, pin: config.expectedHostKeySHA256)
        guard status == .match else {
            let presented = s.hostKeyFingerprintSHA256 ?? "(none presented)"
            s.disconnect()
            let why: String
            switch status {
            case .mismatch:
                why = "The SSH server's host key doesn't match the one SimpleVPN expected"
                    + " — refusing to sign in. It offered \(s.hostKeyType ?? "a key") SHA256:\(presented)."
            case .notFound, .unavailable:
                // Treated as refusals too: "couldn't check" is never permission to
                // proceed, and this process has no second way to ask.
                why = "SimpleVPN couldn't verify the SSH server's identity, so it didn't hand over your sign-in."
            case .match:
                why = ""   // unreachable
            @unknown default:
                why = "SimpleVPN couldn't verify the SSH server's identity."
            }
            return SSHNetworkTunnelEngineError.engine(kind: "hostKey", message: why)
        }
        Self.log.log("sshnet host key verified: pin matched \(config.expectedHostKeySHA256, privacy: .public)")

        // Sign in. Password, key or certificate only — agent and Kerberos cannot
        // work from here (SSH_AUTH_SOCK and the ticket cache belong to the user's
        // session), which is why the editor offers neither and says why.
        do {
            if !config.privateKeyPEM.isEmpty {
                try s.authKey(forUser: config.username,
                              privateKeyPEM: config.privateKeyPEM,
                              certificatePEM: config.certificatePEM.isEmpty ? nil : config.certificatePEM,
                              passphrase: config.password.isEmpty ? nil : config.password)
            } else {
                try s.authPassword(forUser: config.username, password: config.password)
            }
        } catch {
            s.disconnect()
            return SSHNetworkTunnelEngineError.engine(kind: "auth",
                                                      message: error.localizedDescription)
        }

        // Non-blocking from here: a channel read must never block the shared queue.
        s.enterDataMode()
        session = s
        lastKeepalive = Date()
        Self.log.log("sshnet session up to \(host, privacy: .public):\(port)")
        return nil
    }

    /// Close the session and every flow riding it. Safe on any queue.
    private func teardownSession(reason: String) {
        lock.lock()
        sessionUp = false
        let live = flows
        flows.removeAll()
        lock.unlock()

        // Every flow's socketpair closes FIRST, so Go's copy loops see EOF and the
        // guest's connections RESET rather than hanging. A hung flow is worse than
        // a reset one: the app never learns anything.
        for (_, flow) in live { flow.closeSocket() }

        session?.wakeActivityWait()
        sshQueue.async { [weak self] in
            guard let self else { return }
            for (_, flow) in live { flow.channel.close() }
            self.session?.disconnect()
            self.session = nil
        }
        Self.log.log("sshnet session torn down (\(reason, privacy: .public)), \(live.count) flow(s) reset")
    }

    // MARK: - The reader loop (event driven, never polled)

    private func startReaderLoop() {
        lock.lock()
        if pumpRunning || stopping { lock.unlock(); return }
        pumpRunning = true
        lock.unlock()
        sshQueue.async { [weak self] in self?.readerStep() }
    }

    /// One iteration: drain what libssh has, wait for more, reschedule.
    ///
    /// Written as a self-rescheduling step rather than a `while` loop so `stop()`
    /// and every queued flow write interleave between iterations instead of
    /// waiting for a loop to notice.
    private func readerStep() {
        lock.lock()
        let go = pumpRunning && !stopping
        let up = sessionUp
        lock.unlock()
        guard go else { return }

        guard up, let s = session else {
            // Reconnecting: nothing to read. Come back when the session returns —
            // the reconnect path restarts this loop, so just stop here.
            return
        }

        drainChannels()
        sendKeepaliveIfDue(s)

        let rc = s.waitForActivity(withTimeoutMs: Self.pollCeilingMs)
        if rc < 0 {
            handleSessionLoss(reason: "the connection to the SSH server was lost")
            return
        }
        sshQueue.async { [weak self] in self?.readerStep() }
    }

    /// Read every open channel and hand the bytes to its socketpair. MUST run on
    /// sshQueue.
    private func drainChannels() {
        lock.lock(); let live = Array(flows.values); lock.unlock()
        guard !live.isEmpty else { return }

        var buf = [UInt8](repeating: 0, count: Self.chunkSize)
        for flow in live {
            // A flow with bytes the socketpair wouldn't take is NOT read further:
            // that is the server→guest backpressure, and reading more would only
            // grow an unbounded buffer inside this process.
            if !flow.pending.isEmpty {
                if !flush(flow) { continue }
                if !flow.pending.isEmpty { continue }
            }
            if flow.channel.isClosed() {
                finish(flow, reason: "channel closed")
                continue
            }
            // A half-close whose EOF wouldn't fit earlier: retry it here rather than
            // leaving the server waiting for a request end that never arrives.
            if flow.needsEOF, flow.channel.sendEOF() { flow.needsEOF = false }
            var readAnything = false
            while true {
                let n = buf.withUnsafeMutableBytes { raw -> Int in
                    guard let base = raw.baseAddress else { return -1 }
                    return flow.channel.read(base, maxLength: Self.chunkSize)
                }
                if n < 0 {
                    finish(flow, reason: "channel read failed")
                    break
                }
                if n == 0 {
                    // Nothing buffered right now. EOF is the same return with
                    // isEOF set — that is the server closing its half.
                    if flow.channel.isEOF(), !readAnything {
                        finish(flow, reason: "server closed the connection")
                    }
                    break
                }
                readAnything = true
                flow.pending.append(contentsOf: buf[0..<n])
                if !flush(flow) { break }
                if !flow.pending.isEmpty { break }   // socketpair full; stop for now
                if n < Self.chunkSize { break }      // drained
            }
        }
    }

    /// Push a flow's pending bytes into its socketpair without blocking. Returns
    /// false when the flow is finished (peer gone).
    ///
    /// MSG_DONTWAIT rather than O_NONBLOCK on the descriptor: the per-flow pump
    /// does a BLOCKING read on the same fd from another thread, and flipping the
    /// descriptor's flag would turn that into a spin.
    private func flush(_ flow: Flow) -> Bool {
        while !flow.pending.isEmpty {
            let sent = flow.pending.withUnsafeBytes { raw -> Int in
                guard let base = raw.baseAddress else { return -1 }
                return send(flow.fd, base, raw.count, MSG_DONTWAIT)
            }
            if sent > 0 {
                flow.pending.removeFirst(sent)
                continue
            }
            if sent < 0, errno == EAGAIN || errno == EWOULDBLOCK {
                return true   // buffer full; keep the remainder and try next sweep
            }
            // EPIPE/ECONNRESET: Go closed its end (the guest went away).
            finish(flow, reason: "the app closed the connection")
            return false
        }
        return true
    }

    /// Retire a flow. MUST run on sshQueue (it closes the channel).
    private func finish(_ flow: Flow, reason: String) {
        lock.lock()
        let known = flows.removeValue(forKey: flow.id) != nil
        lock.unlock()
        guard known else { return }
        flow.closeSocket()
        flow.channel.close()
        Self.log.debug("sshnet flow \(flow.target, privacy: .public) ended: \(reason, privacy: .public)")
    }

    private func sendKeepaliveIfDue(_ s: SSHSession) {
        lock.lock()
        let interval = start?.keepaliveSeconds ?? 0
        let due = interval > 0 && Date().timeIntervalSince(lastKeepalive) >= Double(interval)
        if due { lastKeepalive = Date() }
        lock.unlock()
        guard due else { return }
        if !s.sendKeepalive() {
            handleSessionLoss(reason: "the SSH server stopped answering keepalives")
        }
    }

    // MARK: - Reconnect

    /// The session dropped. Reset every flow, keep the tunnel's routes, and
    /// reconnect with backoff — indefinitely.
    private func handleSessionLoss(reason: String) {
        lock.lock()
        if stopping || !sessionUp { lock.unlock(); return }
        reconnectCount += 1
        let attempt = reconnectCount
        lastSessionError = reason
        lock.unlock()

        Self.log.error("sshnet session lost: \(reason, privacy: .public) (reconnect #\(attempt))")
        // NOT setTunnelNetworkSettings(nil): the utun keeps its routes so traffic
        // is refused rather than escaping to the physical path while we reconnect.
        // See the kill-switch note in the file header — this is deliberate.
        teardownSession(reason: reason)
        scheduleReconnect(attempt: attempt)
    }

    private func scheduleReconnect(attempt: Int) {
        let base = Self.backoffSeconds[min(attempt - 1, Self.backoffSeconds.count - 1)]
        // ±20% jitter so a fleet of Macs coming back from sleep does not arrive at
        // one server in lockstep.
        let delay = base * Double.random(in: 0.8...1.2)
        Self.log.log("sshnet reconnecting in \(String(format: "%.1f", delay), privacy: .public)s")
        sshQueue.asyncAfter(deadline: .now() + delay) { [weak self] in
            guard let self else { return }
            self.lock.lock()
            let stop = self.stopping
            let config = self.start
            self.lock.unlock()
            guard !stop, let config else { return }

            if let error = self.openSession(config) {
                // A refused sign-in or a mismatched host key will not fix itself,
                // and retrying it forever would hammer the server with a
                // credential it has already rejected. Everything else is transport.
                if let e = error as? SSHNetworkTunnelEngineError, e.isPermanent {
                    Self.log.error("sshnet giving up: \(error.localizedDescription, privacy: .public)")
                    self.lock.lock(); self.lastSessionError = error.localizedDescription; self.lock.unlock()
                    self.delegate?.sshNetworkTunnelEngine(self, didFailWithError: error)
                    return
                }
                self.lock.lock(); self.reconnectCount += 1; let next = self.reconnectCount
                self.lastSessionError = error.localizedDescription; self.lock.unlock()
                self.scheduleReconnect(attempt: next)
                return
            }
            self.lock.lock(); self.sessionUp = true; self.lastSessionError = ""; self.lock.unlock()
            Self.log.log("sshnet session restored")
            self.startReaderLoopAfterReconnect()
        }
    }

    private func startReaderLoopAfterReconnect() {
        lock.lock(); pumpRunning = false; lock.unlock()
        startReaderLoop()
    }

    // MARK: - Flow dialling (called from Go goroutines)

    /// Open one flow. Returns our socketpair peer's fd for Go to adopt, or a
    /// NEGATIVE `FlowRefusal`.
    ///
    /// FAIL FAST, NEVER QUEUE: while the session is down this answers -3
    /// immediately, so the guest's connection is reset and the app can retry or
    /// report. A queue here would turn a 30 s outage into 30 s of apparently-hung
    /// applications, and would then dump a thundering herd at the server.
    fileprivate func dialFlow(host: String, port: Int32) -> Int32 {
        lock.lock()
        let stop = stopping
        let up = sessionUp
        let haveConfig = start != nil
        lock.unlock()
        if stop || !haveConfig { return FlowRefusal.noSession.rawValue }
        if !up {
            lock.lock(); refusedFlows += 1; lock.unlock()
            return FlowRefusal.sessionDown.rawValue
        }

        var pair: [Int32] = [-1, -1]
        guard socketpair(AF_UNIX, SOCK_STREAM, 0, &pair) == 0 else {
            Self.log.error("sshnet socketpair failed: \(String(cString: strerror(errno)), privacy: .public)")
            return FlowRefusal.generic.rawValue
        }
        let ours = pair[0], theirs = pair[1]
        Self.configure(socket: ours)
        Self.configure(socket: theirs)

        let target = "\(host):\(port)"
        let outcome = DialOutcome()
        let ready = DispatchSemaphore(value: 0)

        // Ask for the channel on the session queue. Woken first so the reader
        // loop's poll returns and this work does not wait behind it.
        session?.wakeActivityWait()
        sshQueue.async { [weak self] in
            guard let self, let s = self.session else {
                _ = outcome.finish(channel: nil, refusal: .noSession)
                ready.signal()
                return
            }
            let channel = try? s.openDirectTCPIP(toHost: host, port: port)
            if let channel {
                // LATE COMPLETION: the dial may already have timed out and told Go
                // -5. If so this channel has no owner, and leaving it open would
                // leak a socket AT THE SERVER on every timeout. Close it here.
                if !outcome.finish(channel: channel, refusal: nil) {
                    channel.close()
                    Self.log.log("sshnet late channel to \(target, privacy: .public) closed (dial had timed out)")
                }
            } else {
                self.lock.lock()
                self.lastSessionError = "the SSH server refused a forward to \(target)"
                self.lock.unlock()
                _ = outcome.finish(channel: nil, refusal: .serverRefused)
            }
            ready.signal()
        }

        if ready.wait(timeout: .now() + Self.dialBudget) == .timedOut {
            // Mark it abandoned BEFORE returning, so a channel that arrives later
            // is closed by the block above rather than orphaned.
            outcome.abandon()
            close(ours); close(theirs)
            lock.lock(); refusedFlows += 1; lock.unlock()
            Self.log.error("sshnet dial to \(target, privacy: .public) timed out")
            return FlowRefusal.timedOut.rawValue
        }

        guard let channel = outcome.channel else {
            close(ours); close(theirs)
            lock.lock(); refusedFlows += 1; lock.unlock()
            return (outcome.refusal ?? .generic).rawValue
        }

        let flow = Flow(channel: channel, fd: ours, target: target)
        lock.lock(); flows[flow.id] = flow; openedFlows += 1; lock.unlock()
        startPump(for: flow)
        // Go adopts `theirs` by DUPPING it and closing this number — so we must not
        // touch it again from here (see flowdial.go's adoption note).
        return theirs
    }

    /// The guest→server direction for one flow: a blocking read on our socketpair
    /// end, then a chunked write onto the SSH channel through the session queue.
    /// The `sync` hop IS the backpressure — a guest that outruns the session
    /// simply stops being read.
    private func startPump(for flow: Flow) {
        pumpQueue.async { [weak self] in
            guard let self else { return }
            var buf = [UInt8](repeating: 0, count: Self.chunkSize)
            while true {
                let n = buf.withUnsafeMutableBytes { raw -> Int in
                    guard let base = raw.baseAddress else { return -1 }
                    return recv(flow.fd, base, raw.count, 0)
                }
                if n == 0 { break }                       // Go closed its end
                if n < 0 {
                    if errno == EINTR { continue }
                    break
                }
                if !self.writeAll(flow: flow, bytes: buf, count: n) { break }
            }
            // HALF-CLOSE, NOT CLOSE. `sendEOF` says "this direction is done" and
            // leaves the other one readable, so the reader loop can still deliver a
            // response — including one the server only STARTS writing once it sees
            // the request end (every request/response protocol that ends its request
            // with a FIN). Retiring the flow here, which is what this code used to
            // do, truncated exactly those flows: the comment said half-close and the
            // call said close. The flow is retired by the reader sweep when the
            // SERVER's EOF arrives, or immediately if Go has closed its end (the
            // socketpair write then fails and `flush` finishes the flow).
            self.session?.wakeActivityWait()
            self.sshQueue.async { [weak self] in
                guard let self else { return }
                self.lock.lock(); let stillLive = self.flows[flow.id] != nil; self.lock.unlock()
                guard stillLive else { return }
                if !flow.channel.sendEOF() { flow.needsEOF = true }
            }
        }
    }

    /// Write one buffer to the channel, a chunk per queue hop. Returns false when
    /// the flow is dead.
    private func writeAll(flow: Flow, bytes: [UInt8], count: Int) -> Bool {
        var offset = 0
        while offset < count {
            let chunk = min(Self.chunkSize, count - offset)
            session?.wakeActivityWait()
            let written = sshQueue.sync { () -> Int in
                self.lock.lock(); let live = self.flows[flow.id] != nil && self.sessionUp; self.lock.unlock()
                guard live, !flow.channel.isClosed() else { return -1 }
                return bytes.withUnsafeBytes { raw -> Int in
                    guard let base = raw.baseAddress else { return -1 }
                    return flow.channel.write(base + offset, length: chunk)
                }
            }
            if written < 0 { return false }
            if written == 0 {
                // The session's outgoing buffer is full. Wait for WRITABILITY on
                // the real socket — event driven, not a sleep — and retry.
                let rc = sshQueue.sync { () -> Int32 in
                    guard let s = self.session else { return -1 }
                    return s.waitForActivity(withTimeoutMs: Self.pollCeilingMs)
                }
                if rc < 0 { return false }
                continue
            }
            offset += written
        }
        return true
    }

    /// Socket options for both ends of a flow's socketpair.
    private static func configure(socket fd: Int32) {
        var size = Self.socketBufferBytes
        setsockopt(fd, SOL_SOCKET, SO_SNDBUF, &size, socklen_t(MemoryLayout<Int32>.size))
        setsockopt(fd, SOL_SOCKET, SO_RCVBUF, &size, socklen_t(MemoryLayout<Int32>.size))
        // SO_NOSIGPIPE: a write to a peer that has gone away must return EPIPE, not
        // raise SIGPIPE and kill the whole extension.
        var on: Int32 = 1
        setsockopt(fd, SOL_SOCKET, SO_NOSIGPIPE, &on, socklen_t(MemoryLayout<Int32>.size))
    }

    /// The result of one dial attempt, with the abandonment flag that makes the
    /// late-completion rule enforceable rather than aspirational.
    private final class DialOutcome: @unchecked Sendable {
        private let lock = NSLock()
        private var _channel: SSHChannel?
        private var _refusal: FlowRefusal?
        private var abandoned = false

        var channel: SSHChannel? { lock.lock(); defer { lock.unlock() }; return _channel }
        var refusal: FlowRefusal? { lock.lock(); defer { lock.unlock() }; return _refusal }

        /// Record the outcome. Returns FALSE when the dial was already abandoned,
        /// which is the caller's instruction to close what it just opened.
        func finish(channel: SSHChannel?, refusal: FlowRefusal?) -> Bool {
            lock.lock(); defer { lock.unlock() }
            if abandoned { return false }
            _channel = channel
            _refusal = refusal
            return true
        }

        func abandon() {
            lock.lock(); defer { lock.unlock() }
            abandoned = true
        }
    }

    // MARK: - Status

    /// The netstack's own counters, plus this file's session facts.
    func status() -> SSHNetworkTunnelStatus {
        var s = SSHNetworkTunnelStatus()
        if let json = Self.takeString(PXStatus()),
           let px = ProxyTunnelStatus.decode(json: json) {
            s.netstack = px
        }
        lock.lock()
        s.sessionUp = sessionUp
        s.reconnects = reconnectCount
        s.activeChannels = flows.count
        s.openedFlows = openedFlows
        s.refusedFlows = refusedFlows
        s.lastSessionError = lastSessionError
        lock.unlock()
        return s
    }

    /// Telemetry sample for the app's 1 Hz poll. `serverEndpoint` is the SSH
    /// server — which for this kind is literally where the traffic goes.
    func stats(profile: String, connectedSince: Double, reconnects: Int,
               config: SSHNetworkTunnelConfig) -> TunnelStats {
        let s = status()
        var out = TunnelStats(
            profile: profile,
            timestamp: Date().timeIntervalSince1970,
            connectedSince: connectedSince,
            reconnects: max(reconnects, s.reconnects),
            bytesIn: s.netstack.bytesDown,
            bytesOut: s.netstack.bytesUp,
            serverEndpoint: config.server,
            tunnelIPv4: SSHNetworkTunnelNetworkSettings.tunnelIPv4,
            dnsServers: SSHNetworkTunnelNetworkSettings.resolvers(for: config),
            proxies: [])
        out.serverProto = "ssh"
        out.serverPort = String(config.effectivePort)
        out.mtu = config.mtu
        return out
    }

    // MARK: - Packet pump (flow ↔ netstack)

    /// flow → engine. One outstanding read at a time; the handler re-arms itself.
    /// Started by the provider once the tunnel network settings are applied.
    func startPacketPump() {
        readMore()
    }

    private func readMore() {
        guard let flow = provider?.packetFlow else { return }
        flow.readPackets { [weak self] packets, _ in
            guard let self else { return }
            for packet in packets {
                // Raw IP packet straight in — no PF header on this boundary. A full
                // queue drops (PXPacketIn returns 0), which is correct: a VPN must
                // shed load, never stall the flow reader.
                packet.withUnsafeBytes { raw in
                    guard let base = raw.baseAddress, !raw.isEmpty else { return }
                    _ = PXPacketIn(base, Int32(raw.count))
                }
            }
            self.lock.lock(); let running = !self.stopping; self.lock.unlock()
            if running { self.readMore() }
        }
    }

    /// engine → flow. Called from a Go goroutine; NEPacketTunnelFlow's write is
    /// thread-safe, so no hop is needed (and a hop would add latency per packet).
    fileprivate func deliver(_ packet: Data) {
        guard let flow = provider?.packetFlow, let first = packet.first else { return }
        let proto: Int32 = (first >> 4) == 6 ? AF_INET6 : AF_INET
        flow.writePackets([packet], withProtocols: [NSNumber(value: proto)])
    }

    fileprivate func handleLog(_ line: String) {
        delegate?.sshNetworkTunnelEngine(self, didLog: line)
    }

    // MARK: - C boundary helpers

    /// Split "ssh://user@host:port" into host and port. The engine's Go parser
    /// accepts the same shape; this is the Swift half of that one format.
    static func hostAndPort(from upstream: String) -> (String, Int32)? {
        guard let comps = URLComponents(string: upstream), let host = comps.host, !host.isEmpty else {
            return nil
        }
        return (host, Int32(comps.port ?? 22))
    }

    private static func takeString(_ p: UnsafeMutablePointer<CChar>?) -> String? {
        guard let p else { return nil }
        defer { PXFree(p) }
        return String(cString: p)
    }

    private static func engineError(from json: String?, fallback: String) -> Error? {
        guard let json, let data = json.data(using: .utf8),
              let obj = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else {
            return SSHNetworkTunnelEngineError.engine(kind: "other", message: fallback)
        }
        if let e = obj["error"] as? [String: Any] {
            return SSHNetworkTunnelEngineError.engine(kind: (e["kind"] as? String) ?? "other",
                                                     message: (e["message"] as? String) ?? fallback)
        }
        if obj["ok"] as? Bool == true { return nil }
        return SSHNetworkTunnelEngineError.engine(kind: "other", message: fallback)
    }

    // MARK: - C callbacks
    //
    // `@convention(c)` by inference: none captures anything, which is what lets
    // them be handed to the Go side as function pointers.

    private static let flowDial: PXFlowDialCallback = { host, port in
        guard let host, let engine = active() else { return FlowRefusal.noSession.rawValue }
        return engine.dialFlow(host: String(cString: host), port: port)
    }

    private static let packetOut: PXPacketCallback = { bytes, length in
        guard let bytes, length > 0 else { return }
        let data = Data(bytes: bytes, count: Int(length))
        active()?.deliver(data)
    }

    private static let stateChanged: PXStringCallback = { text in
        guard let text else { return }
        log.log("sshnet netstack state: \(String(cString: text), privacy: .public)")
    }

    private static let logLine: PXStringCallback = { text in
        guard let text else { return }
        active()?.handleLog(String(cString: text))
    }
}

// MARK: - Errors

/// Failures the SSH network tunnel can produce. Messages are plain prose so
/// UserFacingError's generic classifier makes a usable sheet without a bespoke
/// branch.
enum SSHNetworkTunnelEngineError: LocalizedError {
    case engine(kind: String, message: String)

    var errorDescription: String? {
        switch self {
        case .engine(let kind, let message):
            switch kind {
            case "badRequest":
                return "This SSH tunnel's settings are not usable. \(message)"
            case "alreadyRunning":
                return "This SSH tunnel is already connected."
            default:
                return message.isEmpty ? "The SSH tunnel reported a problem." : message
            }
        }
    }

    /// Whether retrying could ever help. A refused sign-in or a host key that
    /// doesn't match will not fix itself, and retrying forever would hammer the
    /// server with a credential it has already rejected — or keep offering trust
    /// to something that may be an interception.
    var isPermanent: Bool {
        switch self {
        case .engine(let kind, _): kind == "auth" || kind == "hostKey" || kind == "badRequest"
        }
    }

    /// How this failure is filed for the incident card.
    var incidentEvent: String {
        switch self {
        case .engine(let kind, _): "SSHNET_\(kind.uppercased())"
        }
    }

    var incidentCategory: IncidentCategory {
        switch self {
        case .engine(let kind, _):
            switch kind {
            case "badRequest": .tunSetup
            case "auth": .auth
            // A host key IS this protocol's server identity, so it files the same
            // way a bad TLS certificate does — the app's failure diagnostics
            // already treat that category as "verify the server, not the network".
            case "hostKey": .tlsIdentity
            default: .network
            }
        }
    }
}
