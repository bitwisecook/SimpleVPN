// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
//  SSHAgent.swift
//  Everything SimpleVPN knows about SSH agents — WHERE one is listening, WHAT it
//  is holding, and WHICH of the three agent sign-in failures actually happened.
//
//  WHY THIS FILE EXISTS AT ALL. Agent sign-in is the one SSH credential path
//  where the private key never leaves its vault: 1Password, Secretive (keys in
//  the Secure Enclave), KeePassXC and hardware tokens all present themselves as
//  an agent, and the agent signs. libssh does the signing conversation
//  (`ssh_userauth_agent`), but it answers only "yes" or "no" — and its "no"
//  (SSH_AUTH_DENIED) is returned for THREE completely different situations:
//
//    • no agent answered at all,
//    • an agent answered but holds no keys,
//    • the server refused every key the agent offered.
//
//  Those need three different pieces of advice, and the user hits all three. So
//  we ask the agent directly, over its own protocol, and let the answer decide
//  what the failure means. Asking is also what lets the editor say "your SSH
//  agent has 3 keys" instead of leaving the user to find out at connect time.
//
//  WHERE THIS CAN RUN: the APP process only. The packet-tunnel extension runs as
//  root in the system context, has no `SSH_AUTH_SOCK` and no business reaching
//  into a login session's container — which is why this lives in the app target
//  and not in Shared/. The SSH kinds that authenticate in the app (SOCKS proxy /
//  port forwards, and the staged SSH probe) can use an agent; the SSH Network
//  Tunnel kind, whose session lives in the extension, cannot — see
//  Docs/AuthSecSSHAgent.md.
//
//  THE AGENT PROTOCOL, in the two messages we need (draft-miller-ssh-agent):
//    request:  uint32 length | byte 11 (REQUEST_IDENTITIES)
//    answer:   uint32 length | byte 12 (IDENTITIES_ANSWER) | uint32 nkeys
//                            | nkeys × ( string blob | string comment )
//  We READ ONLY. Nothing here adds, removes, locks or signs with a key: this is
//  a question, not a mutation of somebody's vault.
//
//  Injectable on purpose: `SSHAgentEnvironment` is the seam, so the state machine
//  (no socket / stale socket / dead socket / socket with no keys / socket with
//  keys / malformed answer) is unit-tested without an agent — see
//  SimpleVPNTests/ControlPlane/SSHAgentTests.swift, and the live proof in
//  SSHAgentLiveTests.swift which drives a real ssh-agent.
//

import Foundation

// MARK: - What an agent is holding

/// One key an SSH agent offers. The blob itself is a PUBLIC key — safe to name,
/// safe to log — and the comment is whatever the agent chose to call it
/// ("alex@mac", a 1Password item title, a Secretive secret's name).
nonisolated struct SSHAgentIdentity: Equatable, Sendable {
    /// The key's algorithm as the agent named it: "ssh-ed25519",
    /// "sk-ecdsa-sha2-nistp256@openssh.com", "ssh-rsa-cert-v01@openssh.com"…
    let keyType: String
    let comment: String

    /// A hardware token (`ssh-keygen -t ed25519-sk`): signing needs a touch, so
    /// a connect can appear to hang while the device waits.
    var isSecurityKey: Bool { keyType.hasPrefix("sk-") }
    /// An OpenSSH certificate rather than a bare key.
    var isCertificate: Bool { keyType.contains("-cert-v01@openssh.com") }

    /// What the UI shows for this key: its comment if it has one, else its type.
    var label: String { comment.isEmpty ? keyType : comment }
}

// MARK: - The state machine

/// Where an SSH agent is, and what it said. The four cases are the four things
/// that actually happen on a Mac, and each maps to different advice.
nonisolated enum SSHAgentState: Equatable, Sendable {
    /// Nothing told us where an agent is: no `SSH_AUTH_SOCK`, no configured path.
    case noAgent
    /// A path is configured or inherited, but there is nothing at it — the classic
    /// stale `SSH_AUTH_SOCK` left behind by an agent that has quit.
    case socketMissing(path: String)
    /// Something IS at the path but it didn't answer as an agent: a dead socket, a
    /// wedged agent, a permission refusal, or a truncated/garbled reply.
    case unreachable(path: String, reason: String)
    /// An agent answered. `identities` may be EMPTY — a running agent holding
    /// nothing is a distinct, common state (a locked vault, or a fresh login).
    case running(path: String, identities: [SSHAgentIdentity])

    /// The socket this state is about, when there is one.
    var socketPath: String? {
        switch self {
        case .noAgent: nil
        case .socketMissing(let p), .unreachable(let p, _): p
        case .running(let p, _): p
        }
    }

    var identities: [SSHAgentIdentity] {
        if case .running(_, let ids) = self { return ids }
        return []
    }

    /// True only when signing in through the agent could possibly work.
    var canSignIn: Bool { !identities.isEmpty }

    /// One plain sentence for the editor — what a user needs to know before they
    /// pick "SSH agent" as their sign-in method. Also the row's accessibility
    /// value, so VoiceOver hears exactly what the screen says.
    var summary: String {
        switch self {
        case .noAgent:
            return "No SSH agent is running."
        case .socketMissing:
            return "No SSH agent is running — the socket it used to listen on is gone."
        case .unreachable(_, let reason):
            return "An SSH agent socket is there, but it didn't answer (\(reason))."
        case .running(_, let ids) where ids.isEmpty:
            return "Your SSH agent is running but holds no keys."
        case .running(_, let ids):
            let keys = ids.count == 1 ? "1 key" : "\(ids.count) keys"
            return "Your SSH agent has \(keys): \(ids.map(\.label).joined(separator: ", "))."
        }
    }
}

// MARK: - The injectable boundary

/// One request/response exchange with an agent. Closed by the caller.
nonisolated protocol SSHAgentTransport: Sendable {
    /// Write `request` whole and read one whole reply. Throws on any short write,
    /// short read, timeout or closed peer.
    func roundTrip(_ request: Data) throws -> Data
    func close()
}

/// Everything about the machine the probe needs — the seam the tests replace.
nonisolated protocol SSHAgentEnvironment: Sendable {
    /// `SSH_AUTH_SOCK` as this process inherited it. nil/empty when absent.
    var inheritedSocketPath: String? { get }
    /// Whether a socket (or anything at all) exists at `path`.
    func socketExists(atPath path: String) -> Bool
    /// Connect, or throw with a reason fit to show a user.
    func connect(toSocketAt path: String) throws -> any SSHAgentTransport
}

/// A reason a socket couldn't be spoken to, carrying user-facing wording.
nonisolated struct SSHAgentTransportError: LocalizedError, Equatable {
    let reason: String
    init(_ reason: String) { self.reason = reason }
    var errorDescription: String? { reason }
}

// MARK: - Wire format

/// The two agent messages we speak, parsed defensively: everything here comes
/// from another process, so a length that overruns the buffer must be an error
/// and never an out-of-bounds read.
nonisolated enum SSHAgentWire {
    static let requestIdentitiesType: UInt8 = 11
    static let identitiesAnswerType: UInt8 = 12
    static let failureType: UInt8 = 5

    /// Whole framed "list your identities" request.
    static func requestIdentities() -> Data {
        var out = Data()
        out.append(contentsOf: [0, 0, 0, 1])   // length: one byte of payload
        out.append(requestIdentitiesType)
        return out
    }

    /// Parse a framed IDENTITIES_ANSWER. Returns the identities (possibly none);
    /// throws `SSHAgentTransportError` with a user-facing reason otherwise.
    static func parseIdentitiesAnswer(_ data: Data) throws -> [SSHAgentIdentity] {
        var cursor = Cursor(Data(data))
        let framed = try cursor.uint32("truncated reply")
        guard framed >= 1 else { throw SSHAgentTransportError("the agent sent an empty reply") }
        let type = try cursor.byte("truncated reply")
        if type == failureType {
            throw SSHAgentTransportError("the agent refused to list its keys")
        }
        guard type == identitiesAnswerType else {
            throw SSHAgentTransportError("the agent sent an unexpected reply (type \(type))")
        }
        let count = try cursor.uint32("truncated key list")
        // A hostile or broken peer must not make us allocate on its word alone.
        guard count <= 1024 else {
            throw SSHAgentTransportError("the agent claimed an implausible number of keys (\(count))")
        }
        var out: [SSHAgentIdentity] = []
        for _ in 0..<count {
            let blob = try cursor.string("truncated key")
            let comment = try cursor.string("truncated key comment")
            var blobCursor = Cursor(blob)
            let keyType = (try? blobCursor.string("unnamed key")).flatMap {
                String(data: $0, encoding: .utf8)
            } ?? ""
            out.append(SSHAgentIdentity(
                keyType: keyType,
                comment: String(data: comment, encoding: .utf8) ?? ""))
        }
        return out
    }

    /// The framed length prefix of a reply, or nil when fewer than 4 bytes are in
    /// yet — how the reader knows how much more to wait for.
    static func framedLength(_ data: Data) -> Int? {
        guard data.count >= 4 else { return nil }
        let b = [UInt8](data.prefix(4))
        return Int(UInt32(b[0]) << 24 | UInt32(b[1]) << 16 | UInt32(b[2]) << 8 | UInt32(b[3]))
    }

    /// Big-endian reader that refuses to read past its buffer.
    private struct Cursor {
        private let bytes: [UInt8]
        private var index = 0
        init(_ data: Data) { bytes = [UInt8](data) }

        mutating func byte(_ what: String) throws -> UInt8 {
            guard index < bytes.count else { throw SSHAgentTransportError(what) }
            defer { index += 1 }
            return bytes[index]
        }

        mutating func uint32(_ what: String) throws -> UInt32 {
            guard index + 4 <= bytes.count else { throw SSHAgentTransportError(what) }
            defer { index += 4 }
            return UInt32(bytes[index]) << 24 | UInt32(bytes[index + 1]) << 16
                 | UInt32(bytes[index + 2]) << 8 | UInt32(bytes[index + 3])
        }

        mutating func string(_ what: String) throws -> Data {
            let length = Int(try uint32(what))
            guard index + length <= bytes.count else {
                throw SSHAgentTransportError(what)
            }
            defer { index += length }
            return Data(bytes[index..<(index + length)])
        }
    }
}

// MARK: - The probe

/// Asks an agent where it is and what it holds. Pure decision logic over
/// `SSHAgentEnvironment`, so every branch is testable with a fake.
nonisolated struct SSHAgentProbe: Sendable {
    let environment: any SSHAgentEnvironment

    init(environment: any SSHAgentEnvironment = SSHAgentSystemEnvironment()) {
        self.environment = environment
    }

    /// The socket libssh (and `/usr/bin/ssh`) should be pointed at: the user's
    /// explicit choice if they made one, otherwise whatever this process
    /// inherited. nil when there is nothing to point at.
    ///
    /// An explicit path WINS on purpose: a GUI app's inherited `SSH_AUTH_SOCK` is
    /// macOS's own ssh-agent, which is almost never where the interesting keys
    /// are (see Docs/AuthSecSSHAgent.md).
    func resolvedSocketPath(configured: String?) -> String? {
        let explicit = (configured ?? "").trimmingCharacters(in: .whitespacesAndNewlines)
        if !explicit.isEmpty { return (explicit as NSString).expandingTildeInPath }
        let inherited = (environment.inheritedSocketPath ?? "")
            .trimmingCharacters(in: .whitespacesAndNewlines)
        return inherited.isEmpty ? nil : inherited
    }

    /// Resolve, connect, ask. Never throws: every failure IS one of the states.
    func probe(configuredSocketPath: String? = nil) -> SSHAgentState {
        guard let path = resolvedSocketPath(configured: configuredSocketPath) else {
            return .noAgent
        }
        guard environment.socketExists(atPath: path) else { return .socketMissing(path: path) }
        let transport: any SSHAgentTransport
        do {
            transport = try environment.connect(toSocketAt: path)
        } catch {
            return .unreachable(path: path, reason: Self.reason(error))
        }
        defer { transport.close() }
        do {
            let reply = try transport.roundTrip(SSHAgentWire.requestIdentities())
            return .running(path: path,
                            identities: try SSHAgentWire.parseIdentitiesAnswer(reply))
        } catch {
            return .unreachable(path: path, reason: Self.reason(error))
        }
    }

    private static func reason(_ error: any Error) -> String {
        (error as? SSHAgentTransportError)?.reason ?? error.localizedDescription
    }

    // MARK: Vendor agents users actually run

    /// One vendor agent and where its current version listens. ONE TABLE, so the
    /// paths are auditable in a single place rather than scattered through views
    /// and docs — and so a vendor moving its socket is a one-line change.
    ///
    /// These are SUGGESTIONS ONLY. Nothing here is used automatically: SimpleVPN
    /// talks to the socket the user configured or the one it inherited, never to
    /// a vendor socket it went looking for. Offering to fill the field in is a
    /// convenience; deciding which agent gets asked about your keys is the user's.
    nonisolated struct VendorAgent: Equatable, Sendable {
        let name: String
        /// Tilde path exactly as the vendor documents it.
        let socketPath: String
        /// The vendor's own documentation — the authority on setup.
        let documentation: String

        var expandedPath: String { (socketPath as NSString).expandingTildeInPath }
    }

    static let vendorAgents: [VendorAgent] = [
        .init(name: "1Password",
              socketPath: "~/Library/Group Containers/2BUA8C4S2C.com.1password/t/agent.sock",
              documentation: "https://www.1password.dev/ssh/get-started/"),
        .init(name: "Secretive",
              socketPath: "~/Library/Containers/com.maxgoedjen.Secretive.SecretAgent/Data/socket.ssh",
              documentation: "https://github.com/maxgoedjen/secretive"),
    ]

    /// The vendor agents whose socket is present right now, so the editor can
    /// offer "use this one" instead of asking a user to type a container path.
    func vendorAgentsPresent() -> [VendorAgent] {
        Self.vendorAgents.filter { environment.socketExists(atPath: $0.expandedPath) }
    }
}

// MARK: - Why agent sign-in failed

/// Turns libssh's one-size-fits-all refusal into the sentence that names what to
/// DO about it. Pure: the state comes from the probe, the kind from the bridge's
/// error code, and the wording is asserted in tests.
nonisolated enum SSHAgentDiagnosis {

    /// What the bridge reported, independent of Objective-C error plumbing.
    nonisolated enum Failure: Equatable, Sendable {
        /// SSH_AUTH_DENIED — ambiguous; the agent state decides what it means.
        case denied
        /// A key was accepted and the server wants a further step too.
        case partial
        /// The exchange broke; `detail` is libssh's own account.
        case transport(String)
    }

    /// Classify an NSError from `SSHSession.authAgent(forUser:)`.
    static func classify(_ error: any Error) -> Failure {
        let ns = error as NSError
        guard ns.domain == "SSHBridge" else { return .transport(ns.localizedDescription) }
        switch ns.code {
        case SSHBridgeErrorCode.agentPartial.rawValue: return .partial
        case SSHBridgeErrorCode.agentTransport.rawValue: return .transport(ns.localizedDescription)
        default: return .denied
        }
    }

    /// THE THREE FAILURE MODES, plus the two honest extras. `username` is named
    /// where it is part of the fix, because "the server said no" with the wrong
    /// account name is the failure users misdiagnose most.
    static func message(for failure: Failure, state: SSHAgentState, username: String) -> String {
        switch failure {
        case .partial:
            return "Your SSH agent's key was accepted, but the server wants another sign-in step as "
                + "well (a verification code, for example). This tunnel can't answer that yet — "
                + "sign in with a password, or ask whoever runs the server for a key-only account."
        case .transport(let detail):
            return "The conversation with your SSH agent broke off. Restart the agent and try again. "
                + "(\(detail))"
        case .denied:
            break
        }
        switch state {
        case .noAgent:
            return "No SSH agent is running, so there were no keys to offer. Start your agent — "
                + "1Password, Secretive, KeePassXC or the built-in ssh-agent — then set “SSH Agent "
                + "Socket” under Sign-In if it doesn't listen where macOS expects."
        case .socketMissing(let path):
            return "The SSH agent SimpleVPN was pointed at is gone: nothing is listening at "
                + "\(path) any more. Start the agent again, or update “SSH Agent Socket” under "
                + "Sign-In."
        case .unreachable(let path, let reason):
            return "The SSH agent at \(path) didn't answer (\(reason)), so no key could be offered. "
                + "Restart the agent, or point “SSH Agent Socket” under Sign-In at the right socket."
        case .running(_, let identities) where identities.isEmpty:
            return "Your SSH agent is running but holds no keys, so there was nothing to sign in "
                + "with. Unlock your vault, turn the SSH agent on for the key you want to use, or "
                + "add one with ssh-add for the built-in agent."
        case .running(_, let identities):
            let keys = identities.count == 1 ? "the 1 key" : "all \(identities.count) keys"
            let names = identities.map(\.label).joined(separator: ", ")
            let touch = identities.contains(where: \.isSecurityKey)
                ? " If one of them is a hardware key, it also has to be plugged in and touched."
                : ""
            return "The server refused \(keys) your SSH agent offered (\(names)). Add the matching "
                + "public key to \(username.isEmpty ? "your account" : "\(username)'s account") on "
                + "the server, or check you're signing in as the right username.\(touch)"
        }
    }
}

// MARK: - The real machine

/// `SSH_AUTH_SOCK`, the filesystem, and a AF_UNIX socket. Everything platform
/// about the probe is here and nowhere else.
nonisolated struct SSHAgentSystemEnvironment: SSHAgentEnvironment {
    /// How long to wait for an agent to answer. Generous enough for a vault that
    /// has to wake up, short enough that a wedged agent can't stall a connect.
    let timeout: TimeInterval

    init(timeout: TimeInterval = 3) { self.timeout = timeout }

    var inheritedSocketPath: String? { ProcessInfo.processInfo.environment["SSH_AUTH_SOCK"] }

    func socketExists(atPath path: String) -> Bool {
        var st = stat()
        return stat(path, &st) == 0
    }

    func connect(toSocketAt path: String) throws -> any SSHAgentTransport {
        try UnixSocketAgentTransport(path: path, timeout: timeout)
    }
}

/// A blocking AF_UNIX client with read/write timeouts, used for exactly one
/// question-and-answer and then closed.
nonisolated final class UnixSocketAgentTransport: SSHAgentTransport, @unchecked Sendable {
    private let fd: Int32
    private let lock = NSLock()
    private var closed = false

    init(path: String, timeout: TimeInterval) throws {
        var addr = sockaddr_un()
        addr.sun_family = sa_family_t(AF_UNIX)
        let bytes = Array(path.utf8)
        // sockaddr_un's path is 104 bytes on Darwin, and a container path can be
        // long — say so plainly rather than connecting to a truncated path.
        let capacity = MemoryLayout.size(ofValue: addr.sun_path)
        guard bytes.count < capacity else {
            throw SSHAgentTransportError("that socket path is too long for macOS "
                                         + "(\(bytes.count) characters; the limit is \(capacity - 1))")
        }
        withUnsafeMutableBytes(of: &addr.sun_path) { raw in
            raw.copyBytes(from: bytes)
        }
        addr.sun_len = UInt8(MemoryLayout<sockaddr_un>.size)

        let sock = socket(AF_UNIX, SOCK_STREAM, 0)
        guard sock >= 0 else {
            throw SSHAgentTransportError("this Mac wouldn't open a socket (\(Self.errnoText()))")
        }
        // A write to a socket whose peer has gone would otherwise raise SIGPIPE
        // and take the whole app down with it.
        var on: Int32 = 1
        setsockopt(sock, SOL_SOCKET, SO_NOSIGPIPE, &on, socklen_t(MemoryLayout<Int32>.size))
        var tv = timeval(tv_sec: Int(timeout), tv_usec: 0)
        setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, socklen_t(MemoryLayout<timeval>.size))
        setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, &tv, socklen_t(MemoryLayout<timeval>.size))

        let size = socklen_t(MemoryLayout<sockaddr_un>.size)
        let connected = withUnsafePointer(to: &addr) { raw in
            raw.withMemoryRebound(to: sockaddr.self, capacity: 1) { connect(sock, $0, size) }
        }
        guard connected == 0 else {
            let text = Self.errnoText()
            _ = Darwin.close(sock)
            throw SSHAgentTransportError(text)
        }
        fd = sock
    }

    deinit { close() }

    func close() {
        lock.lock(); defer { lock.unlock() }
        guard !closed else { return }
        closed = true
        _ = Darwin.close(fd)
    }

    func roundTrip(_ request: Data) throws -> Data {
        try writeAll(request)
        // Read the 4-byte frame, then exactly that many bytes: an agent may
        // answer in several TCP-style chunks even over a unix socket.
        var header = Data()
        while header.count < 4 { header.append(try readSome(4 - header.count)) }
        guard let length = SSHAgentWire.framedLength(header), length > 0, length <= 1 << 20 else {
            throw SSHAgentTransportError("the agent's reply had an implausible length")
        }
        var body = Data()
        while body.count < length { body.append(try readSome(length - body.count)) }
        return header + body
    }

    private func writeAll(_ data: Data) throws {
        var sent = 0
        let bytes = [UInt8](data)
        while sent < bytes.count {
            let n = bytes.withUnsafeBytes { raw -> Int in
                write(fd, raw.baseAddress!.advanced(by: sent), bytes.count - sent)
            }
            if n > 0 { sent += n; continue }
            if n < 0 && errno == EINTR { continue }
            throw SSHAgentTransportError(n == 0 ? "the agent closed the connection"
                                                : Self.errnoText())
        }
    }

    private func readSome(_ want: Int) throws -> Data {
        var buffer = [UInt8](repeating: 0, count: want)
        while true {
            let n = buffer.withUnsafeMutableBytes { raw in read(fd, raw.baseAddress!, want) }
            if n > 0 { return Data(buffer.prefix(n)) }
            if n == 0 { throw SSHAgentTransportError("the agent closed the connection") }
            if errno == EINTR { continue }
            if errno == EAGAIN || errno == EWOULDBLOCK {
                throw SSHAgentTransportError("the agent didn't answer in time")
            }
            throw SSHAgentTransportError(Self.errnoText())
        }
    }

    /// errno in words, lowercased so it reads inside a sentence.
    private static func errnoText() -> String {
        let text = String(cString: strerror(errno))
        return text.prefix(1).lowercased() + text.dropFirst()
    }
}
