// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
//  KeePassXCProvider.swift
//  Fetch credentials from KeePassXC over its browser-integration unix socket
//  (the keepassxc-browser protocol — KeePassXCProtocol.swift has the wire
//  story). Fully local, consent-based: the first use raises KeePassXC's own
//  pairing dialog (the user names the connection), a locked database raises
//  KeePassXC's unlock — its Touch ID quick-unlock included — and entry access
//  can prompt per KeePassXC's settings. SimpleVPN never sees the master
//  password.
//
//  The association (the id + identification key KeePassXC will answer to) is
//  per-DATABASE, keyed by the database hash, and is a bearer credential — so
//  it lives in the keychain (KeePassXCAssociationStore), same invariant as
//  every other secret.
//
//  Blocking socket I/O runs on a dedicated serial queue, never the Swift
//  cooperative pool — an unlock or pairing dialog can sit unanswered for
//  minutes (the OnePasswordNative rule, same reasoning).
//

import Foundation
import os

// MARK: - Socket

/// A blocking unix-domain stream socket with per-call receive deadlines.
/// Confined to KeePassXCProvider's serial queue; only `shutdown()` may be
/// called from elsewhere (cancellation), which is why the fd sits in a lock.
nonisolated final class KeePassXCSocket: @unchecked Sendable {
    private let fd = OSAllocatedUnfairLock<Int32>(initialState: -1)

    /// Connect or throw .notRunning — a missing/refusing socket means
    /// KeePassXC isn't there to ask, whatever the errno flavor.
    func connect(path: String) throws {
        let sock = socket(AF_UNIX, SOCK_STREAM, 0)
        guard sock >= 0 else { throw KeePassXCError.notRunning }
        var addr = sockaddr_un()
        addr.sun_family = sa_family_t(AF_UNIX)
        let ok = withUnsafeMutableBytes(of: &addr.sun_path) { raw -> Bool in
            let bytes = Array(path.utf8)
            guard bytes.count < raw.count else { return false }
            raw.copyBytes(from: bytes)
            return true
        }
        guard ok else { close(sock); throw KeePassXCError.notRunning }
        let result = withUnsafePointer(to: &addr) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                Darwin.connect(sock, $0, socklen_t(MemoryLayout<sockaddr_un>.size))
            }
        }
        guard result == 0 else { close(sock); throw KeePassXCError.notRunning }
        fd.withLock { $0 = sock }
    }

    func send(_ data: Data) throws {
        let sock = fd.withLock { $0 }
        guard sock >= 0 else { throw KeePassXCError.protocolError("socket closed") }
        var remaining = [UInt8](data)
        while !remaining.isEmpty {
            let n = remaining.withUnsafeBytes { Darwin.send(sock, $0.baseAddress, $0.count, 0) }
            guard n > 0 else { throw KeePassXCError.protocolError("socket write failed") }
            remaining.removeFirst(n)
        }
    }

    /// One read, waiting up to `timeout` for anything to arrive. Empty data =
    /// peer closed; a timeout throws .timedOut.
    func receive(timeout: TimeInterval) throws -> Data {
        let sock = fd.withLock { $0 }
        guard sock >= 0 else { throw KeePassXCError.protocolError("socket closed") }
        var tv = timeval(tv_sec: Int(timeout), tv_usec: Int32((timeout - timeout.rounded(.down)) * 1_000_000))
        setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, &tv, socklen_t(MemoryLayout<timeval>.size))
        var buffer = [UInt8](repeating: 0, count: 64 * 1024)
        let n = recv(sock, &buffer, buffer.count, 0)
        if n > 0 { return Data(buffer[0..<n]) }
        if n == 0 { return Data() }
        if errno == EAGAIN || errno == EWOULDBLOCK { throw KeePassXCError.timedOut }
        throw KeePassXCError.protocolError("socket read failed (errno \(errno))")
    }

    /// Safe from any thread — how task cancellation unsticks a blocked recv.
    func shutdown() {
        fd.withLock { sock in
            if sock >= 0 { close(sock); sock = -1 }
        }
    }

    deinit { shutdown() }
}

// MARK: - Session

/// One protocol conversation: handshake once, then sealed request/reply
/// exchanges. Blocking throughout — construct and use on the provider queue.
nonisolated final class KeePassXCSession {
    let socket = KeePassXCSocket()
    private var keys = KeePassXCProtocol.SessionKeys()
    private var buffer = Data()

    /// Connect and swap public keys. `socketPath` is injectable so tests can
    /// point a session at a mock server.
    func open(socketPath: String? = nil, timeout: TimeInterval = 10) throws {
        guard let path = socketPath ?? KeePassXCProtocol.discoverSocket() else {
            throw KeePassXCError.notRunning
        }
        try socket.connect(path: path)
        let nonce = KeePassXCProtocol.freshNonce()
        let hello = KeePassXCProtocol.changePublicKeysEnvelope(keys: keys, nonce: nonce)
        try socket.send(JSONEncoder().encodeOrEmpty(hello))
        let reply = try nextEnvelope(timeout: timeout, skippingSignals: true)
        guard reply.success == "true", let serverKey = reply.publicKey else {
            throw KeePassXCError.handshakeFailed(reply.error ?? "no public key in reply")
        }
        try keys.acceptPeer(publicKeyBase64: serverKey)
    }

    /// One sealed request/reply exchange. Signals arriving in between are
    /// skipped; the reply is verified against this request's nonce.
    func request(action: String, body: some Encodable, timeout: TimeInterval,
                 triggerUnlock: Bool = false, matchHost: String = "")
        throws -> KeePassXCProtocol.InnerResponse {
        let nonce = KeePassXCProtocol.freshNonce()
        let envelope = try KeePassXCProtocol.sealedEnvelope(
            action: action, body: body, keys: keys, nonce: nonce, triggerUnlock: triggerUnlock)
        try socket.send(JSONEncoder().encodeOrEmpty(envelope))
        let deadline = Date(timeIntervalSinceNow: timeout)
        while true {
            let remaining = deadline.timeIntervalSinceNow
            guard remaining > 0 else { throw KeePassXCError.timedOut }
            let reply = try nextEnvelope(timeout: remaining, skippingSignals: true)
            // A stray reply to some other action would fail the nonce check
            // anyway; matching the action first gives a clearer error.
            guard reply.action == action else { continue }
            return try KeePassXCProtocol.openReply(reply, keys: keys, requestNonce: nonce,
                                                   matchHost: matchHost)
        }
    }

    /// Wait (bounded) for KeePassXC's database-unlocked broadcast — what turns
    /// "database locked" + triggerUnlock into a quiet success once the user
    /// gives KeePassXC the fingerprint.
    func waitForUnlock(timeout: TimeInterval) -> Bool {
        let deadline = Date(timeIntervalSinceNow: timeout)
        while deadline.timeIntervalSinceNow > 0 {
            guard let envelope = try? nextEnvelope(timeout: min(2, deadline.timeIntervalSinceNow),
                                                   skippingSignals: false) else { continue }
            if envelope.action == "database-unlocked" { return true }
        }
        return false
    }

    /// Read whole JSON envelopes off the stream, buffering partials.
    private func nextEnvelope(timeout: TimeInterval, skippingSignals: Bool)
        throws -> KeePassXCProtocol.Envelope {
        let deadline = Date(timeIntervalSinceNow: timeout)
        while true {
            if let (object, rest) = KeePassXCProtocol.extractJSONObject(from: buffer) {
                buffer = rest
                guard let envelope = try? JSONDecoder()
                    .decode(KeePassXCProtocol.Envelope.self, from: object) else {
                    throw KeePassXCError.protocolError("unparseable message")
                }
                if skippingSignals, envelope.isSignal { continue }
                return envelope
            }
            let remaining = deadline.timeIntervalSinceNow
            guard remaining > 0 else { throw KeePassXCError.timedOut }
            let chunk = try socket.receive(timeout: remaining)
            guard !chunk.isEmpty else {
                throw KeePassXCError.protocolError("KeePassXC closed the connection")
            }
            buffer.append(chunk)
        }
    }

    /// The session's public key, base64 — what `associate` presents as `key`.
    var publicKeyBase64: String { keys.publicKey.base64EncodedString() }
}

private nonisolated extension JSONEncoder {
    /// Envelope encoding can't fail (strings only); belt-and-braces empties
    /// rather than crashing the connect flow.
    func encodeOrEmpty(_ value: some Encodable) -> Data {
        (try? encode(value)) ?? Data()
    }
}

// MARK: - Association store

/// The pairing KeePassXC recognises us by: the name the user typed into
/// KeePassXC's dialog (`id`) and the identification public key it stored in
/// the database (`key`). Presenting the pair IS the authentication — a bearer
/// token — so it lives in the data-protection keychain, app-only, one item
/// per database hash (associations are per-database, and a user may keep
/// several databases).
nonisolated enum KeePassXCAssociationStore {
    private static let log = Logger(subsystem: "com.bragi0.SimpleVPN", category: "keepassxc")
    private static let service = "com.bragi0.SimpleVPN.keepassxc"
    private static let accessGroup = "QVUFB5676H.com.bragi0.SimpleVPN.shared"

    struct Association: Codable, Sendable, Equatable {
        var id: String
        /// Base64 identification PUBLIC key (its private half is never used
        /// after the associate, so it isn't kept).
        var key: String
    }

    static func save(databaseHash: String, _ association: Association) {
        delete(databaseHash: databaseHash)
        guard let blob = try? JSONEncoder().encode(association) else { return }
        let add: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: databaseHash,
            kSecAttrAccessGroup as String: accessGroup,
            kSecUseDataProtectionKeychain as String: true,
            kSecAttrAccessible as String: kSecAttrAccessibleWhenUnlockedThisDeviceOnly,
            kSecAttrLabel as String: "SimpleVPN \u{2194} KeePassXC pairing",
            kSecValueData as String: blob,
        ]
        let status = SecItemAdd(add as CFDictionary, nil)
        if status != errSecSuccess {
            log.error("association write failed: OSStatus \(status)")
        }
    }

    static func load(databaseHash: String) -> Association? {
        let q: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: databaseHash,
            kSecAttrAccessGroup as String: accessGroup,
            kSecUseDataProtectionKeychain as String: true,
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne,
        ]
        var out: CFTypeRef?
        guard SecItemCopyMatching(q as CFDictionary, &out) == errSecSuccess,
              let data = out as? Data else { return nil }
        return try? JSONDecoder().decode(Association.self, from: data)
    }

    static func delete(databaseHash: String) {
        SecItemDelete([
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: databaseHash,
            kSecAttrAccessGroup as String: accessGroup,
            kSecUseDataProtectionKeychain as String: true,
        ] as CFDictionary)
    }
}

// MARK: - Provider

/// CredentialProvider face: reference = the address to match (a hostname or
/// full URL — KeePassXCProtocol.matchURL documents the matching), account =
/// optional username filter when one address has several entries.
struct KeePassXCProvider: CredentialProvider {
    let id = "keepassxc"
    let displayName = "KeePassXC"
    let reference: String
    var account: String = ""

    private nonisolated static let log = Logger(subsystem: "com.bragi0.SimpleVPN", category: "keepassxc")

    /// Serialises socket conversations (KeePassXC shows one dialog at a time)
    /// and keeps minute-long dialog waits off the cooperative pool.
    private nonisolated static let queue = DispatchQueue(
        label: "com.bragi0.SimpleVPN.keepassxc", qos: .userInitiated)

    /// Prompt-free: is there a socket to talk to at all? (Doesn't confirm the
    /// database is unlocked — that part is interactive by design.)
    nonisolated static func probe() -> Bool {
        KeePassXCProtocol.discoverSocket() != nil
    }

    func isAvailable(for profile: String) async -> Bool {
        guard !reference.trimmingCharacters(in: .whitespaces).isEmpty else { return false }
        return Self.probe()
    }

    func resolve(profile: String, fields: Set<CredentialField>) async throws -> RawCredentials {
        let ref = reference.trimmingCharacters(in: .whitespaces)
        guard !ref.isEmpty else { throw KeePassXCError.noLogins("") }
        let wantOTP = fields.contains(.otp)
        let accountFilter = account.trimmingCharacters(in: .whitespaces)

        // Blocking conversation on the dedicated queue; cancellation (the user
        // giving up on a dialog) closes the socket, which unblocks the recv.
        // Only the SOCKET crosses into the cancellation handler — the session's
        // other state never leaves the queue.
        let socketBox = OSAllocatedUnfairLock<KeePassXCSocket?>(initialState: nil)
        return try await withTaskCancellationHandler {
            try await withCheckedThrowingContinuation { cont in
                Self.queue.async {
                    let session = KeePassXCSession()
                    // Bound out first: the socket alone is Sendable, and
                    // reaching through `session` inside the lock's closure
                    // would capture the (deliberately non-Sendable) session.
                    let socket = session.socket
                    socketBox.withLock { $0 = socket }
                    defer {
                        socketBox.withLock { $0 = nil }
                        socket.shutdown()
                    }
                    do {
                        cont.resume(returning: try Self.resolveBlocking(
                            session: session, reference: ref,
                            accountFilter: accountFilter, wantOTP: wantOTP))
                    } catch {
                        cont.resume(throwing: error)
                    }
                }
            }
        } onCancel: {
            socketBox.withLock { $0?.shutdown() }
        }
    }

    /// The whole conversation, in protocol order: handshake → database hash
    /// (raising KeePassXC's unlock when locked) → test-associate the stored
    /// pairing (or associate afresh) → get-logins → get-totp if still needed.
    private nonisolated static func resolveBlocking(
        session: KeePassXCSession, reference: String, accountFilter: String, wantOTP: Bool
    ) throws -> RawCredentials {
        let host = KeePassXCProtocol.matchHost(for: reference)
        try session.open()

        // triggerUnlock raises KeePassXC's own unlock (Touch ID quick-unlock
        // included) instead of failing; then wait for the unlocked broadcast
        // and re-ask. 60 s is dialog time, not network time.
        var hash: String
        do {
            hash = try databaseHash(session: session, triggerUnlock: true)
        } catch KeePassXCError.databaseLocked {
            guard session.waitForUnlock(timeout: 60) else { throw KeePassXCError.databaseLocked }
            hash = try databaseHash(session: session, triggerUnlock: false)
        }

        let association = try associationEnsured(session: session, databaseHash: hash)

        let inner = try session.request(
            action: "get-logins",
            body: KeePassXCProtocol.GetLoginsRequest(
                url: KeePassXCProtocol.matchURL(for: reference),
                keys: [.init(id: association.id, key: association.key)]),
            timeout: 180, matchHost: host)
        let entry = try pickEntry(from: inner.entries ?? [],
                                  accountFilter: accountFilter, host: host)

        var raw = RawCredentials()
        raw.username = (entry.login?.isEmpty == false) ? entry.login : nil
        raw.password = (entry.password?.isEmpty == false) ? entry.password : nil
        // The code: inline when KeePassXC's settings include TOTP in
        // get-logins, else one more ask by uuid. An entry with no TOTP at all
        // is fine — the caller falls back to the typed code path.
        if wantOTP {
            if let totp = entry.totp, !totp.isEmpty {
                raw.otp = totp
            } else if let uuid = entry.uuid, !uuid.isEmpty {
                let totpReply = try? session.request(
                    action: "get-totp", body: KeePassXCProtocol.GetTOTPRequest(uuid: uuid),
                    timeout: 30)
                if let totp = totpReply?.totp, !totp.isEmpty { raw.otp = totp }
            }
        }
        return raw
    }

    /// Which matched entry signs in. An account narrows several entries to
    /// one; with no account, one match proceeds and several is a genuine
    /// ambiguity — silently picking one would sign in as somebody unintended.
    /// Static and pure so the decision is pinned by tests.
    nonisolated static func pickEntry(from entries: [KeePassXCProtocol.LoginEntry],
                          accountFilter: String, host: String)
        throws -> KeePassXCProtocol.LoginEntry {
        let matches = accountFilter.isEmpty ? entries : entries.filter {
            ($0.login ?? "").caseInsensitiveCompare(accountFilter) == .orderedSame
        }
        guard let entry = matches.first else { throw KeePassXCError.noLogins(host) }
        if matches.count > 1 {
            let names = matches.prefix(4).map { "\($0.name ?? "?") (\($0.login ?? "?"))" }
            throw KeePassXCError.ambiguous(names.joined(separator: ", "))
        }
        return entry
    }

    private nonisolated static func databaseHash(session: KeePassXCSession, triggerUnlock: Bool) throws -> String {
        let inner = try session.request(action: "get-databasehash",
                                        body: KeePassXCProtocol.GetDatabaseHashRequest(),
                                        timeout: triggerUnlock ? 15 : 30,
                                        triggerUnlock: triggerUnlock)
        guard let hash = inner.hash, !hash.isEmpty else {
            throw KeePassXCError.protocolError("no database hash in reply")
        }
        return hash
    }

    /// The stored pairing when KeePassXC still accepts it; a fresh associate
    /// (KeePassXC's naming dialog) when there is none or it was revoked.
    private nonisolated static func associationEnsured(
        session: KeePassXCSession, databaseHash: String
    ) throws -> KeePassXCAssociationStore.Association {
        if let stored = KeePassXCAssociationStore.load(databaseHash: databaseHash) {
            do {
                _ = try session.request(
                    action: "test-associate",
                    body: KeePassXCProtocol.TestAssociateRequest(id: stored.id, key: stored.key),
                    timeout: 30)
                return stored
            } catch let error as KeePassXCError {
                switch error {
                case .associationRevoked, .associationFailed:
                    // Deleted from the database (or the reply politely calls a
                    // stale key a failure) — drop it and pair afresh below.
                    KeePassXCAssociationStore.delete(databaseHash: databaseHash)
                    log.log("stored association rejected — re-associating")
                default:
                    throw error
                }
            }
        }
        // A fresh identification keypair; only its PUBLIC half matters after
        // this call (KeePassXC stores it, we present it), so only that is kept.
        let idKey = KeePassXCProtocol.SessionKeys()
        let inner = try session.request(
            action: "associate",
            body: KeePassXCProtocol.AssociateRequest(
                key: session.publicKeyBase64,
                idKey: idKey.publicKey.base64EncodedString()),
            timeout: 180)
        guard let name = inner.id, !name.isEmpty else {
            throw KeePassXCError.associationFailed("no association id in reply")
        }
        let association = KeePassXCAssociationStore.Association(
            id: name, key: idKey.publicKey.base64EncodedString())
        // Keyed on the hash WE asked with, which is the one the next connect
        // will look up — the reply's own hash names the same database, and
        // storing under both would just leave a stale copy to age out.
        KeePassXCAssociationStore.save(databaseHash: databaseHash, association)
        log.log("associated with KeePassXC as \(name, privacy: .public)")
        return association
    }
}
