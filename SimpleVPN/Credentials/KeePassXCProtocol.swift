// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
//  KeePassXCProtocol.swift
//  The keepassxc-browser wire protocol, minus the socket: message shapes,
//  envelope sealing/opening (NaClBox), nonce discipline, error-code mapping
//  and the socket-path discovery rules. Everything here is pure data-in/
//  data-out so the whole protocol can be pinned by tests against a mock peer
//  — KeePassXC itself is never present on a build machine.
//
//  The protocol in one breath: connect to KeePassXC's browser-integration
//  unix socket, swap Curve25519 public keys in the clear
//  (`change-public-keys`), then every further message is a JSON body sealed
//  with crypto_box under a fresh 24-byte nonce, riding inside a plaintext
//  envelope {action, message, nonce, clientID}. A reply must arrive under the
//  request's nonce + 1 — that increment is what ties an answer to its
//  question. `associate` registers a public "identification key" that
//  KeePassXC stores INSIDE the database (the user names it in a KeePassXC
//  dialog); presenting id + key later (`test-associate`, `get-logins`) is the
//  whole authentication, which is why the pair lives in the keychain
//  (KeePassXCAssociationStore) and nowhere else.
//

import CryptoKit
import Foundation

// MARK: - Errors

/// Typed KeePassXC failures — the vocabulary UserFacingError classifies from.
/// Wire error CODES (BrowserAction.h) are mapped here so the prose the user
/// sees never depends on KeePassXC's own message strings.
enum KeePassXCError: LocalizedError, Sendable, Equatable {
    /// No browser-integration socket to connect to.
    case notRunning
    /// The socket answered but the key exchange didn't (wrong peer, or a
    /// KeePassXC too old to speak protocol v2).
    case handshakeFailed(String)
    /// Code 1 — the database is locked (or still waiting for the unlock the
    /// triggerUnlock raised).
    case databaseLocked
    /// Code 6 — the user dismissed KeePassXC's access-confirmation dialog.
    case accessDenied
    /// Codes 8/9 — the pairing attempt itself was refused or cancelled.
    case associationFailed(String)
    /// Codes 10/11 — KeePassXC no longer recognises our stored identification
    /// key: the association was deleted from the database (or the database
    /// changed). Re-associating is the fix.
    case associationRevoked
    /// Code 15 — the database holds no entry whose URL matches.
    case noLogins(String)
    /// Several entries match and nothing picks between them.
    case ambiguous(String)
    /// The socket went quiet past its deadline.
    case timedOut
    /// Anything structurally wrong with a reply (bad JSON, bad nonce, a
    /// message that wouldn't decrypt).
    case protocolError(String)
    /// A wire error code with no better home.
    case serverError(code: Int, message: String)

    /// Map a wire error code (+ message) onto the typed cases.
    static func fromWire(code: Int, message: String, matchHost: String = "") -> KeePassXCError {
        switch code {
        case 1: .databaseLocked
        case 6: .accessDenied
        case 8, 9: .associationFailed(message)
        case 10, 11: .associationRevoked
        case 15: .noLogins(matchHost)
        default: .serverError(code: code, message: message)
        }
    }

    var errorDescription: String? {
        switch self {
        case .notRunning:
            "KeePassXC doesn't seem to be running (or its browser integration "
            + "is off). Open KeePassXC, and in Settings \u{25B8} Browser "
            + "Integration turn on \u{201C}Enable browser integration\u{201D}."
        case .handshakeFailed(let detail):
            "KeePassXC refused the connection handshake"
            + (detail.isEmpty ? "." : " (\(detail)).")
        case .databaseLocked:
            "The KeePassXC database is locked. Unlock it in KeePassXC, then try again."
        case .accessDenied:
            "KeePassXC's permission prompt was dismissed. Connect again and "
            + "choose Allow when KeePassXC asks."
        case .associationFailed(let detail):
            "Pairing with KeePassXC didn't finish"
            + (detail.isEmpty ? "." : " (\(detail)).")
            + " Connect again and give the connection a name when KeePassXC asks."
        case .associationRevoked:
            "KeePassXC no longer recognises SimpleVPN's pairing — it was "
            + "removed from the database. Connect again to pair afresh."
        case .noLogins(let host):
            "KeePassXC has no entry whose URL matches "
            + (host.isEmpty ? "this VPN." : "\u{201C}\(host)\u{201D}.")
            + " Add the address to the entry's URL field in KeePassXC."
        case .ambiguous(let detail):
            "More than one KeePassXC entry matches (\(detail)). Set the "
            + "account to the entry's username so the right one is used."
        case .timedOut:
            "KeePassXC didn't answer. Bring it to the front, make sure the "
            + "database is unlocked, and try again."
        case .protocolError(let detail):
            "KeePassXC sent an unexpected reply (\(detail))."
        case .serverError(_, let message):
            message.isEmpty ? "KeePassXC request failed." : message
        }
    }
}

// MARK: - Protocol

nonisolated enum KeePassXCProtocol {

    /// The socket KeePassXC 2.7 listens on: QStandardPaths::TempLocation on
    /// macOS, i.e. the per-user $TMPDIR under /var/folders. Also probed: the
    /// confstr(_CS_DARWIN_USER_TEMP_DIR) spelling of the same directory (a
    /// posix_spawn'd process — or one launched from a shell that scrubbed the
    /// environment — has no $TMPDIR, and KeePassXC's may have been resolved
    /// either way), KeePassXC's Application Support directory (where sandboxed
    /// and some packaged builds land), and the pre-2.6 legacy socket name.
    static let socketName = "org.keepassxc.KeePassXC.BrowserServer"
    static let legacySocketName = "kpxc_server"

    static func socketCandidates(
        environment: [String: String] = ProcessInfo.processInfo.environment,
        home: URL = FileManager.default.homeDirectoryForCurrentUser
    ) -> [String] {
        var dirs: [String] = []
        if let t = environment["TMPDIR"], !t.isEmpty { dirs.append(t) }
        var buf = [UInt8](repeating: 0, count: Int(PATH_MAX))
        let length = buf.withUnsafeMutableBytes {
            confstr(_CS_DARWIN_USER_TEMP_DIR, $0.baseAddress, $0.count)
        }
        // confstr's length INCLUDES the terminator; drop it before decoding.
        if length > 1 {
            dirs.append(String(decoding: buf[0..<(length - 1)], as: UTF8.self))
        }
        dirs.append(home.appendingPathComponent("Library/Application Support/KeePassXC").path)
        var seen = Set<String>()
        var out: [String] = []
        for dir in dirs {
            let base = dir.hasSuffix("/") ? String(dir.dropLast()) : dir
            for name in [socketName, legacySocketName] {
                let path = base + "/" + name
                if seen.insert(path).inserted { out.append(path) }
            }
        }
        return out
    }

    /// An absolute socket path the user set in Settings ▸ Sign-In Sources. It wins
    /// over discovery — someone whose KeePassXC listens somewhere our candidates
    /// don't cover must be able to say so — but it is still only used when it really
    /// IS a socket, because a stale setting must not stop the automatic path
    /// working.
    static func userConfiguredSocket(store: UserDefaults = .standard) -> String? {
        guard let raw = store.string(forKey: SignInSourceSettings.keePassXCSocketKey)?
            .trimmingCharacters(in: .whitespaces), raw.hasPrefix("/") else { return nil }
        return raw
    }

    /// The first candidate that exists as a socket — nil means KeePassXC isn't
    /// running with browser integration on (there is nothing to connect to).
    static func discoverSocket(store: UserDefaults = .standard) -> String? {
        func isSocket(_ path: String) -> Bool {
            var st = stat()
            return stat(path, &st) == 0 && (st.st_mode & S_IFMT) == S_IFSOCK
        }
        if let explicit = userConfiguredSocket(store: store), isSocket(explicit) { return explicit }
        return socketCandidates().first(where: isSocket)
    }

    // MARK: Wire shapes

    /// The plaintext envelope both directions travel in. Fields are optional
    /// because the same shape serves requests, replies, errors and KeePassXC's
    /// unsolicited signals ("database-locked"/"database-unlocked", which carry
    /// only an action).
    struct Envelope: Codable, Sendable {
        var action: String
        var publicKey: String?
        var message: String?
        var nonce: String?
        var clientID: String?
        var triggerUnlock: String?
        var version: String?
        var success: String?
        var error: String?
        var errorCode: String?

        /// KeePassXC's unsolicited lock-state broadcasts — anything waiting
        /// for a reply skips these (and may act on them).
        var isSignal: Bool {
            action == "database-locked" || action == "database-unlocked"
        }
    }

    // Inner (encrypted) request/response bodies. Lenient by construction:
    // every response field optional, so a KeePassXC that adds fields or omits
    // one never throws the whole reply away.

    struct AssociateRequest: Codable, Sendable {
        var action = "associate"
        /// The SESSION public key — proves the associate came from the peer
        /// that did the handshake.
        var key: String
        /// The new IDENTIFICATION public key KeePassXC stores in the database.
        var idKey: String
    }

    struct TestAssociateRequest: Codable, Sendable {
        var action = "test-associate"
        var id: String
        var key: String
    }

    struct GetDatabaseHashRequest: Codable, Sendable {
        var action = "get-databasehash"
    }

    struct AssociationKey: Codable, Sendable {
        var id: String
        var key: String
    }

    struct GetLoginsRequest: Codable, Sendable {
        var action = "get-logins"
        var url: String
        var submitUrl: String?
        var keys: [AssociationKey]
    }

    struct GetTOTPRequest: Codable, Sendable {
        var action = "get-totp"
        var uuid: String
    }

    struct InnerResponse: Codable, Sendable {
        var hash: String?
        var version: String?
        var success: String?
        var id: String?
        var nonce: String?
        var count: Int?
        var entries: [LoginEntry]?
        var totp: String?
        var error: String?
        var errorCode: String?
    }

    /// One matched database entry. `totp` rides along when KeePassXC's
    /// "include TOTP in get-logins" setting is on; otherwise a separate
    /// get-totp with the uuid fetches the code.
    struct LoginEntry: Codable, Sendable {
        var login: String?
        var name: String?
        var password: String?
        var uuid: String?
        var totp: String?
    }

    // MARK: Session crypto

    /// One connection's cryptographic identity: our keypair, the negotiated
    /// shared key once the peer's public key arrives, and the clientID that
    /// names this session in every envelope.
    struct SessionKeys: Sendable {
        let privateKey: Curve25519.KeyAgreement.PrivateKey
        let publicKey: Data
        let clientID: String
        var sharedKey: Data?

        init() {
            privateKey = Curve25519.KeyAgreement.PrivateKey()
            publicKey = privateKey.publicKey.rawRepresentation
            clientID = Data(randomBytes: 24).base64EncodedString()
        }

        /// Complete the handshake: derive the crypto_box shared key from the
        /// peer's `change-public-keys` reply.
        mutating func acceptPeer(publicKeyBase64: String) throws {
            guard let peer = Data(base64Encoded: publicKeyBase64), peer.count == 32 else {
                throw KeePassXCError.handshakeFailed("bad server public key")
            }
            do { sharedKey = try NaClBox.sharedKey(peerPublicKey: peer, privateKey: privateKey) }
            catch { throw KeePassXCError.handshakeFailed("key agreement failed") }
        }
    }

    static func freshNonce() -> Data { Data(randomBytes: 24) }

    /// The plaintext handshake envelope — the only unencrypted request.
    static func changePublicKeysEnvelope(keys: SessionKeys, nonce: Data) -> Envelope {
        Envelope(action: "change-public-keys",
                 publicKey: keys.publicKey.base64EncodedString(),
                 nonce: nonce.base64EncodedString(),
                 clientID: keys.clientID)
    }

    /// Seal an inner request into its envelope.
    static func sealedEnvelope(action: String, body: some Encodable, keys: SessionKeys,
                               nonce: Data, triggerUnlock: Bool = false) throws -> Envelope {
        guard let sharedKey = keys.sharedKey else {
            throw KeePassXCError.protocolError("no session key (handshake not done)")
        }
        let plaintext = try JSONEncoder().encode(body)
        guard let sealed = NaClBox.seal(plaintext, nonce: nonce, sharedKey: sharedKey) else {
            throw KeePassXCError.protocolError("encryption failed")
        }
        return Envelope(action: action,
                        message: sealed.base64EncodedString(),
                        nonce: nonce.base64EncodedString(),
                        clientID: keys.clientID,
                        triggerUnlock: triggerUnlock ? "true" : nil)
    }

    /// Open a reply envelope: verify the nonce is the request's + 1, decrypt,
    /// and surface wire errors (which arrive PLAINTEXT on the envelope when
    /// the failure happened before anything could be encrypted) as typed
    /// errors. `matchHost` only flavors the no-logins message.
    static func openReply(_ envelope: Envelope, keys: SessionKeys, requestNonce: Data,
                          matchHost: String = "") throws -> InnerResponse {
        if let codeText = envelope.errorCode, let code = Int(codeText) {
            throw KeePassXCError.fromWire(code: code, message: envelope.error ?? "",
                                          matchHost: matchHost)
        }
        guard let sharedKey = keys.sharedKey else {
            throw KeePassXCError.protocolError("no session key (handshake not done)")
        }
        guard let nonceText = envelope.nonce, let nonce = Data(base64Encoded: nonceText),
              nonce == NaClBox.incremented(nonce: requestNonce) else {
            throw KeePassXCError.protocolError("reply nonce mismatch")
        }
        guard let messageText = envelope.message, let sealed = Data(base64Encoded: messageText),
              let plaintext = NaClBox.open(sealed, nonce: nonce, sharedKey: sharedKey) else {
            throw KeePassXCError.protocolError("reply wouldn't decrypt")
        }
        guard let inner = try? JSONDecoder().decode(InnerResponse.self, from: plaintext) else {
            throw KeePassXCError.protocolError("reply body isn't valid JSON")
        }
        // Errors can also arrive INSIDE the sealed body (the reply encrypted
        // fine, the action itself failed).
        if let codeText = inner.errorCode, let code = Int(codeText) {
            throw KeePassXCError.fromWire(code: code, message: inner.error ?? "",
                                          matchHost: matchHost)
        }
        if inner.success != "true" {
            throw KeePassXCError.protocolError("action \(envelope.action) reported failure")
        }
        return inner
    }

    // MARK: Stream framing

    /// Extract the first complete JSON object from a byte stream. QLocalSocket
    /// writes one JSON document per message, but SOCK_STREAM guarantees no
    /// boundaries — a read may deliver half a message or a signal glued to the
    /// reply — so this walks brace depth (string- and escape-aware; the
    /// envelope is flat but error strings may contain anything) and returns
    /// the object plus the remainder. nil = incomplete, keep reading.
    static func extractJSONObject(from buffer: Data) -> (object: Data, rest: Data)? {
        var depth = 0
        var inString = false
        var escaped = false
        var start: Int?
        for (i, byte) in buffer.enumerated() {
            if inString {
                if escaped { escaped = false }
                else if byte == UInt8(ascii: "\\") { escaped = true }
                else if byte == UInt8(ascii: "\"") { inString = false }
                continue
            }
            switch byte {
            case UInt8(ascii: "\""): inString = true
            case UInt8(ascii: "{"):
                if depth == 0 { start = i }
                depth += 1
            case UInt8(ascii: "}"):
                depth -= 1
                if depth == 0, let s = start {
                    let object = buffer.subdata(in: buffer.index(buffer.startIndex, offsetBy: s)
                        ..< buffer.index(buffer.startIndex, offsetBy: i + 1))
                    let rest = buffer.subdata(in: buffer.index(buffer.startIndex, offsetBy: i + 1)
                        ..< buffer.endIndex)
                    return (object, rest)
                }
            default: break
            }
        }
        return nil
    }

    /// The URL get-logins matches against. The reference the user types is a
    /// hostname (or a full URL, kept verbatim); a bare host is dressed as
    /// https://host because KeePassXC's matcher works on URLs. Matching is
    /// then KeePassXC's own: an entry matches when its URL field's host is
    /// the same site (base-domain by default — configurable per entry in
    /// KeePassXC's Browser Integration settings). So an entry whose URL says
    /// https://vpn.example.com is found for reference "vpn.example.com".
    static func matchURL(for reference: String) -> String {
        let trimmed = reference.trimmingCharacters(in: .whitespaces)
        return trimmed.contains("://") ? trimmed : "https://" + trimmed
    }

    /// The host shown in error prose for a reference.
    static func matchHost(for reference: String) -> String {
        let url = matchURL(for: reference)
        return URL(string: url)?.host ?? reference.trimmingCharacters(in: .whitespaces)
    }
}

// MARK: - Random bytes

nonisolated extension Data {
    /// Cryptographically random bytes (SecRandomCopyBytes; nonces and client
    /// ids — never keys, which CryptoKit generates itself).
    init(randomBytes count: Int) {
        var bytes = [UInt8](repeating: 0, count: count)
        // Only fails when the kernel's RNG is unavailable, which is fatal for
        // everything anyway.
        _ = SecRandomCopyBytes(kSecRandomDefault, count, &bytes)
        self = Data(bytes)
    }
}
