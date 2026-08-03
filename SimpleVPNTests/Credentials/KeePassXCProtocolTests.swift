// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
//  KeePassXCProtocolTests.swift
//  Pins the keepassxc-browser protocol pieces that never see a socket
//  (envelopes, nonce discipline, error mapping, stream framing, URL
//  matching), then runs the full association round-trip — handshake →
//  get-databasehash (locked, triggerUnlock, unlock signal) → associate →
//  test-associate → get-logins → get-totp — against a mock KeePassXC serving
//  the real wire format over a real unix socket. KeePassXC itself is never
//  present on a build machine; the mock speaks with the same NaClBox the
//  client does, which the crypto tests pin against libsodium-compatible
//  reference vectors — so agreement here isn't circular.
//

import CryptoKit
import Foundation
import os
import Testing
@testable import SimpleVPN

// MARK: - Pure protocol pieces

struct KeePassXCProtocolTests {

    @Test func socketCandidatesCoverTheKnownHomes() {
        let home = URL(fileURLWithPath: "/Users/someone")
        let candidates = KeePassXCProtocol.socketCandidates(
            environment: ["TMPDIR": "/var/folders/xx/T/"], home: home)
        // $TMPDIR first (KeePassXC 2.7's actual location), no doubled slash.
        #expect(candidates.first == "/var/folders/xx/T/org.keepassxc.KeePassXC.BrowserServer")
        #expect(candidates.contains(
            "/Users/someone/Library/Application Support/KeePassXC/org.keepassxc.KeePassXC.BrowserServer"))
        // Legacy name probed too, and nothing twice.
        #expect(candidates.contains("/var/folders/xx/T/kpxc_server"))
        #expect(Set(candidates).count == candidates.count)
    }

    @Test func matchURLDressesBareHostsAndKeepsFullURLs() {
        #expect(KeePassXCProtocol.matchURL(for: "vpn.example.com") == "https://vpn.example.com")
        #expect(KeePassXCProtocol.matchURL(for: "  vpn.example.com ") == "https://vpn.example.com")
        #expect(KeePassXCProtocol.matchURL(for: "https://vpn.example.com/gate") == "https://vpn.example.com/gate")
        #expect(KeePassXCProtocol.matchHost(for: "https://vpn.example.com/gate") == "vpn.example.com")
        #expect(KeePassXCProtocol.matchHost(for: "vpn.example.com") == "vpn.example.com")
    }

    @Test func envelopeEncodesTheWireKeys() throws {
        var keys = KeePassXCProtocol.SessionKeys()
        let peer = Curve25519.KeyAgreement.PrivateKey()
        try keys.acceptPeer(publicKeyBase64: peer.publicKey.rawRepresentation.base64EncodedString())
        let nonce = KeePassXCProtocol.freshNonce()
        let envelope = try KeePassXCProtocol.sealedEnvelope(
            action: "get-logins",
            body: KeePassXCProtocol.GetLoginsRequest(url: "https://vpn.example.com", keys: []),
            keys: keys, nonce: nonce, triggerUnlock: true)
        let json = try #require(try JSONSerialization.jsonObject(
            with: JSONEncoder().encode(envelope)) as? [String: Any])
        #expect(json["action"] as? String == "get-logins")
        #expect(json["nonce"] as? String == nonce.base64EncodedString())
        #expect(json["clientID"] as? String == keys.clientID)
        #expect(json["triggerUnlock"] as? String == "true")
        #expect(json["message"] is String)
        // The sealed body must NOT be readable off the envelope.
        #expect(!(json["message"] as? String ?? "").contains("vpn.example.com"))
    }

    @Test func openReplyEnforcesTheNonceIncrement() throws {
        var client = KeePassXCProtocol.SessionKeys()
        var server = KeePassXCProtocol.SessionKeys()
        try client.acceptPeer(publicKeyBase64: server.publicKey.base64EncodedString())
        try server.acceptPeer(publicKeyBase64: client.publicKey.base64EncodedString())

        let requestNonce = KeePassXCProtocol.freshNonce()
        let replyNonce = NaClBox.incremented(nonce: requestNonce)
        let body = Data(#"{"success":"true","hash":"abc"}"#.utf8)
        let sealed = try #require(NaClBox.seal(body, nonce: replyNonce,
                                               sharedKey: server.sharedKey!))
        var envelope = KeePassXCProtocol.Envelope(
            action: "get-databasehash", message: sealed.base64EncodedString(),
            nonce: replyNonce.base64EncodedString())
        let inner = try KeePassXCProtocol.openReply(envelope, keys: client,
                                                    requestNonce: requestNonce)
        #expect(inner.hash == "abc")

        // A reply under the WRONG nonce (replayed / cross-wired) must refuse.
        envelope.nonce = requestNonce.base64EncodedString()
        #expect(throws: KeePassXCError.protocolError("reply nonce mismatch")) {
            _ = try KeePassXCProtocol.openReply(envelope, keys: client,
                                                requestNonce: requestNonce)
        }
    }

    @Test func openReplyMapsWireErrorCodes() throws {
        var client = KeePassXCProtocol.SessionKeys()
        let server = KeePassXCProtocol.SessionKeys()
        try client.acceptPeer(publicKeyBase64: server.publicKey.base64EncodedString())
        let nonce = KeePassXCProtocol.freshNonce()
        // Plaintext-envelope errors (the failure happened before encryption).
        func wireError(_ code: String) -> KeePassXCProtocol.Envelope {
            KeePassXCProtocol.Envelope(action: "x", error: "boom", errorCode: code)
        }
        func mapped(_ code: String) -> KeePassXCError? {
            do {
                _ = try KeePassXCProtocol.openReply(wireError(code), keys: client,
                                                    requestNonce: nonce, matchHost: "h")
                return nil
            } catch { return error as? KeePassXCError }
        }
        #expect(mapped("1") == .databaseLocked)
        #expect(mapped("6") == .accessDenied)
        #expect(mapped("8") == .associationFailed("boom"))
        #expect(mapped("10") == .associationRevoked)
        #expect(mapped("15") == .noLogins("h"))
        #expect(mapped("42") == .serverError(code: 42, message: "boom"))
    }

    @Test func streamFramingSplitsGluedAndPartialMessages() {
        let a = Data(#"{"action":"database-locked"}"#.utf8)
        let b = Data(#"{"action":"x","error":"has } and \" inside"}"#.utf8)
        // Two messages in one read: both come out, in order.
        var buffer = a + b
        let first = KeePassXCProtocol.extractJSONObject(from: buffer)
        #expect(first?.object == a)
        buffer = first!.rest
        let second = KeePassXCProtocol.extractJSONObject(from: buffer)
        #expect(second?.object == b)
        #expect(second?.rest.isEmpty == true)
        // A partial message: nothing yet, keep reading.
        #expect(KeePassXCProtocol.extractJSONObject(from: a.prefix(10)) == nil)
    }

    @Test func entryPickingHonoursTheAccountFilter() throws {
        typealias Entry = KeePassXCProtocol.LoginEntry
        let entries = [Entry(login: "jim", name: "GR Lab", password: "a", uuid: "1"),
                       Entry(login: "root", name: "GR Lab admin", password: "b", uuid: "2")]
        // One match with an account filter — proceeds.
        let jim = try KeePassXCProvider.pickEntry(from: entries, accountFilter: "JIM", host: "h")
        #expect(jim.uuid == "1")   // case-insensitive on purpose
        // Several matches with no filter — a genuine ambiguity.
        #expect(throws: KeePassXCError.self) {
            _ = try KeePassXCProvider.pickEntry(from: entries, accountFilter: "", host: "h")
        }
        // A filter nothing matches reads as "no logins", not ambiguity.
        #expect(throws: KeePassXCError.noLogins("h")) {
            _ = try KeePassXCProvider.pickEntry(from: entries, accountFilter: "nobody", host: "h")
        }
        // A single entry with no filter — the everyday case.
        let single = try KeePassXCProvider.pickEntry(from: [entries[0]], accountFilter: "", host: "h")
        #expect(single.uuid == "1")
    }

    @Test func classifierTurnsTypedErrorsIntoRemedies() {
        let locked = UserFacingError.classify(KeePassXCError.databaseLocked)
        #expect(locked.category == .keePassXC)
        #expect(locked.action == .openKeePassXC)
        #expect(!locked.steps.isEmpty)

        let missing = UserFacingError.classify(KeePassXCError.noLogins("vpn.example.com"))
        #expect(missing.category == .credentials)
        #expect(missing.explanation.contains("vpn.example.com"))

        let revoked = UserFacingError.classify(KeePassXCError.associationRevoked)
        #expect(revoked.title.contains("pair"))
        #expect(revoked.canRetry)

        let notRunning = UserFacingError.classify(KeePassXCError.notRunning)
        #expect(notRunning.category == .keePassXC)
        // The message-text path recognises the connector's prose too.
        let byMessage = UserFacingError.classify(
            message: KeePassXCError.databaseLocked.errorDescription ?? "")
        #expect(byMessage.category == .keePassXC)
    }
}

// MARK: - Mock KeePassXC

/// A KeePassXC stand-in on a real unix socket: real handshake, real crypto_box
/// envelopes, canned database. Configurable to start locked (get-databasehash
/// answers error 1, then a `database-unlocked` signal follows) so the
/// triggerUnlock path is exercised.
private nonisolated final class MockKeePassXC: @unchecked Sendable {
    let socketPath: String
    private let listenFD: Int32
    private let queue = DispatchQueue(label: "mock-keepassxc", attributes: .concurrent)
    private let state: OSAllocatedUnfairLock<State>

    struct Entry {
        var name: String, login: String, password: String, uuid: String, totp: String?
    }
    struct State {
        var locked: Bool
        var associations: [String: String] = [:]   // id → idKey (base64)
        var entries: [Entry]
        var databaseHash = "cafe0000"
        var associateName = "SimpleVPN Test"
    }

    init(startsLocked: Bool = false, entries: [Entry]) throws {
        socketPath = NSTemporaryDirectory() + "kpxc-mock-\(UUID().uuidString.prefix(8)).sock"
        state = OSAllocatedUnfairLock(initialState: State(locked: startsLocked, entries: entries))
        listenFD = socket(AF_UNIX, SOCK_STREAM, 0)
        var addr = sockaddr_un()
        addr.sun_family = sa_family_t(AF_UNIX)
        withUnsafeMutableBytes(of: &addr.sun_path) { raw in
            raw.copyBytes(from: Array(socketPath.utf8))
        }
        let bound = withUnsafePointer(to: &addr) {
            $0.withMemoryRebound(to: sockaddr.self, capacity: 1) {
                bind(listenFD, $0, socklen_t(MemoryLayout<sockaddr_un>.size))
            }
        }
        guard bound == 0, listen(listenFD, 4) == 0 else {
            throw KeePassXCError.protocolError("mock bind failed (errno \(errno))")
        }
        let fd = listenFD
        queue.async { [weak self] in
            while true {
                let client = accept(fd, nil, nil)
                guard client >= 0, let self else { return }
                self.queue.async { self.serve(client) }
            }
        }
    }

    func stop() {
        close(listenFD)
        unlink(socketPath)
    }

    private func send(_ fd: Int32, _ value: some Encodable) {
        guard let data = try? JSONEncoder().encode(value) else { return }
        data.withUnsafeBytes { _ = Darwin.send(fd, $0.baseAddress, $0.count, 0) }
    }

    private func serve(_ fd: Int32) {
        defer { close(fd) }
        var keys = KeePassXCProtocol.SessionKeys()
        var buffer = Data()
        var chunk = [UInt8](repeating: 0, count: 64 * 1024)
        while true {
            let n = recv(fd, &chunk, chunk.count, 0)
            guard n > 0 else { return }
            buffer.append(contentsOf: chunk[0..<n])
            while let (object, rest) = KeePassXCProtocol.extractJSONObject(from: buffer) {
                buffer = rest
                guard let envelope = try? JSONDecoder()
                    .decode(KeePassXCProtocol.Envelope.self, from: object) else { return }
                handle(envelope, keys: &keys, fd: fd)
            }
        }
    }

    private func handle(_ envelope: KeePassXCProtocol.Envelope,
                        keys: inout KeePassXCProtocol.SessionKeys, fd: Int32) {
        guard let nonceText = envelope.nonce, let nonce = Data(base64Encoded: nonceText) else { return }
        let replyNonce = NaClBox.incremented(nonce: nonce)

        if envelope.action == "change-public-keys" {
            try? keys.acceptPeer(publicKeyBase64: envelope.publicKey ?? "")
            send(fd, KeePassXCProtocol.Envelope(
                action: "change-public-keys", publicKey: keys.publicKey.base64EncodedString(),
                nonce: replyNonce.base64EncodedString(), version: "2.7.10", success: "true"))
            return
        }

        guard let shared = keys.sharedKey,
              let messageText = envelope.message, let sealed = Data(base64Encoded: messageText),
              let plain = NaClBox.open(sealed, nonce: nonce, sharedKey: shared),
              let inner = try? JSONSerialization.jsonObject(with: plain) as? [String: Any] else { return }

        func reply(_ body: [String: Any]) {
            var full = body
            full["version"] = "2.7.10"
            full["nonce"] = replyNonce.base64EncodedString()
            guard let data = try? JSONSerialization.data(withJSONObject: full),
                  let sealedReply = NaClBox.seal(data, nonce: replyNonce, sharedKey: shared) else { return }
            send(fd, KeePassXCProtocol.Envelope(
                action: envelope.action, message: sealedReply.base64EncodedString(),
                nonce: replyNonce.base64EncodedString()))
        }
        func replyError(_ code: Int) {
            // KeePassXC reports action failures on a PLAINTEXT envelope.
            send(fd, KeePassXCProtocol.Envelope(
                action: envelope.action, nonce: replyNonce.base64EncodedString(),
                error: "mock error", errorCode: "\(code)"))
        }

        switch inner["action"] as? String {
        case "get-databasehash":
            let locked = state.withLock { $0.locked }
            if locked {
                replyError(1)
                if envelope.triggerUnlock == "true" {
                    // The "user" unlocks shortly after; broadcast like KeePassXC.
                    queue.asyncAfter(deadline: .now() + 0.2) { [self] in
                        state.withLock { $0.locked = false }
                        send(fd, KeePassXCProtocol.Envelope(action: "database-unlocked"))
                    }
                }
                return
            }
            reply(["success": "true", "hash": state.withLock { $0.databaseHash }])
        case "associate":
            guard let idKey = inner["idKey"] as? String else { return replyError(8) }
            let (name, hash) = state.withLock { s in
                s.associations[s.associateName] = idKey
                return (s.associateName, s.databaseHash)
            }
            reply(["success": "true", "id": name, "hash": hash])
        case "test-associate":
            // Values out of the JSON dictionary BEFORE the lock: a
            // [String: Any] can't cross into a Sendable closure.
            let wantID = inner["id"] as? String ?? ""
            let wantKey = inner["key"] as? String ?? ""
            let ok = state.withLock { $0.associations[wantID] == wantKey }
            ok ? reply(["success": "true", "id": wantID,
                        "hash": state.withLock { $0.databaseHash }])
               : replyError(10)
        case "get-logins":
            let presented: [(String, String)] = (inner["keys"] as? [[String: Any]] ?? []).map {
                ($0["id"] as? String ?? "", $0["key"] as? String ?? "")
            }
            let associated = state.withLock { s in
                presented.contains { s.associations[$0.0] == $0.1 }
            }
            guard associated else { return replyError(10) }
            let host = (inner["url"] as? String).flatMap { URL(string: $0)?.host } ?? ""
            let matches = state.withLock { $0.entries }.filter { _ in !host.isEmpty }
            guard !matches.isEmpty else { return replyError(15) }
            reply(["success": "true", "count": matches.count,
                   "entries": matches.map { entry -> [String: Any] in
                       var dict: [String: Any] = ["name": entry.name, "login": entry.login,
                                                  "password": entry.password, "uuid": entry.uuid]
                       if let totp = entry.totp { dict["totp"] = totp }
                       return dict
                   }])
        case "get-totp":
            let uuid = inner["uuid"] as? String ?? ""
            let totp = state.withLock { $0.entries.first { $0.uuid == uuid }?.totp }
            reply(["success": "true", "totp": totp ?? ""])
        default:
            replyError(12)
        }
    }
}

// MARK: - Round trips against the mock

struct KeePassXCMockServerTests {

    /// The whole first-use conversation: handshake, hash, associate, then a
    /// reconnect proving the stored pairing with test-associate, get-logins
    /// under those keys, and get-totp for the code.
    @Test func associationRoundTripAgainstMockServer() throws {
        let mock = try MockKeePassXC(entries: [
            .init(name: "GR Lab VPN", login: "jim", password: "hunter2",
                  uuid: "u-1", totp: "246810"),
        ])
        defer { mock.stop() }

        // First connection: pair.
        let first = KeePassXCSession()
        try first.open(socketPath: mock.socketPath)
        let hash = try first.request(action: "get-databasehash",
                                     body: KeePassXCProtocol.GetDatabaseHashRequest(),
                                     timeout: 5).hash
        #expect(hash == "cafe0000")
        let idKey = KeePassXCProtocol.SessionKeys()
        let paired = try first.request(
            action: "associate",
            body: KeePassXCProtocol.AssociateRequest(
                key: first.publicKeyBase64,
                idKey: idKey.publicKey.base64EncodedString()),
            timeout: 5)
        let pairName = try #require(paired.id)
        #expect(paired.hash == "cafe0000")
        first.socket.shutdown()

        // Reconnect: a NEW session (new transport keys) proves the association.
        let second = KeePassXCSession()
        try second.open(socketPath: mock.socketPath)
        let tested = try second.request(
            action: "test-associate",
            body: KeePassXCProtocol.TestAssociateRequest(
                id: pairName, key: idKey.publicKey.base64EncodedString()),
            timeout: 5)
        #expect(tested.id == pairName)

        let logins = try second.request(
            action: "get-logins",
            body: KeePassXCProtocol.GetLoginsRequest(
                url: "https://vpn.example.com",
                keys: [.init(id: pairName, key: idKey.publicKey.base64EncodedString())]),
            timeout: 5, matchHost: "vpn.example.com")
        let entry = try #require(logins.entries?.first)
        #expect(entry.login == "jim")
        #expect(entry.password == "hunter2")

        let totp = try second.request(action: "get-totp",
                                      body: KeePassXCProtocol.GetTOTPRequest(uuid: "u-1"),
                                      timeout: 5)
        #expect(totp.totp == "246810")
        second.socket.shutdown()
    }

    /// A wrong identification key must be refused as revoked — the trigger for
    /// the provider's re-pair path.
    @Test func staleAssociationIsRefused() throws {
        let mock = try MockKeePassXC(entries: [])
        defer { mock.stop() }
        let session = KeePassXCSession()
        try session.open(socketPath: mock.socketPath)
        let stranger = KeePassXCProtocol.SessionKeys()
        #expect(throws: KeePassXCError.associationRevoked) {
            _ = try session.request(
                action: "test-associate",
                body: KeePassXCProtocol.TestAssociateRequest(
                    id: "NotPaired", key: stranger.publicKey.base64EncodedString()),
                timeout: 5)
        }
        session.socket.shutdown()
    }

    /// Locked database: error 1 first, then the unlock broadcast arrives and
    /// the retry succeeds — the shape of the provider's triggerUnlock flow.
    @Test func triggerUnlockWaitsForTheUnlockSignal() throws {
        let mock = try MockKeePassXC(startsLocked: true, entries: [])
        defer { mock.stop() }
        let session = KeePassXCSession()
        try session.open(socketPath: mock.socketPath)
        #expect(throws: KeePassXCError.databaseLocked) {
            _ = try session.request(action: "get-databasehash",
                                    body: KeePassXCProtocol.GetDatabaseHashRequest(),
                                    timeout: 5, triggerUnlock: true)
        }
        #expect(session.waitForUnlock(timeout: 5))
        let hash = try session.request(action: "get-databasehash",
                                       body: KeePassXCProtocol.GetDatabaseHashRequest(),
                                       timeout: 5).hash
        #expect(hash == "cafe0000")
        session.socket.shutdown()
    }

    /// No socket at the path ⇒ the plain "not running" story, not a hang.
    @Test func missingSocketSaysNotRunning() {
        let session = KeePassXCSession()
        #expect(throws: KeePassXCError.notRunning) {
            try session.open(socketPath: NSTemporaryDirectory() + "kpxc-nowhere.sock")
        }
    }
}
