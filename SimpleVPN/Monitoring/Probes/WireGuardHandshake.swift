// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
//  WireGuardHandshake.swift
//  A real WireGuard handshake initiation, built with the profile's OWN keypair,
//  and the code to check the response that comes back.
//
//  This is the one protocol where a probe can be completely authenticated at no
//  risk whatsoever: WireGuard has no accounts, no passwords and no one-time
//  codes — the keys ARE the identity. A server answers a handshake initiation
//  only when (a) mac1 proves the sender knows the server's public key, (b) the
//  encrypted static key decrypts with the server's private key, and (c) that
//  static key belongs to a configured peer. So a response is proof the whole
//  configuration is right, and nothing is consumed or left behind: WireGuard is
//  stateless until data flows, and we send none.
//
//  That is also why the anonymous probe in VPNProbe.swift is explicitly labelled
//  weak — it sends a random 148 bytes that no server can authenticate, so its
//  silence means nothing. This one's silence means something.
//
//  Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s, per the WireGuard whitepaper §5.4.
//  CryptoKit supplies X25519 and ChaCha20-Poly1305; BLAKE2s it does not have,
//  so RFC 7693 is implemented below (and tested against the RFC's own vectors —
//  a hand-rolled hash with no test vectors would be worse than no probe).
//

import Foundation
import CryptoKit

// MARK: - BLAKE2s (RFC 7693)

nonisolated struct BLAKE2s {

    private static let iv: [UInt32] = [
        0x6A09_E667, 0xBB67_AE85, 0x3C6E_F372, 0xA54F_F53A,
        0x510E_527F, 0x9B05_688C, 0x1F83_D9AB, 0x5BE0_CD19,
    ]

    private static let sigma: [[Int]] = [
        [0, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15],
        [14, 10, 4, 8, 9, 15, 13, 6, 1, 12, 0, 2, 11, 7, 5, 3],
        [11, 8, 12, 0, 5, 2, 15, 13, 10, 14, 3, 6, 7, 1, 9, 4],
        [7, 9, 3, 1, 13, 12, 11, 14, 2, 6, 5, 10, 4, 0, 15, 8],
        [9, 0, 5, 7, 2, 4, 10, 15, 14, 1, 11, 12, 6, 8, 3, 13],
        [2, 12, 6, 10, 0, 11, 8, 3, 4, 13, 7, 5, 15, 14, 1, 9],
        [12, 5, 1, 15, 14, 13, 4, 10, 0, 7, 6, 3, 9, 2, 8, 11],
        [13, 11, 7, 14, 12, 1, 3, 9, 5, 0, 15, 4, 8, 6, 2, 10],
        [6, 15, 14, 9, 11, 3, 0, 8, 12, 2, 13, 7, 1, 4, 10, 5],
        [10, 2, 8, 4, 7, 6, 1, 5, 15, 11, 9, 14, 3, 12, 13, 0],
    ]

    static let blockSize = 64

    private var h: [UInt32]
    private var buffer = [UInt8](repeating: 0, count: blockSize)
    private var bufferLength = 0
    private var counter: UInt64 = 0
    private let digestLength: Int

    init(digestLength: Int = 32, key: [UInt8] = []) {
        precondition((1...32).contains(digestLength))
        precondition(key.count <= 32)
        self.digestLength = digestLength
        h = Self.iv
        h[0] ^= 0x0101_0000 ^ (UInt32(key.count) << 8) ^ UInt32(digestLength)
        if !key.isEmpty {
            // The key occupies one whole first block, zero-padded.
            update(key + [UInt8](repeating: 0, count: Self.blockSize - key.count))
        }
    }

    mutating func update(_ data: [UInt8]) {
        var offset = 0
        while offset < data.count {
            if bufferLength == Self.blockSize {
                // Never compress the final block here: the last one is flagged,
                // and we only know it's last at finalise time.
                counter &+= UInt64(Self.blockSize)
                compress(last: false)
                bufferLength = 0
            }
            let take = min(Self.blockSize - bufferLength, data.count - offset)
            for i in 0..<take { buffer[bufferLength + i] = data[offset + i] }
            bufferLength += take
            offset += take
        }
    }

    mutating func finalize() -> [UInt8] {
        counter &+= UInt64(bufferLength)
        for i in bufferLength..<Self.blockSize { buffer[i] = 0 }
        compress(last: true)
        var out: [UInt8] = []
        out.reserveCapacity(32)
        for word in h {
            out.append(UInt8(truncatingIfNeeded: word))
            out.append(UInt8(truncatingIfNeeded: word >> 8))
            out.append(UInt8(truncatingIfNeeded: word >> 16))
            out.append(UInt8(truncatingIfNeeded: word >> 24))
        }
        return Array(out.prefix(digestLength))
    }

    private mutating func compress(last: Bool) {
        var m = [UInt32](repeating: 0, count: 16)
        for i in 0..<16 {
            let b = i * 4
            m[i] = UInt32(buffer[b]) | (UInt32(buffer[b + 1]) << 8)
                 | (UInt32(buffer[b + 2]) << 16) | (UInt32(buffer[b + 3]) << 24)
        }
        var v = h + Self.iv
        v[12] ^= UInt32(truncatingIfNeeded: counter)
        v[13] ^= UInt32(truncatingIfNeeded: counter >> 32)
        if last { v[14] = ~v[14] }

        @inline(__always) func rotr(_ x: UInt32, _ n: UInt32) -> UInt32 {
            (x >> n) | (x << (32 - n))
        }
        @inline(__always) func mix(_ a: Int, _ b: Int, _ c: Int, _ d: Int,
                                   _ x: UInt32, _ y: UInt32) {
            v[a] = v[a] &+ v[b] &+ x
            v[d] = rotr(v[d] ^ v[a], 16)
            v[c] = v[c] &+ v[d]
            v[b] = rotr(v[b] ^ v[c], 12)
            v[a] = v[a] &+ v[b] &+ y
            v[d] = rotr(v[d] ^ v[a], 8)
            v[c] = v[c] &+ v[d]
            v[b] = rotr(v[b] ^ v[c], 7)
        }

        for round in 0..<10 {
            let s = Self.sigma[round]
            mix(0, 4, 8, 12, m[s[0]], m[s[1]])
            mix(1, 5, 9, 13, m[s[2]], m[s[3]])
            mix(2, 6, 10, 14, m[s[4]], m[s[5]])
            mix(3, 7, 11, 15, m[s[6]], m[s[7]])
            mix(0, 5, 10, 15, m[s[8]], m[s[9]])
            mix(1, 6, 11, 12, m[s[10]], m[s[11]])
            mix(2, 7, 8, 13, m[s[12]], m[s[13]])
            mix(3, 4, 9, 14, m[s[14]], m[s[15]])
        }
        for i in 0..<8 { h[i] ^= v[i] ^ v[i + 8] }
    }

    // MARK: One-shot helpers

    static func hash(_ data: [UInt8], digestLength: Int = 32, key: [UInt8] = []) -> [UInt8] {
        var state = BLAKE2s(digestLength: digestLength, key: key)
        state.update(data)
        return state.finalize()
    }

    static func hash(_ parts: [[UInt8]], digestLength: Int = 32, key: [UInt8] = []) -> [UInt8] {
        var state = BLAKE2s(digestLength: digestLength, key: key)
        for part in parts { state.update(part) }
        return state.finalize()
    }

    /// HMAC as WireGuard's KDF uses it: the RFC 2104 construction over BLAKE2s,
    /// NOT BLAKE2s's own keyed mode (they are different functions).
    static func hmac(key: [UInt8], data: [[UInt8]]) -> [UInt8] {
        var k = key.count > blockSize ? hash(key) : key
        k += [UInt8](repeating: 0, count: blockSize - k.count)
        let inner = hash([k.map { $0 ^ 0x36 }] + data)
        return hash([k.map { $0 ^ 0x5C }, inner])
    }
}

// MARK: - The handshake

nonisolated enum WireGuardHandshake {

    static let construction = "Noise_IKpsk2_25519_ChaChaPoly_BLAKE2s"
    static let identifier = "WireGuard v1 zx2c4 Jason@zx2c4.com"
    static let labelMAC1 = "mac1----"

    static let initiationLength = 148
    static let responseLength = 92
    /// Offset of mac1 in either message: everything before it is what mac1 covers.
    static let initiationMAC1Offset = 116
    static let responseMAC1Offset = 60

    enum MessageType: UInt8 { case initiation = 1, response = 2, cookie = 3, data = 4 }

    enum HandshakeError: Error, Equatable {
        case badPrivateKey
        case badPeerPublicKey
        case badPresharedKey
        case keyAgreementFailed
        case sealFailed
    }

    /// What we keep between sending an initiation and judging the response.
    struct Session: Sendable {
        var message: [UInt8]
        var senderIndex: UInt32
        fileprivate var chainingKey: [UInt8]
        fileprivate var hash: [UInt8]
        fileprivate var ephemeralPrivate: Curve25519.KeyAgreement.PrivateKey
        fileprivate var staticPrivate: Curve25519.KeyAgreement.PrivateKey
        fileprivate var localPublic: [UInt8]
        fileprivate var presharedKey: [UInt8]
    }

    enum ResponseCheck: Sendable, Equatable {
        /// The server completed the handshake with us: it holds the private key
        /// for the peer public key in this profile, and it recognises ours.
        case accepted
        /// Right shape, wrong conversation (a stale or unrelated datagram).
        case notOurs
        /// A cookie reply — the server is under load or rate-limiting, but it
        /// DID authenticate our mac1, so it knows the public key we used.
        case cookieReply
        case malformed
        /// The AEAD didn't open: something answered as WireGuard but the keys
        /// don't line up. In practice this only happens with a forged reply.
        case authenticationFailed
    }

    // MARK: Key handling

    static func decodeKey(_ base64: String) -> [UInt8]? {
        guard let data = Data(base64Encoded: base64.trimmingCharacters(in: .whitespacesAndNewlines)),
              data.count == 32 else { return nil }
        return Array(data)
    }

    /// Base64 of a public key — safe to show; it's public by construction. The
    /// PRIVATE key is never rendered or logged anywhere.
    static func publicKey(forPrivateKey base64: String) -> String? {
        guard let raw = decodeKey(base64),
              let key = try? Curve25519.KeyAgreement.PrivateKey(rawRepresentation: raw) else { return nil }
        return Data(key.publicKey.rawRepresentation).base64EncodedString()
    }

    // MARK: Building the initiation

    static func makeInitiation(privateKey: String, peerPublicKey: String,
                               presharedKey: String? = nil,
                               senderIndex: UInt32 = UInt32.random(in: 1...UInt32.max),
                               now: Date = Date()) throws -> Session {
        guard let rawPrivate = decodeKey(privateKey),
              let staticPrivate = try? Curve25519.KeyAgreement.PrivateKey(rawRepresentation: rawPrivate)
        else { throw HandshakeError.badPrivateKey }
        guard let rawPeer = decodeKey(peerPublicKey),
              let peer = try? Curve25519.KeyAgreement.PublicKey(rawRepresentation: rawPeer)
        else { throw HandshakeError.badPeerPublicKey }
        var psk = [UInt8](repeating: 0, count: 32)
        if let presharedKey, !presharedKey.isEmpty {
            guard let raw = decodeKey(presharedKey) else { throw HandshakeError.badPresharedKey }
            psk = raw
        }

        let localPublic = Array(staticPrivate.publicKey.rawRepresentation)
        var chainingKey = BLAKE2s.hash(Array(construction.utf8))
        var hash = BLAKE2s.hash([chainingKey, Array(identifier.utf8)])
        hash = BLAKE2s.hash([hash, rawPeer])

        let ephemeral = Curve25519.KeyAgreement.PrivateKey()
        let ephemeralPublic = Array(ephemeral.publicKey.rawRepresentation)
        chainingKey = kdf1(chainingKey, ephemeralPublic)
        hash = BLAKE2s.hash([hash, ephemeralPublic])

        let dh1 = try agree(ephemeral, peer)
        let (ck1, key1) = kdf2(chainingKey, dh1)
        guard let encryptedStatic = seal(key: key1, counter: 0, plaintext: localPublic, aad: hash)
        else { throw HandshakeError.sealFailed }
        chainingKey = ck1
        hash = BLAKE2s.hash([hash, encryptedStatic])

        let dh2 = try agree(staticPrivate, peer)
        let (ck2, key2) = kdf2(chainingKey, dh2)
        let stamp = tai64n(now)
        guard let encryptedTimestamp = seal(key: key2, counter: 0, plaintext: stamp, aad: hash)
        else { throw HandshakeError.sealFailed }
        chainingKey = ck2
        hash = BLAKE2s.hash([hash, encryptedTimestamp])

        var message: [UInt8] = [MessageType.initiation.rawValue, 0, 0, 0]
        message += le32(senderIndex)
        message += ephemeralPublic
        message += encryptedStatic
        message += encryptedTimestamp
        precondition(message.count == initiationMAC1Offset)
        message += mac1(over: message, peerPublicKey: rawPeer)
        message += [UInt8](repeating: 0, count: 16)      // mac2: no cookie held
        precondition(message.count == initiationLength)

        return Session(message: message, senderIndex: senderIndex,
                       chainingKey: chainingKey, hash: hash,
                       ephemeralPrivate: ephemeral, staticPrivate: staticPrivate,
                       localPublic: localPublic, presharedKey: psk)
    }

    /// mac1 = keyed-BLAKE2s(BLAKE2s("mac1----" ‖ receiver's public key), message-so-far).
    static func mac1(over prefix: [UInt8], peerPublicKey: [UInt8]) -> [UInt8] {
        let key = BLAKE2s.hash([Array(labelMAC1.utf8), peerPublicKey])
        return BLAKE2s.hash(prefix, digestLength: 16, key: key)
    }

    // MARK: Judging the response

    static func check(response: [UInt8], session: Session) -> ResponseCheck {
        guard let type = response.first else { return .malformed }
        if type == MessageType.cookie.rawValue { return .cookieReply }
        guard type == MessageType.response.rawValue,
              response.count == responseLength else { return .malformed }
        let receiver = readLE32(response, at: 8)
        guard receiver == session.senderIndex else { return .notOurs }

        // mac1 on the way back is keyed with OUR public key: a reply that can't
        // produce it wasn't computed by anyone who knows we exist.
        let expectedMAC1 = mac1(over: Array(response[0..<responseMAC1Offset]),
                                peerPublicKey: session.localPublic)
        guard OpenVPNControlPacket.constantTimeEqual(
            expectedMAC1, Array(response[responseMAC1Offset..<(responseMAC1Offset + 16)]))
        else { return .notOurs }

        let peerEphemeral = Array(response[12..<44])
        let encryptedEmpty = Array(response[44..<60])
        guard let ephemeralPublic = try? Curve25519.KeyAgreement.PublicKey(rawRepresentation: Data(peerEphemeral))
        else { return .malformed }

        var chainingKey = kdf1(session.chainingKey, peerEphemeral)
        var hash = BLAKE2s.hash([session.hash, peerEphemeral])
        guard let dh1 = try? agree(session.ephemeralPrivate, ephemeralPublic),
              let dh2 = try? agree(session.staticPrivate, ephemeralPublic)
        else { return .authenticationFailed }
        chainingKey = kdf1(chainingKey, dh1)
        chainingKey = kdf1(chainingKey, dh2)

        let (ck, tau, key) = kdf3(chainingKey, session.presharedKey)
        _ = ck
        hash = BLAKE2s.hash([hash, tau])
        guard let plaintext = open(key: key, counter: 0, ciphertext: encryptedEmpty, aad: hash),
              plaintext.isEmpty
        else { return .authenticationFailed }
        return .accepted
    }

    // MARK: Noise primitives

    private static func agree(_ priv: Curve25519.KeyAgreement.PrivateKey,
                              _ pub: Curve25519.KeyAgreement.PublicKey) throws -> [UInt8] {
        do {
            let secret = try priv.sharedSecretFromKeyAgreement(with: pub)
            return secret.withUnsafeBytes { Array($0) }
        } catch {
            throw HandshakeError.keyAgreementFailed
        }
    }

    static func kdf1(_ chainingKey: [UInt8], _ input: [UInt8]) -> [UInt8] {
        let tau0 = BLAKE2s.hmac(key: chainingKey, data: [input])
        return BLAKE2s.hmac(key: tau0, data: [[0x01]])
    }

    static func kdf2(_ chainingKey: [UInt8], _ input: [UInt8]) -> ([UInt8], [UInt8]) {
        let tau0 = BLAKE2s.hmac(key: chainingKey, data: [input])
        let tau1 = BLAKE2s.hmac(key: tau0, data: [[0x01]])
        let tau2 = BLAKE2s.hmac(key: tau0, data: [tau1, [0x02]])
        return (tau1, tau2)
    }

    static func kdf3(_ chainingKey: [UInt8], _ input: [UInt8]) -> ([UInt8], [UInt8], [UInt8]) {
        let tau0 = BLAKE2s.hmac(key: chainingKey, data: [input])
        let tau1 = BLAKE2s.hmac(key: tau0, data: [[0x01]])
        let tau2 = BLAKE2s.hmac(key: tau0, data: [tau1, [0x02]])
        let tau3 = BLAKE2s.hmac(key: tau0, data: [tau2, [0x03]])
        return (tau1, tau2, tau3)
    }

    /// ChaCha20-Poly1305 with WireGuard's nonce shape: four zero bytes then the
    /// counter, little-endian.
    static func nonce(_ counter: UInt64) -> [UInt8] {
        [0, 0, 0, 0] + (0..<8).map { UInt8(truncatingIfNeeded: counter >> (8 * UInt64($0))) }
    }

    static func seal(key: [UInt8], counter: UInt64, plaintext: [UInt8], aad: [UInt8]) -> [UInt8]? {
        guard let n = try? ChaChaPoly.Nonce(data: Data(nonce(counter))),
              let box = try? ChaChaPoly.seal(Data(plaintext),
                                             using: SymmetricKey(data: Data(key)),
                                             nonce: n, authenticating: Data(aad))
        else { return nil }
        return Array(box.ciphertext) + Array(box.tag)
    }

    static func open(key: [UInt8], counter: UInt64, ciphertext: [UInt8], aad: [UInt8]) -> [UInt8]? {
        guard ciphertext.count >= 16,
              let n = try? ChaChaPoly.Nonce(data: Data(nonce(counter))) else { return nil }
        let body = Data(ciphertext.prefix(ciphertext.count - 16))
        let tag = Data(ciphertext.suffix(16))
        guard let box = try? ChaChaPoly.SealedBox(nonce: n, ciphertext: body, tag: tag),
              let plain = try? ChaChaPoly.open(box, using: SymmetricKey(data: Data(key)),
                                               authenticating: Data(aad))
        else { return nil }
        return Array(plain)
    }

    /// TAI64N: 8 bytes of TAI seconds (Unix epoch + 2^62 + 10 leap seconds) then
    /// 4 bytes of nanoseconds, both big-endian. A server rejects a timestamp
    /// older than the last one it saw from this peer, so it must be real.
    static func tai64n(_ date: Date) -> [UInt8] {
        let interval = date.timeIntervalSince1970
        let seconds = UInt64(interval.rounded(.down)) &+ 0x4000_0000_0000_000A
        let nanos = UInt32((interval - interval.rounded(.down)) * 1_000_000_000)
        var out: [UInt8] = []
        for shift in stride(from: 56, through: 0, by: -8) {
            out.append(UInt8(truncatingIfNeeded: seconds >> UInt64(shift)))
        }
        for shift in stride(from: 24, through: 0, by: -8) {
            out.append(UInt8(truncatingIfNeeded: nanos >> UInt32(shift)))
        }
        return out
    }

    static func le32(_ v: UInt32) -> [UInt8] {
        [UInt8(truncatingIfNeeded: v), UInt8(truncatingIfNeeded: v >> 8),
         UInt8(truncatingIfNeeded: v >> 16), UInt8(truncatingIfNeeded: v >> 24)]
    }

    static func readLE32(_ bytes: [UInt8], at offset: Int) -> UInt32 {
        guard bytes.count >= offset + 4 else { return 0 }
        return UInt32(bytes[offset]) | (UInt32(bytes[offset + 1]) << 8)
             | (UInt32(bytes[offset + 2]) << 16) | (UInt32(bytes[offset + 3]) << 24)
    }
}
