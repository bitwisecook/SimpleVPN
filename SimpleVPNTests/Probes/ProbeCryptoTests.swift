// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
//  ProbeCryptoTests.swift
//  The authenticated probes stand or fall on getting somebody else's wire
//  format exactly right, and a mistake there produces a confidently WRONG
//  verdict ("your key is wrong" when it isn't) — the worst possible failure for
//  a diagnostic. So: published test vectors where they exist (RFC 7693 for
//  BLAKE2s, the WireGuard chaining-key constant), and byte-level layout checks
//  plus verify-what-we-built round trips where they don't.
//

import Testing
import Foundation
@testable import SimpleVPN

// MARK: - BLAKE2s

struct BLAKE2sTests {

    private func hex(_ bytes: [UInt8]) -> String {
        bytes.map { String(format: "%02x", $0) }.joined()
    }
    private func bytes(_ hex: String) -> [UInt8] {
        stride(from: 0, to: hex.count, by: 2).map {
            let start = hex.index(hex.startIndex, offsetBy: $0)
            return UInt8(hex[start..<hex.index(start, offsetBy: 2)], radix: 16)!
        }
    }

    @Test func rfc7693AbcVector() {
        // RFC 7693 Appendix B.
        #expect(hex(BLAKE2s.hash(Array("abc".utf8)))
                == "508c5e8c327c14e2e1a72ba34eeb452f37458b209ed63a294d999b4c86675982")
    }

    @Test func emptyInputVector() {
        #expect(hex(BLAKE2s.hash([UInt8]()))
                == "69217a3079908094e11121d042354a7c1f55b6482ca1a51e1b250dfd1ed0eef9")
    }

    @Test func keyedVectorFromTheOfficialKnownAnswerTests() {
        // blake2s-kat: key = 00 01 … 1f, input = empty.
        let key = (0..<32).map { UInt8($0) }
        #expect(hex(BLAKE2s.hash([UInt8](), key: key))
                == "48a8997da407876b3d79c0d92325ad3b89cbb754d86ab71aee047ad345fd2c49")
    }

    @Test func streamingMatchesOneShotAcrossABlockBoundary() {
        // 64 bytes is exactly one block: the last-block flag has to land on the
        // finalise, not on the update that filled the buffer.
        for length in [0, 1, 63, 64, 65, 127, 128, 200] {
            let data = (0..<length).map { UInt8($0 % 251) }
            var streamed = BLAKE2s()
            for chunk in stride(from: 0, to: length, by: 7) {
                streamed.update(Array(data[chunk..<min(chunk + 7, length)]))
            }
            #expect(streamed.finalize() == BLAKE2s.hash(data), "length \(length)")
        }
    }

    @Test func shortDigestsAreSupported() {
        // mac1 is a 16-byte keyed digest, and that length is part of the
        // parameter block, so it must not be a truncation of the 32-byte one.
        let short = BLAKE2s.hash(Array("abc".utf8), digestLength: 16)
        let long = BLAKE2s.hash(Array("abc".utf8))
        #expect(short.count == 16)
        #expect(short != Array(long.prefix(16)))
    }

    @Test func hmacIsTheRFC2104ConstructionNotBlake2sKeying() {
        let key = (0..<32).map { UInt8($0) }
        let mac = BLAKE2s.hmac(key: key, data: [Array("abc".utf8)])
        #expect(mac.count == 32)
        #expect(mac != BLAKE2s.hash(Array("abc".utf8), key: key))
    }

    @Test func wireGuardChainingKeyConstant() {
        // BLAKE2s of the Noise construction string — the value every WireGuard
        // implementation starts from.
        #expect(hex(BLAKE2s.hash(Array(WireGuardHandshake.construction.utf8)))
                == "60e26daef327efc02ec335e2a025d2d016eb4206f87277f52d38d1988b78cd36")
    }
}

// MARK: - WireGuard handshake

struct WireGuardHandshakeTests {

    private static func key() -> String {
        Data((0..<32).map { _ in UInt8.random(in: 0...255) }).base64EncodedString()
    }

    @Test func initiationHasTheDocumentedShape() throws {
        let priv = Self.key()
        let peerPriv = Self.key()
        let peerPub = try #require(WireGuardHandshake.publicKey(forPrivateKey: peerPriv))
        let session = try WireGuardHandshake.makeInitiation(privateKey: priv, peerPublicKey: peerPub,
                                                            senderIndex: 0x0A0B0C0D)
        let m = session.message
        #expect(m.count == WireGuardHandshake.initiationLength)
        #expect(m[0] == WireGuardHandshake.MessageType.initiation.rawValue)
        #expect(Array(m[1..<4]) == [0, 0, 0])                        // reserved
        #expect(WireGuardHandshake.readLE32(m, at: 4) == 0x0A0B0C0D) // sender index, little-endian
        // mac2 is zero without a cookie.
        #expect(Array(m[132..<148]) == [UInt8](repeating: 0, count: 16))
    }

    @Test func mac1IsKeyedByTheOtherEndsPublicKey() throws {
        let peerPriv = Self.key()
        let peerPub = try #require(WireGuardHandshake.publicKey(forPrivateKey: peerPriv))
        let session = try WireGuardHandshake.makeInitiation(privateKey: Self.key(),
                                                            peerPublicKey: peerPub)
        let expected = WireGuardHandshake.mac1(
            over: Array(session.message[0..<WireGuardHandshake.initiationMAC1Offset]),
            peerPublicKey: Array(Data(base64Encoded: peerPub)!))
        #expect(Array(session.message[116..<132]) == expected)
        // …and a DIFFERENT public key must not produce the same mac1, or the
        // step would pass for a VPN we aren't configured for.
        let other = try #require(WireGuardHandshake.publicKey(forPrivateKey: Self.key()))
        let wrong = WireGuardHandshake.mac1(
            over: Array(session.message[0..<WireGuardHandshake.initiationMAC1Offset]),
            peerPublicKey: Array(Data(base64Encoded: other)!))
        #expect(wrong != expected)
    }

    @Test func twoInitiationsAreNeverIdentical() throws {
        let peerPub = try #require(WireGuardHandshake.publicKey(forPrivateKey: Self.key()))
        let priv = Self.key()
        let a = try WireGuardHandshake.makeInitiation(privateKey: priv, peerPublicKey: peerPub)
        let b = try WireGuardHandshake.makeInitiation(privateKey: priv, peerPublicKey: peerPub)
        #expect(a.message != b.message)
    }

    @Test func badKeysAreRefusedRatherThanGuessedAt() {
        #expect(throws: WireGuardHandshake.HandshakeError.badPrivateKey) {
            _ = try WireGuardHandshake.makeInitiation(privateKey: "not-a-key", peerPublicKey: "also-not")
        }
        let good = Self.key()
        #expect(throws: WireGuardHandshake.HandshakeError.badPeerPublicKey) {
            _ = try WireGuardHandshake.makeInitiation(privateKey: good, peerPublicKey: "short")
        }
    }

    @Test func responseCheckRejectsWhatIsNotOurs() throws {
        let peerPub = try #require(WireGuardHandshake.publicKey(forPrivateKey: Self.key()))
        let session = try WireGuardHandshake.makeInitiation(privateKey: Self.key(),
                                                            peerPublicKey: peerPub,
                                                            senderIndex: 42)
        // Right length and type, wrong receiver index.
        var response = [UInt8](repeating: 0, count: WireGuardHandshake.responseLength)
        response[0] = WireGuardHandshake.MessageType.response.rawValue
        let receiver = WireGuardHandshake.le32(43)
        for i in 0..<4 { response[8 + i] = receiver[i] }
        #expect(WireGuardHandshake.check(response: response, session: session) == .notOurs)

        // A cookie reply is a distinct, positive answer — it proves the far end
        // verified our mac1 — so it must not be lumped in with "malformed".
        var cookie = [UInt8](repeating: 0, count: 64)
        cookie[0] = WireGuardHandshake.MessageType.cookie.rawValue
        #expect(WireGuardHandshake.check(response: cookie, session: session) == .cookieReply)

        #expect(WireGuardHandshake.check(response: [9, 9, 9], session: session) == .malformed)
    }

    @Test func aResponseWithTheRightIndexButAForgedMAC1IsNotAccepted() throws {
        let peerPub = try #require(WireGuardHandshake.publicKey(forPrivateKey: Self.key()))
        let session = try WireGuardHandshake.makeInitiation(privateKey: Self.key(),
                                                            peerPublicKey: peerPub,
                                                            senderIndex: 7)
        var response = [UInt8](repeating: 0, count: WireGuardHandshake.responseLength)
        response[0] = WireGuardHandshake.MessageType.response.rawValue
        let receiver = WireGuardHandshake.le32(7)
        for i in 0..<4 { response[8 + i] = receiver[i] }
        #expect(WireGuardHandshake.check(response: response, session: session) == .notOurs)
    }

    @Test func timestampsAreTAI64NAndMoveForwards() {
        let now = Date(timeIntervalSince1970: 1_700_000_000)
        let stamp = WireGuardHandshake.tai64n(now)
        #expect(stamp.count == 12)
        // TAI64 label for a post-1970 second is 0x4000000000000000 + secs + 10.
        #expect(stamp[0] == 0x40)
        let later = WireGuardHandshake.tai64n(now.addingTimeInterval(60))
        #expect(later.lexicographicallyPrecedes(stamp) == false)
        #expect(later != stamp)
    }

    @Test func aeadNonceIsFourZeroesThenALittleEndianCounter() {
        #expect(WireGuardHandshake.nonce(0) == [UInt8](repeating: 0, count: 12))
        #expect(Array(WireGuardHandshake.nonce(1).prefix(5)) == [0, 0, 0, 0, 1])
    }

    @Test func aeadRoundTrips() throws {
        let key = (0..<32).map { _ in UInt8.random(in: 0...255) }
        let aad = Array("associated".utf8)
        let sealed = try #require(WireGuardHandshake.seal(key: key, counter: 0,
                                                          plaintext: Array("hello".utf8), aad: aad))
        #expect(WireGuardHandshake.open(key: key, counter: 0, ciphertext: sealed, aad: aad)
                == Array("hello".utf8))
        // A different AAD must not open — that is what binds the handshake hash.
        #expect(WireGuardHandshake.open(key: key, counter: 0, ciphertext: sealed,
                                        aad: Array("other".utf8)) == nil)
    }
}

// MARK: - OpenVPN control-channel wrapping

struct OpenVPNControlCryptoTests {

    /// A key whose two halves are IDENTICAL, so "what we send" and "what we
    /// expect back" use the same material and a self-check round trips.
    private static func symmetricKey(mode: OpenVPNStaticKey.Mode,
                                     digest: OpenVPNStaticKey.Digest = .sha1,
                                     direction: Int? = nil) -> OpenVPNStaticKey {
        let half = (0..<128).map { UInt8($0) }
        return OpenVPNStaticKey(bytes: half + half, mode: mode, direction: direction, digest: digest)
    }

    private static func distinctKey(mode: OpenVPNStaticKey.Mode,
                                    digest: OpenVPNStaticKey.Digest = .sha1,
                                    direction: Int?) -> OpenVPNStaticKey {
        let bytes = (0..<256).map { UInt8($0) }
        return OpenVPNStaticKey(bytes: bytes, mode: mode, direction: direction, digest: digest)
    }

    // MARK: Parsing

    @Test func parsesAStaticKeyBlock() {
        let hex = String(repeating: "0f", count: 256)
        let body = """
        -----BEGIN OpenVPN Static key V1-----
        \(hex)
        -----END OpenVPN Static key V1-----
        """
        let parsed = OpenVPNStaticKey.parseKeyBody(body)
        #expect(parsed?.count == 256)
        #expect(parsed?.allSatisfy { $0 == 0x0f } == true)
    }

    @Test func refusesAKeyOfTheWrongLength() {
        // Padding a short key would produce a confident, wrong "your key is bad".
        #expect(OpenVPNStaticKey.parseKeyBody("-----BEGIN OpenVPN Static key V1-----\nabcd\n") == nil)
    }

    @Test func readsModeDirectionAndDigestFromTheProfile() {
        let ovpn = """
        client
        auth SHA256
        key-direction 1
        <tls-auth>
        -----BEGIN OpenVPN Static key V1-----
        \(String(repeating: "ab", count: 256))
        -----END OpenVPN Static key V1-----
        </tls-auth>
        """
        let key = OpenVPNStaticKey(profile: ovpn)
        #expect(key?.mode == .tlsAuth)
        #expect(key?.direction == 1)
        #expect(key?.digest == .sha256)
    }

    @Test func tlsCryptAlwaysUsesSHA256() {
        let ovpn = """
        client
        auth SHA1
        <tls-crypt>
        -----BEGIN OpenVPN Static key V1-----
        \(String(repeating: "cd", count: 256))
        -----END OpenVPN Static key V1-----
        </tls-crypt>
        """
        #expect(OpenVPNStaticKey(profile: ovpn)?.digest == .sha256)
    }

    @Test func aProfileWithNoStaticKeyHasNone() {
        #expect(OpenVPNStaticKey(profile: "client\nremote vpn.example.org 1194\n") == nil)
    }

    // MARK: Key direction

    @Test func keyDirectionPicksTheSendingHalf() {
        // OpenVPN: direction 1 (the normal client setting) sends with key 1 and
        // receives with key 0; direction 0 is the reverse; absent is key 0 both ways.
        let inverse = Self.distinctKey(mode: .tlsAuth, direction: 1)
        #expect(inverse.outboundKeyIndex == 1)
        #expect(inverse.inboundKeyIndex == 0)
        let normal = Self.distinctKey(mode: .tlsAuth, direction: 0)
        #expect(normal.outboundKeyIndex == 0)
        #expect(normal.inboundKeyIndex == 1)
        let both = Self.distinctKey(mode: .tlsAuth, direction: nil)
        #expect(both.outboundKeyIndex == 0)
        #expect(both.inboundKeyIndex == 0)
    }

    @Test func tlsCryptIgnoresKeyDirection() {
        // tls-crypt fixes the client at "send with key 1"; a stray key-direction
        // line in the profile must not move it.
        let key = Self.distinctKey(mode: .tlsCrypt, direction: 0)
        #expect(key.outboundKeyIndex == 1)
        #expect(key.inboundKeyIndex == 0)
    }

    @Test func hmacKeyComesFromTheSecondHalfOfEachKey() {
        let key = Self.distinctKey(mode: .tlsAuth, digest: .sha1, direction: 1)
        // key 1's hmac half starts at 128 + 64 = 192, truncated to the digest length.
        #expect(key.hmacKey(index: 1) == (192..<212).map { UInt8($0) })
        #expect(key.cipherKey(index: 1) == (128..<160).map { UInt8($0) })
    }

    @Test func evidenceNeverContainsAByteOfTheKey() {
        let key = Self.distinctKey(mode: .tlsAuth, direction: 1)
        let joined = key.evidence.joined(separator: " ")
        #expect(joined.contains("TLS-Auth"))
        #expect(!joined.contains("ff"))
        #expect(!joined.lowercased().contains("beef"))
    }

    // MARK: tls-auth packet layout

    @Test func tlsAuthResetHasTheDocumentedLayout() {
        let key = Self.symmetricKey(mode: .tlsAuth, digest: .sha1)
        let session: [UInt8] = [1, 2, 3, 4, 5, 6, 7, 8]
        let packet = OpenVPNControlPacket.tlsAuthReset(key: key, sessionID: session,
                                                       packetID: 1, netTime: 0x1122_3344)
        // opcode/key-id, session id, HMAC, packet-id, net-time, ack-count, msg packet-id
        #expect(packet.count == 1 + 8 + 20 + 4 + 4 + 1 + 4)
        #expect(packet[0] >> 3 == VPNProbe.openVPNResetClientV2)
        #expect(Array(packet[1..<9]) == session)
        #expect(Array(packet[29..<33]) == [0, 0, 0, 1])              // packet id
        #expect(Array(packet[33..<37]) == [0x11, 0x22, 0x33, 0x44])  // net time
        #expect(packet[37] == 0)                                      // no acknowledgements
    }

    @Test func theHMACCoversPacketIdThenHeaderThenBody() {
        let key = Self.symmetricKey(mode: .tlsAuth, digest: .sha256)
        let session: [UInt8] = [9, 9, 9, 9, 9, 9, 9, 9]
        let packet = OpenVPNControlPacket.tlsAuthReset(key: key, sessionID: session,
                                                       packetID: 7, netTime: 100)
        let head = Array(packet[0..<9])
        let mac = Array(packet[9..<41])
        let rest = Array(packet[41...])
        let expected = OpenVPNHMAC.compute(.sha256, key: key.hmacKey(index: 0),
                                           message: Array(rest[0..<8]) + head + Array(rest[8...]))
        #expect(mac == expected)
    }

    @Test func aReplyWrappedWithTheSameKeyVerifies() {
        let key = Self.symmetricKey(mode: .tlsAuth, digest: .sha1)
        let packet = OpenVPNControlPacket.tlsAuthReset(key: key, sessionID: [1, 2, 3, 4, 5, 6, 7, 8],
                                                       netTime: 42)
        #expect(OpenVPNControlPacket.checkTLSAuthReply(packet, key: key)
                == .verified(opcode: VPNProbe.openVPNResetClientV2,
                             serverSessionID: [1, 2, 3, 4, 5, 6, 7, 8]))
    }

    @Test func aReplyWrappedWithADIFFERENTKeyDoesNotVerify() {
        let ours = Self.symmetricKey(mode: .tlsAuth, digest: .sha1)
        var otherBytes = (0..<128).map { UInt8($0 &+ 1) }
        otherBytes += otherBytes
        let theirs = OpenVPNStaticKey(bytes: otherBytes, mode: .tlsAuth, direction: nil, digest: .sha1)
        let packet = OpenVPNControlPacket.tlsAuthReset(key: theirs, sessionID: [1, 1, 1, 1, 1, 1, 1, 1],
                                                       netTime: 42)
        #expect(OpenVPNControlPacket.checkTLSAuthReply(packet, key: ours) == .wrapperMismatch)
    }

    @Test func theWrongDirectionLooksLikeTheWrongKey() {
        // The single commonest tls-auth misconfiguration: the right file, the
        // wrong key-direction. The check has to catch it.
        let key = Self.distinctKey(mode: .tlsAuth, direction: 1)
        let packet = OpenVPNControlPacket.tlsAuthReset(key: key, sessionID: [2, 2, 2, 2, 2, 2, 2, 2],
                                                       netTime: 42)
        // We sent with key 1; verifying a reply uses key 0, which must not match.
        #expect(OpenVPNControlPacket.checkTLSAuthReply(packet, key: key) == .wrapperMismatch)
    }

    @Test func garbageIsMalformedNotAKeyMismatch() {
        let key = Self.symmetricKey(mode: .tlsAuth)
        #expect(OpenVPNControlPacket.checkTLSAuthReply([1, 2, 3], key: key) == .malformed)
        // A valid length but an impossible opcode.
        var bogus = [UInt8](repeating: 0, count: 60)
        bogus[0] = 0x00                   // opcode 0 doesn't exist
        #expect(OpenVPNControlPacket.checkTLSAuthReply(bogus, key: key) == .malformed)
    }

    // MARK: tls-crypt

    @Test func tlsCryptResetHasTheDocumentedLayout() throws {
        let key = Self.symmetricKey(mode: .tlsCrypt, digest: .sha256)
        let session: [UInt8] = [1, 2, 3, 4, 5, 6, 7, 8]
        let packet = try #require(OpenVPNControlPacket.tlsCryptReset(
            key: key, sessionID: session, packetID: 1, netTime: 0x1122_3344))
        // header + session id + packet id + net time + tag + 5 encrypted bytes
        #expect(packet.count == 1 + 8 + 4 + 4 + 32 + 5)
        #expect(packet[0] >> 3 == VPNProbe.openVPNResetClientV2)
        #expect(Array(packet[1..<9]) == session)
        #expect(Array(packet[9..<13]) == [0, 0, 0, 1])
        #expect(Array(packet[13..<17]) == [0x11, 0x22, 0x33, 0x44])
        // The body is encrypted: the plaintext [0,0,0,0,0] must not appear.
        #expect(Array(packet[49...]) != [0, 0, 0, 0, 0])
    }

    @Test func tlsCryptRoundTrips() throws {
        let key = Self.symmetricKey(mode: .tlsCrypt, digest: .sha256)
        let packet = try #require(OpenVPNControlPacket.tlsCryptReset(
            key: key, sessionID: [7, 7, 7, 7, 7, 7, 7, 7], netTime: 9))
        #expect(OpenVPNControlPacket.checkTLSCryptReply(packet, key: key)
                == .verified(opcode: VPNProbe.openVPNResetClientV2,
                             serverSessionID: [7, 7, 7, 7, 7, 7, 7, 7]))
    }

    @Test func aTamperedTLSCryptPacketDoesNotVerify() throws {
        let key = Self.symmetricKey(mode: .tlsCrypt, digest: .sha256)
        var packet = try #require(OpenVPNControlPacket.tlsCryptReset(
            key: key, sessionID: [7, 7, 7, 7, 7, 7, 7, 7], netTime: 9))
        packet[50] ^= 0xff
        #expect(OpenVPNControlPacket.checkTLSCryptReply(packet, key: key) == .wrapperMismatch)
    }

    @Test func signedResetPicksTheRightFlavour() throws {
        let auth = Self.symmetricKey(mode: .tlsAuth, digest: .sha1)
        let crypt = Self.symmetricKey(mode: .tlsCrypt, digest: .sha256)
        let a = try #require(OpenVPNControlPacket.signedReset(key: auth, sessionID: [0, 1, 2, 3, 4, 5, 6, 7]))
        let c = try #require(OpenVPNControlPacket.signedReset(key: crypt, sessionID: [0, 1, 2, 3, 4, 5, 6, 7]))
        #expect(a.count == 1 + 8 + 20 + 4 + 4 + 5)
        #expect(c.count == 1 + 8 + 4 + 4 + 32 + 5)
    }

    // MARK: AES-CTR

    @Test func aesCTRIsItsOwnInverse() throws {
        let key = (0..<32).map { UInt8($0) }
        let iv = (0..<16).map { UInt8($0) }
        let plaintext = Array("the quick brown fox".utf8)
        let ciphertext = try #require(AESCTR.apply(key: key, iv: iv, data: plaintext))
        #expect(ciphertext != plaintext)
        #expect(ciphertext.count == plaintext.count)     // stream cipher: no padding
        #expect(AESCTR.apply(key: key, iv: iv, data: ciphertext) == plaintext)
    }

    @Test func aesCTRRefusesTheWrongKeyOrIVSize() {
        #expect(AESCTR.apply(key: [1, 2, 3], iv: (0..<16).map { UInt8($0) }, data: [0]) == nil)
        #expect(AESCTR.apply(key: (0..<32).map { UInt8($0) }, iv: [0], data: [0]) == nil)
    }

    @Test func constantTimeCompareIsLengthSafe() {
        #expect(OpenVPNControlPacket.constantTimeEqual([1, 2, 3], [1, 2, 3]))
        #expect(!OpenVPNControlPacket.constantTimeEqual([1, 2, 3], [1, 2]))
        #expect(!OpenVPNControlPacket.constantTimeEqual([1, 2, 3], [1, 2, 4]))
    }
}

// MARK: - IKEv2

struct ProbeIKETests {

    @Test func saInitCarriesTheProfilesOwnTransforms() {
        let proposal = ProbeIKE.Proposal.from(encryption: "aes256", integrity: "sha256", group: "19")
        #expect(proposal.encryptions.count == 1)
        #expect(proposal.keyExchangeGroup == .ecp256)
        let spi: [UInt8] = [1, 2, 3, 4, 5, 6, 7, 8]
        let message = ProbeIKE.saInit(initiatorSPI: spi, proposal: proposal)
        #expect(Array(message.prefix(8)) == spi)
        #expect(message[16] == 33)      // first payload: SA
        #expect(message[17] == 0x20)    // IKE version 2.0
        #expect(message[18] == 34)      // IKE_SA_INIT
        #expect(message[19] & 0x08 != 0)  // initiator flag
        // The declared length must match the bytes actually sent, or a gateway
        // discards the whole thing without a word.
        let declared = (Int(message[24]) << 24) | (Int(message[25]) << 16)
                     | (Int(message[26]) << 8) | Int(message[27])
        #expect(declared == message.count)
    }

    @Test func automaticSettingsOfferABroadProposal() {
        let proposal = ProbeIKE.Proposal.from(encryption: "", integrity: "", group: "")
        #expect(proposal.isAutomatic)
        #expect(proposal.encryptions.count > 1)
        #expect(proposal.groups.count > 1)
    }

    @Test func theKeyExchangeValueMatchesTheGroupItClaims() {
        for group in ProbeIKE.Group.allCases {
            #expect(group.keyExchangeValue().count == group.keyExchangeLength, "\(group)")
        }
    }

    @Test func natTraversalMessagesCarryTheNonESPMarker() {
        let message = ProbeIKE.saInit(initiatorSPI: [1, 1, 1, 1, 1, 1, 1, 1],
                                      proposal: .from(encryption: "aes256", integrity: "sha256", group: "14"),
                                      nonESPMarker: true)
        #expect(Array(message.prefix(4)) == [0, 0, 0, 0])
    }

    // MARK: Parsing

    /// A responder's IKE_SA_INIT reply carrying one chosen proposal.
    private func response(initiatorSPI: [UInt8], encryption: UInt16, keyBits: Int?,
                          prf: UInt16, integrity: UInt16, group: UInt16) -> [UInt8] {
        var transforms: [UInt8] = []
        transforms += ProbeIKE.transform(last: false, type: 1, id: encryption, keyLengthBits: keyBits)
        transforms += ProbeIKE.transform(last: false, type: 2, id: prf)
        transforms += ProbeIKE.transform(last: false, type: 3, id: integrity)
        transforms += ProbeIKE.transform(last: true, type: 4, id: group)
        var proposal: [UInt8] = [0, 0] + ProbeIKE.u16(8 + transforms.count) + [1, 1, 0, 4]
        proposal += transforms
        var sa: [UInt8] = [0, 0] + ProbeIKE.u16(4 + proposal.count)      // last payload
        sa += proposal
        var header: [UInt8] = initiatorSPI
        header += (0..<8).map { UInt8($0 + 1) }         // responder SPI
        header += [33, 0x20, 34, 0x20]                   // SA, v2.0, SA_INIT, response flag
        header += ProbeIKE.u32(0)
        header += ProbeIKE.u32(28 + sa.count)
        return header + sa
    }

    @Test func readsWhatTheGatewayChose() throws {
        let spi: [UInt8] = [8, 7, 6, 5, 4, 3, 2, 1]
        let raw = response(initiatorSPI: spi, encryption: 12, keyBits: 256,
                           prf: 5, integrity: 12, group: 19)
        let parsed = try #require(ProbeIKE.parse(raw, initiatorSPI: spi))
        #expect(parsed.isIKEv2)
        #expect(parsed.isResponse)
        #expect(parsed.matchesInitiator)
        #expect(parsed.agreed)
        #expect(parsed.chosenEncryption?.id == 12)
        #expect(parsed.chosenEncryption?.keyLengthBits == 256)
        #expect(parsed.chosenPRF == 5)
        #expect(parsed.chosenIntegrity == 12)
        #expect(parsed.chosenGroup == 19)
        #expect(ProbeIKE.encryptionName(id: 12, keyBits: 256) == "AES-CBC-256")
        #expect(ProbeIKE.groupName(19).contains("19"))
    }

    @Test func aReplyToSomebodyElseIsNotOurs() throws {
        let raw = response(initiatorSPI: [1, 1, 1, 1, 1, 1, 1, 1], encryption: 12, keyBits: 256,
                           prf: 5, integrity: 12, group: 14)
        let parsed = try #require(ProbeIKE.parse(raw, initiatorSPI: [2, 2, 2, 2, 2, 2, 2, 2]))
        #expect(!parsed.matchesInitiator)
    }

    /// The classic silent failure: the gateway names the group it wants.
    @Test func readsTheGroupTheGatewayAsksFor() throws {
        let spi: [UInt8] = [1, 2, 3, 4, 5, 6, 7, 8]
        var notify: [UInt8] = [0, 0, ProbeIKE.u16(Int(ProbeIKE.invalidKEPayload))[0],
                                     ProbeIKE.u16(Int(ProbeIKE.invalidKEPayload))[1]]
        notify += ProbeIKE.u16(19)                        // the group it wants
        var payload: [UInt8] = [0, 0] + ProbeIKE.u16(4 + notify.count)
        payload += notify
        var header: [UInt8] = spi
        header += (0..<8).map { UInt8($0 + 1) }
        header += [41, 0x20, 34, 0x20]                    // first payload: Notify
        header += ProbeIKE.u32(0)
        header += ProbeIKE.u32(28 + payload.count)
        let parsed = try #require(ProbeIKE.parse(header + payload, initiatorSPI: spi))
        #expect(!parsed.agreed)
        #expect(parsed.requestedGroup == 19)
        #expect(parsed.notifies.contains(ProbeIKE.invalidKEPayload))
    }

    @Test func recognisesNoProposalChosen() throws {
        let spi: [UInt8] = [3, 3, 3, 3, 3, 3, 3, 3]
        var notify: [UInt8] = [0, 0]
        notify += ProbeIKE.u16(Int(ProbeIKE.noProposalChosen))
        var payload: [UInt8] = [0, 0] + ProbeIKE.u16(4 + notify.count)
        payload += notify
        var header: [UInt8] = spi
        header += [UInt8](repeating: 0, count: 8)
        header += [41, 0x20, 34, 0x20]
        header += ProbeIKE.u32(0)
        header += ProbeIKE.u32(28 + payload.count)
        let parsed = try #require(ProbeIKE.parse(header + payload, initiatorSPI: spi))
        #expect(parsed.notifies == [ProbeIKE.noProposalChosen])
        #expect(ProbeIKE.notifyName(ProbeIKE.noProposalChosen) == "NO_PROPOSAL_CHOSEN")
    }

    @Test func rubbishIsRejected() {
        #expect(ProbeIKE.parse([1, 2, 3], initiatorSPI: []) == nil)
        // A plausible length but an impossible version nibble.
        var bogus = [UInt8](repeating: 0, count: 40)
        bogus[17] = 0x70
        #expect(ProbeIKE.parse(bogus, initiatorSPI: []) == nil)
    }

    @Test func profileStringsMapToTheRightTransforms() {
        #expect(ProbeIKE.Encryption.from("aes256")?.transformID == 12)
        #expect(ProbeIKE.Encryption.from("aes256gcm")?.transformID == 20)
        #expect(ProbeIKE.Encryption.from("nonsense") == nil)
        #expect(ProbeIKE.Integrity.from("sha512") == .sha512)
        #expect(ProbeIKE.Group.from("31") == .curve25519)
        #expect(ProbeIKE.Group.from("999") == nil)
    }
}
