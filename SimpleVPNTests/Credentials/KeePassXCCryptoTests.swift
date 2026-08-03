// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
//  KeePassXCCryptoTests.swift
//  Pins the pure-Swift NaCl (KeePassXCCrypto.swift) against the reference
//  implementation: every expected value below was generated with
//  golang.org/x/crypto v0.54.0 (curve25519 / salsa20/salsa / nacl/secretbox /
//  nacl/box — the same code KeePassXC-compatible Go clients use), plus the
//  Poly1305 vector from RFC 8439 §2.5.2. The box vectors use the classic NaCl
//  test keypair, whose beforenm result (1b2755…8389) is itself the most-
//  published shared key in cryptography — a wrong X25519 or HSalsa20 step
//  cannot produce it.
//

import Foundation
import CryptoKit
import Testing
@testable import SimpleVPN

private func hex(_ s: String) -> Data {
    var out = Data()
    var iterator = s.makeIterator()
    while let a = iterator.next(), let b = iterator.next() {
        out.append(UInt8(String([a, b]), radix: 16)!)
    }
    return out
}

struct KeePassXCCryptoTests {

    // MARK: - HSalsa20 (key derivation)

    @Test func hsalsa20MatchesReference() {
        let key = hex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
        let input = hex("000102030405060708090a0b0c0d0e0f")
        let out = NaClBox.hsalsa20(key: [UInt8](key), input: [UInt8](input))
        #expect(Data(out) == hex("f2a52d7cea2bb6babc32b07f89e22487a063c2481084ff41b8190fb7839d501c"))
    }

    @Test func hsalsa20ZeroInputMatchesReference() {
        // The crypto_box_beforenm shape: zero input over the raw X25519 secret.
        let key = hex("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
        let out = NaClBox.hsalsa20(key: [UInt8](key), input: [UInt8](repeating: 0, count: 16))
        #expect(Data(out) == hex("50088706d3e1cee8a5c0f12504d968443211cf12af4a4b49e5c874b3ef4f85e7"))
    }

    // MARK: - Salsa20 keystream

    @Test func salsa20KeystreamMatchesReference() {
        let key = hex("0f62b5085bae0154a7fa4da0f34699ec3f92e5388bde3184d72a7dd02376c91c")
        let nonce = hex("288ff65dc42b92f9")
        let stream = NaClBox.salsa20Stream(key: [UInt8](key), nonce: [UInt8](nonce), count: 64)
        #expect(Data(stream) == hex(
            "5e5e71f90199340304abb22a37b6625bf883fb89ce3b21f54a10b81066ef87da"
            + "30b77699aa7379da595c77dd59542da208e5954f89e40eb7aa80a84a6176663f"))
    }

    // MARK: - Poly1305 (RFC 8439 §2.5.2)

    @Test func poly1305MatchesRFC8439() {
        let key = hex("85d6be7857556d337f4452fe42d506a80103808afb0db2fd4abff6af4149f51b")
        let message = [UInt8]("Cryptographic Forum Research Group".utf8)
        let tag = NaClBox.poly1305(message: message, key: [UInt8](key))
        #expect(Data(tag) == hex("a8061dc1305136c6c22b8baf0c0127a9"))
    }

    // MARK: - secretbox (XSalsa20-Poly1305)

    // The classic NaCl shared key + nonce; plaintext = 131 bytes of i*7.
    private var sbKey: Data { hex("1b27556473e985d462cd51197a9a46c76009549eac6474f206c4ee0844f68389") }
    private var sbNonce: Data { hex("69696ee955b62b73cd62bda875fc73d68219e0036b7a0b37") }
    private var sbPlain: Data { Data((0..<131).map { UInt8(($0 * 7) & 0xff) }) }
    private var sbSealed: Data {
        hex("0d9efcea9928a87431a0ff623486ce7430996a4f68caca9735bd05e18d4c18dc"
            + "6a6c9508d6bcc7d1a4a68ae3914e854fc5d49526576297704f7ffee8861fea12"
            + "4d59a06bd4d49497b23495ebf6347eb07a72c813c402d6168f272a37fdca84d0"
            + "42e32847cb98a401d74e46818ee4649d3dadf23f3e37e3f2c7df666f1cbed5e8"
            + "99c461bbfe875ea7f156b00f5ee760693dd52e")
    }

    @Test func secretboxSealMatchesReference() {
        #expect(NaClBox.seal(sbPlain, nonce: sbNonce, sharedKey: sbKey) == sbSealed)
    }

    @Test func secretboxSealSmallAndEmptyMatchReference() {
        let small = Data("KeePassXC handshake test".utf8)
        #expect(NaClBox.seal(small, nonce: sbNonce, sharedKey: sbKey) == hex(
            "28d670395f2d653e0fa46fbf88ddda2c7bfb010a159a93fe4ea22bcdb77309dd7b708ead2e4a2e04"))
        #expect(NaClBox.seal(Data(), nonce: sbNonce, sharedKey: sbKey) == hex(
            "2539121d8e234e652d651fa4c8cff880"))
    }

    @Test func secretboxOpensItsOwnSeal() {
        #expect(NaClBox.open(sbSealed, nonce: sbNonce, sharedKey: sbKey) == sbPlain)
    }

    @Test func tamperedBoxRefusesToOpen() {
        var sealed = sbSealed
        sealed[40] ^= 0x01                     // one ciphertext bit
        #expect(NaClBox.open(sealed, nonce: sbNonce, sharedKey: sbKey) == nil)
        var badTag = sbSealed
        badTag[0] ^= 0x01                      // one tag bit
        #expect(NaClBox.open(badTag, nonce: sbNonce, sharedKey: sbKey) == nil)
        let wrongNonce = NaClBox.incremented(nonce: sbNonce)
        #expect(NaClBox.open(sbSealed, nonce: wrongNonce, sharedKey: sbKey) == nil)
        #expect(NaClBox.open(Data([1, 2, 3]), nonce: sbNonce, sharedKey: sbKey) == nil)
    }

    // MARK: - crypto_box (Curve25519 + HSalsa20 → the same secretbox)

    @Test func boxSharedKeyMatchesReferenceBeforenm() throws {
        // Alice's secret key + Bob's public key from the NaCl test vectors;
        // beforenm must land on the published shared key (== sbKey above, so
        // the box seal equals the secretbox seal byte for byte).
        let aliceSecret = hex("77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a")
        let bobPublic = hex("de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f")
        let alice = try Curve25519.KeyAgreement.PrivateKey(rawRepresentation: aliceSecret)
        #expect(alice.publicKey.rawRepresentation
                == hex("8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a"))
        let shared = try NaClBox.sharedKey(peerPublicKey: bobPublic, privateKey: alice)
        #expect(shared == sbKey)
        #expect(NaClBox.seal(sbPlain, nonce: sbNonce, sharedKey: shared) == sbSealed)
    }

    @Test func boxRoundTripsBetweenFreshKeypairs() throws {
        let alice = Curve25519.KeyAgreement.PrivateKey()
        let bob = Curve25519.KeyAgreement.PrivateKey()
        let aliceShared = try NaClBox.sharedKey(
            peerPublicKey: bob.publicKey.rawRepresentation, privateKey: alice)
        let bobShared = try NaClBox.sharedKey(
            peerPublicKey: alice.publicKey.rawRepresentation, privateKey: bob)
        #expect(aliceShared == bobShared)   // crypto_box's symmetry
        let nonce = KeePassXCProtocol.freshNonce()
        let message = Data("associate please".utf8)
        let sealed = try #require(NaClBox.seal(message, nonce: nonce, sharedKey: aliceShared))
        #expect(NaClBox.open(sealed, nonce: nonce, sharedKey: bobShared) == message)
    }

    // MARK: - Nonce discipline

    @Test func nonceIncrementIsLittleEndianWithCarry() {
        #expect(NaClBox.incremented(nonce: Data([0, 0, 0])) == Data([1, 0, 0]))
        #expect(NaClBox.incremented(nonce: Data([0xff, 0, 0])) == Data([0, 1, 0]))
        #expect(NaClBox.incremented(nonce: Data([0xff, 0xff, 0])) == Data([0, 0, 1]))
        #expect(NaClBox.incremented(nonce: Data([0xff, 0xff, 0xff])) == Data([0, 0, 0]))
    }
}
