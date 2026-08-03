// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
//  KeePassXCCrypto.swift
//  NaCl crypto_box (X25519 + XSalsa20-Poly1305) in pure Swift — the cipher the
//  keepassxc-browser protocol speaks, and nothing else in Apple's stack speaks
//  for us: CryptoKit has Curve25519 but no XSalsa20 and no standalone Poly1305
//  (its ChaChaPoly is the IETF ChaCha20 construction, a different cipher).
//  Vendoring libsodium for two primitives would drag a C build into the app
//  target, and the Go archives' x/crypto copy is unreachable without routing
//  every protocol message through a helper process — so the ~200 lines live
//  here instead: Salsa20's core is 4 operations in a loop, Poly1305 is the
//  well-trodden donna-32 arithmetic, and both are pinned end-to-end against
//  vectors generated from golang.org/x/crypto (the reference NaCl port) plus
//  the RFC 8439 Poly1305 vector in KeePassXCCryptoTests.
//
//  Key agreement stays CryptoKit's (Curve25519.KeyAgreement, which also
//  rejects low-order results the way libsodium does); this file adds the
//  HSalsa20 key derivation that turns the raw X25519 secret into
//  crypto_box_beforenm's shared key, and the secretbox seal/open around it.
//

import CryptoKit
import Foundation

/// NaCl's crypto_box/crypto_secretbox, shaped for the KeePassXC session:
/// derive one shared key per connection (`sharedKey`), then seal/open every
/// message with fresh 24-byte nonces.
nonisolated enum NaClBox {

    /// crypto_secretbox: 16-byte Poly1305 tag followed by the XSalsa20
    /// ciphertext. The tag is computed over the ciphertext (encrypt-then-MAC),
    /// keyed by the keystream's first 32 bytes — NaCl's construction exactly.
    static func seal(_ plaintext: Data, nonce: Data, sharedKey: Data) -> Data? {
        guard nonce.count == 24, sharedKey.count == 32 else { return nil }
        let subkey = hsalsa20(key: [UInt8](sharedKey), input: [UInt8](nonce.prefix(16)))
        let stream = salsa20Stream(key: subkey, nonce: [UInt8](nonce.suffix(8)),
                                   count: 32 + plaintext.count)
        let message = [UInt8](plaintext)
        var cipher = [UInt8](repeating: 0, count: message.count)
        for i in 0..<message.count { cipher[i] = message[i] ^ stream[32 + i] }
        let tag = poly1305(message: cipher, key: [UInt8](stream[0..<32]))
        return Data(tag) + Data(cipher)
    }

    /// crypto_secretbox_open: nil for anything that doesn't authenticate —
    /// a wrong key, a reused/mismatched nonce, or a tampered byte all land
    /// here rather than producing garbage plaintext.
    static func open(_ box: Data, nonce: Data, sharedKey: Data) -> Data? {
        guard nonce.count == 24, sharedKey.count == 32, box.count >= 16 else { return nil }
        let subkey = hsalsa20(key: [UInt8](sharedKey), input: [UInt8](nonce.prefix(16)))
        let cipher = [UInt8](box.dropFirst(16))
        let stream = salsa20Stream(key: subkey, nonce: [UInt8](nonce.suffix(8)),
                                   count: 32 + cipher.count)
        let expected = poly1305(message: cipher, key: [UInt8](stream[0..<32]))
        // Constant-time compare: an early-out would leak how much of a forged
        // tag was right.
        var diff: UInt8 = 0
        let given = [UInt8](box.prefix(16))
        for i in 0..<16 { diff |= expected[i] ^ given[i] }
        guard diff == 0 else { return nil }
        var plain = [UInt8](repeating: 0, count: cipher.count)
        for i in 0..<cipher.count { plain[i] = cipher[i] ^ stream[32 + i] }
        return Data(plain)
    }

    /// crypto_box_beforenm: X25519 (CryptoKit) then HSalsa20 with a zero
    /// input, yielding the symmetric key both sides seal with. Throws when
    /// CryptoKit rejects the peer key (malformed, or a low-order point whose
    /// agreement would be all zeros).
    static func sharedKey(peerPublicKey: Data,
                          privateKey: Curve25519.KeyAgreement.PrivateKey) throws -> Data {
        let peer = try Curve25519.KeyAgreement.PublicKey(rawRepresentation: peerPublicKey)
        let raw = try privateKey.sharedSecretFromKeyAgreement(with: peer)
        let rawBytes = raw.withUnsafeBytes { [UInt8]($0) }
        return Data(hsalsa20(key: rawBytes, input: [UInt8](repeating: 0, count: 16)))
    }

    /// libsodium's sodium_increment: the response to a request carrying nonce
    /// N must arrive under N+1 (little-endian). Verifying that binds each
    /// reply to its request — a replayed or cross-wired reply won't open.
    static func incremented(nonce: Data) -> Data {
        var bytes = [UInt8](nonce)
        var carry: UInt16 = 1
        for i in 0..<bytes.count {
            carry += UInt16(bytes[i])
            bytes[i] = UInt8(carry & 0xff)
            carry >>= 8
        }
        return Data(bytes)
    }

    // MARK: - Salsa20

    /// "expand 32-byte k" — Salsa20's diagonal constants.
    private static let sigma: [UInt32] = [0x6170_7865, 0x3320_646e, 0x7962_2d32, 0x6b20_6574]

    /// The Salsa20 core: 20 rounds of quarter-rounds over a 4×4 word state.
    /// Returns the mixed state WITHOUT the final feed-forward addition — the
    /// caller adds it for the stream cipher and skips it for HSalsa20 (that
    /// omission is what makes HSalsa20 a PRF usable for key derivation).
    private static func salsaCore(_ input: [UInt32]) -> [UInt32] {
        func rotl(_ v: UInt32, _ n: UInt32) -> UInt32 { (v << n) | (v >> (32 - n)) }
        var x = input
        for _ in 0..<10 {  // 10 double-rounds = 20 rounds
            // Column round.
            x[4] ^= rotl(x[0] &+ x[12], 7);  x[8] ^= rotl(x[4] &+ x[0], 9)
            x[12] ^= rotl(x[8] &+ x[4], 13); x[0] ^= rotl(x[12] &+ x[8], 18)
            x[9] ^= rotl(x[5] &+ x[1], 7);   x[13] ^= rotl(x[9] &+ x[5], 9)
            x[1] ^= rotl(x[13] &+ x[9], 13); x[5] ^= rotl(x[1] &+ x[13], 18)
            x[14] ^= rotl(x[10] &+ x[6], 7); x[2] ^= rotl(x[14] &+ x[10], 9)
            x[6] ^= rotl(x[2] &+ x[14], 13); x[10] ^= rotl(x[6] &+ x[2], 18)
            x[3] ^= rotl(x[15] &+ x[11], 7); x[7] ^= rotl(x[3] &+ x[15], 9)
            x[11] ^= rotl(x[7] &+ x[3], 13); x[15] ^= rotl(x[11] &+ x[7], 18)
            // Row round.
            x[1] ^= rotl(x[0] &+ x[3], 7);   x[2] ^= rotl(x[1] &+ x[0], 9)
            x[3] ^= rotl(x[2] &+ x[1], 13);  x[0] ^= rotl(x[3] &+ x[2], 18)
            x[6] ^= rotl(x[5] &+ x[4], 7);   x[7] ^= rotl(x[6] &+ x[5], 9)
            x[4] ^= rotl(x[7] &+ x[6], 13);  x[5] ^= rotl(x[4] &+ x[7], 18)
            x[11] ^= rotl(x[10] &+ x[9], 7); x[8] ^= rotl(x[11] &+ x[10], 9)
            x[9] ^= rotl(x[8] &+ x[11], 13); x[10] ^= rotl(x[9] &+ x[8], 18)
            x[12] ^= rotl(x[15] &+ x[14], 7); x[13] ^= rotl(x[12] &+ x[15], 9)
            x[14] ^= rotl(x[13] &+ x[12], 13); x[15] ^= rotl(x[14] &+ x[13], 18)
        }
        return x
    }

    private static func load32(_ bytes: [UInt8], _ offset: Int) -> UInt32 {
        UInt32(bytes[offset]) | UInt32(bytes[offset + 1]) << 8
            | UInt32(bytes[offset + 2]) << 16 | UInt32(bytes[offset + 3]) << 24
    }

    private static func store32(_ value: UInt32, into bytes: inout [UInt8], _ offset: Int) {
        bytes[offset] = UInt8(value & 0xff)
        bytes[offset + 1] = UInt8((value >> 8) & 0xff)
        bytes[offset + 2] = UInt8((value >> 16) & 0xff)
        bytes[offset + 3] = UInt8((value >> 24) & 0xff)
    }

    /// HSalsa20(key, input): the un-added Salsa20 core with the output read
    /// from the words the feed-forward wouldn't have touched with secrets
    /// (the diagonal constants and the input positions).
    static func hsalsa20(key: [UInt8], input: [UInt8]) -> [UInt8] {
        precondition(key.count == 32 && input.count == 16)
        var state = [UInt32](repeating: 0, count: 16)
        state[0] = sigma[0]; state[5] = sigma[1]; state[10] = sigma[2]; state[15] = sigma[3]
        for i in 0..<4 {
            state[1 + i] = load32(key, i * 4)
            state[11 + i] = load32(key, 16 + i * 4)
            state[6 + i] = load32(input, i * 4)
        }
        let z = salsaCore(state)
        var out = [UInt8](repeating: 0, count: 32)
        for (i, word) in [z[0], z[5], z[10], z[15], z[6], z[7], z[8], z[9]].enumerated() {
            store32(word, into: &out, i * 4)
        }
        return out
    }

    /// Salsa20 keystream: 64-byte blocks under an 8-byte nonce and a little-
    /// endian 64-bit block counter starting at 0 (block 0's first 32 bytes are
    /// secretbox's Poly1305 key; encryption starts at byte 32).
    static func salsa20Stream(key: [UInt8], nonce: [UInt8], count: Int) -> [UInt8] {
        precondition(key.count == 32 && nonce.count == 8)
        var out = [UInt8](repeating: 0, count: count)
        var state = [UInt32](repeating: 0, count: 16)
        state[0] = sigma[0]; state[5] = sigma[1]; state[10] = sigma[2]; state[15] = sigma[3]
        for i in 0..<4 {
            state[1 + i] = load32(key, i * 4)
            state[11 + i] = load32(key, 16 + i * 4)
        }
        state[6] = load32(nonce, 0)
        state[7] = load32(nonce, 4)
        var counter: UInt64 = 0
        var offset = 0
        while offset < count {
            state[8] = UInt32(truncatingIfNeeded: counter)
            state[9] = UInt32(truncatingIfNeeded: counter >> 32)
            let z = salsaCore(state)
            var block = [UInt8](repeating: 0, count: 64)
            for i in 0..<16 { store32(z[i] &+ state[i], into: &block, i * 4) }
            let n = min(64, count - offset)
            out.replaceSubrange(offset..<(offset + n), with: block[0..<n])
            offset += n
            counter += 1
        }
        return out
    }

    // MARK: - Poly1305

    /// Poly1305 one-time authenticator (donna-32 arithmetic: five 26-bit limbs
    /// so every product fits a UInt64). `key` is 32 bytes: r (clamped) ‖ pad.
    static func poly1305(message: [UInt8], key: [UInt8]) -> [UInt8] {
        precondition(key.count == 32)
        // r with the clamping NaCl requires (mask the bits that would make
        // the schoolbook reduction overflow).
        let r0 = load32(key, 0) & 0x3ffffff
        let r1 = (load32(key, 3) >> 2) & 0x3ffff03
        let r2 = (load32(key, 6) >> 4) & 0x3ffc0ff
        let r3 = (load32(key, 9) >> 6) & 0x3f03fff
        let r4 = (load32(key, 12) >> 8) & 0x00fffff
        let s1 = r1 &* 5, s2 = r2 &* 5, s3 = r3 &* 5, s4 = r4 &* 5

        var h0: UInt32 = 0, h1: UInt32 = 0, h2: UInt32 = 0, h3: UInt32 = 0, h4: UInt32 = 0
        var index = 0
        while index < message.count {
            let remaining = message.count - index
            var block = [UInt8](repeating: 0, count: 17)
            let n = min(16, remaining)
            for i in 0..<n { block[i] = message[index + i] }
            // The 2^128 "high bit" every full block carries; a short final
            // block instead gets a 0x01 terminator inside the block.
            block[n] = n == 16 ? 0 : 1
            let hibit: UInt32 = n == 16 ? (1 << 24) : 0

            h0 &+= load32(block, 0) & 0x3ffffff
            h1 &+= (load32(block, 3) >> 2) & 0x3ffffff
            h2 &+= (load32(block, 6) >> 4) & 0x3ffffff
            h3 &+= (load32(block, 9) >> 6) & 0x3ffffff
            h4 &+= (load32(block, 12) >> 8) | hibit

            // h *= r, reduced mod 2^130 - 5 (the *5 folds the high limbs back).
            func mul(_ a: UInt32, _ b: UInt32) -> UInt64 { UInt64(a) &* UInt64(b) }
            let d0 = mul(h0, r0) &+ mul(h1, s4) &+ mul(h2, s3) &+ mul(h3, s2) &+ mul(h4, s1)
            var d1 = mul(h0, r1) &+ mul(h1, r0) &+ mul(h2, s4) &+ mul(h3, s3) &+ mul(h4, s2)
            var d2 = mul(h0, r2) &+ mul(h1, r1) &+ mul(h2, r0) &+ mul(h3, s4) &+ mul(h4, s3)
            var d3 = mul(h0, r3) &+ mul(h1, r2) &+ mul(h2, r1) &+ mul(h3, r0) &+ mul(h4, s4)
            var d4 = mul(h0, r4) &+ mul(h1, r3) &+ mul(h2, r2) &+ mul(h3, r1) &+ mul(h4, r0)

            var c = UInt32(truncatingIfNeeded: d0 >> 26); h0 = UInt32(truncatingIfNeeded: d0) & 0x3ffffff
            d1 &+= UInt64(c); c = UInt32(truncatingIfNeeded: d1 >> 26); h1 = UInt32(truncatingIfNeeded: d1) & 0x3ffffff
            d2 &+= UInt64(c); c = UInt32(truncatingIfNeeded: d2 >> 26); h2 = UInt32(truncatingIfNeeded: d2) & 0x3ffffff
            d3 &+= UInt64(c); c = UInt32(truncatingIfNeeded: d3 >> 26); h3 = UInt32(truncatingIfNeeded: d3) & 0x3ffffff
            d4 &+= UInt64(c); c = UInt32(truncatingIfNeeded: d4 >> 26); h4 = UInt32(truncatingIfNeeded: d4) & 0x3ffffff
            h0 &+= c &* 5; c = h0 >> 26; h0 &= 0x3ffffff
            h1 &+= c

            index += n
        }

        // Freeze: fully reduce h, then pick h or h - (2^130 - 5) without
        // branching on the secret.
        var c = h1 >> 26; h1 &= 0x3ffffff
        h2 &+= c; c = h2 >> 26; h2 &= 0x3ffffff
        h3 &+= c; c = h3 >> 26; h3 &= 0x3ffffff
        h4 &+= c; c = h4 >> 26; h4 &= 0x3ffffff
        h0 &+= c &* 5; c = h0 >> 26; h0 &= 0x3ffffff
        h1 &+= c

        var g0 = h0 &+ 5; c = g0 >> 26; g0 &= 0x3ffffff
        var g1 = h1 &+ c; c = g1 >> 26; g1 &= 0x3ffffff
        var g2 = h2 &+ c; c = g2 >> 26; g2 &= 0x3ffffff
        var g3 = h3 &+ c; c = g3 >> 26; g3 &= 0x3ffffff
        let g4 = h4 &+ c &- (1 << 26)

        let mask = (g4 >> 31) &- 1  // all-ones when h >= 2^130 - 5
        h0 = (h0 & ~mask) | (g0 & mask)
        h1 = (h1 & ~mask) | (g1 & mask)
        h2 = (h2 & ~mask) | (g2 & mask)
        h3 = (h3 & ~mask) | (g3 & mask)
        h4 = (h4 & ~mask) | (g4 & mask)

        // Serialize back to 128 bits and add the pad (key[16..32]) with carry.
        let t0 = h0 | (h1 << 26)
        let t1 = (h1 >> 6) | (h2 << 20)
        let t2 = (h2 >> 12) | (h3 << 14)
        let t3 = (h3 >> 18) | (h4 << 8)
        var f: UInt64 = 0
        var tag = [UInt8](repeating: 0, count: 16)
        for (i, t) in [t0, t1, t2, t3].enumerated() {
            f = UInt64(t) &+ UInt64(load32(key, 16 + i * 4)) &+ (f >> 32)
            store32(UInt32(truncatingIfNeeded: f), into: &tag, i * 4)
        }
        return tag
    }
}
