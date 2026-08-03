// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
//  OpenVPNControlCrypto.swift
//  The one piece of OpenVPN a diagnostic tool genuinely has to reimplement: the
//  HMAC (`--tls-auth`) or authenticated encryption (`--tls-crypt`) wrapped
//  around the control channel's very first packet.
//
//  WHY. A server configured with tls-auth/tls-crypt discards an unsigned hello
//  in complete silence — no error, no ICMP, nothing. So the anonymous probe in
//  VPNProbe.swift reports "no OpenVPN answer" for a perfectly healthy server,
//  and a WRONG static key (or the wrong direction, or tls-auth where the server
//  wants tls-crypt) is indistinguishable from a firewall. That single ambiguity
//  is the most common "it just times out" support case there is. Signing the
//  hello with the profile's own key removes it: a reply proves the key, its
//  direction and its algorithm are all right; silence after a correctly-signed
//  hello narrows the problem to the key or the network, and nothing else.
//
//  Nothing here starts a session: one packet out, one packet in, and the socket
//  is closed. No account state is touched — a static key is reusable material,
//  which is why this side of the ladder may run automatically.
//
//  Layouts are from OpenVPN's own wire format (ssl_pkt.c / crypto.c):
//
//    tls-auth   [op|kid 1][session-id 8][HMAC n][packet-id 4][net-time 4]
//               [ack-count 1][acks…][remote session-id 8 if any][msg packet-id 4][payload]
//               HMAC input = packet-id ‖ net-time ‖ op|kid ‖ session-id ‖ (everything
//               after the HMAC field except the packet-id/net-time already counted)
//
//    tls-crypt  [op|kid 1][session-id 8][packet-id 4][net-time 4][tag 32][ciphertext]
//               tag = HMAC-SHA256(Ka, first-17-bytes ‖ plaintext)
//               ciphertext = AES-256-CTR(Ke, IV = tag[0..<16], plaintext)
//
//  Key layout: an OpenVPN static key file is 256 bytes = two `struct key`s of
//  {cipher[64], hmac[64]}. `--key-direction 1` (what a client normally uses)
//  means "send with key 1, receive with key 0"; 0 is the reverse; absent is
//  both-ways with key 0. tls-crypt fixes the client at direction 1 and ignores
//  any key-direction line.
//

import Foundation
import CryptoKit
import CommonCrypto

// MARK: - The static key

nonisolated struct OpenVPNStaticKey: Sendable, Equatable {

    enum Mode: String, Sendable, Equatable {
        case tlsAuth = "tls-auth"
        case tlsCrypt = "tls-crypt"

        /// Non-technical name, for a step's evidence line.
        var label: String {
            self == .tlsCrypt ? "TLS-Crypt (encrypts the handshake)"
                              : "TLS-Auth (signs the handshake)"
        }
    }

    /// The HMAC a tls-auth control channel uses. `--auth` picks it; SHA1 is
    /// OpenVPN's default and still the commonest in the wild.
    enum Digest: String, Sendable, Equatable, CaseIterable {
        case sha1, sha256, sha384, sha512, md5

        var length: Int {
            switch self {
            case .md5: 16
            case .sha1: 20
            case .sha256: 32
            case .sha384: 48
            case .sha512: 64
            }
        }
        var label: String {
            switch self {
            case .md5: "MD5"
            case .sha1: "SHA1"
            case .sha256: "SHA256"
            case .sha384: "SHA384"
            case .sha512: "SHA512"
            }
        }
        init?(directive: String) {
            switch directive.uppercased().replacingOccurrences(of: "-", with: "") {
            case "SHA1", "SHA": self = .sha1
            case "SHA256": self = .sha256
            case "SHA384": self = .sha384
            case "SHA512": self = .sha512
            case "MD5": self = .md5
            default: return nil
            }
        }
    }

    /// The 256 raw bytes of the key file.
    var bytes: [UInt8]
    var mode: Mode
    /// `key-direction`, when the profile states one. nil = bidirectional.
    var direction: Int?
    /// The `--auth` digest (tls-auth only; tls-crypt is always SHA256).
    var digest: Digest

    static let byteCount = 256
    static let keySize = 128        // one `struct key`
    static let cipherOffset = 0     // …its cipher half
    static let hmacOffset = 64      // …its hmac half

    // MARK: Parsing

    /// Pull the key out of an .ovpn's `<tls-auth>` / `<tls-crypt>` block,
    /// together with the direction and digest the same profile states.
    init?(profile ovpn: String) {
        guard let mode = OVPNInline.tlsKeyMode(in: ovpn).flatMap(Mode.init(rawValue:)),
              let block = OVPNInline.block(mode.rawValue, in: ovpn),
              let bytes = Self.parseKeyBody(block) else { return nil }
        self.bytes = bytes
        self.mode = mode
        self.direction = OVPNInline.keyDirection(in: ovpn).flatMap(Int.init)
        self.digest = mode == .tlsCrypt
            ? .sha256
            : (OVPNInline.directiveValue("auth", in: ovpn).flatMap(Digest.init(directive:)) ?? .sha1)
    }

    init(bytes: [UInt8], mode: Mode, direction: Int?, digest: Digest) {
        self.bytes = bytes
        self.mode = mode
        self.direction = direction
        self.digest = digest
    }

    /// The hex body of an "OpenVPN Static key V1" block → 256 bytes. Anything
    /// that isn't exactly 256 bytes is not a usable key and is refused rather
    /// than padded, because a short key would produce confidently wrong verdicts.
    static func parseKeyBody(_ text: String) -> [UInt8]? {
        var hex = ""
        for line in text.split(whereSeparator: \.isNewline) {
            let t = line.trimmingCharacters(in: .whitespacesAndNewlines)
            if t.isEmpty || t.hasPrefix("-----") || t.hasPrefix("#") { continue }
            hex += t
        }
        guard hex.count == byteCount * 2 else { return nil }
        var out: [UInt8] = []
        out.reserveCapacity(byteCount)
        var index = hex.startIndex
        while index < hex.endIndex {
            let next = hex.index(index, offsetBy: 2)
            guard let b = UInt8(hex[index..<next], radix: 16) else { return nil }
            out.append(b)
            index = next
        }
        return out
    }

    // MARK: Key selection

    /// Which of the two keys this side SENDS with. tls-crypt pins the client to
    /// key 1; tls-auth follows `key-direction` (1 → key 1, 0 → key 0, absent →
    /// key 0 both ways).
    var outboundKeyIndex: Int {
        if mode == .tlsCrypt { return 1 }
        return direction == 1 ? 1 : 0
    }
    /// …and which it RECEIVES with, so the server's answer can be checked too.
    var inboundKeyIndex: Int {
        if mode == .tlsCrypt { return 0 }
        switch direction {
        case 1: return 0
        case 0: return 1
        default: return 0
        }
    }

    func hmacKey(index: Int) -> [UInt8] {
        let start = index * Self.keySize + Self.hmacOffset
        return Array(bytes[start..<(start + digest.length)])
    }
    func cipherKey(index: Int) -> [UInt8] {
        let start = index * Self.keySize + Self.cipherOffset
        return Array(bytes[start..<(start + 32)])       // AES-256
    }

    /// Facts about the key that are safe to show: never any byte of it.
    var evidence: [String] {
        [
            "Control-channel protection: \(mode.label)",
            mode == .tlsAuth ? "HMAC: \(digest.label) (\(digest.length) bytes)" : "HMAC: SHA256, cipher AES-256-CTR",
            "Key direction: \(direction.map(String.init) ?? "not set (both ways)") \u{2014} sending with key \(outboundKeyIndex)",
        ]
    }
}

// MARK: - HMAC

nonisolated enum OpenVPNHMAC {
    static func compute(_ digest: OpenVPNStaticKey.Digest, key: [UInt8], message: [UInt8]) -> [UInt8] {
        let k = SymmetricKey(data: Data(key))
        let m = Data(message)
        switch digest {
        case .md5: return Array(CryptoKit.HMAC<Insecure.MD5>.authenticationCode(for: m, using: k))
        case .sha1: return Array(CryptoKit.HMAC<Insecure.SHA1>.authenticationCode(for: m, using: k))
        case .sha256: return Array(CryptoKit.HMAC<SHA256>.authenticationCode(for: m, using: k))
        case .sha384: return Array(CryptoKit.HMAC<SHA384>.authenticationCode(for: m, using: k))
        case .sha512: return Array(CryptoKit.HMAC<SHA512>.authenticationCode(for: m, using: k))
        }
    }
}

// MARK: - AES-256-CTR (tls-crypt)

/// CryptoKit has no CTR mode, so this is CommonCrypto. Encrypt and decrypt are
/// the same operation in CTR — one function serves both directions.
nonisolated enum AESCTR {
    static func apply(key: [UInt8], iv: [UInt8], data: [UInt8]) -> [UInt8]? {
        guard key.count == 32, iv.count == 16 else { return nil }
        var cryptor: CCCryptorRef?
        let created = key.withUnsafeBytes { keyBuf in
            iv.withUnsafeBytes { ivBuf in
                CCCryptorCreateWithMode(
                    CCOperation(kCCEncrypt), CCMode(kCCModeCTR), CCAlgorithm(kCCAlgorithmAES),
                    CCPadding(ccNoPadding), ivBuf.baseAddress, keyBuf.baseAddress, key.count,
                    nil, 0, 0, CCModeOptions(kCCModeOptionCTR_BE), &cryptor)
            }
        }
        guard created == kCCSuccess, let cryptor else { return nil }
        defer { CCCryptorRelease(cryptor) }
        let capacity = data.count
        var out = [UInt8](repeating: 0, count: capacity)
        var moved = 0
        let status = data.withUnsafeBytes { input in
            out.withUnsafeMutableBytes { output in
                CCCryptorUpdate(cryptor, input.baseAddress, capacity,
                                output.baseAddress, capacity, &moved)
            }
        }
        guard status == kCCSuccess, moved == data.count else { return nil }
        return out
    }
}

// MARK: - The signed hello

nonisolated enum OpenVPNControlPacket {

    /// Header byte: opcode in the top 5 bits, key id in the low 3.
    static func header(opcode: UInt8, keyID: UInt8 = 0) -> UInt8 {
        (opcode << 3) | (keyID & 0x07)
    }

    static func be32(_ v: UInt32) -> [UInt8] {
        [UInt8(truncatingIfNeeded: v >> 24), UInt8(truncatingIfNeeded: v >> 16),
         UInt8(truncatingIfNeeded: v >> 8), UInt8(truncatingIfNeeded: v)]
    }

    /// The body a HARD_RESET carries after the header: an empty acknowledgement
    /// array and this message's packet id.
    static func resetBody(messagePacketID: UInt32 = 0) -> [UInt8] {
        [0] + be32(messagePacketID)
    }

    /// A P_CONTROL_HARD_RESET_CLIENT_V2 wrapped for `--tls-auth`.
    static func tlsAuthReset(key: OpenVPNStaticKey, sessionID: [UInt8],
                             packetID: UInt32 = 1, netTime: UInt32) -> [UInt8] {
        precondition(sessionID.count == 8)
        let head: [UInt8] = [header(opcode: VPNProbe.openVPNResetClientV2)] + sessionID
        let pidBlock = be32(packetID) + be32(netTime)
        let body = resetBody()
        let mac = OpenVPNHMAC.compute(key.digest,
                                      key: key.hmacKey(index: key.outboundKeyIndex),
                                      message: pidBlock + head + body)
        return head + mac + pidBlock + body
    }

    /// A P_CONTROL_HARD_RESET_CLIENT_V2 wrapped for `--tls-crypt`.
    static func tlsCryptReset(key: OpenVPNStaticKey, sessionID: [UInt8],
                              packetID: UInt32 = 1, netTime: UInt32) -> [UInt8]? {
        precondition(sessionID.count == 8)
        let ad: [UInt8] = [header(opcode: VPNProbe.openVPNResetClientV2)] + sessionID
            + be32(packetID) + be32(netTime)
        let plaintext = resetBody()
        let tag = OpenVPNHMAC.compute(.sha256,
                                      key: key.hmacKey(index: key.outboundKeyIndex),
                                      message: ad + plaintext)
        guard let ciphertext = AESCTR.apply(key: key.cipherKey(index: key.outboundKeyIndex),
                                            iv: Array(tag.prefix(16)), data: plaintext)
        else { return nil }
        return ad + tag + ciphertext
    }

    /// Build the right flavour for the key. Returns nil only when the tls-crypt
    /// cipher can't be set up, which would be a platform fault, not the VPN's.
    static func signedReset(key: OpenVPNStaticKey, sessionID: [UInt8],
                            netTime: UInt32 = UInt32(truncatingIfNeeded: Int(Date().timeIntervalSince1970))) -> [UInt8]? {
        switch key.mode {
        case .tlsAuth: return tlsAuthReset(key: key, sessionID: sessionID, netTime: netTime)
        case .tlsCrypt: return tlsCryptReset(key: key, sessionID: sessionID, netTime: netTime)
        }
    }

    // MARK: Checking what came back

    enum ReplyCheck: Sendable, Equatable {
        /// The server answered AND its wrapper verified with our key: the key,
        /// its direction and its algorithm are all correct.
        case verified(opcode: UInt8, serverSessionID: [UInt8])
        /// It answered in the right shape but the HMAC/tag didn't verify — the
        /// key material differs, or the direction is inverted.
        case wrapperMismatch
        /// Not a control packet we can read at all.
        case malformed
    }

    /// Verify a tls-auth reply with the key we'd RECEIVE on.
    static func checkTLSAuthReply(_ bytes: [UInt8], key: OpenVPNStaticKey) -> ReplyCheck {
        let macLength = key.digest.length
        // header(1) + sid(8) + mac + pid(4) + time(4) + ack-count(1)
        guard bytes.count >= 1 + 8 + macLength + 4 + 4 + 1 else { return .malformed }
        let head = Array(bytes[0..<9])
        let opcode = head[0] >> 3
        guard (1...11).contains(opcode) else { return .malformed }
        let mac = Array(bytes[9..<(9 + macLength)])
        let rest = Array(bytes[(9 + macLength)...])          // pid ‖ time ‖ body
        guard rest.count >= 8 else { return .malformed }
        let pidBlock = Array(rest[0..<8])
        let body = Array(rest[8...])
        let expected = OpenVPNHMAC.compute(key.digest,
                                           key: key.hmacKey(index: key.inboundKeyIndex),
                                           message: pidBlock + head + body)
        guard constantTimeEqual(expected, mac) else { return .wrapperMismatch }
        return .verified(opcode: opcode, serverSessionID: Array(head[1..<9]))
    }

    /// Verify (and decrypt) a tls-crypt reply.
    static func checkTLSCryptReply(_ bytes: [UInt8], key: OpenVPNStaticKey) -> ReplyCheck {
        let adLength = 1 + 8 + 4 + 4
        let tagLength = 32
        guard bytes.count >= adLength + tagLength else { return .malformed }
        let opcode = bytes[0] >> 3
        guard (1...11).contains(opcode) else { return .malformed }
        let ad = Array(bytes[0..<adLength])
        let tag = Array(bytes[adLength..<(adLength + tagLength)])
        let ciphertext = Array(bytes[(adLength + tagLength)...])
        guard let plaintext = AESCTR.apply(key: key.cipherKey(index: key.inboundKeyIndex),
                                           iv: Array(tag.prefix(16)), data: ciphertext)
        else { return .malformed }
        let expected = OpenVPNHMAC.compute(.sha256,
                                           key: key.hmacKey(index: key.inboundKeyIndex),
                                           message: ad + plaintext)
        guard constantTimeEqual(expected, tag) else { return .wrapperMismatch }
        return .verified(opcode: opcode, serverSessionID: Array(bytes[1..<9]))
    }

    static func checkReply(_ bytes: [UInt8], key: OpenVPNStaticKey) -> ReplyCheck {
        switch key.mode {
        case .tlsAuth: return checkTLSAuthReply(bytes, key: key)
        case .tlsCrypt: return checkTLSCryptReply(bytes, key: key)
        }
    }

    /// Length-safe, branch-free-ish comparison. The values here aren't secret,
    /// but comparing MACs any other way is a habit worth not having.
    static func constantTimeEqual(_ a: [UInt8], _ b: [UInt8]) -> Bool {
        guard a.count == b.count else { return false }
        var diff: UInt8 = 0
        for i in a.indices { diff |= a[i] ^ b[i] }
        return diff == 0
    }
}
