// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
//  ProbeIKE.swift
//  An IKE_SA_INIT built from what the PROFILE actually asks for, and a parser
//  for what the gateway picks in reply.
//
//  Why this is worth doing properly rather than reusing the anonymous probe's
//  invented proposal: the commonest IPsec failure on a Mac is not "unreachable"
//  but "the gateway and macOS never agreed on a cipher". From the outside it
//  looks identical to a timeout — the gateway answers NO_PROPOSAL_CHOSEN (or
//  INVALID_KE_PAYLOAD naming the group it wants) and macOS reports nothing
//  useful. Offering exactly the profile's own transforms and printing the
//  gateway's answer turns that silence into a sentence.
//
//  Deliberately stops at IKE_SA_INIT. Going further (IKE_AUTH) means finishing
//  a real key agreement and leaving a half-open security association on the
//  gateway — a session nobody asked for, and one that on many gateways
//  contributes to sign-in counters. The ladder says so in plain words instead
//  of pretending.
//
//  Key exchange values: real public keys for the elliptic-curve groups (19, 20,
//  21, 31), because gateways validate those points and would reject a random
//  one for the wrong reason. The modular groups get random values of the right
//  size — nothing is ever derived from the answer.
//

import Foundation
import CryptoKit

nonisolated enum ProbeIKE {

    // MARK: Transform identifiers (RFC 7296 §3.3.2 and the IANA registry)

    enum Encryption: Sendable, Equatable {
        case aesCBC(bits: Int)
        case aesGCM16(bits: Int)
        case tripleDES
        case chacha20Poly1305

        var transformID: UInt16 {
            switch self {
            case .aesCBC: 12
            case .aesGCM16: 20
            case .tripleDES: 3
            case .chacha20Poly1305: 28
            }
        }
        var keyLengthBits: Int? {
            switch self {
            case .aesCBC(let b), .aesGCM16(let b): b
            case .tripleDES, .chacha20Poly1305: nil
            }
        }
        var label: String {
            switch self {
            case .aesCBC(let b): "AES-CBC-\(b)"
            case .aesGCM16(let b): "AES-GCM-\(b)"
            case .tripleDES: "3DES"
            case .chacha20Poly1305: "ChaCha20-Poly1305"
            }
        }
        /// NativeVPNConfig's `ikeEncryption` strings.
        static func from(_ s: String) -> Encryption? {
            switch s.lowercased() {
            case "aes128": .aesCBC(bits: 128)
            case "aes256": .aesCBC(bits: 256)
            case "aes128gcm": .aesGCM16(bits: 128)
            case "aes256gcm": .aesGCM16(bits: 256)
            case "3des": .tripleDES
            case "chacha20poly1305": .chacha20Poly1305
            default: nil
            }
        }
    }

    /// Integrity + the PRF that pairs with it. macOS's `ikeIntegrity` names the
    /// integrity algorithm; the PRF follows from the same hash.
    struct Integrity: Sendable, Equatable {
        var integrityID: UInt16
        var prfID: UInt16
        var label: String

        static let sha1 = Integrity(integrityID: 2, prfID: 2, label: "SHA1-96")
        static let sha256 = Integrity(integrityID: 12, prfID: 5, label: "SHA2-256-128")
        static let sha384 = Integrity(integrityID: 13, prfID: 6, label: "SHA2-384-192")
        static let sha512 = Integrity(integrityID: 14, prfID: 7, label: "SHA2-512-256")

        static func from(_ s: String) -> Integrity? {
            switch s.lowercased() {
            case "sha160", "sha1", "sha96": .sha1
            case "sha256": .sha256
            case "sha384": .sha384
            case "sha512": .sha512
            default: nil
            }
        }
    }

    /// Diffie-Hellman groups, with the size of the key-exchange value each needs.
    enum Group: UInt16, Sendable, CaseIterable {
        case modp1024 = 2
        case modp2048 = 14
        case modp3072 = 15
        case modp4096 = 16
        case ecp256 = 19
        case ecp384 = 20
        case ecp521 = 21
        case curve25519 = 31

        var keyExchangeLength: Int {
            switch self {
            case .modp1024: 128
            case .modp2048: 256
            case .modp3072: 384
            case .modp4096: 512
            case .ecp256: 64
            case .ecp384: 96
            case .ecp521: 132
            case .curve25519: 32
            }
        }
        var label: String {
            switch self {
            case .modp1024: "Group 2 (1024-bit)"
            case .modp2048: "Group 14 (2048-bit)"
            case .modp3072: "Group 15 (3072-bit)"
            case .modp4096: "Group 16 (4096-bit)"
            case .ecp256: "Group 19 (256-bit elliptic curve)"
            case .ecp384: "Group 20 (384-bit elliptic curve)"
            case .ecp521: "Group 21 (521-bit elliptic curve)"
            case .curve25519: "Group 31 (Curve25519)"
            }
        }
        static func from(_ s: String) -> Group? {
            guard let n = UInt16(s.trimmingCharacters(in: .whitespaces)) else { return nil }
            return Group(rawValue: n)
        }

        /// A key-exchange value the gateway will accept as well-formed. Real
        /// public keys where the group is a curve (they get validated); random
        /// bytes of the right length otherwise.
        func keyExchangeValue() -> [UInt8] {
            switch self {
            case .ecp256: return Array(P256.KeyAgreement.PrivateKey().publicKey.rawRepresentation)
            case .ecp384: return Array(P384.KeyAgreement.PrivateKey().publicKey.rawRepresentation)
            case .ecp521:
                var raw = Array(P521.KeyAgreement.PrivateKey().publicKey.rawRepresentation)
                // P-521 coordinates are 66 bytes each = 132; CryptoKit already
                // gives exactly that, but keep the contract explicit.
                if raw.count != keyExchangeLength {
                    raw = (0..<keyExchangeLength).map { _ in UInt8.random(in: 0...255) }
                }
                return raw
            case .curve25519:
                return Array(Curve25519.KeyAgreement.PrivateKey().publicKey.rawRepresentation)
            default:
                return (0..<keyExchangeLength).map { _ in UInt8.random(in: 0...255) }
            }
        }
    }

    /// What a profile asks for. Empty fields mean "Automatic", which is offered
    /// as a broad proposal — the same thing macOS itself does, so a gateway that
    /// rejects it would reject a real connection too.
    struct Proposal: Sendable, Equatable {
        var encryptions: [Encryption]
        var integrities: [Integrity]
        var groups: [Group]
        /// The group whose key-exchange value actually rides on the message.
        var keyExchangeGroup: Group

        var isAutomatic: Bool { encryptions.count > 1 || integrities.count > 1 }

        var label: String {
            let e = encryptions.map(\.label).joined(separator: " / ")
            let i = integrities.map(\.label).joined(separator: " / ")
            let g = groups.map(\.label).joined(separator: " / ")
            return "\(e) \u{00B7} \(i) \u{00B7} \(g)"
        }

        static func from(encryption: String, integrity: String, group: String) -> Proposal {
            let e = Encryption.from(encryption).map { [$0] }
                ?? [.aesGCM16(bits: 256), .aesCBC(bits: 256), .aesCBC(bits: 128)]
            let i = Integrity.from(integrity).map { [$0] } ?? [.sha256, .sha384, .sha1]
            let g = Group.from(group).map { [$0] } ?? [.ecp256, .modp2048, .modp1024]
            return Proposal(encryptions: e, integrities: i, groups: g,
                            keyExchangeGroup: g.first ?? .modp2048)
        }
    }

    // MARK: Building the request

    static func u16(_ v: Int) -> [UInt8] { [UInt8((v >> 8) & 0xff), UInt8(v & 0xff)] }
    static func u32(_ v: Int) -> [UInt8] {
        [UInt8((v >> 24) & 0xff), UInt8((v >> 16) & 0xff), UInt8((v >> 8) & 0xff), UInt8(v & 0xff)]
    }

    static func transform(last: Bool, type: UInt8, id: UInt16, keyLengthBits: Int? = nil) -> [UInt8] {
        var attributes: [UInt8] = []
        if let bits = keyLengthBits { attributes = [0x80, 0x0e] + u16(bits) }   // AF=1, type 14
        let length = 8 + attributes.count
        return [last ? 0 : 3, 0] + u16(length) + [type, 0] + u16(Int(id)) + attributes
    }

    static func saInit(initiatorSPI: [UInt8], proposal: Proposal,
                       nonESPMarker: Bool = false) -> [UInt8] {
        var transforms: [UInt8] = []
        var pieces: [[UInt8]] = []
        for e in proposal.encryptions {
            pieces.append(transform(last: false, type: 1, id: e.transformID, keyLengthBits: e.keyLengthBits))
        }
        for i in proposal.integrities {
            pieces.append(transform(last: false, type: 2, id: i.prfID))
        }
        // AEAD ciphers carry their own integrity, but offering the separate
        // transform as well is what every real initiator does and what gateways
        // expect to see alongside a CBC option.
        for i in proposal.integrities {
            pieces.append(transform(last: false, type: 3, id: i.integrityID))
        }
        for g in proposal.groups {
            pieces.append(transform(last: false, type: 4, id: g.rawValue))
        }
        var count = 0
        for (index, piece) in pieces.enumerated() {
            var p = piece
            if index == pieces.count - 1 { p[0] = 0 }       // last transform
            transforms += p
            count += 1
        }

        let proposalLength = 8 + transforms.count
        var proposalBytes: [UInt8] = [0, 0] + u16(proposalLength)
            + [1, 1, 0, UInt8(clamping: count)]
        proposalBytes += transforms

        var sa: [UInt8] = [34, 0] + u16(4 + proposalBytes.count)     // next: KE
        sa += proposalBytes

        let ke = proposal.keyExchangeGroup.keyExchangeValue()
        var kePayload: [UInt8] = [40, 0] + u16(8 + ke.count)          // next: Nonce
            + u16(Int(proposal.keyExchangeGroup.rawValue)) + [0, 0]
        kePayload += ke

        let nonce = (0..<32).map { _ in UInt8.random(in: 0...255) }
        var noncePayload: [UInt8] = [0, 0] + u16(4 + nonce.count)     // last payload
        noncePayload += nonce

        let body = sa + kePayload + noncePayload
        var spi = initiatorSPI
        if spi.count != 8 { spi = (0..<8).map { _ in UInt8.random(in: 0...255) } }

        var message: [UInt8] = spi
        message += [UInt8](repeating: 0, count: 8)      // responder SPI unknown
        message += [33]                                  // next payload: SA
        message += [0x20]                                // version 2.0
        message += [34]                                  // exchange: IKE_SA_INIT
        message += [0x08]                                // flags: Initiator
        message += u32(0)                                // message id
        message += u32(28 + body.count)
        message += body
        return nonESPMarker ? [0, 0, 0, 0] + message : message
    }

    // MARK: Reading the answer

    struct Response: Sendable, Equatable {
        var isIKEv2 = false
        var isResponse = false
        var matchesInitiator = false
        var exchangeType: UInt8 = 0
        var chosenEncryption: (id: UInt16, keyLengthBits: Int?)?
        var chosenPRF: UInt16?
        var chosenIntegrity: UInt16?
        var chosenGroup: UInt16?
        var notifies: [UInt16] = []
        /// The group the gateway wants, from an INVALID_KE_PAYLOAD notify.
        var requestedGroup: UInt16?
        var natDetectionOffered = false
        var cookieRequested = false

        var agreed: Bool { chosenEncryption != nil }

        static func == (a: Response, b: Response) -> Bool {
            a.isIKEv2 == b.isIKEv2 && a.isResponse == b.isResponse
                && a.matchesInitiator == b.matchesInitiator
                && a.exchangeType == b.exchangeType
                && a.chosenEncryption?.id == b.chosenEncryption?.id
                && a.chosenEncryption?.keyLengthBits == b.chosenEncryption?.keyLengthBits
                && a.chosenPRF == b.chosenPRF && a.chosenIntegrity == b.chosenIntegrity
                && a.chosenGroup == b.chosenGroup && a.notifies == b.notifies
                && a.requestedGroup == b.requestedGroup
                && a.natDetectionOffered == b.natDetectionOffered
                && a.cookieRequested == b.cookieRequested
        }
    }

    static let natDetectionSourceIP: UInt16 = 16388
    static let natDetectionDestinationIP: UInt16 = 16389
    static let cookieNotify: UInt16 = 16390
    static let noProposalChosen: UInt16 = 14
    static let invalidKEPayload: UInt16 = 17

    static func parse(_ raw: [UInt8], initiatorSPI: [UInt8], nonESPMarker: Bool = false) -> Response? {
        var bytes = raw
        if nonESPMarker {
            guard bytes.count > 4, Array(bytes[0..<4]) == [0, 0, 0, 0] else { return nil }
            bytes = Array(bytes.dropFirst(4))
        }
        guard bytes.count >= 28 else { return nil }
        var out = Response()
        out.matchesInitiator = Array(bytes[0..<8]) == initiatorSPI
        let version = bytes[17]
        out.isIKEv2 = (version >> 4) == 2
        guard (version >> 4) == 1 || (version >> 4) == 2 else { return nil }
        out.exchangeType = bytes[18]
        out.isResponse = bytes[19] & 0x20 != 0

        var next = bytes[16]
        var offset = 28
        while next != 0, offset + 4 <= bytes.count {
            let payloadNext = bytes[offset]
            let length = Int(bytes[offset + 2]) << 8 | Int(bytes[offset + 3])
            guard length >= 4, offset + length <= bytes.count else { break }
            let body = Array(bytes[(offset + 4)..<(offset + length)])
            switch next {
            case 33: parseSA(body, into: &out)
            case 34:
                if body.count >= 2 { out.chosenGroup = UInt16(body[0]) << 8 | UInt16(body[1]) }
            case 41: parseNotify(body, into: &out)
            default: break
            }
            next = payloadNext
            offset += length
        }
        return out
    }

    private static func parseSA(_ body: [UInt8], into out: inout Response) {
        // One proposal is all a response ever carries: the one it chose.
        var offset = 0
        while offset + 8 <= body.count {
            let length = Int(body[offset + 2]) << 8 | Int(body[offset + 3])
            guard length >= 8, offset + length <= body.count else { return }
            let spiSize = Int(body[offset + 6])
            var t = offset + 8 + spiSize
            let end = offset + length
            while t + 8 <= end {
                let tLength = Int(body[t + 2]) << 8 | Int(body[t + 3])
                guard tLength >= 8, t + tLength <= end else { return }
                let type = body[t + 4]
                let id = UInt16(body[t + 6]) << 8 | UInt16(body[t + 7])
                var keyBits: Int?
                var a = t + 8
                while a + 4 <= t + tLength {
                    let af = body[a] & 0x80
                    let attrType = (UInt16(body[a] & 0x7f) << 8) | UInt16(body[a + 1])
                    if af != 0 {
                        if attrType == 14 { keyBits = Int(body[a + 2]) << 8 | Int(body[a + 3]) }
                        a += 4
                    } else {
                        let vLength = Int(body[a + 2]) << 8 | Int(body[a + 3])
                        a += 4 + vLength
                    }
                }
                switch type {
                case 1: out.chosenEncryption = (id, keyBits)
                case 2: out.chosenPRF = id
                case 3: out.chosenIntegrity = id
                case 4: out.chosenGroup = id
                default: break
                }
                t += tLength
            }
            offset += length
        }
    }

    private static func parseNotify(_ body: [UInt8], into out: inout Response) {
        guard body.count >= 4 else { return }
        let spiSize = Int(body[1])
        let type = UInt16(body[2]) << 8 | UInt16(body[3])
        out.notifies.append(type)
        if type == natDetectionSourceIP || type == natDetectionDestinationIP {
            out.natDetectionOffered = true
        }
        if type == cookieNotify { out.cookieRequested = true }
        if type == invalidKEPayload {
            let dataStart = 4 + spiSize
            if body.count >= dataStart + 2 {
                out.requestedGroup = UInt16(body[dataStart]) << 8 | UInt16(body[dataStart + 1])
            }
        }
    }

    // MARK: Naming what came back

    static func encryptionName(id: UInt16, keyBits: Int?) -> String {
        let base: String
        switch id {
        case 3: base = "3DES"
        case 12: base = "AES-CBC"
        case 13: base = "AES-CTR"
        case 20: base = "AES-GCM"
        case 28: base = "ChaCha20-Poly1305"
        default: base = "encryption \(id)"
        }
        return keyBits.map { "\(base)-\($0)" } ?? base
    }

    static func integrityName(_ id: UInt16) -> String {
        switch id {
        case 0: "none"
        case 2: "SHA1-96"
        case 12: "SHA2-256-128"
        case 13: "SHA2-384-192"
        case 14: "SHA2-512-256"
        default: "integrity \(id)"
        }
    }

    static func prfName(_ id: UInt16) -> String {
        switch id {
        case 2: "SHA1"
        case 5: "SHA2-256"
        case 6: "SHA2-384"
        case 7: "SHA2-512"
        default: "PRF \(id)"
        }
    }

    static func groupName(_ id: UInt16) -> String {
        Group(rawValue: id)?.label ?? "group \(id)"
    }

    static func notifyName(_ id: UInt16) -> String {
        switch id {
        case 7: "INVALID_SYNTAX"
        case 14: "NO_PROPOSAL_CHOSEN"
        case 17: "INVALID_KE_PAYLOAD"
        case 24: "AUTHENTICATION_FAILED"
        case 16388, 16389: "NAT_DETECTION"
        case 16390: "COOKIE"
        default: "notify \(id)"
        }
    }
}
