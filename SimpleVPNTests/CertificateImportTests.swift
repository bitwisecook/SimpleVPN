// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
//  CertificateImportTests.swift
//  Pins the profile-rewriting rules (inline blocks replace file references,
//  round-trip cleanly, only one TLS-key flavor survives) and the PEM plumbing.
//

import Foundation
import Testing
@testable import SimpleVPN

struct CertificateImportTests {

    private let samplePEM = """
    -----BEGIN CERTIFICATE-----
    MIIBszCCAVmgAwIBAgIUfake+fake/fakefakefakefakefake=
    -----END CERTIFICATE-----
    """

    // MARK: OVPNInline

    @Test func setBlockInsertsAndBlockReadsBack() {
        let base = "client\nremote vpn.example.org 1194 udp\n"
        let updated = OVPNInline.setBlock("ca", content: samplePEM, in: base)
        #expect(OVPNInline.block("ca", in: updated) == samplePEM)
        #expect(updated.contains("<ca>") && updated.contains("</ca>"))
    }

    @Test func setBlockReplacesExistingBlock() {
        var ovpn = OVPNInline.setBlock("ca", content: "OLD", in: "client\n")
        ovpn = OVPNInline.setBlock("ca", content: "NEW", in: ovpn)
        #expect(OVPNInline.block("ca", in: ovpn) == "NEW")
        #expect(!ovpn.contains("OLD"))
        // Exactly one block remains.
        #expect(ovpn.components(separatedBy: "<ca>").count == 2)
    }

    @Test func setBlockRemovesFileReferenceDirective() {
        let base = "client\nca /etc/ssl/ca.crt\nremote a 1194\n"
        let updated = OVPNInline.setBlock("ca", content: samplePEM, in: base)
        #expect(!updated.contains("ca /etc/ssl/ca.crt"))
        #expect(OVPNInline.block("ca", in: updated) == samplePEM)
    }

    @Test func setBlockNilRemoves() {
        var ovpn = OVPNInline.setBlock("key", content: "SECRET", in: "client\n")
        ovpn = OVPNInline.setBlock("key", content: nil, in: ovpn)
        #expect(OVPNInline.block("key", in: ovpn) == nil)
        #expect(!ovpn.contains("SECRET"))
    }

    @Test func fileReferenceRemovalDoesNotEatOtherDirectives() {
        // "ca" removal must not remove "capath" or lines merely containing "ca".
        let base = "client\ncapath /etc\nca ca.crt\nlocal 1.2.3.4\n"
        let updated = OVPNInline.setBlock("ca", content: "X", in: base)
        #expect(updated.contains("capath /etc"))
        #expect(updated.contains("local 1.2.3.4"))
        #expect(!updated.contains("ca ca.crt"))
    }

    @Test func tlsKeyModeDetectsDirectiveAndBlock() {
        #expect(OVPNInline.tlsKeyMode(in: "tls-auth ta.key 1\n") == "tls-auth")
        #expect(OVPNInline.tlsKeyMode(in: "<tls-crypt>\nX\n</tls-crypt>\n") == "tls-crypt")
        #expect(OVPNInline.tlsKeyMode(in: "client\n") == nil)
    }

    @Test func keyDirectionFromDirectiveOrTlsAuthArgument() {
        #expect(OVPNInline.keyDirection(in: "key-direction 1\n") == "1")
        #expect(OVPNInline.keyDirection(in: "tls-auth ta.key 0\n") == "0")
        #expect(OVPNInline.keyDirection(in: "client\n") == nil)
    }

    @Test func slotBlockPrefersTlsCryptOverTlsAuth() {
        let ovpn = "<tls-crypt>\nA\n</tls-crypt>\n<tls-auth>\nB\n</tls-auth>\n"
        let found = OVPNInline.block(for: .tlsKey, in: ovpn)
        #expect(found?.tag == "tls-crypt")
        #expect(found?.content == "A")
    }

    // MARK: Sniffing & PEM

    @Test func sniffRecognizesPEMCertificateChains() {
        let two = samplePEM + "\n" + samplePEM
        guard case .certificates(_, let count) = CertificateImport.sniff(Data(two.utf8)) else {
            Issue.record("expected certificates"); return
        }
        #expect(count == 2)
    }

    @Test func sniffRecognizesPrivateKeysAndEncryption() {
        let plain = "-----BEGIN PRIVATE KEY-----\nAAAA\n-----END PRIVATE KEY-----"
        guard case .privateKey(_, let enc) = CertificateImport.sniff(Data(plain.utf8)) else {
            Issue.record("expected private key"); return
        }
        #expect(!enc)

        let encrypted = "-----BEGIN ENCRYPTED PRIVATE KEY-----\nAAAA\n-----END ENCRYPTED PRIVATE KEY-----"
        guard case .privateKey(_, let enc2) = CertificateImport.sniff(Data(encrypted.utf8)) else {
            Issue.record("expected encrypted private key"); return
        }
        #expect(enc2)
    }

    @Test func sniffRecognizesStaticKeysAndJunk() {
        let sk = "-----BEGIN OpenVPN Static key V1-----\n00ff\n-----END OpenVPN Static key V1-----"
        guard case .staticKey = CertificateImport.sniff(Data(sk.utf8)) else {
            Issue.record("expected static key"); return
        }
        guard case .unknown = CertificateImport.sniff(Data("hello world".utf8)) else {
            Issue.record("expected unknown"); return
        }
    }

    @Test func pemWrapProducesParseableBlocks() {
        let pem = CertificateImport.pemWrap(der: Data([0x30, 0x03, 0x01, 0x01, 0x00]), label: "CERTIFICATE")
        #expect(pem.hasPrefix("-----BEGIN CERTIFICATE-----"))
        #expect(pem.hasSuffix("-----END CERTIFICATE-----"))
        #expect(CertificateImport.pemBlocks(in: pem, label: "CERTIFICATE").count == 1)
        // Strict PEM (OpenSSL/OpenVPN): every marker starts its own line; no blanks.
        let lines = pem.components(separatedBy: "\n")
        #expect(lines.first == "-----BEGIN CERTIFICATE-----")
        #expect(lines.last == "-----END CERTIFICATE-----")
        #expect(!lines.contains(""))
    }

    @Test func pemWrapExactMultipleOf64HasNoBlankLine() {
        // 48 raw bytes → exactly 64 base64 chars → the lineLength64 encoder ends
        // with a newline; the wrapper must not leave a blank line before END.
        let pem = CertificateImport.pemWrap(der: Data(repeating: 0x42, count: 48), label: "CERTIFICATE")
        #expect(!pem.components(separatedBy: "\n").contains(""))
    }

    // MARK: CRLF round-trip (regression: setBlock left a duplicate on \r\n files)

    @Test func setBlockReplacesExistingBlockInCRLFProfile() {
        let base = "client\r\n<ca>\r\nOLD-CA\r\n</ca>\r\nremote vpn.example.org 1194 udp\r\n"
        let updated = OVPNInline.setBlock("ca", content: samplePEM, in: base)
        // Exactly one <ca> block — the old CRLF region must be found and removed.
        #expect(updated.components(separatedBy: "<ca>").count - 1 == 1)
        #expect(!updated.contains("OLD-CA"))
        #expect(OVPNInline.block("ca", in: updated) == samplePEM)
    }

    @Test func setBlockRemovesBlockInCRLFProfile() {
        let base = "client\r\n<tls-auth>\r\nKEYDATA\r\n</tls-auth>\r\n"
        let updated = OVPNInline.setBlock("tls-auth", content: nil, in: base)
        #expect(OVPNInline.block("tls-auth", in: updated) == nil)
        #expect(!updated.contains("KEYDATA"))
    }

    // MARK: key-direction preservation (regression: dropped when embedding tls-auth)

    @Test func setKeyDirectionAddsReplacesAndRemoves() {
        var s = OVPNInline.setKeyDirection("1", in: "client\nremote host 1194\n")
        #expect(OVPNInline.keyDirection(in: s) == "1")
        s = OVPNInline.setKeyDirection("0", in: s)                 // replace, not duplicate
        #expect(s.components(separatedBy: "key-direction").count - 1 == 1)
        #expect(OVPNInline.keyDirection(in: s) == "0")
        s = OVPNInline.setKeyDirection(nil, in: s)                 // remove (tls-crypt)
        #expect(!s.contains("key-direction"))
    }

    @Test func keyDirectionSurvivesTLSAuthFileRefToInline() {
        // "tls-auth ta.key 1" carries direction in its 3rd arg; reading it and
        // re-asserting it as a directive is what keeps inline tls-auth correct.
        let base = "client\ntls-auth ta.key 1\n"
        #expect(OVPNInline.keyDirection(in: base) == "1")
        let embedded = OVPNInline.setKeyDirection(OVPNInline.keyDirection(in: base) ?? "1",
                                                  in: OVPNInline.setBlock("tls-auth", content: samplePEM, in: base))
        #expect(OVPNInline.keyDirection(in: embedded) == "1")
        #expect(OVPNInline.block("tls-auth", in: embedded) == samplePEM)
    }
}
