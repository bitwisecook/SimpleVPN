// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
//  VPNProbeTests.swift
//  The VPN fingerprint probes hinge on exact packet layouts (OpenVPN control
//  reset, IKE_SA_INIT header) and banner classification — the pieces that must
//  be right regardless of the live network. Only the pure builders/parsers are
//  tested here; the socket exchanges aren't.
//

import Testing
@testable import SimpleVPN

struct VPNProbeTests {

    // MARK: OpenVPN control-channel reset

    @Test func openVPNResetPacketLayout() {
        let sid: [UInt8] = [1, 2, 3, 4, 5, 6, 7, 8]
        let p = VPNProbe.openVPNResetPacket(sessionID: sid)
        // First byte: opcode (P_CONTROL_HARD_RESET_CLIENT_V2 = 7) in the top 5
        // bits, key id in the low 3.
        #expect(p[0] >> 3 == 7)
        #expect(p[0] & 0x07 == 0)
        // The 8-byte session id follows the opcode byte.
        #expect(Array(p[1..<9]) == sid)
    }

    @Test func openVPNResetGeneratesSessionWhenWrongLength() {
        let p = VPNProbe.openVPNResetPacket(sessionID: [0, 1])   // too short
        #expect(p.count >= 9)
        #expect(p[0] >> 3 == 7)
    }

    @Test func parseOpenVPNServerReply() {
        let ourSID: [UInt8] = [9, 9, 9, 9, 9, 9, 9, 9]
        // A server hard-reset-v2 (opcode 8) with its own session id, echoing ours.
        let serverSID: [UInt8] = [0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x11, 0x22]
        var packet: [UInt8] = [(8 << 3) | 0]
        packet += serverSID
        packet += [0]            // ack array length
        packet += ourSID         // echoed remote session id
        let reply = VPNProbe.parseOpenVPNReply(packet, sentSessionID: ourSID, framed: false)
        #expect(reply?.opcode == 8)
        #expect(reply?.serverSessionID == serverSID)
        #expect(reply?.echoesOurSession == true)
    }

    @Test func parseOpenVPNRejectsGarbage() {
        // Random UDP noise: opcode 0 is not a valid control opcode.
        #expect(VPNProbe.parseOpenVPNReply([0x00, 1, 2, 3, 4, 5, 6, 7, 8],
                                           sentSessionID: [], framed: false) == nil)
        // Too short to hold opcode + session id.
        #expect(VPNProbe.parseOpenVPNReply([0x40, 1, 2], sentSessionID: [], framed: false) == nil)
    }

    @Test func parseOpenVPNFramedTCP() {
        let serverSID: [UInt8] = [1, 1, 1, 1, 1, 1, 1, 1]
        var body: [UInt8] = [(8 << 3)]
        body += serverSID
        let framed = VPNProbe.openVPNTCPFramed(body)
        // The 2-byte length prefix must equal the body length.
        #expect(Int(framed[0]) << 8 | Int(framed[1]) == body.count)
        let reply = VPNProbe.parseOpenVPNReply(framed, sentSessionID: [], framed: true)
        #expect(reply?.opcode == 8)
        #expect(reply?.serverSessionID == serverSID)
    }

    // MARK: IKEv2

    @Test func ikeSAInitEchoAndParse() {
        let spi: [UInt8] = [0xDE, 0xAD, 0xBE, 0xEF, 0x00, 0x11, 0x22, 0x33]
        let packet = VPNProbe.ikeSAInit(initiatorSPI: spi)
        // The initiator SPI is the first 8 bytes of the IKE header.
        #expect(Array(packet.prefix(8)) == spi)
        // Build a plausible responder reply: same initiator SPI, a responder SPI,
        // and the response bit set in the flags byte (offset 19).
        var reply = packet
        let responderSPI: [UInt8] = [1, 2, 3, 4, 5, 6, 7, 8]
        for i in 0..<8 { reply[8 + i] = responderSPI[i] }
        reply[19] |= 0x20   // response flag
        let parsed = VPNProbe.parseIKEReply(reply, initiatorSPI: spi)
        #expect(parsed?.responderSPI == responderSPI)
        #expect(parsed?.isResponse == true)
        #expect(parsed?.matchesInitiator == true)
    }

    @Test func parseIKEFlagsWrongInitiatorSPI() {
        // A well-formed IKE header that ISN'T our conversation still parses, but
        // matchesInitiator is false — the probe uses that to reject it.
        let spi: [UInt8] = [1, 1, 1, 1, 1, 1, 1, 1]
        var reply = VPNProbe.ikeSAInit(initiatorSPI: spi)
        reply[0] = 0xFF   // corrupt the echoed initiator SPI
        #expect(VPNProbe.parseIKEReply(reply, initiatorSPI: spi)?.matchesInitiator == false)
    }

    // MARK: SSL-VPN vendor classification

    @Test func classifyFortinet() {
        let g = VPNProbe.classifySSLVPN(head: "HTTP/1.1 302 Found\r\nLocation: /remote/login\r\nSet-Cookie: SVPNCOOKIE=x")
        #expect(g?.kind == .fortinet)
    }
    @Test func classifyF5() {
        let g = VPNProbe.classifySSLVPN(head: "HTTP/1.1 302\r\nLocation: /my.policy\r\nSet-Cookie: MRHSession=abc")
        #expect(g?.kind == .f5apm)
    }
    @Test func classifyGlobalProtect() {
        let g = VPNProbe.classifySSLVPN(head: "HTTP/1.1 200\r\nLocation: /global-protect/login.esp")
        #expect(g?.kind == .globalProtect)
    }
    @Test func classifyAnyConnect() {
        let g = VPNProbe.classifySSLVPN(head: "HTTP/1.1 200\r\n", certSubject: "CN=vpn.example.com", certIssuer: "webvpn portal /+CSCOE+/logon.html")
        #expect(g?.kind == .ciscoAnyConnect)
    }
    @Test func classifyByCertSubject() {
        // Nothing in the HTTP head, but the cert subject names the vendor.
        let g = VPNProbe.classifySSLVPN(head: "HTTP/1.1 200 OK\r\n", certSubject: "CN=fortinet-fw, O=Fortinet")
        #expect(g?.kind == .fortinet)
    }
    @Test func classifyUnknownIsNil() {
        #expect(VPNProbe.classifySSLVPN(head: "HTTP/1.1 200 OK\r\nServer: nginx\r\n") == nil)
    }

    // MARK: SSH banner

    @Test func parseSSHBanner() {
        let b = VPNProbe.parseSSHBanner("SSH-2.0-OpenSSH_9.6 Ubuntu-3\r\n")
        #expect(b?.protocolVersion == "2.0")
        #expect(b?.software == "OpenSSH_9.6")
        #expect(b?.comment == "Ubuntu-3")
    }
    @Test func parseSSHBannerNoComment() {
        let b = VPNProbe.parseSSHBanner("SSH-2.0-dropbear_2022.83\n")
        #expect(b?.software == "dropbear_2022.83")
        #expect(b?.comment == nil)
    }
    @Test func parseSSHBannerSkipsPreamble() {
        // Some servers emit a text banner before the SSH- line.
        let b = VPNProbe.parseSSHBanner("Welcome!\r\nUnauthorized use prohibited\r\nSSH-2.0-OpenSSH_8.9\r\n")
        #expect(b?.software == "OpenSSH_8.9")
    }
    @Test func parseSSHBannerRejectsNonSSH() {
        #expect(VPNProbe.parseSSHBanner("220 smtp.example.com ESMTP\r\n") == nil)
    }

    // MARK: HTTP header extraction

    @Test func headerValue() {
        let head = "HTTP/1.1 200 OK\r\nServer: FortiGate\r\nSet-Cookie: SVPNCOOKIE=abc; Path=/\r\n"
        #expect(VPNProbe.headerValue("server", in: head) == "FortiGate")
        #expect(VPNProbe.headerValue("set-cookie", in: head)?.hasPrefix("SVPNCOOKIE") == true)
        #expect(VPNProbe.headerValue("x-missing", in: head) == nil)
    }
}
