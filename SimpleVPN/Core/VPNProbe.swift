// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
//  VPNProbe.swift
//  "What kind of VPN is actually answering at host:port?" — asked on the wire, in
//  the protocol's own first words, never by shelling out and never by guessing from
//  the port number alone. Five probes, each a single short exchange:
//
//    • OpenVPN  — a P_CONTROL_HARD_RESET_CLIENT_V2 (opcode 7 in the top 5 bits of
//      byte 0) with a random 8-byte session id. A real server answers with
//      P_CONTROL_HARD_RESET_SERVER_V2 (opcode 8) echoing our session id, which is a
//      *positive* identification: nothing else on the internet replies like that.
//    • IKEv2    — a well-formed IKE_SA_INIT (RFC 7296 §3.1) with an invented
//      initiator SPI. A responder answers with the same initiator SPI, response flag
//      set — even when it rejects our proposal (NO_PROPOSAL_CHOSEN is still an answer).
//    • SSL-VPN  — TLS, keep the certificate, then one HTTP GET / and read the vendor's
//      fingerprints out of the headers/redirect (SVPNCOOKIE, /my.policy, PanGP, +CSCOE+).
//    • SSH      — the server speaks first; its "SSH-2.0-…" banner names the software.
//    • WireGuard — deliberately WEAK, and labelled as such. WireGuard is silent to any
//      handshake it cannot authenticate (mac1 is keyed by the server's public key,
//      which we do not have), so "no reply" is *consistent with* WireGuard and with a
//      hundred other things. It is only ever reported as a maybe.
//
//  Everything here is unauthenticated, single-packet and read-only: no session is
//  established, nothing is sent that a server would act on. The app target is not
//  sandboxed, so plain POSIX sockets are used for the datagram/stream work (matching
//  NetworkProbes) and NWConnection only where TLS is needed.
//
//  Honesty rules, because a wrong verdict here sends someone down the wrong road:
//    • Silence is never a detection except in the explicitly-weak WireGuard case.
//    • A server running OpenVPN with --tls-auth / --tls-crypt drops our unsigned reset
//      without a word. "No OpenVPN answer" therefore means "no *unauthenticated*
//      answer", and the detail string says so.
//    • Port numbers are context, never evidence on their own.
//

import Foundation
import Darwin
import Network
import Security

nonisolated enum VPNProbe {

    // MARK: - Result shape

    /// How much weight a finding deserves. `high` is reserved for protocol-positive
    /// answers (the server spoke the protocol back at us).
    enum Confidence: Int, Sendable, Comparable, CaseIterable {
        case none = 0, low, medium, high
        static func < (a: Self, b: Self) -> Bool { a.rawValue < b.rawValue }
        var label: String {
            switch self {
            case .none: "no evidence"
            case .low: "weak evidence"
            case .medium: "good evidence"
            case .high: "confirmed"
            }
        }
    }

    /// One probe's verdict. `label` is the sentence a non-technical user reads;
    /// `detail` is the evidence behind it.
    struct Finding: Sendable, Identifiable, Equatable {
        var probe: String            // "OpenVPN over UDP" — also the identity
        var detected: Bool
        var label: String
        var detail: String
        var confidence: Confidence
        var kind: VPNKind?           // the protocol family, when we can name one
        var id: String { probe }
    }

    /// Which transport a probe should use. `.auto` means "try what makes sense".
    enum Transport: String, Sendable, CaseIterable, Identifiable {
        case auto, udp, tcp
        var id: String { rawValue }
        var label: String { self == .auto ? "Auto" : rawValue.uppercased() }

        /// Parse the loose protocol strings that come from .ovpn files and overrides
        /// ("udp", "tcp-client", "UDP4"…). Unknown → .auto, never a wrong guess.
        init(hint: String?) {
            let s = (hint ?? "").lowercased()
            if s.hasPrefix("tcp") { self = .tcp }
            else if s.hasPrefix("udp") { self = .udp }
            else { self = .auto }
        }
    }

    struct Fingerprint: Sendable {
        var host: String
        var port: Int
        var transport: Transport
        var findings: [Finding] = []
        /// Plain-language headline built by `fingerprint(...)`.
        var summary: String = ""
        /// The strongest positive identification, if any.
        var best: Finding? {
            findings.filter(\.detected).max { $0.confidence < $1.confidence }
        }
    }

    // MARK: - Top level

    /// Run the probes that make sense for `hint` (or a small battery when the kind is
    /// unknown) concurrently, and return the best match plus every raw result.
    ///
    /// `port` is the endpoint the profile would actually dial. The IKE probe is the
    /// one exception that may leave it: IKEv2 lives on UDP 500/4500 by convention and
    /// asking 443 for an IKE_SA_INIT tells us nothing.
    static func fingerprint(host: String, port: Int, proto: Transport,
                            hint: VPNKind?, timeout: TimeInterval = 3) async -> Fingerprint {
        var out = Fingerprint(host: host, port: port, transport: proto)
        let host = host.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !host.isEmpty else {
            out.summary = "No host to probe."
            return out
        }

        var findings: [Finding] = []
        await withTaskGroup(of: Finding?.self) { group in
            for probe in plan(host: host, port: port, proto: proto, hint: hint) {
                group.addTask { await probe.run(timeout) }
            }
            for await f in group { if let f { findings.append(f) } }
        }
        // Stable order: detections first, strongest first, then alphabetical — a task
        // group completes in whatever order the network allows, which would otherwise
        // reshuffle the list on every run.
        out.findings = findings.sorted {
            if $0.detected != $1.detected { return $0.detected }
            if $0.confidence != $1.confidence { return $0.confidence > $1.confidence }
            return $0.probe < $1.probe
        }
        out.summary = summarise(out, hint: hint)
        return out
    }

    /// A named unit of work, so `plan` can be a list rather than a pile of branches.
    private struct PlannedProbe {
        let run: @Sendable (TimeInterval) async -> Finding?
    }

    private static func plan(host: String, port: Int, proto: Transport,
                             hint: VPNKind?) -> [PlannedProbe] {
        var probes: [PlannedProbe] = []
        func openVPN(_ t: Transport) {
            probes.append(PlannedProbe { await probeOpenVPN(host: host, port: port, transport: t, timeout: $0) })
        }
        func wireGuard() {
            probes.append(PlannedProbe { await probeWireGuard(host: host, port: port, expected: hint == .wireGuard, timeout: $0) })
        }
        func ike(_ p: Int) {
            probes.append(PlannedProbe { await probeIKE(host: host, port: p, timeout: $0) })
        }
        func sslVPN(_ p: Int) {
            probes.append(PlannedProbe { await probeSSLVPN(host: host, port: p, timeout: max($0, 6)) })
        }
        func ssh(_ p: Int) {
            probes.append(PlannedProbe { await probeSSH(host: host, port: p, timeout: $0) })
        }

        switch hint {
        case .openVPN:
            if proto == .tcp { openVPN(.tcp) } else if proto == .udp { openVPN(.udp) } else { openVPN(.udp); openVPN(.tcp) }
        case .wireGuard:
            wireGuard()
        case .ikev2, .ipsec, .l2tp:
            ike(port == 443 || port == 0 ? 500 : port)
            if port != 500 { ike(500) }
        case .ssh:
            ssh(port == 0 ? 22 : port)
        case .some(let k) where k.isSSLVPN:
            sslVPN(port == 0 ? 443 : port)
        default:
            // Unknown: a small battery. Deliberately not exhaustive — every extra
            // probe is another 3 s of somebody's time and another chance to mislead.
            openVPN(.udp); openVPN(.tcp)
            sslVPN(port == 0 ? 443 : port)
            ssh(port == 22 ? 22 : port)
            ike(500)
            wireGuard()
        }
        return probes
    }

    /// One sentence for someone who does not know what an SPI is.
    private static func summarise(_ f: Fingerprint, hint: VPNKind?) -> String {
        if let best = f.best { return best.label }
        let anythingAnswered = f.findings.contains { $0.detail.localizedCaseInsensitiveContains("answered")
            || $0.detail.localizedCaseInsensitiveContains("connected") }
        if f.findings.contains(where: { $0.detail.contains("refused") }) {
            return "Nothing is listening on \(f.host):\(f.port) — the connection was refused."
        }
        if anythingAnswered {
            return "Something is listening at \(f.host):\(f.port), but it didn't answer like a VPN we recognise."
        }
        if let hint, hint == .wireGuard {
            return "Silence, which is exactly how WireGuard behaves — this can't be confirmed from outside."
        }
        return "No VPN answered at \(f.host):\(f.port). It may be firewalled, or it may only reply to a properly signed client."
    }

    // MARK: - OpenVPN

    /// P_CONTROL_HARD_RESET_CLIENT_V2 — the first thing a real client sends.
    static let openVPNResetClientV2: UInt8 = 7
    static let openVPNResetServerV2: UInt8 = 8
    static let openVPNResetServerV1: UInt8 = 2

    /// The 14-byte reset a client opens with:
    ///   byte 0     opcode (top 5 bits) | key_id (low 3 bits)   → 7 << 3 = 0x38
    ///   bytes 1-8  our session id (random 64 bits)
    ///   byte 9     P_ACK packet-id array length (0 — nothing to acknowledge yet)
    ///   bytes 10-13 this message's packet-id (0)
    /// No HMAC: with --tls-auth/--tls-crypt configured the server will simply ignore
    /// us, which the caller reports honestly rather than as "not OpenVPN".
    static func openVPNResetPacket(sessionID: [UInt8], keyID: UInt8 = 0) -> [UInt8] {
        var session = sessionID
        if session.count != 8 { session = (0..<8).map { _ in UInt8.random(in: 0...255) } }
        var p: [UInt8] = [(openVPNResetClientV2 << 3) | (keyID & 0x07)]
        p += session
        p.append(0)                       // ACK array length
        p += [0, 0, 0, 0]                 // packet-id
        return p
    }

    /// TCP carries the same bytes behind a 16-bit big-endian length; UDP does not.
    static func openVPNTCPFramed(_ payload: [UInt8]) -> [UInt8] {
        [UInt8((payload.count >> 8) & 0xff), UInt8(payload.count & 0xff)] + payload
    }

    struct OpenVPNReply: Sendable, Equatable {
        var opcode: UInt8
        var keyID: UInt8
        var serverSessionID: [UInt8]
        /// Our session id appears in the acknowledgement — only an OpenVPN server
        /// that parsed our packet can do this.
        var echoesOurSession: Bool
        var isServerReset: Bool {
            opcode == openVPNResetServerV2 || opcode == openVPNResetServerV1
        }
        var opcodeName: String {
            switch opcode {
            case 1: "P_CONTROL_HARD_RESET_CLIENT_V1"
            case 2: "P_CONTROL_HARD_RESET_SERVER_V1"
            case 3: "P_CONTROL_SOFT_RESET_V1"
            case 4: "P_CONTROL_V1"
            case 5: "P_ACK_V1"
            case 6: "P_DATA_V1"
            case 7: "P_CONTROL_HARD_RESET_CLIENT_V2"
            case 8: "P_CONTROL_HARD_RESET_SERVER_V2"
            case 9: "P_DATA_V2"
            case 10: "P_CONTROL_HARD_RESET_CLIENT_V3"
            case 11: "P_CONTROL_WKC_V1"
            default: "opcode \(opcode)"
            }
        }
    }

    /// Parse a reply to our reset. `framed` strips the TCP length prefix first.
    /// Returns nil when the bytes cannot be an OpenVPN control packet at all.
    static func parseOpenVPNReply(_ bytes: [UInt8], sentSessionID: [UInt8],
                                  framed: Bool) -> OpenVPNReply? {
        var body = bytes
        if framed {
            guard body.count >= 3 else { return nil }
            let declared = Int(body[0]) << 8 | Int(body[1])
            body = Array(body.dropFirst(2))
            guard declared > 0, body.count >= min(declared, 9) else { return nil }
            body = Array(body.prefix(declared))
        }
        // opcode byte + 8-byte session id is the shortest thing that can be one.
        guard body.count >= 9 else { return nil }
        let opcode = body[0] >> 3
        guard (1...11).contains(opcode) else { return nil }
        let session = Array(body[1..<9])
        let tail = Array(body.dropFirst(9))
        return OpenVPNReply(opcode: opcode,
                            keyID: body[0] & 0x07,
                            serverSessionID: session,
                            echoesOurSession: sentSessionID.count == 8
                                && contains(tail, subsequence: sentSessionID))
    }

    static func probeOpenVPN(host: String, port: Int, transport: Transport,
                             timeout: TimeInterval = 3) async -> Finding {
        let tcp = transport == .tcp
        let name = "OpenVPN over \(tcp ? "TCP" : "UDP")"
        let session = (0..<8).map { _ in UInt8.random(in: 0...255) }
        let payload = openVPNResetPacket(sessionID: session)
        let wire = tcp ? openVPNTCPFramed(payload) : payload
        let result = tcp
            ? await tcpExchange(host: host, port: port, payload: wire, timeout: timeout)
            : await udpExchange(host: host, port: port, payload: wire, timeout: timeout)

        switch result {
        case .reply(let bytes):
            guard let reply = parseOpenVPNReply(bytes, sentSessionID: session, framed: tcp) else {
                return Finding(probe: name, detected: false,
                               label: "Something answered, but not in OpenVPN's language.",
                               detail: "\(bytes.count) bytes came back that aren't a valid OpenVPN control packet.",
                               confidence: .none)
            }
            if reply.isServerReset {
                let confidence: Confidence = reply.echoesOurSession ? .high : .medium
                return Finding(probe: name, detected: true,
                               label: "An OpenVPN server answered.",
                               detail: "Replied \(reply.opcodeName)"
                                   + (reply.echoesOurSession ? ", acknowledging the session we opened." : ".")
                                   + " Server session id \(hex(reply.serverSessionID)).",
                               confidence: confidence, kind: .openVPN)
            }
            return Finding(probe: name, detected: true,
                           label: "An OpenVPN-speaking endpoint answered.",
                           detail: "Replied \(reply.opcodeName) rather than a server reset — an OpenVPN control packet all the same.",
                           confidence: .medium, kind: .openVPN)
        case .refused:
            return Finding(probe: name, detected: false,
                           label: "Nothing is listening on \(tcp ? "TCP" : "UDP") \(port).",
                           detail: "The connection was refused.", confidence: .none)
        case .silence:
            return Finding(probe: name, detected: false,
                           label: "No OpenVPN answer.",
                           detail: "Silence. A server using tls-auth or tls-crypt ignores an unsigned hello like ours, so this doesn't rule OpenVPN out.",
                           confidence: .none)
        case .connectedNoReply:
            return Finding(probe: name, detected: false,
                           label: "The port is open, but nothing answered as OpenVPN.",
                           detail: "TCP connected and stayed silent after our hello.", confidence: .none)
        case .failed:
            return Finding(probe: name, detected: false,
                           label: "Couldn't reach \(host) on \(tcp ? "TCP" : "UDP") \(port).",
                           detail: "No route, or the name didn't resolve.", confidence: .none)
        }
    }

    // MARK: - WireGuard (weak by construction)

    /// A 148-byte handshake initiation (WireGuard whitepaper §5.4.2):
    ///   type 1 + 3 reserved | sender index 4 | ephemeral 32 | encrypted static 48
    ///   | encrypted timestamp 28 | mac1 16 | mac2 16
    /// mac1 is keyed with the server's public key, which we do not have, so a real
    /// server discards this without a byte in reply. The packet is still worth sending:
    /// a *reply* proves the port is NOT WireGuard, and ICMP refusal proves it's closed.
    static func wireGuardInitiation() -> [UInt8] {
        var p = [UInt8](repeating: 0, count: 148)
        p[0] = 1                                    // message type: handshake initiation
        for i in 4..<148 { p[i] = UInt8.random(in: 0...255) }
        return p
    }

    static let wireGuardDefaultPort = 51820

    static func probeWireGuard(host: String, port: Int, expected: Bool,
                               timeout: TimeInterval = 3) async -> Finding {
        let name = "WireGuard over UDP"
        let result = await udpExchange(host: host, port: port,
                                       payload: wireGuardInitiation(), timeout: timeout)
        switch result {
        case .reply(let bytes):
            return Finding(probe: name, detected: false,
                           label: "Not WireGuard — something answered.",
                           detail: "WireGuard never replies to a handshake it can't authenticate, and \(bytes.count) bytes came back.",
                           confidence: .none)
        case .refused:
            return Finding(probe: name, detected: false,
                           label: "Nothing is listening on UDP \(port).",
                           detail: "The connection was refused, so no WireGuard here.", confidence: .none)
        case .silence, .connectedNoReply:
            let plausible = expected || port == wireGuardDefaultPort
            return Finding(probe: name, detected: plausible,
                           label: plausible
                               ? "Possibly WireGuard (silent UDP, as WireGuard is by design)."
                               : "No sign of WireGuard.",
                           detail: plausible
                               ? "Nothing came back — which is what a WireGuard server does with a handshake it can't authenticate. A closed port looks identical from here, so this is a maybe, not a finding."
                               : "Nothing came back, and \(port) isn't WireGuard's usual port. Silence alone means nothing.",
                           confidence: plausible ? .low : .none,
                           kind: plausible ? .wireGuard : nil)
        case .failed:
            return Finding(probe: name, detected: false,
                           label: "Couldn't reach \(host) on UDP \(port).",
                           detail: "No route, or the name didn't resolve.", confidence: .none)
        }
    }

    // MARK: - IKEv2 / IPsec

    static let ikeDefaultPort = 500
    static let ikeNATTPort = 4500

    struct IKEReply: Sendable, Equatable {
        var initiatorSPI: [UInt8]
        var responderSPI: [UInt8]
        var majorVersion: Int
        var minorVersion: Int
        var exchangeType: UInt8
        var isResponse: Bool
        var messageID: UInt32
        var length: UInt32
        var matchesInitiator: Bool
        var notifyType: UInt16?
        var isIKEv2: Bool { majorVersion == 2 }
        var exchangeName: String {
            switch exchangeType {
            case 34: "IKE_SA_INIT"
            case 35: "IKE_AUTH"
            case 36: "CREATE_CHILD_SA"
            case 37: "INFORMATIONAL"
            default: "exchange type \(exchangeType)"
            }
        }
        var notifyName: String? {
            guard let notifyType else { return nil }
            switch notifyType {
            case 7: return "INVALID_SYNTAX"
            case 14: return "NO_PROPOSAL_CHOSEN"
            case 17: return "INVALID_KE_PAYLOAD"
            case 24: return "AUTHENTICATION_FAILED"
            case 16386: return "COOKIE"
            case 16388, 16389: return "NAT_DETECTION"
            default: return "notify \(notifyType)"
            }
        }
    }

    /// A complete IKE_SA_INIT request (RFC 7296 §3.1–3.4, shaped after the minimal
    /// initiator of RFC 7815): 28-byte header + SA (one proposal:
    /// AES-CBC-256 / PRF-HMAC-SHA2-256 / HMAC-SHA2-256-128 / MODP-2048) + KE + Nonce.
    /// The DH public value is random rather than computed — nothing is ever derived
    /// from the answer, and a responder replies (or rejects) either way.
    static func ikeSAInit(initiatorSPI: [UInt8], nonESPMarker: Bool = false) -> [UInt8] {
        func u16(_ v: Int) -> [UInt8] { [UInt8((v >> 8) & 0xff), UInt8(v & 0xff)] }
        func u32(_ v: Int) -> [UInt8] {
            [UInt8((v >> 24) & 0xff), UInt8((v >> 16) & 0xff), UInt8((v >> 8) & 0xff), UInt8(v & 0xff)]
        }
        /// Transform substructure: `last` is 3 for "more follow", 0 for the final one.
        func transform(last: Bool, type: UInt8, id: UInt16, attributes: [UInt8] = []) -> [UInt8] {
            let len = 8 + attributes.count
            return [last ? 0 : 3, 0] + u16(len) + [type, 0] + u16(Int(id)) + attributes
        }

        // Key-length attribute, AF=1 (short form), type 14, value 256 bits.
        let keyLen256: [UInt8] = [0x80, 0x0e] + u16(256)
        var transforms: [UInt8] = []
        transforms += transform(last: false, type: 1, id: 12, attributes: keyLen256)  // ENCR_AES_CBC
        transforms += transform(last: false, type: 2, id: 5)                          // PRF_HMAC_SHA2_256
        transforms += transform(last: false, type: 3, id: 12)                         // AUTH_HMAC_SHA2_256_128
        transforms += transform(last: true, type: 4, id: 14)                          // MODP-2048

        // Proposal substructure (last=0), protocol IKE(1), no SPI, 4 transforms.
        let proposalLen = 8 + transforms.count
        var proposal: [UInt8] = [0, 0] + u16(proposalLen) + [1, 1, 0, 4]
        proposal += transforms

        // SA payload; next payload = 34 (KE).
        var sa: [UInt8] = [34, 0] + u16(4 + proposal.count)
        sa += proposal

        // KE payload; next payload = 40 (Nonce). 256 bytes for MODP-2048.
        let dh = (0..<256).map { _ in UInt8.random(in: 0...255) }
        var ke: [UInt8] = [40, 0] + u16(8 + dh.count) + u16(14) + [0, 0]
        ke += dh

        // Nonce payload; last, so next payload = 0.
        let nonce = (0..<32).map { _ in UInt8.random(in: 0...255) }
        var ni: [UInt8] = [0, 0] + u16(4 + nonce.count)
        ni += nonce

        let body = sa + ke + ni
        var spi = initiatorSPI
        if spi.count != 8 { spi = (0..<8).map { _ in UInt8.random(in: 0...255) } }

        var msg: [UInt8] = spi                     // initiator SPI
        msg += [UInt8](repeating: 0, count: 8)     // responder SPI: unknown
        msg += [33]                                // next payload: SA
        msg += [0x20]                              // version 2.0
        msg += [34]                                // exchange type: IKE_SA_INIT
        msg += [0x08]                              // flags: Initiator
        msg += u32(0)                              // message id
        msg += u32(28 + body.count)                // total length
        msg += body
        // UDP 4500 multiplexes IKE with ESP; four zero bytes say "this is IKE".
        return nonESPMarker ? [0, 0, 0, 0] + msg : msg
    }

    static func parseIKEReply(_ bytes: [UInt8], initiatorSPI: [UInt8],
                              nonESPMarker: Bool = false) -> IKEReply? {
        var b = bytes
        if nonESPMarker {
            guard b.count > 4, b[0] == 0, b[1] == 0, b[2] == 0, b[3] == 0 else { return nil }
            b = Array(b.dropFirst(4))
        }
        guard b.count >= 28 else { return nil }
        let initiator = Array(b[0..<8])
        let responder = Array(b[8..<16])
        let nextPayload = b[16]
        let version = b[17]
        let major = Int(version >> 4), minor = Int(version & 0x0f)
        guard major == 1 || major == 2 else { return nil }
        let exchange = b[18]
        let flags = b[19]
        let messageID = UInt32(b[20]) << 24 | UInt32(b[21]) << 16 | UInt32(b[22]) << 8 | UInt32(b[23])
        let length = UInt32(b[24]) << 24 | UInt32(b[25]) << 16 | UInt32(b[26]) << 8 | UInt32(b[27])

        // A first payload of type 41 (Notify) is how a responder says no; the reason
        // code is worth surfacing because "NO_PROPOSAL_CHOSEN" still proves IKE.
        var notify: UInt16?
        if nextPayload == 41, b.count >= 28 + 8 {
            notify = UInt16(b[28 + 6]) << 8 | UInt16(b[28 + 7])
        }
        return IKEReply(initiatorSPI: initiator, responderSPI: responder,
                        majorVersion: major, minorVersion: minor,
                        exchangeType: exchange,
                        isResponse: flags & 0x20 != 0,
                        messageID: messageID, length: length,
                        matchesInitiator: initiator == initiatorSPI,
                        notifyType: notify)
    }

    static func probeIKE(host: String, port: Int, timeout: TimeInterval = 3) async -> Finding {
        let name = "IKEv2 on UDP \(port)"
        let spi = (0..<8).map { _ in UInt8.random(in: 0...255) }
        let marker = (port == ikeNATTPort)
        let payload = ikeSAInit(initiatorSPI: spi, nonESPMarker: marker)
        let result = await udpExchange(host: host, port: port, payload: payload, timeout: timeout)

        switch result {
        case .reply(let bytes):
            guard let reply = parseIKEReply(bytes, initiatorSPI: spi, nonESPMarker: marker) else {
                return Finding(probe: name, detected: false,
                               label: "Something answered on UDP \(port), but it wasn't IKE.",
                               detail: "\(bytes.count) bytes came back that don't parse as an IKE header.",
                               confidence: .none)
            }
            guard reply.matchesInitiator else {
                return Finding(probe: name, detected: false,
                               label: "An IKE-shaped reply arrived, but not to our request.",
                               detail: "The initiator SPI didn't match what we sent.", confidence: .none)
            }
            let versionText = reply.isIKEv2 ? "IKEv2" : "IKEv1"
            var detail = "\(versionText) \(reply.exchangeName) response."
            if let n = reply.notifyName { detail += " The gateway said \(n) — it rejected our made-up proposal, which still proves it speaks IKE." }
            return Finding(probe: name, detected: true,
                           label: "An \(versionText) gateway answered — this is an IPsec VPN.",
                           detail: detail, confidence: .high,
                           kind: reply.isIKEv2 ? .ikev2 : .ipsec)
        case .refused:
            return Finding(probe: name, detected: false,
                           label: "Nothing is listening on UDP \(port).",
                           detail: "The connection was refused.", confidence: .none)
        case .silence, .connectedNoReply:
            return Finding(probe: name, detected: false,
                           label: "No IKE gateway answered on UDP \(port).",
                           detail: "Silence. Gateways configured to ignore unknown initiators look the same as an absent one.",
                           confidence: .none)
        case .failed:
            return Finding(probe: name, detected: false,
                           label: "Couldn't reach \(host) on UDP \(port).",
                           detail: "No route, or the name didn't resolve.", confidence: .none)
        }
    }

    // MARK: - SSL-VPN vendor fingerprinting

    struct SSLVPNGuess: Sendable, Equatable {
        var kind: VPNKind?
        var vendor: String
        var evidence: String
    }

    /// Vendor identification from the HTTP response head (status line + headers, and
    /// any redirect target) plus the certificate names. Every rule below is a string
    /// the vendor's own portal emits; nothing is inferred from the port.
    static func classifySSLVPN(head: String, certSubject: String? = nil,
                               certIssuer: String? = nil) -> SSLVPNGuess? {
        let hay = (head + "\n" + (certSubject ?? "") + "\n" + (certIssuer ?? "")).lowercased()
        func any(_ needles: [String]) -> String? { needles.first { hay.contains($0) } }

        // Fortinet: the SSL-VPN session cookie, the portal path, and the famously
        // anonymised Server header FortiOS sends ("Server: xxxxxxxx-xxxxx").
        if let hit = any(["svpncookie", "/remote/login", "/remote/logincheck", "fgt_lang",
                          "server: xxxxxxxx-xxxxx", "fortigate", "fortinet"]) {
            return SSLVPNGuess(kind: .fortinet, vendor: "FortiGate SSL VPN", evidence: hit)
        }
        // F5 BIG-IP APM: the access policy landing page and APM's session cookies.
        if let hit = any(["/my.policy", "mrhsession", "lastmrh_session", "big-ip", "bigipserver",
                          "f5 networks", "f5-"]) {
            return SSLVPNGuess(kind: .f5apm, vendor: "F5 BIG-IP APM", evidence: hit)
        }
        // Palo Alto GlobalProtect.
        if let hit = any(["/global-protect/", "globalprotect", "pangp", "palo alto"]) {
            return SSLVPNGuess(kind: .globalProtect, vendor: "Palo Alto GlobalProtect", evidence: hit)
        }
        // Cisco AnyConnect / ocserv: the +CSCOE+ portal namespace and webvpn cookies.
        if let hit = any(["/+cscoe+/", "/+webvpn+/", "webvpncontext", "webvpnlogin", "webvpn",
                          "anyconnect", "ocserv"]) {
            return SSLVPNGuess(kind: .ciscoAnyConnect, vendor: "Cisco AnyConnect", evidence: hit)
        }
        // Juniper/Pulse/Ivanti share the /dana-na/ portal namespace.
        if let hit = any(["/dana-na/", "dsid=", "pulse secure", "ivanti"]) {
            return SSLVPNGuess(kind: .pulse, vendor: "Pulse / Ivanti Connect Secure", evidence: hit)
        }
        if let hit = any(["/prx/000/", "array networks"]) {
            return SSLVPNGuess(kind: .arrayNetworks, vendor: "Array Networks SSL VPN", evidence: hit)
        }
        // Named but not one of our kinds — still worth telling the user.
        if let hit = any(["sonicwall", "netextender"]) {
            return SSLVPNGuess(kind: nil, vendor: "SonicWall SSL VPN", evidence: hit)
        }
        if let hit = any(["citrix", "netscaler", "/vpn/index.html", "nsc_"]) {
            return SSLVPNGuess(kind: nil, vendor: "Citrix Gateway / NetScaler", evidence: hit)
        }
        if let hit = any(["openvpn access server", "/__session_start__/"]) {
            return SSLVPNGuess(kind: .openVPN, vendor: "OpenVPN Access Server", evidence: hit)
        }
        return nil
    }

    static func probeSSLVPN(host: String, port: Int, timeout: TimeInterval = 6) async -> Finding {
        let name = "SSL-VPN on TCP \(port)"
        let banner = await tlsHTTPProbe(host: host, port: port, timeout: timeout)
        guard banner.connected else {
            return Finding(probe: name, detected: false,
                           label: "No TLS service answered on port \(port).",
                           detail: "The TLS handshake didn't complete — the port is closed, filtered, or speaks something else.",
                           confidence: .none)
        }
        let certLine = banner.subject.map { "Certificate: \($0)" + (banner.issuer.map { i in " (issued by \(i))" } ?? "") }
            ?? "No certificate was captured."

        if let guess = classifySSLVPN(head: banner.head, certSubject: banner.subject,
                                      certIssuer: banner.issuer) {
            return Finding(probe: name, detected: true,
                           label: "This looks like a \(guess.vendor).",
                           detail: "Recognised from “\(guess.evidence)” in the server's response. " + certLine,
                           confidence: .high, kind: guess.kind)
        }
        let server = headerValue("server", in: banner.head)
        var detail = certLine
        if let server { detail += " Server header: \(server)." }
        return Finding(probe: name, detected: false,
                       label: "A TLS server answered, but not one of the SSL-VPNs we recognise.",
                       detail: detail, confidence: .none)
    }

    /// First value of a header from a raw HTTP response head (case-insensitive).
    static func headerValue(_ name: String, in head: String) -> String? {
        for line in head.split(whereSeparator: \.isNewline) {
            let parts = line.split(separator: ":", maxSplits: 1, omittingEmptySubsequences: false)
            guard parts.count == 2,
                  parts[0].trimmingCharacters(in: .whitespaces).lowercased() == name.lowercased()
            else { continue }
            return parts[1].trimmingCharacters(in: .whitespaces)
        }
        return nil
    }

    // MARK: - SSH

    struct SSHBanner: Sendable, Equatable {
        var protocolVersion: String   // "2.0"
        var software: String          // "OpenSSH_9.6"
        var comment: String?          // free text after the first space
    }

    /// RFC 4253 §4.2: `SSH-protoversion-softwareversion SP comments CR LF`.
    /// Servers may send other lines first; we take the first SSH- line.
    static func parseSSHBanner(_ raw: String) -> SSHBanner? {
        // RFC 4253 §4.2: the server MAY send any number of preamble lines before
        // the identification line, so scan every line.
        //
        // Split on UNICODE SCALARS, not Characters: Swift treats "\r\n" as ONE
        // grapheme cluster, so `split(whereSeparator: { $0 == "\r" || $0 == "\n" })`
        // matches neither half and hands back the entire banner as a single
        // "line" — which is exactly how a preamble used to hide the SSH- line.
        let lines = raw.unicodeScalars
            .split(whereSeparator: { $0 == "\r" || $0 == "\n" })
            .map { String(String.UnicodeScalarView($0)) }
        for rawLine in lines {
            let line = rawLine.trimmingCharacters(in: .whitespacesAndNewlines)
            guard line.hasPrefix("SSH-") else { continue }
            let rest = String(line.dropFirst(4))
            guard let dash = rest.firstIndex(of: "-") else { continue }
            let version = String(rest[rest.startIndex..<dash])
            guard !version.isEmpty else { continue }
            let after = String(rest[rest.index(after: dash)...])
            let bits = after.split(separator: " ", maxSplits: 1, omittingEmptySubsequences: false)
            let software = String(bits.first ?? "").trimmingCharacters(in: .whitespacesAndNewlines)
            guard !software.isEmpty else { continue }
            let comment = bits.count > 1
                ? String(bits[1]).trimmingCharacters(in: .whitespacesAndNewlines) : nil
            return SSHBanner(protocolVersion: version, software: software,
                             comment: (comment?.isEmpty ?? true) ? nil : comment)
        }
        return nil
    }

    static func probeSSH(host: String, port: Int, timeout: TimeInterval = 3) async -> Finding {
        let name = "SSH on TCP \(port)"
        // The server speaks first, so we send nothing at all.
        let result = await tcpExchange(host: host, port: port, payload: [], timeout: timeout)
        switch result {
        case .reply(let bytes):
            let text = String(decoding: bytes.prefix(512), as: UTF8.self)
            guard let banner = parseSSHBanner(text) else {
                return Finding(probe: name, detected: false,
                               label: "Something answered on port \(port), but it isn't SSH.",
                               detail: "The greeting didn't start with “SSH-”.", confidence: .none)
            }
            return Finding(probe: name, detected: true,
                           label: "An SSH server answered — \(banner.software).",
                           detail: "Greeting: SSH-\(banner.protocolVersion)-\(banner.software)"
                               + (banner.comment.map { " \($0)" } ?? ""),
                           confidence: .high, kind: .ssh)
        case .refused:
            return Finding(probe: name, detected: false,
                           label: "Nothing is listening on TCP \(port).",
                           detail: "The connection was refused.", confidence: .none)
        case .connectedNoReply:
            return Finding(probe: name, detected: false,
                           label: "Port \(port) is open but sent no SSH greeting.",
                           detail: "TCP connected and the server said nothing — SSH always greets first.",
                           confidence: .none)
        case .silence, .failed:
            return Finding(probe: name, detected: false,
                           label: "No SSH server answered on port \(port).",
                           detail: "Nothing came back.", confidence: .none)
        }
    }

    // MARK: - Wire plumbing

    /// What one send/receive round trip actually produced. `refused` (ICMP port
    /// unreachable / TCP RST) is kept apart from `silence` because they mean opposite
    /// things: one proves nothing is there, the other proves nothing at all.
    enum WireResult: Sendable, Equatable {
        case reply([UInt8])
        case silence
        case connectedNoReply     // TCP only: the handshake completed, the peer stayed quiet
        case refused
        case failed
    }

    /// Blocking socket work runs here, not on the cooperative pool: a 3-second recv
    /// would otherwise park one of a handful of shared threads (same reasoning as
    /// NetworkProbes.probeQueue).
    private static let probeQueue = DispatchQueue(label: "com.bragi0.SimpleVPN.vpnprobe",
                                                  attributes: .concurrent)

    private static func onProbeQueue<T: Sendable>(_ work: @escaping @Sendable () -> T) async -> T {
        await withCheckedContinuation { cont in
            probeQueue.async { cont.resume(returning: work()) }
        }
    }

    private static func recvTimeval(_ seconds: TimeInterval) -> timeval {
        let s = max(seconds, 0.001)
        let sec = Int(s)
        return timeval(tv_sec: sec, tv_usec: suseconds_t((s - Double(sec)) * 1_000_000))
    }

    /// One datagram out, one datagram in. The socket is `connect`ed so that an ICMP
    /// port-unreachable surfaces as ECONNREFUSED instead of vanishing.
    static func udpExchange(host: String, port: Int, payload: [UInt8],
                            timeout: TimeInterval) async -> WireResult {
        await onProbeQueue {
            var hints = addrinfo(ai_flags: 0, ai_family: AF_UNSPEC, ai_socktype: SOCK_DGRAM,
                                 ai_protocol: IPPROTO_UDP, ai_addrlen: 0, ai_canonname: nil,
                                 ai_addr: nil, ai_next: nil)
            var res: UnsafeMutablePointer<addrinfo>?
            guard getaddrinfo(host, String(port), &hints, &res) == 0, let first = res else { return .failed }
            defer { freeaddrinfo(first) }
            let fd = socket(first.pointee.ai_family, first.pointee.ai_socktype, first.pointee.ai_protocol)
            guard fd >= 0 else { return .failed }
            defer { close(fd) }
            var tv = recvTimeval(timeout)
            setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, socklen_t(MemoryLayout<timeval>.size))
            guard connect(fd, first.pointee.ai_addr, first.pointee.ai_addrlen) == 0 else { return .failed }
            let sent = payload.withUnsafeBytes { send(fd, $0.baseAddress, $0.count, 0) }
            guard sent > 0 else { return errno == ECONNREFUSED ? .refused : .failed }
            var buf = [UInt8](repeating: 0, count: 4096)
            let n = recv(fd, &buf, buf.count, 0)
            if n > 0 { return .reply(Array(buf[0..<n])) }
            if n < 0, errno == ECONNREFUSED { return .refused }
            return .silence
        }
    }

    /// Connect, optionally write `payload`, then read whatever the peer says first.
    /// An empty payload is the SSH case (server greets first).
    static func tcpExchange(host: String, port: Int, payload: [UInt8],
                            timeout: TimeInterval, readLimit: Int = 8192) async -> WireResult {
        await onProbeQueue {
            var hints = addrinfo(ai_flags: 0, ai_family: AF_UNSPEC, ai_socktype: SOCK_STREAM,
                                 ai_protocol: IPPROTO_TCP, ai_addrlen: 0, ai_canonname: nil,
                                 ai_addr: nil, ai_next: nil)
            var res: UnsafeMutablePointer<addrinfo>?
            guard getaddrinfo(host, String(port), &hints, &res) == 0, let first = res else { return .failed }
            defer { freeaddrinfo(first) }
            let fd = socket(first.pointee.ai_family, first.pointee.ai_socktype, first.pointee.ai_protocol)
            guard fd >= 0 else { return .failed }
            defer { close(fd) }

            // Non-blocking connect + poll: Darwin doesn't apply SO_SNDTIMEO to
            // connect(), so this is the only way to bound a dead endpoint.
            let flags = fcntl(fd, F_GETFL, 0)
            _ = fcntl(fd, F_SETFL, flags | O_NONBLOCK)
            let rc = connect(fd, first.pointee.ai_addr, first.pointee.ai_addrlen)
            if rc != 0 {
                guard errno == EINPROGRESS else { return errno == ECONNREFUSED ? .refused : .failed }
                var pfd = pollfd(fd: fd, events: Int16(POLLOUT), revents: 0)
                guard poll(&pfd, 1, Int32(timeout * 1000)) > 0 else { return .silence }
                var soError: Int32 = 0
                var len = socklen_t(MemoryLayout<Int32>.size)
                guard getsockopt(fd, SOL_SOCKET, SO_ERROR, &soError, &len) == 0 else { return .failed }
                if soError == ECONNREFUSED { return .refused }
                guard soError == 0 else { return .failed }
            }
            _ = fcntl(fd, F_SETFL, flags)
            var tv = recvTimeval(timeout)
            setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, &tv, socklen_t(MemoryLayout<timeval>.size))
            setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &tv, socklen_t(MemoryLayout<timeval>.size))

            if !payload.isEmpty {
                var written = 0
                while written < payload.count {
                    let n = payload[written...].withUnsafeBytes { send(fd, $0.baseAddress, $0.count, 0) }
                    if n <= 0 { return .connectedNoReply }
                    written += n
                }
            }
            var buf = [UInt8](repeating: 0, count: min(readLimit, 16384))
            let n = recv(fd, &buf, buf.count, 0)
            if n > 0 { return .reply(Array(buf[0..<n])) }
            return .connectedNoReply
        }
    }

    // MARK: TLS + HTTP head (NWConnection — the one place we need a TLS stack)

    struct TLSBanner: Sendable {
        var connected = false
        var subject: String?
        var issuer: String?
        var head: String = ""
    }

    /// TLS handshake that accepts ANY certificate (we are identifying the server, not
    /// trusting it — nothing is sent that matters and the connection is discarded),
    /// then one HTTP GET / and whatever comes back first.
    static func tlsHTTPProbe(host: String, port: Int, timeout: TimeInterval) async -> TLSBanner {
        guard let nwPort = NWEndpoint.Port(rawValue: UInt16(clamping: port)) else { return TLSBanner() }
        let box = BannerBox()

        let tls = NWProtocolTLS.Options()
        sec_protocol_options_set_verify_block(tls.securityProtocolOptions, { _, secTrust, complete in
            let trust = sec_trust_copy_ref(secTrust).takeRetainedValue()
            if let chain = SecTrustCopyCertificateChain(trust) as? [SecCertificate], let leaf = chain.first {
                box.setCertificate(subject: SecCertificateCopySubjectSummary(leaf) as String?,
                                   issuer: issuerName(leaf))
            }
            complete(true)   // identification only; never trusted, never reused
        }, DispatchQueue.global(qos: .userInitiated))

        let request = "GET / HTTP/1.1\r\nHost: \(host)\r\nUser-Agent: SimpleVPN-Probe/1\r\nAccept: */*\r\nConnection: close\r\n\r\n"
        let params = NWParameters(tls: tls, tcp: NWProtocolTCP.Options())
        let connection = NWConnection(host: NWEndpoint.Host(host), port: nwPort, using: params)
        let flag = ResumeOnce()

        await withCheckedContinuation { (cont: CheckedContinuation<Void, Never>) in
            connection.stateUpdateHandler = { state in
                switch state {
                case .ready:
                    box.setConnected()
                    connection.send(content: Data(request.utf8), completion: .contentProcessed { _ in
                        connection.receive(minimumIncompleteLength: 1, maximumLength: 16384) { data, _, _, _ in
                            if let data { box.setHead(String(decoding: data, as: UTF8.self)) }
                            flag.once { cont.resume() }
                            connection.cancel()
                        }
                    })
                case .failed, .cancelled:
                    flag.once { cont.resume() }
                default:
                    break
                }
            }
            connection.start(queue: .global(qos: .userInitiated))
            DispatchQueue.global().asyncAfter(deadline: .now() + timeout) {
                flag.once { cont.resume() }
                connection.cancel()
            }
        }
        return box.value()
    }

    /// CN (else O) of the certificate's issuer — "issued by Fortinet Ltd." is often
    /// the clearest signal on an SSL-VPN portal that serves a bare login page.
    private static func issuerName(_ cert: SecCertificate) -> String? {
        guard let values = SecCertificateCopyValues(cert, [kSecOIDX509V1IssuerName] as CFArray, nil)
                as? [String: Any],
              let issuer = values[kSecOIDX509V1IssuerName as String] as? [String: Any],
              let props = issuer[kSecPropertyKeyValue as String] as? [[String: Any]]
        else { return nil }
        var cn: String?, org: String?
        for p in props {
            let label = p[kSecPropertyKeyLabel as String] as? String
            let value = p[kSecPropertyKeyValue as String] as? String
            if label == "2.5.4.3" { cn = value }        // CN
            if label == "2.5.4.10" { org = value }      // O
        }
        return cn ?? org
    }

    /// Callbacks arrive on Network.framework's queue; these boxes are the handoff.
    private final class BannerBox: @unchecked Sendable {
        private let lock = NSLock()
        private var banner = TLSBanner()
        func setConnected() { lock.lock(); banner.connected = true; lock.unlock() }
        func setCertificate(subject: String?, issuer: String?) {
            lock.lock(); defer { lock.unlock() }
            if banner.subject == nil { banner.subject = subject; banner.issuer = issuer }
        }
        func setHead(_ s: String) { lock.lock(); banner.head = s; lock.unlock() }
        func value() -> TLSBanner { lock.lock(); defer { lock.unlock() }; return banner }
    }

    private final class ResumeOnce: @unchecked Sendable {
        private let lock = NSLock()
        private var done = false
        func once(_ body: () -> Void) {
            lock.lock(); defer { lock.unlock() }
            guard !done else { return }
            done = true
            body()
        }
    }

    // MARK: - Small helpers

    static func hex(_ bytes: [UInt8]) -> String {
        bytes.map { String(format: "%02x", $0) }.joined()
    }

    /// Naive subsequence search — the haystacks here are tens of bytes.
    static func contains(_ haystack: [UInt8], subsequence needle: [UInt8]) -> Bool {
        guard !needle.isEmpty, haystack.count >= needle.count else { return false }
        for start in 0...(haystack.count - needle.count) {
            if Array(haystack[start..<start + needle.count]) == needle { return true }
        }
        return false
    }
}
