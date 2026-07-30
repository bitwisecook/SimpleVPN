// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
//  EndpointDiscovery.swift
//  "I have the address but not the rest." Given a bare host (and optional port),
//  actively probe it across the engines that reveal themselves to a stranger and
//  return ranked candidates the user can turn into a configured VPN in one click:
//
//    • SSH        — the version banner + the server's permitted auth methods,
//                   learned by asking `ssh` to authenticate with nothing.
//    • SSL-VPN    — a TLS handshake (server cert + whether a *client* cert is
//                   demanded) plus an HTTP fingerprint of each vendor's login
//                   surface (Fortinet / F5 APM / GlobalProtect / Cisco), and a
//                   redirect to an external IdP ⇒ SAML sign-in.
//    • IKEv2      — an IKE_SA_INIT to UDP 500; the reply carries the responder's
//                   chosen crypto proposal and vendor IDs (à la ike-scan).
//    • OpenVPN    — a hard-reset to the usual ports; a reply confirms OpenVPN
//                   with no tls-crypt. (tls-crypt makes the server silent.)
//    • WireGuard  — nothing: it never answers an unauthenticated peer by design.
//
//  Everything is best-effort and degrades to a weaker "port open" signal; no
//  result is ever asserted beyond what the wire actually showed.
//

import Foundation
import Network
import Security

nonisolated enum DiscoveredEngine: String, Sendable {
    case ssh, sslVPN, ikev2, openVPN, wireGuard
}

nonisolated enum DiscoveryConfidence: Int, Sendable, Comparable {
    case low = 0, medium = 1, high = 2
    static func < (a: Self, b: Self) -> Bool { a.rawValue < b.rawValue }
    var label: String { self == .high ? "Likely" : self == .medium ? "Possible" : "Maybe" }
}

/// One thing discovery believes is listening, with enough learned facts to
/// pre-fill a config. `kind` names the concrete VPN to create (nil ⇒ advisory).
nonisolated struct DiscoveryCandidate: Identifiable, Sendable {
    var id = UUID().uuidString
    var engine: DiscoveredEngine
    var kind: VPNKind?
    var host: String
    var port: Int
    var transport: String            // "tcp" | "udp" | "tls" — for display
    var confidence: DiscoveryConfidence
    var title: String
    var detail: String
    var facts: [String: String] = [:]   // structured, for prefill + display

    var systemImage: String { kind?.systemImage ?? "questionmark.circle" }
}

nonisolated enum EndpointDiscovery {

    /// Run every prober against `host`. If `onlyPort` is given, engines still probe
    /// their own well-known ports too (the hint just gets tried first / highlighted).
    static func discover(host rawHost: String, hintPort: Int?) async -> [DiscoveryCandidate] {
        let host = normalizedHost(rawHost)
        guard !host.isEmpty else { return [] }

        async let ssh = probeSSH(host: host, port: hintPort ?? 22)
        async let ssl = probeSSLVPN(host: host, ports: sslPorts(hint: hintPort))
        async let ike = probeIKE(host: host)
        async let ovpn = probeOpenVPN(host: host, hintPort: hintPort)

        var out: [DiscoveryCandidate] = []
        if let s = await ssh { out.append(s) }
        out.append(contentsOf: await ssl)
        if let i = await ike { out.append(i) }
        out.append(contentsOf: await ovpn)
        out.append(wireGuardNote(host: host))

        return out.sorted { $0.confidence > $1.confidence }
    }

    /// Strip a scheme and any :port a user pasted, and drop a trailing slash/path.
    static func normalizedHost(_ raw: String) -> String {
        var s = raw.trimmingCharacters(in: .whitespacesAndNewlines)
        if let r = s.range(of: "://") { s = String(s[r.upperBound...]) }
        if let slash = s.firstIndex(of: "/") { s = String(s[..<slash]) }
        // host:port — but keep IPv6 literals ("[::1]:443" or bare "::1")
        if !s.hasPrefix("["), s.filter({ $0 == ":" }).count == 1,
           let colon = s.firstIndex(of: ":") {
            s = String(s[..<colon])
        }
        return s.trimmingCharacters(in: CharacterSet(charactersIn: "[]"))
    }

    static func portHint(from raw: String) -> Int? {
        let s = raw.trimmingCharacters(in: .whitespaces)
        guard !s.hasPrefix("["), s.filter({ $0 == ":" }).count == 1,
              let colon = s.lastIndex(of: ":") else { return nil }
        return Int(s[s.index(after: colon)...])
    }

    private static func sslPorts(hint: Int?) -> [Int] {
        var ports = [443, 10443]
        if let h = hint, !ports.contains(h) { ports.insert(h, at: 0) }
        return ports
    }

    // MARK: - SSH

    /// Ask OpenSSH to connect offering no auth; the server's rejection lists the
    /// methods it *will* accept, and `-v` prints its software version. Nothing is
    /// authenticated — this only reads what the server volunteers.
    static func probeSSH(host: String, port: Int) async -> DiscoveryCandidate? {
        guard let ssh = TunnelCLI.ssh.resolvedPath else { return nil }
        guard await ConnectionDiagnostics.tcpReachable(host: host, port: port, timeout: 4) else { return nil }

        let args = ["-v",
                    "-o", "BatchMode=yes",
                    "-o", "PreferredAuthentications=none",
                    "-o", "PubkeyAuthentication=no",
                    "-o", "StrictHostKeyChecking=no",
                    "-o", "UserKnownHostsFile=/dev/null",
                    "-o", "ConnectTimeout=6",
                    "-p", "\(port)",
                    "endpoint-probe@\(host)"]
        let out = await runProcess(ssh, args, timeout: 12)
        let text = out.stdout + "\n" + out.stderr

        var facts: [String: String] = [:]
        if let sw = firstMatch(#"remote software version (\S+)"#, in: text) { facts["software"] = sw }
        // "Permission denied (publickey,password,keyboard-interactive)." or
        // "Authentications that can continue: publickey,password"
        let methods = firstMatch(#"Permission denied \(([^)]*)\)"#, in: text)
            ?? firstMatch(#"Authentications that can continue: (\S+)"#, in: text)
        if let methods, !methods.isEmpty { facts["authMethods"] = methods }

        // We reached an SSH server if it spoke SSH at all.
        let spokeSSH = text.contains("SSH-2.0") || text.contains("remote software version")
            || facts["authMethods"] != nil
        guard spokeSSH else { return nil }

        let sw = facts["software"] ?? "SSH server"
        let methodText = facts["authMethods"].map { " · accepts \($0)" } ?? ""
        return DiscoveryCandidate(
            engine: .ssh, kind: .ssh, host: host, port: port, transport: "tcp",
            confidence: .high,
            title: "SSH — \(sw)",
            detail: "SSH tunnel endpoint\(methodText). Choose SOCKS, port forwards or a network tunnel after creating it.",
            facts: facts)
    }

    // MARK: - SSL-VPN (TLS + HTTP fingerprint)

    static func probeSSLVPN(host: String, ports: [Int]) async -> [DiscoveryCandidate] {
        var found: [DiscoveryCandidate] = []
        for port in ports {
            guard await ConnectionDiagnostics.tcpReachable(host: host, port: port, timeout: 4) else { continue }
            let tls = await tlsInspect(host: host, port: port, timeout: 6)
            guard tls.spokeTLS else { continue }            // not an HTTPS endpoint
            if let c = await fingerprintSSLVPN(host: host, port: port, tls: tls) {
                found.append(c)
            }
        }
        return found
    }

    /// TLS handshake that captures the server cert subject and whether the server
    /// asks us for a client certificate (a CertificateRequest fires the challenge
    /// block). Trust is intentionally bypassed — we discard the connection.
    private static func tlsInspect(host: String, port: Int, timeout: TimeInterval)
        async -> (spokeTLS: Bool, subject: String?, wantsClientCert: Bool) {
        guard let nwPort = NWEndpoint.Port(rawValue: UInt16(clamping: port)) else { return (false, nil, false) }
        let box = TLSInspectBox()
        let tls = NWProtocolTLS.Options()
        sec_protocol_options_set_verify_block(tls.securityProtocolOptions, { _, secTrust, complete in
            let trust = sec_trust_copy_ref(secTrust).takeRetainedValue()
            if let chain = SecTrustCopyCertificateChain(trust) as? [SecCertificate], let leaf = chain.first {
                box.setSubject((SecCertificateCopySubjectSummary(leaf) as String?) ?? "")
            }
            complete(true)
        }, DispatchQueue.global(qos: .userInitiated))
        sec_protocol_options_set_challenge_block(tls.securityProtocolOptions, { _, complete in
            box.setWantsClientCert()          // server requested a client identity
            complete(nil)                      // we have none — fine for a probe
        }, DispatchQueue.global(qos: .userInitiated))

        let params = NWParameters(tls: tls, tcp: NWProtocolTCP.Options())
        let conn = NWConnection(host: NWEndpoint.Host(host), port: nwPort, using: params)
        let ok = await waitReady(conn, timeout: timeout)
        return (ok, box.subject(), box.wantsClientCert())
    }

    /// HTTP fingerprint of the vendor login surfaces. Order matters only for the
    /// title; every match raises confidence.
    private static func fingerprintSSLVPN(host: String, port: Int,
                                          tls: (spokeTLS: Bool, subject: String?, wantsClientCert: Bool))
        async -> DiscoveryCandidate? {
        let base = "https://\(host):\(port)"
        let root = await httpProbe(base + "/")
        var facts: [String: String] = [:]
        if let s = tls.subject, !s.isEmpty { facts["serverCert"] = s }
        if tls.wantsClientCert { facts["clientCert"] = "required" }

        var vendor: VPNKind?
        var vendorName = "SSL-VPN"
        var proto = "anyconnect"

        func has(_ needle: String, _ r: HTTPProbe?) -> Bool {
            guard let r else { return false }
            let hay = (r.body + " " + r.headers.values.joined(separator: " ")).lowercased()
            return hay.contains(needle.lowercased())
        }

        // Fortinet SSL-VPN
        let forti = await httpProbe(base + "/remote/login")
        if has("svpncookie", root) || has("svpncookie", forti)
            || has("/remote/login", forti) || has("fortinet", forti) || has("sslvpn", forti) {
            vendor = .fortinet; vendorName = "FortiGate SSL-VPN"; proto = "fortinet"
        }
        // F5 BIG-IP APM
        if vendor == nil {
            let f5 = await httpProbe(base + "/my.policy")
            if has("mrhsession", root) || has("mrhsession", f5) || has("f5_st", root)
                || has("bigip", root) || has("/my.policy", f5) || has("f5 networks", root) {
                vendor = .f5apm; vendorName = "F5 BIG-IP APM"; proto = "f5"
            }
        }
        // Palo Alto GlobalProtect (OpenConnect --protocol=gp; no dedicated kind →
        // created as an OpenConnect tunnel with sslProtocol "gp")
        if vendor == nil {
            let gp = await httpProbe(base + "/global-protect/prelogin.esp")
            let gp2 = await httpProbe(base + "/ssl-vpn/prelogin.esp")
            if has("globalprotect", gp) || has("prelogin", gp) || has("prelogin", gp2)
                || has("global-protect", root) {
                vendor = .ciscoAnyConnect; vendorName = "Palo Alto GlobalProtect"; proto = "gp"
            }
        }
        // Cisco ASA / AnyConnect / Secure Client
        if vendor == nil {
            let csco = await httpProbe(base + "/+CSCOE+/logon.html")
            if has("x-aggregate-auth", root) || has("x-aggregate-auth", csco)
                || has("+cscoe+", csco) || has("webvpn", csco) || has("cisco", root) {
                vendor = .ciscoAnyConnect; vendorName = "Cisco AnyConnect / Secure Client"; proto = "anyconnect"
            }
        }

        // SAML: a login surface that 302s to an external identity provider.
        let saml = isSAMLRedirect(root, host: host) || isSAMLRedirect(forti, host: host)
        if saml { facts["saml"] = "yes" }
        facts["sslProtocol"] = proto

        // No vendor fingerprint but a plain HTTPS listener on a VPN-ish port is a
        // weak signal worth surfacing (many gateways hide behind a bare 403/redirect).
        guard vendor != nil || port == 10443 || tls.wantsClientCert else { return nil }

        var bits: [String] = []
        if tls.wantsClientCert { bits.append("wants a client certificate") }
        if saml { bits.append("SAML sign-in") }
        let extra = bits.isEmpty ? "" : " · " + bits.joined(separator: " · ")

        return DiscoveryCandidate(
            engine: .sslVPN, kind: vendor ?? .ciscoAnyConnect, host: host, port: port, transport: "tls",
            confidence: vendor != nil ? .high : .low,
            title: vendorName,
            detail: "TLS VPN gateway on port \(port)\(extra). Connects with OpenConnect/openfortivpn.",
            facts: facts)
    }

    private static func isSAMLRedirect(_ r: HTTPProbe?, host: String) -> Bool {
        guard let r else { return false }
        if r.body.lowercased().contains("samlrequest") { return true }
        guard (300..<400).contains(r.status), let loc = r.headers["Location"] ?? r.headers["location"],
              let u = URL(string: loc), let h = u.host else { return false }
        let idp = ["login.microsoftonline.com", "sts.", "okta.com", "ping", "adfs", "saml", "idp.", "auth."]
        return h != host && idp.contains { h.contains($0) }
    }

    // MARK: - IKEv2

    /// Send an IKE_SA_INIT and read the responder's chosen proposal + vendor IDs.
    /// Best-effort: a garbage-but-correctly-sized KE is enough for most responders
    /// to answer with their SA selection; a group mismatch yields INVALID_KE (still
    /// telling us the group it wants).
    static func probeIKE(host: String) async -> DiscoveryCandidate? {
        let packet = buildIKESAInit()
        var reply = await udpExchange(host: host, port: 500, send: packet, timeout: 4)
        if reply == nil { reply = await udpExchange(host: host, port: 4500, send: packet, timeout: 4) }
        guard let reply, let parsed = parseIKEResponse(reply) else { return nil }

        var facts: [String: String] = [:]
        if let e = parsed.encryption { facts["encryption"] = e }
        if let i = parsed.integrity { facts["integrity"] = i }
        if let p = parsed.prf { facts["prf"] = p }
        if let d = parsed.dhGroup { facts["dhGroup"] = d }
        if let v = parsed.vendor { facts["vendor"] = v }

        let crypto = [parsed.encryption, parsed.integrity, parsed.dhGroup.map { "Group \($0)" }]
            .compactMap { $0 }.joined(separator: " / ")
        let vendorText = parsed.vendor.map { " · \($0)" } ?? ""
        return DiscoveryCandidate(
            engine: .ikev2, kind: .ikev2, host: host, port: 500, transport: "udp",
            confidence: .high,
            title: "IKEv2 / IPsec",
            detail: "IKEv2 responder\(vendorText)\(crypto.isEmpty ? "" : " · \(crypto)"). Native IPsec VPN (needs the Personal VPN capability to connect).",
            facts: facts)
    }

    // MARK: - OpenVPN

    static func probeOpenVPN(host: String, hintPort: Int?) async -> [DiscoveryCandidate] {
        // (proto, port) worth trying; the hint (if TCP-ish) goes first.
        var targets: [(proto: String, port: Int)] = [("udp", 1194), ("tcp", 1194), ("tcp", 443)]
        if let h = hintPort { targets.insert(("udp", h), at: 0); targets.insert(("tcp", h), at: 1) }

        for t in targets {
            let reply = await openVPNHardReset(host: host, port: t.port, proto: t.proto)
            if reply == .confirmed {
                return [DiscoveryCandidate(
                    engine: .openVPN, kind: .openVPN, host: host, port: t.port, transport: t.proto,
                    confidence: .high,
                    title: "OpenVPN",
                    detail: "OpenVPN listener on \(t.proto)/\(t.port) (no tls-crypt). You'll still need the CA and credentials from the provider.",
                    facts: ["proto": t.proto, "port": "\(t.port)"])]
            }
        }
        return []
    }

    private enum OVPNResult { case confirmed, silent, closed }

    /// Send P_CONTROL_HARD_RESET_CLIENT_V2; a P_CONTROL_HARD_RESET_SERVER_V2 reply
    /// (opcode 8) confirms OpenVPN with no HMAC/tls-crypt guarding the channel.
    private static func openVPNHardReset(host: String, port: Int, proto: String) async -> OVPNResult {
        var sid = [UInt8](repeating: 0, count: 8)
        _ = SecRandomCopyBytes(kSecRandomDefault, sid.count, &sid)
        // opcode (7<<3)=0x38, session id (8), msg packet-id array len (0), packet-id (0)
        var pkt: [UInt8] = [0x38]
        pkt.append(contentsOf: sid)
        pkt.append(0x00)
        pkt.append(contentsOf: [0x00, 0x00, 0x00, 0x00])
        let payload = Data(pkt)

        if proto == "udp" {
            guard let reply = await udpExchange(host: host, port: port, send: payload, timeout: 3) else {
                return .silent
            }
            return (reply.first.map { $0 >> 3 } == 8) ? .confirmed : .silent
        } else {
            // TCP frames the packet with a 2-byte big-endian length prefix.
            var framed = Data([UInt8(payload.count >> 8), UInt8(payload.count & 0xff)])
            framed.append(payload)
            guard let reply = await tcpExchange(host: host, port: port, send: framed, timeout: 3),
                  reply.count >= 3 else { return .closed }
            return (reply[2] >> 3 == 8) ? .confirmed : .silent
        }
    }

    // MARK: - WireGuard (advisory only)

    private static func wireGuardNote(host: String) -> DiscoveryCandidate {
        DiscoveryCandidate(
            engine: .wireGuard, kind: nil, host: host, port: 51820, transport: "udp",
            confidence: .low,
            title: "WireGuard — can't be detected",
            detail: "WireGuard never answers a peer it doesn't already know, so an address alone reveals nothing. If this is WireGuard, import the .conf your provider gave you.",
            facts: [:])
    }
}
