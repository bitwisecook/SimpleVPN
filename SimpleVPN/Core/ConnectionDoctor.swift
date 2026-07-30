// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
//  ConnectionDoctor.swift
//  A rules layer over the telemetry the app already collects (link health, the
//  network topology, the last incident, the running stats and the profile's
//  overrides/.ovpn) that recognises the common real-world VPN failure modes and
//  offers a specific, reversible fix for each — the "symptom → cause → fix"
//  matrix from the research, encoded. Each rule returns at most one finding;
//  a finding carries plain-English text, a manual anchor, and either an
//  auto-fix (an override mutation or a .ovpn directive edit) or an explanation
//  when the real fix is server-side.
//

import Foundation
import NetworkExtension

/// Everything a rule may inspect. Assembled on the main actor from live sources;
/// the rules themselves are pure functions of it.
struct DoctorSnapshot {
    var status: NEVPNStatus = .invalid
    var overrides = OpenVPNOverrides()
    var ovpn = ""
    var stats: TunnelStats?
    var stalledSeconds: Int?              // from ThroughputMonitor.linkHealth == .stalled
    var topology = NetworkTopology()
    var incident: TunnelIncident?
    var requiresOTP = false
    var captivePortalSuspected = false
    var pathMTU: Int?                     // from the DF-ping sizer, when run
    var udpBlockedTCP443Open: Bool?       // from the pre-flight probe, when run

    var isConnected: Bool { status == .connected || status == .reasserting }
    /// v4-only tunnel = we were assigned a tunnel v4 but no tunnel v6.
    var tunnelIsV4Only: Bool {
        let s = stats
        return !(s?.tunnelIPv4 ?? "").isEmpty && (s?.tunnelIPv6 ?? "").isEmpty
    }
}

/// What a finding's "Fix it" does.
enum DoctorFix {
    case overrides((inout OpenVPNOverrides) -> Void)  // ClientAPI override + reconnect
    case editOVPN((String) -> String)                // rewrite the .ovpn + reconnect
    case explain                                               // server-side / manual only

    var isExplain: Bool { if case .explain = self { return true }; return false }
}

struct DoctorFinding: Identifiable {
    enum Severity: Int, Sendable { case advice = 0, warning = 1, critical = 2 }
    let id: String
    let severity: Severity
    let title: String
    let detail: String
    let manualAnchor: String
    var fixLabel: String? = nil     // nil ⇒ explanation-only
    var risky = false               // amber emphasis (weakens security / deliberate leak)
    let fix: DoctorFix
}

struct ConnectionRule {
    let id: String
    let evaluate: (DoctorSnapshot) -> DoctorFinding?
}

enum ConnectionDoctor {

    static func findings(for s: DoctorSnapshot) -> [DoctorFinding] {
        rules.compactMap { $0.evaluate(s) }
            .sorted { $0.severity.rawValue > $1.severity.rawValue }
    }

    // MARK: Rules (see manual "Common problems" for the anchors)

    static let rules: [ConnectionRule] = [

        // 1. MTU / PMTUD blackhole — TX flowing, RX flat for a while at the ~1400
        //    boundary (ThroughputMonitor already classifies this as .stalled).
        ConnectionRule(id: "mtu-blackhole") { s in
            guard s.isConnected, let secs = s.stalledSeconds, secs >= 8 else { return nil }
            // Skip if an aggressive mssfix is already in place.
            if let m = OVPNInline.directiveValue("mssfix", in: s.ovpn), let n = Int(m), n <= 1360 { return nil }
            let mss = (s.pathMTU.map { max(576, $0 - 40) }) ?? 1360
            return DoctorFinding(
                id: "mtu-blackhole", severity: .critical,
                title: "Large transfers stall (MTU problem)",
                detail: "Small requests work but big ones hang — a classic sign that oversized packets are being dropped and the “please fragment” message is filtered. Clamping the segment size to \(mss) fixes it.",
                manualAnchor: "problem-mtu", fixLabel: "Set mssfix \(mss)",
                fix: .editOVPN { OVPNInline.setDirective("mssfix", "\(mss)", in: $0) })
        },

        // 2. IPv6 leak — v4-only tunnel while the Mac keeps a global v6 default
        //    over a physical interface.
        ConnectionRule(id: "ipv6-leak") { s in
            guard s.isConnected, s.tunnelIsV4Only, s.overrides.allowUnusedAddrFamilies != .block else { return nil }
            let leaks = s.topology.interfaces.contains { i in
                i.kind != .tunnel && i.ipv6.contains { !$0.hasPrefix("fe80") }
            }
            guard leaks else { return nil }
            return DoctorFinding(
                id: "ipv6-leak", severity: .warning,
                title: "IPv6 traffic may bypass the VPN",
                detail: "This tunnel only carries IPv4, but your Mac still has a public IPv6 address — so IPv6-capable sites can reach the internet outside the VPN and see your real address. Blocking the traffic the VPN doesn't carry closes that leak.",
                manualAnchor: "problem-ipv6-leak", fixLabel: "Block traffic outside the VPN",
                fix: .overrides { $0.allowUnusedAddrFamilies = .block })
        },

        // 3. DNS leak — full tunnel but the VPN set no DNS server, so name lookups
        //    can still go to the local network and reveal where you're browsing.
        ConnectionRule(id: "dns-leak") { s in
            guard s.isConnected, ConnectionManager.isFullTunnel(s.topology) == true else { return nil }
            guard (s.stats?.dnsServers ?? []).isEmpty else { return nil }
            return DoctorFinding(
                id: "dns-leak", severity: .warning,
                title: "Website lookups may be leaking",
                detail: "All your traffic goes through this VPN, but it didn't set a private DNS server — so the names of the sites you visit can still be looked up by your local network, revealing where you're browsing even though the traffic itself is protected. Ask the VPN's administrator to push a DNS server.",
                manualAnchor: "problem-dns-leak", fix: .explain)
        },

        // 4. UDP blocked (pre-flight probe): UDP silent, TCP 443 open.
        ConnectionRule(id: "udp-blocked") { s in
            guard s.udpBlockedTCP443Open == true, s.overrides.proto != .tcp else { return nil }
            return DoctorFinding(
                id: "udp-blocked", severity: .critical,
                title: "This network blocks the VPN's UDP traffic",
                detail: "The VPN's UDP packets aren't getting out, but TCP port 443 works — typical of hotel, airport and guest Wi-Fi. Switching to TCP on 443 makes the VPN look like ordinary secure web traffic and usually gets through.",
                manualAnchor: "problem-udp-blocked", fixLabel: "Use TCP on port 443",
                fix: .overrides { $0.proto = .tcp; $0.port = 443 })
        },

        // 5. OTP forced re-auth — AUTH_FAILED soon after a good connect, OTP
        //    profile, and renegotiation isn't disabled.
        ConnectionRule(id: "otp-reneg") { s in
            guard s.requiresOTP, let i = s.incident, i.event.contains("AUTH_FAILED") else { return nil }
            if OVPNInline.directiveValue("reneg-sec", in: s.ovpn) == "0" { return nil }
            return DoctorFinding(
                id: "otp-reneg", severity: .warning,
                title: "Keeps asking for a new code after connecting",
                detail: "OpenVPN renegotiates the session on a timer, which re-runs sign-in — and your one-time code is already spent, so it fails. Turning off client-side renegotiation stops that. (The server can also issue a session token via auth-gen-token so codes are never re-demanded.)",
                manualAnchor: "problem-otp-reneg", fixLabel: "Disable renegotiation (reneg-sec 0)",
                fix: .editOVPN { OVPNInline.setDirective("reneg-sec", "0", in: $0) })
        },

        // 6. Data-cipher negotiation mismatch — engine offers only its modern AEAD
        //    set; server wants an older cipher. openvpn3 honours this via the
        //    "non-preferred data ciphers" override (AES-CBC), not --data-ciphers.
        ConnectionRule(id: "cipher-mismatch") { s in
            guard let i = s.incident,
                  i.info.localizedCaseInsensitiveContains("cipher") || i.event.localizedCaseInsensitiveContains("cipher"),
                  s.overrides.enableNonPreferredDCAlgorithms != true else { return nil }
            return DoctorFinding(
                id: "cipher-mismatch", severity: .warning,
                title: "Couldn't agree on an encryption cipher",
                detail: "The server wants an older data cipher (such as AES-CBC) than this app offers by default. Allowing the older-but-still-secure ciphers lets the connection negotiate one.",
                manualAnchor: "problem-cipher", fixLabel: "Allow older data ciphers",
                fix: .overrides { $0.enableNonPreferredDCAlgorithms = true })
        },

        // 7. Server certificate verification failed — never auto-weaken; explain.
        ConnectionRule(id: "cert-verify") { s in
            guard let i = s.incident,
                  i.category == .tlsIdentity
                  || i.info.localizedCaseInsensitiveContains("verify")
                  || i.info.localizedCaseInsensitiveContains("certificate") else { return nil }
            return DoctorFinding(
                id: "cert-verify", severity: .critical,
                title: "The server's identity couldn't be verified",
                detail: "The VPN server presented a certificate SimpleVPN doesn't trust — it may be expired, self-signed, from a private authority, or the certificate authority in the configuration is missing or wrong. Contact the VPN's administrator; don't weaken certificate checks to work around this.",
                manualAnchor: "problem-cert", fix: .explain)
        },

        // Captive portal in the way.
        ConnectionRule(id: "captive-portal") { s in
            guard s.captivePortalSuspected else { return nil }
            return DoctorFinding(
                id: "captive-portal", severity: .warning,
                title: "A Wi-Fi sign-in page is blocking the connection",
                detail: "This network wants you to accept terms or sign in a browser first. Open any website to complete that, then connect the VPN.",
                manualAnchor: "problem-captive", fix: .explain)
        },
    ]
}
