// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
//  VPNProbeMenu.swift
//  The right-click "Probe" command, plus the one piece of knowledge behind it:
//  which host/port/protocol a connect would ACTUALLY dial for a saved VPN
//  (overrides first, then the profile's own `remote`, then the manager's server
//  address). Probing anything else would answer a question nobody asked.
//
//  Kept out of ConnectionView on purpose: the menu item carries its own environment
//  so adding it to a context menu is a single line there.
//

import SwiftUI

/// The effective endpoint of a saved VPN — what Connect would dial right now.
struct VPNProbeTarget: Sendable, Equatable {
    var host: String
    var port: Int
    /// "udp" / "tcp" / "" — passed through to the probe as a hint, never a claim.
    var proto: String
    var kind: VPNKind

    /// Port each family lives on when nothing in the profile says otherwise.
    static func defaultPort(for kind: VPNKind) -> Int {
        switch kind {
        case .openVPN: 1194
        case .wireGuard: VPNProbe.wireGuardDefaultPort
        case .ikev2, .ipsec, .l2tp: VPNProbe.ikeDefaultPort
        case .ssh, .sshNetworkTunnel: 22
        default: 443            // the OpenConnect SSL-VPN kinds
        }
    }

    /// Split a stored server address that carries its port ("vpn.example.org:443").
    /// IPv6 literals (many colons) are left alone — there is no port there to take.
    static func splitHostPort(_ address: String) -> (host: String, port: Int?) {
        let parts = address.split(separator: ":", omittingEmptySubsequences: false)
        guard parts.count == 2, let port = Int(parts[1]), (1...65535).contains(port) else {
            return (address, nil)
        }
        return (String(parts[0]), port)
    }

    @MainActor
    static func resolve(profile: VPNController.Profile, vpn: VPNController,
                        evaluator: ProfileEvaluator?) -> VPNProbeTarget {
        let overrides = vpn.overrides(for: profile.id)
        // Only the packet-tunnel kinds have an .ovpn to evaluate; for the rest the
        // manager's server address is the whole truth we hold app-side.
        let eval = vpn.ovpnText(id: profile.id).flatMap { text in evaluator?.evaluation(for: text) }
        let stored = splitHostPort(profile.server)

        let host = overrides.server
            ?? eval?.remoteHostOrNil
            ?? (stored.host.isEmpty ? profile.server : stored.host)
        let port = overrides.port
            ?? eval?.remotePortOrNil
            ?? stored.port
            ?? defaultPort(for: profile.kind)
        let proto = overrides.proto?.rawValue
            ?? eval?.remoteProto
            ?? ""
        return VPNProbeTarget(host: host, port: port, proto: proto, kind: profile.kind)
    }
}

/// How Network Tools names a saved VPN across the four places they're kept
/// (NetworkExtension profiles, subprocess tunnels, WireGuard, native IPsec).
/// A string so it can ride in NetworkToolsRequest without dragging a store —
/// and, crucially, without dragging any key material into a singleton.
nonisolated enum ProbeLadderKey {
    static func make(kind: VPNKind, id: String) -> String { "\(kind.rawValue)/\(id)" }
    static func split(_ key: String) -> (kind: VPNKind, id: String)? {
        guard let slash = key.firstIndex(of: "/"),
              let kind = VPNKind(rawValue: String(key[key.startIndex..<slash])) else { return nil }
        return (kind, String(key[key.index(after: slash)...]))
    }
}

/// "Probe" — opens Network Tools already pointed at this VPN's endpoint, with every
/// test (ping, traceroute, DNS, protocol fingerprint, captive portal) already running,
/// AND the staged step-by-step check for this VPN's own certificates and keys.
struct ProbeVPNMenuItem: View {
    @Bindable var vpn: VPNController
    let profile: VPNController.Profile
    @Environment(ProfileEvaluator.self) private var evaluator: ProfileEvaluator?
    @Environment(\.openWindow) private var openWindow

    var body: some View {
        Button("Probe\u{2026}", systemImage: "stethoscope") {
            let target = VPNProbeTarget.resolve(profile: profile, vpn: vpn, evaluator: evaluator)
            guard !target.host.isEmpty else { return }
            NetworkToolsRequest.shared.probe(
                host: target.host, port: target.port,
                proto: target.proto, vpnKind: target.kind,
                ladderKey: ProbeLadderKey.make(kind: profile.kind, id: profile.id))
            openWindow(id: "tools")
        }
        .help("Check this VPN step by step — the address, the way through this network, its shared key and certificates — and see exactly where it stops")
    }
}
