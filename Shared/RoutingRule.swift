// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
//  RoutingRule.swift
//  A user rule that diverts traffic to a destination away from a VPN. Generated
//  from a traffic-log row (or hand-entered). Diversion is by destination IP/CIDR
//  — NEPacketTunnelNetworkSettings routes at the network layer, so port/proto are
//  recorded for display but the match is address-based. Stored per source profile
//  in providerConfiguration["routingRules"] and applied at connect.
//

import Foundation
#if canImport(Darwin)
import Darwin
#endif

nonisolated struct RoutingRule: Codable, Sendable, Identifiable, Equatable {
    enum Action: Codable, Sendable, Equatable {
        case outside                       // send to the physical interface, around this VPN
        case overVPN(profileID: String)    // route into another VPN (future)
    }

    var id: String = UUID().uuidString
    var destination: String                // IPv4/IPv6 address or CIDR (e.g. 142.250.0.0/16)
    var port: Int? = nil                   // informational (route match is address-only)
    var proto: Int? = nil                  // informational
    var action: Action = .outside
    var note: String = ""                  // human label (host that seeded the rule)
    var enabled: Bool = true

    /// Split a CIDR (or bare address) into address + prefix and IP family.
    var parsed: (address: String, prefix: Int, isIPv6: Bool)? {
        let parts = destination.split(separator: "/", maxSplits: 1)
        let addr = String(parts.first ?? "")
        guard !addr.isEmpty else { return nil }
        let isV6 = addr.contains(":")
        let prefix = parts.count == 2 ? (Int(parts[1]) ?? (isV6 ? 128 : 32)) : (isV6 ? 128 : 32)
        return (addr, prefix, isV6)
    }

    /// Whether this rule is a safe, applicable divert. A malformed address, or a
    /// prefix that is out of range or would swallow the default route (prefix 0 =
    /// 0.0.0.0/0 or ::/0), is rejected — a default-route divert is a full VPN
    /// bypass (and an MDM ForceKeepInsideVPN escape), never what a divert means.
    var isValidDivert: Bool { routeDest != nil }

    static func isValidIP(_ s: String, ipv6: Bool) -> Bool {
        var buf = [UInt8](repeating: 0, count: 16)
        return s.withCString { inet_pton(ipv6 ? AF_INET6 : AF_INET, $0, &buf) == 1 }
    }
}

/// A resolved destination for the bridge (address + prefix + family). Used for
/// the "route into this VPN" include-set a target profile carries.
nonisolated struct RouteDest: Codable, Sendable, Equatable {
    var address: String
    var prefix: Int
    var ipv6: Bool
    var dictionary: [String: Any] { ["address": address, "prefix": prefix, "ipv6": ipv6] }
    /// The same destination as a CIDR string — the form every
    /// `*NetworkSettings` builder in Shared parses.
    var cidr: String { "\(address)/\(prefix)" }
}

/// The connect-time divert decision for ONE tunnel, after org policy: which
/// destinations must leave it (its own `.outside` rules) and which destinations
/// other VPNs route INTO it (the target side of their `.overVPN` rules).
///
/// This exists because the policy gating and the two blob decodes were inline in
/// the extension's OpenVPN branch, which is why every other kind silently
/// ignored both sets. One value, built once before the engine dispatch, applied
/// by whichever engine start path runs — the per-kind seam is only *how* it is
/// applied (bridge API, config merge, or a documented "this kind can't").
nonisolated struct DivertPlan: Sendable, Equatable {
    /// This VPN's own diverts: destinations to route around it.
    var outside: [RouteDest] = []
    /// Destinations other VPNs route into this one.
    var inbound: [RouteDest] = []

    var isEmpty: Bool { outside.isEmpty && inbound.isEmpty }
    var outsideCIDRs: [String] { outside.map(\.cidr) }
    var inboundCIDRs: [String] { inbound.map(\.cidr) }
    var outsideDictionaries: [[String: Any]] { outside.map(\.dictionary) }
    var inboundDictionaries: [[String: Any]] { inbound.map(\.dictionary) }

    /// Build the plan from what `providerConfiguration` carries, with the two MDM
    /// gates applied here rather than at each use site.
    ///
    /// `keepInside` (ForceKeepInsideVPN) and `noDiverts` (DisableDivertRules)
    /// both forbid sending traffic around the VPN, so every `.outside` divert is
    /// dropped. Only `noDiverts` forbids over-VPN diverts — under
    /// ForceKeepInsideVPN the traffic still stays inside *a* VPN, so an inbound
    /// route is allowed.
    ///
    /// The source side of an `.overVPN` rule is deliberately NOT excluded from
    /// its source tunnel: excluding it would push that traffic out the physical
    /// interface in CLEARTEXT whenever the target VPN is down. Left in the source
    /// tunnel it stays encrypted (fail-closed); when the target is up its
    /// more-specific included route wins and pulls the destination over instead.
    static func make(rules: [RoutingRule], inbound inboundDests: [RouteDest],
                     keepInside: Bool, noDiverts: Bool) -> DivertPlan {
        var plan = DivertPlan()
        if !keepInside, !noDiverts {
            plan.outside = rules.compactMap { rule in
                guard rule.enabled, case .outside = rule.action else { return nil }
                return rule.routeDest   // rejects malformed / prefix-0 (full bypass)
            }
        }
        if !noDiverts { plan.inbound = inboundDests }
        return plan
    }

    /// Decode straight from a provider configuration + the session's policy flags.
    static func make(providerConfiguration conf: [String: Any]?,
                     keepInside: Bool, noDiverts: Bool) -> DivertPlan {
        make(rules: RoutingRuleStore.decode(from: conf?["routingRules"] as? Data),
             inbound: RouteDestStore.decode(from: conf?["routingIncludes"] as? Data),
             keepInside: keepInside, noDiverts: noDiverts)
    }
}

nonisolated extension VPNKind {
    /// Whether a destination can be routed INTO this kind by another VPN's
    /// `.overVPN` divert. False means the include-set can't be honoured, and the
    /// UI must say so instead of offering a control that does nothing.
    ///
    /// - packet-tunnel kinds we build the routes for (OpenVPN, OpenConnect,
    ///   WireGuard, Proxy Tunnel) can: we own their `NEPacketTunnelNetworkSettings`
    ///   (and, for WireGuard, the peer's allowed IPs, so cryptokey routing agrees).
    ///   The SSL VPNs carry it only while they run on the IN-PROCESS engine — a
    ///   config that forces the `openconnect` tool (`willRunInProcess`) has the tool
    ///   managing its own routes, and the traffic-log note says so at the point of
    ///   the action, because that depends on the profile's settings, not its kind.
    /// - **Tailscale can't**: what a tailnet carries is the netmap's decision
    ///   (exit node / subnet router). An extra included route for a destination
    ///   no peer advertises is a black hole, not a divert.
    /// - the native personal-VPN kinds can't: macOS owns their routing table and
    ///   `NEVPNProtocolIKEv2`/`IPSec` expose no included-routes API.
    /// - SSH can't: it is a subprocess with a SOCKS/port-forward surface, not a
    ///   route-carrying interface we configure.
    var canAcceptRoutedInTraffic: Bool {
        switch self {
        case .openVPN, .wireGuard, .proxyTunnel: true
        case _ where isSSLVPN: true
        default: false
        }
    }

    /// Why this kind can't take another VPN's traffic — user-facing, nil when it can.
    var routedInUnsupportedReason: String? {
        guard !canAcceptRoutedInTraffic else { return nil }
        switch self {
        case .tailscale:
            return "A Tailscale network only carries what your tailnet advertises — a subnet router or an exit node. Set one of those instead; SimpleVPN can't add a route it wouldn't accept."
        case .ikev2, .ipsec, .l2tp:
            return "macOS owns the routes for this kind of VPN, so extra destinations can't be sent into it."
        case .ssh:
            return "An SSH tunnel carries the forwards and SOCKS port you configure, not arbitrary destinations."
        default:
            return "This kind of VPN can't take traffic routed in from another VPN."
        }
    }

    /// Whether a divert stored on THIS VPN can send a destination around it.
    /// Same seam as above: only the kinds whose tunnel settings (or bridge) we
    /// build can carve a destination out.
    var canDivertOutside: Bool {
        switch self {
        case .openVPN, .wireGuard, .proxyTunnel, .tailscale: true
        case _ where isSSLVPN: true
        default: false
        }
    }

    /// Why a divert-around can't be applied to this VPN — nil when it can.
    var divertOutsideUnsupportedReason: String? {
        guard !canDivertOutside else { return nil }
        switch self {
        case .ikev2, .ipsec, .l2tp:
            return "macOS owns the routes for this kind of VPN, so traffic can't be carved out of it here."
        case .ssh:
            return "An SSH tunnel only carries the forwards and SOCKS port you configure, so there is nothing to carve out."
        default:
            return "This kind of VPN can't have destinations carved out of it."
        }
    }
}

nonisolated extension RoutingRule {
    var routeDest: RouteDest? {
        guard let p = parsed else { return nil }
        let maxPrefix = p.isIPv6 ? 128 : 32
        // Reject default-route/overly-broad or out-of-range prefixes and malformed
        // addresses so an invalid or bypass rule can never be applied as a route.
        guard p.prefix > 0, p.prefix <= maxPrefix,
              RoutingRule.isValidIP(p.address, ipv6: p.isIPv6) else { return nil }
        return RouteDest(address: p.address, prefix: p.prefix, ipv6: p.isIPv6)
    }
}

nonisolated enum RouteDestStore {
    static func decode(from blob: Data?) -> [RouteDest] {
        guard let blob else { return [] }
        return (try? JSONDecoder().decode([RouteDest].self, from: blob)) ?? []
    }
    static func encode(_ dests: [RouteDest]) -> Data? {
        dests.isEmpty ? nil : try? JSONEncoder().encode(dests)
    }
}

nonisolated enum RoutingRuleStore {
    static func decode(from blob: Data?) -> [RoutingRule] {
        guard let blob else { return [] }
        return (try? JSONDecoder().decode([RoutingRule].self, from: blob)) ?? []
    }
    static func encode(_ rules: [RoutingRule]) -> Data? {
        rules.isEmpty ? nil : try? JSONEncoder().encode(rules)
    }
}
