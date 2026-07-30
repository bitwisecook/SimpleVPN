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

struct RoutingRule: Codable, Sendable, Identifiable, Equatable {
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
struct RouteDest: Codable, Sendable, Equatable {
    var address: String
    var prefix: Int
    var ipv6: Bool
    var dictionary: [String: Any] { ["address": address, "prefix": prefix, "ipv6": ipv6] }
}

extension RoutingRule {
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

enum RouteDestStore {
    static func decode(from blob: Data?) -> [RouteDest] {
        guard let blob else { return [] }
        return (try? JSONDecoder().decode([RouteDest].self, from: blob)) ?? []
    }
    static func encode(_ dests: [RouteDest]) -> Data? {
        dests.isEmpty ? nil : try? JSONEncoder().encode(dests)
    }
}

enum RoutingRuleStore {
    static func decode(from blob: Data?) -> [RoutingRule] {
        guard let blob else { return [] }
        return (try? JSONDecoder().decode([RoutingRule].self, from: blob)) ?? []
    }
    static func encode(_ rules: [RoutingRule]) -> Data? {
        rules.isEmpty ? nil : try? JSONEncoder().encode(rules)
    }
}
