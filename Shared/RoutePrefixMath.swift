// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
//  RoutePrefixMath.swift
//  CIDR prefix arithmetic, protocol-neutral and dependency-free. Grew up inside
//  SimpleVPN/Mediators/CustomRouting.swift for the Custom Routing rule checker;
//  it lives in Shared/ now because config validators that must compile into the
//  extension too (ProxyTunnelConfig.routeOverlapWarning) need it as well, and
//  two copies of mask arithmetic is exactly how two answers to "do these
//  overlap?" start to disagree.
//

import Foundation
#if canImport(Darwin)
import Darwin
#endif

/// Whether two CIDR prefixes intersect (one contains the other). Same address family only.
/// Used by `RuleStatus` to flag an Add that overlaps a pushed route, and by the Proxy Tunnel
/// editor to warn that an exclusion swallows part of an inclusion — the filter's own route
/// matching is deliberately EXACT prefix + default token (a documented follow-up is
/// contains-matching in the filter itself).
nonisolated enum RoutePrefixMath {

    static func defaultRoutePrefixes(in routes: [String]) -> Set<String> {
        defaults(in: Set(routes.compactMap(canonicalNetwork)))
    }

    private static func defaults(in networks: Set<String>) -> Set<String> {
        var defaults = networks.intersection(["0.0.0.0/0", "::/0"])
        for halves: Set<String> in [["0.0.0.0/1", "128.0.0.0/1"], ["::/1", "8000::/1"]] where networks.isSuperset(of: halves) {
            defaults.formUnion(halves)
        }
        return defaults
    }

    static func specificRoutes(in routes: [String]) -> [String] {
        let networks = routes.map { canonicalNetwork($0) ?? $0 }
        let defaults = defaults(in: Set(networks))
        return networks.filter { !defaults.contains($0) }
    }

    static func overlaps(_ a: String, _ b: String) -> Bool {
        guard let pa = parse(a), let pb = parse(b), pa.v6 == pb.v6 else { return false }
        return prefixEqual(pa.bytes, pb.bytes, bits: min(pa.prefix, pb.prefix))
    }

    private static func parse(_ s: String) -> (bytes: [UInt8], prefix: Int, v6: Bool)? {
        let trimmed = s.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else { return nil }
        let parts = trimmed.split(separator: "/", maxSplits: 1, omittingEmptySubsequences: false)
        let addrStr = String(parts[0])
        let v6 = addrStr.contains(":")
        let maxLen = v6 ? 128 : 32
        var prefix = maxLen
        if parts.count == 2 {
            guard let p = Int(parts[1]), p >= 0, p <= maxLen else { return nil }
            prefix = p
        }
        var buf = [UInt8](repeating: 0, count: v6 ? 16 : 4)
        let ok = addrStr.withCString { inet_pton(v6 ? AF_INET6 : AF_INET, $0, &buf) == 1 }
        guard ok else { return nil }
        return (buf, prefix, v6)
    }

    private static func prefixEqual(_ a: [UInt8], _ b: [UInt8], bits: Int) -> Bool {
        guard a.count == b.count else { return false }
        let fullBytes = bits / 8
        for i in 0..<fullBytes where a[i] != b[i] { return false }
        let rem = bits % 8
        if rem > 0 {
            let mask = UInt8(truncatingIfNeeded: 0xFF << (8 - rem))
            if (a[fullBytes] & mask) != (b[fullBytes] & mask) { return false }
        }
        return true
    }

    /// The routing wire format uses a network address and prefix length, even
    /// for a single host. netip on the other side rejects IPv4-mapped IPv6.
    static func canonicalNetwork(_ value: String) -> String? {
        guard value.utf8.count <= 80, !value.utf8.contains(0), let parsed = parse(value),
              !hasHostBits(parsed.bytes, prefix: parsed.prefix, byteCount: parsed.bytes.count) else { return nil }
        if parsed.v6 && parsed.bytes.prefix(10).allSatisfy({ $0 == 0 })
            && parsed.bytes[10] == 255 && parsed.bytes[11] == 255 { return nil }
        let address = masked(address: parsed.bytes, prefix: parsed.prefix, isV6: parsed.v6)
        return address.isEmpty ? nil : address + "/" + String(parsed.prefix)
    }

    static func hasHostBits(_ bytes: [UInt8], prefix: Int, byteCount: Int) -> Bool {
        for i in 0..<byteCount {
            let bitsBefore = i * 8
            if prefix >= bitsBefore + 8 { continue }          // whole byte inside the prefix
            let keep = max(0, min(8, prefix - bitsBefore))
            let mask: UInt8 = keep == 0 ? 0 : UInt8(truncatingIfNeeded: 0xFF << (8 - keep))
            if bytes[i] & ~mask != 0 { return true }
        }
        return false
    }

    static func masked(address bytes: [UInt8], prefix: Int, isV6: Bool) -> String {
        let byteCount = isV6 ? 16 : 4
        var out = bytes
        for i in 0..<byteCount {
            let bitsBefore = i * 8
            let keep = max(0, min(8, prefix - bitsBefore))
            let mask: UInt8 = keep == 0 ? 0 : UInt8(truncatingIfNeeded: 0xFF << (8 - keep))
            out[i] = bytes[i] & mask
        }
        var buf = [CChar](repeating: 0, count: Int(INET6_ADDRSTRLEN))
        let s = out.withUnsafeBytes { raw -> String in
            guard let base = raw.baseAddress,
                  let p = inet_ntop(isV6 ? AF_INET6 : AF_INET, base, &buf, socklen_t(INET6_ADDRSTRLEN))
            else { return "" }
            return String(cString: p)
        }
        return s
    }
}
