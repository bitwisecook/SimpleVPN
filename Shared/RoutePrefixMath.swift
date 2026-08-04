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
}
