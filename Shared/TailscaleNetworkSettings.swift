// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
//  TailscaleNetworkSettings.swift
//  Turns the engine's netmapChanged payload into NEPacketTunnelNetworkSettings.
//
//  This is the one translation in the Tailscale path that can silently produce
//  a tunnel that connects and carries nothing, so it lives in Shared and is
//  unit-tested rather than being inlined in the provider. The engine already
//  decided everything (it hands us router.Config + dns.OSConfig); this file
//  only re-spells CIDRs as NE's address/mask pairs and picks the right
//  IPv4/IPv6 bucket for each.
//

import Foundation
import NetworkExtension
#if canImport(Darwin)
import Darwin
#endif

nonisolated enum TailscaleNetworkSettings {

    /// A CIDR split into the parts NE wants.
    nonisolated struct Prefix: Sendable, Equatable {
        var address: String
        var length: Int
        var isIPv6: Bool

        /// Dotted-quad netmask — NEIPv4Route/NEIPv4Settings take a mask, not a
        /// prefix length.
        var ipv4Mask: String {
            guard !isIPv6 else { return "255.255.255.255" }
            let bits = UInt32(length >= 32 ? 0xFFFF_FFFF : (length <= 0 ? 0 : ~UInt32(0) << (32 - length)))
            return "\((bits >> 24) & 0xFF).\((bits >> 16) & 0xFF).\((bits >> 8) & 0xFF).\(bits & 0xFF)"
        }

        var isDefaultRoute: Bool { length == 0 }
    }

    /// Parse "100.64.0.1/32" / "fd7a::1/128". Returns nil for anything the
    /// engine could not plausibly have produced — a malformed entry is dropped
    /// rather than aborting the whole settings apply, because losing one route
    /// beats losing the tunnel.
    static func parse(_ cidr: String) -> Prefix? {
        let parts = cidr.split(separator: "/", maxSplits: 1, omittingEmptySubsequences: false)
        guard parts.count == 2, let length = Int(parts[1]) else { return nil }
        let address = String(parts[0])
        let isV6 = address.contains(":")
        guard length >= 0, length <= (isV6 ? 128 : 32) else { return nil }
        var buf = [UInt8](repeating: 0, count: 16)
        guard address.withCString({ inet_pton(isV6 ? AF_INET6 : AF_INET, $0, &buf) == 1 }) else { return nil }
        return Prefix(address: address, length: length, isIPv6: isV6)
    }

    static func parseAll(_ cidrs: [String]) -> [Prefix] { cidrs.compactMap(parse) }

    /// Build the settings for a netmapChanged payload. Returns nil when the
    /// engine has not yet assigned this node an address — applying settings
    /// with no addresses at all tears the tunnel's IP configuration down.
    ///
    /// `tunnelRemoteAddress` is cosmetic for a mesh VPN (there is no single
    /// server), so it reports this node's own address rather than inventing a
    /// peer that traffic would appear to be destined for.
    /// `proxySettings` is the app-arbitrated system proxy (Proxy mediator applier —
    /// Docs/StateMediators.md), threaded onto the built settings so `proxy:apply` can
    /// hot-swap it by rebuilding + re-applying from the last netmap. nil ⇒ none.
    static func settings(for config: TailscaleTunnelConfig,
                         proxySettings: NEProxySettings? = nil) -> NEPacketTunnelNetworkSettings? {
        let locals = parseAll(config.localAddrs)
        guard !locals.isEmpty else { return nil }

        let v4Locals = locals.filter { !$0.isIPv6 }
        let v6Locals = locals.filter { $0.isIPv6 }
        let remote = v4Locals.first?.address ?? v6Locals.first?.address ?? "127.0.0.1"
        let s = NEPacketTunnelNetworkSettings(tunnelRemoteAddress: remote)

        let routes = parseAll(config.routes)
        let excluded = parseAll(config.localRoutes)

        if !v4Locals.isEmpty {
            let ipv4 = NEIPv4Settings(addresses: v4Locals.map(\.address),
                                      subnetMasks: v4Locals.map(\.ipv4Mask))
            ipv4.includedRoutes = routes.filter { !$0.isIPv6 }.map(ipv4Route)
            let ex = excluded.filter { !$0.isIPv6 }.map(ipv4Route)
            if !ex.isEmpty { ipv4.excludedRoutes = ex }
            s.ipv4Settings = ipv4
        }
        if !v6Locals.isEmpty {
            let ipv6 = NEIPv6Settings(addresses: v6Locals.map(\.address),
                                      networkPrefixLengths: v6Locals.map { NSNumber(value: $0.length) })
            ipv6.includedRoutes = routes.filter(\.isIPv6).map(ipv6Route)
            let ex = excluded.filter(\.isIPv6).map(ipv6Route)
            if !ex.isEmpty { ipv6.excludedRoutes = ex }
            s.ipv6Settings = ipv6
        }

        // DNS. An empty nameserver list means "accept DNS is off" — leave the
        // Mac's own resolvers alone rather than installing an empty resolver
        // that would break every lookup on the machine.
        if !config.dns.nameservers.isEmpty {
            let dns = NEDNSSettings(servers: config.dns.nameservers)
            if !config.dns.searchDomains.isEmpty { dns.searchDomains = config.dns.searchDomains }
            // matchDomains non-empty ⇒ split DNS: only these suffixes go to the
            // tailnet resolver. Empty ⇒ this resolver becomes the primary one.
            if !config.dns.matchDomains.isEmpty { dns.matchDomains = config.dns.matchDomains }
            s.dnsSettings = dns
        }

        // System proxy: the app-arbitrated decision. Tailscale pushes no proxy and the
        // arbiter classifies it as a non-provider, so it is never the system-proxy owner
        // today — this is the forward-looking hot-swap seam for `proxy:apply`.
        if let proxySettings { s.proxySettings = proxySettings }

        s.mtu = NSNumber(value: config.mtu > 0 ? config.mtu : TailscaleStartConfig.defaultMTU)
        return s
    }

    private static func ipv4Route(_ p: Prefix) -> NEIPv4Route {
        p.isDefaultRoute ? NEIPv4Route.default()
                         : NEIPv4Route(destinationAddress: p.address, subnetMask: p.ipv4Mask)
    }

    private static func ipv6Route(_ p: Prefix) -> NEIPv6Route {
        p.isDefaultRoute ? NEIPv6Route.default()
                         : NEIPv6Route(destinationAddress: p.address,
                                       networkPrefixLength: NSNumber(value: p.length))
    }
}
