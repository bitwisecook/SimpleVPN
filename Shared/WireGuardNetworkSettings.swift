// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
//  WireGuardNetworkSettings.swift
//  Turns a WireGuardConfig into NEPacketTunnelNetworkSettings.
//
//  Like the proxy tunnel (and unlike Tailscale, where the engine decides the
//  netmap), a WireGuard tunnel's shape is entirely the user's config: the
//  interface addresses, the peer's allowed IPs as routes (cryptokey routing —
//  what isn't routed here the peer wouldn't carry anyway), the DNS servers and
//  the MTU. This is the whole "what enters the tunnel" decision, so it lives
//  in Shared and is unit-tested — a wrong route here is a tunnel that connects
//  and carries nothing.
//
//  `tunnelRemoteAddress` is the RESOLVED endpoint from WGStart's response:
//  NE uses it to route the tunnel's own encrypted UDP around the tunnel, so it
//  must be the literal address the engine actually dials, not the hostname.
//

import Foundation
import NetworkExtension

nonisolated enum WireGuardNetworkSettings {

    /// Build the settings for a config. Returns nil when the config carries no
    /// parseable interface address — applying settings with no addresses tears
    /// the tunnel's IP configuration down.
    ///
    /// `suppressDefaultRoute` is the default-gateway demotion (PolicyRouting.md
    /// Tier 2): when true, the allowed-IPs' default routes are dropped so this
    /// tunnel carries only its specific networks (plus the DNS /32s that keep
    /// its resolvers reachable) — it stops owning 0.0.0.0/0 with no reconnect.
    /// The peer's cryptokey routing still permits the wider traffic; only the
    /// host's routing table changes, exactly like the proxy tunnel's demotion.
    /// `proxySettings` is the app-arbitrated system proxy (Proxy mediator
    /// applier — Docs/StateMediators.md); nil ⇒ none asserted.
    ///
    /// `extraExcludedRoutes` are this VPN's `.outside` divert destinations
    /// (`DivertPlan.outsideCIDRs`) — carve-outs the connect decided, not the
    /// user's `.conf`, so they stay out of `WireGuardConfig` and are re-passed by
    /// the provider's live re-apply paths. wg-quick has no "excluded IPs" concept;
    /// the peer's cryptokey routing still permits these destinations, only the
    /// host's routing table stops handing them to the tunnel. (The other half of a
    /// divert — a destination routed INTO this tunnel — is merged into
    /// `config.allowedIPs` at connect instead, because wireguard-go would drop a
    /// packet whose destination no peer allows.)
    static func settings(for config: WireGuardConfig,
                         resolvedEndpoint: String,
                         suppressDefaultRoute: Bool = false,
                         proxySettings: NEProxySettings? = nil,
                         extraExcludedRoutes: [String] = []) -> NEPacketTunnelNetworkSettings? {
        let locals = TailscaleNetworkSettings.parseAll(config.addresses.map(Self.withPrefixLength))
        guard !locals.isEmpty else { return nil }

        let remote = remoteAddress(fromResolved: resolvedEndpoint, fallbackHost: config.endpointHost)
        let s = NEPacketTunnelNetworkSettings(tunnelRemoteAddress: remote)

        // Which destinations enter the tunnel: the peer's allowed IPs, with the
        // default routes gated out when this tunnel is demoted to split.
        var routes = TailscaleNetworkSettings.parseAll(config.allowedIPs)
        let carriesDefault = routes.contains(where: \.isDefaultRoute) && !suppressDefaultRoute
        if suppressDefaultRoute { routes.removeAll(where: \.isDefaultRoute) }
        // Advertised DNS servers must reach the tunnel or the resolvers go
        // dark on a split tunnel; under a default route they are covered.
        if !carriesDefault {
            for server in config.dns {
                if let p = TailscaleNetworkSettings.parse(server + (server.contains(":") ? "/128" : "/32")) {
                    routes.append(p)
                }
            }
        }

        let excluded = TailscaleNetworkSettings.parseAll(extraExcludedRoutes)
        let v4Locals = locals.filter { !$0.isIPv6 }
        let v6Locals = locals.filter(\.isIPv6)
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

        // DNS. wg-quick semantics: a DNS= line makes those servers the
        // resolver for everything (matchDomains "" is NE's catch-all). Same
        // demotion rule as the proxy tunnel: only a mediator-demoted tunnel
        // drops the catch-all, so a non-owner that lost the gateway
        // arbitration can't hijack every lookup — the /32 routes above still
        // keep its resolvers reachable for its own networks.
        if !config.dns.isEmpty, !suppressDefaultRoute {
            let dns = NEDNSSettings(servers: config.dns)
            dns.matchDomains = [""]
            s.dnsSettings = dns
        }

        // System proxy: the app-arbitrated decision. WireGuard pushes no proxy
        // of its own, so this is only the mediator's hot-swap seam.
        if let proxySettings { s.proxySettings = proxySettings }

        let mtu = config.mtu ?? 0
        s.mtu = NSNumber(value: mtu > 0 ? mtu : WireGuardStartConfig.defaultMTU)
        return s
    }

    /// wg-quick lets Address/AllowedIPs entries omit the prefix (a bare
    /// address means the whole address): normalise before parsing.
    static func withPrefixLength(_ entry: String) -> String {
        let s = entry.trimmingCharacters(in: .whitespaces)
        guard !s.contains("/") else { return s }
        return s + (s.contains(":") ? "/128" : "/32")
    }

    /// The literal address for `tunnelRemoteAddress`, from the engine's
    /// resolved "ip:port" (v6 arrives bracketed).
    static func remoteAddress(fromResolved resolved: String, fallbackHost: String) -> String {
        let s = resolved.trimmingCharacters(in: .whitespaces)
        if s.hasPrefix("[") {
            let inner = String(s.dropFirst().prefix { $0 != "]" })
            if !inner.isEmpty { return inner }
        } else if let colon = s.lastIndex(of: ":"), !s[s.index(after: colon)...].contains(":") {
            let host = String(s[..<colon])
            if !host.isEmpty { return host }
        } else if !s.isEmpty {
            return s
        }
        return fallbackHost.isEmpty ? "127.0.0.1" : fallbackHost
    }

    private static func ipv4Route(_ p: TailscaleNetworkSettings.Prefix) -> NEIPv4Route {
        p.isDefaultRoute ? NEIPv4Route.default()
                         : NEIPv4Route(destinationAddress: p.address, subnetMask: p.ipv4Mask)
    }

    private static func ipv6Route(_ p: TailscaleNetworkSettings.Prefix) -> NEIPv6Route {
        p.isDefaultRoute ? NEIPv6Route.default()
                         : NEIPv6Route(destinationAddress: p.address,
                                       networkPrefixLength: NSNumber(value: p.length))
    }
}
