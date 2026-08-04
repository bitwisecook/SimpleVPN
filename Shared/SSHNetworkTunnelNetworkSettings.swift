// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
//  SSHNetworkTunnelNetworkSettings.swift
//  Turns an SSHNetworkTunnelConfig into NEPacketTunnelNetworkSettings.
//
//  Same job as ProxyTunnelNetworkSettings and deliberately the same shape (a
//  fixed on-link utun address, the user's routes, their carve-outs, the DNS they
//  advertise) with one addition that is NOT optional here:
//
//  ── THE SSH SERVER'S OWN ADDRESS IS EXCLUDED FROM THE TUNNEL ──
//
//  For the proxy tunnel that exclusion is belt and braces: NetworkExtension
//  exempts a provider's own sockets from its own tunnel, so the proxy dial leaves
//  via the physical interface even under 0.0.0.0/0, and the /32 only makes the
//  host routing table agree. For THIS kind the stake is different in kind, not
//  degree: the excluded address is the tunnel's own CARRIER. If the session's TCP
//  connection were routed into the utun, its packets would enter the netstack,
//  which would try to open a flow for them over the very session that is trying
//  to establish — a loop that does not merely misroute a connection, it hangs the
//  tunnel with no error anywhere. So the address is resolved once at connect and
//  passed to every settings build for the session, including each live re-apply.
//
//  NO MTU REDUCTION AND NO MSS CLAMP — see SSHNetworkTunnelConfig's header. The
//  netstack terminates the guest's TCP and re-originates a byte stream; nothing
//  is encapsulated, so there is no outer header to make room for.
//

import Foundation
import NetworkExtension
#if canImport(Darwin)
import Darwin
#endif

nonisolated enum SSHNetworkTunnelNetworkSettings {

    /// The utun's own addresses. Same ranges as the proxy tunnel and for the same
    /// reason: 198.18.0.0/15 is the RFC 2544 benchmarking range (never used for
    /// real traffic) and fd00::/8 is unique-local. Deliberately NOT a friendly
    /// RFC 1918 network like 192.168.9.0/24 — that is space a user may genuinely
    /// route, and a tunnel that silently steals it is a tunnel that breaks their
    /// LAN. A different address from the proxy tunnel's would be gratuitous: only
    /// one packet-tunnel provider session runs at a time.
    static let tunnelIPv4 = "198.18.0.1"
    static let tunnelIPv6 = "fd6e:7853:0::1"

    /// Build the settings for a config.
    ///
    /// `remoteAddress` is the SSH server — the honest answer to "what does this
    /// tunnel talk to", and unlike the proxy tunnel it is also literally true.
    ///
    /// `suppressDefaultRoute` is the default-gateway demotion (PolicyRouting.md
    /// Tier 2): when true the config's default route is dropped so this tunnel
    /// carries only its explicit included routes (plus the DNS host routes that
    /// keep its resolvers reachable), without a reconnect.
    ///
    /// `extraExcludedRoutes` are carve-outs the CONNECT decided rather than the
    /// user: the SSH server's own resolved address(es) and this VPN's `.outside`
    /// divert destinations. They are kept out of `SSHNetworkTunnelConfig` so a
    /// computed route can never be mistaken for something the user typed, and
    /// EVERY live re-apply path must re-pass them — dropping them on a gateway
    /// hot-swap would install the loop this file exists to prevent.
    static func settings(for config: SSHNetworkTunnelConfig,
                         suppressDefaultRoute: Bool = false,
                         proxySettings: NEProxySettings? = nil,
                         extraExcludedRoutes: [String] = []) -> NEPacketTunnelNetworkSettings {
        let remote = config.server.trimmingCharacters(in: .whitespacesAndNewlines)
        let s = NEPacketTunnelNetworkSettings(tunnelRemoteAddress: remote.isEmpty ? "127.0.0.1" : remote)

        let useDefaultRoute = config.includeDefaultRoute && !suppressDefaultRoute
        let included: [TailscaleNetworkSettings.Prefix]
        if useDefaultRoute {
            included = [TailscaleNetworkSettings.Prefix(address: "0.0.0.0", length: 0, isIPv6: false),
                        TailscaleNetworkSettings.Prefix(address: "::", length: 0, isIPv6: true)]
        } else {
            included = TailscaleNetworkSettings.parseAll(config.includedRoutes)
        }
        let excluded = TailscaleNetworkSettings.parseAll(config.excludedRoutes + extraExcludedRoutes)

        // Every resolver this tunnel advertises must REACH the tunnel or the
        // netstack never sees the queries. Under a default route they already do;
        // on a split tunnel each needs its own host route.
        var extraDNSRoutes: [TailscaleNetworkSettings.Prefix] = []
        if !useDefaultRoute {
            for server in resolvers(for: config) {
                if let p = TailscaleNetworkSettings.parse(server + (server.contains(":") ? "/128" : "/32")) {
                    extraDNSRoutes.append(p)
                }
            }
        }

        // IPv4.
        let ipv4 = NEIPv4Settings(addresses: [tunnelIPv4], subnetMasks: ["255.255.255.255"])
        let v4Included = (included + extraDNSRoutes).filter { !$0.isIPv6 }
        ipv4.includedRoutes = v4Included.map(ipv4Route)
        let v4Excluded = excluded.filter { !$0.isIPv6 }.map(ipv4Route)
        if !v4Excluded.isEmpty { ipv4.excludedRoutes = v4Excluded }
        s.ipv4Settings = ipv4

        // IPv6, advertised only when something v6 is actually routed — a purely v4
        // setup must not claim a v6 default it cannot service.
        let v6Included = (included + extraDNSRoutes).filter(\.isIPv6)
        if !v6Included.isEmpty {
            let ipv6 = NEIPv6Settings(addresses: [tunnelIPv6], networkPrefixLengths: [128])
            ipv6.includedRoutes = v6Included.map(ipv6Route)
            let v6Excluded = excluded.filter(\.isIPv6).map(ipv6Route)
            if !v6Excluded.isEmpty { ipv6.excludedRoutes = v6Excluded }
            s.ipv6Settings = ipv6
        }

        // DNS. Same rule as the proxy tunnel: a non-empty resolver list becomes
        // the resolver with matchDomains [""] (catch everything), except on a
        // mediator-DEMOTED tunnel, which must not hijack every lookup after losing
        // the gateway arbitration.
        let dnsList = resolvers(for: config)
        if !dnsList.isEmpty, !suppressDefaultRoute {
            let dns = NEDNSSettings(servers: dnsList)
            dns.matchDomains = [""]
            s.dnsSettings = dns
        }

        if let proxySettings { s.proxySettings = proxySettings }

        s.mtu = NSNumber(value: SSHNetworkTunnelConfig.mtuRange.contains(config.mtu)
                         ? config.mtu : SSHNetworkTunnelStartConfig.defaultMTU)
        return s
    }

    /// The resolver addresses to advertise on the utun.
    ///
    /// The far-side sentinel goes FIRST when it is on: it is the resolver the user
    /// asked for, and a stub resolver tries the list in order. The explicitly
    /// listed servers stay after it, so someone who wants both (an internal
    /// resolver at the server, a public one as a fallback) gets both.
    static func resolvers(for config: SSHNetworkTunnelConfig) -> [String] {
        var out: [String] = []
        if config.useFarSideResolver {
            out.append(SSHNetworkTunnelConfig.farSideResolverSentinel)
        }
        for d in config.dnsServers where !out.contains(d) { out.append(d) }
        return out
    }

    /// The SSH server's own address(es) as host routes to keep OUT of this tunnel
    /// — `["203.0.113.9/32"]`, `["2001:db8::1/128"]`, one per resolved address (a
    /// server behind a round-robin name has several).
    ///
    /// This is the tunnel's CARRIER: routing it into the utun is a loop that hangs
    /// the session rather than merely misrouting a connection. See the file header.
    ///
    /// Blocking (`getaddrinfo`): call it ONCE at connect and re-pass the result to
    /// later re-applies — never from inside `settings(for:)`, which runs on the
    /// live gateway/proxy hot-swap paths.
    ///
    /// A literal address needs no lookup. A name that doesn't resolve yields an
    /// empty list: NE's implicit exemption of the provider's own sockets still
    /// carries the session, and failing the tunnel over a belt-and-braces route
    /// would be a regression. It IS logged, because on this kind the fallback is
    /// the only thing standing between the tunnel and the loop.
    static func serverExclusions(host: String) -> [String] {
        ProxyTunnelNetworkSettings.proxyExclusions(host: host)
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
