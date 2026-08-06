// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
//  ProxyTunnelNetworkSettings.swift
//  Turns a ProxyTunnelConfig into NEPacketTunnelNetworkSettings.
//
//  Unlike Tailscale (where the engine decides the netmap and hands it back),
//  the proxy tunnel's shape is entirely the user's config: a fixed on-link
//  address for the utun, the routes they chose (default or a specific list),
//  their carve-outs, and the DNS servers they advertise. The gVisor stack behind
//  the utun accepts whatever those routes deliver and re-dials each flow through
//  the proxy — so this file is the whole "what enters the tunnel" decision, and
//  it is unit-tested because a wrong route here is a tunnel that connects and
//  carries nothing (or everything, into a black hole).
//
//  This lives in Shared and is unit-tested rather than inlined in the provider.
//

import Foundation
import NetworkExtension
#if canImport(Darwin)
import Darwin
#endif

nonisolated enum ProxyTunnelNetworkSettings {

    /// The utun's own addresses. Fixed, from ranges chosen to be unlikely to
    /// collide with anything the user actually routes: 198.18.0.0/15 is the
    /// RFC 2544 benchmarking range (not used for real traffic) and fd00::/8 is
    /// a unique-local prefix. These are only the interface's local addresses —
    /// the routes below decide what traffic is sent to it.
    static let tunnelIPv4 = "198.18.0.1"
    static let tunnelIPv6 = "fd6e:7853:0::1"

    /// Build the settings for a config. `remoteAddress` is cosmetic for a proxy
    /// tunnel (there is no single server the traffic is destined for), so it
    /// reports the proxy's host — the honest "what this tunnel talks to".
    ///
    /// `suppressDefaultRoute` is the default-gateway demotion (PolicyRouting.md
    /// Tier 2): when true, the config's default route is dropped so this tunnel
    /// carries only its explicit included routes (and the DNS /32s that keep its
    /// resolvers reachable) — it stops owning 0.0.0.0/0 without a reconnect.
    /// `proxySettings` is the app-arbitrated system proxy (Proxy mediator applier —
    /// Docs/StateMediators.md), threaded onto the built settings so `proxy:apply` can
    /// hot-swap it by rebuilding + re-applying. nil ⇒ no system proxy asserted.
    ///
    /// `extraExcludedRoutes` are carve-outs the CONNECT decided rather than the
    /// user's config: the upstream proxy's own resolved address(es) (see
    /// `proxyExclusions`) and this VPN's `.outside` divert destinations
    /// (`DivertPlan.outsideCIDRs`). They are kept out of `ProxyTunnelConfig` so a
    /// computed route can never be mistaken for something the user typed, and are
    /// re-passed by every live re-apply path in the provider.
    static func settings(for config: ProxyTunnelConfig,
                         suppressDefaultRoute: Bool = false,
                         proxySettings: NEProxySettings? = nil,
                         extraExcludedRoutes: [String] = []) -> NEPacketTunnelNetworkSettings {
        let remote = config.proxyHost.isEmpty ? "127.0.0.1" : config.proxyHost
        let s = NEPacketTunnelNetworkSettings(tunnelRemoteAddress: remote)

        // Which destinations enter the tunnel. A demoted (split) tunnel behaves
        // exactly like a non-default-route config: only its included routes plus
        // the DNS /32s below.
        let useDefaultRoute = config.includeDefaultRoute && !suppressDefaultRoute
        let included: [TailscaleNetworkSettings.Prefix]
        if useDefaultRoute {
            // Default route both families: everything, minus the carve-outs.
            included = [TailscaleNetworkSettings.Prefix(address: "0.0.0.0", length: 0, isIPv6: false),
                        TailscaleNetworkSettings.Prefix(address: "::", length: 0, isIPv6: true)]
        } else {
            included = TailscaleNetworkSettings.parseAll(config.includedRoutes)
        }
        let excluded = TailscaleNetworkSettings.parseAll(config.excludedRoutes + extraExcludedRoutes)
        // Advertised DNS servers must reach the tunnel or the engine never sees
        // the queries; when NOT using the default route, add each resolver's /32
        // (or /128) so a split-route config still resolves through the proxy.
        var extraDNSRoutes: [TailscaleNetworkSettings.Prefix] = []
        if !useDefaultRoute {
            for server in config.dnsServers {
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

        // IPv6. Advertised only when something v6 is actually routed, so a purely
        // v4 setup does not claim a v6 default it cannot service.
        let v6Included = (included + extraDNSRoutes).filter(\.isIPv6)
        if !v6Included.isEmpty {
            let ipv6 = NEIPv6Settings(addresses: [tunnelIPv6], networkPrefixLengths: [128])
            ipv6.includedRoutes = v6Included.map(ipv6Route)
            let v6Excluded = excluded.filter(\.isIPv6).map(ipv6Route)
            if !v6Excluded.isEmpty { ipv6.excludedRoutes = v6Excluded }
            s.ipv6Settings = ipv6
        }

        // DNS. Non-empty ⇒ these servers become the resolver (matchDomains "" is
        // the standard "catch everything" so all lookups go through the proxy);
        // the /32 (/128) routes added above keep the resolvers reachable on a
        // split tunnel. Empty ⇒ leave the Mac's own resolvers alone.
        //
        // A user-configured split tunnel (includeDefaultRoute == false) that
        // advertises DNS STILL applies those resolvers: that is the whole point of
        // listing them, and a proxy tunnel has no per-domain search-domain scoping
        // to fall back on the way openvpn3 does. Only a mediator-DEMOTED tunnel
        // (suppressDefaultRoute) drops the catch-all, so a non-owner that lost the
        // gateway arbitration can't hijack every lookup — its included routes still
        // carry their own traffic.
        //
        // SEARCH DOMAINS: a proxy pushes nothing, so this kind used to set none —
        // and a tunnel with no search list resolves `wiki.corp.example` but not
        // `wiki` (Docs/Networking.md §4.4). The user's own list is carried in the
        // config; empty stays empty. A DEMOTED tunnel with a list scopes its
        // resolvers to it (the OpenVPN/OpenConnect rule) instead of dropping DNS
        // outright; with no list there is nothing safe to scope to, so it still
        // asserts nothing rather than narrowing to a guess.
        if !config.dnsServers.isEmpty {
            let search = DNSSearchDomains.normalized(config.searchDomains)
            if !suppressDefaultRoute || !search.isEmpty {
                let dns = NEDNSSettings(servers: config.dnsServers)
                if !search.isEmpty { dns.searchDomains = search }
                dns.matchDomains = suppressDefaultRoute ? search : [""]
                s.dnsSettings = dns
            }
        }

        // System proxy: the app-arbitrated decision (owner egress only). A proxy tunnel
        // is itself a proxy EGRESS, so today's arbiter never picks it as the system-
        // proxy owner — this is the forward-looking hot-swap seam for `proxy:apply`.
        if let proxySettings { s.proxySettings = proxySettings }

        s.mtu = NSNumber(value: config.mtu > 0 ? config.mtu : ProxyTunnelStartConfig.defaultMTU)
        return s
    }

    /// The upstream proxy's own address(es) as host routes to keep OUT of this
    /// tunnel — `["203.0.113.9/32"]`, `["2001:db8::1/128"]`, one per resolved
    /// address (a proxy behind a round-robin name has several).
    ///
    /// Why this exists: the engine dials the proxy with the plain OS dialer, and
    /// if the utun owns 0.0.0.0/0 that dial would loop back into the tunnel it is
    /// carrying. Today it works only because NetworkExtension implicitly exempts
    /// the provider process's own sockets from its own tunnel — true, but not
    /// something this app states or controls. These /32s make the host routing
    /// table say it too, so the loop is impossible rather than merely unlikely.
    ///
    /// Blocking (`getaddrinfo`): call it ONCE at connect and re-pass the result to
    /// later re-applies — never from inside `settings(for:)`, which runs on the
    /// live gateway/proxy hot-swap paths.
    ///
    /// A literal address needs no lookup. A name that doesn't resolve yields an
    /// empty list: NE's implicit exemption still carries the dial, and failing the
    /// tunnel over a belt-and-braces route would be a regression.
    static func proxyExclusions(host: String) -> [String] {
        let h = host.trimmingCharacters(in: .whitespaces)
        guard !h.isEmpty else { return [] }
        // Already literal? Then it IS the exclusion — skip the resolver entirely.
        if TailscaleNetworkSettings.parse(h + (h.contains(":") ? "/128" : "/32")) != nil {
            return [h + (h.contains(":") ? "/128" : "/32")]
        }

        var hints = addrinfo(ai_flags: 0, ai_family: AF_UNSPEC, ai_socktype: SOCK_STREAM,
                             ai_protocol: 0, ai_addrlen: 0, ai_canonname: nil,
                             ai_addr: nil, ai_next: nil)
        var out: UnsafeMutablePointer<addrinfo>?
        guard h.withCString({ getaddrinfo($0, nil, &hints, &out) }) == 0, let first = out else { return [] }
        defer { freeaddrinfo(first) }

        var cidrs: [String] = []
        var cursor: UnsafeMutablePointer<addrinfo>? = first
        while let node = cursor {
            if let sa = node.pointee.ai_addr {
                var buf = [CChar](repeating: 0, count: Int(NI_MAXHOST))
                if getnameinfo(sa, node.pointee.ai_addrlen, &buf, socklen_t(buf.count),
                               nil, 0, NI_NUMERICHOST) == 0 {
                    let addr = String(decoding: buf.prefix { $0 != 0 }.map { UInt8(bitPattern: $0) },
                                      as: UTF8.self)
                    // Strip a scope id ("fe80::1%en0") — not a route destination.
                    let bare = addr.split(separator: "%", maxSplits: 1).first.map(String.init) ?? addr
                    let cidr = bare + (bare.contains(":") ? "/128" : "/32")
                    if TailscaleNetworkSettings.parse(cidr) != nil, !cidrs.contains(cidr) {
                        cidrs.append(cidr)
                    }
                }
            }
            cursor = node.pointee.ai_next
        }
        return cidrs
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
