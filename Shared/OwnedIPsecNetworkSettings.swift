// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
import Foundation
import NetworkExtension

/// The peer supplies virtual addresses and the authenticated CHILD_SA selectors.
/// Never widen these selectors when constructing the Mac's routes or resolver.
nonisolated struct OwnedIPsecNetworkSettings: Sendable, Equatable {
    let addresses: [String]
    let routes: [String]
    let dns: [String]
    var pppMTU: Int? = nil

    static func hostCIDR(_ host: String) -> String { host + (host.contains(":") ? "/128" : "/32") }

    func settings(gateway: String, excluded: [String], ownsGateway: Bool) throws -> NEPacketTunnelNetworkSettings {
        let locals = TailscaleNetworkSettings.parseAll(addresses.map(Self.hostCIDR))
        let selectors = TailscaleNetworkSettings.parseAll(routes)
        let exclusions = [Self.hostCIDR(gateway)] + excluded
        let carveOuts = TailscaleNetworkSettings.parseAll(exclusions)
        guard !locals.isEmpty, locals.count == addresses.count, selectors.count == routes.count, !selectors.isEmpty,
              carveOuts.count == exclusions.count, locals.allSatisfy({ local in selectors.contains { $0.isIPv6 == local.isIPv6 } })
        else { throw Self.error("The IPsec peer supplied unusable virtual addresses or traffic selectors.") }
        let result = NEPacketTunnelNetworkSettings(tunnelRemoteAddress: gateway)
        if let pppMTU {
            guard (576...1500).contains(pppMTU), locals.count == 1, !locals[0].isIPv6,
                  selectors.count == 1, !selectors[0].isIPv6, selectors[0].isDefaultRoute else {
                throw Self.error("The L2TP peer supplied unusable IPv4 settings or PPP frame size.")
            }
            result.mtu = NSNumber(value: pppMTU)
        } else {
            // Covers outer IPv6, UDP, ESP, an AES-CBC IV, padding and a 32-byte ICV.
            result.tunnelOverheadBytes = 128
        }
        let active = ownsGateway ? selectors : TailscaleNetworkSettings.parseAll(RoutePrefixMath.specificRoutes(in: routes))
        let v4 = locals.filter { !$0.isIPv6 }, v6 = locals.filter(\.isIPv6)
        if !v4.isEmpty {
            let ip = NEIPv4Settings(addresses: v4.map(\.address), subnetMasks: v4.map(\.ipv4Mask))
            ip.includedRoutes = active.filter { !$0.isIPv6 }.map(TailscaleNetworkSettings.ipv4Route)
            ip.excludedRoutes = carveOuts.filter { !$0.isIPv6 }.map(TailscaleNetworkSettings.ipv4Route)
            result.ipv4Settings = ip
        }
        if !v6.isEmpty {
            let ip = NEIPv6Settings(addresses: v6.map(\.address), networkPrefixLengths: v6.map { NSNumber(value: $0.length) })
            ip.includedRoutes = active.filter(\.isIPv6).map(TailscaleNetworkSettings.ipv6Route)
            ip.excludedRoutes = carveOuts.filter(\.isIPv6).map(TailscaleNetworkSettings.ipv6Route)
            result.ipv6Settings = ip
        }
        if !dns.isEmpty, ownsGateway {
            guard dns.allSatisfy({ server in
                let cidr = Self.hostCIDR(server)
                return TailscaleNetworkSettings.parse(cidr) != nil &&
                    locals.contains { $0.isIPv6 == server.contains(":") } &&
                    routes.contains { RoutePrefixMath.overlaps($0, cidr) } &&
                    !exclusions.contains { RoutePrefixMath.overlaps($0, cidr) }
            }) else { throw Self.error("The IPsec peer supplied a DNS resolver outside the tunnel's usable routes.") }
            let resolver = NEDNSSettings(servers: dns)
            resolver.matchDomains = [""]
            result.dnsSettings = resolver
        }
        return result
    }

    static func error(_ text: String) -> NSError {
        NSError(domain: "SimpleVPN.IPsec", code: 1, userInfo: [NSLocalizedDescriptionKey: text])
    }
}
