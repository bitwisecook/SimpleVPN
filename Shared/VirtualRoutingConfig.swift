// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only

import Foundation
import NetworkExtension

/// Persisted capture configuration. Member credentials are deliberately absent;
/// the separate start payload exists only in startTunnel's in-memory options.
nonisolated struct VirtualRoutingConfig: Codable, Sendable, Equatable {
    struct Member: Codable, Sendable, Equatable {
        var id: String
        var wireGuard: WireGuardConfig
        var prefixes: [String]
    }
    var version = 1
    var id: String
    var members: [Member]
    var policy: VirtualRoutingPolicy
    static let captureAddresses = ["198.19.255.1", "fd6e:7853:ffff::1"]

    var problem: String? {
        guard version == 1, (2...16).contains(members.count),
              Set(members.map(\.id)).count == members.count else { return "Choose between two and sixteen different VPNs." }
        for member in members {
            if member.wireGuard.addresses.contains(where: { $0.contains(":") }),
               (member.wireGuard.mtu ?? WireGuardStartConfig.defaultMTU) < 1280 {
                return "An IPv6 VPN needs an MTU of at least 1280 for this virtual connection."
            }
            let config = member.wireGuard
            if let problem = config.connectProblem { return "\(config.name): \(problem)" }
            guard config.privateKey.isEmpty, config.presharedKey.isEmpty else {
                return "VPN credentials must be supplied separately from the saved composition."
            }
            guard config.rawExtraPeers.isEmpty else { return "Multiple WireGuard peers are unavailable in a virtual connection." }
            guard config.addresses.allSatisfy({ value in
                guard let address = TailscaleNetworkSettings.parse(value) else { return false }
                return !Self.captureAddresses.contains(address.address)
            }) else { return "A VPN address conflicts with the virtual connection." }
            guard member.prefixes.allSatisfy({ TailscaleNetworkSettings.parse($0) != nil }) else {
                return "A VPN has an invalid routing prefix."
            }
        }
        // NE exposes one resolver configuration per interface. Distinct scoped
        // resolvers require an internal DNS service; refusing them prevents a
        // private lookup being silently sent through the wrong VPN.
        let resolverSets = Set(members.filter { !$0.wireGuard.dns.isEmpty }.map { $0.wireGuard.dns.sorted() })
        if resolverSets.count > 1 { return "These VPNs use different DNS servers. A virtual connection cannot combine those resolvers yet." }
        if policy.defaultOwner.isEmpty, !resolverSets.isEmpty {
            return "Choose a full tunnel to carry DNS for this virtual connection."
        }
        return nil
    }

    func settings(policy: VirtualRoutingPolicy, endpoints: [String],
                  dns: DNSApplyRequest?, proxy: NEProxySettings? = nil) -> NEPacketTunnelNetworkSettings? {
        var capture = WireGuardConfig()
        capture.addresses = Self.captureAddresses.map { $0 + ($0.contains(":") ? "/128" : "/32") }
        capture.allowedIPs = policy.rules.map(\.prefix)
        if policy.capturesDefault { capture.allowedIPs += ["0.0.0.0/0", "::/0"] }
        capture.mtu = 1280
        let excluded = endpoints.compactMap { endpoint -> String? in
            var config = WireGuardConfig()
            config.endpoint = endpoint
            let host = config.endpointHost
            guard WireGuardConfig.isIPLiteral(host) else { return nil }
            return host + (host.contains(":") ? "/128" : "/32")
        }
        guard excluded.count == endpoints.count, !endpoints.isEmpty,
              let settings = WireGuardNetworkSettings.settings(for: capture,
                resolvedEndpoint: endpoints[0], proxySettings: proxy, extraExcludedRoutes: excluded) else { return nil }
        settings.dnsSettings = dns?.makeNEDNSSettings()
        return settings
    }
}

nonisolated struct VirtualRoutingPolicy: Codable, Sendable, Equatable {
    struct Rule: Codable, Sendable, Equatable {
        var prefix: String
        var port: String
    }
    var version = 1
    var revision: UInt64 = 1
    var rules: [Rule] = []
    var defaultOwner: String = ""
    /// nil reads older saved policies. An unavailable egress can retain capture
    /// with no default port; only an explicit Direct choice releases that route.
    var captureDefault: Bool? = nil
    var capturesDefault: Bool { captureDefault ?? !defaultOwner.isEmpty }
}

/// One transaction for every member sharing an interface. A missing owner means
/// either another interface owns the default, explicit Direct, or unavailable VPN.
nonisolated struct VirtualRouteApplyRequest: Codable, Sendable {
    var owner: String
    var retainUnavailableDefault: Bool
    var routes: [String: RouteApplyRequest]

    func applying(to policy: VirtualRoutingPolicy) -> VirtualRoutingPolicy {
        var next = policy
        next.defaultOwner = owner
        next.captureDefault = !owner.isEmpty || (retainUnavailableDefault && policy.capturesDefault)
        return next
    }
}

nonisolated struct VirtualRoutingStartConfig: Codable, Sendable {
    struct Member: Codable, Sendable {
        var id: String
        var addresses: [String]
        var wireGuard: WireGuardStartConfig
    }
    var version = 1
    var captureAddresses = VirtualRoutingConfig.captureAddresses
    var underlayInterfaceIndex: UInt32 = 0
    var members: [Member]
    var policy: VirtualRoutingPolicy
}

nonisolated struct VirtualRoutingMessage: Codable, Sendable {
    var profile: String
    var message: String
}

nonisolated struct VirtualRoutingStatus: Codable, Sendable {
    struct Routing: Codable, Sendable {
        var revision: UInt64
        var flows: Int
        var packetsOut: UInt64
        var packetsIn: UInt64
        var drops: [String: UInt64]
    }
    var state: String
    var mtu: Int
    var routing: Routing
    var ports: [String: WireGuardEngineStatus]
}
