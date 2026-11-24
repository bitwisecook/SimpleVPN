// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
import Foundation

nonisolated enum StandalonePacketPolicyConfiguration {
    static let sourceKey = "routingEventSource"
    // Released providers with virtual routing decode routingSession before starting any engine.
    // This deliberately non-JSON value makes them reject a protected standalone VPN.
    static let marker = Data("SimpleVPN.standalone-routing.v1".utf8)

    /// The adapter for an actual NETunnelProviderProtocol. External processes and personal VPNs use other transports.
    static func adapterID(for kind: VPNKind, configuration: [String: Any]) -> String? {
        if kind == .ikev2 || kind == .ipsec || kind == .l2tp {
            guard let profile = OwnedIPsecConfiguration.decode(from: configuration), profile.kind == kind else { return nil }
            return profile.adapterID
        }
        if kind == .ssh {
            guard let data = configuration["sshTun"] as? Data,
                  let tun = try? JSONDecoder().decode(SSHTunConfiguration.self, from: data),
                  tun.problem == nil else { return nil }
            return "ssh-tun"
        }
        let teleport = kind == .wireGuard && WireGuardConfig.decode(from: configuration["wireguard"] as? Data).usesTeleport
        let scheme = kind == .proxyTunnel ? ProxyTunnelConfig.decode(from: configuration["proxytunnel"] as? Data).scheme : nil
        return RoutingAdapter.packetID(for: kind, teleport: teleport, proxyScheme: scheme)
    }

    private static func error(_ message: String) -> NSError {
        NSError(domain: "SimpleVPN.PacketPolicy", code: 1, userInfo: [NSLocalizedDescriptionKey: message])
    }

    private static func validate(_ source: String) throws {
        guard !source.isEmpty, source.utf8.count <= 32768, !source.utf8.contains(0) else {
            throw error("Routing rules must contain between 1 and 32,768 UTF-8 bytes and cannot contain a null character.")
        }
    }

    static func store(_ source: String?, in configuration: inout [String: Any]) throws {
        if let source {
            try validate(source)
            guard configuration["routingSession"] == nil || configuration["routingSession"] as? Data == marker else {
                throw error("Edit the shared connection’s routing rules in the composition.")
            }
            configuration[sourceKey] = source
            configuration["routingSession"] = marker
        } else {
            configuration.removeValue(forKey: sourceKey)
            if configuration["routingSession"] as? Data == marker {
                configuration.removeValue(forKey: "routingSession")
            }
        }
    }

    static func source(in configuration: [String: Any]) throws -> String? {
        let marked = configuration["routingSession"] as? Data == marker
        guard marked || configuration[sourceKey] != nil else { return nil }
        guard marked, let source = configuration[sourceKey] as? String else {
            throw error("The saved packet routing policy is incomplete. Save the routing rules again before connecting.")
        }
        try validate(source)
        return source
    }
}
