// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only

import Foundation

/// Public routing facts only. Never retain a whole engine config here: those
/// configs can contain keys, while a routing diagram must never contain one.
struct EditorRoutingDraft: Equatable {
    var networks: [String]?
    var wantsDefault: Bool?
    var canOwnDefault = true
    var resolvers: [String]?
    var searchDomains: [String] = []
    var connection: [String] = []
    var bypasses: [String] = []
    var notes: [String] = []
    var customRouting: CustomRoutingProfile
    var localProxy: ProxyEndpoint?
    var proxyKnown = false
    var serverSettingsChanged = false
    var dnsEnabled = true
    var acceptsSharedRoutes = true
    var osManaged = false

    static func address(_ raw: String) -> String {
        guard !raw.isEmpty else { return "Server address not set" }
        // Parsing discards paths and query strings and refuses embedded sign-in.
        return VPNSetupServer.parse(raw)?.address ?? "Server address not yet valid"
    }

    static func openVPN(_ config: OpenVPNOverrides, server: String,
                        configurationChanged: Bool, customRouting: CustomRoutingProfile) -> Self {
        var result = Self(connection: [address(config.server ?? server)], customRouting: customRouting)
        result.serverSettingsChanged = configurationChanged
        if let proxy = config.proxyHost, !proxy.isEmpty {
            result.connection.insert("Connection proxy: " + address(proxy), at: 0)
        }
        if config.allowLocalLanAccess == true { result.bypasses.append("The local network stays outside this VPN") }
        if config.allowUnusedAddrFamilies == .allow { result.bypasses.append("Address families the VPN does not carry stay outside it") }
        result.notes.append("Server-supplied routes and DNS are learned at connection")
        if config.googleDnsFallback == true { result.notes.append("Google DNS fallback only when a full tunnel supplies no DNS") }
        return result
    }

    static func wireGuard(_ config: WireGuardConfig, customRouting: CustomRoutingProfile) -> Self {
        var result = Self(networks: config.usesTeleport ? nil : config.allowedIPs,
                          wantsDefault: config.usesTeleport ? nil : config.isFullTunnel,
                          canOwnDefault: config.usesTeleport || config.isFullTunnel,
                          resolvers: config.usesTeleport ? nil : config.dns,
                          searchDomains: config.searchDomains,
                          connection: [config.usesTeleport ? "Server supplied by Teleport" : address(config.endpoint)],
                          customRouting: customRouting)
        result.proxyKnown = true
        if config.allowLocalNetworkAccess { result.bypasses.append("The local network stays outside this VPN") }
        return result
    }

    static func proxy(_ config: ProxyTunnelConfig, customRouting: CustomRoutingProfile) -> Self {
        var result = Self(networks: config.includedRoutes, wantsDefault: config.includeDefaultRoute,
                          canOwnDefault: config.includeDefaultRoute,
                          resolvers: config.dnsServers, searchDomains: config.searchDomains,
                          connection: ["Traffic proxy: " + address(config.upstream)],
                          bypasses: config.excludedRoutes, customRouting: customRouting)
        result.proxyKnown = true
        if config.allowLocalNetworkAccess { result.bypasses.append("The local network stays outside this VPN") }
        return result
    }

    static func sshNetwork(_ config: SSHNetworkTunnelConfig, customRouting: CustomRoutingProfile) -> Self {
        var result = Self(networks: config.includedRoutes, wantsDefault: config.includeDefaultRoute,
                          canOwnDefault: config.includeDefaultRoute,
                          resolvers: SSHNetworkTunnelNetworkSettings.resolvers(for: config),
                          searchDomains: config.searchDomains, connection: [address(config.server)],
                          bypasses: config.excludedRoutes, customRouting: customRouting)
        result.proxyKnown = true
        if config.allowLocalNetworkAccess { result.bypasses.append("The local network stays outside this VPN") }
        result.notes.append("TCP traffic only; other protocols cannot use this SSH tunnel")
        if config.useFarSideResolver { result.notes.append("DNS is forwarded to the server-side resolver") }
        return result
    }

    static func tailscale(_ config: TailscaleConfig, customRouting: CustomRoutingProfile) -> Self {
        var result = Self(wantsDefault: config.useExitNode, canOwnDefault: config.useExitNode,
                          connection: [config.useExitNode ? "Exit machine: " + address(config.exitNode) : "Direct connections to machines on this network"],
                          customRouting: customRouting)
        result.proxyKnown = true
        result.dnsEnabled = config.acceptDNS
        result.acceptsSharedRoutes = config.acceptRoutes
        if config.useExitNode && config.exitNodeAllowLANAccess { result.bypasses.append("The local network stays outside the exit machine") }
        if !config.advertiseRoutes.isEmpty { result.notes.append("Networks offered to other machines: " + config.advertiseRoutes.joined(separator: ", ")) }
        return result
    }

    static func native(_ config: NativeVPNConfig, customRouting: CustomRoutingProfile) -> Self {
        var result = Self(wantsDefault: config.includeAllNetworks, canOwnDefault: false,
                          connection: [address(config.server)], customRouting: customRouting)
        result.proxyKnown = true
        result.osManaged = true
        result.notes.append("macOS manages this VPN's routes and DNS at connection")
        if config.excludeLocalNetworks { result.bypasses.append("Local networks are excluded when sending all traffic") }
        return result
    }

    static func subprocess(_ config: SubprocessTunnelConfig, customRouting: CustomRoutingProfile) -> Self {
        var result = Self(connection: [address(config.server)], customRouting: customRouting)
        if config.kind == .ssh {
            result.proxyKnown = true
            result.networks = []
            result.wantsDefault = false
            result.canOwnDefault = false
            result.resolvers = []
            result.notes.append("Only traffic sent to the configured local ports uses this connection")
            switch config.sshMode {
            case .socks:
                result.notes.append("SOCKS port: \(config.socksPort)")
                if config.setSystemProxy {
                    result.localProxy = ProxyEndpoint(scheme: .socks, host: "127.0.0.1", port: config.socksPort)
                }
            case .portForward: result.notes += config.forwards
            case .netTunnel: result.notes.append("Network tunnel requires server support and separate route configuration")
            }
            if config.useJumpHost { result.connection.insert("Jump host: " + address(config.jumpHost), at: 0) }
        } else {
            result.notes.append("Routes and DNS are supplied by the server; a SOCKS-only fallback does not install host routes")
        }
        return result
    }
}
