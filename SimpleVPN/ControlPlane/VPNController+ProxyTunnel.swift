// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
//  VPNController+ProxyTunnel.swift
//  The Proxy Tunnel (tun2socks) face of VPNController. Like Tailscale, a Proxy
//  Tunnel is an ordinary packet-tunnel profile — sidebar, status dots, telemetry
//  and map come for free — so only the settings blob, the credential handling
//  and the connect flow differ, and they live here. Stored state (the observable
//  config/status mirrors) lives in VPNController.swift.
//

import Foundation
@preconcurrency import NetworkExtension
import os

extension VPNController {

    // MARK: Proxy Tunnel (tun2socks)
    //
    // A Proxy Tunnel is an ordinary packet-tunnel profile — that is what buys it
    // the sidebar, status dots, telemetry and map for free. Only the settings
    // blob and the connect flow differ, and both live here. One kind, three
    // schemes (socks5/http/https) chosen by the upstream URL — the editor picks;
    // it is never a second VPNKind.


    func isProxyTunnel(_ id: String) -> Bool {
        profiles.first { $0.id == id }?.kind == .proxyTunnel
    }

    func proxyTunnelConfig(for id: String) -> ProxyTunnelConfig {
        if let c = proxyTunnelConfigs[id] { return c }
        let proto = managers[id]?.protocolConfiguration as? NETunnelProviderProtocol
        return ProxyTunnelConfig.decode(from: proto?.providerConfiguration?["proxytunnel"] as? Data)
    }

    /// Create a new Proxy Tunnel. Starts as a SOCKS5 preset with a full-tunnel
    /// default route — the common case — which the editor then refines.
    @discardableResult
    func createProxyTunnel(name: String = "Proxy Tunnel") async throws -> String {
        guard !ManagedPolicy.lockConfiguration else { throw Self.configLocked }
        let id = UUID().uuidString
        let config = ProxyTunnelConfig()
        let mgr = NETunnelProviderManager()
        let proto = NETunnelProviderProtocol()
        proto.providerBundleIdentifier = Self.providerBundleID
        // serverAddress is what macOS shows in Network settings and what the
        // probe/endpoint machinery dials: the proxy host (empty until set).
        proto.serverAddress = config.proxyHost.isEmpty ? "proxy" : config.proxyHost
        var conf: [String: Any] = ["profile": id, "vpnType": VPNKind.proxyTunnel.rawValue]
        if let blob = config.encodedBlob() { conf["proxytunnel"] = blob }
        proto.providerConfiguration = conf
        mgr.protocolConfiguration = proto
        mgr.localizedDescription = name
        mgr.isEnabled = true
        try await mgr.saveToPreferences()
        try await mgr.loadFromPreferences()
        await loadAll()
        selectedID = id
        Self.log.log("created proxy tunnel id=\(id, privacy: .public)")
        return id
    }

    func setProxyTunnelConfig(_ config: ProxyTunnelConfig, for id: String) async throws {
        guard !ManagedPolicy.lockConfiguration else { throw Self.configLocked }
        guard let mgr = managers[id],
              let proto = mgr.protocolConfiguration as? NETunnelProviderProtocol else { return }
        var conf = proto.providerConfiguration ?? [:]
        conf["profile"] = id
        conf["vpnType"] = VPNKind.proxyTunnel.rawValue
        if let blob = config.encodedBlob() { conf["proxytunnel"] = blob }
        proto.providerConfiguration = conf
        proto.serverAddress = config.proxyHost.isEmpty ? "proxy" : config.proxyHost
        mgr.protocolConfiguration = proto
        try await mgr.saveToPreferences()
        try await mgr.loadFromPreferences()
        proxyTunnelConfigs[id] = config
        await loadAll()
    }

    /// The saved proxy credentials (username + password), if any. Their own
    /// keychain item under the profile id, like every other base credential.
    func proxyTunnelCredentials(for id: String) -> (username: String, password: String) {
        let c = KeychainCredentialStore.loadCredentials(profile: id)
        return (c?.username ?? "", c?.password ?? "")
    }

    func setProxyTunnelCredentials(username: String, password: String, for id: String) {
        let u = username.trimmingCharacters(in: .whitespacesAndNewlines)
        if u.isEmpty && password.isEmpty {
            KeychainCredentialStore.deleteCredentials(profile: id)
        } else {
            try? KeychainCredentialStore.saveCredentials(profile: id, .init(username: u, password: password))
        }
    }

    /// Connect a Proxy Tunnel. Credentials (when the proxy needs them) ride
    /// startTunnel options in memory; a no-auth proxy connects with nothing.
    func connectProxyTunnel(id: String) async throws {
        guard let mgr = managers[id],
              mgr.protocolConfiguration is NETunnelProviderProtocol else { throw err("no such profile") }
        if let ensureExtensionReady, !(await ensureExtensionReady()) {
            throw err("SimpleVPN needs its network extension approved before it can connect. Open System Settings ▸ General ▸ Login Items & Extensions ▸ Network Extensions and allow SimpleVPN.")
        }
        let config = proxyTunnelConfig(for: id)
        if let problem = config.connectProblem { throw err(problem) }

        var options: [String: NSObject] = [:]
        if config.requiresAuth {
            let creds = proxyTunnelCredentials(for: id)
            if !creds.username.isEmpty { options["username"] = creds.username as NSString }
            if !creds.password.isEmpty { options["password"] = creds.password as NSString }
        }
        if ManagedPolicy.forceKeepInsideVPN { options["policyKeepInside"] = true as NSNumber }
        // Establish-time default-gateway ownership, same as OpenVPN (RC3).
        options["gatewayOwned"] = predictedGatewayOwned(id) as NSNumber

        mgr.isEnabled = true
        try await mgr.saveToPreferences()
        try await mgr.loadFromPreferences()
        guard let session = mgr.connection as? NETunnelProviderSession else {
            throw err("The VPN configuration isn't ready — try removing and re-creating it.")
        }
        try session.startTunnel(options: options)
        Self.log.log("proxy tunnel startTunnel dispatched for \(id, privacy: .public)")
        resyncStatuses()
    }

    /// Refresh (and publish) the engine status for a connected Proxy Tunnel.
    @discardableResult
    func refreshProxyTunnelStatus(id: String) async -> ProxyTunnelStatus? {
        guard let data = await sendMessageData("pxstatus", to: id),
              let status = try? JSONDecoder().decode(ProxyTunnelStatus.self, from: data) else { return nil }
        proxyTunnelStatuses[id] = status
        return status
    }
}
