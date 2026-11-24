// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only

import Foundation
@preconcurrency import NetworkExtension

enum ProfilePacketPolicy {
    static let unsupported = "This connection mode cannot enforce traffic event handlers. Use a supported built-in tunnel or remove the handlers before connecting."
    static let fallback = "The built-in tunnel could not start. The external program cannot enforce this VPN’s traffic event handlers."
    static func adapter(for config: SubprocessTunnelConfig) -> String? {
        if config.kind == .ssh {
            if config.sshMode == .netTunnel { return config.sshTunConfiguration == nil ? nil : "ssh-tun" }
            if SubprocessTunnelManager.willRunInProcessSSH(config) { return "ssh-libssh" }
            return OpenSSHReverseDelivery.layout(for: config)?.adapter
        }
        guard SubprocessTunnelManager.willRunInProcess(config) else { return config.kind.isSSLVPN ? "openconnect-proxy" : nil }
        return RoutingAdapter.packetID(for: config.kind)
    }

    static func validate(_ source: String?, adapter: String?) async throws {
        guard let source else { return }
        guard let adapter else { throw failure(unsupported) }
        if case .rejected(let message) = await RoutingEventValidation.check(source, adapter: adapter) {
            throw failure(message)
        }
    }

    /// Attach a required program before the manager can appear or start on demand.
    static func attach(_ source: String?, to proto: NETunnelProviderProtocol) async throws {
        guard let source else { return }
        try await SystemExtensionManager.requireCurrentProvider()
        var settings = proto.providerConfiguration ?? [:]
        try StandalonePacketPolicyConfiguration.store(source, in: &settings)
        proto.providerConfiguration = settings
    }

    nonisolated static func failure(_ reason: String) -> NSError {
        NSError(domain: "SimpleVPN.ProfileRouting", code: 1, userInfo: [NSLocalizedDescriptionKey: reason])
    }
}

extension VPNController {
    func packetPolicy(for id: String) -> String? {
        let proto = managers[id]?.protocolConfiguration as? NETunnelProviderProtocol
        return proto?.providerConfiguration?[StandalonePacketPolicyConfiguration.sourceKey] as? String
    }

    func hasPacketPolicy(for id: String) -> Bool {
        let config = (managers[id]?.protocolConfiguration as? NETunnelProviderProtocol)?.providerConfiguration
        return config?[StandalonePacketPolicyConfiguration.sourceKey] != nil || config?["routingSession"] as? Data == StandalonePacketPolicyConfiguration.marker
    }

    func packetPolicyAdapter(for id: String) -> String? {
        guard let proto = managers[id]?.protocolConfiguration as? NETunnelProviderProtocol,
              let config = proto.providerConfiguration else { return nil }
        if config["vpnType"] as? String == OwnedIPsecConfiguration.providerKind {
            return OwnedIPsecConfiguration.decode(from: config)?.adapterID
        }
        let kind = (config["vpnType"] as? String).flatMap(VPNKind.init(rawValue:)) ?? .openVPN
        return StandalonePacketPolicyConfiguration.adapterID(for: kind, configuration: config)
    }

    func setPacketPolicy(_ source: String?, for id: String) async throws {
        guard !ManagedPolicy.lockConfiguration else { throw Self.configLocked }
        let adapter = packetPolicyAdapter(for: id)
        try await ProfilePacketPolicy.validate(source, adapter: adapter)
        guard adapter == packetPolicyAdapter(for: id), let manager = managers[id] else {
            throw err("The VPN changed. Open its routing settings again.")
        }
        guard virtualManager(for: id) == nil,
              let token = connectionReservations.reserve(owner: "packet-policy." + id, members: [id]) else {
            throw err("Disconnect the VPN before changing its packet event handlers.")
        }
        defer { connectionReservations.finish(token) }
        try await Self.writePacketPolicy(source, to: manager)
        if managers[id] === manager { managers[id] = manager }
    }

    static func writePacketPolicy(_ source: String?, to manager: NETunnelProviderManager) async throws {
        guard !ManagedPolicy.lockConfiguration else { throw configLocked }
        if source != nil { try await SystemExtensionManager.requireCurrentProvider() }
        guard !UI.isActive(manager.connection.status),
              let current = manager.protocolConfiguration as? NETunnelProviderProtocol,
              let proto = current.copy() as? NETunnelProviderProtocol else {
            throw ProfilePacketPolicy.failure("Disconnect the VPN before changing its packet event handlers.")
        }
        var config = proto.providerConfiguration ?? [:]
        try StandalonePacketPolicyConfiguration.store(source, in: &config)
        proto.providerConfiguration = config
        manager.protocolConfiguration = proto
        do { try await manager.saveToPreferences() }
        catch { manager.protocolConfiguration = current; throw error }
    }
}
