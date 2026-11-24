// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
import Foundation
@preconcurrency import NetworkExtension

extension NativeVPNConfig {
    var requiresOwnedIPsec: Bool { routingEventSource != nil || (kind == .l2tp && l2tpMSCHAPv2 == true) || (kind == .ikev2 && !usesSharedSecret && eapMSCHAPv2 == true) }

    var ownedConnectionIssue: ConnectNeed? {
        if let serverProblem { return .init(.blocked, locus: .instance, serverProblem, setting: "native.server") }
        if kind == .l2tp && l2tpMSCHAPv2 != true {
            return .init(.blocked, locus: .transport, "Export this L2TP configuration profile and connect it in System Settings, or choose built-in IPv4 with MSCHAPv2.", setting: "native.shared-secret")
        }
        if kind == .ikev2 && !usesSharedSecret && eapMSCHAPv2 != true {
            return .init(.blocked, locus: .entry, "Choose EAP-MSCHAPv2 or a shared secret for the built-in IKEv2 connection. Automatic EAP remains available through System Settings.", setting: "native.username")
        }
        if kind == .ikev2 && username.isEmpty {
            return .init(.needsSignIn, locus: .entry, "Enter the local IKE identifier for this VPN.", setting: "native.username")
        }
        if kind != .ikev2 && (groupOrRealm.isEmpty || remoteID.isEmpty) {
            return .init(.blocked, locus: .entry, "Enter the group or client identifier and the exact authenticated gateway identifier.", setting: groupOrRealm.isEmpty ? "native.group" : "native.remote-id")
        }
        if kind == .l2tp && !OwnedIPsecConfiguration.validPPPCredential(username) {
            return .init(.blocked, locus: .entry, "Enter a printable ASCII PPP username of 1–255 bytes.", setting: "native.username")
        }
        if kind == .ipsec && usesXAuth && username.isEmpty {
            return .init(.needsSignIn, locus: .entry, "Enter the XAuth username.", setting: "native.username")
        }
        if ownedIPsec == nil {
            return .init(.blocked, locus: .entry, "The built-in engine requires exact identities and default IKE algorithms, lifetimes, DPD, MOBIKE and connection settings. Use the original VPN in System Settings to retain different settings.", setting: "native.remote-id")
        }
        return nil
    }

    /// Only combinations implemented by the authenticated strongSwan packet backend.
    var ownedIPsec: OwnedIPsecConfiguration? {
        guard !onDemand, !includeAllNetworks, !disconnectOnSleep, !disableMOBIKE, !enablePFS,
              ikeEncryption.isEmpty, ikeIntegrity.isEmpty, ikeDHGroup.isEmpty, ikeLifetimeMinutes == nil,
              deadPeerDetection.isEmpty, serverProblem == nil else { return nil }
        let v1 = kind == .ipsec
        let l2tp = kind == .l2tp && l2tpMSCHAPv2 == true
        let eap = kind == .ikev2 && !usesSharedSecret && eapMSCHAPv2 == true
        guard v1 || (kind == .ikev2 && usesSharedSecret) || eap || l2tp else { return nil }
        let xauth = v1 && usesXAuth
        let config = OwnedIPsecConfiguration(profileID: id, kind: kind, server: server,
            localID: v1 || l2tp ? groupOrRealm : username, remoteID: !v1 && !l2tp && remoteID.isEmpty ? server : remoteID,
            username: xauth || eap || l2tp ? username : nil, usesXAuth: xauth, usesEAP: eap ? true : nil, usesL2TP: l2tp ? true : nil)
        return config.problem == nil ? config : nil
    }
}

@MainActor
enum NativePacketMirror {
    static func managers() async throws -> [NETunnelProviderManager] {
        try await NETunnelProviderManager.loadAllFromPreferences().filter {
            guard let proto = $0.protocolConfiguration as? NETunnelProviderProtocol else { return false }
            return proto.providerBundleIdentifier == SystemExtensionManager.extensionIdentifier
                && proto.providerConfiguration?["vpnType"] as? String == OwnedIPsecConfiguration.providerKind
        }
    }

    static func profileID(_ manager: NETunnelProviderManager) -> String? {
        (manager.protocolConfiguration as? NETunnelProviderProtocol)?.providerConfiguration?["profile"] as? String
    }

    static func revoke(_ id: String) async throws {
        for manager in try await managers() where profileID(manager) == id {
            guard !UI.isActive(manager.connection.status) else {
                throw ProfilePacketPolicy.failure("Disconnect the IPsec VPN before changing its routing policy.")
            }
            try await manager.removeFromPreferences()
        }
    }

    static func start(_ config: OwnedIPsecConfiguration, name: String, psk: String, xauthPassword: String, pppPassword: String,
                      source: String?, coordinator: VPNController, stillCurrent: () -> Bool) async throws -> NETunnelProviderManager {
        guard !psk.isEmpty, !config.usesXAuth || !xauthPassword.isEmpty else {
            throw ProfilePacketPolicy.failure("Enter the shared secret and any required XAuth password before connecting with the built-in IPsec engine.")
        }
        if config.usesL2TP == true, !OwnedIPsecConfiguration.validPPPCredential(pppPassword) {
            throw ProfilePacketPolicy.failure("Enter the PPP password using 1–255 printable ASCII characters.")
        }
        try await ProfilePacketPolicy.validate(source, adapter: config.adapterID)
        let matches = try await managers().filter { profileID($0) == config.profileID }
        guard matches.count <= 1, !matches.contains(where: { UI.isActive($0.connection.status) }) else {
            throw ProfilePacketPolicy.failure("Disconnect or remove the duplicate IPsec connection before reconnecting.")
        }
        let manager = matches.first ?? NETunnelProviderManager()
        var configuration: [String: Any] = ["profile": config.profileID, "vpnType": OwnedIPsecConfiguration.providerKind,
                                             OwnedIPsecConfiguration.configurationKey: try JSONEncoder().encode(config)]
        try StandalonePacketPolicyConfiguration.store(source, in: &configuration)
        let proto = NETunnelProviderProtocol()
        proto.providerBundleIdentifier = SystemExtensionManager.extensionIdentifier
        proto.serverAddress = config.server
        proto.providerConfiguration = configuration
        manager.protocolConfiguration = proto
        manager.localizedDescription = name
        manager.isEnabled = true
        manager.isOnDemandEnabled = false
        guard stillCurrent() else { throw CancellationError() }
        try await manager.saveToPreferences()
        try await manager.loadFromPreferences()
        guard stillCurrent(), let session = manager.connection as? NETunnelProviderSession,
              let saved = (manager.protocolConfiguration as? NETunnelProviderProtocol)?.providerConfiguration,
              OwnedIPsecConfiguration.decode(from: saved) == config,
              try StandalonePacketPolicyConfiguration.source(in: saved) == source else {
            throw ProfilePacketPolicy.failure("The saved IPsec connection changed. Reopen the profile and try again.")
        }
        let secretKey = config.usesEAP == true ? OwnedIPsecConfiguration.eapPasswordOption : OwnedIPsecConfiguration.pskOption
        var options: [String: NSObject] = [secretKey: Data(psk.utf8) as NSData]
        if config.usesL2TP == true { options[OwnedIPsecConfiguration.pppPasswordOption] = Data(pppPassword.utf8) as NSData }
        if config.usesXAuth { options[OwnedIPsecConfiguration.xauthPasswordOption] = Data(xauthPassword.utf8) as NSData }
        coordinator.nativePacketManagers[config.profileID] = manager
        coordinator.nativePacketProfiles[config.profileID] = .init(id: config.profileID, name: name, server: config.server, status: .connecting, kind: config.kind)
        do { try coordinator.startWithInitialGateway(session, profile: config.profileID, options: options) }
        catch {
            coordinator.nativePacketManagers[config.profileID] = nil
            coordinator.nativePacketProfiles[config.profileID] = nil
            throw error
        }
        return manager
    }
}
