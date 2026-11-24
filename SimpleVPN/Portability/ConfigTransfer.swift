// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
//  ConfigTransfer.swift
//  The live half: reading the app's current state into a `ConfigSnapshot`, and
//  applying an approved `ConfigImportPlan` back. Everything that touches
//  `VPNController`, the two `UserDefaults`-backed stores, the label catalog or the
//  filesystem is here, and nothing else is — so the format, the scrubbing and the
//  validation stay testable without a running app (see ConfigDocument.swift).
//
//  TWO RULES THIS FILE ENFORCES, both from Docs/SecretsAndSync.md:
//
//  • MDM `lockConfiguration` STOPS BOTH DIRECTIONS. Import is obvious — it is a
//    configuration change, and every mutating method already refuses. Export is the
//    one worth stating: a managed Mac may forbid configuration LEAVING the device,
//    and a whole-configuration file is the most complete form of leaving there is.
//    The buttons are disabled and say why; this is the enforcement that a
//    programmatic path cannot walk around.
//
//  • NOTHING IS DESTROYED WITHOUT A WAY BACK. Before a single setting is written,
//    the CURRENT configuration is exported to a recovery file and READ BACK — if
//    that fails, the import does not start. Write, verify, only then change: the
//    same order `migrateInlineOVPNSecrets()` uses, and for the same reason. VPNs are
//    never overwritten at all; they are added alongside.
//

import Foundation
import LocalAuthentication
import os

@MainActor
enum ConfigTransfer {

    private static let log = Logger(subsystem: "com.bragi0.SimpleVPN", category: "config-transfer")

    /// Why export and import are unavailable, or nil when they are available.
    static var policyRefusal: String? {
        ManagedPolicy.lockConfiguration
            ? "Your organization has locked SimpleVPN\u{2019}s settings, so they can\u{2019}t be exported or imported on this Mac."
            : nil
    }

    // MARK: Reading the Mac

    static func snapshot(vpn: VPNController,
                        tunnels: SubprocessTunnelStore,
                        nativeVPN: NativeVPNManager,
                        labels: LabelStore, profileID: String? = nil) -> ConfigSnapshot {
        var snapshot = ConfigSnapshot()
        snapshot.appVersion = UI.appVersion
        if profileID == nil { snapshot.appSettings = ConfigAppSettings.snapshot() }
        let selectedLabels = profileID.map { labels.labels(for: $0) } ?? labels.labels
        snapshot.labels = selectedLabels.map {
            ConfigLabel(id: $0.id, name: $0.name, red: $0.r, green: $0.g, blue: $0.b)
        }

        // The packet-tunnel VPNs, in the order the sidebar shows them.
        let standalone = ConnectListing.standaloneProfiles(vpn.profiles, tunnels: tunnels.tunnels)
        for profile in standalone where profileID == nil || profileID == profile.id {
            var entry = ConfigSnapshot.VPN(id: profile.id, name: profile.name,
                                           kind: profile.kind, server: profile.server)
            entry.labelIDs = labels.labels(for: profile.id).map(\.id)
            entry.routingEventSource = vpn.packetPolicy(for: profile.id)
            switch profile.kind {
            case .openVPN:
                // The STORED text, not the reassembled one: the point of export is
                // what is persisted, and `ConfigDocument` splits it again anyway.
                entry.ovpn = vpn.storedOVPNText(id: profile.id)
                let overrides = vpn.overrides(for: profile.id)
                if !overrides.isEmpty { entry.overrides = overrides }
            case .wireGuard: entry.wireGuard = vpn.wireGuardConfig(for: profile.id)
            case .tailscale: entry.tailscale = vpn.tailscaleConfig(for: profile.id)
            case .proxyTunnel: entry.proxyTunnel = vpn.proxyTunnelConfig(for: profile.id)
            case .sshNetworkTunnel: entry.sshNetworkTunnel = vpn.sshNetworkTunnelConfig(for: profile.id)
            default: break
            }
            let auth = vpn.authConfig(for: profile.id)
            if !auth.isDefault { entry.auth = auth }
            let source = vpn.credentialSource(for: profile.id)
            if !source.isDefault { entry.credentialSource = source }
            let routing = vpn.customRouting(for: profile.id)
            if !routing.isEmpty { entry.customRouting = routing }
            let endpoints = vpn.endpointList(for: profile.id)
            if !endpoints.endpoints.isEmpty { entry.endpoints = endpoints }
            let prefs = vpn.uiPrefs(for: profile.id)
            if !prefs.isDefault { entry.uiPrefs = prefs }
            snapshot.vpns.append(entry)
        }

        // The subprocess kinds (SSH and the SSL VPNs) and the OS's own kinds live in
        // their own stores rather than in NE preferences — a "whole configuration"
        // that only walked `vpn.profiles` would silently omit both.
        for tunnel in tunnels.tunnels where profileID == nil || profileID == tunnel.id {
            var entry = ConfigSnapshot.VPN(id: tunnel.id, name: tunnel.name,
                                           kind: tunnel.kind, server: tunnel.server)
            entry.labelIDs = labels.labels(for: tunnel.id).map(\.id)
            entry.subprocess = tunnel
            entry.customRouting = vpn.customRouting(for: tunnel.id)
            snapshot.vpns.append(entry)
        }
        for config in nativeVPN.configs where profileID == nil || profileID == config.id {
            var entry = ConfigSnapshot.VPN(id: config.id, name: config.name,
                                           kind: config.kind, server: config.server)
            entry.labelIDs = labels.labels(for: config.id).map(\.id)
            entry.native = config
            entry.customRouting = vpn.customRouting(for: config.id)
            snapshot.vpns.append(entry)
        }
        return snapshot
    }

    // MARK: Export

    static func exportSnapshot(vpn: VPNController, tunnels: SubprocessTunnelStore,
                               nativeVPN: NativeVPNManager, labels: LabelStore,
                               mode: ConfigSecretMode, profileID: String? = nil) async throws -> ConfigSnapshot {
        if let refusal = policyRefusal { throw error(refusal) }
        var snapshot = snapshot(vpn: vpn, tunnels: tunnels, nativeVPN: nativeVPN, labels: labels, profileID: profileID)
        if profileID != nil, snapshot.vpns.count != 1 {
            throw error("The selected VPN could not be identified. Select it again before exporting.")
        }
        var authenticationContext: LAContext?
        if mode == .include, snapshot.vpns.contains(where: { $0.kind == .openVPN && BiometricCredentialStore.exists(profile: $0.id) }) {
            let context = LAContext()
            try await context.evaluatePolicy(.deviceOwnerAuthentication,
                localizedReason: "Export protected VPN credentials to a configuration file")
            authenticationContext = context
        }
        for index in snapshot.vpns.indices {
            let id = snapshot.vpns[index].id
            let protected = snapshot.vpns[index].auth?.protectWithBiometrics == true
            let kind = snapshot.vpns[index].kind
            if let refusal = policyRefusal { throw error(refusal) }
            snapshot.vpns[index].secrets = try await ConfigSecretTransfer.collect(id: id, kind: kind, mode: mode,
                protectSignIn: protected, authenticationContext: authenticationContext)
            if mode == .include, let stored = snapshot.vpns[index].ovpn {
                snapshot.vpns[index].ovpn = OVPNSecretMaterial.merge(stored,
                    secrets: try KeychainCredentialStore.ovpnInlineSecretsForExport(profile: id))
            }
        }
        return snapshot
    }

    private static func exportText(vpn: VPNController, tunnels: SubprocessTunnelStore,
                          nativeVPN: NativeVPNManager, labels: LabelStore,
                          format: ConfigFileFormat) -> String {
        ConfigDocument.text(from: snapshot(vpn: vpn, tunnels: tunnels,
                                           nativeVPN: nativeVPN, labels: labels),
                            format: format)
    }

    /// The suggested file name. Dated, because the second question anybody asks of
    /// a settings file is "which one is the recent one".
    static func suggestedFileName(format: ConfigFileFormat) -> String {
        let stamp = DateFormatter()
        stamp.dateFormat = "yyyy-MM-dd"
        return "SimpleVPN Settings \(stamp.string(from: .now)).\(format.fileExtension)"
    }

    // MARK: Recovery — written and verified BEFORE anything changes

    /// `~/Library/Application Support/SimpleVPN/Recovery`. The app is deliberately
    /// unsandboxed, so this is the real path and the user can open it.
    static var recoveryDirectory: URL {
        let base = FileManager.default.urls(for: .applicationSupportDirectory, in: .userDomainMask).first
            ?? URL(fileURLWithPath: NSHomeDirectory()).appendingPathComponent("Library/Application Support")
        return base.appendingPathComponent("SimpleVPN/Recovery", isDirectory: true)
    }

    /// Export the CURRENT configuration to the recovery folder and read it back.
    /// Throws if either half fails — and a throw here stops the import, because an
    /// import with no way back is the one outcome this whole feature must not have.
    static func writeRecovery(vpn: VPNController, tunnels: SubprocessTunnelStore,
                              nativeVPN: NativeVPNManager, labels: LabelStore) throws -> URL {
        let text = exportText(vpn: vpn, tunnels: tunnels, nativeVPN: nativeVPN,
                              labels: labels, format: .yaml)
        try FileManager.default.createDirectory(at: recoveryDirectory, withIntermediateDirectories: true)
        let stamp = DateFormatter()
        stamp.dateFormat = "yyyy-MM-dd HHmmss"
        let url = recoveryDirectory
            .appendingPathComponent("Before importing \(stamp.string(from: .now)) \(UUID().uuidString.prefix(8)).yaml")
        try ConfigSecretTransfer.write(text, to: url)
        // VERIFY, don't assume: read the bytes back and parse them. A file that
        // exists but cannot be read is not a way back.
        let readBack = try String(contentsOf: url, encoding: .utf8)
        _ = try ConfigImport.parse(readBack)
        log.log("wrote recovery copy before import")
        return url
    }

    // MARK: Import

    nonisolated struct ApplyResult: Sendable {
        var recovery: URL?
        var settingsChanged = 0
        var labelsAdded = 0
        var vpnsAdded: [String] = []
        /// Per-subject failures. An import that only half worked says which half.
        var failures: [String] = []

        var summary: String {
            var parts: [String] = []
            if !vpnsAdded.isEmpty { parts.append("added \(vpnsAdded.count) VPN\(vpnsAdded.count == 1 ? "" : "s")") }
            if settingsChanged > 0 { parts.append("changed \(settingsChanged) setting\(settingsChanged == 1 ? "" : "s")") }
            if labelsAdded > 0 { parts.append("added \(labelsAdded) label\(labelsAdded == 1 ? "" : "s")") }
            if parts.isEmpty { return failures.isEmpty ? "Nothing needed changing." : "No changes were imported." }
            return "Imported \u{2014} " + parts.joined(separator: ", ") + "."
        }
    }

    static func apply(_ plan: ConfigImportPlan, vpn: VPNController,
                      tunnels: SubprocessTunnelStore, nativeVPN: NativeVPNManager,
                      labels: LabelStore) async -> ApplyResult {
        var result = ApplyResult()
        if let refusal = policyRefusal {
            result.failures.append(refusal)
            return result
        }
        guard plan.fatal.isEmpty else {
            result.failures = plan.fatal
            return result
        }
        do {
            result.recovery = try writeRecovery(vpn: vpn, tunnels: tunnels,
                                                nativeVPN: nativeVPN, labels: labels)
        } catch {
            result.failures.append("SimpleVPN couldn\u{2019}t save a copy of your current settings first, so "
                + "it changed nothing. (\(error.localizedDescription))")
            return result
        }

        for change in plan.settingChanges {
            guard let entry = ConfigAppSettings.entry(id: change.id) else { continue }
            // The value is re-read from the plan's own record of what to write, so
            // what was confirmed is what lands.
            guard let value = plan.settingValue(for: change.id) else { continue }
            if let refusal = ConfigAppSettings.refusal(applying: value, to: entry) {
                result.failures.append(refusal)
            } else if ConfigAppSettings.write(value, to: entry) {
                result.settingsChanged += 1
            } else {
                result.failures.append("Couldn’t save “\(entry.name)”.")
            }
        }

        for label in plan.newLabels {
            labels.add(LabelDef(id: label.id, name: label.name,
                                r: label.red, g: label.green, b: label.blue))
            result.labelsAdded += 1
        }

        for planned in plan.vpns {
            do {
                let id = try await create(planned.vpn, vpn: vpn, tunnels: tunnels, nativeVPN: nativeVPN)
                do {
                    try await finish(planned.vpn, id: id, vpn: vpn) {
                        if planned.vpn.native != nil { return nativeVPN.configs.contains { $0.id == id } }
                        if planned.vpn.subprocess != nil { return tunnels.tunnels.contains { $0.id == id } }
                        return vpn.managers[id] != nil && !vpn.locallyRemovedProfileIDs.contains(id)
                    }
                } catch let settingsError {
                    do {
                        if planned.vpn.native != nil {
                            guard await nativeVPN.remove(id) else {
                                throw error(nativeVPN.lastError ?? "macOS could not remove the incomplete VPN.")
                            }
                        } else if planned.vpn.subprocess != nil {
                            tunnels.remove(id)
                        } else {
                            try await vpn.remove(id: id)
                        }
                        vpn.customRoutingCache[id] = nil
                        CustomRoutingFallbackStore().clear(id)
                    } catch {
                        // create() assigned this profile a fresh ID. Even if macOS keeps
                        // its preferences, discard any partially restored sign-in.
                        ConfigSecretTransfer.deleteAll(id: id)
                        result.failures.append("Added “\(planned.addedName)” with incomplete settings. "
                            + settingsError.localizedDescription + " " + error.localizedDescription
                            + " Review this VPN in Manage VPNs before connecting.")
                        result.vpnsAdded.append(planned.addedName)
                        continue
                    }
                    throw settingsError
                }
                for labelID in planned.vpn.labelIDs { labels.assign(labelID, to: id) }
                result.vpnsAdded.append(planned.addedName)
            } catch {
                result.failures.append("\u{201C}\(planned.addedName)\u{201D} couldn\u{2019}t be added: "
                    + error.localizedDescription)
            }
        }
        log.log("import applied: \(result.vpnsAdded.count, privacy: .public) VPN(s), \(result.settingsChanged, privacy: .public) setting(s)")
        return result
    }

    /// Add ONE VPN, through the same paths the editors use — so an imported VPN is
    /// indistinguishable from one made by hand, including every guard those paths
    /// already apply.
    private static func create(_ entry: ConfigSnapshot.VPN, vpn: VPNController,
                               tunnels: SubprocessTunnelStore,
                               nativeVPN: NativeVPNManager) async throws -> String {
        switch entry.kind {
        case .openVPN:
            guard let ovpn = entry.ovpn else { throw error("It has no configuration.") }
            let server = entry.server.isEmpty
                ? (EndpointScanner.endpoints(in: ovpn).first?.host ?? "") : entry.server
            return try await vpn.importProfile(name: entry.name, ovpn: ovpn, server: server, routingEventSource: entry.requiredPacketPolicy)
        case .wireGuard:
            var seed = entry.wireGuard ?? WireGuardConfig()
            seed.id = UUID().uuidString
            seed.name = entry.name
            return try await vpn.createWireGuard(from: seed, name: entry.name, routingEventSource: entry.requiredPacketPolicy)
        case .tailscale:
            return try await vpn.createTailscale(name: entry.name, configuration: entry.tailscale, routingEventSource: entry.requiredPacketPolicy)
        case .proxyTunnel:
            return try await vpn.createProxyTunnel(name: entry.name, configuration: entry.proxyTunnel, routingEventSource: entry.requiredPacketPolicy)
        case .sshNetworkTunnel:
            return try await vpn.createSSHNetworkTunnel(name: entry.name, configuration: entry.sshNetworkTunnel, routingEventSource: entry.requiredPacketPolicy)
        case .ikev2, .ipsec, .l2tp:
            guard var config = entry.native, config.kind == entry.kind else { throw error("It has no matching IPsec settings.") }
            try await ProfilePacketPolicy.validate(entry.requiredPacketPolicy, adapter: config.ownedIPsec?.adapterID)
            config.routingEventSource = entry.requiredPacketPolicy
            config.id = UUID().uuidString
            nativeVPN.save(config)
            return config.id
        case .ssh, .fortinet, .f5apm, .ciscoAnyConnect, .globalProtect,
             .juniper, .pulse, .arrayNetworks:
            guard var config = entry.subprocess else { throw error("It has no settings.") }
            config.id = UUID().uuidString
            try await ProfilePacketPolicy.validate(entry.requiredPacketPolicy, adapter: ProfilePacketPolicy.adapter(for: config))
            config.routingEventSource = entry.requiredPacketPolicy
            guard tunnels.save(config) else { throw error("Enter the address and password separately.") }
            return config.id
        }
    }

    private static func finish(_ entry: ConfigSnapshot.VPN, id: String, vpn: VPNController,
                               exists: () -> Bool) async throws {
        var step = "custom routing"
        do {
            if let routing = routing(entry.customRouting, for: id) { try await vpn.setCustomRouting(routing, for: id) }
            step = "connection settings"
            if let overrides = entry.overrides { try await vpn.setOverrides(overrides, for: id) }
            step = "the server list"
            if let endpoints = entry.endpoints { try await vpn.persistEndpointList(endpoints, for: id) }
            step = "display preferences"
            if let prefs = entry.uiPrefs { try await vpn.persistUIPrefs(prefs, for: id) }
            step = "sign-in settings"
            let auth = ConfigSecretTransfer.importedAuth(entry.auth, secrets: entry.secrets)
            if let auth { try await vpn.setAuthConfig(auth, for: id) }
            if let source = entry.credentialSource { try await vpn.setCredentialSource(source, for: id) }
            step = "credentials"
            guard exists() else { throw error("The new VPN was removed during import.") }
            if let refusal = policyRefusal { throw error(refusal) }
            if !entry.secrets.isEmpty {
                try ConfigSecretTransfer.save(entry.secrets, id: id, kind: entry.kind, protectSignIn: auth?.protectWithBiometrics == true)
            }
        } catch let cause {
            throw error("Import stopped while saving \(step). \(cause.localizedDescription)")
        }
    }

    private static func routing(_ input: CustomRoutingProfile?, for id: String) -> CustomRoutingProfile? {
        guard var routing = input else { return nil }
        if routing.proxy.authSource != nil { routing.proxy.authSource = ProxyAuthSourceRef.ref(forProfile: id) }
        return routing
    }

    private static func error(_ message: String) -> NSError {
        NSError(domain: "ConfigTransfer", code: 1, userInfo: [NSLocalizedDescriptionKey: message])
    }
}

// MARK: - The values behind the diff

nonisolated extension ConfigImportPlan {
    /// The value a confirmed change will write. Held alongside the human-readable
    /// diff rather than re-parsed from the file, so what the user approved and what
    /// is applied cannot come apart.
    func settingValue(for id: String) -> ConfigValue? { pendingValues[id] }
}
