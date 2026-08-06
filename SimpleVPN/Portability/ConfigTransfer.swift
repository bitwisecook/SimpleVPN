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
                        labels: LabelStore) -> ConfigSnapshot {
        var snapshot = ConfigSnapshot()
        snapshot.appVersion = UI.appVersion
        snapshot.appSettings = ConfigAppSettings.snapshot()
        snapshot.labels = labels.labels.map {
            ConfigLabel(id: $0.id, name: $0.name, red: $0.r, green: $0.g, blue: $0.b)
        }

        // The packet-tunnel VPNs, in the order the sidebar shows them.
        for profile in vpn.profiles {
            var entry = ConfigSnapshot.VPN(id: profile.id, name: profile.name,
                                           kind: profile.kind, server: profile.server)
            entry.labelIDs = labels.labels(for: profile.id).map(\.id)
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
            let sourceMap = ConfigDocument.structuralMap(source)
            if !sourceMap.isEmpty { entry.credentialSourceJSON = .map(sourceMap) }
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
        for tunnel in tunnels.tunnels {
            var entry = ConfigSnapshot.VPN(id: tunnel.id, name: tunnel.name,
                                           kind: tunnel.kind, server: tunnel.server)
            entry.labelIDs = labels.labels(for: tunnel.id).map(\.id)
            entry.subprocess = tunnel
            snapshot.vpns.append(entry)
        }
        for config in nativeVPN.configs {
            var entry = ConfigSnapshot.VPN(id: config.id, name: config.name,
                                           kind: config.kind, server: config.server)
            entry.labelIDs = labels.labels(for: config.id).map(\.id)
            entry.native = config
            snapshot.vpns.append(entry)
        }
        return snapshot
    }

    // MARK: Export

    static func exportText(vpn: VPNController, tunnels: SubprocessTunnelStore,
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
            .appendingPathComponent("Before importing \(stamp.string(from: .now)).yaml")
        try text.write(to: url, atomically: true, encoding: .utf8)
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
            if parts.isEmpty { return "Nothing needed changing." }
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
            if ConfigAppSettings.write(value, to: entry) { result.settingsChanged += 1 }
        }

        for label in plan.newLabels {
            labels.add(LabelDef(id: label.id, name: label.name,
                                r: label.red, g: label.green, b: label.blue))
            result.labelsAdded += 1
        }

        for planned in plan.vpns {
            do {
                let id = try await add(planned.vpn, vpn: vpn, tunnels: tunnels, nativeVPN: nativeVPN)
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
    private static func add(_ entry: ConfigSnapshot.VPN, vpn: VPNController,
                           tunnels: SubprocessTunnelStore,
                           nativeVPN: NativeVPNManager) async throws -> String {
        switch entry.kind {
        case .openVPN:
            guard let ovpn = entry.ovpn else { throw error("it has no configuration.") }
            let server = entry.server.isEmpty
                ? (EndpointScanner.endpoints(in: ovpn).first?.host ?? "") : entry.server
            let id = try await vpn.importProfile(name: entry.name, ovpn: ovpn, server: server)
            try await applyShared(entry, to: id, vpn: vpn)
            if let overrides = entry.overrides { try await vpn.setOverrides(overrides, for: id) }
            return id
        case .wireGuard:
            var seed = entry.wireGuard ?? WireGuardConfig()
            seed.id = entry.id
            seed.name = entry.name
            let id = try await vpn.createWireGuard(from: seed, name: entry.name)
            try await applyShared(entry, to: id, vpn: vpn)
            return id
        case .tailscale:
            let id = try await vpn.createTailscale(name: entry.name)
            if let config = entry.tailscale { try await vpn.setTailscaleConfig(config, for: id) }
            try await applyShared(entry, to: id, vpn: vpn)
            return id
        case .proxyTunnel:
            let id = try await vpn.createProxyTunnel(name: entry.name)
            if let config = entry.proxyTunnel { try await vpn.setProxyTunnelConfig(config, for: id) }
            try await applyShared(entry, to: id, vpn: vpn)
            return id
        case .sshNetworkTunnel:
            let id = try await vpn.createSSHNetworkTunnel(name: entry.name)
            if let config = entry.sshNetworkTunnel {
                try await vpn.setSSHNetworkTunnelConfig(config, for: id)
            }
            try await applyShared(entry, to: id, vpn: vpn)
            return id
        case .ikev2, .ipsec, .l2tp:
            guard var config = entry.native else { throw error("it has no settings.") }
            config.id = UUID().uuidString
            nativeVPN.save(config)
            return config.id
        case .ssh, .fortinet, .f5apm, .ciscoAnyConnect, .globalProtect,
             .juniper, .pulse, .arrayNetworks:
            guard var config = entry.subprocess else { throw error("it has no settings.") }
            config.id = UUID().uuidString
            tunnels.save(config)
            return config.id
        }
    }

    /// The per-VPN state every packet-tunnel kind shares. Failures here are not
    /// fatal to the VPN itself — it exists and can be connected; a missing
    /// Custom Routing filter is a setting to redo, not a reason to throw the
    /// profile away.
    private static func applyShared(_ entry: ConfigSnapshot.VPN, to id: String,
                                    vpn: VPNController) async throws {
        if let auth = entry.auth { try? await vpn.setAuthConfig(auth, for: id) }
        if let source = entry.credentialSourceJSON?.mapValue,
           let decoded = ConfigImport.decode(CredentialSource.self, from: source) {
            try? await vpn.setCredentialSource(decoded, for: id)
        }
        if let routing = entry.customRouting { try? await vpn.setCustomRouting(routing, for: id) }
        if let endpoints = entry.endpoints { await vpn.setEndpointList(endpoints, for: id) }
        if let prefs = entry.uiPrefs { await vpn.setUIPrefs(prefs, for: id) }
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
