// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
//  VPNController+WireGuard.swift
//  The WireGuard face of VPNController. Like Tailscale and the Proxy Tunnel, a
//  WireGuard VPN is an ordinary packet-tunnel profile — sidebar, status dots,
//  telemetry and map come for free — so only the settings blob, the key
//  handling and the connect flow differ, and they live here. Stored state (the
//  observable config/status mirrors) lives in VPNController.swift.
//
//  Secrets invariant: the private key and preshared key live in the keychain
//  under the "wg.<id>" profile (the convention WireGuardConfig.keychainProfile
//  established) and ride startTunnel(options:) in memory at connect — they are
//  NEVER in providerConfiguration; the persisted blob is always the redacted
//  copy.
//

import Foundation
@preconcurrency import NetworkExtension
import os

extension VPNController {

    // MARK: WireGuard


    func isWireGuard(_ id: String) -> Bool {
        profiles.first { $0.id == id }?.kind == .wireGuard
    }

    /// The saved (redacted) config for a profile — the keys are in the
    /// keychain, not here.
    func wireGuardConfig(for id: String) -> WireGuardConfig {
        if let c = wireGuardConfigs[id] { return c }
        let proto = managers[id]?.protocolConfiguration as? NETunnelProviderProtocol
        var c = WireGuardConfig.decode(from: proto?.providerConfiguration?["wireguard"] as? Data)
        c.id = id
        return c
    }

    /// Create a new WireGuard VPN, optionally seeded from a parsed .conf (the
    /// import path). Any keys carried by the seed move straight to the
    /// keychain; only the redacted copy is persisted. Returns the profile id
    /// (the seed's own id, so pre-existing "wg.<id>" keychain items keep
    /// matching).
    @discardableResult
    func createWireGuard(from seed: WireGuardConfig = WireGuardConfig(),
                         name: String? = nil) async throws -> String {
        guard !ManagedPolicy.lockConfiguration else { throw Self.configLocked }
        let id = seed.id
        setWireGuardSecrets(privateKey: seed.privateKey.isEmpty ? nil : seed.privateKey,
                            presharedKey: seed.presharedKey.isEmpty ? nil : seed.presharedKey,
                            for: id)
        let config = seed.redactedForStorage()
        let mgr = NETunnelProviderManager()
        let proto = NETunnelProviderProtocol()
        proto.providerBundleIdentifier = Self.providerBundleID
        // serverAddress is what macOS shows in Network settings and what the
        // probe/endpoint machinery dials: the peer's endpoint host.
        proto.serverAddress = config.endpointHost.isEmpty ? "wireguard" : config.endpointHost
        var conf: [String: Any] = ["profile": id, "vpnType": VPNKind.wireGuard.rawValue]
        if let blob = config.encodedBlob() { conf["wireguard"] = blob }
        proto.providerConfiguration = conf
        mgr.protocolConfiguration = proto
        mgr.localizedDescription = name ?? config.name
        mgr.isEnabled = true
        try await mgr.saveToPreferences()
        try await mgr.loadFromPreferences()
        await loadAll()
        selectedID = id
        Self.log.log("created wireguard profile id=\(id, privacy: .public)")
        return id
    }

    /// Persist a config change. Whatever key material the caller left in the
    /// value is stripped here — belt-and-braces; the editor already routes
    /// keys through `setWireGuardSecrets`.
    func setWireGuardConfig(_ config: WireGuardConfig, for id: String) async throws {
        guard !ManagedPolicy.lockConfiguration else { throw Self.configLocked }
        guard let mgr = managers[id],
              let proto = mgr.protocolConfiguration as? NETunnelProviderProtocol else { return }
        var stored = config.redactedForStorage()
        stored.id = id
        var conf = proto.providerConfiguration ?? [:]
        conf["profile"] = id
        conf["vpnType"] = VPNKind.wireGuard.rawValue
        if let blob = stored.encodedBlob() { conf["wireguard"] = blob }
        proto.providerConfiguration = conf
        proto.serverAddress = stored.endpointHost.isEmpty ? "wireguard" : stored.endpointHost
        mgr.protocolConfiguration = proto
        if !stored.name.isEmpty { mgr.localizedDescription = stored.name }
        try await mgr.saveToPreferences()
        try await mgr.loadFromPreferences()
        wireGuardConfigs[id] = stored
        await loadAll()
    }

    // MARK: Keys (keychain "wg.<id>", never providerConfiguration)

    /// Keychain namespace for a profile's keys — the same "wg.<id>" identity
    /// WireGuardConfig.keychainProfile names, so editor-era items carry over.
    nonisolated static func wireGuardKeyProfile(_ id: String) -> String { "wg.\(id)" }

    /// The stored keys: (privateKey, presharedKey) — empty when unset.
    func wireGuardSecrets(for id: String) -> (privateKey: String, presharedKey: String) {
        let c = KeychainCredentialStore.loadCredentials(profile: Self.wireGuardKeyProfile(id))
        return (c?.password ?? "", c?.proxyPassword ?? "")
    }

    /// Store (or update) the keys. nil = leave that key alone (the editor's
    /// write-only private-key field sends nil when untouched); a value —
    /// including "" — replaces it, so clearing the preshared-key field really
    /// clears it. Both empty deletes the item.
    func setWireGuardSecrets(privateKey: String?, presharedKey: String?, for id: String) {
        let existing = wireGuardSecrets(for: id)
        let newPriv = privateKey.map { $0.trimmingCharacters(in: .whitespacesAndNewlines) }
            ?? existing.privateKey
        let newPSK = presharedKey.map { $0.trimmingCharacters(in: .whitespacesAndNewlines) }
            ?? existing.presharedKey
        guard newPriv != existing.privateKey || newPSK != existing.presharedKey else { return }
        if newPriv.isEmpty && newPSK.isEmpty {
            KeychainCredentialStore.deleteCredentials(profile: Self.wireGuardKeyProfile(id))
            return
        }
        try? KeychainCredentialStore.saveCredentials(
            profile: Self.wireGuardKeyProfile(id),
            .init(username: "wireguard", password: newPriv,
                  proxyPassword: newPSK.isEmpty ? nil : newPSK))
    }

    /// Whether a private key is stored for this profile — the connect gate.
    func wireGuardHasPrivateKey(_ id: String) -> Bool {
        !wireGuardSecrets(for: id).privateKey.isEmpty
    }

    // MARK: Connect

    /// Connect a WireGuard VPN. There is no username/password to collect: the
    /// keys ARE the sign-in, read from the keychain here and handed over via
    /// startTunnel options in memory.
    func connectWireGuard(id: String) async throws {
        guard let mgr = managers[id],
              mgr.protocolConfiguration is NETunnelProviderProtocol else { throw err("no such profile") }
        if let ensureExtensionReady, !(await ensureExtensionReady()) {
            throw err("SimpleVPN needs its network extension approved before it can connect. Open System Settings ▸ General ▸ Login Items & Extensions ▸ Network Extensions and allow SimpleVPN.")
        }
        let config = wireGuardConfig(for: id)
        if let problem = config.connectProblem { throw err(problem) }
        let secrets = wireGuardSecrets(for: id)
        guard !secrets.privateKey.isEmpty else {
            throw err("Set this tunnel's private key first — it's in the config your provider gave you (Manage VPNs ▸ this VPN ▸ Set / Replace Key).")
        }

        var options: [String: NSObject] = ["wgPrivateKey": secrets.privateKey as NSString]
        if !secrets.presharedKey.isEmpty {
            options["wgPresharedKey"] = secrets.presharedKey as NSString
        }
        // Establish-time default-gateway ownership, same as OpenVPN (RC3).
        options["gatewayOwned"] = predictedGatewayOwned(id) as NSNumber

        mgr.isEnabled = true
        try await mgr.saveToPreferences()
        try await mgr.loadFromPreferences()
        guard let session = mgr.connection as? NETunnelProviderSession else {
            throw err("The VPN configuration isn't ready — try removing and re-creating it.")
        }
        try session.startTunnel(options: options)
        Self.log.log("wireguard startTunnel dispatched for \(id, privacy: .public)")
        resyncStatuses()
    }

    /// Refresh (and publish) the engine status for a connected WireGuard VPN.
    @discardableResult
    func refreshWireGuardStatus(id: String) async -> WireGuardEngineStatus? {
        guard let data = await sendMessageData("wgstatus", to: id),
              let status = try? JSONDecoder().decode(WireGuardEngineStatus.self, from: data) else { return nil }
        wireGuardStatuses[id] = status
        return status
    }

    // MARK: Legacy-store migration

    /// One-time migration of the pre-engine WireGuardStore (UserDefaults-backed
    /// editor drafts) into real packet-tunnel profiles. Ids are preserved, so
    /// each config's "wg.<id>" keychain item — where the store already kept the
    /// keys — carries over untouched. Configs that migrate leave the store;
    /// anything that fails to save stays for the next launch.
    func migrateLegacyWireGuardStore(_ store: WireGuardStore) async {
        guard !store.configs.isEmpty else { return }
        for config in store.configs {
            if managers[config.id] != nil {   // already migrated once
                store.forget(config.id)
                continue
            }
            do {
                _ = try await createWireGuard(from: config)
                store.forget(config.id)
                Self.log.log("migrated legacy wireguard config \(config.id, privacy: .public)")
            } catch {
                Self.log.error("wireguard migration failed for \(config.id, privacy: .public): \(error.localizedDescription, privacy: .public)")
            }
        }
    }
}
