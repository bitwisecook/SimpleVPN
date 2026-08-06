// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
//  VPNController+CRUD.swift
//  The configuration face of VPNController: importing, renaming and removing
//  profiles, the raw .ovpn text, per-VPN engine overrides, display name,
//  endpoints, interface preferences, the "reconnect to apply" pending-settings
//  signal, the Connection Doctor's apply path and its one-step undo. Everything
//  here persists through each profile's NETunnelProviderManager
//  providerConfiguration; the observable caches it mirrors into live in
//  VPNController.swift.
//

import Foundation
@preconcurrency import NetworkExtension
import os

extension VPNController {

    // MARK: CRUD

    /// Create a new target from an .ovpn. Returns the (stable) profile id.
    ///
    /// Takes the COMPLETE configuration text and splits its secret inline blocks out
    /// itself — the keychain write happens before the profile is ever saved, so a
    /// private key does not reach `providerConfiguration` even momentarily. `id` is a
    /// parameter because the keychain item is keyed by it and has to be written
    /// first, so the caller (`ProfileImport`) needs to know it in advance.
    @discardableResult
    func importProfile(name: String, ovpn: String, server: String,
                       id: String = UUID().uuidString) async throws -> String {
        let split = OVPNSecretMaterial.split(ovpn)
        var storedOVPN = ovpn
        if !split.secrets.isEmpty {
            if KeychainCredentialStore.saveAndVerifyOVPNInlineSecrets(profile: id, split.secrets) {
                storedOVPN = split.config
            } else {
                // The file being imported may be the user's only copy of that key.
                // Storing the profile intact is a leak; refusing the import, or
                // storing it stripped, would be a loss. Import it, and SAY SO —
                // `migrateInlineOVPNSecrets()` retries on the next load.
                Self.log.error("import: keeping inline \(split.secrets.keys.sorted().joined(separator: ","), privacy: .public) in profile \(id, privacy: .public) — the keychain write could not be verified")
                inlineSecretMigrationFailures[id] = "SimpleVPN couldn't copy this VPN's private key into your keychain, so the key is stored with the configuration instead. Make sure your login keychain is unlocked, then reopen SimpleVPN."
            }
        }
        let mgr = NETunnelProviderManager()
        let proto = NETunnelProviderProtocol()
        proto.providerBundleIdentifier = Self.providerBundleID
        proto.serverAddress = server
        proto.providerConfiguration = ["ovpn": storedOVPN, "profile": id,
                                       "vpnType": VPNKind.openVPN.rawValue]
        mgr.protocolConfiguration = proto
        mgr.localizedDescription = name
        mgr.isEnabled = true
        do {
            try await mgr.saveToPreferences()
            try await mgr.loadFromPreferences()
        } catch {
            // No profile, so the keychain item above belongs to nothing: a private
            // key with no owner and nothing in the UI able to delete it.
            KeychainCredentialStore.deleteOVPNInlineSecrets(profile: id)
            inlineSecretMigrationFailures.removeValue(forKey: id)
            throw error
        }
        await loadAll()
        selectedID = id
        Self.log.log("imported profile \(name, privacy: .public) id=\(id, privacy: .public)")
        return id
    }

    /// Rename a target (id stays stable, so keychain/logo/labels are unaffected).
    func rename(id: String, to name: String) async throws {
        guard let mgr = managers[id] else { return }
        mgr.localizedDescription = name
        try await mgr.saveToPreferences()
        try await mgr.loadFromPreferences()
        await loadAll()
    }

    /// Replace a target's .ovpn (e.g. re-import), keeping its id/name/creds/logo/labels.
    ///
    /// The text handed in is COMPLETE — it is what `ovpnText(id:)` gave the caller,
    /// so it carries the secret blocks. This is the one place they are taken back
    /// out again before anything is persisted, which is what makes the Certificates
    /// tab, the Configuration tab, the Doctor's fix-apply and its undo all
    /// secret-free without any of them knowing about it.
    func updateOVPN(id: String, ovpn: String, server: String) async throws {
        guard !ManagedPolicy.lockConfiguration else { throw Self.configLocked }
        guard let mgr = managers[id], let proto = mgr.protocolConfiguration as? NETunnelProviderProtocol else { return }
        let split = OVPNSecretMaterial.split(ovpn)
        if split.secrets.isEmpty {
            // The user cleared the Private Key / TLS Key slot. Drop the stored copy
            // too, or reassembly would put it straight back.
            KeychainCredentialStore.deleteOVPNInlineSecrets(profile: id)
        } else {
            // Write-then-rewrite, never the other way round: refuse the save
            // outright rather than persist a configuration whose key is now
            // nowhere. The editor shows the error and does not dismiss.
            guard KeychainCredentialStore.saveAndVerifyOVPNInlineSecrets(profile: id, split.secrets) else {
                throw err("Couldn't save this VPN's private key to your keychain, so nothing was changed. Make sure your login keychain is unlocked, then save again.")
            }
        }
        var conf = proto.providerConfiguration ?? [:]
        conf["ovpn"] = split.config; conf["profile"] = id
        proto.providerConfiguration = conf
        proto.serverAddress = server
        mgr.protocolConfiguration = proto
        try await mgr.saveToPreferences()
        try await mgr.loadFromPreferences()
        await loadAll()
    }

    func remove(id: String) async throws {
        guard let mgr = managers[id] else { return }
        // A Tailscale node key is this Mac's identity on that network and lives
        // in the extension's root-owned tree, which the app cannot touch — ask
        // the extension to shred it while there is still a session to ask.
        if profiles.first(where: { $0.id == id })?.kind == .tailscale {
            _ = await sendMessageData("tsforget", to: id, timeout: 4)
        }
        try await mgr.removeFromPreferences()
        KeychainCredentialStore.deleteCredentials(profile: id)
        KeychainCredentialStore.deleteProfileSecrets(profile: id)
        KeychainCredentialStore.deleteOVPNInlineSecrets(profile: id)
        KeychainCredentialStore.clearSession(profile: id)
        KeychainCredentialStore.deleteCredentials(profile: Self.tailscaleKeyProfile(id))
        KeychainCredentialStore.deleteCredentials(profile: Self.wireGuardKeyProfile(id))
        BiometricCredentialStore.delete(profile: id)
        wireGuardConfigs[id] = nil
        wireGuardStatuses[id] = nil
        tailscaleConfigs[id] = nil
        tailscaleStatuses[id] = nil
        tailscaleSignInWatch[id]?.cancel()
        tailscaleSignInWatch[id] = nil
        tailscaleSignInURL[id] = nil
        proxyTunnelConfigs[id] = nil
        proxyTunnelStatuses[id] = nil
        appliedOverrides[id] = nil
        appliedOVPN[id] = nil
        ovpnSecretsCache[id] = nil
        ovpnTextCache[id] = nil
        inlineSecretMigrationFailures[id] = nil
        endpointsCache[id] = nil
        await loadAll()
    }

    // MARK: Engine overrides (per-VPN OpenVPN settings)


    /// The saved overrides for a profile; empty when none were ever set.
    func overrides(for id: String) -> OpenVPNOverrides {
        if let cached = overridesCache[id] { return cached }
        let proto = managers[id]?.protocolConfiguration as? NETunnelProviderProtocol
        return OpenVPNOverrides.decode(from: proto?.providerConfiguration?["overrides"] as? Data)
    }

    /// Persist overrides (normalized; the blob is dropped entirely when empty, so
    /// untouched settings keep following the engine's defaults).
    func setOverrides(_ overrides: OpenVPNOverrides, for id: String) async throws {
        guard !ManagedPolicy.lockConfiguration else { throw Self.configLocked }
        guard let mgr = managers[id],
              let proto = mgr.protocolConfiguration as? NETunnelProviderProtocol else { return }
        var conf = proto.providerConfiguration ?? [:]
        var overrides = overrides
        // Org policy: keep everything inside the VPN is forced on and can't be cleared.
        if ManagedPolicy.forceKeepInsideVPN { overrides.allowUnusedAddrFamilies = .block }
        // Org policy: proxy settings are read-only — a save cannot change them, so
        // carry the currently-persisted proxy fields through untouched. (The form
        // also disables the controls, but this is the enforcement that can't be
        // bypassed by a programmatic write.)
        if ManagedPolicy.lockProxySettings {
            let current = self.overrides(for: id)
            overrides.proxyHost = current.proxyHost
            overrides.proxyPort = current.proxyPort
            overrides.proxyUsername = current.proxyUsername
            overrides.proxyAllowCleartextAuth = current.proxyAllowCleartextAuth
        }
        let normalized = overrides.normalized()
        if let blob = normalized.encodedBlob() {
            conf["overrides"] = blob
        } else {
            conf.removeValue(forKey: "overrides")
        }
        // Only ever *stamp* the kind onto a profile that has none (pre-vpnType
        // configs default to OpenVPN). Writing it unconditionally re-branded
        // every non-OpenVPN packet-tunnel profile as OpenVPN the first time
        // anything touched its overrides.
        if conf["vpnType"] == nil { conf["vpnType"] = VPNKind.openVPN.rawValue }
        proto.providerConfiguration = conf
        mgr.protocolConfiguration = proto
        try await mgr.saveToPreferences()
        try await mgr.loadFromPreferences()
        overridesCache[id] = normalized
        Self.log.log("overrides saved for \(id, privacy: .public): \(normalized.logDescription, privacy: .public)")
    }

    // MARK: Display name (deliberately NOT the connection host)

    /// What the user calls this VPN. Held by the manager's localizedDescription,
    /// which is also what macOS shows in Network settings — the addresses it
    /// dials live in the endpoint list below, so renaming a VPN never touches
    /// the connection and moving to a new server never renames it.
    func displayName(for id: String) -> String {
        profiles.first { $0.id == id }?.name ?? managers[id]?.localizedDescription ?? id
    }

    /// Rename with the display-name meaning made explicit at the call site.
    func setDisplayName(_ name: String, for id: String) async throws {
        let trimmed = name.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else { return }       // an unnamed VPN is unfindable
        try await rename(id: id, to: trimmed)
    }

    // MARK: Endpoints (the hosts this VPN can be reached at)


    /// What the user has SAID about this VPN's endpoints (labels, corrected
    /// countries, hand-added addresses). Not the addresses themselves — those
    /// still come from the profile, so a re-import picks up new servers.
    func endpointList(for id: String) -> VPNEndpointList {
        if let cached = endpointsCache[id] { return cached }
        let proto = managers[id]?.protocolConfiguration as? NETunnelProviderProtocol
        return VPNEndpointList.decode(from: proto?.providerConfiguration?["endpoints"] as? Data)
    }

    /// Every endpoint to offer for a VPN: the profile's own `remote` lines wearing
    /// the user's annotations, then anything they added by hand. Profiles with no
    /// .ovpn (SSH, the SSL-VPN kinds, WireGuard) fall back to the single server
    /// address the manager holds, so those get a one-entry list rather than none.
    func endpoints(for id: String) -> [VPNEndpoint] {
        var scanned = ovpnText(id: id).map { EndpointScanner.endpoints(in: $0) } ?? []
        if scanned.isEmpty, let profile = profiles.first(where: { $0.id == id }),
           !profile.server.isEmpty {
            let split = VPNProbeTarget.splitHostPort(profile.server)
            scanned = [Endpoint(host: split.host, port: split.port, proto: nil)]
        }
        return VPNEndpointList.merged(scanned: scanned, stored: endpointList(for: id))
    }

    func setEndpointList(_ list: VPNEndpointList, for id: String) async {
        guard let mgr = managers[id],
              let proto = mgr.protocolConfiguration as? NETunnelProviderProtocol else { return }
        var conf = proto.providerConfiguration ?? [:]
        if let blob = list.encodedBlob() { conf["endpoints"] = blob }
        else { conf.removeValue(forKey: "endpoints") }
        proto.providerConfiguration = conf
        mgr.protocolConfiguration = proto
        try? await mgr.saveToPreferences()
        try? await mgr.loadFromPreferences()
        endpointsCache[id] = list
    }

    /// Store one endpoint's annotations, replacing any it already had.
    func updateEndpoint(_ endpoint: VPNEndpoint, for id: String) async {
        var list = endpointList(for: id)
        list.endpoints.removeAll { $0.id == endpoint.id }
        if endpoint.hasAnnotations { list.endpoints.append(endpoint) }
        await setEndpointList(list, for: id)
    }

    /// Forget a hand-added endpoint (or an annotation). An address the profile
    /// itself advertises comes straight back — the .ovpn is the source of truth.
    func removeEndpoint(id endpointID: String, for id: String) async {
        var list = endpointList(for: id)
        list.endpoints.removeAll { $0.id == endpointID }
        await setEndpointList(list, for: id)
    }

    // MARK: Interface preferences (per-VPN optional controls)


    func uiPrefs(for id: String) -> VPNUIPrefs {
        if let cached = uiPrefsCache[id] { return cached }
        let proto = managers[id]?.protocolConfiguration as? NETunnelProviderProtocol
        return VPNUIPrefs.decode(from: proto?.providerConfiguration?["uiprefs"] as? Data)
    }

    func setUIPrefs(_ prefs: VPNUIPrefs, for id: String) async {
        guard let mgr = managers[id],
              let proto = mgr.protocolConfiguration as? NETunnelProviderProtocol else { return }
        var conf = proto.providerConfiguration ?? [:]
        if let blob = prefs.encodedBlob() { conf["uiprefs"] = blob }
        else { conf.removeValue(forKey: "uiprefs") }
        proto.providerConfiguration = conf
        mgr.protocolConfiguration = proto
        try? await mgr.saveToPreferences()
        try? await mgr.loadFromPreferences()
        uiPrefsCache[id] = prefs
    }

    /// True while a session started with different overrides than are now saved —
    /// the "changes take effect on reconnect" signal.
    func hasPendingSettings(id: String) -> Bool {
        guard isEngaged(id: id) else { return false }
        if let applied = appliedOverrides[id], applied != overrides(for: id) { return true }
        if let appliedText = appliedOVPN[id], appliedText != (ovpnText(id: id) ?? "") { return true }
        return false
    }

    // MARK: Connection Doctor

    /// Apply a Doctor fix (override mutation or .ovpn edit) and, if the profile
    /// is live, reconnect so it takes effect. Explanation-only fixes do nothing.
    func applyDoctorFix(_ fix: DoctorFix, to id: String, undoLabel: String? = nil) async {
        if fix.isExplain { return }
        guard !ManagedPolicy.lockConfiguration else {
            lastError = Self.configLocked.localizedDescription; return
        }
        let wasActive = profiles.first(where: { $0.id == id }).map { UI.isActive($0.status) } == true
        // Snapshot the pre-change state so the user can undo (the finding/toggle
        // that prompted it disappears once applied, so undo can't rely on it).
        let undo = ChangeUndo(label: undoLabel ?? "change",
                              overrides: overrides(for: id), ovpn: ovpnText(id: id))
        // Hold the UI in its connected layout across the apply+reconnect so it
        // never flashes back to the Connect button mid-reapply.
        if wasActive { beginReconfiguring(id) }
        defer { if wasActive { endReconfiguring(id) } }

        switch fix {
        case .explain:
            return
        case .overrides(let mutate):
            var o = overrides(for: id)
            mutate(&o)
            try? await setOverrides(o, for: id)
        case .editOVPN(let edit):
            guard let text = ovpnText(id: id) else { return }
            let server = (managers[id]?.protocolConfiguration as? NETunnelProviderProtocol)?.serverAddress
                ?? profiles.first { $0.id == id }?.server ?? ""
            try? await updateOVPN(id: id, ovpn: edit(text), server: server)
        }
        lastChange[id] = undo
        if wasActive { await reconnect(id: id) }
    }

    /// The overrides the *running* session was started with (nil ⇒ not connected),
    /// so a setting can show whether it's actually applied or only pending.
    func appliedOverrides(for id: String) -> OpenVPNOverrides? { appliedOverrides[id] }

    // MARK: One-step undo of the last applied change

    struct ChangeUndo: Sendable { var label: String; var overrides: OpenVPNOverrides; var ovpn: String? }

    /// Revert the most recent Connection Manager / Doctor change and reconnect.
    func undoLastChange(id: String) async {
        guard !ManagedPolicy.lockConfiguration else {
            lastError = Self.configLocked.localizedDescription; return
        }
        guard let undo = lastChange[id] else { return }
        lastChange[id] = nil
        let wasActive = profiles.first(where: { $0.id == id }).map { UI.isActive($0.status) } == true
        if wasActive { beginReconfiguring(id) }
        defer { if wasActive { endReconfiguring(id) } }
        try? await setOverrides(undo.overrides, for: id)
        if let ovpn = undo.ovpn, ovpn != ovpnText(id: id) {
            let server = (managers[id]?.protocolConfiguration as? NETunnelProviderProtocol)?.serverAddress
                ?? profiles.first { $0.id == id }?.server ?? ""
            try? await updateOVPN(id: id, ovpn: ovpn, server: server)
        }
        if wasActive { await reconnect(id: id) }
    }

    func savedCredentials(id: String) -> KeychainCredentialStore.Credentials? {
        KeychainCredentialStore.loadCredentials(profile: id)
    }

    // MARK: The .ovpn text — two of them, and the difference is the point

    /// The COMPLETE .ovpn text for a profile: what is stored, with the secret
    /// inline blocks put back from the keychain.
    ///
    /// This is the one every existing caller wants and gets, unchanged — the
    /// evaluator (which reads `autologin` and `privateKeyPasswordRequired` off the
    /// presence of `<key>`), the Certificates tab, the control-channel probe that
    /// needs the tls-crypt key, the Doctor, endpoint scanning. Handing those a
    /// configuration with a hole in it would have changed behaviour everywhere;
    /// only what is PERSISTED changed.
    ///
    /// Never use this for anything that leaves the app. Export goes through
    /// `exportableOVPNText(id:)`.
    func ovpnText(id: String) -> String? {
        guard let stored = storedOVPNText(id: id) else { return nil }
        if let cached = ovpnTextCache[id] { return cached }
        let secrets = ovpnSecrets(for: id)
        return secrets.isEmpty ? OVPNSecretMaterial.stripMarkers(stored)
                               : OVPNSecretMaterial.merge(stored, secrets: secrets)
    }

    /// EXACTLY what sits in `providerConfiguration` — no reassembly. The thing the
    /// secret-free invariant is about, and what migration and the tests inspect.
    func storedOVPNText(id: String) -> String? {
        (managers[id]?.protocolConfiguration as? NETunnelProviderProtocol)?
            .providerConfiguration?["ovpn"] as? String
    }

    /// The text `Export .ovpn…` writes: secret-free, with a note in the file
    /// saying what was left out and how to put it back. Built from the STORED
    /// text, so the secret material is not even reassembled on this path — and
    /// `exportText` splits again anyway, so a profile whose migration could not be
    /// verified still exports safely.
    func exportableOVPNText(id: String) -> String? {
        storedOVPNText(id: id).map { OVPNSecretMaterial.exportText($0) }
    }

    /// This profile's keychain-held inline blocks. Cache-only: `ovpnText(id:)` is
    /// called from view bodies, and a keychain round-trip per render is not that.
    /// The cache is filled by `loadAll()`, same as every other blob mirror.
    func ovpnSecrets(for id: String) -> [String: String] { ovpnSecretsCache[id] ?? [:] }

    // MARK: Migration of profiles that still have their key inline

    /// Move any still-inline secret blocks of every OpenVPN profile into the
    /// keychain. Runs from `loadAll()`.
    ///
    /// THE ORDER IS THE WHOLE DESIGN, and it is write → verify → destroy:
    ///
    ///  1. write the blocks to the keychain;
    ///  2. read them back and compare them byte-for-byte
    ///     (`saveAndVerifyOVPNInlineSecrets`);
    ///  3. only then rewrite `providerConfiguration` without them.
    ///
    /// Any step failing leaves the profile completely alone — still working, still
    /// leaky, and recorded in `inlineSecretMigrationFailures` so it is visible
    /// rather than silent. A half-migrated profile (removed from the text, not in
    /// the keychain) is the one outcome that would destroy a user's only copy of a
    /// client private key, and it is unreachable from here.
    ///
    /// Under MDM `lockConfiguration` the rewrite is skipped entirely: the
    /// administrator has said the stored configuration is not to be changed, and
    /// this is a rewrite of it. Logged, not badged — it is a policy outcome, not a
    /// failure the user can clear.
    func migrateInlineOVPNSecrets() async {
        for profile in profiles where profile.kind == .openVPN {
            let id = profile.id
            guard let stored = storedOVPNText(id: id), !stored.isEmpty else { continue }
            let split = OVPNSecretMaterial.split(stored)
            guard !split.secrets.isEmpty else {
                inlineSecretMigrationFailures.removeValue(forKey: id)
                continue
            }
            if ManagedPolicy.lockConfiguration {
                Self.log.log("inline secrets left in place for \(id, privacy: .public): configuration is locked by policy")
                continue
            }
            guard let mgr = managers[id],
                  let proto = mgr.protocolConfiguration as? NETunnelProviderProtocol else { continue }

            // What is inline wins over any earlier keychain copy — it is what the
            // engine has actually been connecting with.
            var blocks = KeychainCredentialStore.loadOVPNInlineSecrets(profile: id) ?? [:]
            for (tag, body) in split.secrets { blocks[tag] = body }

            guard KeychainCredentialStore.saveAndVerifyOVPNInlineSecrets(profile: id, blocks) else {
                inlineSecretMigrationFailures[id] = "SimpleVPN couldn't copy this VPN's private key into your keychain, so it left the key where it was. Make sure your login keychain is unlocked, then reopen SimpleVPN."
                continue
            }
            var conf = proto.providerConfiguration ?? [:]
            conf["ovpn"] = split.config
            proto.providerConfiguration = conf
            mgr.protocolConfiguration = proto
            do {
                try await mgr.saveToPreferences()
                try await mgr.loadFromPreferences()
            } catch {
                // The keychain copy is verified, so nothing is lost — the profile
                // simply still carries its own copy. Try again next launch.
                Self.log.error("inline secret strip could not be saved for \(id, privacy: .public): \(error.localizedDescription, privacy: .public)")
                inlineSecretMigrationFailures[id] = "SimpleVPN couldn't rewrite this VPN's saved configuration, so its private key is still stored with it. Reopen SimpleVPN to try again."
                continue
            }
            ovpnSecretsCache[id] = blocks
            ovpnTextCache[id] = OVPNSecretMaterial.merge(split.config, secrets: blocks)
            inlineSecretMigrationFailures.removeValue(forKey: id)
            Self.log.log("moved inline \(split.secrets.keys.sorted().joined(separator: ","), privacy: .public) out of profile \(id, privacy: .public)")
        }
    }
}
