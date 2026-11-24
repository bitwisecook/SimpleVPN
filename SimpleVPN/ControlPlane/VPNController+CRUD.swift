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

/// Keychain and NetworkExtension have separate commits. Restore the prior
/// verified blocks if either the replacement or the preference write fails.
@MainActor
enum OpenVPNConfigurationEdit {
    enum Failure: LocalizedError {
        case stale, unavailable, missing, verification, restore, incomplete(String)
        var errorDescription: String? {
            switch self {
            case .stale: "This VPN’s saved keys changed after the editor opened. Reopen the editor before saving."
            case .unavailable: "SimpleVPN couldn’t read this VPN’s saved keys. Check access to your login keychain and reopen the editor."
            case .missing: "This VPN is missing saved OpenVPN keys. Restore them in Manage VPNs from the original configuration."
            case .verification: "SimpleVPN couldn’t verify this VPN’s keys in your login keychain."
            case .restore: "SimpleVPN couldn’t restore this VPN’s previous keys. Check your login keychain and the original configuration before connecting."
            case .incomplete(let tag): "Close the <\(tag)> block with </\(tag)> before saving this configuration."
            }
        }
    }

    static func save(previous: [String: String], replacement: [String: String],
                     read: () async throws -> [String: String],
                     write: ([String: String]) async throws -> Void,
                     commit: () async throws -> Void) async throws {
        guard previous != replacement else { try await commit(); return }
        var replaced = false
        do {
            try await write(replacement)
            replaced = true
            try await commit()
        } catch {
            // A refused write can leave the old item intact. Avoid requesting
            // Keychain write access again when we can confirm that directly.
            if !replaced, (try? await read()) == previous { throw error }
            do { try await write(previous) } catch { throw Failure.restore }
            throw error
        }
    }

    static func checkOriginal(_ original: String, stored: String, keys: [String: String], replacement: [String: String]) throws {
        // Older configurations can still contain inline keys pending migration.
        let actual = keys.merging(OVPNSecretMaterial.split(stored).secrets) { _, inline in inline }
        guard OVPNSecretMaterial.split(original).secrets == actual else { throw Failure.stale }
        let missing = OVPNSecretMaterial.markedTags(in: stored).subtracting(actual.keys)
        guard missing.isSubset(of: replacement.keys) else { throw Failure.missing }
    }
}

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
                       id: String = UUID().uuidString, routingEventSource: String? = nil) async throws -> String {
        try await ProfilePacketPolicy.validate(routingEventSource, adapter: RoutingAdapter.packetID(for: .openVPN))
        // An import is a deliberate new profile, even if a caller happens to
        // reuse an identifier from a profile removed earlier in this launch.
        locallyRemovedProfileIDs.remove(id)
        let split = OVPNSecretMaterial.split(ovpn)
        if let tag = split.unterminatedTag { throw OpenVPNConfigurationEdit.Failure.incomplete(tag) }
        guard split.secrets.isEmpty || KeychainCredentialStore.saveAndVerifyOVPNInlineSecrets(profile: id, split.secrets) else {
            KeychainCredentialStore.deleteOVPNInlineSecrets(profile: id)
            throw err("Unlock your login keychain and import the original configuration again. SimpleVPN couldn’t save its private keys or sign-in details securely.")
        }
        let storedOVPN = split.secrets.isEmpty ? ovpn : split.config
        let mgr = NETunnelProviderManager()
        let proto = NETunnelProviderProtocol()
        proto.providerBundleIdentifier = Self.providerBundleID
        proto.serverAddress = server
        proto.providerConfiguration = ["ovpn": storedOVPN, "profile": id,
                                       "vpnType": VPNKind.openVPN.rawValue]
        try await ProfilePacketPolicy.attach(routingEventSource, to: proto)
        mgr.protocolConfiguration = proto
        mgr.localizedDescription = name
        mgr.isEnabled = true
        do {
            try await mgr.saveToPreferences()
        } catch {
            KeychainCredentialStore.deleteOVPNInlineSecrets(profile: id)
            throw error
        }
        await registerCreatedManager(mgr, id: id)
        selectedID = id
        Self.log.log("imported profile \(name, privacy: .public) id=\(id, privacy: .public)")
        return id
    }

    /// Saving creates the profile. Keep its manager available to the caller
    /// even if the asynchronous enumeration fails or a newer one supersedes it.
    func registerCreatedManager(_ manager: NETunnelProviderManager, id: String) async {
        managers[id] = manager
        await loadAll()
        if managers[id] == nil, !locallyRemovedProfileIDs.contains(id) { managers[id] = manager }
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
    func updateOVPN(id: String, ovpn: String, server: String, original: String? = nil) async throws {
        guard !ManagedPolicy.lockConfiguration else { throw Self.configLocked }
        let baseline = original ?? ovpnText(id: id)
        let split = OVPNSecretMaterial.split(ovpn)
        if let tag = split.unterminatedTag { throw OpenVPNConfigurationEdit.Failure.incomplete(tag) }
        do {
            let gate = openVPNConfigurationGate(for: id)
            await gate.acquire()
            defer { gate.release() }
            guard let mgr = managers[id], !locallyRemovedProfileIDs.contains(id),
                  let proto = mgr.protocolConfiguration as? NETunnelProviderProtocol,
                  let stored = proto.providerConfiguration?["ovpn"] as? String, let baseline else {
                throw err("The VPN is no longer available.")
            }
            func readKeys() async throws -> [String: String] {
                try await Task.detached {
                    try KeychainCredentialStore.ovpnInlineSecretsForExport(profile: id)
                }.value
            }
            let previous: [String: String]
            do { previous = try await readKeys() }
            catch { throw OpenVPNConfigurationEdit.Failure.unavailable }
            try OpenVPNConfigurationEdit.checkOriginal(baseline, stored: stored, keys: previous, replacement: split.secrets)
            // A live-save of an unrelated setting needs neither a new key nor an NE write.
            if previous == split.secrets, stored == split.config, proto.serverAddress == server { return }
            try await OpenVPNConfigurationEdit.save(previous: previous, replacement: split.secrets, read: readKeys) { keys in
                try await Task.detached {
                    try KeychainCredentialStore.saveOVPNInlineSecrets(profile: id, keys)
                    guard try KeychainCredentialStore.ovpnInlineSecretsForExport(profile: id) == keys else {
                        throw OpenVPNConfigurationEdit.Failure.verification
                    }
                }.value
            } commit: {
                let oldConfiguration = proto.providerConfiguration
                let oldServer = proto.serverAddress
                var conf = oldConfiguration ?? [:]
                conf["ovpn"] = split.config
                conf["profile"] = id
                proto.providerConfiguration = conf
                proto.serverAddress = server
                mgr.protocolConfiguration = proto
                do { try await mgr.saveToPreferences() }
                catch {
                    proto.providerConfiguration = oldConfiguration
                    proto.serverAddress = oldServer
                    mgr.protocolConfiguration = proto
                    throw error
                }
            }
            // A refresh failure after a successful save must not roll back the new keys.
            ovpnSecretsCache[id] = split.secrets
            ovpnTextCache[id] = ovpn
        }
        await loadAll()
    }

    func remove(id: String) async throws {
        guard !locallyRemovedProfileIDs.contains(id), let mgr = managers[id] else { return }
        let openVPN = (mgr.protocolConfiguration as? NETunnelProviderProtocol)?.providerConfiguration?["ovpn"] is String
        do {
            let gate = openVPN ? openVPNConfigurationGate(for: id) : nil
            await gate?.acquire()
            defer { gate?.release() }
            guard let current = managers[id], !locallyRemovedProfileIDs.contains(id) else { return }
            try await removeProfile(id: id, manager: current)
        } catch {
            await loadAll()
            throw error
        }
        await loadAll()
    }

    private func removeProfile(id: String, manager mgr: NETunnelProviderManager) async throws {
        let kind = isTailscale(id) ? .tailscale : profiles.first(where: { $0.id == id })?.kind
        let lease = kind == .tailscale ? try tailscaleIdentityLease(id) : nil
        defer { withExtendedLifetime(lease) {} }
        if kind == .tailscale, tailscaleStartingIDs.contains(id) { throw err("Wait for this VPN to finish starting before removing it.") }
        connectionReservations.cancel(member: id)
        if kind == .wireGuard { await wireGuardConfigurationOperations.acquire() }
        defer { if kind == .wireGuard { wireGuardConfigurationOperations.release() } }
        guard !locallyRemovedProfileIDs.contains(id), managers[id] === mgr else { return }
        if virtualManager(for: id) != nil {
            guard await sendMessage("router:stop-port", to: id) == "ok" else {
                throw err("The virtual connection did not acknowledge stopping this VPN.")
            }
            virtualStoppedMembers.insert(id)
        }
        locallyRemovedProfileIDs.insert(id)
        sshNetworkAgentEpochs[id] = nil
        sshNetworkAgentBrokers.removeValue(forKey: id)?.cancel()
        await tailscaleIdentityMigrations[id]?.value
        await drainTailscaleStateBroker(id)
        if kind == .tailscale { _ = await sendMessageData("tsforget", to: id, timeout: 4) }
        mgr.connection.stopVPNTunnel()
        // NetworkExtension removes preferences asynchronously.  Hide this
        // profile before awaiting it so an unrelated refresh cannot put the
        // old manager back in the UI, then keep its tombstone until our own
        // confirming refresh has completed.
        hideProfileWhileRemoving(id: id)
        managers.removeValue(forKey: id)
        authConfigs.removeValue(forKey: id)
        credentialSources.removeValue(forKey: id)
        overridesCache.removeValue(forKey: id)
        filterActivity.clear(id)
        customRoutingCache.removeValue(forKey: id)
        uiPrefsCache.removeValue(forKey: id)

        // Remove preferences before deleting their user-Keychain identity.
        do {
            try await mgr.removeFromPreferences()
        } catch {
            // The preference removal did not stick, so allow the next refresh
            // to restore the real profile rather than leaving a phantom delete.
            locallyRemovedProfileIDs.remove(id)
            throw error
        }
        // The manager was hidden while preferences were being removed, so its
        // final disconnected notification may never reach the mediators.
        forgetRemovedNetworkProfiles([id])
        ConfigSecretTransfer.deleteAll(id: id)
        FirstSuccessfulConnectionStore.clear(profile: id)
        ConnectionBaselineStore.clear(profile: id)
        // Keep the tombstone through this refresh: NetworkExtension can briefly
        // hand back the just-removed manager to another request in flight.
    }

    /// Also called when macOS removes a profile outside this app. Release
    /// secrets and editor state in memory without deleting any Keychain items.
    func forgetCachedProfile(_ id: String) {
        connectionReservations.cancel(member: id)
        credentialSaveTasks.removeValue(forKey: id)?.cancel()
        transientCreds[id] = nil
        preparedOnePasswordSignIns[id] = nil
        setTypedSignInOnce(false, for: id)
        sshNetworkTunnelConfigs[id] = nil
        sshNetworkTunnelStatuses[id] = nil
        wireGuardConfigs[id] = nil
        wireGuardStatuses[id] = nil
        tailscaleConfigs[id] = nil
        tailscaleStatuses[id] = nil
        clearTailscaleSignIn(id: id)
        proxyTunnelConfigs[id] = nil
        proxyTunnelStatuses[id] = nil
        appliedOverrides[id] = nil
        appliedOVPN[id] = nil
        ovpnSecretsCache[id] = nil
        ovpnTextCache[id] = nil
        inlineSecretMigrationFailures[id] = nil
        endpointsCache[id] = nil
        lastChange[id] = nil
        credentialSources[id] = nil
        authConfigs[id] = nil
        overridesCache[id] = nil
        filterActivity.clear(id)
        customRoutingCache[id] = nil
        uiPrefsCache[id] = nil
        routingRulesCache[id] = nil
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
              let proto = mgr.protocolConfiguration as? NETunnelProviderProtocol else { throw err("The VPN is no longer available.") }
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
        do { try await persistEndpointList(list, for: id) }
        catch { report(error, profile: id) }
    }

    func persistEndpointList(_ list: VPNEndpointList, for id: String) async throws {
        guard let mgr = managers[id],
              let proto = mgr.protocolConfiguration as? NETunnelProviderProtocol else { throw err("The VPN is no longer available.") }
        var conf = proto.providerConfiguration ?? [:]
        if let blob = list.encodedBlob() { conf["endpoints"] = blob }
        else { conf.removeValue(forKey: "endpoints") }
        proto.providerConfiguration = conf
        mgr.protocolConfiguration = proto
        try await mgr.saveToPreferences()
        try await mgr.loadFromPreferences()
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

    /// Write down the order the user put this VPN's servers in.
    ///
    /// One annotation per server, through `setEndpointList` — the same blob, the
    /// same save, the same cache as a name or a corrected country. There is no
    /// second store for order, and nothing here touches the configuration's own
    /// `remote` lines: a position says which server the app OFFERS first, not what
    /// the file says. That is what makes reordering a configuration-provided server
    /// honest — its address is still the file's, and its lock rides with the row.
    ///
    /// Servers the caller didn't mention keep whatever they had, so a partial list
    /// can't quietly unplace the rest.
    func setEndpointOrder(_ orderedIDs: [String], for id: String) async {
        let shown = endpoints(for: id)
        var byID: [String: VPNEndpoint] = [:]
        for e in endpointList(for: id).endpoints { byID[e.id] = e }
        for (position, endpointID) in orderedIDs.enumerated() {
            // The displayed list is what supplies host/port/proto for a server that
            // has never been annotated before — an entry invented here would be a
            // second, drifting copy of an address the .ovpn owns.
            guard let base = byID[endpointID] ?? shown.first(where: { $0.id == endpointID }) else { continue }
            var e = base
            e.order = position
            byID[endpointID] = e
        }
        var list = endpointList(for: id)
        // Keep the stored list in the shown order where we know it: the tail of
        // `VPNEndpointList.merged` (the hand-added servers) is emitted in stored
        // order, so a stored list that disagrees with the user's would put a new
        // server's position and its row in different places for one render.
        let rank = Dictionary(uniqueKeysWithValues: orderedIDs.enumerated().map { ($1, $0) })
        list.endpoints = byID.values.sorted {
            (rank[$0.id] ?? Int.max, $0.id) < (rank[$1.id] ?? Int.max, $1.id)
        }
        await setEndpointList(list, for: id)
    }

    // MARK: Choosing one (the ONE place a server choice is written)

    /// Point a VPN at one of its servers — or at nothing (Automatic).
    ///
    /// ONE ENTRY POINT FOR TWO MECHANISMS, and that is the whole reason it exists.
    /// For every kind whose server identity is checked by a certificate, choosing a
    /// server writes `OpenVPNOverrides.server/port/proto` and the engine's own name
    /// verification does the rest. WIREGUARD HAS NO CERTIFICATE: the peer's public
    /// key IS the identity, Mullvad gives every relay its own, and so a choice there
    /// has to move the address and the key TOGETHER
    /// (`WireGuardEndpointSelection` — read its header for what getting it wrong
    /// looks like, which is a tunnel that connects to nothing, silently, forever).
    ///
    /// Returns the refusal to show, or nil when the choice was made. A refusal is
    /// never silent: a picker that appears to accept a choice and quietly keeps the
    /// old one is the failure this whole path is defending against.
    @discardableResult
    func selectEndpoint(_ endpoint: VPNEndpoint?, for id: String) async -> String? {
        guard isWireGuard(id) else {
            var o = overrides(for: id)
            o.server = endpoint?.host
            o.port = endpoint?.port
            o.proto = endpoint?.proto.flatMap { OpenVPNOverrides.TransportProto(rawValue: $0) }
            try? await setOverrides(o, for: id)
            return nil
        }
        // "Automatic" has no meaning for WireGuard: a peer is one address and one
        // key, and there is no failover list to fall back to. The picker does not
        // offer it, and a programmatic nil is a no-op rather than a config wiped
        // down to no endpoint at all.
        guard let endpoint else { return nil }
        let config = wireGuardConfig(for: id)
        switch WireGuardEndpointSelection.selecting(endpoint, from: endpoints(for: id), in: config) {
        case .refused(let why):
            return why
        case .applied(let next):
            do { try await setWireGuardConfig(next, for: id) } catch {
                return error.localizedDescription
            }
            return nil
        }
    }

    /// Go back to the automatic order (measured, else nearest). The counterpart to
    /// `setEndpointOrder` and the reason a manual order is never a one-way door —
    /// an annotation left with nothing but a cleared position stops being stored at
    /// all (`VPNEndpointList.encodedBlob` drops it).
    func clearEndpointOrder(for id: String) async {
        var list = endpointList(for: id)
        for i in list.endpoints.indices { list.endpoints[i].order = nil }
        await setEndpointList(list, for: id)
    }

    // MARK: Interface preferences (per-VPN optional controls)


    func uiPrefs(for id: String) -> VPNUIPrefs {
        if let cached = uiPrefsCache[id] { return cached }
        let proto = managers[id]?.protocolConfiguration as? NETunnelProviderProtocol
        return VPNUIPrefs.decode(from: proto?.providerConfiguration?["uiprefs"] as? Data)
    }

    func setUIPrefs(_ prefs: VPNUIPrefs, for id: String) async {
        do { try await persistUIPrefs(prefs, for: id) }
        catch { report(error, profile: id) }
    }

    func persistUIPrefs(_ prefs: VPNUIPrefs, for id: String) async throws {
        guard let mgr = managers[id],
              let proto = mgr.protocolConfiguration as? NETunnelProviderProtocol else { throw err("The VPN is no longer available.") }
        var conf = proto.providerConfiguration ?? [:]
        if let blob = prefs.encodedBlob() { conf["uiprefs"] = blob }
        else { conf.removeValue(forKey: "uiprefs") }
        proto.providerConfiguration = conf
        mgr.protocolConfiguration = proto
        try await mgr.saveToPreferences()
        try await mgr.loadFromPreferences()
        uiPrefsCache[id] = prefs
    }

    // MARK: Sidebar order (the part of the arrangement NE profiles carry)

    /// Write new sidebar positions for the NE profiles named in `positions`.
    ///
    /// THE CACHE IS UPDATED FIRST, SYNCHRONOUSLY, and the saves follow. Each NE
    /// profile is its own `NEVPNManager`, so N rows means N `saveToPreferences()`
    /// round-trips and there is no batch write to be had; doing them before the UI
    /// caught up would draw every intermediate order and the rows would visibly hop
    /// on their way to where they were put. `uiPrefs(for:)` reads the cache, so
    /// seeding it is what makes the drag land in one step.
    ///
    /// Profiles this map doesn't name are left alone — a section's move renumbers
    /// every row, but a row whose rank hasn't changed is not worth an NE save.
    func setSidebarOrder(_ positions: [String: Int]) async {
        var pending: [(String, VPNUIPrefs)] = []
        for (id, rank) in positions {
            guard managers[id] != nil else { continue }
            var prefs = uiPrefs(for: id)
            guard prefs.order != rank else { continue }
            prefs.order = rank
            uiPrefsCache[id] = prefs
            pending.append((id, prefs))
        }
        for (id, prefs) in pending { await setUIPrefs(prefs, for: id) }
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
        guard !authConfig(for: id).protectWithBiometrics else { return nil }
        return KeychainCredentialStore.loadCredentials(profile: id)
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
    /// Secret storage migration preserves the connection's exact values and
    /// applies even when editing is locked. The OS may still reject its rewrite;
    /// that failure retains the original and displays a migration notice.
    func migrateInlineOVPNSecrets() async {
        for profile in profiles where profile.kind == .openVPN {
            let id = profile.id
            let gate = openVPNConfigurationGate(for: id)
            await gate.acquire()
            defer { gate.release() }
            guard !locallyRemovedProfileIDs.contains(id), let stored = storedOVPNText(id: id), !stored.isEmpty else { continue }
            let split = OVPNSecretMaterial.split(stored)
            if let tag = split.unterminatedTag {
                inlineSecretMigrationFailures[id] = OpenVPNConfigurationEdit.Failure.incomplete(tag).localizedDescription
                continue
            }
            guard !split.secrets.isEmpty else {
                inlineSecretMigrationFailures.removeValue(forKey: id)
                continue
            }
            guard let mgr = managers[id],
                  let proto = mgr.protocolConfiguration as? NETunnelProviderProtocol else { continue }

            // What is inline wins over any earlier keychain copy — it is what the
            // engine has actually been connecting with.
            var blocks: [String: String]
            do { blocks = try KeychainCredentialStore.ovpnInlineSecretsForExport(profile: id) }
            catch {
                inlineSecretMigrationFailures[id] = OpenVPNConfigurationEdit.Failure.unavailable.localizedDescription
                continue
            }
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
