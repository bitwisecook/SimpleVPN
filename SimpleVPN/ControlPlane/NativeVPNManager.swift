// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
// App-initiated IPsec sessions use the authenticated packet provider. The personal
// manager is observed only for older profiles installed in System Settings.
// Existing shared-secret, certificate and configuration-profile exports retain their identities.

import Foundation
@preconcurrency import NetworkExtension
import Observation
import os

struct NativeVPNConfig: Codable, Sendable, Equatable, Identifiable {
    var id = UUID().uuidString
    var name = "New Native VPN"
    var routingEventSource: String?
    var kind: VPNKind = .ikev2      // .ikev2 | .ipsec | .l2tp
    var server = ""
    var remoteID = ""               // IKEv2 remote identifier (server cert CN / FQDN)
    var username = ""
    // Auth: username/password (EAP) is the default; a shared secret (PSK) is
    // common for IPsec/L2TP and available for IKEv2.
    var usesSharedSecret = false
    var eapMSCHAPv2: Bool? = nil
    var l2tpMSCHAPv2: Bool? = nil
    var groupOrRealm = ""           // IPsec group name / local identifier
    var onDemand = false

    /// IPsec only: whether XAuth (the username/password pair alongside the group
    /// PSK) is used at all. Cisco-style concentrators come both ways, and there
    /// was no way to say "no XAuth" — a username left over from a `.pcf` import
    /// meant `useExtendedAuthentication` stayed on with nothing behind it.
    ///
    /// OPTIONAL on purpose: the decoder preserves nil for old profiles, rather
    /// than turning a missing choice into an explicit yes/no. nil means "not
    /// answered yet", which `usesXAuth` reads as the old behaviour: XAuth is in
    /// play exactly when a username was entered.
    var xauth: Bool? = nil

    /// Whether this IPsec config signs in with XAuth as well as the group PSK.
    var usesXAuth: Bool { xauth ?? !username.isEmpty }

    // Comprehensive IKEv2 knobs (empty/nil = use the OS default). Crypto choices
    // map to NEVPNIKEv2* enums; "" means "let macOS negotiate its default".
    //
    // 3DES/DES, SHA-1 (sha96/sha160) and DH groups below 14 are API_OBSOLETED as
    // of macOS 26 — the enum cases no longer exist, so they are deliberately
    // absent from these value sets. Don't re-add them: the picker would offer a
    // choice the apply path can only ignore.
    var ikeEncryption = ""          // "" | aes128 | aes256 | aes128gcm | aes256gcm | chacha20poly1305
    var ikeIntegrity = ""           // "" | sha256 | sha384 | sha512
    var ikeDHGroup = ""             // "" | 14 | 15 | 16 | 19 | 20 | 21 | 31
    var ikeLifetimeMinutes: Int? = nil
    var deadPeerDetection = ""      // "" | none | low | medium | high
    var disableMOBIKE = false
    var enablePFS = false
    var disconnectOnSleep = false
    var includeAllNetworks = false  // send *all* traffic (incl. local) into the tunnel
    var excludeLocalNetworks = true // keep LAN reachable when includeAllNetworks is on

    /// WHERE THIS VPN SITS IN THE SIDEBAR, as the user arranged it. nil = never
    /// placed by hand, which sorts after everything that was. The same field, under
    /// the same name, is on `VPNUIPrefs` and `SubprocessTunnelConfig`, because both
    /// sidebars interleave all three stores under one heading; `ConnectOrder` is the
    /// only thing that reads or writes it. Optional so configs saved before the field
    /// existed still decode (the `xauth` precedent).
    var order: Int? = nil

    init() {}

    init(from decoder: Decoder) throws {
        let values = try decoder.container(keyedBy: CodingKeys.self)
        routingEventSource = try values.decodeIfPresent(String.self, forKey: .routingEventSource)
        id = try values.decodeIfPresent(String.self, forKey: .id) ?? id
        name = try values.decodeIfPresent(String.self, forKey: .name) ?? name
        kind = try values.decodeIfPresent(VPNKind.self, forKey: .kind) ?? kind
        server = try values.decodeIfPresent(String.self, forKey: .server) ?? server
        remoteID = try values.decodeIfPresent(String.self, forKey: .remoteID) ?? remoteID
        username = try values.decodeIfPresent(String.self, forKey: .username) ?? username
        l2tpMSCHAPv2 = try values.decodeIfPresent(Bool.self, forKey: .l2tpMSCHAPv2)
        eapMSCHAPv2 = try values.decodeIfPresent(Bool.self, forKey: .eapMSCHAPv2)
        usesSharedSecret = try values.decodeIfPresent(Bool.self, forKey: .usesSharedSecret) ?? usesSharedSecret
        groupOrRealm = try values.decodeIfPresent(String.self, forKey: .groupOrRealm) ?? groupOrRealm
        onDemand = try values.decodeIfPresent(Bool.self, forKey: .onDemand) ?? onDemand
        xauth = try values.decodeIfPresent(Bool.self, forKey: .xauth)
        ikeEncryption = try values.decodeIfPresent(String.self, forKey: .ikeEncryption) ?? ikeEncryption
        ikeIntegrity = try values.decodeIfPresent(String.self, forKey: .ikeIntegrity) ?? ikeIntegrity
        ikeDHGroup = try values.decodeIfPresent(String.self, forKey: .ikeDHGroup) ?? ikeDHGroup
        ikeLifetimeMinutes = try values.decodeIfPresent(Int.self, forKey: .ikeLifetimeMinutes)
        deadPeerDetection = try values.decodeIfPresent(String.self, forKey: .deadPeerDetection) ?? deadPeerDetection
        disableMOBIKE = try values.decodeIfPresent(Bool.self, forKey: .disableMOBIKE) ?? disableMOBIKE
        enablePFS = try values.decodeIfPresent(Bool.self, forKey: .enablePFS) ?? enablePFS
        disconnectOnSleep = try values.decodeIfPresent(Bool.self, forKey: .disconnectOnSleep) ?? disconnectOnSleep
        includeAllNetworks = try values.decodeIfPresent(Bool.self, forKey: .includeAllNetworks) ?? includeAllNetworks
        excludeLocalNetworks = try values.decodeIfPresent(Bool.self, forKey: .excludeLocalNetworks) ?? excludeLocalNetworks
        order = try values.decodeIfPresent(Int.self, forKey: .order)
    }

    // MARK: Legal ranges (single source of truth for UI validation)

    /// `lifetimeMinutes` on both security associations. Apple's accepted window;
    /// the OS defaults are 60 (IKE SA) and 30 (child SA). Outside this range the
    /// value is refused when the configuration is saved, which surfaces as an
    /// opaque "configuration invalid".
    static let ikeLifetimeRange = 10...1440

    /// Trim, and collapse an out-of-range lifetime back to "OS default" (nil).
    /// Called from every save path, the same shape as
    /// `OpenVPNOverrides.normalized()`.
    func normalized() -> NativeVPNConfig {
        var n = self
        n.name = name.trimmingCharacters(in: .whitespacesAndNewlines)
        n.server = server.trimmingCharacters(in: .whitespacesAndNewlines)
        n.remoteID = remoteID.trimmingCharacters(in: .whitespacesAndNewlines)
        n.username = username.trimmingCharacters(in: .whitespacesAndNewlines)
        n.groupOrRealm = groupOrRealm.trimmingCharacters(in: .whitespacesAndNewlines)
        if let m = n.ikeLifetimeMinutes, !Self.ikeLifetimeRange.contains(m) { n.ikeLifetimeMinutes = nil }
        return n
    }

    /// Why this server address can't be used — nil when it's fine. Save and
    /// Connect only checked `.isEmpty`, so a typo (or a pasted URL, or a
    /// host:port) reached NEVPNManager and came back as an IKE timeout minutes
    /// later with nothing pointing at the field.
    static func serverProblem(_ raw: String) -> String? {
        let s = raw.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !s.isEmpty else { return "Enter the server's address." }
        // An IP literal is always fine.
        var bytes = [UInt8](repeating: 0, count: 16)
        let isV6 = s.contains(":") && !s.contains("://")
        if s.withCString({ inet_pton(isV6 ? AF_INET6 : AF_INET, $0, &bytes) == 1 }) { return nil }
        if s.contains("://") {
            return "Enter just the server's address (like vpn.example.com), not a web address."
        }
        if s.contains("@") {
            return "Enter just the server's address — the username goes in the Sign-In section."
        }
        if s.contains("/") {
            return "Enter just the server's address (like vpn.example.com), with nothing after it."
        }
        if s.contains(":") {
            return "Enter just the server's address — IKEv2 and IPsec have no port to set."
        }
        if s.hasPrefix(".") || s.hasSuffix(".") || s.contains("..") {
            return "\(s) isn't a valid server address."
        }
        guard s.allSatisfy({ $0.isASCII && ($0.isLetter || $0.isNumber || $0 == "-" || $0 == ".") }) else {
            return "\(s) isn't a valid server address — use the name or IP address your admin gave you."
        }
        return nil
    }

    var serverProblem: String? { Self.serverProblem(server) }
}

/// Where a native VPN's secrets live, and what saving one must do to each
/// keychain row. Expressed as a PLAN rather than inline `if !secret.isEmpty`
/// writes so the rule that clearing a field really removes the stored secret —
/// instead of leaving the old one in the keychain and still authenticating at
/// the next Connect — is one rule, in one place, and directly testable.
nonisolated enum NativeVPNSecrets {

    /// What a save does to one row.
    enum Action: Equatable, Sendable {
        case write(String)
        case delete
        /// Don't touch this row at all. The kind being saved doesn't OWN it, so
        /// the editor has no field for it and the save has nothing to say about
        /// it. `.delete` here is how switching Protocol to look at a config and
        /// back destroyed the other kind's secret.
        case leave
    }

    /// The rows a native config can own: the base secret (the IKEv2 password or
    /// PSK, or the IPsec XAuth password), the IPsec group PSK, and L2TP's PPP
    /// (user) password.
    struct Plan: Equatable, Sendable {
        var base: Action
        var groupPSK: Action
        /// L2TP only: the PPP password the exported `.mobileconfig` carries as
        /// `PPP.AuthPassword`. Its own row because L2TP needs it AND the IPSec
        /// shared secret at once, exactly like IPsec's pair.
        var pppPassword: Action = .leave
        /// Drop the PERSISTENT-REFERENCE copy of the base secret (the one
        /// `connect()` hands NEVPNManager) while KEEPING the credential row.
        ///
        /// This is IPsec-with-XAuth-off: the group PSK is the whole sign-in, so
        /// nothing username/password-shaped may be referenced — but the password
        /// the user typed is still theirs. It used to be `.delete`d outright, with
        /// the row still on screen showing dots, so turning a toggle off
        /// unrecoverably destroyed a password. `CustomRoutingTabView`'s
        /// `syncCustomRoutingProxyAuth` already made the other choice for exactly
        /// this situation ("a mode flip shouldn't lose what was typed") — this
        /// follows that precedent.
        var dropBaseReference = false
    }

    /// Credential-row ids (the persistent-reference accounts `connect()` writes
    /// share the base names — see `apply`).
    static func baseProfile(_ id: String) -> String { "native.\(id)" }
    static func groupPSKProfile(_ id: String) -> String { "native.\(id).secret" }
    static func pppPasswordProfile(_ id: String) -> String { "native.\(id).ppp" }

    /// An EMPTIED field means "no such secret" — hence `.delete`, never "leave
    /// whatever was there". Two rules bound that, and both were missing:
    ///
    ///  • A row the saved kind DOESN'T OWN is `.leave`, not `.delete`. Only IPsec
    ///    has a group PSK and only L2TP has a PPP password, and the editor has no
    ///    field for either under another kind — so "empty" there means "not
    ///    loaded", not "removed". Deleting on a kind change is how switching
    ///    Protocol to look at a config and switching back (or pressing Export,
    ///    which saves first) wiped the group PSK / PPP password out of the
    ///    keychain with no warning and no way back.
    ///
    ///  • Turning XAuth off does not destroy the XAuth password. With XAuth off
    ///    the group PSK is the entire sign-in, so nothing username/password-shaped
    ///    may be SENT — which `connect()` already guarantees (no
    ///    `useExtendedAuthentication`, no `passwordReference`). The row stays, and
    ///    only the persistent-reference copy goes (`dropBaseReference`).
    static func plan(kind: VPNKind, secret: String, sharedSecret: String = "",
                     pppPassword: String = "", xauth: Bool = true) -> Plan {
        Plan(base: secret.isEmpty ? .delete : .write(secret),
             groupPSK: kind == .ipsec ? (sharedSecret.isEmpty ? .delete : .write(sharedSecret)) : .leave,
             pppPassword: kind == .l2tp ? (pppPassword.isEmpty ? .delete : .write(pppPassword)) : .leave,
             dropBaseReference: kind == .ipsec && !xauth)
    }

    /// Perform a plan. A delete removes BOTH the credential row and the
    /// persistent-reference copy `connect()` made from it — leaving either
    /// behind is a stale-secret leak (the rule `NativeVPNManager.remove(_:)`
    /// already follows).
    @MainActor static func apply(_ plan: Plan, id: String, username: String) throws {
        switch plan.base {
        case .write(let secret):
            try KeychainCredentialStore.saveCredentials(
                profile: baseProfile(id), .init(username: username, password: secret))
        case .delete:
            KeychainCredentialStore.deleteCredentials(profile: baseProfile(id))
            KeychainCredentialStore.deleteNativeSecret(account: "native.\(id)")
        case .leave:
            break
        }
        // XAuth off: the password stays where the user put it, but nothing may
        // reference it. Only the persistent-reference copy goes.
        if plan.dropBaseReference {
            KeychainCredentialStore.deleteNativeSecret(account: "native.\(id)")
        }
        switch plan.groupPSK {
        case .write(let psk):
            try KeychainCredentialStore.saveCredentials(
                profile: groupPSKProfile(id), .init(username: "", password: psk))
        case .delete:
            KeychainCredentialStore.deleteCredentials(profile: groupPSKProfile(id))
            KeychainCredentialStore.deleteNativeSecret(account: "native.\(id).psk")
        case .leave:
            break
        }
        // L2TP's PPP password never reaches NEVPNManager (there is no L2TP API),
        // so it has no persistent-reference copy to clean up — only the row the
        // exporter reads.
        switch plan.pppPassword {
        case .write(let pw):
            try KeychainCredentialStore.saveCredentials(
                profile: pppPasswordProfile(id), .init(username: username, password: pw))
        case .delete:
            KeychainCredentialStore.deleteCredentials(profile: pppPasswordProfile(id))
        case .leave:
            break
        }
    }
}

@MainActor
@Observable
final class NativeVPNManager {
    private static let log = Logger(subsystem: "com.bragi0.SimpleVPN", category: "native")

    var dnsQueryStatusDidChange: (@MainActor () -> Void)?
    private(set) var status: NEVPNStatus = .invalid { didSet { dnsQueryStatusDidChange?() } }
    private(set) var activeConfigID: String? { didSet { dnsQueryStatusDidChange?() } }
    private var lastConnectionFailure: (configID: String, message: String)?
    func connectionError(for id: String) -> String? {
        guard let failure = lastConnectionFailure, failure.configID == id else { return nil }
        return failure.message
    }

    private(set) var lastError: String?
    /// Set when saveToPreferences fails for the missing Personal VPN capability.

    private var store: [NativeVPNConfig] = []
    private static let key = "nativeVPNs.v1"
    private static let installedIdentityKey = "nativeVPN.installedIdentity.v1"
    private var observer: NSObjectProtocol?
    private var packetObserver: NSObjectProtocol?
    weak var gatewayCoordinator: VPNController?
    private var packetManager: NETunnelProviderManager?
    private static let protectedKey = "nativeVPNs.packet-policy.v1"
    @ObservationIgnored private let operations = AsyncOperationGate()
    private var lifecycleRevision: UInt64 = 0

    var configs: [NativeVPNConfig] { store }

    private let configDefaults: UserDefaults

    init(loadSaved: Bool = true, defaults: UserDefaults = .standard, observeSystem: Bool = true) {
        configDefaults = defaults
        guard loadSaved else { return }
        load()
        guard observeSystem else { return }
        // Scope to the shared personal-VPN connection so we don't churn on every
        // unrelated OpenVPN packet-tunnel transition.
        observer = NotificationCenter.default.addObserver(
            forName: .NEVPNStatusDidChange, object: NEVPNManager.shared().connection, queue: .main) { [weak self] _ in
                MainActor.assumeIsolated {
                    guard let self, self.packetManager == nil else { return }
                    let s = NEVPNManager.shared().connection.status
                    self.status = s
                    // The tunnel can drop OS-side (sleep, server, auth) without a
                    // call to disconnect(); clear the active id so the UI doesn't
                    // keep showing the config as connected.
                    self.restoreActiveIdentity(NEVPNManager.shared())
                }
            }
        Task { await refreshStatus() }
    }

    // MARK: CRUD (local field store; the OS holds only the connected one)

    func save(_ raw: NativeVPNConfig) {
        // normalized() on every save path (the OpenVPNOverrides rule).
        var c = raw.normalized()
        if let previous = store.first(where: { $0.id == c.id }) {
            c.routingEventSource = previous.routingEventSource
        }
        if let i = store.firstIndex(where: { $0.id == c.id }) { store[i] = c } else { store.append(c) }
        persist()
    }

    func setPacketPolicy(_ source: String?, for draft: NativeVPNConfig) async throws {
        guard !ManagedPolicy.lockConfiguration else { throw VPNController.configLocked }
        let reservation = gatewayCoordinator?.connectionReservations.reserve(owner: "native-policy." + draft.id, members: [draft.id])
        defer { if let reservation { gatewayCoordinator?.connectionReservations.finish(reservation) } }
        if let coordinator = gatewayCoordinator, reservation == nil || coordinator.virtualManager(for: draft.id) != nil {
            throw ProfilePacketPolicy.failure("Disconnect the virtual connection before changing this member’s handlers.")
        }
        let previous = store.first { $0.id == draft.id }
        guard previous != nil else { throw ProfilePacketPolicy.failure("Save the VPN before adding traffic handlers.") }
        await operations.acquire()
        defer { operations.release() }
        if source != nil {
            try await SystemExtensionManager.requireCurrentProvider()
            try await ProfilePacketPolicy.validate(source, adapter: draft.ownedIPsec?.adapterID)
            try await retirePersonalMirror(of: draft, requiresIsolation: true)
        }
        try await NativePacketMirror.revoke(draft.id)
        guard let index = store.firstIndex(where: { $0.id == draft.id }), store[index] == previous else {
            throw ProfilePacketPolicy.failure("The VPN changed. Reopen its routing settings.")
        }
        store[index].routingEventSource = source
        persist()
    }

    func prepareVirtualMember(_ config: NativeVPNConfig) async throws {
        await operations.acquire()
        defer { operations.release() }
        guard store.first(where: { $0.id == config.id }) == config, !(activeConfigID == config.id && UI.isActive(status)) else {
            throw ProfilePacketPolicy.failure("The selected IPsec VPN changed or is already active.")
        }
        try await retirePersonalMirror(of: config, requiresIsolation: true)
    }

    func status(for id: String) -> NEVPNStatus {
        gatewayCoordinator?.virtualMemberStatus(for: id) ?? (activeConfigID == id ? status : .disconnected)
    }

    func disconnect(_ id: String) {
        if let vpn = gatewayCoordinator, vpn.virtualManager(for: id) != nil { vpn.disconnect(id: id) }
        else if activeConfigID == id { disconnect() }
    }

    private func retirePersonalMirror(of config: NativeVPNConfig, requiresIsolation: Bool) async throws {
        guard config.kind != .l2tp else { return }
        let personal = NEVPNManager.shared()
        let identity = UserDefaults.standard.data(forKey: Self.installedIdentityKey).flatMap {
            try? JSONDecoder().decode(NativeVPNInstalledIdentity.self, from: $0)
        }
        do { try await personal.loadFromPreferences() } catch {
            if identity?.id == config.id || requiresIsolation { throw error }
            return
        }
        guard personal.isEnabled, let proto = personal.protocolConfiguration else { return }
        guard identity?.id == config.id || (identity == nil && proto.serverAddress == config.server && personal.localizedDescription == config.name) else { return }
        if !requiresIsolation, !personal.isOnDemandEnabled, !UI.isActive(personal.connection.status) { return }
        guard identity?.matches(proto) == true, !UI.isActive(personal.connection.status) else {
            throw ProfilePacketPolicy.failure("Disconnect and identify the installed personal VPN before switching it to the built-in IPsec engine.")
        }
        personal.isOnDemandEnabled = false
        personal.isEnabled = false
        try await personal.saveToPreferences()
    }

    private func observePacket(_ manager: NETunnelProviderManager, id: String) {
        if let packetObserver { NotificationCenter.default.removeObserver(packetObserver) }
        packetManager = manager
        activeConfigID = id
        status = manager.connection.status
        updatePacketRole(id: id, manager: manager)
        packetObserver = NotificationCenter.default.addObserver(forName: .NEVPNStatusDidChange, object: manager.connection, queue: .main) { [weak self] _ in
            MainActor.assumeIsolated {
                guard let self, let current = self.packetManager, NativePacketMirror.profileID(current) == id else { return }
                self.status = current.connection.status
                self.updatePacketRole(id: id, manager: current)
                if !UI.isActive(self.status) {
                    self.activeConfigID = nil
                    self.packetManager = nil
                    if let token = self.packetObserver { NotificationCenter.default.removeObserver(token); self.packetObserver = nil }
                }
            }
        }
    }

    private func updatePacketRole(id: String, manager: NETunnelProviderManager) {
        guard let vpn = gatewayCoordinator, let config = store.first(where: { $0.id == id }) else { return }
        let s = manager.connection.status
        let ended = s == .invalid || s == .disconnected
        vpn.nativePacketManagers[id] = ended ? nil : manager
        vpn.nativePacketProfiles[id] = ended ? nil : .init(id: id, name: config.name, server: config.server, status: s, kind: config.kind)
        vpn.routes.handleStatusChange(id: id, connected: s == .connected, reasserting: s == .reasserting, disconnected: ended)
        if ended { vpn.pushedNetworkState[id] = nil }
    }

    /// Write new sidebar positions for the configs named in `positions`, and persist
    /// ONCE — the counterpart to `SubprocessTunnelStore.setOrder`, and a batch for the
    /// same reason: one drag renumbers every row, and saving row by row would publish
    /// (and draw) each intermediate order.
    func setOrder(_ positions: [String: Int]) {
        var changed = false
        for i in store.indices {
            guard let rank = positions[store[i].id], store[i].order != rank else { continue }
            store[i].order = rank
            changed = true
        }
        if changed { persist() }
    }

    @discardableResult func remove(_ id: String) async -> Bool {
        if let vpn = gatewayCoordinator, vpn.virtualManager(for: id) != nil || vpn.connectionReservations.isStarting(id) {
            lastError = "Disconnect the composition before removing this member."
            return false
        }
        lifecycleRevision += 1
        await operations.acquire()
        defer { operations.release() }
        let manager = NEVPNManager.shared()
        do {
            try await manager.loadFromPreferences()
            let identity = UserDefaults.standard.data(forKey: Self.installedIdentityKey).flatMap {
                try? JSONDecoder().decode(NativeVPNInstalledIdentity.self, from: $0)
            }
            if identity?.id == id && identity?.matches(manager.protocolConfiguration) != true {
                lastError = "The installed native VPN changed outside this saved profile. Its configuration and credentials were kept."
                return false
            }
            if identity == nil, let config = store.first(where: { $0.id == id }),
               manager.protocolConfiguration?.serverAddress == config.server,
               manager.localizedDescription == config.name {
                lastError = "Remove this legacy VPN in System Settings before deleting its saved configuration. Its credentials were kept."
                return false
            }
            if let identity,
               identity.id == id, identity.matches(manager.protocolConfiguration) {
                manager.connection.stopVPNTunnel()
                try await manager.removeFromPreferences()
                UserDefaults.standard.removeObject(forKey: Self.installedIdentityKey)
                activeConfigID = nil
            }
        } catch {
            lastError = "The installed native VPN could not be removed. Its configuration and credentials were kept."
            return false
        }
        do { try await NativePacketMirror.revoke(id) }
        catch { lastError = error.localizedDescription; return false }
        store.removeAll { $0.id == id }
        ConfigSecretTransfer.deleteAll(id: id)
        CustomRoutingFallbackStore().clear(id)
        persist()
        return true
    }

    // MARK: Connect

    func refreshStatus() async {
        let revision = lifecycleRevision
        await operations.acquire()
        defer { operations.release() }
        guard revision == lifecycleRevision else { return }
        if !store.isEmpty, let active = try? await NativePacketMirror.managers().first(where: { UI.isActive($0.connection.status) }),
           let id = NativePacketMirror.profileID(active), store.contains(where: { $0.id == id }), revision == lifecycleRevision {
            observePacket(active, id: id)
            return
        }
        let mgr = NEVPNManager.shared()
        try? await mgr.loadFromPreferences()
        guard revision == lifecycleRevision else { return }
        status = mgr.connection.status
        restoreActiveIdentity(mgr)
        if VPNController.permitsLiveCredentialBrokers { _ = await migrateStoredProxyCredentials(mgr) }
    }

    private func restoreActiveIdentity(_ manager: NEVPNManager) {
        guard UI.isActive(status),
              let data = UserDefaults.standard.data(forKey: Self.installedIdentityKey),
              let installed = try? JSONDecoder().decode(NativeVPNInstalledIdentity.self, from: data),
              store.contains(where: { $0.id == installed.id }), installed.matches(manager.protocolConfiguration) else {
            activeConfigID = nil; return
        }
        activeConfigID = installed.id
    }

    private func migrateStoredProxyCredentials(_ manager: NEVPNManager) async -> Bool {
        guard let proto=manager.protocolConfiguration, let proxy=proto.proxySettings,
              NativeProxyCredentials.hasStoredSecret(proxy) else { return true }
        guard manager.connection.status == .disconnected || manager.connection.status == .invalid else {
            lastError="Disconnect the native VPN to move its previous proxy credentials into your Keychain."; return false
        }
        let candidates=store.filter { config in
            config.server == proto.serverAddress && config.name == manager.localizedDescription
                && ((config.kind == .ikev2 && proto is NEVPNProtocolIKEv2) || (config.kind == .ipsec && proto is NEVPNProtocolIPSec && !(proto is NEVPNProtocolIKEv2)))
        }
        guard let id=activeConfigID ?? (candidates.count == 1 ? candidates[0].id : nil) else {
            lastError="The previous native proxy credentials could not be matched to a saved VPN. The original configuration was kept."; return false
        }
        let credentials=[("http",proxy.httpServer),("https",proxy.httpsServer)].compactMap { kind, server -> (String,KeychainCredentialStore.Credentials)? in
            guard let server, let password=server.password, !password.isEmpty else { return nil }
            return ("native.proxy.\(kind).\(id)",.init(username:server.username ?? "",password:password))
        }
        do {
            try await Task.detached {
                for (account,credential) in credentials {
                    try KeychainCredentialStore.saveCredentials(profile:account,credential)
                    guard let saved=try KeychainCredentialStore.credentialsForExport(profile:account), saved.username == credential.username, saved.password == credential.password else { throw NSError(domain:"SimpleVPN.Keychain",code:1) }
                }
            }.value
            guard manager.protocolConfiguration === proto,
                  store.contains(where: { $0.id == id }),
                  manager.connection.status == .disconnected || manager.connection.status == .invalid else {
                lastError="The native VPN changed while its credentials were being migrated. Retry after disconnecting."; return false
            }
            let updated=proto.copy() as! NEVPNProtocol
            updated.proxySettings=NativeProxyCredentials.redacted(proxy)
            manager.protocolConfiguration=updated
            do { try await manager.saveToPreferences(); try await manager.loadFromPreferences() }
            catch { manager.protocolConfiguration=proto; throw error }
            guard !NativeProxyCredentials.hasStoredSecret(manager.protocolConfiguration?.proxySettings) else { throw NSError(domain:"SimpleVPN.Keychain",code:1) }
            lastError=NativeProxyCredentials.unsupported
            return true
        } catch {
            lastError="The previous native proxy credentials could not be migrated. The original configuration was kept."; return false
        }
    }

    func replacementWarning(for id: String) -> String? {
        guard UI.isActive(status), let activeConfigID, activeConfigID != id else { return nil }
        let name = store.first { $0.id == activeConfigID }?.name.trimmingCharacters(in: .whitespaces)
        return "Disconnect the active VPN named \(name.flatMap { $0.isEmpty ? nil : $0 } ?? "the other native VPN")."
    }

    /// An app-initiated session always starts the owned packet transport. Existing
    /// personal VPN configurations can still be connected in System Settings.
    func connect(_ c: NativeVPNConfig, secret: String, sharedSecret: String = "", pppPassword: String = "",
                 proxy: NEProxySettings?) async {
        lifecycleRevision += 1
        let revision = lifecycleRevision
        await operations.acquire()
        defer { operations.release() }
        guard revision == lifecycleRevision, store.contains(where: { $0.id == c.id }), !Task.isCancelled else { return }
        lastConnectionFailure = nil
        lastError = nil
        defer {
            if let lastError { lastConnectionFailure = (c.id, lastError) }
        }
        let reservation = gatewayCoordinator?.connectionReservations.reserve(owner: "native." + c.id, members: [c.id])
        defer { if let reservation { gatewayCoordinator?.connectionReservations.finish(reservation) } }
        func canStart() -> Bool {
            revision == lifecycleRevision && !Task.isCancelled &&
                (reservation.map { gatewayCoordinator?.connectionReservations.isCurrent($0) == true } ?? (gatewayCoordinator == nil))
        }
        if let vpn = gatewayCoordinator, vpn.virtualManager(for: c.id) != nil || reservation == nil {
            lastError = "Disconnect this VPN’s virtual connection before starting it independently."
            return
        }
        let source = store.first(where: { $0.id == c.id })?.routingEventSource
        guard source == c.routingEventSource else {
            lastError = "The VPN’s routing rules changed. Reopen it before connecting."
            return
        }
        if packetManager.map({ UI.isActive($0.connection.status) }) == true {
            lastError = "Disconnect the active IPsec VPN before connecting another."
            return
        }
        if let issue = c.ownedConnectionIssue { lastError = issue.sentence; return }
        guard proxy == nil else { lastError = "Remove the system proxy override or use this VPN in System Settings. The built-in IPsec transport cannot apply it."; return }
        guard let config = c.ownedIPsec, let gatewayCoordinator else { lastError = "The built-in IPsec connection is unavailable."; return }
        let psk = c.kind == .ipsec ? sharedSecret : secret
        guard !psk.isEmpty else { lastError = config.usesEAP == true ? "Enter the EAP password." : "Enter the IPsec shared secret."; return }
        guard !config.usesXAuth || !secret.isEmpty else { lastError = "Enter the XAuth password."; return }
        guard config.usesL2TP != true || OwnedIPsecConfiguration.validPPPCredential(pppPassword) else { lastError = "Enter a printable ASCII PPP password of 1–255 bytes."; return }
        do {
            if let ensure = gatewayCoordinator.ensureExtensionReady, !(await ensure()) {
                throw ProfilePacketPolicy.failure("Approve SimpleVPN’s network extension in System Settings before connecting with the built-in IPsec engine.")
            }
            try await SystemExtensionManager.requireCurrentProvider()
            try await retirePersonalMirror(of: c, requiresIsolation: c.requiresOwnedIPsec)
            let manager = try await NativePacketMirror.start(config, name: c.name, psk: psk, xauthPassword: secret, pppPassword: pppPassword, source: source, coordinator: gatewayCoordinator) {
                canStart() && self.store.first(where: { $0.id == c.id }) == c
            }
            observePacket(manager, id: c.id)
        } catch { lastError = error.localizedDescription }
    }

    func disconnect() {
        lifecycleRevision += 1
        if let packetManager { packetManager.connection.stopVPNTunnel() }
        else { NEVPNManager.shared().connection.stopVPNTunnel() }
        activeConfigID = nil
    }

    private func load() {
        func list(_ key: String) -> [NativeVPNConfig] {
            guard let bytes = configDefaults.data(forKey: key) else { return [] }
            return (try? JSONDecoder().decode([NativeVPNConfig].self, from: bytes)) ?? []
        }
        let protected = list(Self.protectedKey)
        let ids = Set(protected.map(\.id))
        store = list(Self.key).filter { !ids.contains($0.id) } + protected
    }
    private func persist() {
        guard let ordinary = try? JSONEncoder().encode(store.filter { !$0.requiresOwnedIPsec }),
              let protected = try? JSONEncoder().encode(store.filter(\.requiresOwnedIPsec)) else { return }
        configDefaults.set(ordinary, forKey: Self.key)
        configDefaults.set(protected, forKey: Self.protectedKey)
    }
}
