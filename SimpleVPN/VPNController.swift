// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
//  VPNController.swift
//  App-side management of tunnel configurations and connections. Supports multiple
//  saved targets (one NETunnelProviderManager each). Credentials go through the shared
//  keychain (see KeychainCredentialStore); no secrets in providerConfiguration.
//

import Foundation
@preconcurrency import NetworkExtension
import Observation
import os

@MainActor
@Observable
final class VPNController {

    static let providerBundleID = "com.bragi0.SimpleVPN.PacketTunnel"
    static let log = Logger(subsystem: "com.bragi0.SimpleVPN", category: "vpn")

    /// A saved VPN target, projected for the UI.
    struct Profile: Identifiable, Sendable {
        let id: String            // stable key, also used for keychain + providerConfiguration["profile"]
        var name: String
        var server: String
        var status: NEVPNStatus
    }

    private(set) var profiles: [Profile] = []
    var selectedID: Profile.ID?
    var lastError: String?
    /// Bumped by the File ▸ Import menu command; the UI presents the importer in response.
    var importRequested = false
    /// Version of the running extension (via IPC); "unavailable" when nothing is connected.
    private(set) var extensionVersion: String = "unavailable"

    private var managers: [String: NETunnelProviderManager] = [:]
    private var observers: [NSObjectProtocol] = []

    var selected: Profile? { profiles.first { $0.id == selectedID } }
    var anyConnected: Bool { profiles.contains { $0.status == .connected } }
    var menuBarSymbol: String { anyConnected ? "lock.shield.fill" : "lock.open" }

    static func statusText(_ s: NEVPNStatus) -> String {
        switch s {
        case .invalid: return "Not configured"
        case .disconnected: return "Disconnected"
        case .connecting: return "Connecting…"
        case .connected: return "Connected"
        case .reasserting: return "Reconnecting…"
        case .disconnecting: return "Disconnecting…"
        @unknown default: return "Unknown"
        }
    }

    // MARK: Loading

    func loadAll() async {
        Self.log.log("loadAll")
        observers.forEach { NotificationCenter.default.removeObserver($0) }
        observers.removeAll()
        do {
            let mgrs = try await NETunnelProviderManager.loadAllFromPreferences()
            managers.removeAll()
            var list: [Profile] = []
            for mgr in mgrs {
                let proto = mgr.protocolConfiguration as? NETunnelProviderProtocol
                let id = (proto?.providerConfiguration?["profile"] as? String)
                    ?? mgr.localizedDescription ?? UUID().uuidString
                managers[id] = mgr
                list.append(Profile(id: id,
                                    name: mgr.localizedDescription ?? id,
                                    server: proto?.serverAddress ?? "",
                                    status: mgr.connection.status))
                observe(id: id, connection: mgr.connection)
            }
            profiles = list.sorted { $0.name.localizedCaseInsensitiveCompare($1.name) == .orderedAscending }
            if selectedID == nil || !profiles.contains(where: { $0.id == selectedID }) {
                selectedID = profiles.first?.id
            }
            Self.log.log("loadAll: \(self.profiles.count) profile(s)")
        } catch {
            lastError = "load failed: \(error.localizedDescription)"
            Self.log.error("loadAll failed: \(error.localizedDescription, privacy: .public)")
        }
    }

    // MARK: CRUD

    /// Create a new target from an .ovpn. Returns the (stable) profile id.
    @discardableResult
    func importProfile(name: String, ovpn: String, server: String) async throws -> String {
        let id = UUID().uuidString                       // stable id; name is editable separately
        let mgr = NETunnelProviderManager()
        let proto = NETunnelProviderProtocol()
        proto.providerBundleIdentifier = Self.providerBundleID
        proto.serverAddress = server
        proto.providerConfiguration = ["ovpn": ovpn, "profile": id]
        mgr.protocolConfiguration = proto
        mgr.localizedDescription = name
        mgr.isEnabled = true
        try await mgr.saveToPreferences()
        try await mgr.loadFromPreferences()
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
    func updateOVPN(id: String, ovpn: String, server: String) async throws {
        guard let mgr = managers[id], let proto = mgr.protocolConfiguration as? NETunnelProviderProtocol else { return }
        var conf = proto.providerConfiguration ?? [:]
        conf["ovpn"] = ovpn; conf["profile"] = id
        proto.providerConfiguration = conf
        proto.serverAddress = server
        mgr.protocolConfiguration = proto
        try await mgr.saveToPreferences()
        try await mgr.loadFromPreferences()
        await loadAll()
    }

    func remove(id: String) async throws {
        guard let mgr = managers[id] else { return }
        try await mgr.removeFromPreferences()
        KeychainCredentialStore.deleteCredentials(profile: id)
        KeychainCredentialStore.clearSession(profile: id)
        await loadAll()
    }

    // MARK: Connect / disconnect

    func connect(id: String, using provider: CredentialProvider,
                 request: CredentialRequest, remember: Bool) async throws {
        guard let mgr = managers[id],
              let proto = mgr.protocolConfiguration as? NETunnelProviderProtocol else {
            throw err("no such profile")
        }
        Self.log.log("connect: \(id, privacy: .public) source=\(provider.id, privacy: .public)")
        let raw = try await provider.resolve(profile: id, fields: request.fields)
        let engine = request.assemble(from: raw)
        guard !engine.username.isEmpty, !engine.password.isEmpty else { throw err("missing username or password") }

        if remember {
            try? KeychainCredentialStore.saveCredentials(profile: id, .init(username: engine.username, password: raw.password ?? ""))
        }
        try KeychainCredentialStore.setSession(profile: id, .init(username: engine.username, password: engine.password))

        mgr.isEnabled = true
        try await mgr.saveToPreferences()
        try await mgr.loadFromPreferences()
        do {
            try (mgr.connection as? NETunnelProviderSession)?.startTunnel(options: nil)
        } catch {
            KeychainCredentialStore.clearSession(profile: id)
            throw error
        }
    }

    func disconnect(id: String) {
        managers[id]?.connection.stopVPNTunnel()
    }

    func savedCredentials(id: String) -> KeychainCredentialStore.Credentials? {
        KeychainCredentialStore.loadCredentials(profile: id)
    }

    /// The raw .ovpn text for a profile (for export).
    func ovpnText(id: String) -> String? {
        (managers[id]?.protocolConfiguration as? NETunnelProviderProtocol)?
            .providerConfiguration?["ovpn"] as? String
    }

    // MARK: Status observation + version IPC

    private func observe(id: String, connection: NEVPNConnection) {
        let obs = NotificationCenter.default.addObserver(
            forName: .NEVPNStatusDidChange, object: connection, queue: .main) { [weak self] _ in
                MainActor.assumeIsolated {
                    guard let self, let mgr = self.managers[id] else { return }
                    let s = mgr.connection.status
                    if let i = self.profiles.firstIndex(where: { $0.id == id }) { self.profiles[i].status = s }
                    Self.log.log("status[\(id, privacy: .public)] → \(Self.statusText(s), privacy: .public)")
                    if s == .connected { self.queryExtensionVersion(id: id) }
                    else if s == .disconnected { self.extensionVersion = "unavailable" }
                }
            }
        observers.append(obs)
    }

    private func queryExtensionVersion(id: String) {
        guard let session = managers[id]?.connection as? NETunnelProviderSession else { return }
        do {
            try session.sendProviderMessage(Data("version".utf8)) { [weak self] reply in
                Task { @MainActor in
                    guard let self else { return }
                    if let reply, let s = String(data: reply, encoding: .utf8), !s.isEmpty {
                        self.extensionVersion = s
                        Self.log.log("running extension version: \(s, privacy: .public)")
                    } else {
                        self.extensionVersion = "unavailable"
                    }
                }
            }
        } catch {
            extensionVersion = "unavailable"
            Self.log.error("version query failed: \(error.localizedDescription, privacy: .public)")
        }
    }

    private func err(_ m: String) -> NSError {
        NSError(domain: "VPNController", code: 1, userInfo: [NSLocalizedDescriptionKey: m])
    }
}
