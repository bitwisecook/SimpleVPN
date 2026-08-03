// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
//  VPNController+Tailscale.swift
//  The Tailscale/Headscale face of VPNController. A Tailscale VPN is an ordinary
//  packet-tunnel profile — that is what buys it the sidebar, status dots,
//  telemetry, map and compositions for free — so only the settings blob and the
//  connect flow differ, and both live here: config get/set, the auth-key
//  keychain item, connect, the browser sign-in watch, live status refresh and
//  the running-session prefs push. Stored state (the observable config/status
//  mirrors, the sign-in watch tasks) lives in VPNController.swift.
//

import Foundation
@preconcurrency import NetworkExtension
import os

extension VPNController {

    // MARK: Tailscale / Headscale
    //
    // A Tailscale VPN is an ordinary packet-tunnel profile — that is what buys
    // it the sidebar, status dots, telemetry, map and compositions for free.
    // Only the settings blob and the connect flow differ, and both live here.

    /// Keychain namespace for a network's auth key. Its own item, so deleting
    /// the VPN can delete the key without touching the generic credentials.
    static func tailscaleKeyProfile(_ id: String) -> String { "tailscale.\(id)" }   // was private — internal for the +File split


    func isTailscale(_ id: String) -> Bool {
        profiles.first { $0.id == id }?.kind == .tailscale
    }

    func tailscaleConfig(for id: String) -> TailscaleConfig {
        if let c = tailscaleConfigs[id] { return c }
        let proto = managers[id]?.protocolConfiguration as? NETunnelProviderProtocol
        return TailscaleConfig.decode(from: proto?.providerConfiguration?["tailscale"] as? Data)
    }

    /// Create a new Tailscale/Headscale VPN. `serverAddress` is only what macOS
    /// shows in Network settings; the real control server rides the settings
    /// blob, because for the Tailscale preset there is nothing to show.
    @discardableResult
    func createTailscale(name: String = "Tailscale") async throws -> String {
        guard !ManagedPolicy.lockConfiguration else { throw Self.configLocked }
        let id = UUID().uuidString
        var config = TailscaleConfig()
        config.hostname = Self.defaultTailscaleHostname()
        let mgr = NETunnelProviderManager()
        let proto = NETunnelProviderProtocol()
        proto.providerBundleIdentifier = Self.providerBundleID
        // serverAddress is what macOS shows in Network settings AND what the
        // probe/endpoint machinery dials. The coordination server is the honest
        // answer: it IS what this VPN talks to. What carries the traffic is the
        // peers themselves, which is why TunnelStats.serverEndpoint stays empty.
        proto.serverAddress = Self.tailscaleServerAddress(config)
        var conf: [String: Any] = ["profile": id, "vpnType": VPNKind.tailscale.rawValue]
        if let blob = config.encodedBlob() { conf["tailscale"] = blob }
        proto.providerConfiguration = conf
        mgr.protocolConfiguration = proto
        mgr.localizedDescription = name
        mgr.isEnabled = true
        try await mgr.saveToPreferences()
        try await mgr.loadFromPreferences()
        await loadAll()
        selectedID = id
        Self.log.log("created tailscale profile id=\(id, privacy: .public)")
        return id
    }

    /// The coordination server this VPN registers with, as a bare host.
    nonisolated static func tailscaleServerAddress(_ config: TailscaleConfig) -> String {
        guard config.preset == .headscale else { return "controlplane.tailscale.com" }
        let url = config.controlURL.trimmingCharacters(in: .whitespacesAndNewlines)
        return URL(string: url)?.host ?? url
    }

    /// The Mac's own name, which is what a person expects this machine to be
    /// called on their network.
    nonisolated static func defaultTailscaleHostname() -> String {
        let raw = Host.current().localizedName ?? ProcessInfo.processInfo.hostName
        // Tailscale sanitises hostnames anyway, but a name full of spaces and
        // apostrophes reads badly in every peer's machine list.
        let cleaned = raw.replacingOccurrences(of: "'", with: "")
            .replacingOccurrences(of: ".local", with: "")
            .map { $0.isLetter || $0.isNumber || $0 == "-" ? $0 : "-" }
        return String(cleaned).trimmingCharacters(in: CharacterSet(charactersIn: "-"))
    }

    func setTailscaleConfig(_ config: TailscaleConfig, for id: String) async throws {
        guard !ManagedPolicy.lockConfiguration else { throw Self.configLocked }
        guard let mgr = managers[id],
              let proto = mgr.protocolConfiguration as? NETunnelProviderProtocol else { return }
        var conf = proto.providerConfiguration ?? [:]
        conf["profile"] = id
        conf["vpnType"] = VPNKind.tailscale.rawValue
        if let blob = config.encodedBlob() { conf["tailscale"] = blob }
        proto.providerConfiguration = conf
        proto.serverAddress = Self.tailscaleServerAddress(config)
        mgr.protocolConfiguration = proto
        try await mgr.saveToPreferences()
        try await mgr.loadFromPreferences()
        tailscaleConfigs[id] = config
        await loadAll()
    }

    /// The saved auth key, if the user chose to keep one.
    func tailscaleAuthKey(for id: String) -> String {
        KeychainCredentialStore.loadCredentials(profile: Self.tailscaleKeyProfile(id))?.password ?? ""
    }

    func setTailscaleAuthKey(_ key: String, for id: String) {
        let trimmed = key.trimmingCharacters(in: .whitespacesAndNewlines)
        if trimmed.isEmpty {
            KeychainCredentialStore.deleteCredentials(profile: Self.tailscaleKeyProfile(id))
        } else {
            try? KeychainCredentialStore.saveCredentials(
                profile: Self.tailscaleKeyProfile(id),
                .init(username: "authkey", password: trimmed))
        }
    }

    /// Connect a Tailscale/Headscale VPN. There is no username/password to
    /// collect: either a stored auth key registers this Mac silently, or the
    /// engine asks for a browser sign-in and `watchTailscaleSignIn` surfaces it.
    func connectTailscale(id: String) async throws {
        guard let mgr = managers[id],
              mgr.protocolConfiguration is NETunnelProviderProtocol else { throw err("no such profile") }
        if let ensureExtensionReady, !(await ensureExtensionReady()) {
            throw err("SimpleVPN needs its network extension approved before it can connect. Open System Settings ▸ General ▸ Login Items & Extensions ▸ Network Extensions and allow SimpleVPN.")
        }
        let config = tailscaleConfig(for: id)
        if let problem = config.controlURLProblem { throw err(problem) }
        if let problem = TailscaleConfig.routesProblem(config.advertiseRoutes) { throw err(problem) }

        // The auth key is a credential: it goes through startTunnel options in
        // memory, never through providerConfiguration.
        var options: [String: NSObject] = [:]
        let key = tailscaleAuthKey(for: id)
        if !key.isEmpty { options["tailscaleAuthKey"] = key as NSString }

        mgr.isEnabled = true
        try await mgr.saveToPreferences()
        try await mgr.loadFromPreferences()
        guard let session = mgr.connection as? NETunnelProviderSession else {
            throw err("The VPN configuration isn't ready — try removing and re-creating it.")
        }
        try session.startTunnel(options: options)
        Self.log.log("tailscale startTunnel dispatched for \(id, privacy: .public)")
        resyncStatuses()
        watchTailscaleSignIn(id: id)
    }

    /// Poll the extension for a sign-in URL and open it in the user's default
    /// browser. The extension cannot push across the root/user boundary (see
    /// TunnelIncidentStore's note), so this is a short, bounded poll that
    /// stops as soon as the node is authorized. Not the in-app SSO webview:
    /// that window belongs to OpenConnect's loopback-redirect flow — a
    /// Tailscale login is an arbitrary IdP page that may need the user's
    /// password manager or passkeys, which live in their real browser.
    private func watchTailscaleSignIn(id: String) {
        tailscaleSignInWatch[id]?.cancel()
        tailscaleSignInURL[id] = nil   // fresh attempt — last attempt's URL is dead
        tailscaleSignInWatch[id] = Task { [weak self] in
            // Five minutes is longer than any legitimate registration (the user
            // has to read a consent page) and short enough that a wedged session
            // doesn't poll forever.
            for _ in 0..<300 {
                try? await Task.sleep(for: .seconds(1))
                guard let self, !Task.isCancelled else { return }
                guard self.profiles.contains(where: { $0.id == id }) else { return }
                // Keep the status fresh for the whole registration: it is what
                // clears the sign-in state once the control plane completes
                // the login on its own, and what the editor shows meanwhile.
                let status = await self.refreshTailscaleStatus(id: id)
                if status?.backendState == .running { return }
                // The status carries the login URL once the engine has one; the
                // dedicated tsauth message covers a session that can't answer a
                // full status yet.
                var url = status.flatMap { $0.authURL.isEmpty ? nil : URL(string: $0.authURL) }
                if url == nil,
                   let data = await self.sendMessageData("tsauth", to: id, timeout: 4),
                   let text = String(data: data, encoding: .utf8), !text.isEmpty {
                    url = URL(string: text)
                }
                // Each DISTINCT URL opens once per attempt — not once per status
                // tick, and a re-keyed login (new URL) still surfaces.
                guard let url, url != self.tailscaleSignInURL[id] else { continue }
                self.tailscaleSignInURL[id] = url
                self.openTailscaleURL(url, id: id)
            }
        }
    }

    /// Re-open the current browser sign-in (the panel's button — the way back
    /// when the tab was dismissed). No-op while there is nothing to sign in to.
    func openTailscaleSignIn(id: String) {
        guard let url = tailscaleSignInURL[id] else { return }
        openTailscaleURL(url, id: id)
    }

    /// Open a Tailscale sign-in URL in the browser this VPN is configured to use.
    /// Defaults to the OS default browser (its IdP login often needs your real
    /// browser for passkeys/password managers); the user can pick a specific
    /// browser+profile or the in-app window in the Tailscale editor.
    private func openTailscaleURL(_ url: URL, id: String) {
        BrowserCatalog.open(url, using: tailscaleConfig(for: id).signInBrowser)
    }


    /// Refresh (and publish) the engine status for a connected Tailscale VPN.
    @discardableResult
    func refreshTailscaleStatus(id: String) async -> TailscaleStatus? {
        guard let data = await sendMessageData("tsstatus", to: id),
              let status = try? JSONDecoder().decode(TailscaleStatus.self, from: data) else { return nil }
        tailscaleStatuses[id] = status
        // Once the node is registered there is nothing left to sign in to. The
        // control plane completed the sign-in on its own — the browser never
        // redirects anywhere this app can see — so the stale sign-in state has
        // to be cleared from this side.
        if status.backendState == .running {
            tailscaleSignInWatch[id]?.cancel()
            tailscaleSignInURL[id] = nil
        }
        return status
    }

    /// Apply a settings change to a *running* session so the user doesn't have
    /// to reconnect to switch exit node. Returns an error message, or nil.
    func pushTailscalePrefs(_ patch: TailscalePrefsPatch, id: String) async -> String? {
        guard let data = await sendMessageData("tsprefs:\(patch.jsonString())", to: id),
              let text = String(data: data, encoding: .utf8) else { return "The VPN didn't answer." }
        return text == "ok" ? nil : String(text.dropFirst("error: ".count))
    }
}
