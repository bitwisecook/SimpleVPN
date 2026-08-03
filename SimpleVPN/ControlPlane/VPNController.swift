// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
//  VPNController.swift
//  App-side management of tunnel configurations and connections. Supports multiple
//  saved targets (one NETunnelProviderManager each). Credentials go through the shared
//  keychain (see KeychainCredentialStore); no secrets in providerConfiguration.
//

import Foundation
import AppKit
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
        var kind: VPNKind         // protocol family; absent in old configs ⇒ .openVPN
    }

    private(set) var profiles: [Profile] = []
    var selectedID: Profile.ID?

    /// The current failure, already turned into something a person can act on
    /// (see UserFacingError). Every path that reports a problem lands here.
    private(set) var failure: UserFacingError?
    /// Which VPN the failure belongs to, so "Try Again" knows what to re-run.
    private(set) var failureProfileID: String?

    /// The plain-string face of `failure`, kept because a dozen call sites (and
    /// the sidebar's "did anything get reported?" check) speak in strings.
    /// Assigning one classifies it; assigning nil clears the failure entirely.
    var lastError: String? {
        get { failure?.technicalDetail }
        set {
            guard let newValue else { failure = nil; failureProfileID = nil; return }
            failure = UserFacingError.classify(message: newValue)
            failureProfileID = nil
        }
    }

    /// Report a thrown error against a VPN — the preferred path: it keeps the
    /// retry target, and hands the profile's live secrets to the redactor so a
    /// typed password can never reach the details disclosure.
    func report(_ error: Error, profile id: String? = nil) {
        let secrets: [String] = id.map {
            let c = transientCredentials(for: $0)
            return [c.password, c.otp].filter { $0.count >= 4 }
        } ?? []
        let classified = UserFacingError.classify(error, secrets: secrets)
        assert(secrets.allSatisfy { !classified.technicalDetail.contains($0) },
               "a credential reached the error detail")
        failure = classified
        failureProfileID = id
    }

    func clearFailure() {
        failure = nil
        failureProfileID = nil
    }

    /// The failure worth putting a sheet up for. A tunnel failure that already
    /// has an incident card (with its own diagram, advice and Try Again) must
    /// not be reported twice — but only while the two are the same event, so a
    /// stale incident can never swallow a later problem.
    var presentedFailure: UserFacingError? {
        guard let failure else { return nil }
        // Only the failures the incident card actually explains (the tunnel and
        // the network) can be withheld — a 1Password or credential problem is
        // invisible to the extension, so a coincident incident must never
        // silence it.
        guard failure.category == .generic || failure.category == .network else { return failure }
        if let id = failureProfileID, let incident = incidents[id] {
            let gap = abs(incident.timestamp - failure.occurred.timeIntervalSince1970)
            if gap < 30 { return nil }
        }
        return failure
    }

    /// Re-run the connect a failure came from (the sheet's Try Again). Clearing
    /// first is also what dismisses the sheet, so the caller passes the id it
    /// captured rather than reading it back out of the failure.
    func retryConnect(id: String) async {
        clearFailure()
        do {
            try await connectUsingConfiguredSource(
                id: id, typedOTP: transientCredentials(for: id).otp)
        } catch is CancellationError {
            // The user backed out — an outcome, not a failure.
        } catch {
            Self.log.error("retry failed for \(id, privacy: .public): \(error.localizedDescription, privacy: .public)")
            report(error, profile: id)
        }
    }
    /// Bumped by the File ▸ Import menu command; the UI presents the importer in response.
    var importRequested = false
    /// A duplicate/invalid import result awaiting user acknowledgement (see ImportUI).
    var importOutcome: ImportOutcome?
    /// Version of the running extension (via IPC); "unavailable" when nothing is connected.
    private(set) var extensionVersion: String = "unavailable"

    private var managers: [String: NETunnelProviderManager] = [:]
    private var observers: [NSObjectProtocol] = []

    /// The Route mediator (Docs/StateMediators.md, P1): the single authority over the
    /// host's default route. VPNController delegates the gateway logic to it and serves
    /// as its live NE side (`RouteMediatorHost`). Kept as a stored child so the UI's
    /// `@Observable` tracking reaches through `vpn.routes.*`.
    let routes = RouteMediator()

    /// The DNS mediator (Docs/StateMediators.md, P2): the single authority over the
    /// host's resolvers. Arbitrates coherent split-DNS from each tunnel's intent,
    /// watches `State:/Network/Global/DNS` for external drift, and publishes the
    /// effective resolver picture through `vpn.dns.*`.
    let dns = DNSMediator()

    /// The Proxy mediator (Docs/StateMediators.md, P3): the single authority over the
    /// system proxy. Arbitrates the one proxy decision, watches
    /// `State:/Network/Global/Proxies` for external drift, and publishes through
    /// `vpn.proxies.*`.
    let proxies = ProxyMediator()

    /// Overrides in force for the running session (recorded at connect), used to
    /// tell the user that freshly saved settings only apply on reconnect. Tracked
    /// app-side because a live connection's protocolConfiguration snapshot can be
    /// stale.
    private var appliedOverrides: [String: OpenVPNOverrides] = [:]
    /// The raw .ovpn a running session was started with, so edits to it (server,
    /// routes, ciphers) while connected also raise the "reconnect to apply" signal.
    private var appliedOVPN: [String: String] = [:]

    /// Latest classified failure per profile (published by the extension via the
    /// App Group when a tunnel fails; cleared on the next healthy connect).
    private(set) var incidents: [String: TunnelIncident] = [:]

    /// The failure diagnostics found this network holding traffic behind a
    /// sign-in page. Network-wide (not per-profile); drives the captive-portal
    /// dot state until a connect succeeds or the incident is dismissed.
    var captivePortalSuspected = false
    /// Where the sign-in page actually lives (from the probe's redirect), so
    /// "Open Sign-In Page" lands on the portal rather than the probe URL.
    var captivePortalURL: URL?

    /// Bumped when a surface (sidebar play, menu bar) wants the credential form
    /// to draw the eye to what's missing: the detail pane focuses the first
    /// empty required field and gives it a little shake.
    private(set) var credentialNudge: [String: Int] = [:]
    func nudgeCredentials(id: String) {
        selectedID = id                                   // bring the form on screen
        credentialNudge[id, default: 0] += 1
    }
    /// One-shot claim: true exactly once per nudge. Lets the detail view react
    /// both to bumps while it's showing AND to a nudge that arrived just before
    /// it appeared (sidebar click on a different VPN switches the selection).
    func consumeCredentialNudge(id: String) -> Bool {
        guard (credentialNudge[id] ?? 0) > 0 else { return false }
        credentialNudge[id] = 0
        return true
    }

    /// Re-probe the network for a captive portal (user-initiated: connect
    /// attempts and the banner's "Check Again"). Updates the suspicion flag
    /// both ways so signing in clears the banner on recheck.
    func recheckCaptivePortal() async {
        let portal = await ConnectionDiagnostics.captivePortalProbe()
        captivePortalSuspected = portal.detected
        captivePortalURL = portal.url
        if portal.detected {
            Self.log.log("captive portal detected, sign-in at \(portal.url?.absoluteString ?? "unknown", privacy: .public)")
        }
    }

    /// Latest active-probe report per profile (path MTU, TCP-443 reachability,
    /// captive portal). Populated on connection failure and when a live stall is
    /// detected; read by the Connection Doctor to size mssfix and spot UDP blocks.
    ///
    /// Every field in it is a property of ONE network — the path MTU, whether
    /// TCP 443 gets out, what the name resolved to — so the reports are dropped
    /// wholesale when the Mac moves, rather than letting the Doctor prescribe an
    /// mssfix measured in a café for the office LAN.
    private(set) var probeResults: [String: DiagnosticsReport] = [:]

    /// Held for the object's lifetime: drops network-scoped state when the Mac
    /// moves. Rides the app's one path monitor — no timer of its own.
    @ObservationIgnored private var networkWatch: Task<Void, Never>?

    init() {
        networkWatch = NetworkChange.observe { [weak self] _ in
            self?.probeResults.removeAll()
        }
        routes.host = self   // the mediator drives the gateway through us (the live NE side)
        dns.host = self      // DNS + Proxy mediators observe/reconcile through us too
        proxies.host = self
        installCustomRoutingHooks()
    }

    /// Attach the per-profile Custom Routing filters at each mediator's single
    /// intent-capture seam (`intentHook`). This is the TIER-2 (static, UI-driven) form of
    /// the tier-3 `ROUTE_ADVERTISED`/`DNS_PUSHED`/`PROXY_PUSHED` rewrite hooks: at hook
    /// entry `intent` is the RAW pushed intent, so we (1) snapshot it durably per profile
    /// — for the offline "what this VPN pushed last time" editing surface — and then
    /// (2) rewrite it through the profile's filter before it reaches the arbiter. An
    /// empty/absent filter is the identity transform (no behavior change).
    private func installCustomRoutingHooks() {
        routes.intentHook = { [weak self] intent in
            guard let self else { return }
            self.recordPushedRoutes(intent)
            intent = self.customRouting(for: intent.engine).routes.apply(to: intent)
        }
        dns.intentHook = { [weak self] intent in
            guard let self else { return }
            self.recordPushedDNS(intent)
            intent = self.customRouting(for: intent.engine).dns.apply(to: intent)
        }
        proxies.intentHook = { [weak self] intent in
            guard let self else { return }
            self.recordPushedProxy(intent)
            let cust = self.customRouting(for: intent.engine).proxy
            if let result = cust.apply(to: intent, engine: intent.engine) {
                intent = result
            } else {
                // Ignore ⇒ direct: this engine contributes no proxy to arbitration.
                intent.mode = .none
                intent.manual = nil
                intent.bypass = []
            }
        }
    }

    deinit { networkWatch?.cancel() }

    /// Store a fresh probe report for a profile (from the incident view's probe).
    func setProbeResult(_ report: DiagnosticsReport, for id: String) {
        probeResults[id] = report
    }

    /// One-shot path-MTU measurement to `host`, merged into the profile's report.
    /// Used when a connected tunnel stalls, to give the Doctor an exact mssfix.
    func measurePathMTU(host: String, for id: String) async {
        guard !host.isEmpty else { return }
        let mtu = await ConnectionDiagnostics.pathMTU(to: host)
        guard let mtu else { return }
        var report = probeResults[id] ?? DiagnosticsReport(host: host, port: 0)
        report.pathMTU = mtu
        probeResults[id] = report
    }

    func dismissIncident(id: String) {
        TunnelIncidentStore.clear(profile: id)
        incidents[id] = nil
        captivePortalSuspected = false
    }

    var selected: Profile? { profiles.first { $0.id == selectedID } }
    var anyConnected: Bool { profiles.contains { $0.status == .connected } }

    /// Up, or on its way up. The tunnel owns the default route for the whole of
    /// the connecting/reasserting window, so anything that would be wrong while
    /// connected (a "home" snapshot, a probe to the server we're dialling) is
    /// equally wrong here — `connected` alone is a signal that arrives too late.
    func isEngaged(id: String) -> Bool {
        guard let s = profiles.first(where: { $0.id == id })?.status else { return false }
        return Self.isEngaged(s)
    }

    nonisolated static func isEngaged(_ status: NEVPNStatus) -> Bool {
        status == .connected || status == .connecting || status == .reasserting
    }

    var anyEngaged: Bool { profiles.contains { isEngaged(id: $0.id) } }

    /// The status to DISPLAY — not the NE truth that drives routing/mediators.
    /// Tailscale reports `.connected` the instant its extension starts, but the node
    /// isn't really on the network until the backend reaches `.running`; it may still
    /// be mid browser sign-in. So for a Tailscale profile we present `.connecting`
    /// until Running, instead of a "Connected" badge over a machine that can't pass
    /// traffic yet. Everything else passes through unchanged.
    func displayStatus(for id: String) -> NEVPNStatus {
        let raw = profiles.first { $0.id == id }?.status ?? .invalid
        guard isTailscale(id), raw == .connected else { return raw }
        return tailscaleStatuses[id]?.backendState == .running ? .connected : .connecting
    }

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
                authConfigs[id] = VPNAuthConfig.decode(from: proto?.providerConfiguration?["auth"] as? Data)
                overridesCache[id] = OpenVPNOverrides.decode(from: proto?.providerConfiguration?["overrides"] as? Data)
                customRoutingCache[id] = CustomRoutingProfile.decode(from: proto?.providerConfiguration?["customrouting"] as? Data)
                uiPrefsCache[id] = VPNUIPrefs.decode(from: proto?.providerConfiguration?["uiprefs"] as? Data)
                endpointsCache[id] = VPNEndpointList.decode(from: proto?.providerConfiguration?["endpoints"] as? Data)
                credentialSources[id] = CredentialSource.decode(from: proto?.providerConfiguration?["credsource"] as? Data)
                let kind = (proto?.providerConfiguration?["vpnType"] as? String)
                    .flatMap(VPNKind.init(rawValue:)) ?? .openVPN
                if kind == .tailscale {
                    tailscaleConfigs[id] = TailscaleConfig.decode(from: proto?.providerConfiguration?["tailscale"] as? Data)
                }
                if kind == .proxyTunnel {
                    proxyTunnelConfigs[id] = ProxyTunnelConfig.decode(from: proto?.providerConfiguration?["proxytunnel"] as? Data)
                }
                list.append(Profile(id: id,
                                    name: mgr.localizedDescription ?? id,
                                    server: proto?.serverAddress ?? "",
                                    status: mgr.connection.status,
                                    kind: kind))
            }
            observeStatusChanges()
            routes.loadPreference()
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
        proto.providerConfiguration = ["ovpn": ovpn, "profile": id,
                                       "vpnType": VPNKind.openVPN.rawValue]
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
        guard !ManagedPolicy.lockConfiguration else { throw Self.configLocked }
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
        // A Tailscale node key is this Mac's identity on that network and lives
        // in the extension's root-owned tree, which the app cannot touch — ask
        // the extension to shred it while there is still a session to ask.
        if profiles.first(where: { $0.id == id })?.kind == .tailscale {
            _ = await sendMessageData("tsforget", to: id, timeout: 4)
        }
        try await mgr.removeFromPreferences()
        KeychainCredentialStore.deleteCredentials(profile: id)
        KeychainCredentialStore.deleteProfileSecrets(profile: id)
        KeychainCredentialStore.clearSession(profile: id)
        KeychainCredentialStore.deleteCredentials(profile: Self.tailscaleKeyProfile(id))
        BiometricCredentialStore.delete(profile: id)
        tailscaleConfigs[id] = nil
        tailscaleStatuses[id] = nil
        tailscaleSignInWatch[id]?.cancel()
        tailscaleSignInWatch[id] = nil
        tailscaleSignInURL[id] = nil
        proxyTunnelConfigs[id] = nil
        proxyTunnelStatuses[id] = nil
        appliedOverrides[id] = nil
        appliedOVPN[id] = nil
        endpointsCache[id] = nil
        await loadAll()
    }

    // MARK: Tailscale / Headscale
    //
    // A Tailscale VPN is an ordinary packet-tunnel profile — that is what buys
    // it the sidebar, status dots, telemetry, map and compositions for free.
    // Only the settings blob and the connect flow differ, and both live here.

    /// Keychain namespace for a network's auth key. Its own item, so deleting
    /// the VPN can delete the key without touching the generic credentials.
    private static func tailscaleKeyProfile(_ id: String) -> String { "tailscale.\(id)" }

    /// Observable mirror of the persisted Tailscale settings.
    private(set) var tailscaleConfigs: [String: TailscaleConfig] = [:]
    /// Latest engine status per profile, refreshed while connected.
    private(set) var tailscaleStatuses: [String: TailscaleStatus] = [:]

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

    @ObservationIgnored private var tailscaleSignInWatch: [String: Task<Void, Never>] = [:]
    /// The sign-in page we sent this VPN's user to — observable, so the connect
    /// panel can offer to re-open it; cleared once the node registers.
    private(set) var tailscaleSignInURL: [String: URL] = [:]

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

    // MARK: Proxy Tunnel (tun2socks)
    //
    // A Proxy Tunnel is an ordinary packet-tunnel profile — that is what buys it
    // the sidebar, status dots, telemetry and map for free. Only the settings
    // blob and the connect flow differ, and both live here. One kind, three
    // schemes (socks5/http/https) chosen by the upstream URL — the editor picks;
    // it is never a second VPNKind.

    /// Observable mirror of the persisted proxy-tunnel settings.
    private(set) var proxyTunnelConfigs: [String: ProxyTunnelConfig] = [:]
    /// Latest engine status per profile, refreshed while connected.
    private(set) var proxyTunnelStatuses: [String: ProxyTunnelStatus] = [:]

    func isProxyTunnel(_ id: String) -> Bool {
        profiles.first { $0.id == id }?.kind == .proxyTunnel
    }

    func proxyTunnelConfig(for id: String) -> ProxyTunnelConfig {
        if let c = proxyTunnelConfigs[id] { return c }
        let proto = managers[id]?.protocolConfiguration as? NETunnelProviderProtocol
        return ProxyTunnelConfig.decode(from: proto?.providerConfiguration?["proxytunnel"] as? Data)
    }

    /// Create a new Proxy Tunnel. Starts as a SOCKS5 preset with a full-tunnel
    /// default route — the common case — which the editor then refines.
    @discardableResult
    func createProxyTunnel(name: String = "Proxy Tunnel") async throws -> String {
        guard !ManagedPolicy.lockConfiguration else { throw Self.configLocked }
        let id = UUID().uuidString
        let config = ProxyTunnelConfig()
        let mgr = NETunnelProviderManager()
        let proto = NETunnelProviderProtocol()
        proto.providerBundleIdentifier = Self.providerBundleID
        // serverAddress is what macOS shows in Network settings and what the
        // probe/endpoint machinery dials: the proxy host (empty until set).
        proto.serverAddress = config.proxyHost.isEmpty ? "proxy" : config.proxyHost
        var conf: [String: Any] = ["profile": id, "vpnType": VPNKind.proxyTunnel.rawValue]
        if let blob = config.encodedBlob() { conf["proxytunnel"] = blob }
        proto.providerConfiguration = conf
        mgr.protocolConfiguration = proto
        mgr.localizedDescription = name
        mgr.isEnabled = true
        try await mgr.saveToPreferences()
        try await mgr.loadFromPreferences()
        await loadAll()
        selectedID = id
        Self.log.log("created proxy tunnel id=\(id, privacy: .public)")
        return id
    }

    func setProxyTunnelConfig(_ config: ProxyTunnelConfig, for id: String) async throws {
        guard !ManagedPolicy.lockConfiguration else { throw Self.configLocked }
        guard let mgr = managers[id],
              let proto = mgr.protocolConfiguration as? NETunnelProviderProtocol else { return }
        var conf = proto.providerConfiguration ?? [:]
        conf["profile"] = id
        conf["vpnType"] = VPNKind.proxyTunnel.rawValue
        if let blob = config.encodedBlob() { conf["proxytunnel"] = blob }
        proto.providerConfiguration = conf
        proto.serverAddress = config.proxyHost.isEmpty ? "proxy" : config.proxyHost
        mgr.protocolConfiguration = proto
        try await mgr.saveToPreferences()
        try await mgr.loadFromPreferences()
        proxyTunnelConfigs[id] = config
        await loadAll()
    }

    /// The saved proxy credentials (username + password), if any. Their own
    /// keychain item under the profile id, like every other base credential.
    func proxyTunnelCredentials(for id: String) -> (username: String, password: String) {
        let c = KeychainCredentialStore.loadCredentials(profile: id)
        return (c?.username ?? "", c?.password ?? "")
    }

    func setProxyTunnelCredentials(username: String, password: String, for id: String) {
        let u = username.trimmingCharacters(in: .whitespacesAndNewlines)
        if u.isEmpty && password.isEmpty {
            KeychainCredentialStore.deleteCredentials(profile: id)
        } else {
            try? KeychainCredentialStore.saveCredentials(profile: id, .init(username: u, password: password))
        }
    }

    /// Connect a Proxy Tunnel. Credentials (when the proxy needs them) ride
    /// startTunnel options in memory; a no-auth proxy connects with nothing.
    func connectProxyTunnel(id: String) async throws {
        guard let mgr = managers[id],
              mgr.protocolConfiguration is NETunnelProviderProtocol else { throw err("no such profile") }
        if let ensureExtensionReady, !(await ensureExtensionReady()) {
            throw err("SimpleVPN needs its network extension approved before it can connect. Open System Settings ▸ General ▸ Login Items & Extensions ▸ Network Extensions and allow SimpleVPN.")
        }
        let config = proxyTunnelConfig(for: id)
        if let problem = config.connectProblem { throw err(problem) }

        var options: [String: NSObject] = [:]
        if config.requiresAuth {
            let creds = proxyTunnelCredentials(for: id)
            if !creds.username.isEmpty { options["username"] = creds.username as NSString }
            if !creds.password.isEmpty { options["password"] = creds.password as NSString }
        }
        if ManagedPolicy.forceKeepInsideVPN { options["policyKeepInside"] = true as NSNumber }
        // Establish-time default-gateway ownership, same as OpenVPN (RC3).
        options["gatewayOwned"] = predictedGatewayOwned(id) as NSNumber

        mgr.isEnabled = true
        try await mgr.saveToPreferences()
        try await mgr.loadFromPreferences()
        guard let session = mgr.connection as? NETunnelProviderSession else {
            throw err("The VPN configuration isn't ready — try removing and re-creating it.")
        }
        try session.startTunnel(options: options)
        Self.log.log("proxy tunnel startTunnel dispatched for \(id, privacy: .public)")
        resyncStatuses()
    }

    /// Refresh (and publish) the engine status for a connected Proxy Tunnel.
    @discardableResult
    func refreshProxyTunnelStatus(id: String) async -> ProxyTunnelStatus? {
        guard let data = await sendMessageData("pxstatus", to: id),
              let status = try? JSONDecoder().decode(ProxyTunnelStatus.self, from: data) else { return nil }
        proxyTunnelStatuses[id] = status
        return status
    }

    // MARK: Engine overrides (per-VPN OpenVPN settings)

    /// Observable mirror of the persisted override blobs (see authConfigs).
    private(set) var overridesCache: [String: OpenVPNOverrides] = [:]

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

    // MARK: Custom Routing (per-VPN pushed-intent filters — Mediators/CustomRouting.swift)

    /// Observable mirror of the persisted "customrouting" blobs (see overridesCache). The
    /// filter is the tier-2 static form of the tier-3 intent-rewrite hooks; it is applied
    /// at the mediator capture seam by `installCustomRoutingHooks`.
    private(set) var customRoutingCache: [String: CustomRoutingProfile] = [:]

    /// The saved Custom Routing filter for a profile; identity (no-op) when none was set.
    func customRouting(for id: String) -> CustomRoutingProfile {
        if let cached = customRoutingCache[id] { return cached }
        let proto = managers[id]?.protocolConfiguration as? NETunnelProviderProtocol
        return CustomRoutingProfile.decode(from: proto?.providerConfiguration?["customrouting"] as? Data)
    }

    /// Persist a profile's Custom Routing filter (dropped entirely when empty) and
    /// LIVE-APPLY it immediately: re-arbitrate + push through the route/DNS/proxy appliers
    /// with no reconnect. Safe to call when the profile is offline — it then only persists
    /// and takes effect on the next connect.
    func setCustomRouting(_ profile: CustomRoutingProfile, for id: String) async {
        guard let mgr = managers[id],
              let proto = mgr.protocolConfiguration as? NETunnelProviderProtocol else {
            // No manager yet (fresh/importing) — still hold it in the observable cache so
            // the UI round-trips; it persists on the next real save once a manager exists.
            customRoutingCache[id] = profile
            return
        }
        var conf = proto.providerConfiguration ?? [:]
        if let blob = profile.encodedBlob() { conf["customrouting"] = blob }
        else { conf.removeValue(forKey: "customrouting") }
        proto.providerConfiguration = conf
        mgr.protocolConfiguration = proto
        try? await mgr.saveToPreferences()
        try? await mgr.loadFromPreferences()
        customRoutingCache[id] = profile
        await applyCustomRouting(forProfile: id)
    }

    /// Live-reconcile entry point the UI calls on commit (Save / navigate-away). Re-projects
    /// the FILTERED intent for the mediators (captured ∘ filter, via the intent hooks) and
    /// drives all three to re-arbitrate + live-apply through the existing appliers — no
    /// reconnect. When the profile isn't connected there is nothing live to re-project, so
    /// it is a no-op beyond the already-persisted config (which applies on next connect).
    /// Idempotent: the arbiters are pure and the realizers skip an unchanged plan, so it is
    /// safe to call repeatedly.
    func applyCustomRouting(forProfile id: String) async {
        // Arbitration is inherently cross-profile (≤1 default owner, one system proxy, one
        // coherent split-DNS), so a single profile's filter change re-arbitrates the whole
        // connected set. `reassertNow` re-runs intent capture (through the hooks) then
        // reconciles + realizes.
        routes.reassertNow()
        dns.reassertNow()
        proxies.reassertNow()
    }

    // MARK: Last-seen pushed intent (durable per-profile snapshot)

    /// App Group backed store for the raw pre-filter pushed intent (survives disconnect +
    /// relaunch). Kept off the observation graph — the observable mirror is the cache.
    @ObservationIgnored private let pushedIntentStore = PushedIntentStore()
    /// Observable mirror of the durable pushed-intent snapshots.
    private(set) var pushedIntentCache: [String: PushedIntentSnapshot] = [:]

    /// The last-seen pushed intent for a profile — live when connected, last-known when
    /// offline (the offline editing surface the Custom Routing tab reads). nil until first
    /// capture.
    func lastPushedIntent(for id: String) -> PushedIntentSnapshot? {
        if let cached = pushedIntentCache[id] { return cached }
        return pushedIntentStore.load(id)
    }

    /// Snapshot the pushed ROUTE intent (pre-filter). Persist on change; never clobber a
    /// good snapshot with a transient empty (e.g. a just-connected engine that hasn't
    /// reported its routes yet).
    private func recordPushedRoutes(_ intent: RouteIntent) {
        var snap = lastPushedIntent(for: intent.engine) ?? PushedIntentSnapshot()
        let new = PushedIntentSnapshot.Routes(advertisedPrefixes: intent.advertisedPrefixes,
                                              wantsDefault: intent.wantsDefault)
        guard new != snap.routes else { return }
        if new.isEmpty && !snap.routes.isEmpty { return }
        snap.routes = new
        persistPushedIntent(snap, for: intent.engine)
    }

    private func recordPushedDNS(_ intent: DNSIntent) {
        var snap = lastPushedIntent(for: intent.engine) ?? PushedIntentSnapshot()
        let new = PushedIntentSnapshot.DNS(resolvers: intent.resolvers,
                                           searchDomains: intent.searchDomains,
                                           matchDomains: intent.matchDomains)
        guard new != snap.dns else { return }
        if new.isEmpty && !snap.dns.isEmpty { return }
        snap.dns = new
        persistPushedIntent(snap, for: intent.engine)
    }

    private func recordPushedProxy(_ intent: ProxyIntent) {
        var snap = lastPushedIntent(for: intent.engine) ?? PushedIntentSnapshot()
        let new = PushedIntentSnapshot.Proxy(intent)   // nil ⇒ no proxy pushed
        guard new != snap.proxy else { return }
        if (new?.isEmpty ?? true) && !(snap.proxy?.isEmpty ?? true) { return }
        snap.proxy = new
        persistPushedIntent(snap, for: intent.engine)
    }

    private func persistPushedIntent(_ snapshot: PushedIntentSnapshot, for id: String) {
        var snapshot = snapshot
        snapshot.capturedAt = Date()
        pushedIntentCache[id] = snapshot
        pushedIntentStore.save(snapshot, for: id)
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

    /// Observable mirror of the persisted "endpoints" blobs (see overridesCache).
    private(set) var endpointsCache: [String: VPNEndpointList] = [:]

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

    /// Observable mirror of the persisted "uiprefs" blobs (see overridesCache).
    private(set) var uiPrefsCache: [String: VPNUIPrefs] = [:]

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

    // MARK: Transient credentials (menu-bar inline entry)

    /// Credentials mid-typing in the menu-bar dropdown. Memory only — they
    /// survive the menu closing (the user popping over to their authenticator)
    /// but are never written to the keychain or anywhere else; a profile whose
    /// config forbids saving still gets at most this process-lifetime cache.
    struct TransientCredentials {
        var username = ""
        var password = ""
        var otp = ""
    }
    var transientCreds: [String: TransientCredentials] = [:]

    /// The dropdown's starting point for a profile: anything mid-typing, else
    /// the saved credentials, else empty.
    func transientCredentials(for id: String) -> TransientCredentials {
        if let existing = transientCreds[id] { return existing }
        var fresh = TransientCredentials()
        if let saved = savedCredentials(id: id) {
            fresh.username = saved.username
            fresh.password = saved.password
        }
        return fresh
    }

    private var persistTask: Task<Void, Never>?

    /// Route ALL credential edits through here: updates the shared state and —
    /// when Remember is on and the profile allows saving — persists to the
    /// keychain shortly after typing stops. "Remember" means remembered, not
    /// "remembered only if you happened to connect before quitting".
    func setTransientCredentials(_ creds: TransientCredentials, for id: String) {
        transientCreds[id] = creds
        persistTask?.cancel()
        persistTask = Task { [weak self] in
            try? await Task.sleep(for: .milliseconds(600))
            guard !Task.isCancelled else { return }
            self?.persistIfRemembered(id: id)
        }
    }

    private func persistIfRemembered(id: String) {
        let c = transientCredentials(for: id)
        guard authConfig(for: id).rememberCredentials,
              allowsPasswordSave(id: id),
              !c.username.isEmpty, !c.password.isEmpty else { return }
        // Typing an OTP also lands here — don't rewrite an unchanged
        // username/password to the keychain on every pause in typing.
        if let saved = savedCredentials(id: id),
           saved.username == c.username, saved.password == c.password { return }
        do {
            try KeychainCredentialStore.saveCredentials(profile: id, .init(username: c.username, password: c.password))
        } catch {
            Self.log.error("saveCredentials failed for \(id, privacy: .public): \(error.localizedDescription, privacy: .public)")
        }
    }

    // MARK: Credential source (manual / 1Password / Apple Passwords)

    private(set) var credentialSources: [String: CredentialSource] = [:]

    func credentialSource(for id: String) -> CredentialSource {
        if let cached = credentialSources[id] { return cached }
        let proto = managers[id]?.protocolConfiguration as? NETunnelProviderProtocol
        return CredentialSource.decode(from: proto?.providerConfiguration?["credsource"] as? Data)
    }

    func setCredentialSource(_ source: CredentialSource, for id: String) async throws {
        guard !ManagedPolicy.lockConfiguration else { throw Self.configLocked }
        guard let mgr = managers[id],
              let proto = mgr.protocolConfiguration as? NETunnelProviderProtocol else { return }
        var conf = proto.providerConfiguration ?? [:]
        if let blob = source.encodedBlob() { conf["credsource"] = blob }
        else { conf.removeValue(forKey: "credsource") }
        proto.providerConfiguration = conf
        mgr.protocolConfiguration = proto
        try await mgr.saveToPreferences()
        try await mgr.loadFromPreferences()
        credentialSources[id] = source
        Self.log.log("credential source for \(id, privacy: .public): \(source.kind.rawValue, privacy: .public)")
    }

    /// The provider a profile's configured source implies. Manual returns nil —
    /// the caller uses the typed/remembered credentials instead.
    func managerProvider(for id: String) -> CredentialProvider? {
        let source = credentialSource(for: id)
        switch source.kind {
        case .manual:
            // Touch ID-protected saved credentials act as a manager: one
            // fingerprint releases username + password (+ the one-time code,
            // when a TOTP secret is stored).
            if authConfig(for: id).protectWithBiometrics, BiometricCredentialStore.exists(profile: id) {
                let name = profiles.first { $0.id == id }?.name ?? "the VPN"
                return BiometricCredentialProvider(reason: "unlock the sign-in for \(name)")
            }
            return nil
        case .onePassword:
            // A blank account falls back to the one that has worked before:
            // 1Password refuses to answer without one, and the name belongs to
            // the person, not to this VPN. What the VPN names still wins.
            return OnePasswordProvider(
                itemReference: source.reference, vault: source.vault,
                account: OnePasswordAccountMemory.effectiveAccount(profile: source.account),
                fieldMap: source.fieldMap)
        case .applePasswords:
            return ApplePasswordsProvider(server: source.reference, account: source.account)
        }
    }

    /// Whether the Touch ID store can satisfy this profile's whole sign-in
    /// unattended (creds present; the code too when one is required).
    func biometricCanServe(id: String) -> Bool {
        guard authConfig(for: id).protectWithBiometrics else { return false }
        let info = BiometricCredentialStore.info(profile: id)
        guard info.exists else { return false }
        return !requiresOTP(for: id) || info.hasTOTP
    }

    /// Set or replace the authenticator (TOTP) secret inside an existing
    /// protected item. Reading the current username/password back takes one
    /// Touch ID prompt — changing what the fingerprint guards should cost one.
    func updateProtectedTOTP(id: String, secret: String?) async throws {
        guard BiometricCredentialStore.exists(profile: id) else { return }
        let name = profiles.first { $0.id == id }?.name ?? "the VPN"
        let provider = BiometricCredentialProvider(reason: "update the sign-in for \(name)")
        let raw = try await provider.resolve(profile: id, fields: [.username, .password])
        try BiometricCredentialStore.save(profile: id, .init(
            username: raw.username ?? "", password: raw.password ?? "",
            totpSecret: secret?.isEmpty == true ? nil : secret))
        Self.log.log("protected TOTP secret \(secret == nil ? "cleared" : "updated", privacy: .public) for \(id, privacy: .public)")
    }

    /// Flip Touch ID protection for a profile's saved credentials, migrating the
    /// secret between the plain and protected stores. Turning protection OFF
    /// needs the secret back, which itself takes one Touch ID prompt (unless the
    /// live session state already has it).
    func setBiometricProtection(_ on: Bool, for id: String, totpSecret: String? = nil) async throws {
        var auth = authConfig(for: id)
        let name = profiles.first { $0.id == id }?.name ?? "the VPN"
        if on {
            // Source the secret from what's live (typed) or saved.
            let c = transientCredentials(for: id)
            let saved = savedCredentials(id: id)
            let username = !c.username.isEmpty ? c.username : (saved?.username ?? "")
            let password = !c.password.isEmpty ? c.password : (saved?.password ?? "")
            guard !username.isEmpty, !password.isEmpty else {
                throw err("Enter (or save) the username and password first, then turn on Touch ID protection.")
            }
            try BiometricCredentialStore.save(profile: id, .init(
                username: username, password: password, totpSecret: totpSecret))
            // The plain-keychain copy would defeat the point of the gate.
            KeychainCredentialStore.deleteCredentials(profile: id)
            auth.protectWithBiometrics = true
            try await setAuthConfig(auth, for: id)
            Self.log.log("biometric protection ON for \(id, privacy: .public)")
        } else {
            guard BiometricCredentialStore.exists(profile: id) else {
                auth.protectWithBiometrics = false
                try await setAuthConfig(auth, for: id)
                return
            }
            let provider = BiometricCredentialProvider(reason: "move the sign-in for \(name) out of Touch ID protection")
            let raw = try await provider.resolve(profile: id, fields: [.username, .password])
            if auth.rememberCredentials, allowsPasswordSave(id: id) {
                try? KeychainCredentialStore.saveCredentials(profile: id, .init(
                    username: raw.username ?? "", password: raw.password ?? ""))
            }
            var live = transientCredentials(for: id)
            live.username = raw.username ?? live.username
            live.password = raw.password ?? live.password
            transientCreds[id] = live
            BiometricCredentialStore.delete(profile: id)
            auth.protectWithBiometrics = false
            try await setAuthConfig(auth, for: id)
            Self.log.log("biometric protection OFF for \(id, privacy: .public)")
        }
    }

    // MARK: Authentication shape (per-VPN OTP requirement + password template)

    /// Observable mirror of the persisted auth blobs — reads MUST go through this
    /// (not the manager's providerConfiguration) so SwiftUI re-renders on change.
    private(set) var authConfigs: [String: VPNAuthConfig] = [:]

    func authConfig(for id: String) -> VPNAuthConfig {
        if let cached = authConfigs[id] { return cached }
        let proto = managers[id]?.protocolConfiguration as? NETunnelProviderProtocol
        return VPNAuthConfig.decode(from: proto?.providerConfiguration?["auth"] as? Data)
    }

    func setAuthConfig(_ auth: VPNAuthConfig, for id: String) async throws {
        guard !ManagedPolicy.lockConfiguration else { throw Self.configLocked }
        guard let mgr = managers[id],
              let proto = mgr.protocolConfiguration as? NETunnelProviderProtocol else { return }
        var conf = proto.providerConfiguration ?? [:]
        if let blob = auth.encodedBlob() {
            conf["auth"] = blob
        } else {
            conf.removeValue(forKey: "auth")
        }
        proto.providerConfiguration = conf
        mgr.protocolConfiguration = proto
        try await mgr.saveToPreferences()
        try await mgr.loadFromPreferences()
        authConfigs[id] = auth
        Self.log.log("auth config saved for \(id, privacy: .public): requiresOTP=\(auth.requiresOTP)")
    }

    /// True while a session started with different overrides than are now saved —
    /// the "changes take effect on reconnect" signal.
    func hasPendingSettings(id: String) -> Bool {
        guard isEngaged(id: id) else { return false }
        if let applied = appliedOverrides[id], applied != overrides(for: id) { return true }
        if let appliedText = appliedOVPN[id], appliedText != (ovpnText(id: id) ?? "") { return true }
        return false
    }

    // MARK: Connect / disconnect

    func connect(id: String, using provider: CredentialProvider,
                 request: CredentialRequest, remember: Bool) async throws {
        guard let mgr = managers[id],
              mgr.protocolConfiguration is NETunnelProviderProtocol else {
            throw err("no such profile")
        }
        Self.log.log("connect: \(id, privacy: .public) source=\(provider.id, privacy: .public)")

        // First connect of an OpenVPN profile is the moment to ask macOS to approve the
        // system extension — not app launch. A brand-new user should meet the app, not a
        // security dialog for a capability they haven't asked for yet. Every connect path
        // funnels through here, so this covers the sidebar play button and the menu bar
        // as well as the detail pane.
        if let ensureExtensionReady, !(await ensureExtensionReady()) {
            throw err("SimpleVPN needs its network extension approved before it can connect. Open System Settings ▸ General ▸ Login Items & Extensions ▸ Network Extensions and allow SimpleVPN.")
        }
        let raw = try await provider.resolve(profile: id, fields: request.fields)
        let staticChallenge = hasStaticChallenge(id)
        let engine: EngineCredentials
        if staticChallenge {
            // static-challenge profiles: the OTP travels as the engine's
            // challenge response (see the options below), never concatenated
            // into the password — the template concat stays for profiles
            // without one (GR Lab depends on {password}{otp}).
            engine = EngineCredentials(username: raw.username ?? "", password: raw.password ?? "")
        } else {
            engine = request.assemble(from: raw)
        }
        // Autologin profiles authenticate with their certificate — empty
        // credentials are the correct payload, not a user mistake.
        let autologin = isAutologin(id)
        guard autologin || (!engine.username.isEmpty && !engine.password.isEmpty) else {
            throw err("missing username or password")
        }

        if remember, !engine.username.isEmpty {
            try? KeychainCredentialStore.saveCredentials(profile: id, .init(username: engine.username, password: raw.password ?? ""))
        }
        // Session secrets ride startTunnel options — in-memory through the NE
        // session. The extension runs as root in the system context and cannot
        // read the user's keychain, so options are the only reliable handoff.
        let secrets = KeychainCredentialStore.loadProfileSecrets(profile: id)
        var options: [String: NSObject] = [
            "username": engine.username as NSString,
            "password": engine.password as NSString,
        ]
        if let p = secrets?.proxyPassword { options["proxyPassword"] = p as NSString }
        if let p = secrets?.privateKeyPassword { options["privateKeyPassword"] = p as NSString }
        // The static-challenge response rides its own option so the bridge can
        // hand it to the engine as ProvideCreds.response.
        if staticChallenge, let otp = raw.otp?.trimmingCharacters(in: .whitespaces), !otp.isEmpty {
            options["challengeResponse"] = otp as NSString
        }
        // A password manager can also supply the private-key passphrase; it wins
        // over the keychain copy so the mapped 1Password field takes effect.
        if let p = raw.privateKeyPassphrase, !p.isEmpty { options["privateKeyPassword"] = p as NSString }

        // Org policy travels with every session so the extension enforces it at
        // connect regardless of the persisted config (a profile saved before the
        // policy was pushed can't be used to leak). This is the real enforcement
        // point — the UI gates are only cosmetic.
        if ManagedPolicy.forceKeepInsideVPN { options["policyKeepInside"] = true as NSNumber }
        if ManagedPolicy.disableDivertRules { options["policyNoDiverts"] = true as NSNumber }

        // Default-gateway ownership travels with the session so the extension sets
        // its suppress gate at establish — the ≤1-owner invariant then holds from
        // the very first tun build, before (or without) the app reconciling (RC3).
        options["gatewayOwned"] = predictedGatewayOwned(id) as NSNumber

        mgr.isEnabled = true
        do {
            try await mgr.saveToPreferences()
            try await mgr.loadFromPreferences()
        } catch {
            // A silent stop here looked identical to "nothing happened" in the
            // 15:08 diagnostics — every stage failure must name itself.
            Self.log.error("connect prefs save/load failed for \(id, privacy: .public): \(error.localizedDescription, privacy: .public)")
            throw error
        }
        guard let session = mgr.connection as? NETunnelProviderSession else {
            Self.log.error("connect: no NETunnelProviderSession for \(id, privacy: .public)")
            throw err("The VPN configuration isn't ready — try removing and re-importing it.")
        }
        do {
            try session.startTunnel(options: options)
            Self.log.log("startTunnel dispatched for \(id, privacy: .public) (status now \(Self.statusText(mgr.connection.status), privacy: .public))")
        } catch {
            // Without this line a failed start is invisible in a log capture —
            // the error only reaches the UI alert.
            Self.log.error("startTunnel failed for \(id, privacy: .public): \(error.localizedDescription, privacy: .public)")
            throw error
        }
        // The notification observer is matched at fire time, but the transition to
        // .connecting can precede this line — pull current statuses now so the
        // watchdog is guaranteed to start counting.
        resyncStatuses()
        // Part of this connect attempt: is a Wi-Fi sign-in page in the way? The
        // engine would otherwise retry silently against a network that answers
        // every request with a login page. Tell the user in seconds, not after
        // the 45 s watchdog. (Probe runs only on user-initiated connects.)
        Task { [weak self] in
            guard let self else { return }
            await self.recheckCaptivePortal()
            guard self.captivePortalSuspected,
                  self.profiles.first(where: { $0.id == id })?.status != .connected else { return }
            let name = self.profiles.first { $0.id == id }?.name ?? "The VPN"
            ToastCenter.shared.post(
                "This Wi-Fi wants you to sign in before \(name) can connect.",
                symbol: "wifi.exclamationmark", tint: .indigo, seconds: 12,
                actionTitle: "Open Sign-In Page") { [weak self] in
                    guard let self else { return }
                    NSWorkspace.shared.open(self.captivePortalURL ?? ConnectionDiagnostics.captivePortalProbeURL)
                }
        }
        appliedOverrides[id] = overrides(for: id)   // what this session runs with
        appliedOVPN[id] = ovpnText(id: id) ?? ""
    }

    /// Unified connect from the shared credential state (the store every surface
    /// edits). Persists username+password iff the shared Remember preference is on
    /// and the profile allows saving; the OTP is consumed and cleared.
    func connectWithTransientCredentials(id: String) async throws {
        // Tailscale has no username/password to collect — it signs in with a
        // setup key or a browser. Every connect entry point funnels here or to
        // one of the two below, so the branch belongs at each of them.
        if isTailscale(id) { try await connectTailscale(id: id); return }
        if isProxyTunnel(id) { try await connectProxyTunnel(id: id); return }
        let c = transientCredentials(for: id)
        let auth = effectiveAuthConfig(for: id)
        let provider = ManualCredentialProvider(username: c.username, password: c.password, otp: c.otp)
        try await connect(id: id, using: provider, request: auth.request,
                          remember: auth.rememberCredentials && allowsPasswordSave(id: id))
        transientCreds[id]?.otp = ""
    }

    /// The profile's auth-nocache verdict (engine eval); true when unknown.
    var allowsPasswordSaveEvaluator: ((String) -> Bool)?
    private func allowsPasswordSave(id: String) -> Bool {
        allowsPasswordSaveEvaluator?(id) ?? true
    }

    /// Engine-eval facts the connect flow branches on (autologin, static
    /// challenge, userlocked username). Wired at launch like the evaluator
    /// above; nil (unwired, or no .ovpn) degrades to the plain-credentials path.
    var profileEvaluationProvider: ((String) -> ProfileEvaluation?)?
    func profileEvaluation(for id: String) -> ProfileEvaluation? {
        profileEvaluationProvider?(id)
    }

    /// Non-OpenVPN import handoff for the shared pipeline (main-window
    /// drop/Import, Finder open): `importProfile` sniffs the config's real
    /// kind with `ConfigDetector` first, and for anything but `.openVPN` hands
    /// the raw text off here instead of always trying the OpenVPN evaluator.
    /// Wired once at launch (SimpleVPNApp) to the same WireGuard/Cisco/native
    /// stores ManageVPNsView's own importer already dispatches to; nil until
    /// wired (or in tests) degrades to the previous OpenVPN-only behaviour.
    var otherEngineImportHandler: ((DetectedConfigKind, String, String) -> ImportOutcome)?

    /// Autologin profiles authenticate with their certificate alone — there is
    /// no username or password to collect, gate on, or save.
    func isAutologin(_ id: String) -> Bool {
        profileEvaluation(for: id)?.autologin ?? false
    }

    /// The profile declares `static-challenge`: the server demands a challenge
    /// response (the one-time code) alongside — not inside — the password.
    func hasStaticChallenge(_ id: String) -> Bool {
        !(profileEvaluation(for: id)?.staticChallenge.isEmpty ?? true)
    }

    /// The auth shape connect flows and forms should READ: the persisted config
    /// with requiresOTP forced on when the profile itself declares a static
    /// challenge — the server will demand the code regardless of the toggle,
    /// and this is also what fixes profiles imported before the challenge was
    /// wired up. Writes still go through setAuthConfig with the raw config.
    func effectiveAuthConfig(for id: String) -> VPNAuthConfig {
        var auth = authConfig(for: id)
        if hasStaticChallenge(id) { auth.requiresOTP = true }
        return auth
    }

    func requiresOTP(for id: String) -> Bool {
        effectiveAuthConfig(for: id).requiresOTP
    }

    /// The ONE readiness decision every Connect affordance reads — the detail
    /// Connect button, the sidebar play button and the menu row — so a control
    /// is never enabled in one place and disabled in another. (Tailscale used to
    /// be connectable from the detail pane yet stuck on "Sign-in needed" in the
    /// sidebar because each view recomputed this for itself.)
    func connectReadiness(for id: String) -> ConnectReadiness {
        connectInputs(for: id).readiness
    }

    /// Gather the plain facts `ConnectReadiness` turns on. Kept separate from the
    /// (pure, testable) decision so the keychain/evaluator lookups happen once,
    /// and only for the kinds that need them.
    func connectInputs(for id: String) -> ConnectInputs {
        var inputs = ConnectInputs()
        inputs.kind = profiles.first { $0.id == id }?.kind ?? .openVPN

        // Tailscale and Proxy Tunnels decide on their own settings — no typed
        // credentials, so skip the evaluator/keychain work entirely.
        if inputs.kind == .tailscale { return inputs }
        if inputs.kind == .proxyTunnel {
            let config = proxyTunnelConfig(for: id)
            inputs.proxyHasProblem = config.connectProblem != nil
            inputs.proxyRequiresAuth = config.requiresAuth
            let creds = proxyTunnelCredentials(for: id)
            inputs.proxyCredentialsComplete =
                !creds.username.trimmingCharacters(in: .whitespaces).isEmpty && !creds.password.isEmpty
            return inputs
        }

        inputs.autologin = isAutologin(id)
        inputs.managerKind = credentialSource(for: id).kind
        inputs.requiresOTP = effectiveAuthConfig(for: id).requiresOTP
        inputs.hasLockedUsername = !(profileEvaluation(for: id)?.userlockedUsername.isEmpty ?? true)
        let c = transientCredentials(for: id)
        inputs.typedUsername = !c.username.trimmingCharacters(in: .whitespaces).isEmpty
        inputs.typedPassword = !c.password.isEmpty
        inputs.typedOTP = !c.otp.trimmingCharacters(in: .whitespaces).isEmpty

        // Touch ID facts only matter for a manual, protected source (a manager
        // source resolves its own secret); reading them otherwise is a needless
        // keychain hit on every redraw.
        inputs.biometricProtected = authConfig(for: id).protectWithBiometrics
        if inputs.managerKind == .manual, inputs.biometricProtected {
            let info = BiometricCredentialStore.info(profile: id)
            inputs.biometricStored = info.exists
            inputs.biometricHasTOTP = info.hasTOTP
        }
        return inputs
    }

    /// Connect unattended (menu / sidebar quick-connect). Uses a configured
    /// password manager when it can run without typing, else remembered
    /// credentials. Returns false when a fresh OTP or manual entry is needed —
    /// the caller then sends the user to the credential form.
    @discardableResult
    func connectWithSavedCredentials(id: String) async -> Bool {
        if isTailscale(id) {
            do { try await connectTailscale(id: id); return true }
            catch { report(error, profile: id); return false }
        }
        if isProxyTunnel(id) {
            // A no-auth proxy connects unattended; an auth proxy connects with
            // its stored credentials (there is no OTP to type).
            do { try await connectProxyTunnel(id: id); return true }
            catch { report(error, profile: id); return false }
        }
        // Autologin: nothing to look up — the profile's certificate IS the sign-in.
        if isAutologin(id) {
            do {
                try await connect(id: id, using: ManualCredentialProvider(username: "", password: "", otp: ""),
                                  request: .usernamePassword, remember: false)
                return true
            } catch {
                report(error, profile: id)
                return false
            }
        }
        let auth = effectiveAuthConfig(for: id)

        // A password manager can auto-connect when the profile needs no OTP, or
        // when it can supply the OTP itself (1Password TOTP; the Touch ID store
        // with a saved authenticator secret). Apple Passwords can't provide an
        // OTP, so an OTP profile still needs the form.
        if let provider = managerProvider(for: id) {
            let canServeOTP = credentialSource(for: id).kind == .onePassword
                || biometricCanServe(id: id)
            guard !auth.requiresOTP || canServeOTP else { return false }
            do {
                try await connect(id: id, using: provider, request: auth.request, remember: false)
                return true
            } catch {
                report(error, profile: id)
                return false
            }
        }

        guard !auth.requiresOTP,
              let saved = savedCredentials(id: id), !saved.password.isEmpty else { return false }
        let provider = ManualCredentialProvider(username: saved.username, password: saved.password, otp: "")
        do {
            try await connect(id: id, using: provider, request: .usernamePassword, remember: false)
            return true
        } catch {
            report(error, profile: id)
            return false
        }
    }

    /// Connect honoring the profile's configured credential source. For a
    /// manager source, resolves the item (prompting Touch ID / keychain as the
    /// manager sees fit) and overlays the typed OTP only if the manager didn't
    /// supply one. Manual sources fall back to the shared credential state.
    func connectUsingConfiguredSource(id: String, typedOTP: String) async throws {
        if isTailscale(id) { try await connectTailscale(id: id); return }
        if isProxyTunnel(id) { try await connectProxyTunnel(id: id); return }
        let auth = effectiveAuthConfig(for: id)
        guard let provider = managerProvider(for: id) else {
            try await connectWithTransientCredentials(id: id)
            return
        }
        var raw = try await provider.resolve(profile: id, fields: auth.request.fields)
        if auth.requiresOTP, (raw.otp ?? "").isEmpty, !typedOTP.isEmpty { raw.otp = typedOTP }
        let composed = ManualCredentialProvider(username: raw.username ?? "",
                                                password: raw.password ?? "", otp: raw.otp ?? "",
                                                privateKeyPassphrase: raw.privateKeyPassphrase ?? "")
        try await connect(id: id, using: composed, request: auth.request, remember: false)
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

    /// Profiles being reconnected to apply a settings change — the UI shows an
    /// "applying" state instead of collapsing to the disconnected/Connect layout.
    /// Refcounted (not a Set): overlapping applies on the same id must not clear
    /// each other's "Applying…" state early — the flag drops only when the last
    /// in-flight operation finishes.
    private var reconfiguringCounts: [String: Int] = [:]
    private func beginReconfiguring(_ id: String) { reconfiguringCounts[id, default: 0] += 1 }
    private func endReconfiguring(_ id: String) {
        guard let n = reconfiguringCounts[id] else { return }
        if n <= 1 { reconfiguringCounts[id] = nil } else { reconfiguringCounts[id] = n - 1 }
    }
    func isReconfiguring(_ id: String) -> Bool { (reconfiguringCounts[id] ?? 0) > 0 }

    /// The overrides the *running* session was started with (nil ⇒ not connected),
    /// so a setting can show whether it's actually applied or only pending.
    func appliedOverrides(for id: String) -> OpenVPNOverrides? { appliedOverrides[id] }

    // MARK: One-step undo of the last applied change

    struct ChangeUndo: Sendable { var label: String; var overrides: OpenVPNOverrides; var ovpn: String? }
    private(set) var lastChange: [String: ChangeUndo] = [:]

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

    // MARK: Compositions (multiple VPNs connected together)

    /// Members that couldn't be started unattended (need a fresh OTP / manual
    /// entry) after a composition connect — surfaced so the user can finish them.
    private(set) var compositionNeedsAttention: [String] = []

    /// Connect every member of a composition, in dependency order: a member that
    /// runs "over" another waits for that one to reach `.connected` first (bounded).
    /// Members needing a fresh OTP are collected in `compositionNeedsAttention`.
    func connectComposition(_ composition: VPNComposition) async {
        compositionNeedsAttention = []
        for member in composition.startOrder {
            if let dep = member.dependsOn {
                await waitForConnected(id: dep, timeout: 15)
            }
            let ok = await connectWithSavedCredentials(id: member.profileID)
            if !ok {
                compositionNeedsAttention.append(member.profileID)
            }
        }
        if !compositionNeedsAttention.isEmpty {
            let names = compositionNeedsAttention
                .compactMap { id in profiles.first { $0.id == id }?.name }
                .joined(separator: ", ")
            lastError = "Connected the rest of \(composition.name). These still need a code or sign-in: \(names)."
        }
    }

    func disconnectComposition(_ composition: VPNComposition) {
        for member in composition.members { disconnect(id: member.profileID) }
    }

    /// True while any member of the composition is active.
    func isCompositionActive(_ composition: VPNComposition) -> Bool {
        composition.members.contains { m in
            profiles.first { $0.id == m.profileID }.map { UI.isActive($0.status) } ?? false
        }
    }

    private func waitForConnected(id: String, timeout: Int) async {
        for _ in 0..<(timeout * 10) {
            if profiles.first(where: { $0.id == id })?.status == .connected { return }
            try? await Task.sleep(for: .milliseconds(100))
        }
    }

    // MARK: Pause / Resume
    //
    // The engine pauses under a kept TLS session (resume needs no re-auth), so
    // NEVPNStatus stays .connected throughout — paused is app-side state.

    // ONE pause behaviour (the old "hold/block" mode is gone): the tunnel stays
    // signed in, its routes/DNS come out so traffic uses the physical interface,
    // and resume puts them back. The extension still speaks "pause:<mode>", so
    // the wire format is unchanged — the app just only ever asks for bypass.

    /// Profiles currently paused. UI derives DotState.paused from this.
    private(set) var pausedProfiles: Set<String> = []

    func pause(id: String) async {
        guard let reply = await sendMessage("pause:bypass", to: id), reply == "ok" else {
            lastError = "Pause failed — the tunnel didn't acknowledge."
            return
        }
        pausedProfiles.insert(id)
        Self.log.log("paused \(id, privacy: .public)")
    }

    func resume(id: String) async {
        let acknowledged = (await sendMessage("resume", to: id)) == "ok"
        pausedProfiles.remove(id)
        guard acknowledged else {
            await recoverFailedResume(id: id, why: "the tunnel didn't acknowledge resuming")
            return
        }
        Self.log.log("resumed \(id, privacy: .public)")
        // Acknowledged is NOT the same as recovered. Resuming re-applies the tunnel's
        // network settings, which makes NetworkExtension re-negotiate the session — that
        // brief pass through .reasserting is the "flash" — and if the re-apply or the
        // engine restart fails, NE tears the tunnel down a moment later. Watch for it.
        startResumeWatchdog(id: id)
    }

    /// Resume is only really done once the session is back up. Nothing else notices a
    /// teardown that arrives AFTER an "ok", which is how a failed resume used to end up
    /// looking like an ordinary Connect button with no explanation.
    private func startResumeWatchdog(id: String) {
        resumeWatchdogs[id]?.cancel()
        resumeWatchdogs[id] = Task { [weak self] in
            try? await Task.sleep(for: Self.resumeSettleWindow)
            guard !Task.isCancelled, let self else { return }
            let status = self.profiles.first { $0.id == id }?.status
            guard status == .disconnected || status == .invalid else { return }
            await self.recoverFailedResume(id: id, why: "resuming dropped the connection")
        }
    }

    /// AUTH_FAILED right after a successful session, on an OTP profile, is almost
    /// always a one-time code being REUSED: the previous connect consumed it, and
    /// LinOTP-style servers refuse a second use inside the same ~30-second window.
    /// Toggling a connection setting forces exactly that disconnect→reconnect, so
    /// without this the user reads it as "the setting broke my VPN" (it did, twice,
    /// today). Say what actually happened and what to do.
    private func explainOTPReuseIfLikely(id: String) {
        guard incidents[id]?.category == .auth,
              requiresOTP(for: id),
              let lastUp = lastConnectedAt[id],
              Date().timeIntervalSince(lastUp) < 90 else { return }
        let name = profiles.first { $0.id == id }?.name ?? "The VPN"
        ToastCenter.shared.post(
            "\(name) rejected the sign-in \u{2014} the one-time code was probably just used by the previous connection. Wait for your authenticator's next code, then connect again.",
            symbol: "clock.badge.exclamationmark", seconds: 12)
    }

    private func cancelResumeWatchdog(id: String) {
        resumeWatchdogs[id]?.cancel()
        resumeWatchdogs[id] = nil
    }

    /// Both halves of the fix: SAY what happened, and where it's safe to, put it right.
    ///
    /// The reconnect is guarded by `canReconnectUnattended` for a specific reason — a
    /// profile needing a fresh one-time code can't be brought back without the user, and
    /// silently prompting for Touch ID or an OTP in the middle of what looked like
    /// "unpause" would be a worse surprise than saying so plainly.
    private func recoverFailedResume(id: String, why: String) async {
        let name = profiles.first { $0.id == id }?.name ?? "The VPN"
        Self.log.error("resume recovery for \(id, privacy: .public): \(why, privacy: .public)")

        // Persistent half, so the VPN's own pane still explains this later.
        TunnelIncidentStore.write(TunnelIncident(
            profile: id, category: .tunSetup, event: "RESUME_FAILED",
            info: "Resuming \(name) \(why). macOS re-applies the tunnel's settings when a "
                + "paused VPN resumes, and this time it didn't come back.",
            fatal: false))

        if canReconnectUnattended(id: id) {
            ToastCenter.shared.post(
                "\(name): \(why) — reconnecting\u{2026}",
                symbol: "arrow.triangle.2.circlepath", tint: .yellow, seconds: 6)
            await reconnect(id: id)
        } else {
            // Be explicit that this needs them, and why we didn't just do it.
            ToastCenter.shared.post(
                "\(name): \(why). It needs your sign-in again, so it wasn't reconnected for you.",
                symbol: "exclamationmark.triangle.fill", seconds: 12,
                actionTitle: "Connect") { [weak self] in
                    guard let self else { return }
                    Task { try? await self.connectUsingConfiguredSource(id: id, typedOTP: "") }
                }
        }
    }

    /// One-shot IPC to the running tunnel; nil when no session or send fails.
    private func sendMessage(_ message: String, to id: String) async -> String? {
        await sendMessageData(message, to: id).flatMap { String(data: $0, encoding: .utf8) }
    }

    private func sendMessageData(_ message: String, to id: String,
                                 timeout: TimeInterval = 8) async -> Data? {
        guard let session = managers[id]?.connection as? NETunnelProviderSession else { return nil }
        return await withCheckedContinuation { (cont: CheckedContinuation<Data?, Never>) in
            // Single-resume guard + timeout: if the session is torn down between the
            // guard and the call, or the completion never fires, the continuation
            // would otherwise leak and hang this task forever — and this is the
            // channel ReachabilityMonitor/ThroughputMonitor poll continuously.
            let once = OnceResume()
            let finish: @Sendable (Data?) -> Void = { d in if once.claim() { cont.resume(returning: d) } }
            DispatchQueue.global().asyncAfter(deadline: .now() + timeout) { finish(nil) }
            do {
                try session.sendProviderMessage(Data(message.utf8)) { reply in finish(reply) }
            } catch {
                finish(nil)
            }
        }
    }

    /// Live telemetry poll — the only channel that crosses the root(system)
    /// extension ↔ user app boundary. nil when not connected.
    func fetchStats(id: String) async -> TunnelStats? {
        guard let data = await sendMessageData("stats", to: id) else { return nil }
        let stats = try? JSONDecoder().decode(TunnelStats.self, from: data)
        // Fold the engine's ground-truth default-route ownership into the gateway
        // coordinator on every poll: keeps the applied-role cache honest and heals
        // any full/split desync live (RC1/RC4). The stats poll is the only channel
        // that crosses the root-extension ↔ user-app boundary.
        if let owned = stats?.effectiveDefaultOwned { routes.noteEngineDefaultOwned(id: id, owned: owned) }
        // Fold the engine's ground-truth pushed proxy into the Proxy mediator, the same
        // way as the default-route ownership above. Only kinds that PUSH a proxy
        // structurally do this today (OpenVPN); OpenConnect is a marked TODO below.
        if let stats { notePushedProxy(id: id, from: stats) }
        return stats
    }

    /// Update the per-profile pushed-proxy cache from a stats sample and, when the
    /// decision changed, ask the Proxy mediator to re-arbitrate + apply. Per-kind
    /// (StateMediators.md › Pushed-proxy sources): OpenVPN carries structured
    /// `dhcp-option PROXY_*` here; the SOCKS/native/none kinds contribute nothing.
    private func notePushedProxy(id: String, from stats: TunnelStats) {
        let kind = profiles.first { $0.id == id }?.kind
        let newIntent: ProxyIntent?
        switch kind {
        case .openVPN:
            newIntent = Self.proxyIntent(engine: id, from: stats)
        // TODO(StateMediators.md › Pushed-proxy sources by VPN kind): OpenConnect
        // (AnyConnect/GlobalProtect) can push a PAC/proxy, but the channel is
        // vendor-specific and needs a real gateway to verify what libopenconnect
        // surfaces — left uncaptured rather than half-implemented. Native IKEv2/IPsec
        // proxy is OS-owned (we only OBSERVE via SCDynamicStore, never push). SSH /
        // proxy-tunnel / Tailscale / WireGuard push no proxy — no intent by design.
        default:
            newIntent = nil
        }
        let changed = pushedProxyIntents[id] != newIntent
        pushedProxyIntents[id] = newIntent
        proxies.noteEnginePushedProxy(changed: changed)
    }

    /// Build a `ProxyIntent` from the structured pushed-proxy fields of a stats sample
    /// (OpenVPN's `dhcp-option PROXY_HTTP/PROXY_HTTPS/PROXY_AUTO_CONFIG_URL/PROXY_BYPASS`).
    /// PAC wins over manual. `nil` when nothing was pushed. No credentials ever — the
    /// push carries none; a 407 is answered from the keychain.
    nonisolated static func proxyIntent(engine: String, from stats: TunnelStats) -> ProxyIntent? {
        let bypass = stats.proxyBypass ?? []
        if let pac = stats.proxyPACURL, !pac.isEmpty {
            return ProxyIntent(engine: engine, mode: .pac(pac),
                               connectedAt: nil, bypass: bypass)
        }
        var manual = ProxyManual()
        if let h = stats.proxyHTTPHost, !h.isEmpty {
            manual.http = ProxyEndpoint(scheme: .http, host: h, port: stats.proxyHTTPPort ?? 0)
        }
        if let h = stats.proxyHTTPSHost, !h.isEmpty {
            manual.https = ProxyEndpoint(scheme: .https, host: h, port: stats.proxyHTTPSPort ?? 0)
        }
        guard let representative = manual.representative else { return nil }
        return ProxyIntent(engine: engine, mode: .manual(representative),
                           connectedAt: nil, manual: manual, bypass: bypass)
    }

    /// The traffic flows the extension has observed for this VPN (header-only
    /// accounting; empty when disconnected or the engine doesn't route through us).
    func fetchFlows(id: String) async -> [TrafficFlow] {
        guard let data = await sendMessageData("flows", to: id) else { return [] }
        return (try? JSONDecoder().decode([TrafficFlow].self, from: data)) ?? []
    }

    // MARK: Default gateway (PolicyRouting.md Tier 2 — the ≤1-default-owner invariant)
    //
    // At most ONE connected VPN owns 0.0.0.0/0 (full-tunnel) at a time — macOS
    // will not arbitrate two full-tunnel providers, so this is enforced, not
    // hoped for. Every other connected VPN is demoted to split (its own subnets
    // only). The user picks the owner live between any connected VPN and Direct.
    // The pure decision logic lives in GatewayPolicy; this owns the live NE side.

    // The gateway decision + state now live in `routes` (RouteMediator). VPNController
    // keeps only the thin forwarders the UI/menu already call, plus the profile-derived
    // helpers the mediator asks it for through `RouteMediatorHost` (below). See
    // Docs/StateMediators.md — this is the behavior-preserving P1 extraction.

    /// Whether a connected profile can be the full-tunnel owner. (Delegates.)
    func canBeDefaultGateway(_ id: String) -> Bool { routes.canBeDefaultGateway(id) }
    /// The role a connected profile currently plays. (Delegates.)
    func gatewayRole(for id: String) -> GatewayRole { routes.gatewayRole(for: id) }
    /// The owner actually in force right now. (Delegates.)
    var effectiveGatewayOwner: String? { routes.effectiveGatewayOwner }
    /// What the traffic-path picture should show (engine truth). (Delegates.)
    var displayedGatewayOwner: String? { routes.displayedGatewayOwner }
    /// The owner the engines actually report. (Delegates.)
    var engineReportedGatewayOwner: String? { routes.engineReportedGatewayOwner }
    /// Show the default-gateway control when there's a choice to make. (Delegates.)
    var showsDefaultGatewayControl: Bool { routes.showsDefaultGatewayControl }
    /// Establish-time ownership prediction (RC3), passed via `startTunnel`. (Delegates.)
    func predictedGatewayOwned(_ id: String) -> Bool { routes.predictedGatewayOwned(id) }
    /// The user picked a new default-gateway owner. (Delegates the atomic switch.)
    func setDefaultGateway(to newOwner: String?) async { await routes.setDefaultGateway(to: newOwner) }

    /// Connected profiles, most-recently-connected FIRST (the deterministic
    /// tiebreak for auto-promotion). Falls back to name order when recency is
    /// unknown so the ordering is always total.
    var connectedProfiles: [Profile] {
        profiles.filter { $0.status == .connected }
            .sorted { a, b in
                let ta = lastConnectedAt[a.id] ?? .distantPast
                let tb = lastConnectedAt[b.id] ?? .distantPast
                if ta != tb { return ta > tb }
                return a.name.localizedCaseInsensitiveCompare(b.name) == .orderedAscending
            }
    }

    /// The exit node this Tailscale profile would use as a gateway: its
    /// configured node if set, else the first available one the engine sees.
    private func tailscaleExitNode(for id: String) -> String {
        let c = tailscaleConfig(for: id)
        if c.useExitNode, !c.exitNode.isEmpty { return c.exitNode }
        return tailscaleStatuses[id]?.exitNodes.first(where: { $0.online })?.id
            ?? tailscaleStatuses[id]?.exitNodes.first?.id ?? ""
    }

    /// Whether a profile's own config wants to carry everything (redirect-gateway
    /// / default route / exit node). Drives the "wants everything but isn't the
    /// default" demotion note and the initial-role assumption.
    func profileWantsFullTunnel(_ id: String) -> Bool {
        guard let p = profiles.first(where: { $0.id == id }) else { return false }
        switch p.kind {
        case .proxyTunnel:
            return proxyTunnelConfig(for: id).includeDefaultRoute
        case .tailscale:
            let c = tailscaleConfig(for: id)
            return c.useExitNode && !c.exitNode.isEmpty
        case .openVPN:
            return (ovpnText(id: id) ?? "").range(of: "redirect-gateway", options: .caseInsensitive) != nil
        default:
            return p.kind.isSSLVPN   // OpenConnect builds a full-tunnel by default
        }
    }

    /// The specific subnets a connected VPN carries besides (or instead of) the
    /// default route — the "X also routes …" line under the picker. Best-effort
    /// per engine; empty when we can't enumerate them.
    func gatewaySubnets(for id: String) -> [String] {
        guard let p = profiles.first(where: { $0.id == id }) else { return [] }
        switch p.kind {
        case .proxyTunnel:
            let c = proxyTunnelConfig(for: id)
            return c.includeDefaultRoute ? [] : c.includedRoutes
        case .tailscale:
            let routes = tailscaleStatuses[id]?.config?.subnetRoutes ?? []
            return routes.filter { $0 != "0.0.0.0/0" && $0 != "::/0" }
        default:
            return []
        }
    }

    // MARK: Divert rules (route a destination around this VPN)

    private var routingRulesCache: [String: [RoutingRule]] = [:]

    func routingRules(for id: String) -> [RoutingRule] {
        if let cached = routingRulesCache[id] { return cached }
        let proto = managers[id]?.protocolConfiguration as? NETunnelProviderProtocol
        return RoutingRuleStore.decode(from: proto?.providerConfiguration?["routingRules"] as? Data)
    }

    /// Persist a profile's own rules (its excluded/divert destinations), then
    /// re-materialise every profile's "route into me" include-set and reconnect
    /// whatever's live so the change takes effect.
    func setRoutingRules(_ rules: [RoutingRule], for id: String) async {
        guard let mgr = managers[id],
              let proto = mgr.protocolConfiguration as? NETunnelProviderProtocol else { return }
        var conf = proto.providerConfiguration ?? [:]
        if let blob = RoutingRuleStore.encode(rules) { conf["routingRules"] = blob }
        else { conf.removeValue(forKey: "routingRules") }
        proto.providerConfiguration = conf
        mgr.protocolConfiguration = proto
        try? await mgr.saveToPreferences()
        try? await mgr.loadFromPreferences()
        routingRulesCache[id] = rules

        // The source profile's excludes changed → reconnect it.
        await reconnectIfActive(id)
        // Targets of any .overVPN rule need their include-set refreshed.
        await syncIncludes()
    }

    private func reconnectIfActive(_ id: String) async {
        guard profiles.first(where: { $0.id == id }).map({ UI.isActive($0.status) }) == true else { return }
        beginReconfiguring(id); defer { endReconfiguring(id) }
        await reconnect(id: id)
    }

    /// Recompute, for every profile, the destinations *other* profiles route into
    /// it (the target side of `.overVPN`), write them to its providerConfiguration,
    /// and reconnect it if the set changed while live.
    private func syncIncludes() async {
        for target in profiles {
            let dests: [RouteDest] = profiles
                .filter { $0.id != target.id }
                .flatMap { routingRules(for: $0.id) }
                .filter { $0.enabled && $0.action == .overVPN(profileID: target.id) }
                .compactMap { $0.routeDest }
            guard let mgr = managers[target.id],
                  let proto = mgr.protocolConfiguration as? NETunnelProviderProtocol else { continue }
            var conf = proto.providerConfiguration ?? [:]
            let newBlob = RouteDestStore.encode(dests)
            let oldBlob = conf["routingIncludes"] as? Data
            if newBlob == oldBlob { continue }              // no change for this target
            if let newBlob { conf["routingIncludes"] = newBlob } else { conf.removeValue(forKey: "routingIncludes") }
            proto.providerConfiguration = conf
            mgr.protocolConfiguration = proto
            try? await mgr.saveToPreferences()
            try? await mgr.loadFromPreferences()
            await reconnectIfActive(target.id)
        }
    }

    func addRoutingRule(_ rule: RoutingRule, for id: String) async {
        // Org policy can forbid diverting traffic around / off the VPN.
        switch rule.action {
        case .outside where !ManagedPolicy.allowDivertOutside: return
        case .overVPN where !ManagedPolicy.allowDivertOverVPN: return
        default: break
        }
        var rules = routingRules(for: id)
        // Replace any existing rule for the same destination.
        rules.removeAll { $0.destination == rule.destination }
        rules.append(rule)
        await setRoutingRules(rules, for: id)
    }

    func removeRoutingRule(id ruleID: String, for id: String) async {
        var rules = routingRules(for: id)
        rules.removeAll { $0.id == ruleID }
        await setRoutingRules(rules, for: id)
    }

    /// Disconnect and immediately reconnect (used to apply saved settings changes).
    /// Never called automatically — only from the user's explicit Reconnect action.
    func reconnect(id: String) async {
        // Don't tear down a working tunnel we can't bring back unattended: a
        // profile needing a fresh OTP (a one-time code can't be reused) or a
        // password that was never saved would be left silently disconnected — and
        // possibly exposed. The config change is already persisted, so it applies
        // on the next manual connect; leave the live session running until then.
        guard canReconnectUnattended(id: id) else {
            let name = profiles.first { $0.id == id }?.name ?? "this VPN"
            lastError = "Saved. It’ll take effect next time you connect \(name) — this VPN needs a code or sign-in that can’t be reused automatically, so it wasn’t reconnected for you."
            return
        }
        disconnect(id: id)
        // Wait (bounded) for the tunnel to fully stop before starting again.
        for _ in 0..<100 {   // ≤10 s
            if profiles.first(where: { $0.id == id })?.status == .disconnected { break }
            try? await Task.sleep(for: .milliseconds(100))
        }
        // Prefer the in-memory credentials that actually brought this tunnel up
        // (a typed password that Remember didn't persist) over saved ones, so an
        // apply-triggered reconnect doesn't fail a no-save profile.
        if let c = transientCreds[id], !c.password.isEmpty, !requiresOTP(for: id) {
            do { try await connectWithTransientCredentials(id: id) }
            catch { lastError = error.localizedDescription }
            return
        }
        await connectWithSavedCredentials(id: id)
    }

    /// Whether `reconnect` can bring the profile back without user interaction —
    /// used to avoid dropping a live tunnel we couldn't restore.
    private func canReconnectUnattended(id: String) -> Bool {
        // Once a Tailscale node is registered its key is on disk, so a
        // reconnect never needs the user.
        if isTailscale(id) { return true }
        if isAutologin(id) { return true }   // the certificate is the sign-in
        let auth = effectiveAuthConfig(for: id)
        if managerProvider(for: id) != nil {
            // 1Password can serve an OTP itself; Apple Passwords can't.
            return !auth.requiresOTP || credentialSource(for: id).kind == .onePassword
        }
        if auth.requiresOTP { return false }   // a one-time code can't be reused
        if let c = transientCreds[id], !c.password.isEmpty { return true }
        if let saved = savedCredentials(id: id), !saved.password.isEmpty { return true }
        return false
    }

    /// Stop every active tunnel and wait (bounded) for teardown, so the
    /// extension isn't cut off mid-stop. The quit path calls this — a tunnel
    /// lives in the system extension and would happily outlive the app, which
    /// is how "I quit and it was still connected" happened.
    func disconnectAllAndWait() async {
        for p in profiles where p.status != .disconnected && p.status != .invalid {
            disconnect(id: p.id)
        }
        for _ in 0..<50 {   // ≤5 s
            let stillActive = profiles.contains { $0.status != .disconnected && $0.status != .invalid }
            if !stillActive { break }
            try? await Task.sleep(for: .milliseconds(100))
        }
    }

    /// Menu-bar "Disconnect and Quit". Termination then flows through the app
    /// delegate's quit handler, which finds nothing left active and proceeds.
    func disconnectAllAndQuit() async {
        await disconnectAllAndWait()
        NSApplication.shared.terminate(nil)
    }

    func disconnect(id: String) {
        // Cancelling a connect that was already grinding away is the same evidence the
        // watchdog collects — the user just got there first. Remember the network so the
        // next attempt from here is forewarned. Short cancels (changed my mind) don't
        // count: they say nothing about reachability.
        if profiles.first(where: { $0.id == id })?.status == .connecting,
           let started = connectAttemptStarted[id],
           Date().timeIntervalSince(started) >= Self.cancelCountsAsUnreachable {
            Task {
                await NetworkMemory.shared.refresh()
                NetworkMemory.shared.rememberFailure(profile: id)
            }
        }
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

    // MARK: Connect watchdog

    /// How long a connect may sit in `.connecting` before we give up on it. The engine
    /// itself retries indefinitely by design (good on a flaky train, useless when
    /// you're simply on the wrong Wi-Fi), so the deadline lives here.
    static let connectTimeout: Duration = .seconds(45)
    /// Activates the system extension on demand, returning whether it's usable.
    /// Injected at launch (see SimpleVPNApp) so the packet-tunnel approval dialog can be
    /// raised HERE — at the first connect — instead of at app launch.
    var ensureExtensionReady: (() async -> Bool)?

    private var connectWatchdogs: [String: Task<Void, Never>] = [:]
    /// Per-profile watch for "resume said ok, then the tunnel died anyway".
    private var resumeWatchdogs: [String: Task<Void, Never>] = [:]
    /// When each profile last reached .connected — feeds the OTP-reuse explanation.
    private var lastConnectedAt: [String: Date] = [:]
    /// Per-profile pushed-proxy intent, sourced from the engine's ground-truth stats
    /// (the structured `proxy*` fields). The Proxy mediator reads it through
    /// `proxyProfiles` and re-arbitrates when it changes (see `fetchStats`). Absent ⇒
    /// nothing pushed. This is the OpenVPN per-kind capture from StateMediators.md.
    private var pushedProxyIntents: [String: ProxyIntent] = [:]
    /// How long to allow for a resumed session to settle before calling it failed.
    /// Long enough to cover NE's re-negotiation, short enough to still feel like a
    /// reaction to what the user just clicked.
    static let resumeSettleWindow: Duration = .seconds(6)
    /// When each in-flight connect began, so a user-initiated cancel can tell
    /// "this isn't working" from "changed my mind".
    private var connectAttemptStarted: [String: Date] = [:]
    /// A cancel after this long counts as evidence the VPN is unreachable here.
    static let cancelCountsAsUnreachable: TimeInterval = 10

    private func startConnectWatchdog(id: String) {
        guard connectWatchdogs[id] == nil else { return }   // already counting down
        connectAttemptStarted[id] = Date()
        connectWatchdogs[id] = Task { [weak self] in
            try? await Task.sleep(for: Self.connectTimeout)
            guard !Task.isCancelled, let self else { return }
            guard self.profiles.first(where: { $0.id == id })?.status == .connecting else { return }
            // A pending browser sign-in is the USER's wait, not the network's —
            // killing the tunnel mid-consent-page would strand the login. The
            // sign-in watch has its own five-minute bound, and the connecting
            // pill's ✕ stays available throughout.
            guard self.tailscaleSignInURL[id] == nil else { return }
            let profile = self.profiles.first { $0.id == id }
            let name = profile?.name ?? "The VPN"
            let host = profile?.server ?? ""
            Self.log.error("connect watchdog fired for \(id, privacy: .public) — giving up")

            // Persistent half: an incident, so the VPN's own pane still explains this
            // when you come back to it later (ConnectionIncidentCard renders it, and
            // the status observer picks it up as we go .disconnected below).
            TunnelIncidentStore.write(TunnelIncident(
                profile: id, category: .timeout, event: "CONNECT_TIMEOUT",
                info: host.isEmpty
                    ? "No answer while connecting; gave up after \(Self.connectTimeout.components.seconds) seconds."
                    : "No answer from \(host) while connecting; gave up after \(Self.connectTimeout.components.seconds) seconds.",
                fatal: true))

            self.disconnect(id: id)

            // Remember that THIS network can't reach this VPN, so next time we can
            // warn before the user waits out another timeout.
            await NetworkMemory.shared.refresh()
            NetworkMemory.shared.rememberFailure(profile: id)

            // Transient half: a toast, so it's noticed now without blocking the window.
            ToastCenter.shared.post(
                host.isEmpty
                    ? "Couldn't reach \(name) — connecting was stopped."
                    : "Couldn't reach \(name) at \(host) — connecting was stopped.",
                symbol: "wifi.exclamationmark",
                actionTitle: "Network Tools…") {
                    // Arrive pre-loaded with the host that just failed, rather than
                    // making the user retype what the app already knows.
                    if !host.isEmpty { NetworkToolsRequest.shared.request(host) }
                    ToastCenter.shared.openWindow?("tools")
                }
            self.connectWatchdogs[id] = nil
        }
    }

    private func cancelConnectWatchdog(id: String) {
        connectWatchdogs[id]?.cancel()
        connectWatchdogs[id] = nil
    }

    /// ONE process-wide status observer, matched against the CURRENT managers at
    /// fire time. It used to be one observer per connection object — but every
    /// saveToPreferences/loadFromPreferences (connect, overrides, routing rules)
    /// can replace `mgr.connection`, and an observer bound to the old object goes
    /// permanently silent. That's how a connect on a captive-portal network showed
    /// nothing at all: no status change, so no watchdog, no incident, no
    /// diagnostics. Matching by identity at fire time can't go stale; anything
    /// unmatched falls back to a full resync.
    private func observeStatusChanges() {
        let obs = NotificationCenter.default.addObserver(
            forName: .NEVPNStatusDidChange, object: nil, queue: .main) { [weak self] note in
                // Only the object's identity crosses into the isolated region —
                // Notification (and NEVPNConnection) aren't Sendable.
                let objID = note.object.map { ObjectIdentifier($0 as AnyObject) }
                MainActor.assumeIsolated {
                    guard let self else { return }
                    if let objID,
                       let (id, mgr) = self.managers.first(where: { ObjectIdentifier($0.value.connection) == objID }) {
                        self.handleStatusChange(id: id, status: mgr.connection.status)
                    } else {
                        self.resyncStatuses()
                    }
                }
            }
        observers.append(obs)
    }

    /// Pull every profile's status straight from its manager, routing any changes
    /// through the normal handler. Safety net for notifications about connection
    /// objects we no longer hold (and cheap enough to run on suspicion).
    func resyncStatuses() {
        for (id, mgr) in managers {
            let s = mgr.connection.status
            guard profiles.first(where: { $0.id == id })?.status != s else { continue }
            handleStatusChange(id: id, status: s)
        }
    }

    private func handleStatusChange(id: String, status s: NEVPNStatus) {
        if let i = profiles.firstIndex(where: { $0.id == id }) { profiles[i].status = s }
        Self.log.log("status[\(id, privacy: .public)] → \(Self.statusText(s), privacy: .public)")
        // A connect that can never succeed (wrong network, unreachable
        // gateway) is retried by the engine for ever, so the app has to
        // impose its own deadline — otherwise "Connecting…" is permanent.
        if s == .connecting {
            self.startConnectWatchdog(id: id)
        } else {
            self.cancelConnectWatchdog(id: id)
        }
        if s == .connected {
            // Back up for real, so the resume watch has nothing to report.
            cancelResumeWatchdog(id: id)
            // It works here after all — clear any "unreachable on this
            // network" memory so a one-off outage can't warn for ever.
            Task {
                await NetworkMemory.shared.refresh()
                NetworkMemory.shared.forgetFailure(profile: id)
            }
            queryExtensionVersion(id: id)
            incidents[id] = nil
            // Clear the persisted copy too, or the previous failure would
            // resurface as "the incident" after the next clean disconnect.
            TunnelIncidentStore.clear(profile: id)
            lastConnectedAt[id] = Date()
            captivePortalSuspected = false   // we're clearly through it
            recordBaseline(id: id)
        } else if s == .disconnected {
            extensionVersion = "unavailable"
            pausedProfiles.remove(id)      // pause never outlives its session
            pushedProxyIntents[id] = nil   // pushed proxy never outlives its session
            incidents[id] = TunnelIncidentStore.read(profile: id)
            explainOTPReuseIfLikely(id: id)
        }
        // Keep the ≤1-default-owner invariant live across every up/down, and fall
        // back (with a toast) when the picked owner drops. Runs after the blocks
        // above so lastConnectedAt (the recency tiebreak) is already current.
        // .reasserting is included: a reconnect rebuilds the tun, so the role must
        // be re-read from engine truth and re-applied (RC5).
        if s == .connected || s == .reasserting || s == .disconnected || s == .invalid {
            routes.handleStatusChange(id: id,
                                      connected: s == .connected,
                                      reasserting: s == .reasserting,
                                      disconnected: s == .disconnected || s == .invalid)
            dns.handleStatusChange(id: id, connected: s == .connected,
                                   disconnected: s == .disconnected || s == .invalid)
            proxies.handleStatusChange(id: id, connected: s == .connected,
                                       disconnected: s == .disconnected || s == .invalid)
        }
    }

    /// Record what a *working* connection looks like (server transport address
    /// from the extension's telemetry) so failure diagnostics can point out what
    /// changed since. Passive — no probing while connected.
    private func recordBaseline(id: String) {
        Task { [weak self] in
            try? await Task.sleep(for: .seconds(3))   // let the first stats sample land
            guard let self, self.profiles.first(where: { $0.id == id })?.status == .connected else { return }
            let stats = TunnelStatsStore.read(profile: id)
            var baseline = ConnectionBaselineStore.load(profile: id)
                ?? ConnectionBaseline(serverIP: nil, date: .now)
            if let ip = stats?.serverIP, !ip.isEmpty { baseline.serverIP = ip }
            // Sampled here, with the tunnel already up, and that is safe: the
            // fingerprint describes the PHYSICAL network whether or not a tunnel
            // owns the default route (see NetworkFingerprint.key). This used to
            // have to be captured back at .connecting to dodge the tunnel's own
            // route — the invariant makes that dance unnecessary.
            baseline.networkKey = NetworkMemory.shared.current?.key
            baseline.date = .now
            ConnectionBaselineStore.save(baseline, profile: id)
        }
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

    /// Thrown by config-mutating methods when MDM has locked configuration. The
    /// UI also disables the controls, but this is the real enforcement point —
    /// programmatic paths (Doctor fixes, undo) route through the same methods.
    static let configLocked = NSError(domain: "VPNController", code: 2,
        userInfo: [NSLocalizedDescriptionKey: "This connection's settings are locked by your organization."])
}

// MARK: - RouteMediatorHost (the live NE side for the Route mediator)

extension VPNController: RouteMediatorHost {
    /// Project the live profiles into the mediator's snapshot. Reads the observable
    /// `profiles` (and `lastConnectedAt`) so the mediator's computeds stay tracked.
    var routeProfiles: [RouteProfileInfo] {
        profiles.map { p in
            RouteProfileInfo(
                id: p.id, name: p.name, kind: p.kind,
                connected: p.status == .connected,
                engaged: isEngaged(id: p.id),
                lastConnectedAt: lastConnectedAt[p.id],
                tailscaleHasExitNode: p.kind == .tailscale && !tailscaleExitNode(for: p.id).isEmpty)
        }
    }

    func routeSendGateway(full: Bool, to id: String) async -> String? {
        await sendMessage(full ? "gateway:full" : "gateway:split", to: id)
    }

    /// Apply gateway ownership to a Tailscale profile via its exit-node prefs path —
    /// the exact patch the inline code built.
    func routeApplyTailscaleGateway(full: Bool, to id: String) async -> String? {
        let patch: TailscalePrefsPatch
        if full {
            let node = tailscaleExitNode(for: id)
            guard !node.isEmpty else { return nil }   // not capable; leave as-is (no-op success)
            patch = TailscalePrefsPatch(acceptRoutes: nil, acceptDNS: nil,
                                        useExitNode: true, exitNode: node,
                                        exitNodeAllowLANAccess: nil, advertiseRoutes: nil)
        } else {
            patch = TailscalePrefsPatch(acceptRoutes: nil, acceptDNS: nil,
                                        useExitNode: false, exitNode: nil,
                                        exitNodeAllowLANAccess: nil, advertiseRoutes: nil)
        }
        return await pushTailscalePrefs(patch, id: id)
    }

    func routeReconnect(id: String) async { await reconnect(id: id) }

    @discardableResult
    func routeSampleEffectiveOwned(id: String) async -> Bool? {
        await fetchStats(id: id)?.effectiveDefaultOwned
    }

    func routeWantsFullTunnel(id: String) -> Bool { profileWantsFullTunnel(id) }
    func routeAdvertisedPrefixes(id: String) -> [String] { gatewaySubnets(for: id) }
}

// MARK: - DNSMediatorHost (the live NE side for the DNS mediator)

extension VPNController: DNSMediatorHost {
    /// Project the live profiles into the DNS mediator's snapshot, sourcing each
    /// tunnel's DNS intent from the config we hold app-side. Best-effort: proxy-tunnels
    /// carry an explicit resolver list; other kinds' pushed DNS lands at the engine
    /// bridge (the tier-3 `DNS_PUSHED` capture seam) and reads back through the observed
    /// system resolvers the mediator already publishes.
    var dnsProfiles: [DNSProfileInfo] {
        profiles.map { p in
            var resolvers: [String] = []
            var matchDomains: [String] = []
            var wantsCatchAll = false
            if p.kind == .proxyTunnel {
                let c = proxyTunnelConfig(for: p.id)
                resolvers = c.dnsServers
                wantsCatchAll = c.includeDefaultRoute && !c.dnsServers.isEmpty
                matchDomains = wantsCatchAll ? [""] : []
            }
            return DNSProfileInfo(
                id: p.id, name: p.name, kind: p.kind,
                connected: p.status == .connected,
                engaged: isEngaged(id: p.id),
                lastConnectedAt: lastConnectedAt[p.id],
                resolvers: resolvers, searchDomains: [],
                matchDomains: matchDomains, wantsCatchAll: wantsCatchAll)
        }
    }

    var dnsDefaultOwner: String? { routes.effectiveGatewayOwner }

    /// SOLE-WRITER DNS apply: send ONE participant's arbitrated `NEDNSSettings` slice to
    /// its live session via the `dns:apply:` IPC (nil/empty ⇒ `dns:clear`), the same
    /// shape as `proxyApply`. Returns the engine ack, or `nil` when there is no live DNS
    /// applier for this tunnel (native kinds have no NETunnelProviderSession; the
    /// proxy-tunnel / Tailscale engines reply nil because they can't hot-swap DNS) — the
    /// realizer reads that nil as "fall back to reconnect".
    func dnsApply(_ request: DNSApplyRequest?, to id: String) async -> String? {
        guard let request, !request.isEmpty else { return await sendMessage("dns:clear", to: id) }
        guard let json = try? JSONEncoder().encode(request),
              let text = String(data: json, encoding: .utf8) else { return nil }
        return await sendMessage("dns:apply:\(text)", to: id)
    }

    func dnsReconnect(id: String) async { await reconnect(id: id) }
}

// MARK: - ProxyMediatorHost (the live NE side for the Proxy mediator)

extension VPNController: ProxyMediatorHost {
    /// Project the live profiles into the Proxy mediator's snapshot. Pushed/SOCKS proxy
    /// detail for the subprocess kinds (SSH `-D`, ocproxy) is owned by the subprocess
    /// manager, not this controller, so those arrive as `.none` here and the mediator
    /// leans on the observed system proxy it publishes from SCDynamicStore — the
    /// intent-capture seam for populating them live is deliberately left clean (tier-3
    /// `PROXY_PUSHED`).
    var proxyProfiles: [ProxyProfileInfo] {
        profiles.map { p in
            // The engine's ground-truth pushed proxy (from stats) is the OpenVPN
            // per-kind capture; other kinds contribute nothing (mode .none).
            let pushed = pushedProxyIntents[p.id]
            return ProxyProfileInfo(
                id: p.id, name: p.name, kind: p.kind,
                connected: p.status == .connected,
                engaged: isEngaged(id: p.id),
                lastConnectedAt: lastConnectedAt[p.id],
                mode: pushed?.mode ?? .none,
                manual: pushed?.manual,
                bypass: pushed?.bypass ?? [],
                excludeSimpleHostnames: pushed?.excludeSimpleHostnames ?? false,
                authSource: pushed?.authSource)
        }
    }

    var proxyDefaultOwner: String? { routes.effectiveGatewayOwner }

    func proxyReassert(owner: String) async { await reconnect(id: owner) }

    /// SOLE-WRITER proxy apply: send the arbitrated `NEProxySettings` decision to ONE
    /// tunnel's live session via the `proxy:apply:` IPC (nil ⇒ `proxy:clear`), the same
    /// shape as the `gateway:full|split` + DNS re-apply paths. Returns the engine ack
    /// (nil when there's no NE session — e.g. an SSH SOCKS kind that isn't ours to set).
    func proxyApply(_ request: ProxyApplyRequest?, to id: String) async -> String? {
        guard let request, !request.isEmpty else { return await sendMessage("proxy:clear", to: id) }
        guard let json = try? JSONEncoder().encode(request),
              let text = String(data: json, encoding: .utf8) else { return nil }
        return await sendMessage("proxy:apply:\(text)", to: id)
    }
}

/// Thread-safe "resume exactly once" guard for a continuation raced between a
/// callback and a timeout. `nonisolated` so `claim()` is callable from the
/// off-actor @Sendable completion/timeout closures (the app defaults to MainActor
/// isolation, which would otherwise make it main-actor-bound).
private nonisolated final class OnceResume: @unchecked Sendable {
    private let lock = NSLock()
    private var done = false
    func claim() -> Bool { lock.lock(); defer { lock.unlock() }; if done { return false }; done = true; return true }
}
