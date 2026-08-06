// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
//  VPNController.swift
//  App-side management of tunnel configurations and connections. Supports multiple
//  saved targets (one NETunnelProviderManager each). Credentials go through the shared
//  keychain (see KeychainCredentialStore); no secrets in providerConfiguration.
//
//  This is the CORE of the controller: the class itself, every piece of stored
//  state (Swift extensions cannot hold stored properties), loading, and the one
//  process-wide status observer. The behavior lives in the concern files beside
//  it — VPNController+Connect / +Tailscale / +ProxyTunnel / +Gateway / +CRUD /
//  +Telemetry — each an `extension VPNController`.
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

    /// Bumped by the File ▸ Import menu command; the UI presents the importer in response.
    var importRequested = false
    /// A duplicate/invalid import result awaiting user acknowledgement (see ImportUI).
    var importOutcome: ImportOutcome?
    /// Version of the running extension (via IPC); "unavailable" when nothing is connected.
    private(set) var extensionVersion: String = "unavailable"

    var managers: [String: NETunnelProviderManager] = [:]   // was private — internal for the +File split
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
    var appliedOverrides: [String: OpenVPNOverrides] = [:]   // was private — internal for the +File split
    /// The raw .ovpn a running session was started with, so edits to it (server,
    /// routes, ciphers) while connected also raise the "reconnect to apply" signal.
    var appliedOVPN: [String: String] = [:]   // was private — internal for the +File split

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

    /// Control-plane liveness: installed by ControlPlaneDispatcher; every status
    /// flip (and profile-list change) is reported here so the CLI's `watch`,
    /// intents and future Tcl handlers hear exactly what the UI observes.
    @ObservationIgnored var controlEventSink: ((ControlEvent) -> Void)?

    /// Extension-doctor wake-up: a CONNECTED tunnel whose stats IPC stopped
    /// answering — the classic dead/wedged-extension symptom. Installed by
    /// ExtensionDoctor at launch; fired from fetchStats. The doctor debounces,
    /// so the once-a-second stats poll can report freely.
    @ObservationIgnored var statsTimeoutHook: ((String) -> Void)?

    /// The dispatcher's guard chain (MDM today, Tcl `CTL_*` later), installed at
    /// startup. The lifecycle entries below consult it BEFORE acting, so the
    /// guarantee is structural: every interface — UI buttons calling these
    /// methods directly, the CLI, intents — is gated identically, and a future
    /// view can't forget to check. nil (tests, previews) ⇒ allow.
    @ObservationIgnored var controlGuard: ((ControlCommand) -> ControlDecision)?

    /// Run the guard chain for a command; non-nil = the denial reason (already
    /// broadcast to the event stream by the chain's runner).
    func controlDenied(_ command: ControlCommand) -> String? {   // was private — internal for the +File split
        if case .deny(let why) = controlGuard?(command) ?? .allow {
            Self.log.log("control: \(command.name, privacy: .public) denied — \(why, privacy: .public)")
            return why
        }
        return nil
    }

    /// NEVPNStatus → the stable wire word (ControlStatusWord). Interfaces other
    /// than the UI must never see a raw NE value.
    nonisolated static func wireStatus(_ s: NEVPNStatus) -> String {
        switch s {
        case .invalid: ControlStatusWord.invalid
        case .disconnected: ControlStatusWord.disconnected
        case .connecting: ControlStatusWord.connecting
        case .connected: ControlStatusWord.connected
        case .reasserting: ControlStatusWord.reasserting
        case .disconnecting: ControlStatusWord.disconnecting
        @unknown default: ControlStatusWord.invalid
        }
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
                if kind == .openVPN {
                    // The secret inline blocks, and the reassembled configuration
                    // built from them once here rather than per view render. This is
                    // the ONLY keychain read on the path — see ovpnSecretsCache.
                    let secrets = KeychainCredentialStore.loadOVPNInlineSecrets(profile: id) ?? [:]
                    ovpnSecretsCache[id] = secrets
                    if let stored = proto?.providerConfiguration?["ovpn"] as? String {
                        ovpnTextCache[id] = secrets.isEmpty
                            ? OVPNSecretMaterial.stripMarkers(stored)
                            : OVPNSecretMaterial.merge(stored, secrets: secrets)
                    } else {
                        ovpnTextCache.removeValue(forKey: id)
                    }
                } else {
                    // Not an OpenVPN profile, so it has no inline material — and a
                    // stale entry from a previous kind would make `ovpnText(id:)`
                    // hand back something that is no longer stored.
                    ovpnSecretsCache.removeValue(forKey: id)
                    ovpnTextCache.removeValue(forKey: id)
                }
                if kind == .tailscale {
                    tailscaleConfigs[id] = TailscaleConfig.decode(from: proto?.providerConfiguration?["tailscale"] as? Data)
                }
                if kind == .proxyTunnel {
                    proxyTunnelConfigs[id] = ProxyTunnelConfig.decode(from: proto?.providerConfiguration?["proxytunnel"] as? Data)
                }
                if kind == .wireGuard {
                    wireGuardConfigs[id] = WireGuardConfig.decode(from: proto?.providerConfiguration?["wireguard"] as? Data)
                }
                if kind == .sshNetworkTunnel {
                    sshNetworkTunnelConfigs[id] = SSHNetworkTunnelConfig.decode(from: proto?.providerConfiguration?["sshnet"] as? Data)
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
            // Any profile still carrying its private key inline gets it moved into
            // the keychain now — write, read back, compare, and only then rewrite
            // the stored configuration. See migrateInlineOVPNSecrets() for why that
            // order is not negotiable. A no-op once every profile is clean.
            await migrateInlineOVPNSecrets()
            Self.log.log("loadAll: \(self.profiles.count) profile(s)")
            controlEventSink?(.profilesChanged)
        } catch {
            lastError = "load failed: \(error.localizedDescription)"
            Self.log.error("loadAll failed: \(error.localizedDescription, privacy: .public)")
        }
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

    // MARK: Stored state for the concern files (VPNController+*.swift)
    //
    // Swift extensions cannot hold stored properties, so the state each moved
    // concern works on stays here, keeping its original narrative comments.
    // Members that used to be `private` are internal now where the code that
    // touches them moved to another file — Swift's `private` is file-scoped.

    /// Observable mirror of the persisted Tailscale settings.
    var tailscaleConfigs: [String: TailscaleConfig] = [:]   // was private(set) — internal for the +File split
    /// Latest engine status per profile, refreshed while connected.
    var tailscaleStatuses: [String: TailscaleStatus] = [:]   // was private(set) — internal for the +File split
    @ObservationIgnored var tailscaleSignInWatch: [String: Task<Void, Never>] = [:]   // was private — internal for the +File split
    /// The sign-in page we sent this VPN's user to — observable, so the connect
    /// panel can offer to re-open it; cleared once the node registers.
    var tailscaleSignInURL: [String: URL] = [:]   // was private(set) — internal for the +File split

    /// Observable mirror of the persisted proxy-tunnel settings.
    var proxyTunnelConfigs: [String: ProxyTunnelConfig] = [:]   // was private(set) — internal for the +File split
    /// Latest engine status per profile, refreshed while connected.
    var proxyTunnelStatuses: [String: ProxyTunnelStatus] = [:]   // was private(set) — internal for the +File split

    /// Observable mirror of the persisted SSH Network Tunnel settings. No secrets
    /// in it: the password/key/certificate live in the keychain under
    /// "sshnet.<id>" (see VPNController+SSHNetworkTunnel).
    var sshNetworkTunnelConfigs: [String: SSHNetworkTunnelConfig] = [:]
    /// Latest engine status per profile, refreshed while connected — `sessionUp`
    /// is THE health signal here, because the tunnel's routes stay in place while
    /// the session reconnects (traffic is refused, never leaked).
    var sshNetworkTunnelStatuses: [String: SSHNetworkTunnelStatus] = [:]

    /// Observable mirror of the persisted (REDACTED — keys live in the
    /// keychain) WireGuard settings.
    var wireGuardConfigs: [String: WireGuardConfig] = [:]
    /// Latest engine status per profile, refreshed while connected — the
    /// last-handshake time is WireGuard's one health signal.
    var wireGuardStatuses: [String: WireGuardEngineStatus] = [:]

    /// Observable mirror of the persisted override blobs (see authConfigs).
    var overridesCache: [String: OpenVPNOverrides] = [:]   // was private(set) — internal for the +File split

    /// Observable mirror of the persisted "customrouting" blobs (see overridesCache). The
    /// filter is the tier-2 static form of the tier-3 intent-rewrite hooks; it is applied
    /// at the mediator capture seam by `installCustomRoutingHooks`.
    var customRoutingCache: [String: CustomRoutingProfile] = [:]   // was private(set) — internal for the +File split

    /// Observable mirror of the persisted "endpoints" blobs (see overridesCache).
    var endpointsCache: [String: VPNEndpointList] = [:]   // was private(set) — internal for the +File split

    /// Observable mirror of the persisted "uiprefs" blobs (see overridesCache).
    var uiPrefsCache: [String: VPNUIPrefs] = [:]   // was private(set) — internal for the +File split

    /// This launch's copy of each OpenVPN profile's secret inline blocks — the
    /// `<key>`/`<tls-crypt>` material that lives in the keychain instead of in
    /// `providerConfiguration` (see `OVPNSecretMaterial`). MEMORY ONLY, filled from
    /// the keychain by `loadAll()` because `ovpnText(id:)` is called from view
    /// bodies and a keychain round-trip per render is not acceptable. Never
    /// serialised, never logged, never sent anywhere except `startTunnel(options:)`.
    var ovpnSecretsCache: [String: [String: String]] = [:]

    /// Memo of the REASSEMBLED .ovpn per profile (stored text + the blocks above),
    /// so a body that calls `ovpnText(id:)` several times does not re-splice each
    /// time. Filled alongside `ovpnSecretsCache`; both are rebuilt by `loadAll()`,
    /// which every write path already ends with.
    var ovpnTextCache: [String: String] = [:]

    /// Profiles whose inline key material could NOT be moved into the keychain,
    /// id → what to tell the user. Populated by `migrateInlineOVPNSecrets()`; the
    /// point is that a failed migration is visible instead of silent, because the
    /// alternative to being visible is a private key sitting in the preferences
    /// with nobody aware of it.
    var inlineSecretMigrationFailures: [String: String] = [:]

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
    var persistTask: Task<Void, Never>?   // was private — internal for the +File split

    var credentialSources: [String: CredentialSource] = [:]   // was private(set) — internal for the +File split

    /// "Let me type it this time." The recovery path when a VPN's chosen password
    /// app isn't available: the stored choice is left completely alone, and this
    /// process-lifetime flag makes the readiness decision AND the connect path
    /// behave as if the source were manual — both, from one flag, so a Connect
    /// button can never be enabled on a promise the connect won't keep. Cleared
    /// by a successful typed connect and by any change to the source.
    private(set) var typedSignInOnce: Set<String> = []

    func setTypedSignInOnce(_ on: Bool, for id: String) {
        if on { typedSignInOnce.insert(id) } else { typedSignInOnce.remove(id) }
    }

    /// Observable mirror of the persisted auth blobs — reads MUST go through this
    /// (not the manager's providerConfiguration) so SwiftUI re-renders on change.
    var authConfigs: [String: VPNAuthConfig] = [:]   // was private(set) — internal for the +File split

    /// The profile's auth-nocache verdict (engine eval); true when unknown.
    var allowsPasswordSaveEvaluator: ((String) -> Bool)?

    /// Engine-eval facts the connect flow branches on (autologin, static
    /// challenge, userlocked username). Wired at launch like the evaluator
    /// above; nil (unwired, or no .ovpn) degrades to the plain-credentials path.
    var profileEvaluationProvider: ((String) -> ProfileEvaluation?)?

    /// Non-OpenVPN import handoff for the shared pipeline (main-window
    /// drop/Import, Finder open): `importProfile` sniffs the config's real
    /// kind with `ConfigDetector` first, and for anything but `.openVPN` hands
    /// the raw text off here instead of always trying the OpenVPN evaluator.
    /// Wired once at launch (SimpleVPNApp) to the same WireGuard/Cisco/native
    /// destinations ManageVPNsView's own importer already dispatches to; nil
    /// until wired (or in tests) degrades to the previous OpenVPN-only
    /// behaviour. Async because a WireGuard import creates a real NE profile.
    var otherEngineImportHandler: ((DetectedConfigKind, String, String) async -> ImportOutcome)?

    /// Profiles being reconnected to apply a settings change — the UI shows an
    /// "applying" state instead of collapsing to the disconnected/Connect layout.
    /// Refcounted (not a Set): overlapping applies on the same id must not clear
    /// each other's "Applying…" state early — the flag drops only when the last
    /// in-flight operation finishes.
    private var reconfiguringCounts: [String: Int] = [:]
    func beginReconfiguring(_ id: String) { reconfiguringCounts[id, default: 0] += 1 }   // was private — internal for the +File split
    func endReconfiguring(_ id: String) {   // was private — internal for the +File split
        guard let n = reconfiguringCounts[id] else { return }
        if n <= 1 { reconfiguringCounts[id] = nil } else { reconfiguringCounts[id] = n - 1 }
    }
    func isReconfiguring(_ id: String) -> Bool { (reconfiguringCounts[id] ?? 0) > 0 }

    var lastChange: [String: ChangeUndo] = [:]   // was private(set) — internal for the +File split

    /// Members that couldn't be started unattended (need a fresh OTP / manual
    /// entry) after a composition connect — surfaced so the user can finish them.
    var compositionNeedsAttention: [String] = []   // was private(set) — internal for the +File split

    /// Profiles currently paused. UI derives DotState.paused from this.
    var pausedProfiles: Set<String> = []   // was private(set) — internal for the +File split

    var routingRulesCache: [String: [RoutingRule]] = [:]   // was private — internal for the +File split

    // MARK: Guest networks a connect would capture (see VPNController+GuestNetworks)

    /// What virtualization is running on this Mac right now. A CLOSURE for the same
    /// reason the diagnostic report's is: `VirtualizationDiscovery` owns the answer
    /// and the control plane must not become a second scanner. Wired at launch
    /// (SimpleVPNApp); nil — unwired, or in a test that does not care — means the
    /// warning simply never fires, which is the safe direction.
    ///
    /// `async` and `@Sendable`, NOT a synchronous main-actor call. The scan is
    /// filesystem-bound and another process can stall it — done on the main actor it
    /// wedged the whole UI (see `VirtualizationDiscovery.snapshotOffMain`). A connect is
    /// the very last place that may block: the banner arriving a beat later is free,
    /// because the profile sits in `.connecting` for seconds.
    var virtualizationSnapshotProvider: (@Sendable () async -> VirtualizationSnapshot)?

    /// Per-profile guest networks THIS connect would swallow, with the divert rule
    /// that would keep each reachable. Written by
    /// `evaluateGuestNetworkCapture(id:)` when a connect starts and cleared when the
    /// session ends. Observable so the banner appears and disappears on its own.
    var guestNetworkCaptures: [String: [VirtualizationBypassOffer]] = [:]

    /// Profiles whose guest-network warning the user has waved away for this
    /// session. Not persisted: next connect is a new decision, and a permanently
    /// silenced warning about traffic being cut off is a warning that does not work.
    var dismissedGuestNetworkCaptures: Set<String> = []

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
    var resumeWatchdogs: [String: Task<Void, Never>] = [:]   // was private — internal for the +File split
    /// When each profile last reached .connected — feeds the OTP-reuse explanation.
    var lastConnectedAt: [String: Date] = [:]   // was private — internal for the +File split
    /// Per-profile pushed-proxy intent, sourced from the engine's ground-truth stats
    /// (the structured `proxy*` fields). The Proxy mediator reads it through
    /// `proxyProfiles` and re-arbitrates when it changes (see `fetchStats`). Absent ⇒
    /// nothing pushed. This is the OpenVPN per-kind capture from StateMediators.md.
    var pushedProxyIntents: [String: ProxyIntent] = [:]   // was private — internal for the +File split
    /// How long to allow for a resumed session to settle before calling it failed.
    /// Long enough to cover NE's re-negotiation, short enough to still feel like a
    /// reaction to what the user just clicked.
    static let resumeSettleWindow: Duration = .seconds(6)
    /// When each in-flight connect began, so a user-initiated cancel can tell
    /// "this isn't working" from "changed my mind".
    var connectAttemptStarted: [String: Date] = [:]   // was private — internal for the +File split
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
        controlEventSink?(.statusChanged(profile: id, status: Self.wireStatus(s)))
        // A connect that can never succeed (wrong network, unreachable
        // gateway) is retried by the engine for ever, so the app has to
        // impose its own deadline — otherwise "Connecting…" is permanent.
        if s == .connecting {
            self.startConnectWatchdog(id: id)
            // Is a running virtual machine's network about to be swallowed by this
            // tunnel? Asked HERE because every engine — OpenVPN, OpenConnect,
            // WireGuard, Tailscale, the two netstack kinds — arrives at .connecting,
            // and because a guest's subnet only exists while the guest is running, so
            // the interface list has to be read now. Silent unless there is something
            // to say; see VPNController+GuestNetworks.
            self.evaluateGuestNetworkCapture(id: id)
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
            // The session is over, so the guest-network warning has nothing to warn
            // about — and the dismissal goes with it, because the next connect is a
            // new decision taken against a freshly-read interface list.
            clearGuestNetworkCapture(id: id)
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

    func err(_ m: String) -> NSError {   // was private — internal for the +File split
        NSError(domain: "VPNController", code: 1, userInfo: [NSLocalizedDescriptionKey: m])
    }

    /// Thrown by config-mutating methods when MDM has locked configuration. The
    /// UI also disables the controls, but this is the real enforcement point —
    /// programmatic paths (Doctor fixes, undo) route through the same methods.
    static let configLocked = NSError(domain: "VPNController", code: 2,
        userInfo: [NSLocalizedDescriptionKey: "This connection's settings are locked by your organization."])
}
