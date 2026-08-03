// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
//  ProxyMediator.swift
//  P3 of the three system-state mediators (Docs/StateMediators.md). The single
//  authority over the host's system proxy: it captures each connected tunnel's proxy
//  intent, arbitrates the ONE system-proxy decision (via the pure `ProxyArbiter`), and
//  publishes the effective proxy picture to the UI. An `SCStoreMonitor` on
//  `State:/Network/Global/Proxies` + per-service proxy keys watches the real system
//  proxy for external drift and asks it to re-assert.
//
//  Applier note (tier-2, honest): today the SOCKS kinds set the system proxy through
//  `SubprocessTunnelManager` (`networksetup`), and pushed proxies ride each engine's
//  `NEProxySettings` at establish. The re-assert lever the app holds now is to ask the
//  host to re-apply the owner's proxy (re-point / reconnect). The per-flow per-egress
//  PAC (JavaScriptCore) applier is the P3-tier-3 seam — left clean here, like the Route
//  mediator's `PBRRealizer`. Arbitration, drift detection and the effective publish are
//  the real tier-2 deliverables.
//
//  Concurrency: MainActor. The SCDynamicStore monitor reads off-main and hops back here.
//

import Foundation
import Observation
import SystemConfiguration
import os

// MARK: - Host seam (the live NE side, provided by VPNController)

struct ProxyProfileInfo: Sendable, Identifiable {
    let id: String
    let name: String
    let kind: VPNKind
    let connected: Bool
    let engaged: Bool
    let lastConnectedAt: Date?
    /// The proxy this tunnel provides/pushes, as the host can source it app-side.
    let mode: ProxyIntent.Mode
    /// Full realization detail for the tier-2 NEProxySettings applier (per-scheme
    /// endpoints + bypass). Defaults empty for kinds that push nothing structured.
    var manual: ProxyManual? = nil
    var bypass: [String] = []
    var excludeSimpleHostnames: Bool = false
    var authSource: String? = nil
}

@MainActor
protocol ProxyMediatorHost: AnyObject {
    var proxyProfiles: [ProxyProfileInfo] { get }
    /// The profile that owns the default route right now — its proxy is preferred.
    var proxyDefaultOwner: String? { get }
    /// Re-apply the owner's proxy (tier-2 re-assert lever: re-point / reconnect).
    func proxyReassert(owner: String) async
    /// SOLE-WRITER apply: push the arbitrated system proxy onto ONE tunnel's live
    /// `NEProxySettings` via the `proxy:apply:` IPC (Docs/StateMediators.md › P3
    /// applier). `request == nil` clears it. Returns the engine's ack (nil = no NE
    /// session — e.g. a subprocess SOCKS kind that sets the proxy its own way).
    func proxyApply(_ request: ProxyApplyRequest?, to id: String) async -> String?
}

// MARK: - Realizer (stage 3 — the sole-writer seam)

@MainActor
final class ProxyRealizer: MediatorRealizer {
    typealias Plan = ProxyPlan

    weak var host: ProxyMediatorHost?
    private let log: Logger
    /// The last plan this realizer wrote — so it can clear a previous owner's proxy
    /// when ownership moves, and skip an unchanged decision (idempotent).
    private var lastPlan: ProxyPlan?

    /// Resolve a plan's `authSource` keychain REF to the stored proxy sign-in, HERE
    /// (app-side, at realize time) — the intent/plan stay credential-free and the
    /// secret only ever rides the in-memory `proxy:apply:` IPC. Injectable so tests
    /// exercise the auth path without a real keychain.
    var authResolver: @MainActor (String) -> KeychainCredentialStore.CustomRoutingProxyAuth? = { source in
        guard let id = ProxyAuthSourceRef.profileID(from: source) else { return nil }
        return KeychainCredentialStore.loadCustomRoutingProxyAuth(profile: id)
    }
    /// What the last realized apply reported back — the mediator folds these into the
    /// published `ProxyAuthAdvisory` so "this proxy wants auth we couldn't inject"
    /// is surfaced, never silent.
    private(set) var lastAck: String?
    private(set) var lastCredentialsFound = false

    init(host: ProxyMediatorHost?, log: Logger) {
        self.host = host
        self.log = log
    }

    /// The session ended — forget what we wrote (a fresh connect re-applies).
    func forget(id: String) { if lastPlan?.owner == id { lastPlan = nil } }

    /// SOLE WRITER: realize the arbitrated proxy on the OWNER egress via `proxy:apply:`.
    /// STRIP-old → SET-new when ownership moves, so a stale owner never keeps asserting
    /// a proxy the plan no longer wants. `previous` is unused (we track `lastPlan`),
    /// matching how `MultiTunnelRealizer` owns its applied-state cache.
    func realize(_ plan: ProxyPlan, from previous: ProxyPlan?) async {
        let prior = lastPlan
        guard plan != prior else { return }
        lastPlan = plan

        // Ownership moved (or dropped): clear the old owner's proxy first.
        if let old = prior?.owner, old != plan.owner {
            log.log("proxy: clearing \(old, privacy: .public)'s system proxy (owner changed)")
            _ = await host?.proxyApply(nil, to: old)
        }
        guard let owner = plan.owner, plan.providesProxy else {
            // No proxy wanted: clear the current owner too (if any).
            if let owner = prior?.owner, prior?.owner == plan.owner {
                _ = await host?.proxyApply(nil, to: owner)
            }
            lastAck = nil
            lastCredentialsFound = false
            return
        }
        // Resolve the sign-in REF (if any) to real credentials now, and only now —
        // they live on the wire payload for the length of this one IPC. Never logged;
        // the log line carries a with-auth/no-auth flag at most.
        var request = plan.applyRequest
        lastCredentialsFound = false
        if let source = plan.authSource, let auth = authResolver(source) {
            lastCredentialsFound = true
            request = plan.applyRequest(username: auth.username, password: auth.password)
        }
        log.log("proxy: applying \(owner, privacy: .public)'s proxy as the system proxy (\(request.isEmpty ? "clear" : "set", privacy: .public)\(plan.authSource != nil ? (self.lastCredentialsFound ? ", with auth" : ", auth MISSING") : "", privacy: .public))")
        lastAck = await host?.proxyApply(request.isEmpty ? nil : request, to: owner)
    }
}

// MARK: - Proxy mediator

@MainActor
@Observable
final class ProxyMediator {

    private static let log = Logger(subsystem: "com.bragi0.SimpleVPN", category: "proxy-mediator")

    @ObservationIgnored weak var host: ProxyMediatorHost? {
        didSet { realizer.host = host }
    }
    @ObservationIgnored private lazy var realizer = ProxyRealizer(host: host, log: Self.log)

    // MARK: Stage 1 — intent capture (the single hookable seam)

    private(set) var intents: [String: ProxyIntent] = [:]
    @ObservationIgnored var intentHook: MediatorIntentHook<ProxyIntent>?
    @ObservationIgnored var driftHook: MediatorDriftHook<MediatorDriftEvent>?

    func submit(_ intent: ProxyIntent, from engine: String) {
        var rewritten = intent
        intentHook?(&rewritten)
        intents[engine] = rewritten
    }
    func withdraw(engine: String) { intents[engine] = nil }

    // MARK: Stage 4 — drift monitor + published effective/drift state

    @ObservationIgnored private let monitor: SCStoreMonitor<ProxyObservation>
    private(set) var lastDrift: MediatorDriftEvent?
    /// The system proxy the OS actually has right now (from SCDynamicStore). Published.
    private(set) var observed: ProxyObservation = .none
    @ObservationIgnored private var lastApplyAt: Date?
    private let suppressWindow: TimeInterval = 3

    init(monitor: SCStoreMonitor<ProxyObservation>? = nil) {
        self.monitor = monitor ?? SCStoreMonitor(
            label: "com.bragi0.SimpleVPN.ProxyMonitor",
            keys: ["State:/Network/Global/Proxies"],
            patterns: ["State:/Network/Service/.*/Proxies"],
            snapshot: { ProxyMediator.readSystemProxy() })
    }

    // MARK: - Reads / published effective state

    private func info(_ id: String) -> ProxyProfileInfo? {
        host?.proxyProfiles.first { $0.id == id }
    }

    /// Connected profiles that participate in the proxy decision, most-recent-first.
    var participatingProfiles: [ProxyProfileInfo] {
        (host?.proxyProfiles ?? [])
            .filter { $0.connected && ProxyParticipation.classify($0.kind).participates }
            .sorted { a, b in
                let ta = a.lastConnectedAt ?? .distantPast
                let tb = b.lastConnectedAt ?? .distantPast
                if ta != tb { return ta > tb }
                return a.name.localizedCaseInsensitiveCompare(b.name) == .orderedAscending
            }
    }

    /// Why a connected profile doesn't participate in the proxy decision (nil ⇒ it does).
    func participationReason(for id: String) -> String? {
        guard let info = info(id), info.connected else { return nil }
        switch ProxyParticipation.classify(info.kind) {
        case .provider: return nil
        case .egressItself: return "\(info.name) is itself a proxy egress; it re-dials flows directly."
        case .limited: return "\(info.name) uses OS-managed proxy settings, fixed at connect."
        case .none: return "\(info.name) doesn't use a proxy."
        case .unsupported: return "\(info.name) can't be controlled here (engine not built)."
        }
    }

    func name(for id: String?) -> String? {
        guard let id else { return nil }
        return info(id)?.name
    }

    /// The published desired system-proxy plan (drives the Network-Tools panel + tests).
    var plan: ProxyPlan {
        ProxyArbiter.plan(intents: Array(intents.values),
                          policy: ProxyPolicy(defaultOwner: host?.proxyDefaultOwner))
    }

    var effectiveProxyOwner: String? { plan.owner }

    /// Where the effective proxy's SIGN-IN landed (nil when it doesn't need one):
    /// applied with the proxy, or not injectable and why — PAC, missing keychain row,
    /// or a proxy applied outside our control that we only observe. Published so the
    /// Network-Tools proxy card can say it instead of failing auth silently.
    private(set) var authAdvisory: ProxyAuthAdvisory?

    /// A human one-liner for the effective system proxy (for compact UI surfaces).
    var effectiveProxyDescription: String {
        switch plan.mode {
        case .none: return "Direct (no proxy)"
        case .manual(let e): return e.display
        case .pac(let url): return "PAC \(url)"
        }
    }

    // MARK: - Intent refresh

    private func refreshIntents() {
        let live = (host?.proxyProfiles ?? [])
            .filter { $0.connected && ProxyParticipation.classify($0.kind).participates }
        let liveIDs = Set(live.map(\.id))
        for gone in intents.keys where !liveIDs.contains(gone) { withdraw(engine: gone) }
        for info in live {
            submit(ProxyIntent(engine: info.id, mode: info.mode, egress: nil,
                               connectedAt: info.lastConnectedAt,
                               manual: info.manual, bypass: info.bypass,
                               excludeSimpleHostnames: info.excludeSimpleHostnames,
                               authSource: info.authSource),
                   from: info.id)
        }
    }

    // MARK: - Reconcile / re-assert

    @ObservationIgnored private var reconcileTask: Task<Void, Never>?
    func reconcile() {
        refreshIntents()
        let plan = self.plan
        lastApplyAt = Date()
        reconcileTask = Task { [weak self] in
            guard let self else { return }
            await self.realizer.realize(plan, from: nil)
            // Fold the realizer's report into the published auth advisory — a proxy
            // that needs a sign-in we couldn't attach must be said, not dropped.
            let advisory = ProxyAuthAdvisory.decide(plan: plan,
                                                    credentialsFound: self.realizer.lastCredentialsFound,
                                                    ack: self.realizer.lastAck)
            if advisory != self.authAdvisory, let advisory, advisory != .applied {
                Self.log.log("proxy auth: \(String(describing: advisory), privacy: .public)")
            }
            self.authAdvisory = advisory
        }
    }

    func reassertNow() { reconcile() }

    // MARK: - Status hooks

    func handleStatusChange(id: String, connected: Bool, disconnected: Bool) {
        if connected {
            reconcile()
            observeNow()
        } else if disconnected {
            withdraw(engine: id)
            realizer.forget(id: id)
            reconcile()          // recompute + clear/reassign the system proxy
            observeNow()
        }
    }

    /// Fold the engine's ground-truth pushed proxy (from a stats sample) into the
    /// mediator: the app updates its per-profile proxy cache first (so `proxyProfiles`
    /// reflects it), then calls this to re-arbitrate and apply — but ONLY when the
    /// decision actually changes, so the ~1 Hz stats poll doesn't spam `proxy:apply`.
    /// Mirrors `RouteMediator.noteEngineDefaultOwned`.
    func noteEnginePushedProxy(changed: Bool) {
        guard changed else { return }
        reconcile()
    }

    // MARK: - Drift monitor lifecycle + handling

    func startMonitoring() {
        observeNow()
        do {
            try monitor.start { [weak self] obs in
                Task { @MainActor [weak self] in self?.handleObserved(obs) }
            }
        } catch {
            Self.log.error("Proxy SCDynamicStore monitor failed to start: \(String(describing: error), privacy: .public)")
        }
    }

    func stopMonitoring() { monitor.stop() }

    private func observeNow() { observed = Self.readSystemProxy() }

    private func handleObserved(_ obs: ProxyObservation) {
        observed = obs
        let suppressed = lastApplyAt.map { Date().timeIntervalSince($0) < suppressWindow } ?? false
        let action = ProxyDriftDecision.action(expected: plan, observed: obs,
                                               withinSuppressWindow: suppressed)
        guard action == .reassert else { return }
        let event = MediatorDriftEvent(summary: driftSummary(obs), reasserted: plan.providesProxy)
        lastDrift = event
        driftHook?(event)
        Self.log.log("external proxy drift: \(event.summary, privacy: .public)")
        if plan.providesProxy { reconcile() }
    }

    private func driftSummary(_ obs: ProxyObservation) -> String {
        if plan.providesProxy {
            let owner = name(for: effectiveProxyOwner) ?? "the VPN"
            if !obs.enabled { return "The system proxy was cleared externally; expected \(owner)'s." }
            return "The system proxy changed externally; expected \(owner)'s."
        }
        if let e = obs.endpoint { return "A system proxy (\(e.display)) was set externally." }
        return "A system proxy was set externally."
    }

    // MARK: - System proxy snapshot (off-main safe)

    /// Read the current system proxy from the global Proxies dictionary. `nonisolated` +
    /// `@Sendable`-callable so the SC monitor can invoke it on its dispatch queue.
    nonisolated static func readSystemProxy() -> ProxyObservation {
        guard let store = SCDynamicStoreCreate(nil, "SimpleVPN.ProxyMonitor.read" as CFString, nil, nil),
              let p = SCDynamicStoreCopyValue(store, "State:/Network/Global/Proxies" as CFString) as? [String: Any]
        else { return .none }

        func int(_ key: String) -> Int { (p[key] as? NSNumber)?.intValue ?? 0 }
        func str(_ key: String) -> String? { p[key] as? String }

        if int("ProxyAutoConfigEnable") == 1, let url = str("ProxyAutoConfigURLString") {
            return ProxyObservation(enabled: true, endpoint: nil, pacURL: url)
        }
        // Prefer SOCKS (our SSH kinds), then HTTPS, then HTTP.
        if int("SOCKSEnable") == 1, let host = str("SOCKSProxy") {
            return ProxyObservation(enabled: true,
                                    endpoint: ProxyEndpoint(scheme: .socks, host: host, port: int("SOCKSPort")),
                                    pacURL: nil)
        }
        if int("HTTPSEnable") == 1, let host = str("HTTPSProxy") {
            return ProxyObservation(enabled: true,
                                    endpoint: ProxyEndpoint(scheme: .https, host: host, port: int("HTTPSPort")),
                                    pacURL: nil)
        }
        if int("HTTPEnable") == 1, let host = str("HTTPProxy") {
            return ProxyObservation(enabled: true,
                                    endpoint: ProxyEndpoint(scheme: .http, host: host, port: int("HTTPPort")),
                                    pacURL: nil)
        }
        return .none
    }
}
