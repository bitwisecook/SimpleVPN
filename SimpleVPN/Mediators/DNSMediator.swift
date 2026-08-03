// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
//  DNSMediator.swift
//  P2 of the three system-state mediators (Docs/StateMediators.md). The single
//  authority over the host's DNS: it captures each connected tunnel's DNS intent,
//  arbitrates one coherent split-DNS plan (via the pure `DNSArbiter`), and publishes
//  the effective resolver picture to the UI. An `SCStoreMonitor` on
//  `State:/Network/Global/DNS` + per-service DNS keys watches the real resolvers for
//  external drift and asks it to re-assert.
//
//  Applier note (tier-2, now REAL): the mediator is the literal sole writer of
//  per-tunnel DNS. It arbitrates the coherent split-DNS plan and pushes ONE
//  `DNSApplyRequest` PER PARTICIPANT over the `dns:apply:` IPC (Shared/DNSApply.swift):
//  the catch-all owner gets the default resolvers scoped to every lookup; each split
//  participant gets its resolvers scoped to only the domains it won. The engine bridge
//  stores the override and re-applies its captured tun settings LIVE (no reconnect) —
//  the DNS parallel of the proxy applier and the `gateway:full|split` route path. The
//  RECONNECT path survives ONLY as the fallback for engines with no live DNS applier
//  (proxy-tunnel / Tailscale re-establish DNS from their config on reconnect; native
//  kinds are OS-owned): those return no IPC ack, so the realizer re-pushes them by
//  reconnecting. The tier-3 per-flow resolver chains are the remaining P4 seam.
//
//  Concurrency: MainActor (it observes host NE state and reconnects through the host).
//  The SCDynamicStore monitor reads off-main and hops back here to publish.
//

import Foundation
import Observation
import SystemConfiguration
import os

// MARK: - Host seam (the live NE side, provided by VPNController)

/// One connected profile as the DNS mediator needs to see it, plus the DNS intent data
/// the host can source app-side. Built fresh each access so the mediator's computeds
/// stay observation-tracked against the host's `@Observable` profile list.
struct DNSProfileInfo: Sendable, Identifiable {
    let id: String
    let name: String
    let kind: VPNKind
    let connected: Bool
    let engaged: Bool
    let lastConnectedAt: Date?
    /// Best-effort DNS the host knows this tunnel pushes (resolvers/search/match).
    let resolvers: [String]
    let searchDomains: [String]
    let matchDomains: [String]
    /// It claims the catch-all (all lookups) — e.g. a full-tunnel with pushed resolvers.
    let wantsCatchAll: Bool
}

@MainActor
protocol DNSMediatorHost: AnyObject {
    /// Current profiles + their DNS intent, freshly projected.
    var dnsProfiles: [DNSProfileInfo] { get }
    /// The profile that owns the default route right now (== the Route mediator's
    /// `effectiveGatewayOwner`) — its DNS is the catch-all.
    var dnsDefaultOwner: String? { get }
    /// SOLE-WRITER apply: push ONE participant's arbitrated `NEDNSSettings` onto its
    /// live tunnel via the `dns:apply:` IPC (Docs/StateMediators.md › DNS applier).
    /// `request == nil`/empty clears the override (restore the captured/pushed DNS).
    /// Returns the engine's ack, or `nil` when there is no live DNS applier for this
    /// tunnel (native kinds have no NE session; proxy-tunnel / Tailscale can't hot-swap
    /// DNS) — the signal for the realizer to fall back to a reconnect re-assert.
    func dnsApply(_ request: DNSApplyRequest?, to id: String) async -> String?
    /// Reconnect a profile (the fallback re-assert lever — re-establishes its pushed
    /// DNS for engines with no live applier).
    func dnsReconnect(id: String) async
}

// MARK: - Realizer (stage 3 — the sole-writer seam)

/// Realizes a DNS plan as the SOLE WRITER (Docs/StateMediators.md › DNS applier). DNS
/// arbitrates per-domain, so it applies ONE `DNSApplyRequest` per participant: the
/// catch-all owner gets the default resolvers, each split participant its scoped
/// resolvers. Engines with a live applier (openvpn3, in-process OpenConnect) take the
/// override live via `dns:apply:`; engines that return no ack (proxy-tunnel / Tailscale,
/// native) fall back to a reconnect so their config-driven DNS is re-established. The
/// tier-3 resolver-chain backing conforms here the same way — policy flips it with no
/// change to the mediator or UI.
@MainActor
final class DNSRealizer: MediatorRealizer {
    typealias Plan = DNSPlan

    weak var host: DNSMediatorHost?
    private let log: Logger
    /// The last plan this realizer wrote — so it can clear a participant that dropped
    /// out of the plan and skip an unchanged decision (idempotent, mirrors ProxyRealizer).
    private var lastPlan: DNSPlan?

    init(host: DNSMediatorHost?, log: Logger) {
        self.host = host
        self.log = log
    }

    /// A session ended / the mediator reset — forget what we wrote (a fresh reconcile
    /// re-applies from scratch).
    func forgetOwner() { lastPlan = nil }

    /// SOLE WRITER: realize the arbitrated split-DNS on EVERY participant via
    /// `dns:apply:`. STRIP participants that left the plan (clear their override) →
    /// SET the current per-participant requests. An engine with no live applier returns
    /// no ack; we then reconnect it so its config-pushed DNS is re-established.
    func realize(_ plan: DNSPlan, from previous: DNSPlan?) async {
        let prior = lastPlan
        guard plan != prior else { return }
        lastPlan = plan

        let requests = plan.applyRequests()
        // Clear any participant that dropped out of the plan (owner moved, or split
        // domain reassigned), so a stale engine never keeps asserting DNS the plan no
        // longer wants.
        if let prior {
            let gone = Set(prior.applyRequests().keys).subtracting(requests.keys)
            for engine in gone.sorted() {
                log.log("DNS: clearing \(engine, privacy: .public)'s override (left the plan)")
                _ = await host?.dnsApply(nil, to: engine)
            }
        }
        // Apply the current decision to each participant.
        for engine in requests.keys.sorted() {
            let request = requests[engine]!
            let ack = await host?.dnsApply(request.isEmpty ? nil : request, to: engine)
            if ack == nil {
                // No live DNS applier for this tunnel (proxy-tunnel / Tailscale / native):
                // fall back to the reconnect re-assert lever so its pushed DNS is
                // re-established from its own config.
                log.log("DNS: no live applier for \(engine, privacy: .public) — reconnecting to re-push resolvers")
                await host?.dnsReconnect(id: engine)
            } else {
                log.log("DNS: applied \(engine, privacy: .public)'s resolvers (\(request.isEmpty ? "clear" : (request.matchDomains == [""] ? "catch-all" : "split"), privacy: .public))")
            }
        }
    }
}

// MARK: - DNS mediator

@MainActor
@Observable
final class DNSMediator {

    private static let log = Logger(subsystem: "com.bragi0.SimpleVPN", category: "dns-mediator")

    @ObservationIgnored weak var host: DNSMediatorHost? {
        didSet { realizer.host = host }
    }
    @ObservationIgnored private lazy var realizer = DNSRealizer(host: host, log: Self.log)

    // MARK: Stage 1 — intent capture (the single hookable seam)

    /// Current per-engine DNS intents (inspectable; drives the published plan). The
    /// tier-3 `DNS_PUSHED` Tcl handler attaches at `intentHook` to rewrite an intent
    /// before arbitration — left clean here (no Tcl engine now).
    private(set) var intents: [String: DNSIntent] = [:]
    @ObservationIgnored var intentHook: MediatorIntentHook<DNSIntent>?
    /// The tier-3 `DNS_CHANGED` seam — fired after the monitor confirms external drift.
    @ObservationIgnored var driftHook: MediatorDriftHook<MediatorDriftEvent>?

    func submit(_ intent: DNSIntent, from engine: String) {
        var rewritten = intent
        intentHook?(&rewritten)
        intents[engine] = rewritten
    }
    func withdraw(engine: String) { intents[engine] = nil }

    // MARK: Stage 4 — drift monitor + published effective/drift state

    @ObservationIgnored private let monitor: SCStoreMonitor<DNSObservation>
    /// The most recent CONFIRMED external DNS drift event. Published for the UI.
    private(set) var lastDrift: MediatorDriftEvent?
    /// The resolvers the OS is actually using right now (from SCDynamicStore). Published.
    private(set) var observedResolvers: [String] = []
    private(set) var observedSearchDomains: [String] = []
    @ObservationIgnored private var lastApplyAt: Date?
    private let suppressWindow: TimeInterval = 3

    init(monitor: SCStoreMonitor<DNSObservation>? = nil) {
        self.monitor = monitor ?? SCStoreMonitor(
            label: "com.bragi0.SimpleVPN.DNSMonitor",
            keys: ["State:/Network/Global/DNS"],
            patterns: ["State:/Network/Service/.*/DNS"],
            snapshot: { DNSMediator.readSystemDNS() })
    }

    // MARK: - Reads / published effective state

    private func info(_ id: String) -> DNSProfileInfo? {
        host?.dnsProfiles.first { $0.id == id }
    }

    /// Connected profiles that participate in DNS, most-recent-first.
    var participatingProfiles: [DNSProfileInfo] {
        (host?.dnsProfiles ?? [])
            .filter { $0.connected && DNSParticipation.classify($0.kind).participatesInSplitDNS }
            .sorted { a, b in
                let ta = a.lastConnectedAt ?? .distantPast
                let tb = b.lastConnectedAt ?? .distantPast
                if ta != tb { return ta > tb }
                return a.name.localizedCaseInsensitiveCompare(b.name) == .orderedAscending
            }
    }

    /// Why a connected profile does not participate in split-DNS (nil ⇒ it does, or
    /// isn't connected). Surfaced so no kind is silently dropped.
    func participationReason(for id: String) -> String? {
        guard let info = info(id), info.connected else { return nil }
        switch DNSParticipation.classify(info.kind) {
        case .full: return nil
        case .limited: return "\(info.name) uses OS-managed DNS, fixed at connect."
        case .none: return "\(info.name) is a proxy with no DNS of its own."
        case .unsupported: return "\(info.name) can't be controlled here (engine not built)."
        }
    }

    func name(for id: String?) -> String? {
        guard let id else { return nil }
        return info(id)?.name
    }

    /// The published desired split-DNS plan (drives the Network-Tools panel + tests).
    var plan: DNSPlan {
        DNSArbiter.plan(intents: Array(intents.values),
                        policy: DNSPolicy(defaultOwner: host?.dnsDefaultOwner))
    }

    /// Effective catch-all owner id (the tunnel whose DNS serves all lookups), if any.
    var effectiveCatchAllOwner: String? { plan.catchAllOwner }

    // MARK: - Intent refresh (keep captured intents current)

    /// Rebuild intents from the live profiles through the capture seam.
    private func refreshIntents() {
        let live = (host?.dnsProfiles ?? [])
            .filter { $0.connected && DNSParticipation.classify($0.kind).participatesInSplitDNS }
        let liveIDs = Set(live.map(\.id))
        for gone in intents.keys where !liveIDs.contains(gone) { withdraw(engine: gone) }
        for info in live {
            submit(DNSIntent(engine: info.id, resolvers: info.resolvers,
                             searchDomains: info.searchDomains, matchDomains: info.matchDomains,
                             wantsCatchAll: info.wantsCatchAll, egress: nil,
                             connectedAt: info.lastConnectedAt),
                   from: info.id)
        }
    }

    // MARK: - Reconcile / re-assert

    /// Recompute the coherent plan and (tier-2) re-establish the catch-all owner's DNS.
    @ObservationIgnored private var reconcileTask: Task<Void, Never>?
    func reconcile() {
        refreshIntents()
        let plan = self.plan
        lastApplyAt = Date()   // open the suppress window: any resulting change is ours
        reconcileTask = Task { [weak self] in
            await self?.realizer.realize(plan, from: nil)
        }
    }

    /// Re-assert desired DNS on demand (the Network-Tools "Re-assert" action).
    func reassertNow() { reconcile() }

    // MARK: - Status hooks (from the host's NE observer)

    func handleStatusChange(id: String, connected: Bool, disconnected: Bool) {
        if connected {
            refreshIntents()
            // No forced reconnect on a fresh connect — the engine just pushed its DNS.
            // Sample the observed resolvers so the UI reflects reality promptly.
            observeNow()
        } else if disconnected {
            withdraw(engine: id)
            realizer.forgetOwner()
            observeNow()
        }
    }

    // MARK: - Drift monitor lifecycle + handling

    func startMonitoring() {
        observeNow()
        do {
            try monitor.start { [weak self] observed in
                Task { @MainActor [weak self] in self?.handleObserved(observed) }
            }
        } catch {
            Self.log.error("DNS SCDynamicStore monitor failed to start: \(String(describing: error), privacy: .public)")
        }
    }

    func stopMonitoring() { monitor.stop() }

    /// Snapshot the current system DNS immediately (start + on status change), so the
    /// published effective state isn't blank until the first external change.
    private func observeNow() {
        let obs = Self.readSystemDNS()
        observedResolvers = obs.resolvers
        observedSearchDomains = obs.searchDomains
    }

    private func handleObserved(_ observed: DNSObservation) {
        observedResolvers = observed.resolvers
        observedSearchDomains = observed.searchDomains
        let suppressed = lastApplyAt.map { Date().timeIntervalSince($0) < suppressWindow } ?? false
        let expected = plan.systemResolvers
        let action = DNSDriftDecision.action(expected: expected, observed: observed.resolvers,
                                             withinSuppressWindow: suppressed)
        guard action == .reassert else { return }
        let event = MediatorDriftEvent(summary: driftSummary(observed), reasserted: true)
        lastDrift = event
        driftHook?(event)
        Self.log.log("external DNS drift: \(event.summary, privacy: .public) — re-asserting")
        reconcile()
    }

    private func driftSummary(_ observed: DNSObservation) -> String {
        let owner = name(for: effectiveCatchAllOwner) ?? "the VPN"
        let shown = observed.resolvers.prefix(2).joined(separator: ", ")
        if observed.resolvers.isEmpty {
            return "System DNS was cleared externally; expected \(owner)'s resolvers."
        }
        return "System resolvers changed externally (now \(shown)); expected \(owner)'s."
    }

    // MARK: - System DNS snapshot (off-main safe; used by the monitor + observeNow)

    /// Read the resolvers + search domains the OS is currently using from the global
    /// DNS dictionary. `nonisolated` + `@Sendable`-callable so the SC monitor can invoke
    /// it on its dispatch queue.
    nonisolated static func readSystemDNS() -> DNSObservation {
        guard let store = SCDynamicStoreCreate(nil, "SimpleVPN.DNSMonitor.read" as CFString, nil, nil),
              let dns = SCDynamicStoreCopyValue(store, "State:/Network/Global/DNS" as CFString) as? [String: Any]
        else { return DNSObservation(resolvers: [], searchDomains: []) }
        let servers = dns["ServerAddresses"] as? [String] ?? []
        let search = dns["SearchDomains"] as? [String] ?? []
        return DNSObservation(resolvers: servers, searchDomains: search)
    }
}
