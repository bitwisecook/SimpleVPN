// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
//  RouteMediator.swift
//  P1 of the three system-state mediators (Docs/StateMediators.md). The single
//  authority over the host's DEFAULT ROUTE: it captures each connected tunnel's route
//  intent, arbitrates the ≤1-default-owner plan (via the pure `RouteArbiter`/
//  `GatewayPolicy`), drives the `MultiTunnelRealizer` (the existing gateway IPC), and
//  publishes the EFFECTIVE (engine-observed) state to the UI. A `PFRouteMonitor`
//  watches the real routing table for external drift and asks it to re-assert.
//
//  This is a BEHAVIOR-PRESERVING extraction of the gateway logic that used to live
//  inline in `VPNController` (the RC1–RC5 fix). `VPNController` now delegates here and
//  supplies the live NE side through `RouteMediatorHost`. `GatewayPolicy` stays the
//  pure role/invariant math; nothing about the invariant changed.
//
//  Concurrency: MainActor (it observes and drives NE state through the host). The
//  monitor reads PF_ROUTE off-main and hops back here to publish.
//

import Foundation
import Observation
import os

// MARK: - Host seam (the live NE side, provided by VPNController)

/// A snapshot of one saved VPN as the Route mediator needs to see it. Built by the
/// host from its live NE state each access, so the mediator's computeds stay
/// observation-tracked against the host's `@Observable` profile list.
struct RouteProfileInfo: Sendable, Identifiable {
    let id: String
    let name: String
    let kind: VPNKind
    let connected: Bool        // NEVPNStatus == .connected
    let engaged: Bool          // connected/connecting/reasserting (owns routes early)
    let lastConnectedAt: Date? // recency, for the auto-promotion tiebreak
    let tailscaleHasExitNode: Bool
}

/// What the mediator needs the host (VPNController) to do on the live NE side. Kept
/// narrow: reads via `routeProfiles`, and the four effectful primitives.
@MainActor
protocol RouteMediatorHost: AnyObject {
    /// Current profiles, freshly projected (reads the host's observable state).
    var routeProfiles: [RouteProfileInfo] { get }
    /// Send the generic gateway IPC to a running packet-tunnel session. Returns the
    /// engine's ack ("ok" / "needs-reconnect" / error / nil when no session).
    func routeSendGateway(full: Bool, to id: String) async -> String?
    /// Apply gateway ownership to a Tailscale profile via its exit-node prefs path.
    /// Returns nil on success, else a problem string.
    func routeApplyTailscaleGateway(full: Bool, to id: String) async -> String?
    /// Reconnect a profile (the needs-reconnect demotion fallback — no in-process
    /// engine needs it now that OpenConnect demotes live; kept for future engines).
    func routeReconnect(id: String) async
    /// Trigger a stats poll; returns the engine's ground-truth `effectiveDefaultOwned`
    /// (nil when not yet sampled). The poll also feeds `noteEngineDefaultOwned`.
    @discardableResult func routeSampleEffectiveOwned(id: String) async -> Bool?
    /// Config desire — redirect-gateway / exit node / SSL default. Only read when
    /// (re)building intents, so its per-profile cost stays off the hot read paths.
    func routeWantsFullTunnel(id: String) -> Bool
    /// The specific CIDRs a tunnel carries besides any default (for intent fidelity).
    func routeAdvertisedPrefixes(id: String) -> [String]
}

// MARK: - Realizer (stage 3 — the sole writer)

/// The outcome of writing one gateway role to one profile.
enum RouteApplyOutcome: Sendable, Equatable {
    case applied         // the engine took it (cache updated)
    case skipped         // already applied, or not applicable (e.g. tailscale w/o exit)
    case needsReconnect  // engine can't re-apply live — reconnect to apply (fallback;
                         // no in-process engine reports this now that OpenConnect
                         // demotes live like openvpn3)
    case failed          // not acked
}

/// Realizes a route plan through TODAY's backing: per-tunnel gateway IPC + the native
/// manager + the Tailscale exit-node prefs path (Docs/StateMediators.md › Applier).
/// It owns the applied-role cache — the single source of truth for "what has actually
/// been pushed" — seeded from ENGINE REALITY (never a client-.ovpn grep), so its
/// idempotency guard can never suppress a genuinely-needed gateway:split/full (RC1).
///
/// The `PBRRealizer` (P4) will conform to `MediatorRealizer` the same way and the
/// policy will flip the backing with no change to the mediator or the UI — that seam
/// is deliberately left clean here (no PBR implementation now).
@MainActor
final class MultiTunnelRealizer: MediatorRealizer {
    typealias Plan = RoutePlan

    weak var host: RouteMediatorHost?
    private let log: Logger

    /// The role last successfully applied to each profile's extension. SEEDED FROM
    /// ENGINE REALITY (`seed`), never a text guess. A nil (unknown) entry always
    /// sends: the IPC is idempotent engine-side, and never-skip is the safe direction
    /// for the ≤1-owner invariant.
    private var appliedRole: [String: GatewayRole] = [:]

    init(host: RouteMediatorHost?, log: Logger) {
        self.host = host
        self.log = log
    }

    /// Seed/refresh the cache from the engine's ground-truth ownership.
    func seed(id: String, owned: Bool) { appliedRole[id] = owned ? .full : .split }
    /// The engine's session ended — forget what we thought was applied.
    func forget(id: String) { appliedRole[id] = nil }
    /// Read-back for the mediator's applied-role introspection.
    func applied(_ id: String) -> GatewayRole? { appliedRole[id] }

    /// Write ONE role to ONE profile. The idempotency guard, the tailscale-vs-generic
    /// split, and the needs-reconnect signal all live here — this is the sole writer.
    func apply(_ role: GatewayRole, to id: String, kind: VPNKind,
               hasExitNode: Bool) async -> RouteApplyOutcome {
        guard appliedRole[id] != role else { return .skipped }

        if kind == .tailscale {
            if role == .full, !hasExitNode { return .skipped }   // not actually capable; leave as-is
            if let problem = await host?.routeApplyTailscaleGateway(full: role == .full, to: id) {
                log.error("gateway \(role.rawValue, privacy: .public) (tailscale) failed for \(id, privacy: .public): \(problem, privacy: .public)")
                return .failed
            }
            appliedRole[id] = role
            return .applied
        }

        let reply = await host?.routeSendGateway(full: role == .full, to: id)
        switch reply {
        case "ok":
            appliedRole[id] = role
            return .applied
        case "needs-reconnect":
            log.log("gateway \(role.rawValue, privacy: .public) needs reconnect for \(id, privacy: .public)")
            return .needsReconnect
        default:
            log.error("gateway \(role.rawValue, privacy: .public) not acked for \(id, privacy: .public): \(reply ?? "nil", privacy: .public)")
            return .failed
        }
    }

    /// Realize a whole plan in the safe STRIP-old → ADD-new order. The mediator uses
    /// `apply` directly (it needs each outcome for the needs-reconnect path); this
    /// exists to satisfy `MediatorRealizer` and for callers that only want the plan
    /// driven with no per-step handling.
    func realize(_ plan: RoutePlan, from previous: RoutePlan?) async {
        for step in plan.orderedApplication {
            switch step {
            case .split(let id): _ = await apply(.split, to: id, kind: .openVPN, hasExitNode: false)
            case .full(let id):  _ = await apply(.full, to: id, kind: .openVPN, hasExitNode: false)
            }
        }
    }
}

// MARK: - Route mediator

@MainActor
@Observable
final class RouteMediator {

    private static let log = Logger(subsystem: "com.bragi0.SimpleVPN", category: "route-mediator")

    @ObservationIgnored weak var host: RouteMediatorHost? {
        didSet { realizer.host = host }
    }
    @ObservationIgnored private lazy var realizer = MultiTunnelRealizer(host: host, log: Self.log)

    // MARK: Stage 1 — intent capture (the single hookable seam)

    /// Current per-engine route intents (inspectable; drives the published plan). The
    /// tier-3 `ROUTE_ADVERTISED` Tcl handler attaches at `intentHook` to rewrite an
    /// intent before arbitration — left clean here (no Tcl engine now).
    private(set) var intents: [String: RouteIntent] = [:]
    @ObservationIgnored var intentHook: MediatorIntentHook<RouteIntent>?
    /// The tier-3 `ROUTE_CHANGED` seam: fired after the monitor confirms external
    /// drift. Left clean (nil) now.
    @ObservationIgnored var driftHook: MediatorDriftHook<MediatorDriftEvent>?

    /// The one capture point. Records (hook-rewritten) intent for an engine.
    func submit(_ intent: RouteIntent, from engine: String) {
        var rewritten = intent
        intentHook?(&rewritten)
        intents[engine] = rewritten
    }
    func withdraw(engine: String) { intents[engine] = nil }

    // MARK: Persisted policy (the owner pick)

    /// Control-plane liveness: fired with the EFFECTIVE owner whenever the owner
    /// decision moves — explicit set, fallback promotion, drift re-assert. Installed
    /// by ControlPlaneDispatcher; feeds the one event stream every interface
    /// (CLI watch, intents, future Tcl) subscribes to.
    @ObservationIgnored var onOwnerChange: ((String?) -> Void)?

    /// The profile that owns the default route. nil ⇒ Direct. UI policy, not a secret.
    private(set) var defaultGatewayProfileID: String? {
        didSet { if oldValue != defaultGatewayProfileID { onOwnerChange?(effectiveGatewayOwner) } }
    }
    /// The user explicitly parked on Direct (vs. merely "unset").
    private var gatewayUserChoseDirect = false {
        didSet { if oldValue != gatewayUserChoseDirect { onOwnerChange?(effectiveGatewayOwner) } }
    }

    private static let gatewayDefaults = UserDefaults(suiteName: "group.com.bragi0.SimpleVPN")
    private static let gatewayOwnerKey = "gateway.ownerProfileID"
    private static let gatewayDirectKey = "gateway.userChoseDirect"

    /// The engine's GROUND-TRUTH default-route ownership per connected profile (from
    /// the stats IPC's `effectiveDefaultOwned`). Drives the traffic-path read-back and
    /// continuous desync self-healing. Absent ⇒ not yet sampled. Published.
    private(set) var engineDefaultOwned: [String: Bool] = [:]
    /// Profiles whose gateway role we still owe after a needs-reconnect reconnect.
    @ObservationIgnored private var gatewayPendingReassert: Set<String> = []
    @ObservationIgnored private var gatewayReconcileTask: Task<Void, Never>?

    // MARK: Stage 4 — drift monitor + published effective/drift state

    @ObservationIgnored private let monitor: PFRouteMonitor
    /// The most recent CONFIRMED external drift event (what changed + when + whether we
    /// re-asserted). Published for the Routes-window banner and Network-Tools panel.
    private(set) var lastDrift: MediatorDriftEvent?
    /// When we last wrote a gateway change — the suppress window that stops us
    /// re-asserting against our OWN NE-induced route churn.
    @ObservationIgnored private var lastApplyAt: Date?
    /// How long after our own write to ignore observed default-route changes.
    private let suppressWindow: TimeInterval = 3

    init(monitor: PFRouteMonitor = PFRouteMonitor()) {
        self.monitor = monitor
    }

    /// Load the persisted gateway pick. Called from the host's `loadAll`.
    func loadPreference() {
        defaultGatewayProfileID = Self.gatewayDefaults?.string(forKey: Self.gatewayOwnerKey)
        gatewayUserChoseDirect = Self.gatewayDefaults?.bool(forKey: Self.gatewayDirectKey) ?? false
    }

    private func persistPreference() {
        if let id = defaultGatewayProfileID {
            Self.gatewayDefaults?.set(id, forKey: Self.gatewayOwnerKey)
        } else {
            Self.gatewayDefaults?.removeObject(forKey: Self.gatewayOwnerKey)
        }
        Self.gatewayDefaults?.set(gatewayUserChoseDirect, forKey: Self.gatewayDirectKey)
    }

    // MARK: - VPN-kind participation (classify every kind cleanly)

    /// Put a kind in exactly one Route bucket (StateMediators.md › VPN-kind
    /// participation). Pure and unit-tested per kind. `.full` == "gets a live gateway
    /// role"; the tailscale exit-node condition gates OWNERSHIP (`canBeDefaultGateway`)
    /// not the bucket, so tailscale always participates in role application as before.
    nonisolated static func participation(for kind: VPNKind, connected: Bool = true,
                                          tailscaleHasExitNode: Bool = false) -> RouteParticipation {
        switch kind {
        case .openVPN, .proxyTunnel, .tailscale, .wireGuard,
             .fortinet, .f5apm, .ciscoAnyConnect, .globalProtect, .juniper, .pulse, .arrayNetworks:
            return .full
        case .ikev2, .ipsec, .l2tp:
            return .limited
        case .ssh:
            return .proxyOnly
        }
    }

    /// Whether a kind takes a live gateway role at all (== the `.full` bucket). This
    /// is the exact predicate the inline code used as `gatewayRoleApplies`.
    private func gatewayRoleApplies(_ kind: VPNKind) -> Bool {
        Self.participation(for: kind).appliesGatewayRole
    }

    /// Why a connected profile can't be offered as the default gateway (nil ⇒ it can,
    /// or isn't connected). Surfaced in the picker so no kind is silently dropped.
    func gatewayExclusionReason(for id: String) -> String? {
        guard let info = info(id) else { return nil }
        if canBeDefaultGateway(id) { return nil }
        switch Self.participation(for: info.kind) {
        case .full:
            // A route-participant that just can't own right now — only Tailscale
            // without an exit node lands here.
            if info.kind == .tailscale {
                return "\(info.name) needs an exit node before it can be the gateway."
            }
            return "\(info.name) can't carry all traffic, so it can't be the gateway."
        case .limited:
            return "\(info.name) is an OS-managed VPN; its full/split routing is fixed at connect and can't be switched live."
        case .proxyOnly:
            return "\(info.name) is a proxy, not a full tunnel — it has no default route to hand out."
        case .unsupported:
            return "\(info.name) can't be controlled here (its engine isn't built in)."
        }
    }

    // MARK: - Reads / published effective state

    private func info(_ id: String) -> RouteProfileInfo? {
        host?.routeProfiles.first { $0.id == id }
    }

    /// Connected profiles, most-recently-connected FIRST — the deterministic
    /// auto-promotion tiebreak (falls back to name order so it's always total).
    private var connectedInfos: [RouteProfileInfo] {
        (host?.routeProfiles ?? [])
            .filter { $0.connected }
            .sorted { a, b in
                let ta = a.lastConnectedAt ?? .distantPast
                let tb = b.lastConnectedAt ?? .distantPast
                if ta != tb { return ta > tb }
                return a.name.localizedCaseInsensitiveCompare(b.name) == .orderedAscending
            }
    }

    /// Connected profiles projected to the UI (most-recent-first).
    var connectedProfiles: [RouteProfileInfo] { connectedInfos }

    /// Whether a connected profile can be the full-tunnel owner.
    func canBeDefaultGateway(_ id: String) -> Bool {
        guard let info = info(id) else { return false }
        return GatewayPolicy.canBeDefaultGateway(kind: info.kind, connected: info.connected,
                                                 tailscaleHasExitNode: info.tailscaleHasExitNode)
    }

    /// Capable connected profile ids, most-recent-first.
    private func capableConnectedIDs() -> [String] {
        connectedInfos.map(\.id).filter { canBeDefaultGateway($0) }
    }

    /// The owner actually in force right now (resolves the stored pick against what's
    /// connected + capable, honoring an explicit Direct).
    var effectiveGatewayOwner: String? {
        GatewayPolicy.resolveOwner(stored: defaultGatewayProfileID,
                                   userChoseDirect: gatewayUserChoseDirect,
                                   capableConnected: capableConnectedIDs())
    }

    /// The role a connected profile currently plays. Prefers the engine's GROUND TRUTH
    /// (does its tunnel actually hold the default) so it can never disagree with
    /// reality; falls back to the desired pick before the first sample (RC4/RC5).
    func gatewayRole(for id: String) -> GatewayRole {
        if let owned = engineDefaultOwned[id] { return owned ? .full : .split }
        return GatewayPolicy.role(for: id, owner: effectiveGatewayOwner)
    }

    /// The owner the engines ACTUALLY report right now, independent of the stored pick.
    var engineReportedGatewayOwner: String? {
        connectedInfos.first { engineDefaultOwned[$0.id] == true }?.id
    }

    /// What the traffic-path picture should show: engine truth once we've sampled any
    /// connected tunnel, else the desired pick before the first sample (RC4/RC5).
    var displayedGatewayOwner: String? {
        let sampledAny = connectedInfos.contains { engineDefaultOwned[$0.id] != nil }
        return sampledAny ? engineReportedGatewayOwner : effectiveGatewayOwner
    }

    /// Show the default-gateway control when there's a choice to make.
    var showsDefaultGatewayControl: Bool {
        connectedInfos.count >= 2 || connectedInfos.contains { canBeDefaultGateway($0.id) }
    }

    /// The name for a profile id (for the UI).
    func name(for id: String?) -> String? {
        guard let id else { return nil }
        return info(id)?.name
    }

    /// The published desired plan (for inspection / the Network-Tools panel). Computed
    /// from the captured intents via the pure arbiter.
    var plan: RoutePlan {
        RouteArbiter.plan(intents: Array(intents.values),
                          policy: RoutePolicy(storedOwner: defaultGatewayProfileID,
                                              userChoseDirect: gatewayUserChoseDirect))
    }

    // MARK: - Establish-time prediction (RC3)

    /// Whether THIS profile should own the default once it connects, given the current
    /// picture. Passed via `startTunnel` options so the extension sets its suppress
    /// gate at establish and ≤1-owner holds before (or without) the app reconciling.
    func predictedGatewayOwned(_ id: String) -> Bool {
        guard let info = info(id), gatewayRoleApplies(info.kind) else { return false }
        // A native/SSH kind never carries the default; a Tailscale node's ownership
        // rides its own prefs path, not this flag.
        guard info.kind != .tailscale else { return false }
        var capable = capableConnectedIDs()
        if !capable.contains(id) { capable.insert(id, at: 0) }   // most-recent = newest connect
        let owner = GatewayPolicy.resolveOwner(stored: defaultGatewayProfileID,
                                               userChoseDirect: gatewayUserChoseDirect,
                                               capableConnected: capable)
        return owner == id
    }

    // MARK: - The user picked an owner (atomic strip → confirm → add)

    /// The user picked a new default-gateway owner (nil ⇒ Direct). STRIP-OLD → confirm
    /// (await ack) → ADD-NEW, so there is never a moment where two VPNs both advertise
    /// 0.0.0.0/0. The brief no-default gap is masked by the traffic-path animation.
    func setDefaultGateway(to newOwner: String?) async {
        let current = effectiveGatewayOwner
        defaultGatewayProfileID = newOwner
        gatewayUserChoseDirect = (newOwner == nil)
        persistPreference()
        guard current != newOwner else { return }

        for step in GatewayPolicy.switchSteps(from: current, to: newOwner) {
            switch step {
            case .split(let id): await applyGatewayRole(.split, to: id)
            case .full(let id):  await applyGatewayRole(.full, to: id)
            }
        }
        // Any other connected capable VPN must also be split.
        for info in connectedInfos where info.id != newOwner && gatewayRoleApplies(info.kind) {
            await applyGatewayRole(.split, to: info.id)
        }
    }

    // MARK: - Apply / reconcile

    /// Push one role onto one profile's live session, through the realizer. Every
    /// in-process engine (openvpn3, proxy tunnel, OpenConnect) demotes live; the
    /// needs-reconnect fallback stays wired here for any future engine that can't.
    private func applyGatewayRole(_ role: GatewayRole, to id: String) async {
        guard let info = info(id), gatewayRoleApplies(info.kind), info.engaged else { return }
        lastApplyAt = Date()   // open the suppress window: this write is ours
        let outcome = await realizer.apply(role, to: id, kind: info.kind,
                                           hasExitNode: info.tailscaleHasExitNode)
        if outcome == .needsReconnect {
            gatewayPendingReassert.insert(id)
            await host?.routeReconnect(id: id)
        }
    }

    /// Recompute and apply gateway roles across every connected profile. Serialized
    /// through one task so a strip and an add can't interleave. Exactly
    /// `effectiveGatewayOwner` ends up full, everyone else split.
    func reconcileGateway() {
        refreshIntents()
        gatewayReconcileTask = Task { [weak self] in
            guard let self else { return }
            let owner = self.effectiveGatewayOwner
            // Persist an auto-adopted owner so the pick survives relaunch.
            if owner != self.defaultGatewayProfileID, !self.gatewayUserChoseDirect {
                self.defaultGatewayProfileID = owner
                self.persistPreference()
            }
            // Strip everyone that isn't the owner FIRST, then grant the owner.
            for info in self.connectedInfos where info.id != owner && self.gatewayRoleApplies(info.kind) {
                await self.applyGatewayRole(.split, to: info.id)
            }
            if let owner, self.info(owner)?.engaged == true {
                await self.applyGatewayRole(.full, to: owner)
            }
        }
    }

    /// Re-assert desired state on demand (the Network-Tools "Re-assert" action).
    func reassertNow() { reconcileGateway() }

    // MARK: - Status hooks (from the host's NE observer)

    /// A profile just changed state. Keeps the invariant and handles owner-disconnect
    /// fallback with a toast.
    func handleStatusChange(id: String, connected: Bool, reasserting: Bool,
                            disconnected: Bool) {
        if connected || reasserting {
            gatewayPendingReassert.remove(id)
            // Seed from ENGINE REALITY (async, over the stats IPC) so the applied-role
            // guard reflects reality; reconcile immediately too.
            seedGatewayRoleFromEngine(id: id)
            reconcileGateway()
        } else if disconnected {
            realizer.forget(id: id)
            engineDefaultOwned[id] = nil
            withdraw(engine: id)
            let wasOwner = (id == defaultGatewayProfileID) || (id == effectiveGatewayOwner)
            reconcileGateway()
            if wasOwner { announceGatewayFallback(previousOwner: id) }
        }
    }

    /// Seed the applied-role cache for a (re)connected profile from ENGINE REALITY. The
    /// effective state rides the stats IPC and can take a sample or two to settle, so
    /// poll briefly; the host's stats poll records it via `noteEngineDefaultOwned`.
    private func seedGatewayRoleFromEngine(id: String) {
        guard let info = info(id), gatewayRoleApplies(info.kind),
              info.kind != .tailscale else { return }
        Task { [weak self] in
            guard let self else { return }
            for attempt in 0..<4 {
                guard self.info(id)?.connected == true else { return }
                if await self.host?.routeSampleEffectiveOwned(id: id) != nil { return }
                try? await Task.sleep(for: .milliseconds(250 * (attempt + 1)))
            }
        }
    }

    /// Record the engine's ground-truth default-route ownership from a stats sample.
    /// Seeds the realizer cache and self-heals any desync. Called from the host's
    /// ~1 Hz stats poll, so a full/split that drifts out of band is corrected (RC4).
    func noteEngineDefaultOwned(id: String, owned: Bool) {
        let changed = engineDefaultOwned[id] != owned
        engineDefaultOwned[id] = owned
        guard changed, let info = info(id), gatewayRoleApplies(info.kind), info.engaged else { return }
        realizer.seed(id: id, owned: owned)
        let wanted = GatewayPolicy.role(for: id, owner: effectiveGatewayOwner)
        if (owned ? GatewayRole.full : .split) != wanted { reconcileGateway() }
    }

    /// The picked owner just disconnected — say what took over. Fires after
    /// reconciliation, so `effectiveGatewayOwner` already reflects the fallback.
    private func announceGatewayFallback(previousOwner id: String) {
        guard !connectedInfos.isEmpty else { return }
        let goneName = info(id)?.name ?? "The VPN"
        if let newOwner = effectiveGatewayOwner, let newName = info(newOwner)?.name {
            ToastCenter.shared.post(
                "\(goneName) disconnected — \(newName) is now the gateway.",
                symbol: "arrow.triangle.swap", tint: .indigo, seconds: 6)
        } else if !connectedInfos.isEmpty {
            ToastCenter.shared.post(
                "\(goneName) disconnected — traffic is now direct.",
                symbol: "arrow.up.forward", tint: .gray, seconds: 6)
        }
    }

    // MARK: - Intent refresh (keep the captured intents current)

    /// Rebuild intents from the live profiles through the capture seam. Live owner
    /// selection uses `resolveOwner` directly (unchanged); this keeps the inspectable
    /// `intents`/`plan` in step with reality and gives the Tcl hook a real attach point.
    private func refreshIntents() {
        let live = connectedInfos.filter { gatewayRoleApplies($0.kind) }
        let liveIDs = Set(live.map(\.id))
        for gone in intents.keys where !liveIDs.contains(gone) { withdraw(engine: gone) }
        for info in live {
            submit(RouteIntent(engine: info.id,
                               advertisedPrefixes: host?.routeAdvertisedPrefixes(id: info.id) ?? [],
                               wantsDefault: host?.routeWantsFullTunnel(id: info.id) ?? false,
                               canOwnDefault: canBeDefaultGateway(info.id),
                               metric: 0,
                               connectedAt: info.lastConnectedAt),
                   from: info.id)
        }
    }

    // MARK: - Drift monitor lifecycle + handling

    /// Begin watching PF_ROUTE for external default-route drift.
    func startMonitoring() {
        do {
            try monitor.start { [weak self] observed in
                // Off-main callback → hop to main to diff-and-publish.
                Task { @MainActor [weak self] in self?.handleObservedDefault(observed) }
            }
        } catch {
            Self.log.error("PF_ROUTE monitor failed to start: \(String(describing: error), privacy: .public)")
        }
    }

    func stopMonitoring() { monitor.stop() }

    /// What we EXPECT the default route to look like. We know whether a tunnel should
    /// own it; the exact utun name we don't reliably know app-side, so leave it nil
    /// and let the decision compare on tunnel-ownership.
    private func expectedDefaultState() -> DefaultRouteState {
        DefaultRouteState(ownedByTunnel: effectiveGatewayOwner != nil, interface: nil)
    }

    /// The monitor saw the default route change. Suppress our own churn, compare to
    /// expected, and only re-assert (+ publish) on genuine external drift.
    private func handleObservedDefault(_ observed: DefaultRouteState) {
        let suppressed = lastApplyAt.map { Date().timeIntervalSince($0) < suppressWindow } ?? false
        let action = RouteDriftDecision.action(expected: expectedDefaultState(),
                                               observed: observed,
                                               withinSuppressWindow: suppressed)
        guard action == .reassert else { return }
        let event = MediatorDriftEvent(summary: driftSummary(observed), reasserted: true)
        lastDrift = event
        driftHook?(event)
        Self.log.log("external default-route drift: \(event.summary, privacy: .public) — re-asserting")
        reconcileGateway()
    }

    private func driftSummary(_ observed: DefaultRouteState) -> String {
        let expectedTunnel = effectiveGatewayOwner != nil
        if observed.ownedByTunnel && !expectedTunnel {
            return "Something else routed the default through \(observed.interface ?? "a tunnel"); expected Direct."
        }
        if !observed.ownedByTunnel && expectedTunnel {
            let owner = name(for: effectiveGatewayOwner) ?? "the VPN"
            return "The default route left \(owner) for \(observed.interface ?? "the local link")."
        }
        return "The default route changed externally (now via \(observed.interface ?? "unknown"))."
    }
}
