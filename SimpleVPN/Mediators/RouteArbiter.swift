// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
//  RouteArbiter.swift
//  The Route mediator's PURE core (Docs/StateMediators.md › Route mediator). Two
//  total, testable functions with no I/O:
//    • `RouteArbiter.plan(intents:policy:)` — merge every connected tunnel's route
//      intent into one desired state under the ≤1-default-owner invariant. Wraps the
//      pre-existing `GatewayPolicy` role/switch math (kept as the arbiter core) and
//      adds the per-engine role map + safely-ordered application sequence.
//    • `RouteDriftDecision.action(...)` — given the monitor's observed default vs the
//      mediator's expected effective state (and the just-applied suppress window),
//      decide whether an EXTERNAL change warrants a re-assert.
//  Plus `RouteMediator.participation(for:)` — the VPN-kind classifier that puts every
//  connected profile into exactly one clean bucket (StateMediators.md › VPN-kind
//  participation), so no kind is ever silently mis-handled or given a role it can't
//  honor.
//

import Foundation

// MARK: - Intent (stage 1 payload)

/// One engine's structured route intent — what a connected tunnel WANTS on the host.
/// Sourced from engine reports (advertised prefixes + whether it wants the default),
/// never from a client-.ovpn text grep. Inspectable and per-engine; the tier-3
/// `ROUTE_ADVERTISED` hook rewrites exactly this before arbitration.
nonisolated struct RouteIntent: MediatorIntent {
    let engine: String                 // profile id
    var advertisedPrefixes: [String]   // specific CIDRs it carries (besides any default)
    var wantsDefault: Bool             // it would carry 0.0.0.0/0 · ::/0 if allowed
    /// Whether this engine CAN own the default right now (capability, not desire) —
    /// `RouteMediator.participation` == .full && (kind-specific gating, e.g. a
    /// Tailscale exit node). Only capable engines enter owner selection.
    var canOwnDefault: Bool
    var metric: Int
    /// Recency of this engine's connection — the deterministic auto-promotion
    /// tiebreak (newest capable wins). Later = more recent.
    var connectedAt: Date?

    init(engine: String, advertisedPrefixes: [String] = [], wantsDefault: Bool = false,
         canOwnDefault: Bool = false, metric: Int = 0, connectedAt: Date? = nil) {
        self.engine = engine
        self.advertisedPrefixes = advertisedPrefixes
        self.wantsDefault = wantsDefault
        self.canOwnDefault = canOwnDefault
        self.metric = metric
        self.connectedAt = connectedAt
    }
}

// MARK: - Policy input

/// The user-facing policy the arbiter resolves the owner against (tier-2). Mirrors
/// the persisted gateway pick.
nonisolated struct RoutePolicy: Sendable, Equatable {
    var storedOwner: String?     // the user's stored pick (nil ⇒ unset)
    var userChoseDirect: Bool    // explicit Direct (vs. merely unset)
}

// MARK: - Plan (stage 2 output)

/// The computed desired state: who owns the default, the role every participating
/// engine plays, and the SAFELY-ORDERED sequence to realize it (strip-old → add-new,
/// never two `.full` at once).
nonisolated struct RoutePlan: Sendable, Equatable {
    /// The profile that should own 0.0.0.0/0 · ::/0. nil ⇒ Direct (nobody).
    var owner: String?
    /// role per participating engine id. Exactly `owner` (if any) is `.full`.
    var roles: [String: GatewayRole]
    /// The application order: every `.split` FIRST, then the single `.full`. Applying
    /// in this order makes two-defaults structurally impossible. Idempotent per step.
    var orderedApplication: [GatewayPolicy.Step]

    /// Convenience: the ≤1 engine that ends up full.
    var fullOwners: [String] { roles.filter { $0.value == .full }.map(\.key) }
}

// MARK: - Arbiter

nonisolated enum RouteArbiter: MediatorArbiter {

    /// Desired state from intents + policy. PURE — the whole ≤1-owner invariant is
    /// computed here, then handed to the realizer to apply.
    static func plan(intents: [RouteIntent], policy: RoutePolicy) -> RoutePlan {
        // Capable connected engines, most-recent FIRST (the auto-promotion tiebreak),
        // falling back to id order when recency is unknown so the order is total.
        let capable = intents
            .filter { $0.canOwnDefault }
            .sorted { a, b in
                let ta = a.connectedAt ?? .distantPast
                let tb = b.connectedAt ?? .distantPast
                if ta != tb { return ta > tb }
                return a.engine < b.engine
            }
            .map(\.engine)

        let owner = GatewayPolicy.resolveOwner(stored: policy.storedOwner,
                                               userChoseDirect: policy.userChoseDirect,
                                               capableConnected: capable)

        // Every engine that participates in role application (everyone with an intent
        // here is a route-participant by construction) gets a role: exactly the owner
        // is full, the rest split.
        var roles: [String: GatewayRole] = [:]
        for intent in intents {
            roles[intent.engine] = GatewayPolicy.role(for: intent.engine, owner: owner)
        }

        // Ordered application: strip every non-owner first, then grant the owner —
        // the same STRIP-before-ADD discipline as `switchSteps`, generalized to the
        // whole set.
        var ordered: [GatewayPolicy.Step] = []
        for (id, role) in roles.sorted(by: { $0.key < $1.key }) where role == .split {
            ordered.append(.split(id))
        }
        if let owner, roles[owner] == .full { ordered.append(.full(owner)) }

        return RoutePlan(owner: owner, roles: roles, orderedApplication: ordered)
    }
}

// MARK: - Drift decision (stage 4 → re-assert)

/// The observed/expected default-route state the monitor and mediator compare. Kept
/// deliberately coarse (does a TUNNEL carry the default, on which interface) so the
/// diff is robust without needing to name a specific utun the app never learns
/// reliably. `interface` is the BSD name the OS currently egresses the default by.
nonisolated struct DefaultRouteState: Sendable, Equatable {
    /// A VPN tunnel currently carries the default (vs. a physical link / nothing).
    var ownedByTunnel: Bool
    /// The interface the default egresses by ("en0", "utun4"), nil ⇒ no default.
    var interface: String?
}

nonisolated enum RouteDriftAction: Sendable, Equatable {
    case none         // matches expectation (or our own change) — do nothing
    case reassert     // genuine external drift — drive the OS back to desired
}

nonisolated enum RouteDriftDecision {
    /// Decide what to do about an observed default-route change.
    ///
    /// - `withinSuppressWindow`: we applied a gateway change moments ago, so this
    ///   observation is almost certainly our OWN NE-induced change echoing back —
    ///   never re-assert against ourselves.
    /// - otherwise compare observed to expected: only DIVERGENCE (a different owner
    ///   kind, or the default appearing/vanishing unexpectedly) is drift. Matching
    ///   observations are never acted on, which is what stops a reconcile loop.
    static func action(expected: DefaultRouteState,
                       observed: DefaultRouteState,
                       withinSuppressWindow: Bool) -> RouteDriftAction {
        if withinSuppressWindow { return .none }
        // The primary signal: did the KIND of owner change (tunnel ⇄ physical/none)?
        // That is drift we can always judge, without knowing the exact utun name.
        if expected.ownedByTunnel != observed.ownedByTunnel { return .reassert }
        // Only when we actually know the expected egress interface do we hold the
        // observed one to it — an unknown expectation (nil) never manufactures drift.
        if let expectedIface = expected.interface, expectedIface != observed.interface {
            return .reassert
        }
        return .none
    }
}

// MARK: - VPN-kind participation classifier

/// Which clean bucket a connected profile falls into for the ROUTE resource
/// (StateMediators.md › VPN-kind participation). Every kind resolves to exactly one;
/// never a silent no-op, never a role for a kind with no default route.
nonisolated enum RouteParticipation: Sendable, Equatable {
    /// Real default-route capability: gets a gateway role, enters ≤1-owner
    /// arbitration (OpenVPN, proxy-tunnel, in-process-NE OpenConnect, Tailscale-with-
    /// exit-node). In-process OpenConnect now demotes live via `_suppressDefault`
    /// (its `setDefaultRouteOwned:`), exactly like openvpn3 — no reconnect needed.
    case full
    /// Participates only COARSELY and is kept OUT of the live ≤1-owner switch, with a
    /// reason: native NEVPNManager kinds (full/split via `includeAllNetworks`, no live
    /// demote), and Tailscale before it has a usable exit node.
    case limited
    /// NO default route — a SOCKS/CONNECT egress that belongs to the Proxy mediator,
    /// not Routes (SSH, subprocess/ocproxy OpenConnect). Excluded from the gateway
    /// picker with a reason; never assigned a role.
    case proxyOnly

    // THERE IS NO `.unsupported` BUCKET, and its absence is the point. It existed for
    // "WireGuard engine not built" — an engine that has since shipped — and then no
    // kind returned it, so the case, the switch arm and the sentence it produced
    // ("can't be controlled here (its engine isn't built in)") were unreachable: dead
    // code whose comment still described a state the app had left behind. What makes
    // it safe to remove rather than keep "for the next engine-less kind" is that
    // `participation(for:)` switches over `VPNKind` EXHAUSTIVELY with no `default`
    // arm — so the compiler already forces a new kind to be given a bucket, which is
    // the guarantee the spare case was standing in for. A kind that genuinely cannot
    // be controlled gets a bucket added back, with a true comment, at that moment.

    /// May this bucket be OFFERED in the default-gateway picker as a selectable owner?
    var isSelectableOwner: Bool { self == .full }
    /// Does the Route mediator apply a live gateway role to this bucket?
    var appliesGatewayRole: Bool { self == .full }
}
