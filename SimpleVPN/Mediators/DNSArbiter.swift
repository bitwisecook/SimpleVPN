// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
//  DNSArbiter.swift
//  The DNS mediator's PURE core (Docs/StateMediators.md › DNS mediator, P2). Total,
//  testable, no-I/O functions:
//    • `DNSArbiter.plan(intents:policy:)` — merge every connected tunnel's DNS intent
//      into ONE coherent split-DNS config: which resolver serves which domain, with a
//      precedence that stops the last VPN's push from clobbering the rest. Exactly one
//      engine (the route default owner, if it advertises resolvers) owns the CATCH-ALL
//      (`[""]`); every other engine keeps only its SPECIFIC match domains.
//    • `DNSDriftDecision.action(...)` — given the monitor's observed system resolvers
//      vs the plan's expected catch-all resolvers (and the just-applied suppress
//      window), decide whether an EXTERNAL change warrants a re-assert.
//  Plus `DNSParticipation` — the per-kind classifier (mirrors the Route one) so no kind
//  is silently mis-handled.
//

import Foundation

// MARK: - Intent (stage 1 payload)

/// One engine's structured DNS intent — the resolvers/search/match domains a connected
/// tunnel WANTS on the host. Sourced best-effort app-side (pushed config, engine
/// report); the tier-3 `DNS_PUSHED` hook rewrites exactly this before arbitration.
nonisolated struct DNSIntent: MediatorIntent {
    let engine: String                 // profile id
    var resolvers: [String]            // resolver IPs this engine advertises
    var searchDomains: [String]        // search-list domains
    /// The domains this engine's resolvers should serve. `[""]` (or empty when it wants
    /// the default) = the CATCH-ALL: it claims every lookup. A specific list = split-DNS
    /// (only those domains resolve through it).
    var matchDomains: [String]
    /// It advertised a catch-all (`[""]` / empty match domains with resolvers) — i.e. it
    /// would take over ALL name resolution if allowed.
    var wantsCatchAll: Bool
    var egress: String?                // BSD interface, best-effort (nil ⇒ unknown)
    /// Recency of this engine's connection — the deterministic precedence tiebreak on a
    /// domain conflict (newest wins), matching the Route mediator.
    var connectedAt: Date?

    init(engine: String, resolvers: [String] = [], searchDomains: [String] = [],
         matchDomains: [String] = [], wantsCatchAll: Bool = false, egress: String? = nil,
         connectedAt: Date? = nil) {
        self.engine = engine
        self.resolvers = resolvers
        self.searchDomains = searchDomains
        self.matchDomains = matchDomains
        self.wantsCatchAll = wantsCatchAll
        self.egress = egress
        self.connectedAt = connectedAt
    }

    /// The engine's SPECIFIC (non catch-all) match domains — the ones eligible for a
    /// split-DNS assignment.
    var specificDomains: [String] {
        matchDomains.filter { !$0.isEmpty }
    }
}

// MARK: - Policy input

/// The policy the DNS arbiter resolves against (tier-2): the route DEFAULT OWNER's DNS
/// is the catch-all, so global name resolution follows the tunnel that carries the
/// default route. nil ⇒ no owner ⇒ Direct DNS (the Mac's own resolvers).
nonisolated struct DNSPolicy: Sendable, Equatable {
    var defaultOwner: String?   // the profile id that owns the default route (routes.effectiveGatewayOwner)
}

// MARK: - Plan (stage 2 output)

/// One resolver→domains assignment in the split-DNS plan.
nonisolated struct DNSResolverAssignment: Sendable, Equatable, Identifiable {
    let engine: String
    var resolvers: [String]
    /// The domains these resolvers serve. `[""]` ⇒ the catch-all assignment.
    var domains: [String]
    var id: String { engine }
    var isCatchAll: Bool { domains.contains("") || domains.isEmpty }
}

/// The computed coherent DNS desired state: who owns the catch-all, and the per-domain
/// split assignments. Every domain resolves through exactly one engine.
nonisolated struct DNSPlan: Sendable, Equatable {
    /// The engine whose resolvers serve every unmatched lookup. nil ⇒ Direct DNS.
    var catchAllOwner: String?
    /// The catch-all resolver IPs (the owner's), for the drift comparison + the UI.
    var systemResolvers: [String]
    /// Split-DNS: specific-domain assignments, deterministically ordered. Never
    /// includes the catch-all (that is `catchAllOwner`/`systemResolvers`).
    var perDomain: [DNSResolverAssignment]

    /// Every domain that resolves somewhere other than the catch-all.
    var splitDomains: [String] { perDomain.flatMap(\.domains).sorted() }

    /// Project the plan into the per-participant SOLE-WRITER wire payloads
    /// (Docs/StateMediators.md › DNS applier). DNS arbitrates PER DOMAIN, so — unlike
    /// the single-owner proxy applier — each participating engine gets its OWN
    /// `DNSApplyRequest`:
    ///   • the catch-all owner gets the default resolvers scoped to `[""]` (every
    ///     lookup), so global name resolution follows the default-route tunnel;
    ///   • each split participant gets its resolvers scoped to ONLY the specific
    ///     domains it won (`matchDomainsNoSearch` so a scoped resolver can't leak its
    ///     suffixes into global search).
    /// The owner, if it also won specific domains, is still emitted once as the
    /// catch-all (`[""]` already covers those). PURE + testable.
    func applyRequests() -> [String: DNSApplyRequest] {
        var out: [String: DNSApplyRequest] = [:]
        for a in perDomain where a.engine != catchAllOwner {
            out[a.engine] = DNSApplyRequest(servers: a.resolvers,
                                            searchDomains: [],
                                            matchDomains: a.domains,
                                            matchDomainsNoSearch: true)
        }
        if let owner = catchAllOwner {
            out[owner] = DNSApplyRequest(servers: systemResolvers,
                                         searchDomains: [],
                                         matchDomains: [""],
                                         matchDomainsNoSearch: false)
        }
        return out
    }
}

// MARK: - Arbiter

nonisolated enum DNSArbiter: MediatorArbiter {

    /// Coherent split-DNS from intents + policy. PURE.
    ///
    /// Precedence: the route default OWNER (if it advertises resolvers) owns the
    /// catch-all. Every engine's SPECIFIC match domains become split assignments; on a
    /// domain claimed by two engines, the winner is the owner, then the most-recent
    /// connection, then id order — so the result is deterministic and one domain never
    /// resolves two ways.
    static func plan(intents: [DNSIntent], policy: DNSPolicy) -> DNSPlan {
        // Deterministic precedence order: owner first, then newest, then id.
        let ranked = intents.sorted { a, b in
            let ao = a.engine == policy.defaultOwner
            let bo = b.engine == policy.defaultOwner
            if ao != bo { return ao }
            let ta = a.connectedAt ?? .distantPast
            let tb = b.connectedAt ?? .distantPast
            if ta != tb { return ta > tb }
            return a.engine < b.engine
        }

        // Catch-all owner: the route owner when it advertises resolvers; otherwise
        // nobody (Direct DNS) — we deliberately do NOT let a non-owner's catch-all push
        // become the system resolver, which is the clobber this mediator exists to stop.
        let ownerIntent = ranked.first { $0.engine == policy.defaultOwner && !$0.resolvers.isEmpty }
        let catchAllOwner = ownerIntent?.engine
        let systemResolvers = ownerIntent?.resolvers ?? []

        // Split-DNS: assign each specific domain to the highest-precedence engine that
        // claims it. An engine keeps only the domains it actually WON.
        var claimed = Set<String>()
        var assignments: [DNSResolverAssignment] = []
        for intent in ranked where !intent.resolvers.isEmpty {
            let won = intent.specificDomains.filter { claimed.insert($0).inserted }
            guard !won.isEmpty else { continue }
            assignments.append(DNSResolverAssignment(engine: intent.engine,
                                                     resolvers: intent.resolvers,
                                                     domains: won.sorted()))
        }
        // Stable output order for the UI/tests: owner-ness then engine id.
        assignments.sort { a, b in
            let ao = a.engine == catchAllOwner, bo = b.engine == catchAllOwner
            if ao != bo { return ao }
            return a.engine < b.engine
        }

        return DNSPlan(catchAllOwner: catchAllOwner, systemResolvers: systemResolvers,
                       perDomain: assignments)
    }
}

// MARK: - Observation + drift decision (stage 4 → re-assert)

/// What the DNS monitor read from `State:/Network/Global/DNS` — the resolvers the OS is
/// actually using right now (includes any VPN-pushed DNS), and the search domains.
nonisolated struct DNSObservation: Sendable, Equatable {
    var resolvers: [String]
    var searchDomains: [String]
}

nonisolated enum DNSDriftAction: Sendable, Equatable {
    case none         // matches expectation (or our own change) — do nothing
    case reassert     // genuine external drift — drive the OS back to desired
}

nonisolated enum DNSDriftDecision {
    /// Decide what to do about an observed system-resolver change.
    ///
    /// - `withinSuppressWindow`: we applied a DNS change moments ago, so this
    ///   observation is almost certainly our OWN change echoing back — never re-assert
    ///   against ourselves.
    /// - otherwise: when we EXPECT a catch-all owner (non-empty expected resolvers) and
    ///   the observed system resolvers no longer contain ALL of ours, something external
    ///   changed DNS ⇒ re-assert. An empty expectation (Direct DNS) never manufactures
    ///   drift — the Mac's own resolvers changing is not ours to fight.
    static func action(expected: [String], observed: [String],
                       withinSuppressWindow: Bool) -> DNSDriftAction {
        if withinSuppressWindow { return .none }
        guard !expected.isEmpty else { return .none }
        let observedSet = Set(observed)
        return expected.allSatisfy(observedSet.contains) ? .none : .reassert
    }
}

// MARK: - VPN-kind participation classifier (DNS resource)

/// Which clean bucket a connected profile falls into for the DNS resource
/// (StateMediators.md › VPN-kind participation). Every kind resolves to exactly one.
nonisolated enum DNSParticipation: Sendable, Equatable {
    /// Pushes real resolvers we arbitrate into split-DNS (OpenVPN, proxy-tunnel,
    /// Tailscale/MagicDNS, WireGuard's DNS= servers, in-process-NE OpenConnect
    /// and the other SSL VPNs).
    case full
    /// Coarse OS-managed DNS (native NEVPNManager kinds via `NEDNSSettings`) — surfaced
    /// but not part of the live split-DNS arbitration.
    case limited
    /// No DNS of its own (SSH SOCKS, subprocess kinds) — excluded with a reason.
    case none

    // No `.unsupported` bucket: it was "engine not built", nothing returned it, and
    // the sentence it produced could never be shown. `classify(_:)` below switches
    // over `VPNKind` exhaustively with no `default` arm, so a new kind is forced to
    // pick a bucket by the compiler — which is what the spare case was standing in
    // for. Removed here in step with `RouteParticipation`, so the three mediators'
    // buckets stay readable side by side.

    /// Does this bucket contribute an intent to the split-DNS arbitration?
    var participatesInSplitDNS: Bool { self == .full }

    nonisolated static func classify(_ kind: VPNKind) -> DNSParticipation {
        switch kind {
        case .openVPN, .proxyTunnel, .tailscale, .wireGuard, .sshNetworkTunnel,
             .fortinet, .f5apm, .ciscoAnyConnect, .globalProtect, .juniper, .pulse, .arrayNetworks:
            // .sshNetworkTunnel advertises real resolvers on its utun and carries
            // every query as DNS-over-TCP through the session, so it contributes a
            // genuine split-DNS intent — unlike `.ssh`, which has no interface to
            // advertise one on.
            return .full
        case .ikev2, .ipsec, .l2tp:
            return .limited
        case .ssh:
            return .none
        }
    }
}
