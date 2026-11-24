// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only

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
        DNSSearchDomains.normalized(matchDomains.filter { !$0.isEmpty })
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
    var participants: [String] = []
    var searchDomainsByEngine: [String: [String]] = [:]

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
    /// The owner is emitted once with BOTH the catch-all and its specific domains.
    /// Another VPN app can install a higher-priority catch-all; retaining the more
    /// specific matches lets our domains still select our resolvers. PURE + testable.
    func applyRequests() -> [String: DNSApplyRequest] {
        // Empty requests intentionally suppress DNS on participants that lost all
        // scopes; clearing their override would restore an unwanted catch-all push.
        var out = Dictionary(uniqueKeysWithValues: participants.map { ($0, DNSApplyRequest()) })
        for a in perDomain where a.engine != catchAllOwner {
            out[a.engine] = DNSApplyRequest(servers: a.resolvers,
                                            searchDomains: searchDomainsByEngine[a.engine] ?? [],
                                            matchDomains: a.domains,
                                            matchDomainsNoSearch: true)
        }
        if let owner = catchAllOwner {
            let domains = perDomain.first { $0.engine == owner }?.domains ?? []
            out[owner] = DNSApplyRequest(servers: systemResolvers,
                                         searchDomains: searchDomainsByEngine[owner] ?? [],
                                         matchDomains: [""] + domains,
                                         matchDomainsNoSearch: !domains.isEmpty)
        }
        return out
    }
}

// MARK: - Arbiter

nonisolated enum DNSArbiter {

    /// Coherent split-DNS from intents + policy. PURE.
    ///
    /// Precedence: the route default OWNER (if it advertises resolvers) owns the
    /// catch-all. Every engine's SPECIFIC match domains become split assignments; on a
    /// domain claimed by two engines, the winner is the owner, then the most-recent
    /// connection, then id order — so the result is deterministic and one domain never
    /// resolves two ways.
    static func plan(intents: [DNSIntent], policy: DNSPolicy) -> DNSPlan {
        // Deterministic precedence order: owner first, then newest, then id.
        let ranked = ranked(intents: intents, policy: policy)

        // Catch-all owner: only the route owner may claim all otherwise unmatched names.
        let ownerIntent = ranked.first {
            $0.engine == policy.defaultOwner && !$0.resolvers.isEmpty && ($0.wantsCatchAll || $0.matchDomains.isEmpty)
        }
        let catchAllOwner = ownerIntent?.engine
        let systemResolvers = ownerIntent?.resolvers ?? []
        var claimed = Set<String>()
        var assignments: [DNSResolverAssignment] = []
        for intent in ranked where !intent.resolvers.isEmpty {
            let won = intent.specificDomains.filter { claimed.insert($0).inserted }
            guard !won.isEmpty else { continue }
            assignments.append(DNSResolverAssignment(engine: intent.engine, resolvers: intent.resolvers, domains: won.sorted()))
        }
        assignments.sort { a, b in
            let ao = a.engine == catchAllOwner, bo = b.engine == catchAllOwner
            return ao != bo ? ao : a.engine < b.engine
        }
        return DNSPlan(catchAllOwner: catchAllOwner, systemResolvers: systemResolvers,
            perDomain: assignments, participants: intents.map(\.engine).sorted(),
            searchDomainsByEngine: Dictionary(uniqueKeysWithValues:
                intents.map { ($0.engine, DNSSearchDomains.normalized($0.searchDomains)) }))
    }

    /// Shared precedence for native suffix scopes and query-name rules.
    static func ranked(intents: [DNSIntent], policy: DNSPolicy) -> [DNSIntent] {
        intents.sorted { a, b in
            let ao = a.engine == policy.defaultOwner
            let bo = b.engine == policy.defaultOwner
            if ao != bo { return ao }
            let ta = a.connectedAt ?? .distantPast
            let tb = b.connectedAt ?? .distantPast
            if ta != tb { return ta > tb }
            return a.engine < b.engine
        }

    }
}
