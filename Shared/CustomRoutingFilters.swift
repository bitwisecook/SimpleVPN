// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only

import Foundation

/// A structured, per-engine statement of what an engine WANTS on the host — never a
/// direct write. `RouteIntent` / (later) `DNSIntent` / `ProxyIntent` conform.
nonisolated protocol MediatorIntent: Sendable, Equatable {
    /// The engine (our profile id) this intent belongs to. One SCOPE = one subject.
    var engine: String { get }
}

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
    var prefixesRewritten = false
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

// MARK: - Shared vocabulary

/// What happens to a pushed item that NO rule matched. `accept` (default) keeps it —
/// users then add only Ignore/Replace/Add + the odd explicit Accept. `ignore` makes the
/// filter an ALLOW-LIST: nothing survives unless a rule explicitly Accepts/Replaces it.
nonisolated enum UnmatchedDisposition: String, Codable, Sendable, CaseIterable {
    case accept   // Accept unmatched (default)
    case ignore   // Ignore unmatched (allow-list)
}

/// The four route/DNS verbs. A rule matches a pushed item and assigns a disposition:
/// Accept = keep as pushed, Ignore = drop it, Replace = substitute the matched item with
/// the rule's target, Add = inject an item that wasn't pushed (match is nil).
nonisolated enum FilterVerb: String, Codable, Sendable, CaseIterable {
    case accept, ignore, replace, add
}

// MARK: - Route prefixes

/// One route prefix, or the `default` token. Exact-match by normalized string; the
/// default token stands for BOTH 0.0.0.0/0 and ::/0 so a single rule can Ignore/Replace
/// "the default" without spelling each family.
nonisolated struct RoutePrefix: Codable, Sendable, Equatable, Hashable {
    var value: String

    init(_ value: String) { self.value = value }

    /// The tokens that mean "the default route" (either family).
    static let defaultTokens: Set<String> = ["default", "0.0.0.0/0", "::/0"]
    /// The canonical default token a UI should offer.
    static let `default` = RoutePrefix("default")

    /// Whether this prefix denotes the default route.
    var isDefault: Bool { RoutePrefix.defaultTokens.contains(normalized) }
    /// Canonical host or network prefix, including equivalent IPv6 spellings.
    var normalized: String { RoutePrefixMath.canonicalNetwork(value) ?? value.trimmingCharacters(in: .whitespacesAndNewlines).lowercased() }
    var isBlank: Bool { normalized.isEmpty }

    /// EXACT match only (documented limitation — CIDR-CONTAINS is a follow-up). A default
    /// token matches the pushed default; a specific prefix matches an identical string.
    func matches(pushedPrefix p: String) -> Bool {
        guard !isDefault else { return false }
        return normalized == RoutePrefix(p).normalized
    }
}

// MARK: - Route filter

/// Per-profile route rewrite. Ordered rules run first-match-wins against each pushed
/// item; anything unmatched follows `defaultDisposition`. Add rules inject regardless.
nonisolated struct RouteFilter: Codable, Sendable, Equatable {

    /// A rule = { verb, match, target }. `match` is nil ONLY for `.add`; `target` is
    /// required for `.replace`/`.add`. A `default`-token match is how a user reaches the
    /// pushed default (Ignore-default forces split; Replace-default swaps the gateway).
    nonisolated struct RouteRule: Codable, Sendable, Equatable, Identifiable {
        var id: UUID
        var verb: FilterVerb
        var match: RoutePrefix?
        var target: RoutePrefix?

        init(id: UUID = UUID(), verb: FilterVerb, match: RoutePrefix? = nil, target: RoutePrefix? = nil) {
            self.id = id; self.verb = verb; self.match = match; self.target = target
        }

        /// Blank the fields this verb doesn't use.
        ///
        /// The editor HIDES the control a verb doesn't need, but hiding is not
        /// clearing: `dispositionForPrefix` still reads `target` for a Replace,
        /// and `apply` still injects an Add's target — so switching a rule from
        /// Replace to Accept left a target nobody could see, and switching to Add
        /// left a match that changed nothing but sat there. Invisible state that
        /// changes behaviour is a bug however sound the transform is, so the verb
        /// change clears it, and `sanitizedCustomRoutingProfile` clears it again
        /// on the way out for rules already stored that way.
        func clearingUnusedFields() -> RouteRule {
            var out = self
            switch verb {
            case .accept, .ignore: out.target = nil     // nothing to substitute or inject
            case .add:             out.match = nil      // an Add matches nothing; it injects
            case .replace:         break                // uses both
            }
            return out
        }
    }

    var defaultDisposition: UnmatchedDisposition = .accept
    var rules: [RouteRule] = []

    init() {}

    /// True when this filter would leave any intent untouched.
    var isIdentity: Bool { self == RouteFilter() }

    // MARK: Transform

    /// Rewrite one engine's captured route intent → its effective intent. Rewrites
    /// `advertisedPrefixes` + `wantsDefault`. When the filter REMOVES a default the engine
    /// pushed (Ignore-default, or Replace-default-with-a-prefix), it also clears
    /// `canOwnDefault` so the arbiter can no longer make this profile the gateway — that
    /// is how "Ignore-default forces split" holds through arbitration. If the engine never
    /// pushed a default, eligibility is left exactly as captured (the gateway picker's job).
    func apply(to captured: RouteIntent, onMatch: ((UUID?) -> Void)? = nil) -> RouteIntent {
        guard !isIdentity else { return captured }

        var outPrefixes: [String] = []
        var outDefault = false

        func emit(_ target: RoutePrefix?) {
            guard let target, !target.isBlank else { return }
            if target.isDefault { outDefault = true; return }
            let c = target.normalized
            if !outPrefixes.contains(c) { outPrefixes.append(c) }
        }

        // Each pushed specific prefix, in order.
        for p in captured.advertisedPrefixes {
            switch dispositionForPrefix(p, onMatch: onMatch) {
            case .keep:
                let c = RoutePrefix(p).normalized
                if !c.isEmpty, !outPrefixes.contains(c) { outPrefixes.append(c) }
            case .drop:
                break
            case .replace(let target):
                emit(target)
            }
        }

        // The pushed default (if any).
        if captured.wantsDefault {
            switch dispositionForDefault(onMatch: onMatch) {
            case .keep:            outDefault = true
            case .drop:            break
            case .replace(let t):  emit(t)
            }
        }

        // Add rules inject unconditionally (deduped by `emit`).
        for rule in rules where rule.verb == .add { onMatch?(rule.id); emit(rule.target) }

        var out = captured
        out.prefixesRewritten = true
        out.advertisedPrefixes = outPrefixes
        out.wantsDefault = outDefault
        // Removing a pushed default forces split — drop ownership eligibility too.
        if captured.wantsDefault && !outDefault { out.canOwnDefault = false }
        return out
    }

    // MARK: Disposition resolution (first-match-wins)

    private enum Disposition { case keep, drop, replace(RoutePrefix?) }

    private func dispositionForPrefix(_ p: String, onMatch: ((UUID?) -> Void)?) -> Disposition {
        for rule in rules where rule.verb != .add {
            guard let m = rule.match, m.matches(pushedPrefix: p) else { continue }
            onMatch?(rule.id)
            return outcome(for: rule)
        }
        onMatch?(nil)
        return defaultDisposition == .accept ? .keep : .drop
    }

    private func dispositionForDefault(onMatch: ((UUID?) -> Void)?) -> Disposition {
        for rule in rules where rule.verb != .add {
            guard let m = rule.match, m.isDefault else { continue }
            onMatch?(rule.id)
            return outcome(for: rule)
        }
        onMatch?(nil)
        return defaultDisposition == .accept ? .keep : .drop
    }

    private func outcome(for rule: RouteRule) -> Disposition {
        switch rule.verb {
        case .accept:  return .keep
        case .ignore:  return .drop
        case .replace: return .replace(rule.target)
        case .add:     return .keep   // unreachable (filtered above)
        }
    }
}

// MARK: - DNS customization

/// Per-profile DNS rewrite: a verb machine over RESOLVER IPs (same four verbs as routes)
/// plus explicit domain handling. Domain edits are additive/subtractive lists rather than
/// a verb machine — that is what the resolver-vs-domain split in `DNSIntent` needs.
nonisolated struct DNSCustomization: Codable, Sendable, Equatable {

    /// A resolver rule = { verb, match resolver IP, target resolver IP }. `match` nil only
    /// for `.add`; `target` required for `.replace`/`.add`.
    nonisolated struct ResolverRule: Codable, Sendable, Equatable, Identifiable {
        var id: UUID
        var verb: FilterVerb
        var match: String?
        var target: String?

        init(id: UUID = UUID(), verb: FilterVerb, match: String? = nil, target: String? = nil) {
            self.id = id; self.verb = verb; self.match = match; self.target = target
        }

        /// Blank the fields this verb doesn't use — see
        /// `RouteFilter.RouteRule.clearingUnusedFields()` for why hiding isn't
        /// enough (`dispositionForResolver` and `applyResolverVerbs` read them).
        func clearingUnusedFields() -> ResolverRule {
            var out = self
            switch verb {
            case .accept, .ignore: out.target = nil
            case .add:             out.match = nil
            case .replace:         break
            }
            return out
        }
    }

    var defaultDisposition: UnmatchedDisposition = .accept
    var resolverRules: [ResolverRule] = []

    // Domain handling.
    /// Drop EVERY pushed search domain (before any Add).
    var ignorePushedSearchDomains = false
    /// Drop EVERY pushed match domain (before any Add) — collapses a split-DNS push.
    var ignorePushedMatchDomains = false
    /// Specific pushed search / match domains to drop (when not ignoring all).
    var ignoreSearchDomains: [String] = []
    var ignoreMatchDomains: [String] = []
    /// Domains to inject.
    var addSearchDomains: [String] = []
    var addMatchDomains: [String] = []

    // Query-name routing is separate from resolver-IP filtering and OS suffix scopes.
    var queryRoutingEnabled = false
    var queryRules: [DNSQueryRule] = []

    enum CodingKeys: String, CodingKey {
        case defaultDisposition, resolverRules, ignorePushedSearchDomains, ignorePushedMatchDomains
        case ignoreSearchDomains, ignoreMatchDomains, addSearchDomains, addMatchDomains
        case queryRoutingEnabled, queryRules
    }
    init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        defaultDisposition = try c.decodeIfPresent(UnmatchedDisposition.self, forKey: .defaultDisposition) ?? .accept
        resolverRules = try c.decodeIfPresent([ResolverRule].self, forKey: .resolverRules) ?? []
        ignorePushedSearchDomains = try c.decodeIfPresent(Bool.self, forKey: .ignorePushedSearchDomains) ?? false
        ignorePushedMatchDomains = try c.decodeIfPresent(Bool.self, forKey: .ignorePushedMatchDomains) ?? false
        ignoreSearchDomains = try c.decodeIfPresent([String].self, forKey: .ignoreSearchDomains) ?? []
        ignoreMatchDomains = try c.decodeIfPresent([String].self, forKey: .ignoreMatchDomains) ?? []
        addSearchDomains = try c.decodeIfPresent([String].self, forKey: .addSearchDomains) ?? []
        addMatchDomains = try c.decodeIfPresent([String].self, forKey: .addMatchDomains) ?? []
        queryRoutingEnabled = try c.decodeIfPresent(Bool.self, forKey: .queryRoutingEnabled) ?? false
        queryRules = try c.decodeIfPresent([DNSQueryRule].self, forKey: .queryRules) ?? []
    }

    init() {}

    var isIdentity: Bool { self == DNSCustomization() }

    var nativeSettings: Self {
        var native = self
        native.queryRoutingEnabled = false
        native.queryRules = []
        return native
    }

    /// Rewrite one engine's captured DNS intent → its effective intent. Rewrites
    /// `resolvers`, `searchDomains`, `matchDomains`. `wantsCatchAll` is left as captured —
    /// the DNS arbiter recomputes the catch-all from ownership + non-empty resolvers, so
    /// Ignoring all resolvers naturally drops this engine out of the catch-all.
    func apply(to captured: DNSIntent, onMatch: ((UUID?) -> Void)? = nil) -> DNSIntent {
        guard !isIdentity else { return captured }

        var out = captured
        out.resolvers = applyResolverVerbs(to: captured.resolvers, onMatch: onMatch)
        out.searchDomains = editDomains(captured.searchDomains,
                                        ignoreAll: ignorePushedSearchDomains,
                                        ignore: ignoreSearchDomains, add: addSearchDomains)
        out.matchDomains = editDomains(captured.matchDomains,
                                       ignoreAll: ignorePushedMatchDomains,
                                       ignore: ignoreMatchDomains, add: addMatchDomains)
        return out
    }

    // MARK: Resolver verb machine (Accept/Ignore/Replace/Add over IP strings)

    private func applyResolverVerbs(to pushed: [String], onMatch: ((UUID?) -> Void)?) -> [String] {
        var out: [String] = []
        func emit(_ ip: String?) {
            guard let ip = ip?.trimmingCharacters(in: .whitespacesAndNewlines), !ip.isEmpty else { return }
            if !out.contains(ip) { out.append(ip) }
        }
        for r in pushed {
            switch dispositionForResolver(r, onMatch: onMatch) {
            case .keep:            emit(r)
            case .drop:            break
            case .replace(let t):  emit(t)
            }
        }
        for rule in resolverRules where rule.verb == .add { onMatch?(rule.id); emit(rule.target) }
        return out
    }

    private enum Disposition { case keep, drop, replace(String?) }

    private func dispositionForResolver(_ ip: String, onMatch: ((UUID?) -> Void)?) -> Disposition {
        let key = ip.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        for rule in resolverRules where rule.verb != .add {
            guard let m = rule.match?.trimmingCharacters(in: .whitespacesAndNewlines).lowercased(),
                  m == key else { continue }
            onMatch?(rule.id)
            switch rule.verb {
            case .accept:  return .keep
            case .ignore:  return .drop
            case .replace: return .replace(rule.target)
            case .add:     return .keep
            }
        }
        onMatch?(nil)
        return defaultDisposition == .accept ? .keep : .drop
    }

    // MARK: Domain edits (ignore-all → subtract specific → add)

    private func editDomains(_ pushed: [String], ignoreAll: Bool,
                             ignore: [String], add: [String]) -> [String] {
        // DNS suffixes are case-insensitive and an absolute trailing dot is equivalent.
        // Preserve the empty catch-all sentinel; search-list normalisation drops it.
        func canonical(_ value: String) -> String { DNSSearchDomains.normalized(one: value) }
        let drop = Set(ignore.map(canonical))
        var out: [String] = []
        if !ignoreAll {
            for raw in pushed {
                let value = canonical(raw)
                if !drop.contains(value), !out.contains(value) { out.append(value) }
            }
        }
        for raw in add {
            let value = canonical(raw)
            if !value.isEmpty, !out.contains(value) { out.append(value) }
        }
        return out
    }
}
