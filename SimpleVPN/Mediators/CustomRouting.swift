// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
//  CustomRouting.swift
//  Per-VPN declarative "Custom Routing" — the TIER-2 (static, UI-driven) form of the
//  tier-3 `ROUTE_ADVERTISED`/`DNS_PUSHED`/`PROXY_PUSHED` rewrite hooks
//  (Docs/StateMediators.md › Intent capture). A `CustomRoutingProfile` is a per-profile
//  filter that rewrites what an engine pushed BEFORE it reaches the mediator arbiter:
//
//        capturedIntent ──▶ applyFilter(profile) ──▶ effectiveIntent ──▶ mediator
//
//  It attaches at each mediator's single intent-capture seam (`intentHook`), so a live
//  session re-arbitrates + live-applies with no reconnect. An empty/absent filter is
//  the IDENTITY transform — a profile with no customization behaves exactly as before.
//
//  Three resources, three verb sets (from the user):
//    • Routes: Accept / Ignore / Replace / Add  (+ a per-filter default disposition:
//              Accept-unmatched (default) or allow-list = Ignore-unmatched).
//    • DNS:    Accept / Ignore / Replace / Add over RESOLVERS, plus domain handling
//              (add/ignore search & match domains, ignore-all-pushed toggles).
//    • Proxy:  Accept / Ignore / Custom (single value): keep the pushed proxy, force
//              direct, or override with a manual URL / PAC URL. A keychain auth REF
//              rides Accept (a pushed proxy behind sign-in) and Custom alike.
//
//  Route matching is EXACT prefix + a `default` token (0.0.0.0/0 · ::/0). CIDR-contains
//  matching is a documented follow-up (see `RoutePrefix.matches`).
//
//  Persistence: one JSON blob at providerConfiguration["customrouting"], omitted when
//  empty (so existing profiles decode as "no customization"). Decoding is LENIENT — a
//  missing/renamed field degrades to its default rather than nuking the whole blob, so
//  the app and a future version never break each other. Secrets are NEVER inline: proxy
//  auth is a keychain REF only.
//
//  Everything here is a pure value type (`nonisolated`, Codable/Sendable) with no I/O,
//  so the transforms are unit-testable in isolation like `GatewayPolicy`.
//

import Foundation

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
    /// Trimmed + lowercased, for case-insensitive IPv6 and whitespace tolerance.
    var normalized: String { value.trimmingCharacters(in: .whitespacesAndNewlines).lowercased() }
    var isBlank: Bool { normalized.isEmpty }

    /// EXACT match only (documented limitation — CIDR-CONTAINS is a follow-up). A default
    /// token matches the pushed default; a specific prefix matches an identical string.
    func matches(pushedPrefix p: String) -> Bool {
        guard !isDefault else { return false }
        return normalized == p.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
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
    func apply(to captured: RouteIntent) -> RouteIntent {
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
            switch dispositionForPrefix(p) {
            case .keep:
                let c = p.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
                if !c.isEmpty, !outPrefixes.contains(c) { outPrefixes.append(c) }
            case .drop:
                break
            case .replace(let target):
                emit(target)
            }
        }

        // The pushed default (if any).
        if captured.wantsDefault {
            switch dispositionForDefault() {
            case .keep:            outDefault = true
            case .drop:            break
            case .replace(let t):  emit(t)
            }
        }

        // Add rules inject unconditionally (deduped by `emit`).
        for rule in rules where rule.verb == .add { emit(rule.target) }

        var out = captured
        out.advertisedPrefixes = outPrefixes
        out.wantsDefault = outDefault
        // Removing a pushed default forces split — drop ownership eligibility too.
        if captured.wantsDefault && !outDefault { out.canOwnDefault = false }
        return out
    }

    // MARK: Disposition resolution (first-match-wins)

    private enum Disposition { case keep, drop, replace(RoutePrefix?) }

    private func dispositionForPrefix(_ p: String) -> Disposition {
        for rule in rules where rule.verb != .add {
            guard let m = rule.match, m.matches(pushedPrefix: p) else { continue }
            return outcome(for: rule)
        }
        return defaultDisposition == .accept ? .keep : .drop
    }

    private func dispositionForDefault() -> Disposition {
        for rule in rules where rule.verb != .add {
            guard let m = rule.match, m.isDefault else { continue }
            return outcome(for: rule)
        }
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

    init() {}

    var isIdentity: Bool { self == DNSCustomization() }

    /// Rewrite one engine's captured DNS intent → its effective intent. Rewrites
    /// `resolvers`, `searchDomains`, `matchDomains`. `wantsCatchAll` is left as captured —
    /// the DNS arbiter recomputes the catch-all from ownership + non-empty resolvers, so
    /// Ignoring all resolvers naturally drops this engine out of the catch-all.
    func apply(to captured: DNSIntent) -> DNSIntent {
        guard !isIdentity else { return captured }

        var out = captured
        out.resolvers = applyResolverVerbs(to: captured.resolvers)
        out.searchDomains = editDomains(captured.searchDomains,
                                        ignoreAll: ignorePushedSearchDomains,
                                        ignore: ignoreSearchDomains, add: addSearchDomains)
        out.matchDomains = editDomains(captured.matchDomains,
                                       ignoreAll: ignorePushedMatchDomains,
                                       ignore: ignoreMatchDomains, add: addMatchDomains)
        return out
    }

    // MARK: Resolver verb machine (Accept/Ignore/Replace/Add over IP strings)

    private func applyResolverVerbs(to pushed: [String]) -> [String] {
        var out: [String] = []
        func emit(_ ip: String?) {
            guard let ip = ip?.trimmingCharacters(in: .whitespacesAndNewlines), !ip.isEmpty else { return }
            if !out.contains(ip) { out.append(ip) }
        }
        for r in pushed {
            switch dispositionForResolver(r) {
            case .keep:            emit(r)
            case .drop:            break
            case .replace(let t):  emit(t)
            }
        }
        for rule in resolverRules where rule.verb == .add { emit(rule.target) }
        return out
    }

    private enum Disposition { case keep, drop, replace(String?) }

    private func dispositionForResolver(_ ip: String) -> Disposition {
        let key = ip.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        for rule in resolverRules where rule.verb != .add {
            guard let m = rule.match?.trimmingCharacters(in: .whitespacesAndNewlines).lowercased(),
                  m == key else { continue }
            switch rule.verb {
            case .accept:  return .keep
            case .ignore:  return .drop
            case .replace: return .replace(rule.target)
            case .add:     return .keep
            }
        }
        return defaultDisposition == .accept ? .keep : .drop
    }

    // MARK: Domain edits (ignore-all → subtract specific → add)

    private func editDomains(_ pushed: [String], ignoreAll: Bool,
                             ignore: [String], add: [String]) -> [String] {
        var out: [String] = ignoreAll ? [] : pushed
        if !ignoreAll, !ignore.isEmpty {
            let drop = Set(ignore.map { $0.trimmingCharacters(in: .whitespacesAndNewlines).lowercased() })
            out = out.filter { !drop.contains($0.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()) }
        }
        for d in add {
            let t = d.trimmingCharacters(in: .whitespacesAndNewlines)
            guard !t.isEmpty, !out.contains(t) else { continue }
            out.append(t)
        }
        return out
    }
}

// MARK: - Proxy customization

/// The one authoritative shape of the proxy-auth keychain REF (`authSource`): the editor
/// mints it, the realizer parses it back to the profile whose
/// `KeychainCredentialStore.loadCustomRoutingProxyAuth` row holds the sign-in. A prefix
/// (rather than the bare id) so a future second source kind can coexist in the field.
nonisolated enum ProxyAuthSourceRef {
    static let prefix = "customrouting:"
    static func ref(forProfile id: String) -> String { prefix + id }
    static func profileID(from source: String) -> String? {
        guard source.hasPrefix(prefix) else { return nil }
        let id = String(source.dropFirst(prefix.count))
        return id.isEmpty ? nil : id
    }
}

/// Per-profile proxy override — a SINGLE value, so three verbs not four: keep the pushed
/// proxy (`accept`), force direct (`ignore` ⇒ nil intent), or override with the user's
/// own manual URL / PAC (`custom`). Auth is a keychain REF only — never inline creds.
nonisolated struct ProxyCustomization: Codable, Sendable, Equatable {

    nonisolated enum Mode: String, Codable, Sendable, CaseIterable {
        case accept   // use the pushed proxy as-is
        case ignore   // no proxy (direct)
        case custom   // user URL / PAC overrides
    }

    var mode: Mode = .accept
    /// Custom manual proxy: `http://`, `https://`, or `socks5://` host:port.
    var manualURL: String?
    /// Custom PAC URL (wins over `manualURL` when both are set).
    var pacURL: String?
    /// Keychain reference for proxy auth (NEVER inline credentials).
    var authSource: String?

    init() {}

    var isIdentity: Bool { self == ProxyCustomization() }

    /// Whether the effective custom value is a SOCKS manual proxy (no PAC over it) —
    /// the one custom shape the native NEVPNManager kinds can't carry, since
    /// `NEProxySettings` has no SOCKS slot; the editor warns for those kinds.
    var customIsSOCKS: Bool {
        guard mode == .custom,
              (pacURL ?? "").trimmingCharacters(in: .whitespacesAndNewlines).isEmpty,
              let manual = manualURL, let e = Self.parseManual(manual) else { return false }
        return e.scheme == .socks
    }

    /// Rewrite one engine's captured proxy intent → its effective intent.
    ///   • `accept`  ⇒ pass the captured intent through, attaching the stored sign-in's
    ///     `authSource` REF when one is configured — this is how a PUSHED proxy that
    ///     requires authentication gets its credentials (the push itself never carries
    ///     any; the realizer resolves the REF from the keychain at apply time).
    ///   • `ignore`  ⇒ nil (this engine contributes no proxy — direct).
    ///   • `custom`  ⇒ build a user-sourced intent from `pacURL` (preferred) or
    ///     `manualURL`; if custom is selected but nothing parses, fall back to captured.
    /// `engine` is required because `custom` can synthesize an intent even when the engine
    /// pushed nothing (captured == nil).
    func apply(to captured: ProxyIntent?, engine: String) -> ProxyIntent? {
        switch mode {
        case .accept:
            guard var out = captured else { return nil }
            if out.providesProxy, let authSource { out.authSource = authSource }
            return out
        case .ignore:
            return nil
        case .custom:
            if let pac = pacURL?.trimmingCharacters(in: .whitespacesAndNewlines), !pac.isEmpty {
                return ProxyIntent(engine: engine, mode: .pac(pac),
                                   connectedAt: captured?.connectedAt, authSource: authSource)
            }
            if let manual = manualURL, let e = Self.parseManual(manual) {
                var m = ProxyManual()
                switch e.scheme {
                case .http:  m.http = e
                case .https: m.https = e
                case .socks: m.socks = e
                }
                return ProxyIntent(engine: engine, mode: .manual(e),
                                   connectedAt: captured?.connectedAt,
                                   manual: m, authSource: authSource)
            }
            return captured
        }
    }

    /// Parse a `scheme://host:port` proxy URL into an endpoint. `socks5`/`socks` ⇒
    /// `.socks`. An unparseable / unknown-scheme string returns nil (custom then no-ops).
    static func parseManual(_ s: String) -> ProxyEndpoint? {
        let trimmed = s.trimmingCharacters(in: .whitespacesAndNewlines)
        guard let url = URL(string: trimmed), let host = url.host, !host.isEmpty,
              let rawScheme = url.scheme?.lowercased() else { return nil }
        let scheme: ProxyScheme
        let defaultPort: Int
        switch rawScheme {
        case "http":            scheme = .http;  defaultPort = 8080
        case "https":           scheme = .https; defaultPort = 8080
        case "socks5", "socks": scheme = .socks; defaultPort = 1080
        default:                return nil
        }
        return ProxyEndpoint(scheme: scheme, host: host, port: url.port ?? defaultPort)
    }

    /// The user's CUSTOM proxy as the tier-2 apply payload, for the kinds where the APP
    /// is the applier at connect time — the native NEVPNManager kinds carry it on
    /// `NEVPNProtocol.proxySettings` (see `NativeVPNManager.connect`), with the sign-in
    /// riding `NEProxyServer.username`/`password`, never the stored config. nil unless
    /// the mode is `.custom` with a usable value; a SOCKS manual proxy maps to nil too
    /// (`NEProxySettings` has no SOCKS slot — http/https/PAC only, which the editor
    /// calls out for these kinds).
    func nativeApplyRequest(username: String? = nil, password: String? = nil) -> ProxyApplyRequest? {
        guard mode == .custom, let intent = apply(to: nil, engine: "native"),
              intent.providesProxy else { return nil }
        let request = ProxyPlan(owner: intent.engine, mode: intent.mode, manual: intent.manual,
                                bypass: intent.bypass,
                                excludeSimpleHostnames: intent.excludeSimpleHostnames)
            .applyRequest(username: username, password: password)
        return request.isEmpty ? nil : request
    }
}

// MARK: - The per-profile aggregate (persisted blob)

/// One profile's complete Custom Routing configuration. Persisted as a single JSON blob
/// in providerConfiguration["customrouting"]; omitted entirely when all three filters are
/// at their identity, so a profile that never opened the tab decodes as "no customization"
/// and the transform is a no-op.
nonisolated struct CustomRoutingProfile: Codable, Sendable, Equatable {

    /// Bumped only on a SEMANTIC change to an existing key. Newer schemas decode
    /// best-effort, never rejected.
    static let currentSchema = 1
    var schema: Int = Self.currentSchema

    var routes = RouteFilter()
    var dns = DNSCustomization()
    var proxy = ProxyCustomization()

    init() {}

    /// True when nothing is customized (the blob is dropped in that case).
    var isEmpty: Bool {
        routes.isIdentity && dns.isIdentity && proxy.isIdentity
    }

    // MARK: Serialization (mirrors OpenVPNOverrides / VPNUIPrefs)

    func encodedBlob() -> Data? {
        guard !isEmpty else { return nil }
        return try? JSONEncoder().encode(self)
    }

    static func decode(from blob: Data?) -> CustomRoutingProfile {
        guard let blob else { return CustomRoutingProfile() }
        return (try? JSONDecoder().decode(CustomRoutingProfile.self, from: blob)) ?? CustomRoutingProfile()
    }

    // MARK: Lenient Codable
    //
    // A missing/renamed top-level field degrades to its default rather than throwing and
    // nuking the whole blob (app ↔ future-version skew must never break each other).

    enum CodingKeys: String, CodingKey { case schema, routes, dns, proxy }

    init(from decoder: Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        schema = (try? c.decodeIfPresent(Int.self, forKey: .schema)) ?? Self.currentSchema
        routes = ((try? c.decodeIfPresent(RouteFilter.self, forKey: .routes)) ?? nil) ?? RouteFilter()
        dns    = ((try? c.decodeIfPresent(DNSCustomization.self, forKey: .dns)) ?? nil) ?? DNSCustomization()
        proxy  = ((try? c.decodeIfPresent(ProxyCustomization.self, forKey: .proxy)) ?? nil) ?? ProxyCustomization()
    }
}

// MARK: - Last-seen pushed intent (durable, per profile)

/// A durable snapshot of what an engine PUSHED last time it was captured — the raw,
/// PRE-filter intent, per resource. Purpose: the Custom Routing UI must let the user write
/// Accept/Ignore/Replace rules against "what this VPN pushed last time" even while OFFLINE,
/// and see the live set when online. Updated on every fresh capture; the last-known value
/// survives disconnect + relaunch (App Group backed).
nonisolated struct PushedIntentSnapshot: Codable, Sendable, Equatable {

    nonisolated struct Routes: Codable, Sendable, Equatable {
        var advertisedPrefixes: [String] = []
        var wantsDefault = false
        var isEmpty: Bool { advertisedPrefixes.isEmpty && !wantsDefault }
    }

    nonisolated struct DNS: Codable, Sendable, Equatable {
        var resolvers: [String] = []
        var searchDomains: [String] = []
        var matchDomains: [String] = []
        var isEmpty: Bool { resolvers.isEmpty && searchDomains.isEmpty && matchDomains.isEmpty }
    }

    /// Flattened proxy push (the enum `ProxyIntent.Mode` isn't directly Codable). nil ⇒ the
    /// engine pushed no proxy.
    nonisolated struct Proxy: Codable, Sendable, Equatable {
        var pacURL: String?
        var httpHost: String?;  var httpPort: Int?
        var httpsHost: String?; var httpsPort: Int?
        var socksHost: String?; var socksPort: Int?

        var isEmpty: Bool {
            pacURL == nil && httpHost == nil && httpsHost == nil && socksHost == nil
        }

        /// Build from a captured `ProxyIntent`; nil when it provides no proxy.
        init?(_ intent: ProxyIntent) {
            guard intent.providesProxy else { return nil }
            if case .pac(let u) = intent.mode { pacURL = u }
            if let m = intent.manual {
                httpHost = m.http?.host;   httpPort = m.http?.port
                httpsHost = m.https?.host; httpsPort = m.https?.port
                socksHost = m.socks?.host; socksPort = m.socks?.port
            } else if case .manual(let e) = intent.mode {
                switch e.scheme {
                case .http:  httpHost = e.host;  httpPort = e.port
                case .https: httpsHost = e.host; httpsPort = e.port
                case .socks: socksHost = e.host; socksPort = e.port
                }
            }
        }
    }

    var routes = Routes()
    var dns = DNS()
    var proxy: Proxy?
    /// When any resource was last refreshed.
    var capturedAt: Date?

    init() {}

    var isEmpty: Bool { routes.isEmpty && dns.isEmpty && (proxy?.isEmpty ?? true) }
}

/// Reads/writes `PushedIntentSnapshot`s in the App Group (the profile store the mediators
/// already use for the gateway pick). Injectable `UserDefaults` for tests. `nonisolated` +
/// value semantics so it's callable from any actor.
nonisolated struct PushedIntentStore {
    let defaults: UserDefaults?

    init(defaults: UserDefaults? = UserDefaults(suiteName: "group.com.bragi0.SimpleVPN")) {
        self.defaults = defaults
    }

    private func key(_ id: String) -> String { "pushedIntent.\(id)" }

    func load(_ id: String) -> PushedIntentSnapshot? {
        guard let data = defaults?.data(forKey: key(id)) else { return nil }
        return try? JSONDecoder().decode(PushedIntentSnapshot.self, from: data)
    }

    func save(_ snapshot: PushedIntentSnapshot, for id: String) {
        guard let data = try? JSONEncoder().encode(snapshot) else { return }
        defaults?.set(data, forKey: key(id))
    }

    func clear(_ id: String) { defaults?.removeObject(forKey: key(id)) }
}

/// Reads/writes `CustomRoutingProfile`s for profiles with NO `NETunnelProviderManager`
/// to carry the blob in providerConfiguration — the native NEVPNManager kinds, whose
/// own configs live in `UserDefaults.standard` the same way (see `NativeVPNManager`).
/// Carries no secrets: proxy auth is the keychain REF only. Injectable defaults for
/// tests, mirroring `PushedIntentStore`.
nonisolated struct CustomRoutingFallbackStore {
    let defaults: UserDefaults?

    init(defaults: UserDefaults? = .standard) { self.defaults = defaults }

    private func key(_ id: String) -> String { "customrouting.\(id)" }

    func load(_ id: String) -> CustomRoutingProfile {
        CustomRoutingProfile.decode(from: defaults?.data(forKey: key(id)))
    }

    /// An identity (all-defaults) profile drops the entry, matching how the
    /// providerConfiguration blob is omitted when empty.
    func save(_ profile: CustomRoutingProfile, for id: String) {
        if let blob = profile.encodedBlob() { defaults?.set(blob, forKey: key(id)) }
        else { defaults?.removeObject(forKey: key(id)) }
    }

    func clear(_ id: String) { defaults?.removeObject(forKey: key(id)) }
}

// MARK: - Rule status (pure diagnostics against the pushed set)

/// How a filter rule relates to what the VPN actually pushed (last-seen snapshot, or live
/// when connected) — a UI hint so the user can see a rule that no longer bites. PURE +
/// testable; the UI renders an icon + explanation next phase.
nonisolated enum RuleStatus: String, Sendable, Equatable, CaseIterable {
    /// The rule matches/acts on something in the pushed set.
    case active
    /// The matched route/resolver is no longer present — nothing to act on (an Ignore /
    /// Accept, or a Replace whose match vanished; an Accept-proxy with no pushed proxy).
    case orphaned
    /// The replacement/addition is a no-op — a Replace/Add whose target EXACTLY equals a
    /// pushed item.
    case redundant
    /// An Add whose target OVERLAPS a pushed route (CIDR intersection/containment, not
    /// exact) — the injected prefix already partly covered.
    case overlapping
}

extension RouteFilter {
    /// Status of one route rule against the pushed route set. Route MATCHING stays
    /// exact-prefix+default (as briefed); `.overlapping` uses the CIDR-overlap helper —
    /// for the hint only.
    func ruleStatus(_ rule: RouteRule, against pushed: PushedIntentSnapshot.Routes) -> RuleStatus {
        let pushedSet = Set(pushed.advertisedPrefixes.map {
            $0.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        })
        func present(_ p: RoutePrefix) -> Bool {
            p.isDefault ? pushed.wantsDefault : pushedSet.contains(p.normalized)
        }
        switch rule.verb {
        case .accept, .ignore:
            guard let m = rule.match else { return .active }
            return present(m) ? .active : .orphaned
        case .replace:
            guard let m = rule.match else { return .active }
            guard present(m) else { return .orphaned }
            if let t = rule.target, present(t) { return .redundant }
            return .active
        case .add:
            guard let t = rule.target else { return .active }
            if present(t) { return .redundant }
            if !t.isDefault, pushedSet.contains(where: { RoutePrefixMath.overlaps(t.normalized, $0) }) {
                return .overlapping
            }
            return .active
        }
    }
}

extension DNSCustomization {
    /// Status of one resolver rule against the pushed resolver set. Resolvers are host IPs,
    /// so there is no CIDR-overlap axis — only exact presence.
    func ruleStatus(_ rule: ResolverRule, against pushed: PushedIntentSnapshot.DNS) -> RuleStatus {
        let set = Set(pushed.resolvers.map { $0.trimmingCharacters(in: .whitespacesAndNewlines).lowercased() })
        func present(_ ip: String?) -> Bool {
            guard let ip = ip?.trimmingCharacters(in: .whitespacesAndNewlines).lowercased(), !ip.isEmpty
            else { return false }
            return set.contains(ip)
        }
        switch rule.verb {
        case .accept, .ignore:
            guard rule.match != nil else { return .active }
            return present(rule.match) ? .active : .orphaned
        case .replace:
            guard rule.match != nil else { return .active }
            guard present(rule.match) else { return .orphaned }
            return present(rule.target) ? .redundant : .active
        case .add:
            guard rule.target != nil else { return .active }
            return present(rule.target) ? .redundant : .active
        }
    }
}

extension ProxyCustomization {
    /// Status of the single proxy customization against the pushed proxy. Custom is always
    /// active; Accept/Ignore are orphaned when the VPN pushes no proxy (nothing to act on).
    func ruleStatus(against pushed: PushedIntentSnapshot.Proxy?) -> RuleStatus {
        switch mode {
        case .custom: return .active
        case .accept, .ignore: return (pushed?.isEmpty ?? true) ? .orphaned : .active
        }
    }
}

// MARK: - CIDR overlap (status hints only — the filter itself stays exact-match)

/// Whether two CIDR prefixes intersect (one contains the other). Same address family only.
/// Used ONLY by `RuleStatus` to flag an Add that overlaps a pushed route — the filter's own
/// route matching is deliberately EXACT prefix + default token (a documented follow-up is
/// contains-matching in the filter itself).
nonisolated enum RoutePrefixMath {

    static func overlaps(_ a: String, _ b: String) -> Bool {
        guard let pa = parse(a), let pb = parse(b), pa.v6 == pb.v6 else { return false }
        return prefixEqual(pa.bytes, pb.bytes, bits: min(pa.prefix, pb.prefix))
    }

    private static func parse(_ s: String) -> (bytes: [UInt8], prefix: Int, v6: Bool)? {
        let trimmed = s.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else { return nil }
        let parts = trimmed.split(separator: "/", maxSplits: 1, omittingEmptySubsequences: false)
        let addrStr = String(parts[0])
        let v6 = addrStr.contains(":")
        let maxLen = v6 ? 128 : 32
        var prefix = maxLen
        if parts.count == 2 {
            guard let p = Int(parts[1]), p >= 0, p <= maxLen else { return nil }
            prefix = p
        }
        var buf = [UInt8](repeating: 0, count: v6 ? 16 : 4)
        let ok = addrStr.withCString { inet_pton(v6 ? AF_INET6 : AF_INET, $0, &buf) == 1 }
        guard ok else { return nil }
        return (buf, prefix, v6)
    }

    private static func prefixEqual(_ a: [UInt8], _ b: [UInt8], bits: Int) -> Bool {
        guard a.count == b.count else { return false }
        let fullBytes = bits / 8
        for i in 0..<fullBytes where a[i] != b[i] { return false }
        let rem = bits % 8
        if rem > 0 {
            let mask = UInt8(truncatingIfNeeded: 0xFF << (8 - rem))
            if (a[fullBytes] & mask) != (b[fullBytes] & mask) { return false }
        }
        return true
    }
}

// MARK: - Validation (pure, structured, reusable by the editor AND the Routes window)

/// One structured validation problem — the UI renders it as an error/warning icon with the
/// message as a tooltip. Equatable on its content (not identity) so tests can assert on it;
/// `id` is derived for `List`/`ForEach`.
nonisolated struct ValidationIssue: Sendable, Equatable, Identifiable {
    nonisolated enum Severity: String, Sendable, Equatable, CaseIterable {
        case error, warning
    }
    var severity: Severity
    /// Which field the issue attaches to (e.g. "match", "target", "manualURL", "resolver",
    /// "searchDomain", "filter") — a stable key the UI maps to a control.
    var field: String
    var message: String
    /// For overlap/conflict warnings: a machine-usable reference to EACH thing this entry
    /// overlaps (a sibling rule by stable id/index, or a pushed route by value), so the UI
    /// can anchor an arrow from the offending control to every conflicting target. Empty for
    /// non-overlap issues.
    var related: [ValidationRef]

    init(_ severity: Severity, field: String, message: String, related: [ValidationRef] = []) {
        self.severity = severity; self.field = field; self.message = message; self.related = related
    }

    var id: String { "\(severity.rawValue)|\(field)|\(message)" }
    var isError: Bool { severity == .error }
}

/// A machine-usable pointer to what an overlap warning conflicts with.
nonisolated struct ValidationRef: Sendable, Equatable {
    nonisolated enum Kind: String, Sendable, Equatable { case rule, pushedRoute }
    var kind: Kind
    /// The conflicting rule's stable id (`.rule` only).
    var ruleID: UUID?
    /// The conflicting rule's index in the filter (`.rule` only).
    var ruleIndex: Int?
    /// The conflicting route value — the sibling rule's route, or the pushed route.
    var value: String

    static func rule(_ id: UUID, index: Int, value: String) -> ValidationRef {
        ValidationRef(kind: .rule, ruleID: id, ruleIndex: index, value: value)
    }
    static func pushedRoute(_ value: String) -> ValidationRef {
        ValidationRef(kind: .pushedRoute, ruleID: nil, ruleIndex: nil, value: value)
    }
}

/// Pure validators for Custom Routing. No I/O, fully unit-testable; both the SwiftUI editor
/// and the Routes window call these and render the returned issues as icons + tooltips.
///
/// Route CIDRs with host bits set are an ERROR (we do not silently normalize — the user
/// should see and fix the network address, e.g. `10.1.2.3/8` → `10.0.0.0/8`).
nonisolated enum CustomRoutingValidator {

    // MARK: Route rules

    static func validate(_ rule: RouteFilter.RouteRule) -> [ValidationIssue] {
        var issues: [ValidationIssue] = []
        switch rule.verb {
        case .accept, .ignore:
            issues += validateCIDR(rule.match, field: "match", required: true)
        case .replace:
            issues += validateCIDR(rule.match, field: "match", required: true)
            issues += validateCIDR(rule.target, field: "target", required: true)
            if let t = rule.target, isDefaultLike(t) {
                issues.append(.init(.warning, field: "target",
                    message: "Replacing with the default route (/0) sends everything through this VPN."))
            }
        case .add:
            issues += validateCIDR(rule.target, field: "target", required: true)
            if let t = rule.target, isDefaultLike(t) {
                issues.append(.init(.warning, field: "target",
                    message: "Adding the default route (/0) makes this VPN carry all traffic."))
            }
        }
        return issues
    }

    /// Per-rule + cross-rule for a whole route filter. Pass the profile's pushed snapshot
    /// to also get OVERLAP warnings (a rule's route intersecting another rule's route or a
    /// route the VPN actually pushed), each attributed to the offending field.
    static func validate(_ filter: RouteFilter, against pushed: PushedIntentSnapshot.Routes? = nil) -> [ValidationIssue] {
        var issues = filter.rules.flatMap { validate($0) }
        issues += crossRuleRoutes(filter)
        issues += overlapIssues(filter, pushed: pushed)
        return issues
    }

    /// Overlap warnings: for every valid CIDR a rule carries (match and/or target), flag
    /// when it INTERSECTS (CIDR containment/intersection, via `RoutePrefixMath`) another
    /// rule's route or a pushed route. Exact same-rule-set duplicates are left to
    /// `crossRuleRoutes`; here we name what each route overlaps so the editor can bubble the
    /// warning up at the specific `match`/`target` control. Emitted for BOTH sides of an
    /// overlapping pair so each control lights up.
    private static func overlapIssues(_ filter: RouteFilter, pushed: PushedIntentSnapshot.Routes?) -> [ValidationIssue] {
        struct Entry { let idx: Int; let ruleID: UUID; let field: String; let value: String }
        var entries: [Entry] = []
        for (i, r) in filter.rules.enumerated() {
            func take(_ p: RoutePrefix?, _ field: String) {
                guard let p, !p.isDefault, case .ok = parseCIDR(p.value) else { return }
                entries.append(Entry(idx: i, ruleID: r.id, field: field, value: p.normalized))
            }
            switch r.verb {
            case .accept, .ignore: take(r.match, "match")
            case .replace:         take(r.match, "match"); take(r.target, "target")
            case .add:             take(r.target, "target")
            }
        }
        let pushedValid: [String] = (pushed?.advertisedPrefixes ?? []).compactMap {
            guard case .ok = parseCIDR($0) else { return nil }
            return $0.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        }

        // One aggregated issue per entry listing EVERYTHING it overlaps (pushed routes then
        // sibling rules), with a machine-usable `related` ref for each so the UI can draw an
        // arrow to each conflict. Exact sibling dups stay with `crossRuleRoutes`; exact
        // pushed dups are surfaced here (nothing else covers them).
        var issues: [ValidationIssue] = []
        for e in entries {
            var refs: [ValidationRef] = []
            var names: [String] = []
            for p in pushedValid where RoutePrefixMath.overlaps(e.value, p) {
                refs.append(.pushedRoute(p))
                names.append(e.value == p ? "\(p) (duplicate) pushed by this VPN"
                                          : "\(p) pushed by this VPN")
            }
            for other in entries where other.idx != e.idx {
                guard e.value != other.value, RoutePrefixMath.overlaps(e.value, other.value) else { continue }
                refs.append(.rule(other.ruleID, index: other.idx, value: other.value))
                names.append("\(filter.rules[other.idx].verb.rawValue) rule \(other.value)")
            }
            guard !refs.isEmpty else { continue }
            issues.append(.init(.warning, field: e.field,
                message: "\(e.value) overlaps \(names.joined(separator: ", ")).",
                related: refs))
        }
        return issues
    }

    private static func crossRuleRoutes(_ filter: RouteFilter) -> [ValidationIssue] {
        var issues: [ValidationIssue] = []

        // Conflicting rules on the same match (Ignore vs Replace/Accept, or any duplicate).
        var verbsByMatch: [String: [FilterVerb]] = [:]
        for r in filter.rules where r.verb != .add {
            guard let m = r.match?.normalized, !m.isEmpty else { continue }
            verbsByMatch[m, default: []].append(r.verb)
        }
        for m in verbsByMatch.keys.sorted() {
            let verbs = verbsByMatch[m]!
            guard verbs.count > 1 else { continue }
            let set = Set(verbs)
            if set.contains(.ignore) && (set.contains(.replace) || set.contains(.accept)) {
                issues.append(.init(.warning, field: "match",
                    message: "Contradictory rules match \(m) — only the first applies."))
            } else {
                issues.append(.init(.warning, field: "match",
                    message: "\(verbs.count) rules match \(m) — only the first applies."))
            }
        }

        // Duplicate Add/Replace targets (a redundant injection).
        var targetCounts: [String: Int] = [:]
        for r in filter.rules where r.verb == .add || r.verb == .replace {
            guard let t = r.target, !isDefaultLike(t) else { continue }
            let n = t.normalized
            guard !n.isEmpty else { continue }
            targetCounts[n, default: 0] += 1
        }
        for t in targetCounts.keys.sorted() where targetCounts[t]! > 1 {
            issues.append(.init(.warning, field: "target",
                message: "\(targetCounts[t]!) rules add/replace to \(t) — the duplicate is redundant."))
        }
        return issues
    }

    // MARK: DNS

    static func validate(_ rule: DNSCustomization.ResolverRule) -> [ValidationIssue] {
        var issues: [ValidationIssue] = []
        switch rule.verb {
        case .accept, .ignore:
            issues += validateIP(rule.match, field: "resolver", required: true)
        case .replace:
            issues += validateIP(rule.match, field: "resolver", required: true)
            issues += validateIP(rule.target, field: "target", required: true)
        case .add:
            issues += validateIP(rule.target, field: "target", required: true)
        }
        return issues
    }

    static func validate(_ dns: DNSCustomization) -> [ValidationIssue] {
        var issues = dns.resolverRules.flatMap { validate($0) }
        for d in dns.addSearchDomains + dns.ignoreSearchDomains where !isValidDomain(d) {
            issues.append(.init(.error, field: "searchDomain", message: "\"\(d)\" is not a valid domain."))
        }
        for d in dns.addMatchDomains + dns.ignoreMatchDomains where !isValidDomain(d) {
            issues.append(.init(.error, field: "matchDomain", message: "\"\(d)\" is not a valid domain."))
        }
        // Cross-rule: conflicting/duplicate resolver rules.
        var verbsByMatch: [String: [FilterVerb]] = [:]
        for r in dns.resolverRules where r.verb != .add {
            guard let m = r.match?.trimmingCharacters(in: .whitespacesAndNewlines).lowercased(), !m.isEmpty else { continue }
            verbsByMatch[m, default: []].append(r.verb)
        }
        for m in verbsByMatch.keys.sorted() where verbsByMatch[m]!.count > 1 {
            issues.append(.init(.warning, field: "resolver",
                message: "Multiple rules match resolver \(m) — only the first applies."))
        }
        return issues
    }

    // MARK: Proxy

    static func validate(_ proxy: ProxyCustomization) -> [ValidationIssue] {
        guard proxy.mode == .custom else { return [] }
        var issues: [ValidationIssue] = []
        let pac = proxy.pacURL?.trimmingCharacters(in: .whitespacesAndNewlines)
        let manual = proxy.manualURL?.trimmingCharacters(in: .whitespacesAndNewlines)
        if let pac, !pac.isEmpty {
            if !isValidWebURL(pac) {
                issues.append(.init(.error, field: "pacURL", message: "PAC URL must be a valid http/https URL."))
            }
        } else if let manual, !manual.isEmpty {
            if ProxyCustomization.parseManual(manual) == nil {
                issues.append(.init(.error, field: "manualURL",
                    message: "Proxy must be a valid http://, https:// or socks5:// URL with a host."))
            } else if let port = URL(string: manual)?.port, !(1...65535).contains(port) {
                issues.append(.init(.error, field: "manualURL", message: "Proxy port must be 1…65535."))
            }
        } else {
            issues.append(.init(.error, field: "manualURL", message: "A custom proxy needs a URL or a PAC URL."))
        }
        return issues
    }

    // MARK: Whole profile

    static func validate(_ profile: CustomRoutingProfile,
                         against pushed: PushedIntentSnapshot? = nil) -> [ValidationIssue] {
        validate(profile.routes, against: pushed?.routes)
            + validate(profile.dns)
            + validate(profile.proxy)
    }

    // MARK: - Field validators

    /// Validate a route CIDR field: valid IPv4/IPv6 address, prefix length in range, host
    /// bits clear; the `default` token is always valid. Emits suspicious-address warnings.
    static func validateCIDR(_ prefix: RoutePrefix?, field: String, required: Bool) -> [ValidationIssue] {
        guard let prefix, !prefix.isBlank else {
            return required ? [.init(.error, field: field, message: "A route is required.")] : []
        }
        if prefix.isDefault { return [] }
        switch parseCIDR(prefix.value) {
        case .badAddress:
            return [.init(.error, field: field, message: "\"\(prefix.value)\" is not a valid IPv4/IPv6 CIDR.")]
        case .badPrefix(let max):
            return [.init(.error, field: field, message: "Prefix length must be 0…\(max).")]
        case .ok(let parsed):
            var issues: [ValidationIssue] = []
            if parsed.hostBitsSet {
                issues.append(.init(.error, field: field,
                    message: "Host bits are set — use the network address (e.g. 10.0.0.0/8)."))
            }
            if let note = suspiciousNote(parsed) {
                issues.append(.init(.warning, field: field, message: note))
            }
            return issues
        }
    }

    /// Validate a bare IP field (no prefix) — resolvers.
    static func validateIP(_ ip: String?, field: String, required: Bool) -> [ValidationIssue] {
        let s = ip?.trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
        guard !s.isEmpty else {
            return required ? [.init(.error, field: field, message: "An IP address is required.")] : []
        }
        return isValidIP(s) ? [] : [.init(.error, field: field, message: "\"\(s)\" is not a valid IP address.")]
    }

    // MARK: - Primitives

    static func isValidIP(_ s: String) -> Bool {
        let t = s.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !t.isEmpty else { return false }
        var v4 = [UInt8](repeating: 0, count: 4)
        if t.withCString({ inet_pton(AF_INET, $0, &v4) }) == 1 { return true }
        var v6 = [UInt8](repeating: 0, count: 16)
        if t.withCString({ inet_pton(AF_INET6, $0, &v6) }) == 1 { return true }
        return false
    }

    static func isValidWebURL(_ s: String) -> Bool {
        guard let url = URL(string: s.trimmingCharacters(in: .whitespacesAndNewlines)),
              let scheme = url.scheme?.lowercased(), scheme == "http" || scheme == "https",
              let host = url.host, !host.isEmpty else { return false }
        if let port = url.port, !(1...65535).contains(port) { return false }
        return true
    }

    /// Loose domain-syntax check (labels 1–63 of letters/digits/hyphen, not hyphen-edged,
    /// ≤253 total, optional trailing dot). Single-label names (a search suffix) are allowed.
    static func isValidDomain(_ s: String) -> Bool {
        let d = s.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !d.isEmpty, d.count <= 253 else { return false }
        let bare = d.hasSuffix(".") ? String(d.dropLast()) : d
        guard !bare.isEmpty else { return false }
        for label in bare.split(separator: ".", omittingEmptySubsequences: false) {
            guard (1...63).contains(label.count),
                  label.first != "-", label.last != "-",
                  label.allSatisfy({ $0.isLetter || $0.isNumber || $0 == "-" }) else { return false }
        }
        return true
    }

    private static func isDefaultLike(_ p: RoutePrefix) -> Bool {
        if p.isDefault { return true }
        // Any /0 (even a non-canonical one) is "carry everything".
        if case .ok(let parsed) = parseCIDR(p.value), parsed.prefix == 0 { return true }
        return false
    }

    // MARK: CIDR parse (validation-grade — distinguishes bad address from bad prefix)

    nonisolated struct ParsedCIDR: Sendable, Equatable {
        var bytes: [UInt8]
        var prefix: Int
        var v6: Bool
        var hostBitsSet: Bool
    }

    nonisolated enum CIDRParseResult: Sendable, Equatable {
        case ok(ParsedCIDR)
        case badAddress
        case badPrefix(max: Int)
    }

    static func parseCIDR(_ s: String) -> CIDRParseResult {
        let trimmed = s.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else { return .badAddress }
        let parts = trimmed.split(separator: "/", maxSplits: 1, omittingEmptySubsequences: false)
        let addr = String(parts[0])
        let v6 = addr.contains(":")
        let maxLen = v6 ? 128 : 32
        var buf = [UInt8](repeating: 0, count: v6 ? 16 : 4)
        let ok = addr.withCString { inet_pton(v6 ? AF_INET6 : AF_INET, $0, &buf) == 1 }
        guard ok else { return .badAddress }
        var prefix = maxLen
        if parts.count == 2 {
            guard let p = Int(parts[1]), p >= 0, p <= maxLen else { return .badPrefix(max: maxLen) }
            prefix = p
        }
        return .ok(ParsedCIDR(bytes: buf, prefix: prefix, v6: v6,
                              hostBitsSet: hostBitsSet(buf, prefix: prefix)))
    }

    private static func hostBitsSet(_ bytes: [UInt8], prefix: Int) -> Bool {
        let total = bytes.count * 8
        guard prefix < total else { return false }
        for bitPos in prefix..<total {
            let mask = UInt8(0x80) >> (bitPos % 8)
            if bytes[bitPos / 8] & mask != 0 { return true }
        }
        return false
    }

    /// A note for a suspicious-but-valid address (loopback / multicast / link-local), else nil.
    private static func suspiciousNote(_ p: ParsedCIDR) -> String? {
        let b = p.bytes
        if p.v6 {
            if b == [0,0,0,0, 0,0,0,0, 0,0,0,0, 0,0,0,1] { return "This is the IPv6 loopback (::1)." }
            if b[0] == 0xff { return "This is an IPv6 multicast address." }
            if b[0] == 0xfe && (b[1] & 0xc0) == 0x80 { return "This is an IPv6 link-local address (fe80::/10)." }
        } else {
            if b[0] == 127 { return "This is loopback (127.0.0.0/8)." }
            if b[0] >= 224 && b[0] <= 239 { return "This is a multicast address (224.0.0.0/4)." }
            if b[0] == 169 && b[1] == 254 { return "This is link-local (169.254.0.0/16)." }
        }
        return nil
    }
}

// MARK: - Intent diff (what the filter changed vs what the VPN pushed)

/// How one EFFECTIVE (post-filter) item relates to the pushed set — the highlighting the
/// editor tab and the Routes window render.
nonisolated enum IntentDelta: String, Sendable, Equatable, CaseIterable {
    case unchanged   // present in both effective and pushed
    case added       // in effective, not pushed (an Add / Custom)
    case replaced    // effective item that supplanted a pushed one (a Replace target)
    case removed     // pushed item no longer in effective (an Ignore) — see `ResourceDiff.removed`
}

nonisolated struct IntentDeltaItem: Sendable, Equatable, Identifiable {
    var value: String
    var delta: IntentDelta
    var id: String { "\(delta.rawValue)|\(value)" }
}

/// The per-item deltas for one resource plus the list of pushed items the filter REMOVED
/// (which have no effective row to attach a delta to).
nonisolated struct ResourceDiff: Sendable, Equatable {
    var items: [IntentDeltaItem]   // effective items, classified unchanged/added/replaced
    var removed: [String]          // pushed items dropped by the filter (Ignore/Replace-away)

    var isEmpty: Bool { items.isEmpty && removed.isEmpty }
}

/// Pure, reusable diffs: effective (filter applied to the pushed snapshot) vs pushed, for
/// routes, DNS resolvers, and the single proxy. No I/O — the UI feeds a saved filter + the
/// per-profile pushed snapshot and renders `.added`/`.replaced`/`.removed` highlighting.
nonisolated enum CustomRoutingDiff {

    // MARK: Routes

    static func diffRoutes(filter: RouteFilter, pushed: PushedIntentSnapshot.Routes) -> ResourceDiff {
        let captured = RouteIntent(engine: "", advertisedPrefixes: pushed.advertisedPrefixes,
                                   wantsDefault: pushed.wantsDefault, canOwnDefault: true)
        let eff = filter.apply(to: captured)

        var pushedSet = Set(pushed.advertisedPrefixes.map(Self.normPrefix))
        if pushed.wantsDefault { pushedSet.insert("default") }

        // Replace targets whose match was actually present in the push → `.replaced`.
        var replaced = Set<String>()
        for r in filter.rules where r.verb == .replace {
            guard let m = r.match, let t = r.target else { continue }
            let present = m.isDefault ? pushed.wantsDefault : pushedSet.contains(m.normalized)
            if present { replaced.insert(t.isDefault ? "default" : t.normalized) }
        }

        var effItems = eff.advertisedPrefixes.map(Self.normPrefix)
        if eff.wantsDefault { effItems.append("default") }

        let items = effItems.map { v -> IntentDeltaItem in
            if replaced.contains(v) { return IntentDeltaItem(value: v, delta: .replaced) }
            if pushedSet.contains(v) { return IntentDeltaItem(value: v, delta: .unchanged) }
            return IntentDeltaItem(value: v, delta: .added)
        }
        let removed = pushedSet.subtracting(effItems).sorted()
        return ResourceDiff(items: items, removed: removed)
    }

    // MARK: DNS resolvers

    static func diffDNSResolvers(filter: DNSCustomization, pushed: PushedIntentSnapshot.DNS) -> ResourceDiff {
        let captured = DNSIntent(engine: "", resolvers: pushed.resolvers)
        let eff = filter.apply(to: captured)

        let pushedSet = Set(pushed.resolvers.map(Self.normIP))
        var replaced = Set<String>()
        for r in filter.resolverRules where r.verb == .replace {
            guard let m = r.match, let t = r.target else { continue }
            if pushedSet.contains(Self.normIP(m)) { replaced.insert(Self.normIP(t)) }
        }

        let effItems = eff.resolvers.map(Self.normIP)
        let items = effItems.map { v -> IntentDeltaItem in
            if replaced.contains(v) { return IntentDeltaItem(value: v, delta: .replaced) }
            if pushedSet.contains(v) { return IntentDeltaItem(value: v, delta: .unchanged) }
            return IntentDeltaItem(value: v, delta: .added)
        }
        let removed = pushedSet.subtracting(effItems).sorted()
        return ResourceDiff(items: items, removed: removed)
    }

    // MARK: Proxy (single value)

    static func diffProxy(filter: ProxyCustomization, pushed: PushedIntentSnapshot.Proxy?) -> ResourceDiff {
        let captured = Self.proxyIntent(from: pushed)
        let eff = filter.apply(to: captured, engine: "")
        let pd = Self.proxyDisplay(captured)
        let ed = Self.proxyDisplay(eff)

        switch (pd, ed) {
        case (nil, nil):
            return ResourceDiff(items: [], removed: [])
        case (nil, .some(let e)):
            return ResourceDiff(items: [IntentDeltaItem(value: e, delta: .added)], removed: [])
        case (.some(let p), nil):
            return ResourceDiff(items: [], removed: [p])
        case (.some(let p), .some(let e)):
            if p == e { return ResourceDiff(items: [IntentDeltaItem(value: e, delta: .unchanged)], removed: []) }
            return ResourceDiff(items: [IntentDeltaItem(value: e, delta: .replaced)], removed: [p])
        }
    }

    // MARK: - Helpers

    private static func normPrefix(_ s: String) -> String {
        s.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
    }
    private static func normIP(_ s: String) -> String {
        s.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
    }

    /// Rebuild a `ProxyIntent` from the flattened pushed snapshot (inverse of
    /// `PushedIntentSnapshot.Proxy.init`). nil ⇒ no proxy pushed.
    static func proxyIntent(from snap: PushedIntentSnapshot.Proxy?) -> ProxyIntent? {
        guard let s = snap, !s.isEmpty else { return nil }
        if let pac = s.pacURL { return ProxyIntent(engine: "", mode: .pac(pac)) }
        var m = ProxyManual()
        if let h = s.httpHost { m.http = ProxyEndpoint(scheme: .http, host: h, port: s.httpPort ?? 8080) }
        if let h = s.httpsHost { m.https = ProxyEndpoint(scheme: .https, host: h, port: s.httpsPort ?? 8080) }
        if let h = s.socksHost { m.socks = ProxyEndpoint(scheme: .socks, host: h, port: s.socksPort ?? 1080) }
        guard let rep = m.representative else { return nil }
        return ProxyIntent(engine: "", mode: .manual(rep), manual: m)
    }

    /// A stable one-line display for a proxy intent (nil ⇒ direct).
    static func proxyDisplay(_ intent: ProxyIntent?) -> String? {
        guard let intent, intent.providesProxy else { return nil }
        switch intent.mode {
        case .none:            return nil
        case .manual(let e):   return e.display
        case .pac(let url):    return "PAC \(url)"
        }
    }
}
