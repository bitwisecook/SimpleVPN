// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
//  DNSApply.swift
//  The DNS mediator's tier-2 SOLE-WRITER wire payload + NEDNSSettings realizer
//  (Docs/StateMediators.md › DNS mediator, applier). The app's `DNSRealizer`
//  serializes the arbitrated split-DNS decision into ONE `DNSApplyRequest` PER
//  PARTICIPANT — the catch-all owner gets the default resolvers scoped to every
//  lookup, each split participant gets its resolvers scoped to only the domains it
//  won — and sends each over the `dns:apply:<json>` IPC. The packet-tunnel provider
//  rebuilds `NEDNSSettings` from it and stores it on the addressed engine's bridge,
//  which re-applies the captured tun settings LIVE so the override takes effect with
//  no reconnect (mirrors the proxy applier). Shared so the request is Codable across
//  the root(sysext) ↔ app boundary, the mapping is identical on both sides, and the
//  split is unit-testable from the app target.
//
//  This is the DNS parallel of `ProxyApply.swift`: `nil`/empty ⇒ clear (restore the
//  engine's captured/pushed DNS). No credentials or secrets ever ride this wire —
//  only resolver IPs, search domains and the match-domain scoping.
//

import Foundation
import NetworkExtension

/// One engine's slice of the arbitrated split-DNS decision, reduced to what
/// `NEDNSSettings` needs. An empty `servers` list clears the override (the bridge
/// restores whatever DNS it captured from the push). Codable for the `dns:apply:`
/// IPC; Equatable so the realizer can skip re-applying an unchanged decision.
nonisolated struct DNSApplyRequest: Codable, Sendable, Equatable {
    /// Resolver IPs this engine should serve. Empty ⇒ clear (nil settings).
    var servers: [String]
    /// DNS search-list domains → `NEDNSSettings.searchDomains`.
    var searchDomains: [String]
    /// The domains these resolvers serve → `NEDNSSettings.matchDomains`. `[""]` (or
    /// empty) is the CATCH-ALL: every lookup goes through these resolvers. A specific
    /// list is split-DNS: only those suffixes resolve here.
    var matchDomains: [String]
    /// `NEDNSSettings.matchDomainsNoSearch`: when true the match domains are used ONLY
    /// for scoping (they are not appended to the resolver search list). Set for split
    /// participants so a scoped resolver can't leak its domains into global search.
    var matchDomainsNoSearch: Bool

    init(servers: [String] = [], searchDomains: [String] = [],
         matchDomains: [String] = [], matchDomainsNoSearch: Bool = false) {
        self.servers = servers
        self.searchDomains = searchDomains
        self.matchDomains = matchDomains
        self.matchDomainsNoSearch = matchDomainsNoSearch
    }

    /// Nothing to apply ⇒ clear the override (restore the captured/pushed DNS).
    var isEmpty: Bool { servers.isEmpty }

    /// Build `NEDNSSettings` from the decision, or `nil` when there are no resolvers to
    /// set (clear the override). Search domains and match domains are applied only when
    /// non-empty; `matchDomains == [""]` is passed through as the catch-all.
    func makeNEDNSSettings() -> NEDNSSettings? {
        guard !servers.isEmpty else { return nil }
        let s = NEDNSSettings(servers: servers)
        if !searchDomains.isEmpty { s.searchDomains = searchDomains }
        if !matchDomains.isEmpty { s.matchDomains = matchDomains }
        s.matchDomainsNoSearch = matchDomainsNoSearch
        return s
    }
}

// MARK: - Search domains

/// Search-domain normalisation and validation, in ONE place.
///
/// It lives here, beside the only other type that maps to `NEDNSSettings`, because
/// three config formats now carry a search list — WireGuard, the Proxy Tunnel and the
/// SSH Network Tunnel, none of whose file formats has a field for one — and a domain
/// spelled three slightly different ways is a lookup that works on one kind and not
/// the next. The pushed kinds (OpenVPN, OpenConnect, Tailscale) learn theirs from the
/// server and never come through here.
nonisolated enum DNSSearchDomains {

    /// The longest name the DNS allows, and the longest single label in one.
    static let maxNameLength = 253
    static let maxLabelLength = 63

    /// Trim, drop empties, strip the leading and trailing dots people type
    /// (`.corp.example.` → `corp.example`), lower-case, and de-duplicate while
    /// keeping the user's ORDER — a stub resolver tries a search list in order, so
    /// re-sorting it would change which name wins.
    static func normalized(_ list: [String]) -> [String] {
        var out: [String] = []
        for raw in list {
            let one = normalized(one: raw)
            guard !one.isEmpty, !out.contains(one) else { continue }
            out.append(one)
        }
        return out
    }

    static func normalized(one raw: String) -> String {
        var s = raw.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        while s.hasPrefix(".") { s.removeFirst() }
        while s.hasSuffix(".") { s.removeLast() }
        return s
    }

    /// Why a search domain can't be used, in the user's language — nil when it's
    /// fine. Refused at the editor rather than at connect, because macOS accepts an
    /// unusable search list in silence and short names then simply never resolve.
    static func problem(_ raw: String) -> String? {
        let s = normalized(one: raw)
        guard !s.isEmpty else { return "Enter a domain, like corp.example.com." }
        if s.contains("://") { return "Enter just the domain — not a URL." }
        if s.contains(" ") { return "A domain can't contain spaces." }
        if s.contains("/") { return "Enter just the domain, with no slashes." }
        if s.contains("@") { return "Enter the domain on its own, without the part before the @." }
        if s.contains("*") { return "A search domain is a plain domain — wildcards don't work here." }
        if s.count > maxNameLength { return "\(s) is too long to be a domain name." }
        for label in s.split(separator: ".", omittingEmptySubsequences: false) {
            if label.isEmpty { return "\(s) has an empty part between two dots." }
            if label.count > maxLabelLength {
                return "\(label) is too long — each part of a domain is at most \(maxLabelLength) characters."
            }
            for ch in label where !(ch.isLetter || ch.isNumber || ch == "-" || ch == "_") {
                return "\(s) has a character a domain name can't contain (\u{201C}\(ch)\u{201D})."
            }
        }
        return nil
    }

    static func problem(list: [String]) -> String? {
        for one in list where !normalized(one: one).isEmpty {
            if let p = problem(one) { return p }
        }
        return nil
    }
}
