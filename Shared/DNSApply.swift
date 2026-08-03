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
