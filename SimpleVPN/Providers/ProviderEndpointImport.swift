// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
//  ProviderEndpointImport.swift
//  A PROVIDER'S SERVERS BECOMING ORDINARY ENDPOINTS ON AN ORDINARY PROFILE — which
//  is the whole architectural claim of this feature, and the reason it is small.
//
//  THERE IS NO SECOND SERVER LIST AND NO PARALLEL PICKER. `VPNEndpointList` already
//  holds what the Servers table shows; `EndpointRanking` already sorts by measured
//  latency and, failing that, by distance; `EndpointRegions` already groups by
//  region; the table already lets the user drag rows and already lets a hand-made
//  order beat the ranking. So the ENTIRE answer to "a nicely sorted latency or
//  region based list of endpoints to choose" is: put the provider's servers in the
//  list everything already reads. Everything asked for then exists without being
//  built twice, and — more to the point — without a second answer to "which server
//  am I on?".
//
//  WHAT THIS FILE DECIDES, and it is only three things:
//   • WHICH servers (a country filter, because three thousand rows is not a feature,
//     it is the feature failing — Docs/ServiceBundles.md §5).
//   • That each one carries its PEER KEY, so a WireGuard row is a usable half of an
//     (address, key) pair rather than an address that fails closed and silently.
//   • That each one is stamped `fromProvider`, so the Servers table can answer
//     "where did this come from?" and a refresh can tell its own rows from the
//     user's — which `userAdded` could not do without lying.
//
//  PURE. It builds values; writing them is `VPNController.setEndpointList`, the same
//  save a rename or a corrected country goes through.
//

import Foundation

nonisolated enum ProviderEndpointImport {

    /// One provider server as an endpoint row.
    ///
    /// The HOSTNAME is used and the IP literal is not, even where the payload has
    /// one. Three reasons, in order: an OpenVPN provider's `verify-x509-name` checks
    /// the name, so dialling the literal and claiming the name is the configuration
    /// that fails the name check; a provider re-points a name far more often than it
    /// renumbers; and a row a person reads should say `se-got-wg-001` rather than
    /// four numbers. The addresses stay on the fetched list for the DIFF to watch,
    /// which is where they matter — a relay that moved is a pending confirmation.
    static func endpoint(_ server: ProviderServer,
                         provider: VPNServiceProviderID,
                         port: Int? = nil) -> VPNEndpoint {
        VPNEndpoint(
            host: server.hostname.value,
            port: port,
            proto: nil,
            // The user's own name for a row, pre-filled with the place — which is
            // the only thing anyone actually chooses a relay by. Not invented where
            // the provider published nothing: an endpoint with no label shows its
            // host, and a made-up name would be worse than none.
            label: server.cityName,
            country: server.countryCode?.uppercased(),
            region: nil,
            userAdded: nil,          // NOT the user's typing. That claim is not ours to make.
            order: nil,              // no opinion; the ranking decides until the user does
            peerPublicKey: server.peerKey?.base64,
            fromProvider: provider.rawValue)
    }

    /// The servers to offer, filtered and capped.
    ///
    /// `countries` empty means "everywhere", which is the honest reading of an
    /// untouched filter — but `limit` still applies, because a user who picks
    /// nothing has not asked for 3,576 rows either.
    ///
    /// Out-of-service servers are dropped rather than shown: the provider said so,
    /// and a list that offers servers the provider has withdrawn is a list that
    /// wastes somebody's afternoon. A server that goes out of service AFTER it is in
    /// the user's list is a different question and is `ProviderServerListDiff`'s —
    /// there it is marked retired and kept, because removal is an attack too.
    static func servers(from list: ProviderServerList,
                        countries: Set<String>,
                        limit: Int = defaultLimit) -> [ProviderServer] {
        list.servers
            .filter(\.active)
            .filter { countries.isEmpty || $0.countryCode.map(countries.contains) == true }
            .prefix(limit)
            .map { $0 }
    }

    /// How many rows one apply may add.
    ///
    /// A number rather than "all of them", and 200 rather than 20: the Servers table
    /// sorts, groups and searches perfectly well at this size, whereas 3,576 rows is
    /// a table nobody scrolls and a probe sweep nobody wants. It is a CAP on one
    /// action, not a limit on the list — narrowing the countries and applying again
    /// adds more.
    static let defaultLimit = 200

    /// The endpoint list to store: what the profile already had, plus these servers.
    ///
    /// THE MERGE RULES, and each one is a thing that would otherwise be lost:
    ///  • A row the user has ALREADY ANNOTATED keeps its label, its corrected country
    ///    and its position. A refresh must not rename somebody's "London — fastest"
    ///    back to "London".
    ///  • …but its PEER KEY and its provenance are taken from the incoming server,
    ///    because those are facts about the relay rather than opinions about it, and
    ///    a stale key is the one thing this model must never keep.
    ///  • A row the user TYPED IN keeps `userAdded` and is never restamped. Their
    ///    server is theirs even if a provider later publishes the same name.
    ///  • Nothing is removed. Applying a list adds; taking a server away is the
    ///    Servers table's `\u{2212}`, one row at a time, by the person who put it there.
    static func applying(_ servers: [ProviderServer],
                         from provider: VPNServiceProviderID,
                         to stored: VPNEndpointList,
                         port: Int? = nil) -> VPNEndpointList {
        var out = stored
        var byID: [String: Int] = [:]
        for (i, e) in out.endpoints.enumerated() { byID[e.id] = i }
        for server in servers {
            let incoming = endpoint(server, provider: provider, port: port)
            guard let i = byID[incoming.id] else {
                byID[incoming.id] = out.endpoints.count
                out.endpoints.append(incoming)
                continue
            }
            // Facts win; opinions survive.
            out.endpoints[i].peerPublicKey = incoming.peerPublicKey
            if out.endpoints[i].userAdded != true {
                out.endpoints[i].fromProvider = provider.rawValue
                if out.endpoints[i].label == nil { out.endpoints[i].label = incoming.label }
                if out.endpoints[i].country == nil { out.endpoints[i].country = incoming.country }
            }
        }
        return out
    }

    /// Every country in a list, as (code, how many) sorted by name — what the
    /// "which places?" filter offers.
    ///
    /// The display name comes from the system's own locale data rather than from the
    /// payload: a place name that arrived over the network is display text we escape
    /// and never trust, and `Locale` already knows what `se` is called in the user's
    /// language.
    static func countryChoices(_ list: ProviderServerList) -> [(code: String, name: String, count: Int)] {
        var counts: [String: Int] = [:]
        for s in list.servers where s.active {
            guard let code = s.countryCode else { continue }
            counts[code, default: 0] += 1
        }
        return counts
            .map { (code: $0.key, name: countryName($0.key), count: $0.value) }
            .sorted { ($0.name, $0.code) < ($1.name, $1.code) }
    }

    /// A two-letter code as the user's system would name it, falling back to the code
    /// itself uppercased — never to a name from the payload.
    static func countryName(_ code: String) -> String {
        Locale.current.localizedString(forRegionCode: code.uppercased()) ?? code.uppercased()
    }
}
