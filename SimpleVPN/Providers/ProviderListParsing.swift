// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
//  ProviderListParsing.swift
//  READING A PROVIDER'S PUBLISHED LIST, hostilely.
//
//  Three parsers, one rule: **take the fields we need, drop the row if any of them
//  fails, and never look at the rest.** A provider's payload carries a great deal
//  more than SimpleVPN uses — Mullvad ships SSH host fingerprints and SOCKS names,
//  Nord ships nine technologies and a load figure — and every field read is a field
//  that has to be defended. The allow-list is short on purpose.
//
//  WHY THESE ARE PARSERS AND NOT `Codable` MODELS. `Decodable` on the provider's own
//  shape would make the payload's structure our structure: a provider adding a field
//  would change our type, and a `throws` on one bad row would discard three thousand
//  good ones. These walk `JSONSerialization` output instead and answer with values
//  that are already validated, which is the shape `ProviderServerList` documents.
//
//  EVERY FIELD NAME BELOW WAS TAKEN FROM A LIVE PAYLOAD ON 2026-08-07, not from
//  documentation — Mullvad's app API documentation page is a JavaScript shell with
//  no readable content, and Nord's `/v1` carries no stability promise I could find.
//  Docs/ServiceBundles.md §2 records the exact URLs and what they returned.
//

import Foundation

nonisolated enum ProviderListParser {

    /// Why a whole payload was rejected. A ROW failing is not one of these — a bad
    /// row is dropped and counted, because a list of thousands will always have one.
    enum Failure: Error, Equatable {
        /// Not JSON, or not the top-level shape this provider publishes.
        case malformed
        /// It parsed, and there was nothing usable in it. Deliberately distinct from
        /// `malformed`: an empty list is how a broken CDN and a hostile substitution
        /// both look, and either way it must never replace a working list.
        case empty
    }

    // MARK: Mullvad

    /// Mullvad's `/www/relays/all/` — a flat JSON array of relay objects.
    ///
    /// Five fields are read and eighteen are ignored. `type` must be `wireguard`:
    /// the payload also contains `bridge` rows, which have no `pubkey` and are not
    /// something a user connects a tunnel to.
    ///
    /// VERIFIED SHAPE (2026-08-07, 567 wireguard rows of 580):
    /// ```json
    /// { "hostname": "al-tia-wg-001", "country_code": "al", "city_code": "tia",
    ///   "city_name": "Tirana", "fqdn": "al-tia-wg-001.relays.mullvad.net",
    ///   "active": true, "type": "wireguard",
    ///   "ipv4_addr_in": "103.124.165.2", "ipv6_addr_in": "2a04:27c0:0:e::f001",
    ///   "pubkey": "ofyfRvMPB0PPIGGItNL+5tNdvTKXuWye5CfjPgPNvQ8=" }
    /// ```
    ///
    /// **`fqdn` is used and `hostname` is not.** `hostname` is a bare label with no
    /// domain, so it could never be suffix-checked; taking the fully-qualified name
    /// is what lets `ProviderHostname` refuse anything outside
    /// `.relays.mullvad.net`.
    ///
    /// **A row with no `pubkey` is dropped, not defaulted.** For WireGuard the peer
    /// key is the authentication; a server with a missing one is a server that cannot
    /// be connected to, and inventing an empty key would turn that into a mystery.
    static func mullvad(_ data: Data, now: Date = .now) throws(Failure) -> ProviderServerList {
        guard let rows = (try? JSONSerialization.jsonObject(with: data)) as? [[String: Any]] else {
            throw .malformed
        }
        let suffix = VPNServiceProviderCatalog.mullvad.hostnameSuffix
        var servers: [ProviderServer] = []
        var dropped = 0
        for row in rows {
            guard (row["type"] as? String) == "wireguard" else { dropped += 1; continue }
            guard let fqdn = row["fqdn"] as? String,
                  let host = ProviderHostname(fqdn, allowedSuffix: suffix),
                  let key = (row["pubkey"] as? String).flatMap(ProviderPeerKey.init)
            else { dropped += 1; continue }
            servers.append(ProviderServer(
                hostname: host,
                ipv4: ProviderServer.normalisedIPv4(row["ipv4_addr_in"] as? String),
                ipv6: ProviderServer.normalisedIPv6(row["ipv6_addr_in"] as? String),
                countryCode: ProviderServer.normalisedCountry(row["country_code"] as? String),
                cityCode: row["city_code"] as? String,
                cityName: row["city_name"] as? String,
                peerKey: key,
                active: (row["active"] as? Bool) ?? false))
        }
        guard !servers.isEmpty else { throw .empty }
        return ProviderServerList(providerID: .mullvad, servers: servers,
                                  dropped: dropped, fetchedAt: now)
    }

    // MARK: NordVPN

    /// Nord's `/v1/servers` — a flat JSON array of server objects.
    ///
    /// VERIFIED SHAPE (2026-08-07): `hostname`, `station` (the IPv4 the `.ovpn`
    /// actually dials), `ipv6_station`, `status`, `locations[].country.code`, and
    /// `technologies[]` where the WireGuard key lives as
    /// `{"identifier": "wireguard_udp", "metadata": [{"name": "public_key", "value": …}]}`.
    ///
    /// **The peer key is read but this provider is OpenVPN-only** (see
    /// `VPNServiceProviderCatalog.nordVPN`): NordLynx needs a private key Nord's
    /// authenticated API issues, and SimpleVPN holds no provider account. Reading it
    /// anyway costs nothing and means the day that changes is a one-line change
    /// rather than a parser change.
    ///
    /// **Two values per server matter for Nord and only one for the others.** Nord's
    /// `.ovpn` puts an IP literal in `remote` and the hostname in
    /// `verify-x509-name CN=…`, so a substitution that fills in one and not the other
    /// produces a configuration that either dials nowhere or fails the name check.
    /// Both come from here.
    static func nordVPN(_ data: Data, now: Date = .now) throws(Failure) -> ProviderServerList {
        guard let rows = (try? JSONSerialization.jsonObject(with: data)) as? [[String: Any]] else {
            throw .malformed
        }
        let suffix = VPNServiceProviderCatalog.nordVPN.hostnameSuffix
        var servers: [ProviderServer] = []
        var dropped = 0
        for row in rows {
            guard let name = row["hostname"] as? String,
                  let host = ProviderHostname(name, allowedSuffix: suffix)
            else { dropped += 1; continue }
            let country = (row["locations"] as? [[String: Any]])?
                .lazy
                .compactMap { ($0["country"] as? [String: Any])?["code"] as? String }
                .first
            let city = (row["locations"] as? [[String: Any]])?
                .lazy
                .compactMap { ($0["country"] as? [String: Any])?["city"] as? [String: Any] }
                .compactMap { $0["name"] as? String }
                .first
            servers.append(ProviderServer(
                hostname: host,
                ipv4: ProviderServer.normalisedIPv4(row["station"] as? String),
                ipv6: ProviderServer.normalisedIPv6(row["ipv6_station"] as? String),
                countryCode: ProviderServer.normalisedCountry(country),
                cityCode: nil,
                cityName: city,
                peerKey: nordPeerKey(row),
                active: (row["status"] as? String) == "online"))
        }
        guard !servers.isEmpty else { throw .empty }
        return ProviderServerList(providerID: .nordVPN, servers: servers,
                                  dropped: dropped, fetchedAt: now)
    }

    /// `technologies[] → identifier == "wireguard_udp" → metadata[] → name == "public_key"`.
    /// Written out rather than reached by index because the index is not stable: the
    /// entry was `technologies[6]` in the payload read on 2026-08-07 and nothing
    /// promises it stays there.
    private static func nordPeerKey(_ row: [String: Any]) -> ProviderPeerKey? {
        guard let techs = row["technologies"] as? [[String: Any]] else { return nil }
        for tech in techs where (tech["identifier"] as? String) == "wireguard_udp" {
            guard let meta = tech["metadata"] as? [[String: Any]] else { continue }
            for entry in meta where (entry["name"] as? String) == "public_key" {
                if let key = (entry["value"] as? String).flatMap(ProviderPeerKey.init) { return key }
            }
        }
        return nil
    }

    // MARK: IPVanish

    /// IPVanish publishes no list — it publishes a DIRECTORY, and the list is the
    /// filenames in it. So this reads an HTML index rather than JSON, which is the
    /// one genuinely awkward thing about the provider whose configuration shape is
    /// otherwise the cleanest of the four.
    ///
    /// VERIFIED (2026-08-07): the index at `configs.ipvanish.com/configs/` names
    /// 3,576 files as `ipvanish-<CC>-<City>-<code>-<cNN>.ovpn`, plus
    /// `ca.ipvanish.com.crt`, `configs.zip` and `guideCRT.txt`. The two-letter code
    /// after `ipvanish-` is the country; the hostname the `.ovpn` dials is
    /// `<code>-<cNN>.ipvanish.com`, which is the last two dash-separated components
    /// of the stem.
    ///
    /// **The hostname is RECONSTRUCTED and then validated, not scraped.** Nothing in
    /// the HTML becomes a hostname directly: the filename is decomposed, the two
    /// pieces we understand are recombined, and the result goes through
    /// `ProviderHostname` like everything else. An `href` in that page can therefore
    /// contain anything at all without reaching a configuration file.
    ///
    /// Reading a directory index is fragile by nature — it is a rendering, not an
    /// API — so a change in IPVanish's web server would show up as a payload that
    /// parses to nothing, which the integrity rules already treat as "keep the last
    /// good list" rather than "accept an empty one".
    static func ipVanish(_ html: String, now: Date = .now) throws(Failure) -> ProviderServerList {
        let suffix = VPNServiceProviderCatalog.ipVanish.hostnameSuffix
        var seen: Set<String> = []
        var servers: [ProviderServer] = []
        var dropped = 0
        for stem in ovpnStems(in: html) {
            // ipvanish-AE-Dubai-dxb-c10  ->  country "ae", host "dxb-c10.ipvanish.com"
            let parts = stem.split(separator: "-", omittingEmptySubsequences: false)
            guard parts.count >= 4, parts[0].lowercased() == "ipvanish" else {
                dropped += 1; continue
            }
            let country = ProviderServer.normalisedCountry(String(parts[1]))
            let name = "\(parts[parts.count - 2])-\(parts[parts.count - 1])\(suffix)".lowercased()
            guard let host = ProviderHostname(name, allowedSuffix: suffix),
                  seen.insert(host.value).inserted
            else { dropped += 1; continue }
            // The city sits between the country and the two trailing components, and
            // IPVanish writes a space as `-` and an em dash as `---`. Rendered for
            // display only; it never reaches a configuration file.
            let cityParts = parts[2..<(parts.count - 2)]
            let city = cityParts.joined(separator: " ")
                .replacingOccurrences(of: "   ", with: " \u{2014} ")
                .trimmingCharacters(in: .whitespaces)
            servers.append(ProviderServer(
                hostname: host,
                ipv4: nil,          // not published; OpenVPN dials the name
                ipv6: nil,
                countryCode: country,
                cityCode: parts[parts.count - 2].lowercased(),
                cityName: city.isEmpty ? nil : city,
                peerKey: nil,       // IPVanish publishes no WireGuard configuration
                active: true))      // the directory says nothing about service state
        }
        guard !servers.isEmpty else { throw .empty }
        return ProviderServerList(providerID: .ipVanish, servers: servers,
                                  dropped: dropped, fetchedAt: now)
    }

    /// Every `<something>.ovpn` named in an HTML index, without the extension and
    /// **with its case intact**. Nothing else in the page is looked at — no
    /// attributes, no tags, no entity decoding — because the only thing we want from
    /// it is filenames and the less of somebody's HTML we interpret the better.
    ///
    /// The case survives here and is dropped later, per field, and that ordering is
    /// load-bearing: IPVanish writes the city as `Dubai` and the country as `AE`, so
    /// folding the whole page first would put "dubai" on a label a person reads.
    /// The hostname and the country are lowercased where they are built; the city
    /// name is not, because it is display text and never reaches a config file.
    private static func ovpnStems(in html: String) -> [String] {
        var out: [String] = []
        for token in html.split(whereSeparator: { "\"'<> \t\r\n".contains($0) })
        where token.lowercased().hasSuffix(".ovpn") {
            let stem = token.dropLast(5)
            // A path would mean the index is not the flat directory we read; take the
            // last component and let the hostname check reject anything odd.
            out.append(String(stem.split(separator: "/").last ?? stem))
        }
        return out
    }
}
