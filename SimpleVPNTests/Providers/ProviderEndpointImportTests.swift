// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
//  ProviderEndpointImportTests.swift
//  THAT A PROVIDER'S SERVERS BECOME ORDINARY ENDPOINTS — carrying their keys, wearing
//  their provenance, and never trampling what the user already said.
//

import Foundation
import Testing
@testable import SimpleVPN

struct ProviderEndpointImportTests {

    static let keyA = "ofyfRvMPB0PPIGGItNL+5tNdvTKXuWye5CfjPgPNvQ8="
    static let keyB = "V1WC7wt34kcSDyqPuUhN56NJ0v+GlqY9TwZR5WlzzB4="

    static func relay(_ host: String, key: String?, country: String?, city: String?,
                      active: Bool = true) -> ProviderServer {
        ProviderServer(
            hostname: ProviderHostname(host, allowedSuffix: ".relays.mullvad.net")!,
            ipv4: "10.0.0.1", ipv6: nil, countryCode: country, cityCode: nil,
            cityName: city, peerKey: key.flatMap(ProviderPeerKey.init), active: active)
    }

    static func list(_ servers: [ProviderServer]) -> ProviderServerList {
        ProviderServerList(providerID: .mullvad, servers: servers, dropped: 0, fetchedAt: .now)
    }

    // MARK: The pair arrives intact

    /// A relay becomes a row carrying BOTH halves of its identity. Without the key
    /// the row is an address that fails closed and silently.
    @Test("a relay becomes an endpoint carrying its own peer key and its provenance")
    func relayBecomesAKeyedEndpoint() {
        let e = ProviderEndpointImport.endpoint(
            Self.relay("se-got-wg-001.relays.mullvad.net", key: Self.keyA,
                       country: "se", city: "Gothenburg"),
            provider: .mullvad)
        #expect(e.host == "se-got-wg-001.relays.mullvad.net")
        #expect(e.peerPublicKey == Self.keyA)
        #expect(e.fromProvider == "mullvad")
        #expect(e.country == "SE")
        #expect(e.label == "Gothenburg")
        // NOT the user's typing. That claim is not ours to make, and a refresh that
        // inherited it would make the provider's work look like the user's.
        #expect(e.userAdded == nil)
        // No opinion about order — the ranking decides until the user says otherwise.
        #expect(e.order == nil)
    }

    /// The HOSTNAME is used, never the IP literal, even though the payload has one.
    /// An OpenVPN provider's `verify-x509-name` checks the name, so dialling the
    /// literal and claiming the name is the configuration that fails the name check.
    @Test("the hostname is what becomes the endpoint, not the address")
    func theHostnameIsUsedNotTheLiteral() {
        let e = ProviderEndpointImport.endpoint(
            Self.relay("se-got-wg-001.relays.mullvad.net", key: nil, country: "se", city: nil),
            provider: .mullvad)
        #expect(e.host == "se-got-wg-001.relays.mullvad.net")
        #expect(e.host != "10.0.0.1")
    }

    // MARK: Choosing which

    /// Out-of-service servers are not offered: the provider said so, and a list that
    /// offers withdrawn servers wastes somebody's afternoon.
    @Test("servers the provider has withdrawn are not offered")
    func inactiveServersAreNotOffered() {
        let list = Self.list([
            Self.relay("a.relays.mullvad.net", key: Self.keyA, country: "se", city: nil),
            Self.relay("b.relays.mullvad.net", key: Self.keyB, country: "se", city: nil,
                       active: false),
        ])
        let chosen = ProviderEndpointImport.servers(from: list, countries: [])
        #expect(chosen.map(\.hostname.value) == ["a.relays.mullvad.net"])
    }

    /// A country filter, because 3,576 rows is not a feature — and an untouched
    /// filter still honours the cap, since somebody who picked nothing has not asked
    /// for everything either.
    @Test("the country filter narrows, and the cap applies either way")
    func filterAndCap() {
        let list = Self.list([
            Self.relay("a.relays.mullvad.net", key: Self.keyA, country: "se", city: nil),
            Self.relay("b.relays.mullvad.net", key: Self.keyB, country: "gb", city: nil),
        ])
        #expect(ProviderEndpointImport.servers(from: list, countries: ["se"]).count == 1)
        #expect(ProviderEndpointImport.servers(from: list, countries: []).count == 2)
        #expect(ProviderEndpointImport.servers(from: list, countries: [], limit: 1).count == 1)
    }

    /// The country list a person picks from is built from the SYSTEM's locale data,
    /// not from names in the payload — a place name that arrived over the network is
    /// display text we never trust with anything.
    @Test("country choices are named by the system, counted from the list")
    func countryChoicesAreLocalNames() throws {
        let list = Self.list([
            Self.relay("a.relays.mullvad.net", key: Self.keyA, country: "se", city: "Malmö"),
            Self.relay("b.relays.mullvad.net", key: Self.keyB, country: "se", city: "Gothenburg"),
            Self.relay("c.relays.mullvad.net", key: Self.keyA, country: "gb", city: "London"),
        ])
        let choices = ProviderEndpointImport.countryChoices(list)
        let sweden = try #require(choices.first { $0.code == "se" })
        #expect(sweden.count == 2)
        #expect(sweden.name == Locale.current.localizedString(forRegionCode: "SE"))
    }

    // MARK: Merging without trampling

    /// FACTS WIN, OPINIONS SURVIVE. A refresh must not rename somebody's
    /// "London — fastest" back to "London" — but it MUST replace a stale peer key,
    /// because that is a fact about the relay rather than an opinion about it, and a
    /// stale key is the one thing this model must never keep.
    @Test("a refresh replaces the key and keeps the user's name and position")
    func refreshKeepsOpinionsAndReplacesFacts() throws {
        var stored = VPNEndpointList(endpoints: [
            VPNEndpoint(host: "a.relays.mullvad.net", label: "London \u{2014} fastest",
                        order: 0, peerPublicKey: Self.keyA, fromProvider: "mullvad"),
        ])
        stored = ProviderEndpointImport.applying(
            [Self.relay("a.relays.mullvad.net", key: Self.keyB, country: "gb", city: "London")],
            from: .mullvad, to: stored)
        let row = try #require(stored.endpoints.first)
        #expect(row.label == "London \u{2014} fastest", "the user's name was overwritten")
        #expect(row.order == 0, "the user's position was lost")
        #expect(row.peerPublicKey == Self.keyB, "a stale peer key survived a refresh")
    }

    /// A server the user TYPED IN is theirs even if a provider later publishes the
    /// same name. It keeps `userAdded` and is never restamped as the provider's.
    @Test("a hand-typed server is not restamped as the provider's")
    func handTypedServersKeepTheirProvenance() throws {
        var stored = VPNEndpointList(endpoints: [
            VPNEndpoint(host: "a.relays.mullvad.net", userAdded: true),
        ])
        stored = ProviderEndpointImport.applying(
            [Self.relay("a.relays.mullvad.net", key: Self.keyA, country: "gb", city: "London")],
            from: .mullvad, to: stored)
        let row = try #require(stored.endpoints.first)
        #expect(row.userAdded == true)
        #expect(row.fromProvider == nil)
        // …but it still gets the key, because without one it cannot be connected to.
        #expect(row.peerPublicKey == Self.keyA)
    }

    /// Applying ADDS. Taking a server away is the Servers table's `−`, one row at a
    /// time, by the person who put it there — never a side effect of a refresh.
    @Test("applying a list never removes anything")
    func applyingOnlyAdds() {
        let stored = VPNEndpointList(endpoints: [
            VPNEndpoint(host: "old.example.com", userAdded: true),
        ])
        let after = ProviderEndpointImport.applying(
            [Self.relay("a.relays.mullvad.net", key: Self.keyA, country: "se", city: nil)],
            from: .mullvad, to: stored)
        #expect(after.endpoints.count == 2)
        #expect(after.endpoints.contains { $0.host == "old.example.com" })
    }

    // MARK: The stored cache

    /// The disk cache is re-validated on the way back in, because a file in
    /// Application Support is as untrusted as the network — anything that can write
    /// one can write that one. A tampered cache can do no more than lose rows.
    @Test("a stored list is re-validated on the way back in")
    func storedListsAreRevalidated() throws {
        let good = Self.list([
            Self.relay("a.relays.mullvad.net", key: Self.keyA, country: "se", city: "Malmö"),
        ])
        let back = try #require(ProviderServerList.from(good.stored))
        #expect(back.servers.first?.hostname.value == "a.relays.mullvad.net")
        #expect(back.servers.first?.peerKey?.base64 == Self.keyA)
        #expect(back.servers.first?.cityName == "Malmö")

        // A hostname edited outside the provider's own domain is dropped, exactly as
        // it would be coming off the wire — the suffix check is not a fetch-time
        // nicety, it is the property.
        var tampered = good.stored
        tampered.servers[0].hostname = "a.relays.mullvad.net.evil.example"
        #expect(ProviderServerList.from(tampered) == nil)

        // A key edited to something that is not 32 bytes drops the row rather than
        // becoming a key that fails the handshake with nothing to look at.
        var badKey = good.stored
        badKey.servers[0].peerKey = "AAAA"
        #expect(ProviderServerList.from(badKey) == nil)
    }

    /// A cache file naming a different provider than its own filename is not a mix-up
    /// to paper over: it would put one company's relays under another's row.
    @Test("a stored list naming another provider is refused")
    func storedListMustNameItsOwnProvider() {
        var stored = Self.list([
            Self.relay("a.relays.mullvad.net", key: Self.keyA, country: "se", city: nil),
        ]).stored
        stored.providerID = "notaprovider"
        #expect(ProviderServerList.from(stored) == nil)
    }
}
