// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
//  EndpointRankingTests.swift
//  Pins the endpoint ordering: a measured round trip beats a geographic guess,
//  guesses order by distance from where the user actually is, an endpoint that
//  can be neither measured nor placed sorts LAST but is never dropped, and equal
//  endpoints keep the order the profile listed them in.
//

import Foundation
import Testing
@testable import SimpleVPN

struct EndpointRankingTests {

    // Somewhere unambiguous to measure from: central London.
    private let london = GeoPoint(lat: 51.5, lon: -0.1)

    private func item(_ host: String, country: String? = nil,
                      rtt: Double? = nil, reachable: Bool? = nil) -> RankedEndpoint {
        RankedEndpoint(
            endpoint: VPNEndpoint(host: host),
            geoCountry: country,
            geoPoint: country.flatMap(CountryCentroids.coordinate(for:))
                .map { GeoPoint(lat: $0.lat, lon: $0.lon) },
            measurement: (rtt == nil && reachable == nil)
                ? nil
                : EndpointMeasurement(rttMS: rtt, reachable: reachable, measuredAt: Date()))
    }

    // MARK: Measured

    @Test func measuredEndpointsOrderByRoundTrip() {
        let items = [item("slow", country: "US", rtt: 180),
                     item("quick", country: "DE", rtt: 12),
                     item("middling", country: "GB", rtt: 40)]
        let ordered = EndpointRanking.ordered(items, home: london)
        #expect(ordered.map(\.endpoint.host) == ["quick", "middling", "slow"])
    }

    @Test func measuredBeatsGuessedEvenWhenTheGuessIsCloser() {
        // The German server is measured at 90 ms; the London one has never been
        // probed and is 0 km away. Having asked wins over having guessed.
        let items = [item("unprobed.london", country: "GB"),
                     item("measured.berlin", country: "DE", rtt: 90)]
        let ordered = EndpointRanking.ordered(items, home: london)
        #expect(ordered.map(\.endpoint.host) == ["measured.berlin", "unprobed.london"])
    }

    @Test func probedButSilentSinksBelowUnprobedButPlaceable() {
        let items = [item("silent", country: "GB", reachable: false),
                     item("unprobed", country: "AU")]
        let ordered = EndpointRanking.ordered(items, home: london)
        #expect(ordered.map(\.endpoint.host) == ["unprobed", "silent"])
    }

    // MARK: Guessed (geographic proximity)

    @Test func withoutProbesOrderIsNearestFirstFromHome() {
        let items = [item("sydney", country: "AU"),
                     item("newyork", country: "US"),
                     item("paris", country: "FR"),
                     item("tokyo", country: "JP")]
        let ordered = EndpointRanking.ordered(items, home: london)
        #expect(ordered.map(\.endpoint.host) == ["paris", "newyork", "tokyo", "sydney"])
    }

    @Test func homeMovesTheAnswer() {
        let items = [item("sydney", country: "AU"), item("paris", country: "FR")]
        let sydney = GeoPoint(lat: -33.9, lon: 151.2)
        #expect(EndpointRanking.ordered(items, home: sydney).first?.endpoint.host == "sydney")
        #expect(EndpointRanking.ordered(items, home: london).first?.endpoint.host == "paris")
    }

    @Test func withNoHomeKnownTheProfilesOwnOrderIsKept() {
        let items = [item("third", country: "AU"), item("first", country: "FR"),
                     item("second", country: "US")]
        let ordered = EndpointRanking.ordered(items, home: nil)
        #expect(ordered.map(\.endpoint.host) == ["third", "first", "second"])
    }

    // MARK: The unplaceable

    @Test func unknownEndpointsSortLastAndAreNeverDropped() {
        let items = [item("mystery"),                       // no country, no probe
                     item("paris", country: "FR"),
                     item("mystery2"),
                     item("sydney", country: "AU")]
        let ordered = EndpointRanking.ordered(items, home: london)
        #expect(ordered.count == 4)
        #expect(ordered.map(\.endpoint.host) == ["paris", "sydney", "mystery", "mystery2"])
    }

    @Test func aMeasuredButUnplaceableEndpointStillWins() {
        // No idea where it is, but we timed it: that's real knowledge.
        let items = [item("paris", country: "FR"), item("nowhere", rtt: 5)]
        #expect(EndpointRanking.ordered(items, home: london).first?.endpoint.host == "nowhere")
    }

    // MARK: Stability

    @Test func tiesKeepTheirOriginalOrder() {
        let items = [item("a", country: "DE", rtt: 25),
                     item("b", country: "DE", rtt: 25),
                     item("c", country: "DE", rtt: 25)]
        #expect(EndpointRanking.ordered(items, home: london).map(\.endpoint.host) == ["a", "b", "c"])
        // And identically on a second pass — no incidental reshuffling.
        let twice = EndpointRanking.ordered(EndpointRanking.ordered(items, home: london), home: london)
        #expect(twice.map(\.endpoint.host) == ["a", "b", "c"])
    }

    // MARK: Overrides

    @Test func aUserCountryOverrideMovesTheEndpoint() {
        // GeoIP says Australia; the user knows it's actually in France.
        var endpoint = VPNEndpoint(host: "mislabelled")
        endpoint.country = "FR"
        let au = CountryCentroids.coordinate(for: "AU")!
        let corrected = RankedEndpoint(endpoint: endpoint, geoCountry: "AU",
                                       geoPoint: GeoPoint(lat: au.lat, lon: au.lon))
        #expect(corrected.countryCode == "FR")
        #expect(corrected.region == .europe)
        let ordered = EndpointRanking.ordered([item("sydney", country: "AU"), corrected],
                                              home: london)
        #expect(ordered.first?.endpoint.host == "mislabelled")
    }

    @Test func aRegionOverrideWinsOverTheCountry() {
        var endpoint = VPNEndpoint(host: "anycast")
        endpoint.country = "FR"
        endpoint.region = .asiaPacific
        #expect(RankedEndpoint(endpoint: endpoint).region == .asiaPacific)
    }

    // MARK: Grouping

    @Test func groupsFollowTheirBestEndpointAndUnknownIsLast() {
        let items = [item("mystery"),
                     item("sydney", country: "AU"),
                     item("paris", country: "FR"),
                     item("berlin", country: "DE"),
                     item("shanghai", country: "CN")]
        let groups = EndpointRanking.grouped(items, home: london)
        #expect(groups.map(\.region) == [.europe, .china, .oceania, .unknown])
        #expect(groups[0].endpoints.map(\.endpoint.host) == ["paris", "berlin"])
        #expect(groups.last?.endpoints.map(\.endpoint.host) == ["mystery"])
        // Nothing is lost in grouping.
        #expect(groups.flatMap(\.endpoints).count == items.count)
    }

    @Test func aMeasuredEndpointPullsItsWholeRegionForward() {
        let items = [item("paris", country: "FR"),
                     item("sydney", country: "AU", rtt: 8)]
        let groups = EndpointRanking.grouped(items, home: london)
        #expect(groups.map(\.region) == [.oceania, .europe])
    }

    @Test func groupsAreEmptyForNoEndpoints() {
        #expect(EndpointRanking.grouped([], home: london).isEmpty)
        #expect(EndpointRanking.ordered([], home: nil).isEmpty)
    }

    // MARK: Distance

    @Test func distanceIsSaneAndSymmetric() {
        let paris = GeoPoint(lat: 48.86, lon: 2.35)
        let d = EndpointRanking.distanceKM(london, paris)
        #expect(d > 320 && d < 380)                 // ~344 km
        #expect(abs(d - EndpointRanking.distanceKM(paris, london)) < 0.001)
        #expect(EndpointRanking.distanceKM(london, london) == 0)
        // Antipodal-ish: half the circumference, give or take.
        let nz = GeoPoint(lat: -41.3, lon: 174.8)
        #expect(EndpointRanking.distanceKM(london, nz) > 18_000)
    }

    @Test func basisNamesWhyAnEndpointRanksWhereItDoes() {
        #expect(EndpointRanking.basis(for: item("a", country: "FR", rtt: 20), home: london)
                == .measured(20))
        #expect(EndpointRanking.basis(for: item("b", country: "FR"), home: nil) == .unknown)
        #expect(EndpointRanking.basis(for: item("c"), home: london) == .unknown)
        if case .estimated = EndpointRanking.basis(for: item("d", country: "FR"), home: london) {
            // expected
        } else {
            Issue.record("a placeable endpoint with a known home should be an estimate")
        }
    }
}
