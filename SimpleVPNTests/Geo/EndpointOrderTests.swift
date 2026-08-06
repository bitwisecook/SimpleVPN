// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
//  EndpointOrderTests.swift
//  What a HAND-MADE server order means, and that it beats the automatic ranking
//  everywhere rather than being layered on top of it.
//
//  The decision these tests pin: manual order and automatic ranking are in direct
//  conflict, so one has to win, and it is the user's. Nothing in the app connects in
//  ranked order — choosing a server writes the server/port/protocol overrides
//  explicitly, and OpenVPN's own failover follows the configuration's `remote`
//  lines — so what the order decides is which server the app OFFERS first. Once
//  somebody has said what that should be, a probe landing must not undo it.
//

import Foundation
import Testing
@testable import SimpleVPN

struct EndpointOrderTests {

    private let london = GeoPoint(lat: 51.5, lon: -0.12)

    private func item(_ host: String, country: String? = nil, rtt: Double? = nil,
                      order: Int? = nil, userAdded: Bool? = nil) -> RankedEndpoint {
        var e = VPNEndpoint(host: host)
        e.country = country
        e.order = order
        e.userAdded = userAdded
        return RankedEndpoint(endpoint: e,
                              geoCountry: country,
                              geoPoint: country.flatMap { CountryCentroids.coordinate(for: $0) }
                                  .map { GeoPoint(lat: $0.lat, lon: $0.lon) },
                              measurement: rtt.map { EndpointMeasurement(rttMS: $0, reachable: true) })
    }

    // MARK: The conflict, resolved

    /// A manual order wins over a MEASURED ranking. This is the whole decision: the
    /// slowest server sits first because that is where the user put it.
    @Test func aManualOrderBeatsTheMeasuredRanking() {
        let items = [item("fast", country: "FR", rtt: 5, order: 2),
                     item("slow", country: "AU", rtt: 400, order: 0),
                     item("middling", country: "US", rtt: 50, order: 1)]
        #expect(EndpointRanking.ordered(items, home: london).map(\.endpoint.host)
                == ["slow", "middling", "fast"])
    }

    /// …and a probe landing afterwards does not re-sort it. A list that rearranges
    /// itself the moment a measurement arrives is one nobody can arrange.
    @Test func aLaterProbeDoesNotUndoTheOrder() {
        var items = [item("a", country: "FR", order: 0),
                     item("b", country: "FR", order: 1)]
        let before = EndpointRanking.ordered(items, home: london).map(\.endpoint.host)
        items[1].measurement = EndpointMeasurement(rttMS: 1, reachable: true)
        #expect(EndpointRanking.ordered(items, home: london).map(\.endpoint.host) == before)
    }

    /// No positions at all ⇒ nothing changes: the automatic ranking is untouched.
    @Test func withoutAnyPositionTheRankingIsUnchanged() {
        let items = [item("slow", country: "AU", rtt: 400),
                     item("fast", country: "FR", rtt: 5)]
        #expect(!EndpointRanking.isManuallyOrdered(items))
        #expect(EndpointRanking.ordered(items, home: london).map(\.endpoint.host) == ["fast", "slow"])
    }

    /// A server with no position of its own — a remote that appeared in a re-imported
    /// configuration — follows the placed ones in RANKED order. Never dropped, and
    /// never interleaved into somebody's arrangement.
    @Test func serversWithNoPositionFollowInRankedOrder() {
        let items = [item("new-slow", country: "AU", rtt: 400),
                     item("placed-b", country: "US", order: 1),
                     item("new-fast", country: "FR", rtt: 5),
                     item("placed-a", country: "US", order: 0)]
        #expect(EndpointRanking.ordered(items, home: london).map(\.endpoint.host)
                == ["placed-a", "placed-b", "new-fast", "new-slow"])
    }

    /// Equal positions keep the order they arrived in rather than swapping between
    /// renders — the same stability rule the ranking itself follows.
    @Test func equalPositionsAreStable() {
        let items = [item("a", order: 0), item("b", order: 0), item("c", order: 0)]
        #expect(EndpointRanking.ordered(items, home: nil).map(\.endpoint.host) == ["a", "b", "c"])
        let twice = EndpointRanking.ordered(EndpointRanking.ordered(items, home: nil), home: nil)
        #expect(twice.map(\.endpoint.host) == ["a", "b", "c"])
    }

    @Test func orderingIsIdempotentAndTotal() {
        let items = [item("a", country: "FR", order: 5), item("b", country: "US", order: 1)]
        let once = EndpointRanking.ordered(items, home: london)
        #expect(EndpointRanking.ordered(once, home: london).map(\.endpoint.host)
                == once.map(\.endpoint.host))
        // Sparse and out-of-range positions are positions, not crashes.
        #expect(once.map(\.endpoint.host) == ["b", "a"])
        #expect(EndpointRanking.ordered([], home: london).isEmpty)
    }

    // MARK: The pickers must not silently regroup a hand-made order

    /// THE ORDER SURVIVES GROUPING. Gathering every European server under one
    /// heading is part of the automatic ranking; done over a manual order it would
    /// rearrange it (London, New York, Paris → Europe: London, Paris / North
    /// America: New York). So a manual order is grouped into RUNS: flattening the
    /// groups gives back exactly what the user arranged, and a region may appear
    /// more than once.
    @Test func groupingPreservesAHandMadeOrder() {
        let items = [item("london", country: "GB", order: 0),
                     item("newyork", country: "US", order: 1),
                     item("paris", country: "FR", order: 2)]
        let groups = EndpointRanking.grouped(items, home: london)
        #expect(groups.flatMap(\.endpoints).map(\.endpoint.host) == ["london", "newyork", "paris"])
        #expect(groups.count == 3)
        #expect(groups.allSatisfy { $0.isManualOrder })
        // Every heading still names the region it is actually over — the pickers
        // head their sections with `region.name`, so a stand-in would be a lie.
        #expect(groups.map(\.heading) == groups.map(\.region.name))
        // …and the ids are distinct, or a repeated region would collapse two runs
        // into one row of the picker.
        #expect(Set(groups.map(\.id)).count == 3)
    }

    /// Consecutive servers in the same region share one heading.
    @Test func consecutiveServersInOneRegionShareAHeading() {
        let items = [item("london", country: "GB", order: 0),
                     item("paris", country: "FR", order: 1),
                     item("newyork", country: "US", order: 2)]
        let groups = EndpointRanking.grouped(items, home: london)
        #expect(groups.count == 2)
        #expect(groups[0].endpoints.map(\.endpoint.host) == ["london", "paris"])
        #expect(groups[1].endpoints.map(\.endpoint.host) == ["newyork"])
    }

    @Test func withoutAManualOrderTheGroupsAreStillWholeRegions() {
        let groups = EndpointRanking.grouped([item("london", country: "GB"),
                                             item("newyork", country: "US")], home: london)
        #expect(groups.count == 2)
        #expect(groups.allSatisfy { !$0.isManualOrder })
        #expect(groups[0].heading == groups[0].region.name)
        #expect(Set(groups.map(\.id)).count == 2)
    }

    // MARK: The sentence under the list

    /// The footnote must describe the list that is on screen. "Fastest first" over a
    /// hand-made order is a lie, and it is the one sentence a user reads to find out
    /// what the order means.
    @Test func theFootnoteNamesTheUsersOwnOrderFirst() {
        let manual = [item("a", country: "FR", rtt: 5, order: 0),
                      item("b", country: "US", rtt: 400, order: 1)]
        let said = EndpointRegions.orderExplanation(items: manual, home: london)
        #expect(said.contains("the order you put them in"))
        #expect(!said.lowercased().contains("fastest first"))
        // Speed is still measured — it just stops sorting.
        #expect(said.contains("Speed column"))
    }

    /// …and it counts the servers still waiting for a place, because a row sitting at
    /// the end for a reason nobody stated looks like a bug.
    @Test func theFootnoteCountsUnplacedServers() {
        let mixed = [item("placed", country: "FR", order: 0), item("new", country: "US")]
        let said = EndpointRegions.orderExplanation(items: mixed, home: london)
        #expect(said.contains("1 newer server"))
        let two = mixed + [item("newer", country: "US")]
        #expect(EndpointRegions.orderExplanation(items: two, home: london).contains("2 newer servers"))
    }

    // MARK: Persistence — the position is an annotation like any other

    /// A position survives the round trip through the stored blob. Without `order`
    /// counting as an annotation, `encodedBlob()` would throw away an entry that
    /// carried nothing else — which is every configuration-provided server the user
    /// has only MOVED.
    @Test func aPositionSurvivesTheStoredBlob() throws {
        var e = VPNEndpoint(host: "vpn.example.com", port: 1194, proto: "udp")
        e.order = 3
        #expect(e.hasAnnotations)
        let list = VPNEndpointList(endpoints: [e])
        let blob = try #require(list.encodedBlob())
        #expect(VPNEndpointList.decode(from: blob).endpoints.first?.order == 3)
    }

    @Test func aPositionlessAnnotationIsStillDropped() {
        let bare = VPNEndpoint(host: "vpn.example.com")
        #expect(!bare.hasAnnotations)
        #expect(VPNEndpointList(endpoints: [bare]).encodedBlob() == nil)
    }

    /// Lenient decoding, like every other field in this blob: a string position from
    /// a hand-edited or MDM-written file is read, and nonsense degrades to "no
    /// position" rather than sorting ahead of everything.
    @Test func aNonsensePositionDecodesToNoPosition() {
        func decoded(orderLiteral: String) -> VPNEndpoint? {
            let json = "{\"endpoints\":[{\"host\":\"h\",\"order\":\(orderLiteral)}]}"
            return VPNEndpointList.decode(from: Data(json.utf8)).endpoints.first
        }
        #expect(decoded(orderLiteral: "2")?.order == 2)
        #expect(decoded(orderLiteral: "\"3\"")?.order == 3)     // a string, as MDM may write it
        #expect(decoded(orderLiteral: "\"banana\"")?.order == nil)
        #expect(decoded(orderLiteral: "-1")?.order == nil)
        #expect(decoded(orderLiteral: "null")?.order == nil)
    }

    /// A configuration-provided server CAN be moved, and the lock rides with it. The
    /// lock is about existence — the .ovpn owns which servers there are — and a
    /// position changes only the order the app offers them in, so a moved row is
    /// still visibly the configuration's.
    @Test func aConfigurationProvidedServerKeepsItsLockWhenMoved() {
        let scanned = [Endpoint(host: "b.example.com", port: 1194, proto: "udp"),
                       Endpoint(host: "a.example.com", port: 1194, proto: "udp")]
        var placed = VPNEndpoint(host: "a.example.com", port: 1194, proto: "udp")
        placed.order = 0
        placed.userAdded = true      // a stale claim the merge must not honour
        let merged = VPNEndpointList.merged(scanned: scanned,
                                            stored: VPNEndpointList(endpoints: [placed]))
        let moved = try! #require(merged.first { $0.host == "a.example.com" })
        #expect(moved.order == 0)
        // Still the configuration's: `merged` clears `userAdded` for a scanned
        // address, so the row keeps its lock however it has been annotated.
        #expect(moved.userAdded == nil)
        // …and it now sorts first, which is what the user asked for.
        let ranked = merged.map { RankedEndpoint(endpoint: $0) }
        #expect(EndpointRanking.ordered(ranked, home: nil).first?.endpoint.host == "a.example.com")
    }

    /// The lock's own words have to say what it does and doesn't cover, or a movable
    /// row with a padlock on it reads as frozen.
    @Test func theLockSaysItIsAboutExistenceNotPosition() {
        #expect(ServersTableCopy.lockedHelp.contains("move it"))
        #expect(ServersTableCopy.lockedHelp.contains("add or remove"))
        #expect(ServersTableCopy.lockFootnote.contains("never"))
    }
}
