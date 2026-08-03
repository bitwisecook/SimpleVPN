// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
//  EndpointRanking.swift
//  "Which of these servers should I offer first?" — the ordering behind every
//  endpoint picker, and the one place that decides it.
//
//  Two kinds of answer, in this order:
//    • MEASURED — a probe actually timed a round trip to this endpoint. Nothing
//      beats having asked.
//    • GUESSED  — no probe (the setting is off, or nothing has run yet), so the
//      order falls back to great-circle distance from where the user is. It's a
//      guess and the UI says so; it is still far better than file order, which
//      is whatever the provider happened to write down.
//  Anything we can neither measure nor place sorts LAST — never dropped. An
//  endpoint the app can't explain is still an endpoint the user may need.
//
//  Sorting is made stable by hand (Swift's sort is not): equal keys keep their
//  original order, so a list doesn't shuffle itself between two identical
//  probes, and a re-render never moves a row out from under the pointer.
//

import Foundation

/// What a probe learned about one endpoint. All fields optional: "we don't know"
/// is a distinct, common and honest state.
nonisolated struct EndpointMeasurement: Sendable, Equatable {
    /// Round-trip time in milliseconds, when something answered and we timed it.
    var rttMS: Double?
    /// nil = never probed, true = something answered, false = nothing did.
    var reachable: Bool?
    /// One short sentence for the tooltip ("OpenVPN answered over UDP").
    var detail: String?
    var measuredAt: Date?

    init(rttMS: Double? = nil, reachable: Bool? = nil, detail: String? = nil,
         measuredAt: Date? = nil) {
        self.rttMS = rttMS
        self.reachable = reachable
        self.detail = detail
        self.measuredAt = measuredAt
    }

    /// Milliseconds, rounded for display ("42 ms").
    var rttText: String? {
        guard let rttMS else { return nil }
        return "\(Int(rttMS.rounded())) ms"
    }
}

/// A point on the globe. Kept local so the pure ranking code has no CoreLocation
/// dependency and stays testable without a device.
nonisolated struct GeoPoint: Sendable, Equatable {
    var lat: Double
    var lon: Double
}

/// An endpoint with everything known about it at ranking time: where GeoIP put
/// it, what the user overrode, and what a probe (if any) measured.
nonisolated struct RankedEndpoint: Sendable, Equatable, Identifiable {

    var endpoint: VPNEndpoint
    /// What GeoIP made of the address. The user's override wins over it.
    var geoCountry: String?
    /// GeoIP's coordinate for the address, when it had one.
    var geoPoint: GeoPoint?
    var measurement: EndpointMeasurement?

    init(endpoint: VPNEndpoint, geoCountry: String? = nil, geoPoint: GeoPoint? = nil,
         measurement: EndpointMeasurement? = nil) {
        self.endpoint = endpoint
        self.geoCountry = geoCountry
        self.geoPoint = geoPoint
        self.measurement = measurement
    }

    var id: String { endpoint.id }

    /// The country actually shown: the user's correction, else GeoIP's guess.
    var countryCode: String? { endpoint.country ?? geoCountry }
    var countryName: String? { countryCode.flatMap { CountryCentroids.name(for: $0) } }
    var flag: String { countryCode.map { CountryCentroids.flag(for: $0) } ?? "" }

    /// Region override, else the country's bucket, else unknown.
    var region: RegionBucket {
        endpoint.region ?? RegionBucket(countryCode: countryCode)
    }

    /// Where to draw it, and what to measure distance from: a user's country
    /// correction moves the pin, because they know better than the database.
    var point: GeoPoint? {
        if endpoint.country != nil, let c = countryCode,
           let centroid = CountryCentroids.coordinate(for: c) {
            return GeoPoint(lat: centroid.lat, lon: centroid.lon)
        }
        return geoPoint
    }

    /// Host, with the port when the profile pins one — the technical identity,
    /// shown alongside (never instead of) the label.
    var address: String {
        endpoint.port.map { "\(endpoint.host):\($0)" } ?? endpoint.host
    }
}

/// One heading's worth of endpoints in a picker.
nonisolated struct RegionGroup: Sendable, Equatable, Identifiable {
    var region: RegionBucket
    var endpoints: [RankedEndpoint]
    var id: String { region.rawValue }
}

nonisolated enum EndpointRanking {

    /// How an endpoint earned its place. Lower `tier` sorts first; within a tier
    /// the smaller `value` sorts first (milliseconds, then kilometres).
    enum Basis: Sendable, Equatable {
        case measured(Double)       // a probe timed it
        case estimated(Double)      // distance from home, in km
        case unreachable(Double)    // probed, nothing answered (km, or infinity)
        case unknown                // no probe, no position — last, but kept

        var tier: Int {
            switch self {
            case .measured: 0
            case .estimated: 1
            case .unreachable: 2
            case .unknown: 3
            }
        }
        var value: Double {
            switch self {
            case .measured(let v), .estimated(let v), .unreachable(let v): v
            case .unknown: 0
            }
        }
    }

    /// Why one endpoint is above another. Measured beats guessed; a probe that
    /// found nothing sinks below an unprobed neighbour we can at least place,
    /// because "it didn't answer" is worse news than "we haven't asked".
    static func basis(for item: RankedEndpoint, home: GeoPoint?) -> Basis {
        let distance = home.flatMap { h in item.point.map { distanceKM(h, $0) } }
        if let m = item.measurement {
            if let rtt = m.rttMS, m.reachable != false { return .measured(rtt) }
            if m.reachable == false { return .unreachable(distance ?? .infinity) }
        }
        if let distance { return .estimated(distance) }
        return .unknown
    }

    /// Ranked best-first. Stable: endpoints that can't be told apart keep the
    /// order they arrived in (which is the profile's own order).
    static func ordered(_ items: [RankedEndpoint], home: GeoPoint?) -> [RankedEndpoint] {
        items.enumerated()
            .map { (index: $0.offset, item: $0.element, basis: basis(for: $0.element, home: home)) }
            .sorted { a, b in
                if a.basis.tier != b.basis.tier { return a.basis.tier < b.basis.tier }
                if a.basis.value != b.basis.value { return a.basis.value < b.basis.value }
                return a.index < b.index
            }
            .map(\.item)
    }

    /// Ranked and grouped by region. A group sits where its best endpoint would,
    /// so "nearest region first" falls out of the same comparison; the unknown
    /// bucket is always last, whatever it contains.
    static func grouped(_ items: [RankedEndpoint], home: GeoPoint?) -> [RegionGroup] {
        var order: [RegionBucket] = []
        var members: [RegionBucket: [RankedEndpoint]] = [:]
        for item in ordered(items, home: home) {
            if members[item.region] == nil {
                members[item.region] = []
                order.append(item.region)       // first appearance = best member
            }
            members[item.region]?.append(item)
        }
        // `order` is already best-first by construction; the only rearrangement
        // is sending the un-placeable bucket to the bottom.
        let placed = order.filter { $0 != .unknown } + order.filter { $0 == .unknown }
        return placed.map { RegionGroup(region: $0, endpoints: members[$0] ?? []) }
    }

    /// Great-circle distance in kilometres (haversine, spherical earth). Only
    /// ever used to compare distances, so the ~0.3% spheroid error is noise.
    static func distanceKM(_ a: GeoPoint, _ b: GeoPoint) -> Double {
        let radius = 6371.0
        let dLat = (b.lat - a.lat) * .pi / 180
        let dLon = (b.lon - a.lon) * .pi / 180
        let lat1 = a.lat * .pi / 180
        let lat2 = b.lat * .pi / 180
        let h = sin(dLat / 2) * sin(dLat / 2)
            + sin(dLon / 2) * sin(dLon / 2) * cos(lat1) * cos(lat2)
        return 2 * radius * asin(min(1, sqrt(h)))
    }
}
