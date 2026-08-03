// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
//  Regions.swift
//  The bucket a VPN endpoint's country belongs to, for grouping the endpoint
//  pickers. These are NETWORK regions, not continents: the grouping exists so
//  somebody scanning a list of forty servers can find the handful that are near
//  them (or deliberately far from them), so the split follows how traffic
//  actually reaches a place rather than any political or geographic scheme.
//
//  The judgement calls are all recorded next to the country lists below, because
//  every one of them is arguable and none of them should be re-litigated from
//  memory: China is its own bucket (the border is a routing fact, not an
//  opinion), Russia likewise, and Hong Kong / Macao / Taiwan are NOT in the
//  China bucket — they route differently, and putting them there would be a
//  claim this app has no business making.
//

import Foundation

/// A group heading in the endpoint pickers. `unknown` is a real, kept case: an
/// endpoint we can't place must still be pickable, just listed last.
nonisolated enum RegionBucket: String, Codable, Sendable, CaseIterable, Identifiable, Hashable {
    case northAmerica
    case southAmerica
    case europe
    case africa
    case middleEast
    case russia
    case china
    case asiaPacific
    case oceania
    case unknown

    var id: String { rawValue }

    /// Menu heading. Plain names — no acronyms a first-time user has to decode
    /// ("APAC" is jargon; "Asia-Pacific" is not).
    var name: String {
        switch self {
        case .northAmerica: "North America"
        case .southAmerica: "South America"
        case .europe: "Europe"
        case .africa: "Africa"
        case .middleEast: "Middle East"
        case .russia: "Russia"
        case .china: "China"
        case .asiaPacific: "Asia-Pacific"
        case .oceania: "Australia and the Pacific"
        case .unknown: "Location unknown"
        }
    }

    var systemImage: String {
        switch self {
        case .northAmerica, .southAmerica: "globe.americas"
        case .europe, .africa, .middleEast, .russia: "globe.europe.africa"
        case .china, .asiaPacific, .oceania: "globe.asia.australia"
        case .unknown: "questionmark.circle"
        }
    }

    /// Order used when nothing better is known (no probes, no home location).
    /// Matches the declaration order; `unknown` is always last.
    var defaultOrder: Int { Self.allCases.firstIndex(of: self) ?? Self.allCases.count }

    /// The bucket for an ISO 3166-1 alpha-2 country code. Unknown or empty
    /// codes give `.unknown` — never a guess.
    init(countryCode: String?) {
        guard let code = countryCode?.trimmingCharacters(in: .whitespaces).uppercased(),
              code.count == 2, let bucket = Self.table[code] else {
            self = .unknown
            return
        }
        self = bucket
    }

    /// Every country in this bucket, as (code, name), alphabetical by name —
    /// the override picker's contents.
    var countries: [(code: String, name: String)] {
        Self.table.compactMap { code, bucket in
            guard bucket == self, let name = CountryCentroids.name(for: code) else { return nil }
            return (code: code, name: name)
        }
        .sorted { $0.name.localizedCaseInsensitiveCompare($1.name) == .orderedAscending }
    }

    // MARK: Country table

    private static let table: [String: RegionBucket] = {
        var t: [String: RegionBucket] = [:]
        func add(_ bucket: RegionBucket, _ codes: [String]) {
            for c in codes { t[c] = bucket }
        }

        // North America takes Central America and the Caribbean with it: those
        // networks almost all transit Miami or Dallas, so a "nearest region"
        // answer that separated them would be geographically tidy and
        // practically wrong.
        add(.northAmerica, [
            "AG", "AI", "AW", "BB", "BL", "BM", "BQ", "BS", "BZ", "CA", "CR", "CU",
            "CW", "DM", "DO", "GD", "GP", "GT", "HN", "HT", "JM", "KN", "KY", "LC",
            "MF", "MQ", "MS", "MX", "NI", "PA", "PM", "PR", "SV", "SX", "TC", "TT",
            "US", "VC", "VG", "VI",
        ])

        add(.southAmerica, [
            "AR", "BO", "BR", "CL", "CO", "EC", "FK", "GF", "GS", "GY", "PE", "PY",
            "SR", "UY", "VE",
        ])

        // Europe includes Turkey and the Caucasus (their transit and peering is
        // European — Istanbul and Frankfurt, not the Gulf), and Greenland, whose
        // only cables run to Denmark and Iceland.
        add(.europe, [
            "AD", "AL", "AM", "AT", "AX", "AZ", "BA", "BE", "BG", "BY", "CH", "CY",
            "CZ", "DE", "DK", "EE", "ES", "FI", "FO", "FR", "GB", "GE", "GG", "GI",
            "GL", "GR", "HR", "HU", "IE", "IM", "IS", "IT", "JE", "LI", "LT", "LU",
            "LV", "MC", "MD", "ME", "MK", "MT", "NL", "NO", "PL", "PT", "RO", "RS",
            "SE", "SI", "SJ", "SK", "SM", "TR", "UA", "VA", "XK",
        ])

        // Egypt and the rest of North Africa stay in Africa: their landing
        // stations and the traffic that uses them are African, even though the
        // politics are often filed under "Middle East".
        add(.africa, [
            "AO", "BF", "BI", "BJ", "BW", "CD", "CF", "CG", "CI", "CM", "CV", "DJ",
            "DZ", "EG", "EH", "ER", "ET", "GA", "GH", "GM", "GN", "GQ", "GW", "KE",
            "KM", "LR", "LS", "LY", "MA", "MG", "ML", "MR", "MU", "MW", "MZ", "NA",
            "NE", "NG", "RE", "RW", "SC", "SD", "SH", "SL", "SN", "SO", "SS", "ST",
            "SZ", "TD", "TF", "TG", "TN", "TZ", "UG", "YT", "ZA", "ZM", "ZW",
        ])

        // The Gulf plus the Levant and Iran. Deliberately excludes Turkey and
        // North Africa (see above) — this is the set whose traffic hubs are
        // Dubai, Fujairah and Tel Aviv.
        add(.middleEast, [
            "AE", "BH", "IL", "IQ", "IR", "JO", "KW", "LB", "OM", "PS", "QA", "SA",
            "SY", "YE",
        ])

        // Russia alone. Not folded into Europe: routing in and out of it is its
        // own problem, which is exactly why somebody would pick — or avoid — an
        // endpoint there.
        add(.russia, ["RU"])

        // Mainland China alone, for the same reason. Hong Kong, Macao and Taiwan
        // are in Asia-Pacific: their connectivity is not mainland connectivity,
        // and grouping them here would assert something political.
        add(.china, ["CN"])

        add(.asiaPacific, [
            "AF", "BD", "BN", "BT", "HK", "ID", "IN", "IO", "JP", "KG", "KH", "KP",
            "KR", "KZ", "LA", "LK", "MM", "MN", "MO", "MV", "MY", "NP", "PH", "PK",
            "SG", "TH", "TJ", "TL", "TM", "TW", "UZ", "VN",
        ])

        // Australia, New Zealand and the Pacific islands, plus Australia's
        // Indian Ocean territories (Cocos, Christmas Island), which are served
        // from Perth.
        add(.oceania, [
            "AS", "AU", "CC", "CK", "CX", "FJ", "FM", "GU", "HM", "KI", "MH", "MP",
            "NC", "NF", "NR", "NU", "NZ", "PF", "PG", "PN", "PW", "SB", "TK", "TO",
            "TV", "UM", "VU", "WF", "WS",
        ])

        // Antarctica and Bouvet Island have no sensible network region and no
        // permanent population; they are placed nowhere rather than wrongly.
        add(.unknown, ["AQ", "BV"])

        return t
    }()

    /// All buckets that hold at least one country, in default order — the
    /// override picker's sections.
    static var selectable: [RegionBucket] {
        allCases.filter { $0 != .unknown }
    }
}
