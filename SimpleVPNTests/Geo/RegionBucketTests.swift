// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
//  RegionBucketTests.swift
//  Pins the country → region grouping, especially the deliberate calls: China
//  and Russia are their own buckets, Hong Kong / Macao / Taiwan are NOT China,
//  Turkey and the Caucasus sit with Europe, North Africa sits with Africa, and
//  Central America and the Caribbean sit with North America.
//

import Foundation
import Testing
@testable import SimpleVPN

struct RegionBucketTests {

    @Test func continentsBucketAsExpected() {
        #expect(RegionBucket(countryCode: "US") == .northAmerica)
        #expect(RegionBucket(countryCode: "CA") == .northAmerica)
        #expect(RegionBucket(countryCode: "BR") == .southAmerica)
        #expect(RegionBucket(countryCode: "DE") == .europe)
        #expect(RegionBucket(countryCode: "GB") == .europe)
        #expect(RegionBucket(countryCode: "ZA") == .africa)
        #expect(RegionBucket(countryCode: "JP") == .asiaPacific)
        #expect(RegionBucket(countryCode: "SG") == .asiaPacific)
        #expect(RegionBucket(countryCode: "AU") == .oceania)
        #expect(RegionBucket(countryCode: "NZ") == .oceania)
    }

    @Test func chinaIsItsOwnRegionButTheSARsAndTaiwanAreNot() {
        // The bucket exists because routing in and out of the mainland is its
        // own problem — which is exactly not true of Hong Kong or Macao, and
        // calling Taiwan "China" would be a claim this app doesn't get to make.
        #expect(RegionBucket(countryCode: "CN") == .china)
        #expect(RegionBucket(countryCode: "HK") == .asiaPacific)
        #expect(RegionBucket(countryCode: "MO") == .asiaPacific)
        #expect(RegionBucket(countryCode: "TW") == .asiaPacific)
    }

    @Test func russiaIsItsOwnRegionAndNeighboursAreNot() {
        #expect(RegionBucket(countryCode: "RU") == .russia)
        #expect(RegionBucket(countryCode: "BY") == .europe)
        #expect(RegionBucket(countryCode: "UA") == .europe)
        #expect(RegionBucket(countryCode: "KZ") == .asiaPacific)
    }

    @Test func middleEastCoversTheGulfAndLevantOnly() {
        for code in ["AE", "SA", "QA", "BH", "KW", "OM", "IL", "PS", "JO", "LB", "IQ", "IR", "SY", "YE"] {
            #expect(RegionBucket(countryCode: code) == .middleEast, "\(code)")
        }
        // Transcontinental cases that route with Europe, and North Africa,
        // which routes (and lands its cables) with Africa.
        #expect(RegionBucket(countryCode: "TR") == .europe)
        #expect(RegionBucket(countryCode: "CY") == .europe)
        #expect(RegionBucket(countryCode: "GE") == .europe)
        #expect(RegionBucket(countryCode: "AM") == .europe)
        #expect(RegionBucket(countryCode: "AZ") == .europe)
        #expect(RegionBucket(countryCode: "EG") == .africa)
        #expect(RegionBucket(countryCode: "MA") == .africa)
        #expect(RegionBucket(countryCode: "AF") == .asiaPacific)
    }

    @Test func centralAmericaAndCaribbeanGoWithNorthAmerica() {
        for code in ["MX", "PA", "CR", "GT", "JM", "PR", "DO", "BS", "TT", "KY"] {
            #expect(RegionBucket(countryCode: code) == .northAmerica, "\(code)")
        }
        #expect(RegionBucket(countryCode: "GF") == .southAmerica)   // French Guiana
    }

    @Test func unknownAndMalformedCodesAreUnknownNotGuessed() {
        #expect(RegionBucket(countryCode: nil) == .unknown)
        #expect(RegionBucket(countryCode: "") == .unknown)
        #expect(RegionBucket(countryCode: "ZZ") == .unknown)
        #expect(RegionBucket(countryCode: "XYZ") == .unknown)
        #expect(RegionBucket(countryCode: "AQ") == .unknown)        // no sensible region
    }

    @Test func lookupIsCaseAndWhitespaceInsensitive() {
        #expect(RegionBucket(countryCode: "de") == .europe)
        #expect(RegionBucket(countryCode: " jp ") == .asiaPacific)
    }

    @Test func everyCountryWithACentroidHasARegion() {
        // Any code the GeoIP layer can produce must land somewhere sensible;
        // the only permitted exceptions are the uninhabited/no-region places.
        let permitted: Set<String> = ["AQ", "BV"]
        for code in knownCountryCodes where !permitted.contains(code) {
            #expect(RegionBucket(countryCode: code) != .unknown, "\(code) has no region")
        }
    }

    @Test func regionCountryListsAreNonEmptyAndDisjoint() {
        var seen = Set<String>()
        for region in RegionBucket.selectable {
            let countries = region.countries
            #expect(!countries.isEmpty, "\(region.rawValue) has no countries")
            for c in countries {
                #expect(seen.insert(c.code).inserted, "\(c.code) appears twice")
                #expect(RegionBucket(countryCode: c.code) == region)
            }
        }
        #expect(!RegionBucket.selectable.contains(.unknown))
    }

    @Test func unknownSortsLastInTheDefaultOrder() {
        #expect(RegionBucket.unknown.defaultOrder
                == RegionBucket.allCases.map(\.defaultOrder).max())
    }

    /// Codes the app can actually see, sampled across every continent (the full
    /// centroid table is private to GeoIP.swift).
    private var knownCountryCodes: [String] {
        ["US", "CA", "MX", "BR", "AR", "CL", "GB", "DE", "FR", "NL", "SE", "PL",
         "TR", "UA", "RU", "CN", "HK", "TW", "JP", "KR", "SG", "IN", "PK", "ID",
         "AU", "NZ", "FJ", "ZA", "NG", "KE", "EG", "MA", "AE", "SA", "IL", "IR",
         "KZ", "UZ", "GE", "IS", "IE", "PT", "GR", "XK", "AQ", "BV", "GL", "PR"]
    }
}
