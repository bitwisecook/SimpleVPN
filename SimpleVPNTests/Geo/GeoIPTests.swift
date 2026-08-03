// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
//  GeoIPTests.swift
//  Pins the MMDB reader against a synthetic fixture shaped like what DB-IP
//  ships (ip_version 6, 24-bit records, v4 stored under ::/96): one CIDR maps
//  to {"country":{"iso_code":"DE"}}, everything else to "no data". Plus
//  CountryCentroids sanity checks.
//

import Foundation
import Testing
@testable import SimpleVPN

struct GeoIPTests {

    // MARK: Fixture

    /// Big-endian bytes of `value` in `count` bytes.
    private func be(_ value: Int, _ count: Int) -> [UInt8] {
        (0..<count).reversed().map { UInt8((value >> ($0 * 8)) & 0xFF) }
    }

    /// A tiny valid MMDB: 81.2.69.0/24 → DE. One chain node per prefix bit
    /// (96 zero bits for the v4-in-v6 offset, then the 24 bits of 81.2.69);
    /// the off-path record is node_count ("no data").
    private func makeFixture() -> Data {
        let prefix: [UInt8] = [81, 2, 69]
        let prefixBits = 96 + 24
        let nodeCount = prefixBits
        let noData = nodeCount
        let dataPointer = nodeCount + 16        // → offset 0 in the data section

        var out: [UInt8] = []
        for i in 0..<prefixBits {
            let bit: Int
            if i < 96 {
                bit = 0
            } else {
                let j = i - 96
                bit = Int((prefix[j / 8] >> (7 - (j % 8))) & 1)
            }
            let onPath = (i == prefixBits - 1) ? dataPointer : i + 1
            out += be(bit == 0 ? onPath : noData, 3)    // left record
            out += be(bit == 1 ? onPath : noData, 3)    // right record
        }
        out += [UInt8](repeating: 0, count: 16)         // tree/data separator

        // Data section, offset 0: {"country": {"iso_code": "DE"}}.
        out += [0xE1, 0x47] + Array("country".utf8)     // map(1), string(7)
        out += [0xE1, 0x48] + Array("iso_code".utf8)    // map(1), string(8)
        out += [0x42] + Array("DE".utf8)                // string(2)

        // Metadata: marker + {"node_count": …, "record_size": 24, "ip_version": 6}.
        out += [0xAB, 0xCD, 0xEF] + Array("MaxMind.com".utf8)
        out += [0xE3]                                   // map(3)
        out += [0x4A] + Array("node_count".utf8) + [0xA2] + be(nodeCount, 2)
        out += [0x4B] + Array("record_size".utf8) + [0xA1, 24]
        out += [0x4A] + Array("ip_version".utf8) + [0xA1, 6]
        return Data(out)
    }

    // MARK: Reader

    @Test func ipv4InsideCIDRResolves() throws {
        let db = try #require(GeoIPDatabase(data: makeFixture()))
        #expect(db.countryCode(for: "81.2.69.142") == "DE")
        #expect(db.countryCode(for: "81.2.69.0") == "DE")
        #expect(db.countryCode(for: "81.2.69.255") == "DE")
    }

    @Test func ipv4OutsideCIDRIsNil() throws {
        let db = try #require(GeoIPDatabase(data: makeFixture()))
        #expect(db.countryCode(for: "81.2.70.1") == nil)
        #expect(db.countryCode(for: "8.8.8.8") == nil)
        #expect(db.countryCode(for: "0.0.0.0") == nil)
    }

    @Test func ipv6PathResolvesTheSameRecord() throws {
        // ::5102:458e is the raw v6 form of 81.2.69.142 under the ::/96 prefix.
        let db = try #require(GeoIPDatabase(data: makeFixture()))
        #expect(db.countryCode(for: "::5102:458e") == "DE")
        #expect(db.countryCode(for: "2001:db8::1") == nil)
    }

    @Test func garbageInputIsNil() throws {
        let db = try #require(GeoIPDatabase(data: makeFixture()))
        #expect(db.countryCode(for: "not-an-ip") == nil)
        #expect(db.countryCode(for: "") == nil)
        #expect(db.countryCode(for: "999.1.1.1") == nil)
    }

    @Test func corruptDataFailsInit() {
        #expect(GeoIPDatabase(data: Data("definitely not an mmdb".utf8)) == nil)
        #expect(GeoIPDatabase(data: Data()) == nil)
    }

    @Test func opensFromFileURL() throws {
        let url = FileManager.default.temporaryDirectory
            .appendingPathComponent("geoip-fixture-\(UUID().uuidString).mmdb")
        try makeFixture().write(to: url)
        defer { try? FileManager.default.removeItem(at: url) }
        let db = try #require(GeoIPDatabase(url: url))
        #expect(db.countryCode(for: "81.2.69.142") == "DE")
    }

    @Test func missingFileFailsInit() {
        let url = FileManager.default.temporaryDirectory
            .appendingPathComponent("no-such-\(UUID().uuidString).mmdb")
        #expect(GeoIPDatabase(url: url) == nil)
    }

    // MARK: CountryCentroids

    @Test func knownCountryHasCentroidNameAndFlag() throws {
        let de = try #require(CountryCentroids.coordinate(for: "DE"))
        #expect(abs(de.lat - 51.2) < 1.0)
        #expect(abs(de.lon - 10.4) < 1.0)
        #expect(CountryCentroids.name(for: "DE") == "Germany")
        #expect(CountryCentroids.flag(for: "DE") == "🇩🇪")
    }

    @Test func lookupIsCaseInsensitive() {
        #expect(CountryCentroids.name(for: "gb") == "United Kingdom")
        #expect(CountryCentroids.coordinate(for: "us") != nil)
        #expect(CountryCentroids.flag(for: "gb") == "🇬🇧")
    }

    @Test func unknownCodeIsNil() {
        #expect(CountryCentroids.coordinate(for: "ZZ") == nil)
        #expect(CountryCentroids.name(for: "ZZ") == nil)
        #expect(CountryCentroids.coordinate(for: "") == nil)
    }

    @Test func coordinatesAreOnTheGlobe() {
        // A malformed table entry would quietly draw pins in the void.
        for code in ["US", "GB", "DE", "JP", "AU", "BR", "ZA", "RU", "XK"] {
            let c = CountryCentroids.coordinate(for: code)
            #expect(c != nil)
            if let c {
                #expect(c.lat >= -90 && c.lat <= 90)
                #expect(c.lon >= -180 && c.lon <= 180)
            }
        }
    }
}
