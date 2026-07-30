// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
//  GeoIP.swift
//  Country-level IP geolocation for the endpoint map: a minimal MaxMind-DB
//  (MMDB spec 2.0) reader sufficient for DB-IP Country Lite / GeoLite2-Country
//  files, a static ISO 3166-1 centroid/name/flag table, and the app-side
//  EndpointLocator that turns profile endpoints into map pins (DNS → GeoIP →
//  centroid) with a 7-day persistent host cache. No third-party code; the whole
//  DB (~10 MB) loads into memory — no mmap games.
//

import Foundation
import Darwin

// MARK: - MMDB reader

/// Read-only country database. Only decodes what a country lookup needs:
/// metadata (node_count / record_size / ip_version), the binary search tree,
/// and enough of the data section to walk a map to `country.iso_code`.
nonisolated struct GeoIPDatabase: Sendable {

    private let bytes: [UInt8]
    private let nodeCount: Int
    private let recordSize: Int     // bits per record: 24 / 28 / 32
    private let ipVersion: Int      // 4 or 6 (DB-IP ships 6, v4 stored at ::/96)
    private let dataStart: Int      // tree size + 16-byte separator

    init?(url: URL) {
        // Memory-map rather than eagerly read ~10 MB: pages fault in lazily as
        // the search tree is walked, so construction is cheap wherever it runs.
        guard let data = try? Data(contentsOf: url, options: .mappedIfSafe) else { return nil }
        self.init(data: data)
    }

    /// Also the test seam — fixtures construct tiny synthetic DBs in memory.
    init?(data: Data) {
        let all = [UInt8](data)
        // Metadata marker \xAB\xCD\xEF"MaxMind.com", last occurrence wins.
        let marker: [UInt8] = [0xAB, 0xCD, 0xEF] + Array("MaxMind.com".utf8)
        guard let markerStart = Self.lastIndex(of: marker, in: all) else { return nil }
        let meta = markerStart + marker.count   // metadata map; also its pointer base
        guard let ncOffset = Self.mapValue(forKey: "node_count", at: meta, base: meta, in: all),
              let rsOffset = Self.mapValue(forKey: "record_size", at: meta, base: meta, in: all),
              let ivOffset = Self.mapValue(forKey: "ip_version", at: meta, base: meta, in: all),
              let nc = Self.uint(at: ncOffset, base: meta, in: all),
              let rs = Self.uint(at: rsOffset, base: meta, in: all),
              let iv = Self.uint(at: ivOffset, base: meta, in: all),
              rs == 24 || rs == 28 || rs == 32,
              iv == 4 || iv == 6,
              nc > 0, nc < 1 << 32              // sane tree; also keeps Int math safe
        else { return nil }
        let treeBytes = Int(nc) * Int(rs) / 4   // node = 2 records × rs bits
        guard treeBytes + 16 <= all.count else { return nil }
        bytes = all
        nodeCount = Int(nc)
        recordSize = Int(rs)
        ipVersion = Int(iv)
        dataStart = treeBytes + 16
    }

    /// ISO 3166-1 alpha-2 for a numeric IPv4/IPv6 address string, or nil for
    /// unroutable/unknown/garbage input.
    func countryCode(for ip: String) -> String? {
        guard var key = Self.ipBytes(ip) else { return nil }
        if key.count == 4 {
            // v4 in a v6 tree lives under ::/96 — walk 96 zero bits first.
            if ipVersion == 6 { key = [UInt8](repeating: 0, count: 12) + key }
        } else if ipVersion == 4 {
            return nil                          // v6 address, v4-only tree
        }

        var node = 0
        for bitIndex in 0..<(key.count * 8) {
            let bit = (key[bitIndex >> 3] >> (7 - (bitIndex & 7))) & 1
            guard let next = record(node: node, right: bit == 1) else { return nil }
            if next == nodeCount { return nil }                      // no data
            if next > nodeCount {                                    // data pointer
                return isoCode(atDataOffset: dataStart + (next - nodeCount - 16))
            }
            node = next
        }
        return nil
    }

    // MARK: Search tree

    private func record(node: Int, right: Bool) -> Int? {
        guard node < nodeCount else { return nil }
        switch recordSize {
        case 24:
            let base = node * 6 + (right ? 3 : 0)
            return Self.uintBE(at: base, count: 3, in: bytes).map(Int.init)
        case 28:
            let base = node * 7
            guard base + 7 <= bytes.count else { return nil }
            let mid = Int(bytes[base + 3])      // shared byte: high nibble left, low nibble right
            if right {
                return (mid & 0x0F) << 24 | Int(bytes[base + 4]) << 16
                     | Int(bytes[base + 5]) << 8 | Int(bytes[base + 6])
            }
            return (mid & 0xF0) << 20 | Int(bytes[base]) << 16
                 | Int(bytes[base + 1]) << 8 | Int(bytes[base + 2])
        default: // 32
            let base = node * 8 + (right ? 4 : 0)
            return Self.uintBE(at: base, count: 4, in: bytes).map(Int.init)
        }
    }

    private func isoCode(atDataOffset offset: Int) -> String? {
        guard let country = Self.mapValue(forKey: "country", at: offset, base: dataStart, in: bytes),
              let iso = Self.mapValue(forKey: "iso_code", at: country, base: dataStart, in: bytes)
        else { return nil }
        return Self.string(at: iso, base: dataStart, in: bytes)
    }

    // MARK: Data-section decoding (MMDB spec 2.0)
    // Field = control byte (3 type bits / 5 size bits), optional extended-type
    // byte (type 0 → next byte + 7), optional size-extension bytes (29/30/31),
    // then payload. Pointers (type 1) keep their raw size bits.

    private struct Control { var type: Int; var size: Int; var payload: Int }

    private static func control(at offset: Int, in bytes: [UInt8]) -> Control? {
        guard offset < bytes.count else { return nil }
        var type = Int(bytes[offset]) >> 5
        var size = Int(bytes[offset]) & 0x1F
        var p = offset + 1
        if type == 0 {
            guard p < bytes.count else { return nil }
            type = Int(bytes[p]) + 7
            p += 1
        }
        if type != 1 {
            switch size {
            case 29:
                guard let v = uintBE(at: p, count: 1, in: bytes) else { return nil }
                size = 29 + Int(v); p += 1
            case 30:
                guard let v = uintBE(at: p, count: 2, in: bytes) else { return nil }
                size = 285 + Int(v); p += 2
            case 31:
                guard let v = uintBE(at: p, count: 3, in: bytes) else { return nil }
                size = 65_821 + Int(v); p += 3
            default:
                break
            }
        }
        return Control(type: type, size: size, payload: p)
    }

    /// Resolve a pointer field to its absolute target offset (`base` = start of
    /// the section pointers are relative to: data section, or metadata map).
    private static func pointerTarget(_ c: Control, base: Int, in bytes: [UInt8]) -> Int? {
        let ss = (c.size >> 3) & 0x3
        let vvv = UInt64(c.size & 0x7)
        guard let tail = uintBE(at: c.payload, count: ss + 1, in: bytes) else { return nil }
        let value: UInt64
        switch ss {
        case 0: value = vvv << 8 | tail
        case 1: value = (vvv << 16 | tail) + 2_048
        case 2: value = (vvv << 24 | tail) + 526_336
        default: value = tail                   // ss == 3: vvv unused
        }
        return base + Int(value)
    }

    /// Follow pointer chains to the concrete value's control data.
    private static func dereference(at offset: Int, base: Int, in bytes: [UInt8]) -> Control? {
        var offset = offset
        for _ in 0..<16 {                       // bound against corrupt files
            guard let c = control(at: offset, in: bytes) else { return nil }
            if c.type != 1 { return c }
            guard let target = pointerTarget(c, base: base, in: bytes) else { return nil }
            offset = target
        }
        return nil
    }

    /// Offset just past the value at `offset` (never follows pointers).
    private static func skipValue(at offset: Int, in bytes: [UInt8]) -> Int? {
        guard let c = control(at: offset, in: bytes) else { return nil }
        switch c.type {
        case 1:                                 // pointer: control + 1–4 bytes
            return c.payload + ((c.size >> 3) & 0x3) + 1
        case 7:                                 // map: size × (key, value)
            var o = c.payload
            for _ in 0..<(c.size * 2) {
                guard let next = skipValue(at: o, in: bytes) else { return nil }
                o = next
            }
            return o
        case 11:                                // array: size values
            var o = c.payload
            for _ in 0..<c.size {
                guard let next = skipValue(at: o, in: bytes) else { return nil }
                o = next
            }
            return o
        case 14:                                // bool: value lives in the size bits
            return c.payload
        default:                                // string/bytes/double/float/u16/u32/u64/u128/i32:
            return c.payload + c.size           // payload is exactly `size` bytes
        }
    }

    private static func string(at offset: Int, base: Int, in bytes: [UInt8]) -> String? {
        guard let c = dereference(at: offset, base: base, in: bytes), c.type == 2,
              c.payload + c.size <= bytes.count else { return nil }
        return String(decoding: bytes[c.payload..<(c.payload + c.size)], as: UTF8.self)
    }

    private static func uint(at offset: Int, base: Int, in bytes: [UInt8]) -> UInt64? {
        guard let c = dereference(at: offset, base: base, in: bytes),
              c.type == 5 || c.type == 6 || c.type == 9, c.size <= 8 else { return nil }
        return uintBE(at: c.payload, count: c.size, in: bytes)
    }

    /// Offset of the value for `key` in the map at `offset`, or nil.
    private static func mapValue(forKey key: String, at offset: Int, base: Int,
                                 in bytes: [UInt8]) -> Int? {
        guard let c = dereference(at: offset, base: base, in: bytes), c.type == 7 else { return nil }
        var o = c.payload
        for _ in 0..<c.size {
            guard let k = string(at: o, base: base, in: bytes),
                  let valueOffset = skipValue(at: o, in: bytes) else { return nil }
            if k == key { return valueOffset }
            guard let next = skipValue(at: valueOffset, in: bytes) else { return nil }
            o = next
        }
        return nil
    }

    private static func uintBE(at offset: Int, count: Int, in bytes: [UInt8]) -> UInt64? {
        guard count >= 0, count <= 8, offset >= 0, offset + count <= bytes.count else { return nil }
        var v: UInt64 = 0
        for i in 0..<count { v = v << 8 | UInt64(bytes[offset + i]) }
        return v
    }

    private static func lastIndex(of needle: [UInt8], in haystack: [UInt8]) -> Int? {
        guard haystack.count >= needle.count, !needle.isEmpty else { return nil }
        var i = haystack.count - needle.count
        outer: while i >= 0 {
            for j in 0..<needle.count where haystack[i + j] != needle[j] {
                i -= 1
                continue outer
            }
            return i
        }
        return nil
    }

    /// Network-order address bytes: 4 for dotted-quad IPv4, 16 for IPv6.
    private static func ipBytes(_ ip: String) -> [UInt8]? {
        var v4 = in_addr()
        if inet_pton(AF_INET, ip, &v4) == 1 {
            return withUnsafeBytes(of: v4) { Array($0) }
        }
        var v6 = in6_addr()
        if inet_pton(AF_INET6, ip, &v6) == 1 {
            return withUnsafeBytes(of: v6) { Array($0) }
        }
        return nil
    }
}

/// App-wide database handle. nil when the bundled DB is missing — the app works,
/// map pins just don't show. Tools/fetch-geoip.sh maintains the bundled copy
/// (Vendor/geoip/dbip-country-lite.mmdb, DB-IP Country Lite, CC-BY-4.0).
enum GeoIP {
    // nonisolated so the first lookup never has to hop to (and block) the main
    // actor while the DB parses. `warm()` forces that one-time parse onto a
    // background thread at launch so no lookup ever pays for it inline.
    nonisolated static let shared: GeoIPDatabase? = load()

    private nonisolated static func load() -> GeoIPDatabase? {
        Bundle.main.url(forResource: "dbip-country-lite", withExtension: "mmdb")
            .flatMap { GeoIPDatabase(url: $0) }
    }

    static func warm() {
        Task.detached(priority: .utility) { _ = GeoIP.shared }
    }
}

// MARK: - Country centroids / names / flags

/// Static ISO 3166-1 alpha-2 table (all assigned codes plus XK, which DB-IP and
/// MaxMind both emit for Kosovo). Centroids are country-level approximations —
/// exactly the fidelity a whole-world pin map needs, nothing more.
enum CountryCentroids {

    static func coordinate(for isoCode: String) -> (lat: Double, lon: Double)? {
        table[isoCode.uppercased()].map { (lat: $0.lat, lon: $0.lon) }
    }

    static func name(for isoCode: String) -> String? {
        table[isoCode.uppercased()]?.name
    }

    /// Regional-indicator emoji flag ("DE" → "🇩🇪"). Unknown-but-alphabetic codes
    /// still produce the letter glyphs; non-letters are dropped.
    static func flag(for isoCode: String) -> String {
        String(isoCode.uppercased().unicodeScalars.compactMap { scalar -> Character? in
            guard scalar.value >= 65, scalar.value <= 90,
                  let s = UnicodeScalar(0x1F1E6 + scalar.value - 65) else { return nil }
            return Character(s)
        })
    }

    private static let table: [String: (lat: Double, lon: Double, name: String)] = [
        "AD": (42.5, 1.6, "Andorra"),
        "AE": (24.0, 54.0, "United Arab Emirates"),
        "AF": (33.9, 67.7, "Afghanistan"),
        "AG": (17.1, -61.8, "Antigua and Barbuda"),
        "AI": (18.2, -63.1, "Anguilla"),
        "AL": (41.2, 20.2, "Albania"),
        "AM": (40.1, 45.0, "Armenia"),
        "AO": (-11.2, 17.9, "Angola"),
        "AQ": (-75.3, 0.0, "Antarctica"),
        "AR": (-38.4, -63.6, "Argentina"),
        "AS": (-14.3, -170.7, "American Samoa"),
        "AT": (47.5, 14.6, "Austria"),
        "AU": (-25.3, 133.8, "Australia"),
        "AW": (12.5, -70.0, "Aruba"),
        "AX": (60.2, 19.9, "Åland Islands"),
        "AZ": (40.1, 47.6, "Azerbaijan"),
        "BA": (43.9, 17.7, "Bosnia and Herzegovina"),
        "BB": (13.2, -59.5, "Barbados"),
        "BD": (23.7, 90.4, "Bangladesh"),
        "BE": (50.5, 4.5, "Belgium"),
        "BF": (12.2, -1.6, "Burkina Faso"),
        "BG": (42.7, 25.5, "Bulgaria"),
        "BH": (26.0, 50.5, "Bahrain"),
        "BI": (-3.4, 29.9, "Burundi"),
        "BJ": (9.3, 2.3, "Benin"),
        "BL": (17.9, -62.8, "Saint Barthélemy"),
        "BM": (32.3, -64.8, "Bermuda"),
        "BN": (4.5, 114.7, "Brunei"),
        "BO": (-16.3, -63.6, "Bolivia"),
        "BQ": (12.2, -68.3, "Caribbean Netherlands"),
        "BR": (-14.2, -51.9, "Brazil"),
        "BS": (25.0, -77.4, "Bahamas"),
        "BT": (27.5, 90.4, "Bhutan"),
        "BV": (-54.4, 3.4, "Bouvet Island"),
        "BW": (-22.3, 24.7, "Botswana"),
        "BY": (53.7, 27.9, "Belarus"),
        "BZ": (17.2, -88.5, "Belize"),
        "CA": (56.1, -106.3, "Canada"),
        "CC": (-12.2, 96.9, "Cocos (Keeling) Islands"),
        "CD": (-4.0, 21.8, "DR Congo"),
        "CF": (6.6, 20.9, "Central African Republic"),
        "CG": (-0.2, 15.8, "Republic of the Congo"),
        "CH": (46.8, 8.2, "Switzerland"),
        "CI": (7.5, -5.5, "Côte d'Ivoire"),
        "CK": (-21.2, -159.8, "Cook Islands"),
        "CL": (-35.7, -71.5, "Chile"),
        "CM": (7.4, 12.4, "Cameroon"),
        "CN": (35.9, 104.2, "China"),
        "CO": (4.6, -74.3, "Colombia"),
        "CR": (9.7, -83.8, "Costa Rica"),
        "CU": (21.5, -77.8, "Cuba"),
        "CV": (16.0, -24.0, "Cabo Verde"),
        "CW": (12.2, -69.0, "Curaçao"),
        "CX": (-10.4, 105.7, "Christmas Island"),
        "CY": (35.1, 33.4, "Cyprus"),
        "CZ": (49.8, 15.5, "Czechia"),
        "DE": (51.2, 10.4, "Germany"),
        "DJ": (11.8, 42.6, "Djibouti"),
        "DK": (56.3, 9.5, "Denmark"),
        "DM": (15.4, -61.4, "Dominica"),
        "DO": (18.7, -70.2, "Dominican Republic"),
        "DZ": (28.0, 1.7, "Algeria"),
        "EC": (-1.8, -78.2, "Ecuador"),
        "EE": (58.6, 25.0, "Estonia"),
        "EG": (26.8, 30.8, "Egypt"),
        "EH": (24.2, -12.9, "Western Sahara"),
        "ER": (15.2, 39.8, "Eritrea"),
        "ES": (40.5, -3.7, "Spain"),
        "ET": (9.1, 40.5, "Ethiopia"),
        "FI": (61.9, 25.7, "Finland"),
        "FJ": (-17.7, 178.1, "Fiji"),
        "FK": (-51.8, -59.5, "Falkland Islands"),
        "FM": (7.4, 150.6, "Micronesia"),
        "FO": (62.0, -6.9, "Faroe Islands"),
        "FR": (46.2, 2.2, "France"),
        "GA": (-0.8, 11.6, "Gabon"),
        "GB": (54.0, -2.5, "United Kingdom"),
        "GD": (12.1, -61.7, "Grenada"),
        "GE": (42.3, 43.4, "Georgia"),
        "GF": (4.0, -53.1, "French Guiana"),
        "GG": (49.5, -2.6, "Guernsey"),
        "GH": (7.9, -1.0, "Ghana"),
        "GI": (36.1, -5.3, "Gibraltar"),
        "GL": (71.7, -42.6, "Greenland"),
        "GM": (13.4, -15.3, "Gambia"),
        "GN": (9.9, -9.7, "Guinea"),
        "GP": (16.3, -61.6, "Guadeloupe"),
        "GQ": (1.7, 10.3, "Equatorial Guinea"),
        "GR": (39.1, 21.8, "Greece"),
        "GS": (-54.4, -36.6, "South Georgia and the South Sandwich Islands"),
        "GT": (15.8, -90.2, "Guatemala"),
        "GU": (13.4, 144.8, "Guam"),
        "GW": (11.8, -15.2, "Guinea-Bissau"),
        "GY": (4.9, -58.9, "Guyana"),
        "HK": (22.3, 114.2, "Hong Kong"),
        "HM": (-53.1, 73.5, "Heard Island and McDonald Islands"),
        "HN": (15.2, -86.2, "Honduras"),
        "HR": (45.1, 15.2, "Croatia"),
        "HT": (19.0, -72.3, "Haiti"),
        "HU": (47.2, 19.5, "Hungary"),
        "ID": (-0.8, 113.9, "Indonesia"),
        "IE": (53.4, -8.2, "Ireland"),
        "IL": (31.0, 34.9, "Israel"),
        "IM": (54.2, -4.5, "Isle of Man"),
        "IN": (20.6, 79.0, "India"),
        "IO": (-6.3, 71.9, "British Indian Ocean Territory"),
        "IQ": (33.2, 43.7, "Iraq"),
        "IR": (32.4, 53.7, "Iran"),
        "IS": (65.0, -19.0, "Iceland"),
        "IT": (41.9, 12.6, "Italy"),
        "JE": (49.2, -2.1, "Jersey"),
        "JM": (18.1, -77.3, "Jamaica"),
        "JO": (30.6, 36.2, "Jordan"),
        "JP": (36.2, 138.3, "Japan"),
        "KE": (0.0, 37.9, "Kenya"),
        "KG": (41.2, 74.8, "Kyrgyzstan"),
        "KH": (12.6, 105.0, "Cambodia"),
        "KI": (1.9, -157.4, "Kiribati"),
        "KM": (-11.9, 43.9, "Comoros"),
        "KN": (17.4, -62.8, "Saint Kitts and Nevis"),
        "KP": (40.3, 127.5, "North Korea"),
        "KR": (35.9, 127.8, "South Korea"),
        "KW": (29.3, 47.5, "Kuwait"),
        "KY": (19.3, -81.3, "Cayman Islands"),
        "KZ": (48.0, 66.9, "Kazakhstan"),
        "LA": (19.9, 102.5, "Laos"),
        "LB": (33.9, 35.9, "Lebanon"),
        "LC": (13.9, -61.0, "Saint Lucia"),
        "LI": (47.2, 9.6, "Liechtenstein"),
        "LK": (7.9, 80.8, "Sri Lanka"),
        "LR": (6.4, -9.4, "Liberia"),
        "LS": (-29.6, 28.2, "Lesotho"),
        "LT": (55.2, 23.9, "Lithuania"),
        "LU": (49.8, 6.1, "Luxembourg"),
        "LV": (56.9, 24.6, "Latvia"),
        "LY": (26.3, 17.2, "Libya"),
        "MA": (31.8, -7.1, "Morocco"),
        "MC": (43.7, 7.4, "Monaco"),
        "MD": (47.4, 28.4, "Moldova"),
        "ME": (42.7, 19.4, "Montenegro"),
        "MF": (18.1, -63.1, "Saint Martin"),
        "MG": (-18.8, 47.0, "Madagascar"),
        "MH": (7.1, 171.2, "Marshall Islands"),
        "MK": (41.6, 21.7, "North Macedonia"),
        "ML": (17.6, -4.0, "Mali"),
        "MM": (21.9, 96.0, "Myanmar"),
        "MN": (46.9, 103.8, "Mongolia"),
        "MO": (22.2, 113.5, "Macao"),
        "MP": (15.1, 145.7, "Northern Mariana Islands"),
        "MQ": (14.6, -61.0, "Martinique"),
        "MR": (21.0, -10.9, "Mauritania"),
        "MS": (16.7, -62.2, "Montserrat"),
        "MT": (35.9, 14.4, "Malta"),
        "MU": (-20.3, 57.6, "Mauritius"),
        "MV": (3.2, 73.2, "Maldives"),
        "MW": (-13.3, 34.3, "Malawi"),
        "MX": (23.6, -102.6, "Mexico"),
        "MY": (4.2, 102.0, "Malaysia"),
        "MZ": (-18.7, 35.5, "Mozambique"),
        "NA": (-23.0, 18.5, "Namibia"),
        "NC": (-20.9, 165.6, "New Caledonia"),
        "NE": (17.6, 8.1, "Niger"),
        "NF": (-29.0, 168.0, "Norfolk Island"),
        "NG": (9.1, 8.7, "Nigeria"),
        "NI": (12.9, -85.2, "Nicaragua"),
        "NL": (52.1, 5.3, "Netherlands"),
        "NO": (60.5, 8.5, "Norway"),
        "NP": (28.4, 84.1, "Nepal"),
        "NR": (-0.5, 166.9, "Nauru"),
        "NU": (-19.1, -169.9, "Niue"),
        "NZ": (-40.9, 174.9, "New Zealand"),
        "OM": (21.5, 55.9, "Oman"),
        "PA": (8.5, -80.8, "Panama"),
        "PE": (-9.2, -75.0, "Peru"),
        "PF": (-17.7, -149.4, "French Polynesia"),
        "PG": (-6.3, 144.0, "Papua New Guinea"),
        "PH": (12.9, 121.8, "Philippines"),
        "PK": (30.4, 69.3, "Pakistan"),
        "PL": (51.9, 19.1, "Poland"),
        "PM": (46.9, -56.3, "Saint Pierre and Miquelon"),
        "PN": (-24.7, -127.4, "Pitcairn Islands"),
        "PR": (18.2, -66.6, "Puerto Rico"),
        "PS": (32.0, 35.2, "Palestine"),
        "PT": (39.4, -8.2, "Portugal"),
        "PW": (7.5, 134.6, "Palau"),
        "PY": (-23.4, -58.4, "Paraguay"),
        "QA": (25.4, 51.2, "Qatar"),
        "RE": (-21.1, 55.5, "Réunion"),
        "RO": (45.9, 25.0, "Romania"),
        "RS": (44.0, 21.0, "Serbia"),
        "RU": (61.5, 105.3, "Russia"),
        "RW": (-1.9, 29.9, "Rwanda"),
        "SA": (23.9, 45.1, "Saudi Arabia"),
        "SB": (-9.6, 160.2, "Solomon Islands"),
        "SC": (-4.7, 55.5, "Seychelles"),
        "SD": (12.9, 30.2, "Sudan"),
        "SE": (60.1, 18.6, "Sweden"),
        "SG": (1.4, 103.8, "Singapore"),
        "SH": (-16.0, -5.7, "Saint Helena"),
        "SI": (46.2, 15.0, "Slovenia"),
        "SJ": (77.6, 16.0, "Svalbard and Jan Mayen"),
        "SK": (48.7, 19.7, "Slovakia"),
        "SL": (8.5, -11.8, "Sierra Leone"),
        "SM": (43.9, 12.5, "San Marino"),
        "SN": (14.5, -14.5, "Senegal"),
        "SO": (5.2, 46.2, "Somalia"),
        "SR": (3.9, -56.0, "Suriname"),
        "SS": (6.9, 31.3, "South Sudan"),
        "ST": (0.2, 6.6, "São Tomé and Príncipe"),
        "SV": (13.8, -88.9, "El Salvador"),
        "SX": (18.0, -63.1, "Sint Maarten"),
        "SY": (34.8, 39.0, "Syria"),
        "SZ": (-26.5, 31.5, "Eswatini"),
        "TC": (21.7, -71.8, "Turks and Caicos Islands"),
        "TD": (15.5, 18.7, "Chad"),
        "TF": (-49.3, 69.3, "French Southern Territories"),
        "TG": (8.6, 0.8, "Togo"),
        "TH": (15.9, 101.0, "Thailand"),
        "TJ": (38.9, 71.3, "Tajikistan"),
        "TK": (-9.0, -171.9, "Tokelau"),
        "TL": (-8.9, 125.7, "Timor-Leste"),
        "TM": (39.0, 59.6, "Turkmenistan"),
        "TN": (33.9, 9.5, "Tunisia"),
        "TO": (-21.2, -175.2, "Tonga"),
        "TR": (39.0, 35.2, "Turkey"),
        "TT": (10.7, -61.2, "Trinidad and Tobago"),
        "TV": (-7.1, 177.6, "Tuvalu"),
        "TW": (23.7, 121.0, "Taiwan"),
        "TZ": (-6.4, 34.9, "Tanzania"),
        "UA": (48.4, 31.2, "Ukraine"),
        "UG": (1.4, 32.3, "Uganda"),
        "UM": (19.3, 166.6, "U.S. Outlying Islands"),
        "US": (39.8, -98.6, "United States"),
        "UY": (-32.5, -55.8, "Uruguay"),
        "UZ": (41.4, 64.6, "Uzbekistan"),
        "VA": (41.9, 12.5, "Vatican City"),
        "VC": (13.0, -61.3, "Saint Vincent and the Grenadines"),
        "VE": (6.4, -66.6, "Venezuela"),
        "VG": (18.4, -64.6, "British Virgin Islands"),
        "VI": (18.3, -64.9, "U.S. Virgin Islands"),
        "VN": (14.1, 108.3, "Vietnam"),
        "VU": (-15.4, 167.0, "Vanuatu"),
        "WF": (-13.8, -177.2, "Wallis and Futuna"),
        "WS": (-13.8, -172.1, "Samoa"),
        "XK": (42.6, 20.9, "Kosovo"),
        "YE": (15.6, 48.5, "Yemen"),
        "YT": (-12.8, 45.2, "Mayotte"),
        "ZA": (-30.6, 22.9, "South Africa"),
        "ZM": (-13.1, 27.8, "Zambia"),
        "ZW": (-19.0, 29.2, "Zimbabwe"),
    ]
}

// MARK: - Endpoint → location resolution

/// A map pin for one endpoint. Fields stay nil until DNS/GeoIP resolve (or when
/// the DB is missing) — the map shows only what it knows.
struct EndpointLocation: Equatable, Sendable {
    var endpoint: Endpoint
    var ip: String?
    var countryCode: String?
    var countryName: String?
    var lat: Double?
    var lon: Double?
}

/// Turns profile endpoints into pin locations. Cached hosts return immediately;
/// misses kick off DNS → GeoIP in the background and the observable cache
/// mutation re-renders whichever view asked. Cache persists across launches
/// (UserDefaults, 7-day TTL) so the map is warm at startup.
@Observable
final class EndpointLocator {

    private struct HostInfo: Codable, Equatable {
        var ip: String?
        var countryCode: String?
        var timestamp: Double       // epoch seconds of resolution
    }

    private static let cacheKey = "geoip.hostCache"
    private static let ttl: TimeInterval = 7 * 24 * 3600

    private var cache: [String: HostInfo]
    @ObservationIgnored private var inFlight: Set<String> = []

    init() {
        if let data = UserDefaults.standard.data(forKey: Self.cacheKey),
           let stored = try? JSONDecoder().decode([String: HostInfo].self, from: data) {
            cache = stored
        } else {
            cache = [:]
        }
    }

    func locations(for endpoints: [Endpoint]) -> [EndpointLocation] {
        let now = Date().timeIntervalSince1970
        return endpoints.map { endpoint in
            var location = EndpointLocation(endpoint: endpoint)
            if let info = cache[endpoint.host] {
                location.ip = info.ip
                if let code = info.countryCode {
                    location.countryCode = code
                    location.countryName = CountryCentroids.name(for: code)
                    if let c = CountryCentroids.coordinate(for: code) {
                        location.lat = c.lat
                        location.lon = c.lon
                    }
                }
                // Stale entries still pin immediately; a re-resolve refreshes them.
                if now - info.timestamp > Self.ttl { resolveInBackground(host: endpoint.host) }
            } else {
                resolveInBackground(host: endpoint.host)
            }
            return location
        }
    }

    private func resolveInBackground(host: String) {
        guard inFlight.insert(host).inserted else { return }
        Task { [weak self] in
            let ip = await Self.resolve(host: host)
            guard let self else { return }
            let code = ip.flatMap { GeoIP.shared?.countryCode(for: $0) }
            cache[host] = HostInfo(ip: ip, countryCode: code,
                                   timestamp: Date().timeIntervalSince1970)
            inFlight.remove(host)
            persist()
        }
    }

    private func persist() {
        guard let data = try? JSONEncoder().encode(cache) else { return }
        UserDefaults.standard.set(data, forKey: Self.cacheKey)
    }

    /// First numeric address for `host` (A preferred over AAAA). getaddrinfo
    /// blocks, so it runs on a detached task off the main actor.
    nonisolated private static func resolve(host: String) async -> String? {
        await Task.detached(priority: .utility) { () -> String? in
            var hints = addrinfo()
            hints.ai_family = AF_UNSPEC
            hints.ai_socktype = SOCK_STREAM
            var list: UnsafeMutablePointer<addrinfo>?
            guard getaddrinfo(host, nil, &hints, &list) == 0, let head = list else { return nil }
            defer { freeaddrinfo(head) }

            var firstV6: String?
            var node: UnsafeMutablePointer<addrinfo>? = head
            while let ai = node?.pointee {
                var buf = [CChar](repeating: 0, count: Int(NI_MAXHOST))
                if getnameinfo(ai.ai_addr, ai.ai_addrlen,
                               &buf, socklen_t(buf.count), nil, 0, NI_NUMERICHOST) == 0 {
                    let text = String(decoding: buf.prefix { $0 != 0 }.map { UInt8(bitPattern: $0) },
                                      as: UTF8.self)
                    if ai.ai_family == AF_INET { return text }
                    if firstV6 == nil { firstV6 = text }
                }
                node = ai.ai_next
            }
            return firstV6
        }.value
    }
}
