// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
//  WorldMapModel.swift
//  Builds the live world-map topology: where the Mac appears from *before* any VPN
//  (home), each connected VPN's gateway (a hop), and where traffic reaches the
//  internet now (egress) — joined by great-circle arcs. Handles the real shapes:
//  one VPN, several in parallel (spokes from home), a chain, and split tunnels
//  where the egress goes through none of the VPNs (a dashed home→egress link).
//  Locations are country-level (the bundled DB-IP data); overlapping pins in the
//  same country are expected. Every pin carries the IPs/networks in its subtitle
//  for the hover tooltip.
//
//  A connected tunnel is ALWAYS represented, even when its gateway can't be put
//  on the globe (a corporate/lab VPN on RFC1918 space, a GeoIP miss, or a sample
//  that hasn't published the resolved address yet). Such a tunnel is pinned
//  beside home with a screen-space offset — never at an invented country — and
//  its link is still a live tunnel link. Requiring geolocation to draw the tunnel
//  was the bug: those VPNs could only ever render as the dashed bypass line.
//
//  Where a gateway goes is decided by `locateGateway` (see the ladder there).
//  Only the address the tunnel is actually on gives an EXACT position; the rest
//  of the ladder reads the endpoint's own configuration and lands on a country
//  centroid, which the pin shows as approximate. That distinction is the whole
//  ethic of this file: placing a concentrator in the country its OWN
//  configuration names — the country the user set on it, or where its hostname
//  resolves from — is honest and useful; picking a country because the map would
//  look better with an arc on it is a lie, and we draw the placeholder instead.
//

import Foundation
import CoreGraphics
import Darwin

// MARK: - Address scope

/// Whether an address is one that could ever appear in a public geolocation
/// database. A VPN gateway on 10/8 or 192.168/16 (corporate labs, home routers,
/// nested tunnels) has no public location, so a GeoIP miss there is the expected
/// answer rather than a lookup failure — and the map has to say "not public"
/// instead of guessing a country.
enum IPAddressScope {

    /// True for RFC1918 / CGNAT / loopback / link-local / multicast / reserved /
    /// documentation space in either family.
    ///
    /// Non-numeric input (a hostname, an empty string) is deliberately **not**
    /// private: it is merely unresolved, which is a different message to the user.
    static func isPrivateOrReserved(_ address: String) -> Bool {
        // "fe80::1%en0" — inet_pton rejects the zone id, so drop it first.
        let text = address.split(separator: "%", maxSplits: 1).first.map(String.init) ?? address
        guard !text.isEmpty else { return false }

        var v4 = in_addr()
        if inet_pton(AF_INET, text, &v4) == 1 {
            return isPrivateV4(withUnsafeBytes(of: v4) { Array($0) })
        }
        var v6 = in6_addr()
        if inet_pton(AF_INET6, text, &v6) == 1 {
            let b = withUnsafeBytes(of: v6) { Array($0) }
            // ::ffff:a.b.c.d — an IPv4 address wearing a v6 hat; judge the v4.
            if b.prefix(10).allSatisfy({ $0 == 0 }), b[10] == 0xFF, b[11] == 0xFF {
                return isPrivateV4(Array(b[12...]))
            }
            return isPrivateV6(b)
        }
        return false
    }

    private static func isPrivateV4(_ b: [UInt8]) -> Bool {
        guard b.count == 4 else { return false }
        switch b[0] {
        case 0: return true                             // 0.0.0.0/8 "this network"
        case 10: return true                            // RFC1918
        case 100: return b[1] & 0xC0 == 64              // 100.64.0.0/10 CGNAT
        case 127: return true                           // loopback
        case 169: return b[1] == 254                    // 169.254.0.0/16 link-local
        case 172: return b[1] & 0xF0 == 16              // 172.16.0.0/12
        case 192:
            if b[1] == 168 { return true }              // 192.168.0.0/16
            // 192.0.0.0/24 IETF protocol assignments, 192.0.2.0/24 TEST-NET-1.
            return b[1] == 0 && (b[2] == 0 || b[2] == 2)
        case 198:
            // 198.18.0.0/15 benchmarking, 198.51.100.0/24 TEST-NET-2.
            return b[1] & 0xFE == 18 || (b[1] == 51 && b[2] == 100)
        case 203: return b[1] == 0 && b[2] == 113       // 203.0.113.0/24 TEST-NET-3
        case 224...255: return true                     // multicast, reserved, broadcast
        default: return false
        }
    }

    private static func isPrivateV6(_ b: [UInt8]) -> Bool {
        guard b.count == 16 else { return false }
        if b.allSatisfy({ $0 == 0 }) { return true }                            // ::
        if b.prefix(15).allSatisfy({ $0 == 0 }), b[15] == 1 { return true }     // ::1
        if b[0] & 0xFE == 0xFC { return true }                                  // fc00::/7 ULA
        if b[0] == 0xFE, b[1] & 0xC0 == 0x80 { return true }                    // fe80::/10
        if b[0] == 0xFF { return true }                                         // ff00::/8 multicast
        // 2001:db8::/32 documentation.
        return b[0] == 0x20 && b[1] == 0x01 && b[2] == 0x0D && b[3] == 0xB8
    }
}

// MARK: - Topology

@MainActor
enum WorldMapModel {

    /// A point the map can actually draw.
    struct GeoPlace: Equatable {
        var countryCode: String
        var lat: Double
        var lon: Double
    }

    /// Everything the map needs from `PublicIPMonitor`, as a plain value, so the
    /// builder is a pure function of its inputs (and the tests need no network).
    struct Vantage: Equatable {
        var homeLat: Double?
        var homeLon: Double?
        var homeCountryCode: String?
        var homeCountryName: String?
        var egressLat: Double?
        var egressLon: Double?
        var egressCountryCode: String?
        var egressCountryName: String?
        var egressIP: String?

        init(homeLat: Double? = nil, homeLon: Double? = nil,
             homeCountryCode: String? = nil, homeCountryName: String? = nil,
             egressLat: Double? = nil, egressLon: Double? = nil,
             egressCountryCode: String? = nil, egressCountryName: String? = nil,
             egressIP: String? = nil) {
            self.homeLat = homeLat; self.homeLon = homeLon
            self.homeCountryCode = homeCountryCode; self.homeCountryName = homeCountryName
            self.egressLat = egressLat; self.egressLon = egressLon
            self.egressCountryCode = egressCountryCode; self.egressCountryName = egressCountryName
            self.egressIP = egressIP
        }

        init(_ monitor: PublicIPMonitor) {
            self.init(homeLat: monitor.homeLat, homeLon: monitor.homeLon,
                      homeCountryCode: monitor.homeCountryCode,
                      homeCountryName: monitor.homeCountryName,
                      egressLat: monitor.lat, egressLon: monitor.lon,
                      egressCountryCode: monitor.countryCode,
                      egressCountryName: monitor.countryName,
                      egressIP: monitor.publicIPv4 ?? monitor.publicIPv6)
        }
    }

    /// What the app already knows about where a connected VPN's concentrator IS,
    /// apart from the address the tunnel happens to be talking to. All of it is
    /// cached or user-authored — building this never asks the network anything.
    /// Plain values, so `build` stays a pure function of its inputs.
    struct GatewayHint: Equatable {
        /// The host a connect would dial for this VPN (usually a name).
        var host: String = ""
        /// ISO country the user set on that endpoint by clicking its flag. Their
        /// correction beats every database.
        var countryOverride: String?
        /// Country of the address `host` resolves to on the network we are on now.
        var resolvedCountryHere: String?
        /// The same question as answered on some other network this Mac has been
        /// on. A split-horizon name answers with an inside address indoors; the
        /// concentrator did not move when you walked through the door, so for
        /// DISPLAY the other network's answer is still true.
        var resolvedCountryElsewhere: String?
        /// Every address remembered for `host`, on any network, best answer first.
        var addresses: [String] = []

        init(host: String = "", countryOverride: String? = nil,
             resolvedCountryHere: String? = nil, resolvedCountryElsewhere: String? = nil,
             addresses: [String] = []) {
            self.host = host
            self.countryOverride = countryOverride
            self.resolvedCountryHere = resolvedCountryHere
            self.resolvedCountryElsewhere = resolvedCountryElsewhere
            self.addresses = addresses
        }
    }

    /// Which rung of the ladder put a gateway pin where it is. Only `liveAddress`
    /// is a real geolocation of the address in use; everything else is a country
    /// centroid derived from the endpoint's own configuration, and the pin says so.
    enum GatewaySource: Equatable {
        case liveAddress            // the address the tunnel is on
        case countryOverride        // the country the user set on this endpoint
        case resolvedHere           // this network's answer for the configured name
        case resolvedElsewhere      // another network's remembered answer for it
        case configuredAddress      // a public address remembered for that name

        var isExact: Bool { self == .liveAddress }
    }

    struct GatewayFix: Equatable {
        var place: GeoPlace
        var source: GatewaySource
    }

    struct Result: Equatable {
        var pins: [MapPin]
        var connections: [MapConnection]
        /// At least one connected tunnel has no place on the globe. The caption has
        /// to say so, otherwise the pin sitting beside home reads as a real location.
        var hasUnlocatableTunnel: Bool = false
        /// At least one gateway is placed at country level from its own
        /// configuration rather than from the address in use.
        var hasApproximateTunnel: Bool = false
        /// At least one connected tunnel landed on top of home (nothing to place
        /// it, or a country centroid that IS home's), so the home→VPN arc would be
        /// too short to see. Those pins are tethered beside the client pin instead
        /// — a live VPN must never look like the client dot merely moved.
        var hasCoincidentTunnel: Bool = false
    }

    /// GeoIP + centroid, the real lookup. Injected as a parameter below so tests
    /// don't depend on the bundled database being present.
    static func geoIPPlace(_ ip: String) -> GeoPlace? {
        guard let cc = GeoIP.shared?.countryCode(for: ip),
              let c = CountryCentroids.coordinate(for: cc) else { return nil }
        return GeoPlace(countryCode: cc, lat: c.lat, lon: c.lon)
    }

    /// A country's centroid as a place. Country-level is the only fidelity the
    /// whole map has, so an approximate pin is no coarser than an exact one — it
    /// is merely derived from configuration rather than from the live address.
    static func centroidPlace(_ isoCode: String) -> GeoPlace? {
        guard let c = CountryCentroids.coordinate(for: isoCode) else { return nil }
        return GeoPlace(countryCode: isoCode.uppercased(), lat: c.lat, lon: c.lon)
    }

    /// Where to draw a connected VPN's gateway. Best answer first:
    ///  a. the address the tunnel is actually on, geolocated — the only EXACT
    ///     answer, and unavailable on a split-horizon corporate VPN whose gateway
    ///     address is RFC1918 space;
    ///  b. the country the user set on that endpoint — they know, we guessed;
    ///  c. where the configured hostname resolves from: this network's answer if
    ///     it geolocated, else one remembered from another network;
    ///  d. any public address remembered for that hostname (or the host itself,
    ///     when the profile dials an IP literal).
    /// Nothing → nil, and the caller parks a placeholder beside home. (b)–(d) are
    /// approximate: honest, because every one of them is a country the endpoint's
    /// own configuration names.
    static func locateGateway(serverIP: String, hint: GatewayHint,
                              locate: @MainActor (String) -> GeoPlace?) -> GatewayFix? {
        let ip = serverIP.trimmingCharacters(in: .whitespaces)
        // A private gateway address is not a lookup failure — it can never have a
        // public location — so it must fall through to the configuration rungs
        // rather than end the ladder.
        if !ip.isEmpty, !IPAddressScope.isPrivateOrReserved(ip), let place = locate(ip) {
            return GatewayFix(place: place, source: .liveAddress)
        }
        if let cc = hint.countryOverride, let place = centroidPlace(cc) {
            return GatewayFix(place: place, source: .countryOverride)
        }
        if let cc = hint.resolvedCountryHere, let place = centroidPlace(cc) {
            return GatewayFix(place: place, source: .resolvedHere)
        }
        if let cc = hint.resolvedCountryElsewhere, let place = centroidPlace(cc) {
            return GatewayFix(place: place, source: .resolvedElsewhere)
        }
        for address in hint.addresses + [hint.host]
        where !address.isEmpty && !IPAddressScope.isPrivateOrReserved(address) {
            if let place = locate(address) {
                return GatewayFix(place: place, source: .configuredAddress)
            }
        }
        return nil
    }

    /// Below this, two pins are the same dot: the map is country-level, so an arc
    /// this short is a smudge under the markers rather than a line between them.
    static let coincidentKM: Double = 150

    static func coincide(_ a: (lat: Double, lon: Double), _ b: (lat: Double, lon: Double)) -> Bool {
        EndpointRanking.distanceKM(GeoPoint(lat: a.lat, lon: a.lon),
                                   GeoPoint(lat: b.lat, lon: b.lon)) < coincidentKM
    }

    /// `device` is the real position from CoreLocation, present only when the user has
    /// opted into location (Settings ▸ General ▸ Privacy). When absent the home pin
    /// falls back to the country centroid geolocated from the public address — which can
    /// be a thousand kilometres out, hence the setting.
    static func build(publicIP: PublicIPMonitor,
                      stats: [String: TunnelStats],
                      device: (lat: Double, lon: Double, place: String?)? = nil,
                      hints: [String: GatewayHint] = [:],
                      name: (String) -> String) -> Result {
        build(vantage: Vantage(publicIP), stats: stats, device: device, hints: hints, name: name)
    }

    /// `hints` carries what the app knows about each connected profile's
    /// CONFIGURED concentrator (keyed by profile id) — see `GatewayHint`. It stays
    /// a parameter rather than a lookup so the builder never reaches into a
    /// controller, and the tests can drive every rung of the ladder by hand.
    static func build(vantage: Vantage,
                      stats: [String: TunnelStats],
                      device: (lat: Double, lon: Double, place: String?)? = nil,
                      hints: [String: GatewayHint] = [:],
                      locate: @MainActor (String) -> GeoPlace? = WorldMapModel.geoIPPlace,
                      name: (String) -> String) -> Result {
        var pins: [MapPin] = []
        var conns: [MapConnection] = []

        // Home — where we appear from with no VPN.
        var homeCoord: (lat: Double, lon: Double)?
        if let device {
            pins.append(MapPin(id: "home", kind: .user, lat: device.lat, lon: device.lon,
                               title: "This Mac",
                               subtitle: device.place ?? "Your location"))
            homeCoord = (device.lat, device.lon)
        } else if let hlat = vantage.homeLat, let hlon = vantage.homeLon {
            pins.append(MapPin(id: "home", kind: .user, lat: hlat, lon: hlon,
                               title: "This Mac",
                               subtitle: "Your network · \(vantage.homeCountryName ?? "unknown location")"))
            homeCoord = (hlat, hlon)
        }

        // A node per connected VPN. `stats` only ever holds currently-connected
        // profiles (ReachabilityMonitor prunes it each second), so an entry here is
        // a live tunnel and must be drawn as one.
        //
        // Iterate in a stable (id-sorted) order so the map — and the egress
        // attribution below — doesn't flip arbitrarily between rebuilds (Dictionary
        // has no defined order).
        var placed: [(id: String, cc: String, exact: Bool)] = []  // gateways we could put on the globe
        var unlocatable: [String] = []                  // live tunnels with no location at all
        var approximate = false
        var tethered = 0                                // satellite slots already handed out
        for (id, s) in stats.sorted(by: { $0.key < $1.key }) {
            let ip = (s.serverIP ?? "").trimmingCharacters(in: .whitespaces)
            let hint = hints[id] ?? GatewayHint()
            if let fix = locateGateway(serverIP: ip, hint: hint, locate: locate) {
                var node = MapPin(id: "vpn.\(id)", kind: .endpoint(selected: true),
                                  lat: fix.place.lat, lon: fix.place.lon,
                                  title: name(id),
                                  subtitle: gatewayDetail(ip: ip, hint: hint, stats: s, fix: fix),
                                  placement: fix.source.isExact ? .exact : .approximate)
                // Same spot as home — a VPN whose concentrator really is next door,
                // or an approximate pin that landed on home's own country centroid.
                // The arc would be invisible, so separate the two in screen space
                // and let the pins carry the "connected" message instead.
                if let home = homeCoord, coincide(home, (fix.place.lat, fix.place.lon)) {
                    node.tetheredTo = "home"
                    node.screenOffset = satelliteOffset(index: tethered)
                    tethered += 1
                }
                pins.append(node)
                placed.append((id, fix.place.countryCode, fix.source.isExact))
                approximate = approximate || !fix.source.isExact
            } else {
                // Nothing anywhere can say where this is. Pin it *beside* home in
                // screen space (points, not degrees, so zooming can't turn the
                // offset into a claim about where it is) rather than invent a
                // country for it. With no home pin there is nothing to anchor to,
                // so the tunnel simply isn't drawable.
                guard let home = homeCoord else { continue }
                pins.append(MapPin(id: "vpn.\(id)", kind: .endpoint(selected: true),
                                   lat: home.lat, lon: home.lon,
                                   title: name(id),
                                   subtitle: gatewayDetail(ip: ip, hint: hint, stats: s, fix: nil),
                                   placement: .placeholder,
                                   tetheredTo: "home",
                                   screenOffset: satelliteOffset(index: tethered)))
                tethered += 1
                unlocatable.append(id)
            }
            if homeCoord != nil {
                conns.append(MapConnection(from: "home", to: "vpn.\(id)", kind: .tunnel))
            }
        }

        // Egress — where traffic reaches the internet now. Only distinct when it's
        // in a different country than home (country-level data); otherwise egress
        // effectively coincides with home (split tunnel / no full tunnel).
        if let elat = vantage.egressLat, let elon = vantage.egressLon,
           let ecc = vantage.egressCountryCode, ecc != vantage.homeCountryCode {
            let egressIP = vantage.egressIP ?? ""
            pins.append(MapPin(id: "egress", kind: .egress, lat: elat, lon: elon,
                               title: "Internet egress",
                               subtitle: "Appears from \(egressIP.isEmpty ? "" : egressIP + " · ")\(vantage.egressCountryName ?? "")"))
            // Attribution, in order of confidence:
            //  1. a gateway sitting in the egress country (best-effort with
            //     country-level data), preferring one placed from its live address
            //     over one placed from configuration, and deterministically the
            //     first by sorted id so it doesn't reassign at random when several
            //     share a country;
            //  2. otherwise, exactly one tunnel we couldn't place — egress moved off
            //     home's country and that tunnel is the only thing that could have
            //     moved it, so it gets the credit;
            //  3. otherwise it exits via none of them (or the choice is ambiguous) →
            //     a dashed home→egress bypass.
            let inCountry = placed.first { $0.cc == ecc && $0.exact } ?? placed.first { $0.cc == ecc }
            if let match = inCountry {
                conns.append(MapConnection(from: "vpn.\(match.id)", to: "egress", kind: .tunnel))
            } else if unlocatable.count == 1 {
                conns.append(MapConnection(from: "vpn.\(unlocatable[0])", to: "egress", kind: .tunnel))
            } else {
                conns.append(MapConnection(from: "home", to: "egress", kind: .bypass))
            }
        }

        return Result(pins: pins, connections: conns,
                      hasUnlocatableTunnel: !unlocatable.isEmpty,
                      hasApproximateTunnel: approximate,
                      hasCoincidentTunnel: tethered > 0)
    }

    /// Tooltip text for a gateway pin. It has to be straight about how the pin got
    /// where it is: "roughly here, because that's the country this server is
    /// configured for" and "we don't know, so it's parked beside you" are very
    /// different claims, and neither may be dressed up as an exact location.
    private static func gatewayDetail(ip: String, hint: GatewayHint,
                                      stats s: TunnelStats, fix: GatewayFix?) -> String {
        var parts: [String] = []
        if !ip.isEmpty {
            parts.append("Gateway \(ip)")
        } else if !hint.host.isEmpty {
            parts.append("Gateway \(hint.host)")
        } else if !s.serverEndpoint.isEmpty {
            parts.append("Gateway \(s.serverEndpoint)")
        } else {
            parts.append("Connected")
        }
        let country = fix.map { CountryCentroids.name(for: $0.place.countryCode) ?? $0.place.countryCode }
        switch fix?.source {
        case .none:
            if !ip.isEmpty {
                parts.append(IPAddressScope.isPrivateOrReserved(ip)
                             ? "private network, location not public"
                             : "location not public")
            } else if !hint.host.isEmpty || !s.serverEndpoint.isEmpty {
                parts.append("resolving address")
            } else {
                parts.append("gateway not reported yet")
            }
        case .liveAddress:
            break
        case .countryOverride:
            parts.append("shown near \(country ?? "") — the country you chose for this server")
        case .resolvedHere, .resolvedElsewhere, .configuredAddress:
            parts.append("shown near \(country ?? "") (approximate)")
        }
        if !s.tunnelIPv4.isEmpty { parts.append("tunnel \(s.tunnelIPv4)") }
        if let d = s.dnsServers.first { parts.append("DNS \(d)") }
        return parts.joined(separator: " · ")
    }

    /// Screen-space slots around the home marker for gateways that would otherwise
    /// sit underneath it. Points, not degrees: the offset has to survive zooming
    /// without ever implying a coordinate, and several such tunnels must not stack
    /// up. The radius is deliberately wider than the client marker's rings, so the
    /// satellite plus its connector reads as a second place, not as a fatter dot.
    static func satelliteOffset(index: Int) -> CGSize {
        let slots: [CGSize] = [
            CGSize(width: 0, height: -44), CGSize(width: 40, height: -24),
            CGSize(width: -40, height: -24), CGSize(width: 40, height: 24),
            CGSize(width: -40, height: 24), CGSize(width: 0, height: 44),
        ]
        return slots[abs(index) % slots.count]
    }
}
