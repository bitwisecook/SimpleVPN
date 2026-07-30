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

import Foundation

@MainActor
enum WorldMapModel {
    struct Result { var pins: [MapPin]; var connections: [MapConnection] }

    /// `device` is the real position from CoreLocation, present only when the user has
    /// opted into location (Settings ▸ General ▸ Privacy). When absent the home pin
    /// falls back to the country centroid geolocated from the public address — which can
    /// be a thousand kilometres out, hence the setting.
    static func build(publicIP: PublicIPMonitor,
                      stats: [String: TunnelStats],
                      device: (lat: Double, lon: Double, place: String?)? = nil,
                      name: (String) -> String) -> Result {
        var pins: [MapPin] = []
        var conns: [MapConnection] = []

        // Home — where we appear from with no VPN.
        if let device {
            pins.append(MapPin(id: "home", kind: .user, lat: device.lat, lon: device.lon,
                               title: "This Mac",
                               subtitle: device.place ?? "Your location"))
        } else if let hlat = publicIP.homeLat, let hlon = publicIP.homeLon {
            pins.append(MapPin(id: "home", kind: .user, lat: hlat, lon: hlon,
                               title: "This Mac",
                               subtitle: "Your network · \(publicIP.homeCountryName ?? "unknown location")"))
        }

        // A hop per connected VPN whose gateway we can place. Iterate in a stable
        // (id-sorted) order so the map — and the egress attribution below — doesn't
        // flip arbitrarily between rebuilds (Dictionary has no defined order).
        // Track which VPNs actually got a pin, so egress can only be attributed to
        // a pin that exists (a country that resolved but has no centroid is skipped
        // above and must not be referenced by an arc).
        var placedVPN: [(id: String, cc: String)] = []
        for (id, s) in stats.sorted(by: { $0.key < $1.key }) {
            let ip = s.serverIP ?? ""
            guard !ip.isEmpty,
                  let cc = GeoIP.shared?.countryCode(for: ip),
                  let c = CountryCentroids.coordinate(for: cc) else { continue }
            var detail = "Gateway \(ip)"
            if !s.tunnelIPv4.isEmpty { detail += " · tunnel \(s.tunnelIPv4)" }
            if let d = s.dnsServers.first { detail += " · DNS \(d)" }
            pins.append(MapPin(id: "vpn.\(id)", kind: .endpoint(selected: true),
                               lat: c.lat, lon: c.lon,
                               title: name(id), subtitle: detail))
            placedVPN.append((id, cc))
            if pins.contains(where: { $0.id == "home" }) {
                conns.append(MapConnection(from: "home", to: "vpn.\(id)", strong: true))
            }
        }

        // Egress — where traffic reaches the internet now. Only distinct when it's
        // in a different country than home (country-level data); otherwise egress
        // effectively coincides with home (split tunnel / no full tunnel).
        if let elat = publicIP.lat, let elon = publicIP.lon,
           publicIP.countryCode != nil, publicIP.countryCode != publicIP.homeCountryCode {
            let egressIP = publicIP.publicIPv4 ?? publicIP.publicIPv6 ?? ""
            pins.append(MapPin(id: "egress", kind: .egress, lat: elat, lon: elon,
                               title: "Internet egress",
                               subtitle: "Appears from \(egressIP.isEmpty ? "" : egressIP + " · ")\(publicIP.countryName ?? "")"))
            // Attribute egress to the VPN whose gateway is in the egress country
            // (best-effort with country-level data) — but only among VPNs that
            // actually have a pin, and deterministically (first by sorted id) so it
            // doesn't reassign at random when several sit in the same country.
            // Otherwise egress exits via none of them → a dashed home→egress link.
            if let match = placedVPN.first(where: { $0.cc == publicIP.countryCode }) {
                conns.append(MapConnection(from: "vpn.\(match.id)", to: "egress", strong: true))
            } else {
                conns.append(MapConnection(from: "home", to: "egress", strong: false))
            }
        }

        return Result(pins: pins, connections: conns)
    }
}
