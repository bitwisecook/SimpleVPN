// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
//  WorldMapView.swift
//  The live topology map: home → connected VPN gateway(s) → internet egress, drawn
//  with great-circle arcs. Reads home/egress from PublicIPMonitor and each VPN's
//  gateway from the app-wide ReachabilityMonitor stats, so it reflects every
//  connected VPN at once. Hover any dot for its IPs/networks.
//

import SwiftUI

struct WorldMapView: View {
    @Bindable var vpn: VPNController
    @Environment(PublicIPMonitor.self) private var publicIP
    @Environment(ReachabilityMonitor.self) private var reach: ReachabilityMonitor?
    @State private var location = LocationAuthority.shared

    /// Real device position when the user has opted into location; nil otherwise, and
    /// the map falls back to the public-address country centroid.
    private var devicePlacement: (lat: Double, lon: Double, place: String?)? {
        guard let c = location.coordinate else { return nil }
        return (c.latitude, c.longitude, location.ssid.map { "On \u{201C}\($0)\u{201D}" })
    }

    private var model: WorldMapModel.Result {
        WorldMapModel.build(
            publicIP: publicIP,
            stats: reach?.latestStats ?? [:],
            device: devicePlacement,
            name: { id in vpn.profiles.first { $0.id == id }?.name ?? "VPN" })
    }

    var body: some View {
        let m = model
        let hasHops = m.pins.contains { if case .endpoint = $0.kind { return true }; return false }
        if hasHops {
            VStack(alignment: .leading, spacing: 6) {
                // Fill the container width (the leading VStack + the map's own
                // aspect-ratio would otherwise let it size to a narrower ideal);
                // height then follows the 2:1 ratio.
                MercatorMapView(pins: m.pins, connections: m.connections)
                    .frame(maxWidth: .infinity)
                Text("Home → VPN → internet, at country level. Hover a point for its addresses.")
                    .font(.caption).foregroundStyle(.secondary)
            }
            .frame(maxWidth: .infinity)
        }
    }
}
