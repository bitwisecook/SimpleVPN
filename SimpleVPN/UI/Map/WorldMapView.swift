// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
//  WorldMapView.swift
//  The live topology map: home → connected VPN gateway(s) → internet egress, drawn
//  with great-circle arcs. Reads home/egress from PublicIPMonitor and each VPN's
//  gateway from the app-wide ReachabilityMonitor stats, so it reflects every
//  connected VPN at once. Hover any dot for its IPs/networks.
//
//  A live tunnel's gateway address is often useless for placing it (a corporate
//  VPN hands out RFC1918 space), so this view also feeds the model what the app
//  already knows about the connected endpoint. Configuration is a last-resort
//  locator only while the transport has not reported its active address. All of
//  it is cached or user-authored: drawing the map never asks the network anything.
//

import SwiftUI

struct WorldMapView: View {
    @Bindable var vpn: VPNController
    @Environment(PublicIPMonitor.self) private var publicIP
    @Environment(ReachabilityMonitor.self) private var reach: ReachabilityMonitor?
    @Environment(EndpointLocator.self) private var locator: EndpointLocator?
    // Optional: the menu-bar scene has no evaluator, and VPNProbeTarget.resolve
    // degrades to the overrides / the manager's own server address without one.
    @Environment(ProfileEvaluator.self) private var evaluator: ProfileEvaluator?
    @State private var location = LocationAuthority.shared

    /// Real device position when the user has opted into location; nil otherwise, and
    /// the map falls back to the public-address country centroid.
    private var devicePlacement: (lat: Double, lon: Double, place: String?)? {
        guard let c = location.coordinate else { return nil }
        return (c.latitude, c.longitude, location.ssid.map { "On \u{201C}\($0)\u{201D}" })
    }

    /// What we know about each connected VPN's endpoint, keyed by profile id.
    /// The transport-reported address wins; configured data exists only as an
    /// honest fallback before a tunnel has published its first live sample.
    /// Only already-cached/derived data — no lookups start here.
    private func hints(for stats: [String: TunnelStats]) -> [String: WorldMapModel.GatewayHint] {
        var out: [String: WorldMapModel.GatewayHint] = [:]
        for (id, sample) in stats {
            guard let profile = vpn.profiles.first(where: { $0.id == id }) else { continue }
            // The configured target is useful only until the transport reports
            // where this session landed. Once it has, the globe must follow the
            // connected endpoint rather than the selected server row.
            let target = VPNProbeTarget.resolve(profile: profile, vpn: vpn, evaluator: evaluator)
            let activeHost = sample.activeServerAddress
            let host = activeHost.isEmpty ? target.host : activeHost
            guard !host.isEmpty else { continue }
            var hint = WorldMapModel.GatewayHint(host: host)
            let endpoints = vpn.endpoints(for: id)
            let activePort = sample.serverPort.flatMap(Int.init)
            // A user-authored country only applies when it describes the live
            // endpoint. Do not transplant it to a fail-over server merely because
            // that server was selected before the tunnel connected.
            hint.countryOverride = (endpoints.first { endpoint in
                endpoint.host.caseInsensitiveCompare(host) == .orderedSame
                    && (activePort.map { endpoint.port == $0 } ?? true)
            } ?? endpoints.first { endpoint in
                endpoint.host.caseInsensitiveCompare(host) == .orderedSame
            })?.country
            if let locator {
                let everywhere = locator.cachedEverywhere(host: host)
                let here = locator.cached(host: host)
                hint.resolvedCountryHere = here?.countryCode
                hint.resolvedCountryElsewhere = everywhere
                    .first { $0.countryCode != nil && $0 != here }?.countryCode
                var seen = Set<String>()
                hint.addresses = everywhere.flatMap(\.allAddresses).filter { seen.insert($0).inserted }
            }
            out[id] = hint
        }
        return out
    }

    private var model: WorldMapModel.Result {
        let stats = reach?.latestStats ?? [:]
        return WorldMapModel.build(
            publicIP: publicIP,
            stats: stats,
            device: devicePlacement,
            hints: hints(for: stats),
            defaultOwner: vpn.routes.displayedGatewayOwner,
            name: { id in vpn.profiles.first { $0.id == id }?.name ?? "VPN" })
    }

    /// The caption must stay true about how each gateway got where it is: a pin
    /// parked beside you, and one placed at country level from the server's own
    /// configuration, are different claims and neither is an exact location.
    private func caption(_ m: WorldMapModel.Result) -> String {
        var parts = ["Home → VPN → internet, at country level."]
        if m.hasUnlocatableTunnel {
            parts.append("A VPN server with no public location is pinned beside you.")
        } else if m.hasApproximateTunnel {
            parts.append("A VPN server with no public address is shown near the country it's set to.")
            // The line above already explains a pin sitting beside you, so the
            // tether note would only repeat it.
        }
        if m.hasCoincidentTunnel && !m.hasUnlocatableTunnel {
            parts.append("A VPN that lands where you already are is drawn just beside you.")
        }
        parts.append("Hover a point for its addresses.")
        return parts.joined(separator: " ")
    }

    var body: some View {
        let m = model
        let hasHops = m.pins.contains { if case .endpoint = $0.kind { return true }; return false }
        if hasHops {
            VStack(alignment: .leading, spacing: 6) {
                // A draggable Metal globe keeps the route on a real sphere rather
                // than flattening a great-circle into a Mercator approximation.
                MetalGlobeMapView(pins: m.pins, connections: m.connections)
                    .frame(maxWidth: .infinity)
                Text(caption(m))
                    .font(.caption).foregroundStyle(.secondary)
            }
            .frame(maxWidth: .infinity)
        }
    }
}
