// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
//  EndpointSection.swift
//  Endpoint choice for a VPN: the dropdown (canonical control, full list, the
//  accessibility path) plus the Mercator map with a pin per geolocated endpoint
//  and the "you are here" marker. Picking an endpoint just writes the
//  server/port/protocol overrides — Automatic clears them — so it round-trips
//  through exactly the same machinery as the Options tab, and changing it while
//  connected raises the usual "takes effect on reconnect" notice.
//

import SwiftUI

struct EndpointSection: View {
    @Bindable var vpn: VPNController
    let profile: VPNController.Profile

    @Environment(EndpointLocator.self) private var locator
    @Environment(PublicIPMonitor.self) private var publicIP

    private var endpoints: [Endpoint] {
        vpn.ovpnText(id: profile.id).map { EndpointScanner.endpoints(in: $0) } ?? []
    }

    var body: some View {
        let endpoints = endpoints
        if endpoints.count > 1 || locatedPins(endpoints).contains(where: { $0.kind != .user }) {
            VStack(alignment: .leading, spacing: 10) {
                picker(endpoints)
                let pins = locatedPins(endpoints)
                if pins.contains(where: { $0.kind != .user }) {
                    MercatorMapView(pins: pins) { id in
                        if let e = endpoints.first(where: { $0.id == id }) { select(e) }
                    }
                    Text("Endpoint locations are country-level. Pick a pin, or use the menu above.")
                        .font(.footnote)
                        .foregroundStyle(.secondary)
                }
            }
        }
    }

    // MARK: Dropdown (canonical)

    private func picker(_ endpoints: [Endpoint]) -> some View {
        let selection = selectedEndpointID(endpoints)
        return Picker("Endpoint", selection: Binding(
            get: { selection },
            set: { newID in select(endpoints.first { $0.id == newID }) }
        )) {
            Text("Automatic — try in order").tag(String?.none)
            ForEach(locator.locations(for: endpoints), id: \.endpoint.id) { location in
                Text(endpointLabel(location)).tag(String?.some(location.endpoint.id))
            }
            if let selection, !endpoints.contains(where: { $0.id == selection }) {
                Text("Custom (set in Options)").tag(String?.some(selection))
            }
        }
        .accessibilityHint("Choosing an endpoint overrides the server, port and protocol for this VPN.")
    }

    private func endpointLabel(_ location: EndpointLocation) -> String {
        var label = ""
        if let code = location.countryCode {
            label += CountryCentroids.flag(for: code) + " "
        }
        label += location.endpoint.host
        if let port = location.endpoint.port { label += ":\(port)" }
        if let proto = location.endpoint.proto { label += " · \(proto.uppercased())" }
        if let country = location.countryName { label += " — \(country)" }
        return label
    }

    // MARK: Selection ↔ overrides

    /// The endpoint the current overrides point at (nil = Automatic; an id not
    /// in the list = hand-set overrides in the Options tab).
    private func selectedEndpointID(_ endpoints: [Endpoint]) -> String? {
        let o = vpn.overrides(for: profile.id)
        guard let server = o.server else { return nil }
        // Match all three components — profiles commonly list the same host:port
        // as both udp and tcp remotes.
        if let match = endpoints.first(where: {
            $0.host == server && $0.port == o.port
                && $0.proto.flatMap { OpenVPNOverrides.TransportProto(rawValue: $0) } == o.proto
        }) {
            return match.id
        }
        return "custom:\(server)"
    }

    private func select(_ endpoint: Endpoint?) {
        var o = vpn.overrides(for: profile.id)
        o.server = endpoint?.host
        o.port = endpoint?.port
        o.proto = endpoint?.proto.flatMap { OpenVPNOverrides.TransportProto(rawValue: $0) }
        Task { try? await vpn.setOverrides(o, for: profile.id) }
    }

    // MARK: Pins

    private func locatedPins(_ endpoints: [Endpoint]) -> [MapPin] {
        let selectedID = selectedEndpointID(endpoints)
        var pins: [MapPin] = locator.locations(for: endpoints).compactMap { location in
            guard let lat = location.lat, let lon = location.lon else { return nil }
            return MapPin(id: location.endpoint.id,
                          kind: .endpoint(selected: location.endpoint.id == selectedID),
                          lat: lat, lon: lon,
                          title: location.endpoint.host,
                          subtitle: location.countryName ?? "")
        }
        if let lat = publicIP.lat, let lon = publicIP.lon {
            pins.append(MapPin(id: "you", kind: .user, lat: lat, lon: lon,
                               title: "This Mac",
                               subtitle: publicIP.countryName ?? ""))
        }
        return pins
    }
}
