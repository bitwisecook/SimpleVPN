// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
//  EndpointSection.swift
//  Endpoint choice for a VPN: the dropdown (canonical control, full list, the
//  accessibility path) plus the Mercator map with a pin per geolocated endpoint
//  and the "you are here" marker. Servers are grouped under region headings and
//  offered quickest-first where we've measured them, nearest-first where we
//  haven't. Picking an endpoint just writes the server/port/protocol overrides —
//  Automatic clears them — so it round-trips through exactly the same machinery
//  as the Options tab, and changing it while connected raises the usual "takes
//  effect on reconnect" notice.
//

import SwiftUI

struct EndpointSection: View {
    @Bindable var vpn: VPNController
    let profile: VPNController.Profile

    @Environment(EndpointLocator.self) private var locator
    @Environment(PublicIPMonitor.self) private var publicIP
    @Environment(EndpointProbeStore.self) private var probes: EndpointProbeStore?

    private var endpoints: [VPNEndpoint] { vpn.endpoints(for: profile.id) }

    private var home: GeoPoint? { EndpointRegions.home(publicIP: publicIP) }

    private var groups: [RegionGroup] {
        EndpointRegions.groups(endpoints, locator: locator, probes: probes, home: home)
    }

    /// This VPN is up, or coming up (see VPNController.isEngaged). Its servers
    /// are then neither measured nor described by a measurement: the check would
    /// travel through the very tunnel it is asking about and come back as a
    /// timeout, which the user reads as "the server I'm connected to is down".
    private var connected: Bool { vpn.isEngaged(id: profile.id) }

    var body: some View {
        let endpoints = endpoints
        let groups = groups
        let items = groups.flatMap(\.endpoints)
        if endpoints.count > 1 || items.contains(where: { $0.point != nil }) {
            VStack(alignment: .leading, spacing: 10) {
                picker(groups)
                Text(EndpointRegions.orderExplanation(groups, home: home, connected: connected))
                    .font(.footnote)
                    .foregroundStyle(.secondary)
                let pins = locatedPins(items)
                if pins.contains(where: { $0.kind != .user }) {
                    MercatorMapView(pins: pins) { id in
                        if let e = endpoints.first(where: { $0.id == id }) { select(e) }
                    }
                    Text("Endpoint locations are country-level. Pick a pin, or use the menu above.")
                        .font(.footnote)
                        .foregroundStyle(.secondary)
                }
            }
            // Opening a VPN's page is the user asking about its servers, so this
            // is a fair moment to measure them — and the only kind of moment that
            // ever does (no timer, nothing in the background). Changing network
            // counts as the same moment: the page is open, and the measurements
            // it is showing belong to a network the user has left. Connecting and
            // disconnecting count too — the sweep is refused while this VPN is
            // engaged, so disconnecting is when its servers become measurable.
            .task(id: "\(profile.id)\u{1F}\(NetworkMemory.shared.current?.key ?? "")\u{1F}\(connected)") {
                probes?.refresh(endpoints, kind: profile.kind, profile: profile.id)
            }
        }
    }

    // MARK: Dropdown (canonical)

    private func picker(_ groups: [RegionGroup]) -> some View {
        let items = groups.flatMap(\.endpoints)
        let selection = selectedEndpointID(items.map(\.endpoint))
        return Picker("Endpoint", selection: Binding(
            get: { selection },
            set: { newID in select(items.first { $0.id == newID }?.endpoint) }
        )) {
            Text("Automatic — try in order").tag(String?.none)
            ForEach(groups) { group in
                Section(group.region.name) {
                    ForEach(group.endpoints) { item in
                        Text(EndpointRowLabel.oneLine(
                            item, connected: connected && item.id == selection))
                            .tag(String?.some(item.id))
                    }
                }
            }
            if let selection, !items.contains(where: { $0.id == selection }) {
                Text("Custom (set in Options)").tag(String?.some(selection))
            }
        }
        .accessibilityHint("Choosing an endpoint overrides the server, port and protocol for this VPN.")
    }

    // MARK: Selection ↔ overrides

    /// The endpoint the current overrides point at (nil = Automatic; an id not
    /// in the list = hand-set overrides in the Options tab).
    private func selectedEndpointID(_ endpoints: [VPNEndpoint]) -> String? {
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

    private func select(_ endpoint: VPNEndpoint?) {
        var o = vpn.overrides(for: profile.id)
        o.server = endpoint?.host
        o.port = endpoint?.port
        o.proto = endpoint?.proto.flatMap { OpenVPNOverrides.TransportProto(rawValue: $0) }
        Task { try? await vpn.setOverrides(o, for: profile.id) }
    }

    // MARK: Pins

    private func locatedPins(_ items: [RankedEndpoint]) -> [MapPin] {
        let selectedID = selectedEndpointID(items.map(\.endpoint))
        var pins: [MapPin] = items.compactMap { item in
            // A corrected country moves the pin too — the map and the list must
            // never disagree about where a server is.
            guard let point = item.point else { return nil }
            var subtitle = item.countryName ?? ""
            let note = connected && item.id == selectedID
                ? "Connected" : item.measurement?.rttText
            if let note {
                subtitle += subtitle.isEmpty ? note : " · \(note)"
            }
            return MapPin(id: item.id,
                          kind: .endpoint(selected: item.id == selectedID),
                          lat: point.lat, lon: point.lon,
                          title: item.endpoint.displayLabel,
                          subtitle: subtitle)
        }
        if let lat = publicIP.lat, let lon = publicIP.lon {
            pins.append(MapPin(id: "you", kind: .user, lat: lat, lon: lon,
                               title: "This Mac",
                               subtitle: publicIP.countryName ?? ""))
        }
        return pins
    }
}
