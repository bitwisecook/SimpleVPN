// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
//  EndpointSection.swift
//  Endpoint choice for a VPN: the dropdown is the canonical control and full
//  accessibility path. Its inspector globe previews the selected route
//  in grey, then turns it blue only after tunnel telemetry confirms the endpoint
//  actually in use. Servers are grouped under region headings and offered
//  quickest-first where we've measured them, nearest-first where we haven't.
//  Picking an endpoint just writes the server/port/protocol overrides — Automatic
//  clears them — so it round-trips through exactly the same machinery as the
//  Options tab, and changing it while connected raises the usual "takes effect on
//  reconnect" notice.
//

import SwiftUI

struct EndpointSection: View {
    enum Presentation { case picker, globe }

    @Bindable var vpn: VPNController
    let profile: VPNController.Profile
    var presentation: Presentation = .picker

    @Environment(EndpointLocator.self) private var locator
    @Environment(PublicIPMonitor.self) private var publicIP
    @Environment(EndpointProbeStore.self) private var probes: EndpointProbeStore?
    @Environment(ReachabilityMonitor.self) private var reach: ReachabilityMonitor?

    /// A useful globe inside the trailing inspector. The square shader surface
    /// avoids the empty horizontal space needed by the old detail-pane 2:1
    /// presentation while leaving room for live connection details below it.
    private static let inspectorGlobeDiameter: CGFloat = 220

    private var endpoints: [VPNEndpoint] { vpn.endpoints(for: profile.id) }

    private var home: GeoPoint? { EndpointRegions.home(publicIP: publicIP) }

    private var groups: [RegionGroup] {
        EndpointRegions.groups(endpoints, locator: locator, probes: probes, home: home)
    }

    private var rankedEndpoints: [RankedEndpoint] { groups.flatMap(\.endpoints) }

    /// This VPN is up, or coming up (see VPNController.isEngaged). Its servers
    /// are then neither measured nor described by a measurement: the check would
    /// travel through the very tunnel it is asking about and come back as a
    /// timeout, which the user reads as "the server I'm connected to is down".
    private var connected: Bool { vpn.isEngaged(id: profile.id) }

    /// The one server telemetry says is carrying this session. A `.connecting`
    /// state is deliberately not enough: blue means that the transport has already
    /// reported the endpoint, not that a button was pressed.
    private var liveEndpoint: RankedEndpoint? {
        guard vpn.displayStatus(for: profile.id) == .connected,
              let stats = reach?.stats(for: profile.id) else { return nil }
        return rankedEndpoints.first {
            ServersTableCopy.isInUse($0, serverIP: stats.serverIP,
                                      serverEndpoint: stats.serverEndpoint)
        }
    }

    /// What a route preview should point at while no session has named a server:
    /// the selected override, or the first endpoint in the configuration's own
    /// automatic order. Never invent a location when neither is available.
    private var previewEndpoint: RankedEndpoint? {
        if let liveEndpoint { return liveEndpoint }
        let selection = selectedEndpointID(rankedEndpoints.map(\.endpoint))
        return selection.flatMap { id in rankedEndpoints.first { $0.id == id } }
            ?? rankedEndpoints.first
    }

    var body: some View {
        let endpoints = endpoints
        let groups = groups
        if !endpoints.isEmpty {
            VStack(alignment: .leading, spacing: 10) {
                if presentation == .picker, endpoints.count > 1 {
                    picker(groups)
                    Text(EndpointRegions.orderExplanation(groups, home: home, connected: connected))
                        .font(.footnote)
                        .foregroundStyle(.secondary)
                }
                if presentation == .globe { routePreview }
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

    // MARK: Compact route preview

    @ViewBuilder
    private var routePreview: some View {
        if let endpoint = previewEndpoint, let point = endpoint.point {
            let isLive = liveEndpoint?.id == endpoint.id
            let endpointPin = MapPin(
                id: "preview.endpoint.\(endpoint.id)",
                kind: .endpoint(selected: true),
                lat: point.lat, lon: point.lon,
                title: endpoint.primaryLabel,
                subtitle: isLive ? "Connected server" : "Selected server",
                placement: endpoint.endpoint.country == nil && endpoint.geoPoint != nil ? .exact : .approximate)

            VStack(alignment: .leading, spacing: 5) {
                Group {
                    if let home {
                        let userPin = MapPin(id: "preview.home", kind: .user,
                                             lat: home.lat, lon: home.lon,
                                             title: publicIP.homeCountryName ?? "Your location",
                                             subtitle: "This Mac")
                        let link = MapConnection(from: userPin.id, to: endpointPin.id,
                                                 kind: isLive ? .tunnel : .pending)
                        MetalGlobeMapView(pins: [userPin, endpointPin], connections: [link],
                                          maximumGlobeDiameter: Self.inspectorGlobeDiameter,
                                          surfaceAspectRatio: 1) { id in
                            guard id == endpointPin.id else { return }
                            select(endpoint.endpoint)
                        }
                    } else {
                        // Public-location lookup is optional. The earth and known
                        // server must not disappear merely because the route's
                        // starting point is not available yet.
                        MetalGlobeMapView(pins: [endpointPin],
                                          maximumGlobeDiameter: Self.inspectorGlobeDiameter,
                                          surfaceAspectRatio: 1) { id in
                            guard id == endpointPin.id else { return }
                            select(endpoint.endpoint)
                        }
                    }
                }
                .frame(maxWidth: .infinity)
                Text(home == nil
                     ? "Selected server — your location is not available yet."
                     : isLive
                        ? "Connected route — blue shows the server in use."
                        : "Selected route — grey until it connects.")
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .frame(maxWidth: .infinity, alignment: .center)
            }
            .accessibilityElement(children: .contain)
        } else {
            VStack(alignment: .leading, spacing: 5) {
                // DNS/GeoIP can still be resolving. Keep the textured globe in
                // its stable place rather than collapsing the entire preview.
                MetalGlobeMapView(pins: [], maximumGlobeDiameter: Self.inspectorGlobeDiameter,
                                  surfaceAspectRatio: 1)
                    .frame(maxWidth: .infinity)
                Text("Locating the selected server…")
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .frame(maxWidth: .infinity, alignment: .center)
            }
        }
    }

    // MARK: Dropdown (canonical)

    private func picker(_ groups: [RegionGroup]) -> some View {
        let items = groups.flatMap(\.endpoints)
        let selection = selectedEndpointID(items.map(\.endpoint))
        let liveEndpointID = liveEndpoint?.id
        return Picker("Server", selection: Binding(
            get: { selection },
            set: { newID in select(items.first { $0.id == newID }?.endpoint) }
        )) {
            // "Automatic" means "try the configuration's remotes in order", which is
            // an OpenVPN behaviour. A WireGuard peer is one address and one key with
            // nothing to fall back to, so offering it there would be a row that
            // cannot do what it says.
            if !vpn.isWireGuard(profile.id) {
                Text("Automatic — try in order").tag(String?.none)
            }
            ForEach(groups) { group in
                // The heading looks the same but SAYS more: how many servers
                // the region holds and the quickest measured one, so a
                // VoiceOver user can pick a region without walking its rows.
                Section {
                    ForEach(group.endpoints) { item in
                        Text(EndpointRowLabel.oneLine(
                            item, connected: item.id == liveEndpointID))
                            .tag(String?.some(item.id))
                    }
                } header: {
                    Text(group.region.name)
                        .accessibilityLabel(regionHeading(group))
                }
            }
            if let selection, !items.contains(where: { $0.id == selection }) {
                Text("Custom (set in Options)").tag(String?.some(selection))
            }
        }
        .accessibilityHint("Choosing a server overrides the server address, port and protocol for this VPN.")
    }

    /// "Europe, 3 servers, quickest 24 milliseconds" — the region heading as
    /// VoiceOver reads it. The latency clause only appears when something was
    /// actually measured; a nearest-first list must not invent numbers.
    private func regionHeading(_ group: RegionGroup) -> String {
        var s = "\(group.region.name), \(group.endpoints.count) server\(group.endpoints.count == 1 ? "" : "s")"
        if let best = group.endpoints.compactMap(\.measurement?.rttMS).min() {
            s += ", quickest \(Int(best.rounded())) milliseconds"
        }
        return s
    }

    // MARK: Selection ↔ overrides

    /// The endpoint the current overrides point at (nil = Automatic; an id not
    /// in the list = hand-set overrides in the Options tab).
    private func selectedEndpointID(_ endpoints: [VPNEndpoint]) -> String? {
        // WireGuard keeps its choice in its OWN configuration — one peer, one
        // address, one key — rather than in the OpenVPN overrides, which its engine
        // never reads. Asking the wrong store showed every WireGuard VPN as
        // "Automatic" no matter which relay it was actually pointed at.
        if vpn.isWireGuard(profile.id) {
            return WireGuardEndpointSelection
                .selected(in: endpoints, config: vpn.wireGuardConfig(for: profile.id))?.id
        }
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

    /// One call, whatever the kind: `selectEndpoint` decides whether this is an
    /// override to write or a WireGuard peer to swap address AND key on. A refusal
    /// is SPOKEN rather than swallowed — the whole hazard here is a choice that
    /// looks accepted and was not.
    private func select(_ endpoint: VPNEndpoint?) {
        Task {
            if let refusal = await vpn.selectEndpoint(endpoint, for: profile.id) {
                AccessibilityAnnouncer.sayNow(refusal)
                vpn.lastError = refusal
            }
        }
    }

}
