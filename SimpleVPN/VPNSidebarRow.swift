// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
//  VPNSidebarRow.swift
//  The main window's left-column row: taller than a plain list item so it can
//  carry reactive transport controls (play / pause / stop) and, for a VPN that
//  advertises several endpoints, a destination picker (US / EU / APAC …). The
//  controls reflect live state and act in place — you don't have to open the VPN
//  to start, pause or stop it.
//

import SwiftUI

struct VPNSidebarRow: View {
    @Environment(ExtensionController.self) private var ext: ExtensionController?
    @Bindable var vpn: VPNController
    let profile: VPNController.Profile
    let labelDefs: [LabelDef]
    let dotState: DotState

    @Environment(EndpointLocator.self) private var locator: EndpointLocator?
    @Environment(\.accessibilityReduceMotion) private var reduceMotion
    private var stateEase: Animation? { reduceMotion ? nil : .smooth(duration: 0.3) }

    private var endpoints: [Endpoint] {
        vpn.ovpnText(id: profile.id).map { EndpointScanner.endpoints(in: $0) } ?? []
    }
    private var pauseMode: VPNController.PauseMode? { vpn.pausedProfiles[profile.id] }
    private var reconfiguring: Bool { vpn.isReconfiguring(profile.id) }

    var body: some View {
        HStack(spacing: 10) {
            LogoBadge(id: profile.id, status: profile.status, dotState: dotState)
                .scaleEffect(1.15)
                .frame(width: 26, height: 26)

            VStack(alignment: .leading, spacing: 2) {
                Text(profile.name).lineLimit(1).truncationMode(.tail)
                if endpoints.count > 1 {
                    endpointPicker
                } else {
                    Text(statusText).font(.caption).foregroundStyle(.secondary).lineLimit(1)
                }
                if !labelDefs.isEmpty {
                    HStack(spacing: 4) { ForEach(labelDefs) { LabelPill(label: $0) } }
                }
            }

            Spacer(minLength: 6)
            controls
        }
        .padding(.vertical, 6)
        .frame(minHeight: 52)
    }

    // MARK: Reactive transport controls (~34pt tall)

    @ViewBuilder private var controls: some View {
        // One glass control group that morphs between the lifecycle states — the
        // play/pause/stop glass circles blend and cross-fade rather than pop.
        GlassEffectContainer(spacing: 6) {
            controlsContent
        }
        .animation(stateEase, value: profile.status)
        .animation(stateEase, value: reconfiguring)
        .animation(stateEase, value: pauseMode)
    }

    @ViewBuilder private var controlsContent: some View {
        if reconfiguring {
            DrawnSpinner().frame(width: 34, height: 34)
                .transition(.blurReplace)
        } else {
            switch profile.status {
            case .connected, .reasserting:
                if pauseMode != nil {
                    circle("play.fill", tint: .green, help: "Resume") { Task { await vpn.resume(id: profile.id) } }
                        .transition(.blurReplace)
                } else {
                    pauseControl
                        .transition(.blurReplace)
                }
                circle("stop.fill", tint: .red, help: "Disconnect") { vpn.disconnect(id: profile.id) }
            case .connecting, .disconnecting:
                DrawnSpinner().frame(width: 34, height: 34)
                    .transition(.blurReplace)
                // Always offer a way out of "Connecting…" — a gateway that can't be
                // reached is retried indefinitely, so a spinner alone traps the user.
                if profile.status == .connecting {
                    circle("xmark.circle.fill", tint: UI.cancelRed, help: "Cancel connecting") { vpn.disconnect(id: profile.id) }
                        .transition(.blurReplace)
                }
            default:
                // While macOS is withholding permission, a green Play is a promise the
                // app can't keep — it can only fail. Offer the step that unblocks it.
                if ext?.needsApproval == true, ext?.isActivated == false {
                    circle("lock.shield", tint: .orange,
                           help: "macOS needs your permission before SimpleVPN can connect") {
                        Task { await ext?.activate() }
                    }
                    .transition(.blurReplace)
                } else {
                    circle("play.fill", tint: .green, help: "Connect") { play() }
                        .transition(.blurReplace)
                }
            }
        }
    }

    // Sidebar affordance is deliberately a single direct action, not a menu: this
    // is the leaky/risky choice (traffic leaves the Mac outside the VPN), so it
    // gets its own loud, unmistakable control rather than being buried behind a
    // tap-to-reveal picker. Anyone who wants the "block" choice instead opens the
    // connection detail pane, where PauseControl still offers both.
    private var pauseControl: some View {
        Button {
            Task { await vpn.pause(id: profile.id, mode: .bypass) }
        } label: {
            // A lane-diversion road sign: traffic being routed AROUND something. A
            // shield said "protected", which is the opposite of what bypass does.
            Image(systemName: "road.lane.arrowtriangle.2.inward").font(.title3)
                .frame(width: 34, height: 34)
                .foregroundStyle(.orange)
                .contentShape(Circle())
        }
        .buttonStyle(.plain)
        .glassEffect(.regular.tint(.orange.opacity(0.28)).interactive(), in: Circle())
        .help("Bypass — pause and send traffic outside the VPN")
        .accessibilityLabel("Bypass \(profile.name)")
        .accessibilityHint("Pauses the VPN and sends its traffic outside the tunnel, unprotected, until you resume.")
    }

    private func circle(_ symbol: String, tint: Color, help: String, action: @escaping () -> Void) -> some View {
        Button(action: action) {
            Image(systemName: symbol).font(.title3)
                .frame(width: 34, height: 34)
                .foregroundStyle(tint)
                .contentShape(Circle())
        }
        .buttonStyle(.plain)
        .glassEffect(.regular.tint(tint.opacity(0.28)).interactive(), in: Circle())
        .help(help)
    }

    private func play() {
        vpn.selectedID = profile.id                 // focus it if it needs input
        Task { await vpn.connectWithSavedCredentials(id: profile.id) }
    }

    // MARK: Endpoint picker (multi-endpoint VPNs)

    private var endpointPicker: some View {
        Menu {
            Button { selectEndpoint(nil) } label: {
                Label("Automatic", systemImage: selectedID == nil ? "checkmark" : "")
            }
            ForEach(locations, id: \.endpoint.id) { loc in
                Button { selectEndpoint(loc.endpoint) } label: {
                    Label(endpointLabel(loc), systemImage: selectedID == loc.endpoint.id ? "checkmark" : "")
                }
            }
        } label: {
            HStack(spacing: 3) {
                Image(systemName: "mappin.and.ellipse").font(.caption2)
                Text(currentEndpointLabel).font(.caption).lineLimit(1)
            }
            .foregroundStyle(.secondary)
        }
        .menuStyle(.borderlessButton)
        .fixedSize()
    }

    private var locations: [EndpointLocation] { locator?.locations(for: endpoints) ?? [] }

    private var selectedID: String? {
        let o = vpn.overrides(for: profile.id)
        guard let server = o.server else { return nil }
        return endpoints.first {
            $0.host == server && $0.port == o.port
                && $0.proto.flatMap { OpenVPNOverrides.TransportProto(rawValue: $0) } == o.proto
        }?.id
    }

    private var currentEndpointLabel: String {
        guard let id = selectedID, let loc = locations.first(where: { $0.endpoint.id == id }) else {
            return "Automatic"
        }
        return shortLabel(loc)
    }

    private func shortLabel(_ loc: EndpointLocation) -> String {
        if let code = loc.countryCode { return CountryCentroids.flag(for: code) + " " + (loc.countryName ?? loc.endpoint.host) }
        return loc.endpoint.host
    }

    private func endpointLabel(_ loc: EndpointLocation) -> String {
        var s = ""
        if let code = loc.countryCode { s += CountryCentroids.flag(for: code) + " " }
        s += loc.endpoint.host
        if let port = loc.endpoint.port { s += ":\(port)" }
        if let country = loc.countryName { s += " — \(country)" }
        return s
    }

    /// Change endpoint through the smooth apply path (reconnects if connected,
    /// records an undo). Writes the server/port/proto overrides.
    private func selectEndpoint(_ endpoint: Endpoint?) {
        let label = endpoint.map { $0.host } ?? "Automatic"
        Task {
            await vpn.applyDoctorFix(.overrides { o in
                o.server = endpoint?.host
                o.port = endpoint?.port
                o.proto = endpoint?.proto.flatMap { OpenVPNOverrides.TransportProto(rawValue: $0) }
            }, to: profile.id, undoLabel: "endpoint: \(label)")
        }
    }

    private var statusText: String {
        if let pauseMode { return pauseMode == .bypass ? "Paused — traffic outside VPN" : "Paused" }
        return VPNController.statusText(profile.status)
    }
}
