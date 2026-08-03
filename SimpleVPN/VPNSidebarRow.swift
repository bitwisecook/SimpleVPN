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
    @Environment(EndpointProbeStore.self) private var probes: EndpointProbeStore?
    @Environment(PublicIPMonitor.self) private var publicIP: PublicIPMonitor?
    @Environment(\.accessibilityReduceMotion) private var reduceMotion
    private var stateEase: Animation? { reduceMotion ? nil : .smooth(duration: 0.3) }

    private var endpoints: [VPNEndpoint] { vpn.endpoints(for: profile.id) }
    private var isPaused: Bool { vpn.pausedProfiles.contains(profile.id) }
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
                    // The picker replaces the status line, but "waiting on you"
                    // must still be said — it's the reason Play is dimmed.
                    if missingTypedInput != nil,
                       profile.status == .disconnected || profile.status == .invalid {
                        Text(statusText).font(.caption).foregroundStyle(.secondary).lineLimit(1)
                    }
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
        .animation(stateEase, value: isPaused)
    }

    @ViewBuilder private var controlsContent: some View {
        if reconfiguring {
            DrawnSpinner().frame(width: 34, height: 34)
                .transition(.blurReplace)
        } else {
            switch profile.status {
            case .connected, .reasserting:
                if isPaused {
                    circle("play.fill", tint: .green, help: "Resume") { Task { await vpn.resume(id: profile.id) } }
                        .transition(.blurReplace)
                } else if vpn.uiPrefs(for: profile.id).allowPause {
                    // Opt-in per VPN — the default row is just stop.
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
                } else if let missing = missingTypedInput {
                    // Same rule as macOS permission above: a green Play that can only
                    // fail is a lie. Dim it — but a click still helps: it opens this
                    // VPN and shakes the field that needs filling in.
                    circle("play.fill", tint: .gray,
                           help: missing == .code ? "Enter your verification code first"
                                                  : "Enter your sign-in first") {
                        vpn.nudgeCredentials(id: profile.id)
                    }
                    .transition(.blurReplace)
                    .accessibilityLabel("Connect \(profile.name) — needs \(missing == .code ? "your verification code" : "your sign-in") first")
                } else {
                    circle("play.fill", tint: .green, help: "Connect") { play() }
                        .transition(.blurReplace)
                }
            }
        }
    }

    // Sidebar affordance is a single direct action: pause keeps the session
    // signed in but sends traffic outside the VPN, so the icon is the loud
    // lane-diversion sign, not a calm pause glyph.
    private var pauseControl: some View {
        Button {
            Task { await vpn.pause(id: profile.id) }
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
        Task {
            // If saved credentials can't do it after all (a manager item went
            // missing, a code became required), don't fail silently — walk the
            // user to the form like the dimmed play button would have.
            if await !vpn.connectWithSavedCredentials(id: profile.id), vpn.lastError == nil {
                vpn.nudgeCredentials(id: profile.id)
            }
        }
    }

    /// What still has to be typed before this VPN can connect. Reads the SAME
    /// shared readiness decision as the detail pane's `canConnect`, so the
    /// sidebar play button and the detail Connect button can never disagree —
    /// Tailscale/autologin/proxy VPNs (which sign themselves in) resolve to nil
    /// here, so Play stays green and connects rather than showing "Sign-in
    /// needed". nil ⇒ a tap on Play can genuinely connect.
    private enum MissingInput { case signIn, code }
    private var missingTypedInput: MissingInput? {
        switch vpn.connectReadiness(for: profile.id) {
        case .ready: return nil
        case .needsCode: return .code
        case .needsSignIn, .blocked: return .signIn
        }
    }

    // MARK: Endpoint picker (multi-endpoint VPNs)

    private var endpointPicker: some View {
        Menu {
            Button { selectEndpoint(nil) } label: {
                Label("Automatic", systemImage: selectedID == nil ? "checkmark" : "")
            }
            // Grouped by region so a forty-server provider list is scannable;
            // within a group, quickest first (or nearest, when speed checks are
            // off — see EndpointRanking).
            ForEach(groups) { group in
                Section(group.region.name) {
                    ForEach(group.endpoints) { item in
                        Button { selectEndpoint(item.endpoint) } label: {
                            // The server we're actually on says "Connected"
                            // rather than a timing — see EndpointRowLabel.
                            Label(EndpointRowLabel.oneLine(
                                item,
                                connected: selectedID == item.id && vpn.isEngaged(id: profile.id)),
                                  systemImage: selectedID == item.id ? "checkmark" : "")
                        }
                    }
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

    /// Ordered with whatever measurements already exist — this row never starts
    /// a probe of its own. A menu opening is not something SwiftUI tells us
    /// about, and probing on every sidebar redraw would be exactly the timerless
    /// background sweep the app promises not to do. Selecting the VPN (which
    /// shows EndpointSection) is what measures its servers.
    private var groups: [RegionGroup] {
        EndpointRegions.groups(endpoints, locator: locator, probes: probes,
                               home: EndpointRegions.home(publicIP: publicIP))
    }

    private var selectedID: String? {
        let o = vpn.overrides(for: profile.id)
        guard let server = o.server else { return nil }
        return endpoints.first {
            $0.host == server && $0.port == o.port
                && $0.proto.flatMap { OpenVPNOverrides.TransportProto(rawValue: $0) } == o.proto
        }?.id
    }

    private var currentEndpointLabel: String {
        guard let id = selectedID,
              let item = groups.flatMap(\.endpoints).first(where: { $0.id == id }) else {
            return "Automatic"
        }
        let flag = item.flag.isEmpty ? "" : item.flag + " "
        return flag + (item.endpoint.label ?? item.countryName ?? item.endpoint.host)
    }

    /// Change endpoint through the smooth apply path (reconnects if connected,
    /// records an undo). Writes the server/port/proto overrides.
    private func selectEndpoint(_ endpoint: VPNEndpoint?) {
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
        if isPaused { return "Paused — traffic outside VPN" }
        // "Disconnected" is true but useless when the real story is "waiting on
        // you" — say what's needed instead, in non-technical words ("verification
        // code" is Apple's name for a one-time code).
        if profile.status == .disconnected || profile.status == .invalid {
            switch missingTypedInput {
            case .code: return "Verification code needed"
            case .signIn: return "Sign-in needed"
            case nil: break
            }
        }
        return VPNController.statusText(profile.status)
    }
}
