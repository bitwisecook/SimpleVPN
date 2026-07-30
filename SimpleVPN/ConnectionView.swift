// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
//  ConnectionView.swift
//  Main window — connection only. Startup flow (per Apple HIG onboarding guidance):
//   1. extension not activated → activation prompt + instructions
//   2. no VPNs configured → import / add prompt
//   3. otherwise → sidebar of VPNs + connection detail (status, connect/disconnect,
//      OTP entry, and the throughput graph once M6 lands).
//  VPN management (create/import/edit/remove/export) lives in its own window.
//

import SwiftUI
import UniformTypeIdentifiers

struct ConnectionView: View {
    @Bindable var vpn: VPNController
    @Bindable var ext: ExtensionController
    @Bindable var labels: LabelStore
    @Environment(\.openWindow) private var openWindow
    @Environment(ReachabilityMonitor.self) private var reach: ReachabilityMonitor?
    @Environment(LinkStateMonitor.self) private var link: LinkStateMonitor?
    @Environment(SubprocessTunnelManager.self) private var tunnelManager: SubprocessTunnelManager?
    @Environment(SubprocessTunnelStore.self) private var tunnels: SubprocessTunnelStore?
    @Environment(NativeVPNManager.self) private var nativeVPN: NativeVPNManager?
    @State private var showImporter = false
    @State private var sso = SSOAuthModel.shared
    /// Crashes found at launch, offered once (see CrashDiagnostics).
    @State private var pendingCrashes: [CrashReport] = []
    @State private var showCrashReport = false

    /// Sidebar dot — from the ONE shared derivation, so it can never disagree with
    /// the header pill, the menu bar or the route graph (they all used to compute
    /// their own, with two different captive-portal predicates).
    private func rowDot(_ p: VPNController.Profile) -> DotState {
        link?.dot(for: p.id) ?? .from(status: p.status)
    }

    /// Active non-OpenVPN tunnels (SSH / OpenConnect subprocess, native IKEv2) so a
    /// live connection is visible and stoppable here, not only in Manage VPNs.
    private var nativeBackendActive: Bool {
        nativeVPN?.status == .connected || nativeVPN?.status == .connecting
    }

    @ViewBuilder private var otherConnectionsSection: some View {
        let subs = (tunnels?.tunnels ?? []).filter { tunnelManager?.isActive($0.id) == true }
        if !subs.isEmpty || nativeBackendActive {
            Section("Other Connections") {
                ForEach(subs) { t in
                    otherConnectionRow(name: t.name, kindLabel: t.kind.displayName,
                                       dot: .from(subprocess: tunnelManager?.status(t.id) ?? .disconnected)) {
                        tunnelManager?.disconnect(t.id)
                    }
                }
                if nativeBackendActive, let n = nativeVPN,
                   let c = n.configs.first(where: { $0.id == n.activeConfigID }) {
                    otherConnectionRow(name: c.name, kindLabel: c.kind.displayName,
                                       dot: .from(status: n.status)) { n.disconnect() }
                }
            }
        }
    }

    private func otherConnectionRow(name: String, kindLabel: String, dot: DotState,
                                    stop: @escaping () -> Void) -> some View {
        HStack(spacing: 8) {
            StatusDot(state: dot)
            VStack(alignment: .leading, spacing: 1) {
                Text(name).lineLimit(1)
                Text(kindLabel).font(.caption).foregroundStyle(.secondary)
            }
            Spacer(minLength: 8)
            Button(action: stop) { Image(systemName: "stop.fill") }
                .buttonStyle(.borderless).foregroundStyle(.secondary)
                .help("Disconnect")
        }
    }

    /// Deliberately jargon-free: this says what macOS wants and what to do, in the words
    /// someone who just wants their VPN would use. "System extension" is our problem, not
    /// theirs.
    private static func postApprovalToast(_ ext: ExtensionController) {
        ToastCenter.shared.post(
            "macOS needs your permission before SimpleVPN can make VPN connections.",
            symbol: "lock.shield", seconds: 12,
            actionTitle: "Allow\u{2026}") {
                Task { await ext.activate() }
            }
    }

    var body: some View {
        content
            .toasts()
            .navigationTitle("SimpleVPN")
            .task {
                await vpn.loadAll()
                // Deliberately NOT ext.activate() here: activating raises a macOS
                // approval dialog, and a first launch should show the app, not a security
                // prompt for something the user hasn't asked for yet. VPNController does
                // it on the first connect (see ensureExtensionReady).
                vpn.ensureExtensionReady = { [weak ext] in
                    guard let ext else { return true }
                    if ext.isActivated { return true }
                    // Ask ONCE. If approval is already outstanding, re-firing would put
                    // the same dialog up on every connect attempt, which trains people to
                    // dismiss it — the ActivationPrompt banner and its Retry button are
                    // the deliberate second chance.
                    if ext.needsApproval { Self.postApprovalToast(ext); return false }
                    await ext.activate()
                    if !ext.isActivated { Self.postApprovalToast(ext) }
                    return ext.isActivated
                }
                ToastCenter.shared.openWindow = { openWindow(id: $0) }
                // Did we die last time? Offer to report it, once, with the details
                // already gathered (see CrashDiagnostics).
                let crashes = CrashDiagnostics.pendingReports()
                if !crashes.isEmpty {
                    pendingCrashes = crashes
                    showCrashReport = true
                }
            }
            .sheet(isPresented: $showCrashReport) {
                CrashReportSheet(
                    reports: pendingCrashes,
                    facts: IssueReport.gather(vpn: vpn, tunnels: tunnels,
                                              nativeVPN: nativeVPN, wireguard: nil))
            }
            .task {
                // Also drive the app-wide reachability monitor from the main window
                // (start() is idempotent) so sidebar stall dots and the map don't
                // depend solely on the menu-bar label's lifecycle.
                reach?.start(connectedIDs: { vpn.profiles.filter { $0.status == .connected }.map(\.id) },
                             fetch: { await vpn.fetchStats(id: $0) })
            }
            // A VPN needs SAML/SSO sign-in in the in-app window → raise it.
            .onChange(of: sso.generation) {
                if sso.pending != nil { openWindow(id: "sso") }
            }
            .fileImporter(isPresented: $showImporter,
                          allowedContentTypes: [UI.ovpnType, .data, .plainText],
                          onCompletion: importConfig)
            .ovpnDropTarget(vpn: vpn)
            .importOutcomeAlert(vpn: vpn)
            .onChange(of: vpn.importRequested, initial: true) {
                // initial: the ⌘O menu item may set the flag before this window's
                // content exists; without it the flag would stick and go dead.
                if vpn.importRequested { vpn.importRequested = false; showImporter = true }
            }
            .alert("Error", isPresented: .constant(vpn.lastError != nil)) {
                Button("OK") { vpn.lastError = nil }
            } message: { Text(vpn.lastError ?? "") }
    }

    @ViewBuilder private var content: some View {
        // The extension's state no longer gates the whole window. It used to open on
        // "System Extension Required", which is a demand made before the user has any
        // reason to care; approval is now asked for at the first connect, and only a
        // PENDING approval (one the user has already been shown) is worth a banner.
        if ext.needsApproval && !ext.isActivated {
            ActivationPrompt(ext: ext)
        } else if vpn.profiles.isEmpty && !(tunnelManager?.hasActive ?? false) && !nativeBackendActive {
            EmptyVPNsPrompt(importAction: { showImporter = true },
                            manageAction: { openWindow(id: "manage") },
                            dropAction: { vpn.handleImport(of: $0) })
        } else {
            splitView
        }
    }

    private var splitView: some View {
        NavigationSplitView {
            List(selection: $vpn.selectedID) {
                Section("VPNs") {
                    ForEach(vpn.profiles) { p in
                        VPNSidebarRow(vpn: vpn, profile: p, labelDefs: labels.labels(for: p.id), dotState: rowDot(p))
                            .tag(p.id)
                            .contextMenu { sidebarMenu(p) }
                    }
                }
                otherConnectionsSection
            }
            .navigationSplitViewColumnWidth(min: 220, ideal: 260)
            .toolbar {
                ToolbarItem {
                    Button { openWindow(id: "manage") } label: { Image(systemName: "slider.horizontal.3") }
                        .help("Manage VPNs")
                }
            }
        } content: {
            if let p = vpn.selected {
                ConnectionDetailView(vpn: vpn, profile: p).id(p.id)
                    .navigationSplitViewColumnWidth(min: 360, ideal: 400)
            } else {
                ContentUnavailableView("Select a VPN", systemImage: "network")
            }
        } detail: {
            if let p = vpn.selected {
                ConnectionInspectorView(vpn: vpn, profile: p).id(p.id)
                    .navigationSplitViewColumnWidth(min: 320, ideal: 380)
            } else {
                ContentUnavailableView("Live Details", systemImage: "chart.line.uptrend.xyaxis",
                    description: Text("Connect a VPN to see live traffic, the map and connection details."))
            }
        }
        .navigationSubtitle("app \(UI.appVersion) · ext \(vpn.extensionVersion)")
    }

    private func importConfig(_ result: Result<URL, Error>) {
        guard case let .success(url) = result else { return }
        vpn.handleImport(of: [url])
    }

    /// Right-click actions on a sidebar VPN: the whole lifecycle plus settings.
    @ViewBuilder private func sidebarMenu(_ p: VPNController.Profile) -> some View {
        if UI.isActive(p.status) {
            if vpn.pausedProfiles[p.id] != nil {
                Button("Resume") { Task { await vpn.resume(id: p.id) } }
            } else if p.status == .connected {
                Button("Pause") { Task { await vpn.pause(id: p.id, mode: .hold) } }
            }
            Button("Disconnect") { vpn.disconnect(id: p.id) }
        } else if p.status == .disconnected || p.status == .invalid {
            Button("Connect") {
                vpn.selectedID = p.id
                Task {
                    // Full credentials on file → straight through; otherwise the
                    // detail form is already showing for typing.
                    await vpn.connectWithSavedCredentials(id: p.id)
                }
            }
        }
        Divider()
        Button("Settings…") {
            vpn.selectedID = p.id
            openWindow(id: "manage")
        }
    }
}

// MARK: - Startup states

private struct ActivationPrompt: View {
    @Bindable var ext: ExtensionController
    @Environment(\.openURL) private var openURL
    var body: some View {
        ContentUnavailableView {
            Label("System Extension Required", systemImage: "puzzlepiece.extension")
        } description: {
            VStack(spacing: 8) {
                Text("SimpleVPN runs tunnels in a system extension. Activate it, then approve it in System Settings if prompted.")
                Text(ext.status).font(.callout).foregroundStyle(.secondary)
            }
        } actions: {
            Button("Activate Extension") { Task { await ext.activate() } }
                .buttonStyle(.borderedProminent)
            if ext.needsApproval {
                Button("Open Login Items & Extensions") {
                    if let url = URL(string: "x-apple.systempreferences:com.apple.LoginItems-Settings.extension") {
                        openURL(url)
                    }
                }
            }
        }
    }
}

private struct EmptyVPNsPrompt: View {
    let importAction: () -> Void
    let manageAction: () -> Void
    /// The shared import pipeline (same one the open panel and Dock drops use), so a
    /// drop here can't take a different code path from every other way in.
    let dropAction: ([URL]) -> Void
    /// Highlighted while a config is over the window, so the drop reads as live rather
    /// than as decoration.
    @State private var targeted = false

    var body: some View {
        VStack(spacing: 22) {
            ContentUnavailableView {
                Label("No VPNs Configured", systemImage: "network.slash")
            } description: {
                Text("Drop a configuration file here, import one, or add a VPN by hand.")
            } actions: {
                Button("Import .ovpn…", action: importAction).buttonStyle(.borderedProminent)
                Button("Add VPN…", action: manageAction)
            }

            // The whole window already accepts drops (see .ovpnDropTarget), but with an
            // empty list nothing on screen SAYS so — and dragging a .ovpn onto the app is
            // the fastest way in. An explicit well makes the affordance discoverable
            // instead of a thing you'd have to guess at.
            VStack(spacing: 10) {
                Image(systemName: targeted ? "arrow.down.doc.fill" : "arrow.down.doc")
                    .font(.system(size: 38))
                    .foregroundStyle(targeted ? AnyShapeStyle(.tint) : AnyShapeStyle(.secondary))
                    .contentTransition(.symbolEffect(.replace))
                Text("Drag a VPN configuration here")
                    .font(.callout).foregroundStyle(.secondary)
                Text("OpenVPN (.ovpn / .conf), WireGuard (.conf), or a 1Password item")
                    .font(.caption).foregroundStyle(.tertiary)
                    .multilineTextAlignment(.center)
            }
            .padding(.vertical, 26).padding(.horizontal, 34)
            .frame(maxWidth: 420)
            .background {
                RoundedRectangle(cornerRadius: 14, style: .continuous)
                    .strokeBorder(style: StrokeStyle(lineWidth: 2, dash: [7, 5]))
                    .foregroundStyle(targeted ? AnyShapeStyle(.tint) : AnyShapeStyle(.tertiary))
            }
            .animation(.snappy(duration: 0.2), value: targeted)
            .accessibilityLabel("Drop zone for VPN configuration files")
        }
        // Mirrors the window-wide handler's types, so the visible target and the
        // invisible one can't disagree about what's droppable.
        .dropDestination(for: URL.self) { urls, _ in
            dropAction(urls)
            return true
        } isTargeted: { targeted = $0 }
    }
}

// MARK: - Connection detail (connection only)

private struct ConnectionDetailView: View {
    @Bindable var vpn: VPNController
    let profile: VPNController.Profile
    @Environment(ProfileEvaluator.self) private var evaluator
    @Environment(PublicIPMonitor.self) private var publicIP
    @Environment(ReachabilityMonitor.self) private var reach: ReachabilityMonitor?
    @Environment(LinkStateMonitor.self) private var link: LinkStateMonitor?
    @Environment(ExtensionController.self) private var ext: ExtensionController?
    @Environment(\.accessibilityReduceMotion) private var reduceMotion
    @State private var busy = false
    /// The in-flight connect, so the busy pill's ✕ can cancel the credential lookup.
    @State private var connectTask: Task<Void, Never>?
    @State private var loaded = false
    @State private var submitAttempted = false

    /// Shared namespace so the cancel ✕ and the stop ■ are the same glass element
    /// morphing, not two controls swapping.
    @Namespace private var connectGlass

    /// True once a connect attempt has been grinding long enough that something is
    /// probably wrong (unreachable gateway, wrong network) rather than just slow.
    @State private var connectingTooLong = false
    @State private var netMemory = NetworkMemory.shared

    /// State-change easing, honouring Reduce Motion (instant when reduced).
    private var stateEase: Animation? { reduceMotion ? nil : .smooth(duration: 0.35) }

    private enum CredentialField { case username, password, otp }
    @FocusState private var focusedField: CredentialField?

    private var requiresOTP: Bool { vpn.authConfig(for: profile.id).requiresOTP }
    private var allowPasswordSave: Bool {
        vpn.ovpnText(id: profile.id).map { evaluator.evaluation(for: $0).allowPasswordSave } ?? true
    }
    private var pauseMode: VPNController.PauseMode? { vpn.pausedProfiles[profile.id] }
    private var isStalled: Bool { reach?.isStalled(profile.id) == true }
    @Environment(TopologyMonitor.self) private var topo: TopologyMonitor?

    /// Snapshot of live telemetry the Connection Manager + Doctor read.
    private var doctorSnapshot: DoctorSnapshot {
        var stalled: Int?
        if case .stalled(let s) = reach?.health(for: profile.id) { stalled = s }
        var snap = DoctorSnapshot()
        snap.status = profile.status
        snap.overrides = vpn.overrides(for: profile.id)
        snap.ovpn = vpn.ovpnText(id: profile.id) ?? ""
        snap.stats = reach?.stats(for: profile.id)
        snap.stalledSeconds = stalled
        snap.topology = topo?.topology ?? NetworkTopology()
        snap.incident = vpn.incidents[profile.id]
        snap.requiresOTP = requiresOTP
        snap.captivePortalSuspected = vpn.captivePortalSuspected && vpn.incidents[profile.id] != nil
        if let probe = vpn.probeResults[profile.id] {
            snap.pathMTU = probe.pathMTU
            // "UDP is blocked" = the VPN uses UDP, its connect failed with a
            // network error, yet plain web (TCP 443) is reachable on this network.
            let networkIncident = snap.incident.map { $0.category == .network || $0.category == .timeout } ?? false
            snap.udpBlockedTCP443Open = (!probeSpeaksTLS && networkIncident && probe.tcp443Reachable == true)
        }
        return snap
    }
    private var doctorFindings: [DoctorFinding] { ConnectionDoctor.findings(for: doctorSnapshot) }
    private var credentialKind: CredentialSourceKind { vpn.credentialSource(for: profile.id).kind }
    private var usesManager: Bool { credentialKind != .manual }
    /// A manager source still needs a typed OTP only when the profile requires
    /// one AND the manager can't supply it (Apple Passwords can't; 1Password can).
    private var managerNeedsTypedOTP: Bool {
        usesManager && requiresOTP && credentialKind != .onePassword
    }

    // One live credential state shared with the menu bar and edit sheet:
    // typing anywhere shows everywhere. Memory-only until Remember persists it.
    private var username: Binding<String> {
        Binding(get: { vpn.transientCredentials(for: profile.id).username },
                set: { var c = vpn.transientCredentials(for: profile.id); c.username = $0
                       vpn.setTransientCredentials(c, for: profile.id) })
    }
    private var password: Binding<String> {
        Binding(get: { vpn.transientCredentials(for: profile.id).password },
                set: { var c = vpn.transientCredentials(for: profile.id); c.password = $0
                       vpn.setTransientCredentials(c, for: profile.id) })
    }
    private var otp: Binding<String> {
        Binding(get: { vpn.transientCredentials(for: profile.id).otp },
                set: { var c = vpn.transientCredentials(for: profile.id); c.otp = $0
                       vpn.setTransientCredentials(c, for: profile.id) })
    }
    /// The shared Remember preference (persisted with the profile's auth config).
    private var remember: Binding<Bool> {
        Binding(get: { vpn.authConfig(for: profile.id).rememberCredentials },
                set: { on in
                    var auth = vpn.authConfig(for: profile.id)
                    auth.rememberCredentials = on
                    Task { try? await vpn.setAuthConfig(auth, for: profile.id) }
                    if !on { KeychainCredentialStore.deleteCredentials(profile: profile.id) }
                })
    }

    private var canConnect: Bool {
        if usesManager {
            // The manager supplies username/password; only gate on a typed OTP
            // when the manager can't provide one.
            return !managerNeedsTypedOTP
                || !vpn.transientCredentials(for: profile.id).otp.trimmingCharacters(in: .whitespaces).isEmpty
        }
        let c = vpn.transientCredentials(for: profile.id)
        return !c.username.trimmingCharacters(in: .whitespaces).isEmpty
            && !c.password.isEmpty
            && (!requiresOTP || !c.otp.trimmingCharacters(in: .whitespaces).isEmpty)
    }

    var body: some View {
        // Scroll rather than grow: a long detail (Doctor cards + incident +
        // endpoint + credentials) must stay inside the window, not resize it.
        ScrollView {
            VStack(spacing: 20) {
                header
                // Directly under the Connect row it's warning about — a pre-emptive
                // "this network couldn't reach it last time" is useless below the fold.
                // Hidden once a session is live: the warning is about STARTING one, and
                // success is what clears the memory anyway. Keyed on the warning text so
                // switching networks fades the old one out rather than snapping.
                if !UI.isActive(profile.status), !vpn.isReconfiguring(profile.id),
                   let warning = netMemory.knownUnreachableHere(profile: profile.id) {
                    UnreachableHereBanner(vpnName: profile.name, networkLabel: warning) {
                        netMemory.clear(profile: profile.id)
                    }
                    .transition(reduceMotion ? AnyTransition.opacity
                                             : AnyTransition(.blurReplace))
                    .animation(reduceMotion ? nil : .snappy(duration: 0.3), value: warning)
                }
                if vpn.hasPendingSettings(id: profile.id) {
                    PendingSettingsNotice(vpn: vpn, profileID: profile.id)
                }
                ConnectionManagerPanel(vpn: vpn, profileID: profile.id, vpnName: profile.name,
                                       snapshot: doctorSnapshot, findings: doctorFindings)
                // The endpoint picker (and its little map) lives HERE, always — one
                // fixed home below the Connection Manager. It used to appear in the
                // middle column when disconnected and in the inspector when live, which
                // put a second world map under the topology one.
                EndpointSection(vpn: vpn, profile: profile)
                Divider()
                if UI.isActive(profile.status) || vpn.isReconfiguring(profile.id) {
                    connectedBody
                } else {
                    if let incident = vpn.incidents[profile.id] {
                        ConnectionIncidentCard(vpn: vpn, profile: profile, incident: incident,
                                               host: probeHost, port: probePort, speaksTLS: probeSpeaksTLS)
                    }
                    if usesManager { managerForm } else { credentialForm }
                }
            }
            .padding(24)
            .frame(maxWidth: .infinity, alignment: .leading)
        }
        .frame(minWidth: 440)
        .navigationTitle(profile.name)
        .disabled(busy)
        .task { loadOnce() }
        // NetworkMemory now watches the path itself, so this is only the initial read;
        // switching Wi-Fi updates it without any view having to notice.
        .task(id: profile.id) { await netMemory.refresh() }

        .task(id: UI.isActive(profile.status)) {
            // "Appears from" flips when the tunnel comes up or goes away. Throughput
            // is served by the shared app-wide store, so there's no per-view poller.
            await publicIP.refresh()
        }
        .task(id: isStalled) {
            // A live stall at the ~1400-byte boundary is the MTU-blackhole signal.
            // Size the path once so the Doctor can offer an exact mssfix.
            if isStalled { await vpn.measurePathMTU(host: probeHost, for: profile.id) }
        }
        // "Connecting" that never resolves is the common wrong-network case: say so
        // after a grace period instead of spinning silently for ever.
        .task(id: profile.status) {
            connectingTooLong = false
            guard profile.status == .connecting else { return }
            try? await Task.sleep(for: .seconds(20))
            if !Task.isCancelled, profile.status == .connecting { connectingTooLong = true }
        }
    }

    /// Stall/captive-portal/pause aware dot state for this VPN's header badge.
    private var headerDotState: DotState {
        if let link { return link.dot(for: profile.id) }
        let stalled = reach?.isStalled(profile.id) == true
        return .from(status: profile.status,
                     stalled: stalled && pauseMode == nil,   // paused stall is expected
                     captive: vpn.captivePortalSuspected && vpn.incidents[profile.id] != nil,
                     paused: pauseMode != nil)
    }

    // Connect/disconnect lives here, in the header, local to this VPN — not a global button.
    private var header: some View {
        HStack(spacing: 14) {
            LogoBadge(id: profile.id, status: profile.status, dotState: headerDotState)
                .scaleEffect(1.6).frame(width: 40, height: 40)
            VStack(alignment: .leading, spacing: 3) {
                Text(profile.name).font(.title2).bold()
                if UI.isActive(profile.status) && pauseMode == nil {
                    // Show the app-wide reachability judgement (same source the
                    // sidebar dot and menu bar use) so they never disagree; fall
                    // back to the local monitor before the app-wide one has sampled.
                    ReachabilityPill(health: reach?.health(for: profile.id) ?? .healthy)
                } else if !profile.server.isEmpty {
                    Text(profile.server).foregroundStyle(.secondary)
                }
            }
            Spacer()
            connectControl
        }
        // Ease the whole header (badge state, reachability pill ⇄ server line) when
        // the connection or pause state flips, so nothing pops.
        .animation(stateEase, value: UI.isActive(profile.status))
        .animation(stateEase, value: pauseMode)
    }

    // The whole connect lifecycle lives in one Liquid-Glass control that morphs
    // between states — Connect → a tinted "Connecting…" glass pill → the live
    // Pause/Disconnect cluster → "Disconnecting…" → back to Connect — so a state
    // change reads as one continuous transformation, not a hard cut. Transient
    // states are tinted by DotState so colour alone signals what's happening.
    @ViewBuilder private var connectControl: some View {
        GlassEffectContainer(spacing: 8) {
            connectControlContent
        }
        .animation(stateEase, value: profile.status)
        .animation(stateEase, value: vpn.isReconfiguring(profile.id))
        .animation(stateEase, value: pauseMode)
    }

    @ViewBuilder private var connectControlContent: some View {
        if vpn.isReconfiguring(profile.id) {
            workingPill("Applying…", tint: .orange)
                .transition(.blurReplace)
        } else {
            connectControlForStatus
                .transition(.blurReplace)
        }
    }

    @ViewBuilder private var connectControlForStatus: some View {
        switch profile.status {
        case .connected, .reasserting:
            HStack(spacing: 8) {
                if pauseMode != nil {
                    Button("Resume") { Task { await vpn.resume(id: profile.id) } }
                        .buttonStyle(.glassProminent).controlSize(.large)
                        .transition(.blurReplace)
                } else {
                    PauseControl(height: 32,
                                 onBlock: { Task { await vpn.pause(id: profile.id, mode: .hold) } },
                                 onRouteAround: { Task { await vpn.pause(id: profile.id, mode: .bypass) } })
                        .transition(.blurReplace)
                }
                trailingStopButton
            }
        case .connecting, .disconnecting:
            HStack(spacing: 8) {
                workingPill(VPNController.statusText(profile.status),
                            tint: profile.status == .connecting ? .yellow : .orange)
                // Connecting must always be escapable. OpenVPN retries a gateway it
                // can't reach indefinitely (wrong Wi-Fi, no route to the
                // concentrator), so without this the UI is a dead end.
                if profile.status == .connecting { trailingStopButton }
            }
        default:   // disconnected / invalid
            connectButton
        }
    }

    /// A tinted Liquid-Glass pill for the transient connecting/applying states, so
    /// the control keeps a glass shape (and colour) across the whole transition
    /// instead of collapsing to bare text.
    /// ONE trailing control across the whole lifecycle: ✕ while connecting, ■ once
    /// up. Same view identity + the same glassEffectID, so the glass shape matches
    /// geometry and the glyph replaces in place — it visibly becomes the stop button
    /// when the connection succeeds, rather than one control vanishing and another
    /// appearing. Both do the same thing (stopVPNTunnel), which is why it's one view.
    private var trailingStopButton: some View {
        let connecting = profile.status == .connecting
        return Button { vpn.disconnect(id: profile.id) } label: {
            // Filled glyphs both: a bare "xmark" in a glass capsule reads as the LETTER
            // x rather than a cancel control.
            Image(systemName: connecting ? "xmark.circle.fill" : "stop.fill")
                .contentTransition(.symbolEffect(.replace))
        }
        .buttonStyle(.glass).controlSize(.large)
        // Red-ish, not red: full-saturation red read as "destructive/danger" on a glass
        // capsule this size, but plain grey lost the signal that this button stops
        // something. A softened red keeps the meaning without the alarm. The real stop
        // (once connected) keeps full red, matching its stop glyph.
        .tint(connecting ? UI.cancelRed : .red)
        .glassEffectID("trailing-stop", in: connectGlass)
        .help(connecting ? "Cancel connecting" : "Disconnect")
        .accessibilityLabel(connecting ? "Cancel connecting" : "Disconnect")
    }

    private func workingPill(_ text: String, tint: Color) -> some View {
        HStack(spacing: 7) {
            DrawnSpinner()
            // Never wrap: "Connecting…" broke onto two lines in the middle pane, which
            // made the pill twice as tall as the control beside it.
            Text(text).foregroundStyle(.secondary)
                .lineLimit(1)
                .fixedSize(horizontal: true, vertical: false)
        }
        .padding(.horizontal, 14).padding(.vertical, 8)
        .glassEffect(.regular.tint(tint.opacity(0.22)), in: .capsule)
    }

    private var connectButton: some View {
        // Resolving credentials can take real time — a password manager may be locked, or
        // waiting on Touch ID — and `.disabled(busy)` alone made the button look broken:
        // greyed out, no motion, no explanation. Show that work is happening instead.
        if busy {
            return AnyView(HStack(spacing: 8) {
                workingPill(credentialKind == .manual ? "Connecting\u{2026}"
                                                     : "Asking \(credentialKind.displayName)\u{2026}",
                            tint: .yellow)
                // Escapable, like every other wait in this app: cancelling kills the
                // credential lookup (the op subprocess included), not just the spinner.
                Button { connectTask?.cancel() } label: {
                    Image(systemName: "xmark.circle.fill")
                }
                .buttonStyle(.glass).controlSize(.large).tint(UI.cancelRed)
                .help("Stop asking for credentials")
                .accessibilityLabel("Cancel credential lookup")
            })
        }
        // When macOS hasn't granted permission yet, "Connect" is a button that cannot
        // work — pressing it can only fail. Say what the next step actually is instead.
        // Wording avoids "system extension" entirely: that's our implementation detail,
        // not something a person wanting their work VPN should have to learn.
        if ext?.needsApproval == true, ext?.isActivated == false {
            return AnyView(
                Button("Allow VPN Access\u{2026}") {
                    Task { await ext?.activate() }
                }
                .buttonStyle(.glassProminent).controlSize(.large)
                .help("macOS needs your permission before SimpleVPN can make VPN connections")
            )
        }
        return AnyView(
            Button("Connect") { connectTask = Task { await connect() } }
                .buttonStyle(.glassProminent).controlSize(.large).disabled(!canConnect)
        )
    }

    /// Effective probe target with overrides applied (what a connect would use).
    private var probeHost: String {
        let overrides = vpn.overrides(for: profile.id)
        if let s = overrides.server { return s }
        let eval = vpn.ovpnText(id: profile.id).map { evaluator.evaluation(for: $0) }
        return eval?.remoteHostOrNil ?? profile.server
    }
    private var probePort: Int {
        let overrides = vpn.overrides(for: profile.id)
        if let p = overrides.port { return p }
        let eval = vpn.ovpnText(id: profile.id).map { evaluator.evaluation(for: $0) }
        return eval?.remotePortOrNil ?? 1194
    }
    private var probeSpeaksTLS: Bool {
        let overrides = vpn.overrides(for: profile.id)
        if let p = overrides.proto { return p == .tcp }
        let eval = vpn.ovpnText(id: profile.id).map { evaluator.evaluation(for: $0) }
        return eval?.remoteProto.lowercased().hasPrefix("tcp") ?? false
    }

    /// While connected the middle column carries only status banners — the live
    /// graph, map and details live in the inspector (third) column.
    @ViewBuilder private var connectedBody: some View {
        VStack(alignment: .leading, spacing: 16) {
            if profile.status == .connecting, connectingTooLong {
                StuckConnectingBanner(vpnName: profile.name, host: probeHost) {
                    vpn.disconnect(id: profile.id)
                }
            }
            if let mode = pauseMode {
                PausedBanner(mode: mode) { Task { await vpn.resume(id: profile.id) } }
            } else if profile.status == .reasserting {
                LinkInterruptionBanner(reconnects: reach?.stats(for: profile.id)?.reconnects ?? 0)
            } else if case .stalled(let seconds) = reach?.health(for: profile.id) {
                LinkStalledBanner(seconds: seconds)
            }
        }
        .frame(maxWidth: .infinity, alignment: .leading)
    }

    /// Manager-source form: credentials come from 1Password / Apple Passwords on
    /// connect. Only shows an OTP field when the manager can't supply one.
    private var managerForm: some View {
        VStack(alignment: .leading, spacing: 12) {
            Label("Credentials come from \(credentialKind.displayName).",
                  systemImage: credentialKind.systemImage)
                .foregroundStyle(.secondary)
            if managerNeedsTypedOTP {
                Grid(alignment: .leading, horizontalSpacing: 12, verticalSpacing: 10) {
                    GridRow {
                        Text("OTP").gridColumnAlignment(.trailing).foregroundStyle(.secondary)
                        TextField("One-time passcode", text: otp)
                            .textContentType(.oneTimeCode)
                            .focused($focusedField, equals: .otp)
                            .requiredEmphasis(missing: otp.wrappedValue.isEmpty, attempted: submitAttempted)
                            .onSubmit(attemptConnect)
                    }
                }
                .textFieldStyle(.roundedBorder)
                .frame(maxWidth: 380)
            }
            Text(credentialKind == .onePassword
                 ? "1Password will ask for Touch ID when you connect."
                 : "macOS will ask permission to read the saved password the first time.")
                .font(.caption).foregroundStyle(.secondary)
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .onAppear { if managerNeedsTypedOTP { focusedField = .otp } }
    }

    // Inline credentials so you can connect straight from here (Remember saves them).
    private var credentialForm: some View {
        VStack(alignment: .leading, spacing: 14) {
            Grid(alignment: .leading, horizontalSpacing: 12, verticalSpacing: 10) {
                GridRow {
                    Text("Username").gridColumnAlignment(.trailing).foregroundStyle(.secondary)
                    TextField("Username", text: username)
                        .textContentType(.username)
                        .focused($focusedField, equals: .username)
                        .requiredEmphasis(missing: username.wrappedValue.isEmpty, attempted: submitAttempted)
                        .onSubmit(attemptConnect)
                }
                GridRow {
                    Text("Password").gridColumnAlignment(.trailing).foregroundStyle(.secondary)
                    SecureField("Password", text: password)
                        .textContentType(.password)
                        .focused($focusedField, equals: .password)
                        .requiredEmphasis(missing: password.wrappedValue.isEmpty, attempted: submitAttempted)
                        .onSubmit(attemptConnect)
                }
                if requiresOTP {
                    GridRow {
                        Text("OTP").gridColumnAlignment(.trailing).foregroundStyle(.secondary)
                        TextField("One-time passcode", text: otp)
                            .textContentType(.oneTimeCode)
                            .focused($focusedField, equals: .otp)
                            .requiredEmphasis(missing: otp.wrappedValue.isEmpty, attempted: submitAttempted)
                            .onSubmit(attemptConnect)
                    }
                }
            }
            .textFieldStyle(.roundedBorder)
            .frame(maxWidth: 380)

            if allowPasswordSave {
                Toggle("Remember username & password", isOn: remember)
                    .toggleStyle(.checkbox)
            } else {
                Label("This VPN's administrator doesn't allow saving the password.",
                      systemImage: "key.slash")
                    .font(.caption).foregroundStyle(.secondary)
            }

            Text(requiresOTP
                 ? "Credentials are stored in your Keychain. The one-time passcode is used once and never stored."
                 : "Credentials are stored in your Keychain. Manage this VPN in the Manage VPNs window.")
                .font(.caption).foregroundStyle(.secondary)
        }
        .frame(maxWidth: .infinity, alignment: .leading)
        .onAppear {
            // Cursor lands in the first field that actually needs typing.
            focusedField = firstMissingField
        }
    }

    private var firstMissingField: CredentialField? {
        let c = vpn.transientCredentials(for: profile.id)
        return c.username.isEmpty ? .username
             : c.password.isEmpty ? .password
             : requiresOTP ? .otp : nil
    }

    private func attemptConnect() {
        if canConnect {
            Task { await connect() }
        } else {
            // Draw the eye to what's missing, and put the cursor there.
            submitAttempted = true
            focusedField = firstMissingField
        }
    }

    private func loadOnce() {
        guard !loaded else { return }
        loaded = true
        // Materialize the shared credential state (prefills from the keychain)
        // so every surface sees the same values from here on.
        vpn.transientCreds[profile.id] = vpn.transientCredentials(for: profile.id)
    }

    private func connect() async {
        busy = true; defer { busy = false }
        submitAttempted = false
        // (allowsPasswordSaveEvaluator is wired once at app launch — see SimpleVPNApp.)
        do {
            try await vpn.connectUsingConfiguredSource(
                id: profile.id,
                typedOTP: vpn.transientCredentials(for: profile.id).otp)
        } catch is CancellationError {
            // The user backed out — that's an outcome, not an error to report.
        } catch { vpn.lastError = error.localizedDescription }
    }
}

// MARK: - Inspector column (live telemetry)

/// The third column: everything that's alive while connected — the up/down graph,
/// the world map with great-circle arcs to the endpoint, the railroad diagram and
/// the full connection details. Its own 1 Hz poller so it's independent of the
/// controls column. Shows a friendly placeholder when the VPN isn't connected.
private struct ConnectionInspectorView: View {
    @Bindable var vpn: VPNController
    let profile: VPNController.Profile
    @Environment(PublicIPMonitor.self) private var publicIP
    @Environment(ReachabilityMonitor.self) private var reach: ReachabilityMonitor?
    @State private var showTrafficLog = false

    private var pauseMode: VPNController.PauseMode? { vpn.pausedProfiles[profile.id] }
    private var live: Bool { UI.isActive(profile.status) || vpn.isReconfiguring(profile.id) }

    var body: some View {
        ScrollView {
            if live {
                VStack(alignment: .leading, spacing: 16) {
                    HStack {
                        // Shared, app-wide throughput store → the graph keeps its
                        // history and never restarts empty on reopen.
                        ThroughputReadout(inRate: reach?.inRate(for: profile.id) ?? 0,
                                          outRate: reach?.outRate(for: profile.id) ?? 0)
                        Button { showTrafficLog = true } label: { Label("Traffic Log", systemImage: "list.bullet.rectangle") }
                            .controlSize(.small)
                    }
                    // ONE traffic graph. There used to be two stacked here — this VPN's
                    // tunnel counters, then a per-interface chart — which asked the user
                    // to reconcile two different pictures of the same traffic. The
                    // interface chart is the general case (it plots this VPN by default
                    // and can add any other connection), so it's the one that stays.
                    InterfaceTrafficView()
                    WorldMapView(vpn: vpn)
                    Divider()
                    ConnectionInfoPanel(stats: reach?.stats(for: profile.id), clientLabel: profile.server,
                                        publicIP: publicIP,
                                        paused: pauseMode != nil,
                                        bypassing: pauseMode == .bypass)
                }
                .padding(20)
                .frame(maxWidth: .infinity, alignment: .leading)
            } else {
                ContentUnavailableView("Live Details",
                    systemImage: "chart.line.uptrend.xyaxis",
                    description: Text("Connect \(profile.name) to see live traffic, the map and connection details."))
                    .padding(.top, 60)
            }
        }
        .navigationTitle("")
        .sheet(isPresented: $showTrafficLog) {
            TrafficLogView(vpn: vpn, profileID: profile.id, vpnName: profile.name)
        }
    }
}

/// Pre-emptive warning: this VPN has already failed to be reachable from the network
/// we're on now, so say so BEFORE the user clicks Connect and waits out the timeout
/// again. Cleared automatically the moment it does connect from here (see
/// NetworkMemory), and dismissable by hand for when the network has been fixed.
private struct UnreachableHereBanner: View {
    let vpnName: String
    let networkLabel: String
    let forget: () -> Void

    var body: some View {
        HStack(alignment: .top, spacing: 10) {
            Image(systemName: "wifi.exclamationmark").font(.title3).foregroundStyle(.orange)
            VStack(alignment: .leading, spacing: 3) {
                Text("\(vpnName) couldn't be reached from this network before")
                    .font(.callout.weight(.semibold))
                // "You can still TRY" — the honest verb. "You can still connect" promised the
                // very outcome this banner exists to warn is unlikely.
                Text("Last time you tried on \(networkLabel), it never answered. You can still try to connect — if it succeeds, this warning clears itself.")
                    .font(.callout).foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }
            Spacer(minLength: 8)
            Button("Forget", action: forget)
                .buttonStyle(.glass)
                .help("Stop warning about this network")
        }
        .padding(12)
        .background(.orange.opacity(0.12), in: RoundedRectangle(cornerRadius: 10))
    }
}

/// A connect attempt that isn't getting anywhere. The usual cause is being on a
/// network that can't reach the gateway at all (wrong Wi-Fi, guest network, captive
/// portal) — and because the engine retries for ever, nothing would otherwise tell
/// the user that. Names the host it's trying and offers the way out.
private struct StuckConnectingBanner: View {
    let vpnName: String
    let host: String
    let cancel: () -> Void

    var body: some View {
        HStack(alignment: .top, spacing: 10) {
            Image(systemName: "wifi.exclamationmark").font(.title3).foregroundStyle(.orange)
            VStack(alignment: .leading, spacing: 3) {
                Text("Still trying to reach \(vpnName)").font(.callout.weight(.semibold))
                Text("No answer from \(host) yet. This usually means the network you're on can't reach it — a different Wi-Fi, a guest network, or a sign-in page in the way.")
                    .font(.callout).foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }
            Spacer(minLength: 8)
            Button("Cancel", action: cancel).buttonStyle(.glass)
        }
        .padding(12)
        .background(.orange.opacity(0.12), in: RoundedRectangle(cornerRadius: 10))
    }
}

/// Paused state banner. Hold is calm; bypass is deliberately loud — traffic is
/// leaving the Mac outside the VPN and the user must never forget it.
private struct PausedBanner: View {
    let mode: VPNController.PauseMode
    let resume: () -> Void

    var body: some View {
        HStack(spacing: 10) {
            Image(systemName: mode == .bypass ? "road.lane.arrowtriangle.2.inward" : "pause.circle.fill")
                .font(.title3)
                .foregroundStyle(mode == .bypass ? .white : Color.accentColor)
            VStack(alignment: .leading, spacing: 2) {
                Text(mode == .bypass ? "Paused — traffic is NOT going through the VPN"
                                     : "Paused — traffic is blocked until you resume")
                    .bold()
                    .foregroundStyle(mode == .bypass ? .white : .primary)
                Text(mode == .bypass
                     ? "Everything uses your normal connection and is visible to the local network."
                     : "The secure session is kept, so resuming won't ask you to sign in again.")
                    .font(.callout)
                    .foregroundStyle(mode == .bypass ? .white.opacity(0.9) : .secondary)
            }
            Spacer()
            Button("Resume", action: resume)
                .buttonStyle(.borderedProminent)
                .tint(mode == .bypass ? .white : .accentColor)
                .foregroundStyle(mode == .bypass ? .red : .white)
        }
        .padding(12)
        .background(mode == .bypass ? AnyShapeStyle(Color.red) : AnyShapeStyle(.quaternary),
                    in: RoundedRectangle(cornerRadius: 10))
        .accessibilityElement(children: .combine)
    }
}

/// The "fill in this required field" emphasis: quiet until the user actually
/// tries to connect, then a soft accent ring around each still-empty required
/// field (the closest native idiom — no dedicated Liquid Glass component exists).
private struct RequiredFieldEmphasis: ViewModifier {
    let missing: Bool
    let attempted: Bool
    private var active: Bool { missing && attempted }

    func body(content: Content) -> some View {
        content
            .overlay(
                RoundedRectangle(cornerRadius: 6)
                    .strokeBorder(Color.accentColor.opacity(active ? 0.8 : 0), lineWidth: 2)
                    .animation(.easeInOut(duration: 0.25), value: active)
            )
            .accessibilityValue(active ? "Required" : "")
    }
}

private extension View {
    func requiredEmphasis(missing: Bool, attempted: Bool) -> some View {
        modifier(RequiredFieldEmphasis(missing: missing, attempted: attempted))
    }
}
