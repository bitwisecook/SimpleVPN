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
import AppKit
import os

/// Settings key: open the live-details (inspector) pane when the window opens.
let inspectorDefaultsKey = "ui.inspectorOpenByDefault"

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
    @Environment(\.accessibilityReduceMotion) private var reduceMotion
    @State private var showImporter = false
    /// The right-hand live-details pane. Closed by default (simple window);
    /// the Settings toggle changes the launch state, the toolbar button the moment.
    @AppStorage(inspectorDefaultsKey) private var inspectorOpenByDefault = false
    @State private var showInspector = false
    /// The window's width from just BEFORE the inspector opens. AppKit is supposed
    /// to grow the window for `.inspector` and shrink it back on dismiss, but the
    /// shrink-back half is unreliable (the window is left enlarged after toggling
    /// the pane off) — so the pre-inspector width is captured here and force-
    /// restored right after the pane closes, in `restoreWindowWidthAfterInspectorToggle`,
    /// overriding whatever (wider) frame AppKit actually settled on.
    @State private var widthBeforeInspector: CGFloat?
    /// Sidebar visibility — starts closed when there's only one VPN (a list of
    /// one is noise); the standard sidebar toolbar button reopens it.
    @State private var columnVisibility: NavigationSplitViewVisibility = .automatic
    /// Crashes found at launch, offered once (see CrashDiagnostics).
    @State private var pendingCrashes: [CrashReport] = []
    @State private var showCrashReport = false
    /// The failure currently explained by the error sheet (mirror of
    /// VPNController.presentedFailure — see the .onChange below).
    @State private var shownFailure: UserFacingError?

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
            // (SSO sign-in requests raise the in-app window from app scope now —
            // see SSOWindowOpener in SimpleVPNApp — so they surface even when
            // this window is closed.)
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
            // Failures get a real explanation, not a raw string in an alert box:
            // title, one sentence, the numbered steps that fix it, and the
            // underlying text behind a disclosure (see UserFacingErrorSheet).
            // `presentedFailure` withholds it when the incident card is already
            // reporting the same event, so nothing is ever said twice.
            //
            // Mirrored into @State rather than bound straight through: reading
            // the controller inside onChange is what registers the observation
            // dependency, and `initial` catches a failure raised from the menu
            // bar before this window's content existed.
            .onChange(of: vpn.presentedFailure, initial: true) { _, failure in
                shownFailure = failure
            }
            .sheet(item: Binding(get: { shownFailure },
                                 set: { new in
                                     // Only a dismissal of the error STILL being
                                     // reported clears it — a retry that already
                                     // failed again must keep its new one.
                                     if new == nil, let shown = shownFailure, vpn.failure?.id == shown.id {
                                         vpn.clearFailure()
                                     }
                                     shownFailure = new
                                 })) { failure in
                UserFacingErrorSheet(
                    error: failure,
                    // The id is captured now: retrying clears the failure (which
                    // is what dismisses this sheet), so it can't be looked up later.
                    retry: vpn.failureProfileID.map { id in
                        { Task { await vpn.retryConnect(id: id) } }
                    },
                    openWindow: { openWindow(id: $0) })
            }
    }

    @ViewBuilder private var content: some View {
        // The extension's state no longer gates the whole window. It used to open on
        // "System Extension Required", which is a demand made before the user has any
        // reason to care; approval is now asked for at the first connect, and only a
        // PENDING approval (one the user has already been shown) is worth a banner.
        // The three startup states cross-fade into each other (dropping a config
        // morphs the empty page into the real window) rather than hard-cutting.
        Group {
            if ext.needsApproval && !ext.isActivated {
                ActivationPrompt(ext: ext)
                    .transition(reduceMotion ? AnyTransition.opacity : AnyTransition(.blurReplace))
            } else if vpn.profiles.isEmpty && !(tunnelManager?.hasActive ?? false) && !nativeBackendActive {
                EmptyVPNsPrompt(importAction: { showImporter = true },
                                manageAction: { openWindow(id: "manage") },
                                dropAction: { vpn.handleImport(of: $0) })
                    .transition(reduceMotion ? AnyTransition.opacity : AnyTransition(.blurReplace))
            } else {
                splitView
                    .transition(reduceMotion ? AnyTransition.opacity : AnyTransition(.blurReplace))
            }
        }
        .animation(reduceMotion ? nil : .smooth(duration: 0.4), value: vpn.profiles.isEmpty)
        .animation(reduceMotion ? nil : .smooth(duration: 0.4), value: ext.isActivated)
    }

    private var splitView: some View {
        // Two columns + a real inspector (not a third split column): the live
        // telemetry pane is optional detail, closed by default to keep the window
        // simple. Its trailing home and content are unchanged — only whether it's
        // open is new.
        NavigationSplitView(columnVisibility: $columnVisibility) {
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
        } detail: {
            Group {
                if let p = vpn.selected {
                    ConnectionDetailView(vpn: vpn, profile: p).id(p.id)
                } else {
                    ContentUnavailableView("Select a VPN", systemImage: "network")
                }
            }
            .inspector(isPresented: $showInspector) {
                Group {
                    if let p = vpn.selected {
                        ConnectionInspectorView(vpn: vpn, profile: p).id(p.id)
                    } else {
                        ContentUnavailableView("Live Details", systemImage: "chart.line.uptrend.xyaxis",
                            description: Text("Connect a VPN to see live traffic, the map and connection details."))
                    }
                }
                .inspectorColumnWidth(min: 320, ideal: 380)
            }
            .toolbar {
                ToolbarItem {
                    Button { showInspector.toggle() } label: { Image(systemName: "sidebar.trailing") }
                        .help(showInspector ? "Hide live details" : "Show live details — traffic, map and connection info")
                }
            }
        }
        // No version subtitle: "ext unavailable" read as a problem when it just
        // means disconnected, and versions live in About + every diagnostic capture.
        .task {
            // Startup shape, applied once: the inspector follows its setting, and
            // a lone VPN doesn't need a list of one — the sidebar starts closed
            // (the toolbar button still opens it). Never touched again after
            // launch, so the user's own toggling always wins.
            showInspector = inspectorOpenByDefault
            if vpn.profiles.count <= 1 { columnVisibility = .detailOnly }
        }
        .onChange(of: showInspector) { _, isShowing in
            restoreWindowWidthAfterInspectorToggle(isShowing: isShowing)
        }
    }

    /// See `widthBeforeInspector` for why this exists. Captures the width just
    /// before the pane opens; on close, force-restores it — asynchronously, so
    /// AppKit's own (partial) resize gets a chance to run first, and this simply
    /// corrects whatever it left the frame at rather than fighting it mid-flight.
    private func restoreWindowWidthAfterInspectorToggle(isShowing: Bool) {
        guard let window = NSApp.keyWindow ?? NSApp.mainWindow else { return }
        if isShowing {
            widthBeforeInspector = window.frame.width
        } else if let target = widthBeforeInspector {
            DispatchQueue.main.async {
                var frame = window.frame
                guard frame.width > target else { return }   // already restored / narrower
                frame.size.width = target
                window.setFrame(frame, display: true, animate: !reduceMotion)
            }
        }
    }

    private func importConfig(_ result: Result<URL, Error>) {
        guard case let .success(url) = result else { return }
        vpn.handleImport(of: [url])
    }

    /// Right-click actions on a sidebar VPN: the whole lifecycle plus settings.
    @ViewBuilder private func sidebarMenu(_ p: VPNController.Profile) -> some View {
        if UI.isActive(p.status) {
            if vpn.pausedProfiles.contains(p.id) {
                Button("Resume") { Task { await vpn.resume(id: p.id) } }
            } else if p.status == .connected, vpn.uiPrefs(for: p.id).allowPause {
                Button("Pause") { Task { await vpn.pause(id: p.id) } }
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
        ProbeVPNMenuItem(vpn: vpn, profile: p)
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
                .buttonStyle(.glassProminent)
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
    @Environment(\.accessibilityReduceMotion) private var reduceMotion
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
                // No format lecture up front: the import pipeline detects the
                // type itself (ConfigDetector — OpenVPN / WireGuard / Cisco).
                Text("Drop a configuration file here, import one, or add a VPN by hand. The type is worked out automatically.")
            } actions: {
                Button("Import Configuration…", action: importAction).buttonStyle(.glassProminent)
                Button("Add VPN…", action: manageAction).buttonStyle(.glass)
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
                    // A tiny periodic wiggle hints "this is a live target" the same
                    // way the OTP shake hints "type here" — quiet, not looping motion.
                    .symbolEffect(.wiggle, options: .repeat(.periodic(delay: 5)),
                                  isActive: !reduceMotion && !targeted)
                Text("Drag a VPN configuration here")
                    .font(.callout).foregroundStyle(.secondary)
                Text("OpenVPN (.ovpn / .conf), WireGuard (.conf), Cisco (.xml / .pcf), or a 1Password item")
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
    /// Bumped to shake the still-empty required fields (Connect clicked too
    /// early, or the sidebar/menu asked us to show what's missing).
    @State private var nudgeTick = 0
    /// First-connect hand-holding: true until a successful connect writes a
    /// baseline (persisted — survives restarts until the setup is PROVEN).
    @State private var neverConnected = false
    @State private var setupDismissed = false
    /// The big green "Connected" banner shrinks to a compact chip beside the
    /// stop button 5s after connecting — the reassurance, then out of the way.
    @State private var bannerCollapsed = false
    @Namespace private var connectedBannerNS

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
    /// Plain state (not @FocusState): focus is bridged into the AppKit-backed
    /// AutoFillFields, which SwiftUI focus can't reach.
    @State private var focusedField: CredentialField?

    private var requiresOTP: Bool { vpn.requiresOTP(for: profile.id) }
    private var allowPasswordSave: Bool {
        vpn.ovpnText(id: profile.id).map { evaluator.evaluation(for: $0).allowPasswordSave } ?? true
    }
    /// Autologin profiles sign in with their certificate — no credentials to
    /// collect, so no form, no gating, no first-connect credential coaching.
    private var isAutologin: Bool {
        vpn.ovpnText(id: profile.id).map { evaluator.evaluation(for: $0).autologin } ?? false
    }
    /// A `USERNAME` userlock: the profile fixes the username, so the form shows
    /// it read-only and Connect never waits on it.
    private var lockedUsername: String {
        vpn.ovpnText(id: profile.id).map { evaluator.evaluation(for: $0).userlockedUsername } ?? ""
    }
    private var isPaused: Bool { vpn.pausedProfiles.contains(profile.id) }
    private var isStalled: Bool { reach?.isStalled(profile.id) == true }
    /// This VPN's opt-in advanced controls (pause button, Connection Manager).
    private var uiPrefs: VPNUIPrefs { vpn.uiPrefs(for: profile.id) }
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
    /// Protection can only start once there's a sign-in to protect.
    private var canEnableProtection: Bool {
        let c = vpn.transientCredentials(for: profile.id)
        if !c.username.isEmpty && !c.password.isEmpty { return true }
        if let saved = KeychainCredentialStore.loadCredentials(profile: profile.id),
           !saved.username.isEmpty, !saved.password.isEmpty { return true }
        return vpn.authConfig(for: profile.id).protectWithBiometrics
    }

    /// The Touch ID toggle: flipping it MOVES the secret between stores (see
    /// VPNController.setBiometricProtection), so the write happens on change,
    /// not on some later save.
    private var protectBinding: Binding<Bool> {
        Binding(get: { vpn.authConfig(for: profile.id).protectWithBiometrics },
                set: { on in
                    Task {
                        do { try await vpn.setBiometricProtection(on, for: profile.id) }
                        catch is CancellationError {}
                        catch { vpn.lastError = error.localizedDescription }
                    }
                })
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

    /// Touch ID-protected saved credentials (manual source only).
    private var biometricInfo: (exists: Bool, hasTOTP: Bool) {
        guard !usesManager, vpn.authConfig(for: profile.id).protectWithBiometrics else { return (false, false) }
        return BiometricCredentialStore.info(profile: profile.id)
    }
    private var isProtected: Bool { biometricInfo.exists }

    /// Enabled exactly when the shared readiness decision says so — the SAME
    /// source of truth the sidebar play button and menu row read, so the two
    /// controls can never disagree (Tailscale/autologin/proxy included).
    private var canConnect: Bool {
        vpn.connectReadiness(for: profile.id) == .ready
    }

    var body: some View {
        // Scroll rather than grow: a long detail (Doctor cards + incident +
        // endpoint + credentials) must stay inside the window, not resize it.
        ScrollView {
            VStack(spacing: 20) {
                header
                // Default-gateway picker (PolicyRouting.md Tier 2) moved OUT of this
                // window — too prominent for non-technical users to find here. It
                // now lives in VPN ▸ Routes, alongside the route graph and the
                // drift/diff indicators it's naturally paired with (see
                // RouteGraphView's compact `gatewayBar`).
                // Sign-in comes FIRST, directly under the Connect row it feeds —
                // username/password/OTP are what the button is waiting for, so they
                // must not sit below the fold behind panels and pickers.
                if !UI.isActive(profile.status), !vpn.isReconfiguring(profile.id) {
                    // A fresh import knows how to REACH the VPN but nothing about
                    // how you SIGN IN (a gresearch.conf import defaults to plain
                    // username/password — wrong for an OTP gateway, and the user
                    // has no way to know that yet). Hold their hand right here
                    // until the first successful connect proves the setup.
                    // Tailscale has nothing to type: it signs itself in with a
                    // setup key or a browser, so neither the credential form nor
                    // the first-connect credential coaching applies.
                    if profile.kind == .tailscale {
                        tailscalePanel
                    } else if profile.kind == .proxyTunnel {
                        proxyTunnelPanel
                    } else if isAutologin {
                        // Autologin: the profile's certificate signs in by
                        // itself, so there is no credential form to show and
                        // no "how do you sign in" questions to ask.
                        Label("This VPN signs in automatically — no username or password needed.",
                              systemImage: "checkmark.seal")
                            .font(.callout).foregroundStyle(.secondary)
                            .frame(maxWidth: .infinity, alignment: .leading)
                    } else {
                        if neverConnected, !setupDismissed {
                            FirstConnectSetupCard(vpn: vpn, profile: profile,
                                                  dismissed: $setupDismissed.animation(.snappy(duration: 0.25)))
                                .transition(reduceMotion ? AnyTransition.opacity : AnyTransition(.blurReplace))
                        }
                        if usesManager { managerForm } else { credentialForm }
                    }
                    if let incident = vpn.incidents[profile.id] {
                        ConnectionIncidentCard(vpn: vpn, profile: profile, incident: incident,
                                               host: probeHost, port: probePort, speaksTLS: probeSpeaksTLS)
                    }
                }
                // A sign-in page is holding this network's traffic hostage — nothing
                // can connect until the user gets through it, so it outranks the
                // softer "couldn't reach it here before" memory below.
                if !UI.isActive(profile.status), !vpn.isReconfiguring(profile.id),
                   vpn.captivePortalSuspected {
                    CaptivePortalBanner(vpn: vpn)
                        .transition(reduceMotion ? AnyTransition.opacity
                                                 : AnyTransition(.blurReplace))
                }
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
                // Advanced surface, opt-in per VPN (Manage VPNs ▸ this VPN):
                // health checks and connection toggles most people never touch.
                if uiPrefs.showConnectionManager {
                    ConnectionManagerPanel(vpn: vpn, profileID: profile.id, vpnName: profile.name,
                                           snapshot: doctorSnapshot, findings: doctorFindings)
                }
                // Say "connected" in WORDS, not just the dot — a lone red stop
                // button next to a green dot asks the user to know the iconography.
                // Sits above the map; deliberately makes no claims about which
                // traffic is protected (that's the tunnel-mode toggle's story).
                if profile.status == .connected, !vpn.isReconfiguring(profile.id), !isPaused,
                   !bannerCollapsed {
                    ConnectedBanner(vpnName: profile.name, server: profile.server,
                                    uptime: reach?.stats(for: profile.id)?.uptime)
                        .matchedGeometryEffect(id: "connectedChip", in: connectedBannerNS)
                        .transition(reduceMotion ? AnyTransition.opacity : AnyTransition(.blurReplace))
                }
                // The endpoint picker (and its little map) lives HERE, always — one
                // fixed home below the Connection Manager. It used to appear in the
                // middle column when disconnected and in the inspector when live, which
                // put a second world map under the topology one.
                EndpointSection(vpn: vpn, profile: profile)
                if UI.isActive(profile.status) || vpn.isReconfiguring(profile.id) {
                    Divider()
                    connectedBody
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
        // The sidebar play button (and menu bar) land here when this VPN still
        // needs typing: focus the first empty field and shake it. `initial` +
        // consume: a nudge that switched the selection lands before this view
        // exists, so check on appearance too — the one-shot claim keeps a later
        // revisit from replaying it.
        .onChange(of: vpn.credentialNudge[profile.id] ?? 0, initial: true) { _, _ in
            if vpn.consumeCredentialNudge(id: profile.id) { nudgeMissingInput() }
        }
        // A different network means the sign-in-page verdict is stale — drop the
        // banner rather than accusing the new Wi-Fi of the old one's portal.
        .onChange(of: netMemory.current?.key) { _, _ in
            vpn.captivePortalSuspected = false
            vpn.captivePortalURL = nil
        }
        // First-success detection for the setup card: the baseline is written a
        // few seconds after .connected, so re-check on status changes too.
        .task(id: profile.id) {
            neverConnected = ConnectionBaselineStore.load(profile: profile.id) == nil
        }
        .onChange(of: profile.status) { _, new in
            if new == .connected { neverConnected = false }
        }
        // The big "Connected" banner shows for 5s on connect, then shrinks to
        // the header chip. Reset the moment the tunnel isn't cleanly connected.
        .task(id: profile.status) {
            guard profile.status == .connected, !isPaused else {
                bannerCollapsed = false
                return
            }
            try? await Task.sleep(for: .seconds(5))
            guard !Task.isCancelled, profile.status == .connected, !isPaused else { return }
            withAnimation(reduceMotion ? nil : .smooth(duration: 0.45)) { bannerCollapsed = true }
        }
    }

    /// Stall/captive-portal/pause aware dot state for this VPN's header badge.
    private var headerDotState: DotState {
        if let link { return link.dot(for: profile.id) }
        let stalled = reach?.isStalled(profile.id) == true
        return .from(status: profile.status,
                     stalled: stalled && !isPaused,   // paused stall is expected
                     captive: vpn.captivePortalSuspected && vpn.incidents[profile.id] != nil,
                     paused: isPaused)
    }

    // Connect/disconnect lives here, in the header, local to this VPN — not a global button.
    private var header: some View {
        HStack(spacing: 14) {
            LogoBadge(id: profile.id, status: profile.status, dotState: headerDotState)
                .scaleEffect(1.6).frame(width: 40, height: 40)
            VStack(alignment: .leading, spacing: 3) {
                Text(profile.name).font(.title2).bold()
                // A healthy connection says nothing here — good news is the dot's
                // job. The line under the name speaks only when something is
                // wrong (plain English), or shows the server while disconnected.
                if UI.isActive(profile.status) && !isPaused {
                    if let problem = connectionProblem {
                        ProblemPill(text: problem.text, dot: problem.dot)
                    }
                } else if !profile.server.isEmpty {
                    Text(profile.server).foregroundStyle(.secondary)
                }
            }
            Spacer()
            VStack(alignment: .trailing, spacing: 4) {
                connectControl
                // Say WHY Connect is dimmed, pointing at the form directly below.
                if let hint = missingInputHint {
                    Text(hint).font(.caption).foregroundStyle(.secondary)
                }
            }
        }
        // Ease the whole header (badge state, reachability pill ⇄ server line) when
        // the connection or pause state flips, so nothing pops.
        .animation(stateEase, value: UI.isActive(profile.status))
        .animation(stateEase, value: isPaused)
    }

    /// The only states worth a label while connected, in plain English. nil when
    /// everything is fine — the pill disappears rather than saying "Reachable".
    private var connectionProblem: (text: String, dot: DotState)? {
        switch link?.state(for: profile.id) {
        case .captivePortal:
            return ("A sign-in page is in the way", .captivePortal)
        case .stalled(let seconds):
            return (seconds == nil ? "Reconnecting…" : "Not responding", .degraded)
        default:
            // Fallback before LinkStateMonitor exists in the environment.
            if case .stalled = reach?.health(for: profile.id) ?? .healthy {
                return ("Not responding", .degraded)
            }
            return nil
        }
    }

    /// Non-nil while the Connect button is waiting on typed input (and is the
    /// thing on screen). "Verification code" is deliberate — it's the word Apple
    /// uses for one-time codes, so non-technical users recognise it.
    private var missingInputHint: String? {
        guard !busy, !canConnect,
              !UI.isActive(profile.status), profile.status != .connecting,
              profile.status != .disconnecting, !vpn.isReconfiguring(profile.id),
              !(ext?.needsApproval == true && ext?.isActivated == false) else { return nil }
        let c = vpn.transientCredentials(for: profile.id)
        if !usesManager, !isProtected,
           c.username.trimmingCharacters(in: .whitespaces).isEmpty || c.password.isEmpty {
            return "Enter your sign-in below first"
        }
        return "Enter your verification code below first"
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
        .animation(stateEase, value: isPaused)
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
                // The shrunk-down "Connected" chip lands here once the big banner
                // has retired (matchedGeometry morphs one into the other).
                if bannerCollapsed, !isPaused, profile.status == .connected {
                    ConnectedChip()
                        .matchedGeometryEffect(id: "connectedChip", in: connectedBannerNS)
                        .transition(reduceMotion ? AnyTransition.opacity : AnyTransition(.blurReplace))
                }
                if isPaused {
                    Button("Resume") { Task { await vpn.resume(id: profile.id) } }
                        .buttonStyle(.glassProminent).controlSize(.large)
                        .transition(.blurReplace)
                } else if uiPrefs.allowPause {
                    // Opt-in per VPN (Manage VPNs ▸ this VPN): most people never
                    // pause a tunnel, so the default header is just Disconnect.
                    PauseControl(height: 32,
                                 onPause: { Task { await vpn.pause(id: profile.id) } })
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
        // Red-TINTED, not red: a small bright-red capsule read as an alarm. This is
        // the sidebar circles' language at header scale — a 40pt round glass button
        // (matching the 40pt logo badge across the row), softly red-tinted glass
        // with a red glyph. Filled glyphs both: a bare "xmark" reads as the LETTER
        // x rather than a cancel control.
        let tint: Color = connecting ? UI.cancelRed : .red
        return Button { vpn.disconnect(id: profile.id) } label: {
            Image(systemName: connecting ? "xmark.circle.fill" : "stop.fill")
                .font(.title3)
                .contentTransition(.symbolEffect(.replace))
                .frame(width: 40, height: 40)
                .foregroundStyle(tint)
                .contentShape(Circle())
        }
        .buttonStyle(.plain)
        .glassEffect(.regular.tint(tint.opacity(0.25)).interactive(), in: Circle())
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
        // NOT `.disabled(!canConnect)`: a dead button teaches nothing. It LOOKS
        // disabled while input is missing, but a click walks the user to the fix —
        // focus lands on the first empty required field and it gets a little shake.
        return AnyView(
            Button("Connect") {
                if canConnect { connectTask = Task { await connect() } } else { nudgeMissingInput() }
            }
                .buttonStyle(.glassProminent).controlSize(.large)
                .tint(canConnect ? nil : .gray)
                .opacity(canConnect ? 1 : 0.6)
                .accessibilityHint(canConnect ? "" : (missingInputHint ?? ""))
        )
    }

    /// Draw the eye to what's missing: ring + focus + a soft shake.
    private func nudgeMissingInput() {
        submitAttempted = true
        focusedField = firstMissingField
        if reduceMotion { return }   // the focus ring + accent ring carry the message
        withAnimation(.easeInOut(duration: 0.4)) { nudgeTick += 1 }
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
            // A Tailscale connect waiting on the browser sign-in: say so, and
            // keep the URL reachable — a dismissed tab must not be a dead end.
            if profile.status == .connecting, profile.kind == .tailscale,
               vpn.tailscaleSignInURL[profile.id] != nil {
                TailscaleSignInBanner { vpn.openTailscaleSignIn(id: profile.id) }
            }
            if profile.status == .connecting, connectingTooLong,
               vpn.tailscaleSignInURL[profile.id] == nil {   // the sign-in banner already explains the wait
                StuckConnectingBanner(vpnName: profile.name, host: probeHost) {
                    vpn.disconnect(id: profile.id)
                }
            }
            if isPaused {
                PausedBanner { Task { await vpn.resume(id: profile.id) } }
            }
            // No stalled/reconnecting banners here any more: connection state has
            // ONE spot in the window (the header badge + its problem chip). The
            // paused banner stays because it's a safety warning about traffic
            // outside the VPN, not a state duplicate — and pause is opt-in anyway.
        }
        .frame(maxWidth: .infinity, alignment: .leading)
    }

    /// What stands in for the credential form on a Tailscale/Headscale VPN.
    /// Says what will happen rather than asking for something that doesn't
    /// exist, and points at the one place a setup key can be entered.
    @ViewBuilder private var tailscalePanel: some View {
        let status = vpn.tailscaleStatuses[profile.id]
        let signInURL = vpn.tailscaleSignInURL[profile.id]
        VStack(alignment: .leading, spacing: 8) {
            if let status, status.backendState.needsUserAction {
                Label(status.backendState == .needsMachineAuth
                      ? "Waiting for someone to approve this Mac on your network."
                      : "Waiting for you to sign in. The sign-in page should have opened in your browser.",
                      systemImage: "person.badge.key")
                    .foregroundStyle(.orange)
                if status.backendState == .needsLogin {
                    // Re-opens the engine's login URL in the default browser —
                    // the way back when the tab was closed. Disabled until the
                    // engine has actually issued one.
                    Button("Open Sign-In Page") { vpn.openTailscaleSignIn(id: profile.id) }
                        .disabled(signInURL == nil)
                }
            } else if let status, status.backendState == .running {
                Label("This Mac is on the network as \(status.selfDNSName.isEmpty ? status.primaryIPv4 : status.selfDNSName).",
                      systemImage: "checkmark.circle")
                    .foregroundStyle(.secondary)
                if status.peerCount > 0 {
                    Text("\(status.peersOnline) of \(status.peerCount) machines online.")
                        .font(.callout).foregroundStyle(.secondary)
                }
            } else {
                Label("This VPN signs itself in — with a setup key, or by opening a sign-in page the first time.",
                      systemImage: "point.3.connected.trianglepath.dotted")
                    .foregroundStyle(.secondary)
            }
        }
        .font(.callout)
        .frame(maxWidth: .infinity, alignment: .leading)
    }

    /// What stands in for the credential form on a Proxy Tunnel. Says what will
    /// happen and points at the editor for the upstream/credentials, rather than
    /// asking for something the connect row doesn't own.
    @ViewBuilder private var proxyTunnelPanel: some View {
        let config = vpn.proxyTunnelConfig(for: profile.id)
        VStack(alignment: .leading, spacing: 8) {
            if let problem = config.connectProblem {
                Label(problem, systemImage: "exclamationmark.triangle.fill")
                    .foregroundStyle(.orange)
            } else {
                Label("Every connection is dialled through \(config.proxyHost.isEmpty ? "the proxy" : config.proxyHost).",
                      systemImage: "arrow.triangle.branch")
                    .foregroundStyle(.secondary)
                if config.requiresAuth {
                    let creds = vpn.proxyTunnelCredentials(for: profile.id)
                    let ok = !creds.username.isEmpty && !creds.password.isEmpty
                    Label(ok ? "Sign-in details are saved."
                             : "This proxy needs a username and password — add them in this VPN's settings.",
                          systemImage: ok ? "checkmark.circle" : "person.badge.key")
                        .foregroundStyle(ok ? Color.secondary : Color.orange)
                }
            }
        }
        .font(.callout)
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
                        AutoFillField(kind: .oneTimeCode, placeholder: "One-time passcode",
                                      text: otp, focus: $focusedField, focusValue: .otp,
                                      onSubmit: attemptConnect)
                            .requiredEmphasis(missing: otp.wrappedValue.isEmpty, attempted: submitAttempted, nudge: nudgeTick)
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
    @ViewBuilder private var credentialForm: some View {
        if isProtected { protectedForm } else { typedCredentialForm }
    }

    /// The steady state of the fingerprint flow: no fields at all, just the
    /// promise of the prompt. The only field that can appear is the code, and
    /// only for an OTP profile with no stored authenticator secret.
    private var protectedForm: some View {
        VStack(alignment: .leading, spacing: 12) {
            HStack(spacing: 10) {
                Image(systemName: "touchid")
                    .font(.title2)
                    .foregroundStyle(.pink)
                VStack(alignment: .leading, spacing: 2) {
                    Text("Sign-in protected by Touch ID").font(.callout.weight(.semibold))
                    Text(requiresOTP && biometricInfo.hasTOTP
                         ? "Connecting asks for your fingerprint, which unlocks the username, password and one-time code in one go."
                         : "Connecting asks for your fingerprint to unlock the saved sign-in.")
                        .font(.callout).foregroundStyle(.secondary)
                        .fixedSize(horizontal: false, vertical: true)
                }
                Spacer(minLength: 8)
                Menu {
                    Button("Remove Touch ID Protection…") {
                        Task {
                            do { try await vpn.setBiometricProtection(false, for: profile.id) }
                            catch is CancellationError {}
                            catch { vpn.lastError = error.localizedDescription }
                        }
                    }
                } label: {
                    Image(systemName: "ellipsis.circle")
                }
                .menuStyle(.borderlessButton)
                .fixedSize()
                .help("Change how these credentials are stored")
            }
            .padding(12)
            .background(.pink.opacity(0.08), in: RoundedRectangle(cornerRadius: 10))

            if requiresOTP && !biometricInfo.hasTOTP {
                Grid(alignment: .leading, horizontalSpacing: 12, verticalSpacing: 10) {
                    GridRow {
                        Text("Code").gridColumnAlignment(.trailing).foregroundStyle(.secondary)
                        AutoFillField(kind: .oneTimeCode, placeholder: "One-time code",
                                      text: otp, focus: $focusedField, focusValue: .otp,
                                      onSubmit: attemptConnect)
                            .requiredEmphasis(missing: otp.wrappedValue.isEmpty, attempted: submitAttempted, nudge: nudgeTick)
                    }
                }
                .textFieldStyle(.roundedBorder)
                .frame(maxWidth: 380)
                Text("Add your authenticator's setup key in Manage VPNs and the fingerprint will cover the code too.")
                    .font(.caption).foregroundStyle(.secondary)
            }
        }
        .frame(maxWidth: .infinity, alignment: .leading)
    }

    private var typedCredentialForm: some View {
        VStack(alignment: .leading, spacing: 14) {
            Grid(alignment: .leading, horizontalSpacing: 12, verticalSpacing: 10) {
                GridRow {
                    Text("Username").gridColumnAlignment(.trailing).foregroundStyle(.secondary)
                    // A userlocked profile fixes the username: prefilled (see
                    // loadOnce) and read-only, matching the editor's behaviour.
                    AutoFillField(kind: .username, placeholder: "Username",
                                  text: username, focus: $focusedField, focusValue: .username,
                                  onSubmit: attemptConnect)
                        .disabled(!lockedUsername.isEmpty)
                        .requiredEmphasis(missing: username.wrappedValue.isEmpty && lockedUsername.isEmpty,
                                          attempted: submitAttempted, nudge: nudgeTick)
                        .help(lockedUsername.isEmpty ? "" : "This VPN's configuration fixes the username.")
                }
                GridRow {
                    Text("Password").gridColumnAlignment(.trailing).foregroundStyle(.secondary)
                    AutoFillField(kind: .password, placeholder: "Password",
                                  text: password, focus: $focusedField, focusValue: .password,
                                  onSubmit: attemptConnect)
                        .requiredEmphasis(missing: password.wrappedValue.isEmpty, attempted: submitAttempted, nudge: nudgeTick)
                }
                if requiresOTP {
                    GridRow {
                        Text("OTP").gridColumnAlignment(.trailing).foregroundStyle(.secondary)
                        AutoFillField(kind: .oneTimeCode, placeholder: "One-time passcode",
                                      text: otp, focus: $focusedField, focusValue: .otp,
                                      onSubmit: attemptConnect)
                            .requiredEmphasis(missing: otp.wrappedValue.isEmpty, attempted: submitAttempted, nudge: nudgeTick)
                    }
                }
            }
            .textFieldStyle(.roundedBorder)
            .frame(maxWidth: 380)

            if allowPasswordSave {
                Toggle("Remember username & password", isOn: remember)
                    .toggleStyle(.checkbox)
                // The fingerprint upgrade: saved credentials move into a Touch
                // ID-gated keychain item; the plain copy is destroyed. Only
                // offered once there's something to protect.
                Toggle("Protect them with Touch ID", isOn: protectBinding)
                    .toggleStyle(.checkbox)
                    .disabled(!canEnableProtection)
                    .help("Connecting will ask for your fingerprint (or Apple Watch, or your password) to unlock the sign-in.")
                if requiresOTP, vpn.authConfig(for: profile.id).protectWithBiometrics {
                    Text("Tip: add your authenticator's setup key in Manage VPNs so the fingerprint covers the one-time code too.")
                        .font(.caption).foregroundStyle(.secondary)
                }
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
        // Nothing to type at all for these — a nudge must not focus a field
        // that isn't on screen.
        if profile.kind == .tailscale || profile.kind == .proxyTunnel || isAutologin { return nil }
        // The manager/protected forms render at most an OTP field.
        if usesManager { return managerNeedsTypedOTP ? .otp : nil }
        if isProtected { return (requiresOTP && !biometricInfo.hasTOTP) ? .otp : nil }
        let c = vpn.transientCredentials(for: profile.id)
        return (c.username.isEmpty && lockedUsername.isEmpty) ? .username
             : c.password.isEmpty ? .password
             : requiresOTP ? .otp : nil
    }

    private func attemptConnect() {
        if canConnect {
            Task { await connect() }
        } else {
            nudgeMissingInput()
        }
    }

    private func loadOnce() {
        guard !loaded else { return }
        loaded = true
        // Materialize the shared credential state (prefills from the keychain)
        // so every surface sees the same values from here on.
        var creds = vpn.transientCredentials(for: profile.id)
        // A userlocked username always wins — the row is read-only, so a stale
        // saved value could otherwise never be corrected.
        if !lockedUsername.isEmpty { creds.username = lockedUsername }
        vpn.transientCreds[profile.id] = creds
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
        } catch {
            // Log AND alert: an alert can be missed/dismissed, and a connect
            // that dies without a trace is undiagnosable from a capture.
            VPNController.log.error("connect failed for \(profile.id, privacy: .public): \(error.localizedDescription, privacy: .public)")
            // report(profile:) — not lastError — so the sheet's Try Again knows
            // which VPN to re-run, and the redactor knows this profile's secrets.
            vpn.report(error, profile: profile.id)
        }
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

    private var isPaused: Bool { vpn.pausedProfiles.contains(profile.id) }
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
                                        paused: isPaused,
                                        bypassing: isPaused)
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
/// First-connect hand-holding. An imported config describes the TRANSPORT, not
/// the sign-in — so until this VPN has connected successfully once, the main
/// window itself asks the two questions that otherwise ambush people at connect
/// time: "do you also enter a one-time code?" and "where does your sign-in
/// live?" — with the password-manager choice (and its drag-in) right here, no
/// trip to Manage VPNs. Disappears forever after the first proven connect.
private struct FirstConnectSetupCard: View {
    @Bindable var vpn: VPNController
    let profile: VPNController.Profile
    @Binding var dismissed: Bool
    @Environment(\.accessibilityReduceMotion) private var reduceMotion
    /// Marching-ants phase for the drop well (pure Shape drawing — safe).
    @State private var dashPhase: CGFloat = 0
    @State private var apServer = ""
    /// A multi-selection drag, waiting to be narrowed to the one item this VPN
    /// signs in with. Empty = nothing pending.
    @State private var choices: [OnePasswordDrop] = []
    /// The 1Password setup check — run when 1Password is CHOSEN here, never on
    /// appear, and skipped once the integration has been proven to work.
    @State private var preflight = OnePasswordPreflightModel()
    /// Collapses the several deliveries macOS makes of one drag into one apply.
    @State private var drops = OnePasswordDropCollector()

    private var auth: VPNAuthConfig { vpn.authConfig(for: profile.id) }
    private var source: CredentialSource { vpn.credentialSource(for: profile.id) }

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            HStack {
                Label("Before your first connect", systemImage: "hand.wave")
                    .font(.callout.weight(.semibold))
                Spacer()
                Button { dismissed = true } label: { Image(systemName: "xmark") }
                    .buttonStyle(.borderless)
                    .help("Hide until next launch — this card comes back until a connect succeeds")
            }
            Text("The configuration file says how to reach \(profile.name) — but not how you sign in. Two quick questions:")
                .font(.callout).foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)

            Toggle(isOn: otpBinding) {
                VStack(alignment: .leading, spacing: 1) {
                    Text("I also enter a one-time code")
                    Text("A short code from an authenticator app, a key fob, or a text message.")
                        .font(.caption).foregroundStyle(.secondary)
                }
            }
            .toggleStyle(.checkbox)

            Picker("My sign-in is kept", selection: sourceKindBinding) {
                Text("I'll type it in").tag(CredentialSourceKind.manual)
                Text("in 1Password").tag(CredentialSourceKind.onePassword)
                Text("in Apple Passwords").tag(CredentialSourceKind.applePasswords)
            }
            .pickerStyle(.menu)
            .fixedSize()

            switch source.kind {
            case .manual:
                EmptyView()   // the credential form directly below IS the answer
            case .onePassword:
                // Same walkthrough as the editor, in the smaller type this card
                // uses — with the account asked for here, since this card has no
                // Account field of its own to point at.
                OnePasswordSetupCard(model: preflight, compact: true, asksForAccount: true,
                                     onAccount: { useAccount($0) },
                                     onCheckAgain: { checkOnePassword(force: true) })
                onePasswordWell
                Text("Dragging the item itself fills in everything SimpleVPN needs. Dragging one of its fields fills in less.")
                    .font(.caption).foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            case .applePasswords:
                HStack {
                    TextField("Website or server the password is saved for", text: $apServer)
                        .textFieldStyle(.roundedBorder)
                        .autocorrectionDisabled()
                        .onSubmit(saveApplePasswords)
                    Button("Use") { saveApplePasswords() }.buttonStyle(.glass)
                        .disabled(apServer.trimmingCharacters(in: .whitespaces).isEmpty)
                }
                .onAppear {
                    apServer = source.reference.isEmpty ? profile.server : source.reference
                }
            }
        }
        .padding(14)
        .background(.quaternary.opacity(0.45), in: RoundedRectangle(cornerRadius: 12))
        .accessibilityElement(children: .contain)
    }

    /// The drag-in target, with a quiet "things can be dropped here" rhythm:
    /// slowly marching dashes and an occasional key wiggle (both suppressed
    /// under Reduce Motion, and both stop once an item is linked).
    private var onePasswordWell: some View {
        let linked = !source.reference.isEmpty
        return RoundedRectangle(cornerRadius: 8, style: .continuous)
            .strokeBorder(style: StrokeStyle(lineWidth: 1.5, dash: [5], dashPhase: dashPhase))
            .foregroundStyle(linked ? AnyShapeStyle(.tertiary) : AnyShapeStyle(.tint))
            .frame(height: 52)
            .overlay {
                Label(linked ? "Linked to \(linkedName) — drag another item to change"
                             : "Drag the item from 1Password here",
                      systemImage: linked ? "checkmark.circle.fill" : "key.fill")
                    .font(.callout)
                    .foregroundStyle(linked ? AnyShapeStyle(.green) : AnyShapeStyle(.secondary))
                    .symbolEffect(.wiggle, options: .repeat(.periodic(delay: 4)),
                                  isActive: !reduceMotion && !linked)
            }
            .contentShape(Rectangle())
            // 1Password's own drag payload first (it names account, vault AND
            // item), then a link, then op://, then the bare title — see
            // OnePasswordDropItem.
            .onDrop(of: OnePasswordDropItem.acceptedContentTypes, isTargeted: nil) { providers, _ in
                guard OnePasswordDropItem.canAccept(providers) else { return false }
                Task {
                    // Through the collector: macOS delivers one drag more than
                    // once, and applying each delivery turned a single dropped
                    // item into a "which one?" chooser.
                    guard let dropped = await drops.collect(providers),
                          let first = dropped.first else { return }
                    // A VPN signs in with one item; several were dragged, so ask.
                    if dropped.count > 1 { choices = dropped; return }
                    link(first)
                }
                return true
            }
            .popover(isPresented: Binding(get: { !choices.isEmpty },
                                          set: { if !$0 { choices = [] } })) {
                VStack(alignment: .leading, spacing: 8) {
                    Text("Which item is this VPN\u{2019}s sign-in?").font(.callout.weight(.semibold))
                    ForEach(Array(choices.enumerated()), id: \.element.id) { index, drop in
                        Button(drop.displayName(position: index + 1)) { link(drop) }
                            .buttonStyle(.link)
                    }
                }
                .padding(12)
                .frame(minWidth: 220)
            }
            .task(id: linked) {
                guard !reduceMotion, !linked else { return }
                dashPhase = 0
                withAnimation(.linear(duration: 1.8).repeatForever(autoreverses: false)) {
                    dashPhase = -10   // one full dash+gap cycle → seamless march
                }
            }
    }

    private var otpBinding: Binding<Bool> {
        Binding(get: { auth.requiresOTP },
                set: { on in
                    var a = auth
                    a.requiresOTP = on
                    Task { try? await vpn.setAuthConfig(a, for: profile.id) }
                })
    }

    private var sourceKindBinding: Binding<CredentialSourceKind> {
        Binding(get: { source.kind },
                set: { kind in
                    var s = source
                    s.kind = kind
                    Task { try? await vpn.setCredentialSource(s, for: profile.id) }
                    // Choosing 1Password is the first genuine need for a
                    // 1Password lookup — and the only moment this card is
                    // allowed to raise its approval prompt.
                    if kind == .onePassword { checkOnePassword(force: false) }
                })
    }

    /// The setup check. `force` is the Check Again button, which re-checks even
    /// a verified integration — the way back from "it worked yesterday".
    private func checkOnePassword(force: Bool) {
        let account = OnePasswordAccountMemory.effectiveAccount(profile: source.account)
        Task {
            if force { await preflight.check(account: account) }
            else { await preflight.checkIfNeeded(account: account) }
        }
    }

    /// The account name typed into the card's prompt: kept for this VPN, and
    /// checked straight away so the answer lands where the question was asked.
    private func useAccount(_ name: String) {
        var s = source
        s.account = name
        Task {
            try? await vpn.setCredentialSource(s, for: profile.id)
            // A name is only remembered app-wide once it has actually worked —
            // the check itself does that.
            await preflight.check(account: name)
        }
    }

    /// A dragged item is linked by its 1Password id — exact, and immune to
    /// renaming, but not something to read back at anyone.
    private var linkedName: String {
        OnePasswordDrop.looksLikeItemID(source.reference)
            ? "your 1Password item"
            : "\u{201C}\(source.reference)\u{201D}"
    }

    /// Point this VPN's sign-in at a dropped item. The 1Password payload carries
    /// account and vault UUIDs as well as the item's, which is what keeps this
    /// card a one-drag setup — 1Password won't answer without knowing which
    /// account to ask.
    private func link(_ dropped: OnePasswordDrop) {
        choices = []
        var s = source
        s.kind = .onePassword
        s.reference = dropped.reference
        if !dropped.vault.isEmpty { s.vault = dropped.vault }
        if !dropped.account.isEmpty {
            s.account = dropped.account
            // The dragged item names its account, and the SDK takes that UUID as
            // readily as the sidebar name — so one drag answers "which account?"
            // for every other VPN too.
            OnePasswordAccountMemory.seed(dropped.account)
        }
        Task { try? await vpn.setCredentialSource(s, for: profile.id) }
    }

    private func saveApplePasswords() {
        var s = source
        s.kind = .applePasswords
        s.reference = apServer.trimmingCharacters(in: .whitespaces)
        Task { try? await vpn.setCredentialSource(s, for: profile.id) }
    }
}

/// The state, in words: a green "you are connected" banner above the map, for
/// everyone who doesn't speak dot-and-stop-button. Makes no claims about WHICH
/// traffic is protected — that's the tunnel-mode toggle's story.
private struct ConnectedBanner: View {
    let vpnName: String
    let server: String
    let uptime: TimeInterval?

    private var detail: String {
        var bits: [String] = []
        if !server.isEmpty { bits.append(server) }
        if let uptime, uptime >= 1 {
            let d = Duration.seconds(Int(uptime))
            bits.append("connected for \(d.formatted(.units(allowed: [.hours, .minutes, .seconds], width: .abbreviated, maximumUnitCount: 2)))")
        }
        return bits.joined(separator: " \u{00B7} ")
    }

    var body: some View {
        HStack(spacing: 10) {
            Image(systemName: "checkmark.circle.fill").font(.title3).foregroundStyle(.green)
            VStack(alignment: .leading, spacing: 2) {
                Text("Connected to \(vpnName)").font(.callout.weight(.semibold))
                if !detail.isEmpty {
                    Text(detail).font(.callout).foregroundStyle(.secondary)
                        .monospacedDigit()
                }
            }
            Spacer(minLength: 0)
        }
        .padding(12)
        .background(.green.opacity(0.12), in: RoundedRectangle(cornerRadius: 10))
        .accessibilityElement(children: .combine)
    }
}

/// What the big ConnectedBanner shrinks INTO after 5s: a compact green
/// "Connected" pill living beside the stop button, so the header still says in
/// words what the dot says in colour.
private struct ConnectedChip: View {
    var body: some View {
        HStack(spacing: 5) {
            Image(systemName: "checkmark.circle.fill").font(.callout)
            Text("Connected").font(.callout.weight(.medium))
        }
        .foregroundStyle(.green)
        .padding(.horizontal, 12).frame(height: 34)
        .glassEffect(.regular.tint(.green.opacity(0.22)), in: .capsule)
        .accessibilityLabel("Connected")
    }
}

/// A Wi-Fi sign-in page is intercepting this network's traffic — the VPN cannot
/// get through until the user is past it. Indigo (matching the captive-portal
/// dot language everywhere else), with the two actions that actually move things
/// forward: open the page, and re-check after signing in.
private struct CaptivePortalBanner: View {
    @Bindable var vpn: VPNController
    @Environment(\.openURL) private var openURL
    @State private var checking = false

    var body: some View {
        HStack(alignment: .top, spacing: 10) {
            Image(systemName: "wifi.exclamationmark").font(.title3).foregroundStyle(.indigo)
            VStack(alignment: .leading, spacing: 3) {
                Text("This Wi-Fi wants you to sign in first")
                    .font(.callout.weight(.semibold))
                Text("A sign-in page is answering instead of the internet — hotel or guest Wi-Fi usually does this. Sign in there, then connect. The VPN can't get through until you do.")
                    .font(.callout).foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }
            Spacer(minLength: 8)
            VStack(alignment: .trailing, spacing: 6) {
                Button("Open Sign-In Page") {
                    openURL(vpn.captivePortalURL ?? ConnectionDiagnostics.captivePortalProbeURL)
                }
                .buttonStyle(.glassProminent).tint(.indigo)
                Button {
                    checking = true
                    Task { await vpn.recheckCaptivePortal(); checking = false }
                } label: {
                    if checking {
                        HStack(spacing: 5) { DrawnSpinner(); Text("Checking\u{2026}") }
                    } else {
                        Text("Check Again")
                    }
                }
                .buttonStyle(.glass)
                .disabled(checking)
                .help("Re-check whether the sign-in page is still in the way")
            }
        }
        .padding(12)
        .background(.indigo.opacity(0.12), in: RoundedRectangle(cornerRadius: 10))
        .accessibilityElement(children: .combine)
    }
}

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

/// A Tailscale connect waiting on the user's browser sign-in. Orange like the
/// other "waiting on you" states, with the one action that moves it forward:
/// re-open the sign-in page (the engine's login URL stays valid until used).
private struct TailscaleSignInBanner: View {
    let reopen: () -> Void

    var body: some View {
        HStack(alignment: .top, spacing: 10) {
            Image(systemName: "person.badge.key").font(.title3).foregroundStyle(.orange)
            VStack(alignment: .leading, spacing: 3) {
                Text("Sign in in your browser").font(.callout.weight(.semibold))
                Text("A sign-in page opened in your browser. Finish signing in there and this Mac joins the network by itself. Closed the tab? Open it again.")
                    .font(.callout).foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }
            Spacer(minLength: 8)
            Button("Open Sign-In Page", action: reopen)
                .buttonStyle(.glassProminent).tint(.orange)
        }
        .padding(12)
        .background(.orange.opacity(0.12), in: RoundedRectangle(cornerRadius: 10))
        .accessibilityElement(children: .combine)
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

/// Paused state banner — deliberately loud: paused means traffic is leaving the
/// Mac outside the VPN, and the user must never forget it. (There is only one
/// pause behaviour now; the old calm "blocked" variant is gone with hold mode.)
private struct PausedBanner: View {
    let resume: () -> Void

    var body: some View {
        HStack(spacing: 10) {
            Image(systemName: "road.lane.arrowtriangle.2.inward")
                .font(.title3)
                .foregroundStyle(.white)
            VStack(alignment: .leading, spacing: 2) {
                Text("Paused — traffic is NOT going through the VPN")
                    .bold()
                    .foregroundStyle(.white)
                Text("Everything uses your normal connection and is visible to the local network. You're still signed in — resuming won't ask again.")
                    .font(.callout)
                    .foregroundStyle(.white.opacity(0.9))
            }
            Spacer()
            Button("Resume", action: resume)
                .buttonStyle(.borderedProminent)
                .tint(.white)
                .foregroundStyle(.red)
        }
        .padding(12)
        .background(Color.red, in: RoundedRectangle(cornerRadius: 10))
        .accessibilityElement(children: .combine)
    }
}

/// The header's problem chip: appears ONLY when something is wrong (a healthy
/// connection shows nothing here). Plain-English text + the shared dot language.
private struct ProblemPill: View {
    let text: String
    let dot: DotState
    @Environment(\.accessibilityReduceMotion) private var reduceMotion

    var body: some View {
        HStack(spacing: 5) {
            StatusDot(state: dot, size: 7)
            Text(text).font(.callout).foregroundStyle(.secondary)
        }
        .padding(.horizontal, 10).padding(.vertical, 5)
        .glassEffect(.regular.tint(dot.color.opacity(0.18)), in: .capsule)
        .animation(reduceMotion ? nil : .smooth(duration: 0.4), value: text)
        .accessibilityElement(children: .combine)
        .accessibilityLabel(text)
    }
}

/// The "fill in this required field" emphasis: quiet until the user actually
/// tries to connect, then a soft accent ring around each still-empty required
/// field (the closest native idiom — no dedicated Liquid Glass component exists).
/// `nudge` adds the kinetic half: each bump gives every still-empty field a
/// small sideways shake — the "no, over here" gesture for a click on a Connect
/// button that's waiting on input. Reduce Motion suppresses the shake; the ring
/// and focus placement carry the message alone.
private struct RequiredFieldEmphasis: ViewModifier {
    let missing: Bool
    let attempted: Bool
    var nudge: Int = 0
    @Environment(\.accessibilityReduceMotion) private var reduceMotion
    private var active: Bool { missing && attempted }

    func body(content: Content) -> some View {
        content
            .overlay(
                RoundedRectangle(cornerRadius: 6)
                    .strokeBorder(Color.accentColor.opacity(active ? 0.8 : 0), lineWidth: 2)
                    .animation(.easeInOut(duration: 0.25), value: active)
            )
            .modifier(ShakeEffect(animatableData: CGFloat((missing && !reduceMotion) ? nudge : 0)))
            .accessibilityValue(active ? "Required" : "")
    }
}

/// Three quick 4pt side-to-side cycles per nudge unit — enough to catch the eye,
/// small enough not to read as an error condition.
private struct ShakeEffect: GeometryEffect {
    var animatableData: CGFloat
    func effectValue(size: CGSize) -> ProjectionTransform {
        ProjectionTransform(CGAffineTransform(
            translationX: 4 * sin(animatableData * .pi * 6), y: 0))
    }
}

private extension View {
    func requiredEmphasis(missing: Bool, attempted: Bool, nudge: Int = 0) -> some View {
        modifier(RequiredFieldEmphasis(missing: missing, attempted: attempted, nudge: nudge))
    }
}
