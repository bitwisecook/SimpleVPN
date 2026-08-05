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
//  This is the SHELL of the window — the split view, sidebar, toolbar and the
//  startup prompts. The columns it presents live in files beside it:
//  ConnectionDetailView (+ConnectControl), ConnectionInspectorView,
//  ConnectionBanners and FirstConnectSetupCard — split out for size, not
//  redesigned.
//

import SwiftUI
import UniformTypeIdentifiers
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
    @Environment(ExtensionDoctor.self) private var extDoctor: ExtensionDoctor?
    @Environment(SubprocessTunnelManager.self) private var tunnelManager: SubprocessTunnelManager?
    @Environment(SubprocessTunnelStore.self) private var tunnels: SubprocessTunnelStore?
    @Environment(NativeVPNManager.self) private var nativeVPN: NativeVPNManager?
    @Environment(\.accessibilityReduceMotion) private var reduceMotion
    @State private var showImporter = false
    /// The right-hand live-details pane. Closed by default (simple window);
    /// the Settings toggle changes the launch state, the toolbar button the moment.
    @AppStorage(inspectorDefaultsKey) private var inspectorOpenByDefault = false
    @State private var showInspector = false
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
        // For Tailscale mid sign-in the display status (connecting) must win over the
        // link monitor, which only knows the NE tunnel came up — not that the node
        // isn't on the network yet.
        let shown = vpn.displayStatus(for: p.id)
        if shown != p.status { return .from(status: shown) }
        return link?.dot(for: p.id) ?? .from(status: shown)
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
                    otherConnectionRow(name: t.name, kind: t.kind,
                                       dot: .from(subprocess: tunnelManager?.status(t.id) ?? .disconnected)) {
                        tunnelManager?.disconnect(t.id)
                    }
                }
                if nativeBackendActive, let n = nativeVPN,
                   let c = n.configs.first(where: { $0.id == n.activeConfigID }) {
                    otherConnectionRow(name: c.name, kind: c.kind,
                                       dot: .from(status: n.status)) { n.disconnect() }
                }
            }
        }
    }

    private func otherConnectionRow(name: String, kind: VPNKind, dot: DotState,
                                    stop: @escaping () -> Void) -> some View {
        let notice = kind.maturityNotice
        return HStack(spacing: 8) {
            StatusDot(state: dot)
            VStack(alignment: .leading, spacing: 1) {
                HStack(spacing: 5) {
                    Text(name).lineLimit(1)
                    // A LIVE connection on a kind nobody has proven: the chip is
                    // still true, and this is the moment a report is worth most.
                    if let notice { MaturityBadge(notice: notice) }
                }
                Text(kind.displayName).font(.caption).foregroundStyle(.secondary)
            }
            // One sentence per row; the (hidden) dot's state rides in words.
            .accessibilityElement(children: .combine)
            .accessibilityLabel("\(name), \(kind.displayName), \(dot.accessibilityDescription)\(notice.map { ", \($0.spokenValue)" } ?? "")")
            Spacer(minLength: 8)
            Button(action: stop) {
                Image(systemName: "stop.fill").frame(width: 22, height: 22).contentShape(Rectangle())
            }
                .buttonStyle(.borderless).foregroundStyle(.secondary)
                .help("Disconnect")
                .accessibilityLabel("Disconnect \(name)")
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
                let doctor = extDoctor
                vpn.ensureExtensionReady = { [weak ext, weak doctor] in
                    guard let ext else { return true }
                    // The connect gate doubles as a doctor trigger: a wedged
                    // engine should be noticed the moment someone reaches for
                    // it. Fire-and-forget — the doctor single-flights and
                    // debounces, and its non-disruptive rungs never block or
                    // interrupt the connect that's about to run.
                    Task { [weak doctor] in await doctor?.checkUp(trigger: .connectGate) }
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
            // Tab moves column by column — the whole sidebar is one focus
            // section, so Tab from the list lands in the detail pane instead of
            // walking every row.
            .focusSection()
            .toolbar {
                ToolbarItem {
                    Button { openWindow(id: "manage") } label: { Image(systemName: "slider.horizontal.3") }
                        .help("Manage VPNs")
                        .accessibilityLabel("Manage VPNs")
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
                        .accessibilityLabel("Live details")
                        .accessibilityValue(showInspector ? "Shown" : "Hidden")
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
        // The window keeps AppKit's stock `.inspector` resize behaviour: opening the
        // pane grows the window, closing it leaves the window as-is. Attempts to force
        // it to shrink back on close were more trouble than they were worth, so this is
        // deliberately left alone.
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
                    .accessibilityHidden(true)   // decorative; the text below says it all
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
            .accessibilityElement(children: .combine)
            .accessibilityLabel("Drop zone for VPN configuration files")
            // Dragging isn't keyboard-operable — point at the path that is.
            .accessibilityHint("Use the Import Configuration button to choose a file instead.")
        }
        // Mirrors the window-wide handler's types, so the visible target and the
        // invisible one can't disagree about what's droppable.
        .dropDestination(for: URL.self) { urls, _ in
            dropAction(urls)
            return true
        } isTargeted: { targeted = $0 }
    }
}
