// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
//  MenuBarView.swift
//  The menu-bar presence. The label is a narrow lock icon with a status dot
//  and optional reserved space for a traffic sparkline.
//  The window-style dropdown: connect/disconnect per VPN, live throughput
//  graph, copyable IP information, and Disconnect and Quit.
//
//  Menu-bar rendering note (measured on macOS 26.6, not folklore): a MenuBarExtra
//  label is NOT a live hosted view. SwiftUI reduces the whole label to
//  NSStatusBarButton.image + .title, so an Image(systemName:) survives as a
//  TEMPLATE symbol image and every other primitive — Circle, Canvas, ZStack
//  offsets, scaleEffect, symbolEffect, even an explicit .frame — is silently
//  discarded. That is why the status dot and the traffic sparkline never
//  appeared here. The one escape hatch is Image(nsImage:), which is handed to
//  the button verbatim, so MenuBarIcon below renders the label itself.
//  State is still never carried by colour alone: the dot's presence and the
//  lock glyph (closed/open) carry it too.
//

import SwiftUI
import AppKit
import NetworkExtension

/// Settings key: show the traffic sparkline next to the menu-bar icon.
let menuBarGraphDefaultsKey = "menubar.trafficGraph"

// MARK: - Label (the icon in the menu bar)

struct MenuBarLabel: View {
    @Bindable var vpn: VPNController
    @Bindable var reachability: ReachabilityMonitor
    // Passed in (the label isn't inside MenuBarView's environment) so the glyph
    // reflects ALL backends, not just OpenVPN.
    var tunnelManager: SubprocessTunnelManager
    var nativeVPN: NativeVPNManager
    @AppStorage(menuBarGraphDefaultsKey) private var showGraph = false

    private var activeID: String? {
        vpn.profiles.first { UI.isActive($0.status) }?.id
    }
    private var connectedID: String? {
        vpn.profiles.first { $0.status == .connected }?.id
    }
    /// Any backend (OpenVPN, subprocess SSH/OpenConnect, native IKEv2) is up.
    private var nativeActive: Bool { UI.isActive(nativeVPN.status) }
    private var anyActive: Bool { activeID != nil || tunnelManager.hasActive || nativeActive }

    private var labelState: DotState {
        if vpn.captivePortalSuspected && activeID == nil { return .captivePortal }
        guard let id = activeID, let p = vpn.profiles.first(where: { $0.id == id }) else {
            // No OpenVPN tunnel — reflect subprocess/native so the glyph isn't a
            // misleading "disconnected" while an SSH or IKEv2 tunnel is up.
            if anyActive {
                let connecting = tunnelManager.live.values.contains { $0.status == .connecting }
                    || nativeVPN.status == .connecting
                return connecting ? .busy : .connected
            }
            return .off
        }
        // Reachability across ALL connected tunnels (not just this one): if any
        // is stalled, the menu-bar dot goes amber.
        let anyStalled = !reachability.stalledProfiles.isEmpty
        let paused = vpn.pausedProfiles.contains(id)
        return .from(status: vpn.displayStatus(for: p.id), stalled: anyStalled && !paused, paused: paused)
    }

    @State private var phase = 0.0
    @State private var previousState: DotState?
    @Environment(\.accessibilityReduceMotion) private var reduceMotion
    @Environment(\.accessibilityDifferentiateWithoutColor) private var differentiateWithoutColor
    @Environment(\.liveVisualPolicy) private var liveVisuals

    private struct PulseTrigger: Equatable {
        let state: DotState
        let permitsPulse: Bool
    }

    /// Off has no badge so the open-lock glyph is unobstructed.
    private func dotColor(for state: DotState) -> Color? {
        switch state {
        case .connected, .paused: return .green
        case .degraded:           return .red
        case .captivePortal:      return .yellow
        case .busy:               return .yellow
        case .off:                return nil
        }
    }
    private var motion: MenuBarIcon.Motion {
        guard phase > 0 else { return .init() }
        let lift = sin(phase)
        let scale = 1 + 0.22 * lift
        return .init(scale: scale, lift: 2 * lift)
    }

    /// Only touch the throughput store when the sparkline is actually shown, so a
    /// connected-but-graph-off tunnel doesn't pick up the store's 1 Hz churn as a
    /// dependency and re-render a static icon once a second.
    private var graph: (samples: [ThroughputMonitor.Sample], scaleMax: Double)? {
        guard showGraph else { return nil }
        guard let id = connectedID else { return ([], 1_024) }
        return (reachability.samples(for: id), reachability.scaleMax(for: id))
    }

    var body: some View {
        let state = labelState
        let permitsPulse = liveVisuals.permitsContinuousAnimation(reduceMotion: reduceMotion)
        let accessibility = accessibilityText(for: state)
        // One Image(nsImage:) — everything else in a label is discarded (see the
        // file header). MenuBarIcon composes the lock, the dot and the sparkline.
        Image(nsImage: MenuBarIcon.image(glyph: anyActive ? "lock.shield.fill" : "lock.open",
                                        dotColor: dotColor(for: state),
                                        dotSymbol: differentiateWithoutColor ? state.symbolName : nil,
                                        motion: motion,
                                        graph: graph,
                                        accessibility: accessibility))
        // AppKit takes a bitmap for the status item. A bounded task is enough
        // to play one pulse without giving the label a continuous timeline.
        .task(id: PulseTrigger(state: state, permitsPulse: permitsPulse)) {
            let changed = previousState.map { $0 != state } ?? false
            previousState = state
            phase = 0
            guard changed, permitsPulse, state != .off else { return }
            for frame in 1...6 {
                do { try await Task.sleep(for: .milliseconds(75)) }
                catch { return }
                guard !Task.isCancelled else { return }
                phase = .pi * Double(frame) / 7
            }
            do { try await Task.sleep(for: .milliseconds(75)) }
            catch { return }
            if !Task.isCancelled { phase = 0 }
        }
        // Belt-and-braces: this does NOT reach the status item (measured: the
        // button's accessibilityLabel stayed nil). The NSImage's
        // accessibilityDescription, set in MenuBarIcon, is what VoiceOver reads.
        .accessibilityLabel(accessibility)
    }

    private func accessibilityText(for state: DotState) -> String {
        let description = state.accessibilityDescription
        guard let id = activeID, let p = vpn.profiles.first(where: { $0.id == id }) else {
            return "SimpleVPN, \(description)"
        }
        let status = state == .busy ? VPNController.statusText(p.status).lowercased() : description
        return "SimpleVPN, \(p.name), \(status)"
    }
}

// MARK: - Icon composition

/// Composes the menu-bar icon into ONE NSImage, because a MenuBarExtra label is
/// reduced to `NSStatusBarButton.image` (see the file header) and `Image(nsImage:)`
/// is the only primitive that survives that reduction intact — measured: the
/// button holds the very same NSImage object, reps and `isTemplate` untouched.
///
/// The result is a DYNAMIC image (`NSImage(size:flipped:drawingHandler:)`) rather
/// than a flat `ImageRenderer` bitmap, and that is load-bearing rather than
/// fussiness. `isTemplate = false` opts out of the menu bar's automatic template
/// inversion, and the menu bar has its own appearance which routinely disagrees
/// with the app's: measured on a machine in Light mode, `NSApp.effectiveAppearance`
/// was Aqua while the NSStatusBarButton's was VibrantDark, because a dark desktop
/// picture tints the bar. Keying the render on `@Environment(\.colorScheme)` would
/// therefore have painted a black glyph onto a black bar. So the glyph is rendered
/// as a white MASK and recoloured to `NSColor.labelColor` inside the drawing
/// handler, where it resolves against the *bar's* appearance at draw time; only
/// the status dot keeps a literal colour, drawn over the tint.
///
/// (Behaviour verified on macOS 26.6. If a future SwiftUI starts hosting labels
/// properly, `Image(nsImage:)` still works and this simply becomes unnecessary.)
@MainActor
private enum MenuBarIcon {
    /// The composed bitmap IS the icon: anything outside the canvas is cropped and
    /// simply does not exist. That is the real clipping constraint — the old badge
    /// sat at `.offset(x: 1.5, y: 1.5)` past the glyph's corner and could never
    /// have shown. So the dot's centre keeps clearance equal to its worst-case
    /// half-extent during the one-shot pulse. The glyph is a size smaller
    /// than the bar's usual 15pt so it can stay CENTRED in the canvas and still
    /// leave that clearance — otherwise the icon reads visibly left-shifted next to
    /// its neighbours whenever there's no dot to fill the space.
    ///
    /// Sizes are in POINTS and set the status item's width — the bar's content view
    /// is 22pt tall, and a 22pt-wide image measures out as a 38pt item.
    static let canvasHeight: CGFloat = 20
    static let iconWidth: CGFloat = 22
    static let glyphSize: CGFloat = 14
    static let dotCentre = CGPoint(x: 16, y: 13.6)
    static let dotDiameter: CGFloat = 5
    static let graphSize = CGSize(width: 36, height: 14)
    static let graphGap: CGFloat = 3

    /// The dot's transform during the brief transition pulse.
    struct Motion: Equatable {
        var scale: Double = 1
        var lift: Double = 0
    }

    /// Everything that changes a pixel, so a steady tunnel renders exactly one
    /// bitmap and then costs nothing. Deliberately does NOT include the
    /// accessibility text, which varies independently of the drawing.
    private struct Key: Equatable {
        var glyph: String
        var dotColor: Color?
        var dotSymbol: String?
        var motion: Motion
        var graph: GraphKey?
    }
    private struct GraphKey: Equatable {
        var newest: Int
        var count: Int
        var scaleMax: Double
    }

    private static var memo: (key: Key, image: NSImage)?

    static func image(glyph: String, dotColor: Color?, dotSymbol: String?, motion: Motion,
                      graph: (samples: [ThroughputMonitor.Sample], scaleMax: Double)?,
                      accessibility: String) -> NSImage {
        let key = Key(glyph: glyph, dotColor: dotColor, dotSymbol: dotSymbol, motion: motion,
                      graph: graph.map { GraphKey(newest: $0.samples.last?.id ?? -1,
                                                  count: $0.samples.count,
                                                  scaleMax: $0.scaleMax) })
        let image = memo.flatMap { $0.key == key ? $0.image : nil }
            ?? render(glyph: glyph, dotColor: dotColor, dotSymbol: dotSymbol, motion: motion, graph: graph)
        memo = (key, image)
        // VoiceOver reads this: the label's .accessibilityLabel does not survive the
        // reduction to a button image, but the NSImage's description does (measured).
        image.accessibilityDescription = accessibility
        return image
    }

    private static func render(glyph: String, dotColor: Color?, dotSymbol: String?, motion: Motion,
                               graph: (samples: [ThroughputMonitor.Sample], scaleMax: Double)?) -> NSImage {
        let size = CGSize(width: iconWidth + (graph == nil ? 0 : graphGap + graphSize.width),
                          height: canvasHeight)

        // Layer 1: everything that must follow the menu bar's label colour, drawn
        // in white so the tint below reproduces it exactly (alpha is preserved, so
        // the sparkline's lighter upload line stays lighter).
        let mask = bitmap(size: size) {
            ZStack(alignment: .topLeading) {
                Color.clear
                Image(systemName: glyph)
                    .font(.system(size: glyphSize))
                    .foregroundStyle(.white)
                    .frame(width: iconWidth, height: canvasHeight)
                if let graph {
                    ThroughputSparkline(samples: graph.samples, scaleMax: graph.scaleMax,
                                        download: .white, upload: .white.opacity(0.45))
                        .accessibilityHidden(true)
                        .frame(width: graphSize.width, height: graphSize.height)
                        .offset(x: iconWidth + graphGap, y: (canvasHeight - graphSize.height) / 2)
                }
            }
        }

        // Layer 2: the status dot in its true colour, composited over the tint so
        // it survives it. Positioned by centre (not by stack alignment) because the
        // headroom budget above is expressed as clearance from the canvas edges.
        let dot = bitmap(size: size) {
            ZStack(alignment: .topLeading) {
                Color.clear
                if let dotColor {
                    Group {
                        if let dotSymbol {
                            Image(systemName: dotSymbol).resizable().scaledToFit()
                        } else {
                            Circle()
                        }
                    }
                        .foregroundStyle(dotColor)
                        .frame(width: dotDiameter, height: dotDiameter)
                        .scaleEffect(motion.scale)
                        .offset(x: dotCentre.x - dotDiameter / 2,
                                y: dotCentre.y - dotDiameter / 2 - motion.lift)
                }
            }
        }

        let composed = NSImage(size: size, flipped: false) { rect in
            mask.draw(in: rect)
            NSColor.labelColor.set()
            rect.fill(using: .sourceAtop)   // recolour the mask, keeping its alpha
            dot.draw(in: rect)
            return true
        }
        composed.isTemplate = false         // we own the colour now (see the note above)
        return composed
    }

    private static func bitmap<V: View>(size: CGSize, @ViewBuilder _ content: () -> V) -> NSImage {
        let renderer = ImageRenderer(content: content().frame(width: size.width, height: size.height))
        // Render at the deepest attached display's scale so the bar stays crisp on
        // Retina; AppKit downscales on a 1x display.
        renderer.scale = NSScreen.screens.map(\.backingScaleFactor).max() ?? 2
        guard let image = renderer.nsImage else { return NSImage(size: size) }
        image.size = size                   // the reported size must stay in POINTS
        return image
    }
}

// MARK: - Dropdown

enum MenuVPNAction: Equatable {
    case connect, disconnect, resume, cancel, waiting

    init(status: NEVPNStatus, paused: Bool) {
        switch status {
        case .connected, .reasserting: self = paused ? .resume : .disconnect
        case .connecting: self = .cancel
        case .disconnecting: self = .waiting
        default: self = .connect
        }
    }

    var title: String {
        switch self {
        case .connect: "Connect"
        case .disconnect: "Disconnect"
        case .resume: "Resume"
        case .cancel: "Cancel"
        case .waiting: "Disconnecting"
        }
    }

    var symbol: String {
        switch self {
        case .connect: "arrow.right.circle"
        case .disconnect: "stop.circle.fill"
        case .resume: "play.circle.fill"
        case .cancel: "xmark.circle"
        case .waiting: "hourglass"
        }
    }
}

struct MenuBarView: View {
    @Bindable var vpn: VPNController
    @Bindable var labels: LabelStore
    @Environment(\.openWindow) private var openWindow
    @Environment(CompositionStore.self) private var compositions: CompositionStore?
    @Environment(ReachabilityMonitor.self) private var reachability: ReachabilityMonitor?
    @Environment(SubprocessTunnelManager.self) private var tunnelManager: SubprocessTunnelManager?
    @Environment(SubprocessTunnelStore.self) private var tunnels: SubprocessTunnelStore?
    @Environment(NativeVPNManager.self) private var nativeVPN: NativeVPNManager?
    @State private var starting: Set<String> = []
    @State private var inventoryHeight: CGFloat = 36

    private var connected: VPNController.Profile? {
        vpn.profiles.first { $0.status == .connected }
    }

    private var exitNodeProfiles: [VPNController.Profile] {
        vpn.profiles.filter { $0.kind == .tailscale && $0.status == .connected }
    }

    var body: some View {
        VisibleMenuBarContent { popupBody }
            .frame(width: 340)
    }

    private var popupBody: some View {
        VStack(alignment: .leading, spacing: 2) {
            Text("SimpleVPN").font(.headline)
                .padding(.horizontal, 14).padding(.top, 10).padding(.bottom, 6)

            ScrollView {
                inventory
                    .onGeometryChange(for: CGFloat.self) { $0.size.height } action: { inventoryHeight = $0 }
            }
            .scrollBounceBehavior(.basedOnSize)
            .frame(height: min(inventoryHeight, 320))

            if let p = connected {
                Divider().padding(.vertical, 4)
                livePanel(p)
            }

            Divider().padding(.vertical, 4)

            if let p = connected {
                if vpn.pausedProfiles.contains(p.id) {
                    menuButton("Disconnect \(p.name)", systemImage: "stop.circle") {
                        vpn.disconnect(id: p.id)
                    }
                } else if vpn.uiPrefs(for: p.id).allowPause {
                    // Opt-in per VPN. Pause keeps the session signed in but sends
                    // traffic outside the VPN until resumed.
                    menuButton("Pause \(p.name)", systemImage: "pause.circle") {
                        Task { await vpn.pause(id: p.id) }
                    }
                }
            }
            if activeCount > 1 {
                menuButton("Disconnect All", systemImage: "xmark.shield") {
                    for p in vpn.profiles where UI.isActive(p.status) { vpn.disconnect(id: p.id) }
                    if let tm = tunnelManager { for id in tm.activeIDs { tm.disconnect(id) } }
                    if nativeBackendActive { nativeVPN?.disconnect() }
                }
            }
            menuButton("Open SimpleVPN", systemImage: "macwindow") { openAndActivate("main") }
            menuButton("Manage VPNs…", systemImage: "slider.horizontal.3") { openAndActivate("manage") }

            Divider().padding(.vertical, 4)

            menuButton(activeCount > 0 ? "Disconnect and Quit" : "Quit SimpleVPN",
                       systemImage: "power") {
                NSApp.terminate(nil)
            }
        }
        .padding(.bottom, 10)
    }

    private var activeCount: Int {
        let packetIDs = Set(vpn.profiles.lazy.filter { UI.isActive($0.status) }.map(\.id))
        return packetIDs.union(tunnelManager?.activeIDs ?? []).count + (nativeBackendActive ? 1 : 0)
    }

    private var inventory: some View {
        VStack(alignment: .leading, spacing: 2) {
            if vpn.profiles.isEmpty && (tunnels?.tunnels.isEmpty ?? true) && (nativeVPN?.configs.isEmpty ?? true) {
                Text("No VPNs configured")
                    .foregroundStyle(.secondary).font(.callout)
                    .padding(.horizontal, 14).padding(.vertical, 4)
            }
            ForEach(ConnectListing.standaloneProfiles(vpn.profiles, tunnels: tunnels?.tunnels ?? [])) { row($0) }
            if let tunnels, let tunnelManager {
                ForEach(tunnels.tunnels) { tunnelRow($0, manager: tunnelManager) }
            }
            if let nativeVPN {
                ForEach(nativeVPN.configs) { nativeRow($0, manager: nativeVPN) }
            }
            if let compositions, !compositions.compositions.isEmpty {
                Divider().padding(.vertical, 4)
                Text("Compositions").font(.caption).foregroundStyle(.secondary)
                    .padding(.horizontal, 14)
                ForEach(compositions.compositions) { compositionRow($0) }
            }
            if !exitNodeProfiles.isEmpty {
                Divider().padding(.vertical, 4)
                Text("Exit Nodes").font(.caption).foregroundStyle(.secondary)
                    .accessibilityAddTraits(.isHeader)
                    .padding(.horizontal, 14)
                ForEach(exitNodeProfiles) { profile in
                    MenuBarExitNodePicker(vpn: vpn, profile: profile)
                        .padding(.horizontal, 14)
                }
            }
        }
    }

    // MARK: VPN rows

    /// The whole row is the menu item (hover-highlighted, one click):
    /// disconnected → connect (or open the window for OTP entry); active → disconnect.
    @ViewBuilder private func row(_ p: VPNController.Profile) -> some View {
        let paused = vpn.pausedProfiles.contains(p.id)
        let shown = vpn.displayStatus(for: p.id)
        let dotState = DotState.from(
            status: shown,
            stalled: (reachability?.isStalled(p.id) ?? false) && !paused,
            captive: vpn.captivePortalSuspected && vpn.incidents[p.id] != nil,
            paused: paused)
        let command = MenuVPNAction(status: shown, paused: paused)
        let enabled = command != .waiting && !starting.contains(p.id)
        MenuItemRow(action: { rowAction(p, command: command) }, enabled: enabled) {
            HStack(spacing: 8) {
                LogoBadge(id: p.id, status: p.status, dotState: dotState, fallbackSymbol: p.kind.systemImage)
                VStack(alignment: .leading, spacing: 2) {
                    Text(p.name).lineLimit(1).truncationMode(.tail)
                    HStack(spacing: 4) {
                        let assignedLabels = labels.labels(for: p.id)
                        if !assignedLabels.isEmpty { LabelPills(labels: assignedLabels) }
                        if let notice = p.kind.maturityNotice(usesTeleport: vpn.usesTeleport(kind: p.kind, profileID: p.id)) {
                            MaturityBadge(notice: notice)
                        }
                    }
                }
                Spacer(minLength: 4)
                Label(command.title, systemImage: command.symbol)
                    .font(.callout).accessibilityHidden(true)
            }
        }
        .help("\(command.title) \(p.name)")
        .accessibilityLabel(rowAccessibilityLabel(p, dotState: dotState))
        .accessibilityHint(enabled ? "\(command.title) \(p.name)" : "")
    }

    /// The row as one sentence. Maturity comes last: it is the least urgent thing
    /// about a row and the most permanent.
    private func rowAccessibilityLabel(_ p: VPNController.Profile, dotState: DotState) -> String {
        var bits = [p.name, dotState.accessibilityDescription]
        let assignedLabels = labels.labels(for: p.id).map(\.name)
        if !assignedLabels.isEmpty { bits.append(assignedLabels.formatted(.list(type: .and))) }
        if let notice = p.kind.maturityNotice(usesTeleport: vpn.usesTeleport(kind: p.kind, profileID: p.id)) { bits.append(notice.spokenValue) }
        return bits.joined(separator: ", ")
    }

    private func rowAction(_ p: VPNController.Profile, command: MenuVPNAction) {
        switch command {
        case .resume: Task { await vpn.resume(id: p.id) }
        case .disconnect, .cancel: vpn.disconnect(id: p.id)
        case .waiting: break
        case .connect:
            if p.kind == .tailscale && TailscaleConflict.isOfficialClientRunning {
                showConnection(p.id)
                return
            }
            guard starting.insert(p.id).inserted else { return }
            Task {
                defer { starting.remove(p.id) }
                switch await vpn.quickConnect(id: p.id) {
                case .started: break
                case .needsInput:
                    vpn.nudgeCredentials(id: p.id)
                    openAndActivate("main")
                case .failed:
                    showConnection(p.id)
                }
            }
        }
    }

    private func showConnection(_ tag: String) {
        vpn.requestedConnectionTag = tag
        openAndActivate("main")
    }

    /// openWindow alone leaves the app in the background — from another app's
    /// full-screen Space the window would open unseen. Activating pulls macOS
    /// to our window's Space.
    private func openAndActivate(_ id: String) {
        openWindow(id: id)
        NSApp.activate()
    }

    private var nativeBackendActive: Bool {
        nativeVPN.map { UI.isActive($0.status) } ?? false
    }

    private func tunnelRow(_ config: SubprocessTunnelConfig, manager: SubprocessTunnelManager) -> some View {
        let status = manager.status(config.id)
        let command: MenuVPNAction = status == .connecting ? .cancel : status == .connected ? .disconnect : .connect
        let tag = ConnectListing.tunnelTag + config.id
        return otherRow(name: config.name, dot: .from(subprocess: status), command: command) {
            if manager.isActive(config.id) {
                manager.disconnect(config.id)
            } else {
                let tools: Set<TunnelCLI> = SubprocessTunnelManager.willRunInProcess(config) ? [] : TunnelCLI.installed()
                let need = SubprocessTunnelReadiness.need(for: config, installedTools: tools)
                if need != nil || (config.kind.isSSLVPN && SubprocessTunnelManager.openconnectAuthMode(config) == "password" && !config.isOTPRequirementLocked) {
                    showConnection(tag)
                    return
                }
                manager.connect(config, password: KeychainCredentialStore.loadCredentials(profile: "tunnel.\(config.id)")?.password)
                if manager.status(config.id).isFailed { showConnection(tag) }
            }
        }
    }

    private func nativeRow(_ config: NativeVPNConfig, manager: NativeVPNManager) -> some View {
        let status = manager.status(for: config.id)
        let command = MenuVPNAction(status: status, paused: false)
        let tag = ConnectListing.nativeTag + config.id
        return otherRow(name: config.name, dot: .from(status: status), command: command, starting: starting.contains(tag)) {
            if command == .disconnect || command == .cancel {
                manager.disconnect(config.id)
            } else if command == .connect {
                guard manager.replacementWarning(for: config.id) == nil,
                      NativeVPNReadiness.need(for: config) == nil else {
                    showConnection(tag)
                    return
                }
                guard starting.insert(tag).inserted else { return }
                Task {
                    defer { starting.remove(tag) }
                    await vpn.connectNative(config, using: manager)
                    if manager.connectionError(for: config.id) != nil { showConnection(tag) }
                }
            }
        }
    }

    private func otherRow(name: String, dot: DotState, command: MenuVPNAction, starting: Bool = false,
                          action: @escaping () -> Void) -> some View {
        MenuItemRow(action: action, enabled: command != .waiting && !starting) {
            HStack(spacing: 8) {
                StatusDot(state: dot)
                Text(name).lineLimit(1)
                Spacer(minLength: 6)
                Label(command.title, systemImage: command.symbol)
                    .font(.callout).accessibilityHidden(true)
            }
        }
        .accessibilityLabel("\(name), \(dot.accessibilityDescription)")
        .accessibilityHint("\(command.title) \(name)")
    }

    // MARK: Live panel

    private func livePanel(_ profile: VPNController.Profile) -> some View {
        MenuBarConnectionDetails(profileID: profile.id)
            .padding(.horizontal, 14)
    }

    private func menuButton(_ title: String, systemImage: String, action: @escaping () -> Void) -> some View {
        MenuItemRow(action: action) {
            Label(title, systemImage: systemImage)
        }
    }

    /// A composition as one menu row: click connects (or disconnects) the whole group.
    @ViewBuilder private func compositionRow(_ comp: VPNComposition) -> some View {
        let active = vpn.isCompositionActive(comp)
        MenuItemRow(action: {
            if active { vpn.disconnectComposition(comp) }
            else { Task { await vpn.connectComposition(comp) } }
        }) {
            HStack(spacing: 8) {
                Image(systemName: active ? "stop.circle.fill" : "square.stack.3d.up")
                Text(comp.name)
                Spacer(minLength: 6)
                Text("\(comp.members.count)").font(.caption).foregroundStyle(.secondary)
            }
        }
        .help(active ? "Disconnect \(comp.name)" : "Connect \(comp.name)")
        // The bare member count would read as a mystery number.
        // The state's words come from `DotState`, the one status vocabulary — this row
        // and Manage VPNs' composition row each used to spell it out for themselves, so
        // "connected"/"disconnected" existed here as literals that nothing kept in step
        // with the rest of the app (`Docs/Drift.md`).
        .accessibilityLabel("\(comp.name), \((active ? DotState.connected : .off).accessibilityDescription), \(comp.members.count) VPNs")
        .accessibilityHint(active ? "Disconnects the whole group." : "Connects the whole group.")
        .contextMenu {
            if comp.applicationRoutes == nil {
                Button("Connect Through One Virtual Interface") { Task { await vpn.connectThroughVirtualInterface(comp) } }
                    .disabled(vpn.virtualCompositionProblem(comp) != nil)
                    .help(vpn.virtualCompositionProblem(comp) ?? "Route this composition through one virtual interface.")
                    .accessibilityValue(vpn.virtualCompositionProblem(comp) ?? "Available")
            }
        }
    }
}

private struct MenuBarExitNodePicker: View {
    let vpn: VPNController
    let profile: VPNController.Profile
    @State private var switching = false
    @State private var hasRefreshed = false
    @State private var refreshFailed = false
    @State private var errorText: String?
    @State private var copiedNodeID: String?

    private var status: TailscaleStatus? { hasRefreshed ? vpn.tailscaleStatuses[profile.id] : nil }
    private var currentID: String { status?.exitNodeID ?? "" }
    private var isCompositionMember: Bool { vpn.virtualMembers[profile.id] != nil }
    private var choices: [TailscalePeer] {
        (status?.exitNodes ?? []).filter { !$0.id.isEmpty }.sorted { first, second in
            if first.online != second.online { return first.online }
            let order = title(for: first).localizedStandardCompare(title(for: second))
            return order == .orderedSame ? first.id < second.id : order == .orderedAscending
        }
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 4) {
            HStack {
                Text(profile.name).lineLimit(1)
                Spacer(minLength: 8)
                if let status, status.backendState == .running {
                    picker
                    if !currentID.isEmpty && !refreshFailed { copyNodeID }
                } else {
                    Text(statusLabel).foregroundStyle(.secondary)
                }
            }
            if switching {
                ProgressView("Changing exit node…").controlSize(.small)
            } else if let errorText {
                Text(errorText).foregroundStyle(.secondary)
            } else if isCompositionMember {
                Text("Edit this VPN and reconnect the composition to change its exit node.")
                    .foregroundStyle(.secondary)
            } else if ManagedPolicy.lockConfiguration {
                Text("Managed by your organization").foregroundStyle(.secondary)
            }
            if refreshFailed && !switching {
                Button("Refresh Exit Nodes") { Task { await refresh() } }
            }
        }
        .font(.callout)
        .task(id: profile.id) {
            while !Task.isCancelled {
                if !switching { await refresh() }
                do { try await Task.sleep(for: .seconds(10)) } catch { return }
            }
        }
        .task(id: copiedNodeID) {
            guard copiedNodeID != nil else { return }
            do { try await Task.sleep(for: .seconds(2)) } catch { return }
            copiedNodeID = nil
        }
    }

    private var statusLabel: String {
        if refreshFailed { return "Exit nodes unavailable" }
        if status?.backendState.needsUserAction == true { return "Waiting for sign-in" }
        return "Checking exit nodes…"
    }

    private var picker: some View {
        let choices = choices
        return Picker("Exit node for \(profile.name)", selection: Binding(get: { currentID }, set: select)) {
            Text("No Exit Node").tag("")
                .disabled(ManagedPolicy.forceKeepInsideVPN)
            if !currentID.isEmpty, !choices.contains(where: { $0.id == currentID }) {
                let name = status?.exitNodeName ?? ""
                Text(name.isEmpty ? currentID : name)
                    .tag(currentID).disabled(true)
            }
            ForEach(choices) { node in
                Text(title(for: node) + (node.online ? "" : " (offline)"))
                    .tag(node.id).disabled(!node.online)
            }
        }
        .labelsHidden()
        .pickerStyle(.menu)
        .accessibilityLabel("Exit node for \(profile.name)")
        .disabled(switching || refreshFailed || isCompositionMember || ManagedPolicy.lockConfiguration)
    }

    private var copyNodeID: some View {
        let copied = copiedNodeID == currentID
        return Button(copied ? "Copied Exit Node ID" : "Copy Exit Node ID",
                      systemImage: copied ? "checkmark" : "doc.on.doc") {
            NSPasteboard.general.clearContents()
            if NSPasteboard.general.setString(currentID, forType: .string) {
                copiedNodeID = currentID
                AccessibilityAnnouncer.sayNow("Copied exit node ID for \(profile.name)")
            }
        }
        .labelStyle(.iconOnly)
        .buttonStyle(.borderless)
        .help("Copy the exit node ID for routing rules")
    }

    private func title(for node: TailscalePeer) -> String {
        node.pickerLabel.isEmpty ? node.id : node.pickerLabel
    }

    private func select(_ id: String) {
        guard id != currentID, !switching else { return }
        let node = choices.first { $0.id == id && $0.online }
        guard id.isEmpty || node != nil else { return }
        switching = true
        errorText = nil
        Task {
            defer { switching = false }
            do {
                try await vpn.selectTailscaleExitNode(node, id: profile.id)
                AccessibilityAnnouncer.sayNow(node.map { "\(profile.name) uses \(title(for: $0))" }
                    ?? "Exit node off for \(profile.name)")
            } catch {
                errorText = UserFacingError.redact(error.localizedDescription)
                AccessibilityAnnouncer.sayNow("Could not change the exit node for \(profile.name)")
            }
            await refresh()
        }
    }

    private func refresh() async {
        let updated = await vpn.refreshTailscaleStatus(id: profile.id)
        guard !Task.isCancelled else { return }
        refreshFailed = updated == nil
        if updated != nil { hasRefreshed = true }
    }
}

/// Keep ticking traffic values below the popup's command rows so graph updates
/// do not re-evaluate the connection list or its layout.
private struct MenuBarConnectionDetails: View {
    let profileID: String
    @Environment(ReachabilityMonitor.self) private var reachability: ReachabilityMonitor?

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            ThroughputReadout(inRate: reachability?.inRate(for: profileID) ?? 0,
                              outRate: reachability?.outRate(for: profileID) ?? 0)
            ThroughputGraph(samples: reachability?.samples(for: profileID) ?? [],
                            scaleMax: reachability?.scaleMax(for: profileID) ?? 1_024, compact: true)

            MenuBarAddresses(profileID: profileID)
        }
    }
}

private struct MenuBarAddresses: View {
    let profileID: String
    @Environment(ReachabilityMonitor.self) private var reachability: ReachabilityMonitor?
    @Environment(PublicIPMonitor.self) private var publicIP

    var body: some View {
        let addresses = reachability?.tunnelAddresses[profileID]
        VStack(spacing: 2) {
            ipRow("Tunnel", addresses?.ipv4)
            ipRow("Tunnel v6", addresses?.ipv6)
            ipRow("Public", publicIP.publicIPv4 ?? publicIP.publicIPv6,
                  flag: publicIP.countryCode.map { CountryCentroids.flag(for: $0) })
        }
        .font(.callout)
    }

    private func ipRow(_ label: String, _ value: String?, flag: String? = nil) -> some View {
        HStack(spacing: 8) {
            Text(label)
                .foregroundStyle(.secondary)
                .lineLimit(1)
                .frame(width: 63, alignment: .leading)
            Text(flag ?? "")
                .frame(width: 17)
                .accessibilityHidden(true)
            NetworkAddressValue(value: value)
        }
        .accessibilityElement(children: .combine)
    }
}

/// A menu-item look-alike for the window-style dropdown: full-width hover
/// highlight (accent, white content) and a single click action, like NSMenu rows.
private struct MenuItemRow<Content: View>: View {
    let action: () -> Void
    var enabled: Bool = true
    @ViewBuilder let content: Content
    @State private var hovering = false
    @Environment(\.isEnabled) private var isEnabled

    private var active: Bool { hovering && enabled && isEnabled }

    var body: some View {
        Button(action: action) {
            content
                .frame(maxWidth: .infinity, alignment: .leading)
                .padding(.horizontal, 5).padding(.vertical, 3)
                .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
        .foregroundStyle(active ? AnyShapeStyle(.white) : AnyShapeStyle(.primary))
        .background(
            RoundedRectangle(cornerRadius: 5)
                .fill(active ? Color.accentColor : .clear)
        )
        .padding(.horizontal, 5)
        .onHover { hovering = $0 }
        .disabled(!enabled)
    }
}
