// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
//  MenuBarView.swift
//  The menu-bar presence. The label is a narrow lock icon with a status dot
//  that widens with a small iStat-style traffic sparkline while connected
//  (toggleable in Settings — some people guard their menu bar width).
//  The window-style dropdown: connect/disconnect per VPN, live throughput
//  graph, copyable IP information, the small Mercator map, the railroad
//  diagram — and, last, Disconnect and Quit.
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
    private var nativeActive: Bool { nativeVPN.status == .connected || nativeVPN.status == .connecting }
    private var anyActive: Bool { activeID != nil || tunnelManager.hasActive || nativeActive }

    private var labelState: DotState {
        if vpn.captivePortalSuspected && activeID == nil { return .captivePortal }
        guard let id = activeID, let p = vpn.profiles.first(where: { $0.id == id }) else {
            // No OpenVPN tunnel — reflect subprocess/native so the glyph isn't a
            // misleading "disconnected" while an SSH or IKEv2 tunnel is up.
            if anyActive {
                let connecting = (tunnelManager.status(tunnelManager.activeIDs.first ?? "") == .connecting)
                    || nativeVPN.status == .connecting
                return connecting ? .busy : .connected
            }
            return .off
        }
        // Reachability across ALL connected tunnels (not just this one): if any
        // is stalled, the menu-bar dot goes amber.
        let anyStalled: Bool = { if case .stalled = reachability.worst { return true }; return false }()
        let paused = vpn.pausedProfiles.contains(id)
        return .from(status: p.status, stalled: anyStalled && !paused, paused: paused)
    }

    /// The menu bar only re-renders on a STATE change (the system reduces the
    /// label to a button image — continuous SwiftUI rhythms don't play there), so
    /// we animate by driving `phase` from a timer. Two triggers only, per design:
    ///   • a brief ONE-SHOT pulse whenever the state changes (connect, disconnect,
    ///     pause, …) — to draw the eye to the change, then settle;
    ///   • CONTINUOUS motion only while there's an active connection problem
    ///     (lost connection / stalled, or a captive portal).
    /// Otherwise the icon is completely static (battery + the app's dot philosophy).
    @State private var phase = 0.0
    @State private var pulse = false          // transient, ~0.5s after a state change
    @State private var pulseTask: Task<Void, Never>?
    @Environment(\.accessibilityReduceMotion) private var reduceMotion

    /// An ongoing problem worth continuous attention.
    private var activeIssue: Bool {
        switch labelState { case .degraded, .captivePortal: return true; default: return false }
    }
    private var iconAnimating: Bool { !reduceMotion && (activeIssue || pulse) }

    // The lock icon stays still; only the status DOT animates on top of it, in a
    // liquid, friendly way. Colour + motion together name the state:
    //   • connected/paused → green, still (a friendly hop on the state change)
    //   • transport loss (degraded — "train tunnel") → red, bouncing
    //   • captive portal → yellow, spinning (orbiting)
    // (These menu-bar colours are deliberately punchier than the app-wide DotState
    //  palette — red/yellow vs orange/indigo — because the bar is a glanceable alarm.)
    /// nil = no dot at all (off), which is also how "state isn't colour-only" is kept.
    private var dotColor: Color? {
        switch labelState {
        case .connected, .paused: return .green
        case .degraded:           return .red
        case .captivePortal:      return .yellow
        case .busy:               return .yellow
        case .off:                return nil
        }
    }
    private var isSpinning: Bool { labelState == .captivePortal }

    // Amplitudes below are capped by MenuBarIcon's headroom budget: the composed
    // bitmap IS the icon (nothing outside it exists), so the dot's worst-case
    // half-extent has to fit inside the canvas. Widening the motion means
    // widening MenuBarIcon.iconWidth / canvasHeight too — see the note there.

    /// 0…1 drive: a continuous bob while there's an active issue, else a single
    /// friendly hop for a one-shot state change.
    private var dotWave: Double {
        guard iconAnimating else { return 0 }
        if activeIssue { return 0.5 + 0.5 * sin(phase) }
        return sin(min(phase, .pi))
    }
    /// Squash-and-stretch for the bounce/hop; steady (slightly enlarged) while spinning.
    private var dotScale: Double {
        guard iconAnimating else { return 1 }
        return isSpinning ? 1.1 : 1 + 0.3 * dotWave
    }
    /// Captive portal orbits (reads as "spinning"); everything else bounces/hops
    /// vertically with a little liquid sway.
    private var dotOffset: CGSize {
        guard iconAnimating else { return .zero }
        if isSpinning {
            let r = 1.5
            return CGSize(width: r * cos(phase), height: r * sin(phase))
        }
        return CGSize(width: 0.4 * sin(phase * 0.7) * dotWave, height: -2.0 * dotWave)
    }

    // "Jello": an anti-phase XY squish (volume-ish preserving) plus a tilt wobble,
    // at a faster frequency than the travel, so the dot moulds and jiggles like a
    // little gel blob rather than moving rigidly.
    private var jello: (x: CGFloat, y: CGFloat) {
        guard iconAnimating else { return (1, 1) }
        let w = 0.2 * sin(phase * 1.7)
        return (1 + w, 1 - w)
    }
    private var jelloTilt: Double { iconAnimating ? 7 * sin(phase * 1.15) : 0 }

    private var motion: MenuBarIcon.Motion {
        guard iconAnimating else { return .init() }
        return .init(scaleX: dotScale * jello.x, scaleY: dotScale * jello.y,
                     tilt: jelloTilt, offset: dotOffset)
    }

    /// Only touch the throughput store when the sparkline is actually shown, so a
    /// connected-but-graph-off tunnel doesn't pick up the store's 1 Hz churn as a
    /// dependency and re-render a static icon once a second.
    private var graph: (samples: [ThroughputMonitor.Sample], scaleMax: Double)? {
        guard showGraph, let id = connectedID else { return nil }
        return (reachability.samples(for: id), reachability.scaleMax(for: id))
    }

    var body: some View {
        // One Image(nsImage:) — everything else in a label is discarded (see the
        // file header). MenuBarIcon composes the lock, the dot and the sparkline.
        Image(nsImage: MenuBarIcon.image(glyph: anyActive ? "lock.shield.fill" : "lock.open",
                                        dotColor: dotColor,
                                        motion: motion,
                                        graph: graph,
                                        accessibility: accessibilityText))
        .task {
            // Always-alive surface → drive the app-wide reachability + throughput store.
            reachability.start(connectedIDs: { vpn.profiles.filter { $0.status == .connected }.map(\.id) },
                               fetch: { await vpn.fetchStats(id: $0) })
        }
        // Any state change → a brief one-shot pulse (then settle), unless it's an
        // active issue, which animates continuously via `activeIssue` below.
        .onChange(of: labelState) { _, _ in
            guard !reduceMotion else { return }
            pulseTask?.cancel()
            pulse = true
            pulseTask = Task {
                // 700ms, not 500: the one-shot hop is a half-sine that reaches
                // phase π (and so lands back at rest) at ~690ms with the tick
                // rate below. Cutting it at 500ms snapped the dot back mid-hop.
                try? await Task.sleep(for: .milliseconds(700))
                if !Task.isCancelled { pulse = false }
            }
        }
        // Drive the icon breath while (and only while) it's animating — a one-shot
        // hop on change, or continuously during an active issue. The loop exits the
        // moment it settles, so a steady tunnel costs nothing.
        //
        // WHY NOT TimelineView(.animation) here, which would be the idiomatic
        // choice: in a MenuBarExtra label it is not merely inert, it is a hazard.
        // Measured on macOS 26.6 — TimelineView as the label pegged the process at
        // 100% CPU and never returned to the run loop (the app never finished
        // launching), because each frame re-enters SwiftUI's update loop:
        // Update.dispatchActions → MenuBarExtraHost.requestUpdate(after:) →
        // updateButton → invalidateProperties → requestUpdate. StatusDot's
        // TimelineView (ContentView.swift) is correct inside a window; it must
        // never be reused for this label. The driven-phase Task loop is the only
        // mechanism that works here (verified: ~10 Hz of distinct button bitmaps).
        //
        // 90ms/tick rather than 70 because each tick now costs an ImageRenderer
        // pass; the phase step is scaled to match so the rhythm is unchanged.
        .task(id: iconAnimating) {
            guard iconAnimating else { return }
            phase = 0
            while !Task.isCancelled {
                phase += 0.41
                try? await Task.sleep(for: .milliseconds(90))
            }
        }
        // Belt-and-braces: this does NOT reach the status item (measured: the
        // button's accessibilityLabel stayed nil). The NSImage's
        // accessibilityDescription, set in MenuBarIcon, is what VoiceOver reads.
        .accessibilityLabel(accessibilityText)
    }

    private var accessibilityText: String {
        guard let id = activeID, let p = vpn.profiles.first(where: { $0.id == id }) else {
            return "SimpleVPN, disconnected"
        }
        return "SimpleVPN, \(p.name) \(VPNController.statusText(p.status).lowercased())"
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
    /// half-extent from the right and bottom edges: radius 2.5 × 1.3 (hop peak)
    /// × 1.2 (jello) + 1.5 (orbit) ≈ 5, inside the 6pt available (verified by
    /// sweeping a full phase cycle and checking the boundary pixels' alpha stays
    /// at 0). The glyph is a size smaller
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

    /// The dot's live deformation, computed by MenuBarLabel (which owns the rhythm).
    struct Motion: Equatable {
        var scaleX: Double = 1
        var scaleY: Double = 1
        var tilt: Double = 0
        var offset: CGSize = .zero
    }

    /// Everything that changes a pixel, so a steady tunnel renders exactly one
    /// bitmap and then costs nothing. Deliberately does NOT include the
    /// accessibility text, which varies independently of the drawing.
    private struct Key: Equatable {
        var glyph: String
        var dotColor: Color?
        var motion: Motion
        var graph: GraphKey?
    }
    private struct GraphKey: Equatable {
        var newest: Int
        var count: Int
        var scaleMax: Double
    }

    private static var memo: (key: Key, image: NSImage)?

    static func image(glyph: String, dotColor: Color?, motion: Motion,
                      graph: (samples: [ThroughputMonitor.Sample], scaleMax: Double)?,
                      accessibility: String) -> NSImage {
        let key = Key(glyph: glyph, dotColor: dotColor, motion: motion,
                      graph: graph.map { GraphKey(newest: $0.samples.last?.id ?? -1,
                                                  count: $0.samples.count,
                                                  scaleMax: $0.scaleMax) })
        let image = memo.flatMap { $0.key == key ? $0.image : nil }
            ?? render(glyph: glyph, dotColor: dotColor, motion: motion, graph: graph)
        memo = (key, image)
        // VoiceOver reads this: the label's .accessibilityLabel does not survive the
        // reduction to a button image, but the NSImage's description does (measured).
        image.accessibilityDescription = accessibility
        return image
    }

    private static func render(glyph: String, dotColor: Color?, motion: Motion,
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
                    MenuBarSparkline(samples: graph.samples, scaleMax: graph.scaleMax, tint: .white)
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
                    Circle()
                        .fill(dotColor)
                        .frame(width: dotDiameter, height: dotDiameter)
                        .scaleEffect(x: motion.scaleX, y: motion.scaleY)
                        .rotationEffect(.degrees(motion.tilt))   // tilts the squished blob → jello wobble
                        // No glow: a SwiftUI shadow's Gaussian tail reaches ~3× its
                        // radius, which was the ONLY thing that clipped against the
                        // canvas edge (measured: 31/255 alpha on the boundary at the
                        // orbit's extreme). On a 5pt dot it bought nothing anyway.
                        .offset(x: dotCentre.x - dotDiameter / 2 + motion.offset.width,
                                y: dotCentre.y - dotDiameter / 2 + motion.offset.height)
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

/// Tiny two-line traffic sparkline: download as the filled line, upload lighter.
/// `tint` exists because the menu-bar composition draws it as a white mask that is
/// recoloured to the bar's own label colour at draw time (see MenuBarIcon).
struct MenuBarSparkline: View {
    let samples: [ThroughputMonitor.Sample]
    let scaleMax: Double
    var tint: Color = .primary

    var body: some View {
        Canvas { context, size in
            guard samples.count > 1 else { return }
            func line(_ values: [Double]) -> Path {
                var path = Path()
                let stepX = size.width / CGFloat(max(1, samples.count - 1))
                for (i, v) in values.enumerated() {
                    let y = size.height - CGFloat(min(1, v / max(1, scaleMax))) * size.height
                    let point = CGPoint(x: CGFloat(i) * stepX, y: y)
                    if i == 0 { path.move(to: point) } else { path.addLine(to: point) }
                }
                return path
            }
            context.stroke(line(samples.map(\.inRate)), with: .color(tint), lineWidth: 1)
            context.stroke(line(samples.map(\.outRate)),
                           with: .color(tint.opacity(0.45)), lineWidth: 1)
        }
        .accessibilityHidden(true)   // decorative; the label text carries state
    }
}

// MARK: - Dropdown

struct MenuBarView: View {
    @Bindable var vpn: VPNController
    @Bindable var labels: LabelStore
    @Environment(\.openWindow) private var openWindow
    @Environment(PublicIPMonitor.self) private var publicIP
    @Environment(EndpointLocator.self) private var locator
    @Environment(TopologyMonitor.self) private var topo: TopologyMonitor?
    @Environment(CompositionStore.self) private var compositions: CompositionStore?
    @Environment(ReachabilityMonitor.self) private var reachability: ReachabilityMonitor?
    @Environment(SubprocessTunnelManager.self) private var tunnelManager: SubprocessTunnelManager?
    @Environment(SubprocessTunnelStore.self) private var tunnels: SubprocessTunnelStore?
    @Environment(NativeVPNManager.self) private var nativeVPN: NativeVPNManager?
    @State private var quitting = false
    /// Profile whose inline credential entry is slid out.
    @State private var credentialEntryFor: String?

    private var anyLogo: Bool { vpn.profiles.contains { LogoStore.exists($0.id) } }
    private var connected: VPNController.Profile? {
        vpn.profiles.first { $0.status == .connected }
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 2) {
            Text("SimpleVPN").font(.headline)
                .padding(.horizontal, 14).padding(.top, 10).padding(.bottom, 6)

            if vpn.profiles.isEmpty {
                Text("No VPNs configured")
                    .foregroundStyle(.secondary).font(.callout)
                    .padding(.horizontal, 14).padding(.vertical, 4)
            } else {
                ForEach(vpn.profiles) { p in
                    row(p)
                    if credentialEntryFor == p.id, !UI.isActive(p.status) {
                        MenuCredentialEntry(vpn: vpn, profile: p) {
                            withAnimation(.snappy) { credentialEntryFor = nil }
                        }
                        .transition(.asymmetric(insertion: .push(from: .top).combined(with: .opacity),
                                                removal: .opacity))
                    }
                }
            }

            if let compositions, !compositions.compositions.isEmpty {
                Divider().padding(.vertical, 4)
                Text("Compositions").font(.caption).foregroundStyle(.secondary)
                    .padding(.horizontal, 14)
                ForEach(compositions.compositions) { comp in
                    compositionRow(comp)
                }
            }

            otherConnectionsSection

            if let p = connected {
                Divider().padding(.vertical, 4)
                livePanel(p)
            }

            Divider().padding(.vertical, 4)

            if let p = connected {
                if vpn.pausedProfiles.contains(p.id) {
                    menuButton("Resume \(p.name)", systemImage: "play.circle") {
                        Task { await vpn.resume(id: p.id) }
                    }
                } else if vpn.uiPrefs(for: p.id).allowPause {
                    // Opt-in per VPN. Pause keeps the session signed in but sends
                    // traffic outside the VPN until resumed.
                    menuButton("Pause \(p.name)", systemImage: "pause.circle") {
                        Task { await vpn.pause(id: p.id) }
                    }
                }
            }
            if vpn.anyConnected || (tunnelManager?.hasActive ?? false) || nativeBackendActive {
                menuButton("Disconnect All", systemImage: "xmark.shield") {
                    for p in vpn.profiles where UI.isActive(p.status) { vpn.disconnect(id: p.id) }
                    if let tm = tunnelManager { for id in tm.activeIDs { tm.disconnect(id) } }
                    if nativeBackendActive { nativeVPN?.disconnect() }
                }
            }
            menuButton("Open SimpleVPN", systemImage: "macwindow") { openAndActivate("main") }
            menuButton("Manage VPNs…", systemImage: "slider.horizontal.3") { openAndActivate("manage") }

            Divider().padding(.vertical, 4)

            menuButton(vpn.anyConnected ? "Disconnect and Quit" : "Quit SimpleVPN",
                       systemImage: "power") {
                quitting = true
                Task { await vpn.disconnectAllAndQuit() }
            }
            .disabled(quitting)
        }
        .padding(.bottom, 10)
        .frame(width: 340)
    }

    // MARK: VPN rows

    /// The whole row is the menu item (hover-highlighted, one click):
    /// disconnected → connect (or open the window for OTP entry); active → disconnect.
    @ViewBuilder private func row(_ p: VPNController.Profile) -> some View {
        let paused = vpn.pausedProfiles.contains(p.id)
        let dotState = DotState.from(
            status: p.status,
            stalled: (reachability?.isStalled(p.id) ?? false) && !paused,
            captive: vpn.captivePortalSuspected && vpn.incidents[p.id] != nil,
            paused: paused)
        let busy = p.status == .connecting || p.status == .disconnecting
        MenuItemRow(action: { rowAction(p) }, enabled: !busy) {
            HStack(spacing: 8) {
                if anyLogo { LogoBadge(id: p.id, status: p.status, dotState: dotState) }
                else { StatusDot(state: dotState, size: 8) }
                Text(p.name).lineLimit(1).truncationMode(.tail)
                Spacer(minLength: 6)
                ForEach(labels.labels(for: p.id)) { LabelPill(label: $0) }
                trailingGlyph(p)
            }
        }
        .help(rowHelp(p))
    }

    private func rowAction(_ p: VPNController.Profile) {
        switch p.status {
        case .connected, .reasserting:
            if vpn.pausedProfiles.contains(p.id) {
                Task { await vpn.resume(id: p.id) }   // paused row click = resume
                return
            }
            vpn.disconnect(id: p.id)
        case .connecting, .disconnecting:
            break
        default:
            Task {
                // Remembered credentials connect straight from here; profiles
                // that need typing (fresh OTP, unsaved password…) slide out an
                // inline entry right in the menu.
                if await !vpn.connectWithSavedCredentials(id: p.id) {
                    withAnimation(.snappy) {
                        credentialEntryFor = credentialEntryFor == p.id ? nil : p.id
                    }
                }
            }
        }
    }

    /// openWindow alone leaves the app in the background — from another app's
    /// full-screen Space the window would open unseen. Activating pulls macOS
    /// to our window's Space.
    private func openAndActivate(_ id: String) {
        openWindow(id: id)
        NSApp.activate()
    }

    private func rowHelp(_ p: VPNController.Profile) -> String {
        switch p.status {
        case .connected, .reasserting: return "Disconnect \(p.name)"
        case .connecting, .disconnecting: return VPNController.statusText(p.status)
        default: return "Connect \(p.name)"
        }
    }

    @ViewBuilder private func trailingGlyph(_ p: VPNController.Profile) -> some View {
        switch p.status {
        case .connected, .reasserting:
            Image(systemName: vpn.pausedProfiles.contains(p.id) ? "play.circle.fill" : "stop.circle.fill")
        case .connecting, .disconnecting:
            DrawnSpinner()
        default:
            Image(systemName: "arrow.right.circle")
        }
    }

    // MARK: Other backends (SSH / OpenConnect / native IKEv2) — visible + stoppable

    private var nativeBackendActive: Bool {
        nativeVPN?.status == .connected || nativeVPN?.status == .connecting
    }

    @ViewBuilder private var otherConnectionsSection: some View {
        let subs = (tunnels?.tunnels ?? []).filter { tunnelManager?.isActive($0.id) == true }
        if !subs.isEmpty || nativeBackendActive {
            Divider().padding(.vertical, 4)
            Text("Other Connections").font(.caption).foregroundStyle(.secondary)
                .padding(.horizontal, 14)
            ForEach(subs) { t in
                otherRow(name: t.name,
                         dot: .from(subprocess: tunnelManager?.status(t.id) ?? .disconnected)) {
                    tunnelManager?.disconnect(t.id)
                }
            }
            if nativeBackendActive, let n = nativeVPN,
               let c = n.configs.first(where: { $0.id == n.activeConfigID }) {
                otherRow(name: c.name, dot: .from(status: n.status)) { n.disconnect() }
            }
        }
    }

    private func otherRow(name: String, dot: DotState, stop: @escaping () -> Void) -> some View {
        HStack(spacing: 8) {
            StatusDot(state: dot)
            Text(name).lineLimit(1)
            Spacer(minLength: 8)
            Button(action: stop) { Image(systemName: "stop.circle.fill") }
                .buttonStyle(.plain).foregroundStyle(.secondary)
                .help("Disconnect")
        }
        .padding(.horizontal, 14).padding(.vertical, 3)
    }

    // MARK: Live panel (throughput · IPs · map · railroad)

    @ViewBuilder private func livePanel(_ p: VPNController.Profile) -> some View {
        let stats = reachability?.stats(for: p.id)
        VStack(alignment: .leading, spacing: 8) {
            // Shared app-wide throughput store → the menu graph keeps its history
            // and doesn't start empty each time the menu opens.
            ThroughputReadout(inRate: reachability?.inRate(for: p.id) ?? 0,
                              outRate: reachability?.outRate(for: p.id) ?? 0)
            ThroughputGraph(samples: reachability?.samples(for: p.id) ?? [],
                            scaleMax: reachability?.scaleMax(for: p.id) ?? 1_024, compact: true)

            ipRows(stats)

            // Live topology: home → connected VPN(s) → egress. Full panel width.
            WorldMapView(vpn: vpn)
                .frame(maxWidth: .infinity)

            if let topo {
                RailroadView(topology: topo.topology,
                             ourTunnelIPv4: stats?.tunnelIPv4,
                             serverEndpoint: stats?.serverEndpoint ?? "",
                             paused: vpn.pausedProfiles.contains(p.id),
                             bypassing: vpn.pausedProfiles.contains(p.id),
                             compact: true)
                    .onAppear { topo.startWatching() }
                    .onDisappear { topo.stopWatching() }
            }
        }
        .padding(.horizontal, 14)
    }

    @ViewBuilder private func ipRows(_ stats: TunnelStats?) -> some View {
        Grid(alignment: .leading, horizontalSpacing: 10, verticalSpacing: 2) {
            if let v4 = stats?.tunnelIPv4, !v4.isEmpty {
                ipRow("Tunnel", v4)
            }
            if let v6 = stats?.tunnelIPv6, !v6.isEmpty {
                ipRow("Tunnel v6", v6)
            }
            if let pub = publicIP.publicIPv4 ?? publicIP.publicIPv6 {
                ipRow("Public" + (publicIP.countryCode.map { " \(CountryCentroids.flag(for: $0))" } ?? ""), pub)
            }
        }
        .font(.callout)
    }

    private func ipRow(_ label: String, _ value: String) -> some View {
        GridRow {
            Text(label).foregroundStyle(.secondary).gridColumnAlignment(.leading)
            CopyableValue(value: value)
        }
    }

    /// Endpoint pins for the connected profile plus "you are here".
    private func mapPins(_ p: VPNController.Profile) -> [MapPin] {
        let endpoints = vpn.ovpnText(id: p.id).map { EndpointScanner.endpoints(in: $0) } ?? []
        let overrides = vpn.overrides(for: p.id)
        var pins: [MapPin] = locator.locations(for: endpoints).compactMap { location in
            guard let lat = location.lat, let lon = location.lon else { return nil }
            let selected = overrides.server == location.endpoint.host
                || (overrides.server == nil && reachability?.stats(for: p.id)?.serverEndpoint == location.endpoint.host)
            return MapPin(id: location.endpoint.id,
                          kind: .endpoint(selected: selected),
                          lat: lat, lon: lon,
                          title: location.endpoint.host,
                          subtitle: location.countryName ?? "")
        }
        if let lat = publicIP.lat, let lon = publicIP.lon {
            pins.append(MapPin(id: "you", kind: .user, lat: lat, lon: lon,
                               title: "This Mac", subtitle: publicIP.countryName ?? ""))
        }
        return pins
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
    }
}

/// Inline credential entry that slides out under a VPN row in the dropdown.
/// Values are bound to VPNController.transientCreds — in-memory only — so they
/// survive the menu closing (popping over to an authenticator app) but are
/// never persisted; saving to the keychain stays the edit sheet's job and is
/// refused entirely when the profile forbids it.
private struct MenuCredentialEntry: View {
    @Bindable var vpn: VPNController
    let profile: VPNController.Profile
    let onDone: () -> Void

    @State private var busy = false
    @FocusState private var focused: Field?
    private enum Field { case username, password, otp }

    private var requiresOTP: Bool { vpn.authConfig(for: profile.id).requiresOTP }

    private var creds: Binding<VPNController.TransientCredentials> {
        Binding(
            get: { vpn.transientCredentials(for: profile.id) },
            set: { vpn.setTransientCredentials($0, for: profile.id) })
    }

    private var canConnect: Bool {
        let c = creds.wrappedValue
        return !c.username.trimmingCharacters(in: .whitespaces).isEmpty
            && !c.password.isEmpty
            && (!requiresOTP || !c.otp.trimmingCharacters(in: .whitespaces).isEmpty)
    }

    /// Stored credentials stay invisible here: the menu only ever asks for
    /// what's actually missing (usually just the OTP).
    private var needsUserPass: Bool {
        let c = vpn.transientCredentials(for: profile.id)
        return c.username.isEmpty || c.password.isEmpty
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 6) {
            if needsUserPass {
                TextField("Username", text: creds.username)
                    .textContentType(.username)
                    .focused($focused, equals: .username)
                    .onSubmit(connectIfReady)
                SecureField("Password", text: creds.password)
                    .textContentType(.password)
                    .focused($focused, equals: .password)
                    .onSubmit(connectIfReady)
            }
            if requiresOTP {
                TextField("One-time passcode", text: creds.otp)
                    .textContentType(.oneTimeCode)
                    .focused($focused, equals: .otp)
                    .onSubmit(connectIfReady)
            }
            HStack {
                Text("Not stored — used for this connection only.")
                    .font(.caption).foregroundStyle(.secondary)
                Spacer()
                if busy {
                    DrawnSpinner()
                } else {
                    // (No #available fallback: the deployment target IS macOS 26,
                    // so the bordered branch was dead code.)
                    Button("Connect", action: connectIfReady)
                        .buttonStyle(.glassProminent).controlSize(.small)
                        .disabled(!canConnect)
                }
            }
        }
        .textFieldStyle(.roundedBorder)
        .padding(.horizontal, 26).padding(.vertical, 6)
        .onAppear {
            let c = creds.wrappedValue
            vpn.transientCreds[profile.id] = c   // materialize so typing persists across menu closes
            focused = c.username.isEmpty ? .username
                    : c.password.isEmpty ? .password
                    : requiresOTP ? .otp : nil
        }
    }

    private func connectIfReady() {
        guard canConnect, !busy else { return }
        busy = true
        Task {
            defer { busy = false }
            do {
                // Same unified path as the main window: the shared Remember
                // preference decides whether the credentials are persisted.
                try await vpn.connectWithTransientCredentials(id: profile.id)
                onDone()
            } catch {
                // Carries the profile so the main window's sheet can offer a
                // retry (the menu bar has no room to explain a failure itself).
                vpn.report(error, profile: profile.id)
            }
        }
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
        .allowsHitTesting(enabled)
    }
}
