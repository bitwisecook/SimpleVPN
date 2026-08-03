// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
//  RouteGraphView.swift
//  The routing table as a node graph rather than a list: This Mac on the left, one
//  card per active interface (each VPN, Tailscale, the physical link) in the middle,
//  and on the right what each one carries — the networks pushed at us, the local
//  subnet, and, for the ONE interface that actually holds the default route, the
//  Internet itself as a sibling of those cards. That interface visibly fans out into
//  {the networks behind it, the way out}, which is the shape of a split tunnel. When
//  the live connection reports a proxy, it is drawn where it really is: a hop between
//  the tunnel and the Internet. Edges are dashed beziers whose dashes
//  MARCH when that interface is moving bytes, so the picture shows both the shape of
//  the routing table and which parts of it are alive.
//
//  It is a DIAGRAM, not a picture: pan (two-finger scroll), zoom (pinch, ⌘−/⌘=/⌘0,
//  double-click the background), click an interface for its live counters and the
//  actions that apply to it, and type any IPv4/IPv6 address or CIDR to have the
//  carrying interface and the exact route lit up — with a panel under the field
//  saying where it goes NOW, where it COULD go if that dropped, and, for a network
//  that doesn't travel as one piece, exactly how it splits. Every one of those
//  answers comes from RouteResolver: this view decides what to draw, never where
//  traffic goes.
//
//  Every destination card lists the real CIDRs from the table as individual labelled
//  rows — long lists collapse to six with a "Show all N…" expander, never to a bare
//  count, and opened out they scroll INSIDE the card rather than growing over their
//  neighbours — because the point of this view is to answer "where does traffic for X
//  actually go" without reading `netstat -rn`.
//
//  Layout is computed, not draggable: a routing table has an inherent left-to-right
//  flow and hand-arranging it would be busywork that goes stale on every route change.
//
//  DANGER: everything inside the zoomed container is drawn by SwiftUI on purpose —
//  Canvas, Text, shapes and .plain Buttons only. No ProgressView, no Toggle, no
//  NSViewRepresentable: a platform-backed view inside a scaled/animated container
//  deadlocks AppKit layout. Controls (glass, text fields) live in the top bar.
//
//  This file is the SHELL — window chrome (top bar, banners, the answer
//  panel's slot), pan/zoom state, selection, and the top-level diagram
//  composition. What it composes lives in files beside it: RouteGraphLayout
//  (model types, naming and buildLayout), RouteGraphNodes (cards and edges),
//  RouteGraphInspector (the popovers), RouteGraphSearch (the search and its
//  answer panel) and GatewayBar — split for size, not redesigned.
//

import SwiftUI

// MARK: - View

struct RouteGraphView: View {
    @Environment(TopologyMonitor.self) var topo: TopologyMonitor?   // was private — internal for the file split
    @Environment(ReachabilityMonitor.self) var reach: ReachabilityMonitor?   // was private — internal for the file split
    @Bindable var vpn: VPNController
    @Environment(\.accessibilityReduceMotion) var reduceMotion   // was private — internal for the file split
    @Environment(\.openURL) var openURL   // was private — internal for the file split
    @Environment(LinkStateMonitor.self) var link: LinkStateMonitor?   // was private — internal for the file split

    // Card geometry. Columns are fixed so edges stay readable; heights follow content.
    let colWidth: CGFloat = 230   // was private — internal for the file split
    let colGap: CGFloat = 90   // was private — internal for the file split
    let rowGap: CGFloat = 16   // was private — internal for the file split
    let headerHeight: CGFloat = 28   // was private — internal for the file split
    let canvasInset: CGFloat = 24   // was private — internal for the file split
    /// The globe is a SIBLING of the destination cards, in their column: the point of
    /// the picture is that the interface carrying the default fans out into the
    /// networks behind it AND the Internet. Narrower than a card, because it is a
    /// terminus rather than another list.
    let internetWidth: CGFloat = 150   // was private — internal for the file split
    let internetHeight: CGFloat = 84   // was private — internal for the file split
    /// The proxy hop, when there is one, takes the destination column and pushes the
    /// globe out past it — Mac → VPN → Proxy → Internet, drawn in that order.
    let proxyWidth: CGFloat = 156   // was private — internal for the file split
    let proxyHeight: CGFloat = 84   // was private — internal for the file split
    let proxyGap: CGFloat = 56   // was private — internal for the file split
    /// Keys for `inspecting` when the globe's or the proxy's popover is open. Can't
    /// collide with a BSD interface name (those are en0/utun3/… — never a bare word).
    let internetNodeID = "internet"   // was private — internal for the file split
    let proxyNodeID = "proxy"   // was private — internal for the file split

    /// A card longer than this collapses; when it does, this many rows stay visible.
    let collapseThreshold = 8   // was private — internal for the file split
    let collapsedRows = 6   // was private — internal for the file split
    /// Opened out, a card shows at most this many rows and SCROLLS the rest inside
    /// itself — 81 CIDRs as one column made a card taller than the window.
    let expandedWindowRows = 12   // was private — internal for the file split

    // Layout is PREDICTED (destHeight) and then drawn to that prediction, so these
    // three numbers are load-bearing in both places: every route row is exactly
    // `rowHeight`, the expander exactly `expanderHeight`, and the row stack has no
    // spacing. Measuring the rendered card and feeding it back would be the obvious
    // fix and is forbidden — that feedback loop is what deadlocks AppKit layout.
    let rowHeight: CGFloat = 16   // was private — internal for the file split
    let expanderHeight: CGFloat = 22   // was private — internal for the file split
    /// Horizontal gutter reserved inside the row window for the scrollbar capsule, so
    /// the indicator never sits on top of a CIDR. Costs no HEIGHT — which is what
    /// keeps the prediction exact.
    let scrollbarGutter: CGFloat = 8   // was private — internal for the file split

    /// The answer panel lists this many lines before saying "and N more…".
    let panelLineLimit = 8   // was private — internal for the file split

    private let minZoom: CGFloat = 0.5
    private let maxZoom: CGFloat = 3

    @State var zoom: CGFloat = 1   // was private — internal for the file split
    /// Content origin in viewport coordinates. Owned state (not a ScrollView) because
    /// the full Mac gesture vocabulary — click-drag pan, two-finger pan (with system
    /// momentum), pinch zoom, wheel zoom — needs direct control of both axes at once.
    @State private var pan: CGSize = .zero
    /// Pan at the moment the current click-drag began; nil between drags. Captured once
    /// per gesture — the compounding lesson from the pinch bug.
    @State private var dragBase: CGSize?
    @State private var viewport: CGSize = .zero
    @State private var lastContent: CGSize = .zero
    @State private var didInitialFit = false
    /// Which long destination cards the user has opened out, by card id.
    @State var expandedCards: Set<String> = []   // was private — internal for the file split
    /// How far each opened-out card is scrolled inside itself, by card id, in content
    /// points. This is the whole scrolling mechanism: no ScrollView (an NSScrollView
    /// under a transform is the crash), just an offset the rows are drawn at.
    @State var cardScroll: [String: CGFloat] = [:]   // was private — internal for the file split
    /// The interface whose inspector popover is showing, by BSD name.
    @State var inspecting: String?   // was private — internal for the file split
    @State var searchText = ""   // was private — internal for the file split
    /// The route row whose Custom-Routing overlap arrow is showing, keyed
    /// "<dest.id>|<normalized cidr>"; nil = none. The Routes-window cousin of the
    /// editor's `focusedRuleID` — same gesture (click the overlap icon), same
    /// meaning ("show me what this Add collides with"). State lives here in the
    /// shell; everything that reads it is in RouteGraphOverlap.swift.
    @State var overlapFocus: String?
    /// When the current arrow reveal began; nil once settled — which is what pauses
    /// the reveal's TimelineView, so a shown-but-settled arrow costs zero redraws
    /// (the same idle discipline edgeLayer keeps for its marching dashes).
    @State var overlapRevealStart: Date?
    @State var overlapSettle: Task<Void, Never>?

    var body: some View {
        // Resolved ONCE and handed down: every card, row and edge that lights up is
        // reading the same answer, and the resolver runs once per pass rather than
        // once per card.
        let outcome = searchOutcome
        let layout = buildLayout(outcome)
        let content = CGSize(width: layout.canvas.width + canvasInset * 2,
                             height: layout.canvas.height + canvasInset * 2)
        VStack(spacing: 0) {
            controlBar(outcome)
            gatewayBar
            driftBanner
            if let outcome { answerPanel(outcome) }
            Divider()
            GeometryReader { geo in
                // Direct manipulation, Apple Maps style: during a gesture every tick
                // applies 1:1 with no animation (responsiveness IS the feel); only
                // discrete actions (buttons, ⌘0, double-click) get a short ease.
                // Pinch/wheel/two-finger arrive as NSEvents via PanZoomEventCatcher —
                // two-finger flicks glide because macOS keeps sending momentum-phase
                // scroll events to the same monitor.
                ZStack(alignment: .topLeading) {
                    diagram(layout, outcome)
                        .frame(width: content.width, height: content.height,
                               alignment: .topLeading)
                        .scaleEffect(zoom, anchor: .topLeading)
                        .offset(x: pan.width, y: pan.height)
                }
                .frame(width: geo.size.width, height: geo.size.height, alignment: .topLeading)
                .clipped()
                .contentShape(Rectangle())
                .simultaneousGesture(
                    // Click-drag pans. simultaneous, so a drag that happens to start on
                    // a card still pans instead of dying against the card's button.
                    DragGesture(minimumDistance: 2)
                        .onChanged { value in
                            let base = dragBase ?? pan
                            if dragBase == nil { dragBase = base }
                            pan = clampedPan(CGSize(width: base.width + value.translation.width,
                                                    height: base.height + value.translation.height))
                        }
                        .onEnded { _ in dragBase = nil }
                )
                .onTapGesture(count: 2) { toggleZoom() }
                .background(PanZoomEventCatcher(
                    onPan: { delta in
                        pan = clampedPan(CGSize(width: pan.width + delta.width,
                                                height: pan.height + delta.height))
                    },
                    onZoom: { factor, anchor in zoomAround(anchor, by: factor) },
                    // An opened-out route list takes the scroll wheel for itself. The
                    // rects have to be in VIEWPORT coordinates because that is where
                    // the NSEvent lands, so the current pan/zoom is baked in here and
                    // re-baked on every change to either.
                    scrollRegions: layout.scrollRegions.map { region in
                        (id: region.id,
                         rect: CGRect(x: region.rect.minX * zoom + pan.width,
                                      y: region.rect.minY * zoom + pan.height,
                                      width: region.rect.width * zoom,
                                      height: region.rect.height * zoom))
                    },
                    onRegionScroll: { id, delta in
                        scrollCard(id, by: delta, limit: layout.scrollLimits[id] ?? 0)
                    }))
                .onChange(of: geo.size, initial: true) { _, new in
                    viewport = new
                    pan = clampedPan(pan)
                    autoFit(content: content, hasGraph: layout.nodes.count > 1)
                }
                .onChange(of: content, initial: true) { _, _ in
                    autoFit(content: content, hasGraph: layout.nodes.count > 1)
                }
            }
        }
        // A new answer opens whatever it needs to open, once. Keyed on the lit rows,
        // not on the text, so retyping the same query doesn't re-yank a card the user
        // has since scrolled.
        .onChange(of: litSignature(outcome)) { _, _ in revealMatches(outcome) }
        .background(Color(nsColor: .underPageBackgroundColor))
        .navigationTitle("Routes")
        .onAppear { topo?.startWatching() }
        .onDisappear { topo?.stopWatching() }
        .overlay {
            if layout.nodes.count <= 1 {
                ContentUnavailableView("No Active Routes", systemImage: "arrow.triangle.branch",
                    description: Text("Connect a VPN, or wait for the routing table to be read."))
            }
        }
    }

    // MARK: Drift indicator (external default-route change detected + re-asserted)
    //
    // Fed by the Route mediator's PUBLISHED drift event (PF_ROUTE monitor → diff-vs-
    // expected → re-assert). Subtle by design: a single-line badge saying what changed
    // and when, so the picture is honest about the moment something external moved the
    // default. Pure SwiftUI (no platform-backed views) and OUTSIDE the scaled subtree.
    @ViewBuilder private var driftBanner: some View {
        // One row per system-state mediator that has seen external drift (routes/DNS/
        // proxy). Each names its resource so the picture is honest about WHICH thing
        // something else moved, and when.
        let drifts: [(String, MediatorDriftEvent)] = [
            ("Routing", vpn.routes.lastDrift),
            ("DNS", vpn.dns.lastDrift),
            ("Proxy", vpn.proxies.lastDrift),
        ].compactMap { label, event in event.map { (label, $0) } }
        if !drifts.isEmpty {
            VStack(alignment: .leading, spacing: 3) {
                ForEach(drifts, id: \.1.id) { label, drift in
                    HStack(spacing: 6) {
                        Image(systemName: "exclamationmark.arrow.triangle.2.circlepath")
                            .foregroundStyle(.orange)
                        Text(label).fontWeight(.medium).foregroundStyle(.secondary)
                        Text(drift.summary)
                            .foregroundStyle(.secondary)
                            .lineLimit(2)
                        Text("· \(drift.at.formatted(.relative(presentation: .named)))")
                            .foregroundStyle(.tertiary)
                        Spacer(minLength: 0)
                        if drift.reasserted {
                            Text("re-asserted").foregroundStyle(.tertiary)
                        }
                    }
                    .accessibilityElement(children: .combine)
                    .accessibilityLabel("External \(label) change: \(drift.summary)")
                }
            }
            .font(.caption)
            .padding(.horizontal, 12).padding(.vertical, 6)
            .frame(maxWidth: .infinity, alignment: .leading)
            .background(Color.orange.opacity(0.10))
        }
    }

    // MARK: The diagram itself (everything here is scaled — SwiftUI drawing only)

    private func diagram(_ layout: Layout, _ outcome: SearchOutcome?) -> some View {
        // What the current selection feeds off — computed once, read by the edge
        // Canvas and (as a plain id comparison) by each card's border.
        let chain = selectedChain(inspecting, in: layout.edges)
        return ZStack(alignment: .topLeading) {
            dotGrid(size: layout.canvas)
            edgeLayer(layout.edges, chain: chain)
            ForEach(layout.nodes) { node in
                card(node, outcome)
                    .frame(width: node.frame.width, height: node.frame.height)
                    .offset(x: node.frame.minX, y: node.frame.minY)
            }
            // Clickable status controls sit ON the edges, above them.
            ForEach(layout.edges.filter { $0.controllable && $0.status.symbol != nil }) { e in
                edgeControl(e)
                    .offset(x: e.midpoint().x - 14, y: e.midpoint().y - 14)
            }
            // The Custom-Routing overlap arrow, on top of the cards it connects —
            // it points BETWEEN rows, so it can't sit under them. Pure Canvas
            // (we are inside the scaled container) and hit-test-transparent.
            overlapArrowLayer(layout)
        }
        .frame(width: layout.canvas.width, height: layout.canvas.height, alignment: .topLeading)
        .padding(canvasInset)
    }

    // MARK: Top bar — search on the left, zoom on the right, both in fixed homes

    private func controlBar(_ outcome: SearchOutcome?) -> some View {
        HStack(spacing: 10) {
            HStack(spacing: 6) {
                Image(systemName: "magnifyingglass")
                    .font(.caption).foregroundStyle(.secondary)
                TextField("Find an IP address or network", text: $searchText)
                    .textFieldStyle(.plain)
                    .frame(width: 210)
                    .accessibilityLabel("Find an IPv4 or IPv6 address or CIDR in the routing table")
                if !searchText.isEmpty {
                    Button { searchText = "" } label: {
                        Image(systemName: "xmark.circle.fill").font(.caption)
                    }
                    .buttonStyle(.plain)
                    .foregroundStyle(.secondary)
                    .help("Clear")
                    .accessibilityLabel("Clear search")
                }
            }
            .padding(.horizontal, 9).padding(.vertical, 5)
            .background(.background.secondary, in: Capsule())
            .overlay(Capsule().strokeBorder(Color(nsColor: .separatorColor), lineWidth: 1))

            // A wrong address is a nudge, never a dialog — people type while thinking.
            if let hint = searchHint(outcome) {
                Text(hint).font(.caption).foregroundStyle(.secondary).lineLimit(1)
            }

            Spacer(minLength: 8)

            HStack(spacing: 4) {
                Button { setZoom(zoom / 1.25) } label: { Image(systemName: "minus") }
                    .disabled(zoom <= minZoom + 0.001)
                    .keyboardShortcut("-", modifiers: .command)
                    .help("Zoom out (⌘−)")
                    .accessibilityLabel("Zoom out")
                Text("\(Int((zoom * 100).rounded()))%")
                    .font(.caption.monospacedDigit()).foregroundStyle(.secondary)
                    .frame(width: 42)
                Button { setZoom(zoom * 1.25) } label: { Image(systemName: "plus") }
                    .disabled(zoom >= maxZoom - 0.001)
                    .keyboardShortcut("=", modifiers: .command)
                    .help("Zoom in (⌘+)")
                    .accessibilityLabel("Zoom in")
                Button("Fit") { setZoom(fitScale) }
                    .keyboardShortcut("0", modifiers: .command)
                    .help("Fit the whole diagram in the window (⌘0)")
            }
            .buttonStyle(.glass)
            .controlSize(.small)
        }
        .padding(.horizontal, 12).padding(.vertical, 8)
    }

    // MARK: Zoom

    /// The scale at which the whole diagram fits the viewport. Never magnifies —
    /// "Fit" on a small graph means 100%, not a blown-up one.
    private var fitScale: CGFloat {
        guard viewport.width > 40, viewport.height > 40, lastContent.width > 1, lastContent.height > 1
        else { return 1 }
        let s = min(viewport.width / lastContent.width, viewport.height / lastContent.height)
        return min(1, max(minZoom, s))
    }

    /// Keep the content on screen: smaller than the viewport → centred; larger →
    /// clamped so no empty gutter ever opens up. (Soft rubber-banding would be nicer
    /// still; clamping is the correct baseline.)
    private func clampedPan(_ p: CGSize) -> CGSize {
        let scaled = CGSize(width: lastContent.width * zoom, height: lastContent.height * zoom)
        func axis(_ v: CGFloat, content: CGFloat, viewport vp: CGFloat) -> CGFloat {
            content <= vp ? (vp - content) / 2 : min(0, max(vp - content, v))
        }
        return CGSize(width: axis(p.width, content: scaled.width, viewport: viewport.width),
                      height: axis(p.height, content: scaled.height, viewport: viewport.height))
    }

    /// Continuous zoom (pinch/wheel): the point under the cursor stays under the
    /// cursor — the Apple Maps invariant that makes zoom feel like grabbing the map.
    private func zoomAround(_ anchor: CGPoint, by factor: Double) {
        let target = min(maxZoom, max(minZoom, zoom * CGFloat(factor)))
        let k = target / zoom
        guard k != 1 else { return }
        let newPan = CGSize(width: anchor.x - (anchor.x - pan.width) * k,
                            height: anchor.y - (anchor.y - pan.height) * k)
        zoom = target
        pan = clampedPan(newPan)
    }

    /// Discrete zoom (buttons, ⌘0, double-click): anchored on the viewport centre,
    /// with a short ease — the one place animation belongs.
    private func setZoom(_ value: CGFloat, animated: Bool = true) {
        let clamped = min(maxZoom, max(minZoom, value))
        let center = CGPoint(x: viewport.width / 2, y: viewport.height / 2)
        let k = clamped / zoom
        let newPan = CGSize(width: center.x - (center.x - pan.width) * k,
                            height: center.y - (center.y - pan.height) * k)
        if animated && !reduceMotion {
            withAnimation(.easeOut(duration: 0.16)) {
                zoom = clamped
                pan = clampedPan(newPan)
            }
        } else {
            zoom = clamped
            pan = clampedPan(newPan)
        }
    }

    /// Fit once, when there is finally a graph and a window to fit it into. After
    /// that the zoom is the user's, and a route change must not yank it around.
    private func autoFit(content: CGSize, hasGraph: Bool) {
        lastContent = content
        guard !didInitialFit, hasGraph, viewport.width > 40, content.width > 40 else { return }
        didInitialFit = true
        setZoom(fitScale, animated: false)
    }

    /// Double-click on empty background: fit ⇄ 100%, the two views people want.
    func toggleZoom() {   // was private — internal for the file split
        setZoom(abs(zoom - fitScale) < 0.01 && fitScale < 0.999 ? 1 : fitScale)
    }

    // MARK: Selection — the path that feeds the thing you clicked

    /// Every edge on the chain from This Mac to the selected node, found by walking
    /// the graph BACKWARDS from it: take every edge arriving at the node, then every
    /// edge arriving at where those came from, until the walk runs out at the source.
    ///
    /// Standby edges are never followed. They arrive at the globe too, but they are
    /// where traffic WOULD go, not what feeds it now — including them would make
    /// "the path to the Internet" claim two carriers at once, which is the exact lie
    /// the single globe exists to stop telling.
    private func selectedChain(_ selection: String?, in edges: [GraphEdge]) -> Set<String> {
        guard let selection else { return [] }
        var chain = Set<String>()
        var visited = Set<String>()
        var frontier = [selection]
        while let node = frontier.popLast() {
            guard visited.insert(node).inserted else { continue }
            for edge in edges where edge.toNode == node && !edge.standby {
                chain.insert(edge.id)
                frontier.append(edge.fromNode)
            }
        }
        return chain
    }

    /// Clicking a node selects it (and opens whatever popover it has); clicking it
    /// again lets go. One piece of state for both, so the emphasis can't outlive the
    /// popover or vice versa.
    func select(_ id: String) {   // was private — internal for the file split
        let next = (inspecting == id) ? nil : id
        // The cards can ease; the edge Canvas redraws in one step either way, so
        // reduce-motion loses nothing here but the card borders' fade.
        if reduceMotion { inspecting = next }
        else { withAnimation(.easeOut(duration: 0.15)) { inspecting = next } }
    }
}
