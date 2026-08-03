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

import SwiftUI

// MARK: - Model

/// One CIDR out of the routing table. Addressable on its own — the search
/// highlight points at a row, and the future policy editor will need to hang
/// rules off exactly this.
private struct RouteRow: Identifiable, Hashable {
    let cidr: String
    var id: String { cidr }
}

private struct GraphNode: Identifiable {
    enum Kind {
        case source                       // This Mac
        case interfaceCard(NetInterface)
        case destination(Destination)
        /// The one terminal node: everything not matched by a specific route ends up
        /// here. `owner` is the interface the routing table actually egresses by (nil
        /// when nothing carries a default at all); `standbys` are the interfaces that
        /// hold a usable default behind it and would take over.
        case internet(owner: NetInterface?, standbys: [NetInterface])
        /// A real hop: the proxy the live connection says its traffic goes through,
        /// sitting between the tunnel and the Internet because that is where it is.
        case proxy([String])
    }
    /// A bucket of routes carried by one interface. `id` is stable across refreshes
    /// (interface BSD name + bucket), so expansion state and selection survive polls.
    struct Destination: Identifiable {
        let id: String
        var interfaceName: String
        var title: String
        var symbol: String
        var routes: [RouteRow]            // CIDRs, as the table words them
        var tint: Color
    }
    let id: String
    var kind: Kind
    var frame: CGRect
}

/// What a connection is doing, which decides how its edge is drawn AND what the
/// mid-edge control does. Solid = carrying traffic; anything dashed is a link that
/// exists but isn't working right now.
private enum EdgeStatus: Equatable {
    case healthy                          // up and passing traffic → solid
    case stalled(String)                  // connected, nothing coming back (train tunnel)
    case paused(String)                   // the user paused it
    case down(String)                     // interface present but the VPN isn't up
    case captivePortal(String)            // a sign-in page is in the way
    case passive                          // not one of ours (physical link, Tailscale)

    var isSolid: Bool { self == .healthy || self == .passive }

    /// nil ⇒ nothing to click; the badge is just information.
    var symbol: String? {
        switch self {
        case .healthy, .passive: nil
        case .stalled: "exclamationmark.triangle.fill"
        case .paused: "pause.circle.fill"
        case .down: "bolt.horizontal.circle.fill"
        case .captivePortal: "wifi.exclamationmark"
        }
    }
    var tint: Color {
        switch self {
        case .healthy, .passive: .secondary
        case .stalled: .orange
        case .paused: .green
        case .down: .red
        case .captivePortal: .indigo
        }
    }
    var help: String? {
        switch self {
        case .healthy, .passive: nil
        case .stalled: "No traffic is coming back — click to reconnect"
        case .paused: "Paused — click to resume"
        case .down: "Not connected — click to connect"
        case .captivePortal: "A sign-in page is in the way — click to open it"
        }
    }
    var profileID: String? {
        switch self {
        case .healthy, .passive: nil
        case .stalled(let id), .paused(let id), .down(let id), .captivePortal(let id): id
        }
    }
    /// Plain-language state for the inspector popover.
    var summary: String {
        switch self {
        case .healthy: "Connected"
        case .stalled: "Connected, but nothing is coming back"
        case .paused: "Paused"
        case .down: "Not connected"
        case .captivePortal: "A sign-in page is in the way"
        case .passive: "Not managed by SimpleVPN"
        }
    }
}

private struct GraphEdge: Identifiable {
    let id: String
    var from: CGPoint                     // right-edge port
    var to: CGPoint                       // left-edge port
    var active: Bool                      // moving bytes
    var rate: Double                      // thickness/brightness
    var tint: Color
    var status: EdgeStatus = .passive
    /// Only the Mac→interface edge carries the clickable control; the outbound
    /// route edges share the status for line style but must not duplicate the icon.
    var controllable = false
    /// Small label pinned to the curve's midpoint — the live rate on the way into an
    /// interface, the number of routes on the way out of it.
    var badge: String?
    /// Lit in the accent colour because the address in the search box travels this way.
    var highlighted = false
    /// A route that EXISTS but isn't the one in force — the standby default behind the
    /// winner. Drawn dashed and dim whatever the interface's own health says, because
    /// what's being shown is "could carry this", not "is carrying this".
    var standby = false
    /// The nodes this edge runs between, in the same id space as `inspecting` (so
    /// "source", a BSD interface name, a destination card id, "proxy", "internet").
    /// Selecting a node walks these BACKWARDS to This Mac, which is what makes
    /// "emphasise the path that feeds this" a graph walk rather than a guess about
    /// how edge ids happen to be spelled.
    var fromNode = ""
    var toNode = ""

    /// Cubic bezier midpoint for the control points used when drawing.
    func midpoint() -> CGPoint {
        let dx = max(40, (to.x - from.x) * 0.5)
        let c1 = CGPoint(x: from.x + dx, y: from.y)
        let c2 = CGPoint(x: to.x - dx, y: to.y)
        return CGPoint(x: (from.x + 3 * c1.x + 3 * c2.x + to.x) / 8,
                       y: (from.y + 3 * c1.y + 3 * c2.y + to.y) / 8)
    }
}

/// Everything the search wants to SAY and to LIGHT UP, resolved once.
///
/// The routing semantics are not here and must never come back here: `RouteResolver`
/// owns "where does this go and where else could it go" for the whole app. This is
/// only the diagram's view of its answer — which cards glow, which rows, which edges.
///
/// Resolved once per body pass and threaded down, because resolving is real work: a
/// /8 query is cut into pieces by prefix subtraction, and doing that once per card
/// per pan tick would be felt.
private struct SearchOutcome {
    var resolution: RouteResolution
    /// Every interface any part of the query leaves by — for a CIDR that splits,
    /// that is more than one card.
    var interfaces: Set<String>
    /// "<bsd>|<raw table destination>" for every route involved, so a row only lights
    /// on the card that actually carries it.
    var litRows: Set<String>
    /// The query (or its remainder) leaves by a default route ⇒ the globe is part of
    /// the answer, and so is the edge to it.
    var hitsInternet: Bool
    /// Interfaces offering a standby DEFAULT as an alternative — their dashed edge to
    /// the globe glows, quietly: they are where this would go if the winner dropped.
    var standbyDefaults: Set<String>
}

// MARK: - View

struct RouteGraphView: View {
    @Environment(TopologyMonitor.self) private var topo: TopologyMonitor?
    @Environment(ReachabilityMonitor.self) private var reach: ReachabilityMonitor?
    @Bindable var vpn: VPNController
    @Environment(\.accessibilityReduceMotion) private var reduceMotion
    @Environment(\.openURL) private var openURL
    @Environment(LinkStateMonitor.self) private var link: LinkStateMonitor?

    // Card geometry. Columns are fixed so edges stay readable; heights follow content.
    private let colWidth: CGFloat = 230
    private let colGap: CGFloat = 90
    private let rowGap: CGFloat = 16
    private let headerHeight: CGFloat = 28
    private let canvasInset: CGFloat = 24
    /// The globe is a SIBLING of the destination cards, in their column: the point of
    /// the picture is that the interface carrying the default fans out into the
    /// networks behind it AND the Internet. Narrower than a card, because it is a
    /// terminus rather than another list.
    private let internetWidth: CGFloat = 150
    private let internetHeight: CGFloat = 84
    /// The proxy hop, when there is one, takes the destination column and pushes the
    /// globe out past it — Mac → VPN → Proxy → Internet, drawn in that order.
    private let proxyWidth: CGFloat = 156
    private let proxyHeight: CGFloat = 84
    private let proxyGap: CGFloat = 56
    /// Keys for `inspecting` when the globe's or the proxy's popover is open. Can't
    /// collide with a BSD interface name (those are en0/utun3/… — never a bare word).
    private let internetNodeID = "internet"
    private let proxyNodeID = "proxy"

    /// A card longer than this collapses; when it does, this many rows stay visible.
    private let collapseThreshold = 8
    private let collapsedRows = 6
    /// Opened out, a card shows at most this many rows and SCROLLS the rest inside
    /// itself — 81 CIDRs as one column made a card taller than the window.
    private let expandedWindowRows = 12

    // Layout is PREDICTED (destHeight) and then drawn to that prediction, so these
    // three numbers are load-bearing in both places: every route row is exactly
    // `rowHeight`, the expander exactly `expanderHeight`, and the row stack has no
    // spacing. Measuring the rendered card and feeding it back would be the obvious
    // fix and is forbidden — that feedback loop is what deadlocks AppKit layout.
    private let rowHeight: CGFloat = 16
    private let expanderHeight: CGFloat = 22
    /// Horizontal gutter reserved inside the row window for the scrollbar capsule, so
    /// the indicator never sits on top of a CIDR. Costs no HEIGHT — which is what
    /// keeps the prediction exact.
    private let scrollbarGutter: CGFloat = 8

    /// The answer panel lists this many lines before saying "and N more…".
    private let panelLineLimit = 8

    private let minZoom: CGFloat = 0.5
    private let maxZoom: CGFloat = 3

    @State private var zoom: CGFloat = 1
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
    @State private var expandedCards: Set<String> = []
    /// How far each opened-out card is scrolled inside itself, by card id, in content
    /// points. This is the whole scrolling mechanism: no ScrollView (an NSScrollView
    /// under a transform is the crash), just an offset the rows are drawn at.
    @State private var cardScroll: [String: CGFloat] = [:]
    /// The interface whose inspector popover is showing, by BSD name.
    @State private var inspecting: String?
    @State private var searchText = ""

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

    // MARK: Default-gateway control (PolicyRouting.md Tier 2)
    //
    // Moved here from the main window's connection detail — this is its natural
    // home, next to the route graph and the drift indicators it directly affects.
    // Deliberately a single compact row (a label + a menu picker), not the big
    // card the main window used to show: this window is for people who already
    // want to see the routing table, so the control can be plain and small
    // rather than explained at length. Same state & actions as before
    // (`effectiveGatewayOwner`/`displayedGatewayOwner`, `setDefaultGateway`,
    // `canBeDefaultGateway`) — only the surface moved, not the gateway logic.
    @ViewBuilder private var gatewayBar: some View {
        if vpn.showsDefaultGatewayControl {
            let connected = vpn.connectedProfiles
            let capable = connected.filter { vpn.canBeDefaultGateway($0.id) }
            let owner = vpn.effectiveGatewayOwner
            let displayed = vpn.displayedGatewayOwner
            HStack(spacing: 8) {
                Label("Default gateway", systemImage: "arrow.triangle.branch")
                    .font(.caption.weight(.medium))
                    .foregroundStyle(.secondary)
                Picker("Default gateway", selection: Binding(
                    get: { owner },
                    set: { new in Task { await vpn.setDefaultGateway(to: new) } })
                ) {
                    ForEach(capable) { p in
                        Text(p.name).tag(Optional(p.id))
                    }
                    Text("Direct").tag(String?.none)
                }
                .pickerStyle(.menu)
                .labelsHidden()
                .fixedSize()
                .controlSize(.small)
                .help(gatewaySummary(owner: owner))
                // Transient desync surfaced honestly, same as the old card: the
                // engines currently route differently from the pick above while
                // reconciliation converges them (RC4/RC5).
                if displayed != owner {
                    Label("Applying…", systemImage: "arrow.triangle.2.circlepath")
                        .font(.caption2)
                        .foregroundStyle(.secondary)
                        .help(reconcilingGatewayNote(effective: displayed))
                }
                Spacer(minLength: 0)
            }
            .padding(.horizontal, 12).padding(.vertical, 6)
            .frame(maxWidth: .infinity, alignment: .leading)
            .background(Color(nsColor: .controlBackgroundColor).opacity(0.6))
            .accessibilityElement(children: .combine)
            .accessibilityLabel("Default gateway: \(gatewaySummary(owner: owner))")
        }
    }

    private func gatewaySummary(owner: String?) -> String {
        guard let owner, let name = vpn.profiles.first(where: { $0.id == owner })?.name else {
            return "Unmatched traffic goes directly out your normal connection. Each VPN still carries only its own subnets."
        }
        return "Unmatched traffic goes through \(name). Every other VPN carries only its own subnets."
    }

    private func reconcilingGatewayNote(effective: String?) -> String {
        if let effective, let name = vpn.profiles.first(where: { $0.id == effective })?.name {
            return "Applying change — traffic currently routes through \(name)."
        }
        return "Applying change — traffic currently routes directly."
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
        }
        .frame(width: layout.canvas.width, height: layout.canvas.height, alignment: .topLeading)
        .padding(canvasInset)
    }

    // MARK: The answer panel
    //
    // Lives under the search field, OUTSIDE the scaled subtree — a fixed home that
    // doesn't move when the diagram is panned, and ordinary SwiftUI text because
    // nothing here is under a transform. The diagram lights up WHERE traffic goes;
    // this says exactly WHAT it does, including the parts a picture can't show: the
    // takeover order, and the pieces of a CIDR that go somewhere else.

    /// One rendered line: a lead (the query part), then where it goes.
    private struct PanelLine: Identifiable {
        let id: Int
        var lead: String
        var leadIsPrefix: Bool          // monospaced, because it's a prefix
        var interface: String?          // display name; nil ⇒ nowhere
        var route: String?              // raw table destination
        var note: String?               // "standby default", "no route"…
    }

    @ViewBuilder private func answerPanel(_ outcome: SearchOutcome) -> some View {
        let r = outcome.resolution
        let lines = panelLines(outcome)
        VStack(alignment: .leading, spacing: 3) {
            // The headline a picture can't give you: this one query does not have one
            // answer. Said first, and said plainly.
            if r.spansMultipleRoutes {
                Text("Splits across \(r.interfaceNames.count) interfaces")
                    .font(.caption.weight(.semibold))
            }
            ForEach(lines.prefix(panelLineLimit)) { line in
                HStack(alignment: .firstTextBaseline, spacing: 6) {
                    Text(line.lead)
                        .font(line.leadIsPrefix ? .caption.monospaced() : .caption)
                        .foregroundStyle(.secondary)
                        .frame(width: 132, alignment: .leading)
                    Text("→").font(.caption).foregroundStyle(.tertiary)
                    if let iface = line.interface {
                        // Interpolated Text, not an HStack: the three parts are one
                        // run of text that wraps and baselines together.
                        let via = Text(line.route.map { " via \($0)" } ?? "")
                            .font(.caption.monospaced()).foregroundStyle(.secondary)
                        let note = Text(line.note.map { " (\($0))" } ?? "")
                            .font(.caption).foregroundStyle(.secondary)
                        Text("\(Text(iface).font(.caption.weight(.medium)))\(via)\(note)")
                    } else {
                        Text(line.note ?? "nowhere").font(.caption).foregroundStyle(.secondary)
                    }
                }
            }
            if lines.count > panelLineLimit {
                Text("and \(lines.count - panelLineLimit) more…")
                    .font(.caption).foregroundStyle(.tertiary)
            }
            if r.segmentsTruncated {
                Text("Too finely divided to list exactly — the diverting routes are named above.")
                    .font(.caption2).foregroundStyle(.tertiary)
                    .fixedSize(horizontal: false, vertical: true)
            }
        }
        .textSelection(.enabled)
        .padding(.horizontal, 10).padding(.vertical, 8)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(.background.secondary, in: RoundedRectangle(cornerRadius: 8))
        .overlay(RoundedRectangle(cornerRadius: 8)
            .strokeBorder(Color(nsColor: .separatorColor), lineWidth: 1))
        .padding(.horizontal, 12).padding(.bottom, 8)
    }

    /// Turn the resolver's answer into lines. Two shapes: one destination (where it
    /// goes now, then where it could go instead), or a split (each diverted piece,
    /// then ONE line for everything that just falls through).
    private func panelLines(_ outcome: SearchOutcome) -> [PanelLine] {
        let r = outcome.resolution
        var lines: [PanelLine] = []
        func add(_ lead: String, prefix: Bool = false, iface: String?,
                 route: String? = nil, note: String? = nil) {
            lines.append(PanelLine(id: lines.count, lead: lead, leadIsPrefix: prefix,
                                   interface: iface, route: route, note: note))
        }

        guard r.isRoutable else {
            add("No route", iface: nil,
                note: "nothing in the routing table covers \(r.prefix.displayText)")
            return lines
        }

        if r.spansMultipleRoutes {
            // Diverted pieces are the interesting ones and get a line each. The
            // remainder is tiled into however many prefixes the subtraction needed —
            // that's arithmetic, not information, so it collapses to one line.
            for segment in r.segments where segment.source == .specific {
                add(segment.prefix.displayText, prefix: true,
                    iface: segment.interfaceName.map { displayName($0) },
                    route: segment.route?.destination)
            }
            if let remainder = r.segments.first(where: { $0.source == .covering }) {
                add("everything else", iface: remainder.interfaceName.map { displayName($0) },
                    route: remainder.route?.destination)
            }
            if r.segments.contains(where: { $0.source == .unroutable }) {
                add("the rest", iface: nil, note: "no route")
            }
            return lines
        }

        if let winner = r.winner {
            add("Goes now", iface: displayName(winner.interfaceName), route: winner.destination)
        }
        // Where it COULD go, in the order it would actually be taken over.
        for alt in r.alternatives {
            add("Could go", iface: displayName(alt.interfaceName),
                route: alt.isDefault ? nil : alt.destination,
                note: alt.isDefault ? "standby default" : nil)
        }
        if r.alternatives.isEmpty, r.winner != nil {
            add("Nothing else", iface: nil, note: "no other route could take it")
        }
        return lines
    }

    /// The BSD name is what the table says; this is what the user calls it.
    private func displayName(_ bsd: String) -> String {
        guard let iface = topo?.topology.interfaces.first(where: { $0.name == bsd })
        else { return bsd }
        let name = label(for: iface)
        return name == bsd ? bsd : "\(name) (\(bsd))"
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
    private func toggleZoom() {
        setZoom(abs(zoom - fitScale) < 0.01 && fitScale < 0.999 ? 1 : fitScale)
    }

    // MARK: Search

    /// Any IPv4 or IPv6 address, or a CIDR of either family, answered by
    /// `RouteResolver` — the same code that answers it everywhere else in the app.
    /// Nothing about longest prefixes, interface scoping or which default wins is
    /// decided here; this only turns the resolver's answer into things to light up.
    private var searchOutcome: SearchOutcome? {
        let q = searchText.trimmingCharacters(in: .whitespaces)
        guard !q.isEmpty, let topo,
              let r = RouteResolver(topology: topo.topology).resolve(q) else { return nil }
        // Every route any piece of the query rides, keyed by interface so an identical
        // destination string on two interfaces can't light the wrong card's row.
        var rows = Set<String>()
        for route in [r.winner].compactMap({ $0 }) + r.segments.compactMap(\.route) {
            rows.insert("\(route.interfaceName)|\(route.destination)")
        }
        return SearchOutcome(
            resolution: r,
            interfaces: Set(r.interfaceNames),
            litRows: rows,
            // The remainder of a split CIDR still leaves by the default, so the globe
            // belongs to the answer whenever the covering winner is a default — but
            // only when it is THE globe's default. The globe hangs off the IPv4
            // `defaultInterface`; an IPv6 query that egresses by some other tunnel's
            // v6 default must not light it, or the picture claims an egress the
            // answer never mentioned. The panel carries that case.
            hitsInternet: r.winner?.isDefault == true
                && r.winner?.interfaceName == topo.topology.defaultInterface,
            standbyDefaults: Set(r.alternatives.filter(\.isDefault).map(\.interfaceName)))
    }

    /// Only for input that isn't an address or network at all — everything else,
    /// including "nothing routes this", is answered properly by the panel. Takes the
    /// already-resolved outcome rather than resolving again.
    private func searchHint(_ outcome: SearchOutcome?) -> String? {
        guard !searchText.trimmingCharacters(in: .whitespaces).isEmpty, outcome == nil
        else { return nil }
        return "Type an IP address or network, e.g. 10.1.2.3 or 2606:4700::/32"
    }

    private func isHighlighted(_ row: RouteRow, in dest: GraphNode.Destination,
                               _ outcome: SearchOutcome?) -> Bool {
        outcome?.litRows.contains("\(dest.interfaceName)|\(row.cidr)") == true
    }

    /// Changes exactly when the set of lit rows changes — the trigger for revealing
    /// them, and the reason revealing happens ONCE per search rather than continuously.
    private func litSignature(_ outcome: SearchOutcome?) -> String {
        outcome.map { $0.litRows.sorted().joined(separator: ",") } ?? ""
    }

    /// Bring a matched row into view: a highlight inside a collapsed card, or below
    /// the scroll window, is a highlight nobody can see.
    ///
    /// Fires only on a NEW answer. After that the card is the user's again — they can
    /// scroll away and it stays where they put it, and clearing the field leaves
    /// everything open exactly as it is. Nothing snaps back on its own.
    private func revealMatches(_ outcome: SearchOutcome?) {
        guard let outcome, let topo else { return }   // cleared search reveals nothing
        let t = topo.topology
        var opened: [String: CGFloat] = [:]
        var toExpand: Set<String> = []

        for iface in t.interfaces.filter(\.inUse) {
            for dest in destinations(for: iface, in: t) {
                guard let index = dest.routes.firstIndex(where: {
                    outcome.litRows.contains("\(dest.interfaceName)|\($0.cidr)")
                }) else { continue }
                // Short cards show every row, and a collapsed card already shows its
                // first few — neither needs disturbing.
                guard dest.routes.count > collapseThreshold else { continue }
                if !expandedCards.contains(dest.id) && index < collapsedRows { continue }

                toExpand.insert(dest.id)
                let window = min(dest.routes.count, expandedWindowRows)
                let limit = max(0, CGFloat(dest.routes.count - window) * rowHeight)
                // Roughly centred in the window, clamped to the ends of the list.
                let centred = (CGFloat(index) - CGFloat(window - 1) / 2) * rowHeight
                opened[dest.id] = min(limit, max(0, centred))
            }
        }
        guard !toExpand.isEmpty else { return }

        func apply() {
            expandedCards.formUnion(toExpand)
            for (id, offset) in opened { cardScroll[id] = offset }
        }
        // Opening a card reflows everything below it, so the motion is worth easing —
        // unless the user has asked for less of it, in which case it simply happens.
        if reduceMotion { apply() } else { withAnimation(.easeOut(duration: 0.18)) { apply() } }
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
    private func select(_ id: String) {
        let next = (inspecting == id) ? nil : id
        // The cards can ease; the edge Canvas redraws in one step either way, so
        // reduce-motion loses nothing here but the card borders' fade.
        if reduceMotion { inspecting = next }
        else { withAnimation(.easeOut(duration: 0.15)) { inspecting = next } }
    }

    // MARK: Background

    private func dotGrid(size: CGSize) -> some View {
        Canvas { ctx, _ in
            let step: CGFloat = 22
            let dot = Color(nsColor: .separatorColor).opacity(0.55)
            var y: CGFloat = 0
            while y <= size.height {
                var x: CGFloat = 0
                while x <= size.width {
                    ctx.fill(Path(ellipseIn: CGRect(x: x, y: y, width: 1.5, height: 1.5)), with: .color(dot))
                    x += step
                }
                y += step
            }
        }
        .frame(width: size.width, height: size.height)
        .contentShape(Rectangle())
        .onTapGesture(count: 2) { toggleZoom() }
        .accessibilityHidden(true)
    }

    // MARK: Edges

    @ViewBuilder private func edgeLayer(_ edges: [GraphEdge], chain: Set<String>) -> some View {
        let anyActive = edges.contains { $0.active }
        TimelineView(.animation(minimumInterval: 1 / 30, paused: reduceMotion || !anyActive)) { context in
            let t = context.date.timeIntervalSinceReferenceDate
            Canvas { ctx, _ in
                for e in edges {
                    var path = Path()
                    path.move(to: e.from)
                    // Horizontal control points: a clean S-curve between columns.
                    let dx = max(40, (e.to.x - e.from.x) * 0.5)
                    path.addCurve(to: e.to,
                                  control1: CGPoint(x: e.from.x + dx, y: e.from.y),
                                  control2: CGPoint(x: e.to.x - dx, y: e.to.y))
                    // SOLID = up and carrying traffic. DASHED = the link exists but
                    // isn't working (stalled in a train tunnel, paused, down, or a
                    // portal in the way). Stalled dashes drift slowly because it IS
                    // still trying; paused/down sit still because nothing is happening.
                    let load = min(1, e.rate / 2_000_000)
                    // A standby is dashed no matter how healthy its interface is: the
                    // dashes here mean "not the route in force", the same "exists but
                    // isn't carrying you" the other dashed edges mean.
                    let solid = e.status.isSolid && !e.standby
                    // Clicked a node: the chain feeding it fattens and comes up to full
                    // brightness, everything else drops back. Deliberately NOT the
                    // accent colour — that belongs to the search, and the two answer
                    // different questions ("what did I click" vs "where does this
                    // address go"). Where both apply the accent wins, fattened twice.
                    let onPath = chain.contains(e.id)
                    let offPath = !chain.isEmpty && !onPath
                    // The searched-for address travels this way: same line STYLE (the
                    // dashes still mean what they meant) but drawn in the accent colour
                    // and a touch heavier, matching the lit cards.
                    // A highlighted STANDBY only glows — half-strength accent, barely
                    // thicker. The route in force is the one that gets to shout.
                    let width = (e.standby ? 1.2 : (solid ? 1.5 + 1.5 * load : 1.4))
                        + (e.highlighted ? (e.standby ? 0.6 : 1.5) : 0)
                        + (onPath ? 1.5 : 0)
                    let drifting: Bool = if case .stalled = e.status { true } else { false }
                    let phase = drifting ? -(t * 10).truncatingRemainder(dividingBy: 14) : 0
                    let base: Color = if e.highlighted {
                        e.standby ? Color.accentColor.opacity(0.5) : .accentColor
                    } else if e.standby { e.tint.opacity(onPath ? 0.9 : 0.32) }
                        else if solid { e.tint.opacity(onPath ? 1 : 0.55 + 0.45 * load) }
                        else { e.status.tint.opacity(onPath ? 1 : 0.75) }
                    let ink = offPath ? base.opacity(0.5) : base
                    ctx.stroke(path, with: .color(ink),
                               style: StrokeStyle(lineWidth: width, lineCap: .round,
                                                  dash: solid ? [] : [6, 7], dashPhase: phase))
                    // Ports, like a patch bay — they make the attachment points obvious.
                    let portBase: Color = e.highlighted
                        ? (e.standby ? Color.accentColor.opacity(0.5) : .accentColor)
                        : (e.standby ? e.tint.opacity(0.32) : e.tint)
                    let port = offPath ? portBase.opacity(0.5) : portBase
                    for p in [e.from, e.to] {
                        ctx.fill(Path(ellipseIn: CGRect(x: p.x - 3.5, y: p.y - 3.5, width: 7, height: 7)),
                                 with: .color(port))
                    }
                    // Mid-edge badge: what this connection is actually carrying. Drawn
                    // only for edges with no control — an actionable status gets a real
                    // Button in the overlay instead, so it can be clicked and read out.
                    if let badge = e.badge, e.status.symbol == nil {
                        let mid = e.midpoint()
                        let resolved = ctx.resolve(Text(badge).font(.caption2.monospacedDigit())
                            .foregroundStyle(.secondary))
                        let sz = resolved.measure(in: CGSize(width: 200, height: 40))
                        let pad: CGFloat = 5
                        let rect = CGRect(x: mid.x - sz.width / 2 - pad, y: mid.y - sz.height / 2 - 2,
                                          width: sz.width + pad * 2, height: sz.height + 4)
                        ctx.fill(Path(roundedRect: rect, cornerRadius: 5),
                                 with: .color(Color(nsColor: .windowBackgroundColor).opacity(0.95)))
                        ctx.stroke(Path(roundedRect: rect, cornerRadius: 5),
                                   with: .color(e.tint.opacity(0.5)), lineWidth: 1)
                        ctx.draw(resolved, at: mid, anchor: .center)
                    }
                }
            }
        }
        .allowsHitTesting(false)
    }

    // MARK: Edge controls (the clickable status icons)

    /// The fix for whatever is wrong, right on the broken link: reconnect a stalled
    /// or down VPN, resume a paused one, or open the sign-in page that's in the way.
    @ViewBuilder private func edgeControl(_ e: GraphEdge) -> some View {
        if let symbol = e.status.symbol {
            Button { act(on: e.status) } label: {
                Image(systemName: symbol)
                    .font(.system(size: 15))
                    .foregroundStyle(e.status.tint)
                    .frame(width: 28, height: 28)
                    .background(Color(nsColor: .windowBackgroundColor).opacity(0.95), in: Circle())
                    .overlay(Circle().strokeBorder(e.status.tint.opacity(0.7), lineWidth: 1))
            }
            .buttonStyle(.plain)
            .help(e.status.help ?? "")
            .accessibilityLabel(e.status.help ?? "Connection status")
        }
    }

    private func act(on status: EdgeStatus) {
        guard let id = status.profileID else { return }
        switch status {
        case .paused:
            Task { await vpn.resume(id: id) }
        case .stalled, .down:
            // reconnect() refuses (with a message) when it can't come back
            // unattended — an OTP profile can't be silently restarted.
            Task { await vpn.reconnect(id: id) }
        case .captivePortal:
            // Hitting Apple's hotspot-detect URL is what makes a portal reveal
            // itself: the network intercepts it and serves the sign-in page.
            if let url = URL(string: "http://captive.apple.com/hotspot-detect.html") {
                openURL(url)
            }
        case .healthy, .passive:
            break
        }
    }

    // MARK: Cards

    @ViewBuilder private func card(_ node: GraphNode, _ outcome: SearchOutcome?) -> some View {
        switch node.kind {
        case .source:
            titledCard(title: Host.current().localizedName ?? "This Mac",
                       symbol: "laptopcomputer", tint: .accentColor, combined: true) {
                Text("all outbound traffic").font(.caption).foregroundStyle(.secondary)
            }
        case .interfaceCard(let iface):
            interfaceCard(iface, outcome)
        case .destination(let dest):
            destinationCard(dest, outcome)
        case .internet(let owner, let standbys):
            internetCard(owner, standbys: standbys, outcome)
        case .proxy(let proxies):
            proxyCard(proxies)
        }
    }

    /// The hop the connection told us about. Compact on purpose: it is a waypoint on
    /// the way out, not a destination with a list of networks behind it.
    private func proxyCard(_ proxies: [String]) -> some View {
        Button {
            select(proxyNodeID)
        } label: {
            titledCard(title: "Proxy", symbol: "server.rack", tint: .orange,
                       selected: inspecting == proxyNodeID, combined: true) {
                VStack(alignment: .leading, spacing: 2) {
                    Text(proxies.first ?? "")
                        .font(.caption2.monospaced()).foregroundStyle(.secondary)
                        .lineLimit(1).truncationMode(.middle)
                    if proxies.count > 1 {
                        Text("+\(proxies.count - 1) more")
                            .font(.caption2).foregroundStyle(.tertiary)
                    }
                }
            }
        }
        .buttonStyle(.plain)
        .contentShape(RoundedRectangle(cornerRadius: 10))
        .help("Traffic goes through this proxy on the way out")
        .accessibilityLabel(proxies.count == 1
            ? "Proxy \(proxies[0])"
            : "Proxy \(proxies.first ?? ""), and \(proxies.count - 1) more")
        .popover(isPresented: Binding(
            get: { inspecting == proxyNodeID },
            set: { if !$0, inspecting == proxyNodeID { inspecting = nil } }
        ), arrowEdge: .trailing) {
            proxyInspector(proxies)
        }
    }

    /// The terminus: ONE globe for the whole diagram, wired to whichever interface the
    /// routing table really egresses by. Deliberately not a titledCard — it isn't a
    /// list of anything, it's the edge of the map. Dimmed and unwired when nothing
    /// carries a default, which is the honest picture of "no way out".
    private func internetCard(_ owner: NetInterface?, standbys: [NetInterface],
                              _ outcome: SearchOutcome?) -> some View {
        let lit = outcome?.hitsInternet == true && owner != nil
        let selected = inspecting == internetNodeID
        let ink: Color = owner == nil ? .secondary : .blue
        let via = owner.map { label(for: $0) }
        return Button {
            select(internetNodeID)
        } label: {
            VStack(spacing: 6) {
                Image(systemName: "globe")
                    .font(.system(size: 28))
                    .foregroundStyle(ink)
                Text("Internet").font(.callout.weight(.medium))
                    .foregroundStyle(owner == nil ? Color.secondary : Color.primary)
            }
            .frame(maxWidth: .infinity, maxHeight: .infinity)
            .background(.background.secondary, in: RoundedRectangle(cornerRadius: 10))
            // Same three-way border language as every other card: search accent beats
            // click selection, click selection beats resting.
            .overlay(RoundedRectangle(cornerRadius: 10)
                .strokeBorder(lit ? Color.accentColor : (selected ? ink : ink.opacity(0.55)),
                              lineWidth: lit ? (selected ? 3 : 2.5) : (selected ? 2 : 1)))
            .opacity(owner == nil ? 0.5 : 1)
        }
        .buttonStyle(.plain)
        .contentShape(RoundedRectangle(cornerRadius: 10))
        .help(via.map { "Internet egress via \($0)" } ?? "Nothing is carrying the default route")
        .accessibilityElement(children: .combine)
        // The dashed standby edges are information too, and a drawn line is invisible
        // to VoiceOver — so it's said here.
        .accessibilityLabel((via.map { "Internet, egress via \($0)" }
            ?? "Internet, nothing is carrying the default route")
            + (standbys.isEmpty ? ""
               : ", standby \(standbys.map { label(for: $0) }.formatted(.list(type: .and)))"))
        .popover(isPresented: Binding(
            get: { inspecting == internetNodeID },
            set: { if !$0, inspecting == internetNodeID { inspecting = nil } }
        ), arrowEdge: .trailing) {
            internetInspector(owner, standbys: standbys)
        }
    }

    /// Clicking an interface opens its inspector: what it is, what it's carrying
    /// right now, and — only for tunnels we own — what you can do about it.
    private func interfaceCard(_ iface: NetInterface, _ outcome: SearchOutcome?) -> some View {
        Button {
            select(iface.name)
        } label: {
            // A CIDR that splits lights EVERY card it touches — that division is the
            // answer, and showing only the winner would hide half of it.
            titledCard(title: label(for: iface), symbol: iface.systemImage,
                       tint: tint(for: iface),
                       highlighted: outcome?.interfaces.contains(iface.name) == true,
                       selected: inspecting == iface.name,
                       combined: true) {
                VStack(alignment: .leading, spacing: 3) {
                    if let addr = iface.primaryAddress {
                        Text(addr).font(.caption.monospaced()).foregroundStyle(.secondary)
                    }
                    HStack(spacing: 10) {
                        Text("↓ \(Fmt.rate(iface.inRate))")
                        Text("↑ \(Fmt.rate(iface.outRate))")
                    }
                    .font(.caption.monospacedDigit()).foregroundStyle(.secondary)
                    Text(iface.name).font(.caption2.monospaced()).foregroundStyle(.tertiary)
                }
            }
        }
        .buttonStyle(.plain)
        .contentShape(RoundedRectangle(cornerRadius: 10))
        .help("Click for details")
        .accessibilityHint("Shows addresses, live rates and available actions")
        .popover(isPresented: Binding(
            get: { inspecting == iface.name },
            set: { if !$0, inspecting == iface.name { inspecting = nil } }
        ), arrowEdge: .trailing) {
            interfaceInspector(iface)
        }
    }

    /// The real table entries, one labelled row each — the reason this view exists.
    /// A card that would be a wall of CIDRs collapses, but always with the way to
    /// open it again right there in the card; opened out, it scrolls inside itself
    /// rather than growing over its neighbours.
    ///
    /// Every element in here has a FIXED height that `destHeight` knows about, so what
    /// is predicted and what is drawn are the same number by construction. Nothing is
    /// measured and fed back — that is the layout loop that kills the app.
    private func destinationCard(_ dest: GraphNode.Destination,
                                 _ outcome: SearchOutcome?) -> some View {
        let expanded = expandedCards.contains(dest.id)
        let collapsible = dest.routes.count > collapseThreshold
        let total = dest.routes.count
        let window = visibleRowCount(dest)
        let scrollable = scrolls(dest)
        let limit = scrollLimit(dest)
        let offset = scrollable ? min(limit, max(0, cardScroll[dest.id] ?? 0)) : 0
        // Only the rows in (or partly in) the window are built — one spare below for
        // the row a fractional offset has half-exposed.
        let first = Int(offset / rowHeight)
        let last = min(total, first + window + (scrollable ? 1 : 0))
        let slice = first < last ? Array(dest.routes[first..<last]) : []
        let sliceOffset = offset - CGFloat(first) * rowHeight
        let diff = customRoutingDiff(for: dest)
        // No card-level highlight any more: every destination card is a list of real
        // CIDRs, so the matching ROW is the answer. The one routeless answer — the
        // default — is the globe.
        return titledCard(title: dest.title, symbol: dest.symbol, tint: dest.tint,
                          selected: inspecting == dest.id, combined: false) {
            VStack(alignment: .leading, spacing: 0) {
                VStack(alignment: .leading, spacing: 0) {
                    ForEach(slice) { row in
                        routeRow(row, in: dest, outcome, diff: diff)
                    }
                }
                .frame(maxWidth: .infinity, alignment: .topLeading)
                .offset(y: -sliceOffset)
                .frame(height: CGFloat(window) * rowHeight, alignment: .topLeading)
                .clipped()
                .padding(.trailing, scrollable ? scrollbarGutter : 0)
                .overlay(alignment: .topTrailing) {
                    if scrollable {
                        scrollIndicator(window: CGFloat(window) * rowHeight,
                                        total: CGFloat(total) * rowHeight,
                                        offset: offset, limit: limit)
                    }
                }
                if collapsible {
                    Button {
                        if expanded {
                            expandedCards.remove(dest.id)
                            cardScroll[dest.id] = nil     // reopening starts at the top
                        } else {
                            expandedCards.insert(dest.id)
                        }
                    } label: {
                        Text(expanded ? "Show fewer" : "Show all \(dest.routes.count)…")
                            .font(.caption2.weight(.medium))
                            .foregroundStyle(Color.accentColor)
                            .frame(maxWidth: .infinity, alignment: .leading)
                    }
                    .buttonStyle(.plain)
                    // Pinned on the BUTTON, not the label: a style's own insets can't
                    // then push the card past the height destHeight predicted.
                    .frame(height: expanderHeight, alignment: .leading)
                }
            }
        }
        // A destination card has no popover to open, but it is still a node you can
        // point at — clicking it lights the path that fills it (Mac → interface →
        // here) and clicking it again lets go. The expander Button inside keeps its
        // own clicks; taps that miss it land here.
        .contentShape(RoundedRectangle(cornerRadius: 10))
        .onTapGesture { select(dest.id) }
        .help("Click to trace what feeds this")
    }

    /// One CIDR, exactly `rowHeight` tall and one line, always. When this row's
    /// interface belongs to a profile with a Custom Routing filter, a small glyph
    /// marks a route that filter ADDED or REPLACED versus what the VPN actually
    /// pushed (`CustomRoutingDiff`) — the at-a-glance health view the drift banner
    /// above already started. Purely decorative (same fixed height either way), so
    /// it can't touch `destHeight`'s prediction.
    private func routeRow(_ row: RouteRow, in dest: GraphNode.Destination,
                          _ outcome: SearchOutcome?, diff: ResourceDiff?) -> some View {
        let lit = isHighlighted(row, in: dest, outcome)
        let delta = diff?.items.first { $0.value == Self.normCIDR(row.cidr) }?.delta
        return HStack(spacing: 2) {
            Text(row.cidr)
                .font(.caption2.monospaced())
                .foregroundStyle(lit ? Color.accentColor : Color.secondary)
                .lineLimit(1)
            if let delta, delta != .unchanged {
                Image(systemName: delta == .added ? "plus.circle.fill" : "arrow.triangle.2.circlepath")
                    .font(.system(size: 7, weight: .bold))
                    .foregroundStyle(delta == .added ? Color.green : Color.orange)
                    .help(delta == .added ? "Added by this VPN's Custom Routing rules"
                                          : "Replaced by this VPN's Custom Routing rules")
                    .accessibilityLabel(delta == .added ? "added by Custom Routing" : "replaced by Custom Routing")
            }
        }
            .padding(.horizontal, 3)
            .frame(height: rowHeight - 2, alignment: .leading)
            .background(lit ? Color.accentColor.opacity(0.12) : .clear,
                        in: RoundedRectangle(cornerRadius: 4))
            .overlay {
                if lit {
                    RoundedRectangle(cornerRadius: 4)
                        .strokeBorder(Color.accentColor, lineWidth: 1.5)
                }
            }
            .frame(height: rowHeight, alignment: .leading)
            .accessibilityLabel(lit ? "\(row.cidr), carries the address you searched for" : row.cidr)
    }

    /// The scrollbar, drawn rather than hosted: a capsule whose length is the fraction
    /// of the list on screen and whose position is how far down it you are.
    private func scrollIndicator(window: CGFloat, total: CGFloat,
                                 offset: CGFloat, limit: CGFloat) -> some View {
        let thumb = max(18, window * (window / max(window, total)))
        let travel = max(0, window - thumb)
        let y = limit > 0 ? travel * (offset / limit) : 0
        return Capsule()
            .fill(Color.secondary.opacity(0.45))
            .frame(width: 3, height: thumb)
            .offset(x: -1, y: y)
            .accessibilityHidden(true)
    }

    /// `highlighted` = the search found it (accent). `selected` = you clicked it (its
    /// own tint, at full strength and a little heavier). They mean different things,
    /// so they look different; when both are true the accent wins and gets fatter
    /// still, because "this is the address you asked about" is the bigger claim.
    private func titledCard(title: String, symbol: String, tint: Color,
                            highlighted: Bool = false, selected: Bool = false,
                            combined: Bool = true,
                            @ViewBuilder body: () -> some View) -> some View {
        VStack(alignment: .leading, spacing: 0) {
            HStack(spacing: 6) {
                Image(systemName: symbol).foregroundStyle(tint)
                Text(title).font(.callout.weight(.medium)).lineLimit(1)
            }
            .padding(.horizontal, 10).frame(height: headerHeight)
            .frame(maxWidth: .infinity, alignment: .leading)
            .background(tint.opacity(0.16))
            Divider()
            body()
                .padding(10)
                .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
        }
        .background(.background.secondary, in: RoundedRectangle(cornerRadius: 10))
        .overlay(RoundedRectangle(cornerRadius: 10)
            .strokeBorder(highlighted ? Color.accentColor : (selected ? tint : tint.opacity(0.55)),
                          lineWidth: highlighted ? (selected ? 3 : 2.5) : (selected ? 2 : 1)))
        .accessibilityElement(children: combined ? .combine : .contain)
    }

    // MARK: Interface inspector (popover — outside the scaled content, so it may
    // use ordinary controls)

    @ViewBuilder private func interfaceInspector(_ snapshot: NetInterface) -> some View {
        // Re-read from the monitor so the counters keep ticking while it's open.
        let iface = topo?.topology.interfaces.first { $0.name == snapshot.name } ?? snapshot
        let state = status(for: iface)
        VStack(alignment: .leading, spacing: 10) {
            HStack(spacing: 8) {
                Image(systemName: iface.systemImage)
                    .font(.title3).foregroundStyle(tint(for: iface))
                VStack(alignment: .leading, spacing: 1) {
                    Text(label(for: iface)).font(.headline)
                    Text(iface.name).font(.caption.monospaced()).foregroundStyle(.secondary)
                }
            }
            Text(state.summary).font(.caption).foregroundStyle(.secondary)

            Divider()
            HStack(spacing: 22) {
                rateBlock("Download", Fmt.rate(iface.inRate), "arrow.down")
                rateBlock("Upload", Fmt.rate(iface.outRate), "arrow.up")
            }

            if !iface.ipv4.isEmpty || !iface.ipv6.isEmpty {
                Divider()
                VStack(alignment: .leading, spacing: 3) {
                    Text("Addresses").font(.caption.weight(.semibold)).foregroundStyle(.secondary)
                    ForEach(iface.ipv4 + iface.ipv6, id: \.self) { a in
                        Text(a).font(.caption.monospaced()).textSelection(.enabled)
                    }
                }
            }
            if topo?.topology.carriesDefault(iface.name) == true {
                Text("Carries the default route").font(.caption).foregroundStyle(.secondary)
            }

            // Actions only where we can actually act. Wi-Fi and Tailscale get the
            // facts and nothing pretending to be a button.
            if let id = actionProfileID(for: iface) {
                Divider()
                HStack(spacing: 8) { inspectorActions(id: id, state: state) }
            }
        }
        .padding(14)
        .frame(width: 290, alignment: .leading)
    }

    /// The globe's popover: facts only, no actions — whatever you'd want to DO about
    /// the Internet is done to the interface carrying it, one card to the left.
    @ViewBuilder private func internetInspector(_ owner: NetInterface?,
                                                standbys: [NetInterface]) -> some View {
        VStack(alignment: .leading, spacing: 10) {
            HStack(spacing: 8) {
                Image(systemName: "globe")
                    .font(.title3).foregroundStyle(owner == nil ? Color.secondary : Color.blue)
                VStack(alignment: .leading, spacing: 1) {
                    Text("Internet").font(.headline)
                    Text("everything not matched by a specific route")
                        .font(.caption).foregroundStyle(.secondary)
                        .fixedSize(horizontal: false, vertical: true)
                }
            }
            Divider()
            if let owner {
                Text("Internet egress via \(label(for: owner))")
                    .font(.callout)
                    .fixedSize(horizontal: false, vertical: true)
                Text(owner.name).font(.caption.monospaced()).foregroundStyle(.secondary)
                if profileID(for: owner) != nil {
                    Text("This is one of your VPN tunnels, so websites see the VPN's location, not where you actually are.")
                        .font(.caption).foregroundStyle(.secondary)
                        .fixedSize(horizontal: false, vertical: true)
                }
            } else {
                Text("Nothing is carrying the default route right now, so there is no way out to the Internet.")
                    .font(.caption).foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }
            // The dashed edges, in words: these hold a default with a real next hop
            // behind the winner, so dropping the tunnel lands you on one of them.
            if !standbys.isEmpty {
                Divider()
                Text("Standby: \(standbys.map { label(for: $0) }.formatted(.list(type: .and))) would take over")
                    .font(.caption).foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }
        }
        .padding(14)
        .frame(width: 270, alignment: .leading)
    }

    /// Facts about the hop, and where they came from. No actions: a proxy is pushed by
    /// the connection, so there is nothing here for the user to change.
    @ViewBuilder private func proxyInspector(_ proxies: [String]) -> some View {
        VStack(alignment: .leading, spacing: 10) {
            HStack(spacing: 8) {
                Image(systemName: "server.rack").font(.title3).foregroundStyle(.orange)
                VStack(alignment: .leading, spacing: 1) {
                    Text(proxies.count == 1 ? "Proxy" : "\(proxies.count) Proxies").font(.headline)
                    Text("on the way out to the Internet")
                        .font(.caption).foregroundStyle(.secondary)
                }
            }
            Divider()
            VStack(alignment: .leading, spacing: 3) {
                ForEach(proxies, id: \.self) { proxy in
                    Text(proxy).font(.caption.monospaced()).textSelection(.enabled)
                }
            }
            Text("Reported by the live connection.")
                .font(.caption).foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
        }
        .padding(14)
        .frame(width: 270, alignment: .leading)
    }

    private func rateBlock(_ title: String, _ value: String, _ symbol: String) -> some View {
        VStack(alignment: .leading, spacing: 1) {
            Label(title, systemImage: symbol)
                .font(.caption).foregroundStyle(.secondary).labelStyle(.titleAndIcon)
            Text(value).font(.callout.monospacedDigit())
        }
    }

    /// nil ⇒ this interface isn't one of ours (or there's no link monitor to judge
    /// it), so the inspector shows facts and no buttons at all.
    private func actionProfileID(for iface: NetInterface) -> String? {
        guard link != nil else { return nil }
        return profileID(for: iface)
    }

    @ViewBuilder private func inspectorActions(id: String, state: EdgeStatus) -> some View {
        switch state {
        case .paused:
            Button("Resume") { act(on: state); inspecting = nil }
            Button("Disconnect") { vpn.disconnect(id: id); inspecting = nil }
        case .stalled:
            Button("Reconnect") { act(on: state); inspecting = nil }
            Button("Disconnect") { vpn.disconnect(id: id); inspecting = nil }
        case .down:
            Button("Connect") { act(on: state); inspecting = nil }
        case .captivePortal:
            Button("Open Sign-In Page") { act(on: state); inspecting = nil }
            Button("Disconnect") { vpn.disconnect(id: id); inspecting = nil }
        case .healthy:
            Button("Reconnect") { Task { await vpn.reconnect(id: id) }; inspecting = nil }
            Button("Disconnect") { vpn.disconnect(id: id); inspecting = nil }
        case .passive:
            EmptyView()
        }
    }

    // MARK: Naming / colour

    /// Prefer OUR profile name for a tunnel we own — "gresearch" beats "utun4".
    private func label(for iface: NetInterface) -> String {
        if let (id, _) = (reach?.latestStats ?? [:]).first(where: { _, s in
            !s.tunnelIPv4.isEmpty && iface.ipv4.contains(s.tunnelIPv4)
        }), let name = vpn.profiles.first(where: { $0.id == id })?.name {
            return name
        }
        return iface.friendlyName
    }

    /// Proxies the LIVE connection reports for this interface's tunnel — the same
    /// profile lookup the inspector's actions use, so a proxy only ever appears for a
    /// tunnel we own and are actually receiving stats from. Empty for anything else,
    /// and an empty list draws nothing at all.
    private func knownProxies(for iface: NetInterface) -> [String] {
        guard let id = profileID(for: iface) else { return [] }
        return reach?.stats(for: id)?.proxies ?? []
    }

    /// The profile that owns this tunnel interface, matched on the in-tunnel address.
    private func profileID(for iface: NetInterface) -> String? {
        (reach?.latestStats ?? [:]).first { _, s in
            !s.tunnelIPv4.isEmpty && iface.ipv4.contains(s.tunnelIPv4)
        }?.key
    }

    /// This destination's owning profile's Custom Routing diff (effective vs
    /// pushed), or nil when the interface isn't ours or has no filter set — the
    /// common case, so most cards draw exactly as before.
    private func customRoutingDiff(for dest: GraphNode.Destination) -> ResourceDiff? {
        guard let iface = topo?.topology.interfaces.first(where: { $0.name == dest.interfaceName }),
              let pid = profileID(for: iface) else { return nil }
        let filter = vpn.customRouting(for: pid).routes
        guard !filter.isIdentity else { return nil }
        let pushed = vpn.lastPushedIntent(for: pid)?.routes ?? PushedIntentSnapshot.Routes()
        return CustomRoutingDiff.diffRoutes(filter: filter, pushed: pushed)
    }

    private static func normCIDR(_ s: String) -> String {
        s.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
    }

    /// Health of the connection behind an interface. Only interfaces we own get an
    /// actionable status — we can't fix someone else's link or Tailscale from here.
    /// The judgement itself comes from LinkStateMonitor so this view can't drift from
    /// the sidebar dot, the header pill or the menu bar.
    private func status(for iface: NetInterface) -> EdgeStatus {
        guard let id = profileID(for: iface), let link else { return .passive }
        switch link.state(for: id) {
        case .captivePortal: return .captivePortal(id)
        case .paused: return .paused(id)
        case .stalled: return .stalled(id)
        case .connected: return .healthy
        case .connecting, .disconnecting, .disconnected: return .down(id)
        }
    }

    private func tint(for iface: NetInterface) -> Color {
        if iface.isTailscale { return .teal }
        if iface.kind == .tunnel { return .purple }
        if topo?.topology.carriesDefault(iface.name) == true { return .blue }
        return .gray
    }

    // MARK: Layout

    private struct Layout {
        var nodes: [GraphNode]
        var edges: [GraphEdge]
        var canvas: CGSize
        /// Route lists that scroll inside their card, in CONTENT coordinates (canvas
        /// inset included). The body converts these to viewport coordinates for the
        /// event catcher; `limits` says how far each one may scroll.
        var scrollRegions: [(id: String, rect: CGRect)] = []
        var scrollLimits: [String: CGFloat] = [:]
    }

    private func buildLayout(_ outcome: SearchOutcome?) -> Layout {
        guard let topo else { return Layout(nodes: [], edges: [], canvas: CGSize(width: 400, height: 200)) }
        let t = topo.topology
        let ifaces = t.interfaces.filter(\.inUse).sorted { a, b in
            func rank(_ i: NetInterface) -> Int {
                if i.kind == .tunnel && !i.isTailscale { return 0 }
                if i.isTailscale { return 1 }
                if t.carriesDefault(i.name) { return 2 }
                return 3
            }
            let (ra, rb) = (rank(a), rank(b))
            return ra == rb ? a.name < b.name : ra < rb
        }

        var nodes: [GraphNode] = []
        var edges: [GraphEdge] = []
        let x0: CGFloat = 0
        let x1 = x0 + colWidth + colGap
        let x2 = x1 + colWidth + colGap      // destinations — and the Internet, and any proxy

        var y: CGFloat = 0
        var ifaceFrames: [(NetInterface, CGRect)] = []
        var regions: [(id: String, rect: CGRect)] = []
        var limits: [String: CGFloat] = [:]
        // The Internet is a SIBLING of the default carrier's destination cards, so it
        // is placed inside that interface's group rather than off in a column of its
        // own: the card visibly fans out into the networks behind it AND the way out.
        var globeFrame: CGRect?
        var proxyFrame: CGRect?
        var internetOwner: (iface: NetInterface, frame: CGRect)?
        var internetProxies: [String] = []

        for iface in ifaces {
            let dests = destinations(for: iface, in: t)
            let ifaceHeight: CGFloat = 96
            // This is the interface the packets actually leave by, so its fan-out
            // gets the Internet — and the proxy in front of it, if the live
            // connection says there is one.
            let ownsInternet = iface.name == t.defaultInterface
            let proxies = ownsInternet ? knownProxies(for: iface) : []
            let internetSlot = ownsInternet
                ? max(internetHeight, proxies.isEmpty ? 0 : proxyHeight) : 0

            // The interface sits vertically centred against its own destinations.
            var destFrames: [(GraphNode.Destination, CGRect)] = []
            var dy = y
            for d in dests {
                let h = destHeight(d)
                destFrames.append((d, CGRect(x: x2, y: dy, width: colWidth, height: h)))
                dy += h + rowGap
            }
            var slotY: CGFloat?
            if ownsInternet {
                slotY = dy
                dy += internetSlot + rowGap
            }
            let stackEmpty = dests.isEmpty && !ownsInternet
            let groupHeight = max(ifaceHeight, dy - y - (stackEmpty ? 0 : rowGap))
            let ifaceFrame = CGRect(x: x1, y: y + (groupHeight - ifaceHeight) / 2,
                                    width: colWidth, height: ifaceHeight)

            if let slotY {
                // With a proxy in the way the globe moves right to make room for it,
                // and the path reads left to right in the order traffic takes it.
                let globeX = proxies.isEmpty ? x2 : x2 + proxyWidth + proxyGap
                globeFrame = CGRect(x: globeX, y: slotY + (internetSlot - internetHeight) / 2,
                                    width: internetWidth, height: internetHeight)
                if !proxies.isEmpty {
                    proxyFrame = CGRect(x: x2, y: slotY + (internetSlot - proxyHeight) / 2,
                                        width: proxyWidth, height: proxyHeight)
                }
                internetOwner = (iface, ifaceFrame)
                internetProxies = proxies
            }
            nodes.append(GraphNode(id: "if-\(iface.name)", kind: .interfaceCard(iface), frame: ifaceFrame))
            ifaceFrames.append((iface, ifaceFrame))

            let active = iface.inRate > 512 || iface.outRate > 512
            let rate = max(iface.inRate, iface.outRate)
            for (d, f) in destFrames {
                nodes.append(GraphNode(id: d.id, kind: .destination(d), frame: f))
                if scrolls(d) {
                    // The row window inside the card, derived from the SAME constants
                    // the card draws with: header, divider, then the body's 10pt inset.
                    regions.append((id: d.id,
                                    rect: CGRect(x: f.minX + canvasInset + 10,
                                                 y: f.minY + canvasInset + headerHeight + 1 + 10,
                                                 width: colWidth - 20,
                                                 height: CGFloat(visibleRowCount(d)) * rowHeight)))
                    limits[d.id] = scrollLimit(d)
                }
                edges.append(GraphEdge(id: "e2-\(d.id)",
                                       from: CGPoint(x: ifaceFrame.maxX, y: ifaceFrame.midY),
                                       to: CGPoint(x: f.minX, y: f.midY),
                                       active: active, rate: rate, tint: tint(for: iface),
                                       status: status(for: iface),
                                       badge: "\(d.routes.count) route\(d.routes.count == 1 ? "" : "s")",
                                       fromNode: iface.name, toNode: d.id))
            }
            y += groupHeight + rowGap * 2
        }

        // Nothing carries a default: the globe still exists (that absence is the
        // point) and still belongs in the destination column, so it goes at the foot
        // of it rather than floating in a column that no longer exists.
        if globeFrame == nil, !ifaceFrames.isEmpty {
            globeFrame = CGRect(x: x2, y: y, width: internetWidth, height: internetHeight)
            y += internetHeight + rowGap * 2
        }

        let canvasHeight = max(240, y - rowGap * 2)
        // Source node, centred against the whole stack.
        let srcHeight: CGFloat = 72
        let srcFrame = CGRect(x: x0, y: (canvasHeight - srcHeight) / 2, width: colWidth, height: srcHeight)
        nodes.insert(GraphNode(id: "source", kind: .source, frame: srcFrame), at: 0)
        for (iface, f) in ifaceFrames {
            let active = iface.inRate > 512 || iface.outRate > 512
            let rate = max(iface.inRate, iface.outRate)
            edges.append(GraphEdge(id: "e1-\(iface.name)",
                                   from: CGPoint(x: srcFrame.maxX, y: srcFrame.midY),
                                   to: CGPoint(x: f.minX, y: f.midY),
                                   active: active, rate: rate,
                                   tint: tint(for: iface),
                                   status: status(for: iface),
                                   controllable: true,
                                   badge: active ? Fmt.rate(rate) : "idle",
                                   fromNode: "source", toNode: iface.name))
        }

        // The terminus. ONE globe, owned by `defaultInterface` — the routing table's
        // actual answer to `route get default`, never "has a default-flagged entry".
        // With no interfaces at all there is no graph to terminate (and the empty-state
        // overlay keys off nodes.count), so the globe only exists alongside them.
        var canvasWidth = x2 + colWidth
        if let globeFrame {
            // Everything else holding a USABLE default — one with a real next-hop
            // address — is a standby: drop the winner and traffic lands here.
            let standbys = ifaceFrames.filter { iface, _ in
                iface.name != t.defaultInterface && Self.hasUsableDefault(iface.name, in: t)
            }
            nodes.append(GraphNode(id: internetNodeID,
                                   kind: .internet(owner: internetOwner?.iface,
                                                   standbys: standbys.map(\.0)),
                                   frame: globeFrame))
            if let owner = internetOwner {
                let f = owner.frame
                let active = owner.iface.inRate > 512 || owner.iface.outRate > 512
                let rate = max(owner.iface.inRate, owner.iface.outRate)
                let tintColor = tint(for: owner.iface)
                let state = status(for: owner.iface)
                let lit = outcome?.hitsInternet == true
                // Same EdgeStatus as this interface's Mac→interface edge, so solid vs
                // dashed says the same thing at every step of the path. No control:
                // the one clickable status icon lives on the inbound edge.
                if let proxyFrame {
                    // A proxy is a real hop and is drawn as one: the traffic leaves the
                    // tunnel, goes through it, and only THEN reaches the Internet.
                    nodes.append(GraphNode(id: proxyNodeID, kind: .proxy(internetProxies),
                                           frame: proxyFrame))
                    edges.append(GraphEdge(id: "e3-proxy",
                                           from: CGPoint(x: f.maxX, y: f.midY),
                                           to: CGPoint(x: proxyFrame.minX, y: proxyFrame.midY),
                                           active: active, rate: rate, tint: tintColor,
                                           status: state, controllable: false,
                                           badge: "all traffic", highlighted: lit,
                                           fromNode: owner.iface.name, toNode: proxyNodeID))
                    edges.append(GraphEdge(id: "e3-internet",
                                           from: CGPoint(x: proxyFrame.maxX, y: proxyFrame.midY),
                                           to: CGPoint(x: globeFrame.minX, y: globeFrame.midY),
                                           active: active, rate: rate, tint: tintColor,
                                           status: state, controllable: false,
                                           highlighted: lit,
                                           fromNode: proxyNodeID, toNode: internetNodeID))
                } else {
                    edges.append(GraphEdge(id: "e3-internet",
                                           from: CGPoint(x: f.maxX, y: f.midY),
                                           to: CGPoint(x: globeFrame.minX, y: globeFrame.midY),
                                           active: active, rate: rate, tint: tintColor,
                                           status: state, controllable: false,
                                           badge: "all traffic", highlighted: lit,
                                           fromNode: owner.iface.name, toNode: internetNodeID))
                }
            }
            // Standby egresses: dashed, dim, no badge (the winner's "all traffic" is
            // the only claim on the traffic) and no control — there is nothing to fix
            // about a route that is merely waiting. One that the search named as an
            // alternative glows, but only a little: it is where this WOULD go, not
            // where it goes, and the difference has to stay visible.
            for (iface, f) in standbys {
                edges.append(GraphEdge(id: "e3-standby-\(iface.name)",
                                       from: CGPoint(x: f.maxX, y: f.midY),
                                       to: CGPoint(x: globeFrame.minX, y: globeFrame.midY),
                                       active: false, rate: 0,
                                       tint: tint(for: iface),
                                       status: status(for: iface),
                                       controllable: false,
                                       highlighted: outcome?.standbyDefaults.contains(iface.name) == true,
                                       standby: true,
                                       fromNode: iface.name, toNode: internetNodeID))
            }
            canvasWidth = max(canvasWidth, globeFrame.maxX)
        }

        return Layout(nodes: nodes, edges: edges,
                      canvas: CGSize(width: canvasWidth, height: canvasHeight),
                      scrollRegions: regions, scrollLimits: limits)
    }

    /// Does this interface hold a default route that could actually carry traffic?
    ///
    /// The test is the GATEWAY. A default whose gateway parses as an address ("default
    /// → 10.0.7.254" on the Wi-Fi) has a real next hop and is a standby egress. A
    /// default whose gateway is an interface ("default → link#20") has nowhere to send
    /// anything — that is a Tailscale-shaped tunnel claiming the default with no exit
    /// node selected — and gets no edge at all, because drawing one would promise an
    /// Internet path that does not exist.
    ///
    /// The WINNER is never decided here: that is `topology.defaultInterface`.
    private static func hasUsableDefault(_ name: String, in t: NetworkTopology) -> Bool {
        t.routes(via: name).contains { $0.isDefault && isGatewayAddress($0.gateway) }
    }

    private static func isGatewayAddress(_ gateway: String) -> Bool {
        guard !gateway.isEmpty else { return false }
        if NetworkTopology.ipv4ToUInt32(gateway) != nil { return true }
        // IPv6 next hop, possibly zoned ("fe80::1%en0"). Demanding "::" or a full eight
        // groups is what keeps MAC addresses out — an ARP row's "a0:99:9b:18:dc:93" is
        // six groups of hex and would otherwise read as an address.
        let bare = gateway.prefix { $0 != "%" }
        guard bare.contains(":") else { return false }
        let groups = bare.split(separator: ":", omittingEmptySubsequences: false)
        let wellFormed = groups.allSatisfy { $0.isEmpty || ($0.count <= 4 && $0.allSatisfy(\.isHexDigit)) }
        return wellFormed && (bare.contains("::") || groups.count == 8)
    }

    /// How many route rows this card actually SHOWS: all of them if it's short, six if
    /// it's collapsed, and at most a window's worth if it's open — the rest scrolls.
    /// Single source of truth for both the drawing and the height prediction.
    private func visibleRowCount(_ d: GraphNode.Destination) -> Int {
        guard d.routes.count > collapseThreshold else { return d.routes.count }
        return expandedCards.contains(d.id) ? min(d.routes.count, expandedWindowRows) : collapsedRows
    }

    /// Open, and longer than the window ⇒ it scrolls inside itself.
    private func scrolls(_ d: GraphNode.Destination) -> Bool {
        d.routes.count > collapseThreshold
            && expandedCards.contains(d.id)
            && d.routes.count > expandedWindowRows
    }

    /// Furthest this card can be scrolled: the last row lands at the bottom of the
    /// window, never past it.
    private func scrollLimit(_ d: GraphNode.Destination) -> CGFloat {
        scrolls(d) ? CGFloat(d.routes.count - expandedWindowRows) * rowHeight : 0
    }

    /// Cards are laid out, not measured, so this has to predict EXACTLY the height the
    /// card will draw at: fixed-height rows, no stack spacing, a fixed expander. The
    /// old version added up a per-row guess that drifted a fraction of a point each
    /// row — invisible at six rows, an overlap of the card below at eighty-one.
    private func destHeight(_ d: GraphNode.Destination) -> CGFloat {
        let chrome = headerHeight + 1 + 20            // header + divider + body padding
        return chrome
            + CGFloat(visibleRowCount(d)) * rowHeight
            + (d.routes.count > collapseThreshold ? expanderHeight : 0)
    }

    /// Apply a scroll that the catcher routed to this card. Deltas arrive in SCREEN
    /// points, so dividing by the zoom keeps a two-finger swipe moving the list the
    /// same distance under the fingers whatever the diagram is scaled to.
    private func scrollCard(_ id: String, by delta: CGSize, limit: CGFloat) {
        let current = cardScroll[id] ?? 0
        let next = min(limit, max(0, current - delta.height / zoom))
        if next != current { cardScroll[id] = next }
    }

    /// The specific networks an interface carries — the ones with real CIDRs to list.
    /// The default route is NOT here: it belongs to the single globe at the far right,
    /// wired to `defaultInterface`. The table carries standby defaults per interface,
    /// and Tailscale-style tunnels can list default-looking routes while no exit node
    /// is even selected; a per-interface Internet card keyed on those drew three
    /// egresses, two of them lies.
    private func destinations(for iface: NetInterface, in t: NetworkTopology) -> [GraphNode.Destination] {
        let routes = t.routes(via: iface.name)
        guard !routes.isEmpty else { return [] }
        var out: [GraphNode.Destination] = []

        // Link-local/multicast noise isn't interesting; drop it so the card is readable.
        let specific = routes.filter { !$0.isDefault }
            .map(\.destination)
            .filter { !$0.hasPrefix("169.254") && !$0.hasPrefix("224.0") && !$0.hasPrefix("255.") }
            .sorted()
        if !specific.isEmpty {
            let isMesh = iface.isTailscale
            out.append(.init(id: "dest-\(iface.name)-specific", interfaceName: iface.name,
                             title: isMesh ? "Tailscale mesh" : (iface.kind == .tunnel ? "Networks behind the VPN" : "Local network"),
                             symbol: isMesh ? "point.3.connected.trianglepath.dotted"
                                 : (iface.kind == .tunnel ? "building.2" : "house"),
                             routes: specific.map { RouteRow(cidr: $0) },
                             tint: isMesh ? .teal : (iface.kind == .tunnel ? .purple : .gray)))
        }
        return out
    }
}
