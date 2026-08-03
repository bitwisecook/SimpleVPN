// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
//  RouteGraphLayout.swift
//  The route graph's MODEL and LAYOUT, split out of RouteGraphView.swift for
//  size, not redesigned: the node/edge types the whole diagram is built from,
//  the naming/colour/health lookups that decide what an interface is called
//  and how its connection is judged, and buildLayout — the computation that
//  turns the routing table into positioned nodes, edges and scroll regions.
//  Nothing here draws: RouteGraphView composes the picture and
//  RouteGraphNodes renders it.
//

import SwiftUI

// MARK: - Model

/// One CIDR out of the routing table. Addressable on its own — the search
/// highlight points at a row, and the future policy editor will need to hang
/// rules off exactly this.
struct RouteRow: Identifiable, Hashable {   // was private — internal for the file split
    let cidr: String
    var id: String { cidr }
}

struct GraphNode: Identifiable {   // was private — internal for the file split
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
enum EdgeStatus: Equatable {   // was private — internal for the file split
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

struct GraphEdge: Identifiable {   // was private — internal for the file split
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

extension RouteGraphView {

    // MARK: Naming / colour

    /// Prefer OUR profile name for a tunnel we own — "gresearch" beats "utun4".
    func label(for iface: NetInterface) -> String {   // was private — internal for the file split
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
    func profileID(for iface: NetInterface) -> String? {   // was private — internal for the file split
        (reach?.latestStats ?? [:]).first { _, s in
            !s.tunnelIPv4.isEmpty && iface.ipv4.contains(s.tunnelIPv4)
        }?.key
    }

    /// This destination's owning profile's Custom Routing diff (effective vs
    /// pushed), or nil when the interface isn't ours or has no filter set — the
    /// common case, so most cards draw exactly as before.
    func customRoutingDiff(for dest: GraphNode.Destination) -> ResourceDiff? {   // was private — internal for the file split
        guard let iface = topo?.topology.interfaces.first(where: { $0.name == dest.interfaceName }),
              let pid = profileID(for: iface) else { return nil }
        let filter = vpn.customRouting(for: pid).routes
        guard !filter.isIdentity else { return nil }
        let pushed = vpn.lastPushedIntent(for: pid)?.routes ?? PushedIntentSnapshot.Routes()
        return CustomRoutingDiff.diffRoutes(filter: filter, pushed: pushed)
    }

    static func normCIDR(_ s: String) -> String {   // was private — internal for the file split
        s.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
    }

    /// Health of the connection behind an interface. Only interfaces we own get an
    /// actionable status — we can't fix someone else's link or Tailscale from here.
    /// The judgement itself comes from LinkStateMonitor so this view can't drift from
    /// the sidebar dot, the header pill or the menu bar.
    func status(for iface: NetInterface) -> EdgeStatus {   // was private — internal for the file split
        guard let id = profileID(for: iface), let link else { return .passive }
        switch link.state(for: id) {
        case .captivePortal: return .captivePortal(id)
        case .paused: return .paused(id)
        case .stalled: return .stalled(id)
        case .connected: return .healthy
        case .connecting, .disconnecting, .disconnected: return .down(id)
        }
    }

    func tint(for iface: NetInterface) -> Color {   // was private — internal for the file split
        if iface.isTailscale { return .teal }
        if iface.kind == .tunnel { return .purple }
        if topo?.topology.carriesDefault(iface.name) == true { return .blue }
        return .gray
    }

    // MARK: Layout

    struct Layout {   // was private — internal for the file split
        var nodes: [GraphNode]
        var edges: [GraphEdge]
        var canvas: CGSize
        /// Route lists that scroll inside their card, in CONTENT coordinates (canvas
        /// inset included). The body converts these to viewport coordinates for the
        /// event catcher; `limits` says how far each one may scroll.
        var scrollRegions: [(id: String, rect: CGRect)] = []
        var scrollLimits: [String: CGFloat] = [:]
    }

    func buildLayout(_ outcome: SearchOutcome?) -> Layout {   // was private — internal for the file split
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
    func visibleRowCount(_ d: GraphNode.Destination) -> Int {   // was private — internal for the file split
        guard d.routes.count > collapseThreshold else { return d.routes.count }
        return expandedCards.contains(d.id) ? min(d.routes.count, expandedWindowRows) : collapsedRows
    }

    /// Open, and longer than the window ⇒ it scrolls inside itself.
    func scrolls(_ d: GraphNode.Destination) -> Bool {   // was private — internal for the file split
        d.routes.count > collapseThreshold
            && expandedCards.contains(d.id)
            && d.routes.count > expandedWindowRows
    }

    /// Furthest this card can be scrolled: the last row lands at the bottom of the
    /// window, never past it.
    func scrollLimit(_ d: GraphNode.Destination) -> CGFloat {   // was private — internal for the file split
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
    func scrollCard(_ id: String, by delta: CGSize, limit: CGFloat) {   // was private — internal for the file split
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
    func destinations(for iface: NetInterface, in t: NetworkTopology) -> [GraphNode.Destination] {   // was private — internal for the file split
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
