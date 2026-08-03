// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
//  RouteGraphNodes.swift
//  The DRAWING of the route graph, split out of RouteGraphView.swift for
//  size, not redesigned: the dot-grid background, the edge Canvas (dashed
//  beziers that march when bytes move), the clickable mid-edge status
//  controls, and every card — This Mac, the interfaces, the destination route
//  lists, the proxy hop and the globe. Everything here lives INSIDE the
//  scaled container, so it obeys that container's one hard rule: SwiftUI
//  drawing only — Canvas, Text, shapes and .plain Buttons; no platform-backed
//  views. (The popovers the cards open render outside the transform; their
//  contents live in RouteGraphInspector.)
//

import SwiftUI

extension RouteGraphView {

    // MARK: Background

    func dotGrid(size: CGSize) -> some View {   // was private — internal for the file split
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

    @ViewBuilder func edgeLayer(_ edges: [GraphEdge], chain: Set<String>) -> some View {   // was private — internal for the file split
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
    @ViewBuilder func edgeControl(_ e: GraphEdge) -> some View {   // was private — internal for the file split
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

    func act(on status: EdgeStatus) {   // was private — internal for the file split
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

    @ViewBuilder func card(_ node: GraphNode, _ outcome: SearchOutcome?) -> some View {   // was private — internal for the file split
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
}
