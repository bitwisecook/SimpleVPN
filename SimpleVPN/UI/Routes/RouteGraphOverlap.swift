// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
//  RouteGraphOverlap.swift
//  The Custom-Routing overlap arrow for the route graph — the Routes-window port
//  of the editor's arrow (CustomRoutingTabView.swift). Same vocabulary on a
//  different surface: there the arrow runs from an `.overlapping` RULE to the
//  pushed route it collides with; here it runs from the route that rule INJECTED
//  (the row already wearing the green "+" delta glyph) to the sibling row(s) it
//  overlaps in the same destination card, because in this window the routing
//  table's rows ARE the picture.
//
//  Deliberately a re-implementation, not a shared component: the editor resolves
//  row positions through `anchorPreference` because its rows live in a real
//  ScrollView; these rows are laid out by PREDICTION (destHeight/rowHeight — the
//  windowed slice means an off-screen row is never even built, so it could never
//  publish an anchor), which makes arithmetic from the card frame + cardScroll
//  both simpler and the only correct source. Factoring the two onto one geometry
//  mechanism would mean destabilising the editor's working arrow for no gain.
//  What IS shared is the language: the same orange dashed ink, the same draw-in
//  (a path trim revealing 0→1, then still), the same clamp-to-the-window-edge
//  chevron when an endpoint is scrolled or collapsed out of sight.
//
//  Everything here draws inside the scaled container, so the hard rule applies:
//  Canvas, shapes and .plain Buttons only — no platform-backed views. The reveal
//  is driven by a TimelineView that PAUSES the moment the trim settles (and
//  under Reduce Motion never runs at all — the arrow just appears whole).
//

import SwiftUI

extension RouteGraphView {

    // MARK: The model side — which rows overlap what

    /// For one destination card: normalized CIDR of every route an `.overlapping`
    /// Add rule injected → the sibling rows (as worded in the table) it collides
    /// with. Empty for every card whose interface isn't ours or has no filter —
    /// the common case, so most cards pay one guard and nothing else.
    ///
    /// The status judgement is the MODEL's (`RouteFilter.ruleStatus` against the
    /// pushed snapshot — the exact test the editor's badge uses), so the two
    /// surfaces can never disagree about what "overlapping" means. The victims are
    /// then re-found among the rows this card actually DRAWS, because an arrow
    /// must point at a row that exists: a pushed route another rule ignored is a
    /// real overlap in the editor but has no row here to point at.
    func overlapMap(for dest: GraphNode.Destination) -> [String: [String]] {
        guard let iface = topo?.topology.interfaces.first(where: { $0.name == dest.interfaceName }),
              let pid = profileID(for: iface) else { return [:] }
        let filter = vpn.customRouting(for: pid).routes
        guard !filter.isIdentity else { return [:] }
        let pushed = vpn.lastPushedIntent(for: pid)?.routes ?? PushedIntentSnapshot.Routes()
        var map: [String: [String]] = [:]
        for rule in filter.rules where filter.ruleStatus(rule, against: pushed) == .overlapping {
            guard let t = rule.target, !t.isDefault else { continue }
            let added = t.normalized
            let victims = dest.routes.map(\.cidr).filter {
                let n = Self.normCIDR($0)
                return n != added && RoutePrefixMath.overlaps(added, n)
            }
            if !victims.isEmpty { map[added, default: []].append(contentsOf: victims) }
        }
        return map
    }

    func overlapKey(_ dest: GraphNode.Destination, _ cidr: String) -> String {
        "\(dest.id)|\(Self.normCIDR(cidr))"
    }

    /// Click the icon → the arrow draws in; click it again → it goes away. One
    /// piece of state, exactly like the editor's `focusedRuleID`, so an arrow can
    /// never outlive the focus that asked for it.
    func toggleOverlapFocus(_ dest: GraphNode.Destination, _ cidr: String) {
        let key = overlapKey(dest, cidr)
        overlapSettle?.cancel()
        guard overlapFocus != key else {
            overlapFocus = nil
            overlapRevealStart = nil
            return
        }
        overlapFocus = key
        // The arrow is drawn Canvas ink — invisible to VoiceOver — so the
        // reveal SAYS what it shows, through the app's one announcement funnel
        // (user-initiated, so it speaks immediately; the click is the debounce).
        let norm = Self.normCIDR(cidr)
        if let victims = overlapMap(for: dest)[norm], !victims.isEmpty {
            AccessibilityAnnouncer.sayNow(
                "\(cidr) overlaps \(victims.formatted(.list(type: .and)))")
        }
        // Reduce Motion: no reveal to run — the layer draws the finished arrow.
        guard !reduceMotion else { overlapRevealStart = nil; return }
        overlapRevealStart = Date()
        overlapSettle = Task {
            // Trim runs 0→1 over 0.3 s; the extra slack means the pause can never
            // land before the final full-length frame has drawn.
            try? await Task.sleep(for: .milliseconds(450))
            if !Task.isCancelled { overlapRevealStart = nil }
        }
    }

    // MARK: The drawing side

    /// The arrow layer, sized to the whole canvas so it can draw anywhere the
    /// focused card is. Draws nothing at all (and its TimelineView sits paused)
    /// unless a row is focused — the resting cost of this feature is one nil check.
    @ViewBuilder func overlapArrowLayer(_ layout: Layout) -> some View {
        if let focus = overlapFocus,
           let (dest, frame) = overlapFocusTarget(focus, in: layout) {
            let cidr = String(focus.dropFirst(dest.id.count + 1))
            TimelineView(.animation(minimumInterval: 1 / 60,
                                    paused: overlapRevealStart == nil)) { context in
                Canvas { ctx, _ in
                    drawOverlapArrows(ctx: ctx, dest: dest, frame: frame, cidr: cidr,
                                      progress: overlapProgress(at: context.date))
                }
            }
            // Sized to the canvas and positioned like edgeLayer: node frames are
            // already in this ZStack's coordinate space (the canvasInset padding
            // is applied OUTSIDE, on the whole stack), so points are used raw.
            .frame(width: layout.canvas.width, height: layout.canvas.height)
            .allowsHitTesting(false)
            .accessibilityHidden(true)   // the icon's label + help already say it
        }
    }

    /// The focused card, found by its id prefix in the key. A focus whose card has
    /// vanished (route change, disconnect) resolves to nothing and the layer simply
    /// draws nothing — stale focus can't draw a stale arrow.
    private func overlapFocusTarget(_ focus: String, in layout: Layout)
        -> (GraphNode.Destination, CGRect)? {
        for node in layout.nodes {
            if case .destination(let d) = node.kind, focus.hasPrefix("\(d.id)|") {
                return (d, node.frame)
            }
        }
        return nil
    }

    /// 0→1 over 0.3 s from the reveal's start; 1 forever once settled, and 1
    /// immediately under Reduce Motion (the trigger never sets a start date then).
    private func overlapProgress(at date: Date) -> CGFloat {
        guard let start = overlapRevealStart else { return 1 }
        return min(1, CGFloat(date.timeIntervalSince(start)) / 0.3)
    }

    /// One row endpoint, by PREDICTION (the same constants destinationCard draws
    /// with — header + divider + 10pt body inset, rowHeight rows, cardScroll
    /// offset), clamped into the card's visible row window. `offscreen` + `toward`
    /// reproduce the editor's viewport-edge chevron: a collapsed or scrolled-away
    /// row gets the arrow to the window edge and a hint which way it really lies.
    private struct OverlapEndpoint {
        var point: CGPoint
        var offscreen: Bool
        var toward: CGFloat        // sign of (true y − clamped y)
    }

    private func overlapEndpoint(index: Int, dest: GraphNode.Destination,
                                 frame: CGRect) -> OverlapEndpoint {
        let top = frame.minY + headerHeight + 1 + 10
        let windowHeight = CGFloat(visibleRowCount(dest)) * rowHeight
        let offset = scrolls(dest) ? min(scrollLimit(dest), max(0, cardScroll[dest.id] ?? 0)) : 0
        let raw = top + CGFloat(index) * rowHeight - offset + rowHeight / 2
        let y = min(max(raw, top + 5), top + windowHeight - 5)
        // Attached just off the card's LEFT edge: the bracket bows into the column
        // gap (colGap leaves 90pt of guaranteed air), never over the row text, and
        // never outside the canvas the way a right-side bow on the rightmost
        // column would be.
        return OverlapEndpoint(point: CGPoint(x: frame.minX - 2, y: y),
                               offscreen: abs(raw - y) > 0.5, toward: raw - y)
    }

    private func drawOverlapArrows(ctx: GraphicsContext, dest: GraphNode.Destination,
                                   frame: CGRect, cidr: String, progress: CGFloat) {
        guard let fromIdx = dest.routes.firstIndex(where: { Self.normCIDR($0.cidr) == cidr })
        else { return }
        let victims = overlapMap(for: dest)[cidr] ?? []
        guard !victims.isEmpty else { return }
        let from = overlapEndpoint(index: fromIdx, dest: dest, frame: frame)
        for victim in victims {
            guard let toIdx = dest.routes.firstIndex(where: { $0.cidr == victim }) else { continue }
            let to = overlapEndpoint(index: toIdx, dest: dest, frame: frame)
            drawOverlapArrow(ctx: ctx, from: from, to: to, progress: progress)
        }
    }

    /// Same ink as the editor's arrow — orange, dashed, 2pt, trim-revealed —
    /// bowed LEFT as a bracket because both endpoints share one card edge.
    private func drawOverlapArrow(ctx: GraphicsContext, from: OverlapEndpoint,
                                  to: OverlapEndpoint, progress: CGFloat) {
        var path = Path()
        path.move(to: from.point)
        let bulge = max(26, min(70, abs(to.point.y - from.point.y) * 0.5))
        path.addCurve(to: to.point,
                      control1: CGPoint(x: from.point.x - bulge, y: from.point.y),
                      control2: CGPoint(x: to.point.x - bulge, y: to.point.y))
        let clamped = max(0, min(1, progress))
        let trimmed = path.trimmedPath(from: 0, to: clamped)
        ctx.stroke(trimmed, with: .color(.orange),
                   style: StrokeStyle(lineWidth: 2, lineCap: .round, dash: [5, 4]))
        guard clamped > 0.02 else { return }

        // A clamped endpoint's chevron points at the TRUE row position (scroll or
        // expand that way to find it); an on-screen target's chevron is the
        // arrowhead, arriving from the bow so it points into the row.
        if from.offscreen {
            drawOverlapChevron(ctx: ctx, at: from.point, direction: CGPoint(x: 0, y: from.toward))
        }
        if to.offscreen {
            drawOverlapChevron(ctx: ctx, at: to.point, direction: CGPoint(x: 0, y: to.toward))
        } else if clamped > 0.9 {
            drawOverlapChevron(ctx: ctx, at: trimmed.currentPoint ?? to.point,
                               direction: CGPoint(x: bulge, y: 0))
        }
    }

    private func drawOverlapChevron(ctx: GraphicsContext, at point: CGPoint, direction: CGPoint) {
        let len = max(0.001, (direction.x * direction.x + direction.y * direction.y).squareRoot())
        let ux = direction.x / len, uy = direction.y / len
        let px = -uy, py = ux
        let size: CGFloat = 7
        var path = Path()
        path.move(to: CGPoint(x: point.x + ux * size, y: point.y + uy * size))
        path.addLine(to: CGPoint(x: point.x - ux * size * 0.4 + px * size * 0.6,
                                 y: point.y - uy * size * 0.4 + py * size * 0.6))
        path.addLine(to: CGPoint(x: point.x - ux * size * 0.4 - px * size * 0.6,
                                 y: point.y - uy * size * 0.4 - py * size * 0.6))
        path.closeSubpath()
        ctx.fill(path, with: .color(.orange))
    }

    /// The tooltip, worded like the editor's so the two surfaces read as one.
    func overlapHelp(_ victims: [String]) -> String {
        "Overlaps \(victims.joined(separator: ", ")) — click to see it."
    }
}
