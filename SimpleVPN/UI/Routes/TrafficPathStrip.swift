// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
//  TrafficPathStrip.swift
//  The traffic-path indicator, reborn as a compact strip beside the gateway bar's
//  picker: a pure-Canvas picture of where unmatched traffic flows — This Mac →
//  [owner VPN] → Internet, or This Mac → Internet when the pick is Direct. The
//  original lived in the main window's big Default-gateway card; the control it
//  illustrates moved to the Routes window's gatewayBar, so its picture follows it,
//  shrunk to fit the row it now shares.
//
//  ANIMATION lifecycle — motion happens ONLY during a switch, then settles:
//    - `animatingSince` is set on a gateway-owner change and cleared ~0.6 s later,
//      so the TimelineView is `paused` at idle → zero redraws, zero CPU.
//    - accessibilityReduceMotion skips the animation entirely: the Canvas still
//      draws the new static state, it just never runs the moving beam.
//  The transition is a "beam" travelling along the active path, masking the brief
//  no-default gap the STRIP-OLD→ADD-NEW gateway switch opens.
//
//  The OWNER is the route mediator's published truth (`vpn.routes.
//  effectiveGatewayOwner`) — the same value the picker beside this strip binds to,
//  so the two can never tell different stories. (The old card also surfaced the
//  engine-truth desync; here the gatewayBar's own "Applying…" pill carries that.)
//
//  DANGER (layout-loop-crash invariant): this view is Canvas-only — no spinners,
//  toggles or any platform-backed view — so it stays safe even though the bar it
//  sits in is static today. See RouteGraphView.swift for the rule.
//

import SwiftUI

struct TrafficPathStrip: View {
    @Bindable var vpn: VPNController
    @Environment(\.accessibilityReduceMotion) private var reduceMotion

    /// Non-nil only during a switch — gates the TimelineView so idle costs nothing.
    @State private var animatingSince: Date?
    @State private var settle: Task<Void, Never>?

    var body: some View {
        // The mediator's published truth drives the picture — the exact value the
        // picker in the same bar reads and writes.
        let owner = vpn.routes.effectiveGatewayOwner
        let ownerName = vpn.routes.name(for: owner)

        TimelineView(.animation(minimumInterval: 1 / 30,
                                paused: reduceMotion || animatingSince == nil)) { context in
            let phase = animatingSince == nil ? 0 : context.date.timeIntervalSinceReferenceDate
            Canvas { ctx, size in
                draw(ctx: ctx, size: size, ownerName: ownerName, phase: phase)
            }
        }
        .frame(width: 260, height: 40)
        .accessibilityElement()
        .accessibilityLabel(pathDescription(ownerName: ownerName))
        // A switch (or an owner-disconnect fallback) is exactly a change of the
        // effective owner — animate on that, then settle. onChange only, so the
        // strip's first appearance draws still.
        .onChange(of: owner) { _, _ in trigger() }
    }

    private func trigger() {
        guard !reduceMotion else { return }   // reduce motion ⇒ snap, no beam
        settle?.cancel()
        animatingSince = Date()
        settle = Task {
            try? await Task.sleep(for: .milliseconds(600))
            if !Task.isCancelled { animatingSince = nil }
        }
    }

    private func pathDescription(ownerName: String?) -> String {
        if let ownerName { return "Traffic path: this Mac, through \(ownerName), to the Internet." }
        return "Traffic path: this Mac, directly to the Internet."
    }

    // MARK: Drawing (Canvas/Text/shapes only)

    private func draw(ctx: GraphicsContext, size: CGSize, ownerName: String?, phase: TimeInterval) {
        let midY: CGFloat = 14
        let r: CGFloat = 8
        // Inset leaves room for the labels centred under the end nodes.
        let inset: CGFloat = 30
        let mac = CGPoint(x: inset, y: midY)
        let net = CGPoint(x: size.width - inset, y: midY)
        // Middle node only exists when a VPN owns the default.
        let hop: CGPoint? = ownerName == nil ? nil : CGPoint(x: size.width * 0.5, y: midY)
        let ink = Color.accentColor

        var points = [mac]
        if let hop { points.append(hop) }
        points.append(net)

        // Base line — solid, active colour: this is the path in force.
        var line = Path()
        line.move(to: points[0])
        for p in points.dropFirst() { line.addLine(to: p) }
        ctx.stroke(line, with: .color(ink.opacity(0.85)),
                   style: StrokeStyle(lineWidth: 2, lineCap: .round, lineJoin: .round))

        // Travelling beam during the switch — a bright dot sweeping the path with
        // trailing pips so direction reads clearly; nothing when settled.
        if animatingSince != nil {
            let total = polylineLength(points)
            for k in 0..<3 {
                let frac = ((phase * 0.9 + Double(k) * 0.18).truncatingRemainder(dividingBy: 1))
                let at = pointAlong(points, fraction: CGFloat(frac), total: total)
                let sz: CGFloat = k == 0 ? 5 : 3.5
                ctx.fill(Path(ellipseIn: CGRect(x: at.x - sz / 2, y: at.y - sz / 2, width: sz, height: sz)),
                         with: .color(ink.opacity(k == 0 ? 1 : 0.55)))
            }
        }

        // Nodes on top of the line.
        node(ctx, at: mac, radius: r, symbol: "laptopcomputer", tint: ink, filled: true)
        if let hop { node(ctx, at: hop, radius: r, symbol: "lock.shield.fill", tint: ink, filled: true) }
        node(ctx, at: net, radius: r, symbol: "globe",
             tint: ownerName == nil ? .secondary : ink, filled: ownerName != nil)

        // Labels beneath each node. The owner name is clipped by character count —
        // Canvas text doesn't truncate itself, and a long profile name must not
        // run under the globe's label.
        label(ctx, "This Mac", at: CGPoint(x: mac.x, y: mac.y + r + 3))
        if let hop, let ownerName {
            label(ctx, ownerName.count > 16 ? String(ownerName.prefix(15)) + "…" : ownerName,
                  at: CGPoint(x: hop.x, y: hop.y + r + 3), strong: true)
        }
        label(ctx, ownerName == nil ? "Internet (direct)" : "Internet",
              at: CGPoint(x: net.x, y: net.y + r + 3))
    }

    private func node(_ ctx: GraphicsContext, at p: CGPoint, radius r: CGFloat,
                      symbol: String, tint: Color, filled: Bool) {
        let rect = CGRect(x: p.x - r, y: p.y - r, width: 2 * r, height: 2 * r)
        ctx.fill(Path(ellipseIn: rect),
                 with: .color(filled ? tint.opacity(0.16) : Color(nsColor: .windowBackgroundColor)))
        ctx.stroke(Path(ellipseIn: rect), with: .color(tint.opacity(0.9)), lineWidth: 1.5)
        let resolved = ctx.resolve(Text(Image(systemName: symbol))
            .font(.system(size: 8))
            .foregroundStyle(tint))
        ctx.draw(resolved, at: p)
    }

    private func label(_ ctx: GraphicsContext, _ text: String, at p: CGPoint, strong: Bool = false) {
        let t = Text(text)
            .font(.caption2.weight(strong ? .semibold : .regular))
            .foregroundStyle(strong ? AnyShapeStyle(Color.primary) : AnyShapeStyle(Color.secondary))
        ctx.draw(ctx.resolve(t), at: p, anchor: .top)
    }

    // MARK: Polyline maths

    private func polylineLength(_ pts: [CGPoint]) -> CGFloat {
        guard pts.count > 1 else { return 0 }
        var total: CGFloat = 0
        for i in 1..<pts.count { total += distance(pts[i - 1], pts[i]) }
        return total
    }

    private func pointAlong(_ pts: [CGPoint], fraction: CGFloat, total: CGFloat) -> CGPoint {
        guard pts.count > 1, total > 0 else { return pts.first ?? .zero }
        var target = fraction * total
        for i in 1..<pts.count {
            let seg = distance(pts[i - 1], pts[i])
            if target <= seg {
                let f = seg == 0 ? 0 : target / seg
                return CGPoint(x: pts[i - 1].x + (pts[i].x - pts[i - 1].x) * f,
                               y: pts[i - 1].y + (pts[i].y - pts[i - 1].y) * f)
            }
            target -= seg
        }
        return pts.last ?? .zero
    }

    private func distance(_ a: CGPoint, _ b: CGPoint) -> CGFloat {
        hypot(a.x - b.x, a.y - b.y)
    }
}
