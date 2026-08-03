// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
//  TrafficPathView.swift
//  The animated traffic-path indicator for the Default-gateway card
//  (PolicyRouting.md Tier 2): a pure-SwiftUI picture of where unmatched traffic
//  flows — This Mac → [owner VPN] → Internet, or This Mac → Internet for Direct.
//  Other connected VPNs are shown as dim dashed stubs (they carry only their own
//  subnets).
//
//  ANIMATION lifecycle — motion happens ONLY during a switch, then settles:
//    - `isAnimating` flips true on a gateway change and false ~0.6 s later, so
//      the TimelineView is `paused` at idle → zero redraws, zero CPU.
//    - accessibilityReduceMotion skips the animation entirely: the Canvas still
//      draws the new static state, it just never runs the moving beam.
//  The transition animates a "beam" travelling along the active path, masking the
//  brief no-default gap the STRIP-OLD→ADD-NEW switch opens.
//
//  DANGER (layout-loop-crash invariant): everything inside the animated Canvas is
//  drawn by SwiftUI — Canvas/Text/shapes only. NO Toggle/Picker/ProgressView/
//  NSViewRepresentable inside a transform-animated container (it deadlocks AppKit
//  layout at throw time). The Picker lives in DefaultGatewayCard, OUTSIDE this
//  view. See RouteGraphView.swift / MercatorMapView.swift for the same rule.
//

import SwiftUI

struct TrafficPathView: View {
    @Bindable var vpn: VPNController
    @Environment(\.accessibilityReduceMotion) private var reduceMotion

    /// True only during a switch — gates the TimelineView so idle costs nothing.
    @State private var isAnimating = false
    @State private var settle: Task<Void, Never>?

    var body: some View {
        // ENGINE TRUTH drives the picture: whichever tunnel actually holds the
        // default right now (falling back to the desired pick before the first
        // sample). So the beam can never show a hop while traffic really runs
        // direct, nor Direct while a tunnel really owns 0.0.0.0/0 (RC4/RC5).
        let owner = vpn.displayedGatewayOwner
        let ownerName = owner.flatMap { id in vpn.profiles.first { $0.id == id }?.name }
        // Connected VPNs that are NOT the owner — dim dashed stubs off the Mac.
        let others = vpn.connectedProfiles.filter { $0.id != owner }.map(\.name)

        TimelineView(.animation(minimumInterval: 1 / 30, paused: reduceMotion || !isAnimating)) { context in
            let phase = isAnimating ? context.date.timeIntervalSinceReferenceDate : 0
            Canvas { ctx, size in
                draw(ctx: ctx, size: size, ownerName: ownerName, others: others, phase: phase)
            }
        }
        .frame(height: 96)
        .frame(maxWidth: .infinity)
        .accessibilityElement()
        .accessibilityLabel(pathDescription(ownerName: ownerName))
        // A switch (or an owner-disconnect fallback) is exactly a change of the
        // effective owner — animate on that, then settle.
        .onChange(of: owner) { _, _ in trigger() }
    }

    private func trigger() {
        guard !reduceMotion else { return }   // reduce motion ⇒ snap, no beam
        settle?.cancel()
        isAnimating = true
        settle = Task {
            try? await Task.sleep(for: .milliseconds(600))
            if !Task.isCancelled { isAnimating = false }
        }
    }

    private func pathDescription(ownerName: String?) -> String {
        if let ownerName { return "Traffic path: this Mac, through \(ownerName), to the Internet." }
        return "Traffic path: this Mac, directly to the Internet."
    }

    // MARK: Drawing (Canvas/Text/shapes only)

    private func draw(ctx: GraphicsContext, size: CGSize, ownerName: String?,
                      others: [String], phase: TimeInterval) {
        let midY = size.height * 0.42
        let r: CGFloat = 15
        let inset: CGFloat = r + 8
        let mac = CGPoint(x: inset, y: midY)
        let net = CGPoint(x: size.width - inset, y: midY)
        // Middle node only exists when a VPN owns the default.
        let hop: CGPoint? = ownerName == nil ? nil : CGPoint(x: size.width * 0.5, y: midY)

        let inkDim = Color(nsColor: .separatorColor)
        let inkActive = Color.accentColor

        // The active polyline (Mac → [hop] → Internet).
        var points = [mac]
        if let hop { points.append(hop) }
        points.append(net)

        // Base line — solid, active colour.
        var line = Path()
        line.move(to: points[0])
        for p in points.dropFirst() { line.addLine(to: p) }
        ctx.stroke(line, with: .color(inkActive.opacity(0.85)),
                   style: StrokeStyle(lineWidth: 2.5, lineCap: .round, lineJoin: .round))

        // Travelling beam during the switch — a bright dot sweeping the path,
        // plus a couple of trailing flow pips so direction reads clearly.
        if isAnimating {
            let total = polylineLength(points)
            for k in 0..<3 {
                let frac = ((phase * 0.9 + Double(k) * 0.18).truncatingRemainder(dividingBy: 1))
                let at = pointAlong(points, fraction: CGFloat(frac), total: total)
                let sz: CGFloat = k == 0 ? 6 : 4
                ctx.fill(Path(ellipseIn: CGRect(x: at.x - sz / 2, y: at.y - sz / 2, width: sz, height: sz)),
                         with: .color(inkActive.opacity(k == 0 ? 1 : 0.55)))
            }
        }

        // Dim dashed stubs for the other connected VPNs — they carry only their
        // own subnets, not the default, so they hang off the Mac going nowhere.
        if !others.isEmpty {
            let stubY = size.height - 12
            let baseX = mac.x
            for (i, _) in others.enumerated() {
                let x = baseX + CGFloat(i) * 26 + 22
                var stub = Path()
                stub.move(to: CGPoint(x: mac.x, y: mac.y + r))
                stub.addLine(to: CGPoint(x: x, y: stubY))
                ctx.stroke(stub, with: .color(inkDim),
                           style: StrokeStyle(lineWidth: 1.4, lineCap: .round, dash: [4, 4]))
                ctx.fill(Path(ellipseIn: CGRect(x: x - 3, y: stubY - 3, width: 6, height: 6)),
                         with: .color(inkDim))
            }
        }

        // Nodes on top of the lines.
        node(ctx, at: mac, radius: r, symbol: "laptopcomputer", tint: inkActive, filled: true)
        if let hop { node(ctx, at: hop, radius: r, symbol: "lock.shield.fill", tint: inkActive, filled: true) }
        node(ctx, at: net, radius: r, symbol: "globe", tint: ownerName == nil ? .secondary : inkActive,
             filled: ownerName != nil)

        // Labels beneath each node.
        label(ctx, "This Mac", at: CGPoint(x: mac.x, y: mac.y + r + 12))
        if let hop, let ownerName {
            label(ctx, ownerName, at: CGPoint(x: hop.x, y: hop.y + r + 12), strong: true)
        }
        label(ctx, ownerName == nil ? "Internet (direct)" : "Internet",
              at: CGPoint(x: net.x, y: net.y + r + 12))
    }

    private func node(_ ctx: GraphicsContext, at p: CGPoint, radius r: CGFloat,
                      symbol: String, tint: Color, filled: Bool) {
        let rect = CGRect(x: p.x - r, y: p.y - r, width: 2 * r, height: 2 * r)
        ctx.fill(Path(ellipseIn: rect),
                 with: .color(filled ? tint.opacity(0.16) : Color(nsColor: .windowBackgroundColor)))
        ctx.stroke(Path(ellipseIn: rect), with: .color(tint.opacity(0.9)), lineWidth: 2)
        let resolved = ctx.resolve(Text(Image(systemName: symbol))
            .font(.system(size: 13))
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

// MARK: - The Default-gateway card (the Picker lives HERE, outside the Canvas)

/// Shown in the connection detail when two or more VPNs are connected: the live
/// default-gateway picker, the animated traffic path, and the auto-derived notes.
struct DefaultGatewayCard: View {
    @Bindable var vpn: VPNController

    var body: some View {
        let connected = vpn.connectedProfiles
        let capable = connected.filter { vpn.canBeDefaultGateway($0.id) }
        let incapable = connected.filter { !vpn.canBeDefaultGateway($0.id) }
        let owner = vpn.effectiveGatewayOwner

        VStack(alignment: .leading, spacing: 12) {
            Label("Default gateway", systemImage: "arrow.triangle.branch")
                .font(.headline)

            // Animated path — controls are NOT inside it (layout-loop invariant).
            TrafficPathView(vpn: vpn)

            // The live picker. Arms = capable connected VPNs + Direct. Selecting
            // runs the atomic strip→add switch in the coordinator.
            Picker("Default gateway", selection: Binding(
                get: { owner },
                set: { new in Task { await vpn.setDefaultGateway(to: new) } })
            ) {
                ForEach(capable) { p in
                    Text(p.name).tag(Optional(p.id))
                }
                Text("Direct").tag(String?.none)
            }
            .pickerStyle(.segmented)
            .labelsHidden()

            // Where unmatched traffic goes, in words.
            Text(gatewaySummary(owner: owner))
                .font(.callout)
                .foregroundStyle(.secondary)

            // The DNS + Proxy mediators' EFFECTIVE decision, published live (P2/P3).
            // Compact companions to the route owner above so all three system-state
            // resources are visible in one place. Drift is called out when detected.
            if let dnsOwner = vpn.dns.name(for: vpn.dns.effectiveCatchAllOwner) {
                Label("DNS resolves through \(dnsOwner)", systemImage: "network")
                    .font(.caption).foregroundStyle(.secondary)
                    .frame(maxWidth: .infinity, alignment: .leading)
            }
            if vpn.proxies.plan.providesProxy {
                Label("Proxy: \(vpn.proxies.effectiveProxyDescription)", systemImage: "server.rack")
                    .font(.caption).foregroundStyle(.secondary)
                    .frame(maxWidth: .infinity, alignment: .leading)
            }
            if vpn.dns.lastDrift != nil || vpn.proxies.lastDrift != nil {
                Label("An external DNS/proxy change was detected — see Network Tools.",
                      systemImage: "exclamationmark.arrow.triangle.2.circlepath")
                    .font(.caption).foregroundStyle(.orange)
                    .frame(maxWidth: .infinity, alignment: .leading)
            }

            // Transient desync surfaced honestly: the engines currently route
            // differently from the pick above; reconciliation is converging them
            // (RC4/RC5). Shows the effective truth rather than pretending.
            if vpn.displayedGatewayOwner != owner {
                Label(reconcilingNote(effective: vpn.displayedGatewayOwner),
                      systemImage: "arrow.triangle.2.circlepath")
                    .font(.caption)
                    .foregroundStyle(.secondary)
                    .frame(maxWidth: .infinity, alignment: .leading)
            }

            // Auto "also routes …" lines for every connected VPN with subnets.
            ForEach(connected) { p in
                let subnets = vpn.gatewaySubnets(for: p.id)
                if !subnets.isEmpty {
                    Text("\(Text(p.name).fontWeight(.medium)) also routes  \(Text(subnets.joined(separator: " · ")).monospaced())")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                        .frame(maxWidth: .infinity, alignment: .leading)
                }
            }

            // Demotion notes: a VPN that wanted full-tunnel but isn't the owner.
            ForEach(connected) { p in
                if p.id != owner, vpn.canBeDefaultGateway(p.id), vpn.profileWantsFullTunnel(p.id) {
                    Label("\(p.name) wants to route everything; it isn't the default, so only its subnets go through it.",
                          systemImage: "arrow.uturn.down")
                        .font(.caption)
                        .foregroundStyle(.secondary)
                        .frame(maxWidth: .infinity, alignment: .leading)
                }
            }

            // Incapable connected VPNs — listed with why they can't be the gateway.
            ForEach(incapable) { p in
                Label(incapableFootnote(p), systemImage: "info.circle")
                    .font(.caption)
                    .foregroundStyle(.tertiary)
                    .frame(maxWidth: .infinity, alignment: .leading)
            }
        }
        .padding(16)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(RoundedRectangle(cornerRadius: 12)
            .fill(Color(nsColor: .controlBackgroundColor)))
        .overlay(RoundedRectangle(cornerRadius: 12)
            .strokeBorder(Color(nsColor: .separatorColor), lineWidth: 1))
    }

    private func reconcilingNote(effective: String?) -> String {
        if let effective, let name = vpn.profiles.first(where: { $0.id == effective })?.name {
            return "Applying change — traffic currently routes through \(name)."
        }
        return "Applying change — traffic currently routes directly."
    }

    private func gatewaySummary(owner: String?) -> String {
        guard let owner, let name = vpn.profiles.first(where: { $0.id == owner })?.name else {
            return "Unmatched traffic goes directly out your normal connection. Each VPN still carries its own subnets. Change anytime."
        }
        return "Unmatched traffic goes through \(name). Every other VPN carries only its own subnets. Change anytime."
    }

    private func incapableFootnote(_ p: VPNController.Profile) -> String {
        // The mediator classifies every VPN kind into one clean bucket and hands back
        // the exact reason it can't be the gateway (proxy-only, OS-managed, engine not
        // built, or a tailscale without an exit node) — so no kind is silently dropped.
        vpn.routes.gatewayExclusionReason(for: p.id)
            ?? "\(p.name) can't carry all traffic, so it can't be the gateway."
    }
}
