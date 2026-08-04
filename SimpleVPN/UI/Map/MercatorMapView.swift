// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
//  MercatorMapView.swift
//  A simple, beautiful flat-Mercator world map: Natural Earth 110m coastlines
//  rendered in a Canvas (one cached CGPath, so a redraw is two fills and a
//  stroke), endpoint pins + a "you are here" marker as real SwiftUI views on
//  top (clickable, hoverable, accessible). Drag or two-finger-scroll to pan,
//  pinch / ⌘-scroll / double-click / −+ controls to zoom (1–8×). Every color is
//  semantic — the map follows light/dark and Increase Contrast automatically.
//
//  The map is an enhancement, never the only path: the endpoint dropdown next
//  to it is the canonical (and accessibility) control.
//

import SwiftUI
import simd

// MARK: - Pins

struct MapPin: Identifiable, Equatable {
    enum Kind: Equatable { case endpoint(selected: Bool), user, egress }

    /// How much this pin's coordinate is claiming.
    ///  • `exact` — geolocated from the address actually in use.
    ///  • `approximate` — country-level, taken from the endpoint's OWN
    ///    configuration (the country the user set on it, or where that hostname
    ///    resolves from). Approximate is honest; invented is not — this is never
    ///    a country nothing in the configuration names.
    ///  • `placeholder` — no location at all, so the pin is parked beside
    ///    whatever it is tethered to.
    /// Anything but `exact` wears a dotted halo: "this is roughly where it is",
    /// or "this is where we put it, not where it is".
    enum Placement: Equatable { case exact, approximate, placeholder }

    let id: String
    var kind: Kind
    var lat: Double
    var lon: Double
    var title: String
    var subtitle: String
    var placement: Placement = .exact
    /// The id of the pin this one is drawn beside, because it would otherwise sit
    /// underneath it. Presentation only: lat/lon still say where this pin is, and
    /// the separation lives in `screenOffset` (points), never in the coordinate.
    var tetheredTo: String? = nil
    /// Nudge applied after projection, in view points. Zoom-invariant on purpose:
    /// an offset expressed in degrees would grow into a claim about coordinates.
    var screenOffset: CGSize = .zero

    /// True only when lat/lon are a real geolocation of the address in use.
    var locationKnown: Bool { placement == .exact }
    /// Drawn larger and clearly separate: a tethered pin shares its anchor's spot
    /// on the globe, so at normal size the two read as one dot — which is exactly
    /// how a live VPN ended up looking like "the client dot moved".
    var isTethered: Bool { tetheredTo != nil }
}

/// A great-circle link between two pins (by id) for the live-topology map.
struct MapConnection: Equatable {
    /// How the link should read. `tunnel` = traffic is going through the VPN
    /// (solid accent, plus a slow travelling highlight so a live tunnel looks
    /// live); `bypass` = traffic reaches the internet outside every tunnel
    /// (thin and dashed). The dash means *only* bypass — it is the leak /
    /// split-tunnel signal and must never be what a working tunnel looks like.
    enum Kind: Equatable { case tunnel, bypass }
    let from: String
    let to: String
    var kind: Kind = .tunnel

    var isTunnel: Bool { kind == .tunnel }
    /// Stable identity for per-link animation state.
    var key: String { "\(from)\u{2192}\(to)" }
}

// MARK: - Map view

struct MercatorMapView: View {
    let pins: [MapPin]
    /// Explicit great-circle links to draw (live topology). Empty ⇒ the default
    /// "this Mac → each endpoint" arcs.
    var connections: [MapConnection] = []
    /// Endpoint pin tapped (never fired for the user pin).
    var onSelect: (String) -> Void = { _ in }

    @Environment(\.accessibilityReduceMotion) private var reduceMotion
    @State private var camera = MapCamera()
    /// When each link first appeared, so a newly-connected tunnel draws itself in
    /// from home instead of popping into existence. Kept in step with `connections`.
    @State private var linkAppeared: [String: Date] = [:]

    var body: some View {
        // Height comes from the proposed width during layout — see HeightFromWidth. The
        // previous version measured the rendered width into @State and fed it back into a
        // .frame(height:), which is a layout feedback loop: height change → relayout →
        // re-measure → state write → height change. Inside a ScrollView it never settles
        // (a height change can add or remove a scrollbar, changing the width), and AppKit
        // eventually threw NSGenericException: "more Update Constraints in Window passes
        // than there are views in the window". That was the crash.
        HeightFromWidth(ratio: 2) {
        GeometryReader { geo in
            let size = geo.size
            ZStack {
                baseMap(size: size)
                connectionsLayer(size: size)
                pinOverlay(size: size)
                controls
            }
            .clipShape(RoundedRectangle(cornerRadius: 10))
            .overlay(RoundedRectangle(cornerRadius: 10)
                .strokeBorder(Color(nsColor: .separatorColor), lineWidth: 1))
            .contentShape(Rectangle())
            // Mouse / one-finger click-drag pans. Trackpad two-finger pan and pinch
            // are NSEvents that no SwiftUI gesture here ever saw, so they come in
            // through PanZoomEventCatcher below (which also owns pinch outright, so the
            // two paths can't both apply a zoom and square it).
            .gesture(dragGesture(size: size))
            .onTapGesture(count: 2) { location in
                camera.zoom(by: 2, anchor: location, viewSize: size)
            }
            // Keyboard path for the mouse-only pan/zoom (same keys as the route
            // diagram): Tab focuses the map, arrows pan, +/− zoom.
            .focusable()
            .onMoveCommand { direction in
                let step: CGFloat = 40
                let delta: CGSize = switch direction {
                case .left: CGSize(width: step, height: 0)
                case .right: CGSize(width: -step, height: 0)
                case .up: CGSize(width: 0, height: step)
                case .down: CGSize(width: 0, height: -step)
                @unknown default: .zero
                }
                camera.pan(by: delta, viewSize: size)
            }
            .onKeyPress(characters: CharacterSet(charactersIn: "+-=")) { press in
                switch press.characters {
                case "+", "=": camera.zoom(by: 1.5, anchor: nil, viewSize: nil)
                case "-": camera.zoom(by: 1 / 1.5, anchor: nil, viewSize: nil)
                default: return .ignored
                }
                return .handled
            }
            .background(PanZoomEventCatcher(
                onPan: { delta in camera.pan(by: delta, viewSize: size) },
                onZoom: { factor, anchor in
                    camera.setScale(camera.scale * factor, anchor: anchor, viewSize: size)
                }))
        }
        }
        .frame(maxWidth: .infinity)
        .accessibilityElement(children: .contain)
        .accessibilityLabel("World map of VPN servers. Use the server menu for the full list.")
        // The picture in one sentence — where you appear from, each gateway,
        // the egress — built from the same pins the map draws, so it changes
        // when they do. The pins stay individually reachable children (each is
        // a real Button with its own label); this is the read-at-a-glance.
        .accessibilityValue(accessibilitySummary)
    }

    /// "You appear from London. Tig Lab gateway, Zurich. Internet egress,
    /// Frankfurt. 3 endpoints." — user first, then hops, then the crowd.
    private var accessibilitySummary: String {
        var parts: [String] = []
        if let user = pins.first(where: { $0.kind == .user }) {
            parts.append(user.subtitle.isEmpty
                ? "You are at \(user.title)"
                : "You appear from \(user.subtitle)")
        }
        // With explicit topology links this is the live map (home → VPN →
        // egress): name every hop. Without them it's the endpoint picker map,
        // where per-endpoint detail belongs to the pins and the menu — count
        // them and call out the selection instead.
        if !connections.isEmpty {
            for pin in pins {
                switch pin.kind {
                case .endpoint:
                    parts.append("\(pin.title) VPN server"
                        + (pin.subtitle.isEmpty ? "" : ", \(pin.subtitle)"))
                case .egress:
                    parts.append("Internet egress"
                        + (pin.subtitle.isEmpty ? ", \(pin.title)" : ", \(pin.subtitle)"))
                case .user:
                    break
                }
            }
        } else {
            let endpoints = pins.filter { if case .endpoint = $0.kind { return true }; return false }
            if !endpoints.isEmpty {
                parts.append("\(endpoints.count) endpoint\(endpoints.count == 1 ? "" : "s") shown")
            }
            if let selected = endpoints.first(where: isSelected) {
                parts.append("\(selected.title) selected"
                    + (selected.subtitle.isEmpty ? "" : ", \(selected.subtitle)"))
            }
        }
        return parts.joined(separator: ". ")
    }

    // MARK: Base map

    private func baseMap(size: CGSize) -> some View {
        Canvas { context, canvasSize in
            let transform = camera.transform(viewSize: canvasSize)

            context.fill(Path(CGRect(origin: .zero, size: canvasSize)),
                         with: .color(Color(nsColor: .underPageBackgroundColor)))

            guard let land = WorldGeometry.shared?.path else { return }
            var path = Path(land)
            path = path.applying(transform)
            context.fill(path, with: .color(Color(nsColor: .quaternarySystemFill)))
            context.stroke(path, with: .color(Color(nsColor: .separatorColor)), lineWidth: 1)
        }
    }

    // MARK: Great-circle connections (this Mac → each endpoint)

    /// Draw-in time for a link that has just appeared.
    private static let drawInDuration: TimeInterval = 0.55
    /// The travelling highlight: one bright blob per `flowDash` cycle, moving from
    /// `from` towards `to` at ~one pattern length per `flowPeriod`.
    private static let flowDash: [CGFloat] = [14, 96]
    private static let flowPeriod: TimeInterval = 1.8
    private static var flowLength: CGFloat { flowDash.reduce(0, +) }

    /// Only spend frames when there is something live to animate.
    private var flowAnimates: Bool {
        !reduceMotion && connections.contains { $0.isTunnel }
    }

    private func connectionsLayer(size: CGSize) -> some View {
        TimelineView(.animation(minimumInterval: 1.0 / 30.0, paused: !flowAnimates)) { timeline in
            Canvas { context, canvasSize in
                drawConnections(&context, size: canvasSize, now: timeline.date)
            }
        }
        .allowsHitTesting(false)
        .onAppear { syncLinkAppearance() }
        .onChange(of: connections) { syncLinkAppearance() }
    }

    /// Stamp newly-arrived links and forget departed ones. Without this a link that
    /// comes back later would still be holding its original (long past) timestamp
    /// and would skip its draw-in.
    private func syncLinkAppearance() {
        let keys = Set(connections.map(\.key))
        var next = linkAppeared.filter { keys.contains($0.key) }
        let now = Date()
        for k in keys where next[k] == nil { next[k] = now }
        if next != linkAppeared { linkAppeared = next }
    }

    /// 0…1 along the arc. Only tunnel links draw in — a bypass link is a warning,
    /// not a celebration, and the timeline is paused when no tunnel is present so
    /// a time-based progress would freeze part-drawn.
    private func drawInProgress(_ c: MapConnection, now: Date) -> Double {
        guard c.isTunnel, !reduceMotion else { return 1 }
        guard let since = linkAppeared[c.key] else { return 0 }   // stamped on the next frame
        return min(1, max(0, now.timeIntervalSince(since) / Self.drawInDuration))
    }

    private func drawConnections(_ context: inout GraphicsContext, size: CGSize, now: Date) {
        let transform = camera.transform(viewSize: size)

        // Explicit topology links (home → VPN(s) → egress), when provided.
        if !connections.isEmpty {
            func pin(_ id: String) -> MapPin? { pins.first { $0.id == id } }
            // Bypass underneath, so a live tunnel always draws over it.
            for c in connections.sorted(by: { !$0.isTunnel && $1.isTunnel }) {
                guard let a = pin(c.from), let b = pin(c.to) else { continue }
                let progress = drawInProgress(c, now: now)
                guard progress > 0 else { continue }
                var path = Path()
                Self.appendGreatCircle(&path, from: (a.lat, a.lon), to: (b.lat, b.lon),
                                       transform: transform,
                                       offsetA: a.screenOffset, offsetB: b.screenOffset,
                                       progress: progress)
                guard c.isTunnel else {
                    context.stroke(path, with: .color(Color.secondary.opacity(0.5)),
                                   style: StrokeStyle(lineWidth: 1, lineCap: .round, dash: [3, 4]))
                    continue
                }
                context.stroke(path, with: .color(Color.accentColor),
                               style: StrokeStyle(lineWidth: 2, lineCap: .round))
                if flowAnimates, progress >= 1 {
                    // A soft accent blob sliding along the arc: cheap (one extra
                    // stroke), theme-proof (it is the accent colour, not white), and
                    // gone entirely under Reduce Motion.
                    let phase = now.timeIntervalSinceReferenceDate
                        .truncatingRemainder(dividingBy: Self.flowPeriod) / Self.flowPeriod
                    context.stroke(path, with: .color(Color.accentColor.opacity(0.4)),
                                   style: StrokeStyle(lineWidth: 5, lineCap: .round,
                                                      dash: Self.flowDash,
                                                      dashPhase: -phase * Self.flowLength))
                }
            }
            return
        }

        // Default: this Mac → each endpoint.
        guard let user = pins.first(where: { $0.kind == .user }) else { return }
        let endpoints = pins.filter { if case .endpoint = $0.kind { return true }; return false }
        for pin in endpoints.sorted(by: { !isSelected($0) && isSelected($1) }) {
            let selected = isSelected(pin)
            var path = Path()
            Self.appendGreatCircle(&path,
                                   from: (user.lat, user.lon), to: (pin.lat, pin.lon),
                                   transform: transform,
                                   offsetA: user.screenOffset, offsetB: pin.screenOffset)
            context.stroke(
                path,
                with: .color(selected ? Color.accentColor : Color.secondary.opacity(0.45)),
                style: StrokeStyle(lineWidth: selected ? 2 : 1, lineCap: .round,
                                   dash: selected ? [] : [3, 4]))
        }
    }

    private func isSelected(_ pin: MapPin) -> Bool {
        if case .endpoint(true) = pin.kind { return true }; return false
    }

    /// Sample the great circle between two lat/lon points (slerp on the unit
    /// sphere), project each sample, and lift the pen across the antimeridian so
    /// the arc wraps cleanly instead of streaking across the map.
    ///
    /// `offsetA`/`offsetB` are view-point nudges for pins that have no real
    /// coordinate; they are blended along the arc so the line still meets both
    /// markers exactly. `progress` reveals a leading fraction of the (fixed)
    /// geometry — a link grows out of its origin rather than appearing whole.
    static func appendGreatCircle(_ path: inout Path, from a: (Double, Double),
                                  to b: (Double, Double), transform: CGAffineTransform,
                                  offsetA: CGSize = .zero, offsetB: CGSize = .zero,
                                  progress: Double = 1) {
        let pts = greatCirclePoints(from: a, to: b)
        guard pts.count >= 2, progress > 0 else { return }
        let last = pts.count - 1
        let limit = min(last, max(1, Int((Double(last) * min(1, progress)).rounded(.up))))
        var prevUnitX: Double?
        for i in 0...limit {
            let (lat, lon) = pts[i]
            let t = Double(i) / Double(last)
            let unit = MapCameraProjection.unit(lat: lat, lon: lon)
            var p = unit.applying(transform)
            p.x += offsetA.width + (offsetB.width - offsetA.width) * t
            p.y += offsetA.height + (offsetB.height - offsetA.height) * t
            if let px = prevUnitX, abs(unit.x - px) >= 0.5 {
                path.move(to: p)                 // wrapped across ±180° (incl. a polar 180° flip) → new segment
            } else if prevUnitX == nil {
                path.move(to: p)
            } else {
                path.addLine(to: p)
            }
            prevUnitX = unit.x
        }
    }

    private static func greatCirclePoints(from a: (Double, Double), to b: (Double, Double),
                                          samples: Int = 72) -> [(Double, Double)] {
        let φ1 = a.0 * .pi / 180, λ1 = a.1 * .pi / 180
        let φ2 = b.0 * .pi / 180, λ2 = b.1 * .pi / 180
        let v1 = SIMD3(cos(φ1) * cos(λ1), cos(φ1) * sin(λ1), sin(φ1))
        let v2 = SIMD3(cos(φ2) * cos(λ2), cos(φ2) * sin(λ2), sin(φ2))
        let dotp = max(-1.0, min(1.0, simd_dot(v1, v2)))
        let omega = acos(dotp)
        // Coincident endpoints: still emit the full sample count. The two pins may
        // share a coordinate but differ by a screen offset (an unplaceable gateway
        // pinned beside home), and that short link has to draw in like any other.
        guard omega > 1e-6 else { return Array(repeating: a, count: samples + 1) }
        let sinOmega = sin(omega)
        // Near-antipodal (omega → π): sinOmega → 0, so the slerp weights below blow
        // up to NaN. The path is geometrically ambiguous anyway — fall back to the
        // endpoints rather than feed NaN lat/lon into the projection.
        guard sinOmega > 1e-6 else { return [a, b] }
        var out: [(Double, Double)] = []
        out.reserveCapacity(samples + 1)
        for i in 0...samples {
            let t = Double(i) / Double(samples)
            let s1 = sin((1 - t) * omega) / sinOmega
            let s2 = sin(t * omega) / sinOmega
            let v = s1 * v1 + s2 * v2
            let lat = atan2(v.z, (v.x * v.x + v.y * v.y).squareRoot()) * 180 / .pi
            let lon = atan2(v.y, v.x) * 180 / .pi
            out.append((lat, lon))
        }
        return out
    }

    // MARK: Pins

    private func pinOverlay(size: CGSize) -> some View {
        // The ZStack is what carries the animation: a transition needs its
        // *container* inside the animated transaction, not the leaf. Opacity only —
        // a transform-animated container is exactly the shape of the old
        // layout-loop crash, and there is nothing to gain from scaling here.
        ZStack {
            ForEach(pins) { pin in
                let point = camera.project(lat: pin.lat, lon: pin.lon, viewSize: size)
                PinView(pin: pin, anchorsTether: pins.contains { $0.tetheredTo == pin.id }) {
                    if case .endpoint = pin.kind { onSelect(pin.id) }
                }
                .position(x: point.x + pin.screenOffset.width,
                          y: point.y + pin.screenOffset.height)
                .transition(.opacity)
            }
        }
        .animation(reduceMotion ? nil : .easeOut(duration: 0.3), value: pins)
    }

    // MARK: Controls

    private var controls: some View {
        VStack(spacing: 0) {
            // Square, content-shaped frames: a borderless button's hit area is the
            // bare glyph, and "minus" is a ~2pt-tall hairline that's nearly impossible
            // to land on. 22pt gives both a real target.
            Button { camera.zoom(by: 1.5, anchor: nil, viewSize: nil) } label: {
                Image(systemName: "plus").frame(width: 22, height: 22).contentShape(Rectangle())
            }
            .accessibilityLabel("Zoom in")
            Divider().frame(width: 16)
            Button { camera.zoom(by: 1 / 1.5, anchor: nil, viewSize: nil) } label: {
                Image(systemName: "minus").frame(width: 22, height: 22).contentShape(Rectangle())
            }
            .accessibilityLabel("Zoom out")
        }
        .buttonStyle(.borderless)
        .padding(6)
        .background(.regularMaterial, in: RoundedRectangle(cornerRadius: 7))
        .padding(8)
        .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .bottomTrailing)
    }

    // MARK: Gestures

    private func dragGesture(size: CGSize) -> some Gesture {
        DragGesture(minimumDistance: 2)
            .onChanged { value in camera.dragging(translation: value.translation, viewSize: size) }
            .onEnded { _ in camera.endDrag() }
    }
}

// MARK: - Trackpad shim (two-finger pan + pinch)


// MARK: - Camera (pan/zoom state in unit-Mercator space)

/// The visible window onto the unit Mercator square. scale 1 = whole world
/// fitted; offsets are in view points.
private struct MapCamera: Equatable {
    var scale: Double = 1
    var offset: CGSize = .zero
    var dragBase: CGSize? = nil

    static let minScale = 1.0
    static let maxScale = 8.0

    /// Unit-Mercator projection — shared math with the geometry baker.
    static func unit(lat: Double, lon: Double) -> CGPoint {
        MapCameraProjection.unit(lat: lat, lon: lon)
    }

    /// The unit square scaled to fill the view (letterboxed on width) then zoomed/panned.
    func transform(viewSize: CGSize) -> CGAffineTransform {
        let base = max(viewSize.width, viewSize.height * 2) // Mercator square: keep w=2h coverage
        let side = base * scale
        return CGAffineTransform.identity
            .translatedBy(x: offset.width + (viewSize.width - side) / 2,
                          y: offset.height + (viewSize.height - side) / 2)
            .scaledBy(x: side, y: side)
    }

    func project(lat: Double, lon: Double, viewSize: CGSize) -> CGPoint {
        Self.unit(lat: lat, lon: lon).applying(transform(viewSize: viewSize))
    }

    mutating func dragging(translation: CGSize, viewSize: CGSize) {
        let base = dragBase ?? offset
        dragBase = base
        offset = clamped(CGSize(width: base.width + translation.width,
                                height: base.height + translation.height),
                         viewSize: viewSize)
    }

    mutating func endDrag() { dragBase = nil }

    /// Incremental pan, for trackpad scroll (which arrives as deltas, not as a
    /// cumulative translation like DragGesture's).
    mutating func pan(by delta: CGSize, viewSize: CGSize) {
        offset = clamped(CGSize(width: offset.width + delta.width,
                                height: offset.height + delta.height),
                         viewSize: viewSize)
    }

    /// Keep the world covering the view. Without this a pan can drag the map
    /// entirely off-screen — previously only the fully-zoomed-out case was reset.
    private func clamped(_ candidate: CGSize, viewSize: CGSize) -> CGSize {
        let side = max(viewSize.width, viewSize.height * 2) * scale
        let limitX = max(0, (side - viewSize.width) / 2)
        let limitY = max(0, (side - viewSize.height) / 2)
        return CGSize(width: min(limitX, max(-limitX, candidate.width)),
                      height: min(limitY, max(-limitY, candidate.height)))
    }

    mutating func zoom(by factor: Double, anchor: CGPoint?, viewSize: CGSize?) {
        setScale(scale * factor, anchor: anchor, viewSize: viewSize)
    }

    mutating func setScale(_ newScale: Double, anchor: CGPoint?, viewSize: CGSize?) {
        let clamped = min(Self.maxScale, max(Self.minScale, newScale))
        if let anchor, let viewSize {
            // Keep the point under the cursor stationary while zooming.
            let before = transform(viewSize: viewSize).inverted()
            let unitAnchor = anchor.applying(before)
            scale = clamped
            let after = unitAnchor.applying(transform(viewSize: viewSize))
            offset = self.clamped(CGSize(width: offset.width + anchor.x - after.x,
                                         height: offset.height + anchor.y - after.y),
                                  viewSize: viewSize)
        } else {
            scale = clamped
        }
        if scale == Self.minScale { offset = .zero }
    }
}

// MARK: - Pin views

private struct PinView: View {
    let pin: MapPin
    /// Another pin is parked beside this one (a gateway that shares its spot on
    /// the globe). The marker grows a second ring so the pair reads as "you, and
    /// a VPN anchored here" rather than as one dot that wandered.
    var anchorsTether: Bool = false
    let action: () -> Void
    @State private var hovering = false

    var body: some View {
        Button(action: action) {
            // A plain endpoint dot is 10pt — far too small a click target. The
            // min-frame guarantees a 28pt target; because pins are placed with
            // .position() (center-anchored) and a frame centers its content, the
            // drawn marker stays exactly on its map coordinate.
            marker
                .frame(minWidth: 28, minHeight: 28)
                .contentShape(Circle())
        }
        .buttonStyle(.plain)
        .onHover { hovering = $0 }
        .help("\(pin.title)\(pin.subtitle.isEmpty ? "" : " — \(pin.subtitle)")")
        .accessibilityLabel(accessibilityText)
        .zIndex(isSelected ? 2 : (pin.kind == .user ? 1 : 0))
    }

    @ViewBuilder private var marker: some View {
        switch pin.kind {
        case .user:
            // "You are here": a steady ring — no pulsing (Reduce Motion friendly).
            // The outer ring only appears while a VPN is anchored here, and it is
            // static too: the "you're connected" signal must survive Reduce Motion.
            ZStack {
                if anchorsTether {
                    Circle().strokeBorder(.tint.opacity(0.45), lineWidth: 2)
                        .frame(width: 28, height: 28)
                }
                Circle().strokeBorder(.tint, lineWidth: 2).frame(width: 16, height: 16)
                Circle().fill(.tint).frame(width: 6, height: 6)
            }
        case .endpoint(let selected):
            // A gateway we couldn't place exactly: the dot stays solid (the tunnel
            // really is up) and a dotted halo says the *position* is country-level,
            // or a placeholder beside you. The dash on a pin means "position not
            // exact"; the dash on a link means "not through the VPN" — different
            // objects, so the two never appear on the same mark.
            let dot: CGFloat = pin.isTethered ? 17 : (selected ? 13 : 10)
            let halo: CGFloat = pin.isTethered ? 30 : 24
            ZStack {
                if pin.placement != .exact {
                    Circle()
                        .strokeBorder(.tint.opacity(0.5),
                                      style: StrokeStyle(lineWidth: pin.isTethered ? 1.5 : 1,
                                                         dash: [2, 3]))
                        .frame(width: halo, height: halo)
                }
                Circle()
                    .fill(selected ? AnyShapeStyle(.tint) : AnyShapeStyle(Color(nsColor: .systemGray)))
                    .frame(width: dot, height: dot)
                    .overlay(Circle().strokeBorder(Color(nsColor: .windowBackgroundColor), lineWidth: 1.5))
            }
            .scaleEffect(hovering ? 1.25 : 1)
            .animation(.easeOut(duration: 0.1), value: hovering)
        case .egress:
            // Where traffic reaches the internet: a green globe-dot.
            Image(systemName: "globe")
                .font(.system(size: 13))
                .foregroundStyle(.green)
                .background(Circle().fill(Color(nsColor: .windowBackgroundColor)).frame(width: 15, height: 15))
                .scaleEffect(hovering ? 1.25 : 1)
                .animation(.easeOut(duration: 0.1), value: hovering)
        }
    }

    private var isSelected: Bool {
        if case .endpoint(true) = pin.kind { return true }
        return false
    }

    private var accessibilityText: String {
        switch pin.kind {
        // The extra ring is the only thing that says "a VPN is anchored here", so
        // VoiceOver has to be told the same thing in words.
        case .user: "Your location: \(pin.title). \(pin.subtitle)"
            + (anchorsTether ? ". A connected VPN is shown beside this point" : "")
        case .egress: "Internet egress: \(pin.title). \(pin.subtitle)"
        case .endpoint(let selected):
            "\(pin.title), \(pin.subtitle)\(selected ? ", selected" : "")" + placementText
        }
    }

    private var placementText: String {
        switch pin.placement {
        case .exact: ""
        case .approximate: pin.isTethered
            ? ", approximate location, shown beside your location"
            : ", approximate location"
        case .placeholder: ", location not public — shown beside your location"
        }
    }
}

// MARK: - Land geometry (bundled Natural Earth 110m, see Tools/convert-naturalearth.py)

/// Loads land-110m.bin once and bakes a single CGPath in unit-Mercator space.
final class WorldGeometry {
    @MainActor static let shared: WorldGeometry? = WorldGeometry()

    let path: CGPath

    private init?() {
        guard let url = Bundle.main.url(forResource: "land-110m", withExtension: "bin"),
              let data = try? Data(contentsOf: url) else { return nil }
        guard let parsed = Self.parse(data) else { return nil }
        path = parsed
    }

    /// Format: "SVMAP1" magic · uint32 LE polygon count · per polygon:
    /// uint32 LE point count then (float32 lon, float32 lat) pairs.
    private static func parse(_ data: Data) -> CGPath? {
        let magic = Data("SVMAP1".utf8)
        guard data.count > magic.count + 4, data.prefix(magic.count) == magic else { return nil }
        var cursor = magic.count

        func readUInt32() -> UInt32? {
            guard cursor + 4 <= data.count else { return nil }
            let v = data.subdata(in: cursor..<cursor + 4).withUnsafeBytes { $0.loadUnaligned(as: UInt32.self) }
            cursor += 4
            return UInt32(littleEndian: v)
        }
        func readFloat() -> Double? {
            guard cursor + 4 <= data.count else { return nil }
            let bits = data.subdata(in: cursor..<cursor + 4).withUnsafeBytes { $0.loadUnaligned(as: UInt32.self) }
            cursor += 4
            return Double(Float(bitPattern: UInt32(littleEndian: bits)))
        }

        guard let polygonCount = readUInt32() else { return nil }
        let path = CGMutablePath()
        for _ in 0..<polygonCount {
            guard let pointCount = readUInt32(), pointCount >= 3 else { return nil }
            var first: CGPoint?
            for i in 0..<pointCount {
                guard let lon = readFloat(), let lat = readFloat() else { return nil }
                let p = MapCameraProjection.unit(lat: lat, lon: lon)
                if i == 0 { path.move(to: p); first = p } else { path.addLine(to: p) }
            }
            if first != nil { path.closeSubpath() }
        }
        return path
    }
}

/// Projection shared between geometry baking and the camera (same math).
enum MapCameraProjection {
    static func unit(lat: Double, lon: Double) -> CGPoint {
        let clampedLat = min(85, max(-85, lat))
        let x = (lon + 180) / 360
        let rad = clampedLat * .pi / 180
        let y = (1 - log(tan(.pi / 4 + rad / 2)) / .pi) / 2
        return CGPoint(x: x, y: y)
    }
}


/// Sizes its content to `width / ratio`, computed from the layout proposal.
///
/// Deliberately a Layout and not a GeometryReader + @State: a Layout answers "how big am
/// I" synchronously, during the layout pass, with no state write and therefore no second
/// pass. `.aspectRatio(_, contentMode: .fit)` can't be used here because it collapsed
/// inside the menu popover's height-ambiguous layout — it fit to a tiny proposed height
/// and shrank the width to match.
struct HeightFromWidth: Layout {
    var ratio: CGFloat = 2
    /// Used only when the proposal carries no width (nothing to derive from).
    var fallbackHeight: CGFloat = 160

    func sizeThatFits(proposal: ProposedViewSize, subviews: Subviews, cache: inout ()) -> CGSize {
        guard let width = proposal.width, width > 0 else {
            return CGSize(width: proposal.width ?? 0, height: fallbackHeight)
        }
        return CGSize(width: width, height: width / ratio)
    }

    func placeSubviews(in bounds: CGRect, proposal: ProposedViewSize,
                       subviews: Subviews, cache: inout ()) {
        for view in subviews {
            view.place(at: bounds.origin, anchor: .topLeading,
                       proposal: ProposedViewSize(bounds.size))
        }
    }
}
