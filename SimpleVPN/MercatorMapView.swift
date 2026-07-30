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
    let id: String
    var kind: Kind
    var lat: Double
    var lon: Double
    var title: String
    var subtitle: String
}

/// A great-circle link between two pins (by id) for the live-topology map:
/// strong = a tunnel/primary path (solid accent), weak = physical/uncertain egress
/// (dashed).
struct MapConnection: Equatable {
    let from: String
    let to: String
    var strong: Bool = true
}

// MARK: - Map view

struct MercatorMapView: View {
    let pins: [MapPin]
    /// Explicit great-circle links to draw (live topology). Empty ⇒ the default
    /// "this Mac → each endpoint" arcs.
    var connections: [MapConnection] = []
    /// Endpoint pin tapped (never fired for the user pin).
    var onSelect: (String) -> Void = { _ in }

    @State private var camera = MapCamera()

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
            .background(PanZoomEventCatcher(
                onPan: { delta in camera.pan(by: delta, viewSize: size) },
                onZoom: { factor, anchor in
                    camera.setScale(camera.scale * factor, anchor: anchor, viewSize: size)
                }))
        }
        }
        .frame(maxWidth: .infinity)
        .accessibilityElement(children: .contain)
        .accessibilityLabel("World map of VPN endpoints. Use the endpoint menu for the full list.")
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

    private func connectionsLayer(size: CGSize) -> some View {
        Canvas { context, canvasSize in
            let transform = camera.transform(viewSize: canvasSize)

            // Explicit topology links (home → VPN(s) → egress), when provided.
            if !connections.isEmpty {
                func pin(_ id: String) -> MapPin? { pins.first { $0.id == id } }
                for c in connections.sorted(by: { !$0.strong && $1.strong }) {
                    guard let a = pin(c.from), let b = pin(c.to) else { continue }
                    var path = Path()
                    Self.appendGreatCircle(&path, from: (a.lat, a.lon), to: (b.lat, b.lon), transform: transform)
                    context.stroke(path,
                        with: .color(c.strong ? Color.accentColor : Color.secondary.opacity(0.5)),
                        style: StrokeStyle(lineWidth: c.strong ? 2 : 1, lineCap: .round,
                                           dash: c.strong ? [] : [3, 4]))
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
                                       transform: transform)
                context.stroke(
                    path,
                    with: .color(selected ? Color.accentColor : Color.secondary.opacity(0.45)),
                    style: StrokeStyle(lineWidth: selected ? 2 : 1, lineCap: .round,
                                       dash: selected ? [] : [3, 4]))
            }
        }
        .allowsHitTesting(false)
    }

    private func isSelected(_ pin: MapPin) -> Bool {
        if case .endpoint(true) = pin.kind { return true }; return false
    }

    /// Sample the great circle between two lat/lon points (slerp on the unit
    /// sphere), project each sample, and lift the pen across the antimeridian so
    /// the arc wraps cleanly instead of streaking across the map.
    static func appendGreatCircle(_ path: inout Path, from a: (Double, Double),
                                  to b: (Double, Double), transform: CGAffineTransform) {
        let pts = greatCirclePoints(from: a, to: b)
        var prevUnitX: Double?
        for (lat, lon) in pts {
            let unit = MapCameraProjection.unit(lat: lat, lon: lon)
            let p = unit.applying(transform)
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
        guard omega > 1e-6 else { return [a, b] }
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
        ForEach(pins) { pin in
            let point = camera.project(lat: pin.lat, lon: pin.lon, viewSize: size)
            PinView(pin: pin) {
                if case .endpoint = pin.kind { onSelect(pin.id) }
            }
            .position(point)
        }
    }

    // MARK: Controls

    private var controls: some View {
        VStack(spacing: 0) {
            Button { camera.zoom(by: 1.5, anchor: nil, viewSize: nil) } label: {
                Image(systemName: "plus")
            }
            .accessibilityLabel("Zoom in")
            Divider().frame(width: 16)
            Button { camera.zoom(by: 1 / 1.5, anchor: nil, viewSize: nil) } label: {
                Image(systemName: "minus")
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
    let action: () -> Void
    @State private var hovering = false

    var body: some View {
        Button(action: action) {
            marker
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
            ZStack {
                Circle().strokeBorder(.tint, lineWidth: 2).frame(width: 16, height: 16)
                Circle().fill(.tint).frame(width: 6, height: 6)
            }
        case .endpoint(let selected):
            Circle()
                .fill(selected ? AnyShapeStyle(.tint) : AnyShapeStyle(Color(nsColor: .systemGray)))
                .frame(width: selected ? 13 : 10, height: selected ? 13 : 10)
                .overlay(Circle().strokeBorder(Color(nsColor: .windowBackgroundColor), lineWidth: 1.5))
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
        case .user: "Your location: \(pin.title). \(pin.subtitle)"
        case .egress: "Internet egress: \(pin.title). \(pin.subtitle)"
        case .endpoint(let selected): "\(pin.title), \(pin.subtitle)\(selected ? ", selected" : "")"
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
