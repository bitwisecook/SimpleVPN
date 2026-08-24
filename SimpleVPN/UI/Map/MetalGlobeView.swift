// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
// MetalGlobeView.swift
// A lightweight Metal globe for the live network topology. The GPU owns the
// sphere, atmosphere, lighting and graticule. SwiftUI projects the bundled
// Natural Earth coastlines, routes and accessible pins over that one shared
// camera. That split gives the custom drawing the native hover/button behaviour
// a Mac user expects without asking Metal to impersonate an accessibility tree.

import AppKit
@preconcurrency import MetalKit
import SwiftUI
import simd

// MARK: - Shared spherical geometry

/// One great-circle implementation for both map presentations. Coordinates use
/// latitude/longitude in degrees; vectors use a right-handed earth where +Y is
/// north. Keeping interpolation here prevents the flat and globe views from
/// disagreeing about the route they draw.
enum GreatCircle {
    static func vector(lat: Double, lon: Double) -> SIMD3<Double> {
        let latitude = lat * .pi / 180
        let longitude = lon * .pi / 180
        return SIMD3(cos(latitude) * cos(longitude),
                     sin(latitude),
                     cos(latitude) * sin(longitude))
    }

    static func points(from a: SIMD3<Double>, to b: SIMD3<Double>, samples: Int = 96) -> [SIMD3<Double>] {
        let first = simd_normalize(a)
        let second = simd_normalize(b)
        let dotProduct = max(-1.0, min(1.0, simd_dot(first, second)))
        let angle = acos(dotProduct)
        guard angle > 0.000_001 else { return Array(repeating: first, count: samples + 1) }
        let sinAngle = sin(angle)
        // There are infinitely many antipodal great circles. Preserve a usable
        // route rather than produce NaNs; the endpoints remain honest.
        guard sinAngle > 0.000_001 else { return [first, second] }
        return (0...samples).map { index in
            let t = Double(index) / Double(samples)
            return simd_normalize(
                sin((1 - t) * angle) / sinAngle * first
                    + sin(t * angle) / sinAngle * second)
        }
    }

    static func points(from a: (Double, Double), to b: (Double, Double), samples: Int = 96) -> [SIMD3<Double>] {
        points(from: vector(lat: a.0, lon: a.1), to: vector(lat: b.0, lon: b.1), samples: samples)
    }
}

/// Approximate apparent solar position from UTC. It is deliberately calculated
/// locally from `Date`: the night side continues to move correctly offline and
/// needs neither a network location service nor a bundled ephemeris.
struct SolarPosition: Equatable {
    let vector: SIMD3<Double>

    init(date: Date) {
        let julianDay = date.timeIntervalSince1970 / 86_400 + 2_440_587.5
        let daysSinceJ2000 = julianDay - 2_451_545.0
        func radians(_ degrees: Double) -> Double { degrees * .pi / 180 }
        func degrees(_ radians: Double) -> Double { radians * 180 / .pi }
        func wrappedDegrees(_ value: Double) -> Double {
            let result = value.truncatingRemainder(dividingBy: 360)
            return result < 0 ? result + 360 : result
        }

        let meanLongitude = radians(wrappedDegrees(280.460 + 0.9856474 * daysSinceJ2000))
        let meanAnomaly = radians(wrappedDegrees(357.528 + 0.9856003 * daysSinceJ2000))
        let eclipticLongitude = meanLongitude + radians(1.915) * sin(meanAnomaly)
            + radians(0.020) * sin(2 * meanAnomaly)
        let obliquity = radians(23.439 - 0.0000004 * daysSinceJ2000)
        let declination = asin(sin(obliquity) * sin(eclipticLongitude))
        let rightAscension = atan2(cos(obliquity) * sin(eclipticLongitude), cos(eclipticLongitude))
        let greenwichSidereal = radians(wrappedDegrees(280.46061837 + 360.98564736629 * daysSinceJ2000))
        let subsolarLongitude = rightAscension - greenwichSidereal
        vector = GreatCircle.vector(lat: degrees(declination), lon: degrees(subsolarLongitude))
    }
}

// MARK: - Orbit camera

/// An orthographic globe camera. Its reset pose keeps geographic north straight
/// up; reorienting centres the chosen great-circle midpoint so the whole active
/// route starts on the near hemisphere.
struct GlobeCamera: Equatable {
    var forward: SIMD3<Double>
    var up: SIMD3<Double>

    init() {
        forward = SIMD3<Double>(0, 0, 1)
        up = SIMD3<Double>(0, 1, 0)
    }

    mutating func orient(from start: MapPin, to end: MapPin) {
        let route = GreatCircle.points(from: (start.lat, start.lon), to: (end.lat, end.lon), samples: 2)
        let midpoint = route[route.count / 2]
        forward = simd_normalize(midpoint)

        // Project geographic north onto the tangent plane. Near a pole, choose a
        // stable alternate reference rather than let a zero vector poison the view.
        let north = SIMD3<Double>(0, 1, 0)
        let reference = abs(simd_dot(north, forward)) > 0.985
            ? SIMD3<Double>(1, 0, 0) : north
        let northUp = simd_normalize(reference - simd_dot(reference, forward) * forward)
        up = northUp
    }

    mutating func orbit(translation: CGSize, from origin: GlobeCamera) {
        var revised = origin
        let yaw = Double(translation.width) * .pi / 360
        // This is direct manipulation: dragging the visible globe down must move
        // the geography under the pointer down too. The camera moves in its
        // right-handed screen basis to achieve that screen-space result.
        let pitch = Double(translation.height) * .pi / 360
        revised.rotate(angle: yaw, axis: revised.up)
        revised.rotate(angle: pitch, axis: revised.right)
        self = revised
    }

    /// Rolls the globe in the screen plane. This is intentionally based on the
    /// camera at the start of the gesture, so a trackpad rotation has no drift
    /// as its recognizer reports cumulative angles.
    mutating func roll(angle: Double, from origin: GlobeCamera) {
        var revised = origin
        // Preserve direct screen-space rotation with the east-to-the-right
        // screen basis used by `right` below.
        revised.rotate(angle: -angle, axis: revised.forward)
        self = revised
    }

    /// Screen-right points east when north is up. This is the same orientation
    /// users expect from a map: increasing longitude travels to the right.
    var right: SIMD3<Double> { simd_normalize(simd_cross(forward, up)) }

    func visibility(of point: SIMD3<Double>) -> Double {
        simd_dot(point, forward)
    }

    func project(_ point: SIMD3<Double>, in size: CGSize) -> CGPoint? {
        let depth = visibility(of: point)
        guard depth > 0.015 else { return nil }
        return projectUnclipped(point, in: size)
    }

    /// Orthographic screen position even for the far hemisphere. Routes use
    /// this to make the hidden segment legible as a dim dotted line rather than
    /// incorrectly disappearing at the limb.
    func projectUnclipped(_ point: SIMD3<Double>, in size: CGSize) -> CGPoint {
        let radius = min(size.width, size.height) * 0.45
        return CGPoint(x: size.width / 2 + CGFloat(simd_dot(point, right)) * radius,
                       y: size.height / 2 - CGFloat(simd_dot(point, up)) * radius)
    }

    private mutating func rotate(angle: Double, axis: SIMD3<Double>) {
        guard abs(angle) > .ulpOfOne else { return }
        let rotation = simd_quatd(angle: angle, axis: simd_normalize(axis))
        forward = simd_normalize(simd_act(rotation, forward))
        up = simd_normalize(simd_act(rotation, up))
    }
}

// MARK: - SwiftUI composition and interaction

struct MetalGlobeMapView: View {
    let pins: [MapPin]
    var connections: [MapConnection] = []
    /// Maximum diameter of the rendered globe, not the enclosing 2:1 surface.
    /// Nil keeps the full-width presentation used by dedicated map surfaces.
    var maximumGlobeDiameter: CGFloat? = nil
    /// The compact connection screen must remain a wholly SwiftUI hierarchy so
    /// native external-drop negotiation reaches its nested destinations. Full
    /// map surfaces can still opt into the Metal-backed renderer.
    var usesMetalSurface = true
    var onSelect: (String) -> Void = { _ in }

    @Environment(\.accessibilityReduceMotion) private var reduceMotion
    @Environment(\.liveVisualPolicy) private var liveVisuals
    @State private var camera = GlobeCamera()
    @State private var dragOrigin: GlobeCamera?
    @State private var trackpadPanOrigin: GlobeCamera?
    @State private var rotationOrigin: GlobeCamera?
    @State private var orientedRoute = ""

    private var resolvedConnections: [MapConnection] {
        if !connections.isEmpty { return connections }
        guard let home = pins.first(where: { $0.kind == .user }) else { return [] }
        return pins.compactMap { pin in
            if case .endpoint = pin.kind { return MapConnection(from: home.id, to: pin.id) }
            return nil
        }
    }

    private var primaryRoute: (MapPin, MapPin)? {
        for link in resolvedConnections {
            if let first = pins.first(where: { $0.id == link.from }),
               let second = pins.first(where: { $0.id == link.to }) {
                return (first, second)
            }
        }
        return nil
    }

    private var routeKey: String {
        guard let route = primaryRoute else { return "" }
        return "\(route.0.id):\(route.0.lat):\(route.0.lon)→\(route.1.id):\(route.1.lat):\(route.1.lon)"
    }

    /// The globe itself occupies 90% of the shortest surface axis; the surface
    /// is 2:1. Convert the person-facing diameter to the width proposal the
    /// layout needs without using a GeometryReader or feeding resize state back.
    private var maximumSurfaceWidth: CGFloat? {
        maximumGlobeDiameter.map { $0 / 0.45 }
    }

    var body: some View {
        // Update the terminator every minute from local UTC without affecting the
        // interactive camera state. HeightFromWidth remains proposal-driven and
        // never feeds geometry back into state during a resize.
        TimelineView(.periodic(from: .now, by: liveVisuals.isLowPowerModeEnabled ? 300 : 60)) { timeline in
            let sun = SolarPosition(date: timeline.date)
            HeightFromWidth(ratio: 2) {
                GeometryReader { geometry in
                    ZStack {
                        if usesMetalSurface, MTLCreateSystemDefaultDevice() != nil {
                            MetalGlobeSurface(camera: camera, sun: sun.vector,
                                               lowPowerMode: liveVisuals.isLowPowerModeEnabled,
                                               onTrackpadPan: handleTrackpadPan)
                        } else {
                            GlobeFallbackSurface(camera: camera)
                        }
                        coastlineOverlay(in: geometry.size)
                        countryBorderOverlay(in: geometry.size)
                        routeOverlay(in: geometry.size)
                        pinOverlay(in: geometry.size)
                        resetControl
                    }
                    .clipShape(RoundedRectangle(cornerRadius: 10))
                    .overlay(RoundedRectangle(cornerRadius: 10)
                        .strokeBorder(Color(nsColor: .separatorColor), lineWidth: 1))
                    .contentShape(Rectangle())
                    .gesture(orbitGesture)
                    .simultaneousGesture(rotationGesture)
                    .onAppear { orientIfNeeded(force: true) }
                    .onChange(of: routeKey) { orientIfNeeded(force: false) }
                }
            }
            .frame(maxWidth: maximumSurfaceWidth ?? .infinity)
        }
        .accessibilityElement(children: .contain)
        .accessibilityLabel("Interactive globe of VPN servers")
        .accessibilityValue(accessibilitySummary)
    }

    private func orientIfNeeded(force: Bool) {
        guard !routeKey.isEmpty, (force || orientedRoute != routeKey), let route = primaryRoute else { return }
        camera.orient(from: route.0, to: route.1)
        orientedRoute = routeKey
    }

    private var orbitGesture: some Gesture {
        DragGesture(minimumDistance: 2)
            .onChanged { value in
                let origin = dragOrigin ?? camera
                if dragOrigin == nil { dragOrigin = origin }
                camera.orbit(translation: value.translation, from: origin)
            }
            .onEnded { _ in dragOrigin = nil }
    }

    /// macOS reports a two-finger twist as a RotateGesture. It is composed with
    /// the pointer drag rather than replacing it, so a mouse/one-finger drag
    /// still orbits while a trackpad twist rolls the earth directly under the
    /// user's fingers.
    private var rotationGesture: some Gesture {
        RotateGesture(minimumAngleDelta: .degrees(0.25))
            .onChanged { value in
                let origin = rotationOrigin ?? camera
                if rotationOrigin == nil { rotationOrigin = origin }
                camera.roll(angle: value.rotation.radians, from: origin)
            }
            .onEnded { _ in rotationOrigin = nil }
    }

    /// NSPanGestureRecognizer supplies the native two-finger trackpad pan that
    /// DragGesture deliberately reserves for click-and-drag on macOS.
    private func handleTrackpadPan(_ phase: NSGestureRecognizer.State, _ translation: CGSize) {
        switch phase {
        case .began, .changed:
            let origin = trackpadPanOrigin ?? camera
            if trackpadPanOrigin == nil { trackpadPanOrigin = origin }
            camera.orbit(translation: translation, from: origin)
        case .ended, .cancelled, .failed:
            trackpadPanOrigin = nil
        default:
            break
        }
    }

    private func routeOverlay(in size: CGSize) -> some View {
        Canvas { context, _ in
            for link in resolvedConnections {
                guard let first = pins.first(where: { $0.id == link.from }),
                      let second = pins.first(where: { $0.id == link.to }) else { continue }
                let points = GreatCircle.points(from: (first.lat, first.lon), to: (second.lat, second.lon))
                var nearPath = Path()
                var farPath = Path()
                var nearContinues = false
                var farContinues = false
                var previousSample: (location: CGPoint, visible: Bool)?
                for (index, point) in points.enumerated() {
                    var projected = camera.projectUnclipped(point, in: size)
                    let t = CGFloat(index) / CGFloat(max(1, points.count - 1))
                    projected.x += first.screenOffset.width + (second.screenOffset.width - first.screenOffset.width) * t
                    projected.y += first.screenOffset.height + (second.screenOffset.height - first.screenOffset.height) * t
                    let isVisible = camera.visibility(of: point) > 0.015
                    guard let previous = previousSample else {
                        previousSample = (projected, isVisible)
                        continue
                    }

                    // A crossing segment is deliberately treated as far-side:
                    // its small extent (96 samples) makes the transition read as
                    // the arc slipping behind the limb, not as an abrupt cut.
                    if previous.visible && isVisible {
                        if !nearContinues { nearPath.move(to: previous.location) }
                        nearPath.addLine(to: projected)
                        nearContinues = true
                        farContinues = false
                    } else {
                        if !farContinues { farPath.move(to: previous.location) }
                        farPath.addLine(to: projected)
                        farContinues = true
                        nearContinues = false
                    }
                    previousSample = (projected, isVisible)
                }
                let nearStyle: StrokeStyle
                let nearColor: Color
                let farColor: Color
                let farStyle: StrokeStyle
                switch link.kind {
                case .tunnel:
                    nearStyle = StrokeStyle(lineWidth: 2, lineCap: .round)
                    nearColor = .accentColor
                    farColor = Color.accentColor.opacity(0.28)
                    farStyle = StrokeStyle(lineWidth: 1.25, lineCap: .round, dash: [2, 4])
                case .pending:
                    nearStyle = StrokeStyle(lineWidth: 1.5, lineCap: .round)
                    nearColor = Color.secondary.opacity(0.65)
                    farColor = Color.secondary.opacity(0.28)
                    farStyle = StrokeStyle(lineWidth: 0.9, lineCap: .round, dash: [2, 4])
                case .bypass:
                    nearStyle = StrokeStyle(lineWidth: 1, lineCap: .round, dash: [3, 4])
                    nearColor = Color.secondary.opacity(0.55)
                    farColor = Color.secondary.opacity(0.28)
                    farStyle = StrokeStyle(lineWidth: 0.8, lineCap: .round, dash: [2, 4])
                }
                context.stroke(farPath,
                               with: .color(farColor), style: farStyle)
                context.stroke(nearPath,
                               with: .color(nearColor),
                               style: nearStyle)
            }
        }
        .allowsHitTesting(false)
    }

    private func coastlineOverlay(in size: CGSize) -> some View {
        Canvas { context, _ in
            guard let land = WorldGeometry.shared else { return }
            for polygon in land.globePolygons {
                guard !polygon.isEmpty else { continue }
                var path = Path()
                var previousWasVisible = false
                for point in polygon {
                    guard let projected = camera.project(point, in: size) else {
                        previousWasVisible = false
                        continue
                    }
                    if previousWasVisible { path.addLine(to: projected) }
                    else { path.move(to: projected) }
                    previousWasVisible = true
                }
                // The fill is sampled by Metal from a complete Natural Earth
                // land mask. Canvas supplies only this crisp coast edge: filling
                // clipped path fragments here would close them with false wedges
                // at the limb while the globe rotates.
                context.stroke(path,
                               with: .color(Color(nsColor: .secondaryLabelColor).opacity(0.82)),
                               style: StrokeStyle(lineWidth: 0.75, lineJoin: .round))
            }
        }
        .allowsHitTesting(false)
        .accessibilityHidden(true)
    }

    private func countryBorderOverlay(in size: CGSize) -> some View {
        Canvas { context, _ in
            guard let borders = CountryBorderGeometry.shared else { return }
            for line in borders.globeLines {
                var path = Path()
                var previousWasVisible = false
                for point in line {
                    guard let projected = camera.project(point, in: size) else {
                        previousWasVisible = false
                        continue
                    }
                    if previousWasVisible { path.addLine(to: projected) }
                    else { path.move(to: projected) }
                    previousWasVisible = true
                }
                context.stroke(path,
                               with: .color(Color.white.opacity(0.33)),
                               style: StrokeStyle(lineWidth: 0.55, lineCap: .round, lineJoin: .round))
            }
        }
        .allowsHitTesting(false)
        .accessibilityHidden(true)
    }

    private func pinOverlay(in size: CGSize) -> some View {
        ZStack {
            ForEach(pins) { pin in
                let point = GreatCircle.vector(lat: pin.lat, lon: pin.lon)
                if let location = camera.project(point, in: size) {
                    MapPinView(pin: pin, anchorsTether: pins.contains { $0.tetheredTo == pin.id }) {
                        if case .endpoint = pin.kind { onSelect(pin.id) }
                    }
                    .position(x: location.x + pin.screenOffset.width,
                              y: location.y + pin.screenOffset.height)
                }
            }
        }
        // Camera updates arrive at display cadence while the user drags. Do not
        // animate these native pin views between every sample: that made the
        // pins visibly trail the Metal globe and Canvas route.
    }

    private var resetControl: some View {
        Button { orientIfNeeded(force: true) } label: {
            Image(systemName: "location.north.circle")
                .frame(width: 26, height: 26)
                .contentShape(Rectangle())
        }
        .buttonStyle(.borderless)
        .help("Centre the active route and put north up")
        .accessibilityLabel("Centre globe on the active route")
        .padding(8)
        .background(.regularMaterial, in: RoundedRectangle(cornerRadius: 7))
        .padding(8)
        .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .bottomTrailing)
    }

    private var accessibilitySummary: String {
        let visible = pins.filter { camera.visibility(of: GreatCircle.vector(lat: $0.lat, lon: $0.lon)) > 0.015 }
        return "Drag or use a two-finger trackpad pan to rotate. Twist two fingers to roll the globe. The active route is centred. \(visible.count) of \(pins.count) locations are visible."
    }
}

private struct GlobeFallbackSurface: View {
    let camera: GlobeCamera

    var body: some View {
        Canvas { context, size in
            context.fill(Path(CGRect(origin: .zero, size: size)), with: .color(Color(nsColor: .underPageBackgroundColor)))
            let radius = min(size.width, size.height) * 0.45
            let frame = CGRect(x: size.width / 2 - radius, y: size.height / 2 - radius,
                               width: radius * 2, height: radius * 2)
            context.fill(Path(ellipseIn: frame), with: .color(Color.accentColor.opacity(0.13)))
            context.stroke(Path(ellipseIn: frame), with: .color(Color.accentColor.opacity(0.5)), lineWidth: 1)
        }
        .accessibilityHidden(true)
    }
}

// MARK: - Metal surface

private struct GlobeUniforms {
    var right: SIMD4<Float>
    var up: SIMD4<Float>
    var forward: SIMD4<Float>
    var sun: SIMD4<Float>
    var viewport: SIMD4<Float>
}

private struct MetalGlobeSurface: NSViewRepresentable {
    let camera: GlobeCamera
    let sun: SIMD3<Double>
    let lowPowerMode: Bool
    let onTrackpadPan: (NSGestureRecognizer.State, CGSize) -> Void

    func makeCoordinator() -> Coordinator { Coordinator() }

    func makeNSView(context: Context) -> GlobeMetalView {
        let view = GlobeMetalView(frame: .zero, device: MTLCreateSystemDefaultDevice())
        view.colorPixelFormat = .bgra8Unorm
        view.framebufferOnly = true
        // This view lives in the connection detail's ScrollView.  Asking
        // AppKit for a synchronous redraw from `updateNSView` while an
        // NSSplitView divider is being tracked can recursively invalidate the
        // hosting view's constraints (and macOS aborts after detecting that
        // loop).  Let MTKView's display link draw the latest renderer state
        // instead. The shared policy reduces this to 15 fps in Low Power Mode;
        // the globe remains directly manipulable, but its static imagery never
        // deserves an unrestricted display-link render loop.
        view.enableSetNeedsDisplay = false
        view.isPaused = false
        view.preferredFramesPerSecond = LiveVisualCadence.globeFramesPerSecond(lowPower: lowPowerMode)
        view.clearColor = MTLClearColor(red: 0.055, green: 0.07, blue: 0.105, alpha: 1)
        context.coordinator.attach(to: view)
        return view
    }

    func updateNSView(_ view: GlobeMetalView, context: Context) {
        context.coordinator.renderer?.camera = camera
        context.coordinator.renderer?.sun = sun
        context.coordinator.onTrackpadPan = onTrackpadPan
        view.preferredFramesPerSecond = LiveVisualCadence.globeFramesPerSecond(lowPower: lowPowerMode)
    }

    final class Coordinator {
        var renderer: GlobeMetalRenderer?
        var onTrackpadPan: ((NSGestureRecognizer.State, CGSize) -> Void)?
        private var trackpadTranslation = CGSize.zero

        /// Scroll-wheel events are AppKit's supported representation of a
        /// two-finger trackpad pan. Gesture recognizers intentionally support
        /// direct touches only on macOS; attempting to opt one into indirect
        /// touches was the launch crash reported from build 147.
        func handleTrackpadScroll(_ event: NSEvent) -> Bool {
            guard event.hasPreciseScrollingDeltas, event.phase != [] else { return false }
            if event.phase.contains(.began) { trackpadTranslation = .zero }

            // Event deltas may be inverted to honour the user's scrolling
            // preference. A globe is direct manipulation, so compensate and
            // use the physical finger direction instead.
            let preferenceSign: CGFloat = event.isDirectionInvertedFromDevice ? -1 : 1
            trackpadTranslation.width -= event.scrollingDeltaX * preferenceSign
            trackpadTranslation.height -= event.scrollingDeltaY * preferenceSign

            let state: NSGestureRecognizer.State
            if event.phase.contains(.began) { state = .began }
            else if event.phase.contains(.ended) { state = .ended }
            else if event.phase.contains(.cancelled) { state = .cancelled }
            else { state = .changed }
            onTrackpadPan?(state, trackpadTranslation)
            if state == .ended || state == .cancelled { trackpadTranslation = .zero }
            return true
        }

        func attach(to view: GlobeMetalView) {
            guard let device = view.device else { return }
            renderer = GlobeMetalRenderer(device: device, pixelFormat: view.colorPixelFormat)
            view.delegate = renderer
            view.onTrackpadScroll = { [weak self] event in self?.handleTrackpadScroll(event) ?? false }
        }
    }
}

/// MTKView does not expose scroll-wheel handling as a closure. This tiny
/// AppKit bridge keeps that macOS-specific input at the rendering boundary and
/// leaves the SwiftUI scene responsible for camera state and accessibility.
private final class GlobeMetalView: MTKView {
    var onTrackpadScroll: ((NSEvent) -> Bool)?

    // SwiftUI supplies the size through the representable host.  Reporting no
    // intrinsic size prevents this AppKit view from competing with the scroll
    // view and split-view constraint systems during a live divider drag.
    override var intrinsicContentSize: NSSize {
        NSSize(width: NSView.noIntrinsicMetric, height: NSView.noIntrinsicMetric)
    }

    override func scrollWheel(with event: NSEvent) {
        if onTrackpadScroll?(event) == true { return }
        super.scrollWheel(with: event)
    }
}

private final class GlobeMetalRenderer: NSObject, MTKViewDelegate {
    var camera = GlobeCamera()
    var sun = SolarPosition(date: .now).vector
    private let queue: MTLCommandQueue
    private let pipeline: MTLRenderPipelineState
    private let dayEarth: MTLTexture
    private let nightLights: MTLTexture

    init?(device: MTLDevice, pixelFormat: MTLPixelFormat) {
        guard let queue = device.makeCommandQueue(),
              let library = device.makeDefaultLibrary(),
              let vertex = library.makeFunction(name: "globeVertex"),
              let fragment = library.makeFunction(name: "globeFragment"),
              let dayEarth = GlobeDayEarth.makeTexture(device: device),
              let nightLights = GlobeNightLights.makeTexture(device: device)
        else { return nil }
        let descriptor = MTLRenderPipelineDescriptor()
        descriptor.vertexFunction = vertex
        descriptor.fragmentFunction = fragment
        descriptor.colorAttachments[0].pixelFormat = pixelFormat
        do { pipeline = try device.makeRenderPipelineState(descriptor: descriptor) }
        catch { return nil }
        self.queue = queue
        self.dayEarth = dayEarth
        self.nightLights = nightLights
    }

    func mtkView(_ view: MTKView, drawableSizeWillChange size: CGSize) {
        // The fragment shader derives its aspect ratio from the live drawable;
        // there are no cached size-dependent textures to rebuild.
    }

    func draw(in view: MTKView) {
        guard let drawable = view.currentDrawable,
              let pass = view.currentRenderPassDescriptor,
              let commandBuffer = queue.makeCommandBuffer(),
              let encoder = commandBuffer.makeRenderCommandEncoder(descriptor: pass)
        else { return }
        let right = camera.right
        var uniforms = GlobeUniforms(
            right: SIMD4(Float(right.x), Float(right.y), Float(right.z), 0),
            up: SIMD4(Float(camera.up.x), Float(camera.up.y), Float(camera.up.z), 0),
            forward: SIMD4(Float(camera.forward.x), Float(camera.forward.y), Float(camera.forward.z), 0),
            sun: SIMD4(Float(sun.x), Float(sun.y), Float(sun.z), 0),
            viewport: SIMD4(Float(view.drawableSize.width), Float(view.drawableSize.height), 0, 0))
        encoder.setRenderPipelineState(pipeline)
        encoder.setFragmentBytes(&uniforms, length: MemoryLayout<GlobeUniforms>.stride, index: 0)
        encoder.setFragmentTexture(dayEarth, index: 0)
        encoder.setFragmentTexture(nightLights, index: 1)
        encoder.drawPrimitives(type: .triangle, vertexStart: 0, vertexCount: 3)
        encoder.endEncoding()
        commandBuffer.present(drawable)
        commandBuffer.commit()
    }
}

/// NASA's Blue Marble Next Generation map is a conventional equirectangular
/// daytime Earth. The shader pairs it with Black Marble at the live terminator.
@MainActor
private enum GlobeDayEarth {
    static func makeTexture(device: MTLDevice) -> MTLTexture? {
        guard let url = Bundle.main.url(forResource: "blue-marble-2004-5400", withExtension: "jpg") else {
            return nil
        }
        let options: [MTKTextureLoader.Option: Any] = [
            .origin: MTKTextureLoader.Origin.topLeft,
            .SRGB: false,
            .generateMipmaps: true
        ]
        return try? MTKTextureLoader(device: device).newTexture(URL: url, options: options)
    }
}

/// NASA's bundled 2016 VIIRS Black Marble map is intentionally static imagery;
/// the shader reveals it only where this exact UTC moment is on Earth's night
/// side, below the matching Blue Marble daytime texture.
@MainActor
private enum GlobeNightLights {
    static func makeTexture(device: MTLDevice) -> MTLTexture? {
        guard let url = Bundle.main.url(forResource: "black-marble-2016-01deg", withExtension: "jpg") else {
            return nil
        }
        let options: [MTKTextureLoader.Option: Any] = [
            .origin: MTKTextureLoader.Origin.topLeft,
            .SRGB: false,
            .generateMipmaps: true
        ]
        return try? MTKTextureLoader(device: device).newTexture(URL: url, options: options)
    }
}
