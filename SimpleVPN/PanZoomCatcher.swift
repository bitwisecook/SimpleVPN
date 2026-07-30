// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
//  PanZoomCatcher.swift
//  THE gesture vocabulary for anything zoomable/pannable (user-specified):
//  click-drag pans (the host view's own DragGesture), two-finger trackpad scroll pans,
//  pinch zooms, mouse wheel zooms, ⌘+two-finger scroll zooms. Shared by the world map
//  and the Routes diagram so the two can never drift into different dialects.
//
//  This is the NSEvent side: scroll + magnify never reach SwiftUI gestures on macOS,
//  so a local monitor catches them for the view's bounds and consumes them. Extracted
//  from MercatorMapView (it was private there, which is how the Routes window shipped
//  without trackpad support at all).
//

import AppKit
import SwiftUI

struct PanZoomEventCatcher: NSViewRepresentable {
    var onPan: (CGSize) -> Void
    var onZoom: (Double, CGPoint) -> Void
    /// Rectangles, in this view's (viewport) coordinates, that own the scroll wheel
    /// for themselves — a list inside the content that scrolls instead of panning the
    /// whole picture. Since the monitor CONSUMES scroll events, a scrollable region
    /// drawn inside the zoomed content could never see one otherwise. Empty by
    /// default, so a plain pan/zoom surface (the world map) behaves exactly as before.
    var scrollRegions: [(id: String, rect: CGRect)] = []
    /// Where a scroll that landed in one of `scrollRegions` goes instead of `onPan`.
    var onRegionScroll: ((String, CGSize) -> Void)?

    func makeNSView(context: Context) -> CatcherView { CatcherView() }

    func updateNSView(_ view: CatcherView, context: Context) {
        view.onPan = onPan
        view.onZoom = onZoom
        view.scrollRegions = scrollRegions
        view.onRegionScroll = onRegionScroll
    }

    final class CatcherView: NSView {
        var onPan: ((CGSize) -> Void)?
        var onZoom: ((Double, CGPoint) -> Void)?
        var scrollRegions: [(id: String, rect: CGRect)] = []
        var onRegionScroll: ((String, CGSize) -> Void)?
        private var monitor: Any?

        /// Top-left origin, so a location can be handed straight to the camera
        /// (which works in SwiftUI's coordinate space).
        override var isFlipped: Bool { true }
        /// Never the hit view — pins and the +/− controls must stay clickable.
        override func hitTest(_ point: NSPoint) -> NSView? { nil }

        /// Take NO part in sizing. SwiftUI hosts an NSViewRepresentable through
        /// AppKitPlatformViewHost, which builds content-size constraints from the view's
        /// intrinsic size; changing those mid-pass makes SwiftUI invalidate layout
        /// synchronously, which schedules another constraint pass from inside one — the
        /// loop AppKit eventually kills the app over. This view only listens for scroll
        /// and magnify events; it should never influence layout at all.
        override var intrinsicContentSize: NSSize {
            NSSize(width: NSView.noIntrinsicMetric, height: NSView.noIntrinsicMetric)
        }

        override func viewDidMoveToWindow() {
            super.viewDidMoveToWindow()
            if window == nil { removeMonitor() } else { installMonitor() }
        }

        // Both map call sites (the dropdown and the main window) come and go, so the
        // monitor has to be torn down or they accumulate.
        override func viewWillMove(toWindow newWindow: NSWindow?) {
            super.viewWillMove(toWindow: newWindow)
            if newWindow == nil { removeMonitor() }
        }

        private func installMonitor() {
            guard monitor == nil else { return }
            monitor = NSEvent.addLocalMonitorForEvents(matching: [.scrollWheel, .magnify]) { [weak self] event in
                guard let self, self.handle(event) else { return event }
                return nil          // consumed, so nothing downstream double-handles it
            }
        }

        private func removeMonitor() {
            if let monitor { NSEvent.removeMonitor(monitor) }
            monitor = nil
        }

        /// Returns true when the event was ours (and so should be consumed).
        private func handle(_ event: NSEvent) -> Bool {
            guard let window, event.window === window else { return false }
            let point = convert(event.locationInWindow, from: nil)
            guard bounds.contains(point) else { return false }

            switch event.type {
            case .magnify:
                onZoom?(1 + event.magnification, point)
            case .scrollWheel:
                // A classic mouse WHEEL (imprecise deltas) ZOOMS: a mouse can't
                // pinch and click-drag already pans, so the wheel is its zoom control.
                // A trackpad's two-finger scroll (precise deltas) PANS, with pinch for
                // zoom. User-specified vocabulary for everything zoomable/pannable.
                if !event.hasPreciseScrollingDeltas {
                    let notch = max(-3, min(3, event.scrollingDeltaY))
                    guard notch != 0 else { return false }
                    onZoom?(1 + notch * 0.1, point)
                    return true
                }
                let step: CGFloat = 1
                let delta = CGSize(width: event.scrollingDeltaX * step,
                                   height: event.scrollingDeltaY * step)
                guard delta != .zero else { return false }
                if event.modifierFlags.contains(.command) {
                    // ⌘-scroll zooms (the usual Mac convention) — and it is the
                    // fallback if .magnify never reaches the dropdown. Clamped so one
                    // fat wheel notch can't jump several zoom levels.
                    let bounded = max(-40, min(40, delta.height))
                    onZoom?(1 - bounded / 100, point)
                } else if let region = scrollRegions.last(where: { $0.rect.contains(point) }),
                          let onRegionScroll {
                    // Under the pointer is a list that scrolls itself. Last match wins:
                    // regions are handed over in draw order, so the topmost one gets it.
                    // Only PRECISE deltas land here — a mouse wheel still zooms, and
                    // ⌘-scroll above still zooms, everywhere.
                    onRegionScroll(region.id, delta)
                } else {
                    // Raw deltas: AppKit has already applied the user's
                    // natural-scrolling preference, so the map follows the fingers
                    // without us second-guessing the direction.
                    onPan?(delta)
                }
            default:
                return false
            }
            return true
        }
    }
}
