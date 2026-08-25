// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only

import AppKit
import SwiftUI

/// The few structural shapes that justify changing the main window automatically.
/// Ordinary content changes deliberately do not appear here: a banner, disclosure,
/// selection or live status must never make the window twitch.
enum MainWindowLayoutMode: String, Equatable {
    case loading
    case onboarding
    case onboardingWithSidebar
    case compact
    case sidebar
    case inspector
    case sidebarAndInspector

    var suggestedFrameSize: CGSize? {
        switch self {
        case .loading: nil
        case .onboarding: CGSize(width: 900, height: 660)
        case .onboardingWithSidebar: CGSize(width: 1_240, height: 720)
        case .compact: CGSize(width: 680, height: 380)
        case .sidebar: CGSize(width: 1_040, height: 560)
        case .inspector: CGSize(width: 1_080, height: 680)
        case .sidebarAndInspector: CGSize(width: 1_380, height: 720)
        }
    }
}

/// Pure geometry kept separate from the AppKit bridge so screen-edge behaviour is
/// testable. The current top-left is the anchor: growth therefore feels like content
/// being revealed, while the final clamp makes the smallest possible move needed to
/// stay clear of the menu bar and Dock.
nonisolated enum MainWindowSizingPolicy {
    static let screenInset: CGFloat = 12
    static let manualSizingKey = "ui.mainWindow.manualSizing"

    static func fittedFrame(frameSize: CGSize,
                            currentFrame: CGRect,
                            visibleFrame: CGRect) -> CGRect {
        let inset = min(screenInset, max(0, min(visibleFrame.width, visibleFrame.height) / 4))
        let safe = visibleFrame.insetBy(dx: inset, dy: inset)
        let size = CGSize(width: min(frameSize.width, safe.width),
                          height: min(frameSize.height, safe.height))
        var frame = CGRect(x: currentFrame.minX,
                           y: currentFrame.maxY - size.height,
                           width: size.width,
                           height: size.height)

        if frame.maxX > safe.maxX { frame.origin.x -= frame.maxX - safe.maxX }
        if frame.minX < safe.minX { frame.origin.x += safe.minX - frame.minX }
        if frame.minY < safe.minY { frame.origin.y += safe.minY - frame.minY }
        if frame.maxY > safe.maxY { frame.origin.y -= frame.maxY - safe.maxY }
        return frame
    }
}

private struct MainWindowSizingModifier: ViewModifier {
    let mode: MainWindowLayoutMode

    func body(content: Content) -> some View {
        content.background {
            MainWindowSizingBridge(mode: mode)
                .frame(width: 0, height: 0)
                .allowsHitTesting(false)
                .accessibilityHidden(true)
        }
    }
}

extension View {
    /// Suggest a handful of useful main-window sizes until the person resizes the
    /// window themselves. This narrow SwiftUI wrapper is the only AppKit needed:
    /// SwiftUI has no API that both changes an existing window's frame and preserves
    /// unconstrained manual resizing.
    func adaptiveMainWindowSizing(_ mode: MainWindowLayoutMode) -> some View {
        modifier(MainWindowSizingModifier(mode: mode))
    }
}

private struct MainWindowSizingBridge: NSViewRepresentable {
    let mode: MainWindowLayoutMode

    func makeCoordinator() -> Coordinator { Coordinator(mode: mode) }

    func makeNSView(context: Context) -> WindowProbeView {
        let view = WindowProbeView()
        view.windowChanged = { [weak coordinator = context.coordinator] window in
            coordinator?.attach(to: window)
        }
        return view
    }

    func updateNSView(_ view: WindowProbeView, context: Context) {
        context.coordinator.update(mode: mode)
        context.coordinator.attach(to: view.window)
    }

    final class Coordinator: NSObject {
        private var mode: MainWindowLayoutMode
        private weak var window: NSWindow?
        private var suggestionScheduled = false
        private var liveResizeWasStarted = false

        init(mode: MainWindowLayoutMode) {
            self.mode = mode
        }

        func update(mode: MainWindowLayoutMode) {
            guard mode != self.mode else { return }
            self.mode = mode
            scheduleSuggestionIfAllowed()
        }

        func attach(to window: NSWindow?) {
            guard self.window !== window else { return }
            NotificationCenter.default.removeObserver(
                self,
                name: NSWindow.willStartLiveResizeNotification,
                object: self.window
            )
            NotificationCenter.default.removeObserver(
                self,
                name: NSWindow.didEndLiveResizeNotification,
                object: self.window
            )
            NotificationCenter.default.removeObserver(
                self,
                name: NSWindow.didBecomeKeyNotification,
                object: self.window
            )
            self.window = window
            liveResizeWasStarted = false
            guard let window else { return }
            NotificationCenter.default.addObserver(
                self,
                selector: #selector(willStartLiveResize),
                name: NSWindow.willStartLiveResizeNotification,
                object: window,
            )
            NotificationCenter.default.addObserver(
                self,
                selector: #selector(didEndLiveResize),
                name: NSWindow.didEndLiveResizeNotification,
                object: window,
            )
            NotificationCenter.default.addObserver(
                self,
                selector: #selector(didBecomeKey),
                name: NSWindow.didBecomeKeyNotification,
                object: window,
            )
            scheduleSuggestionIfAllowed()
        }

        @objc private func willStartLiveResize() {
            liveResizeWasStarted = true
        }

        @objc private func didEndLiveResize() {
            // One manual resize, in any content state, hands sizing back to the
            // person permanently. AppKit can post an unmatched end notification
            // while restoring or programmatically fitting a window, so require the
            // corresponding live-resize start before treating it as user intent.
            guard liveResizeWasStarted else { return }
            liveResizeWasStarted = false
            UserDefaults.standard.set(true, forKey: MainWindowSizingPolicy.manualSizingKey)
        }

        @objc private func didBecomeKey() {
            scheduleSuggestionIfAllowed()
        }

        private func scheduleSuggestionIfAllowed() {
            guard !suggestionScheduled else { return }
            suggestionScheduled = true
            // `updateNSView` runs inside SwiftUI's graph/layout work. Mutating the
            // NSWindow frame synchronously there re-enters AppKit constraint layout
            // and macOS deliberately terminates the app. Coalesce structural state
            // changes and cross the AppKit boundary on the next main-run-loop turn.
            DispatchQueue.main.async { [weak self] in
                guard let self else { return }
                self.suggestionScheduled = false
                self.applySuggestionIfAllowed()
            }
        }

        private func applySuggestionIfAllowed() {
            guard !UserDefaults.standard.bool(forKey: MainWindowSizingPolicy.manualSizingKey),
                  let suggested = mode.suggestedFrameSize,
                  let window,
                  window.isVisible,
                  !window.styleMask.contains(.fullScreen),
                  let screen = window.screen ?? NSScreen.main
            else { return }

            let target = MainWindowSizingPolicy.fittedFrame(
                frameSize: suggested,
                currentFrame: window.frame,
                visibleFrame: screen.visibleFrame
            )
            guard abs(target.width - window.frame.width) > 1
                    || abs(target.height - window.frame.height) > 1
                    || abs(target.minX - window.frame.minX) > 1
                    || abs(target.minY - window.frame.minY) > 1
            else { return }
            window.setFrame(target, display: true, animate: false)
        }
    }
}

private final class WindowProbeView: NSView {
    var windowChanged: ((NSWindow?) -> Void)?

    override func viewDidMoveToWindow() {
        super.viewDidMoveToWindow()
        windowChanged?(window)
    }

    override var intrinsicContentSize: NSSize { .zero }
}
