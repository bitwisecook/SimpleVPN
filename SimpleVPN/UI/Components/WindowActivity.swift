// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only

import AppKit
import SwiftUI

extension EnvironmentValues {
    /// True outside a tracked window, including in the always-visible status item.
    @Entry var windowShowsLiveContent = true
}

extension View {
    /// Track the host window, rather than a view's appearance or the app's focus.
    /// An inactive window can still be visible on another display.
    func tracksWindowActivity() -> some View {
        modifier(WindowActivityScope())
    }

    func liveWindowTask<ID: Equatable>(id: ID, _ action: @escaping @MainActor () async -> Void) -> some View {
        modifier(LiveWindowTask(id: id, action: action))
    }

    func liveWindowTask(_ action: @escaping @MainActor () async -> Void) -> some View {
        liveWindowTask(id: true, action)
    }
}

private struct WindowActivityScope: ViewModifier {
    @State private var visible = false

    func body(content: Content) -> some View {
        content
            .environment(\.windowShowsLiveContent, visible)
            .background {
                WindowActivityProbe { visible = $0 }
                    .frame(width: 0, height: 0)
                    .allowsHitTesting(false)
                    .accessibilityHidden(true)
            }
    }
}

private struct LiveWindowTask<ID: Equatable>: ViewModifier {
    @Environment(\.windowShowsLiveContent) private var visible
    let id: ID
    let action: @MainActor () async -> Void

    func body(content: Content) -> some View {
        content.task(id: visible ? id : nil) {
            guard visible, !Task.isCancelled else { return }
            await action()
        }
    }
}

private struct WindowActivityProbe: NSViewRepresentable {
    let update: @MainActor (Bool) -> Void

    func makeNSView(context: Context) -> Probe {
        Probe(update: update)
    }

    func updateNSView(_ view: Probe, context: Context) {
        view.update = update
    }

    final class Probe: NSView {
        var update: @MainActor (Bool) -> Void
        private var scheduled = false
        private var reported = false

        init(update: @escaping @MainActor (Bool) -> Void) {
            self.update = update
            super.init(frame: .zero)
        }

        @available(*, unavailable)
        required init?(coder: NSCoder) { fatalError("init(coder:) has not been implemented") }

        override func viewDidMoveToWindow() {
            super.viewDidMoveToWindow()
            let center = NotificationCenter.default
            center.removeObserver(self)
            if let window {
                for name in [NSWindow.didChangeOcclusionStateNotification,
                             NSWindow.didMiniaturizeNotification,
                             NSWindow.didDeminiaturizeNotification,
                             NSWindow.didBecomeKeyNotification,
                             NSWindow.willCloseNotification] {
                    center.addObserver(self, selector: #selector(scheduleRead), name: name, object: window)
                }
            }
            scheduleRead()
        }

        @objc private func scheduleRead() {
            guard !scheduled else { return }
            scheduled = true
            // The attachment and notifications can occur during layout or before
            // AppKit has finished ordering the window. Read on the next turn.
            DispatchQueue.main.async { [weak self] in
                guard let self else { return }
                self.scheduled = false
                let visible = self.window.map {
                    $0.isVisible && !$0.isMiniaturized && $0.occlusionState.contains(.visible)
                } ?? false
                guard visible != self.reported else { return }
                self.reported = visible
                self.update(visible)
            }
        }
    }
}

/// A MenuBarExtra can keep its hosting window and content mounted after
/// dismissal. Keep the probe mounted so reopening can build a fresh popup.
struct VisibleMenuBarContent<Content: View>: View {
    @Environment(\.windowShowsLiveContent) private var visible
    @ViewBuilder let content: () -> Content

    var body: some View {
        if visible {
            content()
        } else {
            Color.clear.frame(height: 1)
                .accessibilityHidden(true)
        }
    }
}
