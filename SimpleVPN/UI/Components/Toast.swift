// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
//  Toast.swift
//  Transient, non-blocking notices — "couldn't reach the gateway", "settings saved".
//
//  Deliberately NOT an alert: a modal sheet demands a click before you can do anything
//  about the thing it's telling you about, which is exactly backwards for a networking
//  problem (you want to open Network Tools, or switch Wi-Fi, while reading it). A toast
//  states the fact, optionally offers the obvious next step, and gets out of the way.
//
//  One at a time, newest wins: a queue of stale network complaints is noise, and the
//  most recent one is nearly always the relevant one.
//

import SwiftUI

@MainActor
@Observable
final class ToastCenter {
    static let shared = ToastCenter()

    struct Toast: Identifiable {
        let id = UUID()
        var message: String
        var symbol: String
        var tint: Color
        /// Optional one-tap next step ("Network Tools…", "Try Again").
        var actionTitle: String?
        var action: (() -> Void)?
    }

    private(set) var current: Toast?
    /// Set once by the main window so a toast can offer "open X" without needing a
    /// view's @Environment(\.openWindow) at the call site (the controller has none).
    var openWindow: ((String) -> Void)?
    private var dismissTask: Task<Void, Never>?

    /// Longer than a "saved" confirmation needs, because a network failure is worth
    /// reading properly — but still self-clearing.
    func post(_ message: String, symbol: String = "exclamationmark.triangle.fill",
              tint: Color = .orange, seconds: Double = 8,
              actionTitle: String? = nil, action: (() -> Void)? = nil) {
        dismissTask?.cancel()
        current = Toast(message: message, symbol: symbol, tint: tint,
                        actionTitle: actionTitle, action: action)
        dismissTask = Task { [weak self] in
            try? await Task.sleep(for: .seconds(seconds))
            guard !Task.isCancelled else { return }
            self?.dismiss()
        }
    }

    func dismiss() {
        dismissTask?.cancel(); dismissTask = nil
        current = nil
    }
}

extension View {
    /// Host the toast layer. Put this on a window's root content.
    func toasts() -> some View { modifier(ToastLayer()) }
}

private struct ToastLayer: ViewModifier {
    @State private var center = ToastCenter.shared
    @Environment(\.accessibilityReduceMotion) private var reduceMotion

    func body(content: Content) -> some View {
        content
            .overlay(alignment: .bottom) {
                if let toast = center.current {
                    HStack(spacing: 10) {
                        Image(systemName: toast.symbol).foregroundStyle(toast.tint)
                        Text(toast.message)
                            .font(.callout)
                            .fixedSize(horizontal: false, vertical: true)
                        if let title = toast.actionTitle, let action = toast.action {
                            Button(title) { action(); center.dismiss() }
                                .buttonStyle(.glass).controlSize(.small)
                        }
                        Button { center.dismiss() } label: { Image(systemName: "xmark") }
                            .buttonStyle(.plain).foregroundStyle(.secondary)
                            .help("Dismiss")
                            .accessibilityLabel("Dismiss")
                    }
                    .padding(.horizontal, 14).padding(.vertical, 10)
                    .frame(maxWidth: 460, alignment: .leading)
                    .glassEffect(.regular.tint(toast.tint.opacity(0.18)), in: .capsule)
                    .padding(.bottom, 18)
                    .transition(reduceMotion
                                ? AnyTransition.opacity
                                : .move(edge: .bottom).combined(with: .opacity))
                    // Announce it — a transient visual notice is invisible to VoiceOver
                    // otherwise, and this is exactly the kind of thing a screen-reader
                    // user must not miss.
                    .accessibilityAddTraits(.isStaticText)
                    .accessibilityLabel(toast.message)
                }
            }
            .animation(reduceMotion ? nil : .snappy(duration: 0.28), value: center.current?.id)
    }
}
