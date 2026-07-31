// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
//  UserFacingErrorSheet.swift
//  The sheet that replaced `.alert("Error", …)` — a title, one sentence, the
//  numbered steps that actually fix it, and one obvious button.
//
//  The raw message lives behind "Details for support" because for the people
//  this app is for it is noise; for the one time it matters it's selectable and
//  copyable. Everything here is plain SwiftUI: no NSTextView, no spinner (see
//  the layout-loop rule — platform-backed views must not sit inside an animated
//  container, and a DisclosureGroup animates).
//

import SwiftUI
import AppKit

struct UserFacingErrorSheet: View {
    let error: UserFacingError
    /// Re-runs the connect this failure came from. nil ⇒ nothing to retry.
    var retry: (() -> Void)?
    /// Opens one of the app's windows by id (Manage VPNs).
    var openWindow: ((String) -> Void)?

    @Environment(\.dismiss) private var dismiss
    @Environment(\.openURL) private var openURL
    @State private var showDetail = false

    private var tint: Color {
        switch error.category {
        case .onePassword: .blue
        case .credentials: .indigo
        case .approval: .orange
        case .network: .yellow
        case .configuration: .secondary
        case .generic: .orange
        }
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 16) {
            header
            if !error.steps.isEmpty {
                VStack(alignment: .leading, spacing: 10) {
                    ForEach(Array(error.steps.enumerated()), id: \.element.id) { index, step in
                        stepRow(number: index + 1, step: step)
                    }
                }
            }
            if !error.technicalDetail.isEmpty {
                details
            }
            Divider()
            buttons
        }
        .padding(22)
        .frame(width: 460)
        .accessibilityElement(children: .contain)
    }

    private var header: some View {
        HStack(alignment: .top, spacing: 14) {
            Image(systemName: error.symbol)
                .font(.system(size: 30))
                .foregroundStyle(tint)
                .frame(width: 38)
                .accessibilityHidden(true)
            VStack(alignment: .leading, spacing: 5) {
                Text(error.title)
                    .font(.title3.bold())
                    .fixedSize(horizontal: false, vertical: true)
                if !error.explanation.isEmpty {
                    Text(error.explanation)
                        .foregroundStyle(.secondary)
                        .fixedSize(horizontal: false, vertical: true)
                }
            }
        }
    }

    private func stepRow(number: Int, step: UserFacingError.Step) -> some View {
        HStack(alignment: .firstTextBaseline, spacing: 9) {
            // SF Symbols only go to 50; past that a plain number is fine.
            Group {
                if number <= 50 {
                    Image(systemName: "\(number).circle.fill").foregroundStyle(tint)
                } else {
                    Text("\(number).")
                }
            }
            .accessibilityHidden(true)
            VStack(alignment: .leading, spacing: 3) {
                // LocalizedStringKey so the **bold** UI names render as bold.
                Text(LocalizedStringKey(step.text))
                    .fixedSize(horizontal: false, vertical: true)
                if let note = step.note {
                    Text(LocalizedStringKey(note))
                        .font(.callout)
                        .foregroundStyle(.secondary)
                        .fixedSize(horizontal: false, vertical: true)
                }
            }
        }
        .accessibilityElement(children: .combine)
        .accessibilityLabel("Step \(number). \(step.text.replacingOccurrences(of: "**", with: ""))")
    }

    private var details: some View {
        DisclosureGroup("Details for support", isExpanded: $showDetail) {
            VStack(alignment: .leading, spacing: 6) {
                ScrollView {
                    Text(error.technicalDetail)
                        .font(.system(.caption, design: .monospaced))
                        .textSelection(.enabled)
                        .frame(maxWidth: .infinity, alignment: .leading)
                        .fixedSize(horizontal: false, vertical: true)
                }
                .frame(maxHeight: 110)
                HStack {
                    Spacer()
                    Button("Copy") {
                        NSPasteboard.general.clearContents()
                        NSPasteboard.general.setString(error.technicalDetail, forType: .string)
                    }
                    .controlSize(.small)
                }
            }
            .padding(.top, 6)
        }
        .font(.callout)
    }

    /// Close on the left, the fix on the right. "Try Again" is subordinate while
    /// there's somewhere to send them (fixing it first is the point); with no
    /// app to open, retrying IS the primary move.
    private var buttons: some View {
        HStack {
            Button("Close") { dismiss() }
                .keyboardShortcut(.cancelAction)
            Spacer()
            let retryButton = (error.canRetry && retry != nil)
            if retryButton, error.action != nil {
                Button("Try Again") { dismiss(); retry?() }
            }
            if let action = error.action {
                Button(action.title) { perform(action) }
                    .keyboardShortcut(.defaultAction)
                    .buttonStyle(.glassProminent)
            } else if retryButton {
                Button("Try Again") { dismiss(); retry?() }
                    .keyboardShortcut(.defaultAction)
                    .buttonStyle(.glassProminent)
            }
        }
    }

    private func perform(_ action: UserFacingError.Action) {
        switch action {
        case .openOnePassword:
            // Deliberately does NOT dismiss: the steps have to stay readable
            // while they're being followed in the other app.
            Self.openOnePassword()
        case .manageVPNs:
            openWindow?("manage")
            dismiss()
        case .networkSettings:
            if let url = URL(string: "x-apple.systempreferences:com.apple.Network-Settings.extension") {
                openURL(url)
            }
        case .openURL(let url):
            openURL(url)
        }
    }

    /// Bring 1Password forward. Resolved by bundle id (the app can live anywhere,
    /// and the Setapp/App Store copies aren't in /Applications); the download page
    /// is the honest fallback when it isn't installed at all.
    static func openOnePassword() {
        let workspace = NSWorkspace.shared
        let ids = ["com.1password.1password", "com.agilebits.onepassword7", "com.1password.1password-launcher"]
        for id in ids {
            if let url = workspace.urlForApplication(withBundleIdentifier: id) {
                workspace.openApplication(at: url, configuration: NSWorkspace.OpenConfiguration())
                return
            }
        }
        if let url = URL(string: "https://1password.com/downloads/mac") { workspace.open(url) }
    }
}
