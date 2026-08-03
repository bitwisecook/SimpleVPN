// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
//  ProbeLadderView.swift
//  The staged probe on screen: one row per rung of the handshake, in the order
//  a real connection climbs them, with a green tick, a red cross or a grey dash
//  against each — so "where does it break?" is answered by looking, not reading.
//
//  Deliberate choices:
//    • The technical evidence is behind a disclosure. The row itself says what
//      happened in a sentence anyone can act on; the fingerprints, cipher names
//      and dates are there for the one time they matter.
//    • A failed rung carries its remedy inline (the same UserFacingError the
//      rest of the app raises), with its action button right there.
//    • The sign-in rung shows as a grey dash with its own reason and an opt-in
//      button. That is the account boundary made visible: the app is saying, in
//      the interface, that it chose not to spend your one-time code.
//
//  No platform-backed views inside the animated containers (the disclosure
//  animates): the "running" indicator is the app's drawn spinner, not
//  ProgressView. See the layout-loop rule.
//

import SwiftUI
import AppKit

struct ProbeLadderCard: View {
    let ladder: ProbeLadder
    let isRunning: Bool
    /// Offered when a sign-in rung is still untested. nil hides the opt-in.
    var testSignIn: (() -> Void)?
    var rerun: (() -> Void)?

    @Environment(\.openWindow) private var openWindow
    @Environment(\.openURL) private var openURL

    var body: some View {
        GroupBox {
            VStack(alignment: .leading, spacing: 12) {
                header
                VStack(alignment: .leading, spacing: 0) {
                    ForEach(Array(ladder.steps.enumerated()), id: \.element.id) { index, step in
                        if index > 0 { Divider().padding(.leading, 26) }
                        ProbeStepRow(step: step, openWindow: openWindow, openURL: openURL)
                    }
                }
                footer
            }
            .padding(6)
        } label: {
            Label("Step-by-Step Check", systemImage: "list.bullet.indent")
        }
    }

    private var header: some View {
        HStack(alignment: .top, spacing: 10) {
            Image(systemName: headlineSymbol)
                .font(.title2)
                .foregroundStyle(headlineTint)
                .accessibilityHidden(true)
            VStack(alignment: .leading, spacing: 2) {
                Text(ladder.summary)
                    .font(.callout.weight(.semibold))
                    .fixedSize(horizontal: false, vertical: true)
                Text(subtitle).font(.caption).foregroundStyle(.secondary)
            }
            Spacer(minLength: 8)
            if isRunning {
                HStack(spacing: 6) {
                    DrawnSpinner()
                    Text("Checking\u{2026}").font(.caption).foregroundStyle(.secondary)
                }
            } else if let rerun {
                Button("Check Again", action: rerun).controlSize(.small)
            }
        }
    }

    private var subtitle: String {
        var parts = ["\(ladder.kind.displayName)"]
        if !ladder.host.isEmpty { parts.append("\(ladder.host):\(ladder.port)") }
        if let elapsed = ladder.elapsed {
            parts.append(String(format: "%.1f s", elapsed))
        }
        return parts.joined(separator: " \u{00B7} ")
    }

    private var headlineSymbol: String {
        if isRunning { return "waveform.path.ecg" }
        if !ladder.securityFindings.isEmpty { return "exclamationmark.shield.fill" }
        return ladder.firstFailure == nil ? "checkmark.seal.fill" : "xmark.octagon.fill"
    }
    private var headlineTint: Color {
        if isRunning { return .secondary }
        if !ladder.securityFindings.isEmpty { return .red }
        return ladder.firstFailure == nil ? .green : .red
    }

    @ViewBuilder private var footer: some View {
        if ladder.hasUntestedSignIn, let testSignIn {
            Divider()
            HStack(alignment: .top, spacing: 8) {
                Image(systemName: "person.badge.key")
                    .foregroundStyle(.secondary)
                    .accessibilityHidden(true)
                VStack(alignment: .leading, spacing: 2) {
                    Text("The sign-in itself hasn\u{2019}t been tried.")
                        .font(.callout)
                    Text(signInCaution)
                        .font(.caption).foregroundStyle(.secondary)
                        .fixedSize(horizontal: false, vertical: true)
                }
                Spacer(minLength: 8)
                Button("Test Sign-In Too", action: testSignIn)
                    .buttonStyle(.glass)
                    .controlSize(.small)
            }
        }
    }

    private var signInCaution: String {
        ladder.accountSteps.first?.detail
            ?? "Testing it would use a real sign-in attempt, so it only happens when you ask."
    }
}

// MARK: - One rung

struct ProbeStepRow: View {
    let step: ProbeStep
    var openWindow: OpenWindowAction?
    var openURL: OpenURLAction?

    @State private var showEvidence = false

    var body: some View {
        VStack(alignment: .leading, spacing: 6) {
            HStack(alignment: .top, spacing: 8) {
                glyph
                VStack(alignment: .leading, spacing: 2) {
                    Text(step.title)
                        .font(.callout.weight(step.status == .failed ? .semibold : .medium))
                    Text(step.detail)
                        .font(.caption)
                        .foregroundStyle(step.status == .failed ? .primary : .secondary)
                        .fixedSize(horizontal: false, vertical: true)
                }
                Spacer(minLength: 8)
                if step.securityFinding {
                    Text("Security")
                        .font(.caption2.weight(.medium))
                        .padding(.horizontal, 6).padding(.vertical, 2)
                        .background(.red.opacity(0.15), in: Capsule())
                        .foregroundStyle(.red)
                }
                if let duration = step.duration {
                    Text(format(duration))
                        .font(.caption2.monospacedDigit())
                        .foregroundStyle(.tertiary)
                }
            }
            if !step.evidence.isEmpty {
                DisclosureGroup("Details", isExpanded: $showEvidence) {
                    VStack(alignment: .leading, spacing: 2) {
                        ForEach(step.evidence, id: \.self) { line in
                            Text(line)
                                .font(.caption2.monospaced())
                                .foregroundStyle(.secondary)
                                .textSelection(.enabled)
                                .fixedSize(horizontal: false, vertical: true)
                                .frame(maxWidth: .infinity, alignment: .leading)
                        }
                    }
                    .padding(.top, 3)
                }
                .font(.caption)
                .padding(.leading, 26)
            }
            if let remedy = step.remedy, step.status != .ok {
                remedyBlock(remedy)
            }
        }
        .padding(.vertical, 7)
        .accessibilityElement(children: .combine)
        .accessibilityLabel("\(accessibleStatus). \(step.title). \(step.detail)")
    }

    private var glyph: some View {
        Image(systemName: step.status.symbol)
            .font(.system(size: 15))
            .foregroundStyle(tint)
            .frame(width: 18)
            .accessibilityHidden(true)
    }

    private var tint: Color {
        switch step.status {
        case .ok: .green
        case .failed: .red
        case .running: .accentColor
        case .pending, .skipped, .notApplicable: .secondary
        }
    }

    private var accessibleStatus: String {
        switch step.status {
        case .ok: "Passed"
        case .failed: "Failed"
        case .running: "Checking"
        case .pending: "Waiting"
        case .skipped: "Not tested"
        case .notApplicable: "Doesn't apply"
        }
    }

    @ViewBuilder
    private func remedyBlock(_ remedy: UserFacingError) -> some View {
        HStack(alignment: .top, spacing: 8) {
            Image(systemName: "lightbulb")
                .foregroundStyle(.orange)
                .accessibilityHidden(true)
            VStack(alignment: .leading, spacing: 3) {
                Text(remedy.title).font(.caption.weight(.semibold))
                Text(remedy.explanation)
                    .font(.caption).foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
                ForEach(remedy.steps) { s in
                    // LocalizedStringKey renders the **bold** UI names the same
                    // way the error sheet does, so one instruction reads
                    // identically wherever it appears.
                    Text(LocalizedStringKey("\u{2022} " + s.text))
                        .font(.caption2).foregroundStyle(.secondary)
                        .fixedSize(horizontal: false, vertical: true)
                }
            }
            Spacer(minLength: 8)
            if let action = remedy.action {
                Button(action.title) { perform(action) }
                    .controlSize(.small)
            }
        }
        .padding(8)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(.orange.opacity(0.08), in: RoundedRectangle(cornerRadius: 7))
        .padding(.leading, 26)
    }

    private func perform(_ action: UserFacingError.Action) {
        switch action {
        case .openOnePassword: UserFacingErrorSheet.openOnePassword()
        case .openKeePassXC: UserFacingErrorSheet.openKeePassXC()
        case .manageVPNs: openWindow?(id: "manage")
        case .networkSettings:
            if let url = URL(string: "x-apple.systempreferences:com.apple.Network-Settings.extension") {
                openURL?(url)
            }
        case .openURL(let url): openURL?(url)
        }
    }

    private func format(_ seconds: TimeInterval) -> String {
        seconds < 1 ? "\(Int(seconds * 1000)) ms" : String(format: "%.1f s", seconds)
    }
}
