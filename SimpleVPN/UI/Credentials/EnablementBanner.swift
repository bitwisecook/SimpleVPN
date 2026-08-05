// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
//  EnablementBanner.swift
//  "You can turn this on." ONE banner, every vendor: shown wherever a password
//  app is present on this Mac but the piece SimpleVPN reads through is missing or
//  switched off. Driven entirely by `EnablementGuidance` data, so a new adapter
//  supplies its own example and its own documentation link declaratively and
//  never touches this file.
//
//  WHAT IT IS, AND WHAT IT DELIBERATELY IS NOT:
//   • It carries ONE short example of OUR OWN — the minimal commands that get it
//     working on the vendor's CURRENT release — because a bare URL is no use to
//     someone whose VPN is down and whose network therefore isn't working. Each
//     command is copyable.
//   • It links to the vendor's own page for everything else. Their page is the
//     authority. This is NOT a hole in the house rule that all of OUR
//     documentation is embedded in the app (AGENTS.md): everything SimpleVPN has
//     to say is here, offline, in the example; what is behind the link is
//     someone else's manual, which we could not bundle and must not paraphrase.
//   • It is NOT a manual, and NOT a version matrix. No "on older versions the
//     toggle is called X, or lives at Y". If a vendor moves something we update
//     our one line; their page carries the history. Maintaining a compatibility
//     matrix for someone else's software is not this app's job.
//   • It NEVER installs anything. SimpleVPN shows the command; the user runs it.
//     No bundled CLI, no bundled runtime, no "Install for me" button — by rule.
//
//  ACCESSIBILITY: the commands and the link are CONTENT, not decoration. The
//  banner is one container whose label is `guidance.spokenSummary` — the benefit,
//  the setting location, every command with its caption, and the page name — so a
//  VoiceOver user hears exactly what a sighted user reads, and each Copy button
//  names the command it copies. Nothing here is hover-only.
//

import SwiftUI
import AppKit

struct EnablementBanner: View {
    let guidance: EnablementGuidance
    /// Announced after a copy, because a clipboard change is invisible.
    @State private var copied: String?

    var body: some View {
        VStack(alignment: .leading, spacing: 6) {
            Text(guidance.benefit)
                .font(.caption).foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)

            if let location = guidance.settingLocation {
                // LocalizedStringKey so **bold** names the real thing on screen.
                Label(LocalizedStringKey(location), systemImage: "switch.2")
                    .font(.caption)
                    .fixedSize(horizontal: false, vertical: true)
                    .accessibilityLabel(location.replacingOccurrences(of: "**", with: ""))
            }

            ForEach(guidance.example) { command in
                commandRow(command)
            }

            Link(destination: guidance.doc.url) {
                Label("\(guidance.doc.title) \u{2014} full details", systemImage: "book")
                    .font(.caption)
            }
            .help(guidance.doc.url.absoluteString)
            .accessibilityLabel("\(guidance.doc.title), the vendor\u{2019}s own documentation")
            .accessibilityHint("Opens \(guidance.doc.url.absoluteString) in your browser.")
        }
        .padding(8)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(.quaternary.opacity(0.5), in: RoundedRectangle(cornerRadius: 8))
        // A container (it holds buttons and a link), with the whole banner as one
        // spoken sentence so nothing in it is reachable only by eye.
        .accessibilityElement(children: .contain)
        .accessibilityLabel(guidance.spokenSummary)
        .accessibilityIdentifier("enablement-banner")
    }

    /// One command: what it does, the command itself in a monospaced field you can
    /// select, and a Copy button. The text is selectable as well as copyable —
    /// someone who wants half a line should be able to take half a line.
    private func commandRow(_ command: EnablementGuidance.Command) -> some View {
        VStack(alignment: .leading, spacing: 2) {
            Text(command.caption)
                .font(.caption2).foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
            HStack(alignment: .firstTextBaseline, spacing: 6) {
                Text(command.text)
                    .font(.caption.monospaced())
                    .textSelection(.enabled)
                    .fixedSize(horizontal: false, vertical: true)
                    .padding(.horizontal, 5).padding(.vertical, 2)
                    .background(.background.opacity(0.6), in: RoundedRectangle(cornerRadius: 4))
                Button {
                    copy(command.text)
                } label: {
                    Image(systemName: copied == command.text ? "checkmark" : "doc.on.doc")
                        .frame(width: 18, height: 16).contentShape(Rectangle())
                }
                .buttonStyle(.borderless)
                .controlSize(.small)
                .help("Copy \u{201C}\(command.text)\u{201D}")
                .accessibilityLabel("Copy the command \(command.text)")
                .accessibilityValue(copied == command.text ? "Copied" : "")
                Spacer(minLength: 0)
            }
        }
        // The row reads as one sentence: what it does, then what to run.
        .accessibilityElement(children: .contain)
        .accessibilityLabel("\(command.caption). Command: \(command.text)")
    }

    private func copy(_ text: String) {
        NSPasteboard.general.clearContents()
        NSPasteboard.general.setString(text, forType: .string)
        copied = text
        AccessibilityAnnouncer.sayNow("Copied \(text)")
    }
}
