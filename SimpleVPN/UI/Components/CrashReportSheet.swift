// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
//  CrashReportSheet.swift
//  "SimpleVPN quit unexpectedly" — offer to report it, pre-filled.
//
//  The same consent rules as the diagnostics bundle apply, and for the same reason: a
//  crash report contains the home-directory path (so, the username) and can contain
//  addresses. So it is scrubbed by default, shown in full for review before anything
//  leaves the machine, and the user can decline entirely. Nothing is uploaded by the
//  app — it opens a pre-filled GitHub form, and the backtrace goes via the clipboard
//  because a URL can't carry one.
//

import SwiftUI

struct CrashReportSheet: View {
    let reports: [CrashReport]
    let facts: IssueReport.Facts
    @Environment(\.dismiss) private var dismiss
    @Environment(\.openURL) private var openURL

    @State private var scrub = true
    @State private var copied = false

    private var report: CrashReport? { reports.first }

    /// What will actually be shared, scrubbed or not.
    private var body_text: String {
        guard let report else { return "" }
        let raw = report.markdown
        return scrub ? DiagnosticBundle.scrubText(raw) : raw
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            Label("SimpleVPN quit unexpectedly", systemImage: "exclamationmark.triangle.fill")
                .font(.title2.bold())
                .foregroundStyle(.orange)

            if reports.count > 1 {
                Text("There are \(reports.count) recent crashes. The most recent one is shown; reporting sends just this one.")
                    .font(.callout).foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }

            if let report {
                FactsCard(title: "What happened", facts: [
                    .init(label: "Type", value: report.kind),
                    .init(label: "Reason", value: report.reason ?? "(none recorded)"),
                    .init(label: "App version", value: report.appVersion),
                    .init(label: "When", value: report.when.formatted(date: .abbreviated, time: .shortened)),
                ])
            }

            Toggle("Replace hostnames, addresses and usernames with placeholders", isOn: $scrub)
            Text("A crash report includes file paths, which contain your user name. Scrubbing keeps the backtrace useful while removing those.")
                .font(.callout).foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)

            GroupBox("Review — this is exactly what gets shared") {
                VStack(alignment: .leading, spacing: 6) {
                    LogText(text: body_text)
                        .frame(height: 220)
                    HStack {
                        Text("Select with \u{2318}A, search with \u{2318}F.")
                            .font(.caption).foregroundStyle(.secondary)
                        Spacer()
                        CopyLogButton(text: body_text)
                    }
                }
                .padding(4)
            }

            HStack {
                if copied {
                    Label("Backtrace copied", systemImage: "checkmark.circle.fill")
                        .font(.caption).foregroundStyle(.green)
                }
                Spacer()
                Button("Don't Report") {
                    CrashDiagnostics.markHandled(reports)
                    dismiss()
                }
                Button("Report on GitHub…") { open() }
                    .keyboardShortcut(.defaultAction)
                    .buttonStyle(.glassProminent)
                    .disabled(report == nil)
            }
        }
        .padding(20)
        .frame(width: 600)
    }

    private func open() {
        guard let report else { return }
        // The backtrace is far too long for a query string, so it rides the clipboard —
        // same approach as the diagnostics bundle.
        NSPasteboard.general.clearContents()
        NSPasteboard.general.setString(body_text, forType: .string)
        copied = true
        if let url = IssueReport.crashURL(facts, summary: report.summary) {
            openURL(url)
        }
        CrashDiagnostics.markHandled(reports)
    }
}
