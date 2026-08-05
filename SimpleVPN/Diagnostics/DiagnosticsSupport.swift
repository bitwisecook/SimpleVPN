// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
//  DiagnosticsSupport.swift
//  The user-facing side of bug reporting:
//   • Help ▸ Capture Debug Log (Scrubbed / Full) — collect and save to a file.
//   • About ▸ Report an Issue… — a guided sheet: choose whether to include a log
//     and which variant, READ exactly what will be shared, then open the prefilled
//     GitHub issue form.
//  Logs are never included by default and never leave without the user seeing them.
//

import SwiftUI
import AppKit

@MainActor
@Observable
final class DiagnosticsCapture {
    private(set) var working = false
    private(set) var lastError: String?

    /// Facts for the bundle header — versions and VPN *types* only.
    var header: [String: String] = [:]
    /// Literal strings to redact in scrubbed output (configured usernames etc).
    var secrets: [String] = []

    func capture(_ variant: DiagnosticBundle.Variant) async -> String {
        working = true; defer { working = false }
        return await DiagnosticBundle.collect(variant: variant, header: header, extraSecrets: secrets)
    }

    /// Collect and offer a Save panel — the Help-menu path.
    func captureAndSave(_ variant: DiagnosticBundle.Variant) async {
        let text = await capture(variant)
        // Collection takes a few seconds (log show + netstat + resolvers), and what a
        // bug-report paste actually wants is the CLIPBOARD — so once it's done, offer
        // that first-class rather than assuming a file save. Copy is the default button;
        // it copies and closes.
        let alert = NSAlert()
        alert.messageText = "Debug log captured (\(variant.title))"
        alert.informativeText = (variant == .full
            ? "This FULL log may contain hostnames, IP addresses and usernames."
            : "Addresses, hostnames and usernames were replaced with placeholders — review before sharing.")
            + "\n\n\(text.count.formatted()) characters collected."
        alert.addButton(withTitle: "Copy to Clipboard")
        alert.addButton(withTitle: "Save\u{2026}")
        alert.addButton(withTitle: "Cancel")
        switch alert.runModal() {
        case .alertFirstButtonReturn:
            NSPasteboard.general.clearContents()
            NSPasteboard.general.setString(text, forType: .string)
        case .alertSecondButtonReturn:
            let panel = NSSavePanel()
            panel.title = "Save Debug Log (\(variant.title))"
            panel.nameFieldStringValue = "SimpleVPN-diagnostics-\(variant.rawValue).txt"
            panel.allowedContentTypes = [.plainText]
            guard panel.runModal() == .OK, let url = panel.url else { return }
            do { try Data(text.utf8).write(to: url) }
            catch { lastError = error.localizedDescription }
        default:
            break
        }
    }
}

/// Help-menu diagnostics: capture a debug log (either variant) straight to a file,
/// jump to the issues you've opened, or start a guided report.
struct DiagnosticsCommands: Commands {
    @Bindable var vpn: VPNController
    var tunnels: SubprocessTunnelStore
    @Environment(\.openWindow) private var openWindow
    @Environment(\.openURL) private var openURL
    @State private var capture = DiagnosticsCapture()

    var body: some Commands {
        // ONE group anchored at .help — replacing the system item (which would
        // look for a help book this app doesn't have) AND carrying the
        // diagnostics entries. It used to be two groups, replacing(.help) plus
        // after(.help): anchoring a second group to a placement the first had
        // replaced sent SwiftUI's menu builder into an infinite invalidation
        // loop — permanent beachball at launch.
        CommandGroup(replacing: .help) {
            Button("SimpleVPN Help") { openWindow(id: "manual") }
                .keyboardShortcut("?", modifiers: [.command])
            Divider()
            Button("Capture Debug Log (Scrubbed)…") { save(.scrubbed) }
            Button("Capture Debug Log (Full)…") { save(.full) }
            Divider()
            // Both reports live in About, where the guided sheets (and the "what
            // will be shared" review) already are.
            // The guided report: asks what you were doing, gathers the tool
            // inventory / what was reachable / what is switched off, and shows
            // the whole payload before anything can be shared. This is the entry
            // point the "Untested" banner's report link shares.
            Button("Report a Problem…") { report() }
            Divider()
            Button("Report an Issue…") {
                ReportRequest.shared.request(.bug); openWindow(id: "about")
            }
            Button("Report a UI Issue…") {
                ReportRequest.shared.request(.ui); openWindow(id: "about")
            }
            Button("My Reported Issues") {
                if let url = IssueReport.myIssuesURL { openURL(url) }
            }
            Button("Open the Issue Tracker") {
                if let url = DiagnosticReportSubmission.trackerURL { openURL(url) }
            }
        }
    }

    /// Open the guided report, wiring the coordinator to the objects this menu
    /// already holds. The banner path wires the rest through
    /// `hostsDiagnosticReports()`; what is missing degrades to "not recorded"
    /// with its reason, never to a wrong answer.
    private func report() {
        var context = DiagnosticReportCoordinator.shared.context
        context.vpn = vpn
        context.tunnels = tunnels
        DiagnosticReportCoordinator.shared.context = context
        DiagnosticReportCoordinator.shared.presentReport(
            DiagnosticReportRequest(kind: vpn.profiles.first(where: { $0.id == vpn.selectedID })?.kind,
                                    profileID: vpn.selectedID,
                                    reason: .userInitiated))
    }

    private func save(_ variant: DiagnosticBundle.Variant) {
        capture.header = [
            "App": UI.appVersion,
            "System extension": vpn.extensionVersion,
            "macOS": ProcessInfo.processInfo.operatingSystemVersionString,
            "Architecture": IssueReport.architecture,
        ]
        capture.secrets = tunnels.tunnels.map(\.username).filter { !$0.isEmpty }
        Task { await capture.captureAndSave(variant) }
    }
}

/// UI/appearance report: get a picture first. Instructions quote the user's OWN
/// screenshot keys, and the Screenshot app is launched rather than us capturing —
/// so SimpleVPN never needs Screen Recording permission.
/// Read-only rendering of exactly what SimpleVPN will attach to the report.
///
/// Read-only is the deliberate choice: the app gathers what it can automatically, and
/// the report itself is written and edited on GitHub. An editable copy here would be a
/// second place to author the same text — and everything in it is either a fact the app
/// measured (versions, appearance) or freely editable on GitHub once the form opens.
struct FactsCard: View {
    let title: String
    let facts: [IssueReport.Fact]

    var body: some View {
        GroupBox(title) {
            Grid(alignment: .leadingFirstTextBaseline, horizontalSpacing: 14, verticalSpacing: 5) {
                ForEach(facts) { fact in
                    GridRow {
                        Text(fact.label)
                            .foregroundStyle(.secondary)
                            .gridColumnAlignment(.leading)
                        Text(fact.value)
                            .fontWeight(.medium)
                            .textSelection(.enabled)
                            .fixedSize(horizontal: false, vertical: true)
                    }
                }
            }
            .font(.callout)
            .frame(maxWidth: .infinity, alignment: .leading)
            .padding(4)
        }
    }
}

/// Says out loud where the writing happens, so the read-only cards above don't read as
/// a broken form.
private struct FinishOnGitHubNote: View {
    var body: some View {
        Label("SimpleVPN fills in the details above. You'll describe the problem \u{2014} and can change anything shown here \u{2014} on GitHub.",
              systemImage: "arrow.up.forward.square")
            .font(.callout).foregroundStyle(.secondary)
            .fixedSize(horizontal: false, vertical: true)
    }
}

struct UIIssueSheet: View {
    let facts: IssueReport.Facts
    @Environment(\.dismiss) private var dismiss
    @Environment(\.openURL) private var openURL

    private var area: ScreenshotShortcuts.Shortcut { ScreenshotShortcuts.selectedArea }
    private var panel: ScreenshotShortcuts.Shortcut { ScreenshotShortcuts.screenshotPanel }

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            Text("Report a UI Issue").font(.title2).bold()
            Text("Layout depends on window size, display scale, appearance and accessibility settings — so a picture is worth far more than a description here.")
                .font(.callout).foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)

            GroupBox("Capture it first") {
                VStack(alignment: .leading, spacing: 8) {
                    Label {
                        Text("Screenshot of a selection: **\(area.phrase)**")
                    } icon: { Image(systemName: "camera.viewfinder") }
                    Label {
                        Text("Screenshot **or screen recording** options: **\(panel.phrase)**")
                    } icon: { Image(systemName: "video.badge.plus") }
                    Text("If it's about animation, or a glitch that flashes past, please record it instead of screenshotting.")
                        .font(.caption).foregroundStyle(.secondary)
                        .fixedSize(horizontal: false, vertical: true)
                    if !area.enabled || !panel.enabled {
                        Label("One of these is switched off in System Settings ▸ Keyboard ▸ Keyboard Shortcuts ▸ Screenshots.",
                              systemImage: "exclamationmark.triangle")
                            .font(.caption).foregroundStyle(.orange)
                            .fixedSize(horizontal: false, vertical: true)
                    }
                    if ScreenshotShortcuts.screenshotAppAvailable {
                        Button("Open Screenshot Tool") { ScreenshotShortcuts.openScreenshotApp() }
                            .help("Opens Apple's Screenshot app, which can capture a still or record the screen.")
                    }
                }
                .frame(maxWidth: .infinity, alignment: .leading)
                .padding(4)
            }

            FactsCard(title: "Included automatically",
                      facts: IssueReport.appearanceRows + IssueReport.factRows(facts))

            Text("On GitHub, drag your screenshot or recording into the first box.")
                .font(.callout).foregroundStyle(.secondary)
            FinishOnGitHubNote()

            HStack {
                Spacer()
                Button("Cancel") { dismiss() }
                    .keyboardShortcut(.cancelAction)
                Button("Open GitHub…") {
                    if let url = IssueReport.uiIssueURL(facts) { openURL(url) }
                    dismiss()
                }
                .keyboardShortcut(.defaultAction)
                .buttonStyle(.glassProminent)
            }
        }
        .padding(20)
        .frame(width: 560)
    }
}

/// Guided report: pick a log variant (default: none), review, then open GitHub.
struct IssueReportSheet: View {
    let facts: IssueReport.Facts
    let capture: DiagnosticsCapture
    @Environment(\.dismiss) private var dismiss
    @Environment(\.openURL) private var openURL

    /// nil = don't include a log (the default).
    @State private var variant: DiagnosticBundle.Variant?
    @State private var logText = ""
    @State private var busy = false
    @State private var copied = false

    var body: some View {
        VStack(alignment: .leading, spacing: 14) {
            Text("Report an Issue").font(.title2).bold()
            Text("The versions below and which VPN **types** you have configured are included. Nothing else about your VPNs is sent.")
                .font(.callout).foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)

            FactsCard(title: "Always included", facts: IssueReport.factRows(facts))

            Picker("Include a debug log", selection: $variant) {
                Text("Don't include a log").tag(DiagnosticBundle.Variant?.none)
                Text("Scrubbed — addresses, hostnames and usernames replaced").tag(Optional(DiagnosticBundle.Variant.scrubbed))
                Text("Full — may contain hostnames, addresses and usernames").tag(Optional(DiagnosticBundle.Variant.full))
            }
            .pickerStyle(.radioGroup)
            .onChange(of: variant) { _, new in
                logText = ""
                guard let new else { return }
                busy = true
                Task { logText = await capture.capture(new); busy = false }
            }

            if busy {
                HStack(spacing: 8) { ProgressView().controlSize(.small); Text("Collecting…").foregroundStyle(.secondary) }
            } else if !logText.isEmpty {
                GroupBox(variant == .full ? "Review — FULL log (read this before sharing)" : "Review — scrubbed log") {
                    LogText(text: logText)
                        .frame(height: 220)
                    HStack { Spacer(); CopyLogButton(text: logText) }
                }
                if variant == .full {
                    Label("A full log can identify you and your network. Only share it if you're comfortable doing so.",
                          systemImage: "exclamationmark.triangle.fill")
                        .font(.caption).foregroundStyle(.orange)
                        .fixedSize(horizontal: false, vertical: true)
                }
                Text("The log is too long for a web link, so it's copied to your clipboard — paste it into the “Diagnostics bundle” field on GitHub.")
                    .font(.caption).foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }

            FinishOnGitHubNote()

            HStack {
                if copied { Label("Log copied", systemImage: "checkmark.circle.fill").font(.caption).foregroundStyle(.green) }
                Spacer()
                Button("Cancel") { dismiss() }
                    .keyboardShortcut(.cancelAction)
                Button("Open GitHub…") { open() }
                    .keyboardShortcut(.defaultAction)
                    .buttonStyle(.glassProminent)
                    .disabled(busy)
            }
        }
        .padding(20)
        .frame(width: 560)
    }

    private func open() {
        if !logText.isEmpty {
            NSPasteboard.general.clearContents()
            NSPasteboard.general.setString(logText, forType: .string)
            copied = true
        }
        if let url = IssueReport.url(facts, includingLogNote: !logText.isEmpty) { openURL(url) }
        dismiss()
    }
}
