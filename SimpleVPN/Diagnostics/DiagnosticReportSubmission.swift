// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
//  DiagnosticReportSubmission.swift
//  Getting the finished report to the project's issue tracker.
//
//  THE SIZE PROBLEM, and the rule about it. GitHub's issue-form prefill rides in
//  the URL's query string, and a URL that gets too long is rejected by the
//  browser or silently cut by the server. So the app prefills a SHORT body (the
//  two answers, the VPN type, and a line saying where the rest is) and hands the
//  full report over as a clipboard paste or a saved file.
//
//  NEVER SILENTLY TRUNCATE. If the short body itself will not fit — someone wrote
//  two thousand words about a captive portal, which is exactly the sort of report
//  worth having — the app says so, in words, and offers the file instead. A report
//  that arrives with its last paragraph missing and no warning is worse than one
//  that arrives as an attachment.
//

import Foundation
import AppKit

/// `@MainActor` because the repository URL lives on `Acknowledgements`, which is
/// main-actor state, and because everything here ends in a pasteboard write, a
/// save panel or a browser launch. `prepare` is still pure and is tested
/// directly.
@MainActor
enum DiagnosticReportSubmission {

    /// The practical ceiling for a prefilled issue URL.
    ///
    /// GitHub documents no number, and browsers differ (Safari and Chrome both
    /// cope with far more than this; some proxies do not). 6 KB is chosen to be
    /// comfortably under every limit anybody reports, because the failure mode of
    /// being wrong is a truncated bug report — and the fallback (clipboard or
    /// file) costs the user one paste.
    static let urlBudget = 6 * 1024

    /// What `prepare` decided.
    nonisolated struct Plan: Sendable, Equatable {
        /// The URL to open. nil when even the short body will not fit.
        var url: URL?
        /// The full report, for the clipboard or a file. Always the complete text.
        var fullReport: String
        /// The sentence shown to the user about what is about to happen. Always
        /// present: a silent action on this scale is not acceptable.
        var explanation: String
        /// True when the prefill had to be abandoned entirely.
        var needsFile: Bool
    }

    /// Percent-encode strictly (an allow-list), so newlines, `|` and `+` in the
    /// markdown cannot be misread by the query parser.
    static func encode(_ s: String) -> String {
        var allowed = CharacterSet.alphanumerics
        allowed.insert(charactersIn: "-._~")
        return s.addingPercentEncoding(withAllowedCharacters: allowed) ?? ""
    }

    /// The issue title. Names the VPN type when there is one, because that is how
    /// these get triaged.
    static func title(_ request: DiagnosticReportRequest) -> String {
        if let kind = request.kind {
            return "\(request.reason.titlePrefix): \(kind.displayName)"
        }
        return request.reason.titlePrefix
    }

    /// Build the plan. Pure — `DiagnosticReportSubmissionTests` drives it with an
    /// oversized report and asserts nothing is cut.
    static func prepare(_ request: DiagnosticReportRequest,
                        answers: DiagnosticReportAnswers,
                        fullReport: String,
                        budget: Int = urlBudget) -> Plan {
        let kindLine = request.kind?.displayName ?? "not specific to one VPN type"
        let short = """
            \(answers.whatYouWereDoing.trimmingCharacters(in: .whitespacesAndNewlines))

            **What went wrong:** \(answers.whatWentWrong.trimmingCharacters(in: .whitespacesAndNewlines))

            **VPN type:** \(kindLine)

            _The full report SimpleVPN assembled is on the clipboard — paste it into the
            "SimpleVPN report" box below._
            """

        var query = "template=\(templateFileName)"
        query += "&title=\(encode(title(request)))"
        query += "&what-happened=\(encode(short))"
        query += "&report=\(encode("(paste the report here \u{2014} it\u{2019}s on your clipboard)"))"
        let candidate = "\(Acknowledgements.sourceURL)/issues/new?\(query)"

        guard candidate.count <= budget, let url = URL(string: candidate) else {
            return Plan(
                url: nil,
                fullReport: fullReport,
                explanation: """
                    What you\u{2019}ve written is too long to carry in a web link, and SimpleVPN will not \
                    shorten it behind your back. Save the report to a file, open a new issue yourself, \
                    and attach it \u{2014} the whole thing gets through that way.
                    """,
                needsFile: true)
        }
        return Plan(
            url: url,
            fullReport: fullReport,
            explanation: """
                SimpleVPN will copy the whole report to your clipboard and open a new issue on GitHub \
                with your description already filled in. Paste the report into the box the form asks \
                for. Nothing is sent until you press Submit on GitHub.
                """,
            needsFile: false)
    }

    /// The issue form this flow targets. Field ids in
    /// `.github/ISSUE_TEMPLATE/simplevpn_report.yml` are load-bearing — renaming
    /// one breaks the prefill silently, which is why they are named here once.
    static let templateFileName = "simplevpn_report.yml"

    // MARK: Carrying it out

    @MainActor
    static func copyToClipboard(_ text: String) {
        NSPasteboard.general.clearContents()
        NSPasteboard.general.setString(text, forType: .string)
    }

    /// Offer a Save panel. Returns the URL written, or nil if the user cancelled
    /// or the write failed (with the reason, for the dialog to show).
    @MainActor
    static func save(_ text: String, suggestedName: String) -> (url: URL?, error: String?) {
        let panel = NSSavePanel()
        panel.title = "Save SimpleVPN Report"
        panel.nameFieldStringValue = suggestedName
        panel.allowedContentTypes = [.plainText]
        guard panel.runModal() == .OK, let url = panel.url else { return (nil, nil) }
        do {
            try Data(text.utf8).write(to: url)
            return (url, nil)
        } catch {
            return (nil, error.localizedDescription)
        }
    }

    /// A stable, boring filename. Includes the date so a user who files two in a
    /// day does not overwrite the first.
    static func suggestedFileName(_ request: DiagnosticReportRequest, now: Date = .now) -> String {
        let day = now.formatted(.iso8601.year().month().day().dateSeparator(.dash))
        let kind = request.kind?.rawValue ?? "general"
        return "SimpleVPN-report-\(kind)-\(day).md"
    }

    /// Where a user goes to see what they have already reported. GitHub resolves
    /// `@me` for whoever is signed in, so the app never stores an issue number.
    static var existingIssuesURL: URL? {
        URL(string: "\(Acknowledgements.sourceURL)/issues?q=\(encode("is:issue author:@me sort:updated-desc"))")
    }

    /// The tracker itself, for "there is no issue link anywhere in the app" —
    /// there is now, in three places: the banner, this dialog, and the Help menu.
    static var trackerURL: URL? { URL(string: "\(Acknowledgements.sourceURL)/issues") }
}
