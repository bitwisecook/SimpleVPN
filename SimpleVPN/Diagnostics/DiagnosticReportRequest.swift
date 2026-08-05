// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
//  DiagnosticReportRequest.swift
//  THE SEAM between "somewhere in the app is offering to report something" and
//  "the diagnostic-report sheet". Two declarations and a coordinator, nothing
//  else: the request (pure data), the presenter protocol, and the one object
//  callers reach for.
//
//  WHY A SEAM AT ALL. The maturity banners (FeatureMaturity.swift) ask users to
//  tell us what happened, because a report is literally the only thing that
//  clears an "Untested" label. The dialog that assembles such a report is a
//  substantial, privacy-critical surface of its own — the environment inventory,
//  the per-section toggles, the verbatim payload preview, the log scrubber and
//  its adversarial corpus. That is built separately and deliberately: two
//  competing "report an issue" surfaces would be worse than one late one.
//
//  So this file defines the call and ships a PLACEHOLDER that does the honest
//  minimum — opens the project's issue tracker with a short templated body. When
//  the real presenter lands it installs itself on `DiagnosticReportCoordinator`
//  and every existing call site starts using it with no edits.
//
//  WHAT THIS FILE MUST NEVER GROW INTO: an inventory gatherer, a log scrubber, a
//  payload preview, or a second issue-submission surface. If something here needs
//  to know about installed password managers, it is in the wrong file.
//
//  PRIVACY, even for the placeholder: the request carries a VPN kind and a
//  profile id, and nothing else. A profile id is SimpleVPN's own stable key, not
//  a name, a server, a username or anything a user typed — and the placeholder
//  URL below does not put even that on the wire. Nothing is uploaded anywhere; a
//  browser is opened on a form the user then reads and submits themselves.
//

import Foundation
import AppKit

// MARK: - The request

/// Requests the diagnostic-report sheet.
nonisolated struct DiagnosticReportRequest: Sendable, Equatable {
    /// The profile's kind, when the request came from one.
    var kind: VPNKind?
    /// Never a secret; may be nil.
    var profileID: String?
    /// Why we are offering to report.
    var reason: Reason

    enum Reason: String, Sendable, Equatable {
        case untestedKind
        case untestedSource
        case connectFailure
        case userInitiated
    }
}

// MARK: - The presenter

@MainActor protocol DiagnosticReportPresenting: AnyObject {
    func presentReport(_ request: DiagnosticReportRequest)
}

// MARK: - The one object callers reach for

/// Where a call site sends a request without knowing who will answer it.
///
/// The same shape as `ReportRequest` in AboutView.swift (a shared, observable
/// request object) so there is no new plumbing idiom to learn. The real presenter
/// installs itself into `presenter` once, at launch; until then the placeholder
/// answers, so a banner's report button is never dead.
@MainActor
@Observable
final class DiagnosticReportCoordinator: DiagnosticReportPresenting {
    static let shared = DiagnosticReportCoordinator()

    /// Install the real presenter here — one line, at launch. Left nil, the
    /// placeholder below answers.
    var presenter: (any DiagnosticReportPresenting)?

    /// The last request served, so a presenter that appears later (or a test) can
    /// see what was asked for.
    private(set) var lastRequest: DiagnosticReportRequest?

    func presentReport(_ request: DiagnosticReportRequest) {
        lastRequest = request
        if let presenter {
            presenter.presentReport(request)
        } else {
            PlaceholderIssueTrackerPresenter.shared.presentReport(request)
        }
    }
}

// MARK: - PLACEHOLDER — replaced wholesale by the real diagnostic-report sheet

/// **This is the placeholder.** Delete this type and its `openURL` hook when the
/// real report sheet lands; nothing else in the app refers to it.
///
/// It does the one useful thing that needs no infrastructure: opens the project's
/// GitHub issue form with a short body naming what the user was looking at. No
/// inventory, no logs, no clipboard, no upload — the user reads and submits the
/// form themselves, exactly as the About window's "Report an Issue…" already
/// works. Deliberately less than the real thing, and deliberately not a
/// half-built version of it.
@MainActor
final class PlaceholderIssueTrackerPresenter: DiagnosticReportPresenting {
    static let shared = PlaceholderIssueTrackerPresenter()

    /// Overridable so tests can see the URL without opening a browser.
    var open: (URL) -> Void = { NSWorkspace.shared.open($0) }

    func presentReport(_ request: DiagnosticReportRequest) {
        guard let url = Self.issueURL(for: request) else { return }
        open(url)
    }

    /// The pre-filled issue form. Fields match `.github/ISSUE_TEMPLATE/bug_report.yml`
    /// (`what-happened`, `area`), whose ids are a contract with that file.
    static func issueURL(for request: DiagnosticReportRequest) -> URL? {
        var query = "template=bug_report.yml"
        query += "&what-happened=\(encode(body(for: request)))"
        query += "&area=\(encode(area(for: request)))"
        return URL(string: "\(Acknowledgements.sourceURL)/issues/new?\(query)")
    }

    /// A prompt, not a blank box: it says what we already know and asks the one
    /// question only the user can answer.
    static func body(for request: DiagnosticReportRequest) -> String {
        var lines: [String] = []
        switch request.reason {
        case .untestedKind:
            let name = request.kind?.displayName ?? "this VPN type"
            let state = (request.kind?.maturity ?? .untested).badgeText.lowercased()
            lines.append("Reporting a result for \(name), which SimpleVPN currently marks as "
                         + "\(state).")
            lines.append("")
            lines.append("Did it connect? If it did, please say so \u{2014} that is what gets the "
                         + "\u{201C}\(name) has never been tested\u{201D} notice removed. If it "
                         + "didn\u{2019}t, what did SimpleVPN say, and what were you doing?")
        case .untestedSource:
            lines.append("Reporting a result for a sign-in source SimpleVPN marks as untested.")
            lines.append("")
            lines.append("Which password app, and did SimpleVPN manage to read your sign-in from "
                         + "it? If not, what did it say?")
        case .connectFailure:
            let name = request.kind?.displayName ?? "a VPN"
            lines.append("A connect to \(name) failed.")
            lines.append("")
            lines.append("What did SimpleVPN say, and what were you doing at the time?")
        case .userInitiated:
            lines.append("What were you doing, and what happened instead of what you expected?")
        }
        lines.append("")
        lines.append("(Please don\u{2019}t paste credentials, verification codes or private "
                     + "hostnames. SimpleVPN \u{25B8} About \u{25B8} \u{201C}Collect "
                     + "Diagnostics\u{2026}\u{201D} produces a scrubbed bundle you can attach.)")
        return lines.joined(separator: "\n")
    }

    /// The template's `area` dropdown — its options are fixed in bug_report.yml.
    private static func area(for request: DiagnosticReportRequest) -> String {
        switch request.reason {
        case .untestedKind, .untestedSource, .connectFailure: "Connecting / authentication"
        case .userInitiated: "Not sure"
        }
    }

    /// Strict allow-list percent-encoding, so newlines and punctuation in the body
    /// cannot be misread by the query parser. (`IssueReport` has the same six
    /// lines; this copy exists only so the placeholder can be deleted in one
    /// piece, without touching About.)
    private static func encode(_ s: String) -> String {
        var allowed = CharacterSet.alphanumerics
        allowed.insert(charactersIn: "-._~")
        return s.addingPercentEncoding(withAllowedCharacters: allowed) ?? ""
    }
}
