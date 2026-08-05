// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
//  DiagnosticReport.swift
//  The model for the report the "Untested" banner (and Help ▸ Report a Problem…)
//  offers to assemble. This file is the DATA; assembly is
//  `DiagnosticReportAssembler`, the dialog is `DiagnosticReportView`, submission
//  is `DiagnosticReportSubmission`.
//
//  THE ARCHITECTURE, and the reason this file exists at all:
//
//  A report that carries someone's password-manager inventory and their logs is
//  one leak away from being a credential disclosure. So it is an ALLOW-LIST, not
//  a scrubbed dump. Concretely:
//
//   1. A report is a list of `Section`s of `Field`s, and a field's value is a
//      `ReportValue` — a CLOSED enum. There is no case that carries arbitrary
//      application state and no raw-passthrough case: `count`, `flag`, `seconds`
//      and `moment` cannot express a string at all, and EVERY string-bearing case
//      is run through `SecretScrubber` when it is rendered. Adding a leak means
//      adding an enum case, which is a visible, reviewable act — not a forgotten
//      string interpolation.
//   2. The only free-form text in a report is (a) the two things the user typed
//      into the dialog, which they can see and edit, and (b) the captured
//      fragments of allow-listed log EVENT TYPES (`DiagnosticReportLog`) — never
//      whole log lines.
//   3. Nothing leaves the machine without the user reading it. The dialog shows
//      the finished payload verbatim, editable, with a per-section switch. There
//      is no auto-upload and no background telemetry anywhere in this feature.
//

import Foundation

// MARK: - The seam with the "Untested" banner

/// Why a report is being offered. Declared here rather than in the banner so the
/// banner and the dialog agree on the vocabulary without either importing the
/// other's internals.
///
/// NOTE FOR THE MERGE: this declaration is byte-identical to the placeholder the
/// banner wave ships, which is what makes reconciling the two branches a delete
/// rather than a rewrite.
nonisolated struct DiagnosticReportRequest: Sendable, Equatable {
    var kind: VPNKind?
    var profileID: String?
    var reason: Reason
    enum Reason: String, Sendable, Equatable { case untestedKind, untestedSource, connectFailure, userInitiated }
}

@MainActor protocol DiagnosticReportPresenting: AnyObject {
    func presentReport(_ request: DiagnosticReportRequest)
}

nonisolated extension DiagnosticReportRequest.Reason {
    /// The one sentence at the top of the dialog. Honest about WHY we are asking:
    /// an untested kind clears by somebody telling us it worked, and that is the
    /// only way it ever clears.
    var invitation: String {
        switch self {
        case .untestedKind:
            "This VPN type hasn\u{2019}t been tested against a real server yet. Telling us how it went "
            + "for you is what changes that \u{2014} whether it worked or not."
        case .untestedSource:
            "This way of signing in hasn\u{2019}t been tested against a real vault yet. Telling us how it "
            + "went for you is what changes that \u{2014} whether it worked or not."
        case .connectFailure:
            "Something went wrong connecting. This gathers what SimpleVPN already knows about your "
            + "setup so you don\u{2019}t have to describe it."
        case .userInitiated:
            "This gathers what SimpleVPN already knows about your setup so you don\u{2019}t have to "
            + "describe it."
        }
    }

    /// The concrete question in the "what were you doing" box. A blank box gets a
    /// blank answer; a question gets an answer.
    var prompt: String {
        switch self {
        case .untestedKind:
            "What were you trying to do? For example: \u{201C}Connecting to my company\u{2019}s FortiGate "
            + "with a username, password and a code from my phone.\u{201D}"
        case .untestedSource:
            "What were you trying to do? For example: \u{201C}Picking Bitwarden so SimpleVPN would fetch "
            + "my VPN password instead of me typing it.\u{201D}"
        case .connectFailure:
            "What were you doing when it went wrong? For example: \u{201C}I clicked Connect on my work "
            + "VPN from a hotel network.\u{201D}"
        case .userInitiated:
            "What were you doing? For example: \u{201C}I opened Routes to see why my printer stopped "
            + "working while connected.\u{201D}"
        }
    }

    /// What GitHub's issue title should start with.
    var titlePrefix: String {
        switch self {
        case .untestedKind: "Untested VPN type"
        case .untestedSource: "Untested sign-in source"
        case .connectFailure: "Connection failed"
        case .userInitiated: "Report"
        }
    }
}

// MARK: - What a value is allowed to be

/// The CLOSED vocabulary of report values. This enum is the allow-list.
///
/// The numeric and boolean cases cannot carry a string, so no amount of careless
/// interpolation at a call site can smuggle one through them. The four
/// string-bearing cases each name what they are FOR, and every one of them is
/// scrubbed on the way out (`rendered(with:)`) — so the worst a mistake can do is
/// put a scrubbed string in the wrong section, not put a password in the report.
///
/// `SecretScrubberTests.everyStringBearingCaseIsScrubbed` seeds a secret into each
/// of them and asserts none survives, and it switches exhaustively over the enum
/// so a NEW case cannot be added without the test failing to compile.
nonisolated enum ReportValue: Sendable, Equatable {
    /// Prose from a fixed, compile-time vocabulary (a state sentence, a reason).
    case words(String)
    /// The name of a state — an enum's own `rawValue` or display name.
    case state(String)
    /// A filesystem path. Scrubbed with the path policy: the home directory
    /// becomes `~`, but the path stays readable, because "found at
    /// ~/.bun/bin/bw" is the single most useful line in the tool inventory.
    case path(String)
    /// A version string as another program printed it. Bounded by
    /// `ToolDiscovery.probeVersion` before it ever gets here.
    case version(String)
    /// Something the user typed into this dialog. They can see it and edit it.
    case userText(String)
    case count(Int)
    case flag(Bool)
    case seconds(Double)
    case moment(Date)
    /// A fact we could not establish, WITH the reason. Never a blank and never a
    /// guess — "version unknown" with no reason sends a maintainer hunting.
    case absent(reason: String)

    /// The rendered value. Every string-bearing case goes through the scrubber.
    func rendered(with scrubber: SecretScrubber) -> String {
        switch self {
        case .words(let s), .state(let s), .userText(let s):
            var report = scrubber
            report.policy = .report
            return report.scrub(s)
        case .path(let s):
            var path = scrubber
            path.policy = .path
            return path.scrub(s)
        case .version(let s):
            var path = scrubber
            path.policy = .path
            return path.scrub(String(s.prefix(120)))
        case .count(let n):
            return n.formatted()
        case .flag(let on):
            return on ? "yes" : "no"
        case .seconds(let t):
            return String(format: "%.1fs", t)
        case .moment(let d):
            // Second precision, local time. A millisecond in a bug report is
            // noise, and an ISO timestamp with a timezone is the one thing that
            // makes two people's logs line up.
            return d.formatted(.iso8601.timeSeparator(.colon).timeZoneSeparator(.colon))
        case .absent(let reason):
            // Scrubbed too, even though every reason in this app is a literal.
            // The claim this enum makes is "no string-bearing case skips the
            // scrubber", and a claim with one exception is not a claim.
            var report = scrubber
            report.policy = .report
            return "not recorded \u{2014} " + report.scrub(reason)
        }
    }
}

// MARK: - Sections

/// A section of the report, and the unit the user switches on and off.
///
/// Each case carries its own "why this helps" line because a switch with no
/// explanation is a switch people leave alone. The password-manager inventory
/// gets the most careful wording of the lot: it reveals which vaults someone
/// uses and can imply who they work for.
nonisolated enum DiagnosticReportSectionID: String, Sendable, CaseIterable, Identifiable, Equatable {
    case whatHappened
    case appAndSystem
    case passwordManagers
    case toolsAndAPIs
    case activeAndReachable
    case virtualMachines
    case switchedOff
    case logEvents

    var id: String { rawValue }

    var title: String {
        switch self {
        case .whatHappened: "What you were doing, and what went wrong"
        case .appAndSystem: "SimpleVPN and this Mac"
        case .passwordManagers: "Password managers on this Mac"
        case .toolsAndAPIs: "Command-line tools and local APIs"
        case .activeAndReachable: "What was active and reachable"
        case .virtualMachines: "Virtual machines and containers"
        case .switchedOff: "Switched off, or decided for you"
        case .logEvents: "Recent log events"
        }
    }

    /// One line, in the dialog, next to the switch. Says what a maintainer does
    /// with it — which is the only honest argument for including it.
    var whyItHelps: String {
        switch self {
        case .whatHappened:
            "Your own words. Everything else here is context for these two answers."
        case .appAndSystem:
            "Versions and the VPN type, so a fix can be aimed at the right build."
        case .passwordManagers:
            "Which password apps and command-line tools are installed, and their versions \u{2014} the "
            + "most common cause of a sign-in source not working is a version that predates the "
            + "thing SimpleVPN talks to. This one also says something about you: it reveals which "
            + "vaults you use, and possibly who you work for. Leave it off if you\u{2019}d rather not."
        case .toolsAndAPIs:
            "Where each tool was found, whether SimpleVPN will run it from there, and what is "
            + "switched on \u{2014} so nobody debugs a tool that was never reachable."
        case .activeAndReachable:
            "What SimpleVPN had already measured about this connection. Nothing is re-tested to "
            + "build this, so it can\u{2019}t change what you saw."
        case .virtualMachines:
            "Which virtual machines and containers this Mac runs, and which of their networks were "
            + "live \u{2014} plus, for each, whether keeping a subnet out of the tunnel could help it "
            + "at all. \u{201C}My container lost the network\u{201D} has two completely different "
            + "causes and this is what tells them apart."
        case .switchedOff:
            "Settings you (or your organisation) have turned off. Without this, a maintainer spends "
            + "a day chasing a bug that is really a switch."
        case .logEvents:
            "Recent events of a few known kinds \u{2014} connection state changes, failures, versions. "
            + "Whole log lines are never included; only these event types are."
        }
    }

    /// Sections that carry personal detail start OFF. Everything else starts ON,
    /// because a report of nothing helps nobody.
    ///
    /// The password-manager inventory is the one that starts off: it is the only
    /// section whose content is about the PERSON rather than the software.
    var startsOn: Bool { self != .passwordManagers }
}

nonisolated struct DiagnosticReportField: Sendable, Equatable, Identifiable {
    var label: String
    var value: ReportValue
    /// Sub-lines, for a fact that is a list (every path a tool was found at).
    var detail: [ReportValue] = []

    var id: String { label }
}

nonisolated struct DiagnosticReportSection: Sendable, Equatable, Identifiable {
    var id: DiagnosticReportSectionID
    var fields: [DiagnosticReportField] = []
    /// Shown when the section has nothing in it, so an empty section reads as an
    /// answer rather than a bug.
    var emptyNote: String?

    var title: String { id.title }
    var isEmpty: Bool { fields.isEmpty }
}

// MARK: - The whole payload

nonisolated struct DiagnosticReportPayload: Sendable, Equatable {
    var request: DiagnosticReportRequest
    var sections: [DiagnosticReportSection]
    /// The per-report salt, so a reviewer can be told that placeholders are
    /// meaningless outside this one report.
    var scrubber: SecretScrubber

    static func == (lhs: Self, rhs: Self) -> Bool {
        lhs.request == rhs.request && lhs.sections == rhs.sections
            && lhs.scrubber.salt == rhs.scrubber.salt
    }

    func section(_ id: DiagnosticReportSectionID) -> DiagnosticReportSection? {
        sections.first { $0.id == id }
    }

    /// Render the payload as the markdown that goes on the clipboard, into the
    /// file, and into the preview the user reads. ONE renderer, so what is shown
    /// and what is shared cannot drift.
    func markdown(including included: Set<DiagnosticReportSectionID>) -> String {
        var out = "## SimpleVPN report\n\n"
        for section in sections where included.contains(section.id) {
            out += "### \(section.title)\n\n"
            if section.isEmpty {
                out += (section.emptyNote ?? "Nothing to report.") + "\n\n"
                continue
            }
            for field in section.fields {
                out += "- **\(field.label):** \(field.value.rendered(with: scrubber))\n"
                for line in field.detail {
                    out += "    - \(line.rendered(with: scrubber))\n"
                }
            }
            out += "\n"
        }
        let omitted = DiagnosticReportSectionID.allCases.filter { id in
            !included.contains(id) && section(id) != nil
        }
        if !omitted.isEmpty {
            out += "### Left out on purpose\n\n"
            for id in omitted { out += "- \(id.title)\n" }
            out += "\n"
        }
        out += Self.footer
        return out
    }

    /// The note that tells a maintainer what the `<kind:hex>` placeholders are,
    /// so nobody asks the reporter to "just send the real address".
    static let footer = """
        ---
        Assembled by SimpleVPN from structured facts, not from raw log text. Values shown as
        `<something:abc123>` were replaced with a placeholder: the same value gets the same
        placeholder inside this one report and a different one in every other report, so they
        cannot be matched up or reversed.
        """

    /// Every section, whether or not it is switched on. The dialog needs this to
    /// draw the switches.
    var availableSections: [DiagnosticReportSection] { sections }

    /// The switches a fresh dialog starts with.
    static func defaultSelection(for sections: [DiagnosticReportSection]) -> Set<DiagnosticReportSectionID> {
        Set(sections.map(\.id).filter { $0.startsOn })
    }
}

// MARK: - The two answers

/// What the user typed. Kept separate from the payload so the dialog can edit it
/// while the gathered facts stay immutable.
nonisolated struct DiagnosticReportAnswers: Sendable, Equatable {
    /// Hard cap, enforced at the field rather than at render time: the spec is
    /// "never silently truncate", and a field that stops accepting characters is
    /// visible, whereas an ellipsis appearing later is not.
    static let maximumAnswerLength = 4000

    var whatYouWereDoing = ""
    var whatWentWrong = ""

    var isEmpty: Bool {
        whatYouWereDoing.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
            && whatWentWrong.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
    }
}
