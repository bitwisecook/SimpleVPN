// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
//  DiagnosticReportTests.swift
//  The allow-list, asserted. Three things are being defended here:
//
//   • The LOG path admits event TYPES, not text. A message that matches no type
//     is counted, never quoted; a secret appended to a message that DOES match is
//     not carried along, because the emitted line is rebuilt from the event's own
//     template plus its typed captures.
//   • The RENDERER shares only what is switched on, and says what it left out.
//   • The SUBMISSION path never silently truncates. When the prefill will not fit,
//     it says so and hands over the whole thing.
//

import Testing
import Foundation
import AppKit
@testable import SimpleVPN

// MARK: - The log allow-list

struct DiagnosticReportLogAllowListTests {

    private let scrubber = SecretScrubber(policy: .report, homeDirectory: "/Users/testuser",
                                          salt: "fixed-test-salt")

    private func record(_ message: String, category: String = "vpn",
                        type: String = "Default") -> DiagnosticReportLog.Record {
        .init(timeOfDay: "12:04:31", category: category, messageType: type, message: message)
    }

    @Test func aKnownEventIsRebuiltFromOurOwnWording() {
        let field = DiagnosticReportLog.admit(
            record("status[ABC-123] → connected"), scrubber: scrubber)
        let rendered = field?.value.rendered(with: scrubber)
        #expect(rendered?.hasPrefix("connection status of") == true)
        #expect(rendered?.hasSuffix("connected") == true)
        // The raw profile identifier is NOT in the output — it becomes a token
        // that is stable inside one report and meaningless outside it.
        #expect(rendered?.contains("ABC-123") == false)
    }

    @Test func theSameProfileGetsTheSameTokenTwice() {
        let a = DiagnosticReportLog.admit(record("paused ABC-123"), scrubber: scrubber)
        let b = DiagnosticReportLog.admit(record("resumed ABC-123"), scrubber: scrubber)
        let tokenA = a?.value.rendered(with: scrubber).components(separatedBy: " ").first
        let tokenB = b?.value.rendered(with: scrubber).components(separatedBy: " ").first
        #expect(tokenA != nil)
        #expect(tokenA == tokenB)
    }

    @Test func aMessageOfNoRecognisedTypeIsRefused() {
        #expect(DiagnosticReportLog.admit(
            record("something nobody enumerated, password=hunter2trombone"),
            scrubber: scrubber) == nil)
    }

    /// THE test this design exists for. `status[…] → …` IS a known event, so the
    /// pattern matches; the emitted sentence must still be OUR template, with a
    /// secret appended to the message nowhere in sight.
    @Test func aSecretAppendedToAKnownMessageCannotRideAlong() {
        let field = DiagnosticReportLog.admit(
            record("status[ABC-123] → connected password=hunter2trombone"),
            scrubber: scrubber)
        // Either the pattern refuses it (anchored at both ends), or the rebuild
        // drops it. Both are correct; what is NOT acceptable is the secret
        // appearing in the report.
        let rendered = field?.value.rendered(with: scrubber) ?? ""
        #expect(!rendered.contains("hunter2trombone"))
    }

    @Test func aCategoryOutsideTheAllowListIsRefused() {
        #expect(DiagnosticReportLog.admit(
            record("status[ABC-123] → connected", category: "keychain"),
            scrubber: scrubber) == nil)
    }

    @Test func anEventTypeOnlyMatchesItsOwnCategory() {
        // `startTunnel — PacketTunnel v…` is a `tunnel` event. The same text
        // arriving under `vpn` matches nothing.
        #expect(DiagnosticReportLog.admit(
            record("startTunnel — PacketTunnel v1.2.3", category: "tunnel"),
            scrubber: scrubber) != nil)
        #expect(DiagnosticReportLog.admit(
            record("startTunnel — PacketTunnel v1.2.3", category: "vpn"),
            scrubber: scrubber) == nil)
    }

    @Test func aMultiLineMessageIsRefusedRatherThanPartlyMatched() {
        #expect(DiagnosticReportLog.admit(
            record("status[ABC-123] → connected\nand then a private key: SECRETMATERIAL"),
            scrubber: scrubber) == nil)
    }

    @Test func aCaptivePortalIsReportedWithoutItsAddress() {
        let field = DiagnosticReportLog.admit(
            record("captive portal detected, sign-in at https://hotel.example.com/login?id=42"),
            scrubber: scrubber)
        let rendered = field?.value.rendered(with: scrubber) ?? ""
        #expect(rendered.contains("captive portal was detected"))
        #expect(!rendered.contains("hotel"))
        #expect(!rendered.contains("id=42"))
    }

    @Test func aFailureDetailIsAdmittedButBoundedAndScrubbed() {
        let long = String(repeating: "x", count: 900)
        let field = DiagnosticReportLog.admit(
            record("startTunnel failed for ABC-123: permission denied \(long) token=SECRETTOKENVALUE"),
            scrubber: scrubber)
        let rendered = field?.value.rendered(with: scrubber) ?? ""
        #expect(rendered.contains("FAILED"))
        #expect(!rendered.contains("SECRETTOKENVALUE"))
        #expect(rendered.count < 400, "an error detail must stay bounded, got \(rendered.count)")
    }

    @Test func countsAreRenderedAsNumbersNotText() {
        let field = DiagnosticReportLog.admit(record("loadAll: 4 profile(s)"), scrubber: scrubber)
        #expect(field?.value.rendered(with: scrubber) == "4 VPN profile(s) loaded")
    }

    @Test func aDivertPlanKeepsItsNumbers() {
        let field = DiagnosticReportLog.admit(
            record("divert plan: 3 destination(s) around this VPN, 1 routed into it (kind openvpn)",
                   category: "tunnel"),
            scrubber: scrubber)
        let rendered = field?.value.rendered(with: scrubber) ?? ""
        #expect(rendered.contains("3 destination(s)"))
        #expect(rendered.contains("kind openvpn"))
    }

    @Test func everyEventTypeOnlyNamesCategoriesTheAllowListHas() {
        for type in DiagnosticReportLog.eventTypes {
            for category in type.categories {
                #expect(DiagnosticReportLog.allowedCategories.contains(category),
                        "\(type.id) names category \(category), which the allow-list doesn't have")
            }
        }
    }

    @Test func everyEventTypeIsAnchoredAtBothEnds() {
        for type in DiagnosticReportLog.eventTypes {
            #expect(type.pattern.hasPrefix("^"), "\(type.id) isn't anchored at the start")
            #expect(type.pattern.hasSuffix("$"), "\(type.id) isn't anchored at the end")
        }
    }

    @Test func everyEventTypeHasATemplateSlotForEveryKeptCapture() {
        for type in DiagnosticReportLog.eventTypes {
            for (index, capture) in type.captures.enumerated() where capture != .discarded {
                #expect(type.template.contains("{\(index)}"),
                        "\(type.id) captures \(capture) at \(index) with nowhere to put it")
            }
        }
    }
}

// MARK: - Parsing what `log show` prints

struct DiagnosticReportLogParsingTests {

    private let scrubber = SecretScrubber(policy: .report, salt: "fixed-test-salt")

    private func ndjson(_ objects: [[String: Any]]) -> String {
        objects.compactMap {
            guard let data = try? JSONSerialization.data(withJSONObject: $0) else { return nil }
            return String(data: data, encoding: .utf8)
        }.joined(separator: "\n")
    }

    @Test func ourOwnRecognisedEventsAreAdmittedAndTheRestAreCounted() {
        let text = ndjson([
            ["subsystem": "com.bragi0.SimpleVPN", "category": "vpn",
             "messageType": "Default", "timestamp": "2026-08-05 12:04:31.123456+0100",
             "eventMessage": "status[ABC-123] → connected"],
            ["subsystem": "com.bragi0.SimpleVPN", "category": "vpn",
             "messageType": "Error", "timestamp": "2026-08-05 12:04:32.000000+0100",
             "eventMessage": "an unenumerated line carrying password=hunter2trombone"],
            ["subsystem": "com.bragi0.SimpleVPN", "category": "keychain",
             "messageType": "Default", "timestamp": "2026-08-05 12:04:33.000000+0100",
             "eventMessage": "stored an item"],
            ["subsystem": "com.apple.something", "category": "vpn",
             "messageType": "Default", "timestamp": "2026-08-05 12:04:34.000000+0100",
             "eventMessage": "status[X] → connected"],
        ])
        let admitted = DiagnosticReportLog.admitAll(ndjson: text, limit: 100, scrubber: scrubber)
        #expect(admitted.fields.count == 1)
        #expect(admitted.unrecognised == 1)
        #expect(admitted.outsideAllowedCategories == 1)
        #expect(admitted.failure == nil)
        let all = admitted.fields.map { $0.value.rendered(with: scrubber) }.joined()
        #expect(!all.contains("hunter2trombone"))
    }

    @Test func alogShowThatPrintsSomethingElseEntirelyFailsClosed() {
        let admitted = DiagnosticReportLog.admitAll(
            ndjson: "log: unrecognized option `--style ndjson'\n", limit: 100, scrubber: scrubber)
        #expect(admitted.fields.isEmpty)
        #expect(admitted.failure != nil)
    }

    @Test func anEmptyLogIsNotAFailure() {
        let admitted = DiagnosticReportLog.admitAll(ndjson: "", limit: 100, scrubber: scrubber)
        #expect(admitted.fields.isEmpty)
        #expect(admitted.failure == nil)
    }

    @Test func theNewestEventsAreKeptWhenThereAreTooMany() {
        let objects = (1...20).map { i -> [String: Any] in
            ["subsystem": "com.bragi0.SimpleVPN", "category": "vpn", "messageType": "Default",
             "timestamp": "2026-08-05 12:04:\(String(format: "%02d", i)).000000+0100",
             "eventMessage": "loadAll: \(i) profile(s)"]
        }
        let admitted = DiagnosticReportLog.admitAll(ndjson: ndjson(objects), limit: 5,
                                                    scrubber: scrubber)
        #expect(admitted.fields.count == 5)
        #expect(admitted.fields.first?.label.contains("12:04:16") == true)
    }

    @Test func onlyTheTimeOfDaySurvivesATimestamp() {
        #expect(DiagnosticReportLog.timeOfDay("2026-08-05 12:04:31.123456+0100") == "12:04:31")
        #expect(DiagnosticReportLog.timeOfDay("nonsense") == "unknown time")
    }
}

// MARK: - Rendering and the switches

struct DiagnosticReportRenderingTests {

    private func payload() -> DiagnosticReportPayload {
        DiagnosticReportPayload(
            request: .init(kind: .fortinet, profileID: "ABC", reason: .untestedKind),
            sections: [
                .init(id: .whatHappened, fields: [
                    .init(label: "What you were doing", value: .userText("Connecting from a hotel")),
                ]),
                .init(id: .passwordManagers, fields: [
                    .init(label: "1Password (app)", value: .version("8.10.60")),
                ]),
                .init(id: .logEvents, fields: [], emptyNote: "Nothing recognised."),
            ],
            scrubber: SecretScrubber(policy: .report, salt: "fixed-test-salt"))
    }

    @Test func thePasswordManagerInventoryStartsSwitchedOff() {
        let p = payload()
        let selection = DiagnosticReportPayload.defaultSelection(for: p.sections)
        #expect(!selection.contains(.passwordManagers))
        #expect(selection.contains(.whatHappened))
        #expect(selection.contains(.logEvents))
    }

    @Test func onlyIncludedSectionsAppearAndTheRestAreNamed() {
        let p = payload()
        let out = p.markdown(including: [.whatHappened])
        #expect(out.contains("Connecting from a hotel"))
        #expect(!out.contains("8.10.60"))
        #expect(out.contains("Left out on purpose"))
        #expect(out.contains(DiagnosticReportSectionID.passwordManagers.title))
    }

    @Test func anEmptySectionReadsAsAnAnswerRatherThanABug() {
        let out = payload().markdown(including: [.logEvents])
        #expect(out.contains("Nothing recognised."))
    }

    @Test func theRenderedReportExplainsItsOwnPlaceholders() {
        #expect(payload().markdown(including: [.whatHappened]).contains("cannot be matched up or reversed"))
    }

    /// Every section must carry a "why this helps" line: a switch with no reason
    /// is a switch people leave alone, and the one that matters most
    /// (the password-manager inventory) has to own what it reveals.
    @Test func everySectionExplainsWhyItHelps() {
        for id in DiagnosticReportSectionID.allCases {
            #expect(!id.title.isEmpty)
            #expect(id.whyItHelps.count > 40, "\(id) has no real explanation")
        }
        #expect(DiagnosticReportSectionID.passwordManagers.whyItHelps.contains("who you work for"))
    }

    @Test func everyReasonAsksAConcreteQuestionWithAnExample() {
        for reason in [DiagnosticReportRequest.Reason.untestedKind, .untestedSource,
                       .connectFailure, .userInitiated] {
            #expect(reason.prompt.contains("For example"), "\(reason) has no worked example")
            #expect(!reason.invitation.isEmpty)
            #expect(!reason.titlePrefix.isEmpty)
        }
    }
}

// MARK: - Submission and the size limit

@MainActor
struct DiagnosticReportSubmissionTests {

    private var answers: DiagnosticReportAnswers {
        .init(whatYouWereDoing: "Connecting to my company's FortiGate from a hotel network.",
              whatWentWrong: "It sat on Connecting for a minute and then said it timed out.")
    }

    private let request = DiagnosticReportRequest(kind: .fortinet, profileID: "ABC",
                                                  reason: .untestedKind)

    @Test func anOrdinaryReportGetsAPrefilledURLWithinBudget() {
        let plan = DiagnosticReportSubmission.prepare(
            request, answers: answers, fullReport: String(repeating: "report line\n", count: 2000))
        #expect(plan.url != nil)
        #expect(plan.needsFile == false)
        #expect((plan.url?.absoluteString.count ?? .max) <= DiagnosticReportSubmission.urlBudget)
        // The FULL report is carried regardless of what the URL can hold.
        #expect(plan.fullReport.count > DiagnosticReportSubmission.urlBudget)
    }

    @Test func theURLNamesTheTemplateTheTitleAndTheVPNType() {
        let query = DiagnosticReportSubmission.prepare(
            request, answers: answers, fullReport: "x").url?.query ?? ""
        #expect(query.contains(DiagnosticReportSubmission.templateFileName))
        #expect(query.contains("title="))
        #expect(query.contains("what-happened="))
        #expect(query.contains("report="))
    }

    /// The rule: never silently truncate. When the prefill will not fit, the plan
    /// abandons the URL entirely, SAYS so, and still carries the whole report.
    @Test func anOversizedDescriptionIsNeverCutDown() {
        let huge = String(repeating: "I pressed Connect and waited. ", count: 400)
        let plan = DiagnosticReportSubmission.prepare(
            request,
            answers: .init(whatYouWereDoing: huge, whatWentWrong: huge),
            fullReport: "the whole report")
        #expect(plan.url == nil)
        #expect(plan.needsFile)
        #expect(plan.explanation.contains("will not shorten it behind your back"))
        #expect(plan.fullReport == "the whole report")
    }

    @Test func theBudgetIsRespectedExactlyAtTheBoundary() {
        // A description sized to sit just under, then just over.
        func planFits(_ characters: Int) -> Bool {
            DiagnosticReportSubmission.prepare(
                request,
                answers: .init(whatYouWereDoing: String(repeating: "a", count: characters),
                               whatWentWrong: ""),
                fullReport: "x").url != nil
        }
        #expect(planFits(100))
        #expect(!planFits(DiagnosticReportSubmission.urlBudget + 1))
    }

    @Test func theFileNameNamesTheVPNTypeAndTheDay() {
        let name = DiagnosticReportSubmission.suggestedFileName(
            request, now: Date(timeIntervalSince1970: 1_770_000_000))
        #expect(name.contains("fortinet"))
        #expect(name.hasSuffix(".md"))
    }

    @Test func theTrackerAndTheUsersOwnIssuesBothResolve() {
        #expect(DiagnosticReportSubmission.trackerURL != nil)
        #expect(DiagnosticReportSubmission.existingIssuesURL != nil)
        #expect(DiagnosticReportSubmission.trackerURL?.absoluteString
            .hasPrefix("https://github.com/bitwisecook/SimpleVPN") == true)
    }

    /// The prefill is bound to field ids in the issue form. If the template file
    /// stops shipping those ids, the prefill fails silently — so the file itself
    /// is checked.
    @Test func theIssueFormShipsTheFieldIdsThePrefillUses() throws {
        // The template lives beside the sources, not in the bundle, so this test
        // walks up from this file's own path.
        let here = URL(fileURLWithPath: #filePath)
        let root = here.deletingLastPathComponent()   // Diagnostics
            .deletingLastPathComponent()              // SimpleVPNTests
            .deletingLastPathComponent()              // repo root
        let template = root.appendingPathComponent(
            ".github/ISSUE_TEMPLATE/\(DiagnosticReportSubmission.templateFileName)")
        let text = try String(contentsOf: template, encoding: .utf8)
        #expect(text.contains("id: what-happened"))
        #expect(text.contains("id: report"))
    }
}

// MARK: - Inventory wording

struct DiagnosticReportInventoryTests {

    /// Every one of the four states (and every blocked reason inside the third)
    /// needs its own sentence. Two states sharing a sentence is how
    /// "installed but not enabled" gets reported as "not installed".
    @Test func everyAvailabilityStateHasItsOwnSentence() {
        var seen = Set<String>()
        let states: [LocalVaultAvailability] = [
            .notInstalled, .unchecked, .ready,
            .blocked(.appNotRunning), .blocked(.needsUpdate), .blocked(.integrationOff),
            .blocked(.toolMissing), .blocked(.notSignedIn), .blocked(.toolOutsideAllowList),
        ]
        for state in states {
            let words = DiagnosticReportInventory.stateWords(state)
            #expect(!words.isEmpty)
            #expect(seen.insert(words).inserted, "two states share the sentence \"\(words)\"")
        }
    }

    /// The two states that read as "broken" but are not must SAY what they are.
    @Test func theTwoMisleadingStatesAreSpeltOut() {
        let outside = DiagnosticReportInventory.stateWords(.blocked(.toolOutsideAllowList))
        #expect(outside.contains("IS installed"))
        #expect(outside.contains("not somewhere SimpleVPN will run from"))
        let off = DiagnosticReportInventory.stateWords(.blocked(.integrationOff))
        #expect(off.contains("switch is off"))
    }

    @Test func everyToolUsabilityHasItsOwnSentence() {
        var seen = Set<String>()
        for usability: ToolUsability in [.runnable, .outsideAllowList, .unsafeDirectory, .notExecutable] {
            let words = DiagnosticReportInventory.usabilityWords(usability)
            #expect(seen.insert(words).inserted)
        }
    }

    /// A tool that discovery found in three places must report all three, with
    /// what would actually be run — that is the whole reason this section exists.
    @Test func aToolReportsEveryPlaceItWasFoundAndWhichOneWouldRun() {
        let found = DiscoveredTool(
            tool: "bw",
            paths: [
                .init(path: "/opt/homebrew/bin/bw", locationClass: .homebrewAppleSilicon,
                      usability: .runnable),
                .init(path: "/Users/testuser/.bun/bin/bw", locationClass: .bun,
                      usability: .outsideAllowList),
            ],
            chosen: "/opt/homebrew/bin/bw",
            version: .known("2024.9.0"))
        let fields = DiagnosticReportInventory.toolFields(discoveries: ["bw": found])
        let bw = fields.first { $0.label.contains("(bw)") }
        let scrubber = SecretScrubber(policy: .report, homeDirectory: "/Users/testuser",
                                      salt: "fixed-test-salt")
        let text = ([bw?.value] + (bw?.detail ?? []).map { Optional($0) })
            .compactMap { $0?.rendered(with: scrubber) }.joined(separator: " | ")
        #expect(text.contains("/opt/homebrew/bin/bw"))
        #expect(text.contains("~/.bun/bin/bw"))
        #expect(text.contains("2024.9.0"))
        #expect(text.contains("would run"))
    }

    @Test func aToolFoundNowhereRunnableIsNotReportedAsAbsent() {
        let found = DiscoveredTool(
            tool: "bw",
            paths: [.init(path: "/Users/testuser/.bun/bin/bw", locationClass: .bun,
                          usability: .outsideAllowList)],
            chosen: nil,
            version: .unknown(why: "SimpleVPN won\u{2019}t run a program from this location"))
        let fields = DiagnosticReportInventory.toolFields(discoveries: ["bw": found])
        let scrubber = SecretScrubber(policy: .report, homeDirectory: "/Users/testuser",
                                      salt: "fixed-test-salt")
        let headline = fields.first { $0.label.contains("(bw)") }?.value.rendered(with: scrubber) ?? ""
        #expect(headline.contains("found"))
        #expect(!headline.contains("not found"))
    }

    /// Discovery being switched off must not look like "nothing is installed".
    @Test func discoveryBeingOffIsSaidRatherThanImplied() {
        let fields = DiagnosticReportInventory.toolFields(discoveries: [:])
        let scrubber = SecretScrubber(policy: .report, salt: "fixed-test-salt")
        let text = fields.map { $0.value.rendered(with: scrubber) }.joined()
        #expect(text.contains("isn\u{2019}t looking"))
    }
}

// MARK: - The window actually opens

/// The one seam a pure unit test cannot reach through the model: the dialog is
/// hosted in its own `NSWindow` rather than as a sheet on somebody else's window,
/// so "does it open, is it titled, does closing it let go" is worth proving.
///
/// Skips rather than fails where there is no window server — a gate that flakes
/// in a headless run is worse than no gate.
@MainActor
struct DiagnosticReportCoordinatorTests {

    @Test func presentingOpensOneTitledWindowAndClosingLetsGoOfIt() throws {
        let app = try #require(NSApp, "no window server in this run")
        let coordinator = DiagnosticReportCoordinator()
        #expect(!coordinator.isPresented)

        coordinator.presentReport(.init(kind: .fortinet, profileID: nil, reason: .untestedKind))
        #expect(coordinator.isPresented)
        let titles = app.windows.compactMap { $0.isVisible ? $0.title : nil }
        #expect(titles.contains("Report a Problem"))

        // Asking twice must re-aim the one window, never stack a second.
        coordinator.presentReport(.init(kind: .ssh, profileID: nil, reason: .userInitiated))
        #expect(app.windows.filter { $0.title == "Report a Problem" }.count == 1)

        coordinator.close()
        #expect(!coordinator.isPresented)
    }
}

// MARK: - The dialog's own state machine

/// Edit tracking is subtle enough to be worth pinning: a `TextEditor`'s
/// `onChange` cannot tell a keystroke from our own re-render, and getting it
/// wrong means the dialog asks permission to rebuild text nobody has touched —
/// or, worse, silently throws away text somebody wrote.
@MainActor
struct DiagnosticReportModelTests {

    private func model() -> DiagnosticReportModel {
        let payload = DiagnosticReportPayload(
            request: .init(kind: .fortinet, profileID: "ABC", reason: .untestedKind),
            sections: [
                .init(id: .whatHappened, fields: [
                    .init(label: "What you were doing", value: .absent(reason: "left blank")),
                ]),
                .init(id: .appAndSystem, fields: [.init(label: "macOS", value: .version("26.0"))]),
                .init(id: .passwordManagers, fields: [
                    .init(label: "1Password (app)", value: .version("8.10.60")),
                ]),
            ],
            scrubber: SecretScrubber(policy: .report, salt: "fixed-test-salt"))
        return DiagnosticReportModel(
            request: payload.request, context: DiagnosticReportContext(), payload: payload)
    }

    @Test func theDialogOpensWithTheReportAlreadyRenderedAndUnedited() {
        let m = model()
        #expect(!m.previewText.isEmpty)
        #expect(!m.previewEdited)
        // Off by default, so it is not in the text the dialog opens with.
        #expect(!m.previewText.contains("8.10.60"))
    }

    @Test func aProgrammaticRenderIsNotMistakenForAUserEdit() {
        let m = model()
        m.renderPreview()
        m.markPreviewEdited()          // what the view's onChange does
        #expect(!m.previewEdited)
    }

    @Test func aRealEditIsRemembered() {
        let m = model()
        m.previewText += "\nI removed the bit about my employer."
        m.markPreviewEdited()
        #expect(m.previewEdited)
    }

    @Test func switchingASectionOnPutsItInTheText() {
        let m = model()
        m.setIncluded(true, .passwordManagers)
        #expect(m.previewText.contains("8.10.60"))
        #expect(!m.previewEdited)
    }

    @Test func whatIsSharedIsExactlyWhatIsOnScreen() {
        let m = model()
        m.previewText = "only this"
        #expect(m.plan.fullReport == "only this")
    }

    @Test func anAnswerLongerThanTheBoxHoldsIsStoppedVisibly() {
        let m = model()
        m.answers.whatYouWereDoing = String(
            repeating: "a", count: DiagnosticReportAnswers.maximumAnswerLength + 500)
        m.answersChanged()
        #expect(m.answers.whatYouWereDoing.count == DiagnosticReportAnswers.maximumAnswerLength)
        #expect(m.answerLimitHit)
    }
}
