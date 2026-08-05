// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
//  VoiceOverWalkthroughTests.swift
//  The mechanical half of the release-QA VoiceOver walkthrough
//  (Docs/Accessibility.md, "Human VoiceOver walkthrough"), one test per step, in
//  the doc's order.
//
//  WHY THIS EXISTS. Each of those fifteen steps mixes two things: a JUDGEMENT
//  ("does this flow feel right, was the announcement timely, is the audio graph
//  legible") and a set of FACTS ("this element exists, it is reachable, and what
//  VoiceOver would read is what the doc promises"). The judgement needs a person.
//  The facts do not — and left to a person they are exactly what gets skipped on
//  the fifteenth release. They are asserted here instead, so the human checklist
//  shrinks to the part only a human can do.
//
//  VOICEOVER IS NEVER TURNED ON BY THESE TESTS. Enabling it would make the
//  machine start speaking, which is not a test's business. What VoiceOver reads is
//  the accessibility tree, and XCTest can read the same tree: `label` is the name
//  it speaks, `value` the state, and a combined row's `value` is the one sentence
//  it reads instead of five fragments. Asserting those IS asserting the speech,
//  minus the loudspeaker.
//
//  WHAT IS DELIBERATELY NOT ASSERTED (each step's comment says so at the point it
//  applies, and Docs/Accessibility.md's checklist repeats it):
//   • SPEECH ITSELF and announcement TIMING. `AccessibilityNotification
//     .Announcement` posts leave no trace in the accessibility tree, so no UI test
//     can hear "Tig Lab connected" or judge the 3 s debounce.
//   • AUDIO GRAPHS. `AXChartDescriptor` is not exposed to XCUITest; that a chart's
//     tones rise and fall with the data is heard, not read.
//   • THE ROTOR. VO-U is a VoiceOver affordance, not an AX attribute — the tests
//     assert the STRUCTURE a rotor is built from (named children with values),
//     which is the thing that breaks.
//   • ANYTHING THAT NEEDS A LIVE CONNECTION (a real connect, the throughput chart,
//     the traffic log) or that would MUTATE the tester's own VPN configuration.
//     These tests are read-only about the user's profiles on purpose: a gate that
//     edits your VPNs to check a label is worse than no gate.
//
//  Environment: same rules as SimpleVPNUITests — a locked console or a session
//  that cannot present UI SKIPS with a reason rather than flaking. A machine with
//  no VPNs configured skips the per-profile steps, saying so.
//

import XCTest
import CoreGraphics   // CGSessionCopyCurrentDictionary — the locked-console pre-check

final class VoiceOverWalkthroughTests: XCTestCase {

    override func setUpWithError() throws {
        continueAfterFailure = false
    }

    // MARK: - The status vocabulary (Docs/Accessibility.md rule 3)

    /// What the main window's rows and Connect controls say a connection is doing:
    /// `VPNController.statusText` plus the two "waiting on you" phrasings
    /// `VPNSidebarRow.statusText` substitutes, plus the paused wording.
    static let connectionStatusPhrases = [
        "not configured", "disconnected", "connecting", "connected",
        "reconnecting", "disconnecting", "unknown",
        "paused", "verification code needed", "sign-in needed",
    ]

    /// What `DotState.accessibilityDescription` says — the vocabulary Manage VPNs'
    /// rows and every pill use. A surface that invents a synonym is a regression:
    /// "the status vocabulary is `DotState` … never invent a parallel status
    /// language."
    static let dotStatePhrases = [
        "disconnected", "working", "connected", "paused",
        "connection problem", "sign-in page in the way",
    ]

    static var allStatusPhrases: [String] { connectionStatusPhrases + dotStatePhrases }

    // MARK: - Step 1 — Launch, arrow through the VPN list

    /// Doc step 1: "Each row must read as one sentence: name, kind, state
    /// ('disconnected'), labels. No 'image', no unlabeled buttons."
    ///
    /// Asserted here: each VPN row is ONE static text (not five fragments), that
    /// sentence names the VPN, its kind and its state in words, and the row
    /// carries no image element at all — the status dot and the logo are
    /// `accessibilityHidden`, so the dot's information can only reach a listener
    /// through the words, which is rule 3's whole point.
    ///
    /// Still human: that arrowing through the list with VO-⇧-↓ feels like reading
    /// a list, and that the sentence is pleasant to hear rather than merely
    /// complete.
    @MainActor
    func testStep01SidebarVPNRowsReadAsOneSentence() throws {
        let app = try launchOrSkip()
        let rows = try vpnRows(in: app, sidebarOf: app.windows.firstMatch)

        for (name, row) in rows {
            let nodes = flatten(row)
            let texts = nodes.filter { $0.elementType == .staticText }
            XCTAssertEqual(texts.count, 1, """
                The row for \u{201C}\(name)\u{201D} reads as \(texts.count) fragments, not one \
                sentence — .accessibilityElement(children: .combine) is missing or was \
                broken up: \(texts.map(describe).joined(separator: " | "))
                """)
            let sentence = (texts.first?.value as? String) ?? ""
            XCTAssertTrue(sentence.contains(name),
                          "The row sentence \u{201C}\(sentence)\u{201D} never says which VPN it is")
            XCTAssertNotNil(Self.phrase(in: sentence, from: Self.allStatusPhrases), """
                The row sentence \u{201C}\(sentence)\u{201D} carries no status word, so the \
                status dot beside it is the only thing that says what this VPN is doing
                """)
            let parts = sentence.split(separator: ",").map { $0.trimmingCharacters(in: .whitespaces) }
            XCTAssertGreaterThanOrEqual(parts.count, 3, """
                The row sentence \u{201C}\(sentence)\u{201D} is missing name, kind or state — \
                the doc promises all three
                """)
            XCTAssertTrue(nodes.allSatisfy { $0.elementType != .image }, """
                The row for \u{201C}\(name)\u{201D} exposes an image \
                (\(nodes.filter { $0.elementType == .image }.map(describe).joined(separator: " | "))). \
                Dots and logos are accessibilityHidden; their state rides in the words.
                """)
        }
    }

    // MARK: - Steps 2 & 3 — The credential form

    /// Doc steps 2–3: focus lands in the first empty field, which VO names
    /// ("Username"); Tab moves Username → Password → verification code; Return
    /// submits.
    ///
    /// Asserted here: every credential field present is NAMED, with a name from
    /// the glossary — never by its example prompt (AGENTS.md: "wrap bare
    /// TextFields in LabeledContent so the example prompt never becomes the
    /// VoiceOver name"), and never a name that is just the placeholder repeated.
    ///
    /// Still human, and unavoidably so: that INITIAL FOCUS lands in the first
    /// empty field, that Return on an incomplete form moves focus to the field
    /// that needs typing and that its value then says "Required" — those are the
    /// results of a submit attempt, and the only submit available here would
    /// connect a real VPN with the tester's real credentials.
    ///
    /// Skips, saying so, when the selected VPN takes its credentials from a
    /// manager (1Password / Apple Passwords) or signs itself in — then there is no
    /// field to name and the human step has to use a manual-credential VPN.
    @MainActor
    func testStep02And03CredentialFieldsAreNamedFromTheGlossary() throws {
        let app = try launchOrSkip()
        let window = app.windows.firstMatch
        let fields = flatten(try snapshot(of: window, "the main window")).filter {
            $0.elementType == .textField || $0.elementType == .secureTextField
        }
        // The glossary's names for the three things a person types to sign in.
        let expected = ["username", "password", "verification code"]
        let credentials = fields.filter { f in
            expected.contains { f.label.lowercased().contains($0) }
                || (f.placeholderValue.map { p in expected.contains { p.lowercased().contains($0) } } ?? false)
        }
        try XCTSkipIf(credentials.isEmpty, """
            The VPN selected on this machine has no credential fields on screen — its \
            credentials come from a manager, or it signs itself in. Nothing to assert; \
            the human walkthrough must use a VPN with manual credentials.
            """)
        for field in credentials {
            XCTAssertFalse(field.label.isEmpty, """
                A credential field has no name, so VoiceOver falls back to its example \
                prompt: \(describe(field))
                """)
            if let prompt = field.placeholderValue, !prompt.isEmpty {
                XCTAssertNotEqual(field.label, prompt, """
                    A credential field is named by its example prompt \u{201C}\(prompt)\u{201D} — \
                    an example is not a name
                    """)
            }
            XCTAssertNotNil(expected.first { field.label.lowercased().contains($0) }, """
                \u{201C}\(field.label)\u{201D} is not one of the glossary's names \
                (\(expected.joined(separator: " / "))) — one term per concept, everywhere
                """)
        }
    }

    // MARK: - Step 2b — The first-run sign-in chooser

    /// Doc step 2, second half: a VPN that has never connected is asked HOW it
    /// signs in, and that chooser must be as legible to a listener as to a
    /// looker. Two classes of row live in it, and the whole design rests on
    /// telling them apart:
    ///   • the ones SimpleVPN can fetch from (type it / the keychain / Apple
    ///     Passwords / a password app we really talk to), and
    ///   • the ones we CANNOT read, listed as pointers to where a password
    ///     probably is.
    ///
    /// Asserted here: every row is named, every row carries a non-empty value
    /// (its state, in words — a row whose value is empty says what it is and then
    /// refuses to say whether it works), and every POINTER row says in its own
    /// words that SimpleVPN can't read that app. The last one is the load-bearing
    /// assertion: the two classes differ in styling, and styling is invisible to
    /// VoiceOver, so if the wording ever stops carrying the distinction a
    /// listener could pick a signpost expecting an integration.
    ///
    /// SKIPS when no VPN on this machine is at its first connect — the chooser is
    /// deliberately absent for a VPN that has already connected (that is the
    /// "never re-ask a returning user" half of the same feature), and these tests
    /// never edit the tester's own VPNs to make a surface appear.
    ///
    /// Still human: that Tab walks the rows, that the keyboard starts on the
    /// choice already made, and that choosing one is SPOKEN (announcements leave
    /// no trace in the tree).
    @MainActor
    func testStep02bSignInChooserRowsSayWhatTheyAreAndWhatTheyCanDo() throws {
        let app = try launchOrSkip()
        let nodes = flatten(try snapshot(of: app.windows.firstMatch, "the main window"))
        let sources = nodes.filter { $0.identifier.hasPrefix("signin-source-") }
        let pointers = nodes.filter { $0.identifier.hasPrefix("signin-hint-") }
        try XCTSkipIf(sources.isEmpty, """
            No sign-in chooser is on screen — every VPN on this machine has already \
            connected (so it is never re-asked), or the selected VPN signs itself in. \
            The human walkthrough needs a freshly imported VPN for this step.
            """)

        // The two rows that always exist, because a chooser that can be empty is
        // a dead end.
        let ids = Set(sources.map(\.identifier))
        XCTAssertTrue(ids.contains("signin-source-type-each-time"),
                      "The chooser offers no way to just type it: \(ids.sorted())")

        for row in sources + pointers {
            XCTAssertFalse(row.label.isEmpty, """
                A sign-in choice has no name: \(describe(row))
                """)
            let value = (row.value as? String) ?? ""
            XCTAssertFalse(value.isEmpty, """
                \(describe(row)) has no value, so focusing it never says whether that way \
                of signing in is ready, needs setting up, or can't be read at all
                """)
        }

        for pointer in pointers {
            let spoken = pointer.label + " " + ((pointer.value as? String) ?? "")
            XCTAssertTrue(spoken.contains("can\u{2019}t read") || spoken.contains("can't read"), """
                \(describe(pointer)) is a signpost to a password app SimpleVPN cannot read, \
                but nothing it SAYS carries that — the styling difference is invisible to \
                VoiceOver, so this row reads as an integration
                """)
        }
    }

    // MARK: - Step 4 — Hear the state

    /// Doc step 4: "VO-focus the Connect area — the Disconnect/stop control
    /// reports the live status in its value."
    ///
    /// Asserted here: every Connect control in the window — the per-row ones in the
    /// sidebar and the big one in the detail header — carries a non-empty
    /// `accessibilityValue`, and that value is drawn from the ONE connection
    /// vocabulary. A Connect button whose value is empty is a control that names
    /// itself and then refuses to say what it would do.
    ///
    /// Still human: that the value is spoken at the moment focus lands, and that
    /// the "Connecting…" pill reads as one element while it churns.
    @MainActor
    func testStep04ConnectControlsReportTheLiveStateInTheirValue() throws {
        let app = try launchOrSkip()
        let controls = flatten(try snapshot(of: app.windows.firstMatch, "the main window")).filter {
            $0.elementType == .button
                && ($0.label == "Connect" || $0.label.hasPrefix("Connect ") || $0.label.hasPrefix("Disconnect"))
        }
        try XCTSkipIf(controls.isEmpty, """
            No Connect control is on screen — this machine has no VPNs configured, or \
            the window is showing the extension-activation prompt.
            """)
        for control in controls {
            let value = (control.value as? String) ?? ""
            XCTAssertFalse(value.isEmpty, """
                \(describe(control)) has no value, so focusing it says what it is but never \
                what the connection is doing
                """)
            // BOTH sanctioned vocabularies, not just the NEVPNStatus one: the
            // "Other Connections" rows stop a subprocess or native tunnel, which has
            // no NEVPNStatus behind it at all, so their controls speak `DotState`
            // ("working", "connection problem") — which is rule 3's own vocabulary,
            // not a second language. Anything outside both lists still fails.
            XCTAssertNotNil(Self.phrase(in: value, from: Self.allStatusPhrases), """
                \(describe(control)) reports \u{201C}\(value)\u{201D}, which is in neither status \
                vocabulary (\(Self.allStatusPhrases.joined(separator: ", "))) — \
                a third status language is a regression
                """)
        }
    }

    // MARK: - Step 5 — Open Routes, search, zoom

    /// Doc step 5: "Open Routes (⇧⌘R or VPN ▸ Routes…). Focus lands in the search
    /// field — type an address you route … then Tab to the diagram and pan with
    /// arrows, zoom with `+`/`-`, `0` to fit."
    ///
    /// Asserted here: the ⇧⌘R shortcut really opens the window (not just the menu
    /// item); the search field is NAMED, and named for what it takes rather than by
    /// its prompt; and the documented ⌘=/⌘0 toolbar shortcuts really change the
    /// zoom, which is the keyboard half of "nothing on these surfaces is reachable
    /// only by pinch/drag/scroll".
    ///
    /// Still human: that INITIAL focus is in the search field and that the answer
    /// panel is spoken (XCUITest cannot make this field the first responder in a
    /// test session, so it cannot type into it either), and that arrow-key panning
    /// feels like panning.
    @MainActor
    func testStep05RoutesSearchIsNamedAndZoomIsKeyboardDriven() throws {
        let app = try launchOrSkip()
        app.typeKey("r", modifierFlags: [.command, .shift])
        let routes = app.windows["routes"]
        guard routes.waitForExistence(timeout: 10) else {
            XCTFail("⇧⌘R did not open the Routes window")
            return
        }

        let field = routes.textFields.firstMatch
        XCTAssertTrue(field.waitForExistence(timeout: 5), "The Routes search field is missing")
        XCTAssertFalse(field.label.isEmpty, "The Routes search field has no name")
        XCTAssertTrue(field.label.lowercased().contains("address"), """
            The Routes search field is named \u{201C}\(field.label)\u{201D}, which doesn't say \
            what it takes
            """)
        if let prompt = field.placeholderValue as String? {
            XCTAssertNotEqual(field.label, prompt,
                              "The Routes search field is named by its example prompt")
        }
        // NOT typed into here. XCUITest cannot make this field the first responder
        // in the test session (a click lands, focus does not: "Neither element nor
        // any descendant has keyboard focus" — measured), which is also why the
        // "focus lands in the search field" claim stays a human one. Typing an
        // address and hearing the answer is on the human list.

        // The zoom readout is the observable half of the pan/zoom keyboard contract.
        let readout = routes.staticTexts.matching(NSPredicate(format: "value ENDSWITH '%'")).firstMatch
        XCTAssertTrue(readout.waitForExistence(timeout: 5), "The Routes zoom readout is missing")
        let before = (readout.value as? String) ?? ""
        app.typeKey("=", modifierFlags: [.command])
        XCTAssertTrue(waitUntil(timeout: 5) { ((readout.value as? String) ?? "") != before }, """
            ⌘= did not change the zoom (\u{201C}\(before)\u{201D} throughout) — the documented \
            keyboard zoom is gone
            """)
        app.typeKey("0", modifierFlags: [.command])
        XCTAssertTrue(waitUntil(timeout: 5) { ((readout.value as? String) ?? "") == before }, """
            ⌘0 did not fit the diagram back to \u{201C}\(before)\u{201D}
            """)
    }

    // MARK: - Step 6 — The rotor

    /// Doc step 6: "VO-U, choose 'VPNs', jump to your VPN's card; then rotor
    /// 'Problems'."
    ///
    /// Asserted here: the STRUCTURE the rotors are built from, which is the part
    /// that breaks. The diagram is a named container ("Route diagram") rather than
    /// a labelled picture; it has children; and every interactive child inside it
    /// carries a name — with the interface/VPN cards additionally carrying a value
    /// (their address and rates), which is what a rotor entry reads out.
    ///
    /// Still human: the rotors themselves. VO-U is a VoiceOver affordance and no AX
    /// attribute reports it, so a person must still open the rotor, confirm "VPNs"
    /// and "Problems" are offered, and say out loud that a healthy connection lists
    /// no problems.
    @MainActor
    func testStep06RouteDiagramIsANavigableStructureNotAPicture() throws {
        let app = try launchOrSkip()
        app.typeKey("r", modifierFlags: [.command, .shift])
        let routes = app.windows["routes"]
        guard routes.waitForExistence(timeout: 10) else {
            XCTFail("⇧⌘R did not open the Routes window")
            return
        }
        let diagram = routes.descendants(matching: .any)
            .matching(NSPredicate(format: "label == 'Route diagram'")).firstMatch
        XCTAssertTrue(diagram.waitForExistence(timeout: 10), """
            No element named \u{201C}Route diagram\u{201D} — the drawn surface has become an \
            unnamed picture
            """)
        let nodes = flatten(try snapshot(of: diagram, "the route diagram"))
        XCTAssertGreaterThan(nodes.count, 1, "The route diagram exposes no children at all")

        let buttons = nodes.filter { $0.elementType == .button }
        for button in buttons {
            XCTAssertFalse(button.label.isEmpty, """
                An element inside the route diagram is a button with no name: \(describe(button))
                """)
        }
        XCTAssertTrue(buttons.contains { !$0.label.isEmpty && !(($0.value as? String) ?? "").isEmpty }, """
            No card in the route diagram carries BOTH a name and a value — a rotor entry \
            that reads only a name says nothing about the link it names. Cards found: \
            \(buttons.map(describe).joined(separator: " | "))
            """)
    }

    // MARK: - Step 7 — The throughput chart

    /// Doc step 7: "VO onto the chart and play the audio graph. Confirm the summary
    /// sentence gives current rates."
    ///
    /// Asserted here: only the reachable half — the live-details pane's toggle is
    /// NAMED and reports whether the pane is showing, so a listener can find the
    /// inspector the chart lives in. The toggle is not clicked: its state is the
    /// tester's window, not ours.
    ///
    /// Still human, and not automatable at all: the audio graph. `AXChartDescriptor`
    /// is invisible to XCUITest, the chart only exists while a VPN is CONNECTED, and
    /// connecting one would need real credentials and would reroute the machine's
    /// traffic mid-test. A person must connect, focus the chart, play the graph and
    /// confirm the summary sentence names the current rates.
    @MainActor
    func testStep07LiveDetailsToggleNamesItselfAndItsState() throws {
        let app = try launchOrSkip()
        let toggle = app.windows.firstMatch.buttons["Live details"]
        guard toggle.waitForExistence(timeout: 10) else {
            throw XCTSkip("""
                No live-details toggle in this window state (the extension-activation or \
                empty-VPNs prompt is showing).
                """)
        }
        let described = describe(try snapshot(of: toggle, "the live-details toggle"))
        let value = (toggle.value as? String) ?? ""
        XCTAssertFalse(value.isEmpty, """
            The live-details toggle never says whether the pane is showing — \(described)
            """)
    }

    // MARK: - Step 8 — Hear the announcement

    /// Doc step 8: "Pause or disconnect and hear the announcement ('<name>
    /// disconnected') without moving focus."
    ///
    /// Asserted here: the nearest observable proxy — that the VPN ▸ Disconnect
    /// command's enabled state agrees with whether the selected VPN is showing a
    /// stoppable connection at all (step 4 owns the vocabulary half). An announcement
    /// nobody can hear is bad; an announcement in words no other surface uses is
    /// worse, and that IS checkable.
    ///
    /// Still human: the announcement itself. `AccessibilityNotification
    /// .Announcement` leaves no trace in the tree, so its wording, its arrival
    /// without moving focus, and the 3 s debounce that stops reconnect churn from
    /// spamming can only be heard.
    @MainActor
    func testStep08StatusIsOneVocabularyAndTheDisconnectCommandAgreesWithIt() throws {
        let app = try launchOrSkip()
        let window = try snapshot(of: app.windows.firstMatch, "the main window")
        let nodes = flatten(window)

        let connectControls = nodes.filter {
            $0.elementType == .button && ($0.label == "Connect" || $0.label.hasPrefix("Connect "))
        }

        // Whether the SELECTED VPN is worth disconnecting, read the way the menu item
        // itself decides it (VPNCommands: `UI.isActive(vpn.selected.status)`).
        //
        // Deliberately NOT inferred from the Connect controls' values, which was the
        // earlier attempt and could not work: a VPN that is up shows no Connect
        // control AT ALL — the detail header becomes a stop button and the sidebar row
        // a per-row one — so "active" was unobservable there and this assertion
        // reduced to "Disconnect is always disabled", failing on any machine with a
        // connection actually running. The detail header's trailing control is the
        // selected VPN's own, and it is the only one named WITHOUT a VPN name after it
        // (the sidebar's say "Disconnect Tig Lab"), which is exactly the scope the
        // menu item has.
        let anythingActive = nodes.contains {
            $0.elementType == .button && ($0.label == "Disconnect" || $0.label == "Cancel connecting")
        }
        try XCTSkipIf(connectControls.isEmpty && !anythingActive,
                      "No VPNs configured on this machine.")

        // The VPN menu's Disconnect: enabled exactly when something is worth
        // disconnecting. A menu that lies about that is a menu a keyboard-only user
        // cannot trust.
        app.menuBarItems["VPN"].click()
        let disconnect = app.menuBarItems["VPN"].menuItems["Disconnect"]
        XCTAssertTrue(disconnect.waitForExistence(timeout: 5), "VPN ▸ Disconnect is missing")
        XCTAssertEqual(disconnect.isEnabled, anythingActive, """
            VPN ▸ Disconnect is \(disconnect.isEnabled ? "enabled" : "disabled") while the window \
            shows \(anythingActive ? "a stoppable" : "no stoppable") connection for the selected VPN
            """)
        app.typeKey(.escape, modifierFlags: [])
    }

    // MARK: - Steps 9 & 10 — Manage VPNs and its editors

    /// Doc steps 9–10: "⇧⌘M. Focus is in the sidebar list … confirm the row
    /// sentence includes its status. Tab into the editor; find a Save button and
    /// hear why it's disabled (or that it saves)." / "type an invalid control URL —
    /// the field's value must speak the problem, and Save must explain itself."
    ///
    /// Asserted here: ⇧⌘M opens the window; every row in its sidebar reads as one
    /// sentence including a `DotState` status word; every setting row's help button
    /// is named for its setting AND that setting's name is on screen as text (which
    /// is what makes "changed from default" audible); and the Save button, if
    /// disabled, carries the reason in its value.
    ///
    /// Still human: typing an INVALID value and hearing the field's own value speak
    /// the problem. Doing that automatically would mean editing one of the tester's
    /// real VPNs, which this gate will not do.
    @MainActor
    func testStep09And10ManageVPNsRowsAndEditorRowsSayWhatTheyAre() throws {
        let app = try launchOrSkip()
        app.typeKey("m", modifierFlags: [.command, .shift])
        let manage = app.windows["manage"]
        guard manage.waitForExistence(timeout: 10) else {
            XCTFail("⇧⌘M did not open the Manage VPNs window")
            return
        }
        _ = manage.outlines["Sidebar"].waitForExistence(timeout: 10)
        let nodes = flatten(try snapshot(of: manage, "the Manage VPNs window"))

        // Rows: one sentence, with a status word from DotState.
        let rowTexts = flatten(try snapshot(of: manage.outlines["Sidebar"], "the sidebar"))
            .filter { $0.elementType == .staticText }
            .compactMap { $0.value as? String }
            .filter { $0.contains(",") }
        try XCTSkipIf(rowTexts.isEmpty, "No VPNs configured on this machine.")
        for sentence in rowTexts {
            XCTAssertNotNil(Self.phrase(in: sentence, from: Self.dotStatePhrases), """
                The Manage VPNs row \u{201C}\(sentence)\u{201D} never says what that VPN is \
                doing — the doc promises "status words" in every store's rows
                """)
        }

        // Help buttons name their setting, and the setting names itself on screen.
        let helpButtons = nodes.filter { $0.elementType == .button && $0.label.hasPrefix("Help for ") }
        XCTAssertFalse(helpButtons.isEmpty, """
            The editor exposes no \u{201C}Help for …\u{201D} buttons — either no VPN is \
            selected or the per-setting manual links have gone
            """)
        let spoken = nodes.compactMap { ($0.value as? String) ?? ($0.label.isEmpty ? nil : $0.label) }
        for help in helpButtons {
            let subject = String(help.label.dropFirst("Help for ".count))
            XCTAssertFalse(subject.isEmpty, "A help button is named \u{201C}Help for \u{201D} and nothing else")
            XCTAssertTrue(spoken.contains { $0.contains(subject) }, """
                \u{201C}\(help.label)\u{201D} names a setting that appears nowhere on screen — \
                the row's own name and its help button have drifted apart
                """)
        }

        // Save: if it can't be used, it says why (Docs/Accessibility.md rule 5).
        let save = manage.buttons["Save"]
        XCTAssertTrue(save.waitForExistence(timeout: 5), "The editor has no Save button")
        if !save.isEnabled {
            XCTAssertFalse(((save.value as? String) ?? "").isEmpty, """
                Save is disabled and says nothing about why — the reason belongs in .help \
                AND .accessibilityValue
                """)
        }
    }

    // MARK: - Step 11 — Custom Routing

    /// Doc step 11: "add a rule that overlaps a pushed route; the row must read as
    /// a sentence ending '…overlaps a pushed route', and the overlap button must
    /// say what it overlaps."
    ///
    /// Asserted here: Custom Routing is its OWN named tab, reachable by keyboard,
    /// in the Manage VPNs editor (AGENTS.md: "Custom Routing stays its own tab
    /// everywhere it exists — enforced, not aspirational"), and every rule row
    /// already present reads as one sentence with its controls still reachable
    /// inside it (rule 4's `.contain` shape, the wave-3 bug class).
    ///
    /// Still human: ADDING a rule that overlaps a pushed route, and hearing the
    /// overlap explained. Adding one would write to the tester's own VPN.
    @MainActor
    func testStep11CustomRoutingIsItsOwnNamedTab() throws {
        let app = try launchOrSkip()
        app.typeKey("m", modifierFlags: [.command, .shift])
        let manage = app.windows["manage"]
        guard manage.waitForExistence(timeout: 10) else {
            XCTFail("⇧⌘M did not open the Manage VPNs window")
            return
        }
        let tab = manage.radioButtons["Custom Routing"]
        guard tab.waitForExistence(timeout: 10) else {
            throw XCTSkip("""
                No VPN is selected in Manage VPNs (this machine has none configured), so \
                there is no editor and no Custom Routing tab.
                """)
        }
        // The tab Custom Routing sits BESIDE. Two shapes, both correct: every tunnel
        // editor (Tailscale, WireGuard, Proxy, SSH, Subprocess, Native) pairs it with
        // "Settings", and the OpenVPN editor — the one a machine with imported .ovpn
        // files selects by default — leads with "General" and has five more tabs
        // besides. Demanding "Settings" alone failed on every OpenVPN selection, which
        // is the common case, not the rare one.
        let siblingTitle = manage.radioButtons["Settings"].exists ? "Settings" : "General"
        let sibling = manage.radioButtons[siblingTitle]
        XCTAssertTrue(sibling.exists, """
            The editor has a Custom Routing tab but neither a Settings tab (tunnel editors) \
            nor a General one (the OpenVPN editor) — the tabbed shape every editor shares \
            is broken
            """)
        // Both tabs must be REACHABLE, not merely present: a tab that exists but
        // can't be hit is a surface a keyboard or Switch Control user cannot get to.
        XCTAssertTrue(tab.isHittable, "The Custom Routing tab is not reachable")
        XCTAssertTrue(sibling.isHittable, "The \(siblingTitle) tab is not reachable")
        // The tabs are NOT clicked. Switching into an editor tab fires the Custom
        // Routing draft's commit path, and these tests are read-only about the
        // tester's own VPNs by design (see this file's header).

        // Any rule rows already on screen must read as sentences. An empty rule list
        // is the normal state and is fine — the human step adds an overlapping rule.
        let ruleRows = flatten(try snapshot(of: manage, "the Manage VPNs editor")).filter {
            $0.elementType == .button && $0.label.lowercased().contains("overlaps")
        }
        for row in ruleRows {
            XCTAssertGreaterThan(row.label.split(separator: ",").count, 1, """
                \u{201C}\(row.label)\u{201D} mentions an overlap without saying what overlaps what
                """)
        }
    }

    // MARK: - Step 12 — Settings

    /// Doc step 12: "⌘, … toggle a checkbox in General, then in Labels rename a
    /// label — every control names WHICH label it edits."
    ///
    /// Asserted here: ⌘, opens Settings; every documented group heading is on
    /// screen as a named element (the group taxonomy is spoken UI — renaming a
    /// group renames what a listener hears); the Labels tab is reachable; and every
    /// control in Labels names which label it edits.
    ///
    /// Nothing is toggled and nothing is renamed: these are the tester's own
    /// settings. The human still flips a checkbox and renames a label to hear the
    /// change confirmed.
    @MainActor
    func testStep12SettingsGroupsAndLabelControlsNameThemselves() throws {
        let app = try launchOrSkip()
        // BOTH paths, in the order a user reaches for them: the app menu first, then
        // ⌘, if the window hasn't appeared. Neither is reliable ALONE in a test
        // session (measured: the menu item clicks with no window appearing, and the
        // bare key equivalent opened it for a probe but not for the suite) — and this
        // step is about what the window says, not about which of the two opened it.
        // The window is matched on the SwiftUI Settings scene's own identifier as
        // well as its title, because the title is macOS-version-dependent.
        let settings = app.windows.matching(NSPredicate(format: """
            identifier == 'com_apple_SwiftUI_Settings_window' OR title == 'General' \
            OR title CONTAINS 'Settings'
            """)).firstMatch
        app.menuBarItems["SimpleVPN"].click()
        app.menuBarItems["SimpleVPN"].menuItems["Settings\u{2026}"].click()
        if !settings.waitForExistence(timeout: 8) {
            app.typeKey(",", modifierFlags: [.command])
        }
        guard settings.waitForExistence(timeout: 10) else {
            XCTFail("Neither SimpleVPN ▸ Settings… nor ⌘, opened the Settings window")
            return
        }
        // The app-wide Settings groups, per AGENTS.md ("General · Menu Bar & Icons ·
        // Updates · Privacy · Advanced").
        // The window remembers its tab between launches, so which pane is showing is
        // whatever the last person left. Drive it explicitly. Settings tabs are AppKit
        // toolbar items carrying a TITLE and no identifier or label, so they are
        // matched on that title.
        func tab(_ title: String) -> XCUIElement {
            settings.descendants(matching: .button)
                .matching(NSPredicate(format: "title == %@", title)).firstMatch
        }
        let general = tab("General"), labels = tab("Labels")
        let signInSources = tab("Sign-In Sources")
        XCTAssertTrue(general.waitForExistence(timeout: 5), "The Settings window has no General tab")
        XCTAssertTrue(labels.exists, "The Settings window has no Labels tab")
        XCTAssertTrue(signInSources.exists, """
            The Settings window has no Sign-In Sources tab — the pane that says which password \
            apps may be used and where their tools are is unreachable
            """)

        general.click()
        // Matched on label/value from a snapshot, not with the `[…]` subscript: the
        // subscript keys on the identifier, and a section header is named by its
        // label — which is what VoiceOver reads.
        var spokenTexts: [String] = []
        XCTAssertTrue(waitUntil(timeout: 10) {
            spokenTexts = ((try? settings.snapshot()).map(flatten) ?? [])
                .filter { $0.elementType == .staticText }
                .flatMap { [$0.label, ($0.value as? String) ?? ""] }
            return spokenTexts.contains("General")
        }, "The General pane never appeared: \(spokenTexts)")
        for heading in ["General", "Menu Bar & Icons", "Updates", "Privacy", "Advanced"] {
            XCTAssertTrue(spokenTexts.contains(heading), """
                The Settings group \u{201C}\(heading)\u{201D} is not on screen under that name — \
                the taxonomy a listener navigates by has drifted
                """)
        }

        // Every named control in Labels must say WHICH label it acts on. With no
        // labels defined there is nothing but the empty state, which is fine.
        labels.click()
        _ = waitUntil(timeout: 5) { settings.title == "Labels" }
        let actions = flatten(try snapshot(of: settings, "the Labels tab")).filter {
            ($0.elementType == .button || $0.elementType == .colorWell) && !$0.label.isEmpty
                && !$0.identifier.hasPrefix("_XCUI")
        }
        // "colour", not "color": the pane's own wording is British ("Colour for the
        // Lab label"), so the American spelling matched nothing and this loop had
        // quietly stopped covering the colour wells — half of what step 12 exists for.
        // Both spellings are accepted so a future rewording can't silence it again.
        for action in actions
        where action.label.lowercased().hasPrefix("delete")
            || action.label.lowercased().contains("colour")
            || action.label.lowercased().contains("color") {
            XCTAssertGreaterThan(action.label.split(separator: " ").count, 1, """
                \u{201C}\(action.label)\u{201D} doesn't say which label it edits — one \
                \u{201C}Delete\u{201D} per label is indistinguishable by ear
                """)
        }
        general.click()   // leave the window on its default tab
    }

    // MARK: - Step 13 — Network Tools

    /// Doc step 13: "⇧⌘T: focus is in the host field; type an address, Return. Hear
    /// the scan finish. Walk the DNS rows — the one macOS used must say so."
    ///
    /// Asserted here: ⇧⌘T opens the window; the host field is NAMED (it used to be
    /// nameless, so VoiceOver read its example prompt "example.com" as its name);
    /// the mediator Re-assert buttons name their subject; every DISABLED control in
    /// the window carries its reason in its value (rule 5 — a disabled Run that says
    /// nothing is a dead end for anyone who cannot see that the field above is
    /// empty); and the DNS card states which resolvers the system is actually using.
    ///
    /// Still human: hearing the scan FINISH (the completion announcement), and the
    /// latency chart's audio graph.
    @MainActor
    func testStep13NetworkToolsIsNamedAndDisabledControlsSayWhy() throws {
        let app = try launchOrSkip()
        app.typeKey("t", modifierFlags: [.command, .shift])
        let tools = app.windows["tools"]
        guard tools.waitForExistence(timeout: 10) else {
            XCTFail("⇧⌘T did not open the Network Tools window")
            return
        }
        XCTAssertTrue(tools.textFields["Host or IP to test"].waitForExistence(timeout: 10), """
            The Network Tools host field is not named \u{201C}Host or IP to test\u{201D} — with \
            no name of its own VoiceOver reads its example prompt (\u{201C}example.com\u{201D}) \
            as the field's name
            """)
        for subject in ["Re-assert routing", "Re-assert DNS", "Re-assert proxy"] {
            XCTAssertTrue(tools.buttons[subject].exists, """
                \u{201C}\(subject)\u{201D} is missing — three bare \u{201C}Re-assert\u{201D} \
                buttons in one window are indistinguishable by ear
                """)
        }

        let nodes = flatten(try snapshot(of: tools, "the Network Tools window"))
        let mutedControls = nodes.filter {
            ($0.elementType == .button || $0.elementType == .checkBox)
                && !$0.isEnabled && !$0.label.isEmpty
                && !$0.identifier.hasPrefix("_XCUI")
        }
        for control in mutedControls {
            XCTAssertFalse(((control.value as? String) ?? "").isEmpty, """
                \u{201C}\(control.label)\u{201D} is disabled and says nothing about why. The \
                reason goes to .help AND .accessibilityValue (Docs/Accessibility.md rule 5).
                """)
        }

        // "the one macOS used must say so" — the DNS card names the live resolvers.
        let dnsAnswer = nodes.compactMap { $0.value as? String }
            .first { $0.hasPrefix("System now uses:") }
        if let dnsAnswer {
            XCTAssertGreaterThan(dnsAnswer.count, "System now uses:".count + 3, """
                The DNS card says \u{201C}\(dnsAnswer)\u{201D} without naming a resolver
                """)
        }
    }

    // MARK: - Step 14 — ESC closes, focus returns

    /// Doc step 14: "Traffic log (from a connected VPN's inspector): rows read as
    /// sentences; ESC closes the sheet and focus returns to the opener."
    ///
    /// The traffic log needs a LIVE CONNECTION, so the sheet half of that claim is
    /// asserted on the one sheet reachable while disconnected: "Find a Setting…"
    /// (⌘⇧F). ESC must close it — the contract the doc states for "every sheet and
    /// popover".
    ///
    /// Still human: the traffic log itself — that its rows read as sentences with
    /// the columns inlined and the glyphs translated, and that focus returns to the
    /// inspector row that opened it.
    @MainActor
    func testStep14EscapeClosesASheetAndFocusReturns() throws {
        let app = try launchOrSkip()
        app.typeKey("f", modifierFlags: [.command, .shift])
        XCTAssertTrue(waitUntil(timeout: 15) { app.sheets.count > 0 },
                      "⌘⇧F did not present the Find a Setting sheet")
        app.typeKey(.escape, modifierFlags: [])
        XCTAssertTrue(waitUntil(timeout: 10) { app.sheets.count == 0 },
                      "ESC did not close the sheet — the .cancelAction contract is broken")
    }

    // MARK: - Step 15 — Accommodations

    /// Doc step 15: turn on Differentiate Without Color, Increase Contrast and
    /// Reduce Motion, and confirm the visual changes.
    ///
    /// Asserted here: the half that must hold WHATEVER the accommodations are set
    /// to — no information rides on a dot. The sidebar's VPN rows expose no image
    /// element at all (dots and logos are `accessibilityHidden`), and the route
    /// diagram's links carry their status in words in their values, so a reader who
    /// cannot distinguish the colours (or the dashes) still gets the state.
    ///
    /// Still human, and not automatable: the visual pass. A UI test cannot toggle a
    /// system accessibility preference, and even with it toggled the audit samples
    /// static colours and misfires on Liquid Glass (see SimpleVPNUITests'
    /// `.contrast` exclusion). A person must switch each setting on and confirm the
    /// dots become shapes, edges change dash rhythm, log errors gain underlines,
    /// pill text darkens, and nothing pulses.
    @MainActor
    func testStep15NoInformationRidesOnColourAlone() throws {
        let app = try launchOrSkip()
        let rows = try vpnRows(in: app, sidebarOf: app.windows.firstMatch)
        for (name, row) in rows {
            let images = flatten(row).filter { $0.elementType == .image }
            XCTAssertTrue(images.isEmpty, """
                The row for \u{201C}\(name)\u{201D} exposes \(images.count) image(s) \
                (\(images.map(describe).joined(separator: " | "))) — a status dot that is \
                visible to VoiceOver is a status that rides on colour
                """)
        }

        app.typeKey("r", modifierFlags: [.command, .shift])
        let routes = app.windows["routes"]
        guard routes.waitForExistence(timeout: 10) else { return }
        let diagram = routes.descendants(matching: .any)
            .matching(NSPredicate(format: "label == 'Route diagram'")).firstMatch
        guard diagram.waitForExistence(timeout: 10) else {
            XCTFail("No element named \u{201C}Route diagram\u{201D}")
            return
        }
        let links = flatten(try snapshot(of: diagram, "the route diagram")).filter {
            $0.elementType == .button && !(($0.value as? String) ?? "").isEmpty
        }
        XCTAssertFalse(links.isEmpty, """
            No link in the route diagram states its condition in words — the dash rhythms \
            and colours would then be the only carriers
            """)
    }

    // MARK: - Helpers

    /// Launches the app and skips (rather than flakes) where no UI can appear.
    /// Deliberately the same pre-checks as `SimpleVPNUITests.launchOrSkip` — the
    /// two suites must skip under identical conditions or a green run means
    /// different things in each.
    @MainActor
    private func launchOrSkip() throws -> XCUIApplication {
        if let session = CGSessionCopyCurrentDictionary() as? [String: Any],
           (session["CGSSessionScreenIsLocked"] as? Bool) == true {
            throw XCTSkip("""
                The console session is locked — macOS won't bring any app to the \
                foreground, so nothing can be read from the accessibility tree here. \
                These run wherever UI tests run for real.
                """)
        }
        let app = XCUIApplication()
        app.launch()
        guard app.wait(for: .runningForeground, timeout: 15),
              app.windows.firstMatch.waitForExistence(timeout: 15) else {
            throw XCTSkip("""
                No window appeared — this environment can't present UI (headless session, \
                or the runner lacks Automation permission).
                """)
        }
        return app
    }

    /// One accessibility snapshot of an element, or a skip when it can't be taken
    /// (a stale hierarchy is an environment problem, not an accessibility one).
    @MainActor
    private func snapshot(of element: XCUIElement, _ what: String) throws -> XCUIElementSnapshot {
        do { return try element.snapshot() } catch {
            throw XCTSkip("Could not snapshot \(what): \(error.localizedDescription)")
        }
    }

    @MainActor
    private func flatten(_ s: XCUIElementSnapshot) -> [XCUIElementSnapshot] {
        var out = [s]
        for child in s.children { out.append(contentsOf: flatten(child)) }
        return out
    }

    /// One line naming an element the way a failure message needs it.
    @MainActor
    private func describe(_ s: XCUIElementSnapshot) -> String {
        var bits = ["\(s.elementType)"]
        if !s.identifier.isEmpty { bits.append("id \(s.identifier)") }
        if !s.label.isEmpty { bits.append("label \u{201C}\(s.label)\u{201D}") }
        if let v = s.value as? String, !v.isEmpty { bits.append("value \u{201C}\(v)\u{201D}") }
        return bits.joined(separator: " ")
    }

    /// The VPN rows of a window's sidebar as (name, row snapshot) pairs, keyed off
    /// each row's own Connect control so the name comes from the app rather than
    /// from a fixture. Skips when the window is showing a prompt instead of a list,
    /// or when the machine has no VPNs.
    @MainActor
    private func vpnRows(
        in app: XCUIApplication, sidebarOf window: XCUIElement
    ) throws -> [(name: String, row: XCUIElementSnapshot)] {
        _ = window.waitForExistence(timeout: 10)
        let sidebar = window.outlines["Sidebar"]
        guard sidebar.waitForExistence(timeout: 10) else {
            throw XCTSkip("""
                No VPN list in this window: it is showing the extension-activation or \
                empty-VPNs prompt, or this machine has exactly ONE VPN — in which case the \
                sidebar deliberately starts closed (ConnectionView: a list of one is noise). \
                All real UI, but not this step's UI; the human walkthrough wants two.
                """)
        }
        var found: [(name: String, row: XCUIElementSnapshot)] = []
        for row in flatten(try snapshot(of: sidebar, "the sidebar"))
        where row.elementType == .outlineRow {
            let connect = flatten(row).first {
                $0.elementType == .button && $0.label.hasPrefix("Connect ")
            }
            guard let connect else { continue }   // the "VPNs" section header
            // The dimmed Play button says WHY it can't connect yet in its own name
            // ("Connect Tig Lab — needs your sign-in first"), which is right for a
            // listener and wrong as a handle: everything after the em dash is the
            // reason, not the VPN. Take the name only — a VPN with manual
            // credentials is exactly the one the doc asks the tester to use, so this
            // is the normal shape here, not an edge case.
            let named = String(connect.label.dropFirst("Connect ".count))
            let name = named.components(separatedBy: " \u{2014} ").first ?? named
            found.append((name, row))
        }
        try XCTSkipIf(found.isEmpty, """
            No VPNs are configured on this machine, so there is no row to read. The human \
            walkthrough needs at least one VPN (ideally one with manual credentials).
            """)
        return found
    }

    /// The first of `phrases` that appears in `text`, case-insensitively — the
    /// vocabulary check rule 3 asks for.
    private static func phrase(in text: String, from phrases: [String]) -> String? {
        let lower = text.lowercased()
        return phrases.first { lower.contains($0) }
    }

    /// Poll a condition. UI state settles asynchronously and `waitForExistence`
    /// only covers existence.
    @MainActor
    private func waitUntil(timeout: TimeInterval, _ condition: () -> Bool) -> Bool {
        let deadline = Date().addingTimeInterval(timeout)
        while Date() < deadline {
            if condition() { return true }
            usleep(150_000)
        }
        return condition()
    }
}
