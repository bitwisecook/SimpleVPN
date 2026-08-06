// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
//  SimpleVPNUITests.swift
//  The accessibility regression gate (AGENTS.md "Accessibility — a first-class
//  requirement"): launch the app for real and run XCTest's accessibility audit
//  over the main window. New audit failures are build-breaking, same as
//  warnings.
//
//  Environment notes:
//   • This launches the freshly built DerivedData copy, which macOS will not
//    activate a system extension for — so the window shows either the
//    activation/empty-VPNs prompts or the normal shell. All of those are real
//    UI and all must pass. (The installed-copy tests live in
//    InstalledExtensionTests.swift.)
//   • UI tests need a window server + Automation permission. When either is
//    missing (headless CI), the test SKIPS with a reason instead of flaking.
//

import XCTest
import CoreGraphics   // CGSessionCopyCurrentDictionary — the locked-console pre-check

final class SimpleVPNUITests: XCTestCase {

    override func setUpWithError() throws {
        continueAfterFailure = false
    }

    /// The audit gate. Audits everything the macOS audit supports EXCEPT:
    ///  • .contrast — the app's status language rides on Liquid Glass materials
    ///    whose effective background is composited at draw time; the audit
    ///    checker assumes static colors and misfires on glass. Contrast (incl.
    ///    the Increase Contrast accommodation) is wave 3's visual pass.
    /// Everything else — element detection, hit regions, sufficient element
    /// descriptions, action support, parent/child structure — must pass.
    @MainActor
    func testMainWindowAccessibilityAudit() throws {
        let app = try launchOrSkip()
        try runAccessibilityAudit(on: app)
    }

    /// The same gate over the Routes window — the wave-2 flagship (route
    /// diagram, gateway bar, traffic-path strip), opened the way a user opens
    /// it: VPN ▸ Routes…. The main window stays open beside it, which is fine —
    /// it passes its own audit above, and auditing both together is strictly
    /// more coverage, never less.
    @MainActor
    func testRoutesWindowAccessibilityAudit() throws {
        let app = try launchOrSkip()

        app.menuBarItems["VPN"].click()
        app.menuBarItems["VPN"].menuItems["Routes…"].click()
        guard app.windows["Routes"].waitForExistence(timeout: 10) else {
            XCTFail("The Routes window didn't open from the VPN menu")
            return
        }

        try runAccessibilityAudit(on: app)
    }

    /// The same gate over the Settings window (wave 3: editors + settings),
    /// opened the way a user opens it: SimpleVPN ▸ Settings… (⌘,), and over EVERY
    /// one of its panes rather than whichever one the tester left showing.
    @MainActor
    func testSettingsWindowAccessibilityAudit() throws {
        let app = try launchOrSkip()

        app.menuBarItems["SimpleVPN"].click()
        app.menuBarItems["SimpleVPN"].menuItems["Settings…"].click()
        // Matched on the SwiftUI Settings scene's own IDENTIFIER as well as the
        // title, the same way VoiceOverWalkthroughTests' step 12 matches it. The
        // window remembers its tab between launches and macOS titles it after the
        // selected pane, so a tester who last used "Labels" or "Sign-In Sources"
        // leaves behind a perfectly healthy window whose title is neither
        // "General" nor anything containing "Settings" — and this guard then
        // failed the audit for a window that was open in front of it.
        let settings = app.windows.matching(
            NSPredicate(format: """
                identifier == 'com_apple_SwiftUI_Settings_window' OR title == 'General' \
                OR title CONTAINS 'Settings'
                """)
        ).firstMatch
        guard settings.waitForExistence(timeout: 10) else {
            XCTFail("The Settings window didn't open from the app menu")
            return
        }

        // A Settings tab is a whole SURFACE — Sign-In Sources alone carries the
        // vault list, the tool-path fields, the database-password rows and their
        // enablement banners — and only the pane on screen is in the tree the
        // audit walks. Auditing whatever tab was remembered means the gate covers
        // a different third of this window on every machine, so all three are
        // driven explicitly. Tabs are AppKit toolbar items carrying a TITLE and no
        // identifier or label, so they are matched on that title (as step 12 does).
        // RE-RESOLVED PER PANE, and not scoped to the window. Both matter, and both were
        // learned the hard way: a `firstMatch` held across a pane switch went stale (the
        // window is retitled after its selected tab, and the tab strip is rebuilt), so
        // "Labels" was reported missing on a window that was showing it. Matching on
        // `app` rather than on the window also covers the toolbar living outside the
        // window element on some macOS versions. `.any` because the strip renders as
        // buttons in some releases and radio buttons in others (VoiceOverWalkthroughTests
        // step 11 hits the radio-button form) — the TITLE is the stable handle, not the role.
        func tab(_ title: String) -> XCUIElement {
            app.descendants(matching: .any)
                .matching(NSPredicate(format: "title == %@", title)).firstMatch
        }
        for title in ["General", "Sign-In Sources", "Labels"] {
            let pane = tab(title)
            guard pane.waitForExistence(timeout: 15) else {
                // Names what WAS there, so a future break is diagnosable from the log
                // instead of being a bare "no Labels tab" on a window showing one.
                let seen = app.descendants(matching: .any).allElementsBoundByIndex
                    .prefix(80).compactMap { $0.title.isEmpty ? nil : $0.title }
                XCTFail("The Settings window has no \(title) tab. Titles seen: \(Set(seen).sorted())")
                return
            }
            pane.click()
            try runAccessibilityAudit(on: app)
        }
        tab("General").click()   // leave the window on its default tab
    }

    /// The same gate over the Network Tools window (mediator cards, the staged
    /// check, the path railroad), opened via VPN ▸ Network Tools…. It is the one
    /// window with a VoiceOver step of its own (13) that no audit ever walked.
    @MainActor
    func testNetworkToolsWindowAccessibilityAudit() throws {
        let app = try launchOrSkip()

        app.menuBarItems["VPN"].click()
        app.menuBarItems["VPN"].menuItems["Network Tools…"].click()
        // By SCENE ID, for the same reason Manage VPNs is: the window's own
        // `.navigationTitle` is what titles it, and the id is the stable handle.
        guard app.windows["tools"].waitForExistence(timeout: 10) else {
            XCTFail("The Network Tools window didn't open from the VPN menu")
            return
        }

        try runAccessibilityAudit(on: app)
    }

    /// The same gate over the Report a Problem window — Help ▸ Report a Problem…,
    /// which is also where every "Untested" banner's report link lands.
    ///
    /// It needs its own test because it is not a sheet on anybody else's window:
    /// DiagnosticReportCoordinator hosts a plain NSWindow, so it is outside every
    /// window the four audits above open. Nothing is submitted — the dialog
    /// gathers the payload and shows it, and an audit only reads the tree.
    @MainActor
    func testDiagnosticReportWindowAccessibilityAudit() throws {
        let app = try launchOrSkip()

        app.menuBarItems["Help"].click()
        app.menuBarItems["Help"].menuItems["Report a Problem…"].click()
        guard app.windows["Report a Problem"].waitForExistence(timeout: 10) else {
            XCTFail("The Report a Problem window didn't open from the Help menu")
            return
        }

        try runAccessibilityAudit(on: app)
        // Leave the machine as we found it — ESC closes it (the window's own
        // cancelOperation), so nothing inherits an open report dialog.
        app.typeKey(.escape, modifierFlags: [])
    }

    /// The same gate over the Manage VPNs window (wave 3: the management
    /// surface — list, editor tabs, import), opened via VPN ▸ Manage VPNs….
    @MainActor
    func testManageVPNsWindowAccessibilityAudit() throws {
        let app = try launchOrSkip()

        app.menuBarItems["VPN"].click()
        app.menuBarItems["VPN"].menuItems["Manage VPNs…"].click()
        // Matched by SCENE ID, not by window title: an embedded editor's
        // `.navigationTitle` replaces the window title on macOS, so as soon as a
        // VPN is selected this window is called e.g. "Tailscale". Looking for
        // "Manage VPNs" therefore failed against a window that was open and
        // perfectly healthy. SwiftUI publishes a `Window(id:)` scene's id as the
        // window's AX identifier, so "manage" is stable whatever the title says.
        // (An `.accessibilityIdentifier` on the view's NavigationSplitView root
        // is NOT an alternative — verified: it never surfaces anywhere in the
        // tree, 0 matches app-wide while the window was demonstrably open.)
        guard app.windows["manage"].waitForExistence(timeout: 10) else {
            XCTFail("The Manage VPNs window didn't open from the VPN menu")
            return
        }

        try runAccessibilityAudit(on: app)
    }

    // MARK: - Never hide a profile the user created

    /// THE CONNECT LIST'S INVARIANT, checked against the real window.
    ///
    /// `ConnectListingTests` proves the decision; this proves the WINDOW obeys it —
    /// that every row visible in the connect list offers a Connect or Disconnect
    /// control, and that a Connect which is DISABLED carries a reason in its value.
    ///
    /// What it would have caught: a subprocess-backed profile used to be filtered out
    /// of this list unless it was already running, so there was no row and therefore
    /// no control — and the "absent button" failure mode this asserts against is the
    /// same one, one level down. Both halves matter: a row with no control is
    /// indistinguishable from a broken layout, and a dead control with no reason is
    /// indistinguishable from a bug.
    ///
    /// Environment-independent by construction: it reads whatever this machine has
    /// and skips when the window is showing a prompt instead of a list. It never
    /// clicks Connect — no test may open a real tunnel.
    @MainActor
    func testEveryConnectListRowOffersAnActionThatSaysWhy() throws {
        let app = try launchOrSkip()
        let window = app.windows.firstMatch
        let sidebar = window.outlines["Sidebar"]
        try XCTSkipIf(!sidebar.waitForExistence(timeout: 10), """
            No VPN list in this window: it is showing the extension-activation or \
            empty-VPNs prompt, or this machine has exactly one VPN (the sidebar then \
            starts closed — ConnectionView: "a list of one is noise").
            """)

        var rowsChecked = 0
        for row in sidebar.descendants(matching: .outlineRow).allElementsBoundByIndex {
            guard let snapshot = try? row.snapshot() else { continue }
            let buttons = Self.flatten(snapshot).filter { $0.elementType == .button }
            let actions = buttons.filter {
                $0.label.hasPrefix("Connect") || $0.label.hasPrefix("Disconnect")
                    || $0.label == "Cancel connecting"
            }
            // A section header is a row with no action, and the only one.
            guard !actions.isEmpty else { continue }
            rowsChecked += 1
            for action in actions {
                let value = (action.value as? String) ?? ""
                XCTAssertFalse(value.isEmpty, """
                    \u{201C}\(action.label)\u{201D} in the connect list has no value, so a listener \
                    is told what it is and never what the connection is doing
                    """)
            }
        }
        // Every row that exists has an action. The count is the assertion: a row that
        // slipped through with none would have been skipped by the `guard` above, so
        // compare against what the sidebar actually holds.
        let headerCount = sidebar.descendants(matching: .outlineRow).allElementsBoundByIndex
            .compactMap { try? $0.snapshot() }
            .filter { snapshot in
                Self.flatten(snapshot).allSatisfy { node in
                    node.elementType != .button
                        || !(node.label.hasPrefix("Connect") || node.label.hasPrefix("Disconnect")
                             || node.label == "Cancel connecting")
                }
            }
            .count
        let total = sidebar.descendants(matching: .outlineRow).count
        XCTAssertEqual(rowsChecked, total - headerCount, """
            \(total - headerCount - rowsChecked) row(s) in the connect list offer no Connect or \
            Disconnect control at all — an absent action is indistinguishable from a broken layout
            """)
        try XCTSkipIf(rowsChecked == 0, "No VPNs are configured on this machine.")
    }

    /// Flatten an accessibility snapshot tree. (The VoiceOver walkthrough has its own
    /// copy for the same reason: the two suites must not share mutable state.)
    @MainActor
    private static func flatten(_ snapshot: XCUIElementSnapshot) -> [XCUIElementSnapshot] {
        var out: [XCUIElementSnapshot] = [snapshot]
        var pending = snapshot.children
        while let next = pending.popLast() {
            out.append(next)
            pending.append(contentsOf: next.children)
        }
        return out
    }

    /// Launches the app and skips (rather than flakes) where no UI can appear.
    @MainActor
    private func launchOrSkip() throws -> XCUIApplication {
        // A locked console (screen asleep behind a password) can spawn the
        // process but never foreground it — launch() itself then fails the
        // test after a 60 s activation timeout, which is an environment
        // problem, not an accessibility regression. Skip up front instead.
        if let session = CGSessionCopyCurrentDictionary() as? [String: Any],
           (session["CGSSessionScreenIsLocked"] as? Bool) == true {
            throw XCTSkip("""
                The console session is locked — macOS won't bring any app to \
                the foreground, so the audit can't run here. It runs wherever \
                UI tests run for real.
                """)
        }

        let app = XCUIApplication()
        app.launch()

        guard app.wait(for: .runningForeground, timeout: 15),
              app.windows.firstMatch.waitForExistence(timeout: 15) else {
            throw XCTSkip("""
                No window appeared — this environment can't present UI \
                (headless session, or the runner lacks Automation permission), \
                so the audit can't run here. It runs wherever UI tests run \
                for real.
                """)
        }
        return app
    }

    /// The system Touch Bar strip and every item inside it, as (type, frame)
    /// pairs — see the exclusion in `runAccessibilityAudit` for why that pair is
    /// the only identity Touch Bar items have. Snapshotted once per audit, from
    /// the same hierarchy the audit walks.
    @MainActor
    private func touchBarChrome(
        of app: XCUIApplication
    ) -> [(type: XCUIElement.ElementType, frame: CGRect)] {
        var chrome: [(type: XCUIElement.ElementType, frame: CGRect)] = []
        var pending = app.descendants(matching: .touchBar)
            .allElementsBoundByIndex.compactMap { try? $0.snapshot() }
        while let element = pending.popLast() {
            chrome.append((element.elementType, element.frame))
            pending.append(contentsOf: element.children)
        }
        return chrome
    }

    /// The shared audit body: one exclusion list, applied identically to every
    /// window, so a new surface can't quietly get a looser gate.
    ///
    /// `.contrast` stays EXCLUDED (wave 3 re-attempted enabling it): the app's
    /// status language rides on Liquid Glass materials whose effective
    /// background is composited at draw time; the audit checker samples static
    /// colors and misfires on glass (observed in wave 1). Wave 3 did the manual
    /// pass instead: the worst caption-on-glass offenders now honor Increase
    /// Contrast (ProblemPill/working-pill text promotes to primary), LabelPill
    /// picks its text color from the pill's own WCAG luminance, and no
    /// information rides on .tertiary text over glass. Re-attempt when the
    /// audit learns to sample composited backgrounds.
    @MainActor
    private func runAccessibilityAudit(on app: XCUIApplication) throws {
        let auditTypes: XCUIAccessibilityAuditType = [
            .elementDetection, .hitRegion, .sufficientElementDescription,
            .action, .parentChild,
        ]
        let touchBar = touchBarChrome(of: app)
        try app.performAccessibilityAudit(for: auditTypes) { issue in
            // Surfaced in the log so a failing gate names its culprit at once.
            print("AUDIT ISSUE [\(issue.auditType)] \(issue.compactDescription) :: \(issue.element.map { $0.debugDescription } ?? "<no element>")")

            // Structural false positives on ANONYMOUS CONTAINER GROUPS — AX
            // "Group" elements with no label and no identifier that the
            // frameworks synthesize, not app code:
            //  • description: NSHostingView puts one between the window and its
            //    content, NavigationSplitView one around each column. Not
            //    reachable from view code (verified: a root-level
            //    .accessibilityLabel and .accessibilityElement(children:
            //    .contain) never land on them).
            //  • parent/child: the window's zoom traffic-light button
            //    (_XCUI:FullScreenWindow) carries a 1pt-inset anonymous group —
            //    AppKit window chrome, again untouchable.
            // Only that exact shape is excused. Real content (buttons, images,
            // text, labeled groups) stays enforced.
            //
            // KNOWN COST, stated so nobody rediscovers it as a mystery: an
            // APP-OWNED container is the same shape when it has no name — an
            // `.accessibilityElement(children: .contain)` with no
            // `.accessibilityLabel` is an unlabeled group and lands here too. The
            // audit therefore cannot enforce "every container says what it is",
            // and it silently excused three real ones (the first-connect setup
            // card, the 1Password walkthrough, and Sign-In Sources' "where it was
            // found" disclosure) until they were labeled by hand. So: `.contain`
            // is ALWAYS paired with a label in this app, and keeping that true is
            // review's job, not this gate's. Narrowing the excusal by provenance
            // the way the Touch Bar one is done needs an identity these framework
            // groups do not have (verified: no label, no identifier, and
            // unreachable from view code).
            if issue.auditType == .sufficientElementDescription || issue.auditType == .parentChild,
               let element = issue.element,
               element.elementType == .group,
               element.label.isEmpty, element.identifier.isEmpty {
                return true
            }

            // An issue whose ELEMENT CANNOT BE RESOLVED AT ALL. The audit
            // reports these when its snapshot goes stale mid-run (the log shows
            // the query retrying and giving up), so there is nothing to inspect,
            // nothing to name, and nothing a developer could fix — and, worse,
            // the shape-based excusals above can never match a nil element, so
            // one stale snapshot fails the gate no matter how clean the app is.
            // Observed on the Routes window, where the resolvable twin of the
            // same issue is the AppKit zoom traffic-light chrome excused above.
            // Excusing nil is therefore strictly the right call: a real,
            // reproducible violation always arrives WITH its element.
            if issue.element == nil {
                return true
            }

            // THE SYSTEM TOUCH BAR STRIP AND EVERYTHING IN IT. AppKit
            // synthesizes an NSTouchBar per window (unnamed), and — whenever a
            // text field holds focus — fills it with the system text-input
            // group: the "emoji & symbols" character picker plus the predictive
            // "Candidate Bar" and its suggestion buttons. The picker has a
            // lowercase AX label and no description, so the audit flags it; the
            // strip itself has neither.
            //
            // None of it is app UI and none of it is nameable from app code: the
            // app never constructs an NSTouchBar, SwiftUI exposes no hook onto
            // the one AppKit makes for a focused text field, and `.accessibility*`
            // on the field (or on the window's root) does not reach the strip —
            // verified by the audit's own "Path to element", which puts the
            // culprit directly under Application ▸ TouchBar, outside every
            // window. This is why it shows up on Routes and not elsewhere:
            // Routes gives its search field initial focus by design
            // (Docs/Accessibility.md "Initial focus"), which is what makes macOS
            // populate the strip. Suppressing the strip would mean giving up
            // that focus behaviour — an accessibility regression to silence a
            // framework artifact.
            //
            // Excused by PROVENANCE, not by type: only elements whose identity
            // is in a live snapshot of the app's touch bars. Touch Bar items
            // carry no identifier at all, so (type, frame) is the only handle
            // there is — and an app element can't share one with a strip that
            // lives outside every window.
            if issue.auditType == .sufficientElementDescription,
               let element = issue.element,
               touchBar.contains(where: { $0.type == element.elementType && $0.frame == element.frame }) {
                return true
            }

            // NSTOOLBAR'S OVERFLOW CHEVRON. When a window's toolbar items don't
            // all fit, AppKit adds its own ≫ control and moves the rest into its
            // menu — it appears in Manage VPNs, whose four sidebar toolbar items
            // are laid out inside the 240pt sidebar column. AppKit names it with
            // an AXDescription only ("more toolbar items", its own sentence-case
            // string), which the audit doesn't count as a description; there is
            // no title and no identifier on it.
            //
            // Not app UI and not nameable from app code: it is created by
            // NSToolbar, is a DIRECT child of the AXToolbar (verified in the
            // audit's "Path to element" — Window ▸ Toolbar ▸ PopUpButton, with our
            // own items as siblings), and no `.toolbar`/`.accessibility*`
            // modifier addresses it. Nor is "make the window wider" a fix: the
            // chevron comes back at any width the user can drag to, so widening
            // would only hide this failure. Matched on AppKit's exact string so
            // an unnamed app-owned popup can never slip through with it.
            if issue.auditType == .sufficientElementDescription,
               let element = issue.element,
               element.elementType == .popUpButton,
               element.identifier.isEmpty,
               element.label == "more toolbar items" {
                return true
            }

            // Framework false positive on SWIFTUI'S MENU-PRESENTING CONTROLS —
            // menu `Picker`s (AX PopUpButton) and `Menu`s (AX MenuButton, e.g.
            // Manage VPNs' "Add VPN" ＋ toolbar item).
            //
            // Measured with the real AX API against a running Debug build
            // (AXUIElementCopyActionNames, which is the ground truth the audit is
            // supposed to be reporting on):
            //   AXMenuButton  id 'plus'  desc 'Add VPN'      → ["AXPress"]
            //   AXPopUpButton (Tailscale / browser pickers)  → ["AXPress"]
            //   AXPopUpButton 'more toolbar items' (AppKit)  → ["AXShowMenu", "AXPress"]
            // So the controls ARE operable — AXPress opens the menu, which is
            // exactly what VoiceOver's VO-Space, Switch Control and Full Keyboard
            // Access perform. What SwiftUI omits on these two roles is the
            // secondary AXShowMenu action AppKit's own equivalents publish, and
            // that omission alone is what the audit reports; plain AXButtons with
            // only AXPress pass. Framework-owned: AXShowMenu isn't expressible
            // from app code (`.accessibilityAction` adds CUSTOM actions, not the
            // system one), and no label/menuStyle/pickerStyle changes it.
            if issue.auditType == .action,
               let element = issue.element,
               element.elementType == .popUpButton || element.elementType == .menuButton {
                return true
            }

            // (The wave-2 by-name exclusions — MercatorMap, RouteGraph,
            // ThroughputGraph, Railroad — are gone: those surfaces now carry
            // their own navigable structure and are held to the full gate.)
            return false          // everything else is build-breaking
        }
    }

    @MainActor
    func testLaunchPerformance() throws {
        // This measures how long it takes to launch your application.
        measure(metrics: [XCTApplicationLaunchMetric()]) {
            XCUIApplication().launch()
        }
    }
}
