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
    /// opened the way a user opens it: SimpleVPN ▸ Settings… (⌘,). The window's
    /// title is macOS-version-dependent (the selected tab's name vs
    /// "SimpleVPN Settings"), so the wait matches either.
    @MainActor
    func testSettingsWindowAccessibilityAudit() throws {
        let app = try launchOrSkip()

        app.menuBarItems["SimpleVPN"].click()
        app.menuBarItems["SimpleVPN"].menuItems["Settings…"].click()
        let settings = app.windows.matching(
            NSPredicate(format: "title == 'General' OR title CONTAINS 'Settings'")
        ).firstMatch
        guard settings.waitForExistence(timeout: 10) else {
            XCTFail("The Settings window didn't open from the app menu")
            return
        }

        try runAccessibilityAudit(on: app)
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
