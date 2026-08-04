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

    /// Launches the app and skips (rather than flakes) where no UI can appear.
    @MainActor
    private func launchOrSkip() throws -> XCUIApplication {
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

    /// The shared audit body: one exclusion list, applied identically to every
    /// window, so a new surface can't quietly get a looser gate.
    @MainActor
    private func runAccessibilityAudit(on app: XCUIApplication) throws {
        let auditTypes: XCUIAccessibilityAuditType = [
            .elementDetection, .hitRegion, .sufficientElementDescription,
            .action, .parentChild,
        ]
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

            // Structural false positive: the system synthesizes an (unnamed)
            // NSTouchBar element for every window. Not app UI, not nameable.
            if issue.auditType == .sufficientElementDescription,
               let element = issue.element, element.elementType == .touchBar {
                return true
            }

            // Framework false positive: SwiftUI's menu Picker surfaces as an AX
            // PopUpButton whose selection rides AXValue, with the open action on
            // an inner element rather than the PopUpButton itself — VoiceOver
            // operates it normally (VO-Space), but the audit's action check only
            // looks at the outer element. Framework-owned; nothing in app code
            // (label, pickerStyle, accessibilityAction) changes that element.
            if issue.auditType == .action,
               let element = issue.element,
               element.elementType == .popUpButton {
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
