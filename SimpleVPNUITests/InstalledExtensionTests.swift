// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
//  InstalledExtensionTests.swift
//  End-to-end checks that exercise the REAL system extension.
//
//  Why these differ from the other UI tests: a plain XCUIApplication() launches the
//  freshly-built copy out of DerivedData, and macOS refuses to activate a system
//  extension whose containing app isn't in /Applications — so those tests can never
//  reach the extension. Initialising with `bundleIdentifier:` attaches to the
//  INSTALLED, signed, notarized /Applications copy instead, which is the only build
//  whose extension can actually load. Run Tools/build-notarize-install.sh first.
//
//  What these assert is deliberately non-destructive: that the extension ACTIVATED
//  and that the app↔extension IPC round-trips. They never connect a VPN — a real
//  connect needs credentials (and often a one-time code, which by definition can't
//  be automated) and would reroute the machine's traffic mid-test.
//
//  First run will raise a TCC prompt ("…wants to control SimpleVPN"): driving a
//  separate app requires Accessibility/Automation permission for the test runner.
//  Approve it once, or these tests fail to find any UI.
//

import XCTest

final class InstalledExtensionTests: XCTestCase {

    private static let bundleID = "com.bragi0.SimpleVPN"
    private static let installedPath = "/Applications/SimpleVPN.app"

    private var app: XCUIApplication!

    override func setUpWithError() throws {
        continueAfterFailure = false

        try XCTSkipUnless(FileManager.default.fileExists(atPath: Self.installedPath),
                          "SimpleVPN isn't installed in /Applications — run Tools/build-notarize-install.sh. "
                          + "A DerivedData build cannot activate the system extension.")

        app = XCUIApplication(bundleIdentifier: Self.bundleID)
        app.launch()
        XCTAssertTrue(app.wait(for: .runningForeground, timeout: 30),
                      "The installed app didn't come to the foreground — check the Automation permission prompt.")
    }

    override func tearDownWithError() throws {
        // Leave the machine as we found it: the app is a menu-bar app, so quitting
        // it is the polite end state rather than leaving windows open.
        if app?.state == .runningForeground { app.terminate() }
    }

    /// The extension activated: the app is NOT showing its "System Extension
    /// Required" prompt. That prompt is the app's own gate (ExtensionController
    /// .isActivated), so its absence is a real signal, not a guess.
    @MainActor
    func testExtensionIsActivatedNotPrompting() throws {
        let prompt = app.staticTexts["System Extension Required"]
        // Give activation a moment: on a fresh install the OS may still be loading it.
        let appeared = prompt.waitForExistence(timeout: 8)
        XCTAssertFalse(appeared,
                       "The app is asking for the system extension to be activated. "
                       + "If this is a brand-new build, approve it in System Settings ▸ General ▸ Login Items & Extensions, then re-run.")
    }

    /// The strongest non-destructive proof that the extension is alive: the About
    /// window reports its version, which the app can only know by asking the
    /// extension over IPC (sendProviderMessage("version")). "unavailable" means the
    /// round-trip failed even though the extension may be registered.
    @MainActor
    func testExtensionVersionRoundTripsOverIPC() throws {
        openAbout()

        let about = app.windows["About SimpleVPN"]
        XCTAssertTrue(about.waitForExistence(timeout: 10), "About window didn't open")

        // The About box shows "System extension: <version>" only via the IPC reply.
        let unavailable = about.staticTexts.containing(
            NSPredicate(format: "value CONTAINS[c] %@ OR label CONTAINS[c] %@", "unavailable", "unavailable"))
        XCTAssertEqual(unavailable.count, 0,
                       "The extension version came back 'unavailable' — the app could not reach the extension over IPC. "
                       + "The extension may be registered but not running.")
    }

    /// Network Tools drives the native probes (ICMP/DNS/MTU) in the APP process, not
    /// the extension — but it's the surface most likely to regress, and a loopback
    /// target keeps it off the network and away from anything we don't own.
    @MainActor
    func testNetworkToolsRunsAgainstLoopback() throws {
        app.typeKey("t", modifierFlags: [.command, .shift])   // VPN ▸ Network Tools…

        let tools = app.windows["Network Tools"]
        XCTAssertTrue(tools.waitForExistence(timeout: 10), "Network Tools window didn't open")

        let field = tools.textFields.firstMatch
        XCTAssertTrue(field.waitForExistence(timeout: 5), "target field missing")
        field.click()
        field.typeText("127.0.0.1\r")

        // The Path railroad appears once anything resolves; that's enough to prove
        // the probe pipeline ran without asserting on live network numbers.
        XCTAssertTrue(tools.staticTexts["Path"].waitForExistence(timeout: 20),
                      "no probe results appeared for a loopback target")
    }

    // MARK: Helpers

    /// About lives under the app menu; use the menu rather than a private URL so the
    /// test exercises the same path a user takes.
    @MainActor
    private func openAbout() {
        let appMenu = app.menuBars.menuBarItems.element(boundBy: 1)   // 0 is Apple
        appMenu.click()
        // firstMatch: "About SimpleVPN" appears both in the app menu and (as the
        // CommandGroup(replacing: .appInfo) button) elsewhere in the hierarchy, so an
        // exact query is ambiguous and throws.
        app.menuItems["About SimpleVPN"].firstMatch.click()
    }
}
