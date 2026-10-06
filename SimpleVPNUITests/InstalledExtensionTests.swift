// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
//  InstalledExtensionTests.swift
//  Installed-app UI and system-extension registration checks.
//
//  Why these differ from the other UI tests: a plain XCUIApplication() launches the
//  freshly-built copy out of DerivedData, and macOS refuses to activate a system
//  extension whose containing app isn't in /Applications — so those tests can never
//  reach the extension. A bundle identifier alone does NOT select the installed
//  copy: Xcode's UITargetAppPath must point at /Applications/SimpleVPN.app. Run
//  Tools/test-installed-app.sh after Tools/build-notarize-install.sh; it sets that
//  path explicitly. The About assertion independently checks the launched version.
//
//  The wrapper also verifies the current enabled extension registration outside
//  the UI runner's sandbox. These do NOT prove live provider IPC or packet capture.
//  They never connect a VPN — a real
//  connect needs credentials (and often a one-time code, which by definition can't
//  be automated) and would reroute the machine's traffic mid-test.
//
//  First run will raise a TCC prompt ("…wants to control SimpleVPN"): driving a
//  separate app requires Accessibility/Automation permission for the test runner.
//  Approve it once, or these tests fail to find any UI.
//

import XCTest

final class InstalledExtensionTests: XCTestCase {

    private static let installedPath = "/Applications/SimpleVPN.app"

    override func setUpWithError() throws {
        continueAfterFailure = false

        try XCTSkipUnless(FileManager.default.fileExists(atPath: Self.installedPath),
                          "SimpleVPN isn't installed in /Applications — run Tools/build-notarize-install.sh. "
                          + "A DerivedData build cannot activate the system extension.")
        try XCTSkipUnless(ProcessInfo.processInfo.environment["SIMPLEVPN_INSTALLED_UI_TEST_TARGET"] == Self.installedPath,
                          "Use Tools/test-installed-app.sh to explicitly select the installed app in the test configuration.")
    }

    /// The installed app, launched and frontmost. XCUIApplication is main-actor
    /// only and XCTest calls setUp/tearDown without isolation, so the launch (and
    /// the matching quit) belong to the test itself.
    @MainActor
    private func launchInstalledApp() throws -> XCUIApplication {
        // Use Xcode's explicitly configured target path. Initializing by bundle
        // identifier bypasses it and lets Launch Services choose a development copy.
        let app = makeSimpleVPNTestApplication()
        app.launch()
        XCTAssertTrue(app.wait(for: .runningForeground, timeout: 30),
                      "The installed app didn't come to the foreground — check the Automation permission prompt.")
        // Leave the machine as we found it: the app is a menu-bar app, so quitting
        // it is the polite end state rather than leaving windows open.
        addTeardownBlock { @MainActor in
            if app.state == .runningForeground { app.terminate() }
        }
        let (version, build) = try installedVersion(at: Self.installedPath)
        openAbout(in: app)
        let about = app.windows["about"]
        XCTAssertTrue(about.waitForExistence(timeout: 10), "About window didn't open")
        let expected = "v\(version) (build \(build))"
        // macOS can include a title-bar StaticText before the view's content.
        // Match the complete combined app identity rather than relying on ordering.
        let identity = app.staticTexts["SimpleVPN, \(expected), © 2026 James Deucker · AGPL-3.0"]
        let found = identity.waitForExistence(timeout: 5)
        if !found {
            let descriptions = about.staticTexts.allElementsBoundByIndex.map {
                "identifier=\($0.identifier) label=\($0.label) value=\(String(describing: $0.value))"
            }.joined(separator: "\n")
            let attachment = XCTAttachment(string: descriptions)
            attachment.name = "About text attributes"
            attachment.lifetime = .keepAlways
            add(attachment)
        }
        XCTAssertTrue(found, "The About identity must report installed version \(expected).")
        about.buttons[XCUIIdentifierCloseWindow].click()
        return app
    }

    /// The wrapper additionally requires the OS to report this exact installed
    /// extension as enabled; absence of a prompt alone cannot prove activation.
    @MainActor
    func testExtensionIsActivatedNotPrompting() throws {
        let app = try launchInstalledApp()
        XCTAssertFalse(app.staticTexts["System Extension Required"].exists,
                       "Approve the installed extension in System Settings, then rerun.")
        XCTAssertFalse(app.staticTexts["Open the Installed SimpleVPN"].exists,
                       "The test launched a development copy instead of the installed app.")
    }

    /// Positive installed-build identity, checked by the launch helper in About.
    /// A provider IPC test needs a separate connected disposable session.
    @MainActor
    func testInstalledAppReportsItsBuild() throws {
        _ = try launchInstalledApp()
    }

    /// Network Tools drives the native probes (ICMP/DNS/MTU) in the APP process, not
    /// the extension — but it's the surface most likely to regress, and a loopback
    /// target keeps it off the network and away from anything we don't own.
    @MainActor
    func testNetworkToolsRunsAgainstLoopback() throws {
        let app = try launchInstalledApp()
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

    private func installedVersion(at path: String) throws -> (String, String) {
        let data = try Data(contentsOf: URL(fileURLWithPath: path).appendingPathComponent("Contents/Info.plist"))
        let info = try XCTUnwrap(PropertyListSerialization.propertyList(from: data, format: nil) as? [String: Any])
        return (try XCTUnwrap(info["CFBundleShortVersionString"] as? String),
                try XCTUnwrap(info["CFBundleVersion"] as? String))
    }

    /// About lives under the app menu; use the menu rather than a private URL so the
    /// test exercises the same path a user takes.
    @MainActor
    private func openAbout(in app: XCUIApplication) {
        let appMenu = app.menuBars.menuBarItems.element(boundBy: 1)   // 0 is Apple
        appMenu.click()
        // firstMatch: "About SimpleVPN" appears both in the app menu and (as the
        // CommandGroup(replacing: .appInfo) button) elsewhere in the hierarchy, so an
        // exact query is ambiguous and throws.
        app.menuItems["About SimpleVPN"].firstMatch.click()
    }
}
