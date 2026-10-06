// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only

import XCTest

/// One deterministic launch contract for every UI-test suite.
///
/// Accessibility, navigation and installed-extension checks do not need to read
/// another application's protected files. Leaving that live scan enabled makes
/// macOS present a Files and Folders consent sheet that XCUITest cannot reliably
/// own or dismiss, so the app never becomes idle and the useful assertions never
/// run. The privacy prompt itself remains a clean-TCC, human verification.
@MainActor
func makeSimpleVPNTestApplication() -> XCUIApplication {
    // Honor the test configuration's UITargetAppPath, including installed-app
    // checks. Bundle-identifier lookup can select a different development copy.
    let app = XCUIApplication()
    app.launchEnvironment["SIMPLEVPN_UI_TEST_SUPPRESS_PROTECTED_FILE_SCAN"] = "1"
    // Do not resurrect a file panel or secondary window left by a previous run.
    app.launchArguments += ["-ApplePersistenceIgnoreState", "YES"]
    return app
}
