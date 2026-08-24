// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only

import Foundation
import Testing

@testable import SimpleVPN

@MainActor
struct AppDelegateLaunchTests {
    @Test("a developer build cannot suppress the installed app")
    func onlyTheSameInstallationCountsAsADuplicate() {
        let installed = URL(fileURLWithPath: "/Applications/SimpleVPN.app")
        let developerBuild = URL(fileURLWithPath:
            "/Users/tester/Library/Developer/Xcode/DerivedData/SimpleVPN/Build/Products/Debug/SimpleVPN.app")

        #expect(AppDelegate.isSameInstallation(
            ourBundleURL: installed,
            otherBundleURL: installed))
        #expect(!AppDelegate.isSameInstallation(
            ourBundleURL: installed,
            otherBundleURL: developerBuild))
        #expect(!AppDelegate.isSameInstallation(
            ourBundleURL: installed,
            otherBundleURL: nil))
    }
}
