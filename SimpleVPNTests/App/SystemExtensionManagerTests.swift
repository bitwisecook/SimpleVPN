// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only

import Foundation
import Testing
@testable import SimpleVPN

@Suite("System extension location")
struct SystemExtensionManagerTests {
    @Test("activation is only eligible from the system Applications folder")
    func activationLocation() {
        #expect(SystemExtensionManager.isEligibleForActivation(
            bundleURL: URL(fileURLWithPath: "/Applications/SimpleVPN.app")))
        #expect(!SystemExtensionManager.isEligibleForActivation(
            bundleURL: URL(fileURLWithPath: "/Users/example/Library/Developer/Xcode/DerivedData/SimpleVPN.app")))
    }
}
