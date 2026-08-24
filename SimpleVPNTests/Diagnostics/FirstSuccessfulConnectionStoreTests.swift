// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only

import Foundation
import Testing
@testable import SimpleVPN

struct FirstSuccessfulConnectionStoreTests {
    @Test func successMarkerSurvivesWithoutWaitingForDiagnostics() {
        let profile = "FirstSuccessfulConnectionStoreTests.\(UUID().uuidString)"
        defer { FirstSuccessfulConnectionStore.clear(profile: profile) }

        #expect(!FirstSuccessfulConnectionStore.hasSucceeded(profile: profile))
        FirstSuccessfulConnectionStore.markSucceeded(profile: profile)
        #expect(FirstSuccessfulConnectionStore.hasSucceeded(profile: profile))
    }

    @Test func existingDiagnosticBaselineMigratesToTheSuccessAnswer() {
        let profile = "FirstSuccessfulConnectionStoreTests.\(UUID().uuidString)"
        defer {
            FirstSuccessfulConnectionStore.clear(profile: profile)
            ConnectionBaselineStore.clear(profile: profile)
        }

        ConnectionBaselineStore.save(ConnectionBaseline(serverIP: nil, date: .now), profile: profile)
        #expect(FirstSuccessfulConnectionStore.hasSucceeded(profile: profile),
                "existing users should not see first-connect coaching again after updating")
    }
}
