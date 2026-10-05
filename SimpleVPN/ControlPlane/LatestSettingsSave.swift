// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only

import Foundation
import Observation

/// Editors enqueue a validated value snapshot even while a previous save awaits
/// preferences. Keep the latest snapshot; stale completions cannot rewrite the UI.
@MainActor
@Observable
final class LatestSettingsSave {
    private(set) var isApplying = false
    @ObservationIgnored private let loop = MediatorApplyLoop<UUID>()
    var requestedRevision: UInt64 { loop.requestedRevision }

    func submit(_ operation: @escaping @MainActor (@MainActor () -> Bool) async -> Void) async {
        isApplying = true
        loop.enqueue(UUID()) { [weak self] _, _, revision in
            guard let self else { return false }
            await operation { self.loop.isCurrent(revision) }
            if self.loop.isCurrent(revision) { self.isApplying = false }
            return true
        }
        await loop.waitUntilIdle()
    }
}
