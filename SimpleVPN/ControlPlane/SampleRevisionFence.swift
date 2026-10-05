// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only

/// A telemetry request begun before an acknowledged mutation cannot restore the
/// earlier network state when its reply arrives late. No wall-clock comparison.
nonisolated struct SampleRevisionFence {
    private(set) var revision: UInt64 = 0
    mutating func invalidate() { revision += 1 }
    func accepts(_ captured: UInt64) -> Bool { captured == revision }
}
