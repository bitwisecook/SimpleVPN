// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
import Testing
@testable import SimpleVPN

struct SampleRevisionFenceTests {
    @Test func delayedSampleCannotUndoAnAcknowledgedRouteSwitchOrSessionEnd() {
        var fence = SampleRevisionFence()
        let beforeSwitch = fence.revision
        #expect(fence.accepts(beforeSwitch))
        fence.invalidate()
        #expect(!fence.accepts(beforeSwitch))
        let afterSwitch = fence.revision
        #expect(fence.accepts(afterSwitch))
        fence.invalidate()
        #expect(!fence.accepts(afterSwitch))
        #expect(fence.accepts(fence.revision))
    }
}
