// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
import Testing
@testable import SimpleVPN

@MainActor struct AsyncOperationGateTests {
    @Test func destructiveOperationWaitsForSuspendedWriterToFinish() async {
        let gate = AsyncOperationGate()
        await gate.acquire()
        var removed = false
        let remove = Task {
            await gate.acquire()
            removed = true
            gate.release()
        }
        for _ in 0..<10 { await Task.yield() }
        #expect(!removed)
        gate.release()
        await remove.value
        #expect(removed)
        // The final release must allow subsequent ownership immediately.
        await gate.acquire()
        gate.release()
    }
}
