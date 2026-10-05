// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
import Foundation
import Testing
@testable import SimpleVPN

@MainActor
struct LatestSettingsSaveTests {
    @Test func editsDuringSaveKeepLatestSnapshotAndRejectStaleUICompletion() async {
        let queue = LatestSettingsSave()
        let entered = AsyncStream<Void>.makeStream()
        var events = entered.stream.makeAsyncIterator()
        var release: CheckedContinuation<Void, Never>?
        var stored: [String] = []
        var displayed = "latest"
        let first = Task {
            await queue.submit { isCurrent in
                stored.append("old")
                await withCheckedContinuation { release = $0; entered.continuation.yield(()) }
                if isCurrent() { displayed = "old" }
            }
        }
        await events.next()
        let pending = Task {
            await queue.submit { isCurrent in
                stored.append("latest")
                if isCurrent() { displayed = "latest" }
            }
        }
        // Enqueue the latest edit on MainActor before releasing the first writer.
        while queue.requestedRevision < 2 { await Task.yield() }
        release?.resume()
        await first.value
        await pending.value
        #expect(stored == ["old", "latest"])
        #expect(displayed == "latest")
        #expect(!queue.isApplying)
    }
}
