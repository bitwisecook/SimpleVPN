// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
import Foundation

/// FIFO ownership across actor suspension points. Unlike plan reconciliation,
/// destructive configuration operations must finish before the next can start.
@MainActor
final class AsyncOperationGate {
    private var held = false
    private var waiters: [CheckedContinuation<Void, Never>] = []
    func acquire() async {
        if !held { held = true; return }
        await withCheckedContinuation { waiters.append($0) }
    }
    func release() {
        if waiters.isEmpty { held = false }
        else { waiters.removeFirst().resume() }
    }
}
