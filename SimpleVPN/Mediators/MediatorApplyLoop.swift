// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only

import Foundation

/// One writer across suspension points. New requests replace the pending plan,
/// never the running task. A superseded operation must check its revision before
/// granting ownership or publishing success. Force survives pending coalescing.
@MainActor
final class MediatorApplyLoop<Plan: Sendable & Equatable> {
    typealias Apply = @MainActor (Plan, Bool, UInt64) async -> Bool
    private struct Pending {
        let plan: Plan
        let revision: UInt64
        let force: Bool
        let apply: Apply
    }
    private var activeForce = false
    private var pending: Pending?
    private var worker: Task<Void, Never>?
    private(set) var requestedRevision: UInt64 = 0
    private(set) var appliedRevision: UInt64 = 0

    @discardableResult
    func enqueue(_ plan: Plan, force: Bool = false, apply: @escaping Apply) -> UInt64 {
        requestedRevision += 1
        pending = Pending(plan: plan, revision: requestedRevision,
                          force: force || activeForce || (pending?.force ?? false), apply: apply)
        if worker == nil {
            worker = Task { [weak self] in
                guard let self else { return }
                await self.drain()
            }
        }
        return requestedRevision
    }

    func isCurrent(_ revision: UInt64) -> Bool { revision == requestedRevision }

    func waitUntilIdle() async {
        while let worker { await worker.value }
    }

    private func drain() async {
        while let next = pending {
            pending = nil
            activeForce = next.force
            let success = await next.apply(next.plan, next.force, next.revision)
            if success, isCurrent(next.revision) { appliedRevision = next.revision }
        }
        activeForce = false
        worker = nil
    }
}
