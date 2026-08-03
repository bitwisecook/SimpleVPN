// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
//  SCStoreMonitor.swift
//  The Stage-4 monitor (Docs/StateMediators.md) shared by the DNS (P2) and Proxy (P3)
//  mediators: an `SCDynamicStore` watch on a set of System-Configuration keys that
//  reports EXTERNAL changes (another VPN client, `scutil`/`networksetup`, macOS
//  reconfiguration) so a mediator can diff-vs-expected and re-assert on genuine drift.
//
//  WHY shared: the DNS monitor watches `State:/Network/Global/DNS` + per-service DNS
//  keys; the Proxy monitor watches `State:/Network/Global/Proxies` + per-service proxy
//  keys. Same machinery, different keys and different snapshot — so it is one generic
//  monitor parameterized by (keys, patterns, snapshot), not two copies of the
//  callback/isolation code.
//
//  ISOLATION (load-bearing — identical to PFRouteMonitor): the app target defaults to
//  `@MainActor` isolation, and a class-level `nonisolated` does NOT propagate to
//  methods OR stored properties. The `SCDynamicStore` callback fires on our dedicated
//  dispatch queue (via `SCDynamicStoreSetDispatchQueue`), OFF the main actor; if any
//  member stayed implicitly `@MainActor`, Swift 6 would trap on the executor check
//  (`swift_task_isCurrentExecutor` → `dispatch_assert_queue`). So EVERY member here is
//  explicitly `nonisolated`, each lock-guarded mutable stored property is
//  `nonisolated(unsafe)` (guarded by an `NSLock`), and every dispatch/callback closure
//  is `@Sendable`. The mediator hops to main to publish.
//

import Foundation
import SystemConfiguration

/// The C `SCDynamicStore` callback cannot be a Swift closure or capture context, so the
/// `info` pointer carries a retained box holding a `@Sendable` "fire" closure. The
/// callback just retrieves the box and invokes it — no generics cross the C boundary.
private final class SCStoreCallbackBox: Sendable {
    let fire: @Sendable () -> Void
    nonisolated init(fire: @escaping @Sendable () -> Void) { self.fire = fire }
}

/// A listen-only `SCDynamicStore` monitor. `Observation` is whatever the owning
/// mediator wants snapshotted when the watched keys change (the current resolvers, the
/// current system proxy). Conforms to `MediatorMonitor` so it slots into the generic
/// mediator shape exactly like `PFRouteMonitor`.
final class SCStoreMonitor<Observation: Sendable>: MediatorMonitor, @unchecked Sendable {
    // @unchecked Sendable: every mutable field is guarded by `lock`; the SC callback is
    // a C function that only touches the retained box.

    private let label: String
    private let keys: [String]        // exact SCDynamicStore keys to watch
    private let patterns: [String]    // key PATTERNS (per-service wildcards)
    private let debounceMS: Int
    /// Snapshots the resource the moment a change has settled. `@Sendable` — it runs on
    /// `queue`, off the main actor.
    private let snapshot: @Sendable () -> Observation

    private let queue: DispatchQueue
    private let lock = NSLock()
    // Mutated only under `lock`, so `nonisolated(unsafe)` is the honest annotation: it
    // opts these out of the target's default @MainActor isolation (a class-level
    // `nonisolated` does NOT), which is what lets the off-actor SC handler touch them.
    nonisolated(unsafe) private var store: SCDynamicStore?
    nonisolated(unsafe) private var box: SCStoreCallbackBox?
    nonisolated(unsafe) private var generation: UInt64 = 0
    nonisolated(unsafe) private var onDrift: (@Sendable (Observation) -> Void)?

    nonisolated init(label: String, keys: [String], patterns: [String],
                     debounce: Duration = .milliseconds(300),
                     snapshot: @escaping @Sendable () -> Observation) {
        self.label = label
        self.keys = keys
        self.patterns = patterns
        self.snapshot = snapshot
        self.queue = DispatchQueue(label: label)
        let ms = debounce.components.seconds * 1_000
            + debounce.components.attoseconds / 1_000_000_000_000_000
        self.debounceMS = Int(max(0, ms))
    }

    deinit { stop() }

    nonisolated var isRunning: Bool { lock.withLock { store != nil } }

    /// Open the store and begin watching. Idempotent.
    nonisolated func start(onDrift: @escaping @Sendable (Observation) -> Void) throws {
        lock.lock()
        guard store == nil else { lock.unlock(); return }
        self.onDrift = onDrift
        lock.unlock()

        // The box holds the debounced snapshot-and-report closure; the C callback only
        // reaches through `info` to call it.
        let box = SCStoreCallbackBox(fire: { [weak self] in self?.scheduleCallback() })
        var context = SCDynamicStoreContext(version: 0, info: Unmanaged.passUnretained(box).toOpaque(),
                                            retain: nil, release: nil, copyDescription: nil)
        let callback: SCDynamicStoreCallBack = { _, _, info in
            guard let info else { return }
            let box = Unmanaged<SCStoreCallbackBox>.fromOpaque(info).takeUnretainedValue()
            box.fire()
        }
        guard let store = SCDynamicStoreCreate(nil, label as CFString, callback, &context) else {
            throw MediatorMonitorError.storeCreateFailed
        }
        SCDynamicStoreSetNotificationKeys(store, keys as CFArray, patterns as CFArray)
        SCDynamicStoreSetDispatchQueue(store, queue)

        lock.lock()
        if self.store == nil {
            self.store = store
            self.box = box
            lock.unlock()
        } else {
            lock.unlock()
            SCDynamicStoreSetDispatchQueue(store, nil)   // lost a start() race
        }
    }

    nonisolated func stop() {
        let doomed: SCDynamicStore? = lock.withLock {
            generation &+= 1
            defer { store = nil; box = nil; onDrift = nil }
            return store
        }
        if let doomed { SCDynamicStoreSetDispatchQueue(doomed, nil) }
    }

    /// A watched key changed. Debounce (SC fires several keys per reconfiguration),
    /// then snapshot the settled state and hand it up.
    nonisolated private func scheduleCallback() {
        let scheduled: UInt64 = lock.withLock { generation &+= 1; return generation }
        let work: @Sendable () -> Void = { [weak self] in
            guard let self else { return }
            let (current, callback) = self.lock.withLock {
                (self.generation == scheduled && self.store != nil, self.onDrift)
            }
            guard current, let callback else { return }   // superseded or stopped
            callback(self.snapshot())
        }
        queue.asyncAfter(deadline: .now() + .milliseconds(debounceMS), execute: work)
    }
}

nonisolated enum MediatorMonitorError: Error, Sendable {
    case storeCreateFailed
}
