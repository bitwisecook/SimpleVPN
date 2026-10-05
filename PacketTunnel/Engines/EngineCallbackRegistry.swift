// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
import Foundation

/// C callbacks carry integers, never unretained Swift pointers. Old contexts
/// never resolve to a restart, and registrations cannot keep failed engines alive.
nonisolated final class EngineCallbackRegistry<Engine: AnyObject>: @unchecked Sendable {
    static func handle(from response: String?) -> UInt64 {
        guard let data = response?.data(using: .utf8),
              let object = try? JSONSerialization.jsonObject(with: data) as? [String: Any],
              object["ok"] as? Bool == true,
              let handle = object["handle"] as? NSNumber else { return 0 }
        return handle.uint64Value
    }
    private final class Entry {
        weak var engine: Engine?
        init(_ engine: Engine) { self.engine = engine }
    }
    private let lock = NSLock()
    private var next: UInt64 = 0
    private var entries: [UInt64: Entry] = [:]
    func register(_ engine: Engine) -> UInt64 {
        lock.withLock {
            next += 1
            entries[next] = Entry(engine)
            return next
        }
    }
    func lookup(_ context: UInt64) -> Engine? { lock.withLock { entries[context]?.engine } }
    func remove(_ context: UInt64) { _ = lock.withLock { entries.removeValue(forKey: context) } }
}
