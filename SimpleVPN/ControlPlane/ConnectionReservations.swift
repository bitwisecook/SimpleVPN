// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only

/// Claims profiles before an asynchronous configuration write. Cancellation
/// invalidates the attempt but retains its claim until that write has drained.
nonisolated struct ConnectionReservations {
    private struct Attempt {
        let owner: String
        let members: Set<String>
        var cancelled = false
    }
    private var next: UInt64 = 0
    private var attempts: [UInt64: Attempt] = [:]

    mutating func reserve(owner: String, members: Set<String>) -> UInt64? {
        guard !members.isEmpty, !attempts.values.contains(where: {
            $0.owner == owner || !$0.members.isDisjoint(with: members)
        }) else { return nil }
        next += 1
        attempts[next] = Attempt(owner: owner, members: members)
        return next
    }
    func isReserved(_ member: String) -> Bool { attempts.values.contains { $0.members.contains(member) } }
    func isStarting(_ member: String) -> Bool {
        attempts.values.contains { !$0.cancelled && $0.members.contains(member) }
    }
    func isCurrent(_ token: UInt64) -> Bool { attempts[token]?.cancelled == false }
    mutating func cancel(member: String) {
        for token in attempts.keys where attempts[token]?.members.contains(member) == true {
            attempts[token]?.cancelled = true
        }
    }
    mutating func cancel(owner: String) {
        for token in attempts.keys where attempts[token]?.owner == owner { attempts[token]?.cancelled = true }
    }
    mutating func finish(_ token: UInt64) { attempts[token] = nil }
}
