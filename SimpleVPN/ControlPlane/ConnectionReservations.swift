// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only

import NetworkExtension

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
    private var submitted: [String: (token: UInt64, initialStatus: NEVPNStatus)] = [:]

    mutating func reserve(owner: String, members: Set<String>) -> UInt64? {
        guard !members.isEmpty, !members.contains(where: { submitted[$0] != nil }), !attempts.values.contains(where: {
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
    func isStarting(owner: String) -> Bool { attempts.values.contains { !$0.cancelled && $0.owner == owner } }
    func isCurrent(_ token: UInt64) -> Bool { attempts[token]?.cancelled == false }
    mutating func cancel(member: String) {
        submitted[member] = nil
        for token in attempts.keys where attempts[token]?.members.contains(member) == true {
            attempts[token]?.cancelled = true
        }
    }
    mutating func cancel(owner: String) {
        for token in attempts.keys where attempts[token]?.owner == owner { attempts[token]?.cancelled = true }
    }
    mutating func finish(_ token: UInt64) { attempts[token] = nil }

    /// Network Extension accepts a start request before publishing its first status.
    mutating func didSubmit(_ member: String, from status: NEVPNStatus) -> UInt64? {
        guard status == .disconnected || status == .invalid else { return nil }
        next += 1
        submitted[member] = (next, status)
        return next
    }

    mutating func expireSubmission(_ token: UInt64, for member: String) -> Bool {
        guard submitted[member]?.token == token else { return false }
        submitted[member] = nil
        return true
    }

    mutating func status(for member: String, reported: NEVPNStatus) -> NEVPNStatus {
        if let submission = submitted[member] {
            if reported == submission.initialStatus { return .connecting }
            submitted[member] = nil
            return reported
        }
        if (reported == .disconnected || reported == .invalid), isStarting(member) {
            return .connecting
        }
        return reported
    }
}
