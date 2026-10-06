// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
import Testing
@testable import SimpleVPN

struct ConnectionReservationsTests {
    @Test func overlapIsRefusedUntilCancelledWriteHasDrained() throws {
        var claims = ConnectionReservations()
        let initial = claims.reserve(owner: "virtual.a", members: ["one", "two"])
        let token = try #require(initial)
        #expect(claims.isStarting("one"))
        let overlap = claims.reserve(owner: "virtual.b", members: ["two", "three"])
        let independent = claims.reserve(owner: "profile.one", members: ["one"])
        #expect(overlap == nil && independent == nil)
        claims.cancel(member: "two")
        #expect(!claims.isCurrent(token) && !claims.isStarting("one"))
        #expect(claims.isReserved("one"))
        let whileDraining = claims.reserve(owner: "profile.one", members: ["one"])
        #expect(whileDraining == nil)
        claims.finish(token)
        let newAttempt = claims.reserve(owner: "profile.one", members: ["one"])
        let replacement = try #require(newAttempt)
        #expect(claims.isCurrent(replacement) && !claims.isCurrent(token))
    }
    @Test func cancellingCompositionDoesNotCancelAnotherIndependentStart() throws {
        var claims = ConnectionReservations()
        let first = claims.reserve(owner: "virtual.a", members: ["one", "two"])
        let second = claims.reserve(owner: "profile.three", members: ["three"])
        let composition = try #require(first)
        let other = try #require(second)
        claims.cancel(owner: "virtual.a")
        #expect(!claims.isCurrent(composition))
        #expect(claims.isCurrent(other))
        claims.finish(composition)
        #expect(claims.isStarting("three") && !claims.isReserved("two"))
    }
    @MainActor @Test func removalWaitsForWriteBeforeDeletingPreferences() async throws {
        let gate = AsyncOperationGate()
        var claims = ConnectionReservations()
        let initial = claims.reserve(owner: "virtual.a", members: ["one", "two"])
        let token = try #require(initial)
        await gate.acquire()
        var removed = false
        claims.cancel(member: "one")
        let removal = Task {
            await gate.acquire()
            removed = true
            gate.release()
        }
        for _ in 0..<10 { await Task.yield() }
        #expect(!removed && !claims.isCurrent(token))
        claims.finish(token)
        gate.release()
        await removal.value
        #expect(removed)
    }
}
