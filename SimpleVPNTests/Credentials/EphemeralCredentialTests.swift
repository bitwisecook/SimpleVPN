// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
//  EphemeralCredentialTests.swift
//  The two programme-wide credential-lifecycle primitives, tested with NO vendor
//  and NO hardware anywhere in sight — which is the point of them living in
//  EphemeralCredential.swift rather than beside the feature that first needed them.
//
//  What these pin down is not arithmetic for its own sake. `SingleUseCode` is the
//  structural version of "a consumed one-time credential is never silently
//  retried", and every claim that makes is asserted here:
//    • consume() answers once and nil for ever after, including under a race;
//    • an expired box answers nil even to a first caller — fail CLOSED;
//    • an expiry check EMPTIES the box, so a later caller cannot get it either;
//    • discard() is final;
//    • the type has no path to text at all (no Codable, no description) — pinned
//      by a conformance test, because that guarantee is what stops a secret
//      reaching a log line, and someone will one day be tempted to add one.
//
//  `InteractionWait` is the deadline/cancel/timeout arithmetic every source that
//  waits on a human shares. Its edges are the ones that bite: tick fires exactly
//  once, cancel stops the clock, a countdown never shows 0 while still running, and
//  the grace window after completion is half-open.
//

import Foundation
import Testing
@testable import SimpleVPN

struct SingleUseCodeTests {

    // MARK: Read once, and only once

    @Test func consumeAnswersOnceThenNilForEver() {
        let box = SingleUseCode("hunter2")
        #expect(box.isSpent() == false)
        #expect(box.consume() == "hunter2")
        #expect(box.isSpent())
        #expect(box.consume() == nil)
        #expect(box.consume() == nil)
    }

    @Test func discardIsFinalAndLeavesNothingToConsume() {
        let box = SingleUseCode("hunter2")
        box.discard()
        #expect(box.isSpent())
        #expect(box.consume() == nil)
    }

    /// The case the lock is FOR: two connect attempts racing for the same code.
    /// Exactly one may win, whatever the interleaving — a second winner is a
    /// duplicate authentication attempt with a burned credential.
    @Test func onlyOneOfManyConcurrentConsumersWins() async {
        let box = SingleUseCode("only-once")
        let winners = await withTaskGroup(of: String?.self, returning: Int.self) { group in
            for _ in 0..<64 {
                group.addTask { box.consume() }
            }
            var count = 0
            for await value in group where value != nil { count += 1 }
            return count
        }
        #expect(winners == 1)
    }

    @Test func lengthIsReadableButTheValueIsNot() {
        let box = SingleUseCode("123456")
        #expect(box.characterCount == 6)
        _ = box.consume()
        // A spent box has no length either — nothing lingers to hint at it.
        #expect(box.characterCount == 0)
    }

    // MARK: Time-bounded as well as single-use

    @Test func anExpiredBoxAnswersNilEvenToItsFirstCaller() {
        let issued = Date(timeIntervalSince1970: 1_000_000)
        let box = SingleUseCode("123456", origin: .computedByDevice,
                               expiresAt: issued.addingTimeInterval(30))
        #expect(box.consume(now: issued.addingTimeInterval(31)) == nil)
    }

    /// Fail CLOSED at the boundary. A code handed over at the exact instant its
    /// window ends will be rejected by the server, and "it ran out" is a far better
    /// thing to tell someone than "rejected".
    @Test func expiryBoundaryIsInclusive() {
        let issued = Date(timeIntervalSince1970: 1_000_000)
        let expires = issued.addingTimeInterval(30)
        #expect(SingleUseCode("1", expiresAt: expires).consume(now: expires) == nil)
        #expect(SingleUseCode("1", expiresAt: expires)
            .consume(now: expires.addingTimeInterval(-0.001)) == "1")
    }

    /// An expiry check must not merely refuse — it must EMPTY the box, so a caller
    /// that asks again with an earlier clock (a clock adjustment, a stale `now`
    /// captured in a closure) still cannot get the value out.
    @Test func askingAfterExpiryDestroysTheValue() {
        let issued = Date(timeIntervalSince1970: 1_000_000)
        let box = SingleUseCode("123456", expiresAt: issued.addingTimeInterval(30))
        #expect(box.consume(now: issued.addingTimeInterval(60)) == nil)
        // …and now even an in-window read gets nothing.
        #expect(box.consume(now: issued.addingTimeInterval(1)) == nil)
    }

    @Test func expiryIsReportedSeparatelyFromBeingUsed() {
        let issued = Date(timeIntervalSince1970: 1_000_000)
        let expiring = SingleUseCode("1", expiresAt: issued.addingTimeInterval(30))
        #expect(expiring.isExpired(now: issued) == false)
        #expect(expiring.isExpired(now: issued.addingTimeInterval(31)))
        #expect(expiring.secondsRemaining(now: issued) == 30)
        // Rounded UP, so a countdown never reads 0 while it is still valid.
        #expect(expiring.secondsRemaining(now: issued.addingTimeInterval(29.2)) == 1)
        // Never negative.
        #expect(expiring.secondsRemaining(now: issued.addingTimeInterval(90)) == 0)

        let plain = SingleUseCode("1")
        #expect(plain.isExpired(now: issued) == false)
        #expect(plain.secondsRemaining(now: issued) == nil)
    }

    @Test func aSpentBoxCountsAsSpentRegardlessOfExpiry() {
        let issued = Date(timeIntervalSince1970: 1_000_000)
        let box = SingleUseCode("1", expiresAt: issued.addingTimeInterval(30))
        _ = box.consume(now: issued)
        #expect(box.isSpent(now: issued))
        #expect(box.isExpired(now: issued) == false)   // used, not expired
    }

    // MARK: The guarantees that are about the TYPE, not its behaviour

    /// The reason a secret in this box cannot reach a log line, a defaults key or
    /// `providerConfiguration` is that the type offers no route to text and no
    /// route to serialisation. Asserted rather than assumed, because the whole
    /// no-leak claim rests on it and adding `CustomStringConvertible` for
    /// "debugging" would quietly undo it.
    @Test func theTypeHasNoRouteToTextOrSerialisation() {
        let box: Any = SingleUseCode("hunter2")
        #expect(box is CustomStringConvertible == false)
        #expect(box is CustomDebugStringConvertible == false)
        #expect(box is any Encodable == false)
        #expect(box is any Decodable == false)
    }

    /// Publishable identifying information rides `publicLabel`, and it is the ONLY
    /// thing about the box that may be shown. Nothing about the secret leaks into
    /// it — the label is supplied by the caller from data that is public by design
    /// (a Yubico public ID).
    @Test func thePublicLabelSurvivesConsumptionBecauseItIsNotSecret() {
        let box = SingleUseCode("ccccccjjbbbbcccccccccccccccccccccccccccccccc",
                                origin: .typedByDevice, publicLabel: "ccccccjjbbbb")
        _ = box.consume()
        #expect(box.publicLabel == "ccccccjjbbbb")
        #expect(box.origin == .typedByDevice)
    }

    /// `SecretOrigin` is extensible by any feed in its own file, which is why it is
    /// a RawRepresentable struct and not an enum. Distinctness matters only so two
    /// sources cannot accidentally claim the same wording.
    @Test func originsAreDistinctAndExtensible() {
        let known: [SecretOrigin] = [.typedByUser, .typedByDevice, .computedByDevice,
                                     .fetchedFromVault, .derivedLocally]
        #expect(Set(known).count == known.count)
        // A later feed adds its own without touching the shared file.
        let mine = SecretOrigin(rawValue: "some-future-vault")
        #expect(!known.contains(mine))
    }
}

struct InteractionWaitTests {

    private let t0 = Date(timeIntervalSince1970: 2_000_000)

    @Test func startsIdle() {
        let wait = InteractionWait()
        #expect(wait.phase == .idle)
        #expect(wait.isWaiting == false)
        #expect(wait.secondsRemaining(now: t0) == 0)
    }

    @Test func armingStartsTheClock() {
        var wait = InteractionWait()
        wait.arm(now: t0, wait: 30)
        #expect(wait.isWaiting)
        #expect(wait.startedAt == t0)
        #expect(wait.secondsRemaining(now: t0) == 30)
        #expect(wait.secondsRemaining(now: t0.addingTimeInterval(29.4)) == 1)
    }

    /// A countdown that reads 0 while the wait is still live tells the user it has
    /// given up when it hasn't.
    @Test func theCountdownNeverReadsZeroWhileStillRunning() {
        var wait = InteractionWait()
        wait.arm(now: t0, wait: 30)
        for elapsed in stride(from: 0.0, to: 29.99, by: 0.37) {
            #expect(wait.secondsRemaining(now: t0.addingTimeInterval(elapsed)) >= 1)
        }
    }

    /// `tick` must report the expiry EXACTLY once — a caller announces on it, and
    /// announcing "no code arrived" once a second is worse than not announcing.
    @Test func tickFiresOnceAndOnlyOnce() {
        var wait = InteractionWait()
        wait.arm(now: t0, wait: 10)
        // Hoisted out of #expect: the macro captures its expression in a closure,
        // which cannot call a mutating method on a local var.
        let early = wait.tick(now: t0.addingTimeInterval(5))
        #expect(early == false)
        let expired = wait.tick(now: t0.addingTimeInterval(10))
        #expect(expired)
        #expect(wait.phase == .timedOut)
        let again = wait.tick(now: t0.addingTimeInterval(11))
        #expect(again == false)
        let muchLater = wait.tick(now: t0.addingTimeInterval(99))
        #expect(muchLater == false)
    }

    @Test func cancelStopsTheClockAndIsDistinctFromATimeout() {
        var wait = InteractionWait()
        wait.arm(now: t0, wait: 10)
        wait.cancel()
        #expect(wait.phase == .cancelled)
        #expect(wait.isWaiting == false)
        // A cancelled wait must never later report a timeout — the user already
        // decided, and two outcomes for one wait is two announcements.
        let afterCancel = wait.tick(now: t0.addingTimeInterval(999))
        #expect(afterCancel == false)
        #expect(wait.phase == .cancelled)
    }

    @Test func completingRecordsWhen() {
        var wait = InteractionWait()
        wait.arm(now: t0, wait: 30)
        wait.complete(now: t0.addingTimeInterval(4))
        #expect(wait.isCompleted)
        #expect(wait.completedAt == t0.addingTimeInterval(4))
        // A completed wait cannot then time out.
        let afterCompletion = wait.tick(now: t0.addingTimeInterval(60))
        #expect(afterCompletion == false)
        #expect(wait.phase == .completed)
    }

    /// The grace window is half-open: `[completedAt, completedAt + grace)`. It is
    /// what a device's trailing keystroke is measured against, and an inclusive
    /// upper bound would keep swallowing the user's own Return one tick too long.
    @Test func theGraceWindowAfterCompletionIsHalfOpen() {
        var wait = InteractionWait()
        wait.arm(now: t0, wait: 30)
        wait.complete(now: t0)
        #expect(wait.isWithinGraceOfCompletion(0.25, now: t0))
        #expect(wait.isWithinGraceOfCompletion(0.25, now: t0.addingTimeInterval(0.24)))
        #expect(wait.isWithinGraceOfCompletion(0.25, now: t0.addingTimeInterval(0.25)) == false)
        // A clock that has gone backwards is not "within grace" — better to hand
        // the keystroke to the user than to swallow it on bad arithmetic.
        #expect(wait.isWithinGraceOfCompletion(0.25, now: t0.addingTimeInterval(-1)) == false)
    }

    @Test func noGraceWindowBeforeAnythingCompletes() {
        var wait = InteractionWait()
        wait.arm(now: t0, wait: 30)
        #expect(wait.isWithinGraceOfCompletion(0.25, now: t0) == false)
    }

    @Test func armingAgainClearsWhatWentBefore() {
        var wait = InteractionWait()
        wait.arm(now: t0, wait: 10)
        wait.complete(now: t0.addingTimeInterval(1))
        wait.arm(now: t0.addingTimeInterval(50), wait: 10)
        #expect(wait.isWaiting)
        #expect(wait.completedAt == nil)
        #expect(wait.isWithinGraceOfCompletion(0.25, now: t0.addingTimeInterval(50)) == false)
    }

    @Test func resetReturnsItToIdle() {
        var wait = InteractionWait()
        wait.arm(now: t0, wait: 10)
        wait.complete(now: t0)
        wait.reset()
        #expect(wait == InteractionWait())
    }

    /// A zero or negative wait must not arm something that has already expired in a
    /// way that never fires — it expires on the first tick, cleanly.
    @Test func aZeroLengthWaitExpiresImmediatelyRatherThanHanging() {
        var wait = InteractionWait()
        wait.arm(now: t0, wait: 0)
        let expiredAtOnce = wait.tick(now: t0)
        #expect(expiredAtOnce)
        #expect(wait.phase == .timedOut)

        var negative = InteractionWait()
        negative.arm(now: t0, wait: -5)
        let negativeExpired = negative.tick(now: t0)
        #expect(negativeExpired)
    }
}
