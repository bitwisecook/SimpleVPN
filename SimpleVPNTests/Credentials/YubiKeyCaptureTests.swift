// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
//  YubiKeyCaptureTests.swift
//  The armed-capture state machine, the trailing-Return decision, the single-use
//  guard, the composition, and the mutual exclusions — all with NO YubiKey attached
//  and none needed, because every one of them is pure over injected time.
//
//  THE TRAILING RETURN IS THE HEADLINE. A YubiKey types its code and then presses
//  Return; in a sign-in form Return means "connect". Left alone that fires a connect
//  the instant the code arrives — possibly half-composed — and a one-time code that
//  fails is gone. One wasted code per attempt, every attempt. The decision is
//  "the key's own Return NEVER connects", and it is asserted here in every ordering
//  the two events can arrive in.
//
//  THE SINGLE-USE GUARD IS THE SECOND. A consumed code is never retried, and that is
//  structural: `consumeCode()` empties the box, so a retry gets nil. Asserted, not
//  commented.
//

import Foundation
import Testing
@testable import SimpleVPN

@MainActor
struct YubiKeyCaptureTests {

    private let t0 = Date(timeIntervalSince1970: 3_000_000)

    private func validCode(publicID: String = "ccccccjjbbbb") -> String {
        publicID + String(repeating: "h", count: 32)
    }

    private func capture(_ mechanism: YubiKeyCodeMechanism = .yubicoOTP,
                         _ delivery: YubiKeyCodeDelivery = .appendedToPassword) -> YubiKeyCapture {
        YubiKeyCapture(mechanism: mechanism, delivery: delivery)
    }

    // MARK: Arming, timing out, cancelling

    @Test func startsIdleAndAsksForATouch() {
        let capture = capture()
        #expect(capture.state == .idle)
        #expect(capture.advice(now: t0) == .askForTouch)
        #expect(capture.state.hasUnspentCode == false)
    }

    @Test func armingWaitsWithACountdown() {
        let capture = capture()
        capture.arm(now: t0, wait: 30)
        #expect(capture.state.isWaiting)
        #expect(capture.secondsRemaining(now: t0) == 30)
        #expect(capture.advice(now: t0) == .waiting(secondsRemaining: 30))
        #expect(capture.advice(now: t0.addingTimeInterval(10)) == .waiting(secondsRemaining: 20))
    }

    @Test func theWaitTimesOutExactlyOnceAndSaysSomethingUseful() {
        let capture = capture()
        capture.arm(now: t0, wait: 10)
        #expect(capture.tick(now: t0.addingTimeInterval(9)) == false)
        #expect(capture.tick(now: t0.addingTimeInterval(10)))
        #expect(capture.state == .timedOut)
        // Announced once, not once a second.
        #expect(capture.tick(now: t0.addingTimeInterval(11)) == false)
        guard case .problem(let reason) = capture.advice(now: t0.addingTimeInterval(11)) else {
            Issue.record("expected a problem"); return
        }
        #expect(reason.lowercased().contains("touch"))
    }

    /// A code that arrives AFTER the wait expired must not be accepted: the user has
    /// been told nothing arrived, and quietly taking a late code would mean the
    /// screen and the state disagree.
    @Test func nothingIsAcceptedAfterATimeout() {
        let capture = capture()
        capture.arm(now: t0, wait: 10)
        capture.tick(now: t0.addingTimeInterval(10))
        #expect(capture.observe(fieldText: validCode(), now: t0.addingTimeInterval(11)) == false)
        #expect(capture.state == .timedOut)
    }

    @Test func cancellingIsDistinctFromATimeoutAndOffersAnotherGo() {
        let capture = capture()
        capture.arm(now: t0, wait: 30)
        capture.cancel()
        #expect(capture.state == .cancelled)
        // Cancel invites another attempt rather than reporting a failure.
        #expect(capture.advice(now: t0) == .askForTouch)
        // And the clock has stopped.
        #expect(capture.tick(now: t0.addingTimeInterval(999)) == false)
        #expect(capture.state == .cancelled)
    }

    @Test func cancellingThrowsAwayAnyCodeAlreadyHeld() {
        let capture = capture()
        capture.arm(now: t0, wait: 30)
        #expect(capture.observe(fieldText: validCode(), now: t0))
        capture.cancel()
        #expect(capture.consumeCode() == nil)
    }

    @Test func resetReturnsToIdleAndForgetsEverything() {
        let capture = capture()
        capture.arm(now: t0, wait: 30)
        _ = capture.observe(fieldText: validCode(), now: t0)
        capture.reset()
        #expect(capture.state == .idle)
        #expect(capture.lastLandingAt == nil)
        #expect(capture.consumeCode() == nil)
    }

    // MARK: A code landing

    @Test func aFullCodeLandsAndIsHeldWithItsPublicID() {
        let capture = capture()
        capture.arm(now: t0, wait: 30)
        #expect(capture.observe(fieldText: validCode(), now: t0))
        #expect(capture.state.hasUnspentCode)
        #expect(capture.state.identity?.publicID == "ccccccjjbbbb")
        #expect(capture.advice(now: t0) == .readyToSend)
        #expect(capture.lastLandingAt == t0)
    }

    /// A code arrives one keystroke at a time. Nothing may be reported until the
    /// whole thing is there — a "malformed code" warning that flashes up 43 times
    /// while the key is still typing would be worse than useless.
    @Test func aPartialCodeIsSilentRatherThanAnError() {
        let capture = capture()
        capture.arm(now: t0, wait: 30)
        let full = validCode()
        for length in 1..<full.count {
            let partial = String(full.prefix(length))
            #expect(capture.observe(fieldText: partial, now: t0) == false, "at \(length)")
            #expect(capture.state.isWaiting, "at \(length)")
        }
        #expect(capture.observe(fieldText: full, now: t0))
    }

    @Test func aMangledCodeIsReportedWithItsDiagnosis() {
        let capture = capture()
        capture.arm(now: t0, wait: 30)
        // 44 characters, wrong alphabet — the keyboard-layout case.
        let mangled = String(repeating: "a", count: 44)
        #expect(capture.observe(fieldText: mangled, now: t0) == false)
        #expect(capture.state == .notRecognised(.outsideModhex(likelyKeyboardLayout: true)))
        guard case .problem(let reason) = capture.advice(now: t0) else {
            Issue.record("expected a problem"); return
        }
        #expect(reason.lowercased().contains("keyboard"))
    }

    @Test func aSecondTouchReplacesTheFirstRatherThanKeepingTheStaleOne() {
        let capture = capture()
        capture.arm(now: t0, wait: 30)
        #expect(capture.observe(fieldText: validCode(publicID: "ccccccjjbbbb"), now: t0))
        capture.arm(now: t0.addingTimeInterval(5), wait: 30)
        #expect(capture.state.isWaiting)
        // The first code is gone — not merely shadowed.
        #expect(capture.consumeCode() == nil)
        let second = validCode(publicID: "ccccccjjbbbc")
        #expect(capture.observe(fieldText: second, now: t0.addingTimeInterval(6)))
        #expect(capture.consumeCode() == second)
    }

    /// The fetched mechanisms are asked, not typed. A key that TYPES while we are
    /// waiting for a fetch means the wrong mechanism is configured, and silently
    /// accepting it would send a 44-character code to a gateway expecting six digits.
    @Test func aTypedCodeIsIgnoredWhenTheMechanismIsAFetch() {
        for mechanism in [YubiKeyCodeMechanism.oathCode, .challengeResponse] {
            let capture = capture(mechanism)
            capture.arm(now: t0, wait: 30)
            #expect(capture.observe(fieldText: validCode(), now: t0) == false,
                    "\(mechanism.rawValue)")
            #expect(capture.state.isWaiting)
        }
    }

    // MARK: THE TRAILING RETURN

    /// While armed, ANY Return belongs to the key. The user is holding a piece of
    /// metal against a disc; they are not deciding to connect.
    @Test func aReturnWhileArmedIsSwallowed() {
        let capture = capture()
        capture.arm(now: t0, wait: 30)
        let decision = capture.noteReturn(fieldText: "", now: t0)
        #expect(decision == .swallowWhileWaiting)
        #expect(decision.swallows)
    }

    /// The ordinary case: the key types the code, the state becomes `.held`, then the
    /// Return arrives a moment later. It must NOT connect.
    @Test func theKeysTrailingReturnAfterACodeLandsIsSwallowed() {
        let capture = capture()
        capture.arm(now: t0, wait: 30)
        #expect(capture.observe(fieldText: validCode(), now: t0))
        // A frame or two later — well inside the grace window.
        let decision = capture.noteReturn(fieldText: validCode(),
                                          now: t0.addingTimeInterval(0.02))
        #expect(decision == .swallowKeyTrailingReturn)
    }

    /// Once the capture has settled, Return is the USER's again and means what it
    /// means in every other field in the app. Otherwise the feature would break
    /// keyboard-only operation.
    @Test func theUsersOwnReturnAfterTheGraceWindowSubmits() {
        let capture = capture()
        capture.arm(now: t0, wait: 30)
        #expect(capture.observe(fieldText: validCode(), now: t0))
        let decision = capture.noteReturn(fieldText: validCode(),
                                          now: t0.addingTimeInterval(1.0))
        #expect(decision == .submit)
        #expect(decision.swallows == false)
    }

    /// The grace boundary, exactly. Half-open, so it stops swallowing the moment it
    /// should — an inclusive bound would eat one more of the user's keypresses.
    @Test func theGraceWindowBoundaryIsExact() {
        let grace = YubiKeyCapture.returnGrace
        var wait = InteractionWait()
        wait.arm(now: t0, wait: 30)
        wait.complete(now: t0)
        let held = YubiKeyCaptureState.held(identity: nil, landedAt: t0)
        #expect(YubiKeyReturnPolicy.decide(state: held, lastLandingAt: t0,
                                           now: t0.addingTimeInterval(grace - 0.001),
                                           grace: grace) == .swallowKeyTrailingReturn)
        #expect(YubiKeyReturnPolicy.decide(state: held, lastLandingAt: t0,
                                           now: t0.addingTimeInterval(grace),
                                           grace: grace) == .submit)
    }

    /// The events can arrive in EITHER order under load, and a `.spent` or
    /// `.notRecognised` state is no reason to let a keystroke the KEY produced fire
    /// a connect. So the grace window is checked regardless of the state.
    @Test func theGraceWindowAppliesEvenAfterTheStateHasMovedOn() {
        let grace = YubiKeyCapture.returnGrace
        let states: [YubiKeyCaptureState] = [
            .held(identity: nil, landedAt: t0),
            .spent(identity: nil),
            .notRecognised(.oddLength(count: 43)),
            .timedOut,
            .cancelled,
        ]
        for state in states {
            #expect(YubiKeyReturnPolicy.decide(state: state, lastLandingAt: t0,
                                                now: t0.addingTimeInterval(0.01),
                                                grace: grace) == .swallowKeyTrailingReturn,
                    "\(state)")
        }
    }

    /// With nothing armed and nothing landed, the field is an ordinary field. The
    /// hook must be completely inert for every VPN that has no security key.
    @Test func withNoCaptureAtAllReturnAlwaysSubmits() {
        #expect(YubiKeyReturnPolicy.decide(state: .idle, lastLandingAt: nil,
                                           now: t0, grace: 0.25) == .submit)
        let capture = capture()
        #expect(capture.noteReturn(fieldText: "", now: t0) == .submit)
    }

    /// A clock that has gone backwards must hand the keystroke to the user rather
    /// than swallow it on bad arithmetic — the failure that loses a keypress is
    /// better than the one that connects unexpectedly, but a negative interval is
    /// nobody's grace window.
    @Test func aBackwardsClockDoesNotOpenAnUnboundedGraceWindow() {
        #expect(YubiKeyReturnPolicy.decide(state: .held(identity: nil, landedAt: t0),
                                           lastLandingAt: t0,
                                           now: t0.addingTimeInterval(-5),
                                           grace: 0.25) == .submit)
    }

    // MARK: Static passwords — the "don't mangle it" mechanism

    /// A static password has no recognisable shape, so its TRAILING RETURN is the
    /// terminator. Whatever is in the box when the key presses Return is the
    /// password — untouched, unvalidated, not cut to 44 characters.
    @Test func aStaticPasswordIsTerminatedByItsReturnAndNotMangled() {
        let capture = capture(.staticPassword, .appendedToPassword)
        #expect(capture.capturesInPasswordField)
        capture.arm(now: t0, wait: 30, passwordSoFar: "PIN1234")
        // A 30-character static password — not modhex, not 44 characters.
        let typed = "Xk!9zQ#4mW@2vB^7nL&5tR$8yU*1oP"
        #expect(capture.observe(fieldText: "PIN1234" + typed, now: t0) == false)  // no shape
        #expect(capture.state.isWaiting)
        let decision = capture.noteReturn(fieldText: "PIN1234" + typed, now: t0)
        #expect(decision == .swallowWhileWaiting)
        #expect(capture.state.hasUnspentCode)
        // The password box's whole contents are the password: the user's prefix plus
        // what the key typed, verbatim.
        let inputs = capture.consumeEngineInputs(password: "PIN1234" + typed)
        #expect(inputs?.password == "PIN1234" + typed)
        #expect(inputs?.separateCode == nil)
    }

    @Test func aStaticPasswordWithNoPrefixIsTheWholeField() {
        let capture = capture(.staticPassword, .appendedToPassword)
        capture.arm(now: t0, wait: 30, passwordSoFar: "")
        _ = capture.noteReturn(fieldText: "verylongstaticpassword", now: t0)
        #expect(capture.consumeEngineInputs(password: "verylongstaticpassword")?.password
                == "verylongstaticpassword")
    }

    /// A static password is not single-use, so the "that code has been used" nag
    /// would be wrong. The wording differs; the box does not.
    @Test func aSpentStaticPasswordDoesNotClaimToBeAOneTimeCode() {
        let capture = capture(.staticPassword)
        capture.arm(now: t0, wait: 30, passwordSoFar: "")
        _ = capture.noteReturn(fieldText: "static", now: t0)
        _ = capture.consumeCode()
        guard case .needsFreshTouch(let reason) = capture.advice(now: t0) else {
            Issue.record("expected needsFreshTouch"); return
        }
        #expect(reason.lowercased().contains("one-time") == false)
        #expect(YubiKeyCodeMechanism.staticPassword.isSingleUse == false)
        #expect(YubiKeyCodeMechanism.yubicoOTP.isSingleUse)
    }

    // MARK: THE SINGLE-USE GUARD

    @Test func aCodeCanBeTakenExactlyOnce() {
        let capture = capture()
        capture.arm(now: t0, wait: 30)
        #expect(capture.observe(fieldText: validCode(), now: t0))
        #expect(capture.consumeCode() == validCode())
        #expect(capture.state == .spent(identity: YubicoOTPIdentity(publicID: "ccccccjjbbbb",
                                                                   totalLength: 44)))
        #expect(capture.consumeCode() == nil)
        #expect(capture.consumeCode() == nil)
    }

    /// The point of the whole guard: a retry gets NOTHING, so it cannot replay a code
    /// the gateway has already burned. And the state says a fresh touch is needed, in
    /// words, so the UI cannot show "ready to send".
    @Test func aRetryAfterAFailedConnectHasNothingToReplay() {
        let capture = capture()
        capture.arm(now: t0, wait: 30)
        _ = capture.observe(fieldText: validCode(), now: t0)
        _ = capture.consumeCode()                        // the connect attempt
        // …which failed. The retry:
        #expect(capture.consumeCode() == nil)
        #expect(capture.state.hasUnspentCode == false)
        #expect(capture.state.isSpent)
        guard case .needsFreshTouch(let reason) = capture.advice(now: t0) else {
            Issue.record("expected needsFreshTouch"); return
        }
        #expect(reason.lowercased().contains("used"))
    }

    @Test func consumingEngineInputsIsAlsoOnceOnly() {
        let capture = capture(.yubicoOTP, .appendedToPassword)
        capture.arm(now: t0, wait: 30)
        _ = capture.observe(fieldText: validCode(), now: t0)
        let first = capture.consumeEngineInputs(password: "hunter2")
        #expect(first?.password == "hunter2" + validCode())
        #expect(first?.separateCode == nil)
        #expect(capture.consumeEngineInputs(password: "hunter2") == nil)
    }

    /// The public ID survives spending, because it is not a secret — so the UI can
    /// still say WHICH key produced the code that just failed, which is exactly the
    /// question someone with two keys is asking.
    @Test func thePublicIDSurvivesBeingSpent() {
        let capture = capture()
        capture.arm(now: t0, wait: 30)
        _ = capture.observe(fieldText: validCode(), now: t0)
        _ = capture.consumeCode()
        #expect(capture.state.identity?.publicID == "ccccccjjbbbb")
    }

    /// A state that claims to hold a code while the box is empty would put "ready to
    /// send" on screen with nothing behind it. The machine corrects itself instead.
    @Test func aStateClaimingACodeItHasNotGotCorrectsItself() {
        let capture = capture()
        capture.arm(now: t0, wait: 30)
        _ = capture.observe(fieldText: validCode(), now: t0)
        _ = capture.consumeCode()
        #expect(capture.state.isSpent)
        #expect(capture.advice(now: t0) != .readyToSend)
    }
}

// MARK: - Composition

struct YubiKeyCompositionTests {

    private let code = "ccccccjjbbbb" + String(repeating: "h", count: 32)

    /// The nonisolated template constants MUST equal `VPNAuthConfig`'s own. They are
    /// duplicated only because this module is main-actor by default and the rules are
    /// deliberately not; this test is what stops the duplication drifting.
    @MainActor
    @Test func theTemplateConstantsMatchTheAuthConfigsOwn() {
        #expect(YubiKeyTemplates.passwordThenCode == VPNAuthConfig.defaultTemplate)
        #expect(YubiKeyTemplates.passwordThenCode == "{password}{otp}")
        #expect(YubiKeyTemplates.codeOnly == "{otp}")
    }

    @Test func everyDeliveryNamesATemplateThatMentionsTheCode() {
        for delivery in YubiKeyCodeDelivery.allCases {
            #expect(delivery.passwordTemplate.contains("{otp}"), Comment(rawValue: delivery.rawValue))
            #expect(YubiKeyComposition.template(for: delivery) == delivery.passwordTemplate)
        }
    }

    @Test func appendedToPasswordSendsOneJoinedValueAndNoSeparateCode() {
        let inputs = YubiKeyComposition.engineInputs(delivery: .appendedToPassword,
                                                     password: "hunter2", code: code)
        #expect(inputs.password == "hunter2" + code)
        #expect(inputs.separateCode == nil)
    }

    @Test func separateFieldKeepsTheHalvesApart() {
        let inputs = YubiKeyComposition.engineInputs(delivery: .separateField,
                                                     password: "hunter2", code: code)
        #expect(inputs.password == "hunter2")
        #expect(inputs.separateCode == code)
    }

    @Test func codeOnlySendsNoPassword() {
        let inputs = YubiKeyComposition.engineInputs(delivery: .codeOnly,
                                                     password: "hunter2", code: code)
        #expect(inputs.password.isEmpty)
        #expect(inputs.separateCode == code)
    }

    /// Someone touching their key out of habit while the PASSWORD field has focus is
    /// the commonest way this goes wrong, and it is recoverable rather than fatal.
    @Test func aCodeThatLandedInThePasswordBoxCanBeRescued() throws {
        let rescued = try #require(
            YubiKeyComposition.rescueCodeFromPassword("hunter2" + code))
        #expect(rescued.password == "hunter2")
        #expect(rescued.code == code)
    }

    @Test func rescuingRefusesToCutAPasswordThatHasNoCodeOnIt() {
        #expect(YubiKeyComposition.rescueCodeFromPassword("hunter2") == nil)
        #expect(YubiKeyComposition.rescueCodeFromPassword("") == nil)
        // Long, but the tail is not modhex.
        #expect(YubiKeyComposition.rescueCodeFromPassword(String(repeating: "q", count: 80)) == nil)
    }

    @Test func clearingTheCodeFieldLeavesNothingBehind() {
        #expect(YubiKeyComposition.clearedCodeField().isEmpty)
    }
}

// MARK: - Mutual exclusion

struct YubiKeyConflictTests {

    private func inputs(_ build: (inout YubiKeyConflictInputs) -> Void) -> YubiKeyConflictInputs {
        var out = YubiKeyConflictInputs()
        out.config.enabled = true
        out.requiresOTP = true
        out.typingKeyAttached = true
        build(&out)
        return out
    }

    @Test func nothingConflictsWhenTheFeatureIsOff() {
        var off = YubiKeyConflictInputs()
        off.config.enabled = false
        off.sourceSuppliesCode = true
        off.credentialKind = .onePassword
        #expect(YubiKeyConflicts.all(off).isEmpty)
        #expect(YubiKeyConflicts.isActive(off) == false)
    }

    @Test func aVPNThatWantsNoCodeHasNothingForAKeyToDo() {
        let it = inputs { $0.requiresOTP = false }
        #expect(YubiKeyConflicts.all(it).contains(.noCodeWanted))
        #expect(YubiKeyConflicts.isActive(it) == false)
        #expect(YubiKeyConflicts.blockingReason(it) != nil)
    }

    /// A profile-declared static challenge means the server WILL ask, whatever the
    /// toggle says — so it counts as wanting a code.
    @Test func aStaticChallengeCountsAsWantingACode() {
        let it = inputs { $0.requiresOTP = false; $0.staticChallenge = true }
        #expect(YubiKeyConflicts.all(it).contains(.noCodeWanted) == false)
        #expect(YubiKeyConflicts.isActive(it))
    }

    /// Two sources for one code is the failure that costs a real one-time code to
    /// discover, so it blocks rather than warns.
    @Test func aPasswordAppThatSuppliesTheCodeBlocks() {
        for kind in [CredentialSourceKind.onePassword, .keePassXC] {
            let it = inputs { $0.credentialKind = kind; $0.sourceSuppliesCode = kind.suppliesOTP }
            #expect(YubiKeyConflicts.all(it).contains(.sourceAlreadySuppliesCode(kind)),
                    Comment(rawValue: kind.rawValue))
            #expect(YubiKeyConflicts.isActive(it) == false)
            // The explanation must NAME the app, or the user cannot act on it.
            let reason = YubiKeyConflicts.blockingReason(it) ?? ""
            #expect(reason.contains(kind.displayName))
        }
    }

    /// A password app that CANNOT supply a code is no conflict at all — Apple
    /// Passwords stores codes but exposes none, and Keeper is deliberately marked
    /// as not promising one.
    @Test func aPasswordAppThatCannotSupplyACodeIsNoConflict() {
        for kind in [CredentialSourceKind.applePasswords, .keeper] {
            let it = inputs { $0.credentialKind = kind; $0.sourceSuppliesCode = kind.suppliesOTP }
            #expect(YubiKeyConflicts.isActive(it), Comment(rawValue: kind.rawValue))
        }
    }

    @Test func aTouchIDItemHoldingAnAuthenticatorSeedBlocks() {
        let it = inputs { $0.keychainSuppliesCode = true }
        #expect(YubiKeyConflicts.all(it).contains(.keychainAlreadySuppliesCode))
        #expect(YubiKeyConflicts.isActive(it) == false)
    }

    @Test func theFetchedMechanismsBlockWithoutYubicosTool() {
        for mechanism in [YubiKeyCodeMechanism.oathCode, .challengeResponse] {
            var it = inputs {
                $0.config.mechanism = mechanism
                $0.config.oathAccount = "Example:me"
                $0.managerToolInstalled = false
            }
            #expect(YubiKeyConflicts.all(it).contains(.needsManagerTool),
                    Comment(rawValue: mechanism.rawValue))
            #expect(YubiKeyConflicts.isActive(it) == false)
            it.managerToolInstalled = true
            #expect(YubiKeyConflicts.isActive(it), Comment(rawValue: mechanism.rawValue))
        }
    }

    /// The typed mechanisms need nothing installed — that is the whole point of them.
    @Test func theTypedMechanismsNeedNothingInstalled() {
        for mechanism in [YubiKeyCodeMechanism.yubicoOTP, .staticPassword] {
            let it = inputs { $0.config.mechanism = mechanism; $0.managerToolInstalled = false }
            #expect(YubiKeyConflicts.all(it).contains(.needsManagerTool) == false)
            #expect(YubiKeyConflicts.isActive(it), Comment(rawValue: mechanism.rawValue))
        }
    }

    /// No key plugged in is a NOTE, not a block: the setup is worth saving on a Mac
    /// with the key in a drawer.
    @Test func noKeyPluggedInIsANoteAndNotABlock() {
        let it = inputs { $0.typingKeyAttached = false }
        #expect(YubiKeyConflicts.all(it).contains(.noTypingKeyAttached))
        #expect(YubiKeyConflicts.blockingReason(it) == nil)
        #expect(YubiKeyConflicts.isActive(it))
    }

    @Test func anOATHSetupWithNoAccountChosenIsNotYetUsableAndSaysWhy() {
        var config = YubiKeyAuthConfig()
        config.enabled = true
        config.mechanism = .oathCode
        #expect(config.isUsable == false)
        #expect(config.incompleteReason != nil)
        config.oathAccount = "Example:me"
        #expect(config.isUsable)
        #expect(config.incompleteReason == nil)
    }

    /// The delivery choice OWNS the template while a key is active — one control,
    /// one meaning — so the template row must be inert and the effective template
    /// must come from the delivery.
    @Test func theDeliveryChoiceOwnsTheTemplateWhileAKeyIsActive() {
        let it = inputs { $0.config.delivery = .codeOnly; $0.passwordTemplate = "{password}{otp}" }
        #expect(YubiKeyConflicts.templateIsOwnedByDelivery(it))
        #expect(YubiKeyConflicts.effectiveTemplate(it) == "{otp}")
        // A disagreement is surfaced rather than silently applied.
        #expect(YubiKeyConflicts.all(it)
            .contains(.templateDisagreesWithDelivery(expected: "{otp}")))
    }

    @Test func aStaticChallengeMakesTheTemplateNobodysBusiness() {
        let it = inputs { $0.staticChallenge = true; $0.passwordTemplate = "weird{otp}" }
        #expect(YubiKeyConflicts.templateIsOwnedByDelivery(it) == false)
        #expect(YubiKeyConflicts.all(it).allSatisfy {
            if case .templateDisagreesWithDelivery = $0 { return false }
            return true
        })
    }

    @Test func whenTheFeatureIsOffTheVPNsOwnTemplateIsTheEffectiveOne() {
        var off = YubiKeyConflictInputs()
        off.config.enabled = false
        off.passwordTemplate = "{password}-{otp}"
        #expect(YubiKeyConflicts.effectiveTemplate(off) == "{password}-{otp}")
        #expect(YubiKeyConflicts.templateIsOwnedByDelivery(off) == false)
    }

    @Test func blockingConflictsSortAheadOfNotes() {
        let it = inputs { $0.requiresOTP = false; $0.typingKeyAttached = false }
        let all = YubiKeyConflicts.all(it)
        #expect(all.count >= 2)
        #expect(all.first?.isBlocking == true)
        #expect(all.last?.isBlocking == false)
    }

    @Test func everyConflictHasNonEmptyPlainLanguageWording() {
        let conflicts: [YubiKeyConflict] = [
            .noCodeWanted, .sourceAlreadySuppliesCode(.onePassword),
            .keychainAlreadySuppliesCode, .needsManagerTool,
            .templateDisagreesWithDelivery(expected: "{otp}"), .noTypingKeyAttached,
        ]
        for conflict in conflicts {
            #expect(!conflict.explanation.isEmpty)
            // The glossary: "verification code", never a bare "OTP".
            #expect(!conflict.explanation.contains(" OTP"))
        }
    }
}

// MARK: - The stored setup holds no secrets

struct YubiKeyAuthConfigTests {

    /// The setup rides `providerConfiguration` inside `VPNAuthConfig`, so it must be
    /// provably secret-free. Every field is enumerated here on purpose: if someone
    /// adds one, this test is where they have to think about it.
    @Test func everyStoredFieldIsAPublicFact() throws {
        var config = YubiKeyAuthConfig()
        config.enabled = true
        config.mechanism = .oathCode
        config.delivery = .separateField
        config.serial = "12345678"          // printed on the key
        config.oathAccount = "Example:me"   // a label
        config.slot = .two                  // a slot number
        config.waitSeconds = 45
        config.armAutomatically = false

        let json = String(decoding: try JSONEncoder().encode(config), as: UTF8.self)
        // A mechanism, a delivery, a serial, a label, a slot, two numbers. Nothing
        // that could be a password, a code, or key material.
        for key in ["enabled", "mechanism", "delivery", "serial", "oathAccount",
                    "slot", "waitSeconds", "armAutomatically"] {
            #expect(json.contains(key), Comment(rawValue: key))
        }
        let decoded = try JSONDecoder().decode(YubiKeyAuthConfig.self,
                                               from: Data(json.utf8))
        #expect(decoded == config)
    }

    /// Lenient decoding, same as every other blob in this app: a partial or
    /// older-build payload must fall back per field rather than throwing the whole
    /// setup away.
    @Test func aPartialBlobDecodesToDefaultsRatherThanFailing() throws {
        let partial = Data(#"{"enabled":true}"#.utf8)
        let decoded = try JSONDecoder().decode(YubiKeyAuthConfig.self, from: partial)
        #expect(decoded.enabled)
        #expect(decoded.mechanism == .yubicoOTP)
        #expect(decoded.delivery == .appendedToPassword)
        #expect(decoded.waitSeconds == Int(YubiKeyCapture.defaultWait))
        #expect(decoded.armAutomatically)
    }

    @Test func anUnknownMechanismFallsBackRatherThanDiscardingTheSetup() throws {
        let future = Data(#"{"enabled":true,"mechanism":"someFutureThing"}"#.utf8)
        let decoded = try JSONDecoder().decode(YubiKeyAuthConfig.self, from: future)
        #expect(decoded.enabled)
        #expect(decoded.mechanism == .yubicoOTP)
    }

    /// A serial goes into argv, so anything that is not digits must never reach it.
    @Test func onlyADigitsOnlySerialIsEverPassedOn() {
        var config = YubiKeyAuthConfig()
        config.serial = "12345678"
        #expect(config.normalizedSerial == "12345678")
        config.serial = "  12345678  "
        #expect(config.normalizedSerial == "12345678")
        for bad in ["", "  ", "my key", "1234-5678", "abc", "12345678;rm -rf /", "--device"] {
            config.serial = bad
            #expect(config.normalizedSerial == nil, Comment(rawValue: bad.debugDescription))
        }
    }

    @Test func theWaitIsClampedToSomethingUsable() {
        var config = YubiKeyAuthConfig()
        config.waitSeconds = 0
        #expect(config.effectiveWait == 5)
        config.waitSeconds = -100
        #expect(config.effectiveWait == 5)
        config.waitSeconds = 100_000
        #expect(config.effectiveWait == 120)
        config.waitSeconds = 30
        #expect(config.effectiveWait == 30)
    }

    /// A default setup must not make an otherwise-default auth config look changed —
    /// `isDefault` decides whether the blob is written at all.
    @MainActor
    @Test func adefaultSetupLeavesTheAuthConfigDefault() {
        var auth = VPNAuthConfig()
        #expect(auth.isDefault)
        auth.yubiKey = YubiKeyAuthConfig()
        #expect(auth.isDefault)
        #expect(auth.securityKey == nil)
        var enabled = YubiKeyAuthConfig()
        enabled.enabled = true
        auth.yubiKey = enabled
        #expect(auth.isDefault == false)
        #expect(auth.securityKey != nil)
    }

    /// An autologin profile has no password and no code, so a security-key setup is
    /// dead state that would go on arming a touch prompt at every connect.
    @MainActor
    @Test func autologinClearsTheSecurityKeySetup() {
        var auth = VPNAuthConfig()
        var key = YubiKeyAuthConfig()
        key.enabled = true
        auth.yubiKey = key
        auth.requiresOTP = true
        let resolved = VPNAuthConfig.resolved(auth, autologin: true, staticChallenge: false)
        #expect(resolved.securityKey == nil)
        #expect(resolved.yubiKey.enabled == false)
        // A static challenge does NOT clear it — the server will ask, so the key is
        // exactly what should answer.
        let challenged = VPNAuthConfig.resolved(auth, autologin: false, staticChallenge: true)
        #expect(challenged.yubiKey.enabled)
    }
}
