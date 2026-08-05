// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
//  YubiKeyTouchCapture.swift
//  "Touch your key now" — the state machine behind catching a code a security key
//  TYPES, and the whole reason this feature is more than a text field.
//
//  ─── FOCUS MANAGEMENT IS THE FEATURE ────────────────────────────────────────
//  A YubiKey with a Yubico OTP credential is a USB keyboard. Touch it and it
//  types 44 characters into WHATEVER HAS KEYBOARD FOCUS — this app, another app,
//  a Slack message, a search box, the Finder. There is no addressing, no target,
//  no API. Focus is the only thing that decides where a one-time credential lands.
//
//  So SimpleVPN does not present a field and hope the user aims at it. It presents
//  an explicit ARMED state: the field is focused for you, the prompt says the key
//  is being waited for, a countdown says for how much longer, and Cancel gets out.
//  Everything in this file exists to make that state honest — including the parts
//  that decide when it ENDS, because an armed state that outlives the user's
//  attention is how a code lands in the wrong window.
//
//  ─── THE TRAILING RETURN ────────────────────────────────────────────────────
//  A YubiKey presses Return after the code. That is its default configuration and
//  effectively universal. In a credential form, Return means "connect" — so a
//  naive field connects the instant the key finishes typing, and if the sign-in
//  isn't complete (no password yet, the code in the wrong field, the user still
//  reading) the gateway rejects it and THE CODE IS GONE. One touch, one wasted
//  code, every single attempt. It is the defining bug of this feature.
//
//  THE DECISION, and it is deliberate: **the key's own Return never connects.**
//  It is consumed by the capture as "the code is complete" and goes no further.
//  The user connects, by pressing Return themselves or clicking Connect.
//
//  Why not "treat it as composition complete, then submit"? Because the two
//  states are not the same. The key finishing typing means the CODE is complete;
//  it says nothing about whether the SIGN-IN is. Auto-submitting is only correct
//  in the one case where everything else was already filled in, and it is
//  destructive in every other — and the cost is asymmetric: a needless extra
//  keypress against a burned single-use credential and a failed authentication
//  attempt that some gateways count towards a lockout. So the Return is
//  swallowed, always, and the user's own Return works normally the moment the
//  capture has settled.
//
//  Two Returns are therefore swallowed, not one, and both cases are real:
//   • While ARMED. Anything that arrives during the wait belongs to the key.
//   • For a short GRACE window after a code lands. The key types the code and the
//     Return in one burst, but they are separate keystrokes and the Return can
//     arrive a frame or two later; and a user who was already holding Return down
//     must not have it fire against a code that arrived underneath them.
//  After the grace window, Return is the user's again. `YubiKeyReturnPolicy` is
//  that decision as a pure function, so it is tested rather than trusted.
//
//  ─── A CONSUMED CODE IS NEVER RETRIED ───────────────────────────────────────
//  Structurally, not by convention. The code lives in a `SingleUseCode`, whose
//  only accessor empties it (see YubicoOTP.swift). Handing it to a connect moves
//  the machine to `.spent`, which reports `nothingToSend` — so a retry has nothing
//  to replay and the UI must ask for another touch. There is no code path that can
//  read the same code twice, because there is no code path that can read a code
//  twice.
//
//  ─── NO INPUT MONITORING ────────────────────────────────────────────────────
//  Nothing here reads HID. The key types into a focused NSTextField and this
//  machine watches that field's own text. See YubiKeyPresence.swift's header.
//

import Foundation

// MARK: - The two password templates, reachable from nonisolated rules

/// The `{password}{otp}` templates, as nonisolated constants.
///
/// They duplicate `VPNAuthConfig.defaultTemplate` for one reason and one only:
/// this module defaults to main-actor isolation, `VPNAuthConfig` is therefore
/// main-actor, and every rule in this file is deliberately nonisolated so it can
/// be reasoned about (and tested) without an actor. `YubiKeyCompositionTests` pins
/// these to `VPNAuthConfig`'s own value, so the duplication cannot drift — which is
/// the only thing that would make it a problem.
nonisolated enum YubiKeyTemplates {
    /// Password first, then the code, joined into one field.
    static let passwordThenCode = "{password}{otp}"
    /// The code is the whole sign-in.
    static let codeOnly = "{otp}"
}

// MARK: - How the code gets into the sign-in

/// HOW the code reaches the gateway once it has been captured — the user's real
/// question, and the thing gateways disagree about.
///
/// ─── WHY THIS IS A JOIN AND NOT A DIFFERENT CAPTURE FIELD ────────────────────
/// The obvious reading of "password, then a touch appends the code" is that the
/// key types into the PASSWORD box. It doesn't need to, and it shouldn't: what
/// reaches the gateway is one string either way, and this app already has a
/// tested seam for building it — `VPNAuthConfig.passwordTemplate`, the
/// `{password}{otp}` assembly that the OpenVPN and OpenConnect paths have used
/// since the first release.
///
/// So the key types into the VERIFICATION CODE box (which the armed state focuses
/// for you), and `delivery` picks the template that joins the halves. That is a
/// better design for three concrete reasons:
///
///  1. **The user's password is never edited.** Nothing has to cut 44 characters
///     back off a secure field after a failed attempt, and nothing can cut the
///     wrong 44 characters.
///  2. **The join is already tested** and already understood by every engine.
///  3. **A code that lands in the wrong box is recoverable** rather than
///     indistinguishable from the password — see
///     `YubiKeyComposition.rescueCodeFromPassword`.
///
/// The one exception is a STATIC password, which is a password and not a code, and
/// which therefore does belong in the password box. `YubiKeyCodeMechanism
/// .capturesInPasswordField` owns that distinction.
nonisolated enum YubiKeyCodeDelivery: String, Codable, Sendable, CaseIterable, Identifiable {

    /// **The common case, and the one this feature was asked for.** Your password
    /// and the key's code arrive at the gateway joined together, in one field —
    /// what FortiGate, Cisco-style gateways and most RADIUS front ends expect.
    /// Template: `{password}{otp}`.
    case appendedToPassword

    /// The code travels separately, as the gateway's own challenge response, and
    /// is never mixed into the password. What a profile with a `static-challenge`
    /// directive does, and what most LinOTP/privacyIDEA setups want.
    case separateField

    /// There is no password: the code IS the sign-in. Template: `{otp}`.
    case codeOnly

    nonisolated var id: String { rawValue }

    /// The row's name. Plain language, no "OTP", per the glossary.
    var title: String {
        switch self {
        case .appendedToPassword: "Joined onto the end of my password"
        case .separateField: "Sent on its own, separately"
        case .codeOnly: "The code is the whole sign-in"
        }
    }

    var summary: String {
        switch self {
        case .appendedToPassword:
            "Your password and the key\u{2019}s code are sent as one, password first. This is what most "
                + "VPN gateways expect, and it is the usual choice."
        case .separateField:
            "The code is sent by itself, in answer to the server\u{2019}s own prompt, and never mixed "
                + "into your password."
        case .codeOnly:
            "There is no password to send \u{2014} touching your key is the whole sign-in."
        }
    }

    /// The password template this delivery means. THE join, in one place: an
    /// editor showing a template and a connect building one must never disagree.
    var passwordTemplate: String {
        switch self {
        case .appendedToPassword: YubiKeyTemplates.passwordThenCode
        // Inert: the code travels as the server's own challenge response, so the
        // template never sees it. The default is carried so a VPN that later loses
        // its static challenge still has a sane join.
        case .separateField: YubiKeyTemplates.passwordThenCode
        case .codeOnly: YubiKeyTemplates.codeOnly
        }
    }
}

/// WHAT the key contributes. The four mechanisms, as one choice — because a user
/// picks a mechanism once and then never thinks about it again, and because they
/// need different plumbing that nothing above this line should have to know about.
nonisolated enum YubiKeyCodeMechanism: String, Codable, Sendable, CaseIterable, Identifiable {

    /// Yubico OTP: the factory credential, usually slot 1, a short touch. The key
    /// TYPES 44 characters. Verified by the gateway or by YubiCloud — never here.
    case yubicoOTP

    /// A verification code (TOTP, or counter-based HOTP) stored on the key and read
    /// back through Yubico's own `ykman`. Nothing is typed by the key; SimpleVPN
    /// asks for the code. Needs `ykman` installed, which SimpleVPN never does for
    /// you.
    case oathCode

    /// Slot HMAC-SHA1 challenge-response, read through `ykman`. For gateways that
    /// send a challenge; the slot's secret never leaves the key.
    case challengeResponse

    /// A static password held in a slot, usually slot 2 on a long touch. The key
    /// types it; there is nothing to compute and nothing to verify. Supported
    /// mostly so we do not MANGLE it — a static password is not 44 modhex
    /// characters and must be let through untouched.
    case staticPassword

    nonisolated var id: String { rawValue }

    var title: String {
        switch self {
        case .yubicoOTP: "The code my key types"
        case .oathCode: "A verification code stored on my key"
        case .challengeResponse: "My key answers a challenge"
        case .staticPassword: "A fixed password stored on my key"
        }
    }

    var summary: String {
        switch self {
        case .yubicoOTP:
            "Touch your key and it types a long one-time code, the kind that starts \u{201C}cccc\u{201D}. "
                + "Your VPN\u{2019}s server checks it \u{2014} SimpleVPN passes it on and cannot check "
                + "it itself."
        case .oathCode:
            "The six- or eight-digit kind, kept on the key instead of on your phone. SimpleVPN asks "
                + "your key for it using Yubico\u{2019}s own tool, which you install yourself."
        case .challengeResponse:
            "Your VPN sends a challenge, your key answers it, and the answer is the code. The "
                + "key\u{2019}s secret never leaves the key."
        case .staticPassword:
            "A long fixed password your key types for you. Not a one-time code \u{2014} it is the same "
                + "every time."
        }
    }

    /// Does the KEY type this, or do we go and get it?
    var isTypedByKey: Bool { self == .yubicoOTP || self == .staticPassword }
    /// Which box the armed state must focus. A static password is a PASSWORD — it
    /// is not a one-time code, it is not joined by a template, and putting it in
    /// the verification-code box would send it to the wrong half of the sign-in.
    /// Everything else goes in the verification-code box; see
    /// `YubiKeyCodeDelivery`'s header for why.
    var capturesInPasswordField: Bool { self == .staticPassword }
    /// Does this need `ykman`?
    var needsManagerTool: Bool { self == .oathCode || self == .challengeResponse }
    /// Is what arrives single-use? A static password is not, and saying it is
    /// would make the UI nag for a fresh touch that changes nothing.
    var isSingleUse: Bool { self != .staticPassword }
}

// MARK: - The state machine

/// Where a capture is. One value; every surface reads it and nobody re-derives it.
nonisolated enum YubiKeyCaptureState: Sendable, Equatable {

    /// Nothing happening. The field behaves like any other field.
    case idle

    /// **Armed.** The right field has focus and the key is being waited for.
    /// `expiresAt` drives the countdown and the timeout.
    case waiting(armedAt: Date, expiresAt: Date)

    /// A code arrived and is held, unspent. `identity` is nil for anything but a
    /// typed Yubico OTP (a static password has no public ID, and inventing one
    /// would be a lie on screen).
    case held(identity: YubicoOTPIdentity?, landedAt: Date)

    /// The held code has been handed to a connect attempt. There is nothing left —
    /// see the file header on why this state exists at all.
    case spent(identity: YubicoOTPIdentity?)

    /// The wait ran out with nothing typed.
    case timedOut

    /// The user cancelled the wait.
    case cancelled

    /// Something arrived, but it was not a code we recognise. Carries WHY, because
    /// "invalid" on its own sends people to factory-reset a working key.
    case notRecognised(YubicoOTP.Problem)

    var isWaiting: Bool { if case .waiting = self { return true }; return false }
    /// A code is in hand and has not been used.
    var hasUnspentCode: Bool { if case .held = self { return true }; return false }
    var isSpent: Bool { if case .spent = self { return true }; return false }

    /// Which key typed it, when we know.
    var identity: YubicoOTPIdentity? {
        switch self {
        case .held(let identity, _), .spent(let identity): identity
        case .idle, .waiting, .timedOut, .cancelled, .notRecognised: nil
        }
    }
}

/// What a caller should DO about the state — so no view has to switch on the
/// state itself and no two views can disagree.
nonisolated enum YubiKeyCaptureAdvice: Sendable, Equatable {
    /// Ask for a touch (or a first touch).
    case askForTouch
    /// Waiting. `secondsRemaining` is for the countdown.
    case waiting(secondsRemaining: Int)
    /// A code is ready to send.
    case readyToSend
    /// A code was used. A fresh touch is needed before another attempt.
    case needsFreshTouch(reason: String)
    /// Something went wrong and the reason is worth showing.
    case problem(String)
}

// MARK: - The capture

/// The armed-capture state machine. Pure over injected time — no timers, no
/// `Date()` inside, no views — so the whole of it (arming, landing, the trailing
/// Return, the timeout, the cancel, the single-use guard) is unit-testable and IS
/// unit-tested with no key attached.
///
/// Held by the connect surface; one instance per VPN being signed in to.
@MainActor
@Observable
final class YubiKeyCapture {

    /// How long an armed wait lasts. Long enough to find a key in a bag, short
    /// enough that a forgotten prompt does not sit there armed all afternoon
    /// waiting to swallow somebody's typing.
    ///
    /// `nonisolated` because the stored setup (`YubiKeyAuthConfig`) and the pure
    /// rules read it, and neither is main-actor.
    nonisolated static let defaultWait: TimeInterval = 30

    /// How long after a code lands the Return still belongs to the KEY rather than
    /// the user. The key sends the code and the Return in one burst — microseconds
    /// apart in HID terms, but separate keystrokes through separate main-loop
    /// turns. A quarter of a second is far more than the gap and far less than a
    /// human deciding to press Return.
    nonisolated static let returnGrace: TimeInterval = 0.25

    private(set) var state: YubiKeyCaptureState = .idle

    /// The code, in the shared read-once box (`SingleUseCode`,
    /// EphemeralCredential.swift). Private: the ONLY way out is `consumeCode()`,
    /// which is what makes the no-retry rule structural rather than a convention.
    private var code: SingleUseCode?

    /// The deadline / cancel / timeout arithmetic, shared with every other
    /// credential source that waits on a human (`InteractionWait`,
    /// EphemeralCredential.swift). COMPOSED rather than reimplemented: what is
    /// generic is the arithmetic, and what is specific stays in
    /// `YubiKeyCaptureState` — a static password has no shape to recognise, a
    /// Yubico OTP does, and "spent" is a state a Touch ID prompt has no equivalent
    /// of.
    ///
    /// It also owns the completion instant, which is what the trailing-Return grace
    /// window is measured from.
    private(set) var wait = InteractionWait()

    /// When a code last landed. Read from the wait — one clock, not two, because
    /// two would eventually disagree and the Return decision turns on it.
    var lastLandingAt: Date? { wait.completedAt }

    /// What this VPN is set up to expect. Decides which field is armed and whether
    /// a 44-character shape is required.
    var mechanism: YubiKeyCodeMechanism = .yubicoOTP
    var delivery: YubiKeyCodeDelivery = .appendedToPassword

    /// The password box as it stood when the wait was armed. Only meaningful for
    /// `.staticPassword`, the one mechanism that captures INTO the password box:
    /// telling what the key typed from what the user typed means knowing where the
    /// user stopped. Nil for every other mechanism, which captures into the
    /// verification-code box and never touches the password.
    private(set) var passwordBeforeCapture: String?

    /// Which box the armed state must focus, and which box `observe` is being fed.
    var capturesInPasswordField: Bool { mechanism.capturesInPasswordField }

    init(mechanism: YubiKeyCodeMechanism = .yubicoOTP,
         delivery: YubiKeyCodeDelivery = .appendedToPassword) {
        self.mechanism = mechanism
        self.delivery = delivery
    }

    // MARK: Arming

    /// Arm the wait. `passwordSoFar` matters only for `.staticPassword`, where the
    /// capture box IS the password box.
    ///
    /// Arming DISCARDS any code already held. That is deliberate: a second touch
    /// replaces the first, and keeping the older one would mean the code we send is
    /// not the one the user just produced.
    func arm(now: Date = Date(), wait duration: TimeInterval = YubiKeyCapture.defaultWait,
             passwordSoFar: String? = nil) {
        code?.discard()
        code = nil
        passwordBeforeCapture = capturesInPasswordField ? (passwordSoFar ?? "") : nil
        wait.arm(now: now, wait: duration)
        state = .waiting(armedAt: now, expiresAt: now.addingTimeInterval(duration))
    }

    /// Give up on the wait, on the user's say-so. Not the same as a timeout: the
    /// wording differs and so does whether we offer to try again straight away.
    func cancel() {
        code?.discard()
        code = nil
        passwordBeforeCapture = nil
        wait.cancel()
        state = .cancelled
    }

    /// Back to nothing — a source change, a different VPN, the form closing.
    func reset() {
        code?.discard()
        code = nil
        passwordBeforeCapture = nil
        wait.reset()
        state = .idle
    }

    /// Called on a timer while armed. Returns true when it has just expired, so a
    /// caller can announce it exactly once.
    @discardableResult
    func tick(now: Date = Date()) -> Bool {
        guard wait.tick(now: now) else { return false }
        code?.discard()
        code = nil
        passwordBeforeCapture = nil
        state = .timedOut
        return true
    }

    /// Seconds left on the wait, rounded up so the countdown never shows 0 while
    /// it is still going.
    func secondsRemaining(now: Date = Date()) -> Int {
        wait.secondsRemaining(now: now)
    }

    // MARK: What arrived

    /// Feed the capture field's text. Called on every keystroke, so it must be
    /// cheap and must not react to a partially typed code.
    ///
    /// Returns true when a code just landed — the caller's cue to announce it and
    /// to move focus on.
    @discardableResult
    func observe(fieldText: String, now: Date = Date()) -> Bool {
        guard state.isWaiting else { return false }
        switch mechanism {
        case .yubicoOTP:
            return observeTypedOTP(fieldText, now: now)
        case .staticPassword:
            // A static password has no shape to recognise — that is the whole
            // point of supporting it, and checking one would MANGLE it. So the
            // text alone never completes a static capture; its trailing Return
            // does, in `noteReturn`.
            return false
        case .oathCode, .challengeResponse:
            // These are FETCHED, not typed. A key that types while we are waiting
            // for a fetch is a misconfiguration (the wrong mechanism chosen), and
            // silently accepting it would send a Yubico OTP to a gateway expecting
            // six digits.
            return false
        }
    }

    /// A typed Yubico OTP, arriving in the (empty) verification-code box. Nothing
    /// is done until at least a full code's worth of characters is there, so a
    /// half-typed burst is never reported as a malformed one.
    private func observeTypedOTP(_ text: String, now: Date) -> Bool {
        guard text.count >= YubicoOTPIdentity.defaultLength else { return false }
        return land(text, now: now)
    }

    /// Try to read `candidate` as a code and hold it.
    private func land(_ candidate: String, now: Date) -> Bool {
        switch YubicoOTP.read(candidate) {
        case .valid(let identity, let single):
            code?.discard()
            code = single
            wait.complete(now: now)
            state = .held(identity: identity, landedAt: now)
            return true
        case .invalid(let problem):
            // A code that is still arriving is not a failure. Only a string that is
            // already long enough to be one, and isn't, is worth reporting.
            switch problem {
            case .tooShort:
                return false
            case .empty, .tooLong, .oddLength, .outsideModhex:
                code?.discard()
                code = nil
                state = .notRecognised(problem)
                return false
            }
        }
    }

    /// A Return arrived in the capture field. Answers whether it may go on to
    /// become a submit, and — for a static password — completes the capture.
    ///
    /// This is where the trailing-Return decision is enacted; the decision itself
    /// is `YubiKeyReturnPolicy.decide`, kept pure and separately tested.
    func noteReturn(fieldText: String, now: Date = Date()) -> YubiKeyReturnPolicy.Decision {
        let decision = YubiKeyReturnPolicy.decide(
            state: state, lastLandingAt: lastLandingAt, now: now, grace: Self.returnGrace)
        // A static password has no recognisable shape, so its Return IS the
        // terminator: whatever is in the field when the key presses Return is the
        // password. Nothing about it is single-use.
        if case .swallowWhileWaiting = decision, mechanism == .staticPassword {
            let typed = staticPasswordPortion(of: fieldText)
            if !typed.isEmpty {
                code?.discard()
                // Not single-use in the gateway's eyes — a static password is the
                // same every time — but it still goes in the read-once box, so the
                // connect path has exactly ONE way to take a captured value and
                // cannot accidentally send a stale one.
                code = SingleUseCode(typed, origin: .typedByDevice)
                wait.complete(now: now)
                state = .held(identity: nil, landedAt: now)
            }
        }
        return decision
    }

    /// For a static password typed after something the user had already typed (a
    /// PIN, classically), what the KEY contributed.
    private func staticPasswordPortion(of fieldText: String) -> String {
        guard capturesInPasswordField, let before = passwordBeforeCapture,
              fieldText.hasPrefix(before) else { return fieldText }
        return String(fieldText.dropFirst(before.count))
    }

    // MARK: Spending it

    /// Take the code for one connect attempt. Returns nil when there is nothing to
    /// take — which is what a retry gets, by design.
    ///
    /// After this the machine is `.spent` and stays there until a fresh `arm`.
    func consumeCode() -> String? {
        guard let taken = code?.consume() else {
            // Nothing to give. If we thought we were holding something, correct
            // the state rather than leaving a lie on screen.
            if state.hasUnspentCode { state = .spent(identity: state.identity) }
            return nil
        }
        state = .spent(identity: state.identity)
        code = nil
        return taken
    }

    /// Everything the engine needs, composed, with the code consumed. THE call the
    /// connect path makes: it can only be made once, and it returns nil the second
    /// time — which is the single-use rule as an API rather than as a comment.
    ///
    /// For `.staticPassword` the key's contribution IS the password, so the halves
    /// come back the other way round.
    func consumeEngineInputs(password: String) -> (password: String, separateCode: String?)? {
        guard let taken = consumeCode() else { return nil }
        if capturesInPasswordField {
            // The password box already holds "what the user typed" + "what the key
            // typed", and that whole thing is the password. There is no code.
            return ((passwordBeforeCapture ?? "") + taken, nil)
        }
        return YubiKeyComposition.engineInputs(delivery: delivery, password: password, code: taken)
    }

    // MARK: What to show

    func advice(now: Date = Date()) -> YubiKeyCaptureAdvice {
        switch state {
        case .idle:
            return .askForTouch
        case .waiting:
            return .waiting(secondsRemaining: secondsRemaining(now: now))
        case .held:
            return .readyToSend
        case .spent:
            return .needsFreshTouch(reason: mechanism.isSingleUse
                ? "That code has been used. A one-time code only works once, so touch your key again "
                    + "for a fresh one."
                : "Touch your key again to fill the sign-in in.")
        case .timedOut:
            return .problem("No code arrived. Touch the gold disc on your security key while "
                            + "SimpleVPN is waiting \u{2014} or check the key is plugged in.")
        case .cancelled:
            return .askForTouch
        case .notRecognised(let problem):
            return .problem(problem.explanation)
        }
    }
}

// MARK: - The trailing-Return decision

/// Whether a Return in a capture field may become a submit. Pure, tiny, and
/// separated out precisely BECAUSE it is the bug everyone gets wrong: a decision
/// this consequential should be readable in one screen and tested exhaustively.
nonisolated enum YubiKeyReturnPolicy {

    nonisolated enum Decision: Sendable, Equatable {
        /// The key pressed it while we were waiting. Consume it; connect nothing.
        case swallowWhileWaiting
        /// The key pressed it just after finishing the code. Consume it.
        case swallowKeyTrailingReturn
        /// The user pressed it. Let the field submit as it always has.
        case submit

        var swallows: Bool { self != .submit }
    }

    /// The rule, in full:
    ///
    ///  • ARMED ⇒ swallow. Everything arriving during the wait belongs to the key,
    ///    and a Return during a wait cannot be a considered decision to connect —
    ///    the user is holding a key against a disc.
    ///  • A code landed within `grace` ⇒ swallow. The key types the code and the
    ///    Return as one burst; they reach us as separate events and the Return can
    ///    trail. This also covers the user who was already leaning on Return.
    ///  • Otherwise ⇒ submit. Once the capture has settled, Return is the user's
    ///    again and means exactly what it means in every other field in the app.
    ///
    /// Note it swallows in `.spent` and `.notRecognised` too, when inside the grace
    /// window: the events can arrive in either order under load, and the state
    /// having moved on is no reason to let a keystroke the KEY produced connect.
    static func decide(state: YubiKeyCaptureState, lastLandingAt: Date?,
                       now: Date, grace: TimeInterval) -> Decision {
        if state.isWaiting { return .swallowWhileWaiting }
        if let lastLandingAt, now.timeIntervalSince(lastLandingAt) < grace,
           now >= lastLandingAt {
            return .swallowKeyTrailingReturn
        }
        return .submit
    }
}

// MARK: - Composition

/// Joining a password and a code, and rescuing one that landed in the wrong box.
/// Pure functions throughout — this is the arithmetic of the feature, and it is
/// the part that must never be "obviously right".
nonisolated enum YubiKeyComposition {

    /// The template a delivery choice means, so the editor's template row and the
    /// connect path cannot disagree about the join. See
    /// `YubiKeyCodeDelivery.passwordTemplate`.
    static func template(for delivery: YubiKeyCodeDelivery) -> String {
        delivery.passwordTemplate
    }

    /// What the engine should be sent. Kept as an explicit function rather than
    /// left to the template alone so a caller that does NOT go through the template
    /// (a native IKEv2 profile, a subprocess engine's own prompt) composes the same
    /// way as one that does.
    ///
    ///  • `.appendedToPassword` — one string, password first, no separate code.
    ///  • `.separateField` — the halves stay apart; the engine answers the
    ///    server's own prompt with the code.
    ///  • `.codeOnly` — no password at all.
    static func engineInputs(delivery: YubiKeyCodeDelivery, password: String, code: String)
        -> (password: String, separateCode: String?) {
        switch delivery {
        case .appendedToPassword: (password + code, nil)
        case .separateField: (password, code)
        case .codeOnly: ("", code)
        }
    }

    /// A code that landed in the PASSWORD box when it should have gone in the
    /// verification-code box — because the user touched their key out of habit
    /// while the password field had focus, which is exactly what people do.
    ///
    /// Returns the password with the code cut off, and the code, or nil when there
    /// is no well-formed code on the end. Only the default 44-character shape is
    /// looked for and only at the END: scanning for any acceptable length anywhere
    /// would happily "find" a code inside a long password and cut it in half, and
    /// silently truncating somebody's password is far worse than not helping.
    static func rescueCodeFromPassword(_ fieldText: String) -> (password: String, code: String)? {
        YubicoOTP.splitPasswordAndCode(fieldText)
    }

    /// The verification-code box with a spent code taken back out. A retry must
    /// never resend it, and leaving it visible in the box is how someone believes
    /// it will be.
    static func clearedCodeField() -> String { "" }
}
