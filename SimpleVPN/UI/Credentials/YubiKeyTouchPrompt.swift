// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
//  YubiKeyTouchPrompt.swift
//  "Touch your key now" — the visible half of the armed capture.
//
//  It exists because a security key types into WHATEVER HAS FOCUS, so the honest
//  UI is not a field the user is expected to aim at: it is a state that says "the
//  right box has the cursor, I am waiting, here is how long for, and here is how
//  to stop". Every one of those four things is on screen, and every one of them is
//  in the accessibility tree — the prompt is ANNOUNCED when it arms, when a code
//  lands, when it times out and when it is cancelled, because a blind user has no
//  other way to know that a field somewhere has quietly started listening.
//
//  ACCESSIBILITY, per Docs/Accessibility.md:
//   • The prompt is ONE element that reads as a sentence (label + live value).
//   • Every state change goes through `AccessibilityAnnouncer.sayNow` — the
//     user-initiated path, because arming IS a user action and the click is the
//     debounce. Never `AccessibilityNotification.Announcement` from a view.
//   • The countdown is in the element's VALUE, so it is spoken on focus, but it is
//     deliberately NOT announced every second: a prompt that talks over itself
//     nine times is worse than one that says nothing.
//   • The spinner is drawn, not hosted (`DrawnSpinner`) — the house rule about
//     platform-backed views inside animated containers.
//   • Reduce Motion: the pulse becomes a static ring.
//   • Nothing is hover-only. Cancel is a real button with a key equivalent.
//

import SwiftUI

// MARK: - The seam a credential field offers

/// Anything that gets to watch a credential field's text as it is typed, and to
/// VETO a Return before it becomes a submit.
///
/// This is the whole hook `AutoFillField` needs for the trailing-Return problem,
/// and it is deliberately generic — the field knows nothing about security keys,
/// and this protocol names no vendor. Nil policy = the field behaves exactly as it
/// always has.
@MainActor
protocol CredentialFieldReturnPolicy: AnyObject {
    /// The field's text, synchronously, on every keystroke. Synchronous matters:
    /// a key types 44 characters and a Return in one burst, and a decision routed
    /// through a SwiftUI binding would not have been made yet when the Return
    /// arrives.
    func fieldTextChanged(_ text: String)
    /// True = let Return submit, as it always has. False = swallow the keystroke.
    func fieldShouldSubmitOnReturn() -> Bool
}

/// The security-key implementation of that seam: a thin adapter onto
/// `YubiKeyCapture`, whose `YubiKeyReturnPolicy.decide` owns the actual rule.
///
/// A class, not a struct, and held by the view for the field's lifetime, because
/// the coordinator inside `AutoFillField` needs a stable identity to consult and
/// SwiftUI rebuilds structs freely.
@MainActor
final class YubiKeyFieldReturnPolicy: CredentialFieldReturnPolicy {

    private let capture: YubiKeyCapture
    /// Called when a code lands, so the surrounding view can announce it and move
    /// focus on to whatever is still empty.
    private let onCodeLanded: (YubicoOTPIdentity?) -> Void

    init(capture: YubiKeyCapture, onCodeLanded: @escaping (YubicoOTPIdentity?) -> Void) {
        self.capture = capture
        self.onCodeLanded = onCodeLanded
    }

    func fieldTextChanged(_ text: String) {
        if capture.observe(fieldText: text) {
            onCodeLanded(capture.state.identity)
        }
    }

    /// THE trailing-Return gate. See YubiKeyTouchCapture.swift's header for the
    /// reasoning; this is only the wiring.
    func fieldShouldSubmitOnReturn() -> Bool {
        !capture.noteReturn(fieldText: "").swallows
    }
}

// MARK: - The prompt

struct YubiKeyTouchPrompt: View {

    let capture: YubiKeyCapture
    /// This VPN's setup — decides the wording and how long the wait lasts.
    let config: YubiKeyAuthConfig
    /// What is plugged in, so the prompt can say "no key is plugged in" rather
    /// than counting down against nothing.
    let presence: SecurityKeyPresence
    /// Arm the wait. Owned by the caller because arming also has to put focus in
    /// the right box, which only the caller knows how to do.
    let arm: () -> Void

    @Environment(\.accessibilityReduceMotion) private var reduceMotion
    /// Re-read on a timer only while armed, so the countdown moves.
    @State private var now = Date()
    @State private var pulsing = false

    private var advice: YubiKeyCaptureAdvice { capture.advice(now: now) }

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            content
        }
        .padding(10)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(background, in: RoundedRectangle(cornerRadius: 10))
        // A container: it holds a button. So an explicit sentence of its own,
        // rather than a `.combine` that would swallow Cancel (the wave-3 bug
        // class — Docs/Accessibility.md rule 4).
        .accessibilityElement(children: .contain)
        .accessibilityLabel(accessibilityLabelText)
        .accessibilityValue(accessibilityValueText)
        .accessibilityIdentifier("security-key-touch-prompt")
        .task(id: capture.state) { await runCountdown() }
        .onChange(of: capture.state) { _, new in announce(new) }
    }

    // MARK: The four states, on screen

    @ViewBuilder private var content: some View {
        switch advice {
        case .askForTouch:
            idleRow
        case .waiting(let secondsRemaining):
            waitingRow(secondsRemaining)
        case .readyToSend:
            readyRow
        case .needsFreshTouch(let reason):
            messageRow(reason, symbol: "arrow.clockwise.circle.fill", tint: .orange, offersTouch: true)
        case .problem(let reason):
            messageRow(reason, symbol: "exclamationmark.triangle.fill", tint: .orange, offersTouch: true)
        }
    }

    private var idleRow: some View {
        HStack(alignment: .firstTextBaseline, spacing: 10) {
            Image(systemName: "key.radiowaves.forward.fill")
                .foregroundStyle(.blue)
                .accessibilityHidden(true)          // the text says the same thing
            VStack(alignment: .leading, spacing: 2) {
                Text(config.mechanism.isTypedByKey
                     ? "Ready for your security key"
                     : "Ready to ask your security key")
                    .font(.callout.weight(.semibold))
                Text(idleExplanation)
                    .font(.callout).foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }
            Spacer(minLength: 8)
            Button(config.mechanism.isTypedByKey ? "Wait for My Touch" : "Get the Code") {
                arm()
            }
            .buttonStyle(.glassProminent)
            .disabled(!canArm)
            .help(armDisabledReason ?? "Put the cursor in the right box and wait for your key.")
            .accessibilityValue(armDisabledReason ?? "")
        }
    }

    private func waitingRow(_ secondsRemaining: Int) -> some View {
        HStack(alignment: .firstTextBaseline, spacing: 10) {
            waitingGlyph
            VStack(alignment: .leading, spacing: 2) {
                Text(config.mechanism.isTypedByKey
                     ? "Touch your security key now"
                     : "Asking your security key\u{2026}")
                    .font(.callout.weight(.semibold))
                Text(config.mechanism.isTypedByKey
                     ? "Press the gold disc. The cursor is already in the right box, so the code will "
                        + "land there \u{2014} and SimpleVPN will not connect on its own."
                     : "If your key\u{2019}s light is flashing, touch it.")
                    .font(.callout).foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
                // The countdown is text, not only a shrinking bar: a bar is
                // invisible to VoiceOver and unreadable at a glance.
                Text("\(secondsRemaining)s left")
                    .font(.caption.monospacedDigit()).foregroundStyle(.secondary)
            }
            Spacer(minLength: 8)
            Button("Cancel") { capture.cancel() }
                // ESC, the house contract for backing out (Docs/Accessibility.md).
                .keyboardShortcut(.cancelAction)
                .accessibilityLabel("Stop waiting for your security key")
        }
    }

    /// Drawn, never a hosted ProgressView — see the file header.
    @ViewBuilder private var waitingGlyph: some View {
        if config.mechanism.isTypedByKey {
            Image(systemName: "hand.point.up.left.fill")
                .foregroundStyle(.blue)
                .scaleEffect(reduceMotion ? 1 : (pulsing ? 1.12 : 1))
                .onAppear {
                    guard !reduceMotion else { return }
                    withAnimation(.easeInOut(duration: 0.7).repeatForever()) { pulsing = true }
                }
                .onDisappear { pulsing = false }
                .accessibilityHidden(true)
        } else {
            DrawnSpinner()
                .accessibilityHidden(true)
        }
    }

    private var readyRow: some View {
        HStack(alignment: .firstTextBaseline, spacing: 10) {
            Image(systemName: "checkmark.circle.fill")
                .foregroundStyle(.green)
                .accessibilityHidden(true)
            VStack(alignment: .leading, spacing: 2) {
                Text("Code ready to send").font(.callout.weight(.semibold))
                // SCOPE HONESTY, and it is a rule not a nicety: a Yubico OTP is
                // verified by the SERVER. Saying "verified" or even "checked" here
                // would be a claim we cannot back, and would make a rejected code
                // look like our bug rather than a wrong key or a mistyped account.
                Text(readyExplanation)
                    .font(.callout).foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
                if let identity = capture.state.identity {
                    // The public ID is published in cleartext by design, so it is
                    // the one part of a code that is safe to show — and it answers
                    // "did the right key just type?" for someone with two.
                    HStack(spacing: 4) {
                        Text("From key").font(.caption).foregroundStyle(.secondary)
                        Text(identity.grouped)
                            .font(.caption.monospaced())
                            .textSelection(.enabled)
                    }
                    .accessibilityElement(children: .combine)
                    .accessibilityLabel("From security key \(identity.spelledOut)")
                }
            }
            Spacer(minLength: 8)
            Button("Touch Again") { arm() }
                .accessibilityLabel("Replace this code with a fresh touch")
        }
    }

    private func messageRow(_ text: String, symbol: String, tint: Color,
                            offersTouch: Bool) -> some View {
        HStack(alignment: .firstTextBaseline, spacing: 10) {
            Image(systemName: symbol).foregroundStyle(tint).accessibilityHidden(true)
            Text(text)
                .font(.callout)
                .fixedSize(horizontal: false, vertical: true)
            Spacer(minLength: 8)
            if offersTouch {
                Button(config.mechanism.isTypedByKey ? "Try Again" : "Ask Again") { arm() }
                    .disabled(!canArm)
                    .help(armDisabledReason ?? "")
                    .accessibilityValue(armDisabledReason ?? "")
            }
        }
    }

    // MARK: Wording

    private var idleExplanation: String {
        if config.mechanism.isTypedByKey {
            return presence.hasTypingKey
                ? "SimpleVPN will put the cursor in the right box and wait, so your key\u{2019}s code "
                    + "lands where it belongs."
                : "\(presence.summary) SimpleVPN will still wait, in case you plug one in."
        }
        return "SimpleVPN will ask your key for this VPN\u{2019}s code using Yubico\u{2019}s own tool."
    }

    private var readyExplanation: String {
        switch config.mechanism {
        case .yubicoOTP:
            "Your VPN\u{2019}s server checks this code when you connect \u{2014} SimpleVPN passes it on "
                + "and cannot check it itself. It works once."
        case .oathCode:
            "It works once, and only for the next few seconds."
        case .challengeResponse:
            "Your key answered the challenge. The answer works once."
        case .staticPassword:
            "Your key typed its fixed password."
        }
    }

    private var canArm: Bool { armDisabledReason == nil }

    private var armDisabledReason: String? {
        if config.mechanism.needsManagerTool, !presence.managerToolInstalled {
            return "Yubico\u{2019}s own command-line tool (ykman) isn\u{2019}t installed on this Mac."
        }
        if let incomplete = config.incompleteReason { return incomplete }
        return nil
    }

    private var background: AnyShapeStyle {
        switch advice {
        case .waiting: AnyShapeStyle(.blue.opacity(0.10))
        case .readyToSend: AnyShapeStyle(.green.opacity(0.10))
        case .needsFreshTouch, .problem: AnyShapeStyle(.orange.opacity(0.10))
        case .askForTouch: AnyShapeStyle(.quaternary.opacity(0.5))
        }
    }

    // MARK: Accessibility sentences

    private var accessibilityLabelText: String {
        config.mechanism.isTypedByKey ? "Security key touch" : "Security key code"
    }

    /// The whole state in words, kept live. The countdown rides here so it is
    /// spoken when focus lands, without being announced every second.
    private var accessibilityValueText: String {
        switch advice {
        case .askForTouch:
            "Ready. \(idleExplanation)"
        case .waiting(let seconds):
            config.mechanism.isTypedByKey
                ? "Waiting for your touch. \(seconds) seconds left."
                : "Asking your security key. \(seconds) seconds left."
        case .readyToSend:
            capture.state.identity.map {
                "A code is ready to send, from security key \($0.spelledOut). \(readyExplanation)"
            } ?? "A code is ready to send. \(readyExplanation)"
        case .needsFreshTouch(let reason), .problem(let reason):
            reason
        }
    }

    // MARK: Announcing

    /// Every transition is spoken, because none of them is discoverable: a field
    /// silently becoming armed, a code silently landing, and a wait silently
    /// expiring are all invisible without sight of the prompt.
    private func announce(_ state: YubiKeyCaptureState) {
        switch state {
        case .idle:
            break
        case .waiting:
            AccessibilityAnnouncer.sayNow(
                config.mechanism.isTypedByKey
                    ? "Touch your security key now. The cursor is in the verification code box, and "
                        + "SimpleVPN will not connect on its own."
                    : "Asking your security key for a verification code.")
        case .held(let identity, _):
            AccessibilityAnnouncer.sayNow(
                identity.map { "Verification code ready, from security key \($0.spelledOut)." }
                    ?? "Verification code ready.")
        case .spent:
            AccessibilityAnnouncer.sayNow(
                "That verification code has been used. Touch your security key again for a fresh one.")
        case .timedOut:
            AccessibilityAnnouncer.sayNow("No code arrived from your security key.")
        case .cancelled:
            AccessibilityAnnouncer.sayNow("Stopped waiting for your security key.")
        case .notRecognised(let problem):
            AccessibilityAnnouncer.sayNow("That wasn\u{2019}t a security key code. \(problem.shortReason).")
        }
    }

    // MARK: The countdown

    /// One tick a second, ONLY while armed, and it stops the moment the state
    /// leaves `.waiting` — a timer that outlives its prompt is how a view goes on
    /// redrawing behind a closed sheet.
    private func runCountdown() async {
        now = Date()
        guard capture.state.isWaiting else { return }
        while capture.state.isWaiting {
            do { try await Task.sleep(for: .seconds(1)) } catch { return }
            now = Date()
            capture.tick(now: now)
        }
    }
}
