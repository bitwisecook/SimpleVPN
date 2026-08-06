// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
//  FeatureRequests.swift
//  THE THINGS SIMPLEVPN DELIBERATELY DOES NOT DO, and where to ask for them.
//
//  WHY THIS IS NOT `FeatureMaturity`, and the distinction is the whole point of a
//  separate file. That registry answers "how much confidence is there in code we
//  shipped?" — three states, all of which mean the code EXISTS and might work.
//  Every sentence it produces ends in "it may well work, tell us what happened".
//  Reusing it here would put exactly the wrong words on screen: an "Untested" badge
//  on a smartcard row would tell somebody holding a card their employer issued that
//  the feature is there and unproven, and they would spend an afternoon finding out
//  that it is not there at all.
//
//  So this is a third axis, orthogonal to both maturity and availability:
//    • AVAILABILITY — is the thing installed on THIS Mac right now (a live probe).
//    • MATURITY     — has anyone seen OUR code work (a constant, one line per
//                     subject, `FeatureMaturityRegistry`).
//    • THIS FILE    — is there any code at all. There is not, and there is no
//                     promise that there will be.
//
//  WHAT IT IS FOR, and it is not a tombstone. Somebody arrives looking for
//  smartcard sign-in — because their gateway demands it, or because they read that
//  SimpleVPN once had it. A row that has simply vanished teaches them nothing and
//  teaches US nothing. A row that says "open an issue and describe your use case"
//  turns that visit into the one input the decision actually needs: which gateway,
//  which device, and what their organisation will and will not allow. Guessing at
//  that is how the removed implementation came to exist in the first place — written
//  against no real token and no real gateway, and unverifiable here.
//
//  IT MUST NOT IMPLY THE FEATURE IS COMING. Every string below is written to be
//  true whether or not it is ever built: no "yet", no "planned", no "soon". The
//  banner asks for evidence and says the decision is open, and that is all.
//
//  THE FEEDBACK PATH IS THE EXISTING ONE. `DiagnosticReportRequest` +
//  `DiagnosticReportCoordinator.presentReport` — the same dialog the "Untested"
//  banner opens, with the same allow-listed payload, the same per-section switches
//  and the same "nothing leaves without you reading it" promise. Two new `Reason`
//  cases carry the wording; there is no second submission path.
//

import Foundation

/// One capability SimpleVPN does not implement, and the ask that goes with it.
///
/// A value type with named instances rather than an enum with computed properties,
/// for the same reason `FeatureMaturityRegistry` is a dictionary: one declaration per
/// subject, greppable, and a diff that adds or removes one is unambiguous.
nonisolated struct FeatureRequestNotice: Sendable, Equatable, Identifiable {

    /// What is missing, named the way the user sees it. Used in the banner, in the
    /// button's help text and in the spoken label.
    var subject: String
    /// Stable key for the collapse flag and the accessibility identifiers. Derived
    /// from the subject's identity, never from its display name, so rewording the
    /// banner does not silently un-collapse it. Never a user's data.
    var key: String
    /// Paired with words everywhere it appears, never colour alone.
    var symbolName: String
    /// The banner's bold first line. States the absence, flatly.
    var title: String
    /// The paragraph: what is missing, what to do instead right now, and what the
    /// decision would turn on.
    var detail: String
    /// Which report this banner opens.
    var reason: DiagnosticReportRequest.Reason

    var id: String { key }

    /// The whole notice as one sentence, for a container's accessibility label.
    var spokenSummary: String { "\(title). \(detail)" }

    /// What Connect says when a stored profile asks for this. It has to agree with
    /// the banner — a refusal that says something different from the row above it is
    /// how a user concludes one of the two is lying — so it is derived here rather
    /// than written a second time in `SubprocessTunnelManager`.
    ///
    /// Note what it does NOT say: it never suggests changing the sign-in method. The
    /// profile was set up this way by somebody who knew what the gateway wanted, and
    /// "switch to a password" may be advice to do something the gateway refuses.
    var blockedConnectReason: String {
        "\(title) This VPN is still configured for it and nothing has been changed \u{2014} SimpleVPN "
            + "would rather refuse than sign in some other way you didn\u{2019}t ask for. Open this "
            + "VPN\u{2019}s Sign-In settings for what works instead, and for how to ask for this."
    }

    // MARK: The two

    /// PKCS#11 — a certificate held on a smartcard, a PIV-enabled YubiKey or an HSM.
    /// Removed rather than repaired; `Docs/AuthSecPKCS11.md` records why, including
    /// why rebuilding the vendored OpenConnect with GnuTLS and p11-kit would not have
    /// helped (AMFI forbids inside a system-extension-embedding app the very `dlopen`
    /// that p11-kit exists to perform).
    ///
    /// NOT the same thing as a YubiKey that TYPES a code. That is built, it is a
    /// priority, and it is untouched — `Docs/AuthSecYubiKey.md`. The two share a
    /// device and nothing else.
    static let smartcardSignIn = FeatureRequestNotice(
        subject: "Smartcard or security-key sign-in",
        key: "not-built.smartcard",
        symbolName: "person.badge.key",
        title: "SimpleVPN doesn\u{2019}t sign in with a smartcard.",
        detail: "A certificate held on a smartcard, a PIV-enabled YubiKey or an HSM \u{2014} where the "
            + "key never leaves the device \u{2014} is not something SimpleVPN can use. There was an "
            + "implementation and it was removed: it had never been run against a real card or a real "
            + "gateway, so nobody could say whether it worked, and shipping a sign-in method that "
            + "might silently fail is worse than not offering one. Whether it comes back depends "
            + "entirely on hearing from people who need it, and what would decide it is your "
            + "situation rather than your vote: which gateway, which device, and whether your "
            + "organisation leaves you any other way in. A certificate in a FILE still works, and so "
            + "does single sign-on where your gateway offers it.",
        reason: .smartcardRequest)

    /// OpenConnect's own `--token-mode` code generator: TOTP, HOTP, OIDC, RSA
    /// SecurID, `yubioath`.
    ///
    /// A SEPARATE GATE, closed for its own reasons rather than as fallout from the
    /// smartcard removal: the seed is a long-lived secret and there is no channel
    /// that carries it to the packet-tunnel extension, while `rsa` and `yubioath`
    /// need libstoken and libpcsclite, which the vendored OpenConnect is built
    /// without. Typing the code always works, and a password app that holds
    /// verification codes can fill it in (Docs/CredentialSources.md).
    static let verificationCodeToken = FeatureRequestNotice(
        subject: "A verification-code token SimpleVPN generates",
        key: "not-built.verification-code-token",
        symbolName: "123.rectangle",
        title: "SimpleVPN doesn\u{2019}t generate verification codes.",
        detail: "It asks you for the code instead \u{2014} typed, or filled in from a password app "
            + "that holds it. Having SimpleVPN compute the code itself (TOTP, HOTP, RSA SecurID) "
            + "means holding the seed, which generates every future code and would have to reach the "
            + "part of SimpleVPN that builds the tunnel; there is no channel for that, and the "
            + "hardware-token kinds need libraries this build doesn\u{2019}t carry. So the code comes "
            + "from you or from your password app. If that doesn\u{2019}t work where you are, the "
            + "useful thing to send is why: which gateway asks, where the code comes from today, and "
            + "what stops you typing it.",
        reason: .verificationCodeTokenRequest)

    /// Both, for the tests that hold the copy to the house rules.
    static let all: [FeatureRequestNotice] = [smartcardSignIn, verificationCodeToken]
}
