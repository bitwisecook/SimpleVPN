// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
//  YubiKeyAuthConfig.swift
//  Per-VPN security-key setup: whether one supplies this VPN's verification code,
//  which of the four mechanisms it uses, and where the code goes in the sign-in.
//
//  Stored inside `VPNAuthConfig` (so it rides `providerConfiguration["auth"]` with
//  the rest of the auth SHAPE), and it holds NO SECRETS — a mechanism, a delivery
//  choice, an account label, a slot number and a serial number, all of which are
//  printed on the key or chosen from a list. The code itself never lands here; it
//  lives in a `SingleUseCode` for as long as one connect attempt takes.
//
//  Everything in this file is pure data plus pure rules, which is what lets the
//  mutual exclusions be tested rather than discovered: two sources for one
//  verification code is the failure mode that costs a real one-time code to find
//  out about, so each conflict is a value with a sentence attached, decided in one
//  place and rendered wherever it is relevant.
//

import Foundation

// MARK: - The stored setup

nonisolated struct YubiKeyAuthConfig: Codable, Sendable, Equatable {

    /// A security key supplies this VPN's verification code. Off by default: this
    /// is opt-in per VPN, like every other sign-in choice in the app.
    var enabled = false

    /// Which of the four mechanisms. See `YubiKeyCodeMechanism`.
    var mechanism: YubiKeyCodeMechanism = .yubicoOTP

    /// Where the code goes in the sign-in — the choice that decides whether the
    /// gateway sees one field or two.
    var delivery: YubiKeyCodeDelivery = .appendedToPassword

    /// Which key, by the serial number printed on it. Empty = whichever key is
    /// plugged in, which is right for the overwhelming majority of people and
    /// wrong only for someone carrying two.
    var serial = ""

    /// For `.oathCode`: the account on the key, exactly as `ykman` lists it
    /// (`Issuer:name`). A label, not a secret.
    var oathAccount = ""

    /// For `.challengeResponse`: which slot holds the credential. Slot 2 by
    /// convention — slot 1 usually holds the factory Yubico OTP credential.
    var slot: YubiKeySlot = .two

    /// How long an armed "touch your key now" wait lasts, in seconds.
    var waitSeconds = Int(YubiKeyCapture.defaultWait)

    /// Arm the wait as soon as the sign-in form is ready, rather than after a
    /// click. On by default because the whole point is that the right field
    /// already has focus when the user reaches for their key — but switchable,
    /// because an armed field that steals a keystroke is worse than a button.
    var armAutomatically = true

    init() {}

    /// Every key optional, same lenient pattern as the blobs it lives inside: a
    /// setup written by a newer build must not throw away an older build's choice,
    /// and an unknown mechanism must fall back rather than discard the lot.
    init(from decoder: any Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        enabled = try c.decodeIfPresent(Bool.self, forKey: .enabled) ?? false
        // `try?`, not `decodeIfPresent`, for the three enums: an UNKNOWN raw value
        // THROWS rather than answering nil, so a blob written by a future build that
        // added a fifth mechanism would otherwise throw away the whole setup — the
        // user's serial number, their account name and their delivery choice — over
        // one field. Falling back per field is the lenient contract every other blob
        // in this app keeps.
        mechanism = (try? c.decode(YubiKeyCodeMechanism.self, forKey: .mechanism)) ?? .yubicoOTP
        delivery = (try? c.decode(YubiKeyCodeDelivery.self, forKey: .delivery)) ?? .appendedToPassword
        serial = try c.decodeIfPresent(String.self, forKey: .serial) ?? ""
        oathAccount = try c.decodeIfPresent(String.self, forKey: .oathAccount) ?? ""
        slot = (try? c.decode(YubiKeySlot.self, forKey: .slot)) ?? .two
        waitSeconds = try c.decodeIfPresent(Int.self, forKey: .waitSeconds)
            ?? Int(YubiKeyCapture.defaultWait)
        armAutomatically = try c.decodeIfPresent(Bool.self, forKey: .armAutomatically) ?? true
    }

    var isDefault: Bool { self == YubiKeyAuthConfig() }

    /// A wait clamped to something sane. A one-second wait is unusable and a
    /// ten-minute one is a field left armed all afternoon.
    var effectiveWait: TimeInterval {
        TimeInterval(min(max(waitSeconds, 5), 120))
    }

    /// The serial to pass to `ykman`, or nil. Digits only — anything else is a
    /// user's note to themselves, not a serial, and must not reach argv.
    var normalizedSerial: String? {
        let trimmed = serial.trimmingCharacters(in: .whitespaces)
        guard !trimmed.isEmpty, trimmed.allSatisfy(\.isNumber) else { return nil }
        return trimmed
    }

    /// The setup is complete enough to try. A mechanism that needs a name or a slot
    /// and hasn't got one is not "on", it is half-configured — and Connect must say
    /// so rather than failing at the gateway.
    var isUsable: Bool {
        guard enabled else { return false }
        switch mechanism {
        case .yubicoOTP, .staticPassword: return true
        case .oathCode: return !oathAccount.trimmingCharacters(in: .whitespaces).isEmpty
        case .challengeResponse: return true
        }
    }

    /// Why it is not usable yet, for the disabled-Connect reason.
    var incompleteReason: String? {
        guard enabled, !isUsable else { return nil }
        switch mechanism {
        case .oathCode:
            return "Choose which account on your security key holds this VPN\u{2019}s code."
        case .yubicoOTP, .staticPassword, .challengeResponse:
            return nil
        }
    }
}

// MARK: - Two sources for one code: the exclusions

/// Everything a conflict decision turns on. A plain value, so every rule below is
/// testable with no key, no `ykman` and no profile.
nonisolated struct YubiKeyConflictInputs: Sendable, Equatable {
    var config = YubiKeyAuthConfig()
    /// This VPN asks for a verification code at all. A security key that supplies
    /// a code to a VPN that wants none has nothing to do.
    var requiresOTP = false
    /// The profile itself declares the code prompt (`static-challenge`), so the
    /// code travels as the engine's challenge response and the password template
    /// is inert.
    var staticChallenge = false
    /// Where username and password come from.
    var credentialKind: CredentialSourceKind = .manual
    /// That source can hand over a code by itself (1Password, KeePassXC).
    var sourceSuppliesCode = false
    /// The Touch ID-protected item holds an authenticator seed, so the fingerprint
    /// already covers the code.
    var keychainSuppliesCode = false
    /// This VPN's password template, as configured.
    var passwordTemplate = YubiKeyTemplates.passwordThenCode
    /// `ykman` is installed somewhere SimpleVPN will run it.
    var managerToolInstalled = false
    /// A key is plugged in that will type when touched.
    var typingKeyAttached = false
}

/// A reason the security-key setup cannot do what it says, or a warning about a
/// combination that will not behave as the user expects. Each carries the sentence
/// it shows, because a conflict with no explanation is just a greyed-out row.
nonisolated enum YubiKeyConflict: Sendable, Equatable {

    /// This VPN doesn't ask for a code, so there is nothing for a key to supply.
    case noCodeWanted
    /// The password app already supplies the code. Two sources, one field.
    case sourceAlreadySuppliesCode(CredentialSourceKind)
    /// The Touch ID-protected sign-in already covers the code.
    case keychainAlreadySuppliesCode
    /// The mechanism needs `ykman`, which isn't installed.
    case needsManagerTool
    /// The password template and the delivery choice say different things about how
    /// the halves are joined. `expected` is the template the delivery implies.
    case templateDisagreesWithDelivery(expected: String)
    /// Nothing is plugged in that types. Not an error — a note.
    case noTypingKeyAttached

    /// Does this stop the setup working, or is it only worth mentioning?
    var isBlocking: Bool {
        switch self {
        case .noCodeWanted, .sourceAlreadySuppliesCode, .keychainAlreadySuppliesCode,
             .needsManagerTool:
            true
        case .templateDisagreesWithDelivery, .noTypingKeyAttached:
            false
        }
    }

    var explanation: String {
        switch self {
        case .noCodeWanted:
            "This VPN doesn\u{2019}t ask for a verification code, so there is nothing for a security "
                + "key to supply. Turn on \u{201C}Requires a verification code\u{201D} first."
        case .sourceAlreadySuppliesCode(let kind):
            "\(kind.displayName) already supplies this VPN\u{2019}s verification code. Two sources for "
                + "one code would send the wrong one, so pick whichever you want to use \u{2014} your "
                + "security key, or \(kind.displayName)."
        case .keychainAlreadySuppliesCode:
            "Your saved sign-in already covers the verification code, because it holds your "
                + "authenticator\u{2019}s setup key. Remove that setup key if you would rather use your "
                + "security key."
        case .needsManagerTool:
            "This needs Yubico\u{2019}s own command-line tool (ykman), which isn\u{2019}t installed on "
                + "this Mac. SimpleVPN never installs it for you."
        case .templateDisagreesWithDelivery(let expected):
            "Your password template doesn\u{2019}t match how you have asked the code to be sent. For "
                + "this choice it should be \u{201C}\(expected)\u{201D} \u{2014} SimpleVPN will use "
                + "that, and leave your template alone."
        case .noTypingKeyAttached:
            "No security key is plugged in at the moment. Plug yours in before you connect \u{2014} the "
                + "setup is saved either way."
        }
    }
}

nonisolated enum YubiKeyConflicts {

    /// Every conflict for this setup, blocking ones first. Order is stable so a
    /// view can show the first one and be showing the most important.
    static func all(_ inputs: YubiKeyConflictInputs) -> [YubiKeyConflict] {
        guard inputs.config.enabled else { return [] }
        var out: [YubiKeyConflict] = []

        // A static challenge means the server WILL ask, whatever the toggle says —
        // so it counts as wanting a code.
        if !inputs.requiresOTP && !inputs.staticChallenge {
            out.append(.noCodeWanted)
        }
        if inputs.sourceSuppliesCode, inputs.credentialKind != .manual {
            out.append(.sourceAlreadySuppliesCode(inputs.credentialKind))
        }
        if inputs.keychainSuppliesCode {
            out.append(.keychainAlreadySuppliesCode)
        }
        if inputs.config.mechanism.needsManagerTool, !inputs.managerToolInstalled {
            out.append(.needsManagerTool)
        }
        // Non-blocking notes.
        //
        // A profile-declared static challenge takes the code out of the password
        // entirely — the engine answers the server's prompt with it — so the
        // template is inert and disagreeing with it means nothing.
        if !inputs.staticChallenge {
            let expected = inputs.config.delivery.passwordTemplate
            let actual = inputs.passwordTemplate.trimmingCharacters(in: .whitespaces)
            if !actual.isEmpty, actual != expected {
                out.append(.templateDisagreesWithDelivery(expected: expected))
            }
        }
        if inputs.config.mechanism.isTypedByKey, !inputs.typingKeyAttached {
            out.append(.noTypingKeyAttached)
        }
        return out.sorted { $0.isBlocking && !$1.isBlocking }
    }

    /// The one sentence that stops this working, or nil.
    static func blockingReason(_ inputs: YubiKeyConflictInputs) -> String? {
        all(inputs).first { $0.isBlocking }?.explanation
    }

    /// Whether a security key will actually be asked for a code on the next
    /// connect. THE single answer the connect surface, the readiness decision and
    /// the editor all read.
    static func isActive(_ inputs: YubiKeyConflictInputs) -> Bool {
        inputs.config.isUsable && blockingReason(inputs) == nil
    }

    /// The template that will actually be used. While a security key is active its
    /// delivery choice OWNS the join — one control, one meaning — and this is the
    /// value both the editor's template row and the connect path read, so they
    /// cannot disagree.
    static func effectiveTemplate(_ inputs: YubiKeyConflictInputs) -> String {
        isActive(inputs) ? inputs.config.delivery.passwordTemplate
                         : inputs.passwordTemplate
    }

    /// Whether the VPN's own template row is inert — true while a security key is
    /// active, because the delivery choice decides it. A control that cannot change
    /// anything must be visibly dead and say why (AGENTS.md), not silently ignored.
    static func templateIsOwnedByDelivery(_ inputs: YubiKeyConflictInputs) -> Bool {
        isActive(inputs) && !inputs.staticChallenge
    }
}

// MARK: - The settings catalog

/// Every security-key control, one spec each, in the `yk.` namespace.
///
/// They are Sign-In settings by the AGENTS.md taxonomy — they are about how YOU
/// are identified — and every one of them is a control a user can see, including
/// the ones that look like plumbing, because an unspec'd control is invisible to
/// search, unaddressable by the CLI and MDM, and has no manual anchor behind its
/// help button.
/// Isolation matches every other catalog in the app (`SSHSettings`,
/// `WireGuardSettings`, …): main-actor, because `EngineSettingSpec` conforms to
/// `SearchableSetting` there and the registry that walks them is a view concern.
enum YubiKeySettings {

    static let all: [EngineSettingSpec] = [

        .init(id: "yk.enabled", name: "Use a Security Key",
              summary: "Get this VPN's verification code from a security key — a YubiKey or similar — instead of typing one.",
              group: .signIn, default: false),

        .init(id: "yk.mechanism", name: "What the Key Supplies",
              summary: "Which kind of code your key provides: the long one it types for you, a six-digit code stored on it, an answer to a challenge, or a fixed password.",
              group: .signIn, default: YubiKeyCodeMechanism.yubicoOTP),

        .init(id: "yk.delivery", name: "Where the Code Goes",
              summary: "Whether the code lands on the end of your password in one box — what most VPN gateways expect — or in its own verification code box.",
              group: .signIn, default: YubiKeyCodeDelivery.appendedToPassword),

        .init(id: "yk.serial", name: "Security Key Serial Number",
              summary: "Which key to use, by the serial number printed on it. Leave empty to use whichever one is plugged in.",
              group: .signIn, default: ""),

        .init(id: "yk.oath-account", name: "Account on the Key",
              summary: "Which account stored on your key holds this VPN's code. Only used when the key supplies a six- or eight-digit code.",
              group: .signIn, default: ""),

        .init(id: "yk.slot", name: "Key Slot",
              summary: "Which of the key's two slots answers the challenge. Slot 2 is the usual one — slot 1 normally holds the code your key types.",
              group: .signIn, default: YubiKeySlot.two),

        .init(id: "yk.wait-seconds", name: "How Long to Wait for a Touch",
              summary: "How many seconds SimpleVPN waits for you to touch your key before giving up.",
              group: .signIn, default: Int(YubiKeyCapture.defaultWait)),

        .init(id: "yk.arm-automatically", name: "Wait for a Touch Automatically",
              summary: "Start waiting for your key as soon as the sign-in is ready, so the right box already has the cursor in it. Turn this off to wait until you click.",
              group: .signIn, default: true),
    ]

    static let specs = EngineSettingCatalog(all)
}
