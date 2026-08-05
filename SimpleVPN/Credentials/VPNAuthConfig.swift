// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
//  VPNAuthConfig.swift
//  Per-VPN authentication shape: whether connecting needs a one-time passcode,
//  and how the engine password is assembled from the parts. Stored (no secrets)
//  as a JSON blob in providerConfiguration["auth"], same lenient pattern as
//  OpenVPNOverrides — a corrupt or missing blob is just the defaults.
//

import Foundation

struct VPNAuthConfig: Codable, Sendable, Equatable {

    static let defaultTemplate = "{password}{otp}"

    /// Connecting requires a fresh one-time passcode each time. The connection
    /// form shows the OTP field, Connect requires it, and menu-bar quick
    /// connect routes to the window instead of silently omitting the code.
    var requiresOTP = false

    /// How the auth password is assembled; `{password}` and `{otp}` tokens.
    /// Only consulted while `requiresOTP` is on.
    var passwordTemplate = defaultTemplate

    /// One remember preference shared by every surface (main window, menu bar,
    /// edit sheet). Ignored — treated as false — when the profile forbids saving.
    var rememberCredentials = true

    /// Credentials live in a Touch ID-gated keychain item instead of the plain
    /// keychain: connecting asks for a fingerprint (or Watch / account password)
    /// to release them. Optional so blobs written by older builds still decode;
    /// nil means off. Only meaningful for the manual/saved credential source.
    var biometricProtection: Bool? = nil
    var protectWithBiometrics: Bool {
        get { biometricProtection ?? false }
        set { biometricProtection = newValue ? true : nil }
    }

    /// A security key (a YubiKey or similar) supplies this VPN's verification
    /// code. Optional, and nil when unset, for the same reason as
    /// `biometricProtection`: an older build's blob has no such key, and a
    /// default-valued struct must not make an otherwise-default config look
    /// changed (`isDefault` drives whether the blob is written at all). Holds no
    /// secrets — see YubiKeyAuthConfig.
    var securityKey: YubiKeyAuthConfig? = nil
    var yubiKey: YubiKeyAuthConfig {
        get { securityKey ?? YubiKeyAuthConfig() }
        set { securityKey = newValue.isDefault ? nil : newValue }
    }

    init() {}

    /// The credential request this configuration implies.
    var request: CredentialRequest {
        requiresOTP
            ? CredentialRequest(fields: [.username, .password, .otp],
                                passwordTemplate: normalizedTemplate)
            : .usernamePassword
    }

    /// A usable template: must mention {otp} while OTP is required, else fall
    /// back to the default rather than silently sending an OTP-less password.
    var normalizedTemplate: String {
        let t = passwordTemplate.trimmingCharacters(in: .whitespaces)
        guard !t.isEmpty, t.contains("{otp}") else { return Self.defaultTemplate }
        return t
    }

    var isDefault: Bool { self == VPNAuthConfig() }

    /// The auth shape an editor must SAVE, given what the PROFILE itself declares.
    /// Two profile facts override whatever the form's state holds, because that
    /// state outlives the profile it was entered against:
    ///
    ///  • `autologin` — there is no password and no code to collect, so an OTP
    ///    requirement and a password template are dead state. Without this, a
    ///    profile that was OTP-enabled and later became autologin kept
    ///    `requiresOTP: true` and went on prompting at every connect, even though
    ///    the Sign-In tab had correctly replaced the whole credential UI.
    ///
    ///  • `staticChallenge` — the server will demand the code regardless of the
    ///    toggle, so the stored shape must agree with `effectiveAuthConfig` (which
    ///    the connect flow reads) rather than contradict it. The template is left
    ///    alone: it is inert under a static challenge (the code travels as the
    ///    engine's challenge response, never concatenated into the password) but
    ///    becomes live again if the directive leaves the configuration.
    static func resolved(_ raw: VPNAuthConfig, autologin: Bool, staticChallenge: Bool) -> VPNAuthConfig {
        var out = raw
        if autologin {
            out.requiresOTP = false
            out.passwordTemplate = defaultTemplate
            // Same reasoning as the OTP requirement above, and the same bug if it
            // is left behind: there is no code to collect, so a security-key setup
            // is dead state that would go on arming a touch prompt at every
            // connect for a sign-in that is already a certificate.
            out.securityKey = nil
        } else if staticChallenge {
            out.requiresOTP = true
        }
        return out
    }

    func encodedBlob() -> Data? {
        guard !isDefault else { return nil }
        return try? JSONEncoder().encode(self)
    }

    static func decode(from blob: Data?) -> VPNAuthConfig {
        guard let blob else { return VPNAuthConfig() }
        return (try? JSONDecoder().decode(VPNAuthConfig.self, from: blob)) ?? VPNAuthConfig()
    }
}

/// Per-VPN interface preferences: which OPTIONAL controls this VPN shows.
/// Advanced surfaces are opt-in per VPN so the default interface stays simple —
/// most people never need to pause a tunnel or read a health panel. Stored as
/// providerConfiguration["uiprefs"], same lenient blob pattern as above.
struct VPNUIPrefs: Codable, Sendable, Equatable {

    /// Show the Pause control (header, sidebar, menu bar). Pause keeps the
    /// session signed in but routes traffic outside the VPN until resumed.
    var allowPause = false

    /// Show the Connection Manager panel (health checks + connection toggles)
    /// on the connection page.
    var showConnectionManager = false

    init() {}

    var isDefault: Bool { self == VPNUIPrefs() }

    func encodedBlob() -> Data? {
        guard !isDefault else { return nil }
        return try? JSONEncoder().encode(self)
    }

    static func decode(from blob: Data?) -> VPNUIPrefs {
        guard let blob else { return VPNUIPrefs() }
        return (try? JSONDecoder().decode(VPNUIPrefs.self, from: blob)) ?? VPNUIPrefs()
    }
}
