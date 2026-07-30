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

    func encodedBlob() -> Data? {
        guard !isDefault else { return nil }
        return try? JSONEncoder().encode(self)
    }

    static func decode(from blob: Data?) -> VPNAuthConfig {
        guard let blob else { return VPNAuthConfig() }
        return (try? JSONDecoder().decode(VPNAuthConfig.self, from: blob)) ?? VPNAuthConfig()
    }
}
