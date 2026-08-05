// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
//  AuthKindCopy.swift
//  What each `AuthKind` is CALLED, and which of them a given VPN actually needs.
//
//  Separate from `Shared/AuthKind.swift` for the same reason `LocalVaultCopy` is
//  separate from a vendor's probe: the words are reviewable and testable without a
//  vault, a token or a tunnel anywhere near the machine — and because the kind enum
//  is compiled into the system extension, which has no UI and must not carry copy.
//
//  This file replaces `CredentialRole.swift`. That type WAS this: the same palette of
//  authentication slots, with the same titles, hints and symbols, and the same
//  `forOpenVPN` rule — but declared as a SECOND enum whose ids "reuse
//  CredentialField.rawValue where they overlap" by convention. One enum with its
//  copy in an extension says the same thing and cannot drift.
//

import Foundation

nonisolated extension AuthKind {

    /// The row's name. House glossary: "verification code", never "OTP" or
    /// "one-time password"; "username"/"password", never "user" or "login".
    var title: String {
        switch self {
        case .username: "Username"
        case .password: "Password"
        case .otp: "Verification code"
        case .passkey: "Passkey"
        case .certificate: "Client certificate"
        case .privateKeyPassphrase: "Private-key passphrase"
        case .sshKey: "SSH private key"
        // The two possession kinds. Both name a THING SOMEBODY HAS rather than
        // something they know, and the wording has to carry that or the row reads as
        // one more password to find.
        case .keyInAgent: "Key held by an agent"
        case .tokenPIN: "Security key PIN"
        }
    }

    var hint: String {
        switch self {
        case .username: "Signed-in account name"
        case .password: "Base password (before any one-time code)"
        case .otp: "A TOTP field — 1Password generates the current code"
        case .passkey: "A WebAuthn passkey stored in the item"
        case .certificate: "PEM client certificate the server requires"
        case .privateKeyPassphrase: "Passphrase that unlocks the client's private key"
        case .sshKey: "PEM/OpenSSH private key for the SSH tunnel"
        case .keyInAgent: "The agent signs — the key itself never leaves it"
        case .tokenPIN: "Unlocks the security key. Three wrong tries can block it."
        }
    }

    var systemImage: String {
        switch self {
        case .username: "person"
        case .password: "key"
        case .otp: "clock.arrow.circlepath"
        case .passkey: "person.badge.key"
        case .certificate: "checkmark.seal"
        case .privateKeyPassphrase: "lock.rotation"
        case .sshKey: "terminal"
        case .keyInAgent: "point.3.filled.connected.trianglepath.dotted"
        case .tokenPIN: "key.card"
        }
    }
}

nonisolated extension AuthKind {
    /// Which kinds an OpenVPN profile authenticates with, from the engine's own
    /// evaluation plus the per-profile verification-code setting. Returns [] for
    /// auto-login profiles (the certificate IS the sign-in). Only kinds the connect
    /// flow can actually consume are returned, so no sheet ever offers a slot that
    /// does nothing.
    static func forOpenVPN(evaluation: ProfileEvaluation?, requiresOTP: Bool) -> [AuthKind] {
        guard let e = evaluation else { return [.username, .password] }
        if e.autologin { return [] }
        var kinds: [AuthKind] = []
        if e.userlockedUsername.isEmpty { kinds.append(.username) }   // fixed username ⇒ nothing to map
        kinds.append(.password)
        if requiresOTP || !e.staticChallenge.isEmpty { kinds.append(.otp) }
        if e.privateKeyPasswordRequired { kinds.append(.privateKeyPassphrase) }
        return kinds
    }
}
