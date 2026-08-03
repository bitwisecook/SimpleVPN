// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
//  CredentialRole.swift
//  The palette of authentication "slots" a VPN can fill from a password manager,
//  and the logic that decides which of them a specific VPN actually uses. The
//  1Password field-mapping sheet renders exactly the roles a VPN needs — an
//  OpenVPN profile with a one-time-code shows username/password/one-time-code; a
//  cert-only profile shows the certificate slot; an SSH tunnel shows its key.
//  Role ids reuse CredentialField.rawValue where they overlap so the provider and
//  the stored mapping agree on names.
//

import Foundation

enum CredentialRole: String, CaseIterable, Identifiable, Sendable {
    case username
    case password
    case otp
    case passkey
    case certificate
    case privateKeyPassphrase
    case sshKey

    var id: String { rawValue }

    var title: String {
        switch self {
        case .username: "Username"
        case .password: "Password"
        case .otp: "One-time code"
        case .passkey: "Passkey"
        case .certificate: "Client certificate"
        case .privateKeyPassphrase: "Private-key passphrase"
        case .sshKey: "SSH private key"
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
        }
    }
}

extension CredentialRole {
    /// Which roles an OpenVPN profile authenticates with, from the engine's own
    /// evaluation plus the per-profile OTP setting. Returns [] for auto-login
    /// profiles (no credentials needed). Only roles the connect flow can actually
    /// consume are returned, so the sheet never offers a slot that does nothing.
    static func forOpenVPN(evaluation: ProfileEvaluation?, requiresOTP: Bool) -> [CredentialRole] {
        guard let e = evaluation else { return [.username, .password] }
        if e.autologin { return [] }
        var roles: [CredentialRole] = []
        if e.userlockedUsername.isEmpty { roles.append(.username) }   // fixed username ⇒ nothing to map
        roles.append(.password)
        if requiresOTP || !e.staticChallenge.isEmpty { roles.append(.otp) }
        if e.privateKeyPasswordRequired { roles.append(.privateKeyPassphrase) }
        return roles
    }
}
