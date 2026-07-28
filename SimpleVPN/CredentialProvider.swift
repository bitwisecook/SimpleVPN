// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
//  CredentialProvider.swift
//  A source of credentials. Manual entry is the only concrete provider today;
//  password managers (1Password, Apple Passwords) implement the same protocol
//  later without changing the connect flow. The connect flow depends only on
//  `CredentialProvider` + `CredentialRequest` (see Credentials.swift).

import Foundation

/// Something that can supply raw credential fields for a profile.
protocol CredentialProvider: Sendable {
    var id: String { get }
    var displayName: String { get }
    /// Whether this source can currently serve credentials for the profile
    /// (e.g. its CLI is installed, or a matching item exists).
    func isAvailable(for profile: String) async -> Bool
    /// Resolve the requested fields, prompting/calling out as needed. May return
    /// fewer fields than requested; the caller assembles via `CredentialRequest`.
    func resolve(profile: String, fields: Set<CredentialField>) async throws -> RawCredentials
}

/// Credentials typed into the app's UI (or filled there by system AutoFill).
struct ManualCredentialProvider: CredentialProvider {
    let id = "manual"
    let displayName = "Manual entry"
    var username: String
    var password: String
    var otp: String

    func isAvailable(for profile: String) async -> Bool { true }

    func resolve(profile: String, fields: Set<CredentialField>) async throws -> RawCredentials {
        RawCredentials(username: username.isEmpty ? nil : username,
                       password: password.isEmpty ? nil : password,
                       otp: otp.isEmpty ? nil : otp)
    }
}

// MARK: - Future providers (see M8 / M9)
//
// 1Password (M8): `OnePasswordCLICredentialProvider`
//   - isAvailable: `op` CLI present + item reference configured on the profile.
//   - resolve: `op item get <ref> --fields username,password --otp` (async Process).
//   - Needs a sandbox/exec exception since the app is otherwise locked down.
//
// Apple Passwords (M9): `ApplePasswordsCredentialProvider`
//   - username/password/otp are best sourced via native AutoFill on the text fields
//     (textContentType .username/.password/.oneTimeCode + associated-domains), so this
//     provider mostly configures the UI rather than fetching.
//   - passkey: AuthenticationServices (ASAuthorizationController) for VPN types that
//     authenticate with WebAuthn.

/// Lists the credential providers usable for a profile, in preference order.
/// Manual is always last (the fallback); managers slot in ahead of it as they land.
enum CredentialProviderRegistry {
    static func providers(for profile: String, manualFallback: ManualCredentialProvider) async -> [CredentialProvider] {
        var out: [CredentialProvider] = []
        // e.g. if await onePassword.isAvailable(for: profile) { out.append(onePassword) }
        out.append(manualFallback)
        return out
    }
}
