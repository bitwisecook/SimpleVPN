// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
//  Credentials.swift
//  Backend-agnostic credential model. A VPN backend declares what it needs
//  (CredentialRequest); a CredentialProvider supplies the raw fields; the request
//  assembles them into the username/password the engine actually uses. This keeps
//  password-manager integrations (manual, 1Password, Apple Passwords, …) and future
//  VPN types (OpenVPN/IPsec/WireGuard) decoupled from how credentials are sourced.

import Foundation

/// A single kind of credential a backend may require.
enum CredentialField: String, Sendable, CaseIterable {
    case username
    case password
    case otp
    case passkey   // future (WebAuthn-style auth for other VPN types)
}

/// Raw fields as supplied by a source; any may be absent if the source can't provide it.
struct RawCredentials: Sendable {
    var username: String?
    var password: String?          // base password (no OTP)
    var otp: String?
    var privateKeyPassphrase: String?  // unlocks the client private key (rides startTunnel options)
    var passkeyAssertion: Data?    // future
}

/// Credentials in the exact form the engine consumes.
struct EngineCredentials: Sendable {
    var username: String
    var password: String           // already assembled (may embed the OTP)
}

/// What a backend/profile needs to authenticate, and how to assemble the password field.
struct CredentialRequest: Sendable {
    /// Fields the backend needs sourced.
    var fields: Set<CredentialField>
    /// Template for the auth password, with `{password}` and `{otp}` tokens.
    /// GR Lab (LinOTP) expects `{password}{otp}`.
    var passwordTemplate: String

    static let usernamePasswordOTP = CredentialRequest(
        fields: [.username, .password, .otp], passwordTemplate: "{password}{otp}")
    static let usernamePassword = CredentialRequest(
        fields: [.username, .password], passwordTemplate: "{password}")

    /// Build the engine credentials from whatever a source provided.
    func assemble(from raw: RawCredentials) -> EngineCredentials {
        let password = passwordTemplate
            .replacingOccurrences(of: "{password}", with: raw.password ?? "")
            .replacingOccurrences(of: "{otp}", with: raw.otp ?? "")
        return EngineCredentials(username: raw.username ?? "", password: password)
    }
}
