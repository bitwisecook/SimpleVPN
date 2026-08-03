// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
//  CredentialProvider.swift
//  A source of credentials. Manual entry is the only concrete provider today;
//  password managers (1Password, Apple Passwords) implement the same protocol
//  later without changing the connect flow. The connect flow depends only on
//  `CredentialProvider` + `CredentialRequest` (see Credentials.swift).

import Foundation
import Security
import LocalAuthentication
import os

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
    var privateKeyPassphrase: String = ""

    func isAvailable(for profile: String) async -> Bool { true }

    func resolve(profile: String, fields: Set<CredentialField>) async throws -> RawCredentials {
        RawCredentials(username: username.isEmpty ? nil : username,
                       password: password.isEmpty ? nil : password,
                       otp: otp.isEmpty ? nil : otp,
                       privateKeyPassphrase: privateKeyPassphrase.isEmpty ? nil : privateKeyPassphrase)
    }
}

// MARK: - Touch ID-protected credentials

/// Credentials held in the DATA-PROTECTION keychain behind Touch ID (`.userPresence`:
/// fingerprint, Apple Watch, or the account password on Macs without Touch ID).
/// This is the "press Connect, give a fingerprint, connected" store.
///
/// Why this works now when an earlier attempt didn't (TN3137): biometric access
/// control requires the data-protection keychain, which on macOS requires the
/// `com.apple.application-identifier` + `keychain-access-groups` entitlements to be
/// validated by an EMBEDDED provisioning profile. The app has shipped with
/// `Contents/embedded.provisionprofile` and both entitlements since the sysext
/// profiles landed — the old failures (-34018) predate that. App-only: the sysext
/// runs as root and can never read these; credentials still ride startTunnel options.
nonisolated enum BiometricCredentialStore {

    private static let log = Logger(subsystem: "com.bragi0.SimpleVPN", category: "keychain")
    private static let service = "com.bragi0.SimpleVPN.protected"
    private static let accessGroup = "QVUFB5676H.com.bragi0.SimpleVPN.shared"

    struct ProtectedCredentials: Codable, Sendable, Equatable {
        var username: String
        var password: String
        /// Canonical TOTP secret (otpauth:// URI or normalized base32), when the
        /// user gave us one — lets the fingerprint cover the one-time code too.
        var totpSecret: String? = nil
    }

    /// Writing needs NO biometric prompt — only reads are gated.
    static func save(profile: String, _ creds: ProtectedCredentials) throws {
        delete(profile: profile)
        var error: Unmanaged<CFError>?
        guard let access = SecAccessControlCreateWithFlags(
            nil, kSecAttrAccessibleWhenUnlockedThisDeviceOnly, .userPresence, &error) else {
            throw error?.takeRetainedValue() as Error? ?? err("access control creation failed")
        }
        let add: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: profile,
            kSecAttrAccessGroup as String: accessGroup,
            kSecUseDataProtectionKeychain as String: true,
            kSecAttrAccessControl as String: access,
            kSecAttrLabel as String: creds.totpSecret == nil ? labelPlain : labelWithTOTP,
            kSecValueData as String: try JSONEncoder().encode(creds),
        ]
        let status = SecItemAdd(add as CFDictionary, nil)
        guard status == errSecSuccess else {
            log.error("protected write failed: OSStatus \(status)")
            throw err("Couldn't protect the credentials (\(status)).")
        }
        log.log("protected write ok")
    }

    /// True when a protected item exists — checked WITHOUT triggering a prompt.
    static func exists(profile: String) -> Bool {
        info(profile: profile).exists
    }

    /// What's stored, prompt-free: item ATTRIBUTES aren't behind the access
    /// control (only the data is), so the label tells the UI whether the
    /// fingerprint will also cover the one-time code.
    static func info(profile: String) -> (exists: Bool, hasTOTP: Bool) {
        // The prompt-free guarantee: an LAContext that refuses interaction is the
        // replacement for kSecUseAuthenticationUIFail — a lookup that would need
        // the fingerprint fails with errSecInteractionNotAllowed instead of asking.
        let noPrompt = LAContext()
        noPrompt.interactionNotAllowed = true
        let q: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: profile,
            kSecAttrAccessGroup as String: accessGroup,
            kSecUseDataProtectionKeychain as String: true,
            kSecUseAuthenticationContext as String: noPrompt,
            kSecReturnAttributes as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne,
        ]
        var out: CFTypeRef?
        let status = SecItemCopyMatching(q as CFDictionary, &out)
        guard status == errSecSuccess || status == errSecInteractionNotAllowed else {
            return (false, false)
        }
        let label = (out as? [String: Any])?[kSecAttrLabel as String] as? String
        return (true, label == Self.labelWithTOTP)
    }

    private static let labelWithTOTP = "SimpleVPN credentials + one-time code"
    private static let labelPlain = "SimpleVPN credentials"

    /// Read under an ALREADY-EVALUATED LAContext so callers control the single
    /// prompt (and its wording) rather than the keychain popping its own.
    static func load(profile: String, context: LAContext) throws -> ProtectedCredentials {
        var q: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: profile,
            kSecAttrAccessGroup as String: accessGroup,
            kSecUseDataProtectionKeychain as String: true,
            kSecReturnData as String: true,
            kSecMatchLimit as String: kSecMatchLimitOne,
        ]
        q[kSecUseAuthenticationContext as String] = context
        var out: CFTypeRef?
        let status = SecItemCopyMatching(q as CFDictionary, &out)
        guard status == errSecSuccess, let data = out as? Data else {
            log.error("protected read failed: OSStatus \(status)")
            if status == errSecUserCanceled { throw CancellationError() }
            throw err("Couldn't unlock the credentials (\(status)).")
        }
        return try JSONDecoder().decode(ProtectedCredentials.self, from: data)
    }

    static func delete(profile: String) {
        SecItemDelete([
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: service,
            kSecAttrAccount as String: profile,
            kSecAttrAccessGroup as String: accessGroup,
            kSecUseDataProtectionKeychain as String: true,
        ] as CFDictionary)
    }

    private static func err(_ m: String) -> NSError {
        NSError(domain: "BiometricCredentialStore", code: 1,
                userInfo: [NSLocalizedDescriptionKey: m])
    }
}

/// Serves credentials from the Touch ID-protected store: ONE fingerprint releases
/// username + password and, when a TOTP secret is stored, the current one-time
/// code — computed locally so the whole sign-in is covered by the one prompt.
struct BiometricCredentialProvider: CredentialProvider {
    let id = "touchid"
    let displayName = "Touch ID"
    /// Shown in the system authentication sheet ("SimpleVPN is trying to …").
    var reason: String

    func isAvailable(for profile: String) async -> Bool {
        BiometricCredentialStore.exists(profile: profile)
    }

    func resolve(profile: String, fields: Set<CredentialField>) async throws -> RawCredentials {
        // Evaluate the policy explicitly (rather than letting the keychain read
        // prompt implicitly) so cancellation surfaces as CancellationError and
        // the prompt carries the VPN's name.
        let context = LAContext()
        do {
            try await context.evaluatePolicy(.deviceOwnerAuthentication, localizedReason: reason)
        } catch let la as LAError where la.code == .userCancel || la.code == .appCancel || la.code == .systemCancel {
            throw CancellationError()
        }
        let creds = try BiometricCredentialStore.load(profile: profile, context: context)
        var otp: String?
        if fields.contains(.otp), let secret = creds.totpSecret,
           let totp = TOTPConfiguration(parsing: secret) {
            otp = totp.code(at: Date())
        }
        return RawCredentials(username: creds.username.isEmpty ? nil : creds.username,
                              password: creds.password.isEmpty ? nil : creds.password,
                              otp: otp,
                              privateKeyPassphrase: nil)
    }
}

// MARK: - Future providers (see M9)
//
// 1Password (M8, shipped): `OnePasswordProvider` — the official SDK over local
//   IPC to the 1Password app (OnePasswordNative / opnative-helper); no `op`
//   CLI, works fully offline.
//
// KeePassXC (shipped): `KeePassXCProvider` — the keepassxc-browser protocol
//   over KeePassXC's unix socket (KeePassXCProtocol/KeePassXCCrypto); pairing
//   lives in the keychain, per-database.
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
