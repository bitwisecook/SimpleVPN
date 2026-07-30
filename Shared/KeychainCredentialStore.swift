// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only

//
//  KeychainCredentialStore.swift
//  Shared by the app and the packet-tunnel extension via a shared keychain access
//  group. The app stores per-profile base credentials (optional) and, at connect
//  time, writes a read-once "session" secret (username + OTP-combined password)
//  that the extension consumes and deletes. Secrets never touch providerConfiguration.
//

import Foundation
import Security
import os

enum KeychainCredentialStore {

    private static let log = Logger(subsystem: "com.bragi0.SimpleVPN", category: "keychain")

    /// Shared keychain access group. Must match the `keychain-access-groups` entitlement
    /// on BOTH targets, with the team prefix resolved ($(AppIdentifierPrefix) = QVUFB5676H.).
    static let accessGroup = "QVUFB5676H.com.bragi0.SimpleVPN.shared"

    private static let credsService = "com.bragi0.SimpleVPN.creds"      // persistent base creds
    private static let sessionService = "com.bragi0.SimpleVPN.session"  // read-once per connect
    private static let secretsService = "com.bragi0.SimpleVPN.secrets"  // persistent engine secrets

    struct Credentials: Codable, Sendable {
        var username: String
        var password: String
        // Per-VPN engine secrets that must never touch providerConfiguration.
        // Optional so blobs written by older app versions still decode, and older
        // extensions ignore the unknown JSON keys.
        var proxyPassword: String? = nil
        var privateKeyPassword: String? = nil
    }

    // MARK: Persistent base credentials (username + base password, no OTP)

    static func saveCredentials(profile: String, _ creds: Credentials) throws {
        try set(service: credsService, account: profile, data: try JSONEncoder().encode(creds))
    }
    static func loadCredentials(profile: String) -> Credentials? {
        guard let d = get(service: credsService, account: profile) else { return nil }
        return try? JSONDecoder().decode(Credentials.self, from: d)
    }
    static func deleteCredentials(profile: String) {
        delete(service: credsService, account: profile)
    }

    // MARK: Persistent per-profile engine secrets (proxy / private-key passwords)
    //
    // Stored separately from the base credentials so "don't remember my password"
    // doesn't discard them. Merged into the session payload at connect time —
    // they must never touch providerConfiguration.

    struct ProfileSecrets: Codable, Sendable, Equatable {
        var proxyPassword: String? = nil
        var privateKeyPassword: String? = nil
        var isEmpty: Bool { proxyPassword == nil && privateKeyPassword == nil }
    }

    static func saveProfileSecrets(profile: String, _ secrets: ProfileSecrets) throws {
        if secrets.isEmpty { deleteProfileSecrets(profile: profile); return }
        try set(service: secretsService, account: profile, data: try JSONEncoder().encode(secrets))
    }
    static func loadProfileSecrets(profile: String) -> ProfileSecrets? {
        guard let d = get(service: secretsService, account: profile) else { return nil }
        return try? JSONDecoder().decode(ProfileSecrets.self, from: d)
    }
    static func deleteProfileSecrets(profile: String) {
        delete(service: secretsService, account: profile)
    }

    // MARK: Transient session secret (username + {password}{otp}), consumed once by the extension

    static func setSession(profile: String, _ creds: Credentials) throws {
        try set(service: sessionService, account: profile, data: try JSONEncoder().encode(creds))
    }
    /// Read and immediately delete the session secret.
    static func takeSession(profile: String) -> Credentials? {
        guard let d = get(service: sessionService, account: profile) else { return nil }
        delete(service: sessionService, account: profile)
        return try? JSONDecoder().decode(Credentials.self, from: d)
    }
    static func clearSession(profile: String) {
        delete(service: sessionService, account: profile)
    }

    // MARK: Primitives
    //
    // Everything lives in the DATA-PROTECTION keychain (kSecUseDataProtectionKeychain).
    // That is the only keychain where kSecAttrAccessGroup sharing between the app
    // and the sandboxed system extension is actually enforced by entitlement; items
    // in the legacy login keychain are guarded by per-app ACLs the extension can't
    // satisfy, which silently breaks the session handoff. Reads fall back to the
    // legacy keychain once to migrate items written by older builds.

    // The store is APP-ONLY. Since credentials reach the extension via
    // startTunnel(options:) — the extension runs as root and can't read a user
    // keychain anyway — there is no cross-process sharing to satisfy. So we use
    // the plain (login) keychain, which a Developer-ID app can always read and
    // write. The data-protection keychain + shared access group (an earlier
    // attempt at extension sharing) silently failed writes for this app type
    // and is only read now to migrate anything a 0.1(build16–22) left behind.

    private static func appQuery(service: String, account: String) -> [String: Any] {
        [kSecClass as String: kSecClassGenericPassword,
         kSecAttrService as String: service,
         kSecAttrAccount as String: account]
    }

    private static func dataProtectionQuery(service: String, account: String) -> [String: Any] {
        [kSecClass as String: kSecClassGenericPassword,
         kSecAttrService as String: service,
         kSecAttrAccount as String: account,
         kSecAttrAccessGroup as String: accessGroup,
         kSecUseDataProtectionKeychain as String: true]
    }

    private static func set(service: String, account: String, data: Data) throws {
        SecItemDelete(appQuery(service: service, account: account) as CFDictionary)
        var q = appQuery(service: service, account: account)
        q[kSecValueData as String] = data
        q[kSecAttrAccessible as String] = kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
        let status = SecItemAdd(q as CFDictionary, nil)
        guard status == errSecSuccess else {
            log.error("keychain write \(service, privacy: .public) failed: OSStatus \(status)")
            throw NSError(domain: NSOSStatusErrorDomain, code: Int(status),
                          userInfo: [NSLocalizedDescriptionKey: "keychain write failed (\(status))"])
        }
        log.log("keychain write \(service, privacy: .public) ok")
        // Retire any data-protection copy a build 16–22 wrote.
        SecItemDelete(dataProtectionQuery(service: service, account: account) as CFDictionary)
    }

    private static func get(service: String, account: String) -> Data? {
        var q = appQuery(service: service, account: account)
        q[kSecReturnData as String] = true
        q[kSecMatchLimit as String] = kSecMatchLimitOne
        var out: CFTypeRef?
        let status = SecItemCopyMatching(q as CFDictionary, &out)
        if status == errSecSuccess, let d = out as? Data {
            log.log("keychain read \(service, privacy: .public) hit")
            return d
        }
        // Migrate an item a data-protection build wrote, if any.
        var dp = dataProtectionQuery(service: service, account: account)
        dp[kSecReturnData as String] = true
        dp[kSecMatchLimit as String] = kSecMatchLimitOne
        var dpOut: CFTypeRef?
        if SecItemCopyMatching(dp as CFDictionary, &dpOut) == errSecSuccess, let d = dpOut as? Data {
            log.log("keychain read \(service, privacy: .public) migrated from data-protection")
            try? set(service: service, account: account, data: d)
            return d
        }
        log.log("keychain read \(service, privacy: .public) miss (status \(status))")
        return nil
    }

    private static func delete(service: String, account: String) {
        SecItemDelete(appQuery(service: service, account: account) as CFDictionary)
        SecItemDelete(dataProtectionQuery(service: service, account: account) as CFDictionary)
    }

    // MARK: Persistent references (for NEVPNProtocol passwordReference / sharedSecretReference)
    //
    // The native personal VPN (NEVPNManager) takes a *persistent keychain
    // reference*, not the secret itself. Store the value and hand back its ref.

    private static let nativeService = "com.bragi0.SimpleVPN.native"

    @discardableResult
    static func persistentReference(forSecret secret: String, account: String) -> Data? {
        let acct = account
        SecItemDelete([kSecClass as String: kSecClassGenericPassword,
                       kSecAttrService as String: nativeService,
                       kSecAttrAccount as String: acct] as CFDictionary)
        let add: [String: Any] = [
            kSecClass as String: kSecClassGenericPassword,
            kSecAttrService as String: nativeService,
            kSecAttrAccount as String: acct,
            kSecValueData as String: Data(secret.utf8),
            kSecAttrAccessible as String: kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly,
            kSecReturnPersistentRef as String: true,
        ]
        var out: CFTypeRef?
        guard SecItemAdd(add as CFDictionary, &out) == errSecSuccess else { return nil }
        return out as? Data
    }

    static func deleteNativeSecret(account: String) {
        SecItemDelete([kSecClass as String: kSecClassGenericPassword,
                       kSecAttrService as String: nativeService,
                       kSecAttrAccount as String: account] as CFDictionary)
    }
}
