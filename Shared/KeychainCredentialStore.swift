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

enum KeychainCredentialStore {

    /// Shared keychain access group. Must match the `keychain-access-groups` entitlement
    /// on BOTH targets, with the team prefix resolved ($(AppIdentifierPrefix) = QVUFB5676H.).
    static let accessGroup = "QVUFB5676H.com.bragi0.SimpleVPN.shared"

    private static let credsService = "com.bragi0.SimpleVPN.creds"      // persistent base creds
    private static let sessionService = "com.bragi0.SimpleVPN.session"  // read-once per connect

    struct Credentials: Codable, Sendable {
        var username: String
        var password: String
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

    private static func baseQuery(service: String, account: String) -> [String: Any] {
        [kSecClass as String: kSecClassGenericPassword,
         kSecAttrService as String: service,
         kSecAttrAccount as String: account,
         kSecAttrAccessGroup as String: accessGroup]
    }

    private static func set(service: String, account: String, data: Data) throws {
        SecItemDelete(baseQuery(service: service, account: account) as CFDictionary)
        var q = baseQuery(service: service, account: account)
        q[kSecValueData as String] = data
        // AfterFirstUnlock so the extension can read while the app isn't frontmost; device-only (no sync/backup).
        q[kSecAttrAccessible as String] = kSecAttrAccessibleAfterFirstUnlockThisDeviceOnly
        let status = SecItemAdd(q as CFDictionary, nil)
        guard status == errSecSuccess else {
            throw NSError(domain: NSOSStatusErrorDomain, code: Int(status),
                          userInfo: [NSLocalizedDescriptionKey: "keychain write failed (\(status))"])
        }
    }

    private static func get(service: String, account: String) -> Data? {
        var q = baseQuery(service: service, account: account)
        q[kSecReturnData as String] = true
        q[kSecMatchLimit as String] = kSecMatchLimitOne
        var out: CFTypeRef?
        guard SecItemCopyMatching(q as CFDictionary, &out) == errSecSuccess else { return nil }
        return out as? Data
    }

    private static func delete(service: String, account: String) {
        SecItemDelete(baseQuery(service: service, account: account) as CFDictionary)
    }
}
