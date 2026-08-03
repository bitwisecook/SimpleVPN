// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
//  ApplePasswordsProvider.swift
//  Fetch a username/password from Apple Passwords (the login + iCloud keychain)
//  via a Security-framework internet-password lookup by server. Items the app
//  didn't create trigger the standard system keychain-access prompt the first
//  time — the correct, user-consented path; the vault password never reaches us.
//  Apple Passwords stores verification codes (TOTP) but doesn't expose them via
//  SecItem, so OTP still comes from the OTP field / another source.
//

import Foundation
import Security
import os

struct ApplePasswordsProvider: CredentialProvider {
    let id = "apple-passwords"
    let displayName = "Apple Passwords"
    let server: String    // e.g. "tig-vpn.grlab.co.uk"
    let account: String   // optional; disambiguates several logins for one server

    private static let log = Logger(subsystem: "com.bragi0.SimpleVPN", category: "apple-passwords")

    func isAvailable(for profile: String) async -> Bool {
        !server.trimmingCharacters(in: .whitespaces).isEmpty
    }

    func resolve(profile: String, fields: Set<CredentialField>) async throws -> RawCredentials {
        let host = server.trimmingCharacters(in: .whitespaces)
        guard !host.isEmpty else { throw AppleError.noServer }

        let acct = account.trimmingCharacters(in: .whitespaces)
        var query: [String: Any] = [
            kSecClass as String: kSecClassInternetPassword,
            kSecAttrServer as String: host,
            // Include iCloud-synced (Apple Passwords) items, not just local ones.
            kSecAttrSynchronizable as String: kSecAttrSynchronizableAny,
            kSecReturnAttributes as String: true,
            kSecReturnData as String: true,
            // Fetch ALL matches so we can detect ambiguity instead of silently
            // returning an unspecified (possibly attacker-seeded iCloud) item.
            kSecMatchLimit as String: kSecMatchLimitAll,
        ]
        if !acct.isEmpty { query[kSecAttrAccount as String] = acct }

        var item: CFTypeRef?
        let status = SecItemCopyMatching(query as CFDictionary, &item)
        switch status {
        case errSecSuccess: break
        case errSecItemNotFound: throw AppleError.notFound(host)
        case errSecUserCanceled, errSecAuthFailed: throw AppleError.denied
        default:
            Self.log.error("keychain lookup failed: OSStatus \(status)")
            throw AppleError.lookup(status)
        }

        let items = (item as? [[String: Any]]) ?? []
        let matches = acct.isEmpty ? items
            : items.filter { ($0[kSecAttrAccount as String] as? String) == acct }
        guard !matches.isEmpty else { throw AppleError.notFound(host) }
        // Require the user to name the account when several logins exist — never
        // pick one arbitrarily (it could be the wrong or a hostile identity).
        guard matches.count == 1 else { throw AppleError.ambiguous(host) }
        let dict = matches[0]
        var raw = RawCredentials()
        raw.username = dict[kSecAttrAccount as String] as? String
        if let data = dict[kSecValueData as String] as? Data {
            raw.password = String(data: data, encoding: .utf8)
        }
        return raw
    }

    enum AppleError: LocalizedError {
        case noServer, notFound(String), ambiguous(String), denied, lookup(OSStatus)
        var errorDescription: String? {
            switch self {
            case .noServer: "No website/server is configured to match in Apple Passwords."
            case .notFound(let h): "No saved password in Apple Passwords for \u{201C}\(h)\u{201D}."
            case .ambiguous(let h): "More than one saved login for \u{201C}\(h)\u{201D} — set the account so the right one is used."
            case .denied: "Access to the saved password was denied."
            case .lookup(let s): "Apple Passwords lookup failed (\(s))."
            }
        }
    }
}
