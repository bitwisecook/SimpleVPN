// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
//  ApplePasswordsProvider.swift
//  A BEST-EFFORT LOOKUP OF LEGACY INTERNET-PASSWORD ITEMS. Read the next paragraph
//  before treating this as "the Apple Passwords integration", because it is not one.
//
//  WHAT THIS CAN AND CANNOT SEE. `SecItemCopyMatching` for
//  `kSecClassInternetPassword` reaches the FILE keychain (`login.keychain`). It does
//  NOT reach anything Safari or the Passwords app manages: those items live in the
//  data-protection keychain under the `com.apple.cfnetwork` access group, and an app
//  can only read an access group its entitlement lists. SimpleVPN's only keychain
//  group is `$(AppIdentifierPrefix)com.bragi0.SimpleVPN.shared`, so those items are
//  not merely absent from the result — they are unreachable by construction, and no
//  amount of query tuning changes that. In practice this query returns the odd
//  legacy item some other program wrote years ago and nothing else.
//
//  SO THE REAL PATH IS AUTOFILL, not this. macOS fills our fields through the
//  AutoFill menu (the key in the field), which is a user-driven system affordance
//  and needs no entitlement and no lookup. `SignInSourceCatalog.applePasswords()`
//  describes the row that way. This provider stays as a fallback because when it
//  DOES find a legacy item that is a genuinely useful answer — but it must never be
//  the basis of a promise, and its failure is worded as "may well find nothing"
//  rather than as something being broken.
//
//  WE ALSO CANNOT WRITE INTO APPLE PASSWORDS AT ALL. The only public path,
//  `SecAddSharedWebCredential`, requires associated domains AND the VPN server's
//  operator to serve an apple-app-site-association file naming SimpleVPN — and it is
//  deprecated as of macOS 26.2 with a replacement that is unavailable on macOS. So no
//  copy anywhere may imply saving into Apple Passwords. "Saved in the Apple
//  keychain, protected by macOS" — what the SimpleVPN row already says — is the true
//  version of that offer.
//
//  Verification codes: Apple Passwords stores them and exposes none of them through
//  `SecItem`, so `suppliesOTP` is correctly false and the code is still typed.
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

    func resolve(profile: String, fields: Set<AuthKind>) async throws -> RawCredentials {
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

    /// The failure wording is deliberately UNALARMED for the common case. Finding
    /// nothing here is the EXPECTED outcome, not a fault: the items most people mean
    /// by "Apple Passwords" are ones macOS does not let another app read at all, so a
    /// message implying something is broken would send someone debugging a keychain
    /// that is working exactly as designed. It names the way that does work instead.
    enum AppleError: LocalizedError {
        case noServer, notFound(String), ambiguous(String), denied, lookup(OSStatus)
        var errorDescription: String? {
            switch self {
            case .noServer:
                "No website or server address is set, so there is nothing to match."
            case .notFound(let h):
                "SimpleVPN couldn\u{2019}t find a saved password it is allowed to read for "
                + "\u{201C}\(h)\u{201D}. That is usually the case: macOS keeps Safari\u{2019}s and the "
                + "Passwords app\u{2019}s entries where other apps can\u{2019}t reach them. Click the "
                + "key in the username or password field to let macOS fill them in instead."
            case .ambiguous(let h):
                "More than one saved login for \u{201C}\(h)\u{201D} \u{2014} set the account so the "
                + "right one is used."
            case .denied:
                "Access to the saved password was denied."
            case .lookup(let s):
                "Looking for a saved password didn\u{2019}t work (\(s)). Click the key in the username "
                + "or password field to let macOS fill them in instead."
            }
        }
    }
}
