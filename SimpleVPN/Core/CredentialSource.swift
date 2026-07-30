// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
//  CredentialSource.swift
//  Per-VPN choice of WHERE credentials come from: typed manually (stored in the
//  login keychain when Remember is on), fetched from 1Password via its CLI, or
//  read from Apple Passwords / the login keychain. Stored (no secrets — only a
//  reference to the item) as a JSON blob in providerConfiguration["credsource"],
//  same lenient pattern as VPNAuthConfig / OpenVPNOverrides.
//

import Foundation

enum CredentialSourceKind: String, Codable, Sendable, CaseIterable {
    case manual
    case onePassword
    case applePasswords

    var displayName: String {
        switch self {
        case .manual: "Manual / Saved"
        case .onePassword: "1Password"
        case .applePasswords: "Apple Passwords"
        }
    }
    var systemImage: String {
        switch self {
        case .manual: "keyboard"
        case .onePassword: "key.fill"
        case .applePasswords: "person.badge.key.fill"
        }
    }
}

struct CredentialSource: Codable, Sendable, Equatable {
    var kind: CredentialSourceKind = .manual

    /// 1Password: item name or UUID (optionally "vault/item"). Apple Passwords:
    /// the service/server to match (e.g. "tig-vpn.grlab.co.uk"). Unused for manual.
    var reference = ""
    /// Optional disambiguator: 1Password account/vault, or the Apple Passwords
    /// account (username) when a service has several saved logins.
    var account = ""

    /// Which of the source item's fields feed which auth role, keyed by
    /// `CredentialField.rawValue` (username/password/otp). Empty ⇒ auto-detect
    /// from the item's field purposes/types (1Password's USERNAME/PASSWORD/OTP).
    var fieldMap: [String: String] = [:]

    var isDefault: Bool { kind == .manual && reference.isEmpty && account.isEmpty && fieldMap.isEmpty }

    func encodedBlob() -> Data? {
        guard !isDefault else { return nil }
        return try? JSONEncoder().encode(self)
    }
    static func decode(from blob: Data?) -> CredentialSource {
        guard let blob else { return CredentialSource() }
        return (try? JSONDecoder().decode(CredentialSource.self, from: blob)) ?? CredentialSource()
    }
}
