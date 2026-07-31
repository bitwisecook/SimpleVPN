// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
//  CredentialSource.swift
//  Per-VPN choice of WHERE credentials come from: typed manually (stored in the
//  login keychain when Remember is on), fetched from the 1Password app, or
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
    /// 1Password: WHICH ACCOUNT to ask — the name shown at the top of
    /// 1Password's sidebar, or its UUID. Not cosmetic: the SDK's desktop-app
    /// integration refuses to build a client without it ("Account not found")
    /// whenever it can't pick one on its own. Apple Passwords: the account
    /// (username) when a service has several saved logins.
    var account = ""
    /// 1Password only: which vault holds the item ("" = search them all).
    /// Separate from `account` — a vault names a drawer inside an account, and
    /// conflating the two is what made every 1Password fetch fail.
    var vault = ""

    /// Which of the source item's fields feed which auth role, keyed by
    /// `CredentialField.rawValue` (username/password/otp). Empty ⇒ auto-detect
    /// from the item's field purposes/types (1Password's USERNAME/PASSWORD/OTP).
    var fieldMap: [String: String] = [:]

    var isDefault: Bool {
        kind == .manual && reference.isEmpty && account.isEmpty && vault.isEmpty && fieldMap.isEmpty
    }

    init() {}

    /// Every key optional: blobs written by older builds are missing whichever
    /// fields hadn't been invented yet, and a strict decode would throw the
    /// whole source away (dropping the user's item choice, not just the new
    /// field). Legacy 1Password blobs carry only `account`, which the app then
    /// used AS THE VAULT — so it is migrated into `vault` while being left in
    /// `account` too: it may equally have been typed into the field labelled
    /// "Account", and the two can't be told apart after the fact. Whichever it
    /// was, it now reaches the side that understands it.
    init(from decoder: any Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        kind = try c.decodeIfPresent(CredentialSourceKind.self, forKey: .kind) ?? .manual
        reference = try c.decodeIfPresent(String.self, forKey: .reference) ?? ""
        account = try c.decodeIfPresent(String.self, forKey: .account) ?? ""
        fieldMap = try c.decodeIfPresent([String: String].self, forKey: .fieldMap) ?? [:]
        if let stored = try c.decodeIfPresent(String.self, forKey: .vault) {
            vault = stored
        } else {
            vault = kind == .onePassword ? account : ""
        }
    }

    func encodedBlob() -> Data? {
        guard !isDefault else { return nil }
        return try? JSONEncoder().encode(self)
    }
    static func decode(from blob: Data?) -> CredentialSource {
        guard let blob else { return CredentialSource() }
        return (try? JSONDecoder().decode(CredentialSource.self, from: blob)) ?? CredentialSource()
    }
}
