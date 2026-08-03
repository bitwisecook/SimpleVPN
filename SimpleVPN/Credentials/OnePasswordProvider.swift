// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
//  OnePasswordProvider.swift
//  Fetch credentials from 1Password via the official SDK's local IPC to the
//  1Password desktop app (OnePasswordNative → opnative-helper) — fully offline,
//  no `op` CLI, no network dependency. Unlock stays 1Password's job: the app
//  shows a Touch ID / authorization prompt naming SimpleVPN; the vault password
//  never reaches this process. Requires 1Password 8+ with Settings ▸ Developer ▸
//  "Integrate with other apps" enabled.
//
//  Two read shapes: explicit coordinates (vault + item + field names) resolve
//  as op:// secret references — the narrowest possible grant; anything less
//  explicit (no vault, a link-style reference, or default field-name guesses
//  that missed) reads the whole item once and picks fields locally.
//

import Foundation
import os

struct OnePasswordProvider: CredentialProvider {
    let id = "1password"
    let displayName = "1Password"
    let itemReference: String
    let vault: String   // optional; "" = search all vaults
    /// Which 1Password account to ask — sidebar name or UUID. Separate from
    /// `vault`, and only optional in the sense that 1Password may still refuse:
    /// its desktop integration answers an account it can't match (including "")
    /// with "Account not found".
    var account: String = ""
    /// Role → field label/id chosen by the user. Empty ⇒ auto-detect by purpose.
    var fieldMap: [String: String] = [:]

    /// One selectable field of a 1Password item, as shown in the mapping sheet.
    struct OPField: Identifiable, Sendable, Hashable {
        let id: String          // 1Password field id (stable) — the map value
        let label: String       // human label ("username", "password", "one-time password")
        let purpose: String     // "USERNAME" | "PASSWORD" | ""
        let type: String        // "STRING" | "CONCEALED" | "OTP" | …
        var isOTP: Bool { type == "OTP" }
    }

    private static let log = Logger(subsystem: "com.bragi0.SimpleVPN", category: "1password")

    func isAvailable(for profile: String) async -> Bool {
        guard !itemReference.trimmingCharacters(in: .whitespaces).isEmpty else { return false }
        return await OnePasswordNative.probe()
    }

    func resolve(profile: String, fields: Set<CredentialField>) async throws -> RawCredentials {
        let ref = itemReference.trimmingCharacters(in: .whitespaces)
        guard !ref.isEmpty else { throw OPError.noReference }

        // Narrow path first: when the item's coordinates are explicit enough to
        // form `op://vault/item/field` secret references (a vault, a non-URL
        // item reference, and a field map covering the wanted roles — the
        // mapping sheet fills it on drag-in), ask 1Password for exactly those
        // fields and nothing else. Roles the map doesn't name use a standard
        // Login item's field names; a wrong guess is the one failure that
        // quietly falls through to the full-item read below.
        if let native = nativeSecretRefs(for: fields, item: ref) {
            let refs = native.refs
            // The key passphrase isn't a CredentialField (it rides alongside),
            // but when the map names one, fetch it in the same authorization.
            let passphraseRef = fieldMap[CredentialRole.privateKeyPassphrase.rawValue]
                .flatMap { $0.isEmpty ? nil : "op://\(vault.trimmingCharacters(in: .whitespaces))/\(ref)/\($0)" }
            do {
                let values = try await OnePasswordNative.resolve(
                    refs: Array(refs.values) + (passphraseRef.map { [$0] } ?? []),
                    account: account.trimmingCharacters(in: .whitespaces))
                return RawCredentials(
                    username: refs[.username].flatMap { values[$0] },
                    password: refs[.password].flatMap { values[$0] },
                    otp: refs[.otp].flatMap { values[$0] },
                    privateKeyPassphrase: passphraseRef.flatMap { values[$0] })
            } catch let e as OnePasswordNativeError {
                switch e {
                case .userCancelled:
                    throw CancellationError()
                case .accountNotFound:
                    // Nothing to retry with: the SDK offers no way to list
                    // accounts and the sandbox can't read 1Password's config,
                    // so an empty (or wrong) account can only be answered by
                    // the user naming it. Surface it as-is — the friendly
                    // error asks for exactly that.
                    throw e
                case .itemNotFound where native.usedDefaults:
                    // Our guessed standard field names missed — the full-item
                    // read auto-detects by purpose, so let it try.
                    Self.log.log("native resolve: default field names missed — retrying via full-item read")
                default:
                    throw e
                }
            }
        }

        // Full-item read: same IPC channel, one authorization, fields picked
        // here — works with a bare title/UUID and no vault.
        let item: OnePasswordNative.OPItem
        do {
            item = try await OnePasswordNative.getItem(
                reference: ref,
                vault: vault.trimmingCharacters(in: .whitespaces),
                account: account.trimmingCharacters(in: .whitespaces))
        } catch let e as OnePasswordNativeError {
            if case .userCancelled = e { throw CancellationError() }
            throw e
        }
        return Self.credentials(from: item, map: fieldMap)
    }

    /// Secret references for the wanted roles, or nil when the native path
    /// can't express this item (no vault, or a link-style reference). Roles the
    /// field map doesn't name fall back to a standard Login item's field names
    /// ("username" / "password" / "one-time password") — `usedDefaults` tells
    /// the caller a wrong guess should quietly retry via the full-item read
    /// rather than surface an error. OTP refs ask for the computed code via
    /// `?attribute=otp` rather than the enrollment secret.
    private func nativeSecretRefs(for fields: Set<CredentialField>, item: String)
        -> (refs: [CredentialField: String], usedDefaults: Bool)? {
        let v = vault.trimmingCharacters(in: .whitespaces)
        guard !v.isEmpty, !item.contains("://") else { return nil }
        var usedDefaults = false
        func fieldName(_ role: CredentialRole, default defaultName: String) -> String {
            if let mapped = fieldMap[role.rawValue], !mapped.isEmpty { return mapped }
            usedDefaults = true
            return defaultName
        }
        var out: [CredentialField: String] = [:]
        for field in fields {
            switch field {
            case .username:
                out[field] = "op://\(v)/\(item)/\(fieldName(.username, default: "username"))"
            case .password:
                out[field] = "op://\(v)/\(item)/\(fieldName(.password, default: "password"))"
            case .otp:
                // Optional either way: an item without a TOTP field serves none.
                out[field] = "op://\(v)/\(item)/\(fieldName(.otp, default: "one-time password"))?attribute=otp"
            case .passkey:
                continue
            }
        }
        return (out, usedDefaults)
    }

    /// List an item's fields so the user can map them to auth roles. Returns the
    /// item title, the vault it turned out to live in, and its selectable fields
    /// (those that actually hold a value). The vault id is the answer to "which
    /// drawer was that in?" — known truth once the read succeeds, and what an
    /// empty Vault field is quietly back-filled from.
    static func listFields(itemReference ref: String, vault: String,
                           account: String = "") async throws
        -> (title: String, vaultID: String, fields: [OPField]) {
        let r = ref.trimmingCharacters(in: .whitespaces)
        guard !r.isEmpty else { throw OPError.noReference }
        let item = try await OnePasswordNative.getItem(
            reference: r, vault: vault.trimmingCharacters(in: .whitespaces),
            account: account.trimmingCharacters(in: .whitespaces))
        let fields: [OPField] = item.fields.compactMap { f in
            // Skip empty fields — a slot with nothing in it can't feed a role.
            // (OTP fields carry their value as `otp`; `value` is always empty.)
            guard !f.value.isEmpty || f.otp?.isEmpty == false else { return nil }
            return OPField(id: f.id, label: f.label.isEmpty ? f.id : f.label,
                           purpose: f.purpose, type: f.type)
        }
        return (item.title, item.vaultID, fields)
    }

    // MARK: Field selection

    /// Pick credentials out of a full item read. Explicit mappings (by field id
    /// or label) win; purposes (USERNAME/PASSWORD) cover the unmapped standard
    /// case; label heuristics are the last resort for items built from custom
    /// fields. The one-time code only ever comes from an OTP field's computed
    /// current code — never a raw value, which would be the enrollment seed.
    static func credentials(from item: OnePasswordNative.OPItem,
                            map: [String: String] = [:]) -> RawCredentials {
        let fields = item.fields
        func mappedField(_ role: CredentialRole) -> OnePasswordNative.OPItemField? {
            guard let key = map[role.rawValue], !key.isEmpty else { return nil }
            return fields.first { $0.id == key || $0.label == key }
        }
        func value(_ f: OnePasswordNative.OPItemField?) -> String? {
            guard let f else { return nil }
            let v = f.type == "OTP" ? (f.otp ?? "") : f.value
            return v.isEmpty ? nil : v
        }

        var raw = RawCredentials()
        // Explicit mappings first.
        raw.username = value(mappedField(.username))
        raw.password = value(mappedField(.password))
        raw.otp = value(mappedField(.otp))
        raw.privateKeyPassphrase = value(mappedField(.privateKeyPassphrase))

        // Purposes cover the unmapped standard Login item.
        for f in fields {
            switch f.purpose {
            case "USERNAME": if raw.username == nil { raw.username = value(f) }
            case "PASSWORD": if raw.password == nil { raw.password = value(f) }
            default:
                if f.type == "OTP", raw.otp == nil { raw.otp = value(f) }
            }
        }

        // Label heuristics last — items assembled from custom fields carry no
        // purposes, but their labels usually still say what they are.
        if raw.username == nil {
            let names: Set<String> = ["username", "user", "login", "email"]
            raw.username = value(fields.first {
                $0.type != "CONCEALED" && $0.type != "OTP"
                    && names.contains($0.label.lowercased())
            })
        }
        if raw.password == nil {
            raw.password = value(
                fields.first { $0.label.lowercased() == "password" }
                ?? fields.first { $0.type == "CONCEALED" && $0.label.lowercased().contains("pass") })
        }
        return raw
    }

    enum OPError: LocalizedError {
        case noReference
        var errorDescription: String? {
            switch self {
            case .noReference: "No 1Password item is configured for this VPN."
            }
        }
    }
}
