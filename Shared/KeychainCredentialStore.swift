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
    private static let customRoutingProxyAuthService = "com.bragi0.SimpleVPN.customrouting-proxyauth"

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

    // MARK: The secret inline blocks lifted out of an OpenVPN profile
    //
    // An `.ovpn` can inline its client private key and its tls-crypt/tls-auth key.
    // Those used to be stored verbatim in `providerConfiguration["ovpn"]`, which put
    // a private key in the VPN preferences and wrote it out through Export.
    // `OVPNSecretMaterial` (Shared/OVPNInline.swift) decides which blocks are secret
    // and why; this is where they live instead. Keyed by profile id, tag → content.
    //
    // Its OWN service rather than a field on `ProfileSecrets`, deliberately: the
    // editor rebuilds a whole `ProfileSecrets` from two form fields on every save
    // (`EditVPNView.save()`), so a field added there would be silently wiped the
    // first time somebody saved the Options tab — and the thing wiped would be the
    // only copy of a private key.

    private static let ovpnInlineService = "com.bragi0.SimpleVPN.ovpninline"

    static func saveOVPNInlineSecrets(profile: String, _ blocks: [String: String]) throws {
        if blocks.isEmpty { deleteOVPNInlineSecrets(profile: profile); return }
        try set(service: ovpnInlineService, account: profile,
                data: try JSONEncoder().encode(blocks))
    }

    static func loadOVPNInlineSecrets(profile: String) -> [String: String]? {
        guard let d = get(service: ovpnInlineService, account: profile) else { return nil }
        return try? JSONDecoder().decode([String: String].self, from: d)
    }

    static func deleteOVPNInlineSecrets(profile: String) {
        delete(service: ovpnInlineService, account: profile)
    }

    /// Write the blocks and READ THEM BACK, returning true only when the stored
    /// copy matches. The caller removes the material from the profile text on the
    /// strength of this and nothing else — losing somebody's only copy of a client
    /// private key is far worse than leaving it stored a while longer.
    static func saveAndVerifyOVPNInlineSecrets(profile: String, _ blocks: [String: String]) -> Bool {
        guard !blocks.isEmpty else { return false }
        do { try saveOVPNInlineSecrets(profile: profile, blocks) }
        catch {
            log.error("ovpn inline secrets write failed for \(profile, privacy: .public)")
            return false
        }
        guard let readBack = loadOVPNInlineSecrets(profile: profile), readBack == blocks else {
            log.error("ovpn inline secrets read-back MISMATCH for \(profile, privacy: .public) — leaving the profile alone")
            return false
        }
        // Tag names only. The block contents are the secret; their names are not.
        log.log("ovpn inline secrets verified for \(profile, privacy: .public): \(blocks.keys.sorted().joined(separator: ","), privacy: .public)")
        return true
    }

    // MARK: Custom Routing proxy auth (Mediators/CustomRouting.swift `ProxyCustomization`)
    //
    // The model carries only a keychain REF (`authSource`) — never inline credentials.
    // This is that ref's backing store: one username/password per profile, keyed by the
    // profile id exactly like the other per-profile stores above.

    struct CustomRoutingProxyAuth: Codable, Sendable, Equatable {
        var username: String
        var password: String
    }

    static func saveCustomRoutingProxyAuth(profile: String, _ auth: CustomRoutingProxyAuth) throws {
        try set(service: customRoutingProxyAuthService, account: profile, data: try JSONEncoder().encode(auth))
    }
    static func loadCustomRoutingProxyAuth(profile: String) -> CustomRoutingProxyAuth? {
        guard let d = get(service: customRoutingProxyAuthService, account: profile) else { return nil }
        return try? JSONDecoder().decode(CustomRoutingProxyAuth.self, from: d)
    }
    static func deleteCustomRoutingProxyAuth(profile: String) {
        delete(service: customRoutingProxyAuthService, account: profile)
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
    // This store is APP-ONLY and lives in the PLAIN (file/login) keychain.
    //
    // WHY app-only: every secret here reaches the extension through
    // startTunnel(options:). The extension runs as root in the SYSTEM context and
    // cannot read a user keychain at all, so there is no cross-process sharing for
    // an access group to enforce. (An earlier design tried to share these items
    // with the extension via kSecAttrAccessGroup; that is what the
    // data-protection read-migration below is cleaning up after.)
    //
    // WHAT THIS COMMENT USED TO SAY, AND WHY IT WAS WRONG. It claimed the
    // data-protection keychain "silently failed writes for this app type". That is
    // NOT true, and believing it would rule out work that is actually available:
    // `BiometricCredentialStore` (Credentials/CredentialProvider.swift) writes to
    // the data-protection keychain with kSecUseDataProtectionKeychain and this same
    // access group, and it is a shipped feature. Per TN3137 the old -34018 failures
    // came from the entitlements not being validated by an EMBEDDED provisioning
    // profile, and the app has shipped one (`Contents/embedded.provisionprofile`,
    // from PROVISIONING_PROFILE_SPECIFIER in project.yml) since the sysext profiles
    // landed. So the data-protection keychain is a CHOICE we have not needed here,
    // not a door that is closed — which matters, because kSecAttrSynchronizable
    // forces the data-protection keychain, so anything that wants iCloud sync one
    // day is a migration rather than an impossibility.
    //
    // Reads still fall back to the data-protection keychain once, to migrate items
    // a 0.1(build16–22) left behind.

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
        // NOTE, and it is a note rather than a fix: on macOS `kSecAttrAccessible` is
        // a NO-OP on this path. Accessibility classes only take effect for an item
        // that is `kSecAttrSynchronizable` or that was written with
        // `kSecUseDataProtectionKeychain` — this is a plain file-keychain item, and is
        // neither. It is passed anyway so the intent is recorded and so the attribute
        // is already correct if this item ever moves to the data-protection keychain.
        //
        // The item is NOT unprotected: a file-keychain item is guarded by the login
        // keychain's own unlock state and by its ACL (only this app, code-signed,
        // may read it without a prompt). What it does not have is the
        // "…ThisDeviceOnly" class this line names, so do not read that guarantee off
        // this call.
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

    /// - Throws: an `NSOSStatusErrorDomain` error carrying the raw `OSStatus`
    ///   if `SecItemAdd` fails, instead of silently handing back `nil` — a
    ///   caller that swallowed that `nil` would only see an opaque native-VPN
    ///   failure much later, with no way back to "the keychain write failed".
    static func persistentReference(forSecret secret: String, account: String) throws -> Data {
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
        let status = SecItemAdd(add as CFDictionary, &out)
        guard status == errSecSuccess, let data = out as? Data else {
            log.error("native keychain ref write for account \(account, privacy: .public) failed: OSStatus \(status)")
            throw NSError(domain: NSOSStatusErrorDomain, code: Int(status),
                          userInfo: [NSLocalizedDescriptionKey: "Couldn't save the secret to the keychain (\(status))."])
        }
        return data
    }

    static func deleteNativeSecret(account: String) {
        SecItemDelete([kSecClass as String: kSecClassGenericPassword,
                       kSecAttrService as String: nativeService,
                       kSecAttrAccount as String: account] as CFDictionary)
    }
}
