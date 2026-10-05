// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only

import Foundation
import LocalAuthentication
import Darwin

nonisolated enum ConfigSecretMode: String, CaseIterable, Sendable {
    case omit, placeholders, include
}

/// The only export/import path allowed to carry credentials. Account names are
/// derived from the newly assigned profile ID, never taken from an input file.
enum ConfigSecretTransfer {
    static func accounts(id: String) -> [(String, String)] {
        [("credentials", id), ("wireguard", "wg.\(id)"), ("tailscale", "tailscale.\(id)"),
         ("ssh-network", "sshnet.\(id)"), ("tunnel", "tunnel.\(id)"),
         ("tunnel-proxy", "tunnel.\(id).proxy"), ("tunnel-jump", "tunnel.\(id).jump"),
         ("tunnel-passphrase", "tunnel.\(id).privateKey"), ("ssh-key", "tunnel.\(id).sshKey"),
         ("native", "native.\(id)"), ("native-secret", "native.\(id).secret"),
         ("native-ppp", "native.\(id).ppp")]
    }

    static func collect(id: String, mode: ConfigSecretMode, authenticationContext: LAContext? = nil) async throws -> ConfigMap {
        guard mode != .omit else { return ConfigMap() }
        var secrets = ConfigMap()
        for (role, account) in accounts(id: id) {
            if let credentials = try KeychainCredentialStore.credentialsForExport(profile: account) {
                secrets.put(role, .map(secretMap(credentials)))
            }
        }
        if let value = try KeychainCredentialStore.profileSecretsForExport(profile: id), !value.isEmpty {
            secrets.put("profile-secrets", .map(secretMap(value)))
        }
        if let value = try KeychainCredentialStore.routingProxyAuthForExport(profile: id) {
            secrets.put("routing-proxy", .map(secretMap(value)))
        }
        let peers = try KeychainCredentialStore.wireGuardPeerSecretsForExport(profile: id)
        if !peers.isEmpty {
            var map = ConfigMap()
            for key in peers.keys.sorted() { map.put(key, .string(peers[key]!)) }
            secrets.put("wireguard-peers", .map(map))
        }
        let protected = BiometricCredentialStore.info(profile: id)
        if protected.exists {
            if mode == .include {
                let context = authenticationContext ?? LAContext()
                if authenticationContext == nil {
                    try await context.evaluatePolicy(.deviceOwnerAuthentication,
                        localizedReason: "Export this VPN's protected credentials to a configuration file")
                }
                let credentials = try BiometricCredentialStore.load(profile: id, context: context)
                secrets.put("protected", .map(secretMap(credentials)))
            } else {
                var map = ConfigMap()
                map.put("username", .string(""))
                map.put("password", .string(""))
                if protected.hasTOTP { map.put("totpSecret", .string("")) }
                secrets.put("protected", .map(map))
            }
        }
        return secrets
    }

    /// This explicit sidecar is the sole exception to settings-map redaction.
    /// ConfigDocument applies the requested omit/placeholder/include mode later.
    private static func secretMap<T: Encodable>(_ value: T) -> ConfigMap {
        let json = ConfigDocument.jsonObject(value)
        var fields = ConfigMap()
        for key in json.keys.sorted() { fields.put(key, ConfigJSON.value(json[key]!)) }
        return fields
    }

    static func placeholders(_ secrets: ConfigMap) -> ConfigMap {
        var output = ConfigMap()
        for role in secrets.entries {
            guard let fields = role.value.mapValue else { continue }
            var record = ConfigMap()
            for field in fields.entries {
                if field.key == "username" && role.key != "wireguard-peers" {
                    record.put(field.key, field.value)
                } else {
                    var marker = ConfigMap()
                    marker.put("placeholder", .string("Supply \(field.key) in the user's Keychain"))
                    record.put(field.key, .map(marker))
                }
            }
            output.put(role.key, .map(record))
        }
        return output
    }

    static func validated(_ secrets: ConfigMap) throws -> ConfigMap {
        let credentialRoles = Set(accounts(id: "").map { $0.0 })
        let roles = credentialRoles.union(["profile-secrets", "routing-proxy", "wireguard-peers", "protected"])
        var output = ConfigMap()
        for entry in secrets.entries {
            guard roles.contains(entry.key), let fields = entry.value.mapValue else { throw invalid() }
            // Placeholders are instructions, never a password. Leave the whole
            // record for the user to fill rather than inventing blank credentials.
            if fields.entries.contains(where: { $0.value.mapValue?["placeholder"]?.stringValue != nil }) { continue }
            guard fields.entries.allSatisfy({ field in
                switch field.value { case .string, .text: return true; default: return false }
            }) else { throw invalid() }
            let allowed: Set<String>
            switch entry.key {
            case "wireguard-peers": allowed = Set(fields.entries.map(\.key))
            case "profile-secrets": allowed = ["proxyPassword", "privateKeyPassword"]
            case "protected": allowed = ["username", "password", "totpSecret"]
            case "routing-proxy": allowed = ["username", "password"]
            default: allowed = ["username", "password", "proxyPassword", "privateKeyPassword"]
            }
            guard Set(fields.entries.map(\.key)).isSubset(of: allowed) else { throw invalid() }
            if credentialRoles.contains(entry.key) || entry.key == "protected" || entry.key == "routing-proxy" {
                guard fields["username"]?.stringValue != nil, fields["password"]?.stringValue != nil else { throw invalid() }
            }
            output.put(entry.key, entry.value)
        }
        return output
    }

    static func save(_ secrets: ConfigMap, id: String) throws {
        let validated = try validated(secrets)
        let accountMap = Dictionary(uniqueKeysWithValues: accounts(id: id))
        for entry in validated.entries {
            guard let fields = entry.value.mapValue else { continue }
            let data = try JSONSerialization.data(withJSONObject: fields.jsonRepresentation)
            if let account = accountMap[entry.key] {
                let credentials = try JSONDecoder().decode(KeychainCredentialStore.Credentials.self, from: data)
                try KeychainCredentialStore.saveCredentials(profile: account, credentials)
            } else {
                switch entry.key {
                case "profile-secrets":
                    try KeychainCredentialStore.saveProfileSecrets(profile: id,
                        JSONDecoder().decode(KeychainCredentialStore.ProfileSecrets.self, from: data))
                case "routing-proxy":
                    try KeychainCredentialStore.saveCustomRoutingProxyAuth(profile: id,
                        JSONDecoder().decode(KeychainCredentialStore.CustomRoutingProxyAuth.self, from: data))
                case "wireguard-peers":
                    try KeychainCredentialStore.saveWireGuardPeerSecrets(profile: id,
                        JSONDecoder().decode([String: String].self, from: data))
                case "protected":
                    try BiometricCredentialStore.save(profile: id,
                        JSONDecoder().decode(BiometricCredentialStore.ProtectedCredentials.self, from: data))
                default: throw invalid()
                }
            }
        }
    }

    /// Create the replacement with mode 0600 before writing any secret bytes.
    /// rename keeps both the write and replacement atomic on this filesystem.
    static func write(_ text: String, to url: URL) throws {
        let temporary = url.deletingLastPathComponent().appendingPathComponent(".simplevpn-export-\(UUID().uuidString)")
        let fd = open(temporary.path, O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW, mode_t(0o600))
        guard fd >= 0 else { throw NSError(domain: NSPOSIXErrorDomain, code: Int(errno)) }
        defer { close(fd) }
        defer { try? FileManager.default.removeItem(at: temporary) }
        try FileHandle(fileDescriptor: fd, closeOnDealloc: false).write(contentsOf: Data(text.utf8))
        guard rename(temporary.path, url.path) == 0 else {
            throw NSError(domain: NSPOSIXErrorDomain, code: Int(errno))
        }
    }

    private static func invalid(_ message: String = "The secret section contains an unknown or malformed credential.") -> NSError {
        NSError(domain: "ConfigSecrets", code: 1, userInfo: [NSLocalizedDescriptionKey: message])
    }
}
