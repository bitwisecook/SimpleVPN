// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
//  PasswordStoreProvider.swift
//  The `pass` / `gopass` source's two seam implementations: the provider that fetches
//  one entry, and the adapter that says whether it could.
//
//  Everything about HOW a store is read lives in PasswordStoreReader.swift — including
//  the reason we decrypt with gpg rather than shelling to `pass`, and the pinentry
//  guard that stops a fetch waiting forever on a prompt that cannot appear.
//

import Foundation

// MARK: - Provider

/// WHICH store, and how its entries are written. Read on the main actor (the settings
/// store lives there) and then handed to a `nonisolated` reader — the same shape as
/// `KeePassFileConfiguration`, and for the same reason: a provider is constructed
/// nonisolated but only ever *fetches* from an async context.
nonisolated struct PasswordStoreConfiguration: Sendable, Equatable {
    var instance: SourceInstanceID?
    var name: String = ""
    var location: PasswordStoreLocation = .default()
    /// nil means "use the conventional names, in order".
    var usernameField: String?
    /// False when the profile names a store that no longer exists. Deliberately not
    /// "fall back to another store": reading the wrong vault because a list changed is
    /// worse than failing to read at all.
    var isResolved: Bool = false

    @MainActor
    static func current(store: SignInSourceSettingsStore = .shared,
                        instance wanted: SourceInstanceID? = nil) -> PasswordStoreConfiguration {
        let resolution = store.instanceStore.resolve(wanted, for: .passwordStore)
        guard let instance = resolution.instance else { return PasswordStoreConfiguration() }
        var out = PasswordStoreConfiguration(instance: instance.id, name: instance.name,
                                            isResolved: true)
        for field in SignInSourceSettings.fields(for: .passwordStore) {
            // `effectivePath` / `value` so an MDM-pinned setting wins, exactly as it
            // does for a tool path.
            let shown = store.presentation(for: field, instance: instance)
            switch field.kind {
            case .storeDirectory:
                if let p = shown.effectivePath, !p.isEmpty {
                    out.location = PasswordStoreLocation(directory: p)
                }
            case .entryFieldName:
                let v = shown.value.trimmingCharacters(in: .whitespaces)
                out.usernameField = v.isEmpty ? nil : v
            case .toolBinary, .unixSocket, .daemonEndpoint, .pkcs11Module,
                 .vaultFile, .keyFile, .securityKeySlot, .serverURL, .toolConfigFile:
                continue
            }
        }
        return out
    }
}

nonisolated struct PasswordStoreProvider: CredentialProvider {
    /// The entry's name: its path inside the store, without the `.gpg`.
    let reference: String
    /// An optional username from the VPN's own profile. Takes precedence over whatever
    /// the entry says, because the person who typed it here meant it.
    let account: String
    /// WHICH store — resolved at fetch time rather than at construction, because the
    /// settings store is main-actor isolated and a provider is built nonisolated.
    let instance: SourceInstanceID?
    /// Injectable so every path is testable with no store, no key and no agent.
    var makeReader: @Sendable (PasswordStoreConfiguration) -> PasswordStoreReader = {
        PasswordStoreReader(location: $0.location)
    }

    var id: String { "passwordstore:\(instance?.rawValue ?? "default")#\(reference)" }
    var displayName: String { "pass / gopass" }

    /// Cheap and prompt-free: the store is there, gpg is runnable, and the entry's file
    /// exists. Deliberately does NOT decrypt — availability must never cost a passphrase
    /// prompt, and on a Mac with nothing cached it would.
    func isAvailable(for profile: String) async -> Bool {
        let config = await MainActor.run { PasswordStoreConfiguration.current(instance: instance) }
        guard config.isResolved else { return false }
        let reader = makeReader(config)
        switch reader.storeState() {
        case .ready, .readyOnlyWhileAgentRemembers:
            guard let file = config.location.file(forEntry: reference) else { return false }
            return reader.files.fileExists(file)
        case .directoryMissing, .notAStore, .gpgMissing:
            return false
        }
    }

    func resolve(profile: String, fields: Set<AuthKind>) async throws -> RawCredentials {
        let config = await MainActor.run { PasswordStoreConfiguration.current(instance: instance) }
        guard config.isResolved else { throw PasswordStoreError.notAStore }
        let entry = try await makeReader(config).read(entry: reference)
        var out = RawCredentials()
        if fields.contains(.password) { out.password = entry.password }
        if fields.contains(.username) {
            let typed = account.trimmingCharacters(in: .whitespaces)
            out.username = typed.isEmpty ? entry.username(preferring: config.usernameField) : typed
        }
        if fields.contains(.otp), let uri = entry.otpauthURI,
           let totp = TOTPConfiguration(parsing: uri) {
            // Computed locally from the seed with the app's own RFC 6238 engine, as
            // Bitwarden's does. `suppliesOTP` is still FALSE for this kind: pass-otp is
            // an optional extension, so a code MAY be here — and "may" is not a promise
            // Connect can be built on.
            out.otp = totp.code(at: Date())
        }
        return out
    }
}

// MARK: - Adapter

nonisolated struct PasswordStoreVaultAdapter: LocalVaultAdapter {
    let vendor = LocalVaultVendor.passwordStore
    let storedKind = CredentialSourceKind.passwordStore
    /// `.file`, and only `.file`: a store is a directory of files and we read them
    /// ourselves. There is no app to talk to, no socket, and no daemon — which is why
    /// this source works for someone who has never installed `pass`.
    let transports: [AuthTransport] = [.file]

    /// Without an instance there is no store to look at, so the vendor-level answer is
    /// the best of its configured stores (computed by the registry) or, with none
    /// configured, "nothing chosen yet" when the machine could otherwise do it.
    func quickScan() -> LocalVaultAvailability {
        quickScan(instance: nil)
    }

    func quickScan(instance: SourceInstance?) -> LocalVaultAvailability {
        // gpg is the one thing that must exist. Ask discovery before saying "not
        // installed": gpg in a version manager's directory is a path to set, not a
        // thing to install, and those need different sentences.
        guard GPGDecrypter().gpgIsAvailable() else {
            if LocalVaultRegistry.toolFoundOutsideAllowList("gpg") != nil
                || LocalVaultRegistry.toolFoundOutsideAllowList("gpg2") != nil {
                return .blocked(.toolOutsideAllowList)
            }
            // Not `.notInstalled`: a password store is a folder, so there is no app
            // whose absence proves the person doesn't use one. If they have configured
            // a store, the honest answer is "install GnuPG", not "you don't have this".
            return instance == nil ? .notInstalled : .blocked(.toolMissing)
        }
        guard let instance else { return .blocked(.noVaultFile) }
        // The instance carries its own field values, so the store's directory comes
        // from it rather than from a second lookup — and `quickScan` stays a pure
        // filesystem question, with no subprocess and no prompt.
        let reader = PasswordStoreReader(location: Self.location(from: instance))
        switch reader.storeState() {
        case .ready:
            return .ready
        case .readyOnlyWhileAgentRemembers:
            // Offered, with the caveat in the row's `uncheckedNote`. NOT blocked: a
            // great many people have their passphrase cached all day and this works
            // perfectly for them.
            //
            // `.wouldPromptTheUser` is the honest ceiling, and naming it is what stops
            // the row promising a check that will never come: the only way to find out
            // whether the agent still remembers the passphrase is to attempt a decrypt,
            // and an uncached one raises GnuPG's own pinentry. A dialog out of a
            // two-second background refresh is exactly what teaches people to click
            // through dialogs, so it is not done — see `deepScan` below, which returns
            // the cheap answer unchanged for this reason.
            return .unchecked(.wouldPromptTheUser)
        case .directoryMissing:
            return .blocked(.vaultFileMissing)
        case .notAStore:
            return .blocked(.vaultNotAPasswordStore)
        case .gpgMissing:
            return .blocked(.toolMissing)
        }
    }

    /// Nothing to add, and deliberately so. The only deeper check is a real decrypt,
    /// which can cost a passphrase prompt — an unexplained prompt from a background
    /// refresh is exactly what a deep scan must not do. See the kdbx adapter, which
    /// reaches the same conclusion for the same reason.
    func deepScan(quick: LocalVaultAvailability) async -> LocalVaultAvailability { quick }

    func provider(for source: CredentialSource) -> (any CredentialProvider)? {
        guard !source.reference.trimmingCharacters(in: .whitespaces).isEmpty else { return nil }
        // The profile says WHICH store as well as which entry — level 2 and level 3,
        // kept apart. Resolution happens at fetch time, on the main actor.
        return PasswordStoreProvider(reference: source.reference,
                                     account: source.account,
                                     instance: source.selection.instance)
    }

    // MARK: One store's directory, without a main-actor hop

    /// Taken from the INSTANCE'S OWN values rather than by asking the settings store.
    /// `quickScan` runs on every refresh from a nonisolated context, and hopping to the
    /// main actor there would mean making the whole scan async for the sake of one
    /// string. An MDM-pinned directory still wins: policy is written into the
    /// instance's values when it is applied, so reading the instance reads the policy.
    static func location(from instance: SourceInstance) -> PasswordStoreLocation {
        for field in SignInSourceSettings.fields(for: .passwordStore) {
            guard case .storeDirectory = field.kind else { continue }
            let v = instance.value(for: field).trimmingCharacters(in: .whitespaces)
            if !v.isEmpty { return PasswordStoreLocation(directory: v) }
        }
        return .default()
    }
}
