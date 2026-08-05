// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
//  PassboltProvider.swift
//  Passbolt's two seam implementations: the provider that reads one resource,
//  and the adapter that says whether it could.
//
//  Everything about HOW a server is read lives in PassboltServer.swift —
//  including why SimpleVPN holds no passphrase, why `--tlsSkipVerify` can never
//  be emitted, and why a name search is matched in Swift rather than turned into
//  one of the tool's CEL filters.
//
//  WHAT A SERVER-SHAPED INSTANCE COSTS. The `.kdbx` and `pass` sources can settle
//  a level-2 question with a `stat`: the file is there or it is not. A server
//  cannot be probed without talking to it, and talking to a Passbolt server means
//  completing an OpenPGP login — an authentication attempt, against somebody
//  else's machine, with somebody else's rate limiter and lockout policy. So this
//  adapter's `deepScan` deliberately adds NOTHING, and the honest ceiling of a
//  background answer is "set up, and never proven". A real login happens when the
//  user asks for one (the editor's test row) or when a VPN connects, and the
//  reachability and certificate states live in `PassboltError` where they belong,
//  not in the availability model that a refresh timer drives.
//

import Foundation

// MARK: - Provider

/// WHICH server, resolved from the level-2 instance. Read on the main actor (the
/// settings store lives there) and handed to a `nonisolated` reader — the same
/// shape as `PasswordStoreConfiguration`, for the same reason.
nonisolated struct PassboltConfiguration: Sendable, Equatable {
    var instance: SourceInstanceID?
    var name: String = ""
    var location = PassboltServerLocation()
    /// False when the profile names a server that is not set up any more.
    /// Deliberately not "fall back to another server": reading somebody's other
    /// Passbolt because a list changed is worse than failing to read at all.
    var isResolved: Bool = false

    @MainActor
    static func current(store: SignInSourceSettingsStore = .shared,
                        instance wanted: SourceInstanceID? = nil) -> PassboltConfiguration {
        let resolution = store.instanceStore.resolve(wanted, for: .passbolt)
        guard let instance = resolution.instance else { return PassboltConfiguration() }
        var out = PassboltConfiguration(instance: instance.id, name: instance.name,
                                        isResolved: true)
        for field in SignInSourceSettings.fields(for: .passbolt) {
            // `effectivePath` / `value` so an MDM-pinned setting wins, exactly as
            // it does for a tool path.
            let shown = store.presentation(for: field, instance: instance)
            switch field.kind {
            case .serverURL:
                out.location.serverURL = shown.value.trimmingCharacters(in: .whitespaces)
            case .toolConfigFile:
                let path = shown.value.trimmingCharacters(in: .whitespaces)
                out.location.configFile = path.isEmpty ? nil : path
            case .toolBinary, .unixSocket, .daemonEndpoint, .pkcs11Module, .vaultFile,
                 .keyFile, .securityKeySlot, .storeDirectory, .entryFieldName:
                continue
            }
        }
        return out
    }
}

nonisolated struct PassboltProvider: CredentialProvider {
    /// The resource's identifier or its name — see `PassboltResourceReference`.
    let reference: String
    /// An optional username from the VPN's own profile. Takes precedence over
    /// what the resource says, because the person who typed it here meant it.
    let account: String
    /// WHICH server — resolved at fetch time rather than at construction, because
    /// the settings store is main-actor isolated and a provider is built
    /// nonisolated.
    let instance: SourceInstanceID?
    /// Injectable so every path is testable with no Passbolt and no server.
    var makeReader: @Sendable (PassboltConfiguration) -> PassboltReader = {
        PassboltReader(location: $0.location)
    }

    var id: String { "passbolt:\(instance?.rawValue ?? "default")#\(reference)" }
    var displayName: String { "Passbolt" }

    /// Cheap and prompt-free: the tool is here, the address is usable, the tool has a
    /// key, and SOMETHING can unlock it. Deliberately does NOT sign in — availability
    /// must never cost an authentication attempt against somebody's server, and on an
    /// account with a lockout policy it would spend budget for nothing. It also must
    /// never raise the Touch ID sheet, which is why it asks `couldSupply` rather than
    /// `passphrase(server:reason:)`.
    func isAvailable(for profile: String) async -> Bool {
        let config = await MainActor.run { PassboltConfiguration.current(instance: instance) }
        guard config.isResolved else { return false }
        guard PassboltResourceReference.parse(reference) != nil else { return false }
        let held = await MainActor.run {
            PassboltPassphraseStore.shared.couldSupply(server: config.location.serverURL)
        }
        var reader = makeReader(config)
        reader.weHoldAPassphrase = held
        return reader.serverState() == .readyToTry
    }

    func resolve(profile: String, fields: Set<AuthKind>) async throws -> RawCredentials {
        let config = await MainActor.run { PassboltConfiguration.current(instance: instance) }
        guard config.isResolved else {
            throw PassboltError.noServerConfigured("no server is set up yet")
        }
        guard let wanted = PassboltResourceReference.parse(reference) else {
            throw PassboltError.resourceNotFound(reference)
        }
        // The passphrase SimpleVPN holds for this server, if any. This is the ONE call
        // that may raise a Touch ID sheet, and it happens on a connect the user asked
        // for — never on a refresh. A cancel is `CancellationError` and is translated
        // into its own case: treating it as a wrong passphrase would spend somebody's
        // server-side lockout budget on a decision they made.
        let held: PassboltPassphrase?
        do {
            held = try await PassboltPassphraseStore.shared.passphrase(
                server: config.location.serverURL,
                reason: "Unlock your Passbolt key so SimpleVPN can read this VPN\u{2019}s sign-in")
        } catch is CancellationError {
            throw PassboltError.cancelled
        }
        var reader = makeReader(config)
        reader.weHoldAPassphrase = held != nil
        let resource = try await reader.read(wanted, passphrase: held)
        var out = RawCredentials()
        if fields.contains(.password) { out.password = resource.password }
        if fields.contains(.username) {
            let typed = account.trimmingCharacters(in: .whitespaces)
            out.username = typed.isEmpty ? resource.username : typed
        }
        if fields.contains(.otp), let totp = resource.totp {
            // Computed locally from the resource's own seed with the app's RFC
            // 6238 engine, as Bitwarden's and the password store's are. The KIND's
            // `suppliesOTP` is still FALSE: only some Passbolt resource types
            // carry a code, so a code MAY be there — and "may" is not a promise
            // Connect can be built on.
            out.otp = totp.code(at: Date())
        }
        return out
    }
}

// MARK: - Adapter

nonisolated struct PassboltVaultAdapter: LocalVaultAdapter {
    let vendor = LocalVaultVendor.passbolt
    let storedKind = CredentialSourceKind.passbolt
    /// `.cli`, and only `.cli`. There is no local daemon and no socket: Passbolt
    /// is a server, and its own command-line program is the whole local surface.
    let transports: [AuthTransport] = [.cli]

    /// Without an instance there is no server to look at, so the vendor-level
    /// answer is the best of its configured servers (computed by the registry) or,
    /// with none configured, "nothing set up yet" when the Mac could otherwise do
    /// it.
    func quickScan() -> LocalVaultAvailability {
        quickScan(instance: nil)
    }

    func quickScan(instance: SourceInstance?) -> LocalVaultAvailability {
        // The tool is the one thing that must exist. Ask discovery before saying
        // "not installed": a `go install` build in ~/go/bin is a path to set, not
        // a thing to install, and those need different sentences.
        guard PassboltCLI.locate() != nil else {
            if outsideAllowListPath() != nil { return .blocked(.toolOutsideAllowList) }
            // Not installed at all, and unlike a password store there is no
            // folder whose presence could suggest otherwise — so the row simply
            // is not offered until a server has been set up, at which point the
            // honest answer is "install Passbolt's program".
            return instance == nil ? .notInstalled : .blocked(.toolMissing)
        }
        guard let instance else { return .blocked(.noServerConfigured) }
        var reader = PassboltReader(location: Self.location(from: instance))
        // Whether SimpleVPN could supply a passphrase, WITHOUT asking for one: held
        // for this run, or remembered behind Touch ID. `couldSupply` never prompts,
        // which matters because this runs on every settings refresh and an
        // unexplained Touch ID sheet from a background pass is exactly what teaches
        // people to click through them.
        reader.weHoldAPassphrase = PassboltPassphraseStore.shared
            .couldSupply(server: reader.location.serverURL)
        switch reader.serverState() {
        case .readyToTry:
            // NEVER `.ready`. Nothing has talked to the server, and this is the
            // whole difference between a file-shaped instance and a server-shaped
            // one: `stat` can prove a file is readable, and nothing short of a
            // login can prove a server is. The row's `uncheckedNote` says so.
            //
            // AND THE CEILING SAYS WHY. `.wouldSignInToServer` is not "we haven't got
            // round to it": it is "we never will, and here is the reason". A deeper
            // probe would be a real authentication attempt against somebody else's
            // machine, spending their rate limiter and their lockout budget, from a
            // background refresh nobody asked for. Before the ceiling existed this
            // state was indistinguishable from 1Password's "the check is owed and
            // picking the row pays it", so the row could promise a check that would
            // never happen — and `AuthProbeCeiling.willBeProbed` is now what tells the
            // two apart, without any caller knowing the word "Passbolt".
            return .unchecked(.wouldSignInToServer)
        case .needsPassphrase:
            // The key is there and nothing can unlock it. Bitwarden named this state
            // and it is the same one — and here its fix is one field on this Mac
            // rather than a command in a Terminal.
            return .blocked(.vaultLocked)
        case .toolNotConfigured:
            return .blocked(.notSignedIn)
        case .noServer:
            return .blocked(.noServerConfigured)
        case .toolMissing:
            return .blocked(.toolMissing)
        }
    }

    /// Nothing to add, and the reason is this feed's most interesting finding: the
    /// only deeper check is a real login, and a real login is an authentication
    /// attempt against somebody else's server. Running one from a background
    /// refresh would put unexplained sign-in attempts — and rate-limit and lockout
    /// budget — against a machine we were only asking a question about. See the
    /// `.kdbx` and password-store adapters, which reach the same conclusion for
    /// the local equivalent (a real unlock can cost a prompt).
    func deepScan(quick: LocalVaultAvailability) async -> LocalVaultAvailability { quick }

    func provider(for source: CredentialSource) -> (any CredentialProvider)? {
        guard !source.reference.trimmingCharacters(in: .whitespaces).isEmpty else { return nil }
        return PassboltProvider(reference: source.reference,
                                account: source.account,
                                instance: source.selection.instance)
    }

    // MARK: Helpers

    /// Where the tool was FOUND but will not be run from, for either of its two
    /// names. Both are asked because both are real installs.
    ///
    /// `@MainActor` because the registry's answer comes from the settings store's
    /// discovery switch, which lives there. `quickScan` can call it: that method is
    /// a protocol witness and takes the protocol's isolation, which is why the
    /// password-store adapter can make the same call inline.
    @MainActor
    func outsideAllowListPath() -> String? {
        for name in PassboltCLI.toolNames {
            if let path = LocalVaultRegistry.toolFoundOutsideAllowList(name) { return path }
        }
        return nil
    }

    /// One server's address and config file, taken from the INSTANCE'S OWN values
    /// rather than by asking the settings store — `quickScan` runs on every
    /// refresh from a nonisolated context, and hopping to the main actor there
    /// would mean making the whole scan async for two strings. An MDM-pinned value
    /// still wins: policy is written into the instance's values when it is
    /// applied, so reading the instance reads the policy.
    static func location(from instance: SourceInstance) -> PassboltServerLocation {
        var out = PassboltServerLocation()
        for field in SignInSourceSettings.fields(for: .passbolt) {
            let value = instance.value(for: field).trimmingCharacters(in: .whitespaces)
            guard !value.isEmpty else { continue }
            switch field.kind {
            case .serverURL: out.serverURL = value
            case .toolConfigFile: out.configFile = value
            default: continue
            }
        }
        return out
    }
}
