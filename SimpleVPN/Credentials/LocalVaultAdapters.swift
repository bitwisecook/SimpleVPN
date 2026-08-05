// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
//  LocalVaultAdapters.swift
//  ONE seam per password vendor SimpleVPN can really talk to locally. Each
//  adapter answers three questions and nothing else:
//
//    1. quickScan()  — is your software here? (file / bundle / socket checks
//                      only, cheap enough to run while a chooser is on screen)
//    2. deepScan()   — can it actually serve right now? (may spawn a helper or
//                      the vendor's CLI; run once per launch, or on demand)
//    3. provider()   — build the thing that fetches a sign-in for a stored source
//
//  WHY A SEAM AND NOT THREE SPECIAL CASES. The first cut of this feature hard-
//  coded "Keeper has no local integration", which was simply wrong: Keeper ships
//  Keeper Commander (MIT, actively maintained) with persistent login and a local
//  REST daemon. Being wrong about one vendor cost a rewrite; being wrong about
//  the next one must cost one file. So the chooser, the readiness decision, the
//  connect path and the copy all go through this seam, and adding a vendor is:
//  one adapter here, one `LocalVaultCopy` entry, one `CredentialSourceKind` case.
//
//  Not built, but each is a small additive adapter when it is wanted:
//   • Bitwarden — `bw` CLI. Needs `bw status` for session liveness, a
//     BW_SESSION key (Bitwarden's own unlock model: `bw unlock --raw` prints one)
//     which we must NOT persist, and `bw get item <id> --session …`. The session
//     key is the hard part, not the fetch.
//   • LastPass — `lpass` CLI. `lpass status` for liveness, `lpass show --json
//     <name>`; `lpass login` is interactive, so it is the "needs a one-time
//     sign-in" state.
//   • Dashlane — `dcli` CLI. `dcli sync` / `dcli password <filter> --output
//     console`; device registration is the one-time step.
//  All three would be `.blocked(.notSignedIn)` until their CLI has a session,
//  exactly like Keeper.
//

import Foundation
import AppKit
import LocalAuthentication

/// A vendor SimpleVPN reaches over a local channel.
protocol LocalVaultAdapter: Sendable {
    var vendor: LocalVaultVendor { get }
    /// The stored-source kind this adapter serves.
    var storedKind: CredentialSourceKind { get }
    /// How it is reached, most-preferred first. A vendor with two ways in lists
    /// both (Keeper: its local daemon, then its CLI) and its own code decides;
    /// this is here so the shape of a channel is a declared fact rather than
    /// something you infer by reading the implementation. See
    /// `LocalVaultTransport` for why `.file` is the one that collapses three
    /// KeePass-format vendors into one future adapter.
    var transports: [LocalVaultTransport] { get }
    /// Cheap, prompt-free, no subprocesses. Safe to call on every refresh.
    /// May answer `.unchecked` when only a deep scan can tell.
    func quickScan() -> LocalVaultAvailability
    /// The full answer. `quick` is what the cheap scan already established, so
    /// an adapter never repeats work (or spawns anything for an absent vendor).
    func deepScan(quick: LocalVaultAvailability) async -> LocalVaultAvailability
    /// The fetcher for a stored source, or nil when the source names nothing to
    /// fetch from (no item linked yet).
    func provider(for source: CredentialSource) -> (any CredentialProvider)?
}

// MARK: - 1Password

/// 1Password over the official SDK's local IPC to the desktop app. The tiers:
/// app absent → not offered; app present but the SDK library isn't → needs
/// updating; app present, not running → its channel is app-to-app, so it can't
/// answer; running but never proven → offered, and picking it runs the existing
/// preflight (which is allowed to raise 1Password's approval prompt); proven →
/// ready.
struct OnePasswordVaultAdapter: LocalVaultAdapter {
    let vendor = LocalVaultVendor.onePassword
    let storedKind = CredentialSourceKind.onePassword
    /// The SDK's signed IPC to the running app. NOT the `op` CLI — that path was
    /// retired, which is why the enablement banner points at 1Password's SDK
    /// setting and its SDK documentation rather than at the CLI's.
    let transports: [LocalVaultTransport] = [.signedIPC]

    /// Every distribution of the app, plus the version-7 bundle id — the same
    /// list the failure sheet already resolves for "Open 1Password".
    static let bundleIDs = ["com.1password.1password", "com.agilebits.onepassword7",
                            "com.1password.1password-launcher"]
    static let runningPrefixes = ["com.1password.", "com.agilebits."]

    static var isAppInstalled: Bool {
        bundleIDs.contains { NSWorkspace.shared.urlForApplication(withBundleIdentifier: $0) != nil }
    }

    static var isAppRunning: Bool {
        NSWorkspace.shared.runningApplications.contains { app in
            guard let id = app.bundleIdentifier else { return false }
            return runningPrefixes.contains { id.hasPrefix($0) }
        }
    }

    func quickScan() -> LocalVaultAvailability {
        guard Self.isAppInstalled else { return .notInstalled }
        guard Self.isAppRunning else { return .blocked(.appNotRunning) }
        // The developer-integration setting has been proven before ⇒ ready
        // without asking anything.
        if OnePasswordPreflight.isVerified() { return .ready }
        // A real call has said the setting is OFF ⇒ say so, with the banner,
        // rather than hiding it or pretending the check is merely owed. Cleared
        // the moment a call succeeds, so following the banner flips this row to
        // ready on the next poll — no restart.
        if OnePasswordPreflight.isIntegrationKnownOff() { return .blocked(.integrationOff) }
        // Otherwise the check is owed, and picking the row is what pays it.
        return .unchecked
    }

    func deepScan(quick: LocalVaultAvailability) async -> LocalVaultAvailability {
        guard quick != .notInstalled else { return .notInstalled }
        // The prompt-free probe only proves the SDK library is on disk. An app
        // that is here without it is an old 1Password, which no amount of
        // approving will fix — say "update" rather than "allow".
        guard await OnePasswordNative.probe() else { return .blocked(.needsUpdate) }
        return quick
    }

    func provider(for source: CredentialSource) -> (any CredentialProvider)? {
        guard !source.reference.trimmingCharacters(in: .whitespaces).isEmpty else { return nil }
        return OnePasswordProvider(
            itemReference: source.reference, vault: source.vault,
            account: OnePasswordAccountMemory.effectiveAccount(profile: source.account),
            fieldMap: source.fieldMap)
    }
}

// MARK: - KeePassXC

/// KeePassXC over its browser-integration unix socket. Installed-with-no-socket
/// is the "one switch to turn on" case, so it is offered WITH the steps rather
/// than hidden: a hidden row is indistinguishable from an app we don't support,
/// which would be a lie about a vendor we do.
struct KeePassXCVaultAdapter: LocalVaultAdapter {
    let vendor = LocalVaultVendor.keePassXC
    let storedKind = CredentialSourceKind.keePassXC
    /// The running app's own socket. A future `.file` adapter would read the same
    /// `.kdbx` directly (and would then also serve Strongbox and KeePassium) —
    /// this path stays first regardless, because a running app owns the unlock.
    let transports: [LocalVaultTransport] = [.appSocket]

    static let bundleIDs = ["org.keepassxc.keepassxc"]

    static var isAppInstalled: Bool {
        bundleIDs.contains { NSWorkspace.shared.urlForApplication(withBundleIdentifier: $0) != nil }
    }

    func quickScan() -> LocalVaultAvailability {
        // The socket is the authority: a KeePassXC installed somewhere Launch
        // Services hasn't indexed still answers on its socket.
        if KeePassXCProvider.probe() { return .ready }
        return Self.isAppInstalled ? .blocked(.integrationOff) : .notInstalled
    }

    /// Nothing a subprocess could add: the socket either exists or it doesn't.
    func deepScan(quick: LocalVaultAvailability) async -> LocalVaultAvailability { quick }

    func provider(for source: CredentialSource) -> (any CredentialProvider)? {
        guard !source.reference.trimmingCharacters(in: .whitespaces).isEmpty else { return nil }
        return KeePassXCProvider(reference: source.reference, account: source.account)
    }
}

// MARK: - Keeper

/// Keeper through Keeper Commander. Four tiers, and the middle two are the reason
/// the enablement banner exists:
///   1. Commander here and signed in → a source SimpleVPN fetches from.
///   2. Commander here, no live session → offered, with the sign-in commands.
///   3. The KEEPER APP here but no Commander → offered, with the install command.
///      SimpleVPN never installs it; the command is shown and the user runs it.
///   4. Nothing Keeper on this Mac → not offered at all.
///
/// `quickScan` only does file checks; whether a persistent-login session is live
/// needs a real `whoami`, which is the deep scan. Until that answers, the row says
/// the check is owed rather than accusing anyone of not being signed in.
struct KeeperVaultAdapter: LocalVaultAdapter {
    let vendor = LocalVaultVendor.keeper
    let storedKind = CredentialSourceKind.keeper
    /// Its local REST daemon when the user has created one, else its CLI. The
    /// order is the preference: a running daemon costs no Python start-up.
    let transports: [LocalVaultTransport] = [.localDaemon, .cli]

    /// The Keeper desktop app, which is NOT a read path — it is only the signal
    /// that this person uses Keeper, and therefore that Commander is worth
    /// telling them about.
    static let appBundleIDs = ["com.callpod.KeeperDesktop", "com.keepersecurity.KeeperDesktop"]

    static var isAppInstalled: Bool {
        appBundleIDs.contains { NSWorkspace.shared.urlForApplication(withBundleIdentifier: $0) != nil }
    }

    func quickScan() -> LocalVaultAvailability {
        if KeeperCommanderChannel.isInstalled() { return .unchecked }
        return Self.isAppInstalled ? .blocked(.toolMissing) : .notInstalled
    }

    func deepScan(quick: LocalVaultAvailability) async -> LocalVaultAvailability {
        guard quick != .notInstalled else { return .notInstalled }
        // Nothing to probe when the tool itself is missing — spawning would be
        // pointless, and "not signed in" would be the wrong thing to say.
        guard quick != .blocked(.toolMissing) else { return quick }
        return await KeeperCommanderChannel.hasLiveSession() ? .ready : .blocked(.notSignedIn)
    }

    func provider(for source: CredentialSource) -> (any CredentialProvider)? {
        guard !source.reference.trimmingCharacters(in: .whitespaces).isEmpty else { return nil }
        return KeeperProvider(reference: source.reference, account: source.account)
    }
}

// MARK: - The registry

enum LocalVaultRegistry {
    /// Every adapter, in the order vendor rows are offered.
    static let all: [any LocalVaultAdapter] = [
        OnePasswordVaultAdapter(),
        KeePassXCVaultAdapter(),
        KeeperVaultAdapter(),
    ]

    static func adapter(for vendor: LocalVaultVendor) -> (any LocalVaultAdapter)? {
        all.first { $0.vendor == vendor }
    }

    static func adapter(for kind: CredentialSourceKind) -> (any LocalVaultAdapter)? {
        all.first { $0.storedKind == kind }
    }

    /// The cheap pass over every vendor.
    static func quickScanAll() -> [LocalVaultVendor: LocalVaultAvailability] {
        var out: [LocalVaultVendor: LocalVaultAvailability] = [:]
        for adapter in all { out[adapter.vendor] = adapter.quickScan() }
        return out
    }

    /// The full pass. Sequential on purpose: each of these can put a vendor's own
    /// approval dialog on screen, and two at once is a mess.
    static func deepScanAll(
        quick: [LocalVaultVendor: LocalVaultAvailability]
    ) async -> [LocalVaultVendor: LocalVaultAvailability] {
        var out = quick
        for adapter in all {
            let start = quick[adapter.vendor] ?? adapter.quickScan()
            out[adapter.vendor] = await adapter.deepScan(quick: start)
        }
        return out
    }
}

// MARK: - Can this Mac ask for a fingerprint?

enum DeviceOwnerAuth {
    /// Touch ID, Apple Watch, or the account password — anything that satisfies
    /// `.deviceOwnerAuthentication`. Decides whether the keychain row promises a
    /// fingerprint; promising one on a Mac that can't is worse than not offering.
    static var isAvailable: Bool {
        var error: NSError?
        return LAContext().canEvaluatePolicy(.deviceOwnerAuthentication, error: &error)
    }
}
