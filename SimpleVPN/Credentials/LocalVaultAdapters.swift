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
//  BUILT ELSEWHERE: Bitwarden — see BitwardenProvider.swift, which carries its
//  adapter as well as its channels (its local `bw serve` service first, then the
//  `bw` CLI). The session key turned out to be the whole design rather than a
//  detail: the CLI cannot read anything without one, so the service — which holds
//  the unlock in its own process — is the channel that works without SimpleVPN ever
//  handling a vault key.
//
//  ALSO BUILT ELSEWHERE: Dashlane — see DashlaneProvider.swift. Its one channel is
//  `dcli`, and the design question that file exists to answer is where `dcli` sends
//  what it reads: by default, to the pasteboard. It is asked for `--output json`
//  instead, which both keeps the password off the clipboard and avoids the
//  interactive picker `--output console` runs into when a filter matches twice.
//
//  Not built, but a small additive adapter when it is wanted:
//   • LastPass — `lpass` CLI. `lpass status` for liveness, `lpass show --json
//     <name>`; `lpass login` is interactive, so it is the "needs a one-time
//     sign-in" state. It would be `.blocked(.notSignedIn)` until its CLI has a
//     session, exactly like Keeper.
//  ALSO BUILT ELSEWHERE: LastPass — see LastPassProvider.swift. `lpass status` is
//  the liveness probe and `lpass show --json` the read, and the one thing that made
//  it worth building rather than declaring dormant is its AGENT: one `lpass login`
//  in Terminal leaves a background process holding the vault key, which it hands to
//  `lpass` and to nothing else — so every later fetch is silent and SimpleVPN never
//  holds a master password or a derived key. Its own file explains why that row's
//  copy nonetheless sets lower expectations than any other.
//
//  Not built, but a small additive adapter when it is wanted:
//   • Dashlane — `dcli` CLI. `dcli sync` / `dcli password <filter> --output
//     console`; device registration is the one-time step. It would be
//     `.blocked(.notSignedIn)` until its CLI has a session, exactly like Keeper.
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
    /// `AuthTransport` for why `.file` is the one that collapses three
    /// KeePass-format vendors into one future adapter.
    var transports: [AuthTransport] { get }
    /// Cheap, prompt-free, no subprocesses. Safe to call on every refresh.
    /// May answer `.unchecked` when only a deep scan can tell.
    func quickScan() -> LocalVaultAvailability
    /// The same cheap answer for ONE configured instance (level 2 — see
    /// SignInSourceInstances.swift). A vendor that declares
    /// `SourceCardinality.single` has exactly one thing to talk to and inherits the
    /// default below, which ignores the argument; a multi-instance vendor probes
    /// each of its vaults separately, because one database can be missing while
    /// another is ready.
    func quickScan(instance: SourceInstance?) -> LocalVaultAvailability
    /// The full answer. `quick` is what the cheap scan already established, so
    /// an adapter never repeats work (or spawns anything for an absent vendor).
    func deepScan(quick: LocalVaultAvailability) async -> LocalVaultAvailability
    /// The fetcher for a stored source, or nil when the source names nothing to
    /// fetch from (no item linked yet).
    func provider(for source: CredentialSource) -> (any CredentialProvider)?
}

extension LocalVaultAdapter {
    /// A singular vendor's instance scan IS its vendor scan. Declared once here so a
    /// `.single` adapter needs no boilerplate and cannot accidentally grow a
    /// per-instance answer that means nothing.
    func quickScan(instance: SourceInstance?) -> LocalVaultAvailability { quickScan() }
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
    let transports: [AuthTransport] = [.signedIPC]

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
        return .unchecked(.checkOwedOnUse)
    }

    func deepScan(quick: LocalVaultAvailability) async -> LocalVaultAvailability {
        guard quick != .notInstalled else { return .notInstalled }
        // The prompt-free probe only proves the SDK library is on disk. An app
        // that is here without it is an old 1Password, which no amount of
        // approving will fix — say "update" rather than "allow".
        //
        // THREE OUTCOMES, and the third is the fix. `.noAnswer` means the helper never
        // ran (a refused spawn, a killed process, an unparseable reply): it is not a
        // finding about 1Password, so the cheap pass's answer stands unchanged. It used
        // to arrive here as `false` and become `.blocked(.needsUpdate)` — which
        // `deepWins` then let override a perfectly good `.ready` for the rest of the
        // session, telling somebody with a healthy 1Password to update it.
        switch await OnePasswordNative.probeAnswer() {
        case .available: return quick
        case .unavailable: return .blocked(.needsUpdate)
        case .noAnswer: return quick
        }
    }

    func provider(for source: CredentialSource) -> (any CredentialProvider)? {
        guard !source.reference.trimmingCharacters(in: .whitespaces).isEmpty else { return nil }
        return OnePasswordProvider(
            itemReference: source.reference, vault: source.vault,
            // THREE LEVELS, in order: what this VPN says, then the CONNECTION it
            // names, then what we remember. The middle step is what makes a work
            // tenant and a personal account both usable — see
            // `OnePasswordAccountMemory.effective(profile:connection:remembered:)`.
            account: OnePasswordAccountMemory.effectiveAccount(for: source),
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
    let transports: [AuthTransport] = [.appSocket]

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
    let transports: [AuthTransport] = [.localDaemon, .cli]

    /// The Keeper desktop app, which is NOT a read path — it is only the signal
    /// that this person uses Keeper, and therefore that Commander is worth
    /// telling them about.
    static let appBundleIDs = ["com.callpod.KeeperDesktop", "com.keepersecurity.KeeperDesktop"]

    static var isAppInstalled: Bool {
        appBundleIDs.contains { NSWorkspace.shared.urlForApplication(withBundleIdentifier: $0) != nil }
    }

    func quickScan() -> LocalVaultAvailability {
        if KeeperCommanderChannel.isInstalled() { return .unchecked(.checkOwedOnUse) }
        // Before saying "not installed", ASK. Discovery searches every location
        // any package manager, version manager or vendor installer uses — plus
        // `PATH`, which the execution side will never consult — so it can tell the
        // difference between "you don't have Commander" and "you have Commander in
        // a virtualenv". Only one of those two is a thing to install.
        if LocalVaultRegistry.toolFoundOutsideAllowList("keeper") != nil {
            return .blocked(.toolOutsideAllowList)
        }
        return Self.isAppInstalled ? .blocked(.toolMissing) : .notInstalled
    }

    func deepScan(quick: LocalVaultAvailability) async -> LocalVaultAvailability {
        guard quick != .notInstalled else { return .notInstalled }
        // Nothing to probe when the tool itself is missing — spawning would be
        // pointless, and "not signed in" would be the wrong thing to say. Same for
        // a tool we can see but won't run: probing it would mean executing exactly
        // the binary the allow-list declined.
        guard quick != .blocked(.toolMissing),
              quick != .blocked(.toolOutsideAllowList) else { return quick }
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
        // Bitwarden's adapter lives in BitwardenProvider.swift with its channels:
        // one vendor is one file plus this one line, so several vendors landing at
        // once do not collide in the same switch.
        BitwardenVaultAdapter(),
        // Dashlane's adapter lives in DashlaneProvider.swift, for the same reason
        // Bitwarden's lives with its channels: one vendor is one file plus this one
        // line.
        DashlaneVaultAdapter(),
        // The `.file` transport — one adapter for KeePassXC-as-a-file, Strongbox and
        // KeePassium, because all three store the same `.kdbx`. LAST on purpose: a
        // running app that owns its own unlock (the KeePassXC row above) is a better
        // answer than a file whose password has to reach us.
        KeePassFileVaultAdapter(),
        // A folder of GPG-encrypted files, read with gpg alone — no app, no socket, no
        // daemon, and neither `pass` nor `gopass` required.
        PasswordStoreVaultAdapter(),
        // Proton Pass through Proton's own `pass-cli`. Its adapter lives in
        // ProtonPassProvider.swift with its channel, like Bitwarden's — one vendor is
        // one file plus this one line. NOT the same vendor as the row above, despite
        // the tool names: see that file's header.
        ProtonPassVaultAdapter(),
        // A SERVER, through Passbolt's own command-line program. The first adapter
        // whose instance is not on this Mac at all, which is why its deepScan adds
        // nothing: see PassboltProvider.swift.
        PassboltVaultAdapter(),
        // LastPass through `lpass`. LAST on purpose, and the order is a statement: it
        // is the least capable source here — no verification code, ever — so anything
        // else that can answer is a better answer.
        LastPassVaultAdapter(),
    ]

    static func adapter(for vendor: LocalVaultVendor) -> (any LocalVaultAdapter)? {
        all.first { $0.vendor == vendor }
    }

    /// Where discovery found a tool the EXECUTION allow-list won't run, or nil.
    ///
    /// The one place adapters ask that question, so every CLI-backed vendor gets
    /// the honest "it's installed, just not where we look" state from one line
    /// instead of each one re-deriving it. Respects the master discovery switch:
    /// with the scan off there is nothing to report and we say nothing, rather than
    /// scanning anyway.
    static func toolFoundOutsideAllowList(_ tool: String) -> String? {
        guard SignInSourceSettingsStore.shared.discoveryEnabled else { return nil }
        guard let found = ToolDiscovery.cachedMap()[tool], found.isFoundButUnusable else { return nil }
        // The most useful path to name is one the user could sanction, not a
        // world-writable one we would refuse even if they asked.
        return found.choosablePaths.first?.path ?? found.paths.first?.path
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

    /// The cheap pass over every vendor AND every configured instance.
    ///
    /// A multi-instance vendor's own row is the BEST of its vaults, because the row
    /// answers "can this vendor get me in at all" — hiding a ready personal
    /// database because the work one is on an unmounted volume would be a lie. The
    /// per-vault answers ride alongside it, so the pane, the chooser and a report
    /// can each say which is which. A vendor with no vaults configured yet still
    /// gets its vendor-level scan, which is what produces "no database chosen".
    static func quickScanAll(
        instances: [LocalVaultVendor: [SourceInstance]]
    ) -> (vendors: [LocalVaultVendor: LocalVaultAvailability],
          instances: [SourceInstanceID: LocalVaultAvailability]) {
        var vendors: [LocalVaultVendor: LocalVaultAvailability] = [:]
        var perInstance: [SourceInstanceID: LocalVaultAvailability] = [:]
        for adapter in all {
            let list = adapter.vendor.cardinality.allowsSeveral
                ? (instances[adapter.vendor] ?? []) : []
            guard !list.isEmpty else {
                vendors[adapter.vendor] = adapter.quickScan()
                continue
            }
            var best = LocalVaultAvailability.notInstalled
            for instance in list {
                let answer = adapter.quickScan(instance: instance)
                perInstance[instance.id] = answer
                if answer.rank > best.rank { best = answer }
            }
            vendors[adapter.vendor] = best
        }
        return (vendors, perInstance)
    }

    /// The full pass. Sequential on purpose: each of these can put a vendor's own
    /// approval dialog on screen, and two at once is a mess.
    ///
    /// `skipping` is the vendors the user has switched off. They are not probed at
    /// all — a vendor's tool can raise its own Touch ID or approval prompt, and
    /// raising one for a source that has been turned off is an unexplained dialog
    /// from nowhere.
    static func deepScanAll(
        quick: [LocalVaultVendor: LocalVaultAvailability],
        skipping: Set<LocalVaultVendor> = []
    ) async -> [LocalVaultVendor: LocalVaultAvailability] {
        var out = quick
        for adapter in all where !skipping.contains(adapter.vendor) {
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
