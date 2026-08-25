// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
//  VPNController+Auth.swift
//  THE CALLER-FACING SURFACE of the unified authentication abstraction: two methods,
//  and everything that wants to know about a VPN's sign-in asks one of them.
//
//    • `authSatisfaction(for:)` — CAN it serve, and if not, WHERE is it broken?
//    • `authPlan(for:typedOTP:)` — the PLAN. Bytes, a name, or an armed capture.
//
//  WHY HERE AND NOT IN A FREE-STANDING BROKER. Producing a plan needs the profile's
//  stored source (level 3), its auth config, its Touch ID state and the live
//  availability facts. All four already live on `VPNController`, which is also where
//  the control-plane guard chain is installed — and "one control plane" is an
//  established constraint in this codebase, not a preference. A separate broker would
//  have needed all four passed in, and would have been a second place a connect could
//  start from.
//
//  WHAT THIS REPLACED, precisely:
//
//   1. TWO ANSWERS TO ONE QUESTION. `SignInSourceAvailability.canServe(_:)` returned a
//      Bool for the connect form; `connectWithSavedCredentials` re-derived the same
//      question from `effectiveCredentialKind(...).suppliesOTP || biometricCanServe(…)`
//      for the unattended path. Different inputs, same question, and free to disagree.
//      Both now read `authSatisfaction(for:)`.
//   2. A DOUBLE RESOLVE. `connectUsingConfiguredSource` resolved the provider, then
//      wrapped the result in a `ManualCredentialProvider` and handed THAT to `connect`,
//      which resolved it again. The wrapper existed only to smuggle a value through a
//      protocol that wanted a fetcher — and it dropped `passkeyAssertion` on the way
//      through, because it had no field for it. `connect(id:plan:…)` takes the plan
//      directly.
//   3. A DEAD REGISTRY. `CredentialProviderRegistry.providers(for:manualFallback:)` had
//      no callers at all; the live dispatch was `managerProvider(for:)`. Deleted rather
//      than adapted — two registries for one job is how the wrong one gets extended.
//

import Foundation

/// A post-drop approval may be reused by exactly one immediate Connect. It is
/// process memory only, keyed to the exact linked coordinates, and deliberately
/// expires just before 1Password's current 30-second TOTP window rolls over.
struct PreparedOnePasswordSignIn: Sendable {
    let reference: String
    let account: String
    let vault: String
    let credentials: RawCredentials
    let expiresAt: Date

    static func expiry(now: Date = Date(), hasVerificationCode: Bool) -> Date {
        guard hasVerificationCode else { return now.addingTimeInterval(30) }
        let window: TimeInterval = 30
        let nextBoundary = (floor(now.timeIntervalSince1970 / window) + 1) * window
        // Do not send a code in the final two seconds of its window: it can roll
        // over between assembling the request and the gateway checking it.
        return Date(timeIntervalSince1970: nextBoundary - 2)
    }

    func matches(_ source: CredentialSource, account resolvedAccount: String,
                 now: Date = Date()) -> Bool {
        now < expiresAt
            && reference == source.reference
            && account == resolvedAccount
            && vault == source.vault
    }
}
import os

extension VPNController {

    // MARK: - Linking a 1Password entry

    /// Link a 1Password entry without reading it. Linking records only the exact
    /// coordinates the drag supplied. The ordinary Connect action performs the
    /// first approved read and learns the fields while consuming those same
    /// returned values; dropping an item must never summon an approval prompt.
    func linkOnePasswordEntry(_ dropped: OnePasswordDrop, for id: String) async throws {
        var source = credentialSource(for: id)
        let droppedAccount = dropped.account.trimmingCharacters(in: .whitespacesAndNewlines)
        let existingAccount = OnePasswordAccountMemory.effectiveAccount(for: source)
        guard !droppedAccount.isEmpty || !existingAccount.isEmpty else {
            throw OnePasswordLinkError.missingAccountCoordinate
        }
        source.kind = .onePassword
        source.reference = dropped.reference
        source.referenceTitle = dropped.title
        source.fieldMap = [:] // field IDs belong to the entry, never its predecessor.
        if !dropped.vault.isEmpty {
            source.vault = dropped.vault
            source.vaultTitle = dropped.vaultTitle
        }
        if !droppedAccount.isEmpty {
            // The profile owns the exact coordinate as a durable fallback. The
            // account row below is for a readable name and future selection; a
            // missing or reset app-level list must not orphan an already-linked
            // VPN or send the user back to a typing prompt.
            source.accountReference = droppedAccount
            source.accountTitle = dropped.accountTitle
            let settings = SignInSourceSettingsStore.shared
            if let connection = OnePasswordAccountMemory.connectionForDroppedAccount(
                droppedAccount, preferred: source.selection.instance, store: settings) {
                source.instanceID = connection.rawValue
                source.account = ""
                if source.accountTitle.isEmpty {
                    source.accountTitle = settings.instances(for: .onePassword)
                        .first { $0.id == connection }?.name ?? ""
                }
            } else {
                // Policy can forbid creating a row. The per-VPN coordinate above
                // is still sufficient for the SDK and remains hidden from the UI.
                OnePasswordAccountMemory.seed(droppedAccount)
                source.account = ""
            }
        }
        try await setCredentialSource(source, for: id)
    }

    /// Read the item once, persist only its non-secret description/mapping, and
    /// optionally keep the returned bytes for one immediate Connect. This is the
    /// post-drop fingerprint path: item/vault names become durable UI, while the
    /// password and current code remain short-lived process memory.
    @discardableResult
    func prepareLinkedOnePasswordEntry(
        for id: String, cacheForImmediateConnect: Bool
    ) async throws -> OnePasswordProvider.PreparedEntry {
        let source = credentialSource(for: id)
        let account = OnePasswordAccountMemory.effectiveAccount(for: source)
        let prepared = try await OnePasswordProvider.prepareEntry(
            itemReference: source.reference, vault: source.vault, account: account)

        var learnedSource = source
        learnedSource.fieldMap = prepared.inspection.fieldMap
        learnedSource.referenceTitle = prepared.inspection.title
        if learnedSource.vault.trimmingCharacters(in: .whitespaces).isEmpty,
           !prepared.inspection.vaultID.trimmingCharacters(in: .whitespaces).isEmpty {
            learnedSource.vault = prepared.inspection.vaultID
        }
        if !prepared.inspection.vaultTitle.isEmpty {
            learnedSource.vaultTitle = prepared.inspection.vaultTitle
        }
        if learnedSource != source {
            try await setCredentialSource(learnedSource, for: id)
        }

        if prepared.inspection.hasVerificationCode, !hasStaticChallenge(id) {
            var learnedAuth = authConfig(for: id)
            if !learnedAuth.requiresOTP {
                learnedAuth.requiresOTP = true
                try await setAuthConfig(learnedAuth, for: id)
            }
        }

        OnePasswordPreflight.markVerified()
        if cacheForImmediateConnect {
            let finalSource = credentialSource(for: id)
            let finalAccount = OnePasswordAccountMemory.effectiveAccount(for: finalSource)
            preparedOnePasswordSignIns[id] = PreparedOnePasswordSignIn(
                reference: finalSource.reference,
                account: finalAccount,
                vault: finalSource.vault,
                credentials: prepared.credentials,
                expiresAt: PreparedOnePasswordSignIn.expiry(
                    hasVerificationCode: prepared.inspection.hasVerificationCode))
        }
        return prepared
    }

    private func takePreparedOnePasswordSignIn(
        for id: String, source: CredentialSource
    ) -> RawCredentials? {
        guard let cached = preparedOnePasswordSignIns.removeValue(forKey: id) else { return nil }
        let account = OnePasswordAccountMemory.effectiveAccount(for: source)
        return cached.matches(source, account: account) ? cached.credentials : nil
    }

    // MARK: - Can it serve, and where is it broken?

    /// THE ONE QUESTION. Every readiness gate, the connect form's warning, the
    /// unattended reconnect and the recovery notice read this.
    ///
    /// It answers at a LEVEL rather than with a Bool, which is what lets a caller send
    /// somebody to the right screen without knowing anything about vendors: a missing
    /// binary is `.transport`, a database that has moved is `.instance`, a renamed
    /// entry is `.entry`, and a server that cannot be reached is `.reach` — different
    /// fixes, different owners.
    func authSatisfaction(for id: String,
                          facts: SignInSourceFacts? = nil) -> AuthSatisfaction {
        // "Type it this time" is the recovery escape, and it wins over everything: the
        // user has just said not to ask a source.
        if typedSignInOnce.contains(id) { return .typedInstead(.typeItThisTime) }

        let source = credentialSource(for: id)

        // LEVELS 1, 2 AND 3 come from the facts, in one derivation shared with the
        // settings pane and the chooser — see `SignInSourceAvailability.satisfaction`.
        // Only what a PROFILE knows is added here, which is why this method is short:
        // the level model was already right and did not need a second implementation.
        let availability = SignInSourceAvailability.shared
        let base: AuthSatisfaction
        if let overlaid = facts {
            // A caller with its own facts (a view holding a snapshot, or a test) gets
            // its facts used rather than the shared object's — same derivation, injected
            // input. Deliberately NOT refreshed here: this path is read from a view body,
            // and a getter that writes and bumps an observation revision mid-render is
            // how a SwiftUI update loop starts.
            base = availability.satisfaction(for: source, facts: overlaid)
        } else {
            // "WE HAVEN'T LOOKED YET" MUST NEVER READ AS "NOT INSTALLED".
            //
            // The facts start empty, and an absent vendor and an unscanned Mac are the
            // same value — so an unattended reconnect that fires before any view has
            // appeared (on-demand, the doctor's repair, a relaunch) would see every
            // vendor as missing and refuse to connect with a source that works perfectly.
            // The cheap pass is synchronous, spawns nothing and prompts for nothing —
            // that is exactly what it is for — so it is paid here rather than guessed at.
            if !availability.scanned { availability.refresh() }
            base = availability.satisfaction(for: source)
        }

        // A prior successful tunnel is per-profile proof that this linked
        // 1Password item has worked.  A global preflight result is only a
        // cache: it may be left over from an earlier approval attempt, and it
        // must not turn app launch into a recovery screen or prevent the next
        // explicit Connect from asking 1Password.  Automatic reconnects are
        // separately refused for 1Password in `canReconnectUnattended`, so
        // this never creates an unexplained Touch ID prompt.
        if source.kind == .onePassword,
           !source.reference.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty,
           FirstSuccessfulConnectionStore.hasSucceeded(profile: id) {
            return .ready
        }

        // THE PROFILE'S OWN HALF. Two things only the profile knows, and both of them
        // used to be re-derived at every call site that cared.
        switch base {
        case .typedInstead(.byChoice) where source.kind == .manual:
            // Touch ID-protected storage is a source in every sense — one fingerprint
            // releases the username, the password and, when a seed is stored, the code.
            if authConfig(for: id).protectWithBiometrics,
               BiometricCredentialStore.exists(profile: id) {
                return biometricCanServe(id: id)
                    ? .ready
                    // Everything is there except a code it cannot cover, and that is a
                    // level-3 problem: this profile needs a verification code and the
                    // item saved for it has no seed in it.
                    : .broken(locus: .entry, block: .vaultLocked)
            }
            if let saved = savedCredentials(id: id), !saved.password.isEmpty,
               !requiresOTP(for: id) {
                return .typedInstead(.savedInKeychain)
            }
            return .typedInstead(.byChoice)

        case .ready, .unproven:
            // Does this profile need a code the source has PROMISED to supply?
            // `suppliesOTP` is that promise and the only place it is made — and it is a
            // promise rather than a capability, because getting it wrong costs a failed
            // sign-in AND a burned one-time code.
            if requiresOTP(for: id), !source.kind.suppliesOTP {
                return .broken(locus: .entry, block: .vaultLocked)
            }
            return base

        case .broken, .typedInstead:
            return base
        }
    }

    // MARK: - The plan

    /// THE ONE CALL. What to DO to sign this VPN in.
    ///
    /// `.value` for everything a source hands over as bytes, which is every one of the
    /// twelve vaults, the keychain and typing. The other two deliveries are produced by
    /// the mechanisms that own them — `AuthPossession` by the SSH and OpenConnect
    /// engines from their own stored configuration, `AuthCaptureTicket` by the connect
    /// form, which is the only place a focused field exists to type into. This method
    /// does not invent either: a plan for a mechanism that authenticates without asking
    /// SimpleVPN for anything would be a plan nobody executes.
    ///
    /// CHECK STATE FIRST, AND REFUSE TO SPAWN A FETCH THAT COULD PROMPT. `pass`
    /// (GnuPG's pinentry), Dashlane (its master password on stdin) and LastPass (its
    /// agent gone) each arrived at that rule separately, in three different feeds, and
    /// it belongs here rather than in each adapter. `.broken` means the plan is refused
    /// BEFORE anything is started.
    func authPlan(for id: String, typedOTP: String = "") async throws -> AuthPlan {
        let auth = effectiveAuthConfig(for: id)
        let source = credentialSource(for: id)
        let satisfaction = authSatisfaction(for: id)
        let hasDroppedOnePasswordItem = source.kind == .onePassword
            && !source.reference.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty

        if case .broken(let locus, let block) = satisfaction,
           !hasDroppedOnePasswordItem {
            // Refused without spawning. The locus tells the caller which screen to
            // offer; the block carries the vendor's own sentence.
            throw AuthFailure(locus: locus, cause: .sourceUnavailable,
                              detail: LocalVaultRegistry
                                  .adapter(for: source.kind)
                                  .map { LocalVaultCopyBook.copy(for: $0.vendor)
                                      .headline(for: block) })
        }

        // A remembered preflight failure is not authoritative for an explicit
        // Connect after a drop. The drag has already supplied exact coordinates,
        // and this is the first user-authorised opportunity to ask 1Password for
        // them. Let that native request report the live result instead of refusing
        // it from stale cached state. Automatic reconnect never reaches this path
        // for 1Password (`canReconnectUnattended` refuses it), so this cannot create
        // an unexplained approval prompt.

        guard let provider = managerProvider(for: id) else {
            // The typed / remembered fields, which are already a `.value`: there is no
            // third shape for "the user typed it".
            let typed = transientCredentials(for: id)
            return .value(RawCredentials(
                username: typed.username.isEmpty ? nil : typed.username,
                password: typed.password.isEmpty ? nil : typed.password,
                otp: typed.otp.isEmpty ? (typedOTP.isEmpty ? nil : typedOTP) : typed.otp))
        }

        var raw: RawCredentials
        do {
            if source.kind == .onePassword,
               let prepared = takePreparedOnePasswordSignIn(for: id, source: source) {
                raw = prepared
            } else if source.kind == .onePassword,
               source.fieldMap.isEmpty,
               !source.reference.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
                // A drag deliberately records coordinates without opening
                // 1Password. The first explicit Connect pays for one full-item
                // read, derives the field roles, and uses the values from that
                // very response. There is no inspect-then-resolve round trip.
                let prepared = try await prepareLinkedOnePasswordEntry(
                    for: id, cacheForImmediateConnect: false)
                raw = prepared.credentials
            } else {
                raw = try await provider.resolve(profile: id, fields: auth.request.fields)
            }
        } catch {
            // ONE translation, at the seam, instead of every caller re-recognising
            // `CancellationError` and every vendor's own error enum. `.entry` because a
            // fetch that got as far as running failed at the item, not at the tool —
            // level 1 and level 2 were already established above.
            throw AuthFailure.from(error, locus: .entry)
        }
        // The person explicitly pressed Connect and 1Password released this
        // profile's credentials.  That is definitive evidence that its SDK
        // integration is working, and it supersedes an older remembered
        // "integration off" result.  Do not perform an additional preflight:
        // it would prompt a second time for the same user action.
        if credentialSource(for: id).kind == .onePassword {
            OnePasswordPreflight.markVerified()
        }
        // The typed code fills in only what the source could not supply. A source that
        // DID supply one wins, because it is the one that knows.
        if auth.requiresOTP, (raw.otp ?? "").isEmpty, !typedOTP.isEmpty {
            raw.otp = typedOTP
        }
        return .value(raw)
    }
}

private enum OnePasswordLinkError: LocalizedError {
    case missingAccountCoordinate

    var errorDescription: String? {
        switch self {
        case .missingAccountCoordinate:
            "That drag named the item but not its 1Password account. Drag the whole item row from 1Password, or set up an account first."
        }
    }
}
