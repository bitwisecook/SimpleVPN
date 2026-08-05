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
import os

extension VPNController {

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
        let satisfaction = authSatisfaction(for: id)

        if case .broken(let locus, let block) = satisfaction {
            // Refused without spawning. The locus tells the caller which screen to
            // offer; the block carries the vendor's own sentence.
            throw AuthFailure(locus: locus, cause: .sourceUnavailable,
                              detail: LocalVaultRegistry
                                  .adapter(for: credentialSource(for: id).kind)
                                  .map { LocalVaultCopyBook.copy(for: $0.vendor)
                                      .headline(for: block) })
        }

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
            raw = try await provider.resolve(profile: id, fields: auth.request.fields)
        } catch {
            // ONE translation, at the seam, instead of every caller re-recognising
            // `CancellationError` and every vendor's own error enum. `.entry` because a
            // fetch that got as far as running failed at the item, not at the tool —
            // level 1 and level 2 were already established above.
            throw AuthFailure.from(error, locus: .entry)
        }
        // The typed code fills in only what the source could not supply. A source that
        // DID supply one wins, because it is the one that knows.
        if auth.requiresOTP, (raw.otp ?? "").isEmpty, !typedOTP.isEmpty {
            raw.otp = typedOTP
        }
        return .value(raw)
    }
}
