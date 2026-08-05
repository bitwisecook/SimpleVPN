// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
//  OnePasswordPreflight.swift
//  "Does the 1Password integration actually work?" — asked once, at the moment
//  someone first chooses 1Password as their sign-in, and answered as one of six
//  states the setup card can walk them through.
//
//  Why a real call and not just the probe: `OnePasswordNative.probe()` is
//  prompt-free but only proves the SDK dylib is on disk (1Password is
//  installed). It says nothing about the one setting that decides whether any of
//  this works — Settings ▸ Developer ▸ Developer Integrations ▸ "Integrate with
//  1Password SDKs". Live testing pinned what a real call (listVaults) reports:
//    • "connection channel is closed" / kind integrationDisabled → that checkbox
//      is OFF, and the walkthrough is the whole answer;
//    • kind accountNotFound → the integration IS on and reachable; only the
//      account name is missing (a nudge, never an error);
//    • success → working, and the vault list is free — handed to the browse
//      cache rather than fetched again;
//    • userCancelled → 1Password showed its approval dialog and it was dismissed;
//    • nothing at all for several seconds → that dialog is almost certainly up
//      right now, waiting.
//
//  Choosing 1Password IS the first genuine need, so raising 1Password's approval
//  prompt then is legitimate. Running this at launch, or merely on opening the
//  editor for a VPN already set up, is not — see the privacy rule. The verified
//  flag exists so the walkthrough is a one-time event: it is cleared the moment
//  a real call says the integration is off again (people do turn it back off).
//
//  Foundation only, and the mapping is separated from the call, so every state
//  transition here is unit-testable without a live SDK.
//

import Foundation

nonisolated enum OnePasswordPreflight {

    /// Everything the setup check can conclude. `.failed` carries an already
    /// classified failure so the card can render an unfamiliar problem (locked,
    /// rate-limited, a future SDK string) without inventing new copy.
    enum State: Sendable, Equatable {
        case notInstalled
        case integrationOff
        case needsAccount
        case waitingForApproval
        case ready(vaults: [OnePasswordNative.OPVaultOverview])
        case failed(UserFacingError)

        var isReady: Bool { if case .ready = self { return true }; return false }
    }

    // MARK: The remembered answer

    /// Set once the integration has been seen working. Not a secret and not a
    /// setting — just "we've already walked this person through it".
    static let verifiedKey = "onePassword.sdkVerified"

    static func isVerified(in store: UserDefaults = .standard) -> Bool {
        store.bool(forKey: verifiedKey)
    }

    static func markVerified(in store: UserDefaults = .standard) {
        store.set(true, forKey: verifiedKey)
    }

    static func clearVerified(in store: UserDefaults = .standard) {
        store.removeObject(forKey: verifiedKey)
    }

    /// The other half of the remembered answer: a real call has said the
    /// developer-integration setting is OFF. Distinct from "not verified", which
    /// only means nobody has looked yet — the sign-in chooser needs to tell those
    /// apart, because one is a row that says "we'll check when you pick this" and
    /// the other is a row that can show the exact setting to switch on.
    /// Cleared the moment a call succeeds, so the chooser flips to ready on its
    /// next refresh without the app being restarted.
    static let integrationOffKey = "onePassword.sdkIntegrationOff"

    static func isIntegrationKnownOff(in store: UserDefaults = .standard) -> Bool {
        store.bool(forKey: integrationOffKey)
    }

    /// Whether picking 1Password should run the check. A verified integration
    /// skips straight to ready — the check costs an authorization prompt, and
    /// asking for one on every visit is exactly the noise this app avoids.
    static func shouldRun(verified: Bool) -> Bool { !verified }

    /// Apply a finished check to the remembered answer. Ready sets the flag;
    /// a real "integration is off" clears it, so the walkthrough comes back for
    /// anyone who turns the setting off later.
    @discardableResult
    static func remember(_ state: State, in store: UserDefaults = .standard) -> State {
        switch state {
        case .ready:
            markVerified(in: store)
            store.removeObject(forKey: integrationOffKey)
        case .integrationOff:
            clearVerified(in: store)
            store.set(true, forKey: integrationOffKey)
        default: break
        }
        return state
    }

    /// The same rule applied to a failure from a REAL call (connect, browse, a
    /// field read) rather than from the check — the only other way to learn the
    /// setting was turned back off.
    static func noteFailure(_ error: Error, in store: UserDefaults = .standard) {
        if outcome(for: error) == .integrationOff { remember(.integrationOff, in: store) }
    }

    // MARK: Mapping (pure)

    /// What a failed SDK call means for setup. Typed kinds map directly; the raw
    /// prose case (`.other`, which is how "desktop app connection channel is
    /// closed" arrives) is matched with the same test the failure classifier
    /// uses, so the two can never disagree about what "integration off" looks
    /// like.
    static func outcome(for error: Error) -> State {
        // Nothing came back in time. 1Password answers a reachable, enabled
        // integration in well under a second, so the overwhelmingly likely
        // reason is its approval dialog sitting somewhere waiting.
        if error is Timeout { return .waitingForApproval }
        if let native = error as? OnePasswordNativeError {
            switch native {
            case .appNotInstalled: return .notInstalled
            case .integrationDisabled: return .integrationOff
            case .accountNotFound: return .needsAccount
            case .userCancelled: return .waitingForApproval
            case .other(let message)
                where UserFacingError.mentionsDisabledIntegration(message.lowercased()):
                return .integrationOff
            default: break
            }
            return .failed(UserFacingError.classify(native))
        }
        if UserFacingError.mentionsDisabledIntegration(error.localizedDescription.lowercased()) {
            return .integrationOff
        }
        return .failed(UserFacingError.classify(error))
    }

    // MARK: Running it

    /// Probe (prompt-free) and then one real call. `account` is what this VPN
    /// names; a blank falls back to the account that has worked before, exactly
    /// as every other lookup does.
    ///
    /// The timeout is short on purpose: nothing comes back while 1Password's
    /// approval dialog is up, and "1Password is asking you something" is a far
    /// better thing to say after six seconds than a spinner is.
    static func run(account: String, timeout: Duration = .seconds(6),
                    store: UserDefaults = .standard) async -> State {
        guard await OnePasswordNative.probe() else { return .notInstalled }
        // Read the remembered name up front: the racing closure has to be
        // Sendable, and UserDefaults isn't.
        let remembered = OnePasswordAccountMemory.remembered(in: store)
        do {
            let listing = try await withTimeout(timeout) {
                try await list(account: account, remembered: remembered)
            }
            // A name that worked is worth remembering for every other VPN.
            OnePasswordAccountMemory.remember(listing.account, in: store)
            return remember(.ready(vaults: listing.vaults), in: store)
        } catch {
            return remember(outcome(for: error), in: store)
        }
    }

    private struct Listing: Sendable {
        var vaults: [OnePasswordNative.OPVaultOverview]
        var account: String
    }

    /// One vault list, with the standard account fallback: if 1Password doesn't
    /// know the account this VPN names, retry once with the one that has worked
    /// before. Rides the authorization the first call already asked for.
    private static func list(account: String, remembered: String) async throws -> Listing {
        let typed = account.trimmingCharacters(in: .whitespaces)
        do {
            return Listing(vaults: try await OnePasswordNative.listVaults(account: typed),
                           account: typed)
        } catch let error as OnePasswordNativeError {
            guard case .accountNotFound = error,
                  let fallback = OnePasswordAccountMemory.retry(after: typed, remembered: remembered)
            else { throw error }
            return Listing(vaults: try await OnePasswordNative.listVaults(account: fallback),
                           account: fallback)
        }
    }

    /// "1Password hasn't answered." Its own case rather than a generic failure:
    /// it is the one outcome that means the user has something to do in ANOTHER
    /// app right now. Visible so the mapping can be pinned by a test.
    struct Timeout: Error {}

    /// Race the call against the clock. Cancellation reaches the helper process
    /// (it is terminated), so a timed-out check leaves nothing running.
    static func withTimeout<T: Sendable>(
        _ duration: Duration, _ body: @escaping @Sendable () async throws -> T
    ) async throws -> T {
        try await withThrowingTaskGroup(of: T.self) { group in
            group.addTask { try await body() }
            group.addTask {
                try await Task.sleep(for: duration)
                throw Timeout()
            }
            defer { group.cancelAll() }
            guard let first = try await group.next() else { throw Timeout() }
            return first
        }
    }

    // MARK: Copy

    /// The nudge shown when the only thing missing is the account name. One
    /// wording, shared by the editor's Account field, the browse popover and the
    /// setup card — it is the single commonest stumbling block, and three
    /// slightly different sentences for it helped nobody.
    static let accountNudge =
        "Almost there \u{2014} add your account name (the name at the top left of "
        + "1Password\u{2019}s sidebar) and SimpleVPN will check the item."

    /// The line the setup card leads with.
    static func headline(for state: State) -> String {
        switch state {
        case .notInstalled: "1Password isn\u{2019}t installed on this Mac"
        case .integrationOff: "1Password needs one setting turned on"
        case .needsAccount: accountNudge
        case .waitingForApproval: "1Password is asking for your approval"
        case .ready: "1Password is connected"
        case .failed(let error): error.title
        }
    }

    /// The numbered walkthrough under the headline. Markdown: **bold** names the
    /// real thing on screen.
    static func steps(for state: State) -> [UserFacingError.Step] {
        switch state {
        case .notInstalled:
            [.init("Install **1Password** (version 8 or later) from 1password.com."),
             .init("Open it and sign in to your account."),
             .init("Come back here and click **Check Again**.")]
        case .integrationOff:
            [.init("Open **1Password**."),
             .init("Choose **1Password \u{25B8} Settings**, then click **Developer**."),
             .init("Under **Developer Integrations**, tick **\(UserFacingError.sdkIntegrationSetting)**.",
                   note: "1Password\u{2019}s own message names an older setting that no longer exists."),
             .init("Come back here and click **Check Again**.")]
        case .waitingForApproval:
            [.init("Switch to **1Password** \u{2014} it\u{2019}s showing a prompt asking to allow **SimpleVPN**."),
             .init("Choose **Allow**, or confirm with Touch ID."),
             .init("Come back here and click **Check Again**.")]
        case .needsAccount, .ready:
            []
        case .failed(let error):
            error.steps
        }
    }

    /// The symbol beside the headline.
    static func symbol(for state: State) -> String {
        switch state {
        case .notInstalled: "arrow.down.app"
        case .integrationOff: "key.slash"
        case .needsAccount: "person.crop.circle.badge.questionmark"
        case .waitingForApproval: "hand.raised.fill"
        case .ready: "checkmark.circle.fill"
        case .failed(let error): error.symbol
        }
    }
}
