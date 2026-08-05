// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
//  AuthOutcome.swift
//  WHERE A SIGN-IN IS BROKEN, AND WHAT WENT WRONG — the two questions every one of
//  the twelve sources answered on its own, in its own vocabulary, before this file.
//
//  There were eight separate error enums (`PassboltError`, `BitwardenError`,
//  `DashlaneError`, `LastPassError`, `ProtonPassError`, `KeeperError`,
//  `KeePassFileError`, `PasswordStoreError`, plus `OPError`, `KeePassXCError`,
//  `AppleError`, `YubiKeyToolError`, `PKCS11Failure`, `SSHAgentTransportError`), and
//  every caller got the same thing out of all of them: a `LocalizedError` string. So
//  the caller could show a sentence and could do nothing else — it could not say
//  which LEVEL of configuration to send somebody to, and it could not tell "your
//  password is wrong" from "your vault is not running", which are opposite advice.
//
//  Two vocabularies, both small, both closed:
//
//    • `AuthLocus`  — WHERE. Which of the configuration levels owns the problem, so
//      the fix and its owner follow from the type rather than from prose.
//    • `AuthCause`  — WHAT. The five-plus-two distinctions the checklist's question
//      10 asks every source to make, including the ones that are honestly ambiguous.
//
//  Each vendor keeps its own rich error enum — those are right, they carry the
//  vendor's own words and its own remedies, and rewriting twelve of them into one
//  flat enum is how a flat enum starts growing again. What each one gains is a
//  translation into this pair, IN ITS OWN FILE.
//

import Foundation

// MARK: - WHERE: the fourth locus

/// WHICH LEVEL a sign-in problem belongs to. Three of these are
/// `SignInConfigLevel`'s levels; the fourth is the one the Passbolt work found
/// missing.
///
/// FAILURE ATTRIBUTION FOLLOWS THE LEVELS, and that is the whole reason this type
/// exists rather than a flat error enum: a missing binary is level 1, a moved
/// database is level 2, a renamed entry is level 3 — different fixes, different
/// screens, different owners. A flat enum kept growing because it was mixing three
/// vocabularies.
nonisolated enum AuthLocus: String, Sendable, Equatable, CaseIterable, Codable {

    /// LEVEL 1 — how SimpleVPN reaches the vendor at all: the binary, the socket, the
    /// endpoint, the vendor's own switch. One per vendor, per Mac. Fixed in
    /// Settings ▸ Sign-In Sources, in the vendor's own section.
    case transport

    /// LEVEL 2 — WHICH one: which `.kdbx`, which store folder, which server address.
    /// One or more per vendor. Fixed by choosing or re-pointing an instance.
    case instance

    /// THE FOURTH LOCUS — THE CHANNEL TO THE INSTANCE.
    ///
    /// This is the gap the Passbolt feed found, and it is a real gap rather than a
    /// tidying-up: for a `.kdbx` the channel to the instance is FREE (the file is on
    /// this Mac, and `stat` settles it), so levels 1 and 2 between them describe
    /// everything that can go wrong. For a SERVER the channel is a NETWORK, and
    /// reachability, TLS and server identity are none of:
    ///
    ///   • level 1 — the `passbolt` binary is installed and fine;
    ///   • level 2 — the address is set and correct;
    ///   • level 3 — the resource exists and is named right.
    ///
    /// Folding them into level 2 would tell somebody to re-check an address that is
    /// perfectly correct; folding them into level 1 would send them to reinstall a
    /// tool that is working. So they get their own locus.
    ///
    /// It is also WHY the honest probe ceiling for a server-shaped instance is
    /// `.unchecked`: this locus is the one nothing can establish without a side
    /// effect. See `AuthProbeCeiling.wouldSignInToServer`.
    case reach

    /// LEVEL 3 — WHICH entry inside the instance, and which login inside the entry.
    /// Lives in the profile. Fixed in that VPN's own sign-in settings.
    case entry

    /// The three-level type this locus maps onto, or nil for `.reach` — which
    /// deliberately has no level, because it is not a thing anybody configures. That
    /// nil is the point: a `.reach` problem has no field to go and correct, which is
    /// exactly what makes it different from the other three.
    var configLevel: SignInConfigLevel? {
        switch self {
        case .transport: .transport
        case .instance: .instance
        case .reach: nil
        case .entry: .perVPN
        }
    }

    /// WHERE the fix lives, in plain language. Named from the locus so no caller has
    /// to match on a string to decide which screen to offer.
    var whereToFixIt: String {
        switch self {
        case .transport:
            "Settings \u{25B8} Sign-In Sources, where SimpleVPN is told how to reach it"
        case .instance:
            "Settings \u{25B8} Sign-In Sources, where you choose which one SimpleVPN reads"
        case .reach:
            // No field to correct, and saying so is more useful than sending somebody
            // to a screen where nothing they can change would help.
            "nothing in SimpleVPN \u{2014} it is the connection to the server itself"
        case .entry:
            "this VPN\u{2019}s own sign-in settings, where you pick the entry"
        }
    }
}

// MARK: - WHY "we haven't checked" is sometimes the ceiling, not a to-do

/// WHY a source is on offer without having been proven — the CEILING on what a probe
/// could honestly establish.
///
/// THE PROBLEM THIS FIXES. `LocalVaultAvailability.unchecked` used to be bare, and it
/// could not distinguish two states that need opposite handling:
///
///   • 1Password, Keeper, Bitwarden — the check is OWED. It is cheap, it is coming,
///     and picking the row pays it. "We haven't checked yet" is the whole truth.
///   • A Passbolt SERVER — the check is IMPOSSIBLE without a side effect. Nothing
///     short of a real sign-in proves a server can answer, and a real sign-in is an
///     authentication attempt against somebody else's machine: it spends their rate
///     limiter and their lockout budget, and it does so from a background refresh
///     that the user never asked for. So `.unchecked` is not a to-do here. It is the
///     honest ceiling, for ever.
///
/// A row that says "SimpleVPN checks this when you pick it" is a promise, and for the
/// second kind it is a promise nothing will keep. This type is what lets the copy be
/// right without any caller matching on the vendor.
nonisolated enum AuthProbeCeiling: String, Sendable, Equatable, CaseIterable, Codable {

    /// THE CHECK IS OWED and it will happen: cheap, local, and paid by picking the
    /// row or by the next deep pass. 1Password's approval, Keeper's `whoami`,
    /// Bitwarden's `status`, Dashlane's `status` are all this.
    case checkOwedOnUse

    /// A DEEPER CHECK WOULD BE A SIGN-IN AGAINST SOMEBODY ELSE'S SERVER. Passbolt is
    /// the case that names it. Never probed, and the row must not imply it will be.
    case wouldSignInToServer

    /// A DEEPER CHECK WOULD PUT A PROMPT ON SCREEN — a database passphrase, a GnuPG
    /// pinentry, a Touch ID sheet, a finger on a security key. An unexplained dialog
    /// out of a two-second background refresh is exactly what teaches people to click
    /// through dialogs, so it is never done. The `.kdbx` and password-store adapters
    /// reached this conclusion independently of Passbolt.
    case wouldPromptTheUser

    /// A DEEPER CHECK WOULD SPEND A ONE-TIME CODE to find out whether a one-time code
    /// works. Guaranteed to leave the next real attempt with nothing, and on some
    /// gateways it counts toward a lockout.
    case wouldSpendSingleUseCode

    /// Whether the unproven-ness will EVER be resolved by SimpleVPN on its own.
    ///
    /// This is the distinction the old bare `.unchecked` could not make: "set up,
    /// deliberately not probed" versus "probeable but not yet probed".
    var willBeProbed: Bool {
        switch self {
        case .checkOwedOnUse: true
        case .wouldSignInToServer, .wouldPromptTheUser, .wouldSpendSingleUseCode: false
        }
    }

    /// The locus the unprovable part sits at. `.reach` for the server case — which is
    /// the fourth locus doing its job — and `.instance` for the local ones, where the
    /// thing that cannot be checked without a prompt is the vault itself.
    var locus: AuthLocus {
        switch self {
        case .checkOwedOnUse: .transport
        case .wouldSignInToServer: .reach
        case .wouldPromptTheUser, .wouldSpendSingleUseCode: .instance
        }
    }

    /// One sentence, for the row and for VoiceOver, when the vendor has supplied no
    /// wording of its own. A vendor's `uncheckedNote` still wins — it can be specific
    /// — but this guarantees the sentence is never the WRONG one, which is what
    /// "SimpleVPN checks this when you pick it" was for a server.
    var fallbackNote: String {
        switch self {
        case .checkOwedOnUse:
            "SimpleVPN checks this when you pick it."
        case .wouldSignInToServer:
            "SimpleVPN hasn\u{2019}t tried to sign in to the server, and won\u{2019}t until you "
            + "connect \u{2014} asking would be a real sign-in attempt on somebody else\u{2019}s "
            + "machine."
        case .wouldPromptTheUser:
            "SimpleVPN can see it, and checking any further would have to ask you for "
            + "something \u{2014} so it waits until you connect."
        case .wouldSpendSingleUseCode:
            "Checking further would use up a verification code, so SimpleVPN waits until "
            + "you connect."
        }
    }
}

// MARK: - WHAT went wrong

/// The distinctions a caller genuinely needs to make, and no more.
///
/// Checklist question 10 asked every source: how do you tell *wrong credential* from
/// *source unavailable* from *user cancelled* from *server rejected* from *timed
/// out*? Twelve answers agreed on those five and added two more that kept coming up.
/// Two pairs are honestly ambiguous, and `isAmbiguousWith(_:)` says which — an
/// honest ambiguity is a design input, not something to paper over.
nonisolated enum AuthCause: String, Sendable, Equatable, CaseIterable, Codable {

    /// The source cannot answer at all: not installed, not running, not signed in,
    /// locked, the file is gone. Never the user's typing. The single most important
    /// one to keep separate, because the advice is "go and fix the source", and
    /// telling somebody their password is wrong instead sends them to change a
    /// password that was fine.
    case sourceUnavailable

    /// The secret was handed over and the thing it unlocks refused it — a database
    /// password, a key-file, a security-key slot.
    case wrongCredential

    /// The user cancelled: a Touch ID sheet dismissed, a vendor approval declined, a
    /// security-key touch that never came and was cancelled rather than timed out.
    /// NOT an error to report loudly; the user already knows.
    case userCancelled

    /// The far end said no. Distinct from `.wrongCredential` because the far end is
    /// somebody else's policy: an expired account, a plan that excludes the tool, a
    /// rate limit, a conditional-access rule.
    case serverRejected

    /// A deadline passed with no answer.
    case timedOut

    /// The entry named does not exist. A level-3 problem almost every time, and its
    /// own cause because "you have no entry called that" and "your password is wrong"
    /// are answered in different places.
    case notFound

    /// SEVERAL entries matched, and picking one would be picking somebody's vault
    /// item for them. Every source that can match loosely (Dashlane on address or
    /// title, Apple Passwords on server) ends up needing this, and every one of them
    /// concluded the same thing: refuse, and say so.
    case ambiguous

    /// Whether telling these two apart is genuinely impossible for at least one
    /// source — recorded rather than hidden, because a caller that must not guess
    /// needs to know when it is guessing.
    ///
    /// The two real ambiguities the feeds found:
    ///
    ///  • `.wrongCredential` versus `.serverRejected` — a gateway that answers
    ///    AUTH_FAILED does not say whether the password was wrong or the account was
    ///    disabled, and a vault that answers "could not decrypt" does not say whether
    ///    the passphrase or the key-file was the wrong one.
    ///  • `.userCancelled` versus `.timedOut` — a vendor dialog that closes tells us
    ///    nothing about why, and a security-key touch that never lands is
    ///    indistinguishable from one the user decided against.
    func isAmbiguousWith(_ other: AuthCause) -> Bool {
        let pair = Set([self, other])
        return pair == Set([AuthCause.wrongCredential, .serverRejected])
            || pair == Set([AuthCause.userCancelled, .timedOut])
    }

    /// Whether a retry could possibly succeed WITHOUT the user changing something.
    /// The gate on any automatic reconnect: retrying a `.wrongCredential` spends
    /// nothing but achieves nothing, and retrying after a one-time code was spent is
    /// worse than nothing.
    var isWorthRetryingUnattended: Bool {
        switch self {
        case .timedOut: true
        case .sourceUnavailable, .wrongCredential, .userCancelled, .serverRejected,
             .notFound, .ambiguous:
            false
        }
    }
}

// MARK: - The two together

/// A sign-in that did not work, ATTRIBUTED. What every caller wanted out of the
/// twelve error enums and could not get: where to send the user, and what to say.
///
/// `detail` is the vendor's own sentence — already scrubbed by the vendor's channel
/// before it gets here, because that is where the scrubbing belongs. NOTHING in this
/// type is ever a secret, and there is no field one could be put in: `detail` is a
/// message, not a value.
nonisolated struct AuthFailure: Error, Equatable, Sendable {

    var locus: AuthLocus
    var cause: AuthCause
    /// The vendor's own words, when it had some worth showing. Scrubbed, and never a
    /// credential.
    var detail: String?

    init(locus: AuthLocus, cause: AuthCause, detail: String? = nil) {
        self.locus = locus
        self.cause = cause
        self.detail = detail
    }

    /// The user cancelled — the one outcome that must never be reported as a fault.
    var isCancellation: Bool { cause == .userCancelled }

    /// What to show. The vendor's sentence when there is one, plus where to fix it
    /// when the locus points somewhere the user can act.
    var sentence: String {
        var parts: [String] = []
        if let detail, !detail.isEmpty { parts.append(detail) }
        if parts.isEmpty { parts.append(Self.plainCause(cause)) }
        if locus != .reach { parts.append("Fix it in \(locus.whereToFixIt).") }
        return parts.joined(separator: " ")
    }

    private static func plainCause(_ cause: AuthCause) -> String {
        switch cause {
        case .sourceUnavailable: "SimpleVPN couldn\u{2019}t reach where your sign-in is kept."
        case .wrongCredential: "That didn\u{2019}t unlock it."
        case .userCancelled: "Cancelled."
        case .serverRejected: "The server wouldn\u{2019}t accept it."
        case .timedOut: "Nothing answered in time."
        case .notFound: "There is no entry with that name."
        case .ambiguous: "More than one entry matched, so SimpleVPN didn\u{2019}t guess."
        }
    }
}

// MARK: - Can it serve? And if not, WHERE is it broken?

/// WHETHER A VPN'S CONFIGURED SIGN-IN CAN SERVE, and where the problem is when it
/// cannot. One answer, replacing two that were derived independently and could
/// disagree.
///
/// THE DUPLICATION THIS FIXES. `SignInSourceAvailability.canServe(_:)` answered
/// "yes/no" for the connect form, while `connectWithSavedCredentials` re-derived the
/// same question from `effectiveCredentialKind(...).suppliesOTP ||
/// biometricCanServe(...)` for the unattended path. Two answers to one question, in
/// two files, with two different sets of inputs — and a Bool cannot say *where* it is
/// broken, so every caller that wanted to help had to go back to the block enum and
/// match on it.
nonisolated enum AuthSatisfaction: Sendable, Equatable {

    /// A click connects. The source is proven, something is linked, and everything the
    /// profile needs can be got without typing.
    case ready

    /// It will probably work and nobody has proven it — with the CEILING, so the
    /// caller can tell "the check is coming" from "the check is never coming".
    /// Offered; a connect is what pays it.
    case unproven(AuthProbeCeiling)

    /// Something must happen first, AT A NAMED LEVEL. The block says what, the locus
    /// says whose screen to send the user to.
    case broken(locus: AuthLocus, block: LocalVaultBlock)

    /// NO SOURCE WILL BE ASKED — the typed fields are what this connect will really
    /// use. Not a failure and not an error: it is the state of a VPN set to "type it
    /// each time", of one whose chosen app has nothing linked yet, and of one where the
    /// user has clicked "type it this time". All three are ordinary, and all three used
    /// to be indistinguishable from a broken source.
    case typedInstead(AuthTypedReason)

    /// Whether a connect can proceed with nothing typed.
    var connectsUnattended: Bool {
        switch self {
        // Unproven is deliberately TRUE: it is what "offered, and picking it pays the
        // check" means, and refusing to try would make every unproven source
        // permanently unusable — including every one of the eleven the development
        // machine cannot verify.
        case .ready, .unproven: true
        case .broken, .typedInstead: false
        }
    }

    /// Whether the user has to be shown something before this can work.
    var needsAttention: Bool {
        if case .broken = self { return true }
        return false
    }

    /// The locus, when there is one to name.
    var locus: AuthLocus? {
        switch self {
        case .broken(let locus, _): locus
        case .unproven(let ceiling): ceiling.locus
        case .ready, .typedInstead: nil
        }
    }
}

/// WHY the typed fields are what will be used. Three ordinary reasons, and telling
/// them apart is the difference between "this is how you set it up" and "something is
/// wrong".
nonisolated enum AuthTypedReason: String, Sendable, Equatable, CaseIterable {
    /// The VPN is set to "type it each time". Working exactly as chosen.
    case byChoice
    /// A password app is chosen but nothing inside it is linked yet — no entry named.
    /// One picker away from working, and NOT the same as a broken app.
    case nothingLinked
    /// The user clicked "type it this time" on the recovery path. Temporary, and it
    /// must not read as a configuration problem.
    case typeItThisTime
    /// Saved in the keychain without Touch ID protection: read back at connect time
    /// and put into the fields, which is a fetch in every sense except that macOS
    /// rather than a vendor holds it.
    case savedInKeychain

    /// Whether this VPN can still connect with nothing typed — true only for the
    /// keychain, which HAS the answer already.
    var connectsUnattended: Bool { self == .savedInKeychain }
}

// MARK: - Every block, attributed to a locus

nonisolated extension LocalVaultBlock {

    /// WHICH LEVEL this block belongs to — derived once, in one exhaustive switch,
    /// rather than decided per call site.
    ///
    /// This is what makes the four-state availability model answer "at which level is
    /// this broken?" instead of only "is it broken?". Every caller that wanted to send
    /// somebody to the right screen was previously matching on the block itself, in a
    /// switch it had to keep up to date; a new block now has to state its locus, and
    /// the compiler asks.
    var locus: AuthLocus {
        switch self {
        // LEVEL 1 — how SimpleVPN reaches the vendor at all. Every one of these is
        // fixed in the vendor's own section of Settings, and none of them has anything
        // to do with which vault or which entry.
        case .appNotRunning, .needsUpdate, .integrationOff, .toolMissing,
             .toolOutsideAllowList, .notSignedIn, .toolDivertsSecretToClipboard,
             .planExcludesTool:
            .transport

        // LEVEL 2 — WHICH one. Choosing it, re-pointing it, unlocking it, or being
        // told it is not the sort of thing that was claimed.
        case .vaultLocked, .noVaultFile, .vaultFileMissing, .vaultFileNotDownloaded,
             .vaultFileNotReadable, .vaultFileNotAKeePassDatabase, .vaultFileTooNew,
             .vaultNotAPasswordStore, .vaultPasswordRejected, .noServerConfigured:
            .instance

        // NOTE ON WHAT IS *NOT* HERE. There is no `.reach` block, and that absence is
        // deliberate and honest: `.reach` problems — a server that does not answer, a
        // certificate that does not verify, an identity that changed — are never
        // PROBED, because probing them would be a sign-in attempt against somebody
        // else's machine (`AuthProbeCeiling.wouldSignInToServer`). They are learned at
        // FETCH time, and they arrive as an `AuthFailure` with `locus == .reach`, which
        // is where they belong. Inventing a block for them would mean inventing a
        // probe to produce it.
        }
    }

    /// Whether the fix is on THIS Mac. `.planExcludesTool` is the case that made this
    /// worth naming: everything is installed, everything is signed in, and the answer
    /// is a subscription on the vendor's own account pages — so telling somebody to
    /// change something here would send them round a loop for ever.
    var fixIsOnThisMac: Bool {
        switch self {
        case .planExcludesTool: false
        case .appNotRunning, .needsUpdate, .integrationOff, .toolMissing,
             .toolOutsideAllowList, .notSignedIn, .toolDivertsSecretToClipboard,
             .vaultLocked, .noVaultFile, .vaultFileMissing, .vaultFileNotDownloaded,
             .vaultFileNotReadable, .vaultFileNotAKeePassDatabase, .vaultFileTooNew,
             .vaultNotAPasswordStore, .vaultPasswordRejected, .noServerConfigured:
            true
        }
    }
}

// MARK: - Translating a cancellation, once

nonisolated extension AuthFailure {
    /// `CancellationError` is what the biometric store, the vendor helpers and the
    /// security-key capture all throw when the user says no, and every caller was
    /// re-recognising it. Once, here.
    static func from(_ error: any Error, locus: AuthLocus) -> AuthFailure {
        if let already = error as? AuthFailure { return already }
        if error is CancellationError {
            return AuthFailure(locus: locus, cause: .userCancelled)
        }
        return AuthFailure(locus: locus, cause: .sourceUnavailable,
                           detail: (error as? any LocalizedError)?.errorDescription
                               ?? error.localizedDescription)
    }
}
