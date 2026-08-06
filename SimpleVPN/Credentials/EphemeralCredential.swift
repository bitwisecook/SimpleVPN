// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
//  EphemeralCredential.swift
//  Two primitives every credential source in this app shares, and NEITHER of them
//  belongs to a vendor. Deliberately vendor-free and deliberately tiny:
//
//   1. `SingleUseCode` — a secret that may be read EXACTLY ONCE, optionally with an
//      expiry. Security-critical, and the reason it lives here rather than beside
//      the feature that first needed it: a dozen more credential sources are
//      coming (Bitwarden, Dashlane, kdbx, Proton Pass, pass/gopass, Passbolt,
//      LastPass, HashiCorp Vault, …) and several of them hand over something
//      single-use or time-bounded. Fifteen home-made single-use boxes would mean
//      fifteen separate refactors of code where a mistake costs somebody's
//      account.
//   2. `InteractionWait` — "we are waiting for a human, with a deadline, and they
//      can cancel". A YubiKey touch, a Touch ID prompt, 1Password's approval
//      dialog, KeePassXC's allow-access dialog, a `gpg` pinentry: all the same
//      arithmetic, and getting the arithmetic wrong is how a prompt sits armed for
//      ever or expires while the user is still reaching for their key.
//
//  WHAT IS NOT HERE, on purpose. This is not the unified auth abstraction: there is
//  no `CredentialPlan`, no source protocol, no registry. That abstraction is
//  deliberately deferred until every feed has landed and we know what is genuinely
//  common. These two are here early only because they are the pieces that get
//  COPIED if they are not.
//

import Foundation
import os

// MARK: - Where a secret came from

/// Where a secret came from, for WORDING ONLY.
///
/// Nothing may branch on this to decide how a secret is handled — that is the
/// caller's own knowledge, and a value used both for prose and for control flow is
/// how prose changes become behaviour changes.
///
/// A struct with static constants rather than an enum, so a new source adds its own
/// case in its own file. An enum here would mean every one of the ~15 remaining
/// feeds editing one shared file, which is exactly the merge conflict this
/// programme is shaped to avoid.
nonisolated struct SecretOrigin: RawRepresentable, Sendable, Hashable {
    let rawValue: String
    init(rawValue: String) { self.rawValue = rawValue }

    /// The person typed it.
    static let typedByUser = SecretOrigin(rawValue: "typed-by-user")
    /// A DEVICE typed it, as keystrokes, into a field we had focused — a security
    /// key's Yubico OTP or static password. The bytes never crossed an API.
    static let typedByDevice = SecretOrigin(rawValue: "typed-by-device")
    /// A device computed it and we read it back (an OATH code from a security key,
    /// a challenge-response answer).
    static let computedByDevice = SecretOrigin(rawValue: "computed-by-device")
    /// Fetched from a password app or secret store.
    static let fetchedFromVault = SecretOrigin(rawValue: "fetched-from-vault")
    /// Computed by SimpleVPN from a stored seed (our own TOTP generator).
    static let derivedLocally = SecretOrigin(rawValue: "derived-locally")
}

// MARK: - A secret that can be read once

/// A secret readable EXACTLY ONCE, optionally with an expiry.
///
/// ─── WHY A CLASS WITH A LOCK, AND NOT A `let String` ─────────────────────────
/// A consumed one-time credential is worse than useless. The server has already
/// burned it, a retry is GUARANTEED to fail, and on anything that counts failures a
/// silent retry loop walks an account into a lockout. "Don't retry" written in a
/// comment is a promise the next edit breaks. So the value lives behind an accessor
/// that empties the box:
///
///   • there is no getter, no `description`, no `debugDescription`, and
///     deliberately no `Codable` — so it cannot be interpolated into a log line,
///     written to `providerConfiguration`, put in a defaults key, or serialised
///     into a diagnostic bundle. Those are not conventions; the API simply has no
///     way to do them.
///   • `consume()` is the ONLY way out, and it answers nil for ever afterwards.
///   • `discard()` empties it early (a cancel, a timeout, a changed source).
///   • an `expiresAt` box answers nil once the moment has passed, WITHOUT waiting
///     to be asked: a stale OATH code that is 40 seconds old must not be sent, and
///     a caller that forgot to check must fail closed rather than send it.
///
/// A retry path that re-reads a spent or expired box therefore gets nil, and has to
/// surface "get a fresh one" — the behaviour we want — instead of replaying a dead
/// secret. That is the structural version of the rule, and it is the reason this
/// type is mandatory for every feed rather than merely available.
///
/// ─── WHAT IT IS NOT ─────────────────────────────────────────────────────────
/// It is NOT a secure-memory container. Swift `String` storage is not locked, not
/// zeroed on release, and may be copied by the runtime; a box that claimed
/// otherwise would be worse than one that does not, because someone would rely on
/// it. What it guarantees is the LIFECYCLE — read once, never twice, never after
/// expiry, and never through an API that could leak it into text.
nonisolated final class SingleUseCode: Sendable {

    /// nil once taken, discarded, or expired. The lock makes `consume()` genuinely
    /// once even if two connect attempts race — which is precisely the case this
    /// type exists for.
    private let storage: OSAllocatedUnfairLock<String?>

    /// When this stops being usable, if it does. nil = spent-on-use only.
    ///
    /// For a code with a window (OATH, a session token) this is the END of the
    /// window, not its start. Being generous here is a bug: an OATH code handed
    /// over one second before it rolls over will be rejected by the server, and
    /// "expired" is a far better thing to tell someone than "rejected".
    let expiresAt: Date?

    /// Where it came from. Wording only — see `SecretOrigin`.
    let origin: SecretOrigin

    /// Optional identifying information that is NOT secret and IS safe to display,
    /// log and speak. A Yubico OTP's public ID is the motivating case: Yubico
    /// publishes public IDs in cleartext by design, and showing one answers "did the
    /// right key just type?".
    ///
    /// `nil` unless a source has something genuinely publishable. Never put part of
    /// a secret here to make a nicer label.
    let publicLabel: String?

    init(_ secret: String, origin: SecretOrigin = .typedByUser,
         expiresAt: Date? = nil, publicLabel: String? = nil) {
        self.storage = OSAllocatedUnfairLock(initialState: secret)
        self.origin = origin
        self.expiresAt = expiresAt
        self.publicLabel = publicLabel
    }

    /// Take the secret. Exactly once, and only while it is still valid.
    ///
    /// An expired box EMPTIES itself rather than merely refusing: if the moment has
    /// passed, the value is of no use to anybody and keeping it around is only a
    /// chance to leak it.
    func consume(now: Date = Date()) -> String? {
        storage.withLock { held in
            if let expiresAt, now >= expiresAt {
                held = nil
                return nil
            }
            defer { held = nil }
            return held
        }
    }

    /// Throw it away unused.
    func discard() {
        storage.withLock { $0 = nil }
    }

    /// Already used, discarded — or expired, which counts, because it can never be
    /// consumed again either.
    func isSpent(now: Date = Date()) -> Bool {
        storage.withLock { held in
            if held == nil { return true }
            if let expiresAt, now >= expiresAt { return true }
            return false
        }
    }

    /// Purely the expiry half, for a UI that wants to distinguish "you used it"
    /// from "it ran out".
    func isExpired(now: Date = Date()) -> Bool {
        guard let expiresAt else { return false }
        return now >= expiresAt
    }

    /// Seconds of validity left, or nil when there is no expiry. Never negative.
    func secondsRemaining(now: Date = Date()) -> Int? {
        guard let expiresAt else { return nil }
        return max(0, Int(expiresAt.timeIntervalSince(now).rounded(.up)))
    }

    /// How long it is, for a field that shows the right number of dots. A length is
    /// not the secret; the characters are.
    var characterCount: Int { storage.withLock { $0?.count ?? 0 } }
}

// MARK: - Waiting for a human

/// "We are waiting for the user to do something physical, with a deadline, and they
/// can stop." The arithmetic only — no UI, no vendor, no secret.
///
/// Every credential source that needs a human has this shape: a security key touch,
/// a Touch ID prompt, 1Password's approval dialog, KeePassXC's allow-access dialog,
/// a `gpg` passphrase. What differs is the WORDING and what arrives at the end; what
/// is identical is arm / count down / complete / time out / cancel, and each of
/// those has a way to be subtly wrong (a prompt that stays armed for ever, one that
/// expires while the user is still reaching, a cancel that leaves the deadline
/// running).
///
/// A value type so it composes into whatever richer state a source needs, rather
/// than being a base class that dictates one.
nonisolated struct InteractionWait: Sendable, Equatable {

    nonisolated enum Phase: Sendable, Equatable {
        case idle
        case waiting
        case completed
        case timedOut
        case cancelled
    }

    private(set) var phase: Phase = .idle
    private(set) var startedAt: Date?
    private(set) var expiresAt: Date?
    /// When it completed, which a caller needs for a grace window after the fact
    /// (see the trailing-Return problem in YubiKeyTouchCapture.swift).
    private(set) var completedAt: Date?

    init() {}

    var isWaiting: Bool { phase == .waiting }
    var isCompleted: Bool { phase == .completed }

    /// Start waiting. Arming always clears whatever went before: a second attempt
    /// replaces the first, and half-remembered state from a previous one is how a
    /// stale value gets used.
    mutating func arm(now: Date = Date(), wait: TimeInterval) {
        phase = .waiting
        startedAt = now
        expiresAt = now.addingTimeInterval(max(0, wait))
        completedAt = nil
    }

    /// It happened.
    mutating func complete(now: Date = Date()) {
        phase = .completed
        completedAt = now
    }

    /// The user stopped it. Distinct from a timeout because the wording differs and
    /// so does whether we offer to start again immediately.
    mutating func cancel() {
        phase = .cancelled
        expiresAt = nil
    }

    mutating func reset() {
        self = InteractionWait()
    }

    /// Called on a timer while waiting. Returns true the ONE time it has just
    /// expired, so a caller can announce it exactly once.
    @discardableResult
    mutating func tick(now: Date = Date()) -> Bool {
        guard phase == .waiting, let expiresAt, now >= expiresAt else { return false }
        phase = .timedOut
        self.expiresAt = nil
        return true
    }

    /// Seconds left on the wait, rounded UP so a countdown never shows 0 while it
    /// is still going.
    func secondsRemaining(now: Date = Date()) -> Int {
        guard phase == .waiting, let expiresAt else { return 0 }
        return max(0, Int(expiresAt.timeIntervalSince(now).rounded(.up)))
    }

    /// Whether `now` is inside `grace` of the completion. The shape a caller needs
    /// when a device sends something immediately AFTER the thing we were waiting
    /// for — a security key's trailing carriage return being the case that named
    /// this method.
    func isWithinGraceOfCompletion(_ grace: TimeInterval, now: Date = Date()) -> Bool {
        guard let completedAt, now >= completedAt else { return false }
        return now.timeIntervalSince(completedAt) < grace
    }
}
