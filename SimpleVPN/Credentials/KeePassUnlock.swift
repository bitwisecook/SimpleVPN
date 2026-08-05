// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
//  KeePassUnlock.swift
//  The three things that unlock a KeePass `.kdbx` database — a password, a key
//  file, and a security key's challenge-response — gathered into one value, plus
//  the decisions about where the password may be KEPT.
//
//  ─── THE COMPOSITE KEY, AND WHO ASSEMBLES IT ───────────────────────────────
//  KeePassXC hashes its factors in a fixed order (`src/keys/CompositeKey.cpp`):
//  every ordinary key first, in the order they were added, then every
//  challenge-response answer. SimpleVPN does NOT reproduce that, and the reason is
//  worth stating because it looks like a gap:
//
//    `keepassxc-cli` has no way to accept externally-derived key material. There
//    is no "here are the composite bytes" input, and a key file is hashed at its
//    own position in the chain, so twenty bytes of challenge-response cannot be
//    smuggled in as one. Either the tool assembles the composite key or we decrypt
//    the database ourselves.
//
//  So the tool assembles it: we hand it a password (on stdin), a key-file path and
//  a slot number, and it does the derivation, the AEAD and the XML. What that buys
//  is that SimpleVPN contains no cryptography of its own for somebody's entire
//  password vault — see the header of KeePassFileProvider.swift for the full
//  argument.
//
//  ─── WHAT `YubiKeyChallengeResponse` IS USED FOR HERE ──────────────────────
//  Since the tool owns the touch during a connect, asking the key ourselves at the
//  same moment would cost a SECOND touch for one unlock — which is exactly the
//  kind of thing that makes a feature infuriating. So the challenge-response call
//  is a CHECK, run when the user asks for it, never during a connect:
//
//    `KeePassSecurityKeyCheck.run(...)` sends the database's own KDF seed to the
//    slot and reports whether twenty bytes came back.
//
//  That is the call `YubiKeyChallengeResponse.keyMaterial(for:requiresTouch:)` was
//  built for, and its precondition holds: the challenge is `kdf.seed()`, which
//  KDBX stores in the CLEARTEXT outer header (KeePassDatabaseFile.swift cites the
//  source), so it is a public value and may ride argv. The padding is
//  `YubiKeyChallengeResponse`'s — `.keePassPKCS7To64`, matched to KeePassXC's own
//  `YubiKeyInterfaceUSB.cpp`. None of it is reimplemented here.
//
//  The check PROVES POSSESSION and nothing more: that a key is plugged in, that
//  the slot holds a credential, and that it answers this database's challenge. It
//  cannot prove the answer is the RIGHT one — only a successful unlock can, because
//  only the database knows what the composite key should hash to. The copy says so.
//  The twenty bytes are key material, so they are dropped on the spot: their length
//  is all that is ever reported, and they are never shown, logged or stored.
//
//  ─── WHERE THE DATABASE PASSWORD MAY LIVE ─────────────────────────────────
//  A `.kdbx` master password is not one VPN's password: it opens EVERYTHING the
//  person owns. That asymmetry decides the storage question, and the answer is
//  narrower than for our own credentials:
//
//   1. DEFAULT: NOWHERE. Nothing is kept. The password is typed once per run of
//      SimpleVPN, held in memory, and gone when the app quits.
//   2. OPT-IN: THE TOUCH ID KEYCHAIN, AND ONLY THAT ONE. Never the ordinary
//      keychain, which would let this app decrypt a person's whole vault silently
//      any time it liked. `.userPresence` means macOS will not release it without
//      a fingerprint, an Apple Watch, or the account password — the same bar
//      KeePassXC and Strongbox apply to their own quick-unlock, and a bar a
//      background process cannot clear on its own.
//   3. NEVER `providerConfiguration`, never a defaults key, never a log line, and
//      never argv. It reaches `keepassxc-cli` on stdin and by no other route.
//
//  Kept per DATABASE, not per VPN: it is the database's password, and five VPNs
//  reading one database must not mean five copies of it.
//

import Foundation
import CryptoKit
import LocalAuthentication
import os

// MARK: - The password, boxed

/// A database password, held so that it cannot leak by accident.
///
/// NOT a `SingleUseCode`: that type is for a secret that is spent by being used,
/// and a database password is the opposite — it is replayable, and one app run may
/// unlock the same database a dozen times. What it borrows from `SingleUseCode` is
/// the part that matters for a value that is never displayed: no `Codable`, no
/// `description`, no `debugDescription`, and no getter that hands back a `String`.
/// The only way out is `stdinLine()`, which produces the bytes to write to a
/// tool's standard input — so there is no API through which this can be
/// interpolated into a log line, a defaults key or a diagnostic bundle.
///
/// It is NOT secure memory. Swift `String` storage is not locked or zeroed, and a
/// box that claimed otherwise would be worse than one that does not.
nonisolated final class KDBXPassword: Sendable {

    private let value: String

    init(_ value: String) { self.value = value }

    /// True for a database that has no password at all (key file and/or security
    /// key only). A real state, not a mistake: it decides whether the tool is told
    /// `--no-password`.
    var isEmpty: Bool { value.isEmpty }

    /// How long it is, for a field that shows the right number of dots. A length is
    /// not the secret.
    var characterCount: Int { value.count }

    /// The bytes to write to the tool's standard input.
    ///
    /// A TRAILING NEWLINE IS REQUIRED, and it is not cosmetic: KeePassXC's
    /// `Utils::getPassword` calls `QTextStream::readLine()`, so without one the
    /// tool blocks until the pipe closes and then reads the whole thing anyway —
    /// but a password that itself contained a newline could never be delivered.
    /// That is a limitation of `keepassxc-cli`, not of this code, and
    /// `containsNewline` exists so the caller can say so plainly instead of
    /// failing with "wrong password".
    func stdinLine() -> Data { Data((value + "\n").utf8) }

    /// A password with a line break in it cannot reach `keepassxc-cli` at all —
    /// it reads exactly one line. Detected up front so the message names the real
    /// problem.
    var containsNewline: Bool { value.contains(where: \.isNewline) }

    /// THE ONLY property that hands back the characters, and it exists for exactly
    /// one caller: the keychain write, which needs a `String`. `fileprivate` and
    /// deliberately clumsily named so that every use is greppable and there is one.
    fileprivate var charactersForKeychainWriteOnly: String { value }
}

// MARK: - Everything one unlock needs

/// The unlock factors for one database. Holds a secret (the password box) and is
/// therefore never persisted, never encoded and never described.
nonisolated struct KDBXUnlock: Sendable {
    var databasePath: String
    /// A key file, when the database has one. Its PATH is not a secret; its
    /// contents are, and we never read them — the tool does.
    var keyFilePath: String?
    /// Which security-key slot answers this database's challenge, or nil for a
    /// database that does not use one. Empty-means-none, so there is no separate
    /// switch to get out of step with the slot number.
    var slot: YubiKeySlot?
    /// Which key, when several are plugged in. Printed on the key; not a secret.
    var serial: String?
    /// nil = we have not got one. Empty = the database genuinely has no password.
    var password: KDBXPassword?

    /// Whether a security key is part of this database's key.
    var usesSecurityKey: Bool { slot != nil }

    /// The `slot[:serial]` form `keepassxc-cli --yubikey` takes (its own man page's
    /// syntax). Digits only for the serial — anything else is somebody's note to
    /// themselves and must not reach argv.
    var yubiKeyArgument: String? {
        guard let slot else { return nil }
        guard let serial = serial?.trimmingCharacters(in: .whitespaces),
              !serial.isEmpty, serial.allSatisfy(\.isNumber) else { return "\(slot.rawValue)" }
        return "\(slot.rawValue):\(serial)"
    }
}

// MARK: - Where the password is kept

/// The database password's lifetime, and the ONE place that decides it.
///
/// Three tiers, in the order they are consulted: this run's memory, then the Touch
/// ID keychain (which costs a fingerprint), then nothing — and "nothing" is a
/// state with a fix, not a failure.
@MainActor
@Observable
final class KDBXMasterPasswordStore {

    static let shared = KDBXMasterPasswordStore()

    private static let log = Logger(subsystem: "com.bragi0.SimpleVPN", category: "keepass-file")

    /// This run only. Keyed by database path, because the password belongs to the
    /// database rather than to a VPN.
    private var session: [String: KDBXPassword] = [:]

    /// Bumped whenever what is held changes, so an `@Observable` pane redraws. The
    /// passwords themselves are never published.
    private(set) var revision = 0

    init() {}

    /// The keychain account for a database. A SHA-256 of the path rather than the
    /// path itself: a keychain item's account is visible in Keychain Access and in
    /// any keychain dump, and "/Users/me/Documents/Personal Passwords.kdbx" is not
    /// something to publish there. Hashing keeps it per-database without naming it.
    static func account(forDatabase path: String) -> String {
        "kdbx:" + SHA256Hex.of(Data(path.utf8))
    }

    // MARK: This run's memory

    /// Hold it for this run of SimpleVPN. What "type it each time" really means on
    /// a Mac: once per launch, not once per connect, because a database password is
    /// long and connecting is frequent.
    func holdForThisRun(_ password: KDBXPassword, database path: String) {
        session[path] = password
        revision += 1
        Self.log.log("database password held for this run")
    }

    func isHeldForThisRun(database path: String) -> Bool { session[path] != nil }

    /// Drop it now — the user changed database, switched the vendor off, or asked.
    func forgetThisRun(database path: String) {
        guard session.removeValue(forKey: path) != nil else { return }
        revision += 1
    }

    func forgetEverythingHeldThisRun() {
        guard !session.isEmpty else { return }
        session.removeAll()
        revision += 1
    }

    // MARK: The Touch ID keychain

    /// Whether this Mac can ask for a fingerprint (or a watch, or the account
    /// password). Promising one on a Mac that cannot would be worse than not
    /// offering it.
    var canRemember: Bool { DeviceOwnerAuth.isAvailable }

    /// Is there a remembered password for this database? Answered WITHOUT a prompt:
    /// keychain attributes are not behind the access control, only the data is.
    func isRemembered(database path: String) -> Bool {
        BiometricCredentialStore.exists(profile: Self.account(forDatabase: path))
    }

    /// Remember it behind Touch ID. Writing needs no prompt; only reading does.
    func remember(_ password: KDBXPassword, database path: String) throws {
        // The password rides in the existing protected item's `password` field.
        // `username` is deliberately empty: a database has no username, and putting
        // the path there would defeat the point of hashing the account.
        try BiometricCredentialStore.save(
            profile: Self.account(forDatabase: path),
            .init(username: "", password: password.charactersForKeychainWriteOnly, totpSecret: nil))
        session[path] = password
        revision += 1
        Self.log.log("database password remembered behind Touch ID")
    }

    func forgetRemembered(database path: String) {
        BiometricCredentialStore.delete(profile: Self.account(forDatabase: path))
        revision += 1
    }

    // MARK: Getting it back

    /// The password for this database, or nil when nothing is held.
    ///
    /// Order matters: this run's memory first, so a user who has already typed it
    /// is not asked for a fingerprint on every connect; then the Touch ID item,
    /// which raises exactly ONE system prompt carrying `reason`. A cancelled prompt
    /// throws `CancellationError`, which the caller must distinguish from a wrong
    /// password — cancelling is not a failed sign-in.
    func password(database path: String, reason: String) async throws -> KDBXPassword? {
        if let held = session[path] { return held }
        guard isRemembered(database: path) else { return nil }
        let context = LAContext()
        do {
            try await context.evaluatePolicy(.deviceOwnerAuthentication, localizedReason: reason)
        } catch let error as LAError
                    where error.code == .userCancel || error.code == .appCancel
                        || error.code == .systemCancel {
            throw CancellationError()
        }
        let stored = try BiometricCredentialStore.load(
            profile: Self.account(forDatabase: path), context: context)
        let password = KDBXPassword(stored.password)
        // Cache for the rest of this run: the fingerprint has already been given,
        // and asking again for the same secret in the same session is friction
        // without a security benefit.
        session[path] = password
        return password
    }

    /// What is held, in words, for the settings row and for VoiceOver. Never says
    /// anything about the password itself beyond whether one is there.
    func heldDescription(database path: String) -> String {
        if isRemembered(database: path) {
            return "Remembered behind Touch ID. SimpleVPN asks macOS for it when you connect."
        }
        if isHeldForThisRun(database: path) {
            return "Held until SimpleVPN quits. You will be asked again next time you open it."
        }
        return "Not held. Type it here once and SimpleVPN can read your database."
    }
}

// MARK: - Checking the security key, on request

/// The outcome of asking a security key to answer this database's challenge.
/// Deliberately says what it does and does not prove.
nonisolated enum KDBXSecurityKeyCheckResult: Sendable, Equatable {
    /// The key answered. Twenty bytes came back and were discarded.
    case answered(slot: YubiKeySlot)
    /// The database's header carries no seed we could find, so there is no
    /// challenge to send. Nothing is wrong with the key.
    case noChallengeAvailable
    /// `ykman` isn't anywhere SimpleVPN will run from, so we cannot ask. The
    /// database can still be unlocked — `keepassxc-cli` talks to the key itself.
    case cannotAsk(reason: String)
    /// It ran and the key said no.
    case failed(reason: String)

    /// The sentence shown and spoken. Says what it proves, because "your key works"
    /// would be a bigger claim than the check can support.
    var sentence: String {
        switch self {
        case .answered(let slot):
            "Your security key answered on \(slot.displayName.lowercased()). That means the key is "
            + "here and the slot is set up. Whether its answer is the right one for this database is "
            + "something only unlocking can tell you."
        case .noChallengeAvailable:
            "SimpleVPN couldn\u{2019}t find the value to send to your key in this database\u{2019}s "
            + "header, so there is nothing to check. Your key may still work \u{2014} KeePassXC\u{2019}s "
            + "own tool talks to it directly when you connect."
        case .cannotAsk(let reason):
            "SimpleVPN can\u{2019}t check your key: \(reason) This doesn\u{2019}t stop the database "
            + "opening \u{2014} KeePassXC\u{2019}s own tool talks to your key itself."
        case .failed(let reason):
            "Your security key didn\u{2019}t answer: \(reason)"
        }
    }

    var succeeded: Bool { if case .answered = self { true } else { false } }
}

/// Ask the key, once, because the user asked us to.
///
/// NEVER CALLED DURING A CONNECT. `keepassxc-cli` performs its own
/// challenge-response as part of the unlock, and a slot programmed with `--touch`
/// wants a finger each time it is asked — so doing this as well would mean two
/// touches for one connect, and a wasted touch is precisely the kind of thing that
/// makes people stop using a feature. This is the settings pane's "check my key"
/// button and nothing else.
nonisolated enum KeePassSecurityKeyCheck {

    private static let log = Logger(subsystem: "com.bragi0.SimpleVPN", category: "keepass-file")

    /// Send `facts.kdfSeed` to the slot and report whether twenty bytes came back.
    ///
    /// The seed is the database's own `kdf.seed()`, stored in cleartext in the
    /// header, so passing it to `respond(toPublicChallenge:)` (which puts it in
    /// argv) is exactly what that API's name permits. `requiresTouch: true`
    /// unconditionally: we cannot tell whether a slot wants a finger, and the cost
    /// of guessing wrong is a "timed out" message while the user is still reaching
    /// for their key.
    static func run(facts: KDBXHeaderFacts, slot: YubiKeySlot, serial: String?,
                    tool: YubiKeyManagerTool = YubiKeyManagerTool()) async
        -> KDBXSecurityKeyCheckResult {
        guard let seed = facts.kdfSeed, !seed.isEmpty else { return .noChallengeAvailable }
        guard tool.isInstalled else {
            return .cannotAsk(reason: "YubiKey\u{2019}s own tool (ykman) isn\u{2019}t installed "
                              + "anywhere SimpleVPN will run it from.")
        }
        let responder = YubiKeyChallengeResponse(slot: slot, serial: serial, tool: tool)
        do {
            // The padding is `YubiKeyChallengeResponse`'s own `.keePassPKCS7To64`,
            // matched to KeePassXC's scheme. Nothing about it is repeated here.
            let material = try await responder.keyMaterial(for: seed, requiresTouch: true)
            // KEY MATERIAL. Its length is the only thing that leaves this scope.
            guard material.count == YubiKeyChallengeResponse.responseLength else {
                return .failed(reason: "it sent back something SimpleVPN couldn\u{2019}t read.")
            }
            Self.log.log("security key answered the database challenge")
            return .answered(slot: slot)
        } catch let error as YubiKeyToolError {
            return .failed(reason: error.errorDescription ?? "it didn\u{2019}t answer.")
        } catch {
            return .failed(reason: "it didn\u{2019}t answer.")
        }
    }
}

// MARK: - A hash, so a database path never becomes a keychain label

/// SHA-256 as hex. The value is a NAME rather than a security boundary — the point
/// is not to publish somebody's file path in Keychain Access, not to resist an
/// attacker who already has both.
nonisolated enum SHA256Hex {
    static func of(_ data: Data) -> String {
        SHA256.hash(data: data).map { String(format: "%02x", $0) }.joined()
    }
}
