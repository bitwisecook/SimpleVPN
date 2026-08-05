// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
//  PassboltUnlock.swift
//  The OpenPGP key passphrase that opens a Passbolt server, and where it may live.
//
//  ─── WHY THIS FILE EXISTS AT ALL ───────────────────────────────────────────
//  The first version of this feed held NOTHING and told people to put their
//  passphrase into `go-passbolt-cli`'s own config file with
//  `passbolt configure --userPassword`. That works, and it is what somebody running
//  the tool from a script would do — which is exactly what was wrong with it. This
//  is a VPN client on a person's laptop, not server infrastructure. A long-lived
//  passphrase sitting at rest in a plaintext file is the shape an operator
//  provisions for an unattended job; the shape a person on a Mac recognises is a
//  Touch ID sheet, or typing it once when they open the app.
//
//  So the tiers below are the `.kdbx` source's, deliberately and for the same
//  reasons (KeePassUnlock.swift states them at length):
//
//   1. DEFAULT: NOWHERE. Typed once per run of SimpleVPN, held in memory, gone when
//      the app quits. Once per LAUNCH rather than once per connect, because a
//      passphrase is long and connecting is frequent.
//   2. OPT-IN: THE TOUCH ID KEYCHAIN, AND ONLY THAT ONE. Never the ordinary
//      keychain, which would let this app open somebody's whole Passbolt silently
//      any time it liked. `.userPresence` means macOS will not release it without a
//      fingerprint, an Apple Watch or the account password — a bar a background
//      process cannot clear on its own.
//   3. ALREADY IN PASSBOLT'S OWN FILE: honoured, not recommended. Plenty of people
//      have set the tool up that way and breaking their working setup to make a
//      point would be worse than the point. SimpleVPN simply needs nothing from
//      them, and never reads the value — it only notices that a `userpassword` key
//      is present. See `PassboltToolConfig`.
//   4. NEVER an environment variable, never argv, never `providerConfiguration`,
//      never a defaults key, never a log line. It reaches the tool on stdin and by
//      no other route.
//
//  Kept per SERVER, not per VPN: it is the key's passphrase, and five VPNs reading
//  one Passbolt must not mean five copies of it.
//
//  ─── THE ONE THING THIS PASSPHRASE IS NOT ──────────────────────────────────
//  It is not a machine identity. There is no service account here, no long-lived
//  token to provision, and no path designed to work while nobody is logged in. If
//  nothing is held and Passbolt's own program has nothing either, the source is
//  visibly dormant and says so — which is the honest answer for a laptop, and a
//  better one than a headless route nobody asked for.
//

import Foundation
import LocalAuthentication
import os

// MARK: - The passphrase, boxed

/// A Passbolt key's passphrase, held so it cannot leak by accident.
///
/// The same box as `KDBXPassword` and for the same reasons: no `Codable`, no
/// `description`, no `debugDescription`, and no getter that hands back a `String`.
/// The only way out is `stdinLine()`. A separate type rather than a shared one
/// because `KDBXPassword`'s keychain accessor is `fileprivate` — which is the point
/// of it — and because the two have genuinely different newline rules.
///
/// It is NOT secure memory. Swift `String` storage is neither locked nor zeroed, and
/// a box claiming otherwise would be worse than one that does not.
nonisolated final class PassboltPassphrase: Sendable {

    private let value: String

    init(_ value: String) { self.value = value }

    var isEmpty: Bool { value.isEmpty }

    /// How long it is, for a field that shows the right number of dots. A length is
    /// not the secret.
    var characterCount: Int { value.count }

    /// The bytes to write to the tool's standard input.
    ///
    /// THE TRAILING NEWLINE IS REQUIRED, and it is not cosmetic: the tool reads with
    /// `bufio.Reader.ReadString('\n')` (`util.ReadPassword` in
    /// `internal/util/client.go`), which returns an error at EOF if it never sees
    /// one — so a passphrase written without it comes back as a read failure, which
    /// reads to a user as "wrong passphrase".
    func stdinLine() -> Data { Data((value + "\n").utf8) }

    /// A passphrase with a line break in it cannot reach the tool at all: it reads
    /// exactly one line, and `strings.Replace(pass, "\n", "", 1)` then removes the
    /// first newline it finds. That is a limitation of `go-passbolt-cli`, not of this
    /// code, and it is detected up front so the message names the real problem
    /// instead of reporting a rejected sign-in.
    var containsNewline: Bool { value.contains(where: \.isNewline) }

    /// THE ONLY property that hands back the characters. It exists for exactly two
    /// callers — the keychain write, which needs a `String`, and the stdin write
    /// above. Deliberately clumsily named so every use is greppable and there are
    /// no others.
    fileprivate var charactersForKeychainWriteOnly: String { value }
}

// MARK: - Where it is kept

/// The passphrase's lifetime, and the ONE place that decides it. Three tiers, in
/// the order they are consulted: this run's memory, then the Touch ID keychain
/// (which costs a fingerprint), then nothing — and "nothing" is a state with a fix,
/// not a failure.
///
/// Deliberately NOT a generalisation of `KDBXMasterPasswordStore`. The two are the
/// same shape today, and merging them would mean one type keyed by "a string that
/// might be a file path or might be a server address", whose keychain account
/// namespace then has to be a parameter. Two small stores with one prefix each is
/// clearer than one store with a mode, and the day a third vendor needs this the
/// abstraction can be taken from three real examples rather than guessed from two.
@MainActor
@Observable
final class PassboltPassphraseStore {

    static let shared = PassboltPassphraseStore()

    private static let log = Logger(subsystem: "com.bragi0.SimpleVPN", category: "passbolt")

    /// This run only. Keyed by SERVER ADDRESS, because the passphrase belongs to the
    /// key that opens that server rather than to a VPN.
    private var session: [String: PassboltPassphrase] = [:]

    /// Bumped whenever what is held changes, so an `@Observable` pane redraws. The
    /// passphrases themselves are never published.
    private(set) var revision = 0

    init() {}

    /// The keychain account for a server. A SHA-256 of the address rather than the
    /// address itself: a keychain item's account is visible in Keychain Access and
    /// in any keychain dump, and "https://passbolt.acme-internal.example" names an
    /// employer. Hashing keeps it per-server without publishing which server.
    static func account(forServer address: String) -> String {
        "passbolt:" + SHA256Hex.of(Data(normalize(address).utf8))
    }

    /// One spelling per server, so `https://x.example.com` and
    /// `https://x.example.com/` are the same server rather than two — otherwise a
    /// trailing slash typed later silently loses a remembered passphrase.
    static func normalize(_ address: String) -> String {
        var trimmed = address.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        while trimmed.hasSuffix("/") { trimmed.removeLast() }
        return trimmed
    }

    // MARK: This run's memory

    /// Hold it for this run of SimpleVPN. What "type it each time" really means on a
    /// Mac: once per launch, not once per connect.
    func holdForThisRun(_ passphrase: PassboltPassphrase, server address: String) {
        session[Self.normalize(address)] = passphrase
        revision += 1
        Self.log.log("Passbolt passphrase held for this run")
    }

    func isHeldForThisRun(server address: String) -> Bool {
        session[Self.normalize(address)] != nil
    }

    func forgetThisRun(server address: String) {
        guard session.removeValue(forKey: Self.normalize(address)) != nil else { return }
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

    /// Is there a remembered passphrase for this server? Answered WITHOUT a prompt:
    /// keychain attributes are not behind the access control, only the data is.
    func isRemembered(server address: String) -> Bool {
        guard !Self.normalize(address).isEmpty else { return false }
        return BiometricCredentialStore.exists(profile: Self.account(forServer: address))
    }

    /// Remember it behind Touch ID. Writing needs no prompt; only reading does.
    func remember(_ passphrase: PassboltPassphrase, server address: String) throws {
        try BiometricCredentialStore.save(
            profile: Self.account(forServer: address),
            .init(username: "", password: passphrase.charactersForKeychainWriteOnly,
                  totpSecret: nil))
        session[Self.normalize(address)] = passphrase
        revision += 1
        Self.log.log("Passbolt passphrase remembered behind Touch ID")
    }

    func forgetRemembered(server address: String) {
        BiometricCredentialStore.delete(profile: Self.account(forServer: address))
        revision += 1
    }

    // MARK: Getting it back

    /// WITHOUT ASKING ANYTHING. True when a fetch could get a passphrase — either it
    /// is already in memory, or it is remembered and a fingerprint would release it.
    /// This is what the cheap availability path uses: a probe must never raise a
    /// Touch ID sheet, because an unexplained sheet from a background refresh is
    /// exactly the thing that teaches people to click through them.
    func couldSupply(server address: String) -> Bool {
        isHeldForThisRun(server: address) || isRemembered(server: address)
    }

    /// The passphrase for this server, or nil when nothing is held.
    ///
    /// Order matters: this run's memory first, so somebody who has already typed it
    /// is not asked for a fingerprint on every connect; then the Touch ID item,
    /// which raises exactly ONE system prompt carrying `reason`. A cancelled prompt
    /// throws `CancellationError`, which the caller must tell apart from a rejected
    /// sign-in — cancelling is not a wrong passphrase, and treating it as one would
    /// spend somebody's server-side lockout budget on a decision they made.
    func passphrase(server address: String, reason: String) async throws -> PassboltPassphrase? {
        let key = Self.normalize(address)
        guard !key.isEmpty else { return nil }
        if let held = session[key] { return held }
        guard isRemembered(server: address) else { return nil }
        let context = LAContext()
        do {
            try await context.evaluatePolicy(.deviceOwnerAuthentication, localizedReason: reason)
        } catch let error as LAError
                    where error.code == .userCancel || error.code == .appCancel
                        || error.code == .systemCancel {
            throw CancellationError()
        }
        let stored = try BiometricCredentialStore.load(
            profile: Self.account(forServer: address), context: context)
        let passphrase = PassboltPassphrase(stored.password)
        // Cache for the rest of this run: the fingerprint has already been given, and
        // asking again for the same secret in the same session is friction with no
        // security benefit.
        session[key] = passphrase
        return passphrase
    }

    /// What is held, in words, for the settings row and for VoiceOver. Never says
    /// anything about the passphrase itself beyond whether one is there.
    ///
    /// `toolHasItsOwn` is the third tier: when Passbolt's own program already has a
    /// passphrase, SimpleVPN needs nothing and must not imply otherwise — but it also
    /// says, once, that a Touch ID sheet is the better place for it on a Mac.
    func heldDescription(server address: String, toolHasItsOwn: Bool) -> String {
        if isRemembered(server: address) {
            return "Remembered behind Touch ID. SimpleVPN asks macOS for it when you connect."
        }
        if isHeldForThisRun(server: address) {
            return "Held until SimpleVPN quits. You will be asked again next time you open it."
        }
        if toolHasItsOwn {
            return "Not held here \u{2014} Passbolt\u{2019}s own program already has one, so "
                + "SimpleVPN doesn\u{2019}t need it. Typing it here instead keeps it out of that "
                + "file and behind Touch ID."
        }
        return "Not held. Type it here once and SimpleVPN can read your server."
    }
}
