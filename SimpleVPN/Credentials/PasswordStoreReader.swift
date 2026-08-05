// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
//  PasswordStoreReader.swift
//  Reading a sign-in out of a `pass` / `gopass` store — the GPG-backed "standard
//  unix password manager".
//
//  WHY WE DECRYPT WITH `gpg` AND NOT `pass show`. Four reasons, in order of weight:
//
//   1. `gpg` is far more likely to be there. On the machine this was written on,
//      `gpg` is installed and `pass` is not — which is the common case, because gpg
//      arrives with a dozen other things and `pass` is a deliberate choice. Going
//      through the CLI would make the feature unavailable to people whose store we
//      can read perfectly well.
//   2. The store layout is a documented, stable format; a CLI's output is not.
//      `~/.password-store/<path>.gpg`, first line the password, `key: value` lines
//      after. That has been stable for over a decade. `pass show`'s formatting,
//      colouring and extension behaviour are not a contract.
//   3. `pass` is a shell script wrapping `gpg -d`. Invoking it buys a shell, a
//      PATH-dependent `getopt`, and its own tempfile handling, in exchange for
//      nothing we need.
//   4. It keeps us away from `pass show -c`, which puts the password on the
//      pasteboard where every app on the Mac can read it. A VPN password must never
//      go there, and the safest way not to call it is not to call `pass` at all.
//
//  `pass` and `gopass` are still DETECTED — they are how we recognise a store the
//  user actually uses, and their presence is worth reporting — but neither is
//  required to read one.
//
//  THE HANG THIS FILE EXISTS TO PREVENT. GPG asks for a passphrase through
//  `gpg-agent`, which asks through a *pinentry*. On a Mac with no GUI pinentry
//  installed, that falls to a curses pinentry which cannot draw anywhere a windowed
//  app can see — so the process waits for input that can never arrive. Forever, with
//  no prompt and no error. That is not a hypothetical: `pinentry-mac` is absent on
//  the machine this was written on, which is the default state for anyone who
//  installed gpg without going looking.
//
//  So there are two modes, and both are bounded:
//
//   • A usable GUI pinentry exists → run normally, let the agent prompt, with a hard
//     deadline. This is the good path and the one that can unlock a fresh key.
//   • No usable GUI pinentry → `--pinentry-mode error`. gpg then FAILS INSTANTLY
//     rather than trying to prompt. It still succeeds when the passphrase is already
//     cached in the agent (the common case for someone who has used their key this
//     session), and when it isn't we say exactly what to install instead of hanging.
//
//  Never remove `--batch`. Without it gpg may try to interact on paths that have
//  nothing to do with pinentry, and interaction is the one thing we cannot survive.
//

import Foundation

// MARK: - Where a store lives, and what one entry looks like

/// A configured store. LEVEL 2 in the three-level model (SignInSourceInstances.swift):
/// the directory is *which vault*, not *how we reach it*, and `PASSWORD_STORE_DIR`
/// exists precisely because one person legitimately has several ("work", "personal").
nonisolated struct PasswordStoreLocation: Sendable, Equatable {
    /// Absolute path to the store's root directory.
    var directory: String

    /// The default, matching `pass`'s own: `~/.password-store`.
    static func `default`(home: URL = FileManager.default.homeDirectoryForCurrentUser) -> PasswordStoreLocation {
        PasswordStoreLocation(directory: home.appendingPathComponent(".password-store").path)
    }

    /// The file an entry name resolves to. Entry names are store-relative paths
    /// without the extension, exactly as `pass` prints them (`vpn/work`).
    ///
    /// Refuses anything that would climb out of the store. An entry name comes from
    /// the profile's stored reference, and while that is the user's own text, a
    /// reference that resolves to `/etc/...` is a bug worth making impossible rather
    /// than a threat worth arguing about.
    func file(forEntry entry: String) -> String? {
        let trimmed = entry.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty, !trimmed.hasPrefix("/") else { return nil }
        let parts = trimmed.split(separator: "/", omittingEmptySubsequences: true)
        guard !parts.isEmpty, !parts.contains("..") , !parts.contains(".") else { return nil }
        let rel = parts.joined(separator: "/")
        return (directory as NSString).appendingPathComponent(rel + ".gpg")
    }

    /// `pass` marks a real store with `.gpg-id` (the key(s) it encrypts to). Its
    /// absence is how we tell "you pointed at the wrong folder" apart from "your
    /// store is empty", which need different sentences.
    var gpgIDFile: String { (directory as NSString).appendingPathComponent(".gpg-id") }
}

/// The parsed contents of one decrypted entry.
///
/// The layout is a CONVENTION, not a format: `pass` itself only guarantees that the
/// file is GPG-encrypted text, and by long habit the first line is the password with
/// `key: value` metadata after it. Nothing enforces that, so this parser is tolerant
/// and the UI says plainly that the username comes from a convention.
nonisolated struct PasswordStoreEntry: Sendable, Equatable {
    var password: String
    /// Every `key: value` line after the first, keys lower-cased for matching.
    var fields: [String: String]

    /// The field names people actually use for a login, most common first. A user
    /// who uses something else can name it (see `PasswordStoreSettings`).
    static let conventionalUsernameKeys = ["login", "username", "user", "email"]

    func username(preferring key: String?) -> String? {
        if let key, !key.isEmpty, let v = fields[key.lowercased()], !v.isEmpty { return v }
        for k in Self.conventionalUsernameKeys {
            if let v = fields[k], !v.isEmpty { return v }
        }
        return nil
    }

    /// A TOTP secret, when the entry carries one in the `pass-otp` convention (an
    /// `otpauth://` URI on its own line or as a field value).
    var otpauthURI: String? {
        for (_, v) in fields where v.lowercased().hasPrefix("otpauth://") { return v }
        return bareOTPAuthLine
    }

    /// `pass-otp` writes the URI as a bare line, which has no `key:` and so never
    /// reaches `fields`. Kept separately by the parser.
    var bareOTPAuthLine: String?

    /// Parse decrypted plaintext. The first line is the password even when it looks
    /// like a `key: value` pair — that is what every `pass` client does, and second-
    /// guessing it would silently return metadata as somebody's password.
    static func parse(_ text: String) -> PasswordStoreEntry {
        // Split on newlines without dropping information: an entry whose password
        // contains no trailing newline and an entry that does are the same entry.
        var lines = text.components(separatedBy: .newlines)
        let password = lines.isEmpty ? "" : lines.removeFirst()
        var fields: [String: String] = [:]
        var bareOTP: String?
        for line in lines {
            let t = line.trimmingCharacters(in: .whitespaces)
            if t.isEmpty { continue }
            if t.lowercased().hasPrefix("otpauth://") { bareOTP = bareOTP ?? t; continue }
            // `key: value`. Only the FIRST colon splits, so a URL in a value survives.
            guard let colon = t.firstIndex(of: ":") else { continue }
            let key = String(t[t.startIndex..<colon]).trimmingCharacters(in: .whitespaces).lowercased()
            let value = String(t[t.index(after: colon)...]).trimmingCharacters(in: .whitespaces)
            guard !key.isEmpty, !key.contains(" "), !value.isEmpty else { continue }
            if fields[key] == nil { fields[key] = value }   // first wins, like pass
        }
        return PasswordStoreEntry(password: password, fields: fields, bareOTPAuthLine: bareOTP)
    }
}

// MARK: - Whether GPG can answer without hanging

/// Whether a passphrase prompt can actually reach the user. See the file header:
/// this is the difference between a bounded failure and an invisible infinite wait.
nonisolated enum PinentryAvailability: Sendable, Equatable {
    /// A GUI pinentry we can name. gpg may prompt; we allow it, with a deadline.
    case graphical(program: String)
    /// No GUI pinentry found. We must run `--pinentry-mode error`: a cached
    /// passphrase still works, an uncached one fails immediately and says why.
    case noneUsable

    var allowsPrompting: Bool {
        switch self {
        case .graphical: true
        case .noneUsable: false
        }
    }
}

nonisolated enum PinentryProbe: Sendable {
    /// GUI pinentries shipped for macOS, in the order we would rather have them.
    /// `pinentry-mac` is what Homebrew's `pinentry-mac` formula installs and what
    /// virtually every macOS gpg guide tells people to use.
    static let graphicalProgramNames = ["pinentry-mac", "pinentry-touchid", "pinentry-qt", "pinentry-gtk-2"]

    /// Read `gpg-agent.conf` for an explicit `pinentry-program`, then fall back to
    /// looking for a known GUI pinentry on disk.
    ///
    /// Deliberately a FILE READ and a `stat`, never an execution: this runs on the
    /// cheap availability path, and spawning here would make every settings refresh
    /// start processes.
    static func detect(home: URL = FileManager.default.homeDirectoryForCurrentUser,
                       fileManager: FileManager = .default) -> PinentryAvailability {
        let conf = home.appendingPathComponent(".gnupg/gpg-agent.conf").path
        if let text = try? String(contentsOfFile: conf, encoding: .utf8) {
            for line in text.components(separatedBy: .newlines) {
                let t = line.trimmingCharacters(in: .whitespaces)
                guard !t.hasPrefix("#"), t.lowercased().hasPrefix("pinentry-program") else { continue }
                let path = t.dropFirst("pinentry-program".count).trimmingCharacters(in: .whitespaces)
                // An explicitly configured pinentry that does NOT exist is worse than
                // none: gpg-agent fails in a way that reads like a broken keyring. So
                // it only counts when the file is really there.
                if !path.isEmpty, fileManager.isExecutableFile(atPath: path) {
                    return .graphical(program: path)
                }
            }
        }
        for name in graphicalProgramNames {
            if let found = LocalToolRunner.locate(name) { return .graphical(program: found) }
        }
        return .noneUsable
    }
}

// MARK: - The reader

nonisolated enum PasswordStoreError: LocalizedError, Equatable {
    case gpgMissing
    case entryMissing(String)
    case needsPassphraseButNoPinentry
    case decryptFailed(String)
    case timedOut
    case notAStore

    var errorDescription: String? {
        switch self {
        case .gpgMissing:
            "GnuPG isn\u{2019}t installed where SimpleVPN can run it, so it can\u{2019}t decrypt your password store."
        case .entryMissing(let name):
            "There\u{2019}s no entry called \u{201C}\(name)\u{201D} in your password store."
        case .needsPassphraseButNoPinentry:
            // The sentence a user can act on. Naming the two config lines matters:
            // "install pinentry-mac" alone leaves them with gpg still not using it.
            "Your GPG key needs its passphrase, but there\u{2019}s no way to ask for it: "
            + "no graphical pinentry is installed. Install one with \u{201C}brew install pinentry-mac\u{201D}, "
            + "add \u{201C}pinentry-program /opt/homebrew/bin/pinentry-mac\u{201D} to ~/.gnupg/gpg-agent.conf, "
            + "then run \u{201C}gpgconf --kill gpg-agent\u{201D}. Until then SimpleVPN can only read your store "
            + "while your passphrase is still remembered by the GPG agent."
        case .decryptFailed(let detail):
            detail.isEmpty ? "GnuPG couldn\u{2019}t decrypt that entry." : "GnuPG couldn\u{2019}t decrypt that entry: \(detail)"
        case .timedOut:
            "GnuPG didn\u{2019}t answer in time. If a passphrase window is waiting somewhere, answer it and try again."
        case .notAStore:
            "That folder isn\u{2019}t a password store \u{2014} SimpleVPN couldn\u{2019}t find a .gpg-id file in it."
        }
    }
}

/// The process boundary, injectable so every path above is testable on a machine
/// with no store, no key and no agent.
nonisolated protocol PasswordStoreDecrypting: Sendable {
    func decrypt(file: String, allowPrompting: Bool) async -> LocalToolResult
    func gpgIsAvailable() -> Bool
}

nonisolated struct GPGDecrypter: PasswordStoreDecrypting {
    /// gpg2 is the same program under an older name; some installs only have that.
    static let toolNames = ["gpg", "gpg2"]

    func gpgIsAvailable() -> Bool { Self.toolNames.contains { LocalToolRunner.locate($0) != nil } }

    func decrypt(file: String, allowPrompting: Bool) async -> LocalToolResult {
        guard let exe = Self.toolNames.compactMap({ LocalToolRunner.locate($0) }).first else {
            return LocalToolResult(exitCode: -1, stdout: Data(),
                                   stderr: "gpg not found in an approved location", timedOut: false)
        }
        var args = ["--batch", "--yes", "--quiet", "--decrypt"]
        if !allowPrompting {
            // The load-bearing flag. Fail instead of trying to prompt through a
            // pinentry that cannot draw. A cached passphrase still succeeds.
            args += ["--pinentry-mode", "error"]
        }
        args.append(file)
        // A deadline in BOTH modes. With a graphical pinentry the user may genuinely
        // need a moment to type, so it is generous; without one, gpg returns at once
        // and the number is irrelevant. It is never absent, because the whole point of
        // this file is that no path waits forever.
        return await LocalToolRunner.run(executable: exe, arguments: args,
                                        deadline: allowPrompting ? 90 : 12)
    }
}

/// Filesystem questions, as closures rather than a `FileManager` — which is not
/// `Sendable` and so cannot be stored in a `Sendable` struct. It also happens to be
/// the better seam: a test can present a whole store layout without touching disk.
nonisolated struct PasswordStoreFileProbe: Sendable {
    var fileExists: @Sendable (String) -> Bool = { FileManager.default.fileExists(atPath: $0) }
    var directoryExists: @Sendable (String) -> Bool = {
        var isDir: ObjCBool = false
        let there = FileManager.default.fileExists(atPath: $0, isDirectory: &isDir)
        return there && isDir.boolValue
    }
}

nonisolated struct PasswordStoreReader: Sendable {
    var location: PasswordStoreLocation
    var decrypter: any PasswordStoreDecrypting = GPGDecrypter()
    var pinentry: PinentryAvailability = PinentryProbe.detect()
    var files = PasswordStoreFileProbe()

    /// Read and parse one entry.
    func read(entry: String) async throws -> PasswordStoreEntry {
        guard decrypter.gpgIsAvailable() else { throw PasswordStoreError.gpgMissing }
        guard let file = location.file(forEntry: entry) else {
            throw PasswordStoreError.entryMissing(entry)
        }
        guard files.fileExists(file) else {
            throw PasswordStoreError.entryMissing(entry)
        }
        let result = await decrypter.decrypt(file: file, allowPrompting: pinentry.allowsPrompting)
        if result.timedOut { throw PasswordStoreError.timedOut }
        guard result.succeeded else {
            // With `--pinentry-mode error` gpg says so in its own words; translate it
            // into the one sentence that tells the user what to install, because
            // "No pinentry" means nothing to somebody who has never configured gpg.
            let lower = result.stderr.lowercased()
            if !pinentry.allowsPrompting,
               lower.contains("pinentry") || lower.contains("no passphrase")
                || lower.contains("cancel") || lower.contains("bad passphrase") {
                throw PasswordStoreError.needsPassphraseButNoPinentry
            }
            throw PasswordStoreError.decryptFailed(result.stderr)
        }
        // stdout is the SECRET. It is decoded here and never logged, never quoted in
        // an error, never returned as part of a diagnostic.
        let text = String(decoding: result.stdout, as: UTF8.self)
        return PasswordStoreEntry.parse(text)
    }

    /// Cheap, prompt-free, no subprocesses — safe on every settings refresh.
    func storeState() -> PasswordStoreState {
        guard files.directoryExists(location.directory) else { return .directoryMissing }
        guard files.fileExists(location.gpgIDFile) else { return .notAStore }
        if !decrypter.gpgIsAvailable() { return .gpgMissing }
        if !pinentry.allowsPrompting { return .readyOnlyWhileAgentRemembers }
        return .ready
    }
}

/// What the cheap probe can establish without decrypting anything.
nonisolated enum PasswordStoreState: Sendable, Equatable {
    case ready
    /// Everything is present, but an uncached passphrase cannot be asked for. Not a
    /// failure — a great many people have their passphrase cached all day — so it is
    /// offered with the caveat rather than blocked.
    case readyOnlyWhileAgentRemembers
    case directoryMissing
    case notAStore
    case gpgMissing
}
