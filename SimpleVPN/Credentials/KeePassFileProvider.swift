// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
//  KeePassFileProvider.swift
//  Reading a sign-in out of a KeePass `.kdbx` FILE the user points SimpleVPN at —
//  the app-independent route, and therefore the one that serves KeePassXC,
//  **Strongbox** and **KeePassium** with a single adapter. All three store the same
//  format and none of them needs a vendor API for this: the database is the API.
//
//  THE EXISTING KEEPASSXC SOCKET PATH IS UNCHANGED AND STAYS PREFERRED. A running
//  KeePassXC owns its own unlock, asks the user to allow us once, and never lets a
//  database password near this app. That is strictly better, and it remains its own
//  vendor row (`KeePassXCVaultAdapter`, `.appSocket`). This row is for the people
//  that path cannot serve: a Strongbox or KeePassium user, someone whose KeePassXC
//  is closed, someone who keeps a database on a share and no KeePass app at all.
//
//  ─── WHY `keepassxc-cli` AND NOT OUR OWN KDBX READER ───────────────────────
//  The alternative was implementing the format: AES-KDF and Argon2d/Argon2id key
//  derivation, HMAC-SHA-256 block authentication, AES-256-CBC or ChaCha20
//  decryption, gzip, an inner random stream (Salsa20 or ChaCha20) protecting each
//  password, and the XML. The standing rule is that this project bundles no
//  third-party runtime or library, so that would mean WRITING all of it. Against:
//
//   • It is a decryption path for somebody's entire password vault. A bug in it is
//     not a broken VPN, it is a wrong answer about a secret — and the well-known
//     kdbx CVEs are exactly here (header-authentication bypasses, malleable
//     KDBX3.1 padding). Being the only implementation of a security-critical
//     format in the tree, with no second implementation to differentially test
//     against, is the worst possible place to be original.
//   • Argon2 is not in CryptoKit or CommonCrypto. We would be writing that too.
//   • `keepassxc-cli` is already there. It ships INSIDE the app bundle at
//     `/Applications/KeePassXC.app/Contents/MacOS/keepassxc-cli`, and the Homebrew
//     cask additionally symlinks it into the Homebrew bin directory — so for most
//     of the audience "the app is installed" already means "the tool is available",
//     which `ToolDiscovery` knows (`bundledCLIs`).
//   • It is the reference implementation of the thing being read, maintained by the
//     people who define the format, and it already handles every KDF, cipher and
//     version including the ones nobody has written yet.
//
//  The cost is the one thing we had to solve rather than accept: the database
//  password must reach the tool. It goes on STDIN and by no other route —
//  `LocalToolRunner.run(stdin:)`, which is why that parameter exists. Argv is
//  world-readable through `ps`, so what rides argv is only the database path, the
//  key-file path, the entry path and a slot number: names, not secrets.
//
//  What we DO read ourselves is the plaintext outer header
//  (`KeePassDatabaseFile.swift`) — no crypto, and it is what lets "this isn't a
//  KeePass database", "this is newer than the tool can read" and "iCloud hasn't
//  downloaded it" be their own sentences instead of all three arriving as *wrong
//  password*.
//
//  ─── READ-ONLY, ALWAYS ─────────────────────────────────────────────────────
//  Every invocation is a `show`. Nothing here can write: no `add`, no `edit`, no
//  `import`, no `db-create`, and the allow-list of subcommands is asserted by a
//  test. A corrupted vault is unrecoverable and it is not our file. The tool is
//  never told to convert a KeePass 1 database either, even though it can — that is
//  a one-way migration of somebody's data and it is not ours to start.
//
//  ─── SECRETS DISCIPLINE ────────────────────────────────────────────────────
//   • The database password: stdin only. Never argv, never a log line, never an
//     error string, never `providerConfiguration`, never a defaults key. See
//     KeePassUnlock.swift for where it may be KEPT (nowhere by default; the Touch
//     ID keychain by opt-in, and never the ordinary keychain).
//   • The entry's password: `stdout` only, straight into `RawCredentials`. The
//     runner keeps `stdout` and `stderr` apart precisely so an error may quote one
//     and never the other.
//   • Nothing is cached. Every connect asks the database again, so changing a
//     password in the vault takes effect immediately.
//

import Foundation
import AppKit
import os

// MARK: - What one entry gives us

/// The two things a sign-in needs, lifted out of one database entry. Never logged,
/// never described in an error.
nonisolated struct KeePassFileEntry: Sendable, Equatable {
    var username: String?
    var password: String?
}

// MARK: - Failures

/// Why a read failed, in the shape the user needs rather than the shape the tool
/// reported. Each case is a different action, which is the whole reason they are
/// separate cases: "wrong password" and "iCloud hasn't finished" are not the same
/// sentence and only one of them involves retyping anything.
nonisolated enum KeePassFileError: LocalizedError, Equatable {
    case noDatabaseChosen
    case databaseMissing(String)
    case databaseNotDownloaded(String)
    /// macOS will not let SimpleVPN read the file. Its own state because the fix is
    /// a permission, not a password and not a path.
    case databaseNotReadable(String)
    case notAKeePassDatabase(KDBXFileState.NotADatabaseReason)
    case databaseTooNew(String)
    case toolMissing
    case noEntryChosen
    case entryNotFound(String)
    case entryHasNoPassword(String)
    case needsDatabasePassword
    /// The password contains a line break, which `keepassxc-cli` cannot be given.
    case passwordHasLineBreak
    /// The unlock was refused. `factors` names every factor that is configured, so
    /// the message can list the real possibilities instead of blaming the password.
    case unlockRefused(factors: [String])
    /// The security key was asked and did not answer.
    case securityKeyDidNotAnswer
    case keyFileUnreadable(String)
    case timedOut
    /// It failed in a way we could not classify. `detail` is already scrubbed and
    /// truncated by the runner and is stderr only.
    case unreadable(String)

    var errorDescription: String? {
        switch self {
        case .noDatabaseChosen:
            "No KeePass database is chosen yet. Pick your .kdbx file in Settings \u{25B8} "
            + "Sign-In Sources."
        case .databaseMissing(let path):
            "SimpleVPN couldn\u{2019}t find your KeePass database at \(path). If you moved it, point "
            + "SimpleVPN at its new place in Settings \u{25B8} Sign-In Sources."
        case .databaseNotDownloaded(let path):
            "Your KeePass database at \(path) hasn\u{2019}t been downloaded to this Mac yet. Open the "
            + "folder in the Finder and wait for it to finish, then try again."
        case .databaseNotReadable(let path):
            "macOS won\u{2019}t let SimpleVPN read your KeePass database at \(path). If it is in your "
            + "Desktop, Documents, Downloads or iCloud Drive folder, macOS asks your permission once "
            + "per app \u{2014} allow SimpleVPN in System Settings \u{25B8} Privacy & Security "
            + "\u{25B8} Files and Folders, or move the database somewhere else."
        case .notAKeePassDatabase(let reason):
            reason.sentence
        case .databaseTooNew(let version):
            "Your KeePass database is version \(version), which is newer than the KeePassXC on this "
            + "Mac can read. Update KeePassXC."
        case .toolMissing:
            "SimpleVPN needs KeePassXC\u{2019}s command-line tool to read a database file, and "
            + "can\u{2019}t find it. Installing KeePassXC provides it."
        case .noEntryChosen:
            "No entry is set for this VPN \u{2014} add the entry\u{2019}s path in your database, for "
            + "example \u{201C}VPN/Work\u{201D}."
        case .entryNotFound(let path):
            "There\u{2019}s no entry at \u{201C}\(path)\u{201D} in your database. Check the name and "
            + "the group it is in \u{2014} an entry\u{2019}s path is its groups and its title, "
            + "separated by slashes."
        case .entryHasNoPassword(let path):
            "The entry \u{201C}\(path)\u{201D} has no password in it."
        case .needsDatabasePassword:
            "SimpleVPN needs your KeePass database\u{2019}s password before it can read it. Type it in "
            + "Settings \u{25B8} Sign-In Sources."
        case .passwordHasLineBreak:
            "KeePassXC\u{2019}s command-line tool can\u{2019}t be given a database password that "
            + "contains a line break. Use the KeePassXC app for this database instead."
        case .unlockRefused(let factors):
            factors.isEmpty
                ? "Your KeePass database wouldn\u{2019}t open. Check the database password."
                : "Your KeePass database wouldn\u{2019}t open. It could be "
                  + factors.joined(separator: ", or ") + "."
        case .securityKeyDidNotAnswer:
            "Your security key didn\u{2019}t answer. Plug it in, and touch it when it flashes."
        case .keyFileUnreadable(let path):
            "SimpleVPN couldn\u{2019}t use the key file at \(path). Check it is still there and that "
            + "it is the right one for this database."
        case .timedOut:
            "Reading your KeePass database took too long. A database with strong settings can be slow "
            + "to open \u{2014} try again."
        case .unreadable(let detail):
            detail.isEmpty ? "SimpleVPN couldn\u{2019}t read your KeePass database."
                           : "SimpleVPN couldn\u{2019}t read your KeePass database: \(detail)"
        }
    }
}

nonisolated extension KDBXFileState.NotADatabaseReason {
    /// One sentence per reason, each naming what to do. "That isn't a KeePass
    /// database" and "that is an old KeePass 1 database" need different answers, so
    /// they get different sentences.
    var sentence: String {
        switch self {
        case .keePass1Database:
            "That file is an old KeePass 1 database (.kdb), which SimpleVPN can\u{2019}t read. Open it "
            + "in KeePassXC and use its own Database \u{25B8} Import feature to convert it, then point "
            + "SimpleVPN at the converted file. SimpleVPN never changes your database itself."
        case .preReleaseFormat:
            "That file is a KeePass database in a format too old to read. Open it in KeePassXC and save "
            + "it again, then point SimpleVPN at it."
        case .notKeePassAtAll:
            "That file isn\u{2019}t a KeePass database. A KeePass database\u{2019}s name normally ends "
            + "in .kdbx."
        case .truncated:
            "That file is too small to be a KeePass database \u{2014} it may still be copying, or it "
            + "may be a placeholder for a file kept elsewhere."
        case .notARegularFile:
            "That isn\u{2019}t a file. Point SimpleVPN at your .kdbx database itself, not at a folder."
        }
    }
}

// MARK: - The process boundary

/// One place a `keepassxc-cli` invocation happens. Injectable, so every argument
/// list, every parser and every failure classification above it is testable with no
/// KeePassXC, no Strongbox, no KeePassium and no database on the machine.
nonisolated protocol KeePassToolRunning: Sendable {
    /// Where the tool is, or nil when it isn't anywhere SimpleVPN will run from.
    func locate() -> String?
    /// Run it. `arguments` NEVER carries a secret; `stdin` is the only channel one
    /// travels on.
    func run(_ arguments: [String], stdin: Data?, deadline: TimeInterval) async -> LocalToolResult
}

/// The real thing: `keepassxc-cli`, resolved and executed through
/// `LocalToolRunner` — so the allow-list, the never-`PATH` rule, the
/// world-writable-directory refusal and the built-not-inherited environment are all
/// the same ones every other tool gets. Nothing about binary resolution is
/// re-derived here.
nonisolated struct KeePassXCCLIRunner: KeePassToolRunning {

    static let toolName = "keepassxc-cli"

    /// A database with strong settings is deliberately slow to open: Argon2id at
    /// KeePassXC's own defaults takes about a second, and a user who has turned the
    /// memory up can be several. This is that with room, and still short enough that
    /// a wedged connect gives up rather than hanging for ever.
    static let defaultDeadline: TimeInterval = 30
    /// A slot programmed with `--touch` leaves the tool waiting on a finger.
    static let touchDeadline: TimeInterval = 60

    var home: URL = FileManager.default.homeDirectoryForCurrentUser

    func locate() -> String? { LocalToolRunner.locate(Self.toolName, home: home) }

    func run(_ arguments: [String], stdin: Data?,
             deadline: TimeInterval) async -> LocalToolResult {
        guard let executable = locate() else {
            return LocalToolResult(exitCode: -1, stdout: Data(),
                                   stderr: "not installed", timedOut: false)
        }
        return await LocalToolRunner.run(
            executable: executable, arguments: arguments, deadline: deadline,
            environment: LocalToolRunner.childEnvironment(home: home),
            stdin: stdin)
    }
}

// MARK: - The channel seam

/// How SimpleVPN reads a `.kdbx`. One implementation ships (`keepassxc-cli`);
/// tests inject a second with no tool and no database anywhere.
nonisolated protocol KeePassFileChannel: Sendable {
    /// Can this channel run at all? (The tool is somewhere we will execute from.)
    func isReachable() -> Bool
    /// One entry, by its path in the database.
    func entry(at path: String, unlock: KDBXUnlock) async throws -> KeePassFileEntry
    /// Entry PATHS matching a search term. Paths only — no secrets — so this is
    /// safe to show in a picker. Costs a full unlock, so it is user-initiated and
    /// never part of a connect.
    func entryPaths(matching term: String, unlock: KDBXUnlock) async throws -> [String]
}

// MARK: - keepassxc-cli

nonisolated struct KeePassXCCommandLineChannel: KeePassFileChannel {

    private static let log = Logger(subsystem: "com.bragi0.SimpleVPN", category: "keepass-file")

    var runner: any KeePassToolRunning = KeePassXCCLIRunner()

    /// The ONLY subcommands this app will ever invoke, and the reason the list is a
    /// constant rather than a habit: `keepassxc-cli` can add entries, edit them,
    /// import a KeePass 1 database and create a new one. None of those may ever
    /// happen to somebody's vault because of a VPN client. A test asserts every
    /// argument list this file builds starts with one of these.
    static let readOnlySubcommands: Set<String> = ["show", "search"]

    func isReachable() -> Bool { runner.locate() != nil }

    // MARK: Arguments — pure, so a test can prove no secret is in argv

    /// `keepassxc-cli show -s -a UserName -a Password [-k key] [-y slot[:serial]]
    /// [--no-password] <database> <entry>`
    ///
    /// Every piece of this is a NAME. `-s/--show-protected` is required or the tool
    /// prints the literal word `PROTECTED` in place of the password (its own
    /// `Show.cpp`); the two `-a` attributes are KDBX's built-in ones, which every
    /// entry always has (possibly empty), so asking for them can never fail the way
    /// asking for a custom attribute would.
    ///
    /// `--quiet` is deliberately NOT passed. It looks like the right flag — it
    /// silences the password prompt — but KeePassXC's `Utils::unlockDatabase` sends
    /// its unlock ERRORS to the same stream (`auto& err = quiet ? DEVNULL : STDERR`),
    /// so quiet would also throw away "Invalid credentials were provided", which is
    /// the one line that lets a wrong password be told apart from a missing key
    /// file. The prompt itself is harmless: it goes to stderr, which is never shown
    /// raw, and stdout stays clean.
    static func showArguments(entryPath: String, unlock: KDBXUnlock) -> [String] {
        var arguments = ["show", "--show-protected", "-a", "UserName", "-a", "Password"]
        arguments += commonArguments(unlock)
        arguments += [unlock.databasePath, entryPath]
        return arguments
    }

    /// `keepassxc-cli search [-k key] [-y slot] [--no-password] <database> <term>`
    static func searchArguments(term: String, unlock: KDBXUnlock) -> [String] {
        var arguments = ["search"]
        arguments += commonArguments(unlock)
        arguments += [unlock.databasePath, term]
        return arguments
    }

    /// The unlock factors that are expressible as arguments. The password is NOT
    /// among them, and never will be.
    static func commonArguments(_ unlock: KDBXUnlock) -> [String] {
        var arguments: [String] = []
        if let keyFile = unlock.keyFilePath?.trimmingCharacters(in: .whitespaces),
           !keyFile.isEmpty {
            arguments += ["--key-file", keyFile]
        }
        if let yubiKey = unlock.yubiKeyArgument {
            arguments += ["--yubikey", yubiKey]
        }
        // A database that genuinely has no password (key file and/or security key
        // only) must be told so, or the tool waits for one and then rejects the
        // empty line it gets.
        if unlock.password?.isEmpty ?? false {
            arguments.append("--no-password")
        }
        return arguments
    }

    // MARK: Running it

    func entry(at entryPath: String, unlock: KDBXUnlock) async throws -> KeePassFileEntry {
        let path = entryPath.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !path.isEmpty else { throw KeePassFileError.noEntryChosen }
        let result = await invoke(Self.showArguments(entryPath: path, unlock: unlock),
                                 unlock: unlock)
        guard result.succeeded else { throw Self.classify(result, unlock: unlock, entryPath: path) }
        guard let entry = Self.parseShowOutput(result.stdout) else {
            throw KeePassFileError.unreadable("its answer couldn\u{2019}t be read.")
        }
        // Only that it happened. Never the entry path (which names a group hierarchy
        // in somebody's vault), never the values.
        Self.log.log("kdbx entry read")
        return entry
    }

    func entryPaths(matching term: String, unlock: KDBXUnlock) async throws -> [String] {
        let query = term.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !query.isEmpty else { return [] }
        let result = await invoke(Self.searchArguments(term: query, unlock: unlock), unlock: unlock)
        guard result.succeeded else {
            // "nothing matched" is not a failure worth an error: `keepassxc-cli
            // search` exits non-zero for it, and an empty list is the honest answer.
            let error = Self.classify(result, unlock: unlock, entryPath: query)
            if case .entryNotFound = error { return [] }
            throw error
        }
        return Self.parseSearchOutput(result.stdout)
    }

    /// One invocation, with the password on stdin and nowhere else.
    private func invoke(_ arguments: [String], unlock: KDBXUnlock) async -> LocalToolResult {
        // Belt and braces on the read-only promise: an argument list that somehow
        // named a mutating subcommand never reaches the tool.
        guard let subcommand = arguments.first,
              Self.readOnlySubcommands.contains(subcommand) else {
            return LocalToolResult(exitCode: -1, stdout: Data(),
                                   stderr: "refused: not a read-only command", timedOut: false)
        }
        let stdin = unlock.password.flatMap { $0.isEmpty ? nil : $0.stdinLine() }
        return await runner.run(
            arguments, stdin: stdin,
            deadline: unlock.usesSecurityKey ? KeePassXCCLIRunner.touchDeadline
                                             : KeePassXCCLIRunner.defaultDeadline)
    }

    // MARK: Parsing — pure

    /// `show -a UserName -a Password` prints the requested values, one per line, in
    /// the order requested and with NO name prefixes (its `Show.cpp` prefixes names
    /// only when attributes were not explicitly asked for). An empty username is an
    /// empty first line, so the split must keep empties — dropping them would
    /// silently shift the password into the username.
    static func parseShowOutput(_ data: Data) -> KeePassFileEntry? {
        let text = String(decoding: data, as: UTF8.self)
        // Trailing newline only: a leading blank line IS the empty username.
        var lines = text.split(separator: "\n", omittingEmptySubsequences: false).map(String.init)
        while let last = lines.last, last.isEmpty { lines.removeLast() }
        guard lines.count >= 2 else { return nil }
        let username = lines[0].trimmingCharacters(in: .whitespacesAndNewlines)
        let password = lines[1]
        // Defensive: if a future release changes how protected attributes are
        // gated, we must not hand the literal word "PROTECTED" to a VPN as a
        // password.
        guard password != "PROTECTED" else { return nil }
        return KeePassFileEntry(username: username.isEmpty ? nil : username,
                                password: password.isEmpty ? nil : password)
    }

    /// `search` prints one entry path per line. Paths only — no secrets — which is
    /// why this output may be shown in a picker.
    static func parseSearchOutput(_ data: Data) -> [String] {
        String(decoding: data, as: UTF8.self)
            .split(whereSeparator: \.isNewline)
            .map { $0.trimmingCharacters(in: .whitespaces) }
            .filter { !$0.isEmpty }
    }

    // MARK: Classifying a failure

    /// Turn a failed run into the right sentence.
    ///
    /// The markers are KeePassXC's own English strings, quoted from its source:
    /// `Kdbx3Reader.cpp` ("Invalid credentials were provided, please try again.",
    /// "Unable to issue challenge-response: %1"), `KeePass2Reader.cpp` ("Not a
    /// KeePass database.", "Unsupported KeePass 2 database version.", the KeePass 1
    /// sentence), `Database.cpp` ("File %1 does not exist.", "Unable to open file
    /// %1.") and `Show.cpp` ("Could not find entry with path %1.").
    ///
    /// TWO HONEST LIMITS, both stated rather than papered over:
    ///  • stderr also carries the tool's password PROMPT, which has no trailing
    ///    newline, so the prompt and the first error share a line. The runner keeps
    ///    the first line and caps it at 200 characters, so a very long database path
    ///    can push a marker past the cap. When nothing matches we fall through to
    ///    `.unlockRefused`, which lists every configured factor — the honest answer
    ///    rather than a guess.
    ///  • A refused unlock genuinely CANNOT distinguish a wrong password from a
    ///    missing or wrong key file from a security key that answered with the wrong
    ///    bytes. The database only knows the composite key was wrong. So the message
    ///    names every factor in play instead of accusing the password.
    static func classify(_ result: LocalToolResult, unlock: KDBXUnlock,
                         entryPath: String) -> KeePassFileError {
        if result.timedOut { return .timedOut }
        let stderr = result.stderr.lowercased()
        if stderr.contains("not installed") { return .toolMissing }
        if stderr.contains("challenge-response") { return .securityKeyDidNotAnswer }
        if stderr.contains("could not find entry") { return .entryNotFound(entryPath) }
        if stderr.contains("keepass 1 database") {
            return .notAKeePassDatabase(.keePass1Database)
        }
        if stderr.contains("not a keepass database") {
            return .notAKeePassDatabase(.notKeePassAtAll)
        }
        if stderr.contains("unsupported keepass 2 database version") {
            return .databaseTooNew("newer than this tool")
        }
        if stderr.contains("does not exist") || stderr.contains("unable to open file") {
            return .databaseMissing(unlock.databasePath)
        }
        if stderr.contains("key file"), let keyFile = unlock.keyFilePath, !keyFile.isEmpty {
            return .keyFileUnreadable(keyFile)
        }
        if stderr.contains("invalid credentials") {
            return .unlockRefused(factors: refusalPossibilities(unlock))
        }
        // Nothing matched. An unlock that failed for an unknown reason is still far
        // more likely to be a credential than anything else, so say that — with the
        // full list — rather than showing somebody a tool's diagnostic.
        return .unlockRefused(factors: refusalPossibilities(unlock))
    }

    /// Every factor that could be the one that was wrong, in the order most likely
    /// first. Built from what is CONFIGURED, so nobody is told to check a key file
    /// they never set.
    static func refusalPossibilities(_ unlock: KDBXUnlock) -> [String] {
        var out = ["the database password"]
        if let keyFile = unlock.keyFilePath?.trimmingCharacters(in: .whitespaces), !keyFile.isEmpty {
            out.append("the key file")
        } else {
            // Not configured is itself a possibility: a database that needs a key
            // file and hasn't been given one fails in exactly this way.
            out.append("a key file this database needs that SimpleVPN hasn\u{2019}t been given")
        }
        if unlock.usesSecurityKey {
            out.append("your security key\u{2019}s answer")
        } else {
            out.append("a security key this database needs that SimpleVPN hasn\u{2019}t been told about")
        }
        return out
    }
}

// MARK: - The configured database

/// ONE CONFIGURED DATABASE — level 2 (`SourceInstance`, SignInSourceInstances
/// .swift). Its file, its key file and its security-key slot, read from the same
/// per-vendor settings surface every other vendor uses, so an MDM-pinned path and a
/// locked pane work here for free.
///
/// It used to be THE database, singular, because its three fields were level-1
/// app defaults. They are now an instance's fields, and this value names which
/// instance it came from — so "the work database" and "the personal one" are two of
/// these rather than one that keeps changing underneath every VPN.
struct KeePassFileConfiguration: Sendable, Equatable {
    /// Which instance this is, or nil when nothing is set up at all.
    var instance: SourceInstanceID?
    /// What the user calls it. Shown in the two-step chooser and in errors, because
    /// "your database wouldn't open" is a different sentence from "Work wouldn't
    /// open" the moment somebody has two.
    var name = ""
    var databasePath = ""
    var keyFilePath = ""
    /// nil = this database does not use a security key. EMPTY MEANS NONE, which is
    /// why there is no separate switch to fall out of step with the slot number.
    var slot: YubiKeySlot?
    var serial = ""

    var isConfigured: Bool { !databasePath.trimmingCharacters(in: .whitespaces).isEmpty }

    /// The configuration for ONE instance — the named one, or the default when the
    /// caller has none in mind (which is what a profile written before instances
    /// existed means).
    static func current(store: SignInSourceSettingsStore = .shared,
                        instance wanted: SourceInstanceID? = nil) -> KeePassFileConfiguration {
        let resolution = store.instanceStore.resolve(wanted, for: .keePassFile)
        // A named instance that is GONE resolves to nothing rather than to somebody
        // else's database: reading the wrong vault because a list changed is the one
        // outcome worse than failing to read at all.
        guard let instance = resolution.instance else { return KeePassFileConfiguration() }
        var out = KeePassFileConfiguration(instance: instance.id, name: instance.name)
        for field in SignInSourceSettings.fields(for: .keePassFile) {
            // `effectivePath` so an MDM-pinned value wins, exactly as it does for a
            // tool path.
            let shown = store.presentation(for: field, instance: instance)
            switch field.kind {
            case .vaultFile:
                out.databasePath = shown.effectivePath ?? ""
            case .keyFile:
                out.keyFilePath = shown.effectivePath ?? ""
            case .securityKeySlot:
                out.slot = YubiKeySlot(rawValue: Int(shown.value.trimmingCharacters(
                    in: .whitespaces)) ?? 0)
            case .toolBinary, .unixSocket, .daemonEndpoint, .pkcs11Module,
                 .storeDirectory, .entryFieldName, .serverURL, .toolConfigFile:
                // Not kdbx fields. `storeDirectory` and `entryFieldName` belong to the
                // password-store source; they can never appear in this vendor's own
                // field list, and skipping them here keeps the switch total without
                // pretending they mean something to a .kdbx.
                continue
            }
        }
        return out
    }

    /// The unlock this configuration implies, with `password` still to be filled in.
    func unlock(password: KDBXPassword?) -> KDBXUnlock {
        KDBXUnlock(
            databasePath: databasePath.trimmingCharacters(in: .whitespaces),
            keyFilePath: keyFilePath.trimmingCharacters(in: .whitespaces).isEmpty
                ? nil : keyFilePath.trimmingCharacters(in: .whitespaces),
            slot: slot,
            serial: serial.trimmingCharacters(in: .whitespaces),
            password: password)
    }
}

// MARK: - Remembering that an unlock was refused

/// "The last time we tried, the database said no." Held in memory for the process,
/// deliberately NOT persisted: a refused unlock is usually a typo, and a defaults
/// key that outlived the launch would keep telling somebody their password is wrong
/// after they had fixed it.
///
/// It exists so the vendor row can say "the database wouldn't open" rather than
/// showing "ready" and failing again at the next connect. Cleared the moment a
/// password is entered or an unlock succeeds — which is what makes following the
/// advice flip the row back without a restart.
@MainActor
final class KeePassFileUnlockMemory {

    static let shared = KeePassFileUnlockMemory()

    private var refused: Set<String> = []

    func noteRefused(database path: String) { refused.insert(path) }
    func noteSucceeded(database path: String) { refused.remove(path) }
    func clear(database path: String) { refused.remove(path) }
    func wasRefused(database path: String) -> Bool { refused.contains(path) }
}

// MARK: - The provider

/// Fetch a username and password from an entry in a `.kdbx` file.
///
/// NO VERIFICATION CODE, on purpose, and the reason is a real constraint rather
/// than an omission: `keepassxc-cli show -t` prints an entry's current TOTP, but
/// its `Show.cpp` FAILS THE WHOLE RUN ("Entry with path %1 has no TOTP set up.")
/// when the entry hasn't got one — and there is no way to ask whether an entry has
/// one without unlocking the database, which is the expensive part and may want a
/// finger. So passing `-t` speculatively would turn every ordinary entry's fetch
/// into a failed sign-in. `CredentialSourceKind.keePassFile.suppliesOTP` is
/// therefore `false`, which is a PROMISE kept rather than a capability missed: the
/// user types the code, and Connect says so instead of lighting up and failing.
struct KeePassFileProvider: CredentialProvider {
    let id = "keepass-file"
    let displayName = "KeePass database file"
    /// The entry's path in the database — its groups and its title, separated by
    /// slashes ("VPN/Work"). Not a secret; it rides argv.
    let entryPath: String
    /// Which login to take when the caller knows it. Matched against the entry's
    /// own username, same as Keeper's.
    var account: String = ""
    /// WHICH DATABASE — the level-2 instance this VPN named (nil = the one SimpleVPN
    /// set up). Carried here rather than read from a single app default, which is
    /// what made two databases impossible.
    var instance: SourceInstanceID?
    /// Injectable so tests drive the whole resolve path with no KeePass anywhere.
    var channel: any KeePassFileChannel = KeePassXCCommandLineChannel()

    private static let log = Logger(subsystem: "com.bragi0.SimpleVPN", category: "keepass-file")

    func isAvailable(for profile: String) async -> Bool {
        guard !entryPath.trimmingCharacters(in: .whitespaces).isEmpty else { return false }
        guard channel.isReachable() else { return false }
        let configuration = KeePassFileConfiguration.current(instance: instance)
        guard configuration.isConfigured else { return false }
        return KeePassDatabaseFile.classify(path: configuration.databasePath).isReadable
    }

    func resolve(profile: String, fields: Set<CredentialField>) async throws -> RawCredentials {
        let configuration = KeePassFileConfiguration.current(instance: instance)
        guard configuration.isConfigured else { throw KeePassFileError.noDatabaseChosen }
        guard channel.isReachable() else { throw KeePassFileError.toolMissing }

        // Our own header read first: four of the states below would otherwise all
        // arrive as "wrong password".
        switch KeePassDatabaseFile.classify(path: configuration.databasePath) {
        case .notConfigured:
            throw KeePassFileError.noDatabaseChosen
        case .missing(let path):
            throw KeePassFileError.databaseMissing(path)
        case .notDownloaded(let path):
            throw KeePassFileError.databaseNotDownloaded(path)
        case .permissionDenied(let path):
            throw KeePassFileError.databaseNotReadable(path)
        case .notADatabase(_, let reason):
            throw KeePassFileError.notAKeePassDatabase(reason)
        case .tooNew(_, let version):
            throw KeePassFileError.databaseTooNew(version.displayName)
        case .readable:
            break
        }

        let name = (profile.isEmpty ? "this VPN" : profile)
        // The prompt names the DATABASE as well as the VPN once there is more than
        // one of them: "unlock your KeePass database" is ambiguous the moment a
        // person has a work vault and a personal one.
        let which = configuration.name.isEmpty ? "your KeePass database"
                                               : "your KeePass database \u{201C}\(configuration.name)\u{201D}"
        let password = try await KDBXMasterPasswordStore.shared.password(
            database: configuration.databasePath,
            reason: "unlock \(which) for \(name)")
        guard let password else { throw KeePassFileError.needsDatabasePassword }
        guard !password.containsNewline else { throw KeePassFileError.passwordHasLineBreak }

        let unlock = configuration.unlock(password: password)
        do {
            let entry = try await channel.entry(at: entryPath, unlock: unlock)
            KeePassFileUnlockMemory.shared.noteSucceeded(database: configuration.databasePath)
            return try Self.credentials(from: entry, entryPath: entryPath, wanted: account)
        } catch let error as KeePassFileError {
            // Only a REFUSED unlock is remembered. An entry that isn't there, or a
            // tool that timed out, says nothing about the password, and marking the
            // row "wouldn't open" for those would be wrong.
            if case .unlockRefused = error {
                KeePassFileUnlockMemory.shared.noteRefused(database: configuration.databasePath)
            }
            throw error
        }
    }

    /// Pure, so the account check and the empty-password rule are testable without
    /// a channel.
    static func credentials(from entry: KeePassFileEntry, entryPath: String,
                            wanted rawWanted: String) throws -> RawCredentials {
        let wanted = rawWanted.trimmingCharacters(in: .whitespaces)
        if !wanted.isEmpty, let username = entry.username, !username.isEmpty,
           username.caseInsensitiveCompare(wanted) != .orderedSame {
            throw KeePassFileError.entryNotFound(entryPath)
        }
        guard let password = entry.password, !password.isEmpty else {
            throw KeePassFileError.entryHasNoPassword(entryPath)
        }
        var raw = RawCredentials()
        raw.username = entry.username ?? (wanted.isEmpty ? nil : wanted)
        raw.password = password
        return raw
    }
}

// MARK: - The adapter

/// The `.file` transport, and the only adapter in the registry that reaches no
/// vendor process at all.
///
/// WHO IT SERVES. KeePassXC's own row stays first and stays preferred: a running
/// app owns its unlock and never shows us a database password. This row is for
/// everyone that cannot reach — Strongbox, KeePassium, a closed KeePassXC, a
/// database on a share with no KeePass app installed at all.
///
/// WHEN THE ROW IS OFFERED AT ALL. Not to somebody with nothing KeePass on their
/// Mac: that would be advertising a file format at a person who does not use it.
/// The row appears when there is evidence they do — the tool is here, a
/// KeePass-format app is installed, or they have already chosen a database.
struct KeePassFileVaultAdapter: LocalVaultAdapter {
    let vendor = LocalVaultVendor.keePassFile
    let storedKind = CredentialSourceKind.keePassFile
    /// The one adapter whose channel is a FILE. No socket, no daemon, no vendor
    /// process — which is exactly why one adapter covers three products.
    let transports: [LocalVaultTransport] = [.file]

    /// Injectable so the whole state machine is testable with no tool present.
    var channel: any KeePassFileChannel = KeePassXCCommandLineChannel()

    /// Apps that store this format. Their presence is the signal that a file-backed
    /// row is worth offering; it is never a read path in itself.
    static var isKeePassFormatAppInstalled: Bool {
        PasswordAppCatalog.entries
            .filter { $0.localReadPath == .keePassFormat }
            .flatMap(\.bundleIDs)
            .contains { NSWorkspace.shared.urlForApplication(withBundleIdentifier: $0) != nil }
            || KeePassXCVaultAdapter.isAppInstalled
    }

    func quickScan() -> LocalVaultAvailability { quickScan(instance: nil) }

    /// ONE database's state. Called per instance, which is what lets the work
    /// database be missing while the personal one is ready — and what makes both
    /// sentences appear in the pane instead of one of them being averaged away.
    /// `nil` means the default instance (a profile written before instances
    /// existed).
    func quickScan(instance: SourceInstance?) -> LocalVaultAvailability {
        let configuration = KeePassFileConfiguration.current(instance: instance?.id)
        let toolHere = channel.isReachable()

        // Nothing KeePass anywhere and nothing chosen: don't offer it. A vault the
        // user has DELIBERATELY ADDED counts as evidence too — having named a database
        // is a clearer statement of intent than having an app installed, and telling
        // somebody the row isn't available for a database they just created would be
        // absurd.
        guard toolHere || configuration.isConfigured || instance != nil
                || Self.isKeePassFormatAppInstalled else {
            return .notInstalled
        }
        if !toolHere {
            // "It's installed, just not where we run from" is a two-second fix and
            // must never be reported as "not installed".
            if LocalVaultRegistry.toolFoundOutsideAllowList(KeePassXCCLIRunner.toolName) != nil {
                return .blocked(.toolOutsideAllowList)
            }
            return .blocked(.toolMissing)
        }
        guard configuration.isConfigured else { return .blocked(.noVaultFile) }

        switch KeePassDatabaseFile.classify(path: configuration.databasePath) {
        case .notConfigured:
            return .blocked(.noVaultFile)
        case .missing:
            return .blocked(.vaultFileMissing)
        case .notDownloaded:
            return .blocked(.vaultFileNotDownloaded)
        case .permissionDenied:
            return .blocked(.vaultFileNotReadable)
        case .notADatabase:
            return .blocked(.vaultFileNotAKeePassDatabase)
        case .tooNew:
            return .blocked(.vaultFileTooNew)
        case .readable:
            break
        }
        // The database is real and readable. What is left is the password.
        let path = configuration.databasePath
        if KeePassFileUnlockMemory.shared.wasRefused(database: path) {
            return .blocked(.vaultPasswordRejected)
        }
        let store = KDBXMasterPasswordStore.shared
        guard store.isHeldForThisRun(database: path) || store.isRemembered(database: path) else {
            // `vaultLocked`, not a case of our own: the Bitwarden adapter named this
            // state first and it means exactly this — the vault is here and something
            // has to unlock it. The FIX differs (Bitwarden: unlock its own tool; a
            // `.kdbx`: type the database password), and the fix is per-vendor copy.
            return .blocked(.vaultLocked)
        }
        return .ready
    }

    /// NOTHING a subprocess could add that would be honest to spend. The only deep
    /// check available is a real unlock, and a real unlock costs a key derivation
    /// measured in seconds, may raise a Touch ID prompt for the stored password, and
    /// may ask the user to touch a security key. Doing all of that on a poll — for a
    /// row nobody has picked yet — would be an unexplained fingerprint prompt from
    /// nowhere. Everything provable for free is already proven in `quickScan`.
    func deepScan(quick: LocalVaultAvailability) async -> LocalVaultAvailability { quick }

    func provider(for source: CredentialSource) -> (any CredentialProvider)? {
        guard !source.reference.trimmingCharacters(in: .whitespaces).isEmpty else { return nil }
        // The profile says WHICH database as well as which entry — level 2 and
        // level 3, kept apart.
        return KeePassFileProvider(entryPath: source.reference, account: source.account,
                                   instance: source.selection.instance,
                                   channel: channel)
    }
}
