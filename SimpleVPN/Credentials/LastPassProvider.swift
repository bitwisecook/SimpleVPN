// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
//  LastPassProvider.swift
//  Fetch a username and password from LastPass through `lpass`, LastPass's own
//  command-line tool — the only local read path LastPass has.
//
//  READ THIS FIRST: THIS SOURCE IS BEST-EFFORT, AND THE COPY SAYS SO. Not because
//  the tool is bad, but because it is the LEAST capable of the tools SimpleVPN
//  reads, and three of its limits are structural rather than temporary:
//
//   1. NO VERIFICATION CODES, EVER. `lpass show --json` emits exactly the fields
//      `account_to_json_field` in the tool's own `json-format.c` writes: id, name,
//      fullname, username, password, last_modified_gmt, last_touch, share, group,
//      url, note. There is no code, no seed, and no `lpass totp` subcommand at all.
//      So `CredentialSourceKind.lastPass.suppliesOTP` is false for a reason nobody
//      can fix at this end, and the code is always typed.
//   2. THE SIGN-IN IS A TERMINAL SIGN-IN, and its session is an AGENT that forgets.
//      See "The agent" below. SimpleVPN never asks for a LastPass master password
//      and never will.
//   3. THE PROJECT MOVES SLOWLY. Measured 2026-08-05 against `lastpass/lastpass-cli`:
//      four releases through 2024 (v1.4.0 April, v1.5.0 May, v1.6.0 August,
//      v1.6.1 on 2026-… no, 2024-11-14), and no commit on the default branch since
//      2025-04-22. Quiet, not abandoned. The shipped copy therefore does NOT print
//      a date that will rot; it says "moves slowly" and names the limits above,
//      which are the part a user can act on.
//
//  THE AGENT — AND WHY THIS SOURCE IS NOT DORMANT (contrast Bitwarden's CLI path,
//  which IS). Verified in the tool's own `agent.c`:
//
//   • `agent_get_decryption_key` (what every read goes through) tries `agent_ask`
//     first, which connects to a unix socket at `$LPASS_HOME/agent.sock` and reads
//     the derived vault key from a background `lpass [agent]` process. If that
//     succeeds, NOTHING IS PROMPTED. So one `lpass login` in Terminal is enough,
//     and every fetch after it is silent — exactly the non-interactive path
//     Bitwarden's `bw` does not have.
//   • The agent quits after ONE HOUR unless `LPASS_AGENT_TIMEOUT` says otherwise
//     (`0` = never). That is the whole reason `vaultLocked` is a state here: a
//     person who signed in this morning is signed in and cannot be read.
//   • THE AGENT WILL NOT GIVE THE KEY TO SIMPLEVPN. `agent_run` refuses any peer
//     whose uid, gid or EXECUTABLE differs from its own
//     (`!process_is_same_executable(cred.pid)`). So the vault key reaches `lpass`
//     and nothing else — better than `bw serve`, which authenticates nobody. That
//     is worth stating: SimpleVPN never holds the master password and never holds
//     the derived key either.
//   • If the agent is gone, `agent_load_key` PROMPTS. SimpleVPN must never let that
//     prompt appear from a background refresh, so the child's environment sets
//     `LPASS_DISABLE_PINENTRY=1` and stdin stays `/dev/null`: the prompt falls back
//     to reading standard input (`password_prompt_fallback` in `password.c`), hits
//     EOF at once, and the read fails cleanly instead of hanging or drawing a
//     dialog nobody asked for.
//
//  THE CLIPBOARD, WHICH IS THE FINDING THIS FILE EXISTS TO GUARD. `-c`/`--clip` is
//  NOT the default: `cmd-show.c` prints to stdout unless `clip` is set, and nothing
//  here ever passes it. But `lpass` expands ALIASES before parsing options
//  (`expand_aliases` in `lpass.c` PREPENDS the tokens in `$LPASS_HOME/alias.show`
//  to argv), and the tool's own man page suggests exactly this:
//      echo 'show --password -c' > ~/.config/lpass/alias.passclip
//  There is no `--no-clip`, so an alias carrying `-c` cannot be overridden — our
//  password would be written to the pasteboard and NOT to stdout
//  (`if (!clip)` guards the print). A VPN password must not sit on the pasteboard,
//  so SimpleVPN READS THAT FILE and refuses to fetch while it would divert, with
//  one sentence and one fix. `LPASS_CLIPBOARD_COMMAND=/usr/bin/true` is also set as
//  defence in depth (`clipboard_open` runs it through a shell and pipes stdout into
//  it), but the refusal is the guard — the environment can be overridden from
//  `$LPASS_HOME/env`, which `load_saved_environment` applies with `setenv(…, true)`.
//
//  Non-negotiables shared with every other CLI-backed source (see LocalToolRunner):
//   • the secret arrives on STDOUT and is never logged, never quoted in an error,
//     never in argv, never in `providerConfiguration`, never in a diagnostic bundle;
//   • only the entry's own name or id rides argv;
//   • the binary is resolved by `LocalToolRunner.locate` — the allow-list, never
//     `PATH`;
//   • we never write LastPass's configuration, never sign in for the user, and
//     never mutate the vault. `--sync=no` is passed on every read so a connect
//     never waits on LastPass's servers and never uploads anything.
//   • nothing is cached: each connect asks again, so an agent timing out takes
//     effect immediately.
//

import Foundation
import AppKit
import os

// MARK: - Where `lpass` keeps its state

/// The one directory `lpass` reads and writes, and the files inside it worth
/// asking about.
///
/// WHY THIS IS `$HOME/.lpass` AND NOT A SEARCH. `config_path_for_type` in the
/// tool's own `config.c` resolves, in order: `$LPASS_HOME`; else an XDG directory
/// but ONLY when `$XDG_RUNTIME_DIR` is set; else `$HOME/.lpass`. SimpleVPN runs
/// `lpass` with an environment BUILT rather than inherited
/// (`LocalToolRunner.childEnvironment`), so no `XDG_*` variable reaches the child
/// and the child resolves `$HOME/.lpass` every time. Probing that same path is
/// therefore not a guess — it is the directory the process we are about to run will
/// use. `LPASS_HOME` is additionally passed explicitly so the two cannot drift even
/// if the resolution rules change.
///
/// The consequence, stated rather than hidden: somebody who keeps their LastPass
/// cache elsewhere by exporting `LPASS_HOME` in their shell profile will be
/// reported as not signed in. That is a coherent answer with a real fix, and it is
/// never a wrong-vault read.
nonisolated struct LastPassHome: Sendable, Equatable {

    var directory: String

    static func standard(
        home: URL = FileManager.default.homeDirectoryForCurrentUser
    ) -> LastPassHome {
        LastPassHome(directory: home.appendingPathComponent(".lpass").path)
    }

    private func file(_ name: String) -> String {
        (directory as NSString).appendingPathComponent(name)
    }

    /// Written by `agent_save` on a successful sign-in.
    var usernameFile: String { file("username") }
    /// The encrypted verification string `agent_load_key` checks a derived key
    /// against. Its presence is what makes "somebody has signed in here" true
    /// rather than "a directory exists".
    var verifyFile: String { file("verify") }
    /// The encrypted vault cache.
    var blobFile: String { file("blob") }
    /// The agent's socket. Its presence means an agent has run; whether one is
    /// LISTENING is `lpass status`'s job, not a `stat`'s.
    var agentSocket: String { file("agent.sock") }
    /// `lpass login --plaintext-key` writes the derived vault key here in the
    /// clear. The tool's own man page calls that "discouraged except in limited
    /// situations, as it greatly decreases the security of data".
    var plaintextKeyFile: String { file("plaintext_key") }
    /// `alias.show` — default options prepended to every `lpass show`.
    var showAliasFile: String { file("alias.show") }
}

/// Filesystem questions as closures rather than a `FileManager` (which is not
/// `Sendable`), the same seam `PasswordStoreFileProbe` uses and for the same
/// reason: a test can present a whole `~/.lpass` without touching disk.
nonisolated struct LastPassFileProbe: Sendable {
    var fileExists: @Sendable (String) -> Bool = { FileManager.default.fileExists(atPath: $0) }
    var directoryExists: @Sendable (String) -> Bool = {
        var isDir: ObjCBool = false
        let there = FileManager.default.fileExists(atPath: $0, isDirectory: &isDir)
        return there && isDir.boolValue
    }
    /// The alias file's contents, or nil. Bounded: it is a line of flags, and a
    /// huge file here is a mistake rather than a configuration.
    var readText: @Sendable (String) -> String? = { path in
        guard let data = FileManager.default.contents(atPath: path), data.count <= 4096 else {
            return nil
        }
        return String(decoding: data, as: UTF8.self)
    }
}

/// What the cheap probe learned. Five `stat` calls and at most one tiny file read
/// — no subprocess, no prompt, no network, and nothing spent.
nonisolated struct LastPassHomeFacts: Sendable, Equatable {
    /// `~/.lpass` is there at all.
    var directoryExists = false
    /// `username` + `verify`: a sign-in has been COMPLETED here at some point.
    /// Deliberately not `blob` alone — a cache can exist without a usable key.
    var hasSignedInBefore = false
    /// `agent.sock` exists, so an agent has run. Not proof one is alive.
    var agentSocketExists = false
    /// `plaintext_key` exists, so reads work with no agent and no prompt — AND
    /// `lpass status` will nonetheless say "Not logged in", because `cmd_status`
    /// asks the agent and `agent_start` never starts one in this mode.
    var keyIsOnDisk = false
    /// `alias.show` would add `--clip`, sending the password to the pasteboard
    /// instead of to us.
    var showDivertsToClipboard = false
}

nonisolated struct LastPassHomeProbe: Sendable {
    var home: LastPassHome
    var files = LastPassFileProbe()

    init(home: LastPassHome = .standard(), files: LastPassFileProbe = LastPassFileProbe()) {
        self.home = home
        self.files = files
    }

    func facts() -> LastPassHomeFacts {
        var out = LastPassHomeFacts()
        out.directoryExists = files.directoryExists(home.directory)
        guard out.directoryExists else { return out }
        out.hasSignedInBefore = files.fileExists(home.usernameFile)
            && files.fileExists(home.verifyFile)
        out.agentSocketExists = files.fileExists(home.agentSocket)
        out.keyIsOnDisk = files.fileExists(home.plaintextKeyFile)
        if let alias = files.readText(home.showAliasFile) {
            out.showDivertsToClipboard = LastPassShowAlias.divertsToClipboard(alias)
        }
        return out
    }
}

// MARK: - The alias guard

/// Whether `$LPASS_HOME/alias.show` would put the password on the pasteboard.
///
/// Pure, and deliberately generous about what counts. `expand_aliases` splits the
/// file on spaces and tabs and PREPENDS the tokens, so the flag can arrive in three
/// shapes and all three are the same outcome:
///
///  • `-c` on its own;
///  • CLUSTERED, as in the man page's own `show --password -c` written `-cp` —
///    `getopt_long` reads `-cp` as `-c -p`, so any short cluster containing `c`
///    counts;
///  • ABBREVIATED, because `getopt_long` accepts any unambiguous prefix of a long
///    option. `show`'s long options include both `clip` and `color`, so `--c` is
///    ambiguous and rejected by the tool, while `--cl`, `--cli` and `--clip` all
///    mean `--clip`. All three count.
///
/// Erring towards refusal is correct: the cost of a false positive is one sentence
/// telling somebody to remove a flag they really did write, and the cost of a false
/// negative is a VPN password on the pasteboard.
nonisolated enum LastPassShowAlias {

    /// The long options `lpass show` declares, so "is this an unambiguous prefix of
    /// `clip`" is answered against the real set rather than a guess.
    static let showLongOptions = [
        "sync", "clip", "quiet", "expand-multi", "json", "all", "username", "password",
        "url", "notes", "field", "id", "name", "attach", "basic-regexp", "fixed-strings",
        "color",
    ]

    static func divertsToClipboard(_ raw: String) -> Bool {
        tokens(raw).contains(where: isClipFlag)
    }

    /// The alias file as `expand_aliases` sees it: trimmed, then split on spaces and
    /// tabs. Newlines are treated as separators too — the file is read with
    /// `config_read_string` and trimmed, and a two-line alias is a mistake we should
    /// still notice rather than skip.
    static func tokens(_ raw: String) -> [String] {
        raw.split(whereSeparator: { $0 == " " || $0 == "\t" || $0.isNewline })
            .map(String.init)
    }

    static func isClipFlag(_ token: String) -> Bool {
        if token.hasPrefix("--") {
            let name = String(token.dropFirst(2)).split(separator: "=").first.map(String.init)
                ?? String(token.dropFirst(2))
            guard !name.isEmpty, "clip".hasPrefix(name) else { return false }
            // An ambiguous prefix is rejected by the tool itself, so it cannot divert.
            let matches = showLongOptions.filter { $0.hasPrefix(name) }
            return matches == ["clip"]
        }
        guard token.hasPrefix("-"), token.count > 1 else { return false }
        // A short cluster. `-c` anywhere in it sets `clip`.
        return token.dropFirst().contains("c")
    }
}

// MARK: - What one entry gives us

/// One LastPass account, lifted out of `lpass show --json`. The field names are the
/// tool's own (`account_to_json_field`, `json-format.c`), so reading them is a
/// lookup rather than an interpretation — and the ones missing from that function
/// are missing from LastPass's command-line surface entirely, which is why there is
/// no verification code here.
nonisolated struct LastPassEntry: Sendable, Equatable {
    /// LastPass's own integer id, as a string. Not a secret — it is what we tell
    /// the user to paste when several entries share a name.
    var id: String?
    /// The entry's own name.
    var name: String?
    /// Name including its group path ("Work/VPN/GR Lab"), which is what a user
    /// typically typed.
    var fullName: String?
    var username: String?
    var password: String?
    var group: String?
    var url: String?

    var hasPassword: Bool { !(password ?? "").isEmpty }

    /// What to call this entry in a sentence. Never a secret.
    var label: String { fullName ?? name ?? id ?? "" }
}

// MARK: - Reading the tool's answers (pure)

nonisolated enum LastPassWire {

    /// `cmd_show.c` prints this on STDOUT and then `exit(EXIT_SUCCESS)` when a name
    /// matched more than one entry and `--expand-multi` was not given. EXIT ZERO,
    /// with no JSON — so a caller that trusted the exit code and took stdout as the
    /// password would hand a VPN a line of prose. SimpleVPN always passes
    /// `--expand-multi`, and still checks for this, because "the vendor changed its
    /// mind" must not become "your password is now the word Multiple".
    static let multipleMatchesMarker = "Multiple matches found."

    /// Every entry out of a `--json` reply. The tool prints a bare JSON ARRAY.
    static func entries(_ stdout: Data) throws -> [LastPassEntry] {
        let text = String(decoding: stdout, as: UTF8.self)
            .trimmingCharacters(in: .whitespacesAndNewlines)
        guard !text.isEmpty else { throw LastPassProvider.LastPassError.emptyAnswer }
        guard !text.hasPrefix(multipleMatchesMarker) else {
            throw LastPassProvider.LastPassError.severalMatches(0)
        }
        guard let any = try? JSONSerialization.jsonObject(with: Data(text.utf8)) else {
            // NOT quoted into the message: this is the shape stdout takes, and
            // stdout is secret-bearing by contract.
            throw LastPassProvider.LastPassError.unreadable(
                "its answer couldn\u{2019}t be read.")
        }
        if let array = any as? [Any] { return array.compactMap(entry) }
        return entry(any).map { [$0] } ?? []
    }

    static func entry(_ any: Any) -> LastPassEntry? {
        guard let dict = any as? [String: Any] else { return nil }
        var out = LastPassEntry()
        out.id = nonEmpty(dict["id"])
        out.name = nonEmpty(dict["name"])
        out.fullName = nonEmpty(dict["fullname"])
        out.username = nonEmpty(dict["username"])
        out.password = nonEmpty(dict["password"])
        out.group = nonEmpty(dict["group"])
        out.url = nonEmpty(dict["url"])
        // An object with nothing identifying in it is not an entry we found.
        return (out.id != nil || out.name != nil || out.fullName != nil
                || out.username != nil || out.password != nil) ? out : nil
    }

    /// The tool's own failure sentences, mapped to states with fixes. Every string
    /// matched here is a `die(…)` in the tool's source, quoted from it — and the
    /// match is loose because the wording belongs to somebody else's release notes.
    ///
    /// The stderr text is ALREADY scrubbed and truncated by `LocalToolRunner`
    /// before it reaches here, and only the scrubbed form may ever be shown.
    static func error(stderr: String) -> LastPassProvider.LastPassError {
        let lowered = stderr.lowercased()
        // `agent_load_key` returned false because stdin was /dev/null. This is the
        // ordinary "your agent has forgotten you" case, and it is NOT a wrong
        // password: nobody typed one.
        if lowered.contains("could not find decryption key") { return .agentAsleep }
        if lowered.contains("not currently logged in") { return .notSignedIn }
        if lowered.contains("could not authenticate for protected entry") {
            return .entryNeedsReprompt
        }
        if lowered.contains("current key is not on-disk key") { return .entryNeedsReprompt }
        if lowered.contains("could not find specified account") { return .notFound("") }
        if lowered.contains("could not find specified field") { return .notFound("") }
        return .unreadable(stderr)
    }

    private static func nonEmpty(_ value: Any?) -> String? {
        guard let text = value as? String, !text.isEmpty else { return nil }
        return text
    }
}

/// Choosing ONE entry when a name matched several. Pure, so "two entries share a
/// name" and "the username picks the right one" are tested with no LastPass
/// anywhere. Deliberately the same SHAPE as `BitwardenItemPicker` — the question is
/// the same question and two answers to it would drift — with one deliberate
/// difference, stated below.
nonisolated enum LastPassEntryPicker {

    static func pick(_ entries: [LastPassEntry],
                     account: String,
                     reference: String) throws -> LastPassEntry {
        // An entry with no password cannot sign anything in, so it is not a
        // candidate — which is also what stops a secure note of the same name being
        // reported as an ambiguity.
        let usable = entries.filter(\.hasPassword)
        guard !usable.isEmpty else {
            throw entries.isEmpty
                ? LastPassProvider.LastPassError.notFound(reference)
                : LastPassProvider.LastPassError.noPassword(reference)
        }
        guard !account.isEmpty else {
            if usable.count == 1 { return usable[0] }
            throw LastPassProvider.LastPassError.severalMatches(usable.count)
        }
        let exact = usable.filter {
            ($0.username ?? "").caseInsensitiveCompare(account) == .orderedSame
        }
        if exact.count == 1 { return exact[0] }
        if exact.count > 1 {
            throw LastPassProvider.LastPassError.severalMatches(exact.count)
        }
        // THE ONE DEVIATION FROM BITWARDEN'S PICKER, and it is deliberate: an entry
        // that names NO username cannot contradict the one the VPN's profile names.
        // A LastPass entry holding only a password is entirely ordinary, and telling
        // somebody "no entry has the username you typed" about one is both true and
        // useless — the username they typed IS the answer, and `resolve` uses it.
        // Only after an exact match has been looked for, so a real username still
        // wins, and still an error when two of them are equally anonymous.
        let anonymous = usable.filter { ($0.username ?? "").isEmpty }
        if anonymous.count == 1 { return anonymous[0] }
        if anonymous.count > 1 {
            throw LastPassProvider.LastPassError.severalMatches(anonymous.count)
        }
        throw LastPassProvider.LastPassError.wrongAccount(account)
    }
}

// MARK: - The channel seam

/// How this Mac talks to LastPass. One implementation ships (the CLI — LastPass has
/// no other local channel: no daemon, no socket of its own we may use, and an agent
/// that deliberately refuses to talk to anything but `lpass`). Tests inject a second
/// with no `lpass` present at all.
nonisolated protocol LastPassChannel: Sendable {
    /// Whether the tool reports a live session. `true` = signed in with a live
    /// agent; `false` = it said no; `nil` = it could not be asked at all (no tool we
    /// may run, or it never answered). The three are kept apart because "we could
    /// not ask" is not "you are not signed in".
    func statusSaysSignedIn() async -> Bool?
    /// One entry, chosen by the reference and — when given — the username.
    func entry(reference: String, account: String) async throws -> LastPassEntry
}

// MARK: - The `lpass` CLI

nonisolated struct LastPassCLIClient: LastPassChannel {

    var home: LastPassHome
    /// Injected so every path — every state, every failure, and the assertion that
    /// no argument ever carries a secret and `--clip` is never among them — is
    /// driven by fixtures with no `lpass` installed.
    var run: @Sendable (_ arguments: [String], _ environment: [String: String]) async -> LocalToolResult

    init(home: LastPassHome = .standard(),
         run: (@Sendable (_ arguments: [String], _ environment: [String: String]) async -> LocalToolResult)? = nil) {
        self.home = home
        self.run = run ?? LastPassCLIClient.liveRun
    }

    /// Where `lpass` is, if anywhere. Resolved against `LocalToolRunner`'s
    /// allow-list — never `PATH`, and never a second copy of those rules. Homebrew's
    /// `lastpass-cli` formula and MacPorts both land in directories the allow-list
    /// already covers; a source build with a custom prefix is what
    /// `signin.tool.lpass.path` is for.
    static func locate() -> String? { LocalToolRunner.locate("lpass") }

    static let liveRun: @Sendable ([String], [String: String]) async -> LocalToolResult = { arguments, environment in
        guard let executable = locate() else {
            return LocalToolResult(exitCode: -1, stdout: Data(),
                                   stderr: "not an approved tool location", timedOut: false)
        }
        return await LocalToolRunner.run(executable: executable, arguments: arguments,
                                         deadline: 20, environment: environment)
    }

    /// The child's environment. The runner's own built-from-scratch set (nothing
    /// inherited) plus four entries, each one a decision:
    ///
    ///  • `LPASS_HOME` — pinned to the directory we PROBED, so the process we run
    ///    and the files we looked at can never disagree.
    ///  • `LPASS_DISABLE_PINENTRY=1` — a graphical master-password dialog must never
    ///    appear from a background refresh. With this set, `password_prompt` takes
    ///    the standard-input path, which is `/dev/null`, so it fails at once.
    ///  • `LPASS_AGENT_DISABLE` is DELIBERATELY ABSENT. Setting it would stop the
    ///    agent being used, which is the one thing that makes this source work
    ///    without a prompt.
    ///  • `LPASS_CLIPBOARD_COMMAND=/usr/bin/true` — defence in depth only. If a
    ///    `--clip` somehow reached the tool despite the alias guard, the password
    ///    would be piped into a program that reads nothing rather than onto the
    ///    pasteboard. It is NOT the guard: `$LPASS_HOME/env` can override any of
    ///    these (`load_saved_environment` uses `setenv(…, overwrite: true)`).
    static func childEnvironment(
        home: LastPassHome,
        userHome: URL = FileManager.default.homeDirectoryForCurrentUser
    ) -> [String: String] {
        var environment = LocalToolRunner.childEnvironment(home: userHome)
        environment["LPASS_HOME"] = home.directory
        environment["LPASS_DISABLE_PINENTRY"] = "1"
        environment["LPASS_CLIPBOARD_COMMAND"] = "/usr/bin/true"
        return environment
    }

    /// `lpass status --quiet`: exit 0 when the agent holds the key, exit 1 when it
    /// does not (`cmd_status.c`). `--quiet` on purpose — without it the tool prints
    /// the signed-in email address on stdout, and there is no reason for an
    /// availability probe to read somebody's address.
    ///
    /// PROMPT-FREE BY CONSTRUCTION: `cmd_status` calls `agent_ask` and NOT
    /// `agent_get_decryption_key`, so it never reaches `agent_load_key` and can
    /// never ask for a master password. That is what makes it usable as a liveness
    /// probe at all.
    ///
    /// THE ONE THING IT DOES NOT MEAN: exit 1 is not "you have never signed in". It
    /// is "no agent is holding a key right now", which also covers an agent that has
    /// timed out and the `--plaintext-key` setup, where no agent is ever started.
    /// `LastPassAvailabilityRules` is where those are told apart, from the files.
    func statusSaysSignedIn() async -> Bool? {
        let result = await run(["status", "--quiet", "--color=never"],
                              Self.childEnvironment(home: home))
        if result.timedOut { return nil }
        switch result.exitCode {
        case 0: return true
        case 1: return false
        default: return nil       // couldn't start, or something we don't recognise
        }
    }

    /// The arguments for one read, as a pure function so a test can assert what
    /// rides argv without running anything.
    ///
    /// Every flag is load-bearing:
    ///  • `--sync=no` — a connect must never wait on LastPass's servers, and must
    ///    never upload. The tool reads its local cache. The cost is stated in the
    ///    copy: a password changed in the browser needs one `lpass sync`.
    ///  • `--expand-multi` — without it, two entries sharing a name make the tool
    ///    print prose and exit ZERO. With it we get both and disambiguate ourselves.
    ///  • `--json` — the whole entry in one parse, so username and password come
    ///    from ONE read rather than two (two reads could straddle a vault change).
    ///  • `--color=never` — colour escapes in the middle of a password would be a
    ///    corrupted password. The tool only colours a tty, and ours is a pipe, but
    ///    saying so costs nothing and removes the assumption.
    ///  • `--` — the reference is the user's own text and may begin with a dash.
    ///  • NO `-c`, NO `--clip`, EVER. The guard for the alias that could add one is
    ///    `LastPassShowAlias`.
    static func showArguments(reference: String) -> [String] {
        ["show", "--sync=no", "--expand-multi", "--json", "--color=never", "--", reference]
    }

    func entry(reference: String, account: String) async throws -> LastPassEntry {
        let result = await run(Self.showArguments(reference: reference),
                              Self.childEnvironment(home: home))
        if result.timedOut { throw LastPassProvider.LastPassError.timedOut }
        guard result.succeeded else {
            // stderr ONLY, already scrubbed by the runner. stdout may hold a
            // password and is never quoted.
            throw LastPassWire.error(stderr: result.stderr)
        }
        let entries = try LastPassWire.entries(result.stdout)
        return try LastPassEntryPicker.pick(entries, account: account, reference: reference)
    }
}

// MARK: - The provider

nonisolated struct LastPassProvider: CredentialProvider {
    let id = "lastpass"
    let displayName = "LastPass"
    /// The entry's name — its own name, or its full path including groups
    /// ("Work/VPN/GR Lab"), or LastPass's numeric id. EXACT MATCHING ONLY: the tool
    /// offers `--fixed-strings` and `--basic-regexp` and SimpleVPN passes neither,
    /// because a substring or a regular expression can quietly match a different
    /// entry, and reading the wrong sign-in is worse than failing to read one.
    let reference: String
    /// Optional: which login to take when several entries share a name.
    var account: String = ""
    /// Injectable so the whole resolve path runs with no LastPass anywhere.
    var channel: any LastPassChannel = LastPassCLIClient()
    /// The cheap facts, so a fetch can refuse BEFORE spawning anything when an
    /// alias would send the password to the pasteboard.
    var homeFacts: @Sendable () -> LastPassHomeFacts = { LastPassHomeProbe().facts() }

    private static let log = Logger(subsystem: "com.bragi0.SimpleVPN", category: "lastpass")

    func isAvailable(for profile: String) async -> Bool {
        guard !reference.trimmingCharacters(in: .whitespaces).isEmpty else { return false }
        guard !homeFacts().showDivertsToClipboard else { return false }
        return await channel.statusSaysSignedIn() == true
    }

    func resolve(profile: String, fields: Set<CredentialField>) async throws -> RawCredentials {
        let ref = reference.trimmingCharacters(in: .whitespaces)
        guard !ref.isEmpty else { throw LastPassError.noEntry }
        // Checked first, and before anything is spawned: with a diverting alias in
        // place the tool would put the password on the pasteboard and print nothing,
        // so running it would be worse than useless.
        guard !homeFacts().showDivertsToClipboard else { throw LastPassError.clipboardAlias }
        let entry = try await channel.entry(reference: ref,
                                            account: account.trimmingCharacters(in: .whitespaces))
        guard let password = entry.password, !password.isEmpty else {
            throw LastPassError.noPassword(ref)
        }
        var raw = RawCredentials()
        // Only what was ASKED FOR. Handing back a field nobody requested is a secret
        // travelling further than it had to, and the store-backed provider already
        // works this way.
        if fields.contains(.username) {
            let wanted = account.trimmingCharacters(in: .whitespaces)
            // The ENTRY's username is the authority; the one typed into the profile
            // fills in for an entry that holds only a password (see
            // `LastPassEntryPicker`, which is what lets such an entry be picked at
            // all).
            raw.username = (entry.username?.isEmpty == false) ? entry.username
                                                              : (wanted.isEmpty ? nil : wanted)
        }
        if fields.contains(.password) { raw.password = password }
        // NOTHING IS SET FOR `.otp`, DELIBERATELY. LastPass's command-line tool has
        // no code and no seed to give: `account_to_json_field` writes no such field
        // and there is no `lpass totp`. Guessing one out of `note` would be reading a
        // free-text field as a secret, which is how a wrong code gets frozen for
        // ever. The code is typed. See this file's header.
        Self.log.log("lastpass entry resolved for \(profile, privacy: .public)")
        return raw
    }

    /// Everything that can go wrong, in the user's words. NOTHING here interpolates
    /// a secret: the entry reference and the username are the user's own labels, a
    /// count of matches is a number, and any text from the tool arrives already
    /// scrubbed and truncated by `LocalToolRunner`.
    nonisolated enum LastPassError: LocalizedError, Equatable {
        case noEntry
        case notSignedIn
        /// Signed in once, but nothing is holding the key now — the agent has timed
        /// out (an hour by default). Deliberately NOT `notSignedIn`: the fix is a
        /// different command and telling somebody who signed in this morning that
        /// they never did is how they conclude the app cannot see their vault.
        case agentAsleep
        /// The entry is marked "require password reprompt" in LastPass. `cmd_show.c`
        /// calls `agent_load_key` for those REGARDLESS of the agent, which means a
        /// master-password prompt — and SimpleVPN does not own that prompt.
        case entryNeedsReprompt
        /// An alias would send the password to the pasteboard.
        case clipboardAlias
        case notFound(String)
        case severalMatches(Int)
        case noPassword(String)
        case wrongAccount(String)
        case timedOut
        case emptyAnswer
        case unreadable(String)

        var errorDescription: String? {
            switch self {
            case .noEntry:
                "No LastPass entry is set for this VPN \u{2014} add the entry\u{2019}s name or its id."
            case .notSignedIn:
                "LastPass isn\u{2019}t signed in on this Mac. Open Terminal and run "
                + "\u{201C}lpass login you@example.com\u{201D}."
            case .agentAsleep:
                "LastPass has forgotten your master password, so its tool can\u{2019}t read your "
                + "vault. Open Terminal and run \u{201C}lpass login you@example.com\u{201D} again. "
                + "To be asked less often, set LPASS_AGENT_TIMEOUT to 0."
            case .entryNeedsReprompt:
                "That LastPass entry asks for your master password every time it is read, and "
                + "SimpleVPN never asks for it. Turn off \u{201C}Require Password Reprompt\u{201D} "
                + "on that entry, or point this VPN at one that doesn\u{2019}t use it."
            case .clipboardAlias:
                "SimpleVPN won\u{2019}t read your LastPass entry while your `alias.show` file adds "
                + "\u{201C}-c\u{201D}: that copies the password to the clipboard instead of giving "
                + "it to SimpleVPN. Remove the -c from ~/.lpass/alias.show."
            case .notFound(let ref):
                ref.isEmpty
                    ? "LastPass has no entry matching what this VPN points at."
                    : "LastPass has no entry named \u{201C}\(ref)\u{201D}. The name has to match "
                      + "exactly \u{2014} include its folders, like Work/VPN/GR Lab."
            case .severalMatches(let count):
                (count > 0 ? "\(count) LastPass entries match" : "Several LastPass entries match")
                + " \u{2014} paste the entry\u{2019}s id instead of its name, or set the username "
                + "so SimpleVPN knows which one you mean."
            case .noPassword(let ref):
                "The LastPass entry \u{201C}\(ref)\u{201D} has no password in it."
            case .wrongAccount(let account):
                "No LastPass entry matching this VPN has the username \u{201C}\(account)\u{201D} "
                + "\u{2014} clear the username, or point this VPN at the right entry."
            case .timedOut:
                "LastPass didn\u{2019}t answer in time."
            case .emptyAnswer:
                "LastPass answered with nothing at all."
            case .unreadable(let detail):
                detail.isEmpty ? "LastPass couldn\u{2019}t provide the sign-in."
                               : "LastPass couldn\u{2019}t provide the sign-in: \(detail)"
            }
        }
    }
}

// MARK: - The four states, as a pure function

/// WHICH of the four availability states LastPass is in, decided from facts rather
/// than from a chain of `if`s inside a scan — so every state, including the two
/// that need a `~/.lpass` nobody here has, is a unit test.
///
/// The ordering is the design. A missing tool beats everything, because nothing else
/// can be attempted without it. The clipboard alias beats every session state,
/// because a fetch would succeed at putting the password somewhere it must not be.
/// Only then do the session states apply.
nonisolated enum LastPassAvailabilityRules {

    /// The cheap answer: file checks only, no subprocess, no prompt.
    static func quick(toolIsRunnable: Bool,
                      foundOutsideAllowList: Bool,
                      appIsInstalled: Bool,
                      home: LastPassHomeFacts) -> LocalVaultAvailability {
        guard toolIsRunnable else {
            // Before saying "not installed", ASK. Discovery searches every location
            // any package manager or vendor installer uses — plus `PATH`, which the
            // execution side will never consult — so it can tell "you don't have
            // `lpass`" apart from "you have `lpass` somewhere we won't run from".
            // Only one of those is a thing to install.
            if foundOutsideAllowList { return .blocked(.toolOutsideAllowList) }
            // The LastPass app on its own is not a read path — it is only the signal
            // that this person uses LastPass. So is a `~/.lpass` from an older
            // install: somebody who has used the tool before should be told to
            // reinstall it, not told they don't use LastPass.
            return (appIsInstalled || home.hasSignedInBefore) ? .blocked(.toolMissing)
                                                              : .notInstalled
        }
        if home.showDivertsToClipboard { return .blocked(.toolDivertsSecretToClipboard) }
        guard home.hasSignedInBefore || home.keyIsOnDisk else {
            return .blocked(.notSignedIn)
        }
        // Signed in at some point. Whether anything is holding the key NOW needs a
        // real `lpass status`, which is the deep scan — so the cheap pass says the
        // check is owed rather than accusing anybody of anything.
        //
        // …except with the key on disk, where `lpass status` is known to answer
        // "Not logged in" while reads work perfectly (`agent_start` returns early
        // when `plaintext_key` exists). That still cannot be PROVEN without a read,
        // so it is `.unchecked` too — with a different note.
        return home.agentSocketExists || home.keyIsOnDisk ? .unchecked
                                                          : .blocked(.vaultLocked)
    }

    /// The deep answer. `statusSaysSignedIn` is `nil` when the tool could not be
    /// asked, in which case whatever the cheap pass established stands: "we
    /// couldn't ask" is not "you aren't signed in".
    static func deep(quick: LocalVaultAvailability,
                     statusSaysSignedIn: Bool?,
                     home: LastPassHomeFacts) -> LocalVaultAvailability {
        // Nothing to refine when the problem is upstream of a session.
        switch quick {
        case .notInstalled,
             .blocked(.toolMissing),
             .blocked(.toolOutsideAllowList),
             .blocked(.toolDivertsSecretToClipboard):
            return quick
        default:
            break
        }
        guard let signedIn = statusSaysSignedIn else { return quick }
        if signedIn { return .ready }
        // The tool said no. With the key on disk that answer is known to be wrong
        // about whether a READ would work, so the honest state is "reachable,
        // unproven" rather than "locked".
        if home.keyIsOnDisk { return .unchecked }
        return home.hasSignedInBefore ? .blocked(.vaultLocked) : .blocked(.notSignedIn)
    }
}

// MARK: - The adapter

/// LastPass's row in the sign-in chooser. Four states, and the middle two are the
/// reason the enablement banner exists:
///   1. `lpass` here with a live agent → a source SimpleVPN fetches from.
///   2. Signed in but its agent has forgotten (an hour is the default) → offered,
///      with the one command that fixes it. Or: an `alias.show` that would divert
///      the password to the pasteboard → offered, with the one line to delete.
///   3. `lpass` here, never signed in → offered, with the sign-in command. Or:
///      `lpass` demonstrably installed somewhere we will not run from → offered,
///      with the path to paste. Or: the LastPass APP here but no `lpass` → offered,
///      with the install command. SimpleVPN never installs it.
///   4. Nothing LastPass on this Mac → not offered at all.
///
/// `quickScan` does file checks only. Whether a session is live needs a real
/// `lpass status`, which is the deep scan — and which is deliberately NOT run on a
/// Mac with no `~/.lpass`, because `config_path_for_type` CREATES that directory
/// (`mkdir(config, 0700)`) on any invocation. A probe must not leave a folder in
/// somebody's home directory to find out they don't use LastPass.
///
/// It lives in this file rather than in `LocalVaultAdapters.swift` on purpose: one
/// vendor is one file plus a one-line registry entry, so several vendors landing at
/// once do not collide in the same switch.
nonisolated struct LastPassVaultAdapter: LocalVaultAdapter {
    let vendor = LocalVaultVendor.lastPass
    let storedKind = CredentialSourceKind.lastPass
    /// `.cli`, and only `.cli`. LastPass has no other local channel: no loopback
    /// service, no documented socket for us, and an agent that refuses any peer
    /// whose executable is not `lpass` itself.
    let transports: [LocalVaultTransport] = [.cli]

    /// The LastPass desktop app, which is NOT a read path.
    static let appBundleIDs = ["com.lastpass.LastPass", "com.lastpass.lastpassmacdesktop"]

    static var isAppInstalled: Bool {
        appBundleIDs.contains { NSWorkspace.shared.urlForApplication(withBundleIdentifier: $0) != nil }
    }

    /// Injectable for tests; the shipped values talk to the real tool and the real
    /// `~/.lpass`.
    var channel: any LastPassChannel = LastPassCLIClient()
    var homeFacts: @Sendable () -> LastPassHomeFacts = { LastPassHomeProbe().facts() }

    func quickScan() -> LocalVaultAvailability {
        LastPassAvailabilityRules.quick(
            toolIsRunnable: LastPassCLIClient.locate() != nil,
            foundOutsideAllowList: LocalVaultRegistry.toolFoundOutsideAllowList("lpass") != nil,
            appIsInstalled: Self.isAppInstalled,
            home: homeFacts())
    }

    func deepScan(quick: LocalVaultAvailability) async -> LocalVaultAvailability {
        let facts = homeFacts()
        // Do not spawn `lpass` on a Mac that has never used it: the tool creates its
        // own configuration directory on ANY invocation, so asking would leave
        // ~/.lpass behind as the price of learning nothing.
        guard facts.directoryExists else {
            return LastPassAvailabilityRules.deep(quick: quick, statusSaysSignedIn: nil,
                                                  home: facts)
        }
        // Nothing to probe when the problem is the tool itself — and probing a tool
        // the allow-list declined would mean executing exactly the binary it
        // declined.
        switch quick {
        case .notInstalled, .blocked(.toolMissing), .blocked(.toolOutsideAllowList),
             .blocked(.toolDivertsSecretToClipboard):
            return quick
        default:
            break
        }
        let status = await channel.statusSaysSignedIn()
        return LastPassAvailabilityRules.deep(quick: quick, statusSaysSignedIn: status,
                                              home: facts)
    }

    func provider(for source: CredentialSource) -> (any CredentialProvider)? {
        guard !source.reference.trimmingCharacters(in: .whitespaces).isEmpty else { return nil }
        return LastPassProvider(reference: source.reference, account: source.account)
    }
}
