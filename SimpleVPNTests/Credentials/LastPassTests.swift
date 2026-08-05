// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
//  LastPassTests.swift
//  Fixture tests for the LastPass sign-in source. ALL of them run on a Mac with no
//  `lpass`, no LastPass account and no `~/.lpass`, which is the machine this was
//  written on — so every fixture below is cited to where it came from, and there is
//  no live half at all.
//
//  FIXTURE PROVENANCE. Every string, exit code and file name here was taken from
//  `lastpass/lastpass-cli` at the default branch, read on 2026-08-05:
//
//   • `lpass.1.txt` — the man page: the `show` synopsis and its whole option list,
//     the agent's one-hour default and `LPASS_AGENT_TIMEOUT`, the alias mechanism
//     (including its own `show --password -c` example), the clipboard section, the
//     configuration-directory precedence, and the `lpass show -p email` example
//     whose output shape the JSON fixtures mirror.
//   • `cmd-status.c` — `cmd_status` returns 1 and prints "Not logged in." when
//     `agent_ask` fails, else returns 0 and prints "Logged in as <username>.".
//   • `cmd-show.c` — the "Multiple matches found." branch and its
//     `exit(EXIT_SUCCESS)`; the `pwprotect` reprompt and its two `die` strings; the
//     `if (!clip)` guard on printing.
//   • `agent.c` — `agent_ask` vs `agent_get_decryption_key`; `agent_load_key`'s
//     prompt; `agent_start` returning early when `plaintext_key` exists;
//     `agent_run`'s uid/gid/executable check; `alarm(agent_timeout)`.
//   • `json-format.c` — `account_to_json_field`, which is the complete list of
//     fields LastPass's tool can hand over. It contains NO verification code, which
//     is why `suppliesOTP` is false and why the provider sets nothing for `.otp`.
//   • `config.c` — `pathname_type_lookup` (the file names `blob`, `iterations`,
//     `username`, `verify`, `plaintext_key`, `agent.sock`, …) and
//     `config_path_for_type`, which `mkdir`s the directory on any invocation.
//   • `lpass.c` — `expand_aliases` prepending `alias.<command>`, and
//     `load_saved_environment` applying `$LPASS_HOME/env` with overwrite.
//   • `password.c` — `password_prompt`: `LPASS_ASKPASS` first, then
//     `LPASS_DISABLE_PINENTRY=1` → `password_prompt_fallback`, which reads stdin.
//   • `util.c` — `die` writes "Error: …" to stderr and `exit(1)`.
//
//  NOTHING HERE CLAIMS A LIVE RUN. No real vault has answered, no agent has been
//  asked for a key, and no VPN has connected with it. `FeatureMaturity` says the
//  same in machine-readable form.
//

import Foundation
import Testing
@testable import SimpleVPN

// MARK: - Stubs

/// The process boundary, recorded. Every argument list and every environment the
/// provider builds is captured, so "no secret in argv" and "never `--clip`" are
/// assertions rather than intentions.
private nonisolated final class RunLog: @unchecked Sendable {
    var arguments: [[String]] = []
    var environments: [[String: String]] = []
}

private nonisolated struct StubRunner: Sendable {
    var log = RunLog()
    var results: [LocalToolResult]

    func run(_ arguments: [String], _ environment: [String: String]) -> LocalToolResult {
        log.arguments.append(arguments)
        log.environments.append(environment)
        let index = min(log.arguments.count - 1, results.count - 1)
        return results.isEmpty
            ? LocalToolResult(exitCode: -1, stdout: Data(), stderr: "", timedOut: false)
            : results[index]
    }
}

private nonisolated func client(_ results: [LocalToolResult],
                    home: LastPassHome = LastPassHome(directory: "/tmp/nowhere/.lpass"))
    -> (LastPassCLIClient, RunLog) {
    let stub = StubRunner(results: results)
    let log = stub.log
    return (LastPassCLIClient(home: home, run: { args, env in stub.run(args, env) }), log)
}

private nonisolated func ok(_ text: String) -> LocalToolResult {
    LocalToolResult(exitCode: 0, stdout: Data(text.utf8), stderr: "", timedOut: false)
}
private nonisolated func failed(_ stderr: String, code: Int32 = 1) -> LocalToolResult {
    LocalToolResult(exitCode: code, stdout: Data(), stderr: stderr, timedOut: false)
}
private nonisolated let cannotRun = LocalToolResult(exitCode: -1, stdout: Data(),
                                        stderr: "not an approved tool location", timedOut: false)
private nonisolated let neverAnswered = LocalToolResult(exitCode: 0, stdout: Data(), stderr: "",
                                            timedOut: true)

/// One account, in exactly the shape `json_format_account_list` emits: a bare array
/// of objects whose keys are `account_to_json_field`'s, two-space indented, with the
/// vendor's own trailing-space-before-newline quirk left in so the parser is proven
/// against the real byte shape rather than a tidied one.
private nonisolated func jsonEntry(name: String = "Work/VPN/GR Lab",
                       username: String = "jim",
                       password: String = "s3cr3t-vpn",
                       id: String = "140613939481239829",
                       group: String = "Work/VPN") -> String {
    """
    [
      {
        "id": "\(id)",
        "name": "\(name)",
        "fullname": "\(name)",
        "username": "\(username)",
        "password": "\(password)",
        "last_modified_gmt": "1732000000",
        "last_touch": "1732000100",
        "group": "\(group)",
        "url": "https://vpn.example.com",
        "note": ""
      }
    ]
    """
}

private nonisolated struct StubChannel: LastPassChannel {
    var signedIn: Bool?
    var entry: Result<LastPassEntry, LastPassProvider.LastPassError>

    func statusSaysSignedIn() async -> Bool? { signedIn }
    func entry(reference: String, account: String) async throws -> LastPassEntry {
        try entry.get()
    }
}

private nonisolated func facts(directory: Bool = true, signedIn: Bool = true, agent: Bool = true,
                   keyOnDisk: Bool = false, clipboard: Bool = false) -> LastPassHomeFacts {
    LastPassHomeFacts(directoryExists: directory, hasSignedInBefore: signedIn,
                      agentSocketExists: agent, keyIsOnDisk: keyOnDisk,
                      showDivertsToClipboard: clipboard)
}

// MARK: - The clipboard guard, which is the whole point of this feed's care

@Suite("LastPass — the clipboard alias guard")
struct LastPassClipboardGuardTests {

    /// The man page's own example is the first thing that must be caught: it writes
    /// `show --password -c`, and `getopt_long` reads a short cluster, so `-cp` is
    /// `-c -p`.
    @Test(arguments: ["show -c", "show --password -c", "show -cp", "show -pc",
                      "show --clip", "show --cl", "show --cli",
                      "  show   -c  ", "show\t-c", "show --password\n-c"])
    func everyShapeThatWouldDivertIsCaught(_ alias: String) {
        #expect(LastPassShowAlias.divertsToClipboard(alias),
                "\u{201C}\(alias)\u{201D} would put the password on the pasteboard")
    }

    /// And the false positives that would be just as wrong: `--color` shares a
    /// prefix with `clip`, so a naive "contains c" test would block a perfectly
    /// ordinary alias. `--c` is AMBIGUOUS and the tool rejects it itself, so it
    /// cannot divert either.
    @Test(arguments: ["show --color=never", "show --color never", "show --colour",
                      "show --c", "show --json", "show --sync=no", "show -x",
                      "show --expand-multi --json", "", "   ", "show"])
    func nothingElseIsCaught(_ alias: String) {
        #expect(!LastPassShowAlias.divertsToClipboard(alias),
                "\u{201C}\(alias)\u{201D} does not divert, and blocking it would be a false alarm")
    }

    /// `clip` and `color` both start `c`, so only a prefix that resolves to exactly
    /// one option counts — which is what `getopt_long` does.
    @Test func abbreviationsResolveTheWayGetoptDoes() {
        #expect(LastPassShowAlias.isClipFlag("--cl"))
        #expect(LastPassShowAlias.isClipFlag("--clip"))
        #expect(!LastPassShowAlias.isClipFlag("--c"))       // ambiguous with --color
        #expect(!LastPassShowAlias.isClipFlag("--co"))
        #expect(!LastPassShowAlias.isClipFlag("--color"))
    }

    /// The provider REFUSES rather than running the tool and hoping. Running it is
    /// what would leave the password on the pasteboard, so the refusal has to happen
    /// before the subprocess — and the assertion is that nothing was spawned.
    @Test func aDivertingAliasStopsTheFetchBeforeAnythingRuns() async {
        let (cli, log) = client([ok(jsonEntry())])
        let provider = LastPassProvider(
            reference: "Work/VPN/GR Lab", channel: cli,
            homeFacts: { facts(clipboard: true) })
        await #expect(throws: LastPassProvider.LastPassError.clipboardAlias) {
            try await provider.resolve(profile: "p", fields: [.username, .password])
        }
        #expect(log.arguments.isEmpty, "the tool must not be run at all")
        #expect(await provider.isAvailable(for: "p") == false)
    }

    /// And it is a first-class availability state with its own words, so somebody
    /// finds out in Settings rather than at connect time.
    @Test func theStateIsBlockedWithItsOwnSentence() {
        let state = LastPassAvailabilityRules.quick(
            toolIsRunnable: true, foundOutsideAllowList: false, appIsInstalled: true,
            home: facts(clipboard: true))
        #expect(state == .blocked(.toolDivertsSecretToClipboard))
        let copy = LocalVaultCopyBook.copy(for: .lastPass)
        #expect(copy.headline(for: .toolDivertsSecretToClipboard).lowercased().contains("clipboard"))
        #expect(!copy.steps(for: .toolDivertsSecretToClipboard).isEmpty)
        #expect(copy.guidance(for: .toolDivertsSecretToClipboard) != nil)
        #expect(LocalVaultBlock.toolDivertsSecretToClipboard.wantsEnablementBanner)
        // A report has to be able to say it too, or a maintainer sees a fetch that
        // returns nothing for no stated reason.
        #expect(DiagnosticReportInventory
            .stateWords(.blocked(.toolDivertsSecretToClipboard)).contains("clipboard"))
    }

    /// A diverting alias must also survive the deep scan unchanged: asking
    /// `lpass status` would tell us nothing we can act on, and the state is not
    /// about sessions.
    @Test func theDeepScanDoesNotArgueWithTheClipboardState() {
        let quick = LocalVaultAvailability.blocked(.toolDivertsSecretToClipboard)
        #expect(LastPassAvailabilityRules.deep(quick: quick, statusSaysSignedIn: true,
                                               home: facts(clipboard: true)) == quick)
    }
}

// MARK: - What rides argv, and what does not

@Suite("LastPass — the command line")
struct LastPassArgumentTests {

    /// Every flag, asserted, because each one is load-bearing and a silent removal
    /// changes behaviour in a way no other test would notice.
    @Test func theReadCommandIsExactlyWhatWasReasonedAbout() {
        let args = LastPassCLIClient.showArguments(reference: "Work/VPN/GR Lab")
        #expect(args.first == "show")
        // Never wait on LastPass's servers during a connect, and never upload.
        #expect(args.contains("--sync=no"))
        // Without this, two entries sharing a name print prose and exit ZERO.
        #expect(args.contains("--expand-multi"))
        #expect(args.contains("--json"))
        // Colour escapes inside a password would be a corrupted password.
        #expect(args.contains("--color=never"))
        // The reference is the user's text and may begin with a dash.
        #expect(args.contains("--"))
        #expect(args.last == "Work/VPN/GR Lab")
    }

    /// THE flag that must never appear, in any of its spellings.
    @Test func theClipFlagIsNeverPassed() {
        for reference in ["Work/VPN/GR Lab", "-c", "--clip", "140613939481239829"] {
            let args = LastPassCLIClient.showArguments(reference: reference)
            // `--` guarantees everything after it is an operand, so a reference that
            // looks like a flag cannot become one.
            let flags = args.prefix(while: { $0 != "--" })
            #expect(!flags.contains("-c"))
            #expect(!flags.contains("--clip"))
            #expect(!flags.contains(where: { LastPassShowAlias.isClipFlag($0) }))
        }
    }

    /// SimpleVPN passes neither of the tool's loose-matching options. A substring or
    /// regular-expression match could read a DIFFERENT entry, and reading the wrong
    /// sign-in is worse than reading none.
    @Test func matchingIsExactOnly() {
        let args = LastPassCLIClient.showArguments(reference: "GR Lab")
        for loose in ["-F", "--fixed-strings", "-G", "--basic-regexp"] {
            #expect(!args.contains(loose))
        }
    }

    /// The status probe is quiet on purpose: without `--quiet` the tool prints the
    /// signed-in email address, and an availability check has no business reading it.
    @Test func theStatusProbeAsksForNothingItDoesNotNeed() async {
        let (cli, log) = client([failed("", code: 1)])
        _ = await cli.statusSaysSignedIn()
        #expect(log.arguments.count == 1)
        #expect(log.arguments[0] == ["status", "--quiet", "--color=never"])
    }

    /// The environment: built, not inherited, plus exactly the entries reasoned
    /// about — and NOT `LPASS_AGENT_DISABLE`, which would defeat the whole design.
    @Test func theEnvironmentIsBuiltAndTheAgentIsLeftAlone() {
        let home = LastPassHome(directory: "/Users/someone/.lpass")
        let env = LastPassCLIClient.childEnvironment(
            home: home, userHome: URL(fileURLWithPath: "/Users/someone"))
        #expect(env["LPASS_HOME"] == "/Users/someone/.lpass")
        // A graphical master-password dialog must never appear from a background
        // refresh; with this set the prompt reads stdin, which is /dev/null.
        #expect(env["LPASS_DISABLE_PINENTRY"] == "1")
        // Defence in depth for a `--clip` that somehow got through the guard.
        #expect(env["LPASS_CLIPBOARD_COMMAND"] == "/usr/bin/true")
        // Setting this would stop the agent being used, which is the ONE thing that
        // makes this source work without a prompt.
        #expect(env["LPASS_AGENT_DISABLE"] == nil)
        // Nothing that could redirect the tool or load code into it.
        #expect(env["LPASS_ASKPASS"] == nil)
        #expect(env["LPASS_PINENTRY"] == nil)
        #expect(env["DYLD_INSERT_LIBRARIES"] == nil)
        #expect(env["PATH"] == "/usr/bin:/bin:/usr/sbin:/sbin")
    }

    /// Nothing secret reaches argv or the environment. Only the user's own labels do.
    @Test func noSecretIsEverHandedOverOnTheCommandLine() async throws {
        let (cli, log) = client([ok(jsonEntry(password: "s3cr3t-vpn"))])
        let provider = LastPassProvider(reference: "Work/VPN/GR Lab", account: "jim",
                                        channel: cli, homeFacts: { facts() })
        let raw = try await provider.resolve(profile: "p", fields: [.username, .password])
        #expect(raw.password == "s3cr3t-vpn")
        for args in log.arguments {
            #expect(!args.contains("s3cr3t-vpn"))
        }
        for env in log.environments {
            #expect(!env.values.contains("s3cr3t-vpn"))
        }
    }
}

// MARK: - Reading the tool's answers

@Suite("LastPass — the wire")
struct LastPassWireTests {

    @Test func theVendorsOwnJSONShapeIsRead() throws {
        let entries = try LastPassWire.entries(Data(jsonEntry().utf8))
        #expect(entries.count == 1)
        #expect(entries[0].id == "140613939481239829")
        #expect(entries[0].fullName == "Work/VPN/GR Lab")
        #expect(entries[0].username == "jim")
        #expect(entries[0].password == "s3cr3t-vpn")
        #expect(entries[0].group == "Work/VPN")
        #expect(entries[0].hasPassword)
    }

    /// THE TRAP. `cmd_show.c` prints this on STDOUT and then `exit(EXIT_SUCCESS)`.
    /// A caller trusting the exit code and taking stdout as the password would hand
    /// a VPN a line of prose, so this is checked even though `--expand-multi` should
    /// make it unreachable.
    @Test func multipleMatchesIsNeverMistakenForAPassword() {
        let stdout = """
        Multiple matches found.
        Work/VPN/GR Lab [id: 1]
        Home/VPN/GR Lab [id: 2]
        """
        #expect(throws: LastPassProvider.LastPassError.severalMatches(0)) {
            _ = try LastPassWire.entries(Data(stdout.utf8))
        }
    }

    @Test func nothingAtAllIsItsOwnAnswer() {
        #expect(throws: LastPassProvider.LastPassError.emptyAnswer) {
            _ = try LastPassWire.entries(Data())
        }
    }

    /// Something that is not JSON at all. The message must NOT quote stdout: stdout
    /// is secret-bearing by contract.
    @Test func unreadableOutputIsNeverQuoted() throws {
        do {
            _ = try LastPassWire.entries(Data("s3cr3t-vpn".utf8))
            Issue.record("should have thrown")
        } catch let error as LastPassProvider.LastPassError {
            #expect(!(error.errorDescription ?? "").contains("s3cr3t-vpn"))
        }
    }

    /// An object with nothing identifying in it is not an entry we found.
    @Test func emptyObjectsAreNotEntries() throws {
        #expect(try LastPassWire.entries(Data("[{}]".utf8)).isEmpty)
        #expect(try LastPassWire.entries(Data("[{\"note\": \"hi\"}]".utf8)).isEmpty)
    }

    /// Every `die` string the read path can produce, mapped to a state with a fix.
    /// The strings are the vendor's, from the files named in this file's header.
    @Test(arguments: [
        ("Error: Could not find decryption key. Perhaps you need to login with `lpass login`.",
         LastPassProvider.LastPassError.agentAsleep),
        ("Error: Could not authenticate for protected entry.",
         LastPassProvider.LastPassError.entryNeedsReprompt),
        ("Error: Current key is not on-disk key.",
         LastPassProvider.LastPassError.entryNeedsReprompt),
        ("Error: Could not find specified account(s).",
         LastPassProvider.LastPassError.notFound("")),
        ("Error: Could not find specified field 'foo'.",
         LastPassProvider.LastPassError.notFound("")),
    ])
    func theToolsOwnFailuresBecomeStatesWithFixes(
        _ pair: (String, LastPassProvider.LastPassError)
    ) {
        #expect(LastPassWire.error(stderr: pair.0) == pair.1)
    }

    /// Anything unrecognised is still safe: it is the runner's already-scrubbed
    /// stderr, and it never becomes a silent success.
    @Test func anUnknownFailureIsReportedRatherThanSwallowed() {
        let error = LastPassWire.error(stderr: "Error: something new in 1.7")
        #expect(error == .unreadable("Error: something new in 1.7"))
        #expect(!(error.errorDescription ?? "").isEmpty)
    }

    @Test func everyErrorHasASentenceAndNoneNamesASecret() {
        let all: [LastPassProvider.LastPassError] = [
            .noEntry, .notSignedIn, .agentAsleep, .entryNeedsReprompt, .clipboardAlias,
            .notFound(""), .notFound("Work/VPN/GR Lab"), .severalMatches(0), .severalMatches(3),
            .noPassword("Work/VPN/GR Lab"), .wrongAccount("jim"), .timedOut, .emptyAnswer,
            .unreadable(""), .unreadable("odd"),
        ]
        for error in all {
            let sentence = error.errorDescription ?? ""
            #expect(!sentence.isEmpty, "\(error) has no sentence")
            #expect(!sentence.contains("s3cr3t"))
        }
    }
}

// MARK: - Picking one entry

@Suite("LastPass — choosing between matches")
struct LastPassPickerTests {

    private func entry(_ username: String, password: String = "p") -> LastPassEntry {
        LastPassEntry(name: "GR Lab", fullName: "Work/VPN/GR Lab",
                      username: username, password: password)
    }

    @Test func oneMatchIsTheAnswer() throws {
        let picked = try LastPassEntryPicker.pick([entry("jim")], account: "", reference: "GR Lab")
        #expect(picked.username == "jim")
    }

    @Test func severalWithNoUsernameIsAnAmbiguityWithACount() {
        #expect(throws: LastPassProvider.LastPassError.severalMatches(2)) {
            _ = try LastPassEntryPicker.pick([entry("jim"), entry("other")],
                                             account: "", reference: "GR Lab")
        }
    }

    @Test func theUsernamePicksOneAndIsCaseInsensitive() throws {
        let picked = try LastPassEntryPicker.pick([entry("jim"), entry("other")],
                                                  account: "JIM", reference: "GR Lab")
        #expect(picked.username == "jim")
    }

    /// An entry that names NO username cannot contradict the one the VPN's profile
    /// names, so it is still a candidate — a LastPass entry holding only a password
    /// is entirely ordinary, and "no entry has the username you typed" about one
    /// would be true and useless. A real username still wins over an anonymous
    /// entry.
    @Test func anEntryWithNoUsernameStillMatchesATypedOne() throws {
        let anonymous = try LastPassEntryPicker.pick([entry("")], account: "typed",
                                                     reference: "GR Lab")
        #expect((anonymous.username ?? "").isEmpty)
        let realWins = try LastPassEntryPicker.pick([entry(""), entry("jim")], account: "jim",
                                                    reference: "GR Lab")
        #expect(realWins.username == "jim")
        // …and two equally anonymous entries are still an ambiguity, not a coin toss.
        #expect(throws: LastPassProvider.LastPassError.severalMatches(2)) {
            _ = try LastPassEntryPicker.pick([entry(""), entry("")], account: "typed",
                                             reference: "GR Lab")
        }
    }

    @Test func aUsernameNothingHasIsItsOwnSentence() {
        #expect(throws: LastPassProvider.LastPassError.wrongAccount("nobody")) {
            _ = try LastPassEntryPicker.pick([entry("jim")], account: "nobody",
                                             reference: "GR Lab")
        }
    }

    /// An entry with no password cannot sign anything in, so it is not a candidate —
    /// which is what stops a secure note of the same name being reported as an
    /// ambiguity.
    @Test func passwordlessEntriesAreNotCandidates() throws {
        let picked = try LastPassEntryPicker.pick([entry("note", password: ""), entry("jim")],
                                                  account: "", reference: "GR Lab")
        #expect(picked.username == "jim")
        #expect(throws: LastPassProvider.LastPassError.noPassword("GR Lab")) {
            _ = try LastPassEntryPicker.pick([entry("note", password: "")],
                                             account: "", reference: "GR Lab")
        }
    }

    @Test func nothingAtAllIsNotFoundRatherThanNoPassword() {
        #expect(throws: LastPassProvider.LastPassError.notFound("GR Lab")) {
            _ = try LastPassEntryPicker.pick([], account: "", reference: "GR Lab")
        }
    }
}

// MARK: - The cheap probe

@Suite("LastPass — the cheap probe")
struct LastPassHomeProbeTests {

    /// The file names are the tool's own (`pathname_type_lookup`, `config.c`), and
    /// getting one wrong would silently mean "never signed in" for everybody.
    @Test func theFileNamesAreTheToolsOwn() {
        let home = LastPassHome(directory: "/h/.lpass")
        #expect(home.usernameFile == "/h/.lpass/username")
        #expect(home.verifyFile == "/h/.lpass/verify")
        #expect(home.blobFile == "/h/.lpass/blob")
        #expect(home.agentSocket == "/h/.lpass/agent.sock")
        #expect(home.plaintextKeyFile == "/h/.lpass/plaintext_key")
        #expect(home.showAliasFile == "/h/.lpass/alias.show")
    }

    @Test func theStandardDirectoryIsWhereTheToolResolvesWithABuiltEnvironment() {
        let home = LastPassHome.standard(home: URL(fileURLWithPath: "/Users/someone"))
        #expect(home.directory == "/Users/someone/.lpass")
    }

    /// No directory means no questions asked: the probe stops rather than reporting
    /// five separate absences.
    @Test func noDirectoryMeansNothingElseIsClaimed() {
        let probe = LastPassHomeProbe(
            home: LastPassHome(directory: "/h/.lpass"),
            files: LastPassFileProbe(fileExists: { _ in true },
                                     directoryExists: { _ in false },
                                     readText: { _ in "show -c" }))
        #expect(probe.facts() == LastPassHomeFacts())
    }

    /// "Signed in before" needs `username` AND `verify`. Deliberately not `blob`
    /// alone — a cache can exist without a usable key, and using it would report a
    /// half-finished sign-in as a finished one.
    @Test func signedInBeforeNeedsBothFilesTheToolWritesOnSuccess() {
        func probe(_ present: Set<String>) -> LastPassHomeFacts {
            LastPassHomeProbe(
                home: LastPassHome(directory: "/h/.lpass"),
                files: LastPassFileProbe(fileExists: { present.contains($0) },
                                         directoryExists: { _ in true },
                                         readText: { _ in nil })).facts()
        }
        #expect(probe(["/h/.lpass/username", "/h/.lpass/verify"]).hasSignedInBefore)
        #expect(!probe(["/h/.lpass/username"]).hasSignedInBefore)
        #expect(!probe(["/h/.lpass/blob"]).hasSignedInBefore)
    }

    @Test func theAgentSocketAndTheOnDiskKeyAreSeenSeparately() {
        func probe(_ present: Set<String>) -> LastPassHomeFacts {
            LastPassHomeProbe(
                home: LastPassHome(directory: "/h/.lpass"),
                files: LastPassFileProbe(fileExists: { present.contains($0) },
                                         directoryExists: { _ in true },
                                         readText: { _ in nil })).facts()
        }
        #expect(probe(["/h/.lpass/agent.sock"]).agentSocketExists)
        #expect(!probe(["/h/.lpass/agent.sock"]).keyIsOnDisk)
        #expect(probe(["/h/.lpass/plaintext_key"]).keyIsOnDisk)
    }

    @Test func theAliasFileIsReadAndItsVerdictCarried() {
        let probe = LastPassHomeProbe(
            home: LastPassHome(directory: "/h/.lpass"),
            files: LastPassFileProbe(fileExists: { _ in true },
                                     directoryExists: { _ in true },
                                     readText: { $0 == "/h/.lpass/alias.show" ? "show -c" : nil }))
        #expect(probe.facts().showDivertsToClipboard)
    }
}

// MARK: - The four states

@Suite("LastPass — availability, all of it")
struct LastPassAvailabilityTests {

    /// Nothing LastPass at all: the row is not offered. That is the ONLY state in
    /// which a row is hidden.
    @Test func nothingAtAllIsNotOffered() {
        #expect(LastPassAvailabilityRules.quick(
            toolIsRunnable: false, foundOutsideAllowList: false, appIsInstalled: false,
            home: LastPassHomeFacts()) == .notInstalled)
    }

    /// The app is here but its tool is not: OFFERED, with the install command. The
    /// app alone is not a read path — it is the signal that this person uses
    /// LastPass.
    @Test func theAppWithoutTheToolIsSomethingToInstall() {
        #expect(LastPassAvailabilityRules.quick(
            toolIsRunnable: false, foundOutsideAllowList: false, appIsInstalled: true,
            home: LastPassHomeFacts()) == .blocked(.toolMissing))
    }

    /// A `~/.lpass` from an older install counts too: somebody who has used the tool
    /// before should be told to reinstall it, not told they don't use LastPass.
    @Test func anOldConfigurationDirectoryAlsoMeansInstallRatherThanAbsent() {
        #expect(LastPassAvailabilityRules.quick(
            toolIsRunnable: false, foundOutsideAllowList: false, appIsInstalled: false,
            home: facts(agent: false)) == .blocked(.toolMissing))
    }

    /// THE state ToolDiscovery exists for. "Not installed" would be a lie, and the
    /// person reading it goes off to install a second copy of what they have.
    @Test func foundButNotWhereWeWillRunFromIsItsOwnState() {
        #expect(LastPassAvailabilityRules.quick(
            toolIsRunnable: false, foundOutsideAllowList: true, appIsInstalled: false,
            home: LastPassHomeFacts()) == .blocked(.toolOutsideAllowList))
    }

    /// Tool here, nobody has ever signed in.
    @Test func theToolWithNoSignInIsNotSignedIn() {
        #expect(LastPassAvailabilityRules.quick(
            toolIsRunnable: true, foundOutsideAllowList: false, appIsInstalled: false,
            home: facts(signedIn: false, agent: false)) == .blocked(.notSignedIn))
    }

    /// Signed in, with a socket: the cheap pass says the check is OWED rather than
    /// accusing anybody. Whether an agent is LISTENING needs a real `lpass status`.
    @Test func signedInWithASocketIsUncheckedRatherThanReady() {
        #expect(LastPassAvailabilityRules.quick(
            toolIsRunnable: true, foundOutsideAllowList: false, appIsInstalled: false,
            home: facts()) == .unchecked)
    }

    /// Signed in and NO socket at all: the agent is gone, which is `vaultLocked` and
    /// deliberately not `notSignedIn` — the person did sign in, possibly this
    /// morning.
    @Test func signedInWithNoAgentIsLockedNotUnsignedIn() {
        #expect(LastPassAvailabilityRules.quick(
            toolIsRunnable: true, foundOutsideAllowList: false, appIsInstalled: false,
            home: facts(agent: false)) == .blocked(.vaultLocked))
    }

    /// The key on disk works with no agent and no prompt, so it is offered.
    @Test func anOnDiskKeyIsOfferedEvenWithNoAgent() {
        #expect(LastPassAvailabilityRules.quick(
            toolIsRunnable: true, foundOutsideAllowList: false, appIsInstalled: false,
            home: facts(signedIn: false, agent: false, keyOnDisk: true)) == .unchecked)
    }

    /// `lpass status` exit 0 is the only thing that makes this ready.
    @Test func aLiveSessionIsTheOnlyRoadToReady() {
        #expect(LastPassAvailabilityRules.deep(
            quick: .unchecked, statusSaysSignedIn: true, home: facts()) == .ready)
    }

    @Test func statusSayingNoResolvesToLockedOrNotSignedIn() {
        #expect(LastPassAvailabilityRules.deep(
            quick: .unchecked, statusSaysSignedIn: false, home: facts()) == .blocked(.vaultLocked))
        #expect(LastPassAvailabilityRules.deep(
            quick: .blocked(.notSignedIn), statusSaysSignedIn: false,
            home: facts(signedIn: false, agent: false)) == .blocked(.notSignedIn))
    }

    /// THE ONE PLACE THE TOOL LIES. `agent_start` returns early when
    /// `plaintext_key` exists, so no agent is ever started, so `lpass status` says
    /// "Not logged in" while reads work perfectly. Reporting `vaultLocked` there
    /// would send somebody to fix something that is not broken.
    @Test func statusIsNotBelievedWhenTheKeyIsOnDisk() {
        #expect(LastPassAvailabilityRules.deep(
            quick: .unchecked, statusSaysSignedIn: false,
            home: facts(signedIn: false, agent: false, keyOnDisk: true)) == .unchecked)
    }

    /// "We couldn't ask" is not "you aren't signed in".
    @Test func anUnaskableToolLeavesTheCheapAnswerAlone() {
        for quick in [LocalVaultAvailability.unchecked, .blocked(.vaultLocked),
                      .blocked(.notSignedIn)] {
            #expect(LastPassAvailabilityRules.deep(
                quick: quick, statusSaysSignedIn: nil, home: facts()) == quick)
        }
    }

    /// Nothing upstream of a session is argued with by the deep pass, and nothing is
    /// spawned for it either.
    @Test func theDeepScanNeverOverridesAToolProblem() {
        for quick in [LocalVaultAvailability.notInstalled, .blocked(.toolMissing),
                      .blocked(.toolOutsideAllowList),
                      .blocked(.toolDivertsSecretToClipboard)] {
            #expect(LastPassAvailabilityRules.deep(
                quick: quick, statusSaysSignedIn: true, home: facts()) == quick)
        }
    }

    /// A Mac that has never used `lpass` is never probed with a subprocess, because
    /// `config_path_for_type` `mkdir`s the configuration directory on ANY
    /// invocation. Leaving a folder in somebody's home directory to learn nothing is
    /// not a probe, it is litter.
    @Test func nothingIsSpawnedOnAMacWithNoLastPassState() async {
        let (cli, log) = client([ok("")])
        let adapter = LastPassVaultAdapter(channel: cli,
                                          homeFacts: { LastPassHomeFacts() })
        _ = await adapter.deepScan(quick: .blocked(.notSignedIn))
        #expect(log.arguments.isEmpty)
    }

    /// The adapter's declared facts, which the rest of the app reads rather than
    /// inferring.
    @Test func theAdapterDeclaresWhatItIs() {
        let adapter = LastPassVaultAdapter()
        #expect(adapter.vendor == .lastPass)
        #expect(adapter.storedKind == .lastPass)
        // No loopback service, no socket of its own we may use, and an agent that
        // refuses any peer that is not `lpass`. One transport, honestly.
        #expect(adapter.transports == [.cli])
        #expect(LocalVaultRegistry.adapter(for: LocalVaultVendor.lastPass) != nil)
        #expect(LocalVaultRegistry.adapter(for: CredentialSourceKind.lastPass)?.vendor == .lastPass)
    }

    /// A source naming no entry yields no provider, which routes to the typed fields
    /// rather than a doomed lookup.
    @Test func aSourceWithNoEntryBuildsNoProvider() {
        var source = CredentialSource()
        source.kind = .lastPass
        #expect(LastPassVaultAdapter().provider(for: source) == nil)
        source.reference = "   "
        #expect(LastPassVaultAdapter().provider(for: source) == nil)
        source.reference = "Work/VPN/GR Lab"
        #expect(LastPassVaultAdapter().provider(for: source) != nil)
    }
}

// MARK: - The status probe, over the process boundary

@Suite("LastPass — the status probe")
struct LastPassStatusTests {

    /// `cmd_status.c`: exit 0 = the agent holds the key.
    @Test func exitZeroMeansSignedIn() async {
        let (cli, _) = client([ok("Logged in as you@example.com.")])
        #expect(await cli.statusSaysSignedIn() == true)
    }

    /// Exit 1 = no agent is holding a key. NOT "you have never signed in" — which is
    /// why the files decide between those two elsewhere.
    @Test func exitOneMeansNoLiveSession() async {
        let (cli, _) = client([failed("Not logged in.", code: 1)])
        #expect(await cli.statusSaysSignedIn() == false)
    }

    /// Anything else — no tool we may run, a timeout, an exit code we don't
    /// recognise — is "could not ask", which is a third answer and not a false one.
    @Test func anythingElseIsCouldNotAsk() async {
        for result in [cannotRun, neverAnswered, failed("odd", code: 42)] {
            let (cli, _) = client([result])
            #expect(await cli.statusSaysSignedIn() == nil)
        }
    }
}

// MARK: - The provider

@Suite("LastPass — the provider")
struct LastPassProviderTests {

    @Test func aRealFetchReturnsTheUsernameAndPassword() async throws {
        let (cli, _) = client([ok(jsonEntry())])
        let provider = LastPassProvider(reference: "Work/VPN/GR Lab", channel: cli,
                                        homeFacts: { facts() })
        let raw = try await provider.resolve(profile: "p", fields: [.username, .password])
        #expect(raw.username == "jim")
        #expect(raw.password == "s3cr3t-vpn")
    }

    /// NO VERIFICATION CODE, EVER, and this is the assertion that pins it. The
    /// vendor's own JSON formatter has no field for one and there is no `lpass totp`,
    /// so the provider sets nothing rather than mining `note` for something that
    /// looks like a seed — which is how a wrong code gets frozen for ever.
    @Test func noCodeIsEverInventedOrMined() async throws {
        let withANoteThatLooksLikeASeed = """
        [
          {
            "id": "1",
            "name": "GR Lab",
            "fullname": "Work/VPN/GR Lab",
            "username": "jim",
            "password": "s3cr3t-vpn",
            "note": "otpauth://totp/GR?secret=JBSWY3DPEHPK3PXP"
          }
        ]
        """
        let (cli, _) = client([ok(withANoteThatLooksLikeASeed)])
        let provider = LastPassProvider(reference: "Work/VPN/GR Lab", channel: cli,
                                        homeFacts: { facts() })
        let raw = try await provider.resolve(profile: "p", fields: [.username, .password, .otp])
        #expect(raw.otp == nil)
        // And the promise the connect path reads says the same, so Connect asks for a
        // code rather than enabling itself and failing.
        #expect(CredentialSourceKind.lastPass.suppliesOTP == false)
    }

    /// The username in the VPN's own profile is a DISAMBIGUATOR, and this pins all
    /// four ways it can meet the entry — the middle one being the interesting one.
    @Test func theProfileUsernameDisambiguatesAndFillsInButNeverOverrides() async throws {
        // Nothing typed: the entry's own username is used.
        let (plain, _) = client([ok(jsonEntry(username: "jim"))])
        #expect(try await LastPassProvider(reference: "e", channel: plain,
                                           homeFacts: { facts() })
            .resolve(profile: "p", fields: [.username]).username == "jim")

        // Typed and agreeing: the same answer, and the entry was picked BY it.
        let (agreeing, _) = client([ok(jsonEntry(username: "jim"))])
        #expect(try await LastPassProvider(reference: "e", account: "JIM", channel: agreeing,
                                           homeFacts: { facts() })
            .resolve(profile: "p", fields: [.username]).username == "jim")

        // Typed and CONTRADICTING: reported, never silently resolved in the entry's
        // favour. Quietly signing in as somebody the user did not name is worse than
        // saying the two disagree.
        let (contradicting, _) = client([ok(jsonEntry(username: "jim"))])
        await #expect(throws: LastPassProvider.LastPassError.wrongAccount("typed")) {
            try await LastPassProvider(reference: "e", account: "typed", channel: contradicting,
                                       homeFacts: { facts() })
                .resolve(profile: "p", fields: [.username])
        }

        // The entry holds only a password: the typed username fills in, which is what
        // makes `LastPassEntryPicker`'s anonymous-entry branch worth having.
        let (anonymous, _) = client([ok(jsonEntry(username: ""))])
        #expect(try await LastPassProvider(reference: "e", account: "typed", channel: anonymous,
                                           homeFacts: { facts() })
            .resolve(profile: "p", fields: [.username]).username == "typed")
    }

    @Test func onlyTheRequestedFieldsComeBack() async throws {
        let (cli, _) = client([ok(jsonEntry())])
        let provider = LastPassProvider(reference: "e", channel: cli, homeFacts: { facts() })
        let raw = try await provider.resolve(profile: "p", fields: [.password])
        #expect(raw.password == "s3cr3t-vpn")
        #expect(raw.username == nil)
    }

    @Test func anEntryWithNoPasswordFailsRatherThanReturningNothing() async {
        let (cli, _) = client([ok(jsonEntry(password: ""))])
        let provider = LastPassProvider(reference: "Work/VPN/GR Lab", channel: cli,
                                        homeFacts: { facts() })
        await #expect(throws: LastPassProvider.LastPassError.noPassword("Work/VPN/GR Lab")) {
            try await provider.resolve(profile: "p", fields: [.password])
        }
    }

    @Test func noEntryNamedIsItsOwnRefusal() async {
        let (cli, log) = client([ok(jsonEntry())])
        let provider = LastPassProvider(reference: "  ", channel: cli, homeFacts: { facts() })
        await #expect(throws: LastPassProvider.LastPassError.noEntry) {
            try await provider.resolve(profile: "p", fields: [.password])
        }
        #expect(log.arguments.isEmpty)
        #expect(await provider.isAvailable(for: "p") == false)
    }

    /// A timeout is its own sentence, and the runner has already killed the child.
    @Test func aTimeoutIsSaidPlainly() async {
        let (cli, _) = client([neverAnswered])
        let provider = LastPassProvider(reference: "e", channel: cli, homeFacts: { facts() })
        await #expect(throws: LastPassProvider.LastPassError.timedOut) {
            try await provider.resolve(profile: "p", fields: [.password])
        }
    }

    /// The "Require Password Reprompt" case, which is the one entry shape this
    /// source can never read: `cmd_show.c` calls `agent_load_key` for it regardless
    /// of the agent, i.e. it prompts, and SimpleVPN does not own that prompt.
    @Test func aRepromptEntryFailsWithItsOwnExplanation() async {
        let (cli, _) = client([failed("Error: Could not authenticate for protected entry.")])
        let provider = LastPassProvider(reference: "e", channel: cli, homeFacts: { facts() })
        await #expect(throws: LastPassProvider.LastPassError.entryNeedsReprompt) {
            try await provider.resolve(profile: "p", fields: [.password])
        }
    }

    /// Availability is prompt-free and needs a live session AND an entry.
    @Test func availabilityNeedsBothAnEntryAndASession() async {
        let signedIn = StubChannel(signedIn: true, entry: .success(LastPassEntry()))
        let asleep = StubChannel(signedIn: false, entry: .success(LastPassEntry()))
        #expect(await LastPassProvider(reference: "e", channel: signedIn,
                                       homeFacts: { facts() }).isAvailable(for: "p"))
        #expect(await LastPassProvider(reference: "e", channel: asleep,
                                        homeFacts: { facts() }).isAvailable(for: "p") == false)
    }

    @Test func theProviderNamesItself() {
        let provider = LastPassProvider(reference: "e")
        #expect(provider.id == "lastpass")
        #expect(provider.displayName == "LastPass")
    }
}

// MARK: - The row, the copy, and the shared-file wiring

@Suite("LastPass — the row and its words")
struct LastPassRowTests {

    /// One signed-in account at a time, verified from the tool rather than assumed:
    /// `agent_save` writes a single `username` value and `login` overwrites it. A
    /// singular vendor must have no instance-level fields, which a shared test also
    /// asserts.
    @Test func theVendorIsSingleInstance() {
        #expect(LocalVaultVendor.lastPass.cardinality == .single)
        #expect(SignInSourceSettings.instanceFields(for: .lastPass).isEmpty)
        #expect(LocalVaultVendor.lastPass.settingSlug == "lastpass")
    }

    /// ONE transport-level field: where the tool is. Nothing else about LastPass can
    /// be configured, and a setting nothing reads is worse than a missing one.
    @Test func thereIsExactlyOneFieldAndItIsTheToolPath() {
        let fields = SignInSourceSettings.fields(for: .lastPass)
        #expect(fields.count == 1)
        #expect(fields[0].settingID == "creds.lastpass.tool-path")
        #expect(fields[0].defaultsKey == SignInSourceSettings.toolPathKey("lpass"))
        #expect(fields[0].level == .transport)
        #expect(fields[0].kind.detectionTool == "lpass")
        // The pane writes the key `LocalToolRunner` resolves — one notion of "the
        // path the user set", not a settings copy to keep in step.
        #expect(fields[0].defaultsKey == "signin.tool.lpass.path")
    }

    /// Discovery knows which row `lpass` serves, which is what decides who gets told
    /// "found at …, but not somewhere SimpleVPN will run it from".
    @Test func discoveryPointsTheToolAtThisRow() {
        #expect(ToolCatalog.tool(named: "lpass")?.vendor == .lastPass)
        #expect(ToolCatalog.tools(for: .lastPass).map(\.name) == ["lpass"])
        // No vendor installer path is asserted, on purpose: a guessed path presented
        // as a documented one sends people looking in the wrong place.
        #expect(ToolCatalog.tool(named: "lpass")?.vendorInstallerPaths.isEmpty == true)
    }

    /// The LastPass app alone points AT the way in rather than appearing as a second,
    /// dead row.
    @Test func theAppIsAPointerAtThisVendor() {
        #expect(PasswordAppCatalog.gatedVendor(forBundleID: "com.lastpass.LastPass") == .lastPass)
        #expect(PasswordAppCatalog.gatedVendor(forBundleID: "com.lastpass.anything-new")
                == .lastPass)
    }

    /// The enablement banner names the install command and the vendor's own page —
    /// and SimpleVPN installs nothing.
    @Test func theBannerShowsTheCommandAndThePage() {
        let copy = LocalVaultCopyBook.copy(for: .lastPass)
        #expect(copy.homebrewInstallCommand == "brew install lastpass-cli")
        #expect(copy.primaryDoc.url.absoluteString == "https://github.com/lastpass/lastpass-cli")
        let guidance = copy.guidance(for: .toolMissing)
        #expect(guidance?.example.first?.text == "brew install lastpass-cli")
        #expect(guidance?.doc.url.absoluteString == "https://github.com/lastpass/lastpass-cli")
        #expect(VendorDocs.all.contains(VendorDocs.lastPassCLI))
    }

    /// Every state this row can reach has a headline, and the ones the user can fix
    /// have guidance. A dead end with no sentence is the failure this whole shape
    /// exists to prevent.
    @Test func everyReachableStateHasWordsAndAFix() {
        let copy = LocalVaultCopyBook.copy(for: .lastPass)
        let reachable: [LocalVaultBlock] = [.toolMissing, .toolOutsideAllowList, .notSignedIn,
                                            .vaultLocked, .toolDivertsSecretToClipboard]
        for block in reachable {
            #expect(!copy.headline(for: block).isEmpty, "\(block) has no headline")
            let option = SignInSourceCatalog.vaultOption(
                .lastPass, availability: .blocked(block),
                foundOutsideAllowList: block == .toolOutsideAllowList ? "/Users/you/bin/lpass" : nil)
            #expect(option != nil)
            #expect(option?.guidance != nil, "\(block) offers no way forward")
        }
        #expect(copy.uncheckedNote != nil)
    }

    /// The two session states must READ differently, because being told you never
    /// signed in when you did is how somebody concludes the app cannot see their
    /// vault at all.
    @Test func lockedAndNotSignedInAreDifferentSentences() {
        let copy = LocalVaultCopyBook.copy(for: .lastPass)
        #expect(copy.headline(for: .vaultLocked) != copy.headline(for: .notSignedIn))
        #expect(copy.headline(for: .vaultLocked).lowercased().contains("forgotten"))
        #expect(copy.headline(for: .notSignedIn).lowercased().contains("signed in"))
    }

    /// The row sets expectations honestly: it says the code is typed, and it says the
    /// session expires. Both in text a user can read BEFORE relying on it.
    @Test func theCopySetsBestEffortExpectationsOnNamedPoints() {
        let copy = LocalVaultCopyBook.copy(for: .lastPass)
        let words = copy.explanation.lowercased()
        #expect(words.contains("verification code"))
        #expect(words.contains("best-effort"))
        #expect(words.contains("hour"))
        #expect(copy.uncheckedNote?.lowercased().contains("verification code") == true)
        // …and it does NOT print a version or a date, which would rot the moment the
        // vendor ships anything.
        #expect(!copy.explanation.contains("1.6"))
        #expect(!copy.explanation.contains("2024"))
        #expect(!copy.explanation.contains("2025"))
    }

    /// The good news is stated too, because it is the strongest thing about this
    /// source and the opposite of Bitwarden's local service.
    @Test func theCopySaysWhereTheMasterPasswordGoes() {
        let copy = LocalVaultCopyBook.copy(for: .lastPass)
        #expect(copy.explanation.contains("never sees your LastPass master password"))
    }

    /// The recovery sentence names the source (a shared test requires that for every
    /// kind) and stays plain text — no `code` spans, because it is rendered with a
    /// plain `Text(String)` and backticks would show up as backticks.
    @Test func theRecoverySentenceNamesLastPassAndCarriesNoMarkup() {
        let headline = SignInFlow.unavailableHeadline(.lastPass)
        #expect(headline.contains("LastPass"))
        #expect(headline.contains(CredentialSourceKind.lastPass.displayName))
        #expect(!headline.contains("`"))
    }

    /// Every string this row can put on screen or into VoiceOver, against the house
    /// glossary. The shared vocabulary test covers all vendors at once; this one
    /// exists so a LastPass-shaped mistake fails in a LastPass-shaped test too —
    /// `lpass login` is the obvious trap, and it belongs in a `code` span.
    @Test func nothingItSaysBreaksTheGlossary() {
        var facts = SignInSourceFacts()
        var strings: [String] = []
        for block in [LocalVaultBlock.toolMissing, .toolOutsideAllowList, .notSignedIn,
                      .vaultLocked, .toolDivertsSecretToClipboard] {
            facts.vaults[.lastPass] = .blocked(block)
            guard let option = SignInSourceCatalog.vaultOption(
                .lastPass, availability: .blocked(block)) else { continue }
            strings += [option.title, option.summary, option.explanation,
                        option.accessibilityStateValue,
                        SignInSourceCatalog.announcement(for: option)]
            if case .needsSetup(let headline, let steps) = option.state {
                strings += [headline] + steps
            }
        }
        strings.append(SignInFlow.unavailableHeadline(.lastPass))
        strings.append(LocalVaultCopyBook.copy(for: .lastPass).uncheckedNote ?? "")
        strings.append(SignInSourceSteps.stepTwoSummary(vendor: .lastPass))
        for text in strings {
            let plain = withoutCodeSpans(text)
            for word in ["credential", "log in", "login", "logon", "authenticate",
                         "one-time passcode"] {
                #expect(!plain.lowercased().contains(word),
                        "\u{201C}\(text)\u{201D} contains \u{201C}\(word)\u{201D}")
            }
            #expect(!plain.contains("OTP"), "\u{201C}\(text)\u{201D} says OTP")
        }
    }

    private func withoutCodeSpans(_ text: String) -> String {
        var out = ""
        var inCode = false
        for character in text {
            if character == "`" { inCode.toggle(); continue }
            if !inCode { out.append(character) }
        }
        return out
    }

    /// The maturity claim: `.untested`, like every other new feed, and NOT claimed by
    /// omission.
    @Test func theRowIsClaimedUntested() {
        #expect(FeatureMaturityRegistry.maturity(ofSource: .vault(.lastPass)) == .untested)
        #expect(FeatureMaturityRegistry.signInSources[.vault(.lastPass)] == .untested)
    }

    /// The diagnostic report can say every state this row reaches, in the same words
    /// the chooser uses.
    @Test func aReportCanNameEveryStateAndTheApp() {
        for block in [LocalVaultBlock.toolMissing, .toolOutsideAllowList, .notSignedIn,
                      .vaultLocked, .toolDivertsSecretToClipboard] {
            #expect(!DiagnosticReportInventory.stateWords(.blocked(block)).isEmpty)
        }
        #expect(DiagnosticReportInventory.vendorBundleIDs(.lastPass)
            .contains("com.lastpass.LastPass"))
    }
}
