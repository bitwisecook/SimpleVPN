// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
//  PassboltTests.swift
//  Fixture tests only, and that is stated up front rather than implied: PASSBOLT IS
//  NOT INSTALLED ON THIS MACHINE AND THERE IS NO PASSBOLT SERVER ANYWHERE NEAR IT.
//  Nothing here has ever talked to one, so nothing here claims to.
//
//  WHERE EVERY FIXTURE CAME FROM. Each is quoted from `passbolt/go-passbolt-cli`
//  itself, named per fixture so the provenance is checkable rather than asserted:
//
//   • `internal/cmd/root.go` — the root command's `Use: "passbolt"`, its persistent
//     flags (`--serverAddress`, `--userPrivateKey`, `--userPassword`, `--mfaMode`,
//     `--tlsSkipVerify`, `--config`, `--timeout`), viper's `AutomaticEnv()` with no
//     prefix, and `initConfig`'s config location (`os.UserConfigDir()` +
//     `go-passbolt-cli`, type `toml`, name `go-passbolt-cli`, mode 0600).
//   • `internal/util/client.go` — `util.ReadPassword` (a terminal prompt, else a
//     line from stdin), `GetClient`'s "serverAddress is not defined" and
//     "userPrivateKey is not defined", its `reading Password: %w` wrap, its
//     "verifying Server: %w" wrap, and `apiStatusHint`'s exact 401 / 403 / 404
//     sentences.
//   • `internal/util/http.go` — `InsecureSkipVerify: tlsSkipVerify`, i.e. the whole
//     of the TLS decision, which is why never emitting the flag is sufficient.
//   • `internal/cmd/resource/get.go` — `get resource --id`, `--json`.
//   • `internal/cmd/resource/list.go` and `internal/cmd/list.go` — `list resource`,
//     `-c/--column`, `-j/--json`, `--filter` (a CEL expression).
//   • `internal/cmd/resource/json.go` — the `ResourceJSONOutput` key names
//     (`id`, `name`, `username`, `uri`, `password`, `description`, `metadata`,
//     `secret`).
//   • `internal/testdata/01_v4_roundtrip.txtar` — a real `get resource --json`
//     shape, field by field.
//   • `internal/testdata/14_totp_resource.txtar` — the TOTP secret object, with the
//     seed `JBSWY3DPEHPK3PXP` this file reuses verbatim.
//   • `internal/testdata/43_error_missing_config.txtar` — `serverAddress is not
//     defined` on stderr, non-zero exit.
//   • `internal/testdata/44_error_resource_not_found.txtar` — a 404 for a
//     well-formed but nonexistent UUID, error on stderr and stdout left empty.
//   • `Formula/go-passbolt-cli.rb` in `passbolt/homebrew-tap` — `bin.install
//     "passbolt"`, which is why the formula and the binary have different names.
//
//  The Go-side text quoted here is the tool's own wording; those strings are
//  Passbolt's, not ours, so they keep their spelling.
//

import Foundation
import Testing
@testable import SimpleVPN

// MARK: - The injected process boundary

/// Records every invocation, so the tests can assert what was on the command line
/// as well as what came back. `@unchecked Sendable` around a class for the same
/// reason the password-store stub does it: a value type could not record.
private nonisolated final class PassboltCalls: @unchecked Sendable {
    var arguments: [[String]] = []
    var stdin: [String?] = []
    var last: [String] { arguments.last ?? [] }
    var flat: String { arguments.map { $0.joined(separator: " ") }.joined(separator: " | ") }
}

private nonisolated struct StubPassbolt: PassboltRunning {
    var installed = true
    /// Answers in order; the last one repeats, so a two-run path (list then get)
    /// can be scripted without the test caring how many runs happen.
    var results: [LocalToolResult]
    var calls = PassboltCalls()

    func locate() -> String? { installed ? "/opt/homebrew/bin/passbolt" : nil }

    func run(arguments: [String], passphrase: PassboltPassphrase?,
             deadline: TimeInterval) async -> LocalToolResult {
        calls.arguments.append(arguments)
        // Recorded as the BYTES that would reach the child's standard input, so the
        // assertions below can check the newline the tool requires as well as the
        // characters — the box has no other way out, which is the point of it.
        calls.stdin.append(passphrase.map { String(decoding: $0.stdinLine(), as: UTF8.self) })
        let index = min(calls.arguments.count - 1, results.count - 1)
        return results[index]
    }
}

private nonisolated func ok(_ text: String) -> LocalToolResult {
    LocalToolResult(exitCode: 0, stdout: Data(text.utf8), stderr: "", timedOut: false)
}
private nonisolated func fail(_ stderr: String, code: Int32 = 1) -> LocalToolResult {
    LocalToolResult(exitCode: code, stdout: Data(), stderr: stderr, timedOut: false)
}
private nonisolated let timedOut = LocalToolResult(exitCode: -1, stdout: Data(), stderr: "",
                                       timedOut: true)

/// A config file that has everything: address, key AND passphrase.
private nonisolated let fullySetUp = PassboltToolConfig(
    path: "/config.toml", exists: true,
    keys: ["serveraddress", "userprivatekey", "userpassword"])
/// Set up, but with no passphrase of its own — THE dormant state.
private nonisolated let noPassphrase = PassboltToolConfig(
    path: "/config.toml", exists: true, keys: ["serveraddress", "userprivatekey"])
/// Never set up.
private nonisolated let notSetUp = PassboltToolConfig(path: "/config.toml", exists: false)

private nonisolated let workServer = PassboltServerLocation(serverURL: "https://passbolt.example.com")

private nonisolated func reader(_ tool: StubPassbolt,
                   config: PassboltToolConfig = fullySetUp,
                   location: PassboltServerLocation = workServer,
                   weHold: Bool = false) -> PassboltReader {
    PassboltReader(location: location, tool: tool, toolConfig: { _ in config },
                   weHoldAPassphrase: weHold)
}

/// One resource, exactly as `get resource --json` prints it —
/// `internal/testdata/01_v4_roundtrip.txtar` field for field.
private nonisolated let v4ResourceJSON = """
{"id":"8f4b9c1e-2a7d-4f60-9c31-5e8a0b7d6c42","folder_parent_id":"",\
"name":"test-v4","username":"user-v4","uri":"https://v4.example.com",\
"password":"pass-v4","description":"v4 description","deleted":false,"expired":false}
"""

/// A v5 resource with a TOTP secret — `internal/testdata/14_totp_resource.txtar`,
/// including its seed.
private nonisolated let totpResourceJSON = """
{"id":"11111111-2222-3333-4444-555555555555","name":"test-totp",\
"password":"totp-pass","deleted":false,"expired":false,\
"metadata":{"name":"test-totp","username":"totp-user","uri":"https://totp.example.com"},\
"secret":{"password":"totp-pass",\
"totp":{"secret_key":"JBSWY3DPEHPK3PXP","algorithm":"SHA1","digits":6,"period":30}}}
"""

// MARK: - The two binary names

struct PassboltToolNamingTests {

    /// THE FACT THE BRIEF ASKED TO VERIFY, and it is not cosmetic: discovery
    /// searches by binary NAME. Homebrew's formula is `go-passbolt-cli`
    /// (`brew install passbolt/tap/go-passbolt-cli`) but its install block is
    /// `bin.install "passbolt"`, so the binary is `passbolt`. A `go install` of the
    /// module produces `go-passbolt-cli` instead. Both must be searched or one of
    /// two perfectly ordinary installs reports "not installed".
    @Test func bothInstalledNamesAreSearched() {
        #expect(PassboltCLI.toolNames == ["passbolt", "go-passbolt-cli"])
        for name in PassboltCLI.toolNames {
            let entry = ToolCatalog.tool(named: name)
            #expect(entry != nil, "\(name) is not in the discovery catalogue")
            // BOTH map to the vendor, so "found at …, but not somewhere SimpleVPN
            // will run it from" lands on the Passbolt row whichever one is present.
            #expect(entry?.vendor == .passbolt, "\(name) is not mapped to Passbolt")
        }
    }

    /// The settings row points at ONE of the names, and that is deliberate: two
    /// rows for one program would be two places to fix the same thing. A full path
    /// typed into it may legitimately end in the other name.
    @MainActor
    @Test func oneToolPathRowCoversBothNames() {
        let fields = SignInSourceSettings.fields(for: .passbolt)
        let toolRows = fields.filter { if case .toolBinary = $0.kind { true } else { false } }
        #expect(toolRows.count == 1)
        #expect(toolRows.first?.kind.detectionTool == "passbolt")
        #expect(toolRows.first?.defaultsKey == SignInSourceSettings.toolPathKey("passbolt"))
    }
}

// MARK: - The command line: what is on it, and what can never be

struct PassboltArgumentTests {

    /// THE SECURITY INVARIANT, asserted rather than commented. `--tlsSkipVerify` is
    /// the tool's own "allow self-signed certificates" flag and it is the only thing
    /// that decides `InsecureSkipVerify` in `internal/util/http.go`. There is no
    /// setting that could ask for it, so never emitting it is the whole control.
    @Test func certificateVerificationCanNeverBeSkipped() async {
        let tool = StubPassbolt(results: [ok(v4ResourceJSON)])
        _ = try? await reader(tool).read(.id("8f4b9c1e-2a7d-4f60-9c31-5e8a0b7d6c42"))
        #expect(!tool.calls.flat.contains("tlsSkipVerify"))
        #expect(!tool.calls.flat.lowercased().contains("insecure"))
        // Nor is it reachable through a setting: no field, and no extra spec.
        let kinds = SignInSourceSettings.fields(for: .passbolt).map(\.kind)
        for kind in kinds {
            if case .serverURL = kind { continue }
            if case .toolConfigFile = kind { continue }
            if case .toolBinary = kind { continue }
            Issue.record("Passbolt declared an unexpected field kind: \(kind)")
        }
    }

    /// READ-ONLY, and provable from the only place a command line is built: `get`
    /// and `list` are the only subcommands, so `create`, `update`, `delete`,
    /// `share`, `move` and `verify` cannot be reached even by mistake. `verify` is
    /// in that list on purpose — it WRITES the tool's config file.
    @Test func onlyReadingSubcommandsAreEverBuilt() {
        let r = reader(StubPassbolt(results: [ok("{}")]))
        let everything = r.getArguments(id: "x") + r.listArguments()
        for forbidden in ["create", "update", "delete", "share", "move", "verify", "export"] {
            #expect(!everything.contains(forbidden),
                    "a \u{201C}\(forbidden)\u{201D} argument can be built")
        }
        #expect(r.getArguments(id: "x").starts(with: ["get", "resource", "--id", "x"]))
        #expect(r.listArguments().starts(with: ["list", "resource"]))
    }

    /// The server address rides argv — it is not a secret — and it is passed even
    /// when the tool's own config has one, so a mis-set config file can never
    /// silently read a different Passbolt.
    @Test func theServerAddressIsAlwaysStated() {
        let r = reader(StubPassbolt(results: [ok("{}")]))
        let args = r.getArguments(id: "x")
        let index = args.firstIndex(of: "--serverAddress")
        #expect(index != nil)
        #expect(args[index! + 1] == "https://passbolt.example.com")
    }

    /// `--mfaMode none`, deliberately. The tool's default is `interactive-totp`,
    /// which reads a code from stdin: with stdin closed that surfaces as an EOF that
    /// reads like a passphrase problem. `none` lets the server's own "a code is
    /// required" answer arrive as itself. `noninteractive-totp` is never used — it
    /// needs the code's SEED, which beside the passphrase is not a second factor.
    @Test func multiFactorIsNeverAnsweredAutomatically() {
        let args = reader(StubPassbolt(results: [ok("{}")])).getArguments(id: "x")
        let index = args.firstIndex(of: "--mfaMode")
        #expect(index != nil)
        #expect(args[index! + 1] == "none")
        #expect(!args.contains("--mfaTotpToken"))
        #expect(!args.contains("--totpToken"))
    }

    /// The tool's own timeout is SHORTER than the runner's deadline, so the tool
    /// reports its own bounded error instead of being killed halfway through. The
    /// tool's default is a whole minute, which is far too long to hold a connect.
    @Test func theToolsOwnTimeoutFiresBeforeOurs() {
        let args = reader(StubPassbolt(results: [ok("{}")])).getArguments(id: "x")
        #expect(args.contains("--timeout"))
        #expect(args.contains("\(PassboltCLI.toolTimeoutSeconds)s"))
        #expect(TimeInterval(PassboltCLI.toolTimeoutSeconds) < PassboltCLI.runnerDeadline)
    }

    /// A per-server config file becomes `--config`, and only when one is set: empty
    /// means the tool's own default file, which is a working state.
    @Test func aPerServerConfigFileBecomesAFlag() {
        let none = reader(StubPassbolt(results: [ok("{}")])).getArguments(id: "x")
        #expect(!none.contains("--config"))

        var location = workServer
        location.configFile = "/Users/you/passbolt-work.toml"
        let named = reader(StubPassbolt(results: [ok("{}")]), location: location)
            .getArguments(id: "x")
        let index = named.firstIndex(of: "--config")
        #expect(index != nil)
        #expect(named[index! + 1] == "/Users/you/passbolt-work.toml")
    }

    /// The listing asks for columns that need NO secret, so "which one did you
    /// mean" never causes a password to be fetched or decrypted —
    /// `RequiresSecrets` in the tool's own `columns.go` is what that turns on.
    /// And there is no `--filter`: a CEL expression built out of somebody's typed
    /// text would be their text quoted into a small language, and matching in Swift
    /// removes the question.
    @Test func theNameSearchAsksForNothingSecret() {
        let args = reader(StubPassbolt(results: [ok("[]")])).listArguments()
        #expect(!args.contains("password"))
        #expect(!args.contains("--filter"))
        #expect(args.contains("id"))
        #expect(args.contains("name"))
    }
}

// MARK: - The passphrase: whose it is, and how it travels

struct PassboltPassphraseTests {

    /// WITH NOTHING TO UNLOCK THE KEY THE SOURCE IS DORMANT, and it gets there
    /// WITHOUT spawning anything. A sign-in that is going to ask for input we cannot
    /// give is still an authentication attempt against somebody's server.
    @Test func withNoPassphraseAnywhereTheSourceIsDormantAndSpawnsNothing() async {
        let tool = StubPassbolt(results: [ok(v4ResourceJSON)])
        await #expect(throws: PassboltError.passphraseUnavailable) {
            try await reader(tool, config: noPassphrase).read(.id("8f4b9c1e-2a7d-4f60-9c31-5e8a0b7d6c42"))
        }
        #expect(tool.calls.arguments.isEmpty, "a fetch was attempted that could not succeed")
    }

    /// THE LAPTOP-SHAPED FIX, in the sentence most people see first: type it here.
    /// It must NOT send somebody off to put a long-lived passphrase into a config
    /// file — that is what an operator provisions for an unattended job, and this is
    /// a VPN client on somebody's Mac.
    @Test func theDormantSentencePointsAtTypingItHere() {
        let sentence = PassboltError.passphraseUnavailable.errorDescription ?? ""
        #expect(sentence.lowercased().contains("passphrase"))
        #expect(sentence.contains("Sign-In Sources"))
        #expect(sentence.contains("Touch ID"))
        // …and it does not recommend the file route.
        #expect(!sentence.contains("passbolt configure"))
        #expect(!sentence.contains("--userPassword"))
    }

    /// EITHER OWNER SATISFIES THE PROBE, and the one SimpleVPN recommends is checked
    /// first. A passphrase already in Passbolt's own file keeps working — breaking
    /// somebody's existing setup to make a point would be worse than the point.
    @Test func eitherOwnerOfThePassphraseIsEnough() {
        // SimpleVPN holds one, the tool has none.
        #expect(reader(StubPassbolt(results: [ok("{}")]), config: noPassphrase, weHold: true)
                    .serverState() == .readyToTry)
        // The tool has one, SimpleVPN holds none.
        #expect(reader(StubPassbolt(results: [ok("{}")]), config: fullySetUp, weHold: false)
                    .serverState() == .readyToTry)
        // Neither.
        #expect(reader(StubPassbolt(results: [ok("{}")]), config: noPassphrase, weHold: false)
                    .serverState() == .needsPassphrase)
    }

    /// THE ONLY ROUTE A PASSPHRASE TRAVELS: stdin, with the newline the tool's
    /// `ReadString('\n')` requires — and NEVER argv, which every process on this Mac
    /// can read through `ps`.
    @Test func aPassphraseTravelsOnStdinAndNeverInArgv() async {
        let tool = StubPassbolt(results: [ok(v4ResourceJSON)])
        _ = try? await reader(tool, config: noPassphrase, weHold: true)
            .read(.id("8f4b9c1e-2a7d-4f60-9c31-5e8a0b7d6c42"),
                  passphrase: PassboltPassphrase("correct horse"))
        #expect(tool.calls.arguments.count == 1, "the fetch should have been attempted")
        #expect(!tool.calls.flat.contains("correct horse"))
        #expect(!tool.calls.flat.contains("--userPassword"))
        // The newline is load-bearing rather than tidy: `util.ReadPassword` reads with
        // `bufio.Reader.ReadString('\n')`, which returns an error at EOF if it never
        // sees one — so a passphrase written without it comes back as a read failure,
        // which reads to a user as "wrong passphrase".
        #expect(tool.calls.stdin.first == "correct horse\n")
    }

    /// The box has NO way to hand back its characters, which is what makes the argv
    /// assertion above structural rather than a habit: there is no getter to
    /// interpolate into a log line, a defaults key or a diagnostic.
    @Test func theBoxCannotBeStringified() {
        let passphrase = PassboltPassphrase("hunter2")
        #expect(passphrase.characterCount == 7)
        #expect(!passphrase.isEmpty)
        #expect(!passphrase.containsNewline)
        #expect(String(decoding: passphrase.stdinLine(), as: UTF8.self) == "hunter2\n")
        #expect(PassboltPassphrase("two\nlines").containsNewline)
    }

    /// …and a passphrase with a line break is refused BEFORE anything is spawned, with
    /// a sentence that says the key itself is fine.
    @Test func aPassphraseWithALineBreakIsRefusedUpFront() async {
        let tool = StubPassbolt(results: [ok(v4ResourceJSON)])
        await #expect(throws: PassboltError.passphraseContainsNewline) {
            try await reader(tool, weHold: true)
                .read(.id("8f4b9c1e-2a7d-4f60-9c31-5e8a0b7d6c42"),
                      passphrase: PassboltPassphrase("two\nlines"))
        }
        #expect(tool.calls.arguments.isEmpty)
        let sentence = PassboltError.passphraseContainsNewline.errorDescription ?? ""
        #expect(sentence.contains("Nothing is wrong with your key"))
    }

    /// A CANCELLED TOUCH ID SHEET IS NOT A WRONG PASSPHRASE, and the distinction has a
    /// concrete cost behind it: treating a cancel as a rejected sign-in would spend
    /// somebody's server-side lockout budget on a decision they made.
    @Test func cancellingIsItsOwnAnswerAndIsNeverRetried() {
        #expect(PassboltError.cancelled != PassboltError.signInRejected)
        #expect(!PassboltError.cancelled.isWorthRetrying)
        let sentence = PassboltError.cancelled.errorDescription ?? ""
        #expect(sentence.contains("cancelled"))
        #expect(sentence.contains("Nothing was read"))
    }

    /// NO UNATTENDED ROUTE. viper is initialised with `AutomaticEnv()` and no prefix
    /// and no key replacer, so the variable the tool reads is the bare, un-namespaced
    /// `USERPASSWORD` — the route somebody automating this in a script would reach
    /// for. SimpleVPN cannot deliver it, because `LocalToolRunner` builds the child
    /// environment from scratch. That is a feature: a secret in an inherited
    /// environment is a secret handed to every program started afterwards. It also
    /// means a `USERPASSWORD` exported in somebody's shell will NOT make a fetch from
    /// SimpleVPN work, which is why the manual says so.
    @Test func theToolsEnvironmentRouteIsUnreachableByConstruction() {
        let environment = LocalToolRunner.childEnvironment()
        for leaked in ["USERPASSWORD", "USERPRIVATEKEY", "SERVERADDRESS",
                       "PASSBOLT_USERPASSWORD", "MFATOTPTOKEN"] {
            #expect(environment[leaked] == nil)
        }
        // Only the four documented variables are handed over at all.
        #expect(Set(environment.keys) == ["HOME", "PATH", "LANG", "PYTHONUNBUFFERED"])
    }
}

// MARK: - Where the passphrase is kept

@MainActor
struct PassboltPassphraseStoreTests {

    /// NOWHERE BY DEFAULT. A fresh store holds nothing and says so in the words the
    /// settings row and VoiceOver both read.
    @Test func nothingIsHeldUntilSomethingIsTyped() {
        let store = PassboltPassphraseStore()
        let server = "https://passbolt.example.com"
        #expect(!store.isHeldForThisRun(server: server))
        #expect(!store.couldSupply(server: server))
        #expect(store.heldDescription(server: server, toolHasItsOwn: false).contains("Not held"))
    }

    /// THIS RUN'S MEMORY: once per launch, not once per connect — a passphrase is long
    /// and connecting is frequent.
    @Test func aTypedPassphraseIsHeldForThisRunOnly() async throws {
        let store = PassboltPassphraseStore()
        let server = "https://passbolt.example.com"
        store.holdForThisRun(PassboltPassphrase("hunter2"), server: server)
        #expect(store.isHeldForThisRun(server: server))
        #expect(store.couldSupply(server: server))
        #expect(store.heldDescription(server: server, toolHasItsOwn: false)
                    .contains("until SimpleVPN quits"))
        // It comes back with no prompt of any kind, because it is already in memory.
        #expect(try await store.passphrase(server: server, reason: "test") != nil)
        store.forgetThisRun(server: server)
        #expect(!store.isHeldForThisRun(server: server))
    }

    /// ONE SPELLING PER SERVER. Without this, typing a trailing slash later would
    /// silently lose a remembered passphrase — the keychain account is derived from the
    /// address, so the two would be different servers.
    @Test func oneServerHasOneSpelling() {
        let store = PassboltPassphraseStore()
        store.holdForThisRun(PassboltPassphrase("x"), server: "https://passbolt.example.com")
        #expect(store.isHeldForThisRun(server: "https://passbolt.example.com/"))
        #expect(store.isHeldForThisRun(server: "HTTPS://Passbolt.Example.com"))
        #expect(!store.isHeldForThisRun(server: "https://other.example.com"))
        #expect(PassboltPassphraseStore.account(forServer: "https://passbolt.example.com/")
                == PassboltPassphraseStore.account(forServer: "https://passbolt.example.com"))
    }

    /// THE KEYCHAIN ACCOUNT NEVER NAMES THE SERVER. A keychain item's account is
    /// visible in Keychain Access and in any keychain dump, and an address names an
    /// employer — so it is hashed: per-server without publishing which server.
    @Test func theKeychainAccountDoesNotPublishTheAddress() {
        let account = PassboltPassphraseStore.account(
            forServer: "https://passbolt.acme-internal.example")
        #expect(account.hasPrefix("passbolt:"))
        #expect(!account.contains("acme"))
        #expect(!account.contains("internal"))
        #expect(account != PassboltPassphraseStore.account(forServer: "https://other.example"))
    }

    /// Held for one server does NOT mean held for another — the passphrase belongs to
    /// the key that opens that server.
    @Test func passphrasesDoNotLeakBetweenServers() {
        let store = PassboltPassphraseStore()
        store.holdForThisRun(PassboltPassphrase("work"), server: "https://work.example.com")
        #expect(store.couldSupply(server: "https://work.example.com"))
        #expect(!store.couldSupply(server: "https://personal.example.com"))
        store.forgetEverythingHeldThisRun()
        #expect(!store.couldSupply(server: "https://work.example.com"))
    }

    /// When Passbolt's own program already has one, SimpleVPN needs nothing and must
    /// not imply otherwise — while still saying, once, that a Touch ID sheet is the
    /// better place for it on a Mac. Neither sentence recommends the file.
    @Test func theToolsOwnPassphraseIsAcknowledgedNotAdvertised() {
        let store = PassboltPassphraseStore()
        let sentence = store.heldDescription(server: "https://passbolt.example.com",
                                            toolHasItsOwn: true)
        #expect(sentence.contains("already has one"))
        #expect(sentence.contains("Touch ID"))
        #expect(!sentence.contains("passbolt configure"))
    }

    /// An empty address can never become a keychain account or a held passphrase:
    /// otherwise every not-yet-configured server would share one slot.
    @Test func anEmptyAddressHoldsNothing() async throws {
        let store = PassboltPassphraseStore()
        #expect(!store.isRemembered(server: ""))
        #expect(try await store.passphrase(server: "", reason: "test") == nil)
    }
}

// MARK: - The tool's own config, read for key NAMES only

struct PassboltToolConfigTests {

    /// The default config location, from `initConfig`: `os.UserConfigDir()` +
    /// `go-passbolt-cli`, type toml, name `go-passbolt-cli`. On macOS
    /// `os.UserConfigDir()` is `$HOME/Library/Application Support` — and `HOME` is
    /// one of the few variables `LocalToolRunner` passes through, so the tool and
    /// SimpleVPN look in the same place.
    @Test func theDefaultConfigPathIsTheToolsOwn() {
        let home = URL(fileURLWithPath: "/Users/you")
        #expect(PassboltServerLocation.defaultConfigFile(home: home)
                == "/Users/you/Library/Application Support/go-passbolt-cli/go-passbolt-cli.toml")
    }

    /// KEY NAMES ONLY. The scanner sees a real config file's worth of text — an
    /// armoured private key included — and comes back with four names and no values.
    @Test func onlyKeyNamesComeOutOfAConfigFile() {
        let text = """
        serveraddress = "https://passbolt.example.com"
        userprivatekey = "-----BEGIN PGP PRIVATE KEY BLOCK-----\\n\\nlQdGBGa...==\\n-----END PGP PRIVATE KEY BLOCK-----"
        userpassword = "hunter2"
        serververifytoken = "abc123"
        """
        let keys = PassboltToolConfigProbe.keyNames(in: text)
        #expect(keys == ["serveraddress", "userprivatekey", "userpassword", "serververifytoken"])
        // Nothing that could be a secret is in the answer.
        for key in keys {
            #expect(!key.contains("hunter2"))
            #expect(!key.contains("PGP"))
        }
    }

    /// A comment, a table header and a continuation line of base64 (whose padding
    /// also contains `=`) must not be mistaken for keys.
    @Test func theScannerIsNotFooledByCommentsTablesOrBase64() {
        let text = """
        # userpassword = not really set
        [section]
        mQINBFabcdefghijklmnopqrstuvwxyz0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZabcdef==
        serveraddress = "https://passbolt.example.com"
        """
        let keys = PassboltToolConfigProbe.keyNames(in: text)
        #expect(keys == ["serveraddress"])
    }

    /// The three states a config file can be in, and each is a different sentence
    /// with a different fix.
    @Test func theConfigFileGivesThreeDistinctStates() {
        #expect(fullySetUp.hasPrivateKey)
        #expect(fullySetUp.hasPassphrase)
        #expect(noPassphrase.hasPrivateKey)
        #expect(!noPassphrase.hasPassphrase)
        #expect(!notSetUp.exists)
        #expect(!notSetUp.hasPrivateKey)
        // `passbolt verify` is a separate, optional thing — reported, never required.
        #expect(!fullySetUp.pinsServerIdentity)
        #expect(PassboltToolConfig(path: "/c", exists: true, keys: ["serververifytoken"])
                    .pinsServerIdentity)
    }
}

// MARK: - Which server, and whether it can be talked to at all

struct PassboltServerAddressTests {

    /// `https` only, and the refusals each have their own clause so the settings row
    /// can say which of the four things is wrong.
    @Test func onlyAnHTTPSAddressIsAccepted() {
        #expect(PassboltServerLocation.validate("https://passbolt.example.com") == nil)
        #expect(PassboltServerLocation.validate("https://passbolt.example.com/") == nil)
        // A self-hosted server on a port and a private name is entirely ordinary and
        // must be accepted — nothing here assumes a hosted domain.
        #expect(PassboltServerLocation.validate("https://vault.internal.lan:8443") == nil)

        #expect(PassboltServerLocation.validate("") != nil)
        #expect(PassboltServerLocation.validate("passbolt.example.com") != nil)
        #expect(PassboltServerLocation.validate("http://passbolt.example.com") != nil)
        #expect(PassboltServerLocation.validate("https://me:secret@passbolt.example.com") != nil)
        #expect(PassboltServerLocation.validate("https://passbolt.example.com?x=1") != nil)
    }

    /// The refusal of `http` says which rule it is, because "that is not a web
    /// address" would be wrong and unhelpful at once.
    @Test func thePlainHTTPRefusalNamesHTTPS() {
        let why = PassboltServerLocation.validate("http://passbolt.example.com") ?? ""
        #expect(why.contains("https"))
    }

    /// A password in the address is refused with the fix, because it would be a
    /// secret sitting in a settings file.
    @Test func credentialsInTheAddressAreRefused() {
        let why = PassboltServerLocation.validate("https://me:secret@passbolt.example.com") ?? ""
        #expect(why.contains("password"))
    }

    /// The settings row uses the SAME definition, so the pane and the reader can
    /// never disagree about what SimpleVPN will talk to.
    @MainActor
    @Test func theSettingsRowValidatesAgainstTheOneDefinition() {
        let suite = "PassboltTests.\(UUID().uuidString)"
        let defaults = UserDefaults(suiteName: suite)!
        defer { defaults.removePersistentDomain(forName: suite) }
        let store = SignInSourceSettingsStore(store: defaults)
        let field = SignInSourceSettings.fields(for: .passbolt).first {
            if case .serverURL = $0.kind { return true }
            return false
        }!
        #expect(store.validate("https://passbolt.example.com", field: field) == .ok)
        guard case .badServerAddress(let why) =
                store.validate("http://passbolt.example.com", field: field) else {
            Issue.record("plain http was accepted")
            return
        }
        #expect(why.contains("https"))
        // A server's address is NEVER guessed: the only thing on this Mac that
        // knows it is the tool's own config file, and reading a value out of that
        // would mean handling its contents.
        #expect(store.detected(for: field) == nil)
        let shown = store.presentation(for: field)
        #expect(shown.value.isEmpty)
        #expect(shown.prompt == field.example)
        #expect(!shown.isSet)
    }
}

// MARK: - Availability, per server

@MainActor
struct PassboltAvailabilityTests {

    private func instance(_ values: [String: String]) -> SourceInstance {
        SourceInstance(id: .fresh(), vendor: .passbolt, name: "Work", values: values)
    }

    /// EVERY not-working state, and the ONE user action that fixes each. The list is
    /// the answer to "unavailable, decomposed" and it is asserted rather than
    /// described.
    @Test func everyStateIsDistinctAndReachable() {
        let adapter = PassboltVaultAdapter()
        // The three that do not depend on a config file at all.
        let noServer = PassboltReader(location: PassboltServerLocation(),
                                     tool: StubPassbolt(results: [ok("{}")]),
                                     toolConfig: { _ in fullySetUp })
        if case .noServer = noServer.serverState() {} else {
            Issue.record("an empty address did not produce the no-server state")
        }
        let noTool = PassboltReader(location: workServer,
                                    tool: StubPassbolt(installed: false, results: [ok("{}")]),
                                    toolConfig: { _ in fullySetUp })
        #expect(noTool.serverState() == .toolMissing)
        // …and the three that do.
        #expect(reader(StubPassbolt(results: [ok("{}")]), config: notSetUp).serverState()
                == .toolNotConfigured)
        #expect(reader(StubPassbolt(results: [ok("{}")]), config: noPassphrase).serverState()
                == .needsPassphrase)
        #expect(reader(StubPassbolt(results: [ok("{}")]), config: fullySetUp).serverState()
                == .readyToTry)
        // Each maps to a block with its own words and its own fix.
        let copy = LocalVaultCopyBook.copy(for: .passbolt)
        for block: LocalVaultBlock in [.toolMissing, .toolOutsideAllowList, .noServerConfigured,
                                       .notSignedIn, .vaultLocked] {
            #expect(!copy.headline(for: block).isEmpty)
            #expect(copy.headline(for: block) != "\(copy.title) needs a moment of setup",
                    "\(block) has no headline of its own")
        }
        // The three enablement states each carry a banner with a benefit and a link.
        for block: LocalVaultBlock in [.toolMissing, .noServerConfigured, .notSignedIn,
                                       .vaultLocked] {
            #expect(block.wantsEnablementBanner)
            let guidance = copy.guidance(for: block)
            #expect(guidance != nil, "\(block) has no enablement guidance")
            #expect(!(guidance?.spokenSummary.isEmpty ?? true))
        }
        #expect(adapter.transports == [.cli])
    }

    /// A FULLY SET-UP SERVER IS NEVER `.ready`, and this is the honest ceiling of a
    /// server-shaped instance: a `stat` can prove a file is readable and nothing
    /// short of a real sign-in can prove a server is. So the best a background pass
    /// offers is "ready to try", with the reason in the row's own note.
    @Test func aServerIsOfferedAsReadyToTryAndNeverAsProven() async {
        let adapter = PassboltVaultAdapter()
        // Built from the instance's own values, with no main-actor hop — the same
        // rule the password store follows, for the same reason.
        let location = PassboltVaultAdapter.location(
            from: instance(["server": "https://passbolt.example.com",
                            "config-file": "/Users/you/work.toml"]))
        #expect(location.serverURL == "https://passbolt.example.com")
        #expect(location.configFile == "/Users/you/work.toml")

        let quick = LocalVaultAvailability.unchecked(.wouldSignInToServer)
        #expect(await adapter.deepScan(quick: quick) == quick,
                "the deep scan signed in to a server it was only asked about")
        let note = LocalVaultCopyBook.copy(for: .passbolt).uncheckedNote ?? ""
        #expect(note.contains("hasn\u{2019}t contacted"))
    }

    /// TWO SERVERS, ONE BROKEN. The row is offered because one of them can answer,
    /// and the per-server answers stay separate so the pane, the chooser and a
    /// report can each say which is which. Hiding a working personal server because
    /// the work one is unreachable would be a lie.
    @Test func oneBrokenServerDoesNotHideAWorkingOne() {
        var facts = SignInSourceFacts()
        let good = SourceInstanceID.fresh(), bad = SourceInstanceID.fresh()
        facts.instances[.passbolt] = [
            SourceInstance(id: good, vendor: .passbolt, name: "Work",
                           values: ["server": "https://passbolt.example.com"]),
            SourceInstance(id: bad, vendor: .passbolt, name: "Personal", values: [:]),
        ]
        facts.vaultInstances[good] = .unchecked(.wouldSignInToServer)
        facts.vaultInstances[bad] = .blocked(.noServerConfigured)
        // The vendor row is the BEST of them, exactly as the registry computes it.
        facts.vaults[.passbolt] = .unchecked(.wouldSignInToServer)

        #expect(facts.availability(.passbolt) == .unchecked(.wouldSignInToServer))
        #expect(facts.availability(.passbolt, instance: good) == .unchecked(.wouldSignInToServer))
        #expect(facts.availability(.passbolt, instance: bad) == .blocked(.noServerConfigured))
        // The row IS offered, and its state comes from the good one.
        let row = SignInSourceCatalog.vaultOption(.passbolt, availability: .unchecked(.wouldSignInToServer))
        #expect(row?.isSelectable == true)
        // Switching the vendor off hides every server at once, including the good one.
        facts.disabledVendors = [.passbolt]
        #expect(facts.availability(.passbolt, instance: good) == .notInstalled)
    }

    /// A server-shaped instance is `.multiple`, and the word the user sees is
    /// "server" — never "vault" and never "instance".
    @Test func passboltDeclaresSeveralServersInItsOwnWords() {
        #expect(LocalVaultVendor.passbolt.cardinality == .multiple)
        #expect(LocalVaultVendor.passbolt.instanceNoun == "server")
        #expect(LocalVaultVendor.passbolt.instanceNounPlural == "servers")
        let step = SignInSourceSteps.stepOneTitle(vendor: .passbolt)
        #expect(step.contains("server"))
        #expect(!step.lowercased().contains("instance"))
        // Removing one must not claim SimpleVPN could have changed a server.
        let warning = SignInSourceSteps.removalWarning(vendor: .passbolt, name: "Work", usedBy: [])
        #expect(warning.contains("nothing on the server changes"))
        #expect(!warning.contains("the file itself"))
    }

    /// Both level-2 fields sit at level 2, and the tool's path sits at level 1.
    /// The address is the interesting one: it SOUNDS transport-shaped and is not —
    /// it says which Passbolt, not how SimpleVPN reaches Passbolt at all.
    @Test func theThreeLevelsAreWhereTheyShouldBe() {
        var seen: [SignInConfigLevel] = []
        for field in SignInSourceSettings.fields(for: .passbolt) { seen.append(field.level) }
        #expect(SignInSourceSettings.transportFields(for: .passbolt).count == 1)
        #expect(SignInSourceSettings.instanceFields(for: .passbolt).count == 2)
        #expect(seen.filter { $0 == .perVPN }.isEmpty, "a level-3 thing became a setting")
        // And the per-VPN reference holds nothing but a pointer.
        var source = CredentialSource()
        source.kind = .passbolt
        source.reference = "8f4b9c1e-2a7d-4f60-9c31-5e8a0b7d6c42"
        source.account = "vpn-user"
        source.instanceID = "abc"
        let blob = String(decoding: source.encodedBlob() ?? Data(), as: UTF8.self)
        for secret in ["hunter2", "PGP", "PRIVATE KEY", "userPassword"] {
            #expect(!blob.contains(secret))
        }
    }
}

// MARK: - Reading one resource

struct PassboltReadTests {

    /// A UUID goes straight to `get resource --id`: one run, no listing, and the
    /// stable reference is the one to prefer.
    @Test func aUUIDIsFetchedDirectly() async throws {
        let tool = StubPassbolt(results: [ok(v4ResourceJSON)])
        let resource = try await reader(tool).read(.id("8f4b9c1e-2a7d-4f60-9c31-5e8a0b7d6c42"))
        #expect(tool.calls.arguments.count == 1)
        #expect(tool.calls.last.starts(with: ["get", "resource", "--id",
                                              "8f4b9c1e-2a7d-4f60-9c31-5e8a0b7d6c42"]))
        #expect(resource.name == "test-v4")
        #expect(resource.username == "user-v4")
        #expect(resource.password == "pass-v4")
    }

    /// Reference SHAPE decides which route is taken, so pasting an identifier just
    /// works and nobody has to be told about a mode switch.
    @Test func theReferenceShapeDecidesTheRoute() {
        #expect(PassboltResourceReference.parse("8f4b9c1e-2a7d-4f60-9c31-5e8a0b7d6c42")
                == .id("8f4b9c1e-2a7d-4f60-9c31-5e8a0b7d6c42"))
        #expect(PassboltResourceReference.parse("  GR Lab VPN ") == .name("GR Lab VPN"))
        #expect(PassboltResourceReference.parse("   ") == nil)
        // A braced UUID is NOT a Passbolt id — `UUID(uuidString:)` would take it and
        // the server would then not recognise it.
        #expect(!PassboltResourceReference.looksLikeUUID("{8f4b9c1e-2a7d-4f60-9c31-5e8a0b7d6c42}"))
        #expect(!PassboltResourceReference.looksLikeUUID("8f4b9c1e2a7d4f609c315e8a0b7d6c42"))
    }

    /// A NAME is resolved by listing and matching in Swift — two runs — and an exact
    /// case-insensitive match wins.
    @Test func aNameIsResolvedThroughAListing() async throws {
        let listing = """
        [{"id":"8f4b9c1e-2a7d-4f60-9c31-5e8a0b7d6c42","name":"GR Lab VPN","username":"a"},
         {"id":"22222222-2222-2222-2222-222222222222","name":"Something else"}]
        """
        let tool = StubPassbolt(results: [ok(listing), ok(v4ResourceJSON)])
        let resource = try await reader(tool).read(.name("gr lab vpn"))
        #expect(tool.calls.arguments.count == 2)
        #expect(tool.calls.arguments[0].starts(with: ["list", "resource"]))
        #expect(tool.calls.arguments[1].contains("8f4b9c1e-2a7d-4f60-9c31-5e8a0b7d6c42"))
        #expect(resource.password == "pass-v4")
    }

    /// SEVERAL MATCHES IS AN ERROR, never a choice made for the user: reading the
    /// wrong sign-in because two resources share a name is worse than failing. The
    /// message names the count and the fix, and lists names rather than identifiers.
    @Test func severalMatchesRefusesRatherThanGuessing() async {
        let listing = """
        [{"id":"11111111-1111-1111-1111-111111111111","name":"VPN"},
         {"id":"22222222-2222-2222-2222-222222222222","name":"vpn"}]
        """
        let tool = StubPassbolt(results: [ok(listing)])
        do {
            _ = try await reader(tool).read(.name("VPN"))
            Issue.record("two matches were silently narrowed to one")
        } catch let error as PassboltError {
            guard case .severalMatches(let name, let names) = error else {
                Issue.record("wrong error: \(error)")
                return
            }
            #expect(name == "VPN")
            #expect(names.count == 2)
            let sentence = error.errorDescription ?? ""
            #expect(sentence.contains("2"))
            #expect(sentence.contains("identifier"))
        } catch {
            Issue.record("wrong error type")
        }
        // …and nothing was fetched.
        #expect(tool.calls.arguments.count == 1)
    }

    @Test func nothingMatchedIsItsOwnAnswer() async {
        let tool = StubPassbolt(results: [ok("[]")])
        await #expect(throws: PassboltError.nothingMatched("Nope")) {
            try await reader(tool).read(.name("Nope"))
        }
    }

    /// A resource with a TOTP secret yields a code computed locally from the seed —
    /// the shape `internal/testdata/14_totp_resource.txtar` round-trips, seed
    /// included. `suppliesOTP` stays FALSE all the same, because only some resource
    /// types carry one.
    @Test func aTOTPResourceYieldsACodeWithoutPromisingOne() async throws {
        let tool = StubPassbolt(results: [ok(totpResourceJSON)])
        let resource = try await reader(tool).read(.id("11111111-2222-3333-4444-555555555555"))
        #expect(resource.username == "totp-user", "the v5 metadata map was not read")
        let totp = try #require(resource.totp)
        #expect(totp.digits == 6)
        #expect(totp.period == 30)
        #expect(totp.algorithm == .sha1)
        // The seed is JBSWY3DPEHPK3PXP — RFC 6238's own test vector shape.
        #expect(totp.code(at: Date(timeIntervalSince1970: 0)) == "282760")
        #expect(!CredentialSourceKind.passbolt.suppliesOTP)
    }

    /// A resource with no TOTP is not an error and produces no code.
    @Test func anOrdinaryResourceHasNoCode() async throws {
        let tool = StubPassbolt(results: [ok(v4ResourceJSON)])
        let resource = try await reader(tool).read(.id("8f4b9c1e-2a7d-4f60-9c31-5e8a0b7d6c42"))
        #expect(resource.totp == nil)
    }

    /// Unknown keys and missing keys are both survivable: the tool's output grows
    /// with Passbolt's resource types, and a strict decode would throw away a
    /// perfectly good password over a new field.
    @Test func theParserToleratesAGrowingOutput() throws {
        let future = """
        {"id":"x","name":"n","password":"p","brand_new_field":{"a":1},
         "secret":{"password":"p","note":"hello"}}
        """
        let resource = try PassboltResource.parse(Data(future.utf8))
        #expect(resource.password == "p")
        #expect(resource.name == "n")
        // …and something that is not JSON at all is an honest failure rather than an
        // empty password treated as a success.
        #expect(throws: PassboltError.unreadableOutput) {
            try PassboltResource.parse(Data("not json".utf8))
        }
    }
}

// MARK: - Failure classification, from the tool's own words

struct PassboltFailureTests {

    private func classify(_ stderr: String) -> PassboltError {
        PassboltFailureClassifier.classify(stderr: stderr, reference: "vpn")
    }

    /// NO SERVER CONFIGURED — the tool's own message, asserted by its own
    /// `internal/testdata/43_error_missing_config.txtar`.
    @Test func noServerConfigured() {
        guard case .noServerConfigured = classify("Error: serverAddress is not defined") else {
            Issue.record("the tool's own no-address message was not recognised")
            return
        }
    }

    /// NOT SET UP — `userPrivateKey is not defined`, from `GetClient`.
    @Test func theToolHasNoKeyForThisServer() {
        guard case .toolNotConfigured = classify("Error: userPrivateKey is not defined") else {
            Issue.record("the tool's own no-key message was not recognised")
            return
        }
    }

    /// PASSPHRASE REFUSED TO ARRIVE — what a closed stdin produces, via `GetClient`'s
    /// `reading Password: %w` wrap.
    @Test func aClosedStdinBecomesTheDormantState() {
        #expect(classify("Error: reading Password: EOF") == .passphraseUnavailable)
    }

    /// TLS FAILURE, and it is tested BEFORE the credential markers on purpose: a
    /// certificate problem inside a sign-in must never be reported as a wrong
    /// passphrase, because the two fixes have nothing in common.
    @Test func aCertificateProblemIsNeverReportedAsAWrongPassphrase() {
        let real = "Error: logging in: Get \"https://passbolt.internal.lan/auth/verify.json\": "
            + "tls: failed to verify certificate: x509: certificate signed by unknown authority"
        guard case .certificateNotTrusted = classify(real) else {
            Issue.record("a certificate failure was misclassified")
            return
        }
        guard case .certificateNotTrusted = classify("x509: certificate has expired or is not yet valid") else {
            Issue.record("an expired certificate was misclassified")
            return
        }
        // The sentence names the fix that works for every program at once, and does
        // NOT hint that the check could be turned off — because here it cannot.
        let sentence = PassboltError.certificateNotTrusted("x").errorDescription ?? ""
        #expect(sentence.contains("keychain"))
        #expect(sentence.contains("will not skip"))
        for hint in ["insecure", "skip verify", "tlsSkipVerify", "self-signed"] {
            #expect(!sentence.lowercased().contains(hint.lowercased()),
                    "the certificate sentence hints at \u{201C}\(hint)\u{201D}")
        }
    }

    /// SERVER UNREACHABLE, in the shapes Go's own dialler produces.
    @Test func serverUnreachable() {
        for stderr in ["dial tcp 10.0.0.5:443: connect: connection refused",
                       "Get \"https://passbolt.internal.lan\": dial tcp: lookup "
                        + "passbolt.internal.lan: no such host",
                       "dial tcp 10.0.0.5:443: i/o timeout"] {
            guard case .serverUnreachable = classify(stderr) else {
                Issue.record("not classified as unreachable: \(stderr)")
                continue
            }
        }
        // …and unreachable is the one class of failure worth retrying unchanged.
        #expect(PassboltError.serverUnreachable("x").isWorthRetrying)
        #expect(PassboltError.timedOut.isWorthRetrying)
    }

    /// NOT AUTHENTICATED / PASSPHRASE REFUSED — `apiStatusHint`'s exact 401 text.
    /// Distinct from "there is no passphrase at all", because only one of the two is
    /// a correction the user can make by typing.
    @Test func aRejectedSignInIsItsOwnState() {
        #expect(classify("logging in: authentication failed, check your private key and "
                         + "password: 401 Unauthorized") == .signInRejected)
        #expect(classify("gopenpgp: error in unlocking key: wrong passphrase") == .signInRejected)
        // A rejected sign-in must never be silently retried: that spends somebody's
        // lockout budget on a passphrase that is already known to be wrong.
        #expect(!PassboltError.signInRejected.isWorthRetrying)
    }

    /// A VERIFICATION CODE IS REQUIRED — `apiStatusHint`'s 403 text. Reported, never
    /// answered.
    @Test func aRequiredCodeIsReportedRatherThanAnswered() {
        #expect(classify("logging in: access denied, you may lack the required permission or "
                         + "MFA may be needed: 403 Forbidden") == .verificationCodeRequired)
        let sentence = PassboltError.verificationCodeRequired.errorDescription ?? ""
        #expect(sentence.contains("verification code"))
        #expect(!PassboltError.verificationCodeRequired.isWorthRetrying)
    }

    /// PASSBOLT'S OWN SERVER-IDENTITY CHECK failing is much louder than a
    /// certificate problem and gets its own sentence.
    @Test func aChangedServerIdentityIsItsOwnAlarm() {
        #expect(classify("verifying Server: token mismatch") == .serverIdentityChanged)
        let sentence = PassboltError.serverIdentityChanged.errorDescription ?? ""
        #expect(sentence.contains("Nothing was read"))
        #expect(sentence.contains("passbolt verify"))
    }

    /// RESOURCE NOT FOUND — the shape `internal/testdata/44_error_resource_not_found
    /// .txtar` asserts, and `apiStatusHint`'s 404 text.
    @Test func resourceNotFound() {
        guard case .resourceNotFound = classify("getting resource: 404 Not Found") else {
            Issue.record("a 404 was misclassified")
            return
        }
        guard case .resourceNotFound = classify("not found, check the requested ID and the "
                                                + "server address") else {
            Issue.record("the tool's own 404 hint was misclassified")
            return
        }
    }

    /// A TIMEOUT is the tool's own bounded answer, and the runner's kill is a
    /// separate path that reaches the same case.
    @Test func timeoutsComeBackAsTimeouts() async {
        #expect(classify("context deadline exceeded") == .timedOut)
        let tool = StubPassbolt(results: [timedOut])
        await #expect(throws: PassboltError.timedOut) {
            try await reader(tool).read(.id("8f4b9c1e-2a7d-4f60-9c31-5e8a0b7d6c42"))
        }
    }

    /// EVERY case says something, and nothing quotes a secret. The stderr the
    /// classifier is given has already been scrubbed by `LocalToolRunner`; what
    /// matters here is that our own sentences add nothing.
    @Test func everySentenceIsPresentAndSecretFree() {
        let all: [PassboltError] = [
            .toolMissing, .noServerConfigured("why"), .toolNotConfigured("/c"),
            .passphraseUnavailable, .signInRejected, .verificationCodeRequired,
            .serverUnreachable("detail"), .certificateNotTrusted("detail"),
            .serverIdentityChanged, .resourceNotFound("vpn"),
            .severalMatches(name: "vpn", names: ["vpn", "vpn"]), .nothingMatched("vpn"),
            .timedOut, .unreadableOutput, .failed("detail"),
        ]
        for error in all {
            let sentence = error.errorDescription ?? ""
            #expect(!sentence.isEmpty, "\(error) has no sentence")
            #expect(!sentence.contains("hunter2"))
            #expect(!sentence.contains("PRIVATE KEY"))
        }
    }

    /// A tool that will not run at all fails at once, without pretending the server
    /// is the problem.
    @Test func aMissingToolIsNamedAsSuch() async {
        let tool = StubPassbolt(installed: false, results: [ok("{}")])
        await #expect(throws: PassboltError.toolMissing) {
            try await reader(tool).read(.id("8f4b9c1e-2a7d-4f60-9c31-5e8a0b7d6c42"))
        }
        #expect(tool.calls.arguments.isEmpty)
    }
}

// MARK: - The vendor's place in the app

@MainActor
struct PassboltIntegrationTests {

    /// The whole row exists, is offered from one adapter, and reaches the connect
    /// path through the same seam as every other vendor.
    @Test func theVendorIsWiredEverywhereItHasToBe() {
        #expect(LocalVaultRegistry.adapter(for: LocalVaultVendor.passbolt) != nil)
        #expect(LocalVaultRegistry.adapter(for: CredentialSourceKind.passbolt)?.vendor == .passbolt)
        #expect(LocalVaultVendor.passbolt.settingSlug == "passbolt")
        #expect(LocalVaultCopyBook.copy(for: .passbolt).storedKind == .passbolt)
        #expect(FeatureMaturityRegistry.maturity(ofSource: .vault(.passbolt)) == .untested)
        // A source that names nothing to fetch yields no provider.
        var source = CredentialSource()
        source.kind = .passbolt
        #expect(PassboltVaultAdapter().provider(for: source) == nil)
        source.reference = "8f4b9c1e-2a7d-4f60-9c31-5e8a0b7d6c42"
        #expect(PassboltVaultAdapter().provider(for: source) != nil)
    }

    /// Its recovery sentence names the source — and deliberately does not guess
    /// WHICH of the four things is missing, because naming one would be wrong three
    /// times in four.
    @Test func theRecoverySentenceNamesPassboltAndGuessesNothing() {
        let headline = SignInFlow.unavailableHeadline(.passbolt)
        #expect(headline.contains("Passbolt"))
        #expect(headline.contains("Sign-In Sources"))
        for guess in ["passphrase", "certificate", "not installed"] {
            #expect(!headline.lowercased().contains(guess),
                    "the recovery sentence guesses \u{201C}\(guess)\u{201D}")
        }
    }

    /// Nothing in the copy names a hosted Passbolt domain: self-hosting is the norm,
    /// and a sentence that assumes otherwise is wrong for most readers.
    @Test func nothingAssumesAHostedPassbolt() {
        let copy = LocalVaultCopyBook.copy(for: .passbolt)
        var text = [copy.title, copy.summary, copy.explanation, copy.uncheckedNote ?? ""]
        for (_, block) in copy.blocks { text += [block.headline] + block.steps }
        for (_, guidance) in copy.guidance {
            text.append(guidance.benefit)
            text.append(guidance.settingLocation ?? "")
        }
        for line in text {
            #expect(!line.contains("passbolt.com"),
                    "\u{201C}\(line)\u{201D} assumes a hosted Passbolt")
        }
        // The example commands DO name a server, and it is example.com — the
        // reserved documentation domain, never a real service.
        let commands = copy.guidance.values.flatMap { $0.example.map(\.text) }
        #expect(commands.contains { $0.contains("passbolt.example.com") })
    }

    /// Its four settings are addressable, documented and grouped like every other —
    /// including the two the catalog GENERATES (the vendor switch and the server
    /// list), which is exactly the pair the previous feed was failed by.
    @Test func everySettingIsInTheCatalog() {
        let ids = Set(CredentialSourceSettings.all.map(\.id))
        for id in ["creds.passbolt.enabled", "creds.passbolt.servers",
                   "creds.passbolt.server", "creds.passbolt.config-file",
                   "creds.passbolt.tool-path", "creds.passbolt.passphrase",
                   "creds.passbolt.remember-passphrase"] {
            #expect(ids.contains(id), "\(id) is not in the creds catalog")
            #expect(CredentialSourceSettings.vendor(forSettingID: id) == .passbolt)
        }
        // THE TWO SETTINGS THAT MUST NEVER EXIST: a way to skip the certificate check,
        // and anything that would keep a passphrase somewhere other than the Touch ID
        // keychain (an ordinary keychain item, a defaults key, an environment
        // variable). Neither is a preference.
        for forbidden in ["passbolt.tls", "passbolt.insecure", "passbolt.skip",
                          "passbolt.self-signed", "passbolt.environment",
                          "passbolt.store-passphrase"] {
            #expect(!ids.contains { $0.contains(forbidden) },
                    "\(forbidden) exists as a setting")
        }
        // The passphrase pair are EXTRA specs rather than fields, because neither is
        // stored where a field is stored: one is in memory, the other IS a keychain
        // item's existence.
        let extra = CredentialSourceSettings.extraSpecs(for: .passbolt).map(\.id)
        #expect(extra == ["creds.passbolt.passphrase", "creds.passbolt.remember-passphrase"])
        #expect(!SignInSourceSettings.fields(for: .passbolt).map(\.settingID)
                    .contains("creds.passbolt.passphrase"),
                "the passphrase became a field, which would put it in UserDefaults")
        // Remembering is OFF by default: nothing is kept between runs until asked.
        let remember = CredentialSourceSettings.all.first {
            $0.id == "creds.passbolt.remember-passphrase"
        }
        #expect(remember?.isChanged(true) == true, "remembering is not off by default")
    }

    /// The tool's setup file row has a working empty state, and its permissions note
    /// is advice rather than a refusal — breaking a working setup to make a point
    /// would be worse than the loose permissions.
    @Test func theSetupFileRowExplainsItsEmptyState() {
        let suite = "PassboltTests.\(UUID().uuidString)"
        let defaults = UserDefaults(suiteName: suite)!
        defer { defaults.removePersistentDomain(forName: suite) }
        let store = SignInSourceSettingsStore(store: defaults)
        let field = SignInSourceSettings.fields(for: .passbolt).first {
            if case .toolConfigFile = $0.kind { return true }
            return false
        }!
        #expect(field.emptyMeansDefault == PassboltServerLocation.defaultConfigFile())
        let empty = store.validate("", field: field)
        guard case .notSetUsingDefault(let fallback) = empty else {
            Issue.record("an empty setup file was reported as a gap")
            return
        }
        #expect(fallback.contains("go-passbolt-cli"))
        #expect(!empty.isProblem)
        // Loose permissions: a statement with the fix, not a fault.
        #expect(!VendorFieldValidation.readableByOthers.isProblem)
        #expect(VendorFieldValidation.readableByOthers.sentence.contains("chmod 600"))
        #expect(!VendorFieldValidation.readableByOthers.sentence.hasPrefix("Problem:"))
    }
}
