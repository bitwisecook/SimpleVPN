// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
//  DashlaneTests.swift
//  The Dashlane sign-in source, driven entirely by fixtures. DASHLANE AND `dcli` ARE
//  NOT INSTALLED ON THE MACHINE THIS WAS WRITTEN ON, so nothing here has been seen
//  working against a live vault and nothing here claims to have been: every byte of
//  every fixture comes from a named source, and the report that accompanies this work
//  says plainly which paths are fixture-tested and which are unverified.
//
//  ─── FIXTURE PROVENANCE (Dashlane/dashlane-cli, `master`, read 2026-08) ──────────
//
//   • THE FLAG, AND THE DEFAULT IT AVOIDS — `src/commands/index.ts`:
//     `program.command('password').alias('p')
//        .description('Retrieve a password from the local vault and copy it to the clipboard')
//        .addOption(new Option('-o, --output <type>', …)
//            .choices(['clipboard', 'console', 'json']).default('clipboard'))
//        .addOption(new Option('-f, --field <type>', …)
//            .choices(['login', 'email', 'otp', 'password']).default('password'))`
//     — so the pasteboard IS the default, and `console` / `json` are the two ways out.
//   • WHERE EACH BRANCH GOES — `src/command-handlers/passwords.ts`, `runPassword`:
//     the `json` branch is `logger.content(JSON.stringify(foundCredentials)); return;`
//     BEFORE `selectCredential`; the `console` branch is `logger.content(result);
//     return;` AFTER it; and only past both does `const clipboard = new Clipboard();
//     clipboard.setText(result)` run. `selectCredential` calls `askCredentialChoice`
//     whenever more than one entry matches — an interactive list prompt. That is why
//     these tests pin `--output json` rather than `--output console`.
//   • THE ENTRY SHAPE — the same file's `findCredentials`, which lower-cases the first
//     letter of Dashlane's own XML `KWDataItem` keys ("OtpSecret => otpSecret"), and
//     `src/types` / `VaultCredential`'s use of `login`, `email`, `secondaryLogin`,
//     `password`, `otpSecret`, `otpUrl`, `title`, `url`, `id`.
//   • `dcli status`'s EXACT LINES — `src/command-handlers/status.ts`, `runStatus`:
//     `logger.content('Logged in: no')` when the database file is absent or the
//     `device` table is empty, else `Logged in: yes` / `Login: <login>` /
//     `Locked: yes|no` where locked comes from `isVaultLocked` (master password not to
//     be saved, or no `masterPasswordEncrypted` in the database, or no local key in the
//     OS keychain).
//   • STATUS COSTS NOTHING — the same function never calls `connectAndPrepare`, so it
//     cannot prompt, cannot verify user presence and cannot synchronise. That is what
//     these tests encode as "the state probe is the cheap one".
//   • A FETCH MAY PROMPT OR SYNC — `src/modules/database/connectAndPrepare.ts` calls
//     `userPresenceVerification` and then `getLocalConfiguration`, and synchronises
//     when the last sync is over 3600s old and auto-sync is not disabled. The sync's
//     own log lines share the stdout stream (one winston Console transport,
//     `src/logger.ts`), which is why `DashlaneWire` reads the LAST JSON array.
//   • THE PROMPT IS DASHLANE'S — `src/modules/auth/userPresenceVerification.ts` calls
//     `node-mac-auth`'s `promptTouchID({reason: 'validate your identity before
//     accessing your vault'})` in `dcli`'s own process.
//   • THE LOCAL KEY IS AN OS-KEYCHAIN ITEM — `src/modules/crypto/keychainManager.ts`,
//     `new Entry('dashlane-cli', login)` from `@napi-rs/keyring`; and
//     `getLocalConfigurationWithoutKeychain` falls back to `askMasterPassword()` on
//     stdin, which is the hang these tests' guard exists to prevent.
//   • THE DATABASE PATH — `src/modules/database/connect.ts`:
//     `process.env.HOME + '/Library/Application Support'` + `/dashlane-cli` +
//     `/userdata.db`.
//   • THE ONE-TIME SETUP AND THE TWO SWITCHES — Dashlane's own documentation at
//     <https://cli.dashlane.com/personal/authentication> (`dcli sync` first, email plus
//     token, master password saved in the OS keychain by default,
//     `dcli configure save-master-password false`,
//     `dcli configure user-presence --method biometrics`) and
//     <https://cli.dashlane.com/install> (`brew install dashlane/tap/dashlane-cli`, and
//     the standalone binary moved to `/usr/local/bin/dcli`).
//
//  The sample VALUES are ours, not Dashlane's: their documentation ships no example
//  entry to copy, so nothing here pretends to be a vendor sample.
//
//  Nothing here reaches the network, spawns a process, or touches the real defaults
//  domain.
//

import Foundation
import Testing
@testable import SimpleVPN

// MARK: - Fixtures

private nonisolated enum DL {

    static let entryID = "1a2b3c4d5e6f7081"

    /// One entry as `--output json` prints it: an ARRAY, on one line, of objects whose
    /// keys are Dashlane's own with the first letter lower-cased.
    static func json(login: String = "jdoe",
                     email: String? = nil,
                     password: String = "s3cr3t-vpn-pw",
                     otpSecret: String? = "JBSWY3DPEHPK3PXP",
                     title: String = "GR Lab VPN",
                     url: String = "https://vpn.example.com") -> Data {
        Data("[\(object(login: login, email: email, password: password, otpSecret: otpSecret, title: title, url: url))]".utf8)
    }

    static func object(login: String = "jdoe",
                       email: String? = nil,
                       password: String = "s3cr3t-vpn-pw",
                       otpSecret: String? = "JBSWY3DPEHPK3PXP",
                       title: String = "GR Lab VPN",
                       url: String = "https://vpn.example.com",
                       id: String = entryID) -> String {
        var fields = ["\"id\":\"\(id)\"", "\"title\":\"\(title)\"", "\"url\":\"\(url)\"",
                      "\"login\":\"\(login)\"", "\"password\":\"\(password)\""]
        if let email { fields.append("\"email\":\"\(email)\"") }
        if let otpSecret { fields.append("\"otpSecret\":\"\(otpSecret)\"") }
        return "{" + fields.joined(separator: ",") + "}"
    }

    /// Two entries matching one filter — the case `--output console` would answer with
    /// an interactive picker.
    static let twoMatches = Data("""
    [\(object(login: "jdoe", password: "personal-pw", title: "GR Lab VPN")),\
    \(object(login: "admin", password: "admin-pw", title: "GR Lab VPN (admin)", id: "9f8e7d6c5b4a3210"))]
    """.utf8)

    /// An entry with no password in it at all — a secure note under the same title.
    static let noPassword = Data("[{\"id\":\"\(entryID)\",\"title\":\"GR Lab VPN\",\"login\":\"jdoe\"}]".utf8)

    /// What auto-sync leaves on stdout ahead of the payload. The prefixes are
    /// winston's own (`success` renders as a tick, `info` bare).
    static func withSyncNoise(_ payload: Data) -> Data {
        var out = Data("\u{2714} Synchronized\nLast sync: 2026-08-05T09:12:44.000Z\n".utf8)
        out.append(payload)
        out.append(Data("\n".utf8))
        return out
    }

    // --- `dcli status` ------------------------------------------------------

    static let statusNotSignedIn = "Logged in: no"
    static let statusUnlocked = """
    Logged in: yes
    Login: jdoe@example.com
    Locked: no
    """
    static let statusLocked = """
    Logged in: yes
    Login: jdoe@example.com
    Locked: yes
    """

    static func ok(_ stdout: Data) -> LocalToolResult {
        LocalToolResult(exitCode: 0, stdout: stdout, stderr: "", timedOut: false)
    }
    static func ok(_ text: String) -> LocalToolResult { ok(Data(text.utf8)) }
    static func failed(_ stderr: String) -> LocalToolResult {
        LocalToolResult(exitCode: 1, stdout: Data(), stderr: stderr, timedOut: false)
    }
    static let timedOut = LocalToolResult(exitCode: -1, stdout: Data(), stderr: "", timedOut: true)
    static let notRunnable = LocalToolResult(exitCode: -1, stdout: Data(),
                                            stderr: "not an approved tool location", timedOut: false)
}

/// Records every argv a `dcli` call would have used, so "never the clipboard" and
/// "nothing secret in argv" are asserted rather than asserted-in-a-comment.
private nonisolated final class DCLISpy: @unchecked Sendable {
    var arguments: [[String]] = []
    var deadlines: [TimeInterval] = []
    /// Answers by sub-command, so one spy serves a whole resolve (status, then fetch).
    var statusReply: LocalToolResult = DL.ok(DL.statusUnlocked)
    var fetchReply: LocalToolResult = DL.ok(DL.json())

    var client: DashlaneCLIClient {
        DashlaneCLIClient { arguments, deadline in
            self.arguments.append(arguments)
            self.deadlines.append(deadline)
            return arguments.first == "status" ? self.statusReply : self.fetchReply
        }
    }

    var everyArgument: [String] { arguments.flatMap { $0 } }
    var fetchArguments: [[String]] { arguments.filter { $0.first != "status" } }
}

/// A channel with no `dcli` behind it at all, for the states that must not spawn.
private nonisolated struct FixedChannel: DashlaneChannel {
    var state: DashlaneVaultState?
    var entries: [DashlaneCredential] = []
    var error: (any Error)?
    /// Set when `credentials(reference:)` was called — the hang guard's whole claim is
    /// that it ISN'T, for a vault that would prompt.
    final class Calls: @unchecked Sendable { var fetched = 0 }
    var calls = Calls()

    func state() async -> DashlaneVaultState? { state }
    func credentials(reference: String) async throws -> [DashlaneCredential] {
        calls.fetched += 1
        if let error { throw error }
        return entries
    }
}

// MARK: - The flag this whole source turns on

struct DashlaneOutputFlagTests {

    /// THE CENTRAL ASSERTION OF THIS FEED. `dcli password`'s default is the
    /// pasteboard; SimpleVPN must never invoke it, and must never fall back to it.
    @Test func theFetchAsksForJSONAndNeverForTheClipboard() {
        let argv = DashlaneCLIClient.fetchArguments(filter: "vpn.example.com")
        #expect(argv.contains("--output"))
        #expect(argv.contains("json"))
        #expect(!argv.contains("clipboard"))
        // Nor the other stdout mode: `--output console` runs Dashlane's interactive
        // picker when two entries match, and a spawned process cannot answer a prompt.
        #expect(!argv.contains("console"))
        // No `--field`: the json branch returns before the field switch is reached, so
        // a field flag would be a lie about what we asked for.
        #expect(!argv.contains("--field"))
        #expect(!argv.contains("-f"))
    }

    /// The filter is the only thing that rides argv, and it rides it after `--` so a
    /// term beginning with a dash stays a term.
    @Test func onlyTheFilterRidesArgv() {
        let argv = DashlaneCLIClient.fetchArguments(filter: "-weird-title")
        #expect(argv.last == "-weird-title")
        #expect(argv[argv.count - 2] == "--")
        #expect(argv.first == "password")
    }

    /// Live at the top level too: whatever else changes, no argument list SimpleVPN
    /// builds for Dashlane may name the pasteboard.
    @Test func noArgumentListEverNamesTheClipboard() async throws {
        let spy = DCLISpy()
        let provider = DashlaneProvider(reference: "vpn.example.com", channel: spy.client)
        _ = try await provider.resolve(profile: "vpn", fields: [.username, .password])
        #expect(!spy.everyArgument.contains("clipboard"))
        #expect(!spy.everyArgument.contains("-o"))
        #expect(spy.fetchArguments.first?.contains("json") == true)
    }
}

// MARK: - Reading `dcli`'s answers

struct DashlaneWireTests {

    @Test func oneEntryIsLifted() throws {
        let entry = try #require(DashlaneWire.credentials(DL.json()).first)
        #expect(entry.login == "jdoe")
        #expect(entry.password == "s3cr3t-vpn-pw")
        #expect(entry.totpSeed == "JBSWY3DPEHPK3PXP")
        #expect(entry.title == "GR Lab VPN")
        #expect(entry.id == DL.entryID)
    }

    /// Auto-sync's own log lines share stdout with the payload. Reading the LAST JSON
    /// array is what keeps a sync from hiding the answer.
    @Test func syncChatterAheadOfThePayloadIsSkipped() throws {
        let entries = DashlaneWire.credentials(DL.withSyncNoise(DL.json()))
        #expect(entries.count == 1)
        #expect(entries.first?.password == "s3cr3t-vpn-pw")
    }

    @Test func everyMatchIsReturned() {
        #expect(DashlaneWire.credentials(DL.twoMatches).count == 2)
    }

    @Test func unreadableBytesAreNotMistakenForAnAnswer() {
        #expect(DashlaneWire.credentials(Data([0xFF, 0xD8, 0xFF])).isEmpty)
        #expect(DashlaneWire.credentials(Data("Logged in: no".utf8)).isEmpty)
        #expect(DashlaneWire.credentials(Data()).isEmpty)
    }

    /// An entry may carry its username in any of three places, and which one is the
    /// user's business rather than ours.
    @Test func allThreeUsernameFieldsAreMatchable() throws {
        let entry = try #require(
            DashlaneWire.credentials(DL.json(login: "", email: "jdoe@example.com")).first)
        #expect(entry.usernames == ["jdoe@example.com"])
        #expect(entry.preferredUsername == "jdoe@example.com")
    }

    /// Only a SEED is usable: a bare six-digit number is a CODE, and taking one as a
    /// seed would freeze one wrong code for ever.
    @Test func onlyASeedIsAcceptedAsASeed() {
        #expect(DashlaneWire.seed("JBSWY3DPEHPK3PXP") == "JBSWY3DPEHPK3PXP")
        #expect(DashlaneWire.seed("otpauth://totp/GR?secret=JBSWY3DPEHPK3PXP")
                == "otpauth://totp/GR?secret=JBSWY3DPEHPK3PXP")
        #expect(DashlaneWire.seed("123456") == nil)
        #expect(DashlaneWire.seed("222222") == nil)
        #expect(DashlaneWire.seed("") == nil)
    }

    /// `otpUrl` is the alternative to `otpSecret`, and either is enough.
    @Test func anOTPAuthURLIsAcceptedInsteadOfASeed() throws {
        let json = Data("""
        [{"id":"x","title":"T","password":"p",\
        "otpUrl":"otpauth://totp/GR?secret=JBSWY3DPEHPK3PXP"}]
        """.utf8)
        let entry = try #require(DashlaneWire.credentials(json).first)
        #expect(entry.totpSeed == "otpauth://totp/GR?secret=JBSWY3DPEHPK3PXP")
    }

    // --- `dcli status` -----------------------------------------------------

    @Test func allThreeStatesAreRead() {
        #expect(DashlaneWire.state(DL.statusNotSignedIn) == .notSignedIn)
        #expect(DashlaneWire.state(DL.statusUnlocked) == .unlocked)
        #expect(DashlaneWire.state(DL.statusLocked) == .locked)
    }

    /// A shape we do not recognise reads as LOCKED, not unlocked: guessing unlocked
    /// would spawn a fetch that could sit on a master-password prompt for ever.
    @Test func anUnrecognisedShapeIsTreatedAsLockedRatherThanReady() {
        #expect(DashlaneWire.state("Logged in: yes") == .locked)
        #expect(DashlaneWire.state("") == nil)
        #expect(DashlaneWire.state("some future banner line") == nil)
    }

    /// winston colours its prefixes; a status parse must not depend on that.
    @Test func ansiColouringDoesNotBreakTheParse() {
        let coloured = "\u{1B}[32mLogged in: yes\u{1B}[0m\nLocked: no"
        #expect(DashlaneWire.state(coloured) == .unlocked)
    }

    /// The person's Dashlane email address is in that output and is deliberately
    /// dropped: nothing in SimpleVPN reads it, so it cannot reach a report.
    @Test func theSignedInEmailAddressIsNotCarriedAnywhere() {
        // The state enum has nowhere to put it — asserted structurally, by the fact
        // that every case is a bare state.
        for state in DashlaneVaultState.allCases {
            #expect(!state.rawValue.contains("@"))
        }
    }
}

// MARK: - Choosing one entry

struct DashlaneItemPickerTests {

    private static func entries(_ data: Data) -> [DashlaneCredential] {
        DashlaneWire.credentials(data)
    }

    @Test func oneMatchIsTheAnswer() throws {
        let picked = try DashlaneItemPicker.pick(Self.entries(DL.json()), account: "", reference: "vpn")
        #expect(picked.password == "s3cr3t-vpn-pw")
    }

    @Test func nothingUsableIsNotFound() {
        #expect(throws: DashlaneProvider.DashlaneError.notFound("vpn")) {
            try DashlaneItemPicker.pick(Self.entries(DL.noPassword), account: "", reference: "vpn")
        }
        #expect(throws: DashlaneProvider.DashlaneError.notFound("vpn")) {
            try DashlaneItemPicker.pick([], account: "", reference: "vpn")
        }
    }

    /// The case `--output console` would have answered with an interactive picker.
    /// Here it is a sentence with a fix in it.
    @Test func severalMatchesSayHowManyAndHowToFixIt() throws {
        let error = #expect(throws: DashlaneProvider.DashlaneError.self) {
            try DashlaneItemPicker.pick(Self.entries(DL.twoMatches), account: "", reference: "GR Lab VPN")
        }
        #expect(error == .severalMatches(2))
        let sentence = try #require(error?.errorDescription)
        #expect(sentence.contains("2"))
        #expect(sentence.contains("title="))
    }

    @Test func theUsernamePicksTheRightOne() throws {
        let picked = try DashlaneItemPicker.pick(Self.entries(DL.twoMatches),
                                                account: "admin", reference: "GR Lab VPN")
        #expect(picked.password == "admin-pw")
    }

    @Test func aUsernameMatchedByEmailAloneStillPicks() throws {
        let entries = Self.entries(DL.json(login: "", email: "jdoe@example.com"))
        let picked = try DashlaneItemPicker.pick(entries, account: "JDOE@EXAMPLE.COM",
                                                reference: "vpn")
        #expect(picked.password == "s3cr3t-vpn-pw")
    }

    @Test func aUsernameThatMatchesNothingSaysSo() {
        #expect(throws: DashlaneProvider.DashlaneError.wrongAccount("someone-else")) {
            try DashlaneItemPicker.pick(Self.entries(DL.twoMatches),
                                        account: "someone-else", reference: "GR Lab VPN")
        }
    }
}

// MARK: - The provider

struct DashlaneProviderTests {

    @Test func aReadyVaultYieldsTheSignIn() async throws {
        let spy = DCLISpy()
        let provider = DashlaneProvider(reference: "vpn.example.com", channel: spy.client)
        let raw = try await provider.resolve(profile: "vpn", fields: [.username, .password, .otp])
        #expect(raw.username == "jdoe")
        #expect(raw.password == "s3cr3t-vpn-pw")
        // Computed locally from the entry's own seed — never a second `dcli` call.
        #expect(raw.otp?.count == 6)
        #expect(spy.arguments.count == 2)          // one status, one fetch
    }

    /// A typed username wins over whatever the entry says: the person who typed it
    /// there meant it.
    @Test func aTypedUsernameWins() async throws {
        let spy = DCLISpy()
        // Two entries match the same title; the username says which.
        spy.fetchReply = DL.ok(DL.twoMatches)
        let provider = DashlaneProvider(reference: "GR Lab VPN", account: "admin", channel: spy.client)
        let raw = try await provider.resolve(profile: "vpn", fields: [.username, .password])
        #expect(raw.username == "admin")
        #expect(raw.password == "admin-pw")
    }

    @Test func onlyTheRequestedFieldsComeBack() async throws {
        let spy = DCLISpy()
        let provider = DashlaneProvider(reference: "vpn.example.com", channel: spy.client)
        let raw = try await provider.resolve(profile: "vpn", fields: [.password])
        #expect(raw.password == "s3cr3t-vpn-pw")
        #expect(raw.username == nil)
        #expect(raw.otp == nil)
    }

    /// THE HANG GUARD. A locked vault must be reported, not fetched from: `dcli` would
    /// ask for the master password on a stdin that is `/dev/null`.
    @Test func aLockedVaultIsNeverFetchedFrom() async {
        let channel = FixedChannel(state: .locked, entries: DashlaneWire.credentials(DL.json()))
        let provider = DashlaneProvider(reference: "vpn.example.com", channel: channel)
        await #expect(throws: DashlaneProvider.DashlaneError.locked) {
            try await provider.resolve(profile: "vpn", fields: [.password])
        }
        #expect(channel.calls.fetched == 0, "a locked vault was asked for an entry anyway")
    }

    @Test func anUnregisteredMacIsNeverFetchedFrom() async {
        let channel = FixedChannel(state: .notSignedIn)
        let provider = DashlaneProvider(reference: "vpn.example.com", channel: channel)
        await #expect(throws: DashlaneProvider.DashlaneError.notSignedIn) {
            try await provider.resolve(profile: "vpn", fields: [.password])
        }
        #expect(channel.calls.fetched == 0)
    }

    /// "We couldn't ask" is its own answer, and it never reads as "you aren't signed
    /// in".
    @Test func noToolAtAllIsItsOwnSentence() async throws {
        let channel = FixedChannel(state: nil)
        let provider = DashlaneProvider(reference: "vpn.example.com", channel: channel)
        let error = await #expect(throws: DashlaneProvider.DashlaneError.self) {
            try await provider.resolve(profile: "vpn", fields: [.password])
        }
        #expect(error == .toolUnavailable)
        let sentence = try #require(error?.errorDescription)
        #expect(!sentence.lowercased().contains("signed in"))
        #expect(channel.calls.fetched == 0)
    }

    @Test func anEntryWithNoPasswordIsSaidPlainly() async throws {
        let spy = DCLISpy()
        spy.fetchReply = DL.ok(DL.noPassword)
        let provider = DashlaneProvider(reference: "vpn.example.com", channel: spy.client)
        // No usable entry at all ⇒ the picker's "not found", which is the honest
        // answer: an entry with no password cannot sign anything in.
        await #expect(throws: DashlaneProvider.DashlaneError.notFound("vpn.example.com")) {
            try await provider.resolve(profile: "vpn", fields: [.password])
        }
    }

    @Test func anEmptyReferenceIsRefusedBeforeAnythingRuns() async {
        let spy = DCLISpy()
        let provider = DashlaneProvider(reference: "   ", channel: spy.client)
        await #expect(throws: DashlaneProvider.DashlaneError.noItem) {
            try await provider.resolve(profile: "vpn", fields: [.password])
        }
        #expect(spy.arguments.isEmpty)
        #expect(await provider.isAvailable(for: "vpn") == false)
    }

    @Test func availabilityIsUnlockedAndNothingLess() async {
        let ready = DashlaneProvider(reference: "vpn", channel: FixedChannel(state: .unlocked))
        #expect(await ready.isAvailable(for: "vpn"))
        for state in [DashlaneVaultState.locked, .notSignedIn] {
            let provider = DashlaneProvider(reference: "vpn", channel: FixedChannel(state: state))
            #expect(await provider.isAvailable(for: "vpn") == false)
        }
    }
}

// MARK: - The channel

struct DashlaneChannelTests {

    @Test func statusIsReadAndCostsTheShorterDeadline() async {
        let spy = DCLISpy()
        let state = await spy.client.state()
        #expect(state == .unlocked)
        #expect(spy.arguments == [["status"]])
        // A status probe cannot prompt, so it gets the short budget; a fetch may raise
        // Dashlane's own Touch ID sheet, so it gets the long one.
        #expect((spy.deadlines.first ?? 0) < DashlaneCLIClient().fetchDeadline)
    }

    @Test func aToolWeWontRunAnswersNothing() async {
        let client = DashlaneCLIClient { _, _ in DL.notRunnable }
        #expect(await client.state() == nil)
    }

    @Test func nothingMatchingIsNotFound() async {
        let client = DashlaneCLIClient { _, _ in DL.failed("No credential found with this filters.") }
        await #expect(throws: DashlaneProvider.DashlaneError.notFound("vpn")) {
            _ = try await client.credentials(reference: "vpn")
        }
    }

    @Test func anEmptyJSONArrayIsNotFoundRatherThanAnEmptyAnswer() async {
        let client = DashlaneCLIClient { _, _ in DL.ok(Data("[]".utf8)) }
        await #expect(throws: DashlaneProvider.DashlaneError.notFound("vpn")) {
            _ = try await client.credentials(reference: "vpn")
        }
    }

    @Test func aTimeoutIsItsOwnAnswer() async throws {
        let client = DashlaneCLIClient { _, _ in DL.timedOut }
        let error = await #expect(throws: DashlaneProvider.DashlaneError.self) {
            _ = try await client.credentials(reference: "vpn")
        }
        #expect(error == .timedOut)
        let sentence = try #require(error?.errorDescription)
        #expect(sentence.lowercased().contains("fingerprint"))
    }

    @Test func theToolsOwnFailuresAreClassified() {
        #expect(DashlaneCLIClient.error(stderr: "No device registered in the database",
                                       reference: "vpn") == .notSignedIn)
        #expect(DashlaneCLIClient.error(stderr: "Touch ID verification failed: cancelled",
                                       reference: "vpn") == .locked)
        #expect(DashlaneCLIClient.error(stderr: "Wrong master password",
                                       reference: "vpn") == .locked)
    }

    /// An unrecognised vendor message is scrubbed and truncated by the SAME function
    /// every tool's stderr goes through before it may be shown.
    @Test func anUnknownVendorMessageIsScrubbedBeforeItCouldBeShown() throws {
        let error = DashlaneCLIClient.error(stderr: "ENOENT: something odd", reference: "vpn")
        guard case .unreadable(let detail) = error else {
            Issue.record("expected an unreadable failure")
            return
        }
        #expect(detail == LocalToolRunner.scrub("ENOENT: something odd"))
    }
}

// MARK: - The four states, and the one fix each

struct DashlaneAvailabilityTests {

    /// NOTHING Dashlane on this Mac: no tool, nowhere, no app, no database of its own.
    @Test func nothingDashlaneIsNotOffered() {
        #expect(DashlaneVaultAdapter.availability(toolIsRunnable: false,
                                                 foundOutsideAllowList: false,
                                                 appIsInstalled: false,
                                                 hasLocalDatabase: false) == .notInstalled)
    }

    /// The app is here (or `dcli` has been used here) but there is no tool we may run:
    /// one command fixes it, and it is NOT "you don't have Dashlane".
    @Test func theToolMissingIsAnInstallNotAnAbsence() {
        #expect(DashlaneVaultAdapter.availability(toolIsRunnable: false,
                                                 foundOutsideAllowList: false,
                                                 appIsInstalled: true,
                                                 hasLocalDatabase: false)
                == .blocked(.toolMissing))
        // Somebody who uses Dashlane only in a browser has no app — but `dcli`'s own
        // database proves they use the tool.
        #expect(DashlaneVaultAdapter.availability(toolIsRunnable: false,
                                                 foundOutsideAllowList: false,
                                                 appIsInstalled: false,
                                                 hasLocalDatabase: true)
                == .blocked(.toolMissing))
    }

    /// THE STATE THAT MUST NEVER READ AS "not installed": `dcli` in Yarn's global
    /// folder is a path to paste, not a thing to install.
    @Test func foundButOutsideTheAllowListIsItsOwnState() {
        #expect(DashlaneVaultAdapter.availability(toolIsRunnable: false,
                                                 foundOutsideAllowList: true,
                                                 appIsInstalled: false,
                                                 hasLocalDatabase: false)
                == .blocked(.toolOutsideAllowList))
        // And it wins over "install it": we can see the copy they already have.
        #expect(DashlaneVaultAdapter.availability(toolIsRunnable: false,
                                                 foundOutsideAllowList: true,
                                                 appIsInstalled: true,
                                                 hasLocalDatabase: true)
                == .blocked(.toolOutsideAllowList))
    }

    /// A runnable tool is offered with the check owed — not claimed ready, because
    /// whether the vault is unlocked needs a real `dcli status`.
    @Test func arunnableToolOwesACheck() {
        #expect(DashlaneVaultAdapter.availability(toolIsRunnable: true,
                                                 foundOutsideAllowList: false,
                                                 appIsInstalled: false,
                                                 hasLocalDatabase: false) == .unchecked(.checkOwedOnUse))
    }

    @Test func eachVaultStateHasItsOwnBlock() {
        #expect(DashlaneVaultAdapter.availability(for: .unlocked) == .ready)
        #expect(DashlaneVaultAdapter.availability(for: .locked) == .blocked(.vaultLocked))
        #expect(DashlaneVaultAdapter.availability(for: .notSignedIn) == .blocked(.notSignedIn))
    }

    /// The deep scan never spawns for a tool we would refuse to run, and never
    /// invents a state when nothing answered.
    @Test func theDeepScanRespectsWhatTheCheapPassAlreadyKnows() async {
        let adapter = DashlaneVaultAdapter(channel: FixedChannel(state: .unlocked))
        #expect(await adapter.deepScan(quick: .notInstalled) == .notInstalled)
        #expect(await adapter.deepScan(quick: .blocked(.toolMissing)) == .blocked(.toolMissing))
        #expect(await adapter.deepScan(quick: .blocked(.toolOutsideAllowList))
                == .blocked(.toolOutsideAllowList))
        #expect(await adapter.deepScan(quick: .unchecked(.checkOwedOnUse)) == .ready)
        let silent = DashlaneVaultAdapter(channel: FixedChannel(state: nil))
        #expect(await silent.deepScan(quick: .unchecked(.checkOwedOnUse)) == .unchecked(.checkOwedOnUse))
    }

    /// Every blocked state a Dashlane row can be in has copy AND a way out on screen.
    @Test func everyBlockedStateHasCopyAndAFix() throws {
        let copy = LocalVaultCopyBook.copy(for: .dashlane)
        for block in [LocalVaultBlock.toolMissing, .toolOutsideAllowList, .notSignedIn, .vaultLocked] {
            #expect(copy.blocks[block] != nil, "\(block.rawValue) has no copy")
            #expect(!copy.headline(for: block).isEmpty)
            #expect(block.wantsEnablementBanner, "\(block.rawValue) offers no banner")
        }
        // `toolOutsideAllowList`'s guidance is BUILT at runtime so it can name the path
        // on this Mac; the others are declared.
        for block in [LocalVaultBlock.toolMissing, .notSignedIn, .vaultLocked] {
            #expect(copy.guidance(for: block) != nil, "\(block.rawValue) has no way out")
        }
        let built = try #require(copy.guidance(for: .toolOutsideAllowList,
                                               foundAt: "/Users/you/.yarn/bin/dcli"))
        #expect(built.benefit.contains("/Users/you/.yarn/bin/dcli"))
        #expect(built.example.contains { $0.text == "brew install dashlane/tap/dashlane-cli" })
    }

    /// The one-time setup is surfaced as an enablement banner with a CURRENT-version
    /// example, and it says what Dashlane will ask for.
    @Test func theOneTimeRegistrationIsInTheBanner() throws {
        let guidance = try #require(LocalVaultCopyBook.copy(for: .dashlane).guidance(for: .notSignedIn))
        #expect(guidance.example.contains { $0.text == "dcli sync" })
        let spoken = guidance.spokenSummary
        #expect(spoken.contains("token"))
        #expect(spoken.contains(VendorDocs.dashlaneAuthentication.title))
    }
}

// MARK: - What the source promises, and what it declares

struct DashlaneDeclarationTests {

    /// A PROMISE nobody has watched kept is not made. Dashlane's entries can carry a
    /// seed and the fetch uses it — but `suppliesOTP` stays false, exactly as Keeper's,
    /// Bitwarden's and the password store's do.
    @Test func codesAreNotPromised() {
        #expect(CredentialSourceKind.dashlane.suppliesOTP == false)
    }

    /// ONE signed-in account per Mac: one database, one device row, one keychain entry,
    /// and no `--config` anywhere in `dcli`. So no instance list, and no instance-level
    /// fields.
    @Test func dashlaneIsSingleInstance() {
        #expect(LocalVaultVendor.dashlane.cardinality == .single)
        #expect(!LocalVaultVendor.dashlane.cardinality.allowsSeveral)
        for field in SignInSourceSettings.fields(for: .dashlane) {
            #expect(field.vendor == .dashlane)
        }
    }

    /// The only thing configurable is where the tool is — level 1, per Mac. Everything
    /// else about reaching Dashlane is `dcli`'s own configuration.
    @Test func theOnlySettingIsTheToolPath() throws {
        let fields = SignInSourceSettings.fields(for: .dashlane)
        #expect(fields.count == 1)
        let field = try #require(fields.first)
        #expect(field.settingID == "creds.dashlane.tool-path")
        #expect(field.defaultsKey == "signin.tool.dcli.path")
        guard case .toolBinary(let tool) = field.kind else {
            Issue.record("the Dashlane field is not a tool path")
            return
        }
        #expect(tool == "dcli")
    }

    /// Discovery knows `dcli` belongs to Dashlane — which is what puts "found at …, but
    /// not somewhere SimpleVPN will run it from" on the Dashlane row rather than
    /// nowhere.
    @Test func discoveryAttributesTheToolToTheVendor() throws {
        let tool = try #require(ToolCatalog.tool(named: "dcli"))
        #expect(tool.vendor == .dashlane)
        // Dashlane's own manual-install instructions name this path verbatim.
        #expect(tool.vendorInstallerPaths.contains("/usr/local/bin/dcli"))
        #expect(ToolCatalog.tools(for: .dashlane).map(\.name) == ["dcli"])
    }

    @Test func theAdapterIsRegisteredAndReachableBothWays() throws {
        let byVendor = try #require(LocalVaultRegistry.adapter(for: LocalVaultVendor.dashlane))
        #expect(byVendor.storedKind == .dashlane)
        #expect(byVendor.transports == [.cli])
        let byKind = try #require(LocalVaultRegistry.adapter(for: CredentialSourceKind.dashlane))
        #expect(byKind.vendor == .dashlane)
    }

    /// A source that names nothing to fetch yields no provider, which routes to the
    /// typed fields rather than a doomed lookup.
    @Test func aSourceWithNoEntryYieldsNoProvider() {
        var source = CredentialSource()
        source.kind = .dashlane
        #expect(DashlaneVaultAdapter().provider(for: source) == nil)
        source.reference = "vpn.example.com"
        #expect(DashlaneVaultAdapter().provider(for: source) != nil)
    }

    /// The app is a POINTER to the way in, never a second row of its own.
    @Test func theDesktopAppPointsAtTheToolRatherThanBeingASecondRow() {
        #expect(PasswordAppCatalog.gatedVendor(forBundleID: "com.dashlane.Dashlane") == .dashlane)
        #expect(PasswordAppCatalog.gatedVendor(forBundleID: "com.dashlane.something-new") == .dashlane)
        #expect(!PasswordAppCatalog.isIntegratedApp(bundleID: "com.dashlane.Dashlane"))
    }

    /// The recovery sentence names the source, as every other one does — and does not
    /// claim Dashlane is missing, because it probably isn't.
    @Test func theRecoverySentenceNamesDashlaneAndTheFix() {
        let sentence = SignInFlow.unavailableHeadline(.dashlane)
        #expect(sentence.contains("Dashlane"))
        #expect(sentence.contains("dcli sync"))
        #expect(!sentence.contains("isn\u{2019}t installed"))
    }

    /// The database path is `dcli`'s own, spelled as its source spells it.
    @Test func theCheapProbeLooksAtOneFile() {
        let home = URL(fileURLWithPath: "/Users/you")
        #expect(DashlaneLocalStore.databasePath(home: home)
                == "/Users/you/Library/Application Support/dashlane-cli/userdata.db")
        #expect(DashlaneLocalStore.hasDatabase(home: home, fileExists: { _ in true }))
        #expect(!DashlaneLocalStore.hasDatabase(home: home, fileExists: { _ in false }))
    }

    /// Every diagnostic-report switch stays exhaustive, and Dashlane's app is named in
    /// it: "app here, tool missing" and "neither" are different reports.
    @Test func theInventoryNamesTheApp() {
        #expect(DiagnosticReportInventory.vendorBundleIDs(.dashlane)
                .contains("com.dashlane.Dashlane"))
    }

    /// Unproven, and it says so: the registry is what keeps the app honest about a
    /// source no real vault has ever answered.
    @Test func theSourceIsDeclaredUntested() {
        #expect(FeatureMaturityRegistry.maturity(ofSource: .vault(.dashlane)) == .untested)
    }
}
