// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
//  DashlaneProvider.swift
//  Fetch a username/password (and a verification code, when the entry carries a
//  seed) from Dashlane — through `dcli`, Dashlane's own command-line tool.
//
//  THE FLAG THIS WHOLE FILE TURNS ON: `--output console`.
//
//  `dcli password` COPIES TO THE PASTEBOARD BY DEFAULT. That is not a rumour, it is
//  the vendor's own declaration — `src/commands/index.ts` registers the command as
//  "Retrieve a password from the local vault and copy it to the clipboard" with
//  `new Option('-o, --output <type>').choices(['clipboard', 'console', 'json'])
//  .default('clipboard')`. A VPN password on the pasteboard is readable by every
//  program on this Mac, and no amount of "we clear it afterwards" makes that
//  acceptable, so the default is the one thing this file may never invoke.
//
//  Two escape routes exist and both are in `src/command-handlers/passwords.ts`:
//
//      if (output === 'json') { logger.content(JSON.stringify(foundCredentials)); return; }
//      ...
//      if (output === 'console') { logger.content(result); return; }
//      const clipboard = new Clipboard();
//      clipboard.setText(result);
//
//  Both RETURN BEFORE the `Clipboard` is ever constructed. So the pasteboard is
//  reached only on the path we do not take, and that is a structural fact about the
//  vendor's own control flow rather than a promise in a release note.
//
//  WE USE `--output json`, NOT `--output console`, AND THE REASON IS THE PROMPT.
//  Look at the order in `runPassword`: the `json` branch returns before
//  `selectCredential`, while the `console` branch runs after it — and
//  `selectCredential` calls `askCredentialChoice`, an INTERACTIVE list prompt,
//  whenever more than one entry matches. A prompt cannot be answered by a program
//  SimpleVPN spawned with `/dev/null` on stdin, so `--output console` would work
//  perfectly for a term matching one entry and hang (or die) for a term matching
//  two. `--output json` never reaches the picker: it prints every match and lets US
//  choose, by username, which is also the only way to express "the admin login on
//  that entry, not the personal one". The same reasoning made Bitwarden's channel
//  list-then-pick rather than `bw get item`.
//
//  So: one invocation, `dcli password --output json <filter>`, and the whole match
//  set arrives on stdout — which `LocalToolResult` already treats as secret-bearing.
//  The pasteboard is never written, `-f/--field` is never needed (the json branch
//  ignores it), and disambiguation is ours.
//
//  WHAT MUST BE TRUE BEFORE WE SPAWN ANYTHING, and this is a hang guard rather than
//  politeness. `runPassword` calls `connectAndPrepare({})`, which will ask
//  `askMasterPassword()` on stdin when the local key is not in the OS keychain
//  (`getLocalConfigurationWithoutKeychain` in `src/modules/crypto/keychainManager
//  .ts`). With `/dev/null` on stdin that question can never be answered. So a fetch
//  is only ever attempted when `dcli status` has already said the vault is
//  UNLOCKED, and "locked" is reported as a state with a fix instead of being
//  discovered as a timeout. The `pass` feed reached the identical conclusion about
//  gpg's pinentry, for the identical reason.
//
//  WHO OWNS THE PROMPT WHEN THERE IS ONE: Dashlane does, entirely. With
//  `dcli configure user-presence --method biometrics` the CLI itself calls
//  `promptTouchID` through `node-mac-auth` (`src/modules/auth/
//  userPresenceVerification.ts`, reason string "validate your identity before
//  accessing your vault"). SimpleVPN neither raises that sheet nor sees its result;
//  it only waits, with a deadline. There is no path here that asks anyone for a
//  Dashlane master password — the sentence every other vendor's copy makes ("the
//  app does the unlocking") stays true for this one.
//
//  Non-negotiables shared with every other CLI-backed source (see LocalToolRunner):
//   • the secret arrives on stdout and is never logged, quoted in an error, or
//     placed in argv;
//   • only the entry's own filter term rides argv — the user's own label, which is
//     what they typed to find it;
//   • we never write Dashlane's configuration, never register a device, never sign
//     anyone in and never modify the vault. Setup stays the user's to perform and we
//     print the commands;
//   • nothing is cached: each connect asks again, so `dcli lock` takes effect
//     immediately.
//
//  ONE THING `dcli` DOES THAT NO OTHER SOURCE HERE DOES: a fetch may go to the
//  network. `connectAndPrepare` synchronises the local vault when the last sync is
//  over an hour old and auto-sync has not been switched off, so `dcli password` is
//  sometimes a sync as well as a read. That is why the fetch deadline is generous
//  and why the recipe in Docs/Dashlane.md suggests `dcli configure disable-auto-sync
//  true` plus a scheduled `dcli sync` for anyone who wants connects to be purely
//  local. It also means sync's own progress lines land on stdout ahead of the JSON,
//  which is exactly why `DashlaneWire` reads the LAST JSON array rather than the
//  whole stream.
//
//  `CredentialSourceKind.dashlane.suppliesOTP` is FALSE, deliberately, and it is not
//  because Dashlane cannot: an entry's `otpSecret` / `otpUrl` arrives in the same
//  JSON and the code is computed locally from it with the app's own RFC 6238 engine
//  when it is there. But that flag is a PROMISE that Connect works with nothing
//  typed, and no real Dashlane vault has ever answered here — the Keeper, Bitwarden
//  and `pass` precedent, kept on purpose.
//

import Foundation
import AppKit
import os

// MARK: - What one entry gives us

/// One Dashlane vault entry, as much of it as a sign-in needs.
///
/// The key names are the vendor's own, after the transformation `findCredentials`
/// applies: Dashlane's XML `KWDataItem` keys are lower-cased in their first letter
/// only, so `Login` becomes `login`, `OtpSecret` becomes `otpSecret`. That mapping
/// is in `src/command-handlers/passwords.ts` and is why this decoder does not
/// guess at casing.
///
/// The secret halves are never logged and never described in an error.
nonisolated struct DashlaneCredential: Sendable, Equatable {
    /// Dashlane's own id for the entry. Not a secret — it is what we tell the user
    /// to paste when several entries match — but not shown unless they ask.
    var id: String?
    /// The entry's title, and the address it is for. Not secrets: they are what the
    /// user typed to find it.
    var title: String?
    var url: String?
    /// The three places a username can live in a Dashlane entry. All three are
    /// matched when disambiguating, because which one an entry uses is the user's
    /// choice and not something we get to insist on.
    var login: String?
    var email: String?
    var secondaryLogin: String?
    var password: String?
    /// A base32 SEED or an `otpauth://` URL, so the code is computed locally —
    /// never a second invocation of `dcli password -f otp`, which would be a second
    /// vault read, a second possible Touch ID prompt and a second chance to hit the
    /// pasteboard default.
    var totpSeed: String?

    var hasPassword: Bool { !(password ?? "").isEmpty }

    /// Every username this entry answers to, in the order Dashlane's own UI shows
    /// them. Used only for matching, never displayed.
    var usernames: [String] {
        [login, email, secondaryLogin].compactMap { $0 }.filter { !$0.isEmpty }
    }

    /// The username to hand over: the primary login, else whichever of the others
    /// exists. An entry that only carries an email address still has a username as
    /// far as a VPN is concerned.
    var preferredUsername: String? { usernames.first }

    /// A label safe to put in an error message: the title, else the address, else
    /// nothing at all. Deliberately never the username or the id.
    var safeLabel: String? {
        for candidate in [title, url] {
            if let candidate, !candidate.isEmpty { return candidate }
        }
        return nil
    }
}

/// Which of `dcli`'s three states this Mac's Dashlane is in.
///
/// They are the vendor's own, and the mapping is a lookup rather than an
/// interpretation: `runStatus` in `src/command-handlers/status.ts` prints
/// `Logged in: no` when there is no registered device, and otherwise
/// `Logged in: yes` / `Login: …` / `Locked: yes|no`, where `Locked` is computed by
/// `isVaultLocked` from three facts — the master password is not to be saved, or no
/// encrypted master password is in its database, or the OS keychain has no local key
/// for that login.
nonisolated enum DashlaneVaultState: String, Sendable, Equatable, CaseIterable {
    /// No device registered: nobody has signed this Mac in to Dashlane.
    case notSignedIn
    /// Signed in, but nothing on this Mac can decrypt the vault without the master
    /// password being typed. Its own state because the fix is a different command
    /// from signing in, and telling someone who IS signed in that they are not is
    /// how a person concludes the app cannot see their vault at all.
    case locked
    /// Signed in and the local key is in the OS keychain: a fetch can succeed with
    /// nothing typed (a Touch ID sheet from Dashlane aside).
    case unlocked
}

// MARK: - The channel seam

/// How this Mac talks to Dashlane. One implementation ships (`dcli`); tests inject
/// another with no Dashlane present at all.
///
/// Two calls, and the split matters: `state()` is prompt-free and cheap enough for a
/// deep scan, while `credentials(reference:)` may sync, may raise Dashlane's own
/// Touch ID sheet, and returns secrets.
nonisolated protocol DashlaneChannel: Sendable {
    /// Which state this Mac's Dashlane is in, or nil when the channel cannot answer
    /// at all (no tool we may run). Prompt-free and secret-free.
    func state() async -> DashlaneVaultState?
    /// Every entry matching `reference`. Disambiguation is the caller's.
    func credentials(reference: String) async throws -> [DashlaneCredential]
}

// MARK: - Reading `dcli`'s answers (pure, and tolerant of its logging)

/// `dcli` prints its payload through winston at a custom `content` level with an
/// empty prefix, on the same Console transport its `info`, `success` and `warn`
/// lines use (`src/logger.ts`). So the JSON is one line on stdout, and it is not
/// necessarily the only line: an auto-sync ahead of it logs progress, and an
/// unreachable keychain logs a warning.
///
/// Hence: find the LAST line that is a JSON array. Not the first, because sync
/// output comes first; not the whole buffer, because it is not JSON.
nonisolated enum DashlaneWire {

    /// Every entry in a `--output json` reply. An answer that is not an array at all
    /// yields an empty list rather than an error — "no JSON came back" is reported by
    /// the caller as "nothing matched", which is what it means.
    static func credentials(_ data: Data) -> [DashlaneCredential] {
        let text = String(decoding: data, as: UTF8.self)
        for line in text.components(separatedBy: .newlines).reversed() {
            let trimmed = line.trimmingCharacters(in: .whitespaces)
            guard trimmed.hasPrefix("["), trimmed.hasSuffix("]"),
                  let bytes = trimmed.data(using: .utf8),
                  let any = try? JSONSerialization.jsonObject(with: bytes),
                  let array = any as? [Any] else { continue }
            return array.compactMap(credential)
        }
        return []
    }

    /// One entry out of one JSON object. Every field is optional: Dashlane's entries
    /// are assembled from whichever `KWDataItem`s a given entry happens to have, so a
    /// strict decode would throw away a perfectly good password because an entry had
    /// no `email` on it.
    static func credential(_ any: Any) -> DashlaneCredential? {
        guard let dict = any as? [String: Any] else { return nil }
        var out = DashlaneCredential()
        out.id = nonEmpty(dict["id"])
        out.title = nonEmpty(dict["title"])
        out.url = nonEmpty(dict["url"])
        out.login = nonEmpty(dict["login"])
        out.email = nonEmpty(dict["email"])
        out.secondaryLogin = nonEmpty(dict["secondaryLogin"])
        out.password = nonEmpty(dict["password"])
        // `otpSecret` is the base32 seed; `otpUrl` is a whole `otpauth://` URL.
        // `passwords.ts` prefers the secret when both are present, and so does this.
        out.totpSeed = nonEmpty(dict["otpSecret"]).flatMap(seed)
            ?? nonEmpty(dict["otpUrl"]).flatMap(seed)
        // An object with nothing in it we can use is not an entry we found.
        return (out.id != nil || out.title != nil || out.url != nil
                || out.login != nil || out.password != nil) ? out : nil
    }

    /// `dcli status`, as a state. Line-oriented and case-insensitive on the labels,
    /// because the labels are somebody else's release notes; the SHAPE (a
    /// `Logged in:` line, and a `Locked:` line when it is yes) is what is relied on.
    ///
    /// The `Login:` line — the person's Dashlane email address — is deliberately
    /// dropped on the floor. Nothing in SimpleVPN needs it, and a personal
    /// identifier nobody reads is one that cannot end up in a report.
    static func state(_ text: String) -> DashlaneVaultState? {
        var signedIn: Bool?
        var locked: Bool?
        for line in text.components(separatedBy: .newlines) {
            let stripped = strippingANSI(line).trimmingCharacters(in: .whitespaces).lowercased()
            guard let colon = stripped.firstIndex(of: ":") else { continue }
            let label = stripped[stripped.startIndex..<colon].trimmingCharacters(in: .whitespaces)
            let value = stripped[stripped.index(after: colon)...].trimmingCharacters(in: .whitespaces)
            switch label {
            case "logged in": signedIn = (value == "yes")
            case "locked": locked = (value == "yes")
            default: continue
            }
        }
        guard let signedIn else { return nil }
        guard signedIn else { return .notSignedIn }
        // Signed in with no `Locked:` line at all is a shape we do not recognise, and
        // guessing "unlocked" would mean spawning a fetch that could sit on a master
        // password prompt. So the cautious reading is the locked one.
        return (locked ?? true) ? .locked : .unlocked
    }

    /// winston colours its level prefixes with ANSI escapes (`src/logger.ts`), and a
    /// status line could pick one up if the vendor ever changes which level it prints
    /// at. Stripping them costs nothing and keeps the parse from depending on that.
    static func strippingANSI(_ line: String) -> String {
        var out = ""
        var inEscape = false
        for character in line {
            if inEscape {
                if character.isLetter { inEscape = false }
                continue
            }
            if character == "\u{1B}" { inEscape = true; continue }
            out.append(character)
        }
        return out
    }

    private static func nonEmpty(_ value: Any?) -> String? {
        guard let text = value as? String, !text.isEmpty else { return nil }
        return text
    }

    /// Only a SEED is usable, and the test is the one Bitwarden's wire already
    /// makes for the same reason: a bare six-to-eight digit number is a CODE, and
    /// taking one as a seed would freeze one wrong code for ever. Digits alone
    /// cannot always be told from base32 ("222222" decodes), so that shape is
    /// refused outright rather than guessed at.
    static func seed(_ value: String) -> String? {
        let trimmed = value.trimmingCharacters(in: .whitespacesAndNewlines)
        if trimmed.lowercased().hasPrefix("otpauth://") { return trimmed }
        let compact = trimmed.filter { !" -".contains($0) }
        if (6...8).contains(compact.count), compact.allSatisfy(\.isNumber) { return nil }
        return trimmed.isEmpty ? nil : trimmed
    }
}

/// Choosing ONE entry when a filter matched several. Pure, so "several matches" and
/// "the username picks the right one" are tested without a vault.
///
/// It exists because the alternative is `dcli`'s own interactive picker, which a
/// spawned process with no stdin cannot answer — see this file's header.
nonisolated enum DashlaneItemPicker {

    static func pick(_ entries: [DashlaneCredential],
                     account: String,
                     reference: String) throws -> DashlaneCredential {
        // An entry with no password cannot sign anything in, so it is not a
        // candidate. That is also what stops a note or a payment card of the same
        // name from being reported as an ambiguity.
        let usable = entries.filter(\.hasPassword)
        guard !usable.isEmpty else { throw DashlaneProvider.DashlaneError.notFound(reference) }
        guard !account.isEmpty else {
            if usable.count == 1 { return usable[0] }
            throw DashlaneProvider.DashlaneError.severalMatches(usable.count)
        }
        let matching = usable.filter { entry in
            entry.usernames.contains { $0.caseInsensitiveCompare(account) == .orderedSame }
        }
        guard let first = matching.first else {
            throw DashlaneProvider.DashlaneError.wrongAccount(account)
        }
        guard matching.count == 1 else {
            throw DashlaneProvider.DashlaneError.severalMatches(matching.count)
        }
        return first
    }
}

// MARK: - Where `dcli` keeps its own state

/// The two files-on-disk facts about Dashlane that cost no subprocess and no prompt.
///
/// `dcli` keeps one SQLite database — `~/Library/Application Support/dashlane-cli/
/// userdata.db`, built from `process.env.HOME + '/Library/Application Support'` in
/// `src/modules/database/connect.ts`. Its existence is the cheapest possible proof
/// that somebody on this Mac uses the Dashlane CLI, and it is the signal that turns
/// "you don't have Dashlane" into "install the tool" for a person who uses Dashlane
/// in a browser and has never installed the desktop app.
///
/// NOTHING IS READ OUT OF IT. It is another program's database, it is encrypted, and
/// `dcli status` already answers the only question we have about its contents. A
/// `stat` is the whole interaction.
nonisolated enum DashlaneLocalStore {

    static func databasePath(home: URL = FileManager.default.homeDirectoryForCurrentUser) -> String {
        home.appendingPathComponent("Library/Application Support/dashlane-cli/userdata.db").path
    }

    static func hasDatabase(home: URL = FileManager.default.homeDirectoryForCurrentUser,
                            fileExists: (String) -> Bool = { FileManager.default.fileExists(atPath: $0) })
    -> Bool {
        fileExists(databasePath(home: home))
    }
}

// MARK: - The `dcli` channel

/// The shipped channel. One tool, two invocations, and neither of them ever names
/// the pasteboard.
nonisolated struct DashlaneCLIClient: DashlaneChannel {

    /// Injected so the whole path — every state, every failure, the several-matches
    /// case, and the assertion that no argument ever says `clipboard` — is driven by
    /// fixtures with no `dcli` installed.
    var run: @Sendable (_ arguments: [String], _ deadline: TimeInterval) async -> LocalToolResult

    /// A fetch's budget. Generous on purpose, and for two reasons that are both
    /// somebody else's work rather than ours: Dashlane may put a Touch ID sheet on
    /// screen (which a person has to notice and answer), and `connectAndPrepare` may
    /// synchronise the vault over the network first. It is never absent — a connect
    /// that waits for ever is the failure this deadline exists to prevent.
    var fetchDeadline: TimeInterval = 60
    /// A status probe's budget. Short, because `runStatus` cannot prompt, cannot
    /// sync and touches nothing but a SQLite file and the OS keychain.
    var statusDeadline: TimeInterval = 15

    init(run: (@Sendable (_ arguments: [String], _ deadline: TimeInterval) async -> LocalToolResult)? = nil) {
        self.run = run ?? DashlaneCLIClient.liveRun
    }

    /// Where `dcli` is, if anywhere. Resolved against `LocalToolRunner`'s allow-list
    /// — never `PATH`, and never a second copy of those rules. Dashlane documents
    /// three installs: Homebrew (`brew install dashlane/tap/dashlane-cli`), a
    /// standalone binary the guide moves to `/usr/local/bin/dcli`, and Yarn. The
    /// first two land somewhere the runner already searches; the third is exactly
    /// the case `signin.tool.dcli.path` exists for.
    static func locate() -> String? { LocalToolRunner.locate("dcli") }

    static let liveRun: @Sendable ([String], TimeInterval) async -> LocalToolResult = { arguments, deadline in
        guard let executable = locate() else {
            return LocalToolResult(exitCode: -1, stdout: Data(),
                                   stderr: "not an approved tool location", timedOut: false)
        }
        // No `stdin:` — the runner's default is `/dev/null`, and that is deliberate
        // here rather than incidental: it is what guarantees SimpleVPN can never
        // answer one of `dcli`'s prompts, and therefore that a prompt is always a
        // state to report rather than a thing to satisfy.
        return await LocalToolRunner.run(executable: executable, arguments: arguments,
                                         deadline: deadline)
    }

    /// `dcli status`. Prompt-free, network-free and secret-free by construction:
    /// `runStatus` does not call `connectAndPrepare`, so it cannot ask for a master
    /// password, cannot verify user presence and cannot synchronise.
    func state() async -> DashlaneVaultState? {
        let result = await run(["status"], statusDeadline)
        guard result.succeeded else { return nil }
        return DashlaneWire.state(result.text)
    }

    /// `dcli password --output json <filter>` — the one fetch, and the flag that
    /// keeps the password off the pasteboard.
    ///
    /// ARGV holds the filter and nothing else. The filter is the user's own label
    /// for the entry (a title, an address, or Dashlane's `<param>=<value>` form),
    /// which they typed in order to find it; it is not a secret, and nothing that is
    /// one goes near an argument list `ps` shows to every process on this Mac.
    func credentials(reference: String) async throws -> [DashlaneCredential] {
        let filter = reference.trimmingCharacters(in: .whitespaces)
        guard !filter.isEmpty else { throw DashlaneProvider.DashlaneError.noItem }
        let result = await run(Self.fetchArguments(filter: filter), fetchDeadline)
        if result.timedOut {
            throw DashlaneProvider.DashlaneError.timedOut
        }
        guard result.succeeded else {
            // stderr only, already scrubbed by the runner. stdout may hold entries.
            throw Self.error(stderr: result.stderr, reference: filter)
        }
        let entries = DashlaneWire.credentials(result.stdout)
        guard !entries.isEmpty else { throw DashlaneProvider.DashlaneError.notFound(filter) }
        return entries
    }

    /// The argument list, as a pure function so a test can assert what it is —
    /// specifically that `--output json` is present and that the word `clipboard`
    /// never appears. `--` ends option parsing so a filter beginning with a dash is
    /// a filter rather than a flag commander will reject.
    static func fetchArguments(filter: String) -> [String] {
        ["password", "--output", "json", "--", filter]
    }

    /// `dcli`'s own failure sentences, mapped to states we can act on. The strings
    /// are the vendor's (`No credential found with this filters.` from
    /// `selectCredential`, and the master-password and device errors from
    /// `keychainManager`), matched loosely because the wording belongs to somebody
    /// else's release.
    static func error(stderr: String, reference: String) -> DashlaneProvider.DashlaneError {
        let lowered = stderr.lowercased()
        if lowered.contains("no credential found") || lowered.contains("no credential") {
            return .notFound(reference)
        }
        if lowered.contains("no device registered") || lowered.contains("device registration") {
            return .notSignedIn
        }
        if lowered.contains("master password") || lowered.contains("user presence")
            || lowered.contains("touch id") {
            return .locked
        }
        return .unreadable(LocalToolRunner.scrub(stderr))
    }
}

// MARK: - The provider

struct DashlaneProvider: CredentialProvider {
    let id = "dashlane"
    let displayName = "Dashlane"
    /// What Dashlane should match: an entry's title or address by default, or one of
    /// Dashlane's own `<param>=<value>` filters (`title=…`, `url=…`, `id=…`).
    let reference: String
    /// Optional: which username to take when several entries match.
    var account: String = ""
    /// Injectable so tests drive the whole resolve path with no Dashlane anywhere.
    var channel: any DashlaneChannel = DashlaneCLIClient()

    private static let log = Logger(subsystem: "com.bragi0.SimpleVPN", category: "dashlane")

    func isAvailable(for profile: String) async -> Bool {
        guard !reference.trimmingCharacters(in: .whitespaces).isEmpty else { return false }
        return await channel.state() == .unlocked
    }

    func resolve(profile: String, fields: Set<CredentialField>) async throws -> RawCredentials {
        let ref = reference.trimmingCharacters(in: .whitespaces)
        guard !ref.isEmpty else { throw DashlaneError.noItem }
        // THE HANG GUARD, and the reason it is here rather than in the channel: a
        // fetch against a locked vault does not fail, it ASKS — on a stdin that is
        // /dev/null. So the state is established first, and "locked" becomes a
        // sentence with a fix instead of a connect that stalls for a minute and then
        // says nothing useful. It costs one extra `dcli status`, which prompts
        // nothing and touches no network.
        switch await channel.state() {
        case .unlocked: break
        case .locked: throw DashlaneError.locked
        case .notSignedIn: throw DashlaneError.notSignedIn
        case nil: throw DashlaneError.toolUnavailable
        }
        let entries = try await channel.credentials(reference: ref)
        let entry = try DashlaneItemPicker.pick(entries,
                                                account: account.trimmingCharacters(in: .whitespaces),
                                                reference: ref)
        guard let password = entry.password, !password.isEmpty else {
            throw DashlaneError.noPassword(entry.safeLabel ?? ref)
        }
        var raw = RawCredentials()
        if fields.contains(.password) { raw.password = password }
        if fields.contains(.username) {
            let typed = account.trimmingCharacters(in: .whitespaces)
            raw.username = typed.isEmpty ? entry.preferredUsername : typed
        }
        if fields.contains(.otp), let seed = entry.totpSeed,
           let totp = TOTPConfiguration(parsing: seed) {
            // Computed locally from the seed, as Bitwarden's and the password
            // store's are. `suppliesOTP` is still FALSE for this kind: an entry MAY
            // carry a seed, and "may" is not a promise Connect can be built on.
            raw.otp = totp.code(at: Date())
        }
        Self.log.log("dashlane entry resolved for \(profile, privacy: .public)")
        return raw
    }

    /// Everything that can go wrong, in the user's words. NOTHING here interpolates
    /// a secret: the reference and the account are the user's own labels, the count
    /// of matches is a number, an entry's label is its title or address, and a vendor
    /// message is scrubbed and truncated before it is quoted.
    nonisolated enum DashlaneError: LocalizedError, Equatable {
        case noItem
        case toolUnavailable
        case notSignedIn
        case locked
        case notFound(String)
        case severalMatches(Int)
        case noPassword(String)
        case wrongAccount(String)
        case timedOut
        case unreadable(String)

        var errorDescription: String? {
            switch self {
            case .noItem:
                "No Dashlane entry is set for this VPN \u{2014} add the entry\u{2019}s name or its address."
            case .toolUnavailable:
                "SimpleVPN couldn\u{2019}t ask Dashlane anything: its command-line tool isn\u{2019}t "
                + "installed where SimpleVPN can run it."
            case .notSignedIn:
                "Dashlane isn\u{2019}t signed in on this Mac. Open Terminal and run "
                + "\u{201C}dcli sync\u{201D} to sign in and register this Mac."
            case .locked:
                "Dashlane is locked. Open Terminal and run \u{201C}dcli sync\u{201D}, and type your "
                + "Dashlane password when it asks \u{2014} it asks you, not SimpleVPN."
            case .notFound(let ref):
                ref.isEmpty
                    ? "Dashlane has no entry matching what this VPN points at."
                    : "Dashlane has no entry matching \u{201C}\(ref)\u{201D}."
            case .severalMatches(let count):
                (count > 0 ? "\(count) Dashlane entries match" : "Several Dashlane entries match")
                + " \u{2014} narrow it down (for example \u{201C}title=My VPN\u{201D}), or set the "
                + "username so SimpleVPN knows which one you mean."
            case .noPassword(let label):
                "The Dashlane entry \u{201C}\(label)\u{201D} has no password in it."
            case .wrongAccount(let account):
                "No Dashlane entry matching this VPN has the username \u{201C}\(account)\u{201D} "
                + "\u{2014} clear the username, or point this VPN at the right entry."
            case .timedOut:
                "Dashlane didn\u{2019}t answer in time. If it is waiting for your fingerprint, "
                + "answer that and try again."
            case .unreadable(let detail):
                detail.isEmpty ? "Dashlane couldn\u{2019}t provide the sign-in."
                               : "Dashlane couldn\u{2019}t provide the sign-in: \(detail)"
            }
        }
    }
}

// MARK: - The adapter

/// Dashlane's row in the sign-in chooser. Four states, and the middle two are the
/// reason the enablement banner exists:
///   1. `dcli` here, signed in and unlocked → a source SimpleVPN fetches from.
///   2. Signed in but locked → offered, with the one command that unlocks it.
///   3. Signed in to nothing → offered, with the sign-in-and-register command.
///      Or: `dcli` demonstrably installed somewhere we will not run from → offered,
///      with the path to paste. Or: Dashlane used on this Mac but no `dcli` →
///      offered, with the install command. SimpleVPN never installs it.
///   4. Nothing Dashlane on this Mac → not offered at all.
///
/// `quickScan` does file checks only. Which state the vault is in needs a real
/// `dcli status`, and that is the deep scan.
///
/// It lives in this file rather than in `LocalVaultAdapters.swift` on purpose: one
/// vendor is one file plus a one-line registry entry, so several vendors landing at
/// once do not collide in the same switch.
struct DashlaneVaultAdapter: LocalVaultAdapter {
    let vendor = LocalVaultVendor.dashlane
    let storedKind = CredentialSourceKind.dashlane
    /// `.cli`, and only `.cli`. Dashlane's desktop app exposes nothing local — no
    /// socket, no daemon, no signed IPC — and `dcli` has no serve mode of its own, so
    /// unlike Keeper and Bitwarden there is no second channel to prefer.
    let transports: [LocalVaultTransport] = [.cli]

    /// The Dashlane desktop app, which is NOT a read path — it is only the signal
    /// that this person uses Dashlane, and therefore that `dcli` is worth telling
    /// them about.
    static let appBundleIDs = ["com.dashlane.Dashlane", "com.dashlane.dashlanephonefinal"]

    static var isAppInstalled: Bool {
        appBundleIDs.contains { NSWorkspace.shared.urlForApplication(withBundleIdentifier: $0) != nil }
    }

    /// Injectable for tests; the shipped value talks to the real tool.
    var channel: any DashlaneChannel = DashlaneCLIClient()

    /// The cheap answer as a PURE function of four file-check facts, so all four
    /// states are tested on a Mac with no `dcli`, no Dashlane app and no discovery
    /// scan. `quickScan()` only gathers.
    ///
    /// `hasLocalDatabase` earns its place: plenty of people use Dashlane entirely in
    /// a browser and have never installed the desktop app, so the app's absence does
    /// not prove they don't use Dashlane — but `dcli`'s own database on disk proves
    /// they do.
    static func availability(toolIsRunnable: Bool,
                             foundOutsideAllowList: Bool,
                             appIsInstalled: Bool,
                             hasLocalDatabase: Bool) -> LocalVaultAvailability {
        if toolIsRunnable { return .unchecked }
        // Before saying "not installed", ASK. Discovery searches every location any
        // package manager, version manager or vendor installer uses — plus `PATH`,
        // which the execution side will never consult — so it can tell "you don't
        // have `dcli`" apart from "you have `dcli` in ~/.yarn/bin". Only one of those
        // is a thing to install.
        if foundOutsideAllowList { return .blocked(.toolOutsideAllowList) }
        return (appIsInstalled || hasLocalDatabase) ? .blocked(.toolMissing) : .notInstalled
    }

    /// The deep answer as a pure mapping. Each of `dcli`'s three states has one fix,
    /// and each fix is a different command — which is why `locked` is its own block
    /// rather than being folded into "not signed in".
    static func availability(for state: DashlaneVaultState) -> LocalVaultAvailability {
        switch state {
        case .unlocked: .ready
        case .locked: .blocked(.vaultLocked)
        case .notSignedIn: .blocked(.notSignedIn)
        }
    }

    func quickScan() -> LocalVaultAvailability {
        Self.availability(
            toolIsRunnable: DashlaneCLIClient.locate() != nil,
            foundOutsideAllowList: LocalVaultRegistry.toolFoundOutsideAllowList("dcli") != nil,
            appIsInstalled: Self.isAppInstalled,
            hasLocalDatabase: DashlaneLocalStore.hasDatabase())
    }

    func deepScan(quick: LocalVaultAvailability) async -> LocalVaultAvailability {
        guard quick != .notInstalled else { return .notInstalled }
        // Nothing to probe when the tool itself is missing, or when it is one we
        // decline to run: probing would mean executing exactly the binary the
        // allow-list refused, and "not signed in" would be the wrong thing to say.
        guard quick != .blocked(.toolMissing),
              quick != .blocked(.toolOutsideAllowList) else { return quick }
        if let state = await channel.state() { return Self.availability(for: state) }
        // Nothing answered. Keep whatever the cheap pass established rather than
        // inventing a state: "we couldn't ask" is not "you aren't signed in".
        return quick
    }

    func provider(for source: CredentialSource) -> (any CredentialProvider)? {
        guard !source.reference.trimmingCharacters(in: .whitespaces).isEmpty else { return nil }
        return DashlaneProvider(reference: source.reference, account: source.account)
    }
}
