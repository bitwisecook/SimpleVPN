// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
//  ProtonPassTests.swift
//  The Proton Pass sign-in source, driven entirely by fixtures. NEITHER PROTON PASS
//  NOR `pass-cli` IS INSTALLED ON THE MACHINE THIS WAS WRITTEN ON, AND THERE IS NO
//  PROTON ACCOUNT. So nothing here has been seen working against a live vault and
//  nothing here claims to have been: every fixture comes from a named source, cited
//  below and again at the fixture itself, and `FeatureMaturity` records the source as
//  `.untested` with the same split.
//
//  ─── FIXTURE PROVENANCE ────────────────────────────────────────────────────────
//
//  Proton's CLI is open source (GPL-3.0, `github.com/protonpass/pass-cli`, `main`
//  branch read 2026-08), so every string here is quoted from the implementation
//  rather than from a transcript somebody remembered.
//
//   • `item view --field <name>` printing THE VALUE ALONE on stdout —
//     `pass-cli/src/commands/item/view.rs`: `Some(field_value) => println!("{}",
//     field_value.value())`. Also documented at
//     <https://protonpass.github.io/pass-cli/commands/item/>.
//   • "Field does not exist: <name>" — the same function's `None => bail!("Field does
//     not exist: {}", field)`.
//   • A login item's field NAMES, and that each appears only when non-empty —
//     `pass-domain/src/models/item/field.rs`, `add_login_fields`: `email`, `username`,
//     `password`, `totp`, `totp_uri`, `urls`. This is why the provider tries
//     `username` and then `email`.
//   • A TOTP field resolving to the CODE by default rather than the seed —
//     `pass-cli/src/commands/secret_resolver.rs`: `enum TotpOutput { #[default] Code,
//     Uri }`, and `view.rs` calling `totp.unwrap_or_default()`.
//   • The `item list --output json` shape — `pass-cli/src/commands/item/list.rs`,
//     `ItemsList { items }` over `ItemSummary { id, share_id, vault_id, state, flags,
//     create_time, modify_time, folder_id, title, item_type }`, with `#[serde(rename_all
//     = "snake_case")] enum ItemType { Note, Login, … }`. That file also carries the
//     comment this feed relies on: "Fields here must never carry user-provided secret
//     material (no content, note, extra_fields)."
//   • The `info --output json` shape and `session_has_lock` —
//     `pass-cli/src/commands/info.rs`, `struct InfoOutput`.
//   • WHAT AN ID LOOKS LIKE — `pass/src/utils.rs`: `pub fn is_id(value: &str) -> bool
//     { value.len() == 88 && value.ends_with("==") }`, used by `FindItemQuery::new`
//     (`pass/src/item/find.rs`) to decide ID-pair versus name-pair.
//   • NAME LOOKUP TAKES THE FIRST MATCH, with no ambiguity error —
//     `pass/src/item/find.rs`: `items.into_iter().find(|i| i.content.title ==
//     item_name)`, and `pass-cli/src/commands/item/common.rs`: `items.iter().find(|item|
//     item.content.title.eq(title))`. Proton's own documentation states the
//     consequence: "If there are several objects that match the name, one of them will
//     be used."
//   • "This operation requires an authenticated client" and "Your session has been
//     invalidated and you have been logged out automatically." —
//     `pass-cli/src/main.rs`.
//   • "There was not an active session, you are already logged out" — the same file.
//   • "Session is locked. Please unlock your session and try again." — `pass/src/
//     macros.rs`, printed when the API answers `SessionLocked` (300008 in
//     `pass/src/error.rs`); the accompanying error is "Could not perform operation.
//     Reason: SessionLocked".
//   • THE ENTITLEMENT SENTENCE "Your account is not yet allowed to use our CLI" —
//     `pass-cli/src/commands/login.rs`, in `after_login`, which then calls
//     `client.logout()`, `force_logout()` and `std::process::exit(1)`. The check
//     itself is `can_use_cli` in `pass/src/user/access.rs`: the `PassCanUseCli`
//     feature flag AND the account's `Plan.cli_allowed`.
//   • WHICH PLANS INCLUDE IT — Proton's own announcement: "The CLI is now available
//     on Pass Plus, Pass Family, Pass Professional, and all Proton bundles. If you
//     have a free plan, you can upgrade to get access."
//     <https://proton.me/blog/proton-pass-cli>
//   • "Error finding vault [<name>]: …" — `pass-cli/src/commands/item/common.rs`,
//     `ShareQuery::share_id`; "Could not find vault <name>" — `pass/src/vault/find.rs`.
//   • WHERE THE SESSION FILE LIVES — `get_base_dir()` in `pass-cli/src/utils.rs`
//     (`dirs::data_dir()` joined with `proton-pass-cli`, then `.session`, with
//     `PROTON_PASS_SESSION_DIR` overriding the lot) and `SESSION_FILE_NAME =
//     "session.json"` in `pass-cli/src/constants.rs`.
//   • NO CLIPBOARD ANYWHERE — established by ABSENCE, which is stated as such: a
//     case-insensitive search of the whole repository for "clipboard", "pbcopy" and
//     "copy to clip" returns nothing, and no subcommand in `pass-cli/src/main.rs`
//     declares a `-c`/`--clipboard` argument. `noClipboardFlagIsEverPassed` pins our
//     side of that.
//   • The install locations — `install.sh` in the same repository (`$HOME/.local/bin`,
//     falling back to `/usr/local/bin`, overridable with
//     `PROTON_PASS_CLI_INSTALL_DIR`) and the Homebrew tap
//     `brew install protonpass/tap/pass-cli` from
//     <https://protonpass.github.io/pass-cli/get-started/installation/>.
//
//  UNVERIFIED, and deliberately not asserted anywhere: that a real `pass-cli` prints
//  exactly these bytes, that a real Proton account can be read at all, and that the
//  entitlement sentence can be observed from a command SimpleVPN is willing to run —
//  Proton checks the plan inside `login`, which this app never runs.
//
//  Nothing here reaches the network, spawns a process, or touches the real defaults
//  domain.
//

import Foundation
import Testing
@testable import SimpleVPN

// MARK: - Fixtures

private nonisolated enum PP {

    /// An 88-character base64 string ending "==" — the shape `pass/src/utils.rs`
    /// calls an ID. Built rather than typed so the length is right by construction.
    static func id(_ seed: String) -> String {
        let filler = String(repeating: seed.isEmpty ? "A" : seed, count: 88)
        return String(filler.prefix(86)) + "=="
    }

    static let shareID = id("Sh4r")
    static let itemID = id("It3m")
    static let otherItemID = id("Oth3")

    /// `item list --output json`. Field names and the wrapper are `ItemsList` /
    /// `ItemSummary` from `pass-cli/src/commands/item/list.rs`.
    static func list(_ entries: [(id: String, title: String, type: String)],
                     share: String = shareID) -> Data {
        let items = entries.map { entry in
            """
            {"id":"\(entry.id)","share_id":"\(share)","vault_id":"\(id("V4lt"))",\
            "state":"active","flags":[],"create_time":"2026-08-01T09:00:00",\
            "modify_time":"2026-08-01T09:00:00","title":"\(entry.title)",\
            "item_type":"\(entry.type)"}
            """
        }
        return Data("{\"items\":[\(items.joined(separator: ","))]}".utf8)
    }

    /// `info --output json` — `InfoOutput` in `pass-cli/src/commands/info.rs`.
    static func info(hasLock: Bool) -> Data {
        Data("""
        {"release_track":"stable","id":"\(id("Us3r"))","username":"alice",\
        "email":"alice@proton.me","session_has_lock":\(hasLock)}
        """.utf8)
    }

    static func ok(_ stdout: Data) -> LocalToolResult {
        LocalToolResult(exitCode: 0, stdout: stdout, stderr: "", timedOut: false)
    }
    static func ok(_ stdout: String) -> LocalToolResult { ok(Data(stdout.utf8)) }

    static func fail(_ stderr: String, exitCode: Int32 = 1) -> LocalToolResult {
        LocalToolResult(exitCode: exitCode, stdout: Data(), stderr: stderr, timedOut: false)
    }

    static let timedOut = LocalToolResult(exitCode: -1, stdout: Data(), stderr: "",
                                          timedOut: true)

    // --- The vendor's own sentences, verbatim ------------------------------

    static let notAuthenticated = "Error: This operation requires an authenticated client"
    static let invalidated =
        "Your session has been invalidated and you have been logged out automatically."
    static let alreadyLoggedOut = "There was not an active session, you are already logged out"
    static let sessionLocked = "Session is locked. Please unlock your session and try again."
    static let sessionLockedCode = "Error: Could not perform operation. Reason: SessionLocked"
    static let notAllowed = "Your account is not yet allowed to use our CLI"
    static let noVault = "Error: Error finding vault [Work]: Could not find vault Work"
    static func noField(_ name: String) -> String { "Error: Field does not exist: \(name)" }
}

/// A channel that answers from a script and RECORDS EVERY ARGUMENT LIST it was given,
/// so the argv contract is a test rather than a comment.
private nonisolated final class RecordingRunner: @unchecked Sendable {
    private let lock = NSLock()
    nonisolated(unsafe) private var recorded: [[String]] = []

    var calls: [[String]] { lock.withLock { recorded } }

    /// Every argument of every call, flattened — what an argv audit looks at.
    var allArguments: [String] { calls.flatMap { $0 } }

    private let answer: @Sendable ([String]) -> LocalToolResult

    init(_ answer: @escaping @Sendable ([String]) -> LocalToolResult) {
        self.answer = answer
    }

    var run: @Sendable ([String]) async -> LocalToolResult {
        { [self] arguments in
            record(arguments)
            return answer(arguments)
        }
    }

    private func record(_ arguments: [String]) {
        lock.withLock { recorded.append(arguments) }
    }

    func channel() -> ProtonPassCLIChannel { ProtonPassCLIChannel(run: run) }
}

/// The shorthand every fetch test uses: answer per subcommand, in the CLI's own
/// vocabulary.
private nonisolated func runner(info: LocalToolResult? = nil,
                    list: LocalToolResult? = nil,
                    fields: [String: LocalToolResult] = [:],
                    fallback: LocalToolResult = PP.fail("Error: unexpected call")) -> RecordingRunner {
    RecordingRunner { arguments in
        if arguments.first == "info" { return info ?? fallback }
        if arguments.prefix(2) == ["item", "list"] { return list ?? fallback }
        if arguments.prefix(2) == ["item", "view"] {
            guard let flag = arguments.firstIndex(of: "--field"),
                  arguments.indices.contains(flag + 1) else { return fallback }
            return fields[arguments[flag + 1]] ?? fallback
        }
        return fallback
    }
}

/// Every sentence the provider can put in front of a user, so the glossary sweep
/// covers the connect-time wording as well as the chooser's.
private nonisolated enum ProtonPassBlockErrors {
    static let everySentence: [String] = [
        .noItem, .needsVault("GR Lab"), .notSignedIn, .locked, .planExcludesTool,
        .notFound(title: "GR Lab", vault: "Work"), .severalMatches(2),
        .noPassword("GR Lab"), .toolMissing, .unreadable("something went wrong"),
    ].map { (error: ProtonPassProvider.ProtonPassError) in error.errorDescription ?? "" }
}

// MARK: - Addressing

@Suite("Proton Pass addressing")
struct ProtonPassAddressingTests {

    /// Proton's own ID predicate, mirrored: 88 characters ending "==".
    /// `pass/src/utils.rs`. It matters that ours agrees with theirs, because both
    /// sides use it to decide ID-pair versus name-pair.
    @Test func anIDIsEightyEightCharactersEndingInTwoEqualsSigns() {
        #expect(ProtonPassID.looksLikeID(PP.shareID))
        #expect(PP.shareID.count == 88)
        // One character short, one too long, and the right length without the padding.
        #expect(!ProtonPassID.looksLikeID(String(PP.shareID.dropFirst())))
        #expect(!ProtonPassID.looksLikeID(PP.shareID + "A"))
        #expect(!ProtonPassID.looksLikeID(String(repeating: "A", count: 88)))
        #expect(!ProtonPassID.looksLikeID("Work"))
        #expect(!ProtonPassID.looksLikeID(""))
    }

    /// The canonical form, and the three shapes people will really type.
    @Test func everyShapeAUserWillTypeIsUnderstood() {
        let expected = ProtonPassAddress.names(vault: "Work", title: "GR Lab")
        for text in ["pass://Work/GR Lab", "Work/GR Lab", "  pass://Work/GR Lab  ",
                     "PASS://Work/GR Lab"] {
            #expect(ProtonPassReference.parse(text) == .success(expected),
                    "\u{201C}\(text)\u{201D} did not parse to the same address")
        }
    }

    /// A FIELD in the reference is dropped, not honoured. A `pass://Work/GR
    /// Lab/username` pasted out of Proton's documentation must not turn this VPN's
    /// password into its username.
    @Test func aFieldInTheReferenceIsDropped() {
        let parsed = try? ProtonPassReference.parse("pass://Work/GR Lab/username").get()
        #expect(parsed == .names(vault: "Work", title: "GR Lab"))
        // …and so is the `?totp=` selector, which addresses a field by another route.
        let withTOTP = try? ProtonPassReference.parse("pass://Work/GR Lab/totp?totp=uri").get()
        #expect(withTOTP == .names(vault: "Work", title: "GR Lab"))
    }

    /// BOTH halves have to be IDs for the ID path, exactly as `FindItemQuery::new`
    /// decides. A mixed reference is a name reference — which costs a listing and
    /// gains a duplicate check, so getting this wrong would skip the check.
    @Test func bothHalvesMustBeIdentifiersForTheIdentifierPath() {
        #expect(ProtonPassReference.parse("pass://\(PP.shareID)/\(PP.itemID)")
            == .success(.ids(share: PP.shareID, item: PP.itemID)))
        #expect(ProtonPassReference.parse("pass://Work/\(PP.itemID)")
            == .success(.names(vault: "Work", title: PP.itemID)))
        #expect(ProtonPassReference.parse("pass://\(PP.shareID)/GR Lab")
            == .success(.names(vault: PP.shareID, title: "GR Lab")))
    }

    /// A BARE TITLE IS REFUSED, and the sentence says why rather than just "no".
    /// `pass-cli` would search whichever vault its own `default-vault` setting names —
    /// something SimpleVPN cannot see — and then take the first match inside it.
    @Test func aBareTitleIsRefusedWithAReasonAndAnExample() {
        guard case .failure(let error) = ProtonPassReference.parse("GR Lab") else {
            Issue.record("a bare title was accepted")
            return
        }
        #expect(error == .needsVault("GR Lab"))
        let sentence = error.errorDescription ?? ""
        #expect(sentence.contains("GR Lab"))
        #expect(sentence.contains("Work/GR Lab"))
        // It explains the risk, so the refusal reads as a decision rather than a bug.
        #expect(sentence.lowercased().contains("first"))
    }

    @Test func anEmptyReferenceSaysNoItemIsSetYet() {
        #expect(ProtonPassReference.parse("   ") == .failure(.noItem))
        #expect((ProtonPassProvider.ProtonPassError.noItem.errorDescription ?? "")
            .contains("Work/GR Lab"))
    }

    /// Extra slashes, empty components and a trailing slash are tolerated rather than
    /// failing on punctuation — the vault and the item are still unambiguous.
    @Test func punctuationDoesNotDefeatIt() {
        #expect(ProtonPassReference.parse("pass://Work/GR Lab/")
            == .success(.names(vault: "Work", title: "GR Lab")))
        #expect(ProtonPassReference.parse("pass:///Work//GR Lab")
            == .success(.names(vault: "Work", title: "GR Lab")))
    }

    /// Only an ID address can be READ, structurally — which is what forces a name
    /// through the duplicate check before anything is fetched.
    @Test func onlyAnIdentifierAddressCanBeRead() {
        #expect(ProtonPassAddress.names(vault: "Work", title: "GR Lab").viewArguments == nil)
        #expect(ProtonPassAddress.ids(share: PP.shareID, item: PP.itemID).viewArguments
            == ["--share-id", PP.shareID, "--item-id", PP.itemID])
    }

    /// A vault is listed by ID or by name, whichever the address holds.
    @Test func aVaultIsListedByWhicheverHalfTheAddressHolds() {
        #expect(ProtonPassAddress.names(vault: "Work", title: "x").listArguments
            == ["--vault-name", "Work"])
        #expect(ProtonPassAddress.ids(share: PP.shareID, item: PP.itemID).listArguments
            == ["--share-id", PP.shareID])
    }
}

// MARK: - Choosing one item

@Suite("Proton Pass item choice")
struct ProtonPassItemChoiceTests {

    private func summary(_ id: String, _ title: String,
                         _ type: String = "login") -> ProtonPassItemSummary {
        ProtonPassItemSummary(id: id, shareID: PP.shareID, title: title, itemType: type)
    }

    /// EXACT, CASE-SENSITIVE — the same comparison `pass/src/item/find.rs` makes.
    /// Being more forgiving than the tool would mean SimpleVPN resolving a name to one
    /// item and `pass-cli` to another.
    @Test func titlesMatchExactlyAndCaseSensitively() {
        let items = [summary(PP.itemID, "GR Lab"), summary(PP.otherItemID, "gr lab")]
        #expect(ProtonPassItemPicker.matching(title: "GR Lab", in: items).map(\.id) == [PP.itemID])
        #expect(ProtonPassItemPicker.matching(title: "gr lab", in: items).map(\.id)
            == [PP.otherItemID])
        #expect(ProtonPassItemPicker.matching(title: "GR", in: items).isEmpty)
    }

    /// A note of the same name is not a candidate. It cannot sign anything in, so
    /// counting it would report an ambiguity that does not exist.
    @Test func onlyLoginItemsAreCandidates() {
        let items = [summary(PP.itemID, "GR Lab"), summary(PP.otherItemID, "GR Lab", "note")]
        #expect(ProtonPassItemPicker.matching(title: "GR Lab", in: items).map(\.id) == [PP.itemID])
    }

    /// TWO LOGINS OF THE SAME NAME ARE AN AMBIGUITY WE REFUSE. The CLI would take one
    /// of them — Proton's documentation says so outright — so this check is the whole
    /// reason a name reference costs a listing.
    @Test func twoLoginsOfTheSameNameAreBothReturnedSoTheFetchCanRefuse() async {
        let list = PP.list([(PP.itemID, "GR Lab", "login"),
                            (PP.otherItemID, "GR Lab", "login")])
        let provider = ProtonPassProvider(reference: "Work/GR Lab",
                                          channel: runner(list: PP.ok(list)).channel())
        await #expect(throws: ProtonPassProvider.ProtonPassError.severalMatches(2)) {
            _ = try await provider.resolve(profile: "p", fields: [.password])
        }
    }

    /// And the sentence tells the user what to do about it — the identifiers — rather
    /// than only that something is wrong.
    @Test func theAmbiguitySentenceNamesTheWayOut() {
        let sentence = ProtonPassProvider.ProtonPassError.severalMatches(3).errorDescription ?? ""
        #expect(sentence.contains("3"))
        #expect(sentence.lowercased().contains("identifier"))
        #expect(sentence.lowercased().contains("rename"))
    }
}

// MARK: - The wire

@Suite("Proton Pass wire")
struct ProtonPassWireTests {

    @Test func theListingIsRead() {
        let items = ProtonPassWire.items(PP.list([(PP.itemID, "GR Lab", "login"),
                                                  (PP.otherItemID, "Notes", "note")]))
        #expect(items.count == 2)
        #expect(items[0].id == PP.itemID)
        #expect(items[0].shareID == PP.shareID)
        #expect(items[0].title == "GR Lab")
        #expect(items[0].isLogin)
        #expect(!items[1].isLogin)
    }

    /// A bare array is accepted as well as the wrapper, so a release that drops
    /// `{"items":…}` does not silently stop finding items.
    @Test func aBareArrayIsAcceptedToo() {
        let wrapped = PP.list([(PP.itemID, "GR Lab", "login")])
        guard let object = try? JSONSerialization.jsonObject(with: wrapped) as? [String: Any],
              let inner = object["items"],
              let bare = try? JSONSerialization.data(withJSONObject: inner) else {
            Issue.record("could not build the bare-array fixture")
            return
        }
        #expect(ProtonPassWire.items(bare).map(\.id) == [PP.itemID])
    }

    @Test func nonsenseIsNoItemsRatherThanACrash() {
        #expect(ProtonPassWire.items(Data("not json".utf8)).isEmpty)
        #expect(ProtonPassWire.items(Data()).isEmpty)
        #expect(ProtonPassWire.items(Data("{\"items\":[{\"title\":\"x\"}]}".utf8)).isEmpty)
    }

    /// "Has a lock" is read, because it is the only field of `info` this app wants.
    /// Proton's own documentation is explicit that it is NOT "is locked right now",
    /// which is why it never becomes a blocked state.
    @Test func theLockFlagIsReadAndIsNotAState() {
        #expect(ProtonPassWire.hasSessionLock(PP.info(hasLock: true)))
        #expect(!ProtonPassWire.hasSessionLock(PP.info(hasLock: false)))
        #expect(!ProtonPassWire.hasSessionLock(Data("not json".utf8)))
        // A session that merely HAS a lock is ready: exit 0 is the authority.
        #expect(ProtonPassWire.state(exitCode: 0, stderr: "") == .ready)
    }

    /// Every one of Proton's own failure sentences maps to the state whose FIX is
    /// different. Each string is cited in this file's header.
    @Test func everyVendorSentenceMapsToItsOwnState() {
        #expect(ProtonPassWire.state(exitCode: 1, stderr: PP.notAuthenticated) == .notSignedIn)
        #expect(ProtonPassWire.state(exitCode: 1, stderr: PP.invalidated) == .notSignedIn)
        #expect(ProtonPassWire.state(exitCode: 1, stderr: PP.alreadyLoggedOut) == .notSignedIn)
        #expect(ProtonPassWire.state(exitCode: 1, stderr: PP.sessionLocked) == .locked)
        #expect(ProtonPassWire.state(exitCode: 1, stderr: PP.sessionLockedCode) == .locked)
        #expect(ProtonPassWire.state(exitCode: 1, stderr: PP.notAllowed) == .planExcludesTool)
    }

    /// THE ENTITLEMENT SENTENCE WINS over anything else in the same output. It is the
    /// only one of these a person cannot fix by typing a command, so mistaking it for
    /// "not signed in" is the wasted afternoon the state exists to prevent — and the
    /// tool DOES log itself out immediately afterwards, so both sentences can
    /// plausibly appear together.
    @Test func theEntitlementSentenceOutranksTheSignInOne() {
        let both = PP.notAllowed + "\n" + PP.notAuthenticated
        #expect(ProtonPassWire.state(exitCode: 1, stderr: both) == .planExcludesTool)
        let reversed = PP.notAuthenticated + "\n" + PP.notAllowed
        #expect(ProtonPassWire.state(exitCode: 1, stderr: reversed) == .planExcludesTool)
    }

    /// An unrecognised failure is NOT a state. "We couldn't tell" must never be
    /// reported as "you aren't signed in".
    @Test func anUnrecognisedFailureIsNotAState() {
        #expect(ProtonPassWire.state(exitCode: 1, stderr: "Error: something else entirely") == nil)
        #expect(ProtonPassWire.state(exitCode: 1, stderr: "") == nil)
    }

    /// A missing vault is "no such item", not a channel failure — the fix is the
    /// reference, and the sentence names both halves of what was looked for.
    @Test func aMissingVaultIsReportedAsAMissingItem() {
        let address = ProtonPassAddress.names(vault: "Work", title: "GR Lab")
        let error = ProtonPassWire.error(exitCode: 1, stderr: PP.noVault, address: address)
        #expect(error == .notFound(title: "GR Lab", vault: "Work"))
        let sentence = error.errorDescription ?? ""
        #expect(sentence.contains("GR Lab"))
        #expect(sentence.contains("Work"))
        #expect(sentence.lowercased().contains("exactly"))
    }
}

// MARK: - The session file (the cheap probe)

@Suite("Proton Pass session file")
struct ProtonPassSessionFileTests {

    /// The documented macOS location, assembled the way `get_base_dir()` assembles it.
    @Test func theDefaultLocationIsTheDocumentedOne() {
        let home = URL(fileURLWithPath: "/Users/someone")
        let path = ProtonPassSessionFile.url(home: home, environment: [:]).path
        #expect(path
            == "/Users/someone/Library/Application Support/proton-pass-cli/.session/session.json")
    }

    /// `PROTON_PASS_SESSION_DIR` moves the whole thing, and is honoured — somebody
    /// who has moved their session has not stopped having one.
    @Test func theEnvironmentOverrideIsHonoured() {
        let path = ProtonPassSessionFile.url(
            home: URL(fileURLWithPath: "/Users/someone"),
            environment: [ProtonPassSessionFile.directoryEnvironmentVariable: "/tmp/pp"]).path
        #expect(path == "/tmp/pp/.session/session.json")
        // An empty value is not an override — it is an unset variable spelled oddly.
        let empty = ProtonPassSessionFile.url(
            home: URL(fileURLWithPath: "/Users/someone"),
            environment: [ProtonPassSessionFile.directoryEnvironmentVariable: "  "]).path
        #expect(empty.hasPrefix("/Users/someone/Library"))
    }

    /// The probe is ONE `stat`: no subprocess, no prompt, no network. Driven here in a
    /// temporary directory, so it is a real filesystem answer and not a stub.
    @Test func theProbeIsAFileCheckAndNothingElse() throws {
        let root = URL(fileURLWithPath: NSTemporaryDirectory())
            .appendingPathComponent("pp-\(UUID().uuidString)")
        let environment = [ProtonPassSessionFile.directoryEnvironmentVariable: root.path]
        #expect(!ProtonPassSessionFile.exists(environment: environment))

        let file = ProtonPassSessionFile.url(environment: environment)
        try FileManager.default.createDirectory(at: file.deletingLastPathComponent(),
                                               withIntermediateDirectories: true)
        try Data("{}".utf8).write(to: file)
        #expect(ProtonPassSessionFile.exists(environment: environment))

        // A DIRECTORY of that name is not a session file.
        try FileManager.default.removeItem(at: file)
        try FileManager.default.createDirectory(at: file, withIntermediateDirectories: true)
        #expect(!ProtonPassSessionFile.exists(environment: environment))
        try? FileManager.default.removeItem(at: root)
    }
}

// MARK: - Availability: four states, one fix each

@Suite("Proton Pass availability")
struct ProtonPassAvailabilityTests {

    /// TOOL MISSING ENTIRELY, and nothing Proton on this Mac ⇒ the row is not offered
    /// at all. Offering it would be advertising a vendor there is no evidence the
    /// person uses.
    @Test func nothingProtonMeansNoRow() {
        #expect(ProtonPassVaultAdapter.availability(
            toolIsRunnable: false, foundOutsideAllowList: false,
            appIsInstalled: false, sessionFileExists: false) == .notInstalled)
    }

    /// THE APP IS HERE AND THE TOOL IS NOT ⇒ offered, with the install command. The
    /// app is not a read path; it is the evidence that the tool is worth mentioning.
    @Test func theAppWithoutTheToolIsAnInstallState() {
        #expect(ProtonPassVaultAdapter.availability(
            toolIsRunnable: false, foundOutsideAllowList: false,
            appIsInstalled: true, sessionFileExists: false) == .blocked(.toolMissing))
    }

    /// OUTSIDE THE ALLOW-LIST wins over both. Saying "not installed" about a binary we
    /// can see is what sends somebody to install a second copy.
    @Test func foundButNotRunnableIsItsOwnStateAndOutranksTheOthers() {
        for app in [false, true] {
            #expect(ProtonPassVaultAdapter.availability(
                toolIsRunnable: false, foundOutsideAllowList: true,
                appIsInstalled: app, sessionFileExists: false)
                == .blocked(.toolOutsideAllowList))
        }
    }

    /// NO SESSION FILE IS A COMPLETE, CHEAP ANSWER — the tool writes it on sign-in and
    /// deletes it on sign-out, so its absence cannot mean anything else.
    @Test func aRunnableToolWithNoSessionFileIsNotSignedIn() {
        #expect(ProtonPassVaultAdapter.availability(
            toolIsRunnable: true, foundOutsideAllowList: false,
            appIsInstalled: false, sessionFileExists: false) == .blocked(.notSignedIn))
    }

    /// A SESSION FILE IS NOT PROOF. It says a session existed, not that the API still
    /// accepts it — so this way round is `.unchecked` and the deep scan earns `.ready`.
    @Test func aSessionFileIsUncheckedRatherThanReady() {
        #expect(ProtonPassVaultAdapter.availability(
            toolIsRunnable: true, foundOutsideAllowList: false,
            appIsInstalled: false, sessionFileExists: true) == .unchecked)
    }

    /// Each session state maps to the availability whose FIX is different — and the
    /// entitlement gate is its own, which is the whole point of this feed.
    @Test func eachSessionStateHasItsOwnAvailability() {
        #expect(ProtonPassVaultAdapter.availability(for: .ready) == .ready)
        #expect(ProtonPassVaultAdapter.availability(for: .locked) == .blocked(.vaultLocked))
        #expect(ProtonPassVaultAdapter.availability(for: .notSignedIn)
            == .blocked(.notSignedIn))
        #expect(ProtonPassVaultAdapter.availability(for: .planExcludesTool)
            == .blocked(.planExcludesTool))
    }

    /// THE DEEP SCAN SPAWNS NOTHING for the three states where a subprocess cannot
    /// help — a missing tool, a tool we declined to run, and a Mac with no session
    /// file. The last one matters most: without it, a signed-out Mac would make a
    /// request to Proton on every refresh.
    @Test func theDeepScanSpawnsNothingWhenItCannotHelp() async {
        for quick in [LocalVaultAvailability.notInstalled,
                      .blocked(.toolMissing),
                      .blocked(.toolOutsideAllowList),
                      .blocked(.notSignedIn)] {
            let recorder = runner(info: PP.ok(PP.info(hasLock: false)))
            let adapter = ProtonPassVaultAdapter(channel: recorder.channel())
            let answer = await adapter.deepScan(quick: quick)
            #expect(answer == quick)
            #expect(recorder.calls.isEmpty, "the deep scan ran a command for \(quick)")
        }
    }

    /// From `.unchecked`, the deep scan asks once and reports what it heard.
    @Test func theDeepScanTurnsUncheckedIntoTheRealAnswer() async {
        let cases: [(LocalToolResult, LocalVaultAvailability)] = [
            (PP.ok(PP.info(hasLock: false)), .ready),
            (PP.ok(PP.info(hasLock: true)), .ready),
            (PP.fail(PP.sessionLocked), .blocked(.vaultLocked)),
            (PP.fail(PP.notAuthenticated), .blocked(.notSignedIn)),
            (PP.fail(PP.notAllowed), .blocked(.planExcludesTool)),
        ]
        for (reply, expected) in cases {
            let adapter = ProtonPassVaultAdapter(channel: runner(info: reply).channel())
            #expect(await adapter.deepScan(quick: .unchecked) == expected)
        }
    }

    /// A probe that cannot answer leaves the cheap answer alone. "We couldn't ask" is
    /// not a state to accuse anybody of.
    @Test func anUnanswerableProbeChangesNothing() async {
        for reply in [PP.timedOut, PP.fail("Error: something else entirely")] {
            let adapter = ProtonPassVaultAdapter(channel: runner(info: reply).channel())
            #expect(await adapter.deepScan(quick: .unchecked) == .unchecked)
        }
    }

    /// The adapter declares ONE transport. The SSH agent is not a second way in: it
    /// serves keys to `ssh`, not usernames and passwords to us.
    @Test func oneChannelIsDeclaredAndItIsTheCommandLineTool() {
        #expect(ProtonPassVaultAdapter().transports == [.cli])
        #expect(ProtonPassVaultAdapter().vendor == .protonPass)
        #expect(ProtonPassVaultAdapter().storedKind == .protonPass)
    }

    /// An empty reference yields no fetcher, so a half-set-up VPN routes to the typed
    /// fields rather than a doomed lookup.
    @Test func noReferenceMeansNoFetcher() {
        var source = CredentialSource()
        source.kind = .protonPass
        #expect(ProtonPassVaultAdapter().provider(for: source) == nil)
        source.reference = "Work/GR Lab"
        #expect(ProtonPassVaultAdapter().provider(for: source) != nil)
    }
}

// MARK: - Fetching

@Suite("Proton Pass fetch")
struct ProtonPassFetchTests {

    /// THE HAPPY PATH BY IDENTIFIER: one run per field, no listing at all.
    @Test func anIdentifierReferenceReadsWithoutListingAnything() async throws {
        let recorder = runner(fields: ["password": PP.ok("s3cret-vpn-pass"),
                                       "username": PP.ok("alice")])
        let provider = ProtonPassProvider(
            reference: "pass://\(PP.shareID)/\(PP.itemID)", channel: recorder.channel())
        let raw = try await provider.resolve(profile: "p", fields: [.username, .password])
        #expect(raw.password == "s3cret-vpn-pass")
        #expect(raw.username == "alice")
        #expect(!recorder.calls.contains { $0.prefix(2) == ["item", "list"] })
    }

    /// A NAME REFERENCE IS RESOLVED TO IDENTIFIERS BY US, and the read then uses those
    /// — so nothing downstream can take the first of several matches.
    @Test func aNameReferenceIsResolvedToIdentifiersBeforeAnythingIsRead() async throws {
        let recorder = runner(list: PP.ok(PP.list([(PP.itemID, "GR Lab", "login")])),
                              fields: ["password": PP.ok("s3cret"), "username": PP.ok("alice")])
        let provider = ProtonPassProvider(reference: "Work/GR Lab", channel: recorder.channel())
        _ = try await provider.resolve(profile: "p", fields: [.username, .password])
        let views = recorder.calls.filter { $0.prefix(2) == ["item", "view"] }
        #expect(!views.isEmpty)
        for view in views {
            #expect(view.contains("--share-id"))
            #expect(view.contains(PP.itemID))
            // The TITLE never reaches the read: it was only ever a lookup key.
            #expect(!view.contains("GR Lab"))
        }
    }

    /// THE USERNAME FALLS BACK TO `email`, because Proton Pass keeps both and only
    /// offers a field when it is non-empty (`add_login_fields`).
    @Test func theUsernameFallsBackToTheEmailField() async throws {
        let recorder = runner(fields: ["password": PP.ok("s3cret"),
                                       "username": PP.fail(PP.noField("username")),
                                       "email": PP.ok("alice@proton.me")])
        let provider = ProtonPassProvider(
            reference: "pass://\(PP.shareID)/\(PP.itemID)", channel: recorder.channel())
        let raw = try await provider.resolve(profile: "p", fields: [.username, .password])
        #expect(raw.username == "alice@proton.me")
    }

    /// A username typed into the PROFILE wins over the item's own, and costs no run:
    /// the person who typed it there meant it.
    @Test func aTypedUsernameWinsAndCostsNoExtraRun() async throws {
        let recorder = runner(fields: ["password": PP.ok("s3cret")])
        let provider = ProtonPassProvider(reference: "pass://\(PP.shareID)/\(PP.itemID)",
                                          account: "override", channel: recorder.channel())
        let raw = try await provider.resolve(profile: "p", fields: [.username, .password])
        #expect(raw.username == "override")
        #expect(!recorder.allArguments.contains("username"))
    }

    /// An item with no password is a REAL failure, named. It is the one field whose
    /// absence cannot be worked around.
    @Test func anItemWithNoPasswordIsReportedAsSuch() async {
        for reply in [PP.fail(PP.noField("password")), PP.ok("")] {
            let provider = ProtonPassProvider(reference: "pass://\(PP.shareID)/\(PP.itemID)",
                                              channel: runner(fields: ["password": reply]).channel())
            await #expect(throws: ProtonPassProvider.ProtonPassError.noPassword(PP.itemID)) {
                _ = try await provider.resolve(profile: "p", fields: [.password])
            }
        }
    }

    /// A VERIFICATION CODE IS USED WHEN IT IS THERE and its absence is silent — the
    /// promise (`suppliesOTP`) stays false either way.
    @Test func aVerificationCodeIsUsedWhenPresentAndSilentWhenNot() async throws {
        let with = runner(fields: ["password": PP.ok("s3cret"), "totp": PP.ok("482910")])
        let provider = ProtonPassProvider(reference: "pass://\(PP.shareID)/\(PP.itemID)",
                                          channel: with.channel())
        #expect(try await provider.resolve(profile: "p", fields: [.password, .otp]).otp == "482910")

        let without = runner(fields: ["password": PP.ok("s3cret"),
                                       "totp": PP.fail(PP.noField("totp"))])
        let bare = ProtonPassProvider(reference: "pass://\(PP.shareID)/\(PP.itemID)",
                                      channel: without.channel())
        #expect(try await bare.resolve(profile: "p", fields: [.password, .otp]).otp == nil)
    }

    /// Something that is not a code is left alone rather than handed to the engine as
    /// one. A wrong code costs a failed sign-in and a burned attempt.
    @Test func somethingThatIsNotACodeIsNotTreatedAsOne() async throws {
        let recorder = runner(fields: ["password": PP.ok("s3cret"),
                                       "totp": PP.ok("otpauth://totp/x?secret=JBSWY3DPEHPK3PXP")])
        let provider = ProtonPassProvider(reference: "pass://\(PP.shareID)/\(PP.itemID)",
                                          channel: recorder.channel())
        #expect(try await provider.resolve(profile: "p", fields: [.password, .otp]).otp == nil)
    }

    /// A code is not fetched at all when nobody asked for one.
    @Test func noCodeIsFetchedWhenNoneWasAskedFor() async throws {
        let recorder = runner(fields: ["password": PP.ok("s3cret")])
        let provider = ProtonPassProvider(reference: "pass://\(PP.shareID)/\(PP.itemID)",
                                          channel: recorder.channel())
        _ = try await provider.resolve(profile: "p", fields: [.password])
        #expect(!recorder.allArguments.contains("totp"))
    }

    /// A TITLE THAT MATCHES NOTHING says which title, in which vault.
    @Test func aTitleThatMatchesNothingIsNamed() async {
        let provider = ProtonPassProvider(
            reference: "Work/GR Lab",
            channel: runner(list: PP.ok(PP.list([(PP.itemID, "Something else", "login")]))).channel())
        await #expect(throws: ProtonPassProvider.ProtonPassError
            .notFound(title: "GR Lab", vault: "Work")) {
            _ = try await provider.resolve(profile: "p", fields: [.password])
        }
    }

    /// Every state the CLI can report during a FETCH surfaces as the matching error,
    /// including the entitlement gate — a fetch must never report a subscription as a
    /// generic failure either.
    @Test func fetchTimeFailuresKeepTheirIdentity() async {
        let cases: [(String, ProtonPassProvider.ProtonPassError)] = [
            (PP.notAuthenticated, .notSignedIn),
            (PP.invalidated, .notSignedIn),
            (PP.sessionLocked, .locked),
            (PP.notAllowed, .planExcludesTool),
        ]
        for (stderr, expected) in cases {
            let provider = ProtonPassProvider(reference: "Work/GR Lab",
                                              channel: runner(list: PP.fail(stderr)).channel())
            await #expect(throws: expected) {
                _ = try await provider.resolve(profile: "p", fields: [.password])
            }
        }
    }

    /// A timeout says so rather than pretending to be a missing item.
    @Test func aTimeoutIsItsOwnSentence() async {
        let provider = ProtonPassProvider(reference: "pass://\(PP.shareID)/\(PP.itemID)",
                                          channel: runner(fields: ["password": PP.timedOut]).channel())
        await #expect(throws: ProtonPassProvider.ProtonPassError
            .unreadable("Proton Pass didn\u{2019}t answer in time.")) {
            _ = try await provider.resolve(profile: "p", fields: [.password])
        }
    }

    /// `isAvailable` is prompt-free and does NOT read the item — availability must
    /// never spend a fetch.
    @Test func availabilityDoesNotReadTheItem() async {
        let recorder = runner(info: PP.ok(PP.info(hasLock: false)))
        let provider = ProtonPassProvider(reference: "pass://\(PP.shareID)/\(PP.itemID)",
                                          channel: recorder.channel())
        #expect(await provider.isAvailable(for: "p"))
        #expect(recorder.calls == [["info", "--output", "json"]])

        // A reference that cannot be read is unavailable without asking anything.
        let quiet = runner(info: PP.ok(PP.info(hasLock: false)))
        let bare = ProtonPassProvider(reference: "GR Lab", channel: quiet.channel())
        #expect(!(await bare.isAvailable(for: "p")))
        #expect(quiet.calls.isEmpty)
    }
}

// MARK: - The argv and clipboard contracts

@Suite("Proton Pass secret handling")
struct ProtonPassSecretHandlingTests {

    /// NOTHING SECRET IS EVER AN ARGUMENT. `ps` shows argv to every process on this
    /// Mac. Only the item's identifiers and the field NAMES may ride it, and the value
    /// that comes back must never reappear in a later call.
    @Test func nothingSecretIsEverAnArgument() async throws {
        let secret = "s3cret-vpn-pass"
        let code = "482910"
        let recorder = runner(list: PP.ok(PP.list([(PP.itemID, "GR Lab", "login")])),
                              fields: ["password": PP.ok(secret),
                                       "username": PP.ok("alice"),
                                       "totp": PP.ok(code)])
        let provider = ProtonPassProvider(reference: "Work/GR Lab", channel: recorder.channel())
        let raw = try await provider.resolve(profile: "p", fields: [.username, .password, .otp])
        #expect(raw.password == secret)

        let arguments = recorder.allArguments
        #expect(!arguments.contains(secret))
        #expect(!arguments.contains(code))
        #expect(!arguments.contains("alice"))
        // The only thing resembling a secret in argv is the field's NAME.
        #expect(arguments.contains("--field"))
        #expect(arguments.contains("password"))
    }

    /// NO CLIPBOARD FLAG, EVER. `pass-cli` has no clipboard option at all — its
    /// repository contains no clipboard code — but a future release adding one must
    /// not find SimpleVPN already reaching for it. A VPN password on the pasteboard is
    /// the next paste away from anywhere.
    @Test func noClipboardFlagIsEverPassed() async throws {
        let recorder = runner(list: PP.ok(PP.list([(PP.itemID, "GR Lab", "login")])),
                              fields: ["password": PP.ok("s3cret"), "username": PP.ok("alice"),
                                       "totp": PP.ok("482910")])
        let provider = ProtonPassProvider(reference: "Work/GR Lab", channel: recorder.channel())
        _ = try await provider.resolve(profile: "p", fields: [.username, .password, .otp])
        let adapter = ProtonPassVaultAdapter(channel: recorder.channel())
        _ = await adapter.deepScan(quick: .unchecked)

        for argument in recorder.allArguments {
            let lowered = argument.lowercased()
            #expect(!lowered.contains("clip"), "\u{201C}\(argument)\u{201D} mentions the clipboard")
            #expect(argument != "-c")
        }
    }

    /// WE NEVER HAND PROTON A SECRET EITHER. Proton's own documentation warns that a
    /// password in an environment variable is readable by every process in the
    /// session; SimpleVPN holds none of those secrets and must never set those
    /// variables. This pins the names.
    @Test func theSecretBearingEnvironmentVariablesAreNeverSet() {
        let forbidden = ["PROTON_PASS_PASSWORD", "PROTON_PASS_PASSWORD_FILE",
                         "PROTON_PASS_TOTP", "PROTON_PASS_TOTP_FILE",
                         "PROTON_PASS_EXTRA_PASSWORD", "PROTON_PASS_EXTRA_PASSWORD_FILE",
                         "PROTON_PASS_PERSONAL_ACCESS_TOKEN",
                         "PROTON_PASS_SSH_KEY_PASSWORD"]
        // The child's environment is built, never inherited, and this source adds
        // nothing to it — so the runner's own set is the whole of it.
        let environment = LocalToolRunner.childEnvironment(
            home: URL(fileURLWithPath: "/Users/someone"))
        for name in forbidden {
            #expect(environment[name] == nil, "\(name) reached a child\u{2019}s environment")
        }
    }
}

// MARK: - Keeping `pass-cli` and `pass` apart

@Suite("Proton Pass is not the password store")
struct ProtonPassIsNotThePasswordStoreTests {

    /// THREE SEPARATE TOOLS IN THE CATALOGUE, and only one of them is Proton's. This
    /// is the test that would have caught a copy-paste sending Proton Pass's row at
    /// the unix password store's binary.
    @Test func threeToolsAndOnlyOneIsProtons() {
        #expect(ToolCatalog.tool(named: "pass-cli")?.vendor == .protonPass)
        #expect(ToolCatalog.tool(named: "pass")?.vendor == nil)
        #expect(ToolCatalog.tool(named: "gopass")?.vendor == nil)
        #expect(ToolCatalog.tools(for: .protonPass).map(\.name) == ["pass-cli"])
        // And the password store's row reaches GnuPG — not `pass`, which nothing runs.
        // So the two vendors' tool sets are disjoint as well as differently named.
        #expect(ToolCatalog.tools(for: .passwordStore).map(\.name) == ["gpg", "gpg2"])
        #expect(Set(ToolCatalog.tools(for: .protonPass).map(\.name))
            .isDisjoint(with: Set(ToolCatalog.tools(for: .passwordStore).map(\.name))))
    }

    /// The two vendors' SLUGS cannot be confused — they are the MDM, CLI and
    /// manual-anchor contract, and an administrator's payload naming the wrong one
    /// would allow or forbid the wrong vendor.
    @Test func theSlugsAreDistinctAndNeitherIsAPrefixOfTheOther() {
        #expect(LocalVaultVendor.protonPass.settingSlug == "protonpass")
        #expect(LocalVaultVendor.passwordStore.settingSlug == "passwordstore")
        #expect(LocalVaultVendor.vendor(withSlug: "protonpass") == .protonPass)
        #expect(LocalVaultVendor.vendor(withSlug: "passwordstore") == .passwordStore)
        #expect(LocalVaultVendor.vendor(withSlug: "pass") == nil)
    }

    /// SEPARATE FIELDS, SEPARATE TOOLS. Proton Pass's one field points at `pass-cli`;
    /// the password store's points at `gpg`. Neither points at `pass`, which nothing
    /// runs — a row pointing there would let somebody carefully fix a path that is
    /// never read.
    @Test func eachVendorsFieldPointsAtItsOwnTool() {
        let proton = SignInSourceSettings.fields(for: .protonPass)
        #expect(proton.count == 1)
        #expect(proton.first?.kind.detectionTool == "pass-cli")
        #expect(proton.first?.settingID == "creds.protonpass.tool-path")
        #expect(proton.first?.defaultsKey == "signin.tool.pass-cli.path")

        let store = SignInSourceSettings.fields(for: .passwordStore)
        #expect(store.compactMap { $0.kind.detectionTool } == ["gpg"])
        #expect(!SignInSourceSettings.allFields.contains { $0.kind.detectionTool == "pass" })
    }

    /// EVERY ONE OF THIS VENDOR'S STATES obeys the house glossary, not just the one
    /// the shared vocabulary test happens to render. `SignInSourceTests` sweeps the
    /// chooser with every vendor blocked on `notSignedIn`, which leaves this feed's
    /// other four states — including the entitlement one, whose copy is the most likely
    /// to reach for the word "login" — unchecked. So they are checked here.
    @Test func everyStatesCopyObeysTheGlossary() {
        let copy = LocalVaultCopyBook.copy(for: .protonPass)
        var strings = [copy.title, copy.summary, copy.explanation, copy.uncheckedNote ?? ""]
        for block in [LocalVaultBlock.toolMissing, .notSignedIn, .vaultLocked,
                      .planExcludesTool, .toolOutsideAllowList] {
            strings.append(copy.headline(for: block))
            strings += copy.steps(for: block)
            if let guidance = copy.guidance(for: block) {
                strings.append(guidance.benefit)
                strings.append(guidance.settingLocation ?? "")
                // The CAPTIONS are ours and are checked. The command TEXT is Proton's
                // own and is not — renaming `pass-cli login` in our copy would make the
                // instruction wrong, which is the glossary's "keep their vocabulary"
                // rule. `spokenSummary` is excluded for the same reason: it splices
                // that verbatim text into a sentence, and every part of it that IS ours
                // is already in this list.
                strings += guidance.example.map(\.caption)
            }
        }
        strings.append(SignInFlow.unavailableHeadline(.protonPass))
        strings += ProtonPassBlockErrors.everySentence

        let forbidden = ["credential", "log in", "login", "logon", "authenticate",
                         "one-time passcode"]
        for text in strings {
            let visible = Self.withoutCodeSpans(text)
            for word in forbidden {
                #expect(!visible.lowercased().contains(word),
                        "\u{201C}\(text)\u{201D} contains \u{201C}\(word)\u{201D}")
            }
            #expect(!visible.contains("OTP"), "\u{201C}\(text)\u{201D} says OTP")
        }
    }

    /// A command the user types verbatim is exempt from our glossary and ONLY from our
    /// glossary — `pass-cli login` is Proton's own subcommand, and renaming it in our
    /// copy would make the instruction wrong. AGENTS.md's glossary says so outright:
    /// other products' own labels keep their vocabulary.
    ///
    /// This app spells a command two ways depending on where it appears, and both are
    /// stripped here: **backticks** in the numbered steps (which the banner renders as
    /// `code`), and **curly quotes** inside a running sentence, which is how every
    /// error string in this project quotes one — Bitwarden's says "run “bw unlock”" in
    /// exactly the same shape.
    private static func withoutCodeSpans(_ text: String) -> String {
        var out = ""
        var inBackticks = false
        var inQuotes = false
        for character in text {
            switch character {
            case "`":
                inBackticks.toggle()
            case "\u{201C}":
                inQuotes = true
            case "\u{201D}":
                inQuotes = false
            default:
                if !inBackticks, !inQuotes { out.append(character) }
            }
        }
        return out
    }

    /// The two rows never call themselves the same thing, and Proton's row never says
    /// the bare word "pass" outside a `code` span — which is where a tool name to type
    /// belongs.
    @Test func theCopyKeepsThemApart() {
        let proton = LocalVaultCopyBook.copy(for: .protonPass)
        let store = LocalVaultCopyBook.copy(for: .passwordStore)
        #expect(proton.title == "Proton Pass")
        #expect(store.title == "pass / gopass")
        #expect(proton.title != store.title)
        #expect(proton.symbol != store.symbol)
        #expect(CredentialSourceKind.protonPass.systemImage
            != CredentialSourceKind.passwordStore.systemImage)
        // Proton's install command names Proton's tap, not `pass`.
        #expect(proton.homebrewInstallCommand == "brew install protonpass/tap/pass-cli")
        #expect(store.homebrewInstallCommand == "brew install gnupg")
        // Its explanation warns about the confusion rather than leaving it to chance.
        #expect(proton.explanation.contains("Proton"))
    }
}

// MARK: - The entitlement state, as a first-class state

@Suite("Proton Pass entitlement state")
struct ProtonPassEntitlementTests {

    /// IT IS ITS OWN STATE, and it is offered WITH a banner. A row that says only
    /// "Proton Pass can't answer" leads somewhere useless.
    @Test func itIsABlockedStateWithAnEnablementBanner() {
        #expect(LocalVaultBlock.planExcludesTool.wantsEnablementBanner)
        let option = SignInSourceCatalog.vaultOption(
            .protonPass, availability: .blocked(.planExcludesTool))
        guard let option else {
            Issue.record("the entitlement state produced no row")
            return
        }
        #expect(option.role == .fetches)
        guard case .needsSetup(let headline, _) = option.state else {
            Issue.record("the entitlement state is not a setup state")
            return
        }
        #expect(headline.lowercased().contains("plan"))
        #expect(option.guidance != nil)
    }

    /// THE WORDING SAYS "PLAN" AND SAYS "NOTHING IS BROKEN". Both halves are load
    /// bearing: the first names the cause, the second stops the search for a bug.
    @Test func theWordingNamesThePlanAndAbsolvesTheMac() {
        let guidance = LocalVaultCopyBook.copy(for: .protonPass)
            .guidance(for: .planExcludesTool)
        guard let guidance else {
            Issue.record("no guidance for the entitlement state")
            return
        }
        let benefit = guidance.benefit
        #expect(benefit.contains("Pass Plus"))
        #expect(benefit.contains("Pass Family"))
        #expect(benefit.contains("Pass Professional"))
        #expect(benefit.lowercased().contains("bundle"))
        #expect(benefit.lowercased().contains("nothing here to fix"))
        // NO COMMAND, because running one would change nothing. The fix is on
        // Proton's own pages, and the link is the actionable part.
        #expect(guidance.example.isEmpty)
        #expect(guidance.doc == VendorDocs.protonPassPlans)
        // The whole banner is spoken, so a VoiceOver user hears the plan too.
        #expect(guidance.spokenSummary.contains("Pass Plus"))
    }

    /// The provider's own sentence says the same thing, because a fetch can hit this
    /// too and a connect-time failure must not read as a bug either.
    @Test func theFetchTimeSentenceSaysItToo() {
        let sentence = ProtonPassProvider.ProtonPassError.planExcludesTool.errorDescription ?? ""
        #expect(sentence.contains("Pass Plus"))
        #expect(sentence.lowercased().contains("nothing is broken")
            || sentence.lowercased().contains("correctly"))
    }

    /// A DIAGNOSTIC REPORT SAYS IT OUT LOUD, because a maintainer reading "not signed
    /// in" would start debugging a tool that is behaving correctly.
    @Test func aReportSaysNothingIsBroken() {
        let words = DiagnosticReportInventory.stateWords(.blocked(.planExcludesTool))
        #expect(words.lowercased().contains("plan"))
        #expect(words.lowercased().contains("not a fault"))
    }

    /// THE OTHER HALF OF THE HONESTY: the state a free-plan user actually LANDS in is
    /// "not signed in", because Proton's tool logs itself out when it is refused. So
    /// that row's steps must mention the plan as well — otherwise the sign-in loop
    /// never ends.
    @Test func theNotSignedInRowAlsoNamesThePlan() {
        let copy = LocalVaultCopyBook.copy(for: .protonPass)
        let steps = copy.steps(for: .notSignedIn).joined(separator: " ")
        #expect(steps.contains("Pass Plus"))
        #expect(steps.contains("`pass-cli login`"))
    }

    /// And so does the connect-time recovery sentence, which names the source (the
    /// house rule) and all three reasons.
    @Test func theRecoverySentenceNamesTheSourceAndAllThreeReasons() {
        let headline = SignInFlow.unavailableHeadline(.protonPass)
        #expect(headline.contains(CredentialSourceKind.protonPass.displayName))
        #expect(headline.lowercased().contains("signed in"))
        #expect(headline.lowercased().contains("locked"))
        #expect(headline.lowercased().contains("plan"))
    }
}

// MARK: - Registration in the shared surfaces

@Suite("Proton Pass registration")
struct ProtonPassRegistrationTests {

    @Test func theAdapterIsRegisteredAndReachableBothWays() {
        #expect(LocalVaultRegistry.adapter(for: LocalVaultVendor.protonPass) != nil)
        #expect(LocalVaultRegistry.adapter(for: CredentialSourceKind.protonPass)?.vendor
            == .protonPass)
    }

    /// SINGLE-INSTANCE, with a reason: one session file, one signed-in account, and no
    /// `--config`. A vault is named inside the item reference, which is level 3.
    @Test func itIsSingleInstanceSoItHasNoInstanceFields() {
        #expect(LocalVaultVendor.protonPass.cardinality == .single)
        #expect(!LocalVaultVendor.protonPass.cardinality.allowsSeveral)
        #expect(SignInSourceSettings.instanceFields(for: .protonPass).isEmpty)
        // Its one field is level 1: how we reach the vendor at all.
        #expect(SignInSourceSettings.transportFields(for: .protonPass).count == 1)
    }

    /// The promise Connect relies on is FALSE, deliberately — nobody has watched a
    /// code come back from a live Proton account.
    @Test func itPromisesNoVerificationCode() {
        #expect(!CredentialSourceKind.protonPass.suppliesOTP)
    }

    /// It is claimed as UNTESTED, which is the honest answer for a feed built with
    /// neither the tool nor an account present.
    @Test func itIsClaimedAsUntested() {
        #expect(FeatureMaturityRegistry.maturity(ofSource: .vault(.protonPass)) == .untested)
    }

    /// The app row is a POINTER when the tool is absent, and the pointer names the
    /// real tool — `pass-cli`, so the sentence is searchable and cannot be read as the
    /// `pass` somebody may already have.
    @Test func theAppAloneIsAPointerThatNamesTheTool() {
        #expect(PasswordAppCatalog.gatedVendor(forBundleID: "me.proton.pass.electron")
            == .protonPass)
        #expect(PasswordAppCatalog.localReadPath(forBundleID: "me.proton.pass.electron")
            == .officialCLI("pass-cli"))
        // And the other distribution's id resolves the same way.
        #expect(PasswordAppCatalog.gatedVendor(forBundleID: "ch.protonmail.pass") == .protonPass)
    }

    /// A report can name the app, so "the tool is here and the app is not" is a fact a
    /// maintainer can read rather than infer.
    @Test func aReportKnowsWhichAppToLookFor() {
        let ids = DiagnosticReportInventory.vendorBundleIDs(.protonPass)
        #expect(ids.contains("me.proton.pass.electron"))
    }

    /// Its settings are GENERATED like every other vendor's, so they are searchable,
    /// documented and MDM-addressable without a second mechanism.
    @Test func itsSettingsAreInTheCatalog() async {
        let ids = await MainActor.run { Set(CredentialSourceSettings.all.map(\.id)) }
        #expect(ids.contains("creds.protonpass.enabled"))
        #expect(ids.contains("creds.protonpass.tool-path"))
        // Single-instance, so there is no list control — a spec for a list that cannot
        // have two entries would be a question with no answer.
        #expect(!ids.contains(SignInSourceSettings.instanceListSettingID(.protonPass)))
        for id in ["creds.protonpass.enabled", "creds.protonpass.tool-path"] {
            #expect(await MainActor.run { CredentialSourceSettings.vendor(forSettingID: id) }
                == .protonPass)
        }
    }

    /// Every documentation link this feed adds is in the audited table, so a dead link
    /// is one edit rather than a grep through view bodies.
    @Test func itsDocumentationLinksAreAudited() {
        for page in [VendorDocs.protonPassCLI, VendorDocs.protonPassCLILogin,
                     VendorDocs.protonPassCLISession, VendorDocs.protonPassCLIReferences,
                     VendorDocs.protonPassPlans] {
            #expect(VendorDocs.all.contains(page), "\(page.title) is not in the audit table")
            // The docs site requires the trailing slash: the same address without one
            // is a 301, and shipping a redirecting URL is the mistake this table's
            // comment records.
            if page.url.host == "protonpass.github.io" {
                #expect(page.url.absoluteString.hasSuffix("/"),
                        "\(page.title) would be a redirect")
            }
        }
    }
}
