// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
//  ProtonPassProvider.swift
//  Fetch a username and password from Proton Pass, through Proton's own
//  command-line tool.
//
//  THE TOOL IS `pass-cli`, AND THAT NAME IS THE FIRST HAZARD THIS FILE HAS TO
//  HANDLE. SimpleVPN already reads the unix password store, whose tool is `pass`
//  (PasswordStoreReader.swift). Two different products, two different vaults, two
//  adjacent binary names — and discovery searches BY BINARY NAME, so a mix-up
//  would not be a cosmetic slip: it would be one vendor's row reporting the other
//  vendor's tool, and a person carefully setting a path that is never read. So:
//   • `ToolCatalog` carries `pass`, `gopass` and `pass-cli` as three separate
//     entries, and only `pass-cli` maps to this vendor;
//   • nothing here ever resolves the bare name `pass`, and nothing in the password
//     store's code resolves `pass-cli`;
//   • the copy never says "pass" unqualified — this vendor is "Proton Pass" and its
//     tool is named in `code` spans only.
//
//  ONE CHANNEL, `.cli`, AND NO DAEMON. `pass-cli` has an SSH agent and an "AI
//  agent" mode, but neither is a general read channel: the SSH agent serves SSH
//  keys to `ssh`, not usernames and passwords to us. So this is a plain
//  spawn-per-fetch source, like Keeper Commander.
//
//  HOW A FETCH WORKS, and why it is field by field rather than one JSON read:
//  `pass-cli item view --field <name>` prints THAT FIELD'S VALUE ON STDOUT AND
//  NOTHING ELSE (pass-cli/src/commands/item/view.rs — `println!("{}", field_value
//  .value())`). That is exactly the shape `LocalToolRunner` is built around: the
//  secret is on stdout, stderr carries only diagnostics, and nothing has to be
//  parsed out of a document whose field names belong to somebody else's release
//  notes. `--output json` would hand back the whole item — every field of it,
//  including ones we never asked for — and would tie us to an item schema we have
//  not verified. Two small runs beat one big guess.
//
//  ADDRESSING, AND THE TRADE-OFF STATED IN THE COPY. Proton Pass items are
//  addressed by a `pass://` reference whose two halves may each be an ID or a name
//  (`commands/contents/secret-references/`). IDs are stable and unique; names are
//  neither. AND — this is the part that decides the design — the CLI resolves a
//  name with `.find(…)`, the FIRST match, and Proton's own documentation says so:
//  "If there are several objects that match the name, one of them will be used."
//  There is no ambiguity error to catch. So SimpleVPN resolves a name reference
//  ITSELF, from `item list --output json` (a deliberately secret-free listing —
//  see `ProtonPassWire`), and REFUSES when more than one item carries the title
//  rather than reading an arbitrary one. Reading the wrong vault entry is worse
//  than failing to read at all, which is the same rule the `.kdbx` feed follows for
//  entry paths.
//
//  NOTHING GOES TO THE PASTEBOARD. Verified by absence in Proton's own source:
//  `pass-cli` has no clipboard code and no `-c`/`--clipboard` flag anywhere (a
//  case-insensitive search of the repository for "clipboard" finds nothing). Had
//  one existed it would not be used — a VPN password must not sit on the
//  pasteboard for the next paste to pick up.
//
//  THE SECRET'S ROUTE, in writing: it arrives on the child's stdout and is
//  returned as `RawCredentials`, which the connect path hands to the engine
//  through `startTunnel(options:)`. It is never in argv (only the item's own
//  reference and the field NAME ride argv), never in `providerConfiguration`,
//  never in a log line, never in an error string, never in a diagnostic bundle.
//  Nothing travels the other way, so `LocalToolRunner`'s `stdin:` channel is not
//  used and stdin stays `/dev/null`.
//
//  THE DEADLINE IS LOAD-BEARING, not a nicety. `pass-cli`'s own prompt helper
//  LOOPS on an empty answer (`pass-cli/src/utils.rs`: `loop { … read_line(…); if
//  !value.trim().is_empty() { return … } eprintln!("Value is empty") }`), so a
//  tool that decides to prompt against `/dev/null` would spin rather than hit EOF
//  and stop. `LocalToolRunner`'s hard deadline plus SIGKILL is what makes that a
//  bounded failure instead of a wedged connect. The read path is not supposed to
//  prompt at all — only `login`, `session unlock` and the extra-password step do —
//  which is precisely why this is written down rather than assumed.
//
//  WE NEVER SIGN IN FOR THE USER. `pass-cli login` is the vendor's own flow: a web
//  round trip, or a password plus a verification code, or a Pass-specific extra
//  password. SimpleVPN shows the command and the user runs it. Nor do we ever set
//  `PROTON_PASS_PASSWORD`, `PROTON_PASS_TOTP` or `PROTON_PASS_EXTRA_PASSWORD` —
//  Proton's own documentation warns that a password in an environment variable is
//  "readable by all other processes under the same session", and we hold none of
//  those secrets anyway.
//

import Foundation
import AppKit
import os

// MARK: - Which item, and how it is named

/// A Proton Pass item ID or share ID, recognised by SHAPE.
///
/// The predicate is Proton's own, copied rather than invented: `pass/src/utils.rs`
/// is `value.len() == 88 && value.ends_with("==")` — base64 of 64 bytes. It matters
/// that ours agrees, because the CLI uses the same test to decide whether a
/// `pass://` reference is a pair of IDs or a pair of names, and a SimpleVPN that
/// disagreed would send an ID down the name path (or worse).
nonisolated enum ProtonPassID {
    static func looksLikeID(_ value: String) -> Bool {
        value.count == 88 && value.hasSuffix("==")
    }
}

/// WHERE one item lives, as SimpleVPN understands the user's stored reference.
///
/// Two shapes, and the difference is the whole addressing trade-off:
///  • `.ids` — a share ID and an item ID. Unique, stable across renames and moves,
///    and readable in ONE subprocess with no listing first.
///  • `.names` — a vault name and an item title. Easy to type, easy to recognise,
///    and NOT unique — which is why this shape costs a listing and can legitimately
///    fail with "several items are called that".
///
/// A mixed reference (an ID vault with a named item, say) is treated as `.names`,
/// which is exactly what the CLI does: `FindItemQuery::new` takes the ID path only
/// when BOTH halves are IDs.
nonisolated enum ProtonPassAddress: Sendable, Equatable {
    case ids(share: String, item: String)
    case names(vault: String, title: String)

    /// The vault half, whichever shape this is — for an error sentence that can name
    /// the vault the user typed.
    var vaultLabel: String {
        switch self {
        case .ids(let share, _): share
        case .names(let vault, _): vault
        }
    }

    var itemLabel: String {
        switch self {
        case .ids(_, let item): item
        case .names(_, let title): title
        }
    }

    /// The arguments that name this item to `pass-cli`. IDs only — a `.names`
    /// address is resolved to IDs before anything is read, so this is never asked to
    /// express a name.
    var viewArguments: [String]? {
        guard case .ids(let share, let item) = self else { return nil }
        return ["--share-id", share, "--item-id", item]
    }

    /// The arguments that list the vault this address points into.
    var listArguments: [String] {
        switch self {
        case .ids(let share, _): ["--share-id", share]
        case .names(let vault, _): ["--vault-name", vault]
        }
    }
}

/// Turning what the user stored into an address, and refusing the shapes that
/// cannot be read without guessing.
///
/// Accepted, in the order people will type them:
///  • `pass://Work/GR Lab` and `pass://<share-id>/<item-id>` — the vendor's own
///    reference syntax, which is what the documentation and the app's own share
///    affordances produce.
///  • `Work/GR Lab` — the same thing without the scheme, because someone who has
///    seen the syntax once will type the short form.
///  • `pass://Work/GR Lab/password` — a reference WITH a field, which is the most
///    likely thing to be pasted out of Proton's documentation. The field is dropped
///    on purpose: which field holds the password is SimpleVPN's question, not the
///    profile's, and a stored `/username` would otherwise silently become the
///    password.
///
/// REFUSED, with a sentence rather than a guess:
///  • a bare title with no vault. `pass-cli` would accept it against whatever vault
///    `settings set default-vault` names — a setting SimpleVPN cannot see and did
///    not choose — and would then take the first title match inside it. Two layers
///    of guessing to read a password with. Naming the vault costs one word.
nonisolated enum ProtonPassReference {

    static let scheme = "pass://"

    static func parse(_ raw: String) -> Result<ProtonPassAddress, ProtonPassProvider.ProtonPassError> {
        var text = raw.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !text.isEmpty else { return .failure(.noItem) }
        // The scheme is optional in what we accept and irrelevant to what we do.
        if text.lowercased().hasPrefix(scheme) { text = String(text.dropFirst(scheme.count)) }
        // A query string is the `?totp=` selector, which addresses a FIELD. Same
        // reasoning as the field path component below: not the profile's business.
        if let question = text.firstIndex(of: "?") { text = String(text[text.startIndex..<question]) }
        let parts = text.split(separator: "/", omittingEmptySubsequences: false).map(String.init)
        let named = parts.filter { !$0.isEmpty }
        guard named.count >= 2 else { return .failure(.needsVault(named.first ?? text)) }
        let vault = named[0]
        let item = named[1]
        if ProtonPassID.looksLikeID(vault), ProtonPassID.looksLikeID(item) {
            return .success(.ids(share: vault, item: item))
        }
        return .success(.names(vault: vault, title: item))
    }
}

// MARK: - What one item gives us

/// The non-secret half of an item, out of `item list --output json`.
///
/// SAFE BY THE VENDOR'S OWN CONSTRUCTION, not by our care: `ItemSummary` in
/// `pass-cli/src/commands/item/list.rs` carries the comment "Fields here must never
/// carry user-provided secret material (no content, note, extra_fields)" and holds
/// exactly IDs, timestamps, a type and a title. So a listing is a channel a
/// duplicate-title check can use without a secret ever being in the buffer.
nonisolated struct ProtonPassItemSummary: Sendable, Equatable {
    var id: String
    var shareID: String
    var title: String
    /// `"login"`, `"note"`, `"ssh_key"`, … — the vendor's own snake-case names.
    var itemType: String

    var isLogin: Bool { itemType == "login" }
}

/// What a session probe can say. Deliberately only the states that have DIFFERENT
/// FIXES: everything else is "we could not ask", which is not a state to accuse
/// anybody of.
nonisolated enum ProtonPassSessionState: Sendable, Equatable {
    /// A live session the Proton Pass API accepts.
    case ready
    /// No session at all — nobody has signed in, or the session was invalidated and
    /// the tool logged itself out.
    case notSignedIn
    /// A session that exists and is gated by its own lock code (`pass-cli session
    /// lock`). SIGNED IN BUT LOCKED — the existing `vaultLocked` state, and the same
    /// distinction Bitwarden's row draws for the same reason.
    case locked
    /// THE ENTITLEMENT GATE. The tool is installed, the account is real, and the
    /// plan does not include the command-line tool.
    case planExcludesTool
}

// MARK: - The channel seam

/// How this Mac talks to Proton Pass. One implementation ships; tests inject
/// another with no `pass-cli` and no Proton account anywhere.
nonisolated protocol ProtonPassChannel: Sendable {
    /// Which state the session is in, or nil when this channel cannot answer at all
    /// (no tool we may run). Prompt-free.
    func sessionState() async -> ProtonPassSessionState?
    /// Every item in the vault an address points into. Non-secret.
    func items(in address: ProtonPassAddress) async throws -> [ProtonPassItemSummary]
    /// ONE field of one item, by IDs. The returned string is SECRET-BEARING.
    func field(_ name: String, of address: ProtonPassAddress) async throws -> String?
}

// MARK: - The provider

nonisolated struct ProtonPassProvider: CredentialProvider {
    let id = "protonpass"
    let displayName = "Proton Pass"
    /// The stored `pass://` reference — vault plus item, by ID or by name.
    let reference: String
    /// An optional username from the VPN's own profile. It WINS over the item's own,
    /// because the person who typed it here meant it.
    var account: String = ""
    /// Injectable so every path — no tool, no session, locked, no such item, several
    /// items, no password — is driven by fixtures.
    var channel: any ProtonPassChannel = ProtonPassCLIChannel()

    private static let log = Logger(subsystem: "com.bragi0.SimpleVPN", category: "protonpass")

    /// Cheap and prompt-free at the level this seam allows: a reference exists and
    /// the session probe says the API accepts us. Deliberately does NOT read the
    /// item — availability must never spend a fetch, and on a slow link it would
    /// make the chooser wait for a network round trip per refresh.
    func isAvailable(for profile: String) async -> Bool {
        guard case .success = ProtonPassReference.parse(reference) else { return false }
        return await channel.sessionState() == .ready
    }

    func resolve(profile: String, fields: Set<AuthKind>) async throws -> RawCredentials {
        let address = try ProtonPassReference.parse(reference).get()
        // A name is resolved to IDs BY US, so nothing downstream can silently take
        // the first of several matches. An ID address skips this entirely — one
        // subprocess, no listing.
        let resolved = try await resolvedByID(address)
        guard let password = try await channel.field("password", of: resolved), !password.isEmpty else {
            throw ProtonPassError.noPassword(address.itemLabel)
        }
        var raw = RawCredentials()
        raw.password = password
        if fields.contains(.username) {
            let typed = account.trimmingCharacters(in: .whitespaces)
            raw.username = typed.isEmpty ? try await username(of: resolved) : typed
        }
        if fields.contains(.otp) { raw.otp = await verificationCode(of: resolved) }
        // The reference is the user's own label and the profile name is not secret;
        // no field VALUE is ever in this line.
        Self.log.log("proton pass item resolved for \(profile, privacy: .public)")
        return raw
    }

    /// A `.names` address turned into a `.ids` one, or the reason it cannot be.
    ///
    /// This is where "several items are called that" is DETECTED, because the CLI
    /// will not detect it: `find_item_by_name` takes the first match and Proton's own
    /// documentation says one of them will be used. A listing is secret-free, so
    /// asking is cheap in the only currency that matters here.
    func resolvedByID(_ address: ProtonPassAddress) async throws -> ProtonPassAddress {
        guard case .names(let vault, let title) = address else { return address }
        let items = try await channel.items(in: address)
        let matches = ProtonPassItemPicker.matching(title: title, in: items)
        guard let first = matches.first else {
            throw ProtonPassError.notFound(title: title, vault: vault)
        }
        guard matches.count == 1 else { throw ProtonPassError.severalMatches(matches.count) }
        return .ids(share: first.shareID, item: first.id)
    }

    /// The username, from `username` and then from `email`.
    ///
    /// Both are real, separate fields on a Proton Pass login item and either may be
    /// the empty one — `add_login_fields` in `pass-domain/src/models/item/field.rs`
    /// only offers a field when it is non-empty, so an item with an address in
    /// "email" and nothing in "username" answers "Field does not exist: username".
    /// That is not a failure to report; it is the other field's turn.
    private func username(of address: ProtonPassAddress) async throws -> String? {
        for name in ["username", "email"] {
            if let value = try? await channel.field(name, of: address), !value.isEmpty {
                return value
            }
        }
        return nil
    }

    /// The verification code, when the item has one — and never a promise that it
    /// will.
    ///
    /// `CredentialSourceKind.protonPass.suppliesOTP` is FALSE on purpose, following
    /// Keeper's and Bitwarden's precedent: the flag means "Connect works with nothing
    /// typed", and asking for a field an item may not have cannot support that claim
    /// (`item view --field totp` FAILS the whole run for an item with no code, so
    /// there is no way to ask "is there one?" without spending a run). So the code is
    /// used when it is there and its absence is silent — the user types one either
    /// way, and nothing is broken when they do not have to.
    private func verificationCode(of address: ProtonPassAddress) async -> String? {
        guard let value = try? await channel.field("totp", of: address) else { return nil }
        let trimmed = value.trimmingCharacters(in: .whitespacesAndNewlines)
        // `pass-cli` prints the CODE for a TOTP field by default (`TotpOutput::Code`
        // is `#[default]`), so this really is six-to-eight digits and not a seed. A
        // value that is not digits is something else and is left alone rather than
        // handed to the engine as a code.
        guard (6...10).contains(trimmed.count), trimmed.allSatisfy(\.isNumber) else { return nil }
        return trimmed
    }

    /// Everything that can go wrong, in the user's words.
    ///
    /// NOTHING here interpolates a secret. A vault name, an item title and a count
    /// are the user's own labels and a number; a vendor message is scrubbed and
    /// truncated by `LocalToolRunner.scrub` before it may be quoted at all.
    nonisolated enum ProtonPassError: LocalizedError, Equatable {
        case noItem
        case needsVault(String)
        case notSignedIn
        case locked
        case planExcludesTool
        case notFound(title: String, vault: String)
        case severalMatches(Int)
        case noPassword(String)
        case toolMissing
        case unreadable(String)

        var errorDescription: String? {
            switch self {
            case .noItem:
                "No Proton Pass item is set for this VPN \u{2014} add the vault and item, like "
                + "\u{201C}Work/GR Lab\u{201D}."
            case .needsVault(let title):
                (title.isEmpty
                    ? "Name the vault as well as the item"
                    : "Name the vault as well as \u{201C}\(title)\u{201D}")
                + " \u{2014} for example \u{201C}Work/\(title.isEmpty ? "GR Lab" : title)\u{201D}. "
                + "Without a vault, Proton Pass would pick whichever item it found first, and "
                + "SimpleVPN won\u{2019}t read a password on a guess."
            case .notSignedIn:
                "Proton Pass isn\u{2019}t signed in on this Mac. Open Terminal and run "
                + "\u{201C}pass-cli login\u{201D}."
            case .locked:
                "Your Proton Pass session is locked. Open Terminal and run "
                + "\u{201C}pass-cli session unlock\u{201D}."
            case .planExcludesTool:
                // THE SUBSCRIPTION SENTENCE. Everything is installed and working;
                // what is missing is a plan that includes the tool. Saying anything
                // vaguer sends somebody to debug software that is behaving correctly.
                "Proton Pass\u{2019}s command-line tool needs a Proton Pass plan that includes it "
                + "\u{2014} Pass Plus, Pass Family, Pass Professional, or any Proton bundle. "
                + "Everything on this Mac is set up correctly; the tool is refusing because of the "
                + "plan on your account, not because anything is broken."
            case .notFound(let title, let vault):
                "Proton Pass has no item called \u{201C}\(title)\u{201D} in \u{201C}\(vault)\u{201D}. "
                + "Titles have to match exactly, including capital letters."
            case .severalMatches(let count):
                "\(count) Proton Pass items in that vault are called the same thing, so SimpleVPN "
                + "won\u{2019}t guess which one you meant. Use the vault\u{2019}s and item\u{2019}s "
                + "own identifiers instead of their names, or rename one of them."
            case .noPassword(let title):
                "The Proton Pass item \u{201C}\(title)\u{201D} has no password in it."
            case .toolMissing:
                "Proton Pass\u{2019}s command-line tool isn\u{2019}t installed anywhere SimpleVPN "
                + "will run it from."
            case .unreadable(let detail):
                detail.isEmpty ? "Proton Pass couldn\u{2019}t provide the sign-in."
                               : "Proton Pass couldn\u{2019}t provide the sign-in: \(detail)"
            }
        }
    }
}

// MARK: - Choosing an item (pure)

/// Which listed items answer to a title. Pure, so "several matches" and "titles are
/// exact" are tested with no Proton account.
nonisolated enum ProtonPassItemPicker {

    /// EXACT, CASE-SENSITIVE title equality, and only login items.
    ///
    /// Exact because that is what the CLI does (`items.find(|i| i.content.title ==
    /// item_name)`), and being cleverer than the tool we are about to run is how
    /// SimpleVPN would resolve a name to one item and `pass-cli` to another. Logins
    /// only because a secure note of the same title cannot sign anything in, and
    /// counting it would report an ambiguity that does not exist.
    static func matching(title: String, in items: [ProtonPassItemSummary]) -> [ProtonPassItemSummary] {
        items.filter { $0.isLogin && $0.title == title }
    }
}

// MARK: - Reading the tool's answers (pure, and narrow)

nonisolated enum ProtonPassWire {

    /// The items out of `item list --output json`:
    /// `{"items":[{"id":…,"share_id":…,"vault_id":…,"title":…,"item_type":"login"}]}`
    /// (`ItemsList`/`ItemSummary`, `pass-cli/src/commands/item/list.rs`). A bare
    /// array is accepted too, so a release that drops the wrapper does not silently
    /// stop finding items.
    static func items(_ data: Data) -> [ProtonPassItemSummary] {
        guard let any = try? JSONSerialization.jsonObject(with: data) else { return [] }
        if let array = any as? [Any] { return array.compactMap(item) }
        guard let dict = any as? [String: Any], let array = dict["items"] as? [Any] else { return [] }
        return array.compactMap(item)
    }

    private static func item(_ any: Any) -> ProtonPassItemSummary? {
        guard let dict = any as? [String: Any],
              let id = dict["id"] as? String, !id.isEmpty,
              let share = dict["share_id"] as? String, !share.isEmpty,
              let title = dict["title"] as? String else { return nil }
        let type = (dict["item_type"] as? String) ?? ""
        return ProtonPassItemSummary(id: id, shareID: share, title: title, itemType: type)
    }

    /// Whether `info` reports a lock on the session
    /// (`{"session_has_lock":true,…}` — `InfoOutput`, `pass-cli/src/commands/info
    /// .rs`).
    ///
    /// DELIBERATELY THE ONLY FIELD READ. `info` also prints the account's e-mail
    /// address and username, and neither is anything SimpleVPN needs, keeps or
    /// reports. What is not read cannot leak into a diagnostic bundle.
    ///
    /// NOTE, because the distinction bites: "has a lock" is not "is locked". Proton's
    /// own documentation says so — "Having a session lock does not mean that the
    /// session is locked at this moment" — so a `true` here is NOT a blocked state.
    /// A session that is locked RIGHT NOW is the one whose API calls fail, which is
    /// what `state(exitCode:stderr:)` classifies.
    static func hasSessionLock(_ data: Data) -> Bool {
        guard let dict = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else {
            return false
        }
        return dict["session_has_lock"] as? Bool ?? false
    }

    /// The session state out of ONE run's exit code and stderr.
    ///
    /// Every string matched here is Proton's own, quoted from the CLI's source
    /// rather than from a transcript, and matched loosely because the exact wording
    /// belongs to somebody else's release notes:
    ///
    ///  • "This operation requires an authenticated client" — `pass-cli/src/main.rs`,
    ///    for both "there is no session" and "the session is not authenticated".
    ///  • "Your session has been invalidated and you have been logged out
    ///    automatically." — `pass-cli/src/main.rs`, printed when the API rejects the
    ///    session; the tool then has no session at all, so it is the same state.
    ///  • "Session is locked. Please unlock your session and try again." — `pass/src/
    ///    macros.rs`, printed when the API answers `SessionLocked` (300008). The
    ///    error that accompanies it names the code as `SessionLocked`, so both are
    ///    matched.
    ///  • "Your account is not yet allowed to use our CLI" — `pass-cli/src/commands/
    ///    login.rs`, the entitlement gate. See `ProtonPassCLIChannel.sessionState`
    ///    for the honest note about where this can and cannot be observed.
    ///
    /// nil means "we could not tell", which is not a state to report as one.
    static func state(exitCode: Int32, stderr: String) -> ProtonPassSessionState? {
        if exitCode == 0 { return .ready }
        let lowered = stderr.lowercased()
        // The entitlement gate is checked FIRST: it is the only one of these that a
        // person cannot fix by typing a command, and mistaking it for "not signed in"
        // is exactly the wasted afternoon this state exists to prevent.
        if lowered.contains("allowed to use our cli") || lowered.contains("allowed to use the cli") {
            return .planExcludesTool
        }
        if lowered.contains("session is locked") || lowered.contains("sessionlocked") {
            return .locked
        }
        if lowered.contains("requires an authenticated client")
            || lowered.contains("session has been invalidated")
            || lowered.contains("there was not an active session") {
            return .notSignedIn
        }
        return nil
    }

    /// A fetch failure, classified. Same sources as `state(exitCode:stderr:)`, plus
    /// the two the read path adds:
    ///  • "Field does not exist: …" — `commands/item/view.rs`, for a field the item
    ///    has not got. NOT a fetch failure when we are trying `username` then
    ///    `email`, which is why the provider swallows it there and only a missing
    ///    PASSWORD is reported.
    ///  • "Error finding vault [name]" / "Could not find vault" — `commands/item/
    ///    common.rs` and `pass/src/vault/find.rs`.
    static func error(exitCode: Int32, stderr: String,
                      address: ProtonPassAddress) -> ProtonPassProvider.ProtonPassError {
        if let state = state(exitCode: exitCode, stderr: stderr) {
            switch state {
            case .notSignedIn: return .notSignedIn
            case .locked: return .locked
            case .planExcludesTool: return .planExcludesTool
            case .ready: break
            }
        }
        let lowered = stderr.lowercased()
        if lowered.contains("find vault") || lowered.contains("no item found with title")
            || lowered.contains("could not find item") || lowered.contains("item not found") {
            return .notFound(title: address.itemLabel, vault: address.vaultLabel)
        }
        // Already scrubbed and truncated by the runner; quoted, not interpreted.
        return .unreadable(stderr)
    }
}

// MARK: - Where the tool's session lives (a probe with no subprocess)

/// The CHEAP probe: does a session file exist at all?
///
/// `pass-cli` keeps its session at `<data dir>/proton-pass-cli/.session/session.json`
/// — `get_base_dir()` in `pass-cli/src/utils.rs` joins `dirs::data_dir()` (which is
/// `~/Library/Application Support` on macOS) with `proton-pass-cli`, then `.session`,
/// and `SESSION_FILE_NAME` in `pass-cli/src/constants.rs` is `session.json`. The
/// `PROTON_PASS_SESSION_DIR` environment variable moves the whole thing, and is
/// honoured here for the same reason: a person who has moved it has not stopped
/// having a session.
///
/// One `stat`. No subprocess, no prompt, no network, and no spent attempt — which is
/// what lets a chooser refresh while it is on screen. Its ANSWER IS ONE-SIDED, and
/// the copy depends on that being understood: no file means definitely not signed
/// in; a file means a session existed once, not that the API still accepts it. So a
/// present file is `.unchecked` and the deep scan is what earns `.ready`.
nonisolated enum ProtonPassSessionFile {

    static let directoryEnvironmentVariable = "PROTON_PASS_SESSION_DIR"
    static let fileName = "session.json"

    /// Where the session file is, from an injected home directory and environment so
    /// the whole thing is testable in a temporary directory.
    static func url(home: URL = FileManager.default.homeDirectoryForCurrentUser,
                    environment: [String: String] = ProcessInfo.processInfo.environment) -> URL {
        let base: URL
        if let custom = environment[directoryEnvironmentVariable]?
            .trimmingCharacters(in: .whitespaces), !custom.isEmpty {
            base = URL(fileURLWithPath: custom)
        } else {
            base = home.appendingPathComponent("Library/Application Support/proton-pass-cli")
        }
        return base.appendingPathComponent(".session").appendingPathComponent(fileName)
    }

    static func exists(home: URL = FileManager.default.homeDirectoryForCurrentUser,
                       environment: [String: String] = ProcessInfo.processInfo.environment,
                       files: FileManager = .default) -> Bool {
        var isDirectory: ObjCBool = false
        let path = url(home: home, environment: environment).path
        guard files.fileExists(atPath: path, isDirectory: &isDirectory) else { return false }
        return !isDirectory.boolValue
    }
}

// MARK: - The `pass-cli` channel

/// The shipped channel: `pass-cli`, resolved through `LocalToolRunner`'s allow-list
/// and never through `PATH`.
nonisolated struct ProtonPassCLIChannel: ProtonPassChannel {

    /// The binary's name. `pass-cli`, and never `pass` — see this file's header for
    /// why that sentence is worth writing down.
    static let toolName = "pass-cli"

    /// Injected so the whole path — every state, every failure, and the assertion
    /// that no argument ever carries a secret — is driven by fixtures with no
    /// `pass-cli` installed.
    var run: @Sendable (_ arguments: [String]) async -> LocalToolResult

    init(run: (@Sendable (_ arguments: [String]) async -> LocalToolResult)? = nil) {
        self.run = run ?? ProtonPassCLIChannel.liveRun
    }

    /// Where `pass-cli` is, if anywhere. Proton's own installer prefers
    /// `~/.local/bin` and falls back to `/usr/local/bin` (`install.sh`), and their
    /// Homebrew tap (`brew install protonpass/tap/pass-cli`) lands in the Homebrew
    /// prefix — all three are already on `LocalToolRunner`'s list, so this needed no
    /// new location. Anywhere else is what `signin.tool.pass-cli.path` is for.
    static func locate() -> String? { LocalToolRunner.locate(toolName) }

    static let liveRun: @Sendable ([String]) async -> LocalToolResult = { arguments in
        guard let executable = locate() else {
            return LocalToolResult(exitCode: -1, stdout: Data(),
                                   stderr: "not an approved tool location", timedOut: false)
        }
        // 25 seconds: every read here is a network round trip to Proton, and the
        // deadline has to allow for a slow link without letting a wedged prompt
        // outlive the connect that asked for it. Nothing is passed on stdin, so the
        // child keeps `/dev/null` and a prompt gets EOF.
        return await LocalToolRunner.run(executable: executable, arguments: arguments,
                                         deadline: 25)
    }

    /// `pass-cli info --output json` — one run, no prompt, and it proves the thing
    /// that matters: the Proton Pass API accepted this session just now.
    ///
    /// THE ENTITLEMENT GATE IS CLASSIFIED HERE BUT CANNOT BE PROVOKED HERE, and
    /// saying so is better than implying otherwise. Proton checks the plan inside
    /// `pass-cli login` (`is_login_allowed` → `can_use_cli`, which reads the
    /// account's `Plan.cli_allowed`), prints "Your account is not yet allowed to use
    /// our CLI", and then LOGS THE TOOL OUT and exits. SimpleVPN never runs `login`
    /// — signing somebody in to their password manager is not ours to do — so the
    /// state this probe normally finds for a free-plan account is `notSignedIn`,
    /// because that is genuinely what the tool has been left in. Two things follow,
    /// and both are deliberate:
    ///   1. the sentence is recognised WHEREVER it appears on a `pass-cli` run's
    ///      stderr, so it is never reported as a generic failure; and
    ///   2. the `notSignedIn` copy for this vendor NAMES THE PLAN as one of its two
    ///      reasons, so somebody on a free plan is told about the subscription by the
    ///      state they actually land in rather than only by the one they do not.
    func sessionState() async -> ProtonPassSessionState? {
        let result = await run(["info", "--output", "json"])
        if result.timedOut { return nil }
        return ProtonPassWire.state(exitCode: result.exitCode, stderr: result.stderr)
    }

    /// `pass-cli item list … --output json`. Non-secret by the vendor's own
    /// construction — see `ProtonPassItemSummary`.
    func items(in address: ProtonPassAddress) async throws -> [ProtonPassItemSummary] {
        let result = await run(["item", "list"] + address.listArguments + ["--output", "json"])
        if result.timedOut {
            throw ProtonPassProvider.ProtonPassError.unreadable(
                "Proton Pass didn\u{2019}t answer in time.")
        }
        guard result.succeeded else {
            throw ProtonPassWire.error(exitCode: result.exitCode, stderr: result.stderr,
                                       address: address)
        }
        return ProtonPassWire.items(result.stdout)
    }

    /// `pass-cli item view --share-id … --item-id … --field <name>`, whose stdout is
    /// the field's value and nothing else.
    ///
    /// ONLY THE FIELD'S NAME AND THE ITEM'S IDENTIFIERS RIDE ARGV. That is the whole
    /// argv contract for this source: `ps` shows arguments to every process on this
    /// Mac, so a secret may never be one, and nothing here has any reason to be.
    func field(_ name: String, of address: ProtonPassAddress) async throws -> String? {
        guard let addressing = address.viewArguments else {
            // Structural: a name is resolved to IDs before anything is read, so this
            // is a programming mistake rather than a user's.
            throw ProtonPassProvider.ProtonPassError.needsVault(address.itemLabel)
        }
        let result = await run(["item", "view"] + addressing + ["--field", name])
        if result.timedOut {
            throw ProtonPassProvider.ProtonPassError.unreadable(
                "Proton Pass didn\u{2019}t answer in time.")
        }
        guard result.succeeded else {
            // "Field does not exist" is a fact about the item, not a failure of the
            // channel: nil lets the caller try the next field name (username →
            // email) and lets a missing verification code stay silent.
            if result.stderr.lowercased().contains("field does not exist") { return nil }
            throw ProtonPassWire.error(exitCode: result.exitCode, stderr: result.stderr,
                                       address: address)
        }
        // `result.text` is stdout, trimmed — and secret-bearing. It is returned and
        // never logged.
        let value = result.text
        return value.isEmpty ? nil : value
    }
}

// MARK: - The adapter

/// Proton Pass's row in the sign-in chooser. FOUR STATES, each with exactly one fix,
/// and the fourth is the one this feed exists to name:
///   1. `pass-cli` here with a live session → a source SimpleVPN fetches from.
///   2. `pass-cli` here, no session (or a locked one) → offered, with the one command
///      that fixes it.
///   3. `pass-cli` demonstrably installed somewhere SimpleVPN will not run from →
///      offered, with the path to paste. Or: the Proton Pass APP here and no
///      `pass-cli` → offered, with the install command. SimpleVPN never installs it.
///   4. Everything installed, everything signed in, AND THE PLAN DOES NOT INCLUDE
///      THE TOOL → offered, and said in those words. This is not a fifth flavour of
///      failure: nothing is broken, and someone told "Proton Pass isn't available"
///      here would spend an afternoon debugging a subscription.
///
/// `quickScan` is file checks only — the binary, and whether a session file exists.
/// Whether the API still accepts that session needs a subprocess and a network round
/// trip, and that is the deep scan.
struct ProtonPassVaultAdapter: LocalVaultAdapter {
    let vendor = LocalVaultVendor.protonPass
    let storedKind = CredentialSourceKind.protonPass
    /// One channel, and only one: Proton's own command-line tool. Its SSH agent is
    /// not a second way in — it serves keys to `ssh`, not usernames and passwords to
    /// us — so listing `.localDaemon` here would claim a channel that does not exist.
    let transports: [AuthTransport] = [.cli]

    /// The Proton Pass desktop app, which is NOT a read path — it has no local API.
    /// It is only the signal that this person uses Proton Pass, and therefore that
    /// the command-line tool is worth telling them about.
    static let appBundleIDs = ["me.proton.pass.electron", "ch.protonmail.pass"]

    static var isAppInstalled: Bool {
        appBundleIDs.contains { NSWorkspace.shared.urlForApplication(withBundleIdentifier: $0) != nil }
    }

    /// Injectable for tests; the shipped value talks to the real tool.
    var channel: any ProtonPassChannel

    init(channel: any ProtonPassChannel = ProtonPassCLIChannel()) {
        self.channel = channel
    }

    /// The cheap answer as a PURE function of four file-check facts, so all four
    /// states are tested on a Mac with no `pass-cli`, no Proton Pass app and no
    /// discovery scan.
    static func availability(toolIsRunnable: Bool,
                             foundOutsideAllowList: Bool,
                             appIsInstalled: Bool,
                             sessionFileExists: Bool) -> LocalVaultAvailability {
        guard toolIsRunnable else {
            // Before saying "not installed", ASK. Discovery searches every location
            // any package manager, version manager or vendor installer uses — plus
            // `PATH`, which the execution side will never consult — so it can tell
            // "you don't have it" apart from "you have it in ~/.local/bin with the
            // wrong permissions". Only one of those is a thing to install.
            if foundOutsideAllowList { return .blocked(.toolOutsideAllowList) }
            return appIsInstalled ? .blocked(.toolMissing) : .notInstalled
        }
        // NO SESSION FILE IS A COMPLETE ANSWER, and a cheap one: the tool writes it
        // on sign-in and deletes it on sign-out, so its absence cannot mean anything
        // else. Its presence proves only that a session existed, which is why that
        // way round is `.unchecked` rather than `.ready`.
        return sessionFileExists ? .unchecked(.checkOwedOnUse) : .blocked(.notSignedIn)
    }

    /// The deep answer as a pure mapping. Each state has one fix, and each fix is a
    /// different sentence — which is exactly why the entitlement gate is its own
    /// state rather than a shade of "not signed in".
    static func availability(for state: ProtonPassSessionState) -> LocalVaultAvailability {
        switch state {
        case .ready: .ready
        case .locked: .blocked(.vaultLocked)
        case .notSignedIn: .blocked(.notSignedIn)
        case .planExcludesTool: .blocked(.planExcludesTool)
        }
    }

    func quickScan() -> LocalVaultAvailability {
        Self.availability(
            toolIsRunnable: ProtonPassCLIChannel.locate() != nil,
            foundOutsideAllowList:
                LocalVaultRegistry.toolFoundOutsideAllowList(ProtonPassCLIChannel.toolName) != nil,
            appIsInstalled: Self.isAppInstalled,
            sessionFileExists: ProtonPassSessionFile.exists())
    }

    func deepScan(quick: LocalVaultAvailability) async -> LocalVaultAvailability {
        guard quick != .notInstalled else { return .notInstalled }
        // Nothing to probe when the tool is missing, or when it is a copy the
        // allow-list declined: probing the second would mean executing exactly the
        // binary we refused to execute.
        guard quick != .blocked(.toolMissing),
              quick != .blocked(.toolOutsideAllowList) else { return quick }
        // Nor when the cheap pass already proved there is no session: a network
        // round trip cannot improve on "the session file does not exist", and this
        // keeps a signed-out Mac from making a request to Proton on every refresh.
        guard quick != .blocked(.notSignedIn) else { return quick }
        if let state = await channel.sessionState() { return Self.availability(for: state) }
        // Nothing answered. Keep what the cheap pass established rather than
        // inventing a state: "we couldn't ask" is not "you aren't signed in".
        return quick
    }

    func provider(for source: CredentialSource) -> (any CredentialProvider)? {
        guard !source.reference.trimmingCharacters(in: .whitespaces).isEmpty else { return nil }
        return ProtonPassProvider(reference: source.reference, account: source.account)
    }
}
