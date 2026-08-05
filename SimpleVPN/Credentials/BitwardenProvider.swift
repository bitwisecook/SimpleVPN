// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
//  BitwardenProvider.swift
//  Fetch a username/password (and a verification code, when the item carries a
//  seed) from Bitwarden — through Bitwarden's own tooling, and preferring the one
//  channel that lets SimpleVPN read an item without ever touching the key that
//  unlocks the vault.
//
//  TWO CHANNELS, AND THE PREFERENCE IS A SECURITY DECISION, NOT A SPEED ONE:
//
//   1. **`bw serve`** — Bitwarden's own local REST service (`127.0.0.1:8087` by
//      default, `--port`/`--hostname` configurable). The user unlocks their vault
//      once in Terminal and leaves the service running; the UNLOCK LIVES IN THAT
//      PROCESS. SimpleVPN then reads one item over loopback and never handles a
//      session key at all. It is also cheaper than starting Node for every fetch,
//      which is the same argument Keeper's Service Mode wins on — but the reason
//      it is FIRST here is the key, not the milliseconds.
//   2. **the `bw` CLI** — the fallback, and an honest one: it can tell us which
//      state the vault is in (`bw status`), but it CANNOT read an item without a
//      `BW_SESSION` key. See `BitwardenSessionSupplier` for exactly why that path
//      is dormant rather than absent.
//
//  WHY THE CLI CANNOT FETCH ON ITS OWN (verified in Bitwarden's own source, not
//  inferred): the CLI stores its unlocked user key on disk ENCRYPTED WITH THE
//  SESSION KEY (`NodeEnvSecureStorageService`, and `ServiceContainer.init` calls
//  `setUserKeyInMemoryIfAutoUserKeySet` precisely so that `BW_SESSION` from the
//  environment can decrypt it). No session key in the environment therefore means
//  `bw status` answers `locked` even for a user who is signed in and has an
//  unlocked session in their own Terminal — because that session key is theirs,
//  not ours. There is no "remember the unlock" for the CLI to consult.
//
//  BW_SESSION IS A LIVE VAULT KEY AND IS NEVER PERSISTED. When a key does exist
//  for one connect attempt it is held in a `SingleUseCode` (EphemeralCredential
//  .swift): no `Codable`, no `description`, no getter — `consume()` is the only way
//  out and it empties the box. It leaves this app exactly once, as one entry in the
//  environment dictionary handed to `LocalToolRunner.run`. Never argv (`ps` shows
//  argv to every process on the Mac, and `bw --session <key>` would put a vault key
//  there), never a log line, never an error string, never `providerConfiguration`,
//  never a defaults key, never a diagnostic bundle. Those are structural facts
//  about the type, not conventions to remember.
//
//  Non-negotiables shared with every other CLI-backed source (see LocalToolRunner):
//   • the secret arrives on stdout (or in the service's response body) and is never
//     logged, quoted in an error, or placed in argv;
//   • only the item's own name/ID rides argv;
//   • we never write Bitwarden's configuration and never mutate the vault — we
//     read, and setup stays the user's to perform (we print the commands);
//   • nothing is cached: each connect asks again, so locking the vault or stopping
//     the service takes effect immediately.
//
//  NOTHING HERE ASSUMES bitwarden.com. A self-hosted Bitwarden and a Vaultwarden
//  server both answer through the same `bw`, and the `serverUrl` a status reply
//  carries is deliberately IGNORED rather than checked — see
//  `BitwardenWire.state(_:)`.
//
//  The verification code, when the item has a TOTP field, is computed LOCALLY from
//  that field with the same RFC 6238 engine the Touch ID store uses — never a
//  second round trip for `bw get totp`, which additionally answers "Premium status
//  is required to use this feature." for accounts without it.
//  `CredentialSourceKind.bitwarden.suppliesOTP` still says false on purpose: that
//  flag is a PROMISE that Connect works with nothing typed, and this path has not
//  been proven against a live Bitwarden vault (the Keeper precedent, deliberately).
//

import Foundation
import AppKit
import os

// MARK: - An address on this Mac, and only on this Mac

/// A `host:port` for a loopback service, parsed once and refused when it is not
/// loopback.
///
/// A non-loopback endpoint is a MISCONFIGURATION TO REFUSE, not one to use.
/// `bw serve --hostname all` exists, and Bitwarden's own documentation warns that
/// it "will allow any machine on the network to make API requests" — a service with
/// no authentication of any kind. Sending an item request to a host on the network
/// would put a vault read on the wire in clear text and would let something that is
/// not Bitwarden answer it. So this type exists to make "is it loopback?" a checked
/// property rather than a habit, and the Settings pane refuses the value with a
/// sentence that explains itself.
///
/// Deliberately vendor-neutral: Keeper's Service Mode is the same shape, and the
/// next daemon-backed source should not write a third parser.
nonisolated struct LoopbackEndpoint: Sendable, Equatable {

    var host: String
    var port: Int

    /// Bitwarden's documented default for `bw serve`.
    static let bitwardenDefault = LoopbackEndpoint(host: "127.0.0.1", port: 8087)

    /// `host:port`, with `[::1]:8087` accepted for IPv6. Nothing else — a URL, a
    /// bare port or a trailing path is a different thing the user meant to type,
    /// and guessing which would be worse than saying so.
    init?(parsing raw: String) {
        let trimmed = raw.trimmingCharacters(in: .whitespaces)
        guard !trimmed.isEmpty, !trimmed.contains("/") else { return nil }
        let hostPart: String
        let portPart: String
        if trimmed.hasPrefix("[") {
            guard let close = trimmed.firstIndex(of: "]") else { return nil }
            hostPart = String(trimmed[trimmed.index(after: trimmed.startIndex)..<close])
            let rest = trimmed[trimmed.index(after: close)...]
            guard rest.hasPrefix(":") else { return nil }
            portPart = String(rest.dropFirst())
        } else {
            let parts = trimmed.split(separator: ":", omittingEmptySubsequences: false)
            guard parts.count == 2 else { return nil }
            hostPart = String(parts[0])
            portPart = String(parts[1])
        }
        guard !hostPart.isEmpty, let port = Int(portPart), (1...65535).contains(port),
              portPart.allSatisfy(\.isNumber) else { return nil }
        self.host = hostPart
        self.port = port
    }

    init(host: String, port: Int) {
        self.host = host
        self.port = port
    }

    /// Is this an address on THIS Mac? `127.0.0.0/8`, IPv6 `::1`, and the name
    /// `localhost` (which macOS resolves to those two and nothing else).
    ///
    /// `0.0.0.0` is refused: as a bind address it means "everywhere", and as a
    /// destination it is a mistake worth naming rather than quietly treating as
    /// loopback.
    var isLoopback: Bool {
        let lowered = host.lowercased()
        if lowered == "localhost" { return true }
        if lowered == "::1" || lowered == "0:0:0:0:0:0:0:1" { return true }
        let octets = lowered.split(separator: ".", omittingEmptySubsequences: false)
        guard octets.count == 4, octets.allSatisfy({ !$0.isEmpty && $0.allSatisfy(\.isNumber) }),
              let first = Int(octets[0]) else { return false }
        return first == 127
    }

    /// The base for a request, or nil when this is not an address we will talk to.
    /// Refusal is expressed as "no URL exists" so no caller can forget to check.
    var loopbackBaseURL: URL? {
        guard isLoopback else { return nil }
        let literal = host.contains(":") ? "[\(host)]" : host
        return URL(string: "http://\(literal):\(port)")
    }

    var settingValue: String { "\(host):\(port)" }
}

// MARK: - What one item gives us

/// The three things a sign-in needs, lifted out of whatever item shape Bitwarden
/// hands back, plus the two non-secret facts that make a good error message.
/// The secret halves are never logged and never described in an error.
nonisolated struct BitwardenItem: Sendable, Equatable {
    /// The item's own ID. Not a secret (it is what we tell the user to paste when
    /// several items match) but not shown unless they asked for it either.
    var id: String?
    /// The item's name. Not a secret; it is what the user typed to find it.
    var name: String?
    var username: String?
    var password: String?
    /// Bitwarden's `login.totp`: either an `otpauth://` URL or a bare base32
    /// SEED. The seed, so the code is computed locally — never a code fetched
    /// separately.
    var totpSeed: String?

    var hasPassword: Bool { !(password ?? "").isEmpty }
}

/// Which of Bitwarden's three states the vault is in. The values are Bitwarden's
/// own (`apps/cli/src/commands/status.command.ts` returns exactly these three
/// strings), so the mapping is a lookup rather than an interpretation.
nonisolated enum BitwardenVaultState: String, Sendable, Equatable, CaseIterable {
    case unauthenticated
    case locked
    case unlocked
}

// MARK: - The session key, boxed

/// A `BW_SESSION` key, held for the lifetime of ONE connect attempt.
///
/// It is a live vault key: with it, anything can read the whole vault until the
/// user locks it. So it is stored in the app's read-once primitive rather than in a
/// `String` — `SingleUseCode` has no getter, no `description` and no `Codable`, so
/// there is no API by which it can reach a log line, a defaults key,
/// `providerConfiguration` or a diagnostic bundle. `consume()` empties the box.
///
/// A SEMANTIC NOTE, because the type's name says "single use" and a session key is
/// replayable until the vault locks: what is being expressed here is the LIFECYCLE
/// we choose — one read, for one attempt, then gone — not a claim about Bitwarden's
/// own semantics. Using the shared primitive rather than a home-made box is the
/// programme's frozen decision (fifteen hand-rolled secret holders would mean
/// fifteen separate refactors of security-critical code), and the expiry is what
/// makes "it must not outlive the attempt" true even if a caller forgets.
nonisolated struct BitwardenSessionKey: Sendable {
    private let box: SingleUseCode

    /// `validFor` is the attempt's own budget, not Bitwarden's: the box empties
    /// itself when it passes, so a key that somehow outlived its attempt is
    /// already useless.
    init(_ key: String, validFor: TimeInterval = 120) {
        self.box = SingleUseCode(key, origin: .fetchedFromVault,
                                 expiresAt: Date().addingTimeInterval(validFor))
    }

    /// The ONE exit: the environment entry for a single child process. Answers nil
    /// once taken, discarded or expired, which is what makes a retry surface "get a
    /// fresh one" instead of replaying a dead key.
    func consumeAsEnvironment() -> [String: String]? {
        guard let key = box.consume() else { return nil }
        return ["BW_SESSION": key]
    }

    func discard() { box.discard() }
}

/// Where a session key for THIS attempt comes from.
///
/// The shipped implementation answers nil, and that is the honest answer rather
/// than a gap. There are exactly three ways to obtain one, and none of them is
/// available to SimpleVPN as it stands:
///
///  • keep one from a previous attempt — FORBIDDEN. It is a live vault key; the
///    rule is that it is never persisted, and "in memory until the app quits" is
///    still keeping it.
///  • ask for the user's Bitwarden master password and run `bw unlock` — NOT BUILT,
///    deliberately. Every other sentence this app writes about a password app says
///    the vendor does the unlocking and the master password never reaches
///    SimpleVPN. Asking for one here would make that false for one vendor.
///  • have the user paste a session key per connect attempt — a connect-surface
///    field, which is not this file's to add. When it exists, it supplies one of
///    these and nothing else here changes.
///
/// So `bw serve` is the fetch channel, the CLI is the state channel, and the CLI's
/// fetch path is exercised by fixture tests through this seam. A dormant path with
/// one reason and one plug is better than a rewrite the day the field lands.
nonisolated protocol BitwardenSessionSupplier: Sendable {
    func sessionKey() -> BitwardenSessionKey?
}

nonisolated struct BitwardenNoSession: BitwardenSessionSupplier {
    func sessionKey() -> BitwardenSessionKey? { nil }
}

// MARK: - The channel seam

/// How this Mac talks to Bitwarden. Two implementations ship (the local service,
/// then the CLI) behind one combined channel; tests inject a third with no
/// Bitwarden present at all.
nonisolated protocol BitwardenChannel: Sendable {
    /// Which state the vault is in, or nil when this channel cannot answer at all
    /// (nothing listening / no tool we may run). Prompt-free.
    func state() async -> BitwardenVaultState?
    /// One item, chosen by the reference and — when given — the username.
    func item(reference: String, account: String) async throws -> BitwardenItem
}

// MARK: - The provider

struct BitwardenProvider: CredentialProvider {
    let id = "bitwarden"
    let displayName = "Bitwarden"
    /// The item's ID, or a search term matched against its name, username and URLs
    /// (Bitwarden's own basic search).
    let reference: String
    /// Optional: which login to take when several items match.
    var account: String = ""
    /// Injectable so tests drive the whole resolve path with no Bitwarden anywhere.
    var channel: any BitwardenChannel = BitwardenLocalChannel()

    private static let log = Logger(subsystem: "com.bragi0.SimpleVPN", category: "bitwarden")

    func isAvailable(for profile: String) async -> Bool {
        guard !reference.trimmingCharacters(in: .whitespaces).isEmpty else { return false }
        return await channel.state() == .unlocked
    }

    func resolve(profile: String, fields: Set<CredentialField>) async throws -> RawCredentials {
        let ref = reference.trimmingCharacters(in: .whitespaces)
        guard !ref.isEmpty else { throw BitwardenError.noItem }
        let item = try await channel.item(reference: ref,
                                          account: account.trimmingCharacters(in: .whitespaces))
        guard let password = item.password, !password.isEmpty else {
            throw BitwardenError.noPassword(ref)
        }
        var raw = RawCredentials()
        let wanted = account.trimmingCharacters(in: .whitespaces)
        raw.username = (item.username?.isEmpty == false) ? item.username
                                                         : (wanted.isEmpty ? nil : wanted)
        raw.password = password
        if fields.contains(.otp), let seed = item.totpSeed,
           let totp = TOTPConfiguration(parsing: seed) {
            raw.otp = totp.code(at: Date())
        }
        Self.log.log("bitwarden item resolved for \(profile, privacy: .public)")
        return raw
    }

    /// Everything that can go wrong, in the user's words. NOTHING here interpolates
    /// a secret: the item reference and the account are the user's own labels, the
    /// count of matches is a number, and a vendor message is scrubbed and truncated
    /// before it is quoted.
    nonisolated enum BitwardenError: LocalizedError, Equatable {
        case noItem
        case notSignedIn
        case locked
        case needsSession
        case notFound(String)
        case severalMatches(Int)
        case noPassword(String)
        case wrongAccount(String)
        case endpointNotLoopback(String)
        case unreadable(String)

        var errorDescription: String? {
            switch self {
            case .noItem:
                "No Bitwarden item is set for this VPN \u{2014} add the item\u{2019}s name or its ID."
            case .notSignedIn:
                "Bitwarden isn\u{2019}t signed in on this Mac. Open Terminal and run "
                + "\u{201C}bw login\u{201D}."
            case .locked:
                "Bitwarden is locked. Open Terminal, run \u{201C}bw unlock\u{201D}, then "
                + "\u{201C}bw serve\u{201D} to leave Bitwarden\u{2019}s own local service running."
            case .needsSession:
                "Bitwarden\u{2019}s command-line tool can\u{2019}t read your vault without the key "
                + "that unlocks it, and SimpleVPN doesn\u{2019}t keep one. Run "
                + "\u{201C}bw serve\u{201D} and SimpleVPN will read your item from Bitwarden\u{2019}s "
                + "own local service instead."
            case .notFound(let ref):
                // Bitwarden's own "Not found." carries no reference, so neither
                // does the sentence in that case — a quoted empty string would
                // read as a bug.
                ref.isEmpty
                    ? "Bitwarden has no item matching what this VPN points at."
                    : "Bitwarden has no item matching \u{201C}\(ref)\u{201D}."
            case .severalMatches(let count):
                (count > 0 ? "\(count) Bitwarden items match" : "Several Bitwarden items match")
                + " \u{2014} paste the item\u{2019}s ID instead of its name, or set the username "
                + "so SimpleVPN knows which one you mean."
            case .noPassword(let ref):
                "The Bitwarden item \u{201C}\(ref)\u{201D} has no password in it."
            case .wrongAccount(let account):
                "No Bitwarden item matching this VPN has the username \u{201C}\(account)\u{201D} "
                + "\u{2014} clear the username, or point this VPN at the right item."
            case .endpointNotLoopback(let endpoint):
                "SimpleVPN only talks to Bitwarden\u{2019}s local service on this Mac, and "
                + "\u{201C}\(endpoint)\u{201D} isn\u{2019}t on this Mac. Set it to 127.0.0.1 and the "
                + "port the service is on."
            case .unreadable(let detail):
                detail.isEmpty ? "Bitwarden couldn\u{2019}t provide the sign-in."
                               : "Bitwarden couldn\u{2019}t provide the sign-in: \(detail)"
            }
        }
    }
}

// MARK: - Reading Bitwarden's answers (pure, and tolerant)

/// Bitwarden hands the same data back in two dressings, and both are read here so
/// that neither channel needs its own parser:
///
///  • **`bw serve`** replies with the CLI's own `Response` object serialised whole:
///    `{"success":true,"data":{…}}`, or `{"success":false,"message":"…"}` with HTTP
///    400 (`processResponse` in `apps/cli/src/oss-serve-configurator.ts`).
///  • **the CLI** prints the `data` half only, already unwrapped — a `template`
///    becomes its inner object, a `list` becomes its array, a `string` becomes bare
///    text (`processResponse` in `apps/cli/src/base-program.ts`) — and prints
///    failures to STDERR with exit code 1.
///
/// So every entry point accepts "enveloped or bare". That is not defensive
/// vagueness: it is two documented shapes, and a release that changes which one a
/// channel uses must not silently stop finding the password.
nonisolated enum BitwardenWire {

    /// The `data` half of a reply, or the error the reply carries.
    static func payload(_ data: Data) -> Result<Any, BitwardenProvider.BitwardenError> {
        guard let any = try? JSONSerialization.jsonObject(with: data) else {
            return .failure(.unreadable("its answer couldn\u{2019}t be read."))
        }
        guard let dict = any as? [String: Any], let success = dict["success"] as? Bool else {
            return .success(any)        // the CLI's already-unwrapped shape
        }
        guard success else {
            return .failure(error(message: dict["message"] as? String ?? ""))
        }
        return .success(dict["data"] ?? [:])
    }

    /// Bitwarden's own failure sentences, mapped to states we can act on. The
    /// strings are the vendor's (`Response.notFound()`, `Response.multipleResults`,
    /// and the two guards in `errorIfLocked`), matched loosely because the wording
    /// belongs to somebody else's release notes.
    static func error(message: String) -> BitwardenProvider.BitwardenError {
        let lowered = message.lowercased()
        if lowered.contains("not logged in") { return .notSignedIn }
        if lowered.contains("vault is locked") || lowered.contains("locked") { return .locked }
        if lowered.contains("more than one result") { return .severalMatches(0) }
        if lowered.contains("not found") { return .notFound("") }
        // A vendor message may be anything, including something a vendor decided to
        // echo, so it is scrubbed and truncated by the same function every tool's
        // stderr goes through before it may be shown.
        return .unreadable(LocalToolRunner.scrub(message))
    }

    /// The vault's state out of a `status` reply, enveloped or bare.
    ///
    /// `serverUrl` IS DELIBERATELY IGNORED. A self-hosted Bitwarden and a
    /// Vaultwarden server both answer here, and checking the URL would be a
    /// hostname allow-list for somebody else's server — it would break exactly the
    /// installations that most need this to work.
    static func state(_ any: Any) -> BitwardenVaultState? {
        guard let dict = any as? [String: Any] else { return nil }
        // `serve` wraps the status in a template object; the CLI prints the
        // template's contents directly.
        if let template = dict["template"] as? [String: Any] {
            return state(template)
        }
        guard let raw = dict["status"] as? String else { return nil }
        return BitwardenVaultState(rawValue: raw.lowercased())
    }

    /// One item out of an item reply, enveloped or bare.
    static func item(_ any: Any) -> BitwardenItem? {
        guard let dict = any as? [String: Any] else { return nil }
        var out = BitwardenItem()
        out.id = dict["id"] as? String
        out.name = dict["name"] as? String
        if let login = dict["login"] as? [String: Any] {
            out.username = nonEmpty(login["username"])
            out.password = nonEmpty(login["password"])
            out.totpSeed = nonEmpty(login["totp"]).flatMap(seed)
        }
        // An item with nothing in it at all is not an item we found.
        return (out.id != nil || out.name != nil || out.username != nil || out.password != nil)
            ? out : nil
    }

    /// Every item out of a list reply: `{"object":"list","data":[…]}` from `serve`,
    /// or the bare array the CLI prints.
    static func items(_ any: Any) -> [BitwardenItem] {
        if let array = any as? [Any] {
            return array.compactMap(item)
        }
        guard let dict = any as? [String: Any] else { return [] }
        if let nested = dict["data"] as? [Any] { return nested.compactMap(item) }
        return item(dict).map { [$0] } ?? []
    }

    private static func nonEmpty(_ value: Any?) -> String? {
        guard let text = value as? String, !text.isEmpty else { return nil }
        return text
    }

    /// Only a SEED is usable. Bitwarden's `login.totp` is documented as a base32
    /// secret (`LoginExport.template()` ships `"JBSWY3DPEHPK3PXP"`) or a full
    /// `otpauth://` URL, and both are accepted — but a bare six-to-eight digit
    /// number is a CODE, and taking one as a seed would freeze one wrong code for
    /// ever. Digits alone cannot be told apart from base32 in every case
    /// ("222222" decodes), so the shape is rejected outright.
    static func seed(_ value: String) -> String? {
        let trimmed = value.trimmingCharacters(in: .whitespacesAndNewlines)
        if trimmed.lowercased().hasPrefix("otpauth://") { return trimmed }
        let compact = trimmed.filter { !" -".contains($0) }
        if (6...8).contains(compact.count), compact.allSatisfy(\.isNumber) { return nil }
        return trimmed
    }
}

/// Choosing ONE item when a search matched several. Pure, so "several matches" and
/// "the username picks the right one" are tested without a vault.
nonisolated enum BitwardenItemPicker {

    static func pick(_ items: [BitwardenItem],
                     account: String,
                     reference: String) throws -> BitwardenItem {
        // An item with no password cannot sign anything in, so it is not a
        // candidate — that is also what stops a secure note of the same name from
        // being reported as an ambiguity.
        let usable = items.filter(\.hasPassword)
        guard !usable.isEmpty else { throw BitwardenProvider.BitwardenError.notFound(reference) }
        guard !account.isEmpty else {
            if usable.count == 1 { return usable[0] }
            throw BitwardenProvider.BitwardenError.severalMatches(usable.count)
        }
        let matching = usable.filter {
            ($0.username ?? "").caseInsensitiveCompare(account) == .orderedSame
        }
        guard let first = matching.first else {
            throw BitwardenProvider.BitwardenError.wrongAccount(account)
        }
        guard matching.count == 1 else {
            throw BitwardenProvider.BitwardenError.severalMatches(matching.count)
        }
        return first
    }
}

// MARK: - `bw serve` — Bitwarden's own local service

/// The preferred channel. The user unlocks their vault and starts the service; the
/// unlock lives in THAT process, and SimpleVPN reads one item over loopback without
/// ever holding a session key.
///
/// Two things this client does on purpose:
///
///  • **It sends no `Origin` header.** `bw serve` blocks requests that carry one
///    unless it was started with `--disable-origin-protection`, which Bitwarden's
///    documentation says is "not recommended". A plain `URLSession` GET adds none,
///    and nothing here adds one either.
///  • **It insists the thing answering looks like Bitwarden.** Port 8087 on
///    loopback is not reserved to anybody; some other program may be listening
///    there. So the status probe requires a recognisable Bitwarden status reply
///    before any item request is made — otherwise a request for a vault item would
///    be sent to a stranger.
///
/// The service has NO authentication of any kind: while it is running, any program
/// on this Mac can ask it for items. That is Bitwarden's design decision, not ours,
/// and the enablement copy says so rather than quietly relying on it.
nonisolated struct BitwardenServeClient: Sendable {

    var endpoint: LoopbackEndpoint
    /// Injected so every response shape — locked, not signed in, not found, several
    /// matches, a stranger on the port, nothing listening — is driven by a fixture
    /// on a Mac with no Bitwarden at all.
    var fetch: @Sendable (URL) async -> (status: Int, body: Data)?

    init(endpoint: LoopbackEndpoint = .bitwardenDefault,
         fetch: @escaping @Sendable (URL) async -> (status: Int, body: Data)? = BitwardenServeClient.liveFetch) {
        self.endpoint = endpoint
        self.fetch = fetch
    }

    static let liveFetch: @Sendable (URL) async -> (status: Int, body: Data)? = { url in
        var request = URLRequest(url: url, timeoutInterval: 10)
        request.httpMethod = "GET"
        request.setValue("application/json", forHTTPHeaderField: "Accept")
        // Ephemeral: nothing about a secret-bearing response belongs in a cache,
        // and no cookie of ours belongs on a local service.
        let session = URLSession(configuration: .ephemeral)
        guard let (data, response) = try? await session.data(for: request),
              let http = response as? HTTPURLResponse else { return nil }
        return (http.statusCode, data)
    }

    /// `GET /status`, which the service answers whether or not the vault is
    /// unlocked (it is one of the few routes with no lock guard). nil means nothing
    /// recognisable is there.
    func state() async -> BitwardenVaultState? {
        guard let base = endpoint.loopbackBaseURL else { return nil }
        guard let (_, body) = await fetch(base.appendingPathComponent("status")) else { return nil }
        guard case .success(let payload) = BitwardenWire.payload(body) else { return nil }
        return BitwardenWire.state(payload)
    }

    /// One item. An ID goes straight to `GET /object/item/<id>`; anything else is a
    /// search, because `GET /list/object/items?search=…` both encodes safely and
    /// lets US disambiguate by username — which `get item` cannot do, since it
    /// simply fails when a term matches more than one thing.
    func item(reference: String, account: String) async throws -> BitwardenItem {
        guard let base = endpoint.loopbackBaseURL else {
            throw BitwardenProvider.BitwardenError.endpointNotLoopback(endpoint.settingValue)
        }
        if isItemID(reference) {
            let payload = try await get(path: "object/item/\(reference)", base: base)
            guard let item = BitwardenWire.item(payload) else {
                throw BitwardenProvider.BitwardenError.notFound(reference)
            }
            return try BitwardenItemPicker.pick([item], account: account, reference: reference)
        }
        var components = URLComponents(url: base.appendingPathComponent("list/object/items"),
                                       resolvingAgainstBaseURL: false)
        components?.queryItems = [URLQueryItem(name: "search", value: reference)]
        guard let url = components?.url else {
            throw BitwardenProvider.BitwardenError.notFound(reference)
        }
        let payload = try await get(url: url)
        return try BitwardenItemPicker.pick(BitwardenWire.items(payload),
                                            account: account, reference: reference)
    }

    private func get(path: String, base: URL) async throws -> Any {
        try await get(url: base.appendingPathComponent(path))
    }

    private func get(url: URL) async throws -> Any {
        guard let (_, body) = await fetch(url) else {
            throw BitwardenProvider.BitwardenError.unreadable(
                "Bitwarden\u{2019}s local service didn\u{2019}t answer.")
        }
        // The status code is not the authority: `serve` answers 400 WITH a JSON
        // body that says which failure it was, and that body is the useful thing.
        switch BitwardenWire.payload(body) {
        case .success(let payload): return payload
        case .failure(let error): throw error
        }
    }

    /// Bitwarden's item IDs are GUIDs, and `getCipherView` treats a GUID as an
    /// exact ID and anything else as a search term. Recognising the same shape here
    /// keeps the two channels asking the same question.
    static func looksLikeItemID(_ reference: String) -> Bool {
        let parts = reference.split(separator: "-", omittingEmptySubsequences: false)
        guard parts.count == 5,
              parts.map(\.count) == [8, 4, 4, 4, 12] else { return false }
        return parts.allSatisfy { $0.allSatisfy(\.isHexDigit) }
    }

    private func isItemID(_ reference: String) -> Bool { Self.looksLikeItemID(reference) }
}

// MARK: - The `bw` CLI

/// The fallback channel: it answers which state the vault is in, and it can fetch
/// only when a session key exists for this attempt (see `BitwardenSessionSupplier`
/// for why that is normally nil).
nonisolated struct BitwardenCLIClient: Sendable {

    /// Injected so the whole CLI path — every state, every failure, and the
    /// assertion that no argument ever carries the session key — is driven by
    /// fixtures with no `bw` installed.
    var run: @Sendable (_ arguments: [String], _ environment: [String: String]) async -> LocalToolResult
    var sessions: any BitwardenSessionSupplier

    init(sessions: any BitwardenSessionSupplier = BitwardenNoSession(),
         run: (@Sendable (_ arguments: [String], _ environment: [String: String]) async -> LocalToolResult)? = nil) {
        self.sessions = sessions
        self.run = run ?? BitwardenCLIClient.liveRun
    }

    /// Where `bw` is, if anywhere. Resolved against `LocalToolRunner`'s allow-list
    /// — never `PATH`, and never a second copy of those rules. `bw` arrives by npm,
    /// by Homebrew or as a standalone zip, so it lands in many places; the ones we
    /// will RUN from are the runner's, and `signin.tool.bw.path` is the one
    /// sanctioned way to name another.
    static func locate() -> String? { LocalToolRunner.locate("bw") }

    static let liveRun: @Sendable ([String], [String: String]) async -> LocalToolResult = { arguments, environment in
        guard let executable = locate() else {
            return LocalToolResult(exitCode: -1, stdout: Data(),
                                   stderr: "not an approved tool location", timedOut: false)
        }
        return await LocalToolRunner.run(executable: executable, arguments: arguments,
                                         deadline: 25, environment: environment)
    }

    /// `bw status`, which exits 0 in all three states and prints the state on
    /// stdout. nil means the tool could not answer at all.
    ///
    /// Without a session key this can only ever say `locked` or `unauthenticated`
    /// — see this file's header. A key IS passed when one exists, so a supplied
    /// session can legitimately report `unlocked`.
    func state() async -> BitwardenVaultState? {
        let session = sessions.sessionKey()
        defer { session?.discard() }
        let result = await run(["status", "--nointeraction"], environment(with: session))
        guard result.succeeded else { return nil }
        guard case .success(let payload) = BitwardenWire.payload(result.stdout) else { return nil }
        return BitwardenWire.state(payload)
    }

    func item(reference: String, account: String) async throws -> BitwardenItem {
        guard let session = sessions.sessionKey() else {
            throw BitwardenProvider.BitwardenError.needsSession
        }
        defer { session.discard() }
        // ONLY the item's own name or ID rides argv. The session key goes in the
        // environment; `bw --session <key>` exists and is deliberately not used,
        // because argv is readable by every process on this Mac.
        let arguments = BitwardenServeClient.looksLikeItemID(reference)
            ? ["get", "item", reference, "--nointeraction"]
            : ["list", "items", "--search", reference, "--nointeraction"]
        let result = await run(arguments, environment(with: session))
        if result.timedOut {
            throw BitwardenProvider.BitwardenError.unreadable(
                "Bitwarden didn\u{2019}t answer in time.")
        }
        guard result.succeeded else {
            // stderr only, already scrubbed by the runner. stdout may hold an item.
            throw BitwardenWire.error(message: result.stderr)
        }
        switch BitwardenWire.payload(result.stdout) {
        case .failure(let error):
            throw error
        case .success(let payload):
            let items = BitwardenServeClient.looksLikeItemID(reference)
                ? [BitwardenWire.item(payload)].compactMap { $0 }
                : BitwardenWire.items(payload)
            return try BitwardenItemPicker.pick(items, account: account, reference: reference)
        }
    }

    /// The child's environment: the runner's own built-from-scratch set, plus the
    /// session key when there is one. Nothing is inherited (see
    /// `LocalToolRunner.childEnvironment`), and this dictionary is a local value
    /// that is never logged.
    private func environment(with session: BitwardenSessionKey?) -> [String: String] {
        var environment = LocalToolRunner.childEnvironment()
        if let entry = session?.consumeAsEnvironment() {
            environment.merge(entry) { _, new in new }
        }
        return environment
    }
}

// MARK: - The combined channel: the service, then the tool

/// What ships. The preference is stated once, here, and it is the service first
/// for the reason in this file's header: it is the only channel that reads an item
/// without SimpleVPN handling the key that unlocks the vault.
nonisolated struct BitwardenLocalChannel: BitwardenChannel {

    private static let log = Logger(subsystem: "com.bragi0.SimpleVPN", category: "bitwarden")

    /// Injected by tests. nil means "build one from the CURRENT setting on every
    /// call", which is deliberate: the endpoint is a live setting, and this channel
    /// is held by a registry that is constructed once per launch. Capturing the
    /// address at construction would mean a user who changes the port has to restart
    /// the app to be believed.
    private let injectedServe: BitwardenServeClient?
    var cli: BitwardenCLIClient

    var serve: BitwardenServeClient {
        injectedServe ?? BitwardenServeClient(endpoint: BitwardenSettings.configuredEndpoint())
    }

    init(serve: BitwardenServeClient? = nil, cli: BitwardenCLIClient = BitwardenCLIClient()) {
        self.injectedServe = serve
        self.cli = cli
    }

    func state() async -> BitwardenVaultState? {
        if let state = await serve.state() { return state }
        return await cli.state()
    }

    func item(reference: String, account: String) async throws -> BitwardenItem {
        // The service answers ⇒ use it, and do not fall back on a FETCH failure:
        // "no such item" and "several match" are answers, not channel problems, and
        // retrying them through the CLI would only turn a good message into
        // "Bitwarden can't read your vault without the key that unlocks it".
        if await serve.state() != nil {
            return try await serve.item(reference: reference, account: account)
        }
        Self.log.log("bitwarden local service isn\u{2019}t there; trying the command-line tool")
        return try await cli.item(reference: reference, account: account)
    }
}

// MARK: - Where the endpoint setting lives

/// The one place the daemon endpoint is read.
///
/// `UserDefaults` directly, and nonisolated, for the same reason
/// `LocalToolRunner.userConfiguredPath` does it: this is read from the connect path,
/// which is not the main actor, and a managed (MDM-forced) preference wins in the
/// defaults search order for free — so an administrator pinning the endpoint is
/// honoured here without a second mechanism.
nonisolated enum BitwardenSettings {

    /// `defaults write com.bragi0.SimpleVPN signin.bitwarden.endpoint 127.0.0.1:8087`
    /// — and the row in Settings ▸ Sign-In Sources writes the same key.
    static let endpointKey = "signin.bitwarden.endpoint"

    /// What SimpleVPN will actually talk to: the user's setting when it parses and
    /// is loopback, else Bitwarden's own documented default.
    ///
    /// A non-loopback setting falls back to the default rather than being used, and
    /// the Settings row says so in words (`VendorFieldValidation.notLoopback`) — a
    /// vault read must not leave this Mac because a field was typed wrongly.
    static func configuredEndpoint(store: UserDefaults = .standard) -> LoopbackEndpoint {
        guard let raw = store.string(forKey: endpointKey),
              let endpoint = LoopbackEndpoint(parsing: raw), endpoint.isLoopback
        else { return .bitwardenDefault }
        return endpoint
    }
}

// MARK: - The adapter

/// Bitwarden's row in the sign-in chooser. Four states, and the middle two are the
/// reason the enablement banner exists:
///   1. Bitwarden's local service answering, unlocked → a source SimpleVPN fetches
///      from.
///   2. Signed in but locked → offered, with the unlock-and-serve commands.
///   3. `bw` here, nobody signed in → offered, with the sign-in commands.
///      Or: `bw` demonstrably installed somewhere we will not run from → offered,
///      with the path to paste. Or: the Bitwarden APP here but no `bw` → offered,
///      with the install command. SimpleVPN never installs it.
///   4. Nothing Bitwarden on this Mac → not offered at all.
///
/// `quickScan` does file checks only. Which state the vault is in needs either a
/// loopback request or a `bw status`, and both are the deep scan.
///
/// It lives in this file rather than in `LocalVaultAdapters.swift` on purpose: one
/// vendor is one file plus a one-line registry entry, so several vendors landing at
/// once do not collide in the same switch.
struct BitwardenVaultAdapter: LocalVaultAdapter {
    let vendor = LocalVaultVendor.bitwarden
    let storedKind = CredentialSourceKind.bitwarden
    /// Its own local service when the user has one running, else its CLI. The order
    /// is the preference, and here it is a security preference rather than a speed
    /// one — see BitwardenProvider's header.
    let transports: [LocalVaultTransport] = [.localDaemon, .cli]

    /// The Bitwarden desktop app, which is NOT a read path — it is only the signal
    /// that this person uses Bitwarden, and therefore that `bw` is worth telling
    /// them about.
    static let appBundleIDs = ["com.bitwarden.desktop"]

    static var isAppInstalled: Bool {
        appBundleIDs.contains { NSWorkspace.shared.urlForApplication(withBundleIdentifier: $0) != nil }
    }

    /// Injectable for tests; the shipped value talks to the real service and tool.
    var channel: any BitwardenChannel = BitwardenLocalChannel()

    /// The cheap answer as a PURE function of three file-check facts, so all four
    /// states are tested on a Mac with no `bw`, no Bitwarden app and no discovery
    /// scan. `quickScan()` only gathers.
    static func availability(toolIsRunnable: Bool,
                             foundOutsideAllowList: Bool,
                             appIsInstalled: Bool) -> LocalVaultAvailability {
        if toolIsRunnable { return .unchecked }
        // Before saying "not installed", ASK. Discovery searches every location any
        // package manager, version manager or vendor installer uses — plus `PATH`,
        // which the execution side will never consult — so it can tell "you don't
        // have `bw`" apart from "you have `bw` in ~/.bun/bin". Only one of those is
        // a thing to install.
        if foundOutsideAllowList { return .blocked(.toolOutsideAllowList) }
        return appIsInstalled ? .blocked(.toolMissing) : .notInstalled
    }

    /// The deep answer as a pure mapping. Each of Bitwarden's three states has one
    /// fix, and each fix is a different command — which is why `locked` is its own
    /// block rather than being folded into "not signed in".
    static func availability(for state: BitwardenVaultState) -> LocalVaultAvailability {
        switch state {
        case .unlocked: .ready
        case .locked: .blocked(.vaultLocked)
        case .unauthenticated: .blocked(.notSignedIn)
        }
    }

    func quickScan() -> LocalVaultAvailability {
        Self.availability(
            toolIsRunnable: BitwardenCLIClient.locate() != nil,
            foundOutsideAllowList: LocalVaultRegistry.toolFoundOutsideAllowList("bw") != nil,
            appIsInstalled: Self.isAppInstalled)
    }

    func deepScan(quick: LocalVaultAvailability) async -> LocalVaultAvailability {
        guard quick != .notInstalled else { return .notInstalled }
        // The service first, and it is asked EVEN WHEN we would decline to run the
        // tool: an HTTP request to a loopback port executes nothing, so a running
        // service is a complete answer regardless of where `bw` happens to live.
        // The tool half of the same call needs no guard for that case either —
        // `BitwardenCLIClient.liveRun` resolves through `LocalToolRunner.locate`,
        // which answers nil for a binary the allow-list declines, so nothing is
        // spawned rather than something being spawned and then refused.
        if let state = await channel.state() { return Self.availability(for: state) }
        // Nothing answered. Keep whatever the cheap pass established rather than
        // inventing a state: "we couldn't ask" is not "you aren't signed in".
        return quick
    }

    func provider(for source: CredentialSource) -> (any CredentialProvider)? {
        guard !source.reference.trimmingCharacters(in: .whitespaces).isEmpty else { return nil }
        return BitwardenProvider(reference: source.reference, account: source.account)
    }
}
