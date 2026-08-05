// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
//  PassboltServer.swift
//  Reading one sign-in out of a Passbolt SERVER, through Passbolt's own
//  `go-passbolt-cli`.
//
//  THE FIRST SOURCE WHOSE INSTANCE IS NOT A FILE. Every multi-instance vendor
//  before this one was a thing on disk — a `.kdbx`, a `pass` store. A Passbolt
//  instance is a SERVER: an https address, plus that server's own sign-in
//  configuration (which OpenPGP key, and how its passphrase is supplied). The
//  three-level model (SignInSourceInstances.swift) takes that without a change:
//  level 1 is where the `passbolt` binary is, level 2 is one server, level 3 is
//  which resource inside it. What DOES differ is that a level-2 answer here can
//  never be settled by a `stat`, and that is stated rather than papered over —
//  see `deepScan`.
//
//  WHERE THE PASSPHRASE LIVES, AND WHICH ROUTE IT TRAVELS
//
//  A Passbolt sign-in is OpenPGP: a server address, an armoured private key, and
//  that key's passphrase. `go-passbolt-cli` accepts all three from its own config
//  file, from flags, or from environment variables (`internal/cmd/root.go`).
//  SimpleVPN uses ONE delivery route and refuses the other two outright:
//
//   • STDIN — yes, and only this. `util.ReadPassword` in
//     `internal/util/client.go` reads a line from stdin whenever stdin is not a
//     terminal, so `LocalToolRunner`'s `stdin:` channel is a supported, documented
//     way in. THIS IS WHERE A PASSPHRASE SIMPLEVPN HOLDS TRAVELS, and where it
//     travels is decided in one place (`PassboltCLI.run`).
//   • `--userPassword` ON ARGV — never. Arguments are world-readable through
//     `ps`, so a passphrase there is a passphrase published to every process on
//     the Mac.
//   • THE ENVIRONMENT VARIABLE — never, and it is worth being precise about why
//     twice over. viper is initialised with `AutomaticEnv()` and NO prefix and NO
//     key replacer, so the variable the tool reads is the bare, un-namespaced
//     `USERPASSWORD`. That is the route somebody automating this in a script would
//     reach for, and it is the wrong shape for a laptop: `LocalToolRunner` builds
//     the child environment from scratch and inherits nothing, so SimpleVPN could
//     not deliver it even if it wanted to — which also means a `USERPASSWORD`
//     exported in somebody's shell profile will NOT make a fetch from SimpleVPN
//     work. The copy says so, because otherwise it looks like a bug in this app.
//
//  WHO HOLDS IT is a separate question from how it travels, and it is answered in
//  PassboltUnlock.swift: nowhere by default, the Touch ID keychain by opt-in, and
//  Passbolt's own config file honoured-but-not-recommended when it already has one.
//  The short version of why: a passphrase at rest in a plaintext config file is what
//  an operator provisions for an unattended job, and this is a VPN client on
//  somebody's laptop. A Touch ID sheet, or one passphrase typed per app run, is the
//  affordance a person recognises.
//
//  AND IF NOTHING HAS ONE, THE SOURCE IS VISIBLY DORMANT. Nothing is spawned: a
//  sign-in that is going to ask for input we cannot give is still an authentication
//  attempt against somebody's server. Even if one were spawned, stdin would be
//  `/dev/null` and the tool would hit EOF and fail at once rather than wait for
//  input that can never arrive — the same bounded-failure shape as
//  `--pinentry-mode error` in the `pass` reader.
//
//  CERTIFICATE VERIFICATION IS NOT NEGOTIABLE. The tool has a `--tlsSkipVerify`
//  flag ("Allow servers with self-signed certificates", `internal/cmd/root.go`).
//  SimpleVPN never passes it and offers no setting that could. Self-hosting is
//  the norm for Passbolt, so the pressure to add that toggle is real — and a
//  toggle like it, once present, ends up switched on across an estate. The
//  supported answer for a private CA is to trust the CA on this Mac, which fixes
//  it for every program at once. A test asserts the flag is never emitted.
//
//  READ-ONLY, BY CONSTRUCTION. The only subcommands this file can emit are
//  `get resource` and `list resource`. `create`, `update`, `delete`, `share`,
//  `move` and `verify` are never built — `verify` included, because it WRITES the
//  tool's config file, and writing another program's configuration is not
//  SimpleVPN's business (LocalToolRunner's header states the rule; Keeper's
//  documentation is where it was learned).
//

import Foundation

// MARK: - Level 2: one server

/// One configured Passbolt SERVER. LEVEL 2 in the three-level model: the address
/// is *which* Passbolt, not *how* we reach Passbolt at all, and one person
/// legitimately has a company server and a community one.
///
/// Holds an address and a file path. No key, no passphrase, no token — those are
/// the tool's, in the tool's own file.
nonisolated struct PassboltServerLocation: Sendable, Equatable {
    /// The server's address, `https://passbolt.example.com`. Empty means nothing
    /// has been set up yet, which is an enablement state and not a failure.
    var serverURL: String = ""
    /// The tool's config file for THIS server, or nil for the tool's own default
    /// one. A per-server file is what makes two servers possible at all: the
    /// default config holds exactly one `serverAddress`, one key and one
    /// passphrase, so a second server needs a second file (`--config`).
    var configFile: String?

    /// Where `go-passbolt-cli` keeps its own config with no `--config` given.
    /// From `initConfig` in `internal/cmd/root.go`: `os.UserConfigDir()` +
    /// `go-passbolt-cli`, config type `toml`, config name `go-passbolt-cli`. On
    /// macOS `os.UserConfigDir()` is `$HOME/Library/Application Support`, and
    /// `HOME` is one of the few variables `LocalToolRunner` passes through, so
    /// the tool and this function look in the same place.
    static func defaultConfigFile(
        home: URL = FileManager.default.homeDirectoryForCurrentUser
    ) -> String {
        home.appendingPathComponent(
            "Library/Application Support/go-passbolt-cli/go-passbolt-cli.toml").path
    }

    /// The config file this server actually uses.
    func effectiveConfigFile(
        home: URL = FileManager.default.homeDirectoryForCurrentUser
    ) -> String {
        if let configFile, !configFile.isEmpty { return configFile }
        return Self.defaultConfigFile(home: home)
    }

    /// Whether the address is one SimpleVPN will talk to. `https` only, and that
    /// is a deliberate refusal rather than an oversight: a Passbolt sign-in is an
    /// OpenPGP challenge and a session cookie, and putting either on a plain
    /// connection is not something to offer a switch for. It also refuses a URL
    /// with a query, a fragment or credentials in it — none of those mean
    /// anything to the tool, and userinfo in a URL is a secret in a setting.
    var isUsableAddress: Bool {
        Self.validate(serverURL) == nil
    }

    /// Why an address is unusable, in one clause, or nil when it is fine. A
    /// clause rather than a Bool so the settings row can say which of the four
    /// things is wrong.
    static func validate(_ raw: String) -> String? {
        let trimmed = raw.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else { return "there is no address yet" }
        guard let url = URL(string: trimmed), let scheme = url.scheme?.lowercased(),
              let host = url.host, !host.isEmpty else {
            return "that is not a web address"
        }
        guard scheme == "https" else {
            return "SimpleVPN only talks to a Passbolt server over https"
        }
        guard url.user == nil, url.password == nil else {
            return "take the name and password out of the address"
        }
        guard url.query == nil, url.fragment == nil else {
            return "leave off anything after the address itself"
        }
        return nil
    }
}

// MARK: - What the tool's own config says, WITHOUT reading what it holds

/// WHICH KEYS are set in `go-passbolt-cli`'s own config file — never their
/// values.
///
/// This is the cheap probe, and the reason it can exist at all: "the tool has no
/// key configured", "the tool has a key but no passphrase" and "the tool is set
/// up" are three different states with three different fixes, and none of them
/// can be told apart from the file's existence alone.
///
/// THE VALUES ARE NEVER CAPTURED. The scanner walks the file a line at a time,
/// keeps the text BEFORE the first `=` and discards the rest inside the loop.
/// Nothing that could be a private key or a passphrase is ever stored in a
/// property, returned to a caller, logged, or put in a diagnostic — a report
/// says whether a key is present, and that is a Boolean.
nonisolated struct PassboltToolConfig: Sendable, Equatable {
    var path: String
    var exists: Bool = false
    /// The key NAMES present, lower-cased. viper lower-cases every key it
    /// writes; lower-casing here also covers a file somebody hand-edited.
    var keys: Set<String> = []
    /// The file holds an OpenPGP private key and possibly its passphrase, and
    /// another account on this Mac can read it. viper creates it 0600 and
    /// re-chmods it 0600 on every run, so this means somebody widened it by
    /// hand — worth one sentence, and not a reason to refuse.
    var isReadableByOthers = false

    var hasServerAddress: Bool { keys.contains("serveraddress") }
    var hasPrivateKey: Bool { keys.contains("userprivatekey") }
    /// The tool has a passphrase of its own, so a fetch needs nothing typed.
    var hasPassphrase: Bool { keys.contains("userpassword") }
    /// `passbolt verify` has been run against this server, so the tool checks the
    /// server's OWN OpenPGP identity on every login as well as its certificate.
    /// Not required, and not something SimpleVPN can set up — `verify` writes the
    /// config file, which SimpleVPN does not do.
    var pinsServerIdentity: Bool { keys.contains("serververifytoken") }
}

nonisolated enum PassboltToolConfigProbe {

    /// Read one config file and report only its key names. A file read and a
    /// `stat`; never an execution, so it is safe on the cheap availability path.
    static func read(path: String,
                     fileManager: FileManager = .default) -> PassboltToolConfig {
        var out = PassboltToolConfig(path: path)
        var st = stat()
        guard stat(path, &st) == 0, (st.st_mode & S_IFMT) == S_IFREG else { return out }
        out.exists = true
        out.isReadableByOthers = (st.st_mode & (S_IRGRP | S_IROTH)) != 0
        guard let text = try? String(contentsOfFile: path, encoding: .utf8) else {
            // Present but unreadable: the honest answer is "it is there", with no
            // claim about what is in it. macOS protects some folders from every
            // app, and a config in one of those is a permission to grant rather
            // than a file to fix.
            return out
        }
        out.keys = keyNames(in: text)
        return out
    }

    /// The key names in a TOML document. Deliberately tolerant and deliberately
    /// dumb: this is not a TOML parser, it is a "which of four keys is present"
    /// question, and a real parser would have to hold every value in memory to
    /// answer it.
    static func keyNames(in text: String) -> Set<String> {
        var out: Set<String> = []
        for line in text.split(whereSeparator: \.isNewline) {
            let trimmed = line.trimmingCharacters(in: .whitespaces)
            guard !trimmed.isEmpty, !trimmed.hasPrefix("#"), !trimmed.hasPrefix("[") else { continue }
            guard let equals = trimmed.firstIndex(of: "=") else { continue }
            var key = String(trimmed[trimmed.startIndex..<equals])
                .trimmingCharacters(in: .whitespaces)
            // A quoted key is legal TOML.
            if key.count >= 2, key.hasPrefix("\""), key.hasSuffix("\"") {
                key = String(key.dropFirst().dropLast())
            }
            // An armoured key's base64 padding also contains `=`, so a
            // continuation line could otherwise look like a key. A TOML bare key
            // is letters, digits, `_` and `-`, and nothing here is long.
            guard !key.isEmpty, key.count <= 64,
                  key.allSatisfy({ $0.isLetter || $0.isNumber || $0 == "_" || $0 == "-" || $0 == "." })
            else { continue }
            out.insert(key.lowercased())
            // The value is now out of scope. It is never assigned anywhere.
        }
        return out
    }
}

// MARK: - Addressing one resource

/// HOW a VPN names the resource it reads. Two shapes, and the trade-off between
/// them is the same one the `.kdbx` source spells out for entry paths, so the
/// copy spells it out here too:
///
///  • an `id` is Passbolt's own UUID. STABLE: renaming the resource, moving it
///    between folders or sharing it differently does not change it. Unreadable,
///    and you have to go and get it once.
///  • a `name` is what you see in Passbolt. Readable, and it is what somebody
///    will type — but it is not unique, so it can match several resources, and it
///    changes the moment anybody renames one.
///
/// Neither is secret. A UUID identifies a row; it does not open it.
nonisolated enum PassboltResourceReference: Sendable, Equatable {
    case id(String)
    case name(String)

    /// A reference is a UUID when it looks exactly like one, and a name
    /// otherwise. Deliberately shape-based rather than a user-visible switch:
    /// pasting a UUID should just work, and nobody names a resource with 36
    /// characters of hex.
    static func parse(_ raw: String) -> PassboltResourceReference? {
        let trimmed = raw.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else { return nil }
        return looksLikeUUID(trimmed) ? .id(trimmed) : .name(trimmed)
    }

    /// 8-4-4-4-12 hex. Not `UUID(uuidString:)`, which also accepts a braced form
    /// and would then be handed to the server as an id it does not recognise.
    static func looksLikeUUID(_ raw: String) -> Bool {
        let groups = raw.split(separator: "-", omittingEmptySubsequences: false)
        guard groups.count == 5 else { return false }
        let lengths = [8, 4, 4, 4, 12]
        for (group, want) in zip(groups, lengths) {
            guard group.count == want, group.allSatisfy(\.isHexDigit) else { return false }
        }
        return true
    }

    var isUUID: Bool { if case .id = self { true } else { false } }
    /// What the user typed, for a message. Never a secret: a resource's name and
    /// its id are both metadata.
    var display: String {
        switch self {
        case .id(let value), .name(let value): value
        }
    }
}

// MARK: - What comes back

/// One resource, as `passbolt get resource --id … --json` prints it. Field names
/// from `ResourceJSONOutput` in `internal/cmd/resource/json.go`.
nonisolated struct PassboltResource: Sendable, Equatable {
    var id: String?
    var name: String = ""
    var username: String?
    var uri: String?
    /// SECRET. Decoded from the tool's stdout and never logged, never quoted in
    /// an error, never in a diagnostic.
    var password: String?
    /// A TOTP secret, when the resource is one of Passbolt's TOTP types. From
    /// `secret.totp.secret_key` plus its algorithm, digits and period — the shape
    /// `internal/testdata/14_totp_resource.txtar` round-trips.
    var totp: TOTPConfiguration?

    /// Parse the `--json` object. Tolerant: an unknown key is ignored, and a
    /// missing one is nil rather than an error, because the tool's output grows
    /// with Passbolt's resource types (v4 and v5 differ) and a strict decode
    /// would throw away a perfectly good password over a new field.
    static func parse(_ data: Data) throws -> PassboltResource {
        guard let object = try? JSONSerialization.jsonObject(with: data),
              let dict = object as? [String: Any] else {
            throw PassboltError.unreadableOutput
        }
        return parse(dict)
    }

    static func parse(_ dict: [String: Any]) -> PassboltResource {
        var out = PassboltResource()
        out.id = string(dict["id"])
        out.name = string(dict["name"]) ?? ""
        out.username = string(dict["username"])
        out.uri = string(dict["uri"])
        out.password = string(dict["password"])
        // v5 resources put the same values in `metadata`, and a caller asking for
        // only some columns gets only those — so fall back to the maps rather
        // than reporting a resource with no username when one is right there.
        if let metadata = dict["metadata"] as? [String: Any] {
            if out.name.isEmpty { out.name = string(metadata["name"]) ?? "" }
            if out.username == nil { out.username = string(metadata["username"]) }
            if out.uri == nil { out.uri = string(metadata["uri"]) }
        }
        if let secret = dict["secret"] as? [String: Any] {
            if out.password == nil { out.password = string(secret["password"]) }
            if let totp = secret["totp"] as? [String: Any] {
                out.totp = parseTOTP(totp)
            }
        }
        return out
    }

    /// Passbolt's TOTP secret object. Built into the app's own RFC 6238
    /// configuration rather than asking the tool for a code: there is no command
    /// that prints one, and the seed is already in hand.
    static func parseTOTP(_ dict: [String: Any]) -> TOTPConfiguration? {
        guard let seed = string(dict["secret_key"]), !seed.isEmpty,
              var config = TOTPConfiguration(parsing: seed) else { return nil }
        if let raw = string(dict["algorithm"]),
           let algorithm = TOTPAlgorithm(rawValue: raw.uppercased()) {
            config.algorithm = algorithm
        }
        if let digits = integer(dict["digits"]), (6...8).contains(digits) {
            config.digits = digits
        }
        if let period = integer(dict["period"]), period > 0 { config.period = period }
        return config
    }

    private static func string(_ any: Any?) -> String? {
        guard let value = any as? String, !value.isEmpty else { return nil }
        return value
    }
    private static func integer(_ any: Any?) -> Int? {
        if let value = any as? Int { return value }
        if let value = any as? Double { return Int(value) }
        if let value = any as? String { return Int(value) }
        return nil
    }
}

/// One row of `passbolt list resource --json`: enough to choose between matches
/// and nothing more. NO PASSWORD — the listing deliberately asks for columns
/// that need no secret, so the server never joins the secrets in and nothing
/// secret-bearing is decrypted to answer "which one did you mean".
nonisolated struct PassboltResourceSummary: Sendable, Equatable, Identifiable {
    var id: String
    var name: String
    var username: String?
    var uri: String?

    static func parseList(_ data: Data) throws -> [PassboltResourceSummary] {
        guard let object = try? JSONSerialization.jsonObject(with: data) else {
            throw PassboltError.unreadableOutput
        }
        // A single object is accepted as a one-row list: the tool prints an array
        // for `list` and an object for `get`, and being strict about which buys
        // nothing.
        let rows: [[String: Any]]
        if let array = object as? [[String: Any]] {
            rows = array
        } else if let dict = object as? [String: Any] {
            rows = [dict]
        } else {
            throw PassboltError.unreadableOutput
        }
        return rows.compactMap { row in
            let resource = PassboltResource.parse(row)
            guard let id = resource.id, !id.isEmpty else { return nil }
            return PassboltResourceSummary(id: id, name: resource.name,
                                           username: resource.username, uri: resource.uri)
        }
    }
}

// MARK: - Failures, decomposed

/// Every distinct way a Passbolt fetch does not work. Separate cases because
/// each one has a different fix and a different owner, and because a flat
/// "couldn't sign in" is what sends somebody to retype a passphrase that was
/// never the problem.
nonisolated enum PassboltError: LocalizedError, Equatable {
    /// Level 1: the tool is not installed anywhere SimpleVPN will run it from.
    case toolMissing
    /// Level 2: no server has been set up, or its address is unusable.
    case noServerConfigured(String)
    /// Level 2: the tool has no configuration for this server at all.
    case toolNotConfigured(String)
    /// Level 2: something has to unlock the key and nothing can — SimpleVPN holds no
    /// passphrase for this server and Passbolt's own program has none either. THE
    /// DORMANT STATE, and it is a state with a fix rather than a failure.
    case passphraseUnavailable
    /// The user cancelled the Touch ID sheet. NOT a wrong passphrase, and kept
    /// separate for a concrete reason: treating a cancel as a rejected sign-in would
    /// spend somebody's server-side lockout budget on a decision they made.
    case cancelled
    /// A passphrase with a line break in it cannot reach the tool at all — it reads
    /// exactly one line. Named up front so the message is the real problem rather
    /// than "your server wouldn't accept that".
    case passphraseContainsNewline
    /// The server rejected the key or the passphrase (401).
    case signInRejected
    /// The account needs a verification code. SimpleVPN passes `--mfaMode none`,
    /// so this is reported rather than answered — answering would mean holding the
    /// second factor's seed beside the first factor, which is not a second factor.
    case verificationCodeRequired
    /// Nothing answered at that address.
    case serverUnreachable(String)
    /// The certificate did not verify. NEVER worked around.
    case certificateNotTrusted(String)
    /// Passbolt's own server-identity check (`passbolt verify`) failed. Distinct
    /// from a certificate problem: this one says the server is not the Passbolt
    /// it was, which is a much louder thing.
    case serverIdentityChanged
    case resourceNotFound(String)
    /// A NAME matched more than one resource. Never resolved by picking one:
    /// reading the wrong sign-in because two resources share a name is worse
    /// than failing.
    case severalMatches(name: String, names: [String])
    case nothingMatched(String)
    case timedOut
    case unreadableOutput
    /// Anything else the tool said. Already scrubbed and truncated by
    /// `LocalToolRunner`.
    case failed(String)

    var errorDescription: String? {
        switch self {
        case .toolMissing:
            "Passbolt\u{2019}s own command-line program isn\u{2019}t installed where SimpleVPN can "
            + "run it, so it can\u{2019}t read your Passbolt server."
        case .noServerConfigured(let why):
            "SimpleVPN doesn\u{2019}t know which Passbolt server to read \u{2014} \(why)."
        case .toolNotConfigured(let path):
            "Passbolt\u{2019}s own program isn\u{2019}t set up for this server yet: there\u{2019}s no "
            + "key for it in \(path). Run \u{201C}passbolt configure\u{201D} once in Terminal."
        case .passphraseUnavailable:
            // The sentence most people will see first, so it points at the fix a
            // person on a Mac would expect: type it once, here.
            "Your Passbolt key needs its passphrase. Type it in Settings \u{25B8} Sign-In "
            + "Sources \u{2014} SimpleVPN holds it until it quits, and can ask macOS to remember it "
            + "behind Touch ID if you would rather not type it again."
        case .cancelled:
            "Nothing was read from Passbolt \u{2014} you cancelled."
        case .passphraseContainsNewline:
            "That passphrase has a line break in it, and Passbolt\u{2019}s own program reads only "
            + "one line, so it can never be handed over. Nothing is wrong with your key."
        case .signInRejected:
            "Your Passbolt server wouldn\u{2019}t accept that key and passphrase."
        case .verificationCodeRequired:
            "Your Passbolt account asks for a verification code, and SimpleVPN can\u{2019}t supply "
            + "one \u{2014} it would have to keep the code\u{2019}s secret next to your passphrase, "
            + "which would undo the point of asking. Read this VPN\u{2019}s sign-in another way."
        case .serverUnreachable(let detail):
            detail.isEmpty
                ? "SimpleVPN couldn\u{2019}t reach your Passbolt server."
                : "SimpleVPN couldn\u{2019}t reach your Passbolt server: \(detail)"
        case .certificateNotTrusted:
            // Names the fix, and does NOT hint that verification could be turned
            // off — because it cannot, here, ever.
            "Your Passbolt server\u{2019}s certificate isn\u{2019}t trusted by this Mac. If your "
            + "organization runs its own certificate authority, add that authority to this Mac\u{2019}s "
            + "keychain and mark it trusted \u{2014} that fixes it for every program at once. "
            + "SimpleVPN will not skip the check."
        case .serverIdentityChanged:
            "Your Passbolt server didn\u{2019}t prove it is the same server as before. Nothing was "
            + "read. If the server was genuinely rebuilt, run \u{201C}passbolt verify\u{201D} again in "
            + "Terminal; if it wasn\u{2019}t, stop and find out why."
        case .resourceNotFound(let reference):
            "Your Passbolt server has nothing called \u{201C}\(reference)\u{201D}, or you can\u{2019}t "
            + "see it."
        case .severalMatches(let name, let names):
            "\u{201C}\(name)\u{201D} matches \(names.count) things in Passbolt, so SimpleVPN "
            + "doesn\u{2019}t know which one you mean. Use the one you want\u{2019}s identifier "
            + "instead \u{2014} Passbolt shows it in the web address when you open it."
        case .nothingMatched(let name):
            "Nothing in your Passbolt server is called \u{201C}\(name)\u{201D}."
        case .timedOut:
            "Your Passbolt server didn\u{2019}t answer in time."
        case .unreadableOutput:
            "SimpleVPN couldn\u{2019}t make sense of what Passbolt\u{2019}s program printed."
        case .failed(let detail):
            detail.isEmpty ? "Passbolt\u{2019}s program couldn\u{2019}t provide the sign-in."
                           : "Passbolt\u{2019}s program couldn\u{2019}t provide the sign-in: \(detail)"
        }
    }

    /// Whether trying again, unchanged, could plausibly work. `false` for
    /// everything a person has to go and fix — which is what stops a connect path
    /// retrying a rejected passphrase and burning through a server's lockout
    /// budget.
    var isWorthRetrying: Bool {
        switch self {
        case .serverUnreachable, .timedOut: true
        case .toolMissing, .noServerConfigured, .toolNotConfigured, .passphraseUnavailable,
             .cancelled, .passphraseContainsNewline, .signInRejected,
             .verificationCodeRequired, .certificateNotTrusted,
             .serverIdentityChanged, .resourceNotFound, .severalMatches, .nothingMatched,
             .unreadableOutput, .failed: false
        }
    }
}

// MARK: - Classifying what the tool said

/// Turning `go-passbolt-cli`'s stderr into one of the cases above.
///
/// Every marker here is quoted from the tool's own source, so the provenance of
/// each is checkable rather than guessed:
///   • `serverAddress is not defined`, `userPrivateKey is not defined` —
///     `internal/util/client.go` (`GetClient`), and asserted by the tool's own
///     `internal/testdata/43_error_missing_config.txtar`.
///   • `reading Password` — `GetClient` wrapping `util.ReadPassword`, which is
///     what a closed stdin produces.
///   • `authentication failed, check your private key and password` (401),
///     `access denied, you may lack the required permission or MFA may be needed`
///     (403), `not found, check the requested ID and the server address` (404) —
///     `apiStatusHint` in the same file.
///   • `verifying Server` — `GetClient`'s wrap of `client.VerifyServer`.
///   • `getting resource` — `ResourceGet` in `internal/cmd/resource/get.go`,
///     asserted by `internal/testdata/44_error_resource_not_found.txtar`.
///   • `x509`, `certificate signed by unknown authority`, `tls:` — Go's own
///     `crypto/x509` and `crypto/tls` text, which reaches us through the tool's
///     wrapped error.
///
/// Order matters: the specific markers are tested before the generic ones, so a
/// certificate problem inside a login is not reported as "wrong passphrase".
nonisolated enum PassboltFailureClassifier {

    static func classify(stderr raw: String, reference: String) -> PassboltError {
        let text = raw.lowercased()

        // --- Level 2 configuration, before anything touched the network ---
        if text.contains("serveraddress is not defined") {
            return .noServerConfigured("Passbolt\u{2019}s own program has no address for it")
        }
        if text.contains("userprivatekey is not defined") {
            return .toolNotConfigured(PassboltServerLocation.defaultConfigFile())
        }
        // A closed stdin is how "no passphrase anywhere" arrives.
        if text.contains("reading password") || text.contains("enter password") {
            return .passphraseUnavailable
        }

        // --- Transport and identity, before credentials ------------------
        if text.contains("x509") || text.contains("certificate signed by unknown authority")
            || text.contains("certificate is not trusted") || text.contains("tls: failed to verify")
            || text.contains("certificate has expired") {
            return .certificateNotTrusted(raw)
        }
        if text.contains("verifying server") { return .serverIdentityChanged }
        if text.contains("no such host") || text.contains("connection refused")
            || text.contains("dial tcp") || text.contains("network is unreachable")
            || text.contains("i/o timeout") || text.contains("no route to host")
            || text.contains("eof") && text.contains("dial") {
            return .serverUnreachable(raw)
        }

        // --- Credentials -------------------------------------------------
        if text.contains("may be needed") || text.contains("mfa") {
            return .verificationCodeRequired
        }
        if text.contains("authentication failed") || text.contains("check your private key")
            || text.contains("gopenpgp") || text.contains("wrong passphrase")
            || text.contains("incorrect passphrase") {
            return .signInRejected
        }

        // --- The resource ------------------------------------------------
        if text.contains("404") || text.contains("not found") || text.contains("does not exist")
            || text.contains("getting resource") {
            return .resourceNotFound(reference)
        }
        if text.contains("context deadline exceeded") || text.contains("timeout") {
            return .timedOut
        }
        return .failed(raw)
    }
}

// MARK: - What the cheap probe can settle

/// The states a filesystem-only probe can reach for one server. Deliberately
/// short: everything past "the tool is set up and the address looks right" needs
/// a real login, and a real login is an authentication against somebody's
/// server.
nonisolated enum PassboltServerState: Sendable, Equatable {
    /// The tool is here, the address is usable, and a passphrase can be supplied —
    /// either SimpleVPN holds one or Passbolt's own program has one. Nothing has been
    /// proven against the server itself.
    case readyToTry
    /// Set up, but nothing can unlock the key: SimpleVPN holds no passphrase for this
    /// server and the tool has none of its own. The dormant state.
    case needsPassphrase
    /// The tool has no configuration for this server.
    case toolNotConfigured
    /// No server address, or an unusable one.
    case noServer(String)
    /// The `passbolt` program is not installed anywhere SimpleVPN will run it.
    case toolMissing
}

// MARK: - The process boundary

/// The one seam every test injects. A `PassboltRunning` never touches the
/// network itself — it runs the tool, or pretends to.
nonisolated protocol PassboltRunning: Sendable {
    /// Where the tool is, or nil.
    func locate() -> String?
    /// Run it. `arguments` never carries a secret; `passphrase` is written to the
    /// child's stdin and nowhere else.
    func run(arguments: [String], passphrase: PassboltPassphrase?,
             deadline: TimeInterval) async -> LocalToolResult
}

nonisolated struct PassboltCLI: PassboltRunning {

    /// BOTH names, because both are real installs and reporting "not installed"
    /// for the other would be false. Homebrew's `passbolt/tap/go-passbolt-cli`
    /// formula does `bin.install "passbolt"`, so the binary is `passbolt`;
    /// `go install github.com/passbolt/go-passbolt-cli@latest` produces a binary
    /// named after the module, `go-passbolt-cli`. The cobra root command is
    /// `Use: "passbolt"` either way (`internal/cmd/root.go`).
    static let toolNames = ["passbolt", "go-passbolt-cli"]

    /// The tool's own name for its config directory, used in copy so the sentence
    /// names a folder somebody can find.
    static let configDirectoryName = "go-passbolt-cli"

    func locate() -> String? { Self.locate() }

    /// The path SimpleVPN would run. An explicit path set for `passbolt` wins for
    /// either name — `LocalToolRunner.userConfiguredPath` checks that the path is
    /// absolute and safe, not what the file is called, so somebody whose only
    /// copy is a `go install` build in an unusual place points the one row at it.
    static func locate() -> String? {
        toolNames.compactMap { LocalToolRunner.locate($0) }.first
    }

    /// The tool's own timeout, and ours. The tool's is SHORTER on purpose: it
    /// then reports its own bounded error ("context deadline exceeded") instead of
    /// being SIGTERMed halfway through, which is the difference between a sentence
    /// and a shrug. `--timeout` is a root persistent flag defaulting to a whole
    /// minute, which is far too long to hold a connect.
    static let toolTimeoutSeconds = 20
    static let runnerDeadline: TimeInterval = 26

    func run(arguments: [String], passphrase: PassboltPassphrase?,
             deadline: TimeInterval) async -> LocalToolResult {
        guard let executable = Self.locate() else {
            return LocalToolResult(exitCode: -1, stdout: Data(),
                                   stderr: "passbolt not found in an approved location",
                                   timedOut: false)
        }
        // THE ONE PLACE A PASSPHRASE CROSSES THE PROCESS BOUNDARY. `stdinLine()`
        // appends the newline the tool's `ReadString('\n')` requires, and there is no
        // other API on the box that hands back its characters. nil leaves stdin at
        // `/dev/null`, so a tool that decides to prompt hits EOF and fails at once.
        let stdin = passphrase?.stdinLine()
        return await LocalToolRunner.run(executable: executable, arguments: arguments,
                                         deadline: deadline, stdin: stdin)
    }
}

// MARK: - The reader

/// Reading one resource out of one server. Pure argument-building plus the
/// injected process boundary, so every path is testable with no Passbolt, no
/// server and no key.
nonisolated struct PassboltReader: Sendable {
    var location: PassboltServerLocation
    var tool: any PassboltRunning = PassboltCLI()
    /// Injected so a test can present any config-file state.
    var toolConfig: @Sendable (String) -> PassboltToolConfig = {
        PassboltToolConfigProbe.read(path: $0)
    }
    var home: URL = FileManager.default.homeDirectoryForCurrentUser
    /// Whether SIMPLEVPN could supply a passphrase for this server — held for this
    /// run, or remembered behind Touch ID. Injected as a plain Bool rather than read
    /// from the store, because `serverState()` must stay synchronous, prompt-free and
    /// callable from a nonisolated context, and because a test can then present every
    /// combination without a keychain.
    var weHoldAPassphrase = false

    // MARK: The arguments — the only place a command line is built

    /// The flags every invocation carries. Nothing here is a secret, and the two
    /// omissions are the point:
    ///
    ///  • `--tlsSkipVerify` IS NEVER EMITTED. There is no code path that can add
    ///    it and no setting that could ask for it.
    ///  • `--mfaMode none` is emitted deliberately. The tool's default is
    ///    `interactive-totp`, which reads a code from stdin — with stdin closed
    ///    that is an EOF that reads like a passphrase problem. `none` makes the
    ///    server's own "a code is required" answer arrive as itself, which is a
    ///    sentence somebody can act on. `noninteractive-totp` is never used: it
    ///    needs the code's SEED, which beside the passphrase is not a second
    ///    factor at all.
    func commonArguments() -> [String] {
        var out: [String] = ["--json", "--mfaMode", "none",
                             "--timeout", "\(PassboltCLI.toolTimeoutSeconds)s"]
        let trimmed = location.serverURL.trimmingCharacters(in: .whitespacesAndNewlines)
        if !trimmed.isEmpty {
            // Passed even when the tool's config already has one: SimpleVPN's
            // instance IS the server, so saying which server is SimpleVPN's job.
            // Without this, a mis-set config file would silently read a different
            // Passbolt.
            out += ["--serverAddress", trimmed]
        }
        if let configFile = location.configFile, !configFile.isEmpty {
            out += ["--config", configFile]
        }
        return out
    }

    /// `passbolt get resource --id <uuid> …`. The ONLY read-by-id command.
    func getArguments(id: String) -> [String] {
        ["get", "resource", "--id", id] + commonArguments()
    }

    /// `passbolt list resource -c id -c name -c username -c uri …`.
    ///
    /// The columns are chosen so the listing needs NO secret: `RequiresSecrets`
    /// in `internal/cmd/resource/columns.go` decides whether the tool asks the
    /// server to join secrets in and then decrypts them, and none of these four
    /// is secret-bearing. So "which one did you mean" costs a metadata read and
    /// never a password.
    ///
    /// There is deliberately no `--filter`: the tool's filter is a CEL
    /// expression, and building one out of text somebody typed means quoting
    /// their text into a small language. Matching in Swift instead removes that
    /// question entirely, and lets "several matches" be seen and reported rather
    /// than silently narrowed.
    func listArguments() -> [String] {
        ["list", "resource", "-c", "id", "-c", "name", "-c", "username", "-c", "uri"]
            + commonArguments()
    }

    // MARK: The cheap answer

    /// Filesystem only: no subprocess, no network, no prompt. Safe on every
    /// settings refresh.
    func serverState() -> PassboltServerState {
        guard tool.locate() != nil else { return .toolMissing }
        if let why = PassboltServerLocation.validate(location.serverURL) {
            return .noServer(why)
        }
        let config = toolConfig(location.effectiveConfigFile(home: home))
        guard config.exists, config.hasPrivateKey else { return .toolNotConfigured }
        // EITHER owner will do. SimpleVPN's own is checked first because it is the
        // one this app recommends; the tool's own is honoured because plenty of
        // people already have it that way and breaking their setup to make a point
        // would be worse than the point.
        guard weHoldAPassphrase || config.hasPassphrase else { return .needsPassphrase }
        return .readyToTry
    }

    /// The config file's key presence, for the settings pane's note and for a
    /// diagnostic report. Booleans and a path; never a value.
    func configuration() -> PassboltToolConfig {
        toolConfig(location.effectiveConfigFile(home: home))
    }

    // MARK: The fetch

    /// Read one resource. `passphrase` is whatever SimpleVPN holds for this server
    /// (nil when Passbolt's own program has its own, which is the honoured-but-not-
    /// recommended tier). It travels on the tool's stdin and by no other route.
    func read(_ reference: PassboltResourceReference,
              passphrase: PassboltPassphrase? = nil) async throws -> PassboltResource {
        if let passphrase, passphrase.containsNewline {
            // Named before anything is spawned, because the tool would report it as a
            // read failure and the user would go and change a passphrase that is fine.
            throw PassboltError.passphraseContainsNewline
        }
        switch serverState() {
        case .toolMissing: throw PassboltError.toolMissing
        case .noServer(let why): throw PassboltError.noServerConfigured(why)
        case .toolNotConfigured:
            throw PassboltError.toolNotConfigured(location.effectiveConfigFile(home: home))
        case .needsPassphrase:
            // Dormant, unless the caller genuinely has one in hand. Nothing is
            // spawned: a sign-in that is going to ask for input we cannot give is
            // an authentication attempt against somebody's server for nothing.
            guard passphrase != nil else { throw PassboltError.passphraseUnavailable }
        case .readyToTry: break
        }

        let id: String
        switch reference {
        case .id(let value):
            id = value
        case .name(let value):
            id = try await resolve(name: value, passphrase: passphrase)
        }
        let result = await tool.run(arguments: getArguments(id: id), passphrase: passphrase,
                                    deadline: PassboltCLI.runnerDeadline)
        if result.timedOut { throw PassboltError.timedOut }
        guard result.succeeded else {
            throw PassboltFailureClassifier.classify(stderr: result.stderr,
                                                     reference: reference.display)
        }
        // stdout is the SECRET. Parsed here, and nothing from it is ever logged,
        // quoted in an error, or put in a report.
        return try PassboltResource.parse(result.stdout)
    }

    /// Turn a NAME into an id, or refuse. Exact case-insensitive match first,
    /// because that is what somebody typing a name means; several matches are an
    /// error rather than a choice made for them.
    func resolve(name: String, passphrase: PassboltPassphrase?) async throws -> String {
        let result = await tool.run(arguments: listArguments(), passphrase: passphrase,
                                    deadline: PassboltCLI.runnerDeadline)
        if result.timedOut { throw PassboltError.timedOut }
        guard result.succeeded else {
            throw PassboltFailureClassifier.classify(stderr: result.stderr, reference: name)
        }
        let rows = try PassboltResourceSummary.parseList(result.stdout)
        let wanted = name.trimmingCharacters(in: .whitespacesAndNewlines)
        let matches = rows.filter {
            $0.name.compare(wanted, options: [.caseInsensitive, .diacriticInsensitive])
                == .orderedSame
        }
        switch matches.count {
        case 0: throw PassboltError.nothingMatched(wanted)
        case 1: return matches[0].id
        default:
            // The NAMES, never the ids: a message that lists five UUIDs helps
            // nobody, and the fix is "use the identifier of the one you want".
            throw PassboltError.severalMatches(name: wanted,
                                               names: matches.map(\.name))
        }
    }
}
