// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
//  KeeperProvider.swift
//  Fetch a username/password (and a verification code, when the record carries
//  one) from Keeper — through **Keeper Commander**, Keeper's own MIT-licensed
//  command-line tool. The Keeper desktop app exposes no local API; Commander is
//  the supported local path, and it is a real one: `persistent-login` gives
//  non-interactive use, and Commander keeps its own sign-in in this Mac's
//  keychain (so macOS protects it, exactly as we tell users about our own).
//
//  Two channels, preferred in this order:
//   1. **Service Mode** — Commander's own local REST daemon (`service-create` /
//      `service-start`), when the user has configured one. Cheaper per fetch than
//      spawning Python, and the same architectural shape as the KeePassXC socket.
//   2. **The CLI** — one `keeper get <record> --format json --unmask` per fetch.
//
//  Non-negotiables (see LocalToolRunner for the enforcement):
//   • The secret arrives on stdout (or in the daemon's response body) and is
//     never logged, never quoted in an error, never placed in argv.
//   • Only the record's own name/UID goes in argv. `ps` shows argv to everyone.
//   • We NEVER write Commander's configuration. Keeper's docs warn that reusing
//     one config on a second device revokes both sessions and breaks persistent
//     login, so setup is the user's to perform — we only print the commands
//     (LocalVaultCopyBook.keeper).
//   • Nothing is cached: each connect asks again, so revoking access in Keeper
//     takes effect immediately.
//
//  The verification code, when the record has a TOTP field, is computed LOCALLY
//  from the field's otpauth:// URL with the same RFC 6238 engine the Touch ID
//  store uses — no second Commander round trip. `CredentialSourceKind.keeper
//  .suppliesOTP` still says false on purpose: that flag is a promise about
//  Connect being enabled with nothing typed, and this path has not been proven
//  against a live Keeper vault.
//

import Foundation
import os

struct KeeperProvider: CredentialProvider {
    let id = "keeper"
    let displayName = "Keeper"
    /// Record UID, title, or folder path ("Work/VPN/GR Lab").
    let reference: String
    /// Optional: which login to take when a record has several (matched against
    /// the record's login field).
    var account: String = ""
    /// Injectable so tests drive the whole resolve path with no Keeper anywhere.
    var channel: any KeeperChannel = KeeperCommanderChannel()

    private static let log = Logger(subsystem: "com.bragi0.SimpleVPN", category: "keeper")

    func isAvailable(for profile: String) async -> Bool {
        guard !reference.trimmingCharacters(in: .whitespaces).isEmpty else { return false }
        return await channel.isReachable()
    }

    func resolve(profile: String, fields: Set<AuthKind>) async throws -> RawCredentials {
        let ref = reference.trimmingCharacters(in: .whitespaces)
        guard !ref.isEmpty else { throw KeeperError.noRecord }
        let record = try await channel.record(reference: ref)

        let wanted = account.trimmingCharacters(in: .whitespaces)
        if !wanted.isEmpty, let login = record.login, !login.isEmpty,
           login.caseInsensitiveCompare(wanted) != .orderedSame {
            throw KeeperError.wrongAccount(wanted)
        }
        guard let password = record.password, !password.isEmpty else {
            throw KeeperError.noPassword(ref)
        }
        var raw = RawCredentials()
        raw.username = (record.login?.isEmpty == false) ? record.login : (wanted.isEmpty ? nil : wanted)
        raw.password = password
        if fields.contains(.otp), let seed = record.totpSeed,
           let totp = TOTPConfiguration(parsing: seed) {
            raw.otp = totp.code(at: Date())
        }
        Self.log.log("keeper record resolved for \(profile, privacy: .public)")
        return raw
    }

    nonisolated enum KeeperError: LocalizedError, Equatable {
        case noRecord
        case notSignedIn
        case noPassword(String)
        case wrongAccount(String)
        case unreadable(String)

        var errorDescription: String? {
            switch self {
            case .noRecord:
                "No Keeper record is set for this VPN \u{2014} add the record\u{2019}s name or its UID."
            case .notSignedIn:
                "Keeper Commander isn\u{2019}t signed in on this Mac. Open Terminal, run "
                + "\u{201C}keeper shell\u{201D}, sign in once, then run \u{201C}this-device register\u{201D} "
                + "and \u{201C}this-device persistent-login on\u{201D}."
            case .noPassword(let ref):
                "The Keeper record \u{201C}\(ref)\u{201D} has no password in it."
            case .wrongAccount(let account):
                "The Keeper record\u{2019}s username isn\u{2019}t \u{201C}\(account)\u{201D} \u{2014} "
                + "clear the account, or point this VPN at the right record."
            case .unreadable(let detail):
                detail.isEmpty ? "Keeper couldn\u{2019}t provide the sign-in."
                               : "Keeper couldn\u{2019}t provide the sign-in: \(detail)"
            }
        }
    }
}

// MARK: - What one record gives us

/// The three things a sign-in needs, lifted out of whatever record shape Keeper
/// hands back. Never logged, never described in an error.
nonisolated struct KeeperRecord: Sendable, Equatable {
    var login: String?
    var password: String?
    /// An `otpauth://` URL from the record's TOTP field, when it has one. The
    /// SEED, so the code is computed locally — never a code fetched separately.
    var totpSeed: String?
}

// MARK: - The channel seam

/// How this Mac talks to Keeper. Two implementations ship (Service Mode, then
/// the CLI); tests inject a third with no Keeper present at all.
nonisolated protocol KeeperChannel: Sendable {
    /// Prompt-free-ish: can this channel serve right now? (Tool present AND a
    /// live session.)
    func isReachable() async -> Bool
    /// One record. Throws `KeeperProvider.KeeperError` on anything else.
    func record(reference: String) async throws -> KeeperRecord
}

// MARK: - Commander (Service Mode, then the CLI)

nonisolated struct KeeperCommanderChannel: KeeperChannel {

    private static let log = Logger(subsystem: "com.bragi0.SimpleVPN", category: "keeper")

    /// Where the `keeper` executable is, if anywhere. Cheap: file checks only,
    /// and resolved against LocalToolRunner's allow-list rather than `PATH` —
    /// nothing user-writable gets to choose which binary is handed a request for
    /// a password.
    static func locateCLI() -> String? { LocalToolRunner.locate("keeper") }

    /// Is Commander here at all? (Doesn't prove a signed-in session.)
    static func isInstalled() -> Bool {
        locateCLI() != nil || KeeperServiceMode.configured() != nil
    }

    /// Is there a live, non-interactive session? Runs `whoami`, which persistent
    /// login answers without prompting — and which, without one, fails fast
    /// because stdin is /dev/null.
    static func hasLiveSession() async -> Bool {
        if let service = KeeperServiceMode.configured(),
           await KeeperServiceMode.ping(service) { return true }
        guard let cli = locateCLI() else { return false }
        let result = await LocalToolRunner.run(executable: cli, arguments: ["whoami"], deadline: 10)
        return result.succeeded
    }

    func isReachable() async -> Bool { await Self.hasLiveSession() }

    func record(reference: String) async throws -> KeeperRecord {
        // Service Mode first when it is configured: no Python start-up cost, and
        // it is the channel Keeper themselves point automation at.
        if let service = KeeperServiceMode.configured() {
            if let record = await KeeperServiceMode.record(reference: reference, service: service) {
                return record
            }
            Self.log.log("keeper service mode didn\u{2019}t answer; falling back to the CLI")
        }
        guard let cli = Self.locateCLI() else { throw KeeperProvider.KeeperError.notSignedIn }
        // Only the record reference rides argv — never a secret, either way.
        let result = await LocalToolRunner.run(
            executable: cli,
            arguments: ["get", reference, "--format", "json", "--unmask"],
            deadline: 25)
        if result.timedOut { throw KeeperProvider.KeeperError.unreadable("Keeper didn\u{2019}t answer in time.") }
        guard result.succeeded else {
            // stderr only, already scrubbed by the runner. Commander says
            // "Not logged in" / "session expired" in various spellings.
            let detail = result.stderr.lowercased()
            if detail.contains("logged in") || detail.contains("login") || detail.contains("session") {
                throw KeeperProvider.KeeperError.notSignedIn
            }
            throw KeeperProvider.KeeperError.unreadable(result.stderr)
        }
        guard let record = KeeperRecordParser.parse(result.stdout) else {
            throw KeeperProvider.KeeperError.unreadable("its answer couldn\u{2019}t be read.")
        }
        return record
    }
}

// MARK: - Record parsing (pure, and tolerant)

/// Commander prints more than one record shape depending on the record type and
/// the Commander version: a flat `{"login":…, "password":…}` for legacy records,
/// and a typed `{"fields":[{"type":"login","value":["…"]}]}` for v3 ones (some
/// builds wrap either in a single-element array). All of them are read here,
/// because a version bump must not silently stop finding the password.
nonisolated enum KeeperRecordParser {

    static func parse(_ data: Data) -> KeeperRecord? {
        guard let any = try? JSONSerialization.jsonObject(with: data) else { return nil }
        if let array = any as? [Any] {
            for element in array {
                if let dict = element as? [String: Any], let record = parse(dict) { return record }
            }
            return nil
        }
        return (any as? [String: Any]).flatMap(parse)
    }

    static func parse(_ dict: [String: Any]) -> KeeperRecord? {
        var record = KeeperRecord()
        // Flat shape.
        record.login = string(dict, ["login", "username", "user"])
        record.password = string(dict, ["password", "secret"])
        record.totpSeed = string(dict, ["totp", "otp", "one_time_code"]).flatMap(otpauth)

        // Typed shape: fields + custom fields, each {type, value:[…]}.
        for key in ["fields", "custom", "custom_fields"] {
            guard let fields = dict[key] else { continue }
            if let list = fields as? [[String: Any]] {
                for field in list { absorb(field, into: &record) }
            } else if let map = fields as? [String: Any] {
                // `custom_fields` is sometimes a plain label→value map.
                for (label, value) in map {
                    guard let text = value as? String else { continue }
                    absorb(label: label, value: text, into: &record)
                }
            }
        }
        return (record.login != nil || record.password != nil) ? record : nil
    }

    private static func absorb(_ field: [String: Any], into record: inout KeeperRecord) {
        let label = (field["type"] as? String) ?? (field["label"] as? String) ?? ""
        let value: String?
        if let list = field["value"] as? [Any] {
            value = list.compactMap { $0 as? String }.first
        } else {
            value = field["value"] as? String
        }
        guard let value, !value.isEmpty else { return }
        absorb(label: label, value: value, into: &record)
    }

    private static func absorb(label: String, value: String, into record: inout KeeperRecord) {
        switch label.lowercased() {
        case "login", "username", "user", "email":
            if record.login?.isEmpty ?? true { record.login = value }
        case "password", "secret":
            if record.password?.isEmpty ?? true { record.password = value }
        case "onetimecode", "one_time_code", "totp", "otp", "twofactor", "two_factor_code":
            if record.totpSeed?.isEmpty ?? true { record.totpSeed = otpauth(value) }
        default:
            break
        }
    }

    private static func string(_ dict: [String: Any], _ keys: [String]) -> String? {
        for key in keys {
            if let value = dict[key] as? String, !value.isEmpty { return value }
        }
        return nil
    }

    /// Only an enrollment URL is usable as a seed. A bare six-digit code is a
    /// code, not a seed — taking it would freeze one code for ever.
    private static func otpauth(_ value: String) -> String? {
        value.lowercased().hasPrefix("otpauth://") ? value : nil
    }
}

// MARK: - Service Mode (Commander's local REST daemon)

/// Commander's Service Mode, when the user has created one. The daemon's config
/// is READ, never written (a Commander config copied or rewritten can revoke the
/// device's sessions — Keeper's own warning).
///
/// The request shape below is Commander's documented "run a command" endpoint as
/// of writing. It is deliberately the ONLY place that assumption lives, and every
/// failure here falls back to the CLI rather than failing the connect — so a
/// Commander release that renames the route costs a slower fetch, not a broken
/// sign-in.
nonisolated enum KeeperServiceMode {

    nonisolated struct Service: Sendable, Equatable {
        var port: Int
        var apiKey: String
    }

    /// The config Commander writes for `service-create`, if it is there.
    static func configured(
        home: URL = FileManager.default.homeDirectoryForCurrentUser
    ) -> Service? {
        let candidates = ["service_config.json", "service/service_config.json"]
        for name in candidates {
            let url = home.appendingPathComponent(".keeper").appendingPathComponent(name)
            guard let data = try? Data(contentsOf: url) else { continue }
            if let service = parse(data) { return service }
        }
        return nil
    }

    /// Pure, so the tolerant key matching is testable without a Keeper install.
    static func parse(_ data: Data) -> Service? {
        guard let dict = (try? JSONSerialization.jsonObject(with: data)) as? [String: Any] else { return nil }
        let port: Int? = ["port", "service_port", "servicePort"].lazy.compactMap { key -> Int? in
            if let n = dict[key] as? Int { return n }
            if let s = dict[key] as? String { return Int(s) }
            return nil
        }.first
        let key: String? = ["api_key", "apiKey", "token", "service_api_key"].lazy
            .compactMap { dict[$0] as? String }
            .first { !$0.isEmpty }
        guard let port, port > 0, let key else { return nil }
        return Service(port: port, apiKey: key)
    }

    /// Is the daemon answering? Cheap, local, and never fatal.
    static func ping(_ service: Service) async -> Bool {
        await command("whoami", service: service) != nil
    }

    static func record(reference: String, service: Service) async -> KeeperRecord? {
        // The reference is a record name/UID — never a secret — so it is safe in
        // the command string. The ANSWER carries the secret and is parsed
        // straight into KeeperRecord without being logged.
        guard let data = await command("get \(reference) --format json --unmask", service: service)
        else { return nil }
        return KeeperRecordParser.parse(data) ?? unwrapped(data)
    }

    /// Service Mode wraps command output in an envelope on some builds
    /// (`{"data": …}` / `{"result": …}`); look one level in before giving up.
    private static func unwrapped(_ data: Data) -> KeeperRecord? {
        guard let dict = (try? JSONSerialization.jsonObject(with: data)) as? [String: Any] else { return nil }
        for key in ["data", "result", "response", "output"] {
            if let nested = dict[key] {
                if let text = nested as? String,
                   let record = KeeperRecordParser.parse(Data(text.utf8)) { return record }
                if let nestedData = try? JSONSerialization.data(withJSONObject: nested),
                   let record = KeeperRecordParser.parse(nestedData) { return record }
            }
        }
        return nil
    }

    private static func command(_ command: String, service: Service) async -> Data? {
        guard let url = URL(string: "http://127.0.0.1:\(service.port)/api/v1/executecommand")
        else { return nil }
        var request = URLRequest(url: url, timeoutInterval: 10)
        request.httpMethod = "POST"
        request.setValue("application/json", forHTTPHeaderField: "Content-Type")
        request.setValue(service.apiKey, forHTTPHeaderField: "api-key")
        request.httpBody = try? JSONSerialization.data(withJSONObject: ["command": command])
        // Ephemeral: nothing about a secret-bearing response belongs in a cache.
        let session = URLSession(configuration: .ephemeral)
        guard let (data, response) = try? await session.data(for: request),
              let http = response as? HTTPURLResponse, http.statusCode == 200
        else { return nil }
        return data
    }
}
