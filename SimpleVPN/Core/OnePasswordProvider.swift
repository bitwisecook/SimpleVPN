// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
//  OnePasswordProvider.swift
//  Fetch credentials from 1Password via its CLI (`op`). One `op item get
//  --format json` returns username, password and any one-time-code field, so a
//  single call satisfies the whole CredentialRequest. Unlock is handled by
//  1Password itself: with the desktop-app CLI integration on, `op` prompts for
//  Touch ID; the app never sees the vault password. Requires the `op` binary
//  (Homebrew or the 1Password install) — isAvailable reports whether it's found.
//

import Foundation
import os

struct OnePasswordProvider: CredentialProvider {
    let id = "1password"
    let displayName = "1Password"
    let itemReference: String
    let vault: String   // optional; "" = search all vaults
    /// Role → field label/id chosen by the user. Empty ⇒ auto-detect by purpose.
    var fieldMap: [String: String] = [:]

    /// One selectable field of a 1Password item, as shown in the mapping sheet.
    struct OPField: Identifiable, Sendable, Hashable {
        let id: String          // 1Password field id (stable) — the map value
        let label: String       // human label ("username", "password", "one-time password")
        let purpose: String     // "USERNAME" | "PASSWORD" | ""
        let type: String        // "STRING" | "CONCEALED" | "OTP" | …
        var isOTP: Bool { type == "OTP" }
    }

    private static let log = Logger(subsystem: "com.bragi0.SimpleVPN", category: "1password")

    /// Common install locations (the app has no inherited shell PATH).
    private static let candidatePaths = [
        "/opt/homebrew/bin/op",
        "/usr/local/bin/op",
        "/usr/bin/op",
    ]

    static var cliPath: String? {
        candidatePaths.first { FileManager.default.isExecutableFile(atPath: $0) }
    }

    func isAvailable(for profile: String) async -> Bool {
        Self.cliPath != nil && !itemReference.trimmingCharacters(in: .whitespaces).isEmpty
    }

    func resolve(profile: String, fields: Set<CredentialField>) async throws -> RawCredentials {
        guard let op = Self.cliPath else { throw OPError.notInstalled }
        let ref = itemReference.trimmingCharacters(in: .whitespaces)
        guard !ref.isEmpty else { throw OPError.noReference }

        var args = ["item", "get", ref, "--format", "json"]
        if !vault.trimmingCharacters(in: .whitespaces).isEmpty {
            args += ["--vault", vault]
        }
        let result = try await Self.run(op, args)
        guard result.status == 0 else {
            throw OPError.cli(Self.friendlyError(result.stderr))
        }
        return try Self.parse(json: result.stdout, want: fields, map: fieldMap)
    }

    /// List an item's fields so the user can map them to auth roles. Returns the
    /// item title and its selectable fields (those that actually hold a value).
    static func listFields(itemReference ref: String, vault: String) async throws
        -> (title: String, fields: [OPField]) {
        guard let op = cliPath else { throw OPError.notInstalled }
        let r = ref.trimmingCharacters(in: .whitespaces)
        guard !r.isEmpty else { throw OPError.noReference }
        var args = ["item", "get", r, "--format", "json"]
        let v = vault.trimmingCharacters(in: .whitespaces)
        if !v.isEmpty { args += ["--vault", v] }
        let result = try await run(op, args)
        guard result.status == 0 else { throw OPError.cli(friendlyError(result.stderr)) }
        guard let obj = try? JSONSerialization.jsonObject(with: result.stdout) as? [String: Any] else {
            throw OPError.parse
        }
        let title = (obj["title"] as? String) ?? r
        let rawFields = (obj["fields"] as? [[String: Any]]) ?? []
        let fields: [OPField] = rawFields.compactMap { f in
            let type = (f["type"] as? String) ?? ""
            let hasValue = (f["value"] as? String)?.isEmpty == false || (f["totp"] as? String) != nil
            guard hasValue else { return nil }                 // skip empty fields
            let id = (f["id"] as? String) ?? (f["label"] as? String) ?? UUID().uuidString
            let label = (f["label"] as? String) ?? id
            return OPField(id: id, label: label,
                           purpose: (f["purpose"] as? String) ?? "", type: type)
        }
        return (title, fields)
    }

    // MARK: JSON parsing

    /// 1Password item JSON: `fields[]` each with `purpose`/`type`/`label`/`id`/`value`
    /// and, for OTP, a `totp` value. When `map` names a field for a role (by id or
    /// label) that wins; otherwise fall back to purpose (USERNAME/PASSWORD) and
    /// `type == "OTP"`.
    static func parse(json: Data, want: Set<CredentialField>,
                      map: [String: String] = [:]) throws -> RawCredentials {
        guard let obj = try? JSONSerialization.jsonObject(with: json) as? [String: Any],
              let fields = obj["fields"] as? [[String: Any]] else {
            throw OPError.parse
        }
        // Value a role should take from an explicitly-mapped field (id or label match).
        func mappedValue(for role: CredentialField) -> String? {
            guard let key = map[role.rawValue], !key.isEmpty else { return nil }
            guard let f = fields.first(where: { ($0["id"] as? String) == key || ($0["label"] as? String) == key }) else { return nil }
            // For an OTP field, only ever expose the current code (`totp`), NEVER
            // fall back to `value` — that's the otpauth:// seed, and returning it
            // as a username/password would exfiltrate the TOTP secret to the server.
            if (f["type"] as? String) == "OTP" { return f["totp"] as? String }
            return f["value"] as? String
        }

        var raw = RawCredentials()
        // Explicit mappings first.
        raw.username = mappedValue(for: .username)
        raw.password = mappedValue(for: .password)
        raw.otp = mappedValue(for: .otp)
        // Private-key passphrase has no CredentialField; look it up by its role key.
        if let key = map["privateKeyPassphrase"], !key.isEmpty,
           let f = fields.first(where: { ($0["id"] as? String) == key || ($0["label"] as? String) == key }) {
            raw.privateKeyPassphrase = f["value"] as? String
        }

        // Auto-detect anything the map didn't cover.
        for f in fields {
            let purpose = (f["purpose"] as? String) ?? ""
            let type = (f["type"] as? String) ?? ""
            let value = f["value"] as? String
            switch purpose {
            case "USERNAME": if raw.username == nil { raw.username = value }
            case "PASSWORD": if raw.password == nil { raw.password = value }
            default:
                if type == "OTP", raw.otp == nil {
                    // `totp` is the current code; `value` is the otpauth:// secret.
                    raw.otp = (f["totp"] as? String) ?? raw.otp
                }
            }
        }
        return raw
    }

    static func friendlyError(_ stderr: String) -> String {
        let s = stderr.lowercased()
        // The whole family of "the CLI can't get a session from the desktop app" errors.
        // Verified against the real failure: `op account list` happily lists the account
        // while `op whoami` says "account is not signed in" and the connect attempt dies
        // with "RequestDelegatedSession: cannot setup session". None of that tells a user
        // anything, and the fix is a specific switch in another app that nobody would
        // guess at — so name it, in order, and say what to do next.
        if s.contains("requestdelegatedsession") || s.contains("cannot setup session")
            || s.contains("error initializing client") || s.contains("not signed in")
            || s.contains("not currently signed in") || s.contains("no account") {
            return """
            1Password didn't let SimpleVPN ask for your credentials.

            Things that fix this, in order of likelihood:
            1. If you JUST approved a 1Password prompt or Touch ID \u{2014} press Connect \
            again. The first attempt after approving often fails while 1Password \
            finishes setting up the link.
            2. The link to the saved item can go stale \u{2014} open this VPN's \
            credential settings and drag the 1Password item in again.
            3. In 1Password: unlock it, then Settings \u{25B8} Developer \u{25B8} switch \
            \u{201C}Integrate with 1Password CLI\u{201D} off and on again.
            """
        }
        if s.contains("connect") && s.contains("refused") {
            return "1Password doesn't seem to be running. Open it, unlock it, and try again."
        }
        if s.contains("more than one item") || s.contains("isn't unique") {
            return "More than one 1Password item matches — use the item's UUID or a vault."
        }
        if s.contains("no item") || s.contains("not found") {
            return "No 1Password item matches that reference."
        }
        return stderr.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
            ? "1Password CLI failed." : stderr.trimmingCharacters(in: .whitespacesAndNewlines)
    }

    // MARK: Process

    struct RunResult { let status: Int32; let stdout: Data; let stderr: String }

    static func run(_ path: String, _ args: [String], timeout: TimeInterval = 60) async throws -> RunResult {
        // Cancellation must reach the SUBPROCESS: cancelling the Swift task alone
        // leaves `op` running (possibly holding a 1Password prompt open) until the
        // timeout reaps it. The lock hands the Process across the cancel boundary.
        let running = OSAllocatedUnfairLock<Process?>(initialState: nil)
        return try await withTaskCancellationHandler {
            try await Task.detached(priority: .userInitiated) {
            let p = Process()
            p.executableURL = URL(fileURLWithPath: path)
            p.arguments = args
            // No inherited config; force non-interactive so it never hangs on a prompt.
            var env = ProcessInfo.processInfo.environment
            env["OP_FORMAT"] = "json"
            p.environment = env
            let out = Pipe(), err = Pipe()
            p.standardOutput = out
            p.standardError = err
            try p.run()
            running.withLock { $0 = p }
            // Kill-on-timeout: `op` can raise a Touch-ID / CLI-integration prompt.
            // If the user never answers, waitUntilExit() would block forever — and
            // this call is on the reconnect / "Applying…" path, so a hang wedges the
            // UI. Bound it and terminate so the caller always makes progress.
            let killer = DispatchWorkItem { if p.isRunning { p.terminate() } }
            DispatchQueue.global().asyncAfter(deadline: .now() + timeout, execute: killer)
            let outData = out.fileHandleForReading.readDataToEndOfFile()
            let errData = err.fileHandleForReading.readDataToEndOfFile()
            p.waitUntilExit()
            killer.cancel()
            // A cancel surfaces as a cancel — not as a weird op exit status.
            try Task.checkCancellation()
            return RunResult(status: p.terminationStatus, stdout: outData,
                             stderr: String(data: errData, encoding: .utf8) ?? "")
            }.value
        } onCancel: {
            running.withLock { $0?.terminate() }
        }
    }

    enum OPError: LocalizedError {
        case notInstalled, noReference, parse, cli(String)
        var errorDescription: String? {
            switch self {
            case .notInstalled: "The 1Password command-line tool (op) isn't installed."
            case .noReference: "No 1Password item is configured for this VPN."
            case .parse: "1Password returned an unexpected response."
            case .cli(let m): m
            }
        }
    }
}
