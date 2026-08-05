// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
//  YubiKeyManagerTool.swift
//  Talking to `ykman` — Yubico's own command-line tool — for the two things a
//  security key COMPUTES rather than types: OATH codes (TOTP/HOTP stored on the
//  key) and slot HMAC-SHA1 challenge-response.
//
//  RULES INHERITED FROM THE SEAM, none of them negotiable here:
//   • WE NEVER SHIP OR INSTALL IT. `ykman` is the user's to install; SimpleVPN
//     detects it and shows the command. No bundled Python, no bundled binary.
//   • `PATH` IS NEVER CONSULTED. Resolution runs through `LocalToolRunner.locate`,
//     which walks a fixed allow-list of documented install locations (Homebrew's
//     two prefixes, MacPorts, the system directories, and the per-user bin
//     directories `pipx`/`pip --user` install into — `ykman` is a Python tool, so
//     that last group is the DOCUMENTED install, not an indulgence). A user who
//     has it somewhere else sets an absolute path.
//   • SECRETS COME BACK ON STDOUT AND NOWHERE ELSE, and stdout is never logged,
//     never interpolated into an error, never put in a diagnostic.
//   • NOTHING SECRET GOES IN ARGV. What DOES ride argv is called out at each call
//     site with why it is not a secret.
//
//  Everything below the process boundary is a pure parser over recorded output,
//  because there is no YubiKey on the machine this was written on and there may
//  well not be one on yours. `YubiKeyToolRunning` is the seam the tests drive.
//
//  OUTPUT FORMATS ARE PINNED TO YUBICO'S OWN SOURCE, not to memory. Each parser
//  names where its format comes from (`ykman/_cli/*.py` in
//  github.com/Yubico/yubikey-manager, BSD-2-Clause, and the published CLI guide
//  at docs.yubico.com). Where a format is inferred rather than verified, the
//  comment says so and the parser is written to tolerate drift instead of
//  pretending to precision it hasn't got.
//

import Foundation
import os

// MARK: - The process boundary

/// One place a `ykman` invocation happens. Injectable so every parser, every
/// failure classification and every piece of copy above it is unit-testable with
/// no key, no Python and no `ykman`.
nonisolated protocol YubiKeyToolRunning: Sendable {
    /// Where the tool is, or nil when it isn't anywhere we will run from.
    func locate() -> String?
    /// Run it. `arguments` never carries a secret.
    func run(_ arguments: [String], deadline: TimeInterval) async -> LocalToolResult
}

extension YubiKeyToolRunning {
    func run(_ arguments: [String]) async -> LocalToolResult {
        await run(arguments, deadline: YkmanRunner.defaultDeadline)
    }
}

/// The real thing: `ykman`, resolved and executed through `LocalToolRunner`.
nonisolated struct YkmanRunner: YubiKeyToolRunning {

    static let toolName = "ykman"

    /// Long enough for a Python start-up plus a smartcard round trip, short
    /// enough that a wedged connect gives up rather than hanging. A TOUCH-required
    /// operation needs far longer and passes its own deadline.
    static let defaultDeadline: TimeInterval = 12
    /// A touch-required OATH account or challenge-response leaves `ykman` waiting
    /// on a human finger. `ykman`'s own touch prompt gives up after about fifteen
    /// seconds; this is that plus room for the start-up, and it is the reason a
    /// caller must ALSO show a visible countdown of its own.
    static let touchDeadline: TimeInterval = 25

    var home: URL = FileManager.default.homeDirectoryForCurrentUser

    /// Resolution — including the user's own `signin.tool.ykman.path` override —
    /// is entirely `LocalToolRunner`'s. Note there is no injected `UserDefaults`
    /// here: `UserDefaults` is not `Sendable`, and a test that needed to vary the
    /// override would be testing `LocalToolRunner`, which has its own tests. The
    /// seam tests use is `YubiKeyToolRunning` itself.
    func locate() -> String? {
        LocalToolRunner.locate(Self.toolName, home: home)
    }

    func run(_ arguments: [String], deadline: TimeInterval) async -> LocalToolResult {
        guard let executable = locate() else {
            return LocalToolResult(exitCode: -1, stdout: Data(),
                                   stderr: "not installed", timedOut: false)
        }
        return await LocalToolRunner.run(executable: executable, arguments: arguments,
                                         deadline: deadline,
                                         environment: LocalToolRunner.childEnvironment(home: home))
    }
}

// MARK: - Failures

nonisolated enum YubiKeyToolError: LocalizedError, Equatable {
    /// `ykman` isn't installed anywhere SimpleVPN will run from.
    case toolMissing
    /// It ran, but no key was plugged in.
    case noKeyAttached
    /// Several keys are plugged in and the request didn't say which.
    case severalKeysAttached
    /// The key's code list is protected by a password. We will NOT pass a password
    /// on the command line, so this is a dead end until the user tells `ykman` to
    /// remember it for this Mac.
    case oathPasswordRequired
    /// The applet the request needs is switched off on the key.
    case appletDisabled(String)
    /// Nothing on the key matched.
    case noSuchAccount(String)
    /// The query matched more than one account, and the operation needs exactly one.
    case severalAccountsMatched(String)
    /// A touch was needed and never came.
    case touchTimedOut
    /// `ykman` answered something we could not read.
    case unreadableOutput
    /// It ran and failed. `detail` is already scrubbed and truncated by the runner.
    case failed(detail: String)

    var errorDescription: String? {
        switch self {
        case .toolMissing:
            "Yubico\u{2019}s own command-line tool (ykman) isn\u{2019}t installed on this Mac."
        case .noKeyAttached:
            "No security key is plugged in."
        case .severalKeysAttached:
            "More than one security key is plugged in \u{2014} SimpleVPN needs to know which one to use."
        case .oathPasswordRequired:
            "This security key\u{2019}s code list is protected by a password."
        case .appletDisabled(let applet):
            "This security key\u{2019}s \(applet) feature is switched off."
        case .noSuchAccount(let query):
            "No account on the security key matches \u{201C}\(query)\u{201D}."
        case .severalAccountsMatched(let query):
            "More than one account on the security key matches \u{201C}\(query)\u{201D}."
        case .touchTimedOut:
            "The security key wasn\u{2019}t touched in time."
        case .unreadableOutput:
            "SimpleVPN couldn\u{2019}t read what the security key\u{2019}s tool sent back."
        case .failed(let detail):
            detail.isEmpty ? "The security key\u{2019}s tool couldn\u{2019}t provide the code."
                           : "The security key\u{2019}s tool couldn\u{2019}t provide the code: \(detail)"
        }
    }

    /// What to do about it, in a sentence. Every case has one — a failure with no
    /// way forward is where people give up on a feature.
    var remedy: String? {
        switch self {
        case .toolMissing:
            "Install it with Homebrew (`brew install ykman`), then come back \u{2014} SimpleVPN never "
                + "installs it for you."
        case .noKeyAttached:
            "Plug your security key in and try again."
        case .severalKeysAttached:
            "Unplug the ones you aren\u{2019}t using, or set this VPN\u{2019}s security key by its "
                + "serial number."
        case .oathPasswordRequired:
            "SimpleVPN won\u{2019}t put that password on a command line where other programs could "
                + "read it. Run `ykman oath accounts code -r <name>` once in Terminal to let ykman "
                + "remember it on this Mac, or type the code yourself."
        case .appletDisabled:
            "Switch it back on with Yubico Authenticator, or `ykman config usb --enable OATH`."
        case .noSuchAccount:
            "Check the account name against the list \u{2014} `ykman oath accounts list`."
        case .severalAccountsMatched:
            "Use more of the account\u{2019}s name so only one matches."
        case .touchTimedOut:
            "Touch the gold disc on your security key while SimpleVPN is waiting."
        case .unreadableOutput, .failed:
            "Try `ykman info` in Terminal to check the tool and the key are talking to each other."
        }
    }
}

// MARK: - What `ykman` says

/// One line of `ykman list`.
nonisolated struct ListedSecurityKey: Sendable, Equatable {
    var name: String
    /// Firmware version as reported, e.g. "5.4.3". Absent on an access-denied line.
    var firmware: String?
    /// The interfaces, as `ykman` prints them: "OTP+FIDO+CCID".
    var interfaces: String
    /// Absent for a key with no serial, and for the access-denied fallback.
    var serial: String?
    /// `ykman` could see the device but not talk to it (a FIDO-only key with no
    /// permission). Worth its own flag: the key IS there, so "no key" is wrong.
    var accessDenied = false
}

/// `ykman info`, the fields we act on.
nonisolated struct SecurityKeyInfo: Sendable, Equatable {
    var deviceType: String?
    var serial: String?
    var firmware: String?
    var formFactor: String?
    /// The USB interfaces the key currently has switched ON, e.g. ["OTP", "FIDO", "CCID"].
    /// This is the one that decides whether OATH is reachable at all: OATH lives
    /// behind CCID.
    var enabledUSBInterfaces: [String] = []
    /// The Applications block, applet name → status word ("Enabled", "Disabled",
    /// "Not available"). Parsed LENIENTLY — see `parseInfo`.
    var applications: [String: String] = [:]

    /// Whether the smartcard interface is on, which is what OATH needs.
    var hasCCID: Bool {
        enabledUSBInterfaces.contains { $0.caseInsensitiveCompare("CCID") == .orderedSame }
    }
    /// Whether the typing interface is on, which is what Yubico OTP needs.
    var hasOTP: Bool {
        enabledUSBInterfaces.contains { $0.caseInsensitiveCompare("OTP") == .orderedSame }
    }
}

/// Which of the two OTP slots hold a credential. `ykman otp info`.
nonisolated struct OTPSlotStatus: Sendable, Equatable {
    var slotOneProgrammed = false
    var slotTwoProgrammed = false

    func isProgrammed(_ slot: YubiKeySlot) -> Bool {
        slot == .one ? slotOneProgrammed : slotTwoProgrammed
    }
}

/// One account in the key's OATH list.
nonisolated struct OATHAccount: Sendable, Equatable, Identifiable, Hashable {
    /// OATH's default period, in seconds. Credentials with anything else carry a
    /// `period/` prefix on their id — see `splitCredentialID`.
    static let defaultPeriod = 30

    /// The credential id exactly as `ykman` prints it — what we pass back as a
    /// query, so it must be preserved verbatim rather than reassembled.
    var id: String
    var issuer: String?
    var name: String
    /// "TOTP" / "HOTP" when `--oath-type` was asked for.
    var kind: Kind?
    /// The period in seconds when `--period` was asked for.
    var period: Int?

    nonisolated enum Kind: String, Sendable, Equatable {
        case totp = "TOTP"
        case hotp = "HOTP"
    }

    /// What the picker shows. The issuer first, because that is how someone finds
    /// their VPN in a list of thirty accounts.
    var displayName: String {
        guard let issuer, !issuer.isEmpty else { return name }
        return "\(issuer) \u{2014} \(name)"
    }

    /// A code for this account cannot be produced in a batch listing: HOTP steps a
    /// counter (so reading it in a list would burn codes), and a touch-required
    /// account needs a finger. Both need a single-match request.
    var needsSingleMatchRequest: Bool { kind == .hotp || requiresTouch }
    var requiresTouch = false
}

/// One line of `ykman oath accounts code` without `--single`.
nonisolated struct OATHCodeLine: Sendable, Equatable {
    var accountID: String
    /// nil when the key printed a marker instead of a code.
    var code: String?
    var marker: Marker?

    nonisolated enum Marker: String, Sendable, Equatable {
        /// `[Requires Touch]` — added with `--touch`, so a code needs a finger and
        /// a single-match request.
        case requiresTouch
        /// `[HOTP Account]` — counter-based, so a batch listing deliberately does
        /// not step it.
        case hotpAccount
    }
}

// MARK: - The parsers

nonisolated enum YkmanOutput {

    // MARK: `ykman list`

    /// Format, from `list_keys` in `ykman/_cli/__main__.py`:
    ///
    ///     {name} ({firmware}) [{interfaces}]           # `_describe_device`
    ///     … + " Serial: {serial}"                      # when the key has one
    ///
    /// so a real line reads
    ///
    ///     YubiKey 5 NFC (5.4.3) [OTP+FIDO+CCID] Serial: 12345678
    ///
    /// and the fallback for a device `ykman` can see but not open is
    ///
    ///     YubiKey [FIDO] <access denied>
    static func parseList(_ stdout: String) -> [ListedSecurityKey] {
        stdout.split(whereSeparator: \.isNewline).compactMap { rawLine in
            let line = rawLine.trimmingCharacters(in: .whitespaces)
            guard !line.isEmpty else { return nil }

            var remainder = Substring(line)
            var serial: String?
            if let marker = remainder.range(of: " Serial: ") {
                serial = String(remainder[marker.upperBound...]).trimmingCharacters(in: .whitespaces)
                remainder = remainder[remainder.startIndex..<marker.lowerBound]
            }
            let accessDenied = remainder.hasSuffix("<access denied>")
            if accessDenied {
                remainder = remainder.dropLast("<access denied>".count)
            }
            let text = remainder.trimmingCharacters(in: .whitespaces)

            // Interfaces are the bracketed group; the version is the parenthesised
            // one. Both are optional in the fallback shape, so neither is required.
            var interfaces = ""
            var head = Substring(text)
            if let open = text.lastIndex(of: "["), let close = text.lastIndex(of: "]"),
               open < close {
                interfaces = String(text[text.index(after: open)..<close])
                head = text[text.startIndex..<open]
            }
            var firmware: String?
            var name = head.trimmingCharacters(in: .whitespaces)
            if let open = name.lastIndex(of: "("), let close = name.lastIndex(of: ")"),
               open < close {
                firmware = String(name[name.index(after: open)..<close])
                name = String(name[name.startIndex..<open]).trimmingCharacters(in: .whitespaces)
            }
            guard !name.isEmpty else { return nil }
            return ListedSecurityKey(name: name, firmware: firmware, interfaces: interfaces,
                                     serial: serial, accessDenied: accessDenied)
        }
    }

    /// `ykman list --serials`: one serial per line, nothing else. Keys with no
    /// serial are simply absent, which is why a count from here can be lower than
    /// a count from the plain listing.
    static func parseSerials(_ stdout: String) -> [String] {
        stdout.split(whereSeparator: \.isNewline)
            .map { $0.trimmingCharacters(in: .whitespaces) }
            .filter { !$0.isEmpty && $0.allSatisfy(\.isNumber) }
    }

    // MARK: `ykman info`

    /// Format, from the published CLI guide:
    ///
    ///     Device type: YubiKey 5Ci FIPS
    ///     Serial number: 31234067
    ///     Firmware version: 5.7.3
    ///     Form factor: Keychain (USB-C, Lightning)
    ///     Enabled USB interfaces: OTP, FIDO, CCID
    ///
    /// followed by an "Applications" block listing each applet and its state. The
    /// five header lines above are VERIFIED against Yubico's documentation and are
    /// what any decision is taken on. The Applications block's exact column
    /// spacing is NOT verified here, so it is parsed leniently — any indented
    /// "name<gap>status" line — and nothing important depends on it.
    static func parseInfo(_ stdout: String) -> SecurityKeyInfo {
        var info = SecurityKeyInfo()
        var inApplications = false
        for rawLine in stdout.split(whereSeparator: \.isNewline) {
            let line = String(rawLine)
            let trimmed = line.trimmingCharacters(in: .whitespaces)
            if trimmed.isEmpty { continue }

            if trimmed.lowercased().hasPrefix("applications") {
                inApplications = true
                continue
            }

            // A header line is unindented and has a "Key: value" shape.
            let isIndented = line.first == " " || line.first == "\t"
            if !isIndented, let colon = trimmed.firstIndex(of: ":") {
                inApplications = false
                let key = trimmed[trimmed.startIndex..<colon].lowercased()
                let value = trimmed[trimmed.index(after: colon)...]
                    .trimmingCharacters(in: .whitespaces)
                switch key {
                case "device type": info.deviceType = value
                case "serial number": info.serial = value
                case "firmware version": info.firmware = value
                case "form factor": info.formFactor = value
                case "enabled usb interfaces":
                    info.enabledUSBInterfaces = value.split(separator: ",")
                        .map { $0.trimmingCharacters(in: .whitespaces) }
                        .filter { !$0.isEmpty }
                default: break
                }
                continue
            }

            guard inApplications, isIndented else { continue }
            // "Yubico OTP<gap>Enabled" — split on the LAST run of two-or-more
            // spaces or a tab, so an applet name containing a single space
            // survives.
            if let (name, status) = splitOnGap(trimmed) {
                info.applications[name] = status
            }
        }
        return info
    }

    /// Split "some name        status" on the last run of ≥2 spaces or any tab.
    /// Returns nil when there is no gap to split on.
    static func splitOnGap(_ text: String) -> (String, String)? {
        let characters = Array(text)
        var index = characters.count - 1
        var gapEnd: Int?
        while index > 0 {
            if characters[index] == "\t" {
                gapEnd = index
                break
            }
            if characters[index] == " " && characters[index - 1] == " " {
                gapEnd = index
                break
            }
            index -= 1
        }
        guard var end = gapEnd else { return nil }
        // Walk back over the whole run of gap characters.
        while end > 0, characters[end - 1] == " " || characters[end - 1] == "\t" { end -= 1 }
        let name = String(characters[0..<end]).trimmingCharacters(in: .whitespaces)
        let status = String(characters[gapEnd!...]).trimmingCharacters(in: .whitespaces)
        guard !name.isEmpty, !status.isEmpty else { return nil }
        return (name, status)
    }

    // MARK: `ykman otp info`

    /// Format, from `ykman/_cli/otp.py`:
    ///
    ///     Slot 1: programmed
    ///     Slot 2: empty
    static func parseOTPSlots(_ stdout: String) -> OTPSlotStatus {
        var status = OTPSlotStatus()
        for rawLine in stdout.split(whereSeparator: \.isNewline) {
            let line = rawLine.trimmingCharacters(in: .whitespaces).lowercased()
            guard line.hasPrefix("slot "), let colon = line.firstIndex(of: ":") else { continue }
            let value = line[line.index(after: colon)...].trimmingCharacters(in: .whitespaces)
            let programmed = value == "programmed"
            if line.hasPrefix("slot 1") { status.slotOneProgrammed = programmed }
            if line.hasPrefix("slot 2") { status.slotTwoProgrammed = programmed }
        }
        return status
    }

    // MARK: `ykman oath accounts list`

    /// Format, from `ykman/_cli/oath.py`: the credential's own string id, then
    /// `", TOTP"` when `--oath-type` was asked for and `", 30"` when `--period`
    /// was. The id itself is OATH's `[period/]issuer:name`, so
    ///
    ///     Example:user@example.com, TOTP, 30
    ///     15/Short:period@example.com, TOTP, 15
    ///     Bank:me, HOTP
    ///
    /// The id is kept VERBATIM, because it is what goes back as a query.
    static func parseAccounts(_ stdout: String) -> [OATHAccount] {
        stdout.split(whereSeparator: \.isNewline).compactMap { rawLine in
            let line = rawLine.trimmingCharacters(in: .whitespaces)
            guard !line.isEmpty else { return nil }
            // Only the trailing metadata is comma-separated; an account NAME may
            // itself contain commas, so split from the right and only for tokens
            // that look like metadata.
            var id = line
            var kind: OATHAccount.Kind?
            var period: Int?
            var changed = true
            while changed {
                changed = false
                guard let comma = id.range(of: ",", options: .backwards) else { break }
                let tail = id[comma.upperBound...].trimmingCharacters(in: .whitespaces)
                if let matched = OATHAccount.Kind(rawValue: tail.uppercased()) {
                    kind = matched
                    id = String(id[id.startIndex..<comma.lowerBound])
                    changed = true
                } else if let seconds = Int(tail), seconds > 0, seconds <= 3600 {
                    period = seconds
                    id = String(id[id.startIndex..<comma.lowerBound])
                    changed = true
                }
            }
            let (issuer, name) = splitCredentialID(id)
            return OATHAccount(id: id, issuer: issuer, name: name, kind: kind, period: period)
        }
    }

    /// OATH credential ids are `[period/]issuer:name`. A leading "<digits>/" is the
    /// period prefix non-30-second credentials carry; the FIRST colon separates
    /// issuer from name (a name may contain colons — an email address doesn't, but
    /// a URL does).
    static func splitCredentialID(_ id: String) -> (issuer: String?, name: String) {
        var rest = Substring(id)
        if let slash = rest.firstIndex(of: "/") {
            let prefix = rest[rest.startIndex..<slash]
            if !prefix.isEmpty, prefix.allSatisfy(\.isNumber) {
                rest = rest[rest.index(after: slash)...]
            }
        }
        guard let colon = rest.firstIndex(of: ":") else { return (nil, String(rest)) }
        let issuer = String(rest[rest.startIndex..<colon])
        let name = String(rest[rest.index(after: colon)...])
        return (issuer.isEmpty ? nil : issuer, name)
    }

    // MARK: `ykman oath accounts code`

    /// Format, from `ykman/_cli/oath.py`. With several matches the columns are
    /// padded to the longest value — `"{:<name}  {:>code}"` — so the separator is
    /// a run of two or more spaces and the code is right-aligned:
    ///
    ///     Example:user@example.com    123456
    ///     Bank:me                     [HOTP Account]
    ///     Touchy:me                   [Requires Touch]
    ///
    /// With `--single` only the code is printed, which `parseSingleCode` handles.
    static func parseCodes(_ stdout: String) -> [OATHCodeLine] {
        stdout.split(whereSeparator: \.isNewline).compactMap { rawLine in
            let line = rawLine.trimmingCharacters(in: .whitespaces)
            guard !line.isEmpty, let (id, tail) = splitOnGap(line) else { return nil }
            switch tail {
            case "[Requires Touch]":
                return OATHCodeLine(accountID: id, code: nil, marker: .requiresTouch)
            case "[HOTP Account]":
                return OATHCodeLine(accountID: id, code: nil, marker: .hotpAccount)
            default:
                guard isCodeShaped(tail) else { return nil }
                return OATHCodeLine(accountID: id, code: tail, marker: nil)
            }
        }
    }

    /// `ykman oath accounts code --single`: the code, alone, on one line.
    ///
    /// Deliberately strict — this value goes to a gateway, and a stray banner line
    /// silently accepted as a "code" would burn an authentication attempt. Digits
    /// only, and a length OATH actually produces.
    static func parseSingleCode(_ stdout: String) -> String? {
        let lines = stdout.split(whereSeparator: \.isNewline)
            .map { $0.trimmingCharacters(in: .whitespaces) }
            .filter { !$0.isEmpty }
        guard let last = lines.last, isCodeShaped(last) else { return nil }
        return last
    }

    /// OATH codes are 6, 7 or 8 digits (RFC 4226 allows 6–8; `ykman` offers 6 and
    /// 8). Leading zeros are significant, so this stays a string throughout.
    static func isCodeShaped(_ text: String) -> Bool {
        (6...8).contains(text.count) && text.allSatisfy(\.isNumber)
    }

    // MARK: `ykman otp calculate`

    /// Format, from `ykman/_cli/otp.py`: without `--totp` the response is printed
    /// as `response.hex()` — lowercase hex, and HMAC-SHA1 is always 20 bytes, so
    /// exactly 40 characters. With `--totp` it is a 6- or 8-digit code instead.
    static func parseChallengeResponse(_ stdout: String) -> Data? {
        let line = stdout.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        guard line.count == 40, line.allSatisfy({ $0.isHexDigit }) else { return nil }
        var out = Data(capacity: 20)
        var index = line.startIndex
        while index < line.endIndex {
            let next = line.index(index, offsetBy: 2)
            guard let byte = UInt8(line[index..<next], radix: 16) else { return nil }
            out.append(byte)
            index = next
        }
        return out
    }

    // MARK: Classifying a failure

    /// Turn a failed run into something with a remedy. `ykman`'s messages are not
    /// a stable API, so this matches on SUBSTRINGS and falls through to the raw
    /// (already scrubbed) detail rather than pretending to understand everything.
    static func classify(_ result: LocalToolResult) -> YubiKeyToolError {
        if result.stderr == "not installed" { return .toolMissing }
        if result.timedOut { return .touchTimedOut }
        let text = result.stderr.lowercased()
        if text.contains("no yubikey found") || text.contains("no device found")
            || text.contains("failed connecting to a yubikey") {
            return .noKeyAttached
        }
        if text.contains("multiple yubikeys") || text.contains("multiple devices") {
            return .severalKeysAttached
        }
        if text.contains("password") { return .oathPasswordRequired }
        if text.contains("not supported") || text.contains("not enabled")
            || text.contains("applet") {
            return .appletDisabled("code")
        }
        if text.contains("no matching") || text.contains("no accounts") {
            return .noSuchAccount("")
        }
        if text.contains("multiple matches") || text.contains("single match") {
            return .severalAccountsMatched("")
        }
        return .failed(detail: result.stderr)
    }
}

// MARK: - Which slot

nonisolated enum YubiKeySlot: Int, Sendable, CaseIterable, Codable {
    case one = 1
    case two = 2

    /// What the key does to reach each slot, in the words Yubico uses.
    var touchDescription: String {
        switch self {
        case .one: "a short touch"
        case .two: "a long touch \u{2014} hold for about three seconds"
        }
    }

    /// How it reads on screen. "Slot 1" is Yubico's own label and appears on their
    /// configuration tools, so it is kept rather than translated.
    var displayName: String { "Slot \(rawValue)" }
}

// MARK: - The operations

/// The `ykman`-backed operations, each a thin wrapper over a parser. Kept
/// separate from the parsers so the parsers stay pure and the operations stay
/// trivial — there is no logic here worth testing that isn't already covered by
/// a parser test plus a stub runner.
nonisolated struct YubiKeyManagerTool: Sendable {

    private static let log = Logger(subsystem: "com.bragi0.SimpleVPN", category: "security-key")

    var runner: any YubiKeyToolRunning = YkmanRunner()

    var isInstalled: Bool { runner.locate() != nil }

    /// Every key `ykman` can see.
    func list() async throws -> [ListedSecurityKey] {
        let result = await runner.run(["list"])
        guard result.succeeded else { throw YkmanOutput.classify(result) }
        return YkmanOutput.parseList(result.text)
    }

    /// `ykman info` for the attached key, or for one named by serial.
    func info(serial: String? = nil) async throws -> SecurityKeyInfo {
        // A serial number is not a secret — it is printed on the key and quoted to
        // administrators — so it may ride argv.
        let result = await runner.run(deviceArguments(serial: serial) + ["info"])
        guard result.succeeded else { throw YkmanOutput.classify(result) }
        return YkmanOutput.parseInfo(result.text)
    }

    /// Which OTP slots hold a credential — the answer to "can this key do
    /// challenge-response yet?".
    func otpSlots(serial: String? = nil) async throws -> OTPSlotStatus {
        let result = await runner.run(deviceArguments(serial: serial) + ["otp", "info"])
        guard result.succeeded else { throw YkmanOutput.classify(result) }
        return YkmanOutput.parseOTPSlots(result.text)
    }

    /// The key's OATH accounts, with their type and period, for a picker.
    func oathAccounts(serial: String? = nil) async throws -> [OATHAccount] {
        // `--oath-type` and `--period` so the picker can say which accounts need a
        // touch and which are counter-based, instead of finding out at connect time.
        let result = await runner.run(
            deviceArguments(serial: serial) + ["oath", "accounts", "list", "--oath-type", "--period"])
        guard result.succeeded else { throw YkmanOutput.classify(result) }
        var accounts = YkmanOutput.parseAccounts(result.text)
        // Touch-required accounts are only visible in the CODE listing, where they
        // print a marker instead of a code. A best-effort second call fills that
        // in; failing it must not fail the list, so a touch-required account is
        // simply not flagged rather than the picker being empty.
        if let markers = try? await touchRequiredAccountIDs(serial: serial) {
            for index in accounts.indices where markers.contains(accounts[index].id) {
                accounts[index].requiresTouch = true
            }
        }
        return accounts
    }

    /// Which accounts print `[Requires Touch]` rather than a code. This is a
    /// listing call: it does NOT step an HOTP counter and does not consume
    /// anything, because `ykman` deliberately prints a marker for those too.
    func touchRequiredAccountIDs(serial: String? = nil) async throws -> Set<String> {
        let result = await runner.run(deviceArguments(serial: serial) + ["oath", "accounts", "code"])
        guard result.succeeded else { throw YkmanOutput.classify(result) }
        return Set(YkmanOutput.parseCodes(result.text)
            .filter { $0.marker == .requiresTouch }
            .map(\.accountID))
    }

    /// A code for ONE account, in a box that opens once.
    ///
    /// `--single` always, never a batch read, and that is a correctness
    /// requirement rather than tidiness: `ykman` refuses to produce a code for an
    /// HOTP or touch-required account without it, and an HOTP code is
    /// counter-stepping — reading it in a batch would burn every account's counter
    /// to fetch one.
    ///
    /// The account NAME rides argv. That is not a secret: it is a label like
    /// "Example:me@example.com", the same class of value as a Keeper record path,
    /// and the seam explicitly sanctions record names in argv. The CODE comes back
    /// on stdout and goes straight into a `SingleUseCode`.
    func oathCode(account: String, serial: String? = nil,
                  requiresTouch: Bool = false) async throws -> SingleUseCode {
        let query = account.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !query.isEmpty else { throw YubiKeyToolError.noSuchAccount("") }
        let result = await runner.run(
            deviceArguments(serial: serial) + ["oath", "accounts", "code", "--single", query],
            deadline: requiresTouch ? YkmanRunner.touchDeadline : YkmanRunner.defaultDeadline)
        guard result.succeeded else {
            var error = YkmanOutput.classify(result)
            // Put the query back into the two errors that read badly without it.
            if error == .noSuchAccount("") { error = .noSuchAccount(query) }
            if error == .severalAccountsMatched("") { error = .severalAccountsMatched(query) }
            throw error
        }
        guard let code = YkmanOutput.parseSingleCode(result.text) else {
            throw YubiKeyToolError.unreadableOutput
        }
        // Never the code, never the account — only that one happened.
        Self.log.log("security key: fetched a verification code")
        // An OATH code is TIME-BOUNDED as well as single-use, and the box enforces
        // both. The expiry is deliberately conservative: `ykman` does not report how
        // much of the window is left, so we assume the WORST case (the code was
        // produced at the very end of its period) rather than the best. Sending a
        // code that has just rolled over gets a rejection the user cannot explain;
        // "it ran out, get another" is a far better thing to be told.
        //
        // 30 s is OATH's default period. A non-default period is a per-account fact
        // we would have to have read from `accounts list --period`; where we have
        // not, this stays the safe assumption.
        let window = TimeInterval(OATHAccount.defaultPeriod)
        return SingleUseCode(code, origin: .computedByDevice,
                             expiresAt: Date().addingTimeInterval(window))
    }

    /// `--device <serial>` when we know which key to use. Empty otherwise, which
    /// lets `ykman` pick the only attached key and fail loudly when there are two.
    private func deviceArguments(serial: String?) -> [String] {
        guard let serial = serial?.trimmingCharacters(in: .whitespaces), !serial.isEmpty,
              serial.allSatisfy(\.isNumber) else { return [] }
        return ["--device", serial]
    }
}
