// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
//  PKCS11.swift
//  Hardware-backed certificate sign-in: the value types for a PKCS#11 provider
//  module, the tokens and certificates on it, and the RFC 7512 URI that names one.
//
//  WHY THIS IS A VALUE-TYPE FILE AND NOT A LOADER. A PKCS#11 provider module is a
//  third-party dylib (`libykcs11.dylib`, `opensc-pkcs11.so`) that the USER installs.
//  Neither the app nor the packet-tunnel extension can `dlopen` one: both run under
//  the hardened runtime, and the library-validation relaxation that would allow a
//  foreign dylib is the single relaxation AMFI forbids on a system-extension-embedding
//  app (AGENTS.md — it is why `opnative-helper` is a separate process at all). So
//  SimpleVPN never loads a module: it names one, and the `openconnect` tool the user
//  installed does the loading. Enumeration goes through the user's own PKCS#11 tools
//  (`p11tool`, `pkcs11-tool`) — see ControlPlane/PKCS11Discovery.swift.
//
//  THE PIN IS NEVER IN THIS FILE, in any form. `PKCS11URI` actively REFUSES a URI
//  carrying `pin-value=` or `pin-source=` (RFC 7512 allows both; blogs are full of
//  them) because a URI is handed to openconnect on its command line, where any local
//  process reads it with `ps`. The PIN rides the tool's stdin instead — see
//  `SubprocessTunnelManager.openconnectArgs`.
//

import Foundation

// MARK: - The URI (RFC 7512)

/// A parsed `pkcs11:` URI. Attribute ORDER is preserved: the URI a user pasted is
/// the URI we hand the tool, so a round-trip never silently rewrites their value.
nonisolated struct PKCS11URI: Equatable, Sendable {

    /// Path attributes (`;`-separated), in the order they appeared.
    var path: [(key: String, value: String)]
    /// Query attributes (`?`/`&`-separated), in the order they appeared.
    var query: [(key: String, value: String)]

    static func == (a: PKCS11URI, b: PKCS11URI) -> Bool {
        a.path.map { [$0.key, $0.value] } == b.path.map { [$0.key, $0.value] }
            && a.query.map { [$0.key, $0.value] } == b.query.map { [$0.key, $0.value] }
    }

    /// Path attributes RFC 7512 defines, plus the deprecated `object-type` alias for
    /// `type` (which is what OpenConnect's own documentation still prints, while
    /// GnuTLS 3.8's `p11tool` emits `type`). Both are accepted; neither is rewritten.
    static let pathKeys: Set<String> = [
        "id", "library-description", "library-manufacturer", "library-version",
        "manufacturer", "model", "object", "object-type", "serial",
        "slot-description", "slot-id", "slot-manufacturer", "token", "type",
    ]
    /// Query attributes RFC 7512 defines. `pin-value` and `pin-source` are listed
    /// here so they can be REFUSED by name with a useful reason rather than as an
    /// anonymous "unknown attribute".
    static let queryKeys: Set<String> = [
        "module-name", "module-path", "pin-source", "pin-value",
    ]
    /// What `type=` may be.
    static let objectTypes: Set<String> = ["cert", "private", "public", "secret-key", "data"]

    /// The value of a path attribute (checking `type`/`object-type` as one key).
    func value(_ key: String) -> String? {
        if key == "type" {
            return path.first { $0.key == "type" || $0.key == "object-type" }?.value
        }
        return path.first { $0.key == key }?.value
    }

    /// `cert` / `private` / … or nil when the URI doesn't name one.
    var objectType: String? { value("type") }

    /// The URI text, rebuilt from the parsed parts. Query attributes are DROPPED:
    /// the only ones anyone puts there are the two PIN attributes we refuse, and a
    /// `module-path` would fight the module the user picked in the editor.
    var withoutQuery: String {
        "pkcs11:" + path.map { "\($0.key)=\($0.value)" }.joined(separator: ";")
    }

    /// The same URI narrowed to the TOKEN — everything that identifies the device,
    /// nothing that identifies an object on it. This is what `p11tool --list-…`
    /// takes, and what a "which token is this?" status query addresses.
    var tokenScope: String {
        let keys: Set<String> = ["model", "manufacturer", "serial", "token",
                                 "slot-id", "slot-description", "slot-manufacturer",
                                 "library-description", "library-manufacturer", "library-version"]
        let kept = path.filter { keys.contains($0.key) }
        guard !kept.isEmpty else { return "pkcs11:" }
        return "pkcs11:" + kept.map { "\($0.key)=\($0.value)" }.joined(separator: ";")
    }

    /// Human-friendly: the token label, percent-decoding undone.
    var tokenLabel: String? { value("token").map(Self.percentDecoded) }
    /// Human-friendly: the object label.
    var objectLabel: String? { value("object").map(Self.percentDecoded) }

    // MARK: Parsing

    /// Parse, or nil when `problem(_:)` would return a reason. The two are one
    /// implementation so the editor's inline error and the argv builder can never
    /// disagree about what a valid URI is.
    static func parse(_ raw: String) -> PKCS11URI? {
        parsed(raw).uri
    }

    /// Why this isn't a PKCS#11 URI OpenConnect would accept, or nil. BLOCKING in
    /// the editor (the `serverCertPinProblem` precedent): a malformed URI is not a
    /// warning but a connection that always fails, complaining about a certificate
    /// a long way from the character that was wrong.
    static func problem(_ raw: String) -> String? {
        parsed(raw).problem
    }

    private static func parsed(_ raw: String) -> (uri: PKCS11URI?, problem: String?) {
        let text = raw.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !text.isEmpty else {
            return (nil, "Enter the PKCS#11 URI of the certificate on your token — it starts with \u{201C}pkcs11:\u{201D}.")
        }
        guard text.lowercased().hasPrefix("pkcs11:") else {
            return (nil, "A PKCS#11 URI starts with \u{201C}pkcs11:\u{201D} \u{2014} for example pkcs11:id=%01. Use \u{201C}Find Certificates\u{201D} to read one off the token.")
        }
        var body = String(text.dropFirst("pkcs11:".count))
        var queryText = ""
        if let mark = body.firstIndex(of: "?") {
            queryText = String(body[body.index(after: mark)...])
            body = String(body[..<mark])
        }

        var path: [(key: String, value: String)] = []
        for segment in body.split(separator: ";", omittingEmptySubsequences: true) {
            let piece = String(segment)
            guard let eq = piece.firstIndex(of: "=") else {
                return (nil, "\u{201C}\(piece)\u{201D} isn't a PKCS#11 attribute \u{2014} each part is name=value, separated by semicolons.")
            }
            let key = String(piece[..<eq]).lowercased()
            let value = String(piece[piece.index(after: eq)...])
            guard !key.isEmpty else {
                return (nil, "One of the attributes has no name before its \u{201C}=\u{201D}.")
            }
            guard pathKeys.contains(key) || key.hasPrefix("x-") else {
                return (nil, "\u{201C}\(key)\u{201D} isn't a PKCS#11 attribute. The ones that identify a certificate are id, object, token, serial, model, manufacturer and type.")
            }
            if let bad = percentProblem(value) { return (nil, bad) }
            path.append((key, value))
        }
        guard !path.isEmpty else {
            return (nil, "This URI names nothing \u{2014} add at least one attribute, such as id=%01 or object=Certificate%20for%20PIV%20Authentication.")
        }
        if let type = path.first(where: { $0.key == "type" || $0.key == "object-type" })?.value,
           !objectTypes.contains(type.lowercased()) {
            return (nil, "\u{201C}type=\(type)\u{201D} isn't a kind of PKCS#11 object. For a certificate it is type=cert; for its key, type=private.")
        }

        var query: [(key: String, value: String)] = []
        for segment in queryText.split(separator: "&", omittingEmptySubsequences: true) {
            let piece = String(segment)
            guard let eq = piece.firstIndex(of: "=") else {
                return (nil, "\u{201C}\(piece)\u{201D} after the \u{201C}?\u{201D} isn't a PKCS#11 attribute \u{2014} each part is name=value.")
            }
            let key = String(piece[..<eq]).lowercased()
            let value = String(piece[piece.index(after: eq)...])
            // THE PIN RULE, enforced where it can be explained. A URI is handed to
            // openconnect on its command line, and every local process can read a
            // command line. Refusing this is why SimpleVPN can promise the PIN is
            // never `ps`-visible.
            if key == "pin-value" || key == "pin-source" {
                return (nil, "Take \u{201C}\(key)\u{201D} out of the URI. SimpleVPN types the PIN into the tool privately; anything in the URI would be visible to every program running on this Mac.")
            }
            guard queryKeys.contains(key) || key.hasPrefix("x-") else {
                return (nil, "\u{201C}\(key)\u{201D} isn't a PKCS#11 URI option.")
            }
            if let bad = percentProblem(value) { return (nil, bad) }
            query.append((key, value))
        }
        return (PKCS11URI(path: path, query: query), nil)
    }

    /// RFC 7512 values are percent-encoded; a stray `%` is the commonest paste
    /// error (a URI copied out of a terminal that wrapped, or one hand-typed with a
    /// literal space).
    private static func percentProblem(_ value: String) -> String? {
        let chars = Array(value)
        var i = 0
        while i < chars.count {
            if chars[i] == "%" {
                guard i + 2 < chars.count, chars[i + 1].isHexDigit, chars[i + 2].isHexDigit else {
                    return "\u{201C}\(value)\u{201D} has a \u{201C}%\u{201D} that isn't followed by two digits. Spaces are written %20 in a PKCS#11 URI."
                }
                i += 3
            } else if chars[i] == " " {
                return "\u{201C}\(value)\u{201D} contains a space. Write it as %20 \u{2014} or use \u{201C}Find Certificates\u{201D}, which quotes it for you."
            } else {
                i += 1
            }
        }
        return nil
    }

    static func percentDecoded(_ value: String) -> String {
        value.replacingOccurrences(of: "+", with: "%2B").removingPercentEncoding ?? value
    }
}

// MARK: - The provider module

/// One PKCS#11 provider module found on this Mac (or named by the user).
nonisolated struct PKCS11Module: Equatable, Sendable, Identifiable, Hashable {

    /// Where a module came from — decides how it is described, and nothing else.
    /// A user-supplied path is never demoted for being unrecognised.
    enum Origin: String, Equatable, Sendable, Hashable {
        case openSC          // OpenSC — smartcards, and YubiKey PIV via CCID
        case yubiKey         // Yubico's own YKCS11
        case softHSM         // SoftHSM — a software token, used for testing
        case p11KitRegistered  // declared in a p11-kit .module file
        case userSupplied    // an absolute path the user typed
        case other
    }

    var path: String
    var origin: Origin
    /// The label a `.module` file declared, when there was one.
    var declaredName: String?
    /// Whether a p11-kit `.module` file declares this library.
    ///
    /// THIS IS THE LOAD-BEARING FIELD, and it took measuring to find out. OpenConnect
    /// has no "use this module" option: it resolves a `pkcs11:` URI through p11-kit,
    /// which only loads modules the registry declares. RFC 7512's `module-path=`
    /// query attribute does NOT fill the gap — p11-kit knows the attribute but
    /// GnuTLS's URI path ignores it (verified: `p11tool` finds nothing for a
    /// `?module-path=…` URI, and finds the token immediately once a `.module` file
    /// exists). So an installed-but-unregistered module can be enumerated by us
    /// (we pass `--provider <path>` explicitly) and still be invisible to the tool
    /// that has to sign in with it. The editor says so, and offers the one command
    /// that fixes it.
    var registeredWithP11Kit = false

    var id: String { path }

    /// What the picker shows: the product, then the file, so two builds of the same
    /// provider are told apart.
    var displayName: String {
        let file = (path as NSString).lastPathComponent
        if let declaredName, !declaredName.isEmpty { return "\(declaredName) — \(file)" }
        switch origin {
        case .openSC: return "OpenSC — \(file)"
        case .yubiKey: return "YubiKey (YKCS11) — \(file)"
        case .softHSM: return "SoftHSM (software token) — \(file)"
        case .p11KitRegistered, .userSupplied, .other: return file
        }
    }

    /// One sentence about what this module talks to, for the row's summary.
    var summary: String {
        switch origin {
        case .openSC:
            "OpenSC: PIV and CAC smartcards, including a YubiKey used over the card reader."
        case .yubiKey:
            "Yubico's own module for YubiKey PIV — use it when OpenSC doesn't see the key."
        case .softHSM:
            "A software token. Useful for testing a setup without a physical device."
        case .p11KitRegistered:
            "Registered on this Mac as a PKCS#11 provider."
        case .userSupplied:
            "A provider module you named yourself."
        case .other:
            "A PKCS#11 provider module found on this Mac."
        }
    }

    /// A short, stable filename for this module's p11-kit registration file.
    var registrationFileName: String {
        let base = (path as NSString).lastPathComponent
            .replacingOccurrences(of: ".dylib", with: "")
            .replacingOccurrences(of: ".so", with: "")
            .replacingOccurrences(of: "lib", with: "")
        let cleaned = base.isEmpty ? "provider" : base
        return "\(cleaned).module"
    }

    /// The ONE command that makes this module visible to `openconnect`, written to
    /// the per-user p11-kit directory so it needs no admin rights and touches
    /// nothing the system owns. SimpleVPN never runs it — the user does (the
    /// programme's rule: we show the command, we don't mutate anyone's config).
    var registrationCommand: String {
        "mkdir -p ~/.config/pkcs11/modules && printf 'module: \(path)\\n' > ~/.config/pkcs11/modules/\(registrationFileName)"
    }

    /// Why this path can't be used as a provider module, or nil. Non-blocking in
    /// the editor (`missingFileWarning`'s rule): the file may be installed between
    /// now and the next connect, and a removable-volume path may be remounted.
    static func pathWarning(_ raw: String) -> String? {
        let p = raw.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !p.isEmpty else { return nil }
        guard p.hasPrefix("/") || p.hasPrefix("~") else {
            return "Give the full path to the module, starting with \u{201C}/\u{201D} \u{2014} a bare name would let whatever is first on the search path decide which library is loaded."
        }
        let expanded = (p as NSString).expandingTildeInPath
        var isDir: ObjCBool = false
        guard FileManager.default.fileExists(atPath: expanded, isDirectory: &isDir) else {
            return "No file at that path."
        }
        if isDir.boolValue { return "That's a folder. Point at the module file itself (it ends in .so or .dylib)." }
        let ext = (expanded as NSString).pathExtension.lowercased()
        guard ext == "so" || ext == "dylib" else {
            return "A PKCS#11 provider module is a library file ending in .so or .dylib."
        }
        return nil
    }
}

// MARK: - Token and certificate

/// A token's login state, as reported by the user's PKCS#11 tools. Every field is
/// Optional-ish on purpose: a tool that doesn't report a fact must not be allowed to
/// imply the safe-sounding answer.
nonisolated struct PKCS11TokenStatus: Equatable, Sendable {
    var label: String = ""
    var uri: String = ""
    /// The provider module this token came through, when the tool named it
    /// (`p11tool --list-tokens` prints a `Module:` line).
    var modulePath: String?
    var isHardware = false
    var requiresLogin = false
    /// The token itself says the PIN retry counter is down. THE anti-bricking
    /// signal: exhausting a YubiKey PIV PIN destroys the key material.
    var pinCountLow = false
    /// One attempt left. After this the token locks.
    var pinFinalTry = false
    var pinLocked = false
    var pinUninitialized = false
    /// Exact attempts remaining, when a tool reports a number rather than a flag.
    var triesLeft: Int?

    /// The warning to show BEFORE a connect is attempted, or nil. Ordered
    /// worst-first: locked, then final try, then low.
    var pinWarning: String? {
        if pinLocked {
            return "This token's PIN is locked. Unblock it with your PUK using the manufacturer's tool before connecting — SimpleVPN can't, and further attempts do nothing."
        }
        if pinFinalTry || triesLeft == 1 {
            return "One PIN attempt left on this token. A wrong PIN now locks it, and on a YubiKey that destroys the key it protects — be certain before connecting."
        }
        if pinCountLow {
            let count = triesLeft.map { "\($0) attempts" } ?? "only a few attempts"
            return "This token reports \(count) left before it locks. Getting the PIN wrong again may destroy the key it protects."
        }
        if let triesLeft, triesLeft <= 2 {
            return "This token reports \(triesLeft) PIN attempts left before it locks."
        }
        return nil
    }

    /// Whether connecting should be refused outright rather than warned about.
    var isBlocked: Bool { pinLocked || pinUninitialized }
}

/// One certificate on a token, as a row a user can pick.
nonisolated struct PKCS11Certificate: Equatable, Sendable, Identifiable {
    var label: String = ""
    /// The `id=` attribute's raw (percent-encoded) value, e.g. `%01`.
    var objectID: String = ""
    var uri: String = ""
    /// The certificate's subject, when a tool that reads it is installed.
    var subject: String?
    var expires: Date?
    /// e.g. "RSA-2048" / "EC/SECP384R1".
    var keySummary: String?

    var id: String { uri }

    var isExpired: Bool {
        guard let expires else { return false }
        return expires < Date()
    }

    /// The one-line description the picker shows. Never "nil" or an empty gap: a
    /// row that says nothing is worse than a row that says what little is known.
    func rowSummary(now: Date = Date(), calendar: Calendar = .current) -> String {
        var parts: [String] = []
        if let subject, !subject.isEmpty { parts.append(subject) }
        if let keySummary, !keySummary.isEmpty { parts.append(keySummary) }
        if let expires {
            let day = expires.formatted(.dateTime.year().month().day())
            if expires < now {
                parts.append("expired \(day)")
            } else if let days = calendar.dateComponents([.day], from: now, to: expires).day, days <= 30 {
                parts.append("expires \(day) — in \(days) day\(days == 1 ? "" : "s")")
            } else {
                parts.append("valid until \(day)")
            }
        }
        if !objectID.isEmpty { parts.append("id \(objectID)") }
        return parts.isEmpty ? "No details reported by the token." : parts.joined(separator: " · ")
    }
}

// MARK: - Failure modes

/// The distinct ways token sign-in fails, each with the ONE thing to do about it.
/// A single "smartcard error" is what this enum exists to prevent: "no module
/// installed" and "wrong PIN" have nothing in common except that both stop the
/// connection.
nonisolated enum PKCS11Failure: Equatable, Sendable, Error {
    case noModuleInstalled
    case moduleUnusable(path: String)
    case noTokenPresent(module: String)
    case certificateNotFound
    case keyNotFound
    case pinRequired
    case pinWrong(remaining: PKCS11TokenStatus?)
    case pinLocked
    case certificateExpired(when: String?)
    case serverRejectedCertificate
    case toolLacksPKCS11Support

    /// The sentence shown to the user. It names what happened and what to do —
    /// never an errno, never a library's own wording.
    var message: String {
        switch self {
        case .noModuleInstalled:
            "No PKCS#11 provider module is installed, so there is nothing to read the token with. Install OpenSC (for smartcards and YubiKey PIV) or Yubico's YKCS11, then pick it under Sign-In."
        case .moduleUnusable(let path):
            "The provider module at \(path) couldn't be loaded. Check the path is still right — and that the module matches this Mac's architecture."
        case .noTokenPresent(let module):
            "No token is inserted. \(module) is installed and working — plug the card or security key in and try again."
        case .certificateNotFound:
            "The token is there, but it holds no certificate matching that URI. Use \u{201C}Find Certificates\u{201D} to pick one from the token instead of typing it."
        case .keyNotFound:
            "The certificate was found but its private key wasn't. Set the key's own PKCS#11 URI under Sign-In — some tokens label the key differently from the certificate."
        case .pinRequired:
            "The token needs its PIN. Enter it and connect again."
        case .pinWrong(let status):
            if let warning = status?.pinWarning {
                "That PIN was refused. \(warning)"
            } else {
                "That PIN was refused by the token. Check it before trying again — tokens lock after a few wrong attempts."
            }
        case .pinLocked:
            "This token's PIN is locked after too many wrong attempts. Unblock it with your PUK using the manufacturer's tool; SimpleVPN can't reset it."
        case .certificateExpired(let when):
            if let when {
                "The certificate on the token expired on \(when). Ask whoever issued it for a new one — the gateway will refuse this."
            } else {
                "The certificate on the token has expired. Ask whoever issued it for a new one — the gateway will refuse this."
            }
        case .serverRejectedCertificate:
            "The token's certificate was read correctly, but the VPN server refused it. Check with your administrator that this certificate is enrolled for VPN access, and that you picked the right one of the certificates on the token."
        case .toolLacksPKCS11Support:
            "The installed openconnect was built without smartcard support, so it can't use a token. Reinstall it with Homebrew (brew reinstall openconnect), which builds it with GnuTLS and p11-kit."
        }
    }
}
