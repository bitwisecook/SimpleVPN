// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
//  SecretScrubber.swift
//  THE redactor. One implementation, four policies.
//
//  Before this file there were three: `DiagnosticBundle.Scrubber` (bundle text),
//  `UserFacingError.redact` (error details) and `ProbeEvidence.sanitise` (probe
//  evidence, which already delegated to the second). Three redactors means three
//  different answers to "is a Tailscale auth key a secret?", and the one that
//  hasn't heard of a secret shape is the one your log line goes through. So:
//  every rule lives here, and the callers pick a POLICY rather than owning rules.
//
//  READ THIS BEFORE TRUSTING IT. Scrubbing arbitrary text is a BLACKLIST, and a
//  blacklist eventually loses — here a loss is a credential. It is therefore
//  never the primary control anywhere in this app:
//
//   • The diagnostic report (`DiagnosticReport`) is assembled from an ALLOW-LIST
//     of structured facts. Nothing free-form reaches it except the two things the
//     user typed into the dialog and the captures of allow-listed log events.
//     The scrubber runs over those as defence in depth.
//   • The debug bundle (`DiagnosticBundle`) is free-form by nature — which is
//     exactly why it is shown to the user verbatim before it can leave, why the
//     "full" variant is a separate labelled choice, and why the sheet says
//     scrubbing is best-effort.
//
//  Two invariants worth keeping:
//   • Same value ⇒ same placeholder within one report, because "that host again"
//     is diagnostically load-bearing. The salt is per-report, so placeholders
//     cannot be correlated across reports or reversed with a precomputed table.
//   • Placeholders are shaped `<kind:hex>` so `LogHighlighter` colours them —
//     the reviewer can SEE every place something was removed.
//

import Foundation
import CryptoKit

// MARK: - Policies

nonisolated struct SecretScrubber: Sendable {

    /// What a removed value is replaced WITH. Two shapes because two audiences:
    /// a bundle reviewer wants to see that a value was removed and be able to
    /// correlate repeats; a one-line error detail wants to stay a sentence.
    nonisolated enum Style: String, Sendable, Equatable {
        /// `<ip4-private:ab12ef>` / `<redacted>` — the report and bundle style.
        case placeholder
        /// `••••` — the error-detail style.
        case bullets
    }

    /// Which passes run. Every policy runs the secret-shape passes; they differ
    /// only in the passes that trade usefulness against caution.
    nonisolated struct Policy: Sendable, Equatable {
        var style: Style = .placeholder
        /// Bare 6–8 digit runs. A verification code looks exactly like a port,
        /// a PID or a byte count, so this is ON where the text is prose and OFF
        /// where it is machine output that would be gutted by it.
        var redactsBareNumericCodes = false
        /// Long hex/base64 runs — the catch-all for secret shapes nobody has
        /// thought of yet. OFF for error details because a SHA-256 host-key
        /// fingerprint is 64 hex characters, is PUBLIC information, and is the
        /// entire point of the host-key check.
        var redactsHighEntropyRuns = true
        /// IPv4/IPv6/MAC addresses.
        var redactsAddresses = true
        /// Hostnames and FQDNs.
        var redactsHostnames = true
        /// `/Users/<me>/…` → `~/…`, so a path stays readable without naming the
        /// account. Applied before the literal pass, which would otherwise turn
        /// the same path into an opaque token.
        var normalisesHomeDirectory = true
        /// Hard cap, applied last.
        var maximumLength: Int?

        /// The diagnostic report: maximal caution. Free text here is either the
        /// user's own two answers or a captured fragment of an allow-listed log
        /// event, and neither is worth a nasty surprise.
        static let report = Policy(style: .placeholder,
                                   redactsBareNumericCodes: true,
                                   redactsHighEntropyRuns: true,
                                   redactsAddresses: true,
                                   redactsHostnames: true,
                                   normalisesHomeDirectory: true,
                                   maximumLength: 4000)

        /// A filesystem path in the report. Addresses and hostnames are OFF: a
        /// path's last label looks like a TLD often enough
        /// (`opensc-pkcs11.so`, `libykcs11.dylib`) that the hostname pass would
        /// turn the single most useful fact in the tool inventory into
        /// `<host:ab12ef>`. High-entropy runs are OFF for the same reason.
        static let path = Policy(style: .placeholder,
                                 redactsBareNumericCodes: false,
                                 redactsHighEntropyRuns: false,
                                 redactsAddresses: false,
                                 redactsHostnames: false,
                                 normalisesHomeDirectory: true,
                                 maximumLength: 400)

        /// The scrubbed debug bundle: machine output, so numbers stay.
        static let logBundle = Policy(style: .placeholder,
                                      redactsBareNumericCodes: false,
                                      redactsHighEntropyRuns: true,
                                      redactsAddresses: true,
                                      redactsHostnames: true,
                                      normalisesHomeDirectory: false,
                                      maximumLength: nil)

        /// `UserFacingError.technicalDetail`. Addresses stay (an error about a
        /// server is useless without it), fingerprints stay, and the result is
        /// one bounded sentence.
        static let errorDetail = Policy(style: .bullets,
                                        redactsBareNumericCodes: true,
                                        redactsHighEntropyRuns: false,
                                        redactsAddresses: false,
                                        redactsHostnames: false,
                                        normalisesHomeDirectory: false,
                                        maximumLength: 2000)
    }

    var policy: Policy
    /// Values known to be secret or identifying for THIS machine: the login name,
    /// the computer name, configured usernames, a live typed password.
    var literalSecrets: [String]
    /// Used by `normalisesHomeDirectory`.
    var homeDirectory: String
    /// Per-report salt. Placeholders are stable inside one report and meaningless
    /// outside it.
    let salt: String

    init(policy: Policy,
         literalSecrets: [String] = [],
         homeDirectory: String = FileManager.default.homeDirectoryForCurrentUser.path,
         salt: String = UUID().uuidString) {
        self.policy = policy
        self.literalSecrets = literalSecrets
        self.homeDirectory = homeDirectory
        self.salt = salt
    }

    // MARK: The pipeline

    /// Order is load-bearing. Whole blocks first (a PEM body is base64 and would
    /// otherwise be minced into a dozen tokens), then values identified by their
    /// key, then values identified by their own SHAPE, then the entropy
    /// catch-all, then addresses and hostnames, and the literals right at the
    /// front so a login name inside a path or a hostname is gone before anything
    /// tokenises it.
    func scrub(_ input: String) -> String {
        var s = input
        if policy.normalisesHomeDirectory { s = normaliseHome(s) }
        s = redactLiterals(s)
        s = redactBlocks(s)
        s = redactCredentialedURLs(s)
        s = redactAuthorizationSchemes(s)
        s = redactKeychainDumps(s)
        s = redactPropertyListSecrets(s)
        s = redactKeyedValues(s)
        s = redactArgumentValues(s)
        s = redactShapedSecrets(s)
        if policy.redactsHighEntropyRuns { s = redactHighEntropyRuns(s) }
        if policy.redactsAddresses {
            s = redactIPv6(s)
            s = redactIPv4(s)
            s = redactMACs(s)
        }
        if policy.redactsHostnames { s = redactHostnames(s) }
        if policy.redactsBareNumericCodes { s = redactBareNumericCodes(s) }
        if let limit = policy.maximumLength, s.count > limit {
            s = String(s.prefix(limit)) + "\u{2026}"
        }
        return s
    }

    // MARK: Replacement vocabulary

    /// A stable, salted placeholder. Shaped for `LogHighlighter.Token.placeholder`
    /// (`<[a-z0-9]+(-[a-z0-9]+)*:[0-9a-f]+>`) so a reviewer sees it highlighted.
    ///
    /// In `.bullets` style there is nothing to correlate — a one-line error detail
    /// is a sentence, not a report — so it degrades to bullets.
    func token(_ kind: String, _ value: String) -> String {
        if policy.style == .bullets { return "\u{2022}\u{2022}\u{2022}\u{2022}" }
        let digest = SHA256.hash(data: Data((salt + value).utf8))
        let hex = digest.compactMap { String(format: "%02x", $0) }.joined().prefix(6)
        return "<\(kind):\(hex)>"
    }

    /// A value removed outright, with no need to correlate repeats.
    private var gone: String {
        policy.style == .bullets ? "\u{2022}\u{2022}\u{2022}\u{2022}" : "<redacted>"
    }

    private func goneAs(_ kind: String) -> String {
        policy.style == .bullets ? "\u{2022}\u{2022}\u{2022}\u{2022}" : "<\(kind)>"
    }

    // MARK: Regex plumbing

    private func replace(_ s: String, _ pattern: String,
                         options: NSRegularExpression.Options = [.caseInsensitive],
                         _ transform: (_ match: String, _ groups: [String?]) -> String) -> String {
        guard let re = try? NSRegularExpression(pattern: pattern, options: options) else { return s }
        let ns = s as NSString
        var result = ""
        var last = 0
        re.enumerateMatches(in: s, range: NSRange(location: 0, length: ns.length)) { m, _, _ in
            guard let m else { return }
            result += ns.substring(with: NSRange(location: last, length: m.range.location - last))
            var groups: [String?] = []
            for i in 1..<m.numberOfRanges {
                let r = m.range(at: i)
                groups.append(r.location == NSNotFound ? nil : ns.substring(with: r))
            }
            result += transform(ns.substring(with: m.range), groups)
            last = m.range.location + m.range.length
        }
        result += ns.substring(from: last)
        return result
    }

    // MARK: Passes

    private func normaliseHome(_ s: String) -> String {
        guard homeDirectory.hasPrefix("/"), homeDirectory.count > 1 else { return s }
        return s.replacingOccurrences(of: homeDirectory, with: "~")
    }

    /// Literal strings we KNOW identify this user or machine. First, deliberately:
    /// a login name is a substring of paths, hostnames and URLs, and removing it
    /// afterwards would mean removing it from inside an opaque token.
    private func redactLiterals(_ s: String) -> String {
        var out = s
        for secret in literalSecrets.sorted(by: { $0.count > $1.count }) {
            let trimmed = secret.trimmingCharacters(in: .whitespacesAndNewlines)
            // Four characters is the floor everywhere in this app: shorter and
            // every "ab" in a sentence becomes bullets. `ProbeSignInMaterial`
            // agrees with this number on purpose.
            guard trimmed.count >= 4 else { continue }
            guard let re = try? NSRegularExpression(
                pattern: NSRegularExpression.escapedPattern(for: trimmed),
                options: [.caseInsensitive]) else { continue }
            out = re.stringByReplacingMatches(
                in: out, range: NSRange(out.startIndex..., in: out),
                withTemplate: policy.style == .bullets
                    ? "\u{2022}\u{2022}\u{2022}\u{2022}" : "<redacted-identity>")
        }
        return out
    }

    /// Whole blocks of key material. Before every other pass: a PEM body is
    /// base64, an OpenSSH private key is base64, and a `<data>` blob is base64,
    /// so leaving these to the entropy pass would produce a hundred tokens where
    /// one honest sentence belongs.
    private func redactBlocks(_ s: String) -> String {
        // The label character class is deliberately WIDER than "uppercase PEM".
        // It used to be `[A-Z0-9 ]+`, which does not match
        // `-----BEGIN OpenVPN Static key V1-----` — the armour around a tls-crypt /
        // tls-auth key, which is a shared symmetric key protecting the whole control
        // channel. A blacklist that has never heard of a shape is the one your log
        // line goes through, so mixed case, dots, dashes and underscores are all in.
        var out = replace(s, #"-----BEGIN [A-Za-z0-9 ._-]+-----[\s\S]*?-----END [A-Za-z0-9 ._-]+-----"#) { _, _ in
            self.goneAs("redacted-key-material")
        }
        // PuTTY / .ppk private keys, which are not PEM.
        out = replace(out, #"PuTTY-User-Key-File-\d+:[\s\S]*?Private-MAC:\s*\S+"#) { _, _ in
            self.goneAs("redacted-key-material")
        }
        // An `<data>` blob in a configuration profile or plist. Certificates and
        // .p12 identities travel this way.
        out = replace(out, #"<data>\s*[A-Za-z0-9+/=\s]{40,}</data>"#) { _, _ in
            "<data>" + self.goneAs("redacted-key-material") + "</data>"
        }
        return out
    }

    /// `scheme://user:password@host`. The userinfo goes; the host survives to be
    /// dealt with by the hostname pass, so the sentence still says WHERE.
    private func redactCredentialedURLs(_ s: String) -> String {
        replace(s, #"\b([a-z][a-z0-9+.\-]*)://([^\s/:@]+):([^\s/@]+)@"#) { _, groups in
            "\(groups.first.flatMap { $0 } ?? "scheme")://\(self.goneAs("redacted-userinfo"))@"
        }
    }

    /// `Authorization: Bearer <token>` and `Basic <base64>`. Needs its own pass:
    /// the keyed pass below stops at the first whitespace, so `Authorization:
    /// Bearer eyJ…` would remove the word "Bearer" and leave the token.
    private func redactAuthorizationSchemes(_ s: String) -> String {
        replace(s, #"\b(Bearer|Basic|Digest|Negotiate|Token)\s+([A-Za-z0-9._~+/=\-]{8,})"#) { _, groups in
            "\(groups.first.flatMap { $0 } ?? "Bearer") \(self.gone)"
        }
    }

    /// `security dump-keychain` / `find-generic-password` output. Its shape is
    /// `"acct"<blob>="value"`, which no other pass recognises, and the values are
    /// account names and passwords.
    private func redactKeychainDumps(_ s: String) -> String {
        var out = replace(
            s, #""([a-z0-9]{4})"<(blob|timedate|uint32|sint32)>=(?:"[^"]*"|0x[0-9A-Fa-f]+(?:\s+"[^"]*")?|<NULL>)"#,
            options: []) { _, groups in
                let key = groups.first.flatMap { $0 } ?? "attr"
                let type = groups.count > 1 ? (groups[1] ?? "blob") : "blob"
                return "\"\(key)\"<\(type)>=\(self.gone)"
            }
        // `password: "hunter2"` as printed by `security find-generic-password -w`.
        out = replace(out, #"\bpassword:\s*("[^"]*"|\S+)"#) { _, _ in "password: " + self.gone }
        return out
    }

    /// Configuration-profile (MDM) payloads: `<key>VPNPassword</key><string>…`.
    /// Keyed by the KEY's own name, so a payload nobody has seen still loses its
    /// password as long as the key is called what Apple's keys are called.
    private func redactPropertyListSecrets(_ s: String) -> String {
        replace(
            s,
            #"<key>([A-Za-z0-9_.\-]*(?:Password|Passphrase|Secret|Token|SharedSecret|PIN|PrivateKey|AuthKey|Credential)[A-Za-z0-9_.\-]*)</key>\s*<(string|data|integer)>[^<]*</\2>"#
        ) { _, groups in
            let key = groups.first.flatMap { $0 } ?? "Password"
            let tag = groups.count > 1 ? (groups[1] ?? "string") : "string"
            return "<key>\(key)</key><\(tag)>\(self.gone)</\(tag)>"
        }
    }

    /// Keys whose VALUE is a secret, in `key=value` / `key: value` form.
    ///
    /// NOTE the deliberate absence of a bare `key`: `ProbeEvidence` relies on a
    /// `key: <160-character blob>` line surviving this pass so that IT can say
    /// "…characters withheld", and a bare `key` here would also eat
    /// `key: value` pairs that are not secrets at all. Every entry below names
    /// what it is.
    private static let secretKeys = [
        "pass(?:word|wd|phrase)?", "passcode", "secret", "client[-_]?secret",
        "token", "auth[-_]?token", "access[-_]?token", "refresh[-_]?token",
        "id[-_]?token", "session[-_]?(?:id|key|token)", "session",
        "cookie", "authorization", "credentials?",
        "otp", "totp", "hotp", "one[-_ ]?time[-_ ]?(?:code|password|passcode)",
        "verification[-_ ]?code",
        "api[-_]?key", "apikey", "private[-_]?key", "privkey",
        "pre[-_]?shared[-_]?key", "psk", "auth[-_]?key", "authkey",
        "setup[-_]?key", "node[-_]?key", "machine[-_]?key",
        "pin", "user[-_]?pin", "so[-_]?pin",
        "challenge", "response",
        "BW_SESSION", "OP_SERVICE_ACCOUNT_TOKEN", "VAULT_TOKEN",
        "KEEPER_PASSWORD", "TS_AUTHKEY",
    ].joined(separator: "|")

    private func redactKeyedValues(_ s: String) -> String {
        // `"key": "value"` (JSON) and `key=value` / `key: value` in one pattern:
        // an optional quote around the key, then the separator, then a quoted or
        // bare value.
        replace(s, #"\"?\b(\#(Self.secretKeys))\b\"?\s*[:=]\s*("[^"]*"|'[^']*'|\S+)"#) { _, groups in
            "\(groups.first.flatMap { $0 } ?? "secret")=\(self.gone)"
        }
    }

    /// `--password hunter2`, `--pin 123456`. Space-separated, so the keyed pass
    /// above cannot see it. The value floor of four characters keeps this from
    /// eating the next English word in "pass --password to the tool".
    private func redactArgumentValues(_ s: String) -> String {
        replace(s, #"(--(?:\#(Self.secretKeys)))[= ]+((?!-)\S{4,})"#) { _, groups in
            "\(groups.first.flatMap { $0 } ?? "--secret")=\(self.gone)"
        }
    }

    /// Values recognisable from their OWN shape, with no helpful key in sight.
    /// This is the half that catches a secret pasted into free text.
    private func redactShapedSecrets(_ s: String) -> String {
        var out = s

        // An SSH public/host key line: `ssh-ed25519 AAAAC3Nza…`. The algorithm
        // stays (it is the useful half); the material goes. A host-key
        // FINGERPRINT is deliberately not touched — it is public, and it is the
        // whole point of the host-key check.
        out = replace(
            out,
            #"\b(ssh-rsa|ssh-ed25519|ssh-dss|ecdsa-sha2-nistp\d+|sk-ssh-ed25519@openssh\.com|sk-ecdsa-sha2-nistp256@openssh\.com)\s+[A-Za-z0-9+/]{20,}={0,3}"#
        ) { _, groups in
            "\(groups.first.flatMap { $0 } ?? "ssh-key") \(self.goneAs("redacted-key-material"))"
        }

        // `otpauth://` provisioning URI — carries the TOTP SEED, which is worth
        // more than any single code.
        out = replace(out, #"\botpauth(?:-migration)?://[^\s"'<>]+"#) { _, _ in
            self.goneAs("redacted-totp-seed")
        }

        // A Yubico OTP: 32–64 characters of modhex (`cbdefghijklnrtuv`) — what
        // the key TYPES when you touch it. The first 12 characters are the
        // device's public id and would be safe to show; nothing in a report
        // needs it, so the whole token goes.
        out = replace(out, #"\b[cbdefghijklnrtuv]{32,64}\b"#, options: []) { m, _ in
            self.token("yubico-otp", m.lowercased())
        }

        // Tailscale keys: auth, client, api and scope keys all share the prefix.
        out = replace(out, #"\btskey-[A-Za-z0-9]+-[A-Za-z0-9\-]{8,}"#, options: []) { _, _ in
            self.goneAs("redacted-tailscale-key")
        }

        // A WireGuard key is exactly 44 base64 characters ending in `=`.
        out = replace(out, #"(?<![A-Za-z0-9+/=])[A-Za-z0-9+/]{43}=(?![A-Za-z0-9+/=])"#,
                      options: []) { m, _ in self.token("wireguard-key", m) }

        // A JWT. Three base64url segments; the middle one is readable.
        out = replace(out, #"\beyJ[A-Za-z0-9_\-]{6,}\.[A-Za-z0-9_\-]{6,}\.[A-Za-z0-9_\-]{6,}"#,
                      options: []) { _, _ in self.goneAs("redacted-token") }

        // Vendor API-token prefixes, each one documented by its vendor.
        for pattern in [
            #"\bops_[A-Za-z0-9]{20,}"#,              // 1Password service account
            #"\bghp_[A-Za-z0-9]{20,}"#,              // GitHub personal access token
            #"\bgithub_pat_[A-Za-z0-9_]{20,}"#,
            #"\bxox[baprs]-[A-Za-z0-9\-]{10,}"#,     // Slack
            #"\bsk-[A-Za-z0-9]{20,}"#,               // OpenAI-style
            #"\bAKIA[0-9A-Z]{16}\b"#,                // AWS access key id
            #"\bhv[sb]\.[A-Za-z0-9._\-]{20,}"#,      // HashiCorp Vault
        ] {
            out = replace(out, pattern, options: []) { _, _ in self.goneAs("redacted-token") }
        }

        // A base32 run is what a TOTP seed looks like when it is not in a URI.
        //
        // Gated on the entropy switch rather than always-on, because base32 and
        // upper-case base64 are the same character set: a 160-character base64
        // blob in an ERROR DETAIL has to survive this pass so that
        // `ProbeEvidence` can collapse it and say how much was withheld. Every
        // policy that carries bulk text has the switch on, so a seed of any
        // length is caught there.
        if policy.redactsHighEntropyRuns {
            out = replace(out, #"\b[A-Z2-7]{16,}={0,6}\b"#, options: []) { m, _ in
                self.token("base32-secret", m)
            }
        }

        return out
    }

    /// The catch-all: a long run of hex or base64 is, in a diagnostic, almost
    /// never anything a maintainer needs and quite often a secret nobody has
    /// enumerated yet. Bounded rather than absolute — see `Policy`.
    private func redactHighEntropyRuns(_ s: String) -> String {
        var out = replace(s, #"\b[0-9a-fA-F]{40,}\b"#, options: []) { m, _ in
            self.token("opaque-hex", m.lowercased())
        }
        out = replace(out, #"(?<![A-Za-z0-9+/=])[A-Za-z0-9+/]{40,}={0,2}(?![A-Za-z0-9+/=])"#,
                      options: []) { m, _ in self.token("opaque-blob", m) }
        return out
    }

    private func redactBareNumericCodes(_ s: String) -> String {
        replace(s, #"\b[0-9]{6,8}\b"#, options: []) { _, _ in
            self.policy.style == .bullets
                ? "\u{2022}\u{2022}\u{2022}\u{2022}\u{2022}\u{2022}"
                : "<redacted-code>"
        }
    }

    // MARK: Addresses and names

    private func redactIPv4(_ s: String) -> String {
        replace(s, #"\b(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})\b"#, options: []) { match, _ in
            let parts = match.split(separator: ".").compactMap { UInt32($0) }
            guard parts.count == 4, parts.allSatisfy({ $0 <= 255 }) else { return match }
            // Well-known addresses carry meaning, not identity.
            let keep: Set<String> = ["0.0.0.0", "127.0.0.1", "255.255.255.255", "169.254.169.254"]
            if keep.contains(match) { return match }
            return self.token(Self.kindForIPv4(parts), match)
        }
    }

    private static func kindForIPv4(_ p: [UInt32]) -> String {
        let a = (p[0] << 24) | (p[1] << 16) | (p[2] << 8) | p[3]
        func within(_ net: UInt32, _ plen: Int) -> Bool {
            let mask: UInt32 = plen == 0 ? 0 : (~UInt32(0)) << (32 - plen)
            return (a & mask) == (net & mask)
        }
        if within(0x6440_0000, 10) { return "ip4-tailscale-or-cgnat" }
        if within(0x0A00_0000, 8) || within(0xAC10_0000, 12) || within(0xC0A8_0000, 16) { return "ip4-private" }
        if within(0xA9FE_0000, 16) { return "ip4-linklocal" }
        if within(0x7F00_0000, 8) { return "ip4-loopback" }
        if within(0xE000_0000, 4) { return "ip4-multicast" }
        return "ip4-public"
    }

    private func redactIPv6(_ s: String) -> String {
        // Conservative: at least three groups and a colon-pair, so clock times
        // (12:34:56) and MAC addresses survive to their own passes.
        replace(s, #"\b(?=[0-9a-f]*:)(?:[0-9a-f]{0,4}:){2,7}[0-9a-f]{0,4}(?:%[0-9a-z]+)?\b"#) { match, _ in
            let keep: Set<String> = ["::", "::1"]
            if keep.contains(match.lowercased()) { return match }
            guard match.contains("::") || match.filter({ $0 == ":" }).count >= 4 else { return match }
            let lower = match.lowercased()
            let kind = lower.hasPrefix("fe80") ? "ip6-linklocal"
                : (lower.hasPrefix("fd") || lower.hasPrefix("fc")) ? "ip6-private" : "ip6"
            return self.token(kind, lower)
        }
    }

    private func redactMACs(_ s: String) -> String {
        replace(s, #"\b([0-9a-f]{1,2}:){5}[0-9a-f]{1,2}\b"#) { match, _ in
            self.token("mac", match.lowercased())
        }
    }

    /// Hostnames and FQDNs. Deliberately conservative: anything whose last label
    /// looks like a file extension or a bundle id we want readable survives, so
    /// source filenames and our own subsystem names stay legible.
    private func redactHostnames(_ s: String) -> String {
        let skipSuffixes: Set<String> = [
            "swift", "plist", "app", "dylib", "framework", "xcframework", "a", "h", "m", "mm", "c", "cpp",
            "sh", "yml", "yaml", "json", "txt", "log", "png", "md", "pem", "crt", "key", "ovpn",
            "so", "kdbx", "p12", "pfx", "conf", "module",
            "systemextension", "appex", "0", "1", "2", "3", "4", "5", "6", "7", "8", "9",
        ]
        let keepPrefixes = ["com.bragi0.", "com.apple."]
        return replace(s, #"\b([a-z0-9](?:[a-z0-9-]*[a-z0-9])?(?:\.[a-z0-9](?:[a-z0-9-]*[a-z0-9])?)+)\b"#) { match, _ in
            let lower = match.lowercased()
            if keepPrefixes.contains(where: { lower.hasPrefix($0) }) { return match }
            guard let last = lower.split(separator: ".").last,
                  !skipSuffixes.contains(String(last)) else { return match }
            // Require a plausible TLD so version strings like 1.2.3 survive.
            guard last.count >= 2, last.allSatisfy({ $0.isLetter }) else { return match }
            return self.token("host", lower)
        }
    }

    // MARK: Machine identity

    /// The strings that identify this Mac and its owner. Every caller wants
    /// these, so nobody has to remember them.
    static func machineIdentifiers() -> [String] {
        var out = [NSUserName(), NSFullUserName(), ProcessInfo.processInfo.hostName]
        if let name = Host.current().localizedName { out.append(name) }
        return out.filter { $0.count >= 4 }
    }
}
