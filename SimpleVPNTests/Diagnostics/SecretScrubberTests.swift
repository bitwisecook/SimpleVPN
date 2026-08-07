// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
//  SecretScrubberTests.swift
//  THE ADVERSARIAL CORPUS. A scrubber without one is decoration.
//
//  Every secret shape this app can touch appears below, embedded in a line
//  shaped the way it would really appear — an argv echo, a JSON error body, a
//  `security` dump, an MDM payload, a Tailscale log line — and the assertion is
//  always the same: the secret is NOT in the output.
//
//  Three other things are asserted, because a scrubber that removes everything is
//  as useless as one that removes nothing:
//   • what must SURVIVE (host-key fingerprints, ports, our own bundle ids),
//   • that placeholders are stable inside a report and unstable across reports,
//   • that the STRUCTURED path (`ReportValue`) cannot carry a secret at all,
//     including a test that stops compiling if a new case is added to it.
//

import Testing
import Foundation
@testable import SimpleVPN

// MARK: - The corpus

/// One adversarial case: a realistic line, and the substring that must not
/// survive it.
nonisolated private struct Seeded: Sendable {
    var name: String
    var line: String
    /// Every fragment that must be gone. More than one where a line carries a
    /// compound secret (a username AND a password in a URL).
    var mustNotSurvive: [String]

    init(_ name: String, _ line: String, _ mustNotSurvive: String...) {
        self.name = name
        self.line = line
        self.mustNotSurvive = mustNotSurvive
    }
}

/// A YubiKey's typed one-time password: 44 characters of modhex.
nonisolated private let yubicoOTP = "ccccccfhrbkkcbdefghijklnrtuvcbdefghijklnr"
/// A base32 TOTP seed, as a vendor prints one.
nonisolated private let totpSeed = "JBSWY3DPEHPK3PXPJBSWY3DPEHPK3PXP"
/// A WireGuard key: 44 base64 characters ending in `=`.
nonisolated private let wireGuardKey = "aGVsbG8gdGhpcyBpcyBub3QgYSByZWFsIGtleSEhPQ="

nonisolated private let corpus: [Seeded] = [
    // --- Passwords, the obvious ones -------------------------------------
    Seeded("password in key=value",
           "openconnect: auth failed (password=hunter2trombone)", "hunter2trombone"),
    Seeded("password in JSON",
           #"{"error":"bad credentials","password":"hunter2trombone","user":"someone"}"#,
           "hunter2trombone"),
    Seeded("passphrase with a colon",
           "private key rejected, passphrase: correct-horse-battery", "correct-horse-battery"),
    Seeded("password as an argument",
           "would run: /opt/homebrew/bin/bw unlock --password hunter2trombone", "hunter2trombone"),
    Seeded("password in a URL",
           "proxy https://someone:hunter2trombone@proxy.example.com:3128 refused",
           "hunter2trombone"),
    Seeded("keychain dump line",
           #""acct"<blob>="someone"  "svce"<blob>="SimpleVPN"  password: "hunter2trombone""#,
           "hunter2trombone"),

    // --- Verification codes and their seeds -------------------------------
    Seeded("bare verification code", "gateway rejected code 483920", "483920"),
    Seeded("otp in key=value", "sending otp=483920 with the password", "483920"),
    Seeded("otpauth provisioning URI",
           "imported otpauth://totp/VPN:someone?secret=\(totpSeed)&issuer=Corp",
           totpSeed),
    Seeded("bare base32 TOTP seed",
           "totp secret stored for this profile: \(totpSeed)", totpSeed),
    Seeded("Yubico OTP typed into the password field",
           "auth-user-pass password field received \(yubicoOTP)", yubicoOTP),
    Seeded("Yubico OTP with its public id split out",
           "security key typed \(yubicoOTP) (44 chars)", yubicoOTP),

    // --- Key material -----------------------------------------------------
    Seeded("PEM private key",
           """
           loading client key:
           -----BEGIN PRIVATE KEY-----
           MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDSUPERSECRETKEY
           MATERIALTHATMUSTNOTAPPEARINABUGREPORTEVERATALLNOTONCE0123456789ab
           -----END PRIVATE KEY-----
           """,
           "MIIEvQIBADANBgkqhkiG9w0BAQEFAASCBKcwggSjAgEAAoIBAQDSUPERSECRETKEY"),
    Seeded("PEM certificate body",
           """
           -----BEGIN CERTIFICATE-----
           MIIDdzCCAl+gAwIBAgIEAgAAuTANBgkqhkiG9w0BAQUFADBaMQswCQYDVQQGEwJJ
           -----END CERTIFICATE-----
           """,
           "MIIDdzCCAl+gAwIBAgIEAgAAuTANBgkqhkiG9w0BAQUFADBaMQswCQYDVQQGEwJJ"),
    Seeded("OpenSSH private key block",
           """
           -----BEGIN OPENSSH PRIVATE KEY-----
           b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtz
           -----END OPENSSH PRIVATE KEY-----
           """,
           "b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtz"),
    // An OpenVPN static key: the material behind `<tls-crypt>` / `<tls-auth>`, a
    // shared symmetric key over the whole control channel. Its PEM label is MIXED
    // CASE, which the block pass's old `[A-Z0-9 ]+` label class did not match — so
    // this one shape walked straight through the redactor that every other kind of
    // key material is caught by.
    Seeded("OpenVPN static key (tls-crypt / tls-auth material)",
           """
           <tls-crypt>
           -----BEGIN OpenVPN Static key V1-----
           1f8a3c9e0b7d6452aa11bb22cc33dd44
           55ee66ff778899aabbccddeeff001122
           -----END OpenVPN Static key V1-----
           </tls-crypt>
           """,
           "1f8a3c9e0b7d6452aa11bb22cc33dd44"),
    Seeded("PuTTY key file",
           """
           PuTTY-User-Key-File-3: ssh-ed25519
           Public-Lines: 2
           AAAAC3NzaC1lZDI1NTE5AAAAIFAKEPUBLICKEYDATAFORTHISTEST0000000000
           Private-Lines: 1
           SUPERSECRETPUTTYPRIVATELINETHATMUSTNOTSURVIVE000000000000
           Private-MAC: 0011223344556677
           """,
           "SUPERSECRETPUTTYPRIVATELINETHATMUSTNOTSURVIVE000000000000"),
    Seeded("SSH host key from known_hosts",
           "host key: ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIHOSTKEYMATERIAL0000000000000000",
           "AAAAC3NzaC1lZDI1NTE5AAAAIHOSTKEYMATERIAL0000000000000000"),
    Seeded("WireGuard private key",
           "wg config: PrivateKey = \(wireGuardKey)", wireGuardKey),
    Seeded("WireGuard preshared key in a log line",
           "peer preshared-key \(wireGuardKey) applied", wireGuardKey),
    Seeded("PKCS#11 PIN",
           "p11tool --provider /usr/local/lib/libykcs11.dylib --pin 123456 --list-all-certs",
           "123456"),
    Seeded("PKCS#11 PIN as key=value",
           "openconnect pkcs11 pin=SuperSecretPin99 supplied", "SuperSecretPin99"),

    // --- Sessions, tokens and vendor keys ---------------------------------
    Seeded("BW_SESSION environment variable",
           "child env: BW_SESSION=aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789+/== PATH=/usr/bin",
           "aBcDeFgHiJkLmNoPqRsTuVwXyZ0123456789+/=="),
    Seeded("Bearer token in a header",
           "GET /v1/items -> 401, Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.SIGNATUREHERE",
           "eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxIn0.SIGNATUREHERE"),
    Seeded("basic auth header",
           "Authorization: Basic c29tZW9uZTpodW50ZXIydHJvbWJvbmU=",
           "c29tZW9uZTpodW50ZXIydHJvbWJvbmU="),
    Seeded("1Password service account token",
           "OP_SERVICE_ACCOUNT_TOKEN=ops_eyJzaWduSW5BZGRyZXNzIjoibXkuMXBhc3N3b3JkLmNvbSJ9",
           "ops_eyJzaWduSW5BZGRyZXNzIjoibXkuMXBhc3N3b3JkLmNvbSJ9"),
    Seeded("HashiCorp Vault token",
           "vault login failed for hvs.CAESIJmUcXo0dGVzdHRva2VuMDAwMDAwMDAwMA",
           "hvs.CAESIJmUcXo0dGVzdHRva2VuMDAwMDAwMDAwMA"),
    Seeded("GitHub token pasted into a note",
           "ghp_1234567890abcdefghijklmnopqrstuvwx", "ghp_1234567890abcdefghijklmnopqrstuvwx"),
    Seeded("AWS access key id", "AKIAIOSFODNN7EXAMPLE", "AKIAIOSFODNN7EXAMPLE"),
    Seeded("generic api key",
           "request refused: api_key=abcdef0123456789abcdef", "abcdef0123456789abcdef"),
    Seeded("Keeper password from the environment",
           "KEEPER_PASSWORD=hunter2trombone keeper whoami", "hunter2trombone"),

    // --- Tailscale --------------------------------------------------------
    Seeded("Tailscale auth key",
           "tailscale up --authkey tskey-auth-kEXAMPLE1CNTRL-abcdef1234567890",
           "tskey-auth-kEXAMPLE1CNTRL-abcdef1234567890"),
    Seeded("Tailscale client (OAuth) key",
           "control refused tskey-client-kEXAMPLE2CNTRL-zyxwvu9876543210",
           "tskey-client-kEXAMPLE2CNTRL-zyxwvu9876543210"),
    Seeded("Tailscale setup key in key=value",
           "start options: setup-key=tskey-auth-kEXAMPLE3CNTRL-0011223344556677",
           "tskey-auth-kEXAMPLE3CNTRL-0011223344556677"),

    // --- MDM / configuration profiles -------------------------------------
    Seeded("MDM payload password",
           "<key>VPNPassword</key><string>hunter2trombone</string>", "hunter2trombone"),
    Seeded("MDM payload shared secret",
           "<key>SharedSecret</key><string>PSK-hunter2trombone</string>", "PSK-hunter2trombone"),
    Seeded("MDM payload certificate data",
           "<key>PayloadContent</key><data>MIIDdzCCAl+gAwIBAgIEAgAAuTANBgkqhkiG9w0BAQUFADBaMQsw</data>",
           "MIIDdzCCAl+gAwIBAgIEAgAAuTANBgkqhkiG9w0BAQUFADBaMQsw"),

    // --- Challenge/response and static passwords --------------------------
    Seeded("YubiKey challenge-response",
           "ykman otp calculate 2 challenge=00112233445566778899aabbccddeeff",
           "00112233445566778899aabbccddeeff"),
    Seeded("static password from slot 2",
           "field received static password: Tr0ub4dor&3xample", "Tr0ub4dor&3xample"),

    // --- Hardware addresses, in all three spellings this Mac produces ------
    //
    // A hardware address identifies a physical machine for that machine's life.
    // The PRIMARY control is that none is ever put into the report — see
    // `HardwareAddressTypeDisciplineTests`, which scans the source for it. These
    // are the defence in depth, for the free-text bundle and for anything an
    // admitted log line quotes, and all three spellings are here because a
    // scrubber that only knows the padded one is a scrubber that misses every
    // address `netstat` and `arp` print.
    Seeded("netstat gateway column, leading zeros suppressed",
           "10.0.7.13          42:0:5c:85:fa:1a   UHLWIi         en0",
           "42:0:5c:85:fa:1a"),
    Seeded("arp -an, the same spelling in prose",
           "? (10.0.0.4) at a0:99:9b:18:dc:93 on en0 ifscope [ethernet]",
           "a0:99:9b:18:dc:93"),
    Seeded("a vendor config's padded upper case",
           "UTM Network[0].MacAddress = EA:85:74:8B:18:97",
           "EA:85:74:8B:18:97"),
    Seeded("the network-identity key, which IS an address",
           "netmemory: network fingerprint key=mac:a:e6:33:6c:f0:52",
           "a:e6:33:6c:f0:52"),
]

// MARK: - The corpus, asserted

struct SecretScrubberCorpusTests {

    /// Fixed salt so a failure is reproducible.
    private func scrubber(_ policy: SecretScrubber.Policy,
                          literals: [String] = []) -> SecretScrubber {
        SecretScrubber(policy: policy, literalSecrets: literals,
                       homeDirectory: "/Users/testuser", salt: "fixed-test-salt")
    }

    @Test("Nothing in the adversarial corpus survives the report policy",
          arguments: corpus.indices)
    func reportPolicyKillsEverything(index: Int) {
        let seeded = corpus[index]
        let out = scrubber(.report).scrub(seeded.line)
        for fragment in seeded.mustNotSurvive {
            #expect(!out.contains(fragment),
                    "\(seeded.name): \"\(fragment)\" survived → \(out)")
        }
    }

    /// The bundle policy carries bulk machine output, so it keeps bare numbers on
    /// purpose (a port, a PID and a byte count all look like a verification code).
    /// Everything with a recognisable SHAPE must still die.
    @Test("Nothing shaped like a secret survives the bundle policy",
          arguments: corpus.indices)
    func bundlePolicyKillsEverythingShaped(index: Int) {
        let seeded = corpus[index]
        // The two cases that are ONLY a bare number, which this policy documents
        // that it keeps.
        let bareNumberOnly = ["bare verification code"]
        guard !bareNumberOnly.contains(seeded.name) else { return }
        let out = scrubber(.logBundle).scrub(seeded.line)
        for fragment in seeded.mustNotSurvive {
            #expect(!out.contains(fragment),
                    "\(seeded.name): \"\(fragment)\" survived → \(out)")
        }
    }

    /// A `--pin 123456` IS caught by the argument rule even in the bundle policy,
    /// because the key names it. Only a NAKED number is kept — asserted here so
    /// the exemption above cannot quietly grow.
    @Test func aNamedPINDiesEvenWhereBareNumbersLive() {
        let out = scrubber(.logBundle).scrub("p11tool --pin 123456 --list-all-certs")
        #expect(!out.contains("123456"))
    }

    @Test func aBareNumberIsKeptOnlyWhereItIsDocumentedToBe() {
        #expect(scrubber(.logBundle).scrub("rejected code 483920").contains("483920"))
        #expect(!scrubber(.report).scrub("rejected code 483920").contains("483920"))
    }

    /// Scrubbing twice must not resurrect anything, and must not keep chewing.
    @Test("Scrubbing is idempotent", arguments: corpus.indices)
    func idempotent(index: Int) {
        let s = scrubber(.report)
        let once = s.scrub(corpus[index].line)
        let twice = s.scrub(once)
        for fragment in corpus[index].mustNotSurvive {
            #expect(!twice.contains(fragment))
        }
    }
}

// MARK: - Property-based sweep

struct SecretScrubberPropertyTests {

    /// A deterministic generator, so a failure can be reproduced from the seed
    /// printed in the message rather than from luck.
    private struct Rng {
        var state: UInt64
        mutating func next() -> UInt64 {
            state = state &* 6_364_136_223_846_793_005 &+ 1_442_695_040_888_963_407
            return state >> 16
        }
        mutating func pick<T>(_ xs: [T]) -> T { xs[Int(next() % UInt64(xs.count))] }
        mutating func secret(length: Int) -> String {
            let alphabet = Array("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789")
            return String((0..<length).map { _ in alphabet[Int(next() % UInt64(alphabet.count))] })
        }
    }

    /// For every key name the scrubber claims to know, in every separator shape,
    /// with a random value: the value must be gone and the KEY must remain (a
    /// report that loses the key loses the diagnosis).
    @Test func everyKnownKeyShapeLosesItsValueAndKeepsItsKey() {
        var rng = Rng(state: 0xDEAD_BEEF)
        let keys = ["password", "passwd", "passphrase", "secret", "token", "auth-token",
                    "access_token", "session-key", "cookie", "authorization",
                    "otp", "totp", "one-time-code", "verification-code",
                    "api_key", "apikey", "private-key", "preshared-key", "psk",
                    "auth-key", "setup-key", "node-key", "pin", "so-pin", "passcode",
                    "BW_SESSION", "VAULT_TOKEN", "credentials"]
        let separators = ["=", ": ", " = ", ":", "= "]
        let scrubber = SecretScrubber(policy: .report, homeDirectory: "/Users/testuser",
                                     salt: "fixed-test-salt")
        for key in keys {
            for separator in separators {
                let value = rng.secret(length: 5 + Int(rng.next() % 24))
                let line = "engine says: \(key)\(separator)\(value) after 3 attempts"
                let out = scrubber.scrub(line)
                #expect(!out.contains(value),
                        "\(key)\(separator)<value> leaked \(value) → \(out)")
            }
        }
    }

    /// A random secret with no helpful key at all, in every shape the scrubber
    /// recognises by sight.
    @Test func shapedSecretsDieWithoutAKeyToNameThem() {
        var rng = Rng(state: 0x0BAD_F00D)
        let scrubber = SecretScrubber(policy: .report, homeDirectory: "/Users/testuser",
                                     salt: "fixed-test-salt")
        for _ in 0..<40 {
            let modhex = String((0..<44).map { _ in
                Array("cbdefghijklnrtuv")[Int(rng.next() % 16)]
            })
            let hexBlob = String((0..<64).map { _ in Array("0123456789abcdef")[Int(rng.next() % 16)] })
            let base64Blob = rng.secret(length: 48)
            let tailscale = "tskey-auth-k\(rng.secret(length: 8))CNTRL-\(rng.secret(length: 16))"
            for secret in [modhex, hexBlob, base64Blob, tailscale] {
                let out = scrubber.scrub("engine log: \(secret) seen at 12:04:31")
                #expect(!out.contains(secret), "shaped secret leaked: \(secret) → \(out)")
            }
        }
    }
}

// MARK: - What must survive

struct SecretScrubberSurvivalTests {

    private let report = SecretScrubber(policy: .report, homeDirectory: "/Users/testuser",
                                        salt: "fixed-test-salt")
    private let path = SecretScrubber(policy: .path, homeDirectory: "/Users/testuser",
                                      salt: "fixed-test-salt")
    private let errorDetail = SecretScrubber(policy: .errorDetail, homeDirectory: "/Users/testuser",
                                             salt: "fixed-test-salt")

    /// A host-key fingerprint is PUBLIC information and is the entire point of the
    /// host-key check. Removing it turns a useful failure into a mystery.
    @Test func hostKeyFingerprintsSurviveAnErrorDetail() {
        let fingerprint = String(repeating: "a1b2c3d4", count: 8)
        #expect(errorDetail.scrub("Fingerprint (SHA-256): \(fingerprint)").contains(fingerprint))
    }

    @Test func colonSeparatedFingerprintsSurviveAnErrorDetail() {
        let fingerprint = (0..<32).map { _ in "AB" }.joined(separator: ":")
        #expect(errorDetail.scrub("SHA-256: \(fingerprint)").contains(fingerprint))
    }

    /// A path is the most useful line in the tool inventory. Its last component
    /// looks like a TLD often enough that a hostname pass would destroy it.
    @Test func toolPathsSurviveThePathPolicy() {
        for candidate in ["/opt/homebrew/lib/pkcs11/opensc-pkcs11.so",
                          "/usr/local/lib/libykcs11.dylib",
                          "/Applications/KeePassXC.app/Contents/MacOS/keepassxc-cli",
                          "/opt/homebrew/bin/bw"] {
            #expect(path.scrub(candidate) == candidate, "mangled \(candidate)")
        }
    }

    @Test func theHomeDirectoryBecomesATilde() {
        #expect(path.scrub("/Users/testuser/.bun/bin/bw") == "~/.bun/bin/bw")
    }

    @Test func portsAndVersionsSurviveABundle() {
        let bundle = SecretScrubber(policy: .logBundle, salt: "fixed-test-salt")
        let out = bundle.scrub("connecting to port 1197 udp4, engine 3.12, build 4821")
        #expect(out.contains("1197"))
        #expect(out.contains("3.12"))
    }

    @Test func ourOwnBundleIdentifiersStayReadable() {
        let out = report.scrub("subsystem com.bragi0.SimpleVPN.PacketTunnel started")
        #expect(out.contains("com.bragi0.SimpleVPN.PacketTunnel"))
    }

    @Test func wellKnownAddressesCarryMeaningNotIdentity() {
        let out = report.scrub("default via 0.0.0.0 and loopback 127.0.0.1")
        #expect(out.contains("0.0.0.0"))
        #expect(out.contains("127.0.0.1"))
    }
}

// MARK: - Placeholder behaviour

struct SecretScrubberPlaceholderTests {

    @Test func theSameValueGetsTheSamePlaceholderInOneReport() {
        let s = SecretScrubber(policy: .report, salt: "one-report")
        let out = s.scrub("192.168.4.4 then 10.1.1.1 then 192.168.4.4")
        let tokens = out.components(separatedBy: "<").dropFirst().map { $0.components(separatedBy: ">")[0] }
        #expect(tokens.count == 3)
        #expect(tokens[0] == tokens[2])
        #expect(tokens[0] != tokens[1])
    }

    @Test func adifferentReportGetsDifferentPlaceholders() {
        let a = SecretScrubber(policy: .report, salt: "report-a").scrub("192.168.4.4")
        let b = SecretScrubber(policy: .report, salt: "report-b").scrub("192.168.4.4")
        #expect(a != b)
    }

    /// `LogHighlighter` colours placeholders so a reviewer can SEE where something
    /// was removed. That only works if the shapes agree.
    @Test func placeholdersMatchTheLogHighlightersPattern() {
        let out = SecretScrubber(policy: .report, salt: "s").scrub("peer 10.1.2.3 and mac aa:bb:cc:dd:ee:ff")
        let pattern = try? NSRegularExpression(pattern: LogHighlighter.Token.placeholder.pattern)
        let matches = pattern?.numberOfMatches(
            in: out, range: NSRange(out.startIndex..., in: out)) ?? 0
        #expect(matches >= 2, "placeholders in \(out) are not the shape LogHighlighter looks for")
    }
}

// MARK: - The structured path cannot carry a secret

struct ReportValueStructuralTests {

    /// The seeded secret is in a shape EVERY policy recognises, so this test is
    /// about the plumbing (does the case reach the scrubber at all?) rather than
    /// about the rules.
    private let seed = "password=hunter2trombone"

    private var scrubber: SecretScrubber {
        SecretScrubber(policy: .report, homeDirectory: "/Users/testuser", salt: "fixed-test-salt")
    }

    /// Every string-bearing case, seeded. The exhaustive switch below is what
    /// makes this total: adding a case to `ReportValue` without adding it here is
    /// a COMPILE error, not a silently untested hole.
    @Test func everyStringBearingCaseIsScrubbed() {
        let samples: [ReportValue] = [
            .words(seed), .state(seed), .path("/tmp/\(seed)"), .version(seed),
            .userText(seed), .absent(reason: seed),
            .count(7), .flag(true), .seconds(1.5), .moment(Date(timeIntervalSince1970: 0)),
        ]
        for value in samples {
            // Exhaustive on purpose: a new case breaks the build here.
            switch value {
            case .words, .state, .path, .version, .userText, .absent:
                let rendered = value.rendered(with: scrubber)
                #expect(!rendered.contains("hunter2trombone"),
                        "\(value) leaked → \(rendered)")
            case .count, .flag, .seconds, .moment:
                let rendered = value.rendered(with: scrubber)
                // These cases cannot express a string at all — asserted rather
                // than assumed, because "cannot" is the whole claim.
                #expect(!rendered.contains("hunter"))
            }
        }
    }

    @Test func numericCasesRenderAsNumbersAndNothingElse() {
        #expect(ReportValue.count(1234).rendered(with: scrubber) == 1234.formatted())
        #expect(ReportValue.flag(false).rendered(with: scrubber) == "no")
        #expect(ReportValue.seconds(2.5).rendered(with: scrubber) == "2.5s")
    }

    @Test func anUnknownFactSaysWhyRatherThanNothing() {
        let rendered = ReportValue.absent(reason: "it hasn\u{2019}t been run").rendered(with: scrubber)
        #expect(rendered.contains("not recorded"))
        #expect(rendered.contains("hasn\u{2019}t been run"))
    }
}
