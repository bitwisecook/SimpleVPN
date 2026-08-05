// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
//  PasswordStoreTests.swift
//  Two halves, and the split is the point.
//
//  FIXTURE TESTS always run. They cover the parser, the path handling, the state
//  machine and every error sentence, over an injected process boundary — so they pass
//  on a machine with no store, no key and no agent.
//
//  THE LIVE TEST runs only when `gpg` is really installed, and then it is a genuine
//  end-to-end proof: it builds a throwaway keyring and a throwaway store in /tmp,
//  encrypts a real entry to a real key, and reads it back through the real
//  `PasswordStoreReader`. Almost nothing else in the credentials programme can be
//  verified for real on a developer machine — `pass` itself is not even installed
//  here — so where a real proof IS available it is worth taking.
//
//  Why /tmp and not `NSTemporaryDirectory()`: gpg-agent's socket lives inside
//  GNUPGHOME, and a unix socket path is capped at 104 bytes by `sockaddr_un`. The test
//  host's temporary directory is long enough on its own to blow that, and gpg then
//  fails with "File name too long" while looking like a broken keyring. (The SSH agent
//  work hit the identical ceiling from the other direction.)
//
//  The throwaway key has NO passphrase, deliberately: nothing in a test run may ever
//  be able to raise a passphrase prompt, because a prompt no one answers is a hang.
//

import Foundation
import Testing
@testable import SimpleVPN

// MARK: - Fixtures and stubs

private nonisolated struct StubDecrypter: PasswordStoreDecrypting {
    var available = true
    var result: LocalToolResult
    /// Records what the reader asked for, so a test can assert the no-prompting mode
    /// is actually used rather than merely configured.
    final class Calls: @unchecked Sendable { var allowedPrompting: [Bool] = [] }
    var calls = Calls()

    func gpgIsAvailable() -> Bool { available }
    func decrypt(file: String, allowPrompting: Bool) async -> LocalToolResult {
        calls.allowedPrompting.append(allowPrompting)
        return result
    }
}

private func ok(_ text: String) -> LocalToolResult {
    LocalToolResult(exitCode: 0, stdout: Data(text.utf8), stderr: "", timedOut: false)
}
private func fail(_ stderr: String, code: Int32 = 2) -> LocalToolResult {
    LocalToolResult(exitCode: code, stdout: Data(), stderr: stderr, timedOut: false)
}

private let everythingThere = PasswordStoreFileProbe(
    fileExists: { _ in true }, directoryExists: { _ in true })

// MARK: - The store convention

struct PasswordStoreEntryParsingTests {

    /// The first line is the password even when it looks like metadata. Every `pass`
    /// client behaves this way, and "helpfully" treating it as a field would hand
    /// somebody's URL back as their password.
    @Test func theFirstLineIsAlwaysThePassword() {
        let e = PasswordStoreEntry.parse("login: not-a-password\nlogin: jimd\n")
        #expect(e.password == "login: not-a-password")
        #expect(e.fields["login"] == "jimd")
    }

    @Test func onlyTheFirstColonSplitsAField() {
        let e = PasswordStoreEntry.parse("pw\nurl: https://vpn.example.invalid:1194/path\n")
        #expect(e.fields["url"] == "https://vpn.example.invalid:1194/path")
    }

    @Test func theFirstValueForAKeyWins() {
        let e = PasswordStoreEntry.parse("pw\nlogin: first\nlogin: second\n")
        #expect(e.fields["login"] == "first")
    }

    /// pass-otp writes a bare `otpauth://` line, which has no `key:` and so would be
    /// dropped by field parsing alone.
    @Test func aBareOTPAuthLineIsKept() {
        let e = PasswordStoreEntry.parse("pw\notpauth://totp/VPN:jimd?secret=JBSWY3DPEHPK3PXP\n")
        #expect(e.otpauthURI == "otpauth://totp/VPN:jimd?secret=JBSWY3DPEHPK3PXP")
    }

    @Test func linesWithoutAColonAreIgnoredRatherThanGuessedAt() {
        let e = PasswordStoreEntry.parse("pw\njust some free text\nlogin: jimd\n")
        #expect(e.fields.count == 1)
        #expect(e.fields["login"] == "jimd")
    }

    @Test func anEmptyEntryDoesNotCrashAndHasNoPassword() {
        #expect(PasswordStoreEntry.parse("").password.isEmpty)
    }

    /// A configured field name beats the conventional list; without one the
    /// conventional order applies. Both matter because the layout is a convention and
    /// people genuinely differ.
    @Test func theUsernameFieldIsConfigurableWithAConventionalFallback() {
        let e = PasswordStoreEntry.parse("pw\naccount: from-account\nlogin: from-login\n")
        #expect(e.username(preferring: "account") == "from-account")
        #expect(e.username(preferring: nil) == "from-login")
        #expect(e.username(preferring: "nonexistent") == "from-login")
    }

    @Test func aStoreWithNoUsernameAnywhereSaysSoRatherThanInventingOne() {
        #expect(PasswordStoreEntry.parse("pw\nurl: x.invalid\n").username(preferring: nil) == nil)
    }
}

// MARK: - Paths

struct PasswordStorePathTests {
    private let store = PasswordStoreLocation(directory: "/Users/someone/.password-store")

    @Test func anEntryNameResolvesToItsGPGFile() {
        #expect(store.file(forEntry: "vpn/work") == "/Users/someone/.password-store/vpn/work.gpg")
    }

    @Test func theGPGIDFileMarksARealStore() {
        #expect(store.gpgIDFile == "/Users/someone/.password-store/.gpg-id")
    }

    /// The reference is the user's own text, but a reference that escapes the store is
    /// a bug worth making impossible rather than a threat worth debating.
    @Test func anEntryNameCannotClimbOutOfTheStore() {
        #expect(store.file(forEntry: "../../etc/passwd") == nil)
        #expect(store.file(forEntry: "vpn/../../../etc/passwd") == nil)
        #expect(store.file(forEntry: "/etc/passwd") == nil)
        #expect(store.file(forEntry: ".") == nil)
        #expect(store.file(forEntry: "") == nil)
        #expect(store.file(forEntry: "   ") == nil)
    }

    @Test func theDefaultStoreIsPassOwnDefault() {
        let home = URL(fileURLWithPath: "/Users/someone")
        #expect(PasswordStoreLocation.default(home: home).directory == "/Users/someone/.password-store")
    }
}

// MARK: - Pinentry detection (the anti-hang guard)

struct PinentryProbeTests {

    private func withTempHome(_ body: (URL) throws -> Void) throws {
        let home = URL(fileURLWithPath: "/tmp").appendingPathComponent("svpn-pinentry-\(UUID().uuidString.prefix(8))")
        try FileManager.default.createDirectory(at: home.appendingPathComponent(".gnupg"),
                                                withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: home) }
        try body(home)
    }

    @Test func anExplicitlyConfiguredPinentryThatExistsIsUsed() throws {
        try withTempHome { home in
            // Any executable will do — the probe's job is to establish that the
            // configured program is really there, not to run it.
            let conf = home.appendingPathComponent(".gnupg/gpg-agent.conf")
            try "pinentry-program /bin/echo\n".write(to: conf, atomically: true, encoding: .utf8)
            #expect(PinentryProbe.detect(home: home) == .graphical(program: "/bin/echo"))
        }
    }

    /// A configured pinentry that does NOT exist is worse than none at all: gpg-agent
    /// then fails in a way that reads like a broken keyring. So it must not count.
    @Test func aConfiguredPinentryThatIsMissingDoesNotCount() throws {
        try withTempHome { home in
            let conf = home.appendingPathComponent(".gnupg/gpg-agent.conf")
            try "pinentry-program /nonexistent/pinentry-mac\n".write(to: conf, atomically: true, encoding: .utf8)
            // Falls through to the on-disk search, whose result depends on the machine;
            // the assertion is only that the bogus path was not accepted.
            #expect(PinentryProbe.detect(home: home) != .graphical(program: "/nonexistent/pinentry-mac"))
        }
    }

    @Test func aCommentedOutPinentryLineIsIgnored() throws {
        try withTempHome { home in
            let conf = home.appendingPathComponent(".gnupg/gpg-agent.conf")
            try "# pinentry-program /bin/echo\n".write(to: conf, atomically: true, encoding: .utf8)
            #expect(PinentryProbe.detect(home: home) != .graphical(program: "/bin/echo"))
        }
    }

    @Test func promptingIsOnlyAllowedWithAGraphicalPinentry() {
        #expect(PinentryAvailability.graphical(program: "/x").allowsPrompting)
        #expect(!PinentryAvailability.noneUsable.allowsPrompting)
    }
}

// MARK: - Reading, and every way it can fail

struct PasswordStoreReaderTests {
    private let loc = PasswordStoreLocation(directory: "/tmp/store")

    private func reader(_ d: StubDecrypter,
                       pinentry: PinentryAvailability = .graphical(program: "/x"),
                       files: PasswordStoreFileProbe = everythingThere) -> PasswordStoreReader {
        PasswordStoreReader(location: loc, decrypter: d, pinentry: pinentry, files: files)
    }

    @Test func aGoodEntryIsReadAndParsed() async throws {
        let r = reader(StubDecrypter(result: ok("pw\nlogin: jimd\n")))
        let e = try await r.read(entry: "vpn/work")
        #expect(e.password == "pw")
        #expect(e.username(preferring: nil) == "jimd")
    }

    @Test func aMissingGPGIsItsOwnAnswer() async {
        let r = reader(StubDecrypter(available: false, result: ok("")))
        await #expect(throws: PasswordStoreError.gpgMissing) { try await r.read(entry: "vpn/work") }
    }

    @Test func aMissingFileIsReportedBeforeAnythingIsSpawned() async {
        let d = StubDecrypter(result: ok("pw"))
        let r = reader(d, files: PasswordStoreFileProbe(fileExists: { _ in false },
                                                       directoryExists: { _ in true }))
        await #expect(throws: PasswordStoreError.entryMissing("vpn/work")) {
            try await r.read(entry: "vpn/work")
        }
        #expect(d.calls.allowedPrompting.isEmpty, "no decrypt should be attempted for a file that isn't there")
    }

    @Test func aTimeoutIsItsOwnAnswerAndNeverAHang() async {
        let r = reader(StubDecrypter(result: LocalToolResult(exitCode: -1, stdout: Data(),
                                                            stderr: "", timedOut: true)))
        await #expect(throws: PasswordStoreError.timedOut) { try await r.read(entry: "vpn/work") }
    }

    /// The case this whole feed is shaped around: no GUI pinentry, an uncached
    /// passphrase, and gpg refusing rather than prompting. It must become the sentence
    /// that says what to install.
    @Test func noPinentryPlusAnUncachedPassphraseBecomesActionableAdvice() async {
        for stderr in ["gpg: public key decryption failed: No pinentry",
                       "gpg: decryption failed: No secret key\ngpg: No passphrase given",
                       "gpg: cancelled by user"] {
            let r = reader(StubDecrypter(result: fail(stderr)), pinentry: .noneUsable)
            await #expect(throws: PasswordStoreError.needsPassphraseButNoPinentry) {
                try await r.read(entry: "vpn/work")
            }
        }
    }

    @Test func withoutAGraphicalPinentryThePromptingModeIsActuallyDisabled() async throws {
        let d = StubDecrypter(result: ok("pw"))
        _ = try await reader(d, pinentry: .noneUsable).read(entry: "vpn/work")
        #expect(d.calls.allowedPrompting == [false])
    }

    @Test func withAGraphicalPinentryPromptingIsAllowed() async throws {
        let d = StubDecrypter(result: ok("pw"))
        _ = try await reader(d).read(entry: "vpn/work")
        #expect(d.calls.allowedPrompting == [true])
    }

    /// Any other gpg failure keeps its detail — but that detail comes from stderr,
    /// which `LocalToolRunner` has already scrubbed and truncated. stdout, which is
    /// where the secret lives, is never quoted.
    @Test func anUnrecognisedFailureKeepsItsDetailAndNeverTheSecret() async {
        let secret = "sup3r-secret-pw"
        let d = StubDecrypter(result: LocalToolResult(exitCode: 2, stdout: Data(secret.utf8),
                                                     stderr: "gpg: no such thing", timedOut: false))
        do {
            _ = try await reader(d).read(entry: "vpn/work")
            Issue.record("should have thrown")
        } catch let e as PasswordStoreError {
            let text = e.errorDescription ?? ""
            #expect(text.contains("no such thing"))
            #expect(!text.contains(secret), "a secret must never reach an error string")
        } catch { Issue.record("wrong error: \(error)") }
    }

    // MARK: The cheap state probe

    @Test func aMissingDirectoryIsDistinguishedFromANonStore() {
        let noDir = PasswordStoreFileProbe(fileExists: { _ in false }, directoryExists: { _ in false })
        #expect(reader(StubDecrypter(result: ok("")), files: noDir).storeState() == .directoryMissing)

        let dirButNoGPGID = PasswordStoreFileProbe(fileExists: { _ in false }, directoryExists: { _ in true })
        #expect(reader(StubDecrypter(result: ok("")), files: dirButNoGPGID).storeState() == .notAStore)
    }

    @Test func aStoreWithoutGPGSaysSo() {
        let r = reader(StubDecrypter(available: false, result: ok("")))
        #expect(r.storeState() == .gpgMissing)
    }

    /// No GUI pinentry is NOT a block: plenty of people have their passphrase cached
    /// all day. It is offered with the caveat instead.
    @Test func noPinentryIsOfferedWithACaveatRatherThanBlocked() {
        let r = reader(StubDecrypter(result: ok("")), pinentry: .noneUsable)
        #expect(r.storeState() == .readyOnlyWhileAgentRemembers)
    }

    @Test func everythingPresentIsReady() {
        #expect(reader(StubDecrypter(result: ok(""))).storeState() == .ready)
    }
}

// MARK: - The live round trip

/// Real `gpg`, a real throwaway key, a real encrypted entry, read by the real reader.
/// Skipped when gpg is absent; `livePasswordStoreMode` always runs so a skipped run
/// says so rather than looking like a proven one.
private nonisolated let livePasswordStoreEnabled: Bool = GPGDecrypter().gpgIsAvailable()

@Suite(.serialized, .timeLimit(.minutes(1)))
struct PasswordStoreLiveTests {

    /// ALWAYS RUNS. Without it, "no live coverage" and "live coverage passed" look
    /// identical in a log.
    @Test func livePasswordStoreMode() {
        print("PasswordStore live tests: \(livePasswordStoreEnabled ? "ENABLED — gpg found" : "SKIPPED — no gpg on this machine")")
        #expect(Bool(true))
    }

    /// Short path on purpose: gpg-agent's socket lives in GNUPGHOME and is capped at
    /// 104 bytes by sockaddr_un. The test host's own temp dir overruns it, and gpg then
    /// reports "File name too long" while looking like a broken keyring.
    private func makeThrowawayGPGHome() throws -> URL {
        let home = URL(fileURLWithPath: "/tmp/svpn-pass-live-\(UUID().uuidString.prefix(6))")
        try FileManager.default.createDirectory(at: home, withIntermediateDirectories: true,
                                               attributes: [.posixPermissions: 0o700])
        return home
    }

    private func gpg(_ args: [String], gnupgHome: URL, stdin: Data? = nil) async throws -> LocalToolResult {
        let exe = try #require(LocalToolRunner.locate("gpg") ?? LocalToolRunner.locate("gpg2"))
        return await LocalToolRunner.run(executable: exe, arguments: args, deadline: 45,
                                        environment: ["GNUPGHOME": gnupgHome.path,
                                                      "PATH": "/usr/bin:/bin"],
                                        stdin: stdin)
    }

    @Test(.enabled(if: livePasswordStoreEnabled))
    func aRealStoreEntryIsDecryptedAndParsed() async throws {
        let home = try makeThrowawayGPGHome()
        let store = URL(fileURLWithPath: "/tmp/svpn-pass-store-\(UUID().uuidString.prefix(6))")
        defer {
            // Kill the throwaway agent BEFORE removing its home. Skipping this leaves a
            // `gpg-agent --homedir /tmp/…` running indefinitely, holding a socket in a
            // directory that no longer exists — one such stray was found alive on this
            // machine an hour after the run that made it. `gpgconf --kill` is the only
            // thing that actually stops it; running gpg again just starts another.
            if let gpgconf = LocalToolRunner.locate("gpgconf") {
                let p = Process()
                p.executableURL = URL(fileURLWithPath: gpgconf)
                p.arguments = ["--homedir", home.path, "--kill", "gpg-agent"]
                p.standardOutput = FileHandle.nullDevice
                p.standardError = FileHandle.nullDevice
                try? p.run()
                p.waitUntilExit()
            }
            try? FileManager.default.removeItem(at: home)
            try? FileManager.default.removeItem(at: store)
        }

        // No passphrase, so nothing in a test run can ever raise a prompt.
        let gen = try await gpg(["--batch", "--quiet", "--passphrase", "", "--quick-generate-key",
                                 "SimpleVPN Test <test@example.invalid>", "default", "default", "never"],
                                gnupgHome: home)
        try #require(gen.succeeded, "couldn't make a throwaway key: \(gen.stderr)")

        try FileManager.default.createDirectory(at: store.appendingPathComponent("vpn"),
                                               withIntermediateDirectories: true)
        try "test@example.invalid\n".write(to: store.appendingPathComponent(".gpg-id"),
                                          atomically: true, encoding: .utf8)
        let plaintext = "sup3r-secret-pw\nlogin: jimd\nurl: https://vpn.example.invalid\n"
            + "otpauth://totp/VPN:jimd?secret=JBSWY3DPEHPK3PXP\n"
        let entryFile = store.appendingPathComponent("vpn/work.gpg").path
        let enc = try await gpg(["--batch", "--yes", "--quiet", "--encrypt", "--no-auto-key-locate",
                                 "--recipient", "test@example.invalid", "--output", entryFile],
                                gnupgHome: home, stdin: Data(plaintext.utf8))
        try #require(enc.succeeded, "couldn't encrypt the fixture entry: \(enc.stderr)")

        // Now the real reader, against the real file. A throwaway GNUPGHOME has to be
        // injected, which is the only reason this decrypter is bespoke rather than
        // GPGDecrypter itself.
        struct HomedDecrypter: PasswordStoreDecrypting {
            let home: URL
            func gpgIsAvailable() -> Bool { GPGDecrypter().gpgIsAvailable() }
            func decrypt(file: String, allowPrompting: Bool) async -> LocalToolResult {
                guard let exe = LocalToolRunner.locate("gpg") ?? LocalToolRunner.locate("gpg2") else {
                    return LocalToolResult(exitCode: -1, stdout: Data(), stderr: "no gpg", timedOut: false)
                }
                var args = ["--batch", "--yes", "--quiet", "--decrypt"]
                if !allowPrompting { args += ["--pinentry-mode", "error"] }
                args.append(file)
                return await LocalToolRunner.run(executable: exe, arguments: args, deadline: 30,
                                                environment: ["GNUPGHOME": home.path, "PATH": "/usr/bin:/bin"])
            }
        }

        let reader = PasswordStoreReader(location: PasswordStoreLocation(directory: store.path),
                                        decrypter: HomedDecrypter(home: home),
                                        pinentry: .noneUsable)   // the harsher of the two modes
        #expect(reader.storeState() == .readyOnlyWhileAgentRemembers)

        let entry = try await reader.read(entry: "vpn/work")
        #expect(entry.password == "sup3r-secret-pw")
        #expect(entry.username(preferring: nil) == "jimd")
        #expect(entry.fields["url"] == "https://vpn.example.invalid")
        #expect(entry.otpauthURI == "otpauth://totp/VPN:jimd?secret=JBSWY3DPEHPK3PXP")

        // And a name that isn't there must fail as "no such entry", not as a crypto error.
        await #expect(throws: PasswordStoreError.entryMissing("vpn/nope")) {
            try await reader.read(entry: "vpn/nope")
        }
    }
}
