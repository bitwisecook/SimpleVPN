// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
//  YubiKeyManagerToolTests.swift
//  Parsing `ykman` output, and the slot challenge-response primitive.
//
//  THERE IS NO YUBIKEY ON THE MACHINE THIS WAS WRITTEN ON, and `ykman` is not
//  installed on it either. So every fixture below is RECORDED output whose format is
//  pinned to a named source, and every source is named at its fixture:
//
//   • `ykman list` — the format string in `list_keys` /`_describe_device`
//     (`ykman/_cli/__main__.py`, github.com/Yubico/yubikey-manager, BSD-2-Clause):
//     `{name} ({version}) [{mode}]` plus `" Serial: {serial}"`, and the
//     `<access denied>` fallback.
//   • `ykman list --serials` — one serial per line, per Yubico's published CLI
//     guide (docs.yubico.com/software/yubikey/tools/ykman/Base_Commands.html).
//   • `ykman info` — the five header lines exactly as that same page publishes them.
//   • `ykman otp info` — `click.echo(f"Slot 1: {…'programmed' or 'empty'}")` from
//     `ykman/_cli/otp.py`.
//   • `ykman oath accounts list|code` — the echo statements and the dynamic column
//     format `"{:<name}  {:>code}"` from `ykman/_cli/oath.py`, including the
//     `[Requires Touch]` and `[HOTP Account]` markers.
//   • `ykman otp calculate` — `response.hex()` from `ykman/_cli/otp.py`; HMAC-SHA1
//     is always 20 bytes, so exactly 40 lowercase hex characters.
//
//  Anything NOT verified says so: the `ykman info` "Applications" block's exact
//  column spacing is not published, so the parser is lenient about it and nothing
//  important depends on it. That is stated in the parser and asserted here.
//
//  The KeePassXC padding vectors ARE verifiable, and are: KeePassXC's own
//  `YubiKeyInterfaceUSB.cpp` pads the challenge to 64 bytes PKCS#7-style ("append
//  padLen bytes each holding padLen") and trims the response to 20. Getting that
//  wrong produces a silently WRONG answer — a database that unlocks everywhere else
//  and not here, with no error to explain it — which is why it is pinned by
//  arithmetic rather than by comment.
//

import Foundation
import Testing
@testable import SimpleVPN

// MARK: - A stub tool

/// The injection point that makes all of this testable with none of the hardware or
/// software present: one protocol, one method that would have spawned a process.
private struct StubYkman: YubiKeyToolRunning {
    var installed = true
    var stdout = ""
    var stderr = ""
    var exitCode: Int32 = 0
    var timedOut = false
    /// Every invocation's arguments, so a test can assert what did (and did not) ride
    /// argv.
    let recorded = ArgumentLog()

    final class ArgumentLog: @unchecked Sendable {
        private let lock = NSLock()
        private var calls: [[String]] = []
        func record(_ arguments: [String]) { lock.lock(); calls.append(arguments); lock.unlock() }
        var all: [[String]] { lock.lock(); defer { lock.unlock() }; return calls }
    }

    func locate() -> String? { installed ? "/opt/homebrew/bin/ykman" : nil }

    func run(_ arguments: [String], deadline: TimeInterval) async -> LocalToolResult {
        recorded.record(arguments)
        guard installed else {
            return LocalToolResult(exitCode: -1, stdout: Data(),
                                   stderr: "not installed", timedOut: false)
        }
        return LocalToolResult(exitCode: exitCode, stdout: Data(stdout.utf8),
                              stderr: stderr, timedOut: timedOut)
    }
}

// MARK: - `ykman list`

struct YkmanListParsingTests {

    @Test func aRealDeviceLine() throws {
        let key = try #require(
            YkmanOutput.parseList("YubiKey 5 NFC (5.4.3) [OTP+FIDO+CCID] Serial: 12345678").first)
        #expect(key.name == "YubiKey 5 NFC")
        #expect(key.firmware == "5.4.3")
        #expect(key.interfaces == "OTP+FIDO+CCID")
        #expect(key.serial == "12345678")
        #expect(key.accessDenied == false)
    }

    /// A key with no serial: the `" Serial: …"` suffix is simply absent, and it must
    /// not be reported as an unnamed device.
    @Test func aKeyWithNoSerial() throws {
        let key = try #require(
            YkmanOutput.parseList("YubiKey NEO (3.4.9) [OTP+FIDO+CCID]").first)
        #expect(key.name == "YubiKey NEO")
        #expect(key.firmware == "3.4.9")
        #expect(key.serial == nil)
    }

    /// `ykman` can SEE a device it cannot open. "No key" would be the wrong thing to
    /// tell the user — the key is right there.
    @Test func theAccessDeniedFallback() throws {
        let key = try #require(YkmanOutput.parseList("YubiKey [FIDO] <access denied>").first)
        #expect(key.name == "YubiKey")
        #expect(key.firmware == nil)
        #expect(key.interfaces == "FIDO")
        #expect(key.accessDenied)
    }

    @Test func severalKeysAtOnce() {
        let output = """
        YubiKey 5 NFC (5.4.3) [OTP+FIDO+CCID] Serial: 12345678
        YubiKey 5C Nano (5.2.7) [OTP+FIDO+CCID] Serial: 87654321
        Security Key by Yubico (5.1.2) [FIDO]
        """
        let keys = YkmanOutput.parseList(output)
        #expect(keys.count == 3)
        #expect(keys.map(\.serial) == ["12345678", "87654321", nil])
        #expect(keys[2].name == "Security Key by Yubico")
    }

    @Test func blankLinesAndPaddingAreIgnored() {
        let output = "\n  YubiKey 5 NFC (5.4.3) [OTP+FIDO+CCID] Serial: 1  \n\n"
        #expect(YkmanOutput.parseList(output).count == 1)
        #expect(YkmanOutput.parseList("").isEmpty)
        #expect(YkmanOutput.parseList("\n\n \n").isEmpty)
    }

    @Test func serialsOnlyMode() {
        #expect(YkmanOutput.parseSerials("0123456\n") == ["0123456"])
        #expect(YkmanOutput.parseSerials("12345678\n87654321\n") == ["12345678", "87654321"])
        // Anything that isn't a bare number is not a serial — a banner or a warning
        // line must never become one.
        #expect(YkmanOutput.parseSerials("WARNING: something\n12345678") == ["12345678"])
        #expect(YkmanOutput.parseSerials("").isEmpty)
    }
}

// MARK: - `ykman info`

struct YkmanInfoParsingTests {

    /// The five header lines exactly as Yubico's CLI guide publishes them.
    private let fixture = """
    Device type: YubiKey 5Ci FIPS
    Serial number: 31234067
    Firmware version: 5.7.3
    Form factor: Keychain (USB-C, Lightning)
    Enabled USB interfaces: OTP, FIDO, CCID
    """

    @Test func theVerifiedHeaderLines() {
        let info = YkmanOutput.parseInfo(fixture)
        #expect(info.deviceType == "YubiKey 5Ci FIPS")
        #expect(info.serial == "31234067")
        #expect(info.firmware == "5.7.3")
        // Note the value itself contains a comma and parentheses — it must survive.
        #expect(info.formFactor == "Keychain (USB-C, Lightning)")
        #expect(info.enabledUSBInterfaces == ["OTP", "FIDO", "CCID"])
    }

    /// The two facts anything is DECIDED on: OATH lives behind CCID, and a Yubico
    /// OTP needs the typing interface.
    @Test func theInterfacesDecideWhatIsReachable() {
        let all = YkmanOutput.parseInfo(fixture)
        #expect(all.hasCCID)
        #expect(all.hasOTP)

        let fidoOnly = YkmanOutput.parseInfo("Enabled USB interfaces: FIDO")
        #expect(fidoOnly.hasCCID == false)
        #expect(fidoOnly.hasOTP == false)

        // Case must not decide it.
        let lower = YkmanOutput.parseInfo("Enabled USB interfaces: otp, ccid")
        #expect(lower.hasCCID)
        #expect(lower.hasOTP)
    }

    /// The Applications block's exact spacing is NOT published, so the parser is
    /// lenient — tab-separated or run-of-spaces, either way. Nothing important
    /// depends on it, which is why this is the only claim made about it.
    @Test func theApplicationsBlockIsParsedLeniently() {
        let tabbed = fixture + """

        Applications
        \tYubico OTP\tEnabled
        \tFIDO2\tEnabled
        \tOATH\tDisabled
        \tYubiHSM Auth\tNot available
        """
        let info = YkmanOutput.parseInfo(tabbed)
        #expect(info.applications["Yubico OTP"] == "Enabled")
        #expect(info.applications["OATH"] == "Disabled")
        #expect(info.applications["YubiHSM Auth"] == "Not available")
        // The headers still parsed — the block must not swallow them.
        #expect(info.serial == "31234067")

        let spaced = """
        Applications
          Yubico OTP        Enabled
          OATH              Disabled
        """
        let alt = YkmanOutput.parseInfo(spaced)
        #expect(alt.applications["Yubico OTP"] == "Enabled")
        #expect(alt.applications["OATH"] == "Disabled")
    }

    @Test func anEmptyOrUnexpectedOutputYieldsNothingRatherThanNonsense() {
        let empty = YkmanOutput.parseInfo("")
        #expect(empty.deviceType == nil)
        #expect(empty.enabledUSBInterfaces.isEmpty)
        #expect(empty.hasCCID == false)
    }

    /// A name containing a single space must survive the gap split; only a run of two
    /// or more spaces (or a tab) is a column separator.
    @Test func theGapSplitKeepsNamesWithSingleSpacesIntact() throws {
        let split = try #require(YkmanOutput.splitOnGap("Yubico OTP        Enabled"))
        #expect(split.0 == "Yubico OTP")
        #expect(split.1 == "Enabled")
        #expect(YkmanOutput.splitOnGap("NoGapHere") == nil)
        #expect(YkmanOutput.splitOnGap("one space only") == nil)
    }
}

// MARK: - `ykman otp info`

struct YkmanOTPSlotParsingTests {

    @Test func bothSlotStates() {
        let status = YkmanOutput.parseOTPSlots("Slot 1: programmed\nSlot 2: empty")
        #expect(status.slotOneProgrammed)
        #expect(status.slotTwoProgrammed == false)
        #expect(status.isProgrammed(.one))
        #expect(status.isProgrammed(.two) == false)
    }

    @Test func slotTwoProgrammedIsTheChallengeResponseCase() {
        let status = YkmanOutput.parseOTPSlots("Slot 1: empty\nSlot 2: programmed")
        #expect(status.isProgrammed(.two))
    }

    @Test func nothingParsedMeansNothingProgrammed() {
        let status = YkmanOutput.parseOTPSlots("")
        #expect(status.slotOneProgrammed == false)
        #expect(status.slotTwoProgrammed == false)
        // Not a slot line — must not be misread as one.
        #expect(YkmanOutput.parseOTPSlots("Something else entirely").slotOneProgrammed == false)
    }
}

// MARK: - `ykman oath accounts`

struct YkmanOATHParsingTests {

    @Test func accountsWithTypeAndPeriod() {
        let output = """
        Example:user@example.com, TOTP, 30
        15/Short:period@example.com, TOTP, 15
        Bank:me, HOTP
        NoIssuer, TOTP, 30
        """
        let accounts = YkmanOutput.parseAccounts(output)
        #expect(accounts.count == 4)

        #expect(accounts[0].id == "Example:user@example.com")
        #expect(accounts[0].issuer == "Example")
        #expect(accounts[0].name == "user@example.com")
        #expect(accounts[0].kind == .totp)
        #expect(accounts[0].period == 30)

        // The `period/` prefix is part of the ID — which is what goes back as a
        // query — but not part of the issuer.
        #expect(accounts[1].id == "15/Short:period@example.com")
        #expect(accounts[1].issuer == "Short")
        #expect(accounts[1].period == 15)

        #expect(accounts[2].kind == .hotp)
        #expect(accounts[2].period == nil)
        // HOTP steps a counter, so it needs a single-match request rather than a
        // batch read.
        #expect(accounts[2].needsSingleMatchRequest)

        #expect(accounts[3].issuer == nil)
        #expect(accounts[3].name == "NoIssuer")
    }

    /// The ID goes back to `ykman` verbatim as a query, so it must be preserved
    /// exactly — including any commas in the account NAME, which the metadata split
    /// must not eat.
    @Test func anAccountNameContainingACommaSurvives() throws {
        let account = try #require(
            YkmanOutput.parseAccounts("Corp:Smith, John <j@example.com>, TOTP, 30").first)
        #expect(account.id == "Corp:Smith, John <j@example.com>")
        #expect(account.kind == .totp)
        #expect(account.period == 30)
    }

    @Test func aBareIDWithNoMetadata() throws {
        let account = try #require(YkmanOutput.parseAccounts("Example:me").first)
        #expect(account.id == "Example:me")
        #expect(account.kind == nil)
        #expect(account.period == nil)
    }

    /// A name containing colons (a URL) splits on the FIRST colon only.
    @Test func theIssuerSplitTakesTheFirstColon() {
        let split = YkmanOutput.splitCredentialID("Site:https://example.com/login")
        #expect(split.issuer == "Site")
        #expect(split.name == "https://example.com/login")
        // A non-numeric prefix before a slash is NOT a period.
        let notPeriod = YkmanOutput.splitCredentialID("some/path:me")
        #expect(notPeriod.issuer == "some/path")
    }

    @Test func codesWithTheDynamicColumnFormat() {
        // Columns padded to the longest name and the longest code, two spaces between.
        let output = """
        Example:user@example.com    123456
        Bank:me                     [HOTP Account]
        Touchy:me                   [Requires Touch]
        """
        let lines = YkmanOutput.parseCodes(output)
        #expect(lines.count == 3)
        #expect(lines[0].accountID == "Example:user@example.com")
        #expect(lines[0].code == "123456")
        #expect(lines[0].marker == nil)
        #expect(lines[1].marker == .hotpAccount)
        #expect(lines[1].code == nil)
        #expect(lines[2].marker == .requiresTouch)
        #expect(lines[2].code == nil)
    }

    /// `--single` prints only the code. Parsing it must be STRICT: this value goes to
    /// a gateway, and a banner line accepted as a "code" would burn an authentication
    /// attempt for nothing.
    @Test func singleModeAcceptsOnlyACodeShapedLine() {
        #expect(YkmanOutput.parseSingleCode("123456\n") == "123456")
        #expect(YkmanOutput.parseSingleCode("  12345678  ") == "12345678")
        // Leading zeros are significant, so the code stays a string.
        #expect(YkmanOutput.parseSingleCode("000042") == "000042")
        for junk in ["", "\n", "Enter your password:", "12345", "123456789", "12 3456",
                     "abcdef", "[Requires Touch]", "123456 extra"] {
            #expect(YkmanOutput.parseSingleCode(junk) == nil, Comment(rawValue: junk.debugDescription))
        }
    }

    /// A tool that prints a warning before the code: the LAST non-empty line is the
    /// answer, and it still has to be code-shaped.
    @Test func aWarningBeforeTheCodeDoesNotStopIt() {
        #expect(YkmanOutput.parseSingleCode("Touch your YubiKey...\n123456\n") == "123456")
    }

    @Test func sevenDigitCodesAreAccepted() {
        // RFC 4226 allows 6–8; ykman offers 6 and 8, but a 7 from another source must
        // not be rejected as malformed.
        #expect(YkmanOutput.isCodeShaped("1234567"))
        #expect(YkmanOutput.isCodeShaped("12345") == false)
        #expect(YkmanOutput.isCodeShaped("123456789") == false)
    }
}

// MARK: - Failure classification

struct YkmanFailureClassificationTests {

    private func result(stderr: String, exitCode: Int32 = 1,
                        timedOut: Bool = false) -> LocalToolResult {
        LocalToolResult(exitCode: exitCode, stdout: Data(), stderr: stderr, timedOut: timedOut)
    }

    @Test func theToolNotBeingInstalledIsItsOwnState() {
        #expect(YkmanOutput.classify(result(stderr: "not installed", exitCode: -1)) == .toolMissing)
    }

    @Test func aTimeoutIsAMissingTouchRatherThanAFailure() {
        #expect(YkmanOutput.classify(result(stderr: "", timedOut: true)) == .touchTimedOut)
    }

    @Test func noKeyAndTooManyKeysAreDistinguished() {
        #expect(YkmanOutput.classify(result(stderr: "No YubiKey found.")) == .noKeyAttached)
        #expect(YkmanOutput.classify(result(stderr: "Failed connecting to a YubiKey"))
                == .noKeyAttached)
        #expect(YkmanOutput.classify(result(stderr: "Multiple YubiKeys found"))
                == .severalKeysAttached)
    }

    /// A password-protected OATH applet is a dead end for us on purpose: we will not
    /// put a password on a command line where every process can read it. So it gets
    /// its own state, with a remedy the user can carry out themselves.
    @Test func aPasswordProtectedAppletIsItsOwnStateWithARemedy() throws {
        let error = YkmanOutput.classify(result(stderr: "Authentication to the YubiKey failed. Wrong password?"))
        #expect(error == .oathPasswordRequired)
        let remedy = try #require(error.remedy)
        #expect(remedy.contains("-r"))          // ykman's own "remember it" flag
    }

    /// Every state has something to say AND something to do. A failure with no way
    /// forward is where people give up.
    @Test func everyErrorHasADescriptionAndARemedy() {
        let errors: [YubiKeyToolError] = [
            .toolMissing, .noKeyAttached, .severalKeysAttached, .oathPasswordRequired,
            .appletDisabled("code"), .noSuchAccount("Example:me"),
            .severalAccountsMatched("Example"), .touchTimedOut, .unreadableOutput,
            .failed(detail: "something"),
        ]
        for error in errors {
            #expect(error.errorDescription?.isEmpty == false, "\(error)")
            #expect(error.remedy?.isEmpty == false, "\(error)")
        }
    }

    /// An unrecognised message falls through with the runner's ALREADY-SCRUBBED
    /// stderr rather than being guessed at.
    @Test func anUnrecognisedFailureCarriesTheScrubbedDetail() {
        #expect(YkmanOutput.classify(result(stderr: "some novel failure"))
                == .failed(detail: "some novel failure"))
    }
}

// MARK: - The operations, over the stub

struct YubiKeyManagerToolOperationTests {

    @Test func oathCodeAlwaysUsesSingleMatchAndNeverPutsTheCodeInArgv() async throws {
        let stub = StubYkman(stdout: "123456\n")
        let tool = YubiKeyManagerTool(runner: stub)
        let box = try await tool.oathCode(account: "Example:me", serial: "12345678")
        #expect(box.consume() == "123456")
        #expect(box.consume() == nil)

        let call = try #require(stub.recorded.all.first)
        // `--single` is a CORRECTNESS requirement, not tidiness: ykman refuses to
        // produce a code for an HOTP or touch-required account without it, and a
        // batch read would step every HOTP counter to fetch one.
        #expect(call.contains("--single"))
        #expect(call == ["--device", "12345678", "oath", "accounts", "code",
                         "--single", "Example:me"])
        // The account LABEL rides argv; nothing else does.
        #expect(call.contains("123456") == false)
    }

    /// An OATH code is time-bounded as well as single-use, and the box enforces both.
    @Test func anOATHCodeCarriesAnExpiry() async throws {
        let tool = YubiKeyManagerTool(runner: StubYkman(stdout: "123456"))
        let box = try await tool.oathCode(account: "Example:me")
        #expect(box.expiresAt != nil)
        #expect((box.secondsRemaining() ?? 0) <= OATHAccount.defaultPeriod)
    }

    @Test func aNonNumericSerialIsNeverPassedOn() async throws {
        let stub = StubYkman(stdout: "123456")
        _ = try await YubiKeyManagerTool(runner: stub).oathCode(account: "Example:me",
                                                               serial: "my key; rm -rf /")
        let call = try #require(stub.recorded.all.first)
        #expect(call.contains("--device") == false)
        #expect(call == ["oath", "accounts", "code", "--single", "Example:me"])
    }

    @Test func anEmptyAccountIsRefusedWithoutSpawningAnything() async {
        let stub = StubYkman(stdout: "123456")
        await #expect(throws: YubiKeyToolError.noSuchAccount("")) {
            _ = try await YubiKeyManagerTool(runner: stub).oathCode(account: "   ")
        }
        #expect(stub.recorded.all.isEmpty)
    }

    @Test func anUnreadableAnswerIsRefusedRatherThanSent() async {
        let tool = YubiKeyManagerTool(runner: StubYkman(stdout: "Enter your password:"))
        await #expect(throws: YubiKeyToolError.unreadableOutput) {
            _ = try await tool.oathCode(account: "Example:me")
        }
    }

    /// A failure names the query the user typed, or the message is useless.
    @Test func aMissingAccountErrorNamesTheQuery() async {
        let tool = YubiKeyManagerTool(
            runner: StubYkman(stdout: "", stderr: "No matching account", exitCode: 1))
        await #expect(throws: YubiKeyToolError.noSuchAccount("Example:me")) {
            _ = try await tool.oathCode(account: "Example:me")
        }
    }

    @Test func withoutTheToolNothingIsAttempted() async {
        let tool = YubiKeyManagerTool(runner: StubYkman(installed: false))
        #expect(tool.isInstalled == false)
        await #expect(throws: YubiKeyToolError.toolMissing) { _ = try await tool.list() }
    }

    @Test func listingAccountsAsksForTypeAndPeriodSoThePickerCanBeHonest() async throws {
        let stub = StubYkman(stdout: "Example:me, TOTP, 30")
        _ = try await YubiKeyManagerTool(runner: stub).oathAccounts()
        let call = try #require(stub.recorded.all.first)
        #expect(call == ["oath", "accounts", "list", "--oath-type", "--period"])
    }
}

// MARK: - The reusable challenge-response primitive

struct YubiKeyChallengeResponseTests {

    /// KeePassXC pads the challenge to 64 bytes PKCS#7-style: append `64 - len` bytes
    /// each holding the value `64 - len`. Verified against KeePassXC's own
    /// `YubiKeyInterfaceUSB.cpp`. This is the vector the kdbx adapter depends on.
    @Test func keePassPaddingMatchesKeePassXCsOwnScheme() {
        let challenge = Data(repeating: 0xAB, count: 32)
        let padded = YubiKeyChallengeResponse.pad(challenge, .keePassPKCS7To64)
        #expect(padded.count == 64)
        #expect(padded.prefix(32) == challenge)
        #expect(padded.suffix(32).allSatisfy { $0 == 32 })
    }

    @Test func keePassPaddingAtEveryLengthUpTo64() {
        for length in 1..<64 {
            let padded = YubiKeyChallengeResponse.pad(Data(repeating: 0x01, count: length),
                                                      .keePassPKCS7To64)
            #expect(padded.count == 64, "length \(length)")
            let padLength = 64 - length
            #expect(padded.suffix(padLength).allSatisfy { $0 == UInt8(padLength) },
                    "length \(length)")
        }
    }

    /// A challenge that is ALREADY 64 bytes is sent unchanged. This is precisely where
    /// a textbook PKCS#7 implementation would differ (it would add a whole further
    /// block), and differing would produce a wrong answer with no error.
    @Test func aFullLengthChallengeIsNotGivenAFurtherBlock() {
        let full = Data(repeating: 0x7F, count: 64)
        #expect(YubiKeyChallengeResponse.pad(full, .keePassPKCS7To64) == full)
    }

    @Test func noPaddingSendsTheChallengeExactlyAsGiven() {
        let challenge = Data([0xDE, 0xAD, 0xBE, 0xEF])
        #expect(YubiKeyChallengeResponse.pad(challenge, .none) == challenge)
    }

    @Test func hexEncodingIsLowercaseAndTwoCharactersPerByte() {
        #expect(YubiKeyChallengeResponse.hexEncode(Data([0x00, 0x0F, 0xAB, 0xFF]))
                == "000fabff")
        #expect(YubiKeyChallengeResponse.hexEncode(Data()).isEmpty)
    }

    /// `ykman otp calculate` prints `response.hex()` — HMAC-SHA1 is always 20 bytes,
    /// so exactly 40 lowercase hex characters. Anything else must be REFUSED rather
    /// than half-decoded into wrong key material.
    @Test func aResponseIsExactlyTwentyBytesOfHexOrNothing() throws {
        let hex = "0102030405060708090a0b0c0d0e0f1011121314"
        let bytes = try #require(YkmanOutput.parseChallengeResponse(hex))
        #expect(bytes.count == 20)
        #expect(Array(bytes) == Array(UInt8(1)...UInt8(20)))
        // Case and whitespace tolerated; length and alphabet are not.
        #expect(YkmanOutput.parseChallengeResponse("  " + hex.uppercased() + "\n") == bytes)
        for bad in ["", hex.dropLast().description, hex + "00",
                    String(repeating: "z", count: 40), "0x" + hex] {
            #expect(YkmanOutput.parseChallengeResponse(bad) == nil,
                    Comment(rawValue: bad.debugDescription))
        }
    }

    @Test func theOperationSendsThePaddedChallengeAsHexToTheChosenSlot() async throws {
        let stub = StubYkman(stdout: "0102030405060708090a0b0c0d0e0f1011121314")
        var primitive = YubiKeyChallengeResponse(slot: .two,
                                                 tool: YubiKeyManagerTool(runner: stub))
        let response = try await primitive.keyMaterial(for: Data(repeating: 0xAB, count: 32))
        #expect(response.count == YubiKeyChallengeResponse.responseLength)

        let call = try #require(stub.recorded.all.first)
        #expect(call[0...2] == ["otp", "calculate", "2"])
        // The padded 64-byte challenge, in hex: 32 bytes of AB then 32 bytes of 0x20.
        let expected = String(repeating: "ab", count: 32) + String(repeating: "20", count: 32)
        #expect(call[3] == expected)
        #expect(call[3].count == 128)

        primitive.slot = .one
        _ = try await primitive.respond(toPublicChallenge: Data([0x01]), padding: .none)
        #expect(stub.recorded.all.last?[0...3] == ["otp", "calculate", "1", "01"])
    }

    @Test func aVerificationCodeComesBackInTheReadOnceBox() async throws {
        let stub = StubYkman(stdout: "0102030405060708090a0b0c0d0e0f1011121314")
        let primitive = YubiKeyChallengeResponse(tool: YubiKeyManagerTool(runner: stub))
        let box = try await primitive.verificationCode(
            forGatewayChallenge: Data([0xDE, 0xAD]))
        #expect(box.consume() == "0102030405060708090a0b0c0d0e0f1011121314")
        #expect(box.consume() == nil)
        #expect(box.origin == .computedByDevice)
    }

    @Test func anEmptyOrOversizedChallengeIsRefusedWithoutSpawningAnything() async {
        let stub = StubYkman(stdout: "0102030405060708090a0b0c0d0e0f1011121314")
        let primitive = YubiKeyChallengeResponse(tool: YubiKeyManagerTool(runner: stub))
        await #expect(throws: YubiKeyToolError.unreadableOutput) {
            _ = try await primitive.respond(toPublicChallenge: Data(), padding: .none)
        }
        await #expect(throws: YubiKeyToolError.unreadableOutput) {
            _ = try await primitive.respond(toPublicChallenge: Data(repeating: 0, count: 65),
                                            padding: .none)
        }
        #expect(stub.recorded.all.isEmpty)
    }

    @Test func aSlotWithNoCredentialIsDiscoverableBeforeItIsNeeded() async throws {
        let programmed = YubiKeyChallengeResponse(
            slot: .two,
            tool: YubiKeyManagerTool(runner: StubYkman(stdout: "Slot 1: empty\nSlot 2: programmed")))
        #expect(try await programmed.isSlotProgrammed())

        let empty = YubiKeyChallengeResponse(
            slot: .two,
            tool: YubiKeyManagerTool(runner: StubYkman(stdout: "Slot 1: programmed\nSlot 2: empty")))
        #expect(try await empty.isSlotProgrammed() == false)
    }

    @Test func theSlotVocabularyIsYubicosOwn() {
        #expect(YubiKeySlot.one.displayName == "Slot 1")
        #expect(YubiKeySlot.two.displayName == "Slot 2")
        #expect(YubiKeySlot.two.touchDescription.contains("long"))
        #expect(YubiKeySlot.one.touchDescription.contains("short"))
    }
}

// MARK: - Detection, without a key and without Input Monitoring

struct SecurityKeyPresenceTests {

    private func key(typing: Bool, productID: Int = 0x0407) -> AttachedSecurityKey {
        AttachedSecurityKey(id: 1, productName: "YubiKey OTP+FIDO+CCID",
                            vendorID: YubicoUSB.vendorID, productID: productID,
                            typesAsKeyboard: typing, presentsFIDO: true)
    }

    @Test func nothingPluggedInSaysSoPlainly() {
        let presence = SecurityKeyPresence()
        #expect(presence.isAttached == false)
        #expect(presence.hasTypingKey == false)
        #expect(presence.hasKeyWithoutTypingInterface == false)
        #expect(presence.summary.contains("No security key"))
    }

    /// "A key is plugged in but its code applet is off" and "no key at all" have
    /// completely different fixes, so they are different states.
    @Test func aKeyWithNoTypingInterfaceIsNotTheSameAsNoKey() {
        var presence = SecurityKeyPresence()
        presence.keys = [key(typing: false)]
        #expect(presence.isAttached)
        #expect(presence.hasTypingKey == false)
        #expect(presence.hasKeyWithoutTypingInterface)
        #expect(presence.summary.contains("isn\u{2019}t switched on"))
    }

    @Test func aTypingKeyIsReadyAndSaysSo() {
        var presence = SecurityKeyPresence()
        presence.keys = [key(typing: true)]
        #expect(presence.hasTypingKey)
        #expect(presence.summary.contains("ready to type"))
    }

    @Test func severalKeysAreCountedAndTheTypingOnesDistinguished() {
        var presence = SecurityKeyPresence()
        presence.keys = [key(typing: true), key(typing: false)]
        #expect(presence.keys.count == 2)
        #expect(presence.typingKeys.count == 1)
        #expect(presence.summary.contains("2 security keys"))
        #expect(presence.summary.contains("1 will type"))
    }

    /// The product-id table comes from Yubico's own `yubikit.core.PID`. The YubiKey 5
    /// series REUSES the YubiKey 4 ids — that is Yubico's choice, so the table says
    /// "YubiKey" rather than guessing a generation the id does not carry.
    @Test func theProductTableMatchesYubicosOwn() {
        #expect(YubicoUSB.vendorID == 0x1050)
        #expect(YubicoUSB.family(productID: 0x0407) == "YubiKey")
        #expect(YubicoUSB.family(productID: 0x0116) == "YubiKey NEO")
        #expect(YubicoUSB.family(productID: 0x0120) == "Security Key by Yubico")
        #expect(YubicoUSB.family(productID: 0x0010) == "YubiKey Standard")
        #expect(YubicoUSB.family(productID: 0x0410) == "YubiKey Plus")
        #expect(YubicoUSB.family(productID: 0x9999) == nil)
    }

    @Test func theInterfaceSetSaysWhatTheIDCarriesAndNothingMore() {
        #expect(YubicoUSB.interfaces(productID: 0x0407) == "OTP+FIDO+CCID")
        #expect(YubicoUSB.interfaces(productID: 0x0402) == "FIDO")
        #expect(YubicoUSB.builtWithOTP(productID: 0x0407))
        // FIDO-only: touching it will never type a code.
        #expect(YubicoUSB.builtWithOTP(productID: 0x0402) == false)
        #expect(YubicoUSB.builtWithOTP(productID: 0x0120) == false)
        // An id we have never seen says so rather than guessing.
        #expect(YubicoUSB.interfaces(productID: 0x9999).contains("not known"))
        #expect(YubicoUSB.builtWithOTP(productID: 0x9999) == false)
    }

    /// The scan reads the IORegistry and opens nothing. On a machine with no key it
    /// must answer cleanly rather than throwing or hanging — which is also the only
    /// assertion this test can honestly make here.
    @Test func theRealScanRunsAndAnswersOnAMachineWithNoKey() async {
        let keys = await MainActor.run { IORegistrySecurityKeyScanner().scan() }
        // Not an assertion about the count: whoever runs this may have a key plugged
        // in. What IS asserted is that every row it produces is Yubico's, which is
        // what the matching dictionary is supposed to guarantee.
        for found in keys {
            #expect(found.vendorID == YubicoUSB.vendorID)
        }
    }
}
