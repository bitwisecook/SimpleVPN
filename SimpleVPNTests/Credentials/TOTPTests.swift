// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
//  TOTPTests.swift
//  Pins the TOTP engine to published truth and to paste-tolerant parsing:
//    • the full RFC 6238 Appendix B vector table for SHA-1/-256/-512 — note
//      each algorithm uses a different-length seed (20/32/64 bytes of the
//      repeating ASCII "12345678901234567890"), a detail the RFC buries in a
//      footnote and implementations routinely get wrong;
//    • base32 must accept every form a human pastes (lowercase, spaces,
//      dashes, optional padding) but reject anything outside the alphabet —
//      a mistyped secret must fail, never mint plausible wrong codes;
//    • otpauth:// URIs: full param set, RFC-mandated defaults when params are
//      absent, percent-encoded Issuer:Account labels, case-insensitive
//      algorithm names, and hard rejection of counter-based hotp;
//    • period edges: the code flips exactly at the 30 s boundary and the
//      countdown reads full-period at the instant of rollover.
//

import Foundation
import Testing
@testable import SimpleVPN

struct TOTPTests {

    /// RFC 6238 seeds: the ASCII digits "12345678901234567890" repeated to the
    /// hash's block-appropriate length — 20 bytes (SHA-1), 32 (SHA-256), 64 (SHA-512).
    private func seed(length: Int) -> Data {
        let pattern = Array("12345678901234567890".utf8)
        return Data((0..<length).map { pattern[$0 % pattern.count] })
    }

    private func config(_ algorithm: TOTPAlgorithm, seedLength: Int) -> TOTPConfiguration {
        TOTPConfiguration(secret: seed(length: seedLength), algorithm: algorithm,
                          digits: 8, period: 30)
    }

    // MARK: - RFC 6238 Appendix B vectors

    /// (unix time, SHA-1, SHA-256, SHA-512) rows exactly as published.
    private nonisolated static let appendixB: [(t: Double, sha1: String, sha256: String, sha512: String)] = [
        (59,          "94287082", "46119246", "90693936"),
        (1111111109,  "07081804", "68084774", "25091201"),
        (1111111111,  "14050471", "67062674", "99943326"),
        (1234567890,  "89005924", "91819424", "93441116"),
        (2000000000,  "69279037", "90698825", "38618901"),
        (20000000000, "65353130", "77737706", "47863826"),
    ]

    @Test(arguments: appendixB)
    func rfc6238SHA1(vector: (t: Double, sha1: String, sha256: String, sha512: String)) {
        let cfg = config(.sha1, seedLength: 20)
        #expect(cfg.code(at: Date(timeIntervalSince1970: vector.t)) == vector.sha1)
    }

    @Test(arguments: appendixB)
    func rfc6238SHA256(vector: (t: Double, sha1: String, sha256: String, sha512: String)) {
        let cfg = config(.sha256, seedLength: 32)
        #expect(cfg.code(at: Date(timeIntervalSince1970: vector.t)) == vector.sha256)
    }

    @Test(arguments: appendixB)
    func rfc6238SHA512(vector: (t: Double, sha1: String, sha256: String, sha512: String)) {
        let cfg = config(.sha512, seedLength: 64)
        #expect(cfg.code(at: Date(timeIntervalSince1970: vector.t)) == vector.sha512)
    }

    // MARK: - Base32 decoding

    private let foobar = Data("foobar".utf8)

    @Test func base32CanonicalWithPadding() {
        #expect(TOTPConfiguration.base32Decode("MZXW6YTBOI======") == foobar)
    }

    @Test func base32WithoutPadding() {
        #expect(TOTPConfiguration.base32Decode("MZXW6YTBOI") == foobar)
    }

    @Test func base32Lowercase() {
        #expect(TOTPConfiguration.base32Decode("mzxw6ytboi") == foobar)
    }

    @Test func base32SpacesAndDashes() {
        #expect(TOTPConfiguration.base32Decode("mzxw 6ytb-oi") == foobar)
        #expect(TOTPConfiguration.base32Decode("MZXW-6YTB OI==") == foobar)
    }

    @Test func base32RejectsInvalidCharacters() {
        // '0', '1', '8', '9' are deliberately absent from the RFC 4648 alphabet.
        #expect(TOTPConfiguration.base32Decode("MZXW6YTB0I") == nil)
        #expect(TOTPConfiguration.base32Decode("MZXW6YTB1I") == nil)
        #expect(TOTPConfiguration.base32Decode("ABC!DEF") == nil)
    }

    @Test func base32RejectsDataAfterPadding() {
        #expect(TOTPConfiguration.base32Decode("MZXW6YTBOI==MZ") == nil)
    }

    @Test func parsingRejectsHopelessInput() {
        #expect(throws: TOTPParseError.emptyInput) {
            try TOTPConfiguration.parse("   ")
        }
        #expect(throws: TOTPParseError.invalidBase32) {
            try TOTPConfiguration.parse("not base32 at all!")
        }
    }

    // MARK: - otpauth:// URI parsing

    @Test func uriFullParameterSet() throws {
        let cfg = try TOTPConfiguration.parse(
            "otpauth://totp/Example:alice@example.com?secret=JBSWY3DPEHPK3PXP&issuer=Example&algorithm=SHA256&digits=8&period=60")
        #expect(cfg.secret == TOTPConfiguration.base32Decode("JBSWY3DPEHPK3PXP"))
        #expect(cfg.algorithm == .sha256)
        #expect(cfg.digits == 8)
        #expect(cfg.period == 60)
        #expect(cfg.issuer == "Example")
        #expect(cfg.accountName == "alice@example.com")
    }

    @Test func uriDefaultsWhenParamsAbsent() throws {
        let cfg = try TOTPConfiguration.parse("otpauth://totp/alice?secret=JBSWY3DPEHPK3PXP")
        #expect(cfg.algorithm == .sha1)
        #expect(cfg.digits == 6)
        #expect(cfg.period == 30)
        #expect(cfg.issuer == nil)
        #expect(cfg.accountName == "alice")
    }

    @Test func uriPercentEncodedLabel() throws {
        let cfg = try TOTPConfiguration.parse(
            "otpauth://totp/Big%20Corp%3Aalice%40example.com?secret=JBSWY3DPEHPK3PXP")
        #expect(cfg.issuer == "Big Corp")
        #expect(cfg.accountName == "alice@example.com")
    }

    @Test func uriIssuerParamOverridesLabelPrefix() throws {
        let cfg = try TOTPConfiguration.parse(
            "otpauth://totp/LabelIssuer:alice?secret=JBSWY3DPEHPK3PXP&issuer=ParamIssuer")
        #expect(cfg.issuer == "ParamIssuer")
        #expect(cfg.accountName == "alice")
    }

    @Test func uriAlgorithmCaseInsensitive() throws {
        let cfg = try TOTPConfiguration.parse(
            "otpauth://totp/alice?secret=JBSWY3DPEHPK3PXP&algorithm=sha512")
        #expect(cfg.algorithm == .sha512)
    }

    @Test func uriRejectsHOTP() {
        #expect(throws: TOTPParseError.unsupportedOTPType("hotp")) {
            try TOTPConfiguration.parse("otpauth://hotp/alice?secret=JBSWY3DPEHPK3PXP&counter=0")
        }
    }

    @Test func uriRejectsMissingSecret() {
        #expect(throws: TOTPParseError.missingSecret) {
            try TOTPConfiguration.parse("otpauth://totp/alice?digits=6")
        }
    }

    @Test func uriRejectsBadDigitsAndPeriod() {
        #expect(throws: TOTPParseError.invalidDigits("5")) {
            try TOTPConfiguration.parse("otpauth://totp/a?secret=JBSWY3DPEHPK3PXP&digits=5")
        }
        #expect(throws: TOTPParseError.invalidDigits("9")) {
            try TOTPConfiguration.parse("otpauth://totp/a?secret=JBSWY3DPEHPK3PXP&digits=9")
        }
        #expect(throws: TOTPParseError.invalidPeriod("0")) {
            try TOTPConfiguration.parse("otpauth://totp/a?secret=JBSWY3DPEHPK3PXP&period=0")
        }
        #expect(throws: TOTPParseError.invalidAlgorithm("MD5")) {
            try TOTPConfiguration.parse("otpauth://totp/a?secret=JBSWY3DPEHPK3PXP&algorithm=MD5")
        }
    }

    /// The failable convenience is what connect-time code uses on the stored
    /// canonical string — it must round-trip both storage forms and fail
    /// (not trap, not mis-parse) on corrupted keychain contents.
    @Test func failableInitMatchesThrowingParse() {
        #expect(TOTPConfiguration(parsing: "JBSWY3DPEHPK3PXP")?.digits == 6)
        #expect(TOTPConfiguration(parsing: "otpauth://totp/a?secret=JBSWY3DPEHPK3PXP&digits=7")?.digits == 7)
        #expect(TOTPConfiguration(parsing: "definitely not a secret 0!") == nil)
    }

    // MARK: - Canonical storage string

    @Test func canonicalStoragePreservesURIs() {
        let uri = "otpauth://totp/Example:alice?secret=JBSWY3DPEHPK3PXP&digits=8"
        #expect(TOTPConfiguration.canonicalStorageString(from: "  \(uri)\n") == uri)
    }

    @Test func canonicalStorageNormalisesBareSecrets() {
        #expect(TOTPConfiguration.canonicalStorageString(from: "mzxw 6ytb-oi==") == "MZXW6YTBOI")
        #expect(TOTPConfiguration.canonicalStorageString(from: "JBSWY3DPEHPK3PXP") == "JBSWY3DPEHPK3PXP")
    }

    @Test func canonicalStorageRejectsGarbage() {
        #expect(TOTPConfiguration.canonicalStorageString(from: "") == nil)
        #expect(TOTPConfiguration.canonicalStorageString(from: "hello world 0189!") == nil)
        #expect(TOTPConfiguration.canonicalStorageString(from: "otpauth://hotp/a?secret=JBSWY3DPEHPK3PXP") == nil)
    }

    // MARK: - Period boundaries

    private var boundaryConfig: TOTPConfiguration {
        TOTPConfiguration(secret: seed(length: 20))
    }

    @Test func codeStableWithinPeriodAndFlipsAtBoundary() {
        let cfg = boundaryConfig
        let atStart = cfg.code(at: Date(timeIntervalSince1970: 30))
        let justBefore = cfg.code(at: Date(timeIntervalSince1970: 59.9))
        let atBoundary = cfg.code(at: Date(timeIntervalSince1970: 60))
        #expect(atStart == justBefore)
        #expect(justBefore != atBoundary)
    }

    @Test func secondsRemainingAtEdges() {
        let cfg = boundaryConfig
        // At an exact boundary the freshly minted code has the full period.
        #expect(cfg.secondsRemaining(at: Date(timeIntervalSince1970: 0)) == 30)
        #expect(cfg.secondsRemaining(at: Date(timeIntervalSince1970: 30)) == 30)
        // One second into the period, one second short of the next.
        #expect(cfg.secondsRemaining(at: Date(timeIntervalSince1970: 1)) == 29)
        #expect(cfg.secondsRemaining(at: Date(timeIntervalSince1970: 29)) == 1)
        // Fractional seconds floor: 59.9 s is still in the 30–60 window.
        #expect(cfg.secondsRemaining(at: Date(timeIntervalSince1970: 59.9)) == 1)
    }

    @Test func nonDefaultPeriodRespected() throws {
        let cfg = try TOTPConfiguration.parse(
            "otpauth://totp/a?secret=JBSWY3DPEHPK3PXP&period=60")
        #expect(cfg.code(at: Date(timeIntervalSince1970: 0))
             == cfg.code(at: Date(timeIntervalSince1970: 59)))
        #expect(cfg.secondsRemaining(at: Date(timeIntervalSince1970: 10)) == 50)
    }
}
