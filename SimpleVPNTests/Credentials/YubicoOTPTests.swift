// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
//  YubicoOTPTests.swift
//  Reading a Yubico OTP: the modhex alphabet, the public-ID split, and — most of
//  the value here — the NEAR MISSES.
//
//  Why the near misses matter more than the happy path. Every one of them is a real
//  support case with a different fix, and lumping them together as "invalid code"
//  is what sends people to factory-reset a working key:
//    • 44 characters of the wrong letters → the KEYBOARD LAYOUT (Dvorak). The key
//      sends scancodes; the Mac decides what letters they are. Length survives,
//      letters don't. Fix: change input source.
//    • too short → the touch was too brief. Fix: hold for about a second.
//    • too long → two touches. Fix: clear the field, touch once.
//    • odd length → a keystroke was dropped. Fix: try again.
//  So each case is asserted separately, and the near-miss strings are built to be
//  one edit away from valid.
//
//  The alphabet is pinned against Yubico's published modhex table (c b d e f g h i
//  j k l n r t u v ↔ nibbles 0–15) by round-tripping every byte, not by trusting a
//  literal.
//

import Foundation
import Testing
@testable import SimpleVPN

struct ModhexTests {

    @Test func theAlphabetIsYubicosSixteenLetters() {
        #expect(Modhex.alphabet == "cbdefghijklnrtuv")
        #expect(Modhex.alphabet.count == 16)
        #expect(Set(Modhex.alphabet).count == 16)
    }

    /// Index in the alphabet IS the nibble value. Round-tripping every byte pins the
    /// mapping without restating the table — a restated table would just be the same
    /// possible typo twice.
    @Test func everyByteRoundTrips() {
        for value in UInt8.min...UInt8.max {
            let data = Data([value])
            let text = Modhex.encode(data)
            #expect(text.count == 2)
            #expect(Modhex.decode(text) == data)
        }
    }

    @Test func knownNibblePairs() {
        // c = 0, v = 15 → 0x0F; and the all-zero pair is "cc" — which is exactly why
        // a factory public ID reads "cccc…".
        #expect(Modhex.encode(Data([0x00])) == "cc")
        #expect(Modhex.encode(Data([0x0F])) == "cv")
        #expect(Modhex.encode(Data([0xFF])) == "vv")
        #expect(Modhex.decode("cc") == Data([0x00]))
        #expect(Modhex.decode("vv") == Data([0xFF]))
    }

    @Test func decodeRefusesAnythingOutsideTheAlphabet() {
        // 'a', 'm', 'o', 'p', 'q', 's', 'w', 'x', 'y', 'z' are NOT modhex — the
        // alphabet deliberately omits letters that move between layouts.
        for stray in ["ca", "am", "co", "cp", "sq", "cw", "xx", "cy", "zz", "c1", "c-", "cC"] {
            #expect(Modhex.decode(stray) == nil, "\(stray) should not decode")
        }
    }

    @Test func decodeRefusesOddLengthsAndEmpty() {
        #expect(Modhex.decode("c") == nil)
        #expect(Modhex.decode("ccc") == nil)
        #expect(Modhex.decode("") == nil)
    }

    @Test func isModhexRejectsEmptyRatherThanVacuouslyAccepting() {
        #expect(Modhex.isModhex("") == false)
        #expect(Modhex.isModhex("cbdefghijklnrtuv"))
        #expect(Modhex.isModhex("cbdefghijklnrtuva") == false)
    }
}

struct YubicoOTPReadingTests {

    /// A well-formed 44-character code: a 12-character public ID plus the
    /// 32-character encrypted token. Built rather than pasted so the arithmetic is
    /// visible.
    private func code(publicID: String = "ccccccjjbbbb",
                      token: String = "hknhfjbrjnlnldnhcujvddbikngjrtgh") -> String {
        // Token is 31 here; pad to the required 32 so the shape is exact.
        publicID + token.padding(toLength: 32, withPad: "c", startingAt: 0)
    }

    // MARK: The happy path

    @Test func readsAValidCodeAndSplitsThePublicID() throws {
        let text = code()
        #expect(text.count == 44)
        let reading = YubicoOTP.read(text)
        let identity = try #require(reading.identity)
        #expect(identity.publicID == "ccccccjjbbbb")
        #expect(identity.publicID.count == 12)
        #expect(identity.totalLength == 44)
        #expect(identity.isDefaultShape)
        // The code itself is in the box, and the box opens once.
        guard case .valid(_, let box) = reading else { Issue.record("not valid"); return }
        #expect(box.consume() == text)
        #expect(box.consume() == nil)
        // Only the public ID is publishable.
        #expect(box.publicLabel == "ccccccjjbbbb")
    }

    /// The split is from the END, not at a hard-coded 12. The encrypted token is
    /// always 16 bytes; everything before it is the public ID. So a key whose public
    /// ID was reprogrammed to another length still reads correctly — and pinning
    /// this stops someone "simplifying" it to `prefix(12)`.
    @Test func thePublicIDSplitIsFromTheEndSoAReprogrammedLengthStillWorks() throws {
        let token = String(repeating: "c", count: 32)
        for publicIDLength in [0, 2, 8, 12, 16, 32] {
            let publicID = String(repeating: "b", count: publicIDLength)
            let reading = YubicoOTP.read(publicID + token)
            if publicIDLength == 0 {
                // 32 characters is the token alone: nothing identifies the key, and
                // `read` treats it as too short rather than inventing an empty ID.
                #expect(reading.problem == .tooShort(count: 32))
                continue
            }
            let identity = try #require(reading.identity, "length \(publicIDLength)")
            #expect(identity.publicID == publicID)
            #expect(identity.publicID.count == publicIDLength)
        }
    }

    /// Modhex has no uppercase forms and Yubico's own validation protocol is
    /// case-insensitive about the body, so lowercasing a genuine code cannot change
    /// what it decrypts to. Refusing one because Caps Lock was on would be a bug
    /// nobody could diagnose.
    @Test func caseIsNormalisedRatherThanRejected() throws {
        let text = code()
        let reading = YubicoOTP.read(text.uppercased())
        let identity = try #require(reading.identity)
        #expect(identity.publicID == "ccccccjjbbbb")
        guard case .valid(_, let box) = reading else { Issue.record("not valid"); return }
        #expect(box.consume() == text)   // lowercased on the way in
    }

    /// A pasted code arrives with whitespace, and the key's own trailing Return can
    /// show up as a newline.
    @Test func surroundingWhitespaceAndNewlinesAreTrimmed() throws {
        let text = code()
        for wrapped in ["  \(text)", "\(text)\n", " \(text) \r\n", "\t\(text)"] {
            let identity = try #require(YubicoOTP.read(wrapped).identity, Comment(rawValue: wrapped.debugDescription))
            #expect(identity.publicID == "ccccccjjbbbb")
        }
    }

    // MARK: The near misses, each with its own diagnosis

    @Test func emptyIsItsOwnCase() {
        #expect(YubicoOTP.read("").problem == .empty)
        #expect(YubicoOTP.read("   \n ").problem == .empty)
    }

    /// 44 characters of lowercase Latin letters that aren't all modhex is the
    /// keyboard-layout case — the single most common "my YubiKey is broken" report.
    @Test func aLayoutMangledCodeIsDiagnosedAsSuch() {
        // What a Dvorak Mac makes of a code: right LENGTH (the key sends a fixed
        // number of scancodes), lowercase letters, but outside the alphabet.
        let mangled = "jjjjjjennnnnnhtahdegugtahdgeuahdgeuahdgeuaha"
        #expect(mangled.count == 44)
        #expect(Modhex.isModhex(mangled) == false)
        #expect(YubicoOTP.read(mangled).problem == .outsideModhex(likelyKeyboardLayout: true))
        #expect(YubicoOTP.looksLayoutMangled(mangled))
    }

    /// A single wrong letter in an otherwise perfect code is still the layout case:
    /// the length is right, so a scancode mapping is the likely cause.
    @Test func oneStrayLetterInAFullLengthCodeReadsAsALayoutProblem() {
        var text = Array(code())
        text[20] = "a"          // 'a' is not modhex
        let broken = String(text)
        #expect(broken.count == 44)
        #expect(YubicoOTP.read(broken).problem == .outsideModhex(likelyKeyboardLayout: true))
    }

    /// Wrong length AND wrong letters is NOT the layout case — the layout preserves
    /// length, so claiming it would send the user to the wrong fix.
    @Test func nonModhexAtTheWrongLengthIsNotBlamedOnTheLayout() {
        #expect(YubicoOTP.read("hello there").problem == .outsideModhex(likelyKeyboardLayout: false))
        #expect(YubicoOTP.read("123456").problem == .outsideModhex(likelyKeyboardLayout: false))
        // Digits at exactly 44 are not a mangled code either — they aren't letters.
        let digits = String(repeating: "1", count: 44)
        #expect(YubicoOTP.read(digits).problem == .outsideModhex(likelyKeyboardLayout: false))
        #expect(YubicoOTP.looksLayoutMangled(digits) == false)
    }

    @Test func tooShortIsReportedWithItsLength() {
        // Valid modhex, but no longer than the token alone.
        for length in [2, 10, 31, 32] {
            let short = String(repeating: "c", count: length)
            #expect(YubicoOTP.read(short).problem == .tooShort(count: length),
                    "length \(length)")
        }
        // 33 is odd, so it fails on length parity, not shortness — a different fix.
        #expect(YubicoOTP.read(String(repeating: "c", count: 33)).problem == .oddLength(count: 33))
    }

    @Test func twoTouchesAreReportedAsTooLong() {
        let doubled = code() + code()       // 88 characters
        #expect(YubicoOTP.read(doubled).problem == .tooLong(count: 88))
        // The ceiling is 64: a 16-byte public ID plus the 16-byte token.
        #expect(YubicoOTP.read(String(repeating: "c", count: 64)).identity != nil)
        #expect(YubicoOTP.read(String(repeating: "c", count: 66)).problem == .tooLong(count: 66))
    }

    @Test func aDroppedKeystrokeIsReportedAsAnOddLength() {
        let dropped = String(code().dropLast())      // 43
        #expect(dropped.count == 43)
        #expect(YubicoOTP.read(dropped).problem == .oddLength(count: 43))
    }

    /// Every problem has something to say and something to do about it. A failure
    /// with no way forward is where people give up on a feature.
    @Test func everyProblemHasNonEmptyWording() {
        let problems: [YubicoOTP.Problem] = [
            .empty, .tooShort(count: 10), .tooLong(count: 88), .oddLength(count: 43),
            .outsideModhex(likelyKeyboardLayout: true),
            .outsideModhex(likelyKeyboardLayout: false),
        ]
        for problem in problems {
            #expect(!problem.explanation.isEmpty)
            #expect(!problem.shortReason.isEmpty)
            // Plain language: no jargon a user has never met.
            #expect(!problem.explanation.lowercased().contains("modhex"))
            #expect(!problem.explanation.lowercased().contains("otp"))
        }
        // The layout case must actually mention the keyboard, or it is useless.
        let layout = YubicoOTP.Problem.outsideModhex(likelyKeyboardLayout: true)
        #expect(layout.explanation.lowercased().contains("keyboard"))
    }

    // MARK: The automatic detector

    /// The strict shape test the capture field runs on every keystroke. Deliberately
    /// only the default 44: at 32 characters a modhex string is just as likely to be
    /// part of a static password, and treating one as a code would send a password
    /// to a validation server.
    @Test func theAutomaticDetectorAcceptsOnlyTheDefaultShape() {
        #expect(YubicoOTP.looksLikeTypedOTP(code()))
        #expect(YubicoOTP.looksLikeTypedOTP(String(repeating: "c", count: 44)))
        #expect(YubicoOTP.looksLikeTypedOTP(String(repeating: "c", count: 32)) == false)
        #expect(YubicoOTP.looksLikeTypedOTP(String(repeating: "c", count: 46)) == false)
        #expect(YubicoOTP.looksLikeTypedOTP(String(repeating: "c", count: 43)) == false)
        #expect(YubicoOTP.looksLikeTypedOTP("") == false)
    }

    // MARK: Splitting a password from a trailing code

    @Test func aTrailingCodeIsFoundAfterAPassword() throws {
        let split = try #require(YubicoOTP.splitPasswordAndCode("hunter2" + code()))
        #expect(split.password == "hunter2")
        #expect(split.code == code())
    }

    @Test func aPasswordAloneIsNotAMisreadCode() {
        #expect(YubicoOTP.splitPasswordAndCode("hunter2") == nil)
        #expect(YubicoOTP.splitPasswordAndCode("") == nil)
        // Long enough, but the tail isn't modhex.
        #expect(YubicoOTP.splitPasswordAndCode(String(repeating: "z", count: 60)) == nil)
    }

    /// A password that HAPPENS to end in modhex letters, but not 44 of them, must
    /// not be cut. Truncating somebody's password is far worse than not helping.
    @Test func aPasswordEndingInModhexLettersIsLeftAlone() {
        // A modhex-ish tail that is SHORTER than a code: nothing is cut.
        let shortTail = String(repeating: "z", count: 20) + String(repeating: "c", count: 20)
        #expect(YubicoOTP.trailingOTPRange(in: shortTail) == nil)
        #expect(YubicoOTP.splitPasswordAndCode(shortTail) == nil)

        // 43 modhex characters after a non-modhex character: the final 44 include
        // that character, so it is not a code and the password stays whole.
        let oneShort = "pw" + String(repeating: "c", count: 43)
        #expect(YubicoOTP.trailingOTPRange(in: oneShort) == nil)
        #expect(YubicoOTP.splitPasswordAndCode(oneShort) == nil)

        // And the honest limit of the heuristic, stated rather than hidden: a
        // password whose last 44 characters happen to be modhex IS cut. That is
        // accepted — the alternative is failing to find real codes — and it is why
        // the search is anchored to the END and to the exact default length only.
        let ambiguous = "zz" + String(repeating: "c", count: 44)
        #expect(YubicoOTP.trailingOTPRange(in: ambiguous) != nil)
        #expect(YubicoOTP.splitPasswordAndCode(ambiguous)?.password == "zz")
    }

    // MARK: The publishable half

    @Test func thePublicIDIsGroupedAndSpelledForTheEyeAndTheEar() {
        let identity = YubicoOTPIdentity(publicID: "ccccccjjbbbb", totalLength: 44)
        #expect(identity.grouped == "cccc ccjj bbbb")
        #expect(identity.spelledOut == "c c c c c c j j b b b b")
        // A non-multiple-of-four ID must not lose its last characters.
        let odd = YubicoOTPIdentity(publicID: "ccccccjjbb", totalLength: 42)
        #expect(odd.grouped.replacingOccurrences(of: " ", with: "") == "ccccccjjbb")
    }
}
