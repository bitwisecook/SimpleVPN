// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
//  YubicoOTP.swift
//  The shape of a Yubico OTP, and the box a one-time code lives in.
//
//  A YubiKey with its factory Yubico OTP credential in a slot is a USB HID
//  KEYBOARD. Touch it and it TYPES — into whatever has keyboard focus, in any
//  app — a 44-character string in "modhex", then presses Return. There is no API
//  call, no framework, and nothing to ask permission for: the characters arrive
//  as keystrokes like any others. That is why this file has no IOKit in it and
//  why SimpleVPN takes NO Input Monitoring dependency (see YubiKeyPresence.swift
//  for the detection side, which is registry reads only).
//
//  Two jobs, and the split between them is the security design:
//
//   • `YubicoOTPIdentity` — what a well-formed OTP tells us WITHOUT being
//     secret: its public ID, the first 12 modhex characters, which name the KEY
//     rather than the code. Yubico publishes public IDs in cleartext by design
//     (a validation server needs one to pick a key), so this half is safe to
//     show on screen, put in a log line and read out to VoiceOver.
//   • `SingleUseCode` — the code itself. Read-once, by construction: there is
//     no getter, no `description`, no `Codable`, and `consume()` takes the value
//     out and leaves nil behind. A second call gets nil. See its own comment for
//     why that shape and not a `let`.
//
//  WHAT WE CANNOT DO, stated once so no UI string implies otherwise: a Yubico
//  OTP is verified by the SERVER — YubiCloud, or whatever validator the gateway
//  is pointed at — by decrypting it with the key's AES secret, which only Yubico
//  and the gateway hold. SimpleVPN can check the SHAPE and read the public ID.
//  It cannot tell a real code from a well-formed forgery, and must never say it
//  has "verified" or "checked" one. "Ready to send" is the strongest honest
//  wording.
//

import Foundation
import os

// MARK: - Modhex

/// Yubico's "modhex" alphabet: sixteen letters standing in for hex nibbles.
///
/// The letters are not arbitrary. Yubico picked characters that sit on the same
/// physical keys across the common Latin keyboard layouts (QWERTY, QWERTZ,
/// AZERTY), because the key types SCANCODES and the host decides what letter
/// each one means. So a code typed on a German Mac still reads correctly. Dvorak
/// and non-Latin layouts are the exception, and that exception is the single most
/// common "my YubiKey is broken" report — which is why `diagnose` below tells
/// the difference between "not a code" and "your keyboard layout mangled it"
/// rather than lumping both into one failure.
nonisolated enum Modhex {

    /// Index in this string IS the nibble value: c=0, b=1, d=2, … v=15.
    static let alphabet = "cbdefghijklnrtuv"

    private static let set = Set(alphabet)

    static func isModhex(_ character: Character) -> Bool {
        set.contains(character)
    }

    static func isModhex(_ string: some StringProtocol) -> Bool {
        !string.isEmpty && string.allSatisfy(isModhex)
    }

    /// Decode modhex to bytes, or nil if anything is outside the alphabet or the
    /// length is odd. Present because the public ID is sometimes quoted to a
    /// gateway administrator as hex or as a decimal serial, and because it is the
    /// natural way to test the alphabet mapping.
    static func decode(_ string: some StringProtocol) -> Data? {
        let characters = Array(string)
        guard !characters.isEmpty, characters.count % 2 == 0 else { return nil }
        var out = Data(capacity: characters.count / 2)
        var index = 0
        while index < characters.count {
            guard let high = alphabet.firstIndex(of: characters[index]),
                  let low = alphabet.firstIndex(of: characters[index + 1]) else { return nil }
            let hi = alphabet.distance(from: alphabet.startIndex, to: high)
            let lo = alphabet.distance(from: alphabet.startIndex, to: low)
            out.append(UInt8(hi << 4 | lo))
            index += 2
        }
        return out
    }

    static func encode(_ bytes: Data) -> String {
        let letters = Array(alphabet)
        var out = ""
        out.reserveCapacity(bytes.count * 2)
        for byte in bytes {
            out.append(letters[Int(byte >> 4)])
            out.append(letters[Int(byte & 0x0F)])
        }
        return out
    }
}

// MARK: - The safe half of a code

/// Which KEY typed a code — never the code. Every field here is safe to display,
/// speak and log.
nonisolated struct YubicoOTPIdentity: Sendable, Equatable, Hashable {

    /// The public ID: the leading modhex characters, which identify the key and
    /// are published in cleartext by design. Twelve characters on a
    /// factory-configured key.
    let publicID: String
    /// How long the whole code was. Kept because a non-default public-ID length
    /// is worth showing to someone comparing what their gateway expects.
    let totalLength: Int

    /// The default: a 6-byte public ID and a 16-byte token, 44 modhex characters.
    static let defaultLength = 44
    /// The token half is always 16 bytes — 32 modhex characters. Everything
    /// before it is the public ID, which is what makes the split below correct
    /// for a key whose public ID was reprogrammed to another length rather than
    /// only for the factory default.
    static let tokenLength = 32

    var isDefaultShape: Bool { totalLength == Self.defaultLength }

    /// How the public ID is shown: grouped in fours, because that is how a person
    /// compares it with what their gateway's administrator sent them.
    var grouped: String {
        stride(from: 0, to: publicID.count, by: 4).map { offset in
            let start = publicID.index(publicID.startIndex, offsetBy: offset)
            let end = publicID.index(start, offsetBy: min(4, publicID.count - offset))
            return String(publicID[start..<end])
        }.joined(separator: " ")
    }

    /// What VoiceOver hears. Spelled out letter by letter: "cccc jjbb" read as a
    /// word is noise, and this string exists so someone can compare it against a
    /// gateway's records by ear.
    var spelledOut: String {
        publicID.map(String.init).joined(separator: " ")
    }
}

// MARK: - Reading a typed code
//
// The box a code goes into is `SingleUseCode` — see EphemeralCredential.swift. It
// deliberately does NOT live here: read-once-and-never-again is a rule every
// credential source in this app needs, not a YubiKey detail, and one shared box is
// the difference between one audited implementation and fifteen home-made ones.

nonisolated enum YubicoOTP {

    /// Why a string that arrived in a capture field is not a Yubico OTP. Each
    /// case is something the UI can say a useful sentence about — "not a code"
    /// on its own sends people to reset a working key.
    nonisolated enum Problem: Sendable, Equatable {
        case empty
        /// Shorter than the 32 characters the encrypted half alone occupies.
        case tooShort(count: Int)
        /// Longer than a YubiKey can produce (a 16-byte public ID is the maximum,
        /// so 64 characters is the ceiling).
        case tooLong(count: Int)
        /// Modhex throughout and within range, but an odd number of characters —
        /// so a keystroke was dropped or an extra one arrived.
        case oddLength(count: Int)
        /// Characters outside the modhex alphabet. `likelyKeyboardLayout` is set
        /// when the string is otherwise the right size and made of lowercase
        /// letters, which is what a Dvorak (or other non-Latin-layout) Mac does
        /// to a Yubico OTP: the key sends scancodes and the host names them.
        case outsideModhex(likelyKeyboardLayout: Bool)
    }

    nonisolated enum Reading: Sendable {
        case valid(YubicoOTPIdentity, SingleUseCode)
        case invalid(Problem)

        var identity: YubicoOTPIdentity? {
            if case .valid(let identity, _) = self { return identity }
            return nil
        }
        var problem: Problem? {
            if case .invalid(let problem) = self { return problem }
            return nil
        }
    }

    /// The longest code a YubiKey can type: a 16-byte public ID plus the 16-byte
    /// token, both in modhex.
    static let maximumLength = 64

    /// Whether `text` is a code we would accept — the cheap test a capture field
    /// runs on every keystroke, with nothing allocated and no box created.
    ///
    /// Deliberately STRICT about the default 44: this is the automatic detector,
    /// and a 32-character modhex string is just as likely to be four words of a
    /// static password. Someone with a reprogrammed public ID can still submit by
    /// hand, where `read` accepts the general form.
    static func looksLikeTypedOTP(_ text: some StringProtocol) -> Bool {
        text.count == YubicoOTPIdentity.defaultLength && Modhex.isModhex(text)
    }

    /// Read a code out of whatever arrived in the field.
    ///
    /// Case is normalised: some configurations type uppercase (Caps Lock, or a
    /// key programmed that way), modhex has no uppercase forms, and Yubico's own
    /// validation protocol is case-insensitive about the modhex body. Lowercasing
    /// a genuine code cannot change what it decrypts to; refusing one because
    /// Caps Lock was on would be a bug people could not diagnose.
    ///
    /// Surrounding whitespace is trimmed for the same reason: a pasted code
    /// arrives with it, and the trailing Return the key itself presses shows up
    /// here as a newline when the field is a multi-line one.
    static func read(_ raw: some StringProtocol) -> Reading {
        let text = raw.trimmingCharacters(in: .whitespacesAndNewlines).lowercased()
        guard !text.isEmpty else { return .invalid(.empty) }
        guard Modhex.isModhex(text) else {
            return .invalid(.outsideModhex(likelyKeyboardLayout: looksLayoutMangled(text)))
        }
        guard text.count > YubicoOTPIdentity.tokenLength else {
            return .invalid(.tooShort(count: text.count))
        }
        guard text.count <= maximumLength else { return .invalid(.tooLong(count: text.count)) }
        guard text.count % 2 == 0 else { return .invalid(.oddLength(count: text.count)) }

        // Split from the END, not at a hard-coded 12: the encrypted token is
        // always 16 bytes, and everything before it is the public ID. A key whose
        // public ID was reprogrammed to another length still reads correctly.
        let publicID = String(text.dropLast(YubicoOTPIdentity.tokenLength))
        let identity = YubicoOTPIdentity(publicID: publicID, totalLength: text.count)
        // `publicLabel` carries the public ID and NOTHING else: Yubico publishes
        // public IDs in cleartext by design, so it is the one part of a code that
        // may be shown, spoken and logged.
        return .valid(identity, SingleUseCode(text, origin: .typedByDevice,
                                              publicLabel: identity.publicID))
    }

    /// Does this look like a Yubico OTP that the keyboard layout scrambled?
    ///
    /// The tell: a key types a fixed number of scancodes, so the LENGTH survives
    /// a layout mismatch even though the letters don't. So — right length, all
    /// ASCII lowercase letters, but not all of them modhex.
    static func looksLayoutMangled(_ text: some StringProtocol) -> Bool {
        guard text.count == YubicoOTPIdentity.defaultLength else { return false }
        guard text.allSatisfy({ $0.isASCII && $0.isLetter && $0.isLowercase }) else { return false }
        return !Modhex.isModhex(text)
    }

    /// If `text` ENDS with a well-formed 44-character Yubico OTP, where it starts.
    /// This is the password+code case: the user typed a password and then touched
    /// the key, so one field now holds both and the split has to be found rather
    /// than assumed.
    ///
    /// Only the default length is looked for, and only at the end. Scanning for
    /// any acceptable length anywhere would happily "find" a code inside a long
    /// modhex-ish password and quietly cut it in half.
    static func trailingOTPRange(in text: String) -> Range<String.Index>? {
        guard text.count >= YubicoOTPIdentity.defaultLength else { return nil }
        let start = text.index(text.endIndex, offsetBy: -YubicoOTPIdentity.defaultLength)
        let candidate = text[start..<text.endIndex]
        guard Modhex.isModhex(candidate) else { return nil }
        return start..<text.endIndex
    }

    /// Split a field that holds `password` followed by a typed code.
    ///
    /// Returns nil when there is no trailing code — a field with only a password
    /// in it is not an error, it is someone who hasn't touched their key yet.
    static func splitPasswordAndCode(_ text: String) -> (password: String, code: String)? {
        guard let range = trailingOTPRange(in: text) else { return nil }
        return (String(text[text.startIndex..<range.lowerBound]), String(text[range]))
    }
}

// MARK: - What we say about a problem

nonisolated extension YubicoOTP.Problem {

    /// One plain sentence. No jargon, no "modhex", and never an accusation that
    /// the key is broken when the likely cause is a setting on this Mac.
    var explanation: String {
        switch self {
        case .empty:
            "Nothing arrived. Touch the gold disc on your security key \u{2014} a short press."
        case .tooShort(let count):
            "That came through as \(count) characters, which is too short for a security key\u{2019}s "
                + "code. It usually means the touch was too brief \u{2014} press and hold for about a "
                + "second, then let go."
        case .tooLong(let count):
            "That came through as \(count) characters, which is longer than a security key\u{2019}s "
                + "code. If you touched the key twice, clear the field and try once."
        case .oddLength(let count):
            "A character went missing on the way in \u{2014} \(count) arrived, and a code is always an "
                + "even number. Clear the field and touch the key again."
        case .outsideModhex(let likelyKeyboardLayout):
            likelyKeyboardLayout
                ? "The right number of characters arrived, but they aren\u{2019}t the ones a security "
                    + "key sends. This is almost always the keyboard layout: the key sends key "
                    + "PRESSES, and your Mac decides which letters they are. Switch the input source "
                    + "to a standard layout \u{2014} in the menu bar, or System Settings \u{25B8} "
                    + "Keyboard \u{25B8} Input Sources \u{2014} and touch the key again."
                : "That isn\u{2019}t a security key\u{2019}s code. If you meant to type your "
                    + "verification code by hand, use the code field instead."
        }
    }

    /// The one-line version for a field's own accessibility value, where the long
    /// explanation would bury the fact that something is wrong.
    var shortReason: String {
        switch self {
        case .empty: "Nothing arrived from the key"
        case .tooShort: "Too short for a security key\u{2019}s code"
        case .tooLong: "Longer than a security key\u{2019}s code"
        case .oddLength: "A character went missing"
        case .outsideModhex(let likelyKeyboardLayout):
            likelyKeyboardLayout ? "Your keyboard layout scrambled the code"
                                 : "Not a security key\u{2019}s code"
        }
    }
}
