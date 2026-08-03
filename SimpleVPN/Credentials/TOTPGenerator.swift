// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
//  TOTPGenerator.swift
//  RFC 6238 TOTP generation for VPN one-time-password prompts. The app stores a
//  single user-supplied string in the keychain (a full otpauth:// URI kept
//  verbatim, or a bare secret normalised to uppercase unpadded base32) and
//  re-parses it at connect time — so parsing has to accept everything a user
//  plausibly pastes (lowercase, spaces, dashes, padding) while rejecting input
//  that could silently generate wrong codes. Base32 is implemented here (RFC
//  4648) rather than pulled in as a dependency; HMAC comes from CryptoKit.
//  Everything is pure computation, so the types are nonisolated — codes are
//  minted from the tunnel side, off the main actor.
//

import Foundation
import CryptoKit

/// The HMAC hash of RFC 6238. SHA-1 is the overwhelming deployed default and
/// remains safe in the HMAC construction, so it stays the default here too.
nonisolated enum TOTPAlgorithm: String, Sendable, Equatable, Codable, CaseIterable {
    case sha1 = "SHA1"
    case sha256 = "SHA256"
    case sha512 = "SHA512"
}

/// Why an input string can't become a TOTP configuration. Typed (not just nil)
/// so UI can tell "that's not base32" apart from "that's an unsupported HOTP
/// URI" — the fixes a user needs are different.
nonisolated enum TOTPParseError: Error, Equatable {
    case emptyInput
    case notAnOTPAuthURI
    /// otpauth:// with a non-totp type (e.g. hotp) — counter-based tokens need
    /// persistent counter state we deliberately don't keep.
    case unsupportedOTPType(String)
    case missingSecret
    case invalidBase32
    case invalidAlgorithm(String)
    /// RFC 4226 truncation yields at most 9 useful digits; authenticators agree
    /// on 6–8, so anything else is a typo, not a preference.
    case invalidDigits(String)
    case invalidPeriod(String)
}

nonisolated struct TOTPConfiguration: Sendable, Equatable, Codable {
    var secret: Data
    var algorithm: TOTPAlgorithm
    var digits: Int
    var period: Int
    var issuer: String?
    var accountName: String?

    init(secret: Data,
         algorithm: TOTPAlgorithm = .sha1,
         digits: Int = 6,
         period: Int = 30,
         issuer: String? = nil,
         accountName: String? = nil) {
        self.secret = secret
        self.algorithm = algorithm
        self.digits = digits
        self.period = period
        self.issuer = issuer
        self.accountName = accountName
    }

    // MARK: - Parsing

    /// Accepts either a full `otpauth://totp/...` URI or a bare base32 secret.
    /// Bare secrets tolerate lowercase, spaces, dashes, and optional `=`
    /// padding, because that's how they arrive: read aloud, copy-pasted from a
    /// PDF, or grouped in fours by the issuing site.
    static func parse(_ input: String) throws -> TOTPConfiguration {
        let trimmed = input.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else { throw TOTPParseError.emptyInput }
        if trimmed.lowercased().hasPrefix("otpauth://") {
            return try parse(uri: trimmed)
        }
        guard let data = base32Decode(trimmed), !data.isEmpty else {
            throw TOTPParseError.invalidBase32
        }
        return TOTPConfiguration(secret: data)
    }

    /// Failable convenience for connect-time re-parsing of the stored string,
    /// where the only recovery is "prompt the user" regardless of which way it
    /// failed. Editing UI should call `parse(_:)` for the typed diagnosis.
    init?(parsing input: String) {
        guard let parsed = try? Self.parse(input) else { return nil }
        self = parsed
    }

    private static func parse(uri: String) throws -> TOTPConfiguration {
        guard let components = URLComponents(string: uri),
              components.scheme?.lowercased() == "otpauth" else {
            throw TOTPParseError.notAnOTPAuthURI
        }
        let type = components.host?.lowercased() ?? ""
        guard type == "totp" else { throw TOTPParseError.unsupportedOTPType(type) }

        // Label is "Issuer:Account" or just "Account"; URLComponents has
        // already undone percent-encoding (including %3A → ":", which is why
        // the split happens after decoding — that's what the spec intends).
        var issuer: String?
        var account: String?
        let label = components.path.hasPrefix("/")
            ? String(components.path.dropFirst()) : components.path
        if !label.isEmpty {
            if let colon = label.firstIndex(of: ":") {
                issuer = String(label[..<colon])
                // Some issuers emit "Issuer: Account" with a cosmetic space.
                account = String(label[label.index(after: colon)...])
                    .trimmingCharacters(in: .whitespaces)
            } else {
                account = label
            }
        }

        var secret: Data?
        var algorithm = TOTPAlgorithm.sha1
        var digits = 6
        var period = 30
        for item in components.queryItems ?? [] {
            let value = item.value ?? ""
            switch item.name.lowercased() {
            case "secret":
                guard let data = base32Decode(value), !data.isEmpty else {
                    throw TOTPParseError.invalidBase32
                }
                secret = data
            case "algorithm":
                guard let parsed = TOTPAlgorithm(rawValue: value.uppercased()) else {
                    throw TOTPParseError.invalidAlgorithm(value)
                }
                algorithm = parsed
            case "digits":
                guard let parsed = Int(value), (6...8).contains(parsed) else {
                    throw TOTPParseError.invalidDigits(value)
                }
                digits = parsed
            case "period":
                guard let parsed = Int(value), parsed > 0 else {
                    throw TOTPParseError.invalidPeriod(value)
                }
                period = parsed
            case "issuer":
                // The explicit parameter is authoritative over the label prefix.
                issuer = value
            default:
                break   // Unknown params (counter=, image=, ...) are harmless.
            }
        }
        guard let secretData = secret else { throw TOTPParseError.missingSecret }
        return TOTPConfiguration(secret: secretData, algorithm: algorithm,
                                 digits: digits, period: period,
                                 issuer: issuer, accountName: account)
    }

    /// Validate arbitrary user input and produce the exact string the app
    /// persists in the keychain. Full otpauth URIs are kept verbatim (they may
    /// carry params we don't model, and re-serialising risks re-encoding
    /// differences); bare secrets normalise to uppercase unpadded base32 so
    /// the stored form is canonical regardless of how it was pasted.
    static func canonicalStorageString(from userInput: String) -> String? {
        let trimmed = userInput.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else { return nil }
        guard (try? parse(trimmed)) != nil else { return nil }
        if trimmed.lowercased().hasPrefix("otpauth://") { return trimmed }
        return trimmed.uppercased().filter { !" -=".contains($0) }
    }

    // MARK: - Code generation

    /// RFC 6238: HMAC over the big-endian 64-bit count of `period`-second
    /// steps since the Unix epoch, then RFC 4226 dynamic truncation,
    /// zero-padded to `digits`.
    func code(at date: Date = Date()) -> String {
        let counter = Int64((date.timeIntervalSince1970 / Double(period)).rounded(.down))
        let message = withUnsafeBytes(of: UInt64(bitPattern: counter).bigEndian) { Data($0) }
        let key = SymmetricKey(data: secret)
        let mac: Data
        switch algorithm {
        case .sha1:
            mac = Data(HMAC<Insecure.SHA1>.authenticationCode(for: message, using: key))
        case .sha256:
            mac = Data(HMAC<SHA256>.authenticationCode(for: message, using: key))
        case .sha512:
            mac = Data(HMAC<SHA512>.authenticationCode(for: message, using: key))
        }
        let offset = Int(mac[mac.count - 1] & 0x0F)
        let binary = (UInt32(mac[offset] & 0x7F) << 24)
            | (UInt32(mac[offset + 1]) << 16)
            | (UInt32(mac[offset + 2]) << 8)
            | UInt32(mac[offset + 3])
        // digits ≤ 8 so 10^digits fits comfortably in UInt32.
        let modulus = (0..<digits).reduce(UInt32(1)) { m, _ in m * 10 }
        let code = String(binary % modulus)
        return String(repeating: "0", count: digits - code.count) + code
    }

    /// Whole seconds until the current code rolls over — for the UI countdown
    /// ring. At an exact period boundary the new code has the full period left.
    func secondsRemaining(at date: Date = Date()) -> Int {
        let seconds = Int64(date.timeIntervalSince1970.rounded(.down))
        let step = Int64(period)
        let intoPeriod = ((seconds % step) + step) % step
        return period - Int(intoPeriod)
    }

    // MARK: - Base32 (RFC 4648)

    /// Case-insensitive; skips spaces and dashes (common paste grouping);
    /// padding optional but nothing may follow it. Returns nil on any
    /// character outside the alphabet — a wrong secret must fail loudly, not
    /// generate plausible-looking wrong codes.
    static func base32Decode(_ string: String) -> Data? {
        var buffer: UInt32 = 0
        var bits = 0
        var out = Data()
        var paddingSeen = false
        for scalar in string.uppercased().unicodeScalars {
            switch scalar {
            case " ", "-":
                continue
            case "=":
                paddingSeen = true
            case "A"..."Z", "2"..."7":
                guard !paddingSeen else { return nil }
                let value: UInt32
                if case "A"..."Z" = scalar {
                    value = scalar.value - Unicode.Scalar("A").value
                } else {
                    value = scalar.value - Unicode.Scalar("2").value + 26
                }
                buffer = (buffer << 5) | value
                bits += 5
                if bits >= 8 {
                    bits -= 8
                    out.append(UInt8((buffer >> UInt32(bits)) & 0xFF))
                }
            default:
                return nil
            }
        }
        return out
    }
}
