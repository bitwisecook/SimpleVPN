// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
//  YubiKeyChallengeResponse.swift
//  Slot HMAC-SHA1 challenge-response on a YubiKey — a SELF-CONTAINED primitive
//  with no VPN anywhere in its signature, on purpose.
//
//  WHY IT IS SHAPED LIKE THIS, and the note for whoever writes the kdbx adapter.
//  Two features in this programme need exactly this operation and nothing more:
//
//   1. A gateway that takes a challenge-response value as the verification code.
//   2. **Unlocking a KeePass `.kdbx` database.** KeePassXC (and Strongbox, and
//      KeePassium) can require a YubiKey challenge-response as a second factor:
//      the database header carries a challenge, the key answers it, and the
//      answer becomes key material for the unlock. That is the SAME twenty bytes
//      out of the same slot.
//
//  So this type takes `Data` in and gives `Data` out, knows nothing about
//  credentials, profiles or connect flows, and is safe to call from a file-format
//  adapter. **The kdbx adapter should consume this rather than writing its own.**
//  Everything KeePass-specific it needs is already here and named after it:
//  `Padding.keePassPKCS7To64` reproduces KeePassXC's own padding exactly, and
//  `keyMaterial(for:)` is the one call an unlock needs.
//
//  WHAT IS AND ISN'T A SECRET HERE, because it decides what may ride argv:
//   • THE CHALLENGE IS NOT SECRET in either use. A kdbx challenge is the
//     database's transform seed, which is stored in the file header in
//     cleartext — anyone with the file has it. A gateway's challenge arrives over
//     the wire. So it may be passed as a command-line argument, and the API says
//     so in its own name: `respond(toPublicChallenge:)`. A caller with a genuinely
//     secret challenge must NOT use this path — there is no way to hand `ykman` a
//     challenge off the command line, so such a caller has no `ykman` route at
//     all and must say so rather than leaking one.
//   • THE RESPONSE IS SECRET. It comes back on stdout, is never logged, never
//     interpolated into an error, and callers that hold it as a credential put it
//     in a `SingleUseCode`.
//
//  The slot's own secret never leaves the key — that is the entire point of
//  challenge-response, and it is why this is worth having even though it costs a
//  subprocess.
//

import Foundation

/// Slot HMAC-SHA1 challenge-response. Slot 2 by default, because slot 1 normally
/// holds the factory Yubico OTP credential and overwriting it is a thing people
/// regret; Yubico's own tools default the same way.
nonisolated struct YubiKeyChallengeResponse: Sendable {

    /// HMAC-SHA1 is 20 bytes. Always, for every key and every slot.
    static let responseLength = 20
    /// The key's challenge buffer.
    static let challengeBufferLength = 64

    var slot: YubiKeySlot = .two
    /// Which key, when several are plugged in. A serial number is printed on the
    /// key and is not a secret.
    var serial: String?
    var tool = YubiKeyManagerTool()

    /// How a short challenge is grown to the key's 64-byte buffer.
    nonisolated enum Padding: Sendable, Equatable {
        /// Send the challenge exactly as given. What a gateway-driven
        /// challenge-response wants: the gateway decides the bytes.
        case none
        /// Pad to 64 bytes, PKCS#7 style — append `64 - length` bytes each holding
        /// the value `64 - length`. A challenge that is already 64 bytes is sent
        /// unchanged (NOT given a further full block, which is where a textbook
        /// PKCS#7 implementation would differ).
        ///
        /// THIS IS KEEPASSXC'S SCHEME, matched deliberately and verified against
        /// KeePassXC's own `YubiKeyInterfaceUSB.cpp`, whose comment reads "The
        /// challenge sent to the yubikey should always be 64 bytes for
        /// compatibility with all configurations. Follow PKCS7 padding." Anything
        /// else produces a different response and therefore fails to unlock a
        /// database that works elsewhere — with no error to explain why.
        case keePassPKCS7To64
    }

    // MARK: The pure half

    /// Grow a challenge to what will actually be sent. Pure, and the piece worth
    /// testing hardest: a padding bug here is a silent wrong answer, not a crash.
    static func pad(_ challenge: Data, _ padding: Padding) -> Data {
        switch padding {
        case .none:
            return challenge
        case .keePassPKCS7To64:
            let shortfall = challengeBufferLength - challenge.count
            guard shortfall > 0 else { return challenge }
            return challenge + Data(repeating: UInt8(shortfall), count: shortfall)
        }
    }

    /// Lowercase hex, which is the form `ykman otp calculate` takes.
    static func hexEncode(_ data: Data) -> String {
        data.map { String(format: "%02x", $0) }.joined()
    }

    // MARK: The operation

    /// Send `challenge` to the slot and read the 20-byte answer.
    ///
    /// The name carries the precondition: the challenge travels as a command-line
    /// argument, so it must be a value that is already public. See the file header.
    ///
    /// `requiresTouch` only changes the DEADLINE — a slot programmed with `--touch`
    /// leaves `ykman` waiting on a finger, and a 12-second deadline would report a
    /// timeout while the user was still reaching for the key. It never changes what
    /// is sent.
    func respond(toPublicChallenge challenge: Data, padding: Padding,
                 requiresTouch: Bool = false) async throws -> Data {
        guard !challenge.isEmpty else { throw YubiKeyToolError.unreadableOutput }
        guard challenge.count <= Self.challengeBufferLength else {
            throw YubiKeyToolError.unreadableOutput
        }
        let sent = Self.pad(challenge, padding)
        var arguments: [String] = []
        if let serial, !serial.isEmpty, serial.allSatisfy(\.isNumber) {
            arguments += ["--device", serial]
        }
        arguments += ["otp", "calculate", String(slot.rawValue), Self.hexEncode(sent)]
        let result = await tool.runner.run(
            arguments,
            deadline: requiresTouch ? YkmanRunner.touchDeadline : YkmanRunner.defaultDeadline)
        guard result.succeeded else { throw YkmanOutput.classify(result) }
        guard let response = YkmanOutput.parseChallengeResponse(result.text) else {
            throw YubiKeyToolError.unreadableOutput
        }
        return response
    }

    // MARK: The two callers' front doors

    /// **The call a KeePass `.kdbx` unlock wants.** Hand it the database's
    /// challenge (its transform seed) and it returns the twenty bytes to fold into
    /// the composite key, padded exactly as KeePassXC pads.
    ///
    /// Nothing about `.kdbx` is parsed here — that belongs to the adapter that owns
    /// the file format. This is only the key half, so the two concerns stay
    /// separable and neither has to know the other's tests.
    func keyMaterial(for databaseChallenge: Data, requiresTouch: Bool = false) async throws -> Data {
        try await respond(toPublicChallenge: databaseChallenge,
                          padding: .keePassPKCS7To64, requiresTouch: requiresTouch)
    }

    /// The verification-code caller: a gateway's challenge answered as a
    /// hex string, in a box that opens once.
    func verificationCode(forGatewayChallenge challenge: Data,
                          requiresTouch: Bool = false) async throws -> SingleUseCode {
        let response = try await respond(toPublicChallenge: challenge, padding: .none,
                                         requiresTouch: requiresTouch)
        return SingleUseCode(Self.hexEncode(response), origin: .computedByDevice)
    }

    /// Whether the slot this is set to actually holds a credential. Asked before
    /// offering the feature, so nobody meets "the key said no" at connect time.
    func isSlotProgrammed() async throws -> Bool {
        try await tool.otpSlots(serial: serial).isProgrammed(slot)
    }
}
