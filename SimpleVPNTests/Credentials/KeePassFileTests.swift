// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
//  KeePassFileTests.swift
//  The `.kdbx` file sign-in source, pinned — on a Mac with none of the software.
//
//  ─── WHAT IS AND ISN'T VERIFIED HERE, STATED UP FRONT ──────────────────────
//  NONE of KeePassXC, Strongbox, KeePassium or `keepassxc-cli` is installed on the
//  machine these tests were written on, and the standing rules forbid installing
//  software to get one. So there is NO end-to-end unlock in this suite, and nothing
//  here should be read as one. What IS real:
//
//   • THE HEADERS ARE GENUINE BYTES. `KDBXFixture` builds KDBX3 and KDBX4 outer
//     headers byte-for-byte to the format, from KeePassXC's own source (every
//     constant is cited in KeePassDatabaseFile.swift's header, and the builder cites
//     the layout again). The classifier therefore parses real KDBX bytes, not a
//     mock. A file with these bytes IS a KDBX file as far as its header goes; what
//     is absent is the encrypted body, which nothing in this feed reads.
//   • THE COMMAND OUTPUT AND ERROR STRINGS ARE QUOTED FROM SOURCE, not invented:
//     `Show.cpp` (values one per line, no name prefixes when attributes were asked
//     for; the literal "PROTECTED" when `--show-protected` is absent; "Could not
//     find entry with path %1."), `Kdbx3Reader.cpp` ("Invalid credentials were
//     provided, please try again.", "Unable to issue challenge-response: %1"),
//     `KeePass2Reader.cpp` ("Not a KeePass database.", "Unsupported KeePass 2
//     database version.", the KeePass 1 sentence), `Database.cpp` ("File %1 does not
//     exist.", "Unable to open file %1.").
//   • THE PROCESS BOUNDARY IS INJECTED (`KeePassToolRunning`), so every argument
//     list, every parser and every classification runs with no tool present.
//
//  What a human with KeePassXC installed still has to confirm is the short list in
//  Docs/AuthPwdKeePassFile.md. Nothing in this file claims that work has been done.
//

import Foundation
import Testing
@testable import SimpleVPN

// MARK: - Building real KDBX headers

/// A KDBX outer header, assembled to the format.
///
/// PROVENANCE, per field, from KeePassXC's own source:
///  • three little-endian `quint32`s to start: SIGNATURE_1 (0x9AA2D903), SIGNATURE_2
///    (0xB54BFB67) and the version (major in the high half, minor in the low half) —
///    `KdbxReader::readMagicNumbers`, `KeePass2.h`.
///  • then header fields until id 0. KDBX4: one-byte id, `quint32` length, data
///    (`Kdbx4Reader::readHeaderField`). KDBX3: one-byte id, `quint16` length, data.
///  • KDBX3 carries the transform seed as field 5; KDBX4 carries the KDF parameters
///    as field 11, a VariantDictionary whose `"S"` entry is the seed
///    (`KeePass2.cpp`: KDFPARAM_AES_SEED = KDFPARAM_ARGON2_SALT = "S").
///  • a VariantDictionary is a `quint16` version then, per entry, a one-byte type,
///    `quint32` name length, name, `quint32` value length, value; terminated by a
///    0x00 type byte (`Kdbx4Reader::readVariantMap`). Type 0x42 is ByteArray.
enum KDBXFixture {

    static let signature1: UInt32 = 0x9AA2_D903
    static let signature2: UInt32 = 0xB54B_FB67
    /// The 32 bytes a real Argon2 salt / AES transform seed is. Fixed here so the
    /// security-key challenge assertion is exact.
    static let seed = Data((0..<32).map { UInt8($0 &+ 0xA0) })

    static let argon2idUUID = Data([0x9e, 0x29, 0x8b, 0x19, 0x56, 0xdb, 0x47, 0x73,
                                   0xb2, 0x3d, 0xfc, 0x3e, 0xc6, 0xf0, 0xa1, 0xe6])
    static let aesKdbx3UUID = Data([0xc9, 0xd9, 0xf3, 0x9a, 0x62, 0x8a, 0x44, 0x60,
                                   0xbf, 0x74, 0x0d, 0x08, 0xc1, 0x8a, 0x4f, 0xea])

    static func le32(_ value: UInt32) -> Data {
        Data([UInt8(value & 0xFF), UInt8((value >> 8) & 0xFF),
              UInt8((value >> 16) & 0xFF), UInt8((value >> 24) & 0xFF)])
    }
    static func le16(_ value: UInt16) -> Data {
        Data([UInt8(value & 0xFF), UInt8((value >> 8) & 0xFF)])
    }

    /// The three opening uint32s.
    static func magic(major: UInt16, minor: UInt16,
                      signature2 override: UInt32? = nil) -> Data {
        le32(signature1) + le32(override ?? signature2)
            + le32((UInt32(major) << 16) | UInt32(minor))
    }

    /// A KDBX 4.1 header whose KDF parameters carry `seed` under `"S"`.
    static func kdbx4(seed: Data = KDBXFixture.seed, uuid: Data = argon2idUUID,
                      minor: UInt16 = 1) -> Data {
        var variant = le16(0x0100)                       // VariantDictionary version
        variant += variantEntry(name: "$UUID", value: uuid)
        variant += variantEntry(name: "S", value: seed)
        variant += variantEntry(name: "I", value: le32(2))   // iterations, ignored by us
        variant += Data([0x00])                          // End
        var header = magic(major: 4, minor: minor)
        header += field4(id: 2, data: Data(repeating: 0x11, count: 16))   // CipherID
        header += field4(id: 4, data: Data(repeating: 0x22, count: 32))   // MasterSeed
        header += field4(id: 11, data: variant)                          // KdfParameters
        header += field4(id: 7, data: Data(repeating: 0x33, count: 16))   // EncryptionIV
        header += field4(id: 0, data: Data([0x0D, 0x0A, 0x0D, 0x0A]))     // EndOfHeader
        return header
    }

    /// A KDBX 3.1 header whose field 5 is the transform seed.
    static func kdbx3(seed: Data = KDBXFixture.seed) -> Data {
        var header = magic(major: 3, minor: 1)
        header += field3(id: 2, data: Data(repeating: 0x11, count: 16))   // CipherID
        header += field3(id: 4, data: Data(repeating: 0x22, count: 32))   // MasterSeed
        header += field3(id: 5, data: seed)                              // TransformSeed
        header += field3(id: 6, data: Data(repeating: 0x00, count: 8))    // TransformRounds
        header += field3(id: 0, data: Data([0x0D, 0x0A, 0x0D, 0x0A]))     // EndOfHeader
        return header
    }

    static func field4(id: UInt8, data: Data) -> Data {
        Data([id]) + le32(UInt32(data.count)) + data
    }
    static func field3(id: UInt8, data: Data) -> Data {
        Data([id]) + le16(UInt16(data.count)) + data
    }
    static func variantEntry(name: String, value: Data) -> Data {
        let nameBytes = Data(name.utf8)
        return Data([0x42]) + le32(UInt32(nameBytes.count)) + nameBytes
            + le32(UInt32(value.count)) + value
    }
}

// MARK: - Header classification

struct KeePassDatabaseFileTests {

    // MARK: The two real formats

    @Test func aRealKDBX4HeaderIsReadAndItsSeedIsTheSecurityKeyChallenge() throws {
        let state = KeePassDatabaseFile.classify(headerBytes: KDBXFixture.kdbx4(),
                                                path: "/db.kdbx")
        #expect(state.isReadable)
        let facts = try #require(state.facts)
        #expect(facts.version == KDBXVersion(major: 4, minor: 1))
        #expect(facts.keyDerivation == .argon2id)
        // THE value the security key answers, taken from the cleartext header.
        #expect(facts.kdfSeed == KDBXFixture.seed)
        #expect(facts.canComputeSecurityKeyChallenge)
    }

    @Test func aRealKDBX3HeaderTakesItsSeedFromTheTransformSeedField() {
        let state = KeePassDatabaseFile.classify(headerBytes: KDBXFixture.kdbx3(),
                                                path: "/db.kdbx")
        #expect(state.isReadable)
        #expect(state.facts?.version == KDBXVersion(major: 3, minor: 1))
        #expect(state.facts?.keyDerivation == .aesKDF)
        // KDBX3's `kdf.seed()` IS the transform seed — a different header field from
        // KDBX4's, and getting that wrong would send the wrong challenge to the key
        // with no error to explain it.
        #expect(state.facts?.kdfSeed == KDBXFixture.seed)
    }

    @Test func kdbx4WithAESKDFIsRecognisedToo() {
        let state = KeePassDatabaseFile.classify(
            headerBytes: KDBXFixture.kdbx4(uuid: KDBXFixture.aesKdbx3UUID), path: "/db.kdbx")
        #expect(state.facts?.keyDerivation == .aesKDF)
        #expect(state.facts?.kdfSeed == KDBXFixture.seed)
    }

    // MARK: Every way a file can be the wrong file

    /// The distinction that matters most: a KeePass 1 `.kdb` is not "not a KeePass
    /// database", and telling somebody it is sends them looking for a file they are
    /// already holding. Converting it is a one-way migration of their data, so the
    /// copy sends them to KeePassXC rather than offering to do it.
    @Test func aKeePass1DatabaseIsItsOwnAnswer() {
        let bytes = KDBXFixture.magic(major: 3, minor: 1, signature2: 0xB54B_FB65)
            + Data(repeating: 0, count: 32)
        let state = KeePassDatabaseFile.classify(headerBytes: bytes, path: "/old.kdb")
        #expect(state == .notADatabase(path: "/old.kdb", reason: .keePass1Database))
        let sentence = KDBXFileState.NotADatabaseReason.keePass1Database.sentence
        #expect(sentence.contains("KeePass 1"))
        #expect(sentence.contains("Import"))
        // …and it must never imply SimpleVPN would do the conversion.
        #expect(sentence.contains("never changes your database"))
    }

    @Test func aPreReleaseKDBX2IsDistinctFromNotAKeePassFileAtAll() {
        let bytes = KDBXFixture.magic(major: 2, minor: 0, signature2: 0xB54B_FB66)
            + Data(repeating: 0, count: 32)
        #expect(KeePassDatabaseFile.classify(headerBytes: bytes, path: "/x")
                == .notADatabase(path: "/x", reason: .preReleaseFormat))
    }

    @Test func somethingElseEntirelyIsNotAKeePassDatabase() {
        let bytes = Data("this is a text file, quite definitely not a vault".utf8)
        #expect(KeePassDatabaseFile.classify(headerBytes: bytes, path: "/notes.txt")
                == .notADatabase(path: "/notes.txt", reason: .notKeePassAtAll))
    }

    @Test func aTruncatedFileIsTruncatedRatherThanUnreadable() {
        #expect(KeePassDatabaseFile.classify(headerBytes: Data([0x03, 0xD9]), path: "/p")
                == .notADatabase(path: "/p", reason: .truncated))
        #expect(KeePassDatabaseFile.classify(headerBytes: Data(), path: "/p")
                == .notADatabase(path: "/p", reason: .truncated))
    }

    /// A version we cannot read is an UPDATE, not a credential problem — and the
    /// major number alone decides, because that is what KeePassXC's own
    /// `FILE_VERSION_CRITICAL_MASK` masks to.
    @Test func aNewerMajorVersionAsksForAnUpdateAndANewerMinorDoesNot() {
        let five = KeePassDatabaseFile.classify(headerBytes: KDBXFixture.magic(major: 5, minor: 0),
                                               path: "/db.kdbx")
        #expect(five == .tooNew(path: "/db.kdbx", version: KDBXVersion(major: 5, minor: 0)))
        // A 4.7 that does not exist yet is still a 4, and a 4 reader copes.
        let futureMinor = KeePassDatabaseFile.classify(headerBytes: KDBXFixture.kdbx4(minor: 7),
                                                      path: "/db.kdbx")
        #expect(futureMinor.isReadable)
    }

    @Test func anEmptyPathIsNotConfiguredRatherThanMissing() {
        #expect(KeePassDatabaseFile.classify(path: "") == .notConfigured)
        #expect(KeePassDatabaseFile.classify(path: "   ") == .notConfigured)
    }

    // MARK: A header we cannot fully parse is still a header

    /// A KDBX whose KDF parameters are damaged is still a KDBX. It stays readable —
    /// `keepassxc-cli` may well open it — and the only thing lost is the ability to
    /// pre-check a security key. Refusing the file over it would be a worse answer
    /// than saying "no challenge available".
    @Test func aDamagedKDFParameterBlockLosesTheChallengeAndNothingElse() {
        var header = KDBXFixture.magic(major: 4, minor: 1)
        header += KDBXFixture.field4(id: 11, data: Data([0x00, 0x01]))   // version, then nothing
        header += KDBXFixture.field4(id: 0, data: Data([0x0D, 0x0A]))
        let state = KeePassDatabaseFile.classify(headerBytes: header, path: "/db.kdbx")
        #expect(state.isReadable)
        #expect(state.facts?.canComputeSecurityKeyChallenge == false)
    }

    /// A length field that runs past the end of what we read stops the walk instead
    /// of trapping. This parses a file somebody else wrote.
    @Test func aLengthRunningPastTheEndDoesNotCrash() {
        var header = KDBXFixture.magic(major: 4, minor: 1)
        header += Data([11]) + KDBXFixture.le32(0xFFFF_FF00)
        let state = KeePassDatabaseFile.classify(headerBytes: header, path: "/db.kdbx")
        #expect(state.isReadable)
        #expect(state.facts?.kdfSeed == nil)
    }

    // MARK: On the real filesystem

    @Test func aFileOnDiskIsClassifiedFromItsFirstBytesOnly() throws {
        let directory = URL(fileURLWithPath: NSTemporaryDirectory())
            .appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: directory) }
        let url = directory.appendingPathComponent("Passwords.kdbx")
        // Real header, then a megabyte of body. The reader must not need the body.
        try (KDBXFixture.kdbx4() + Data(repeating: 0x5A, count: 1_000_000)).write(to: url)
        let state = KeePassDatabaseFile.classify(path: url.path)
        #expect(state.isReadable)
        #expect(state.facts?.kdfSeed == KDBXFixture.seed)
        // …and the bounded read really is bounded.
        let prefix = try #require(KeePassDatabaseFile.readPrefix(path: url.path))
        #expect(prefix.count <= KeePassDatabaseFile.headerReadLimit)
    }

    @Test func aMissingFileIsMissingAndADirectoryIsNotAFile() throws {
        let directory = URL(fileURLWithPath: NSTemporaryDirectory())
            .appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: directory) }
        let gone = directory.appendingPathComponent("Nowhere.kdbx").path
        #expect(KeePassDatabaseFile.classify(path: gone) == .missing(path: gone))
        #expect(KeePassDatabaseFile.classify(path: directory.path)
                == .notADatabase(path: directory.path, reason: .notARegularFile))
    }

    /// The state this app would otherwise get wrong. macOS protects `~/Desktop`,
    /// `~/Documents`, `~/Downloads` and iCloud Drive from every app, sandboxed or
    /// not; a denial lets `stat` through and refuses `open`. Without its own case the
    /// database would be reported as empty or truncated — a sentence about the FILE
    /// for a problem entirely about PERMISSION.
    ///
    /// A `chmod 000` file is the same syscall outcome (`stat` ok, `open` EACCES) and is
    /// what makes this testable here; the TCC half of it needs a human with a database
    /// in a protected folder (Docs/AuthPwdKeePassFile.md's manual list).
    @Test func aFileMacOSWillNotLetUsOpenIsAPermissionStateNotAnEmptyDatabase() throws {
        let directory = URL(fileURLWithPath: NSTemporaryDirectory())
            .appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        defer {
            try? FileManager.default.setAttributes([.posixPermissions: 0o700],
                                                   ofItemAtPath: directory.path)
            try? FileManager.default.removeItem(at: directory)
        }
        let url = directory.appendingPathComponent("Passwords.kdbx")
        try KDBXFixture.kdbx4().write(to: url)
        try FileManager.default.setAttributes([.posixPermissions: 0o000],
                                              ofItemAtPath: url.path)
        defer {
            try? FileManager.default.setAttributes([.posixPermissions: 0o600],
                                                   ofItemAtPath: url.path)
        }
        // Metadata still readable, contents not — exactly TCC's shape.
        var st = stat()
        #expect(stat(url.path, &st) == 0)
        #expect(KeePassDatabaseFile.classify(path: url.path) == .permissionDenied(path: url.path))
        // …and it must NOT be reported as a truncated or absent database.
        #expect(KeePassDatabaseFile.classify(path: url.path)
                != .notADatabase(path: url.path, reason: .truncated))
    }

    /// iCloud Drive's placeholder: the visible file disappears and `.name.icloud`
    /// appears beside it. That is NOT a missing database, and it is the one state
    /// here that fixes itself — so it must never be reported as a read failure.
    @Test func anUndownloadedICloudFileIsItsOwnStateRatherThanMissing() throws {
        let directory = URL(fileURLWithPath: NSTemporaryDirectory())
            .appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: directory) }
        let visible = directory.appendingPathComponent("Passwords.kdbx").path
        // The placeholder macOS leaves: a dot-prefixed sibling with `.icloud` appended.
        try Data("placeholder".utf8).write(
            to: directory.appendingPathComponent(".Passwords.kdbx.icloud"))
        #expect(KeePassDatabaseFile.hasICloudPlaceholder(for: visible))
        #expect(KeePassDatabaseFile.classify(path: visible) == .notDownloaded(path: visible))
    }
}

// MARK: - The command line

/// A stub tool. Records what it was asked to run — including whether anything was
/// written to stdin — so "no secret in argv" is a test rather than a promise.
final class StubKeePassTool: KeePassToolRunning, @unchecked Sendable {
    var located: String? = "/opt/homebrew/bin/keepassxc-cli"
    var result = LocalToolResult(exitCode: 0, stdout: Data(), stderr: "", timedOut: false)
    private(set) var lastArguments: [String] = []
    private(set) var lastStdin: Data?
    private(set) var lastDeadline: TimeInterval = 0
    private(set) var runCount = 0

    func locate() -> String? { located }

    func run(_ arguments: [String], stdin: Data?,
             deadline: TimeInterval) async -> LocalToolResult {
        lastArguments = arguments
        lastStdin = stdin
        lastDeadline = deadline
        runCount += 1
        return result
    }
}

struct KeePassFileChannelTests {

    private func unlock(password: String? = "correct horse battery staple",
                        keyFile: String? = nil,
                        slot: YubiKeySlot? = nil,
                        serial: String? = nil) -> KDBXUnlock {
        KDBXUnlock(databasePath: "/Users/me/Passwords.kdbx", keyFilePath: keyFile,
                   slot: slot, serial: serial,
                   password: password.map(KDBXPassword.init))
    }

    // MARK: Argv carries names; stdin carries the secret

    @Test func theDatabasePasswordIsOnStdinAndNowhereElse() async throws {
        let tool = StubKeePassTool()
        tool.result = LocalToolResult(exitCode: 0, stdout: Data("alice\ns3cret\n".utf8),
                                      stderr: "", timedOut: false)
        let channel = KeePassXCCommandLineChannel(runner: tool)
        _ = try await channel.entry(at: "VPN/Work", unlock: unlock())

        // THE assertion this whole feed turns on: `ps` shows argv to every process on
        // the Mac, so a database password there would be readable by anything.
        let argv = tool.lastArguments.joined(separator: " ")
        #expect(!argv.contains("correct horse battery staple"))
        #expect(!argv.contains("s3cret"))
        // …and it did travel, on the one channel that is safe.
        #expect(tool.lastStdin == Data("correct horse battery staple\n".utf8))
    }

    /// KeePassXC's `Utils::getPassword` calls `readLine()`, so the newline is not
    /// cosmetic — without it the tool waits.
    @Test func theStdinLineIsTerminated() {
        #expect(KDBXPassword("hunter2").stdinLine() == Data("hunter2\n".utf8))
    }

    @Test func theShowCommandAsksForBothAttributesAndUnmasksThem() {
        let arguments = KeePassXCCommandLineChannel.showArguments(
            entryPath: "VPN/Work", unlock: unlock())
        #expect(arguments.first == "show")
        // Without --show-protected the tool prints the literal word PROTECTED
        // (its own Show.cpp), which would be handed to a VPN as a password.
        #expect(arguments.contains("--show-protected"))
        #expect(arguments.contains("UserName"))
        #expect(arguments.contains("Password"))
        // Positionals last, database then entry.
        #expect(arguments.suffix(2) == ["/Users/me/Passwords.kdbx", "VPN/Work"])
        // `--quiet` must NOT be there: it also silences the unlock errors we classify
        // on (KeePassXC's `err = quiet ? DEVNULL : STDERR`).
        #expect(!arguments.contains("--quiet"))
        #expect(!arguments.contains("-q"))
    }

    @Test func aKeyFileAndASecurityKeySlotRideArgvBecauseNeitherIsASecret() {
        let arguments = KeePassXCCommandLineChannel.showArguments(
            entryPath: "VPN/Work",
            unlock: unlock(keyFile: "/Users/me/Passwords.keyx", slot: .two, serial: "12345678"))
        #expect(arguments.contains("--key-file"))
        #expect(arguments.contains("/Users/me/Passwords.keyx"))
        // `--yubikey slot[:serial]`, its own man page's syntax.
        #expect(arguments.contains("--yubikey"))
        #expect(arguments.contains("2:12345678"))
    }

    /// A serial is digits. Anything else is somebody's note to themselves and must
    /// not reach argv — the same rule the security-key feed applies.
    @Test func aNonNumericSerialIsDroppedRatherThanPassedThrough() {
        let value = KDBXUnlock(databasePath: "/db.kdbx", slot: .one,
                               serial: "my spare key").yubiKeyArgument
        #expect(value == "1")
    }

    /// A database with no password at all (key file and/or security key only) has to
    /// be told so, or the tool waits for one and rejects the empty line it gets.
    @Test func aPasswordlessDatabaseIsToldSoAndNothingIsWrittenToStdin() async throws {
        let tool = StubKeePassTool()
        tool.result = LocalToolResult(exitCode: 0, stdout: Data("alice\ns3cret\n".utf8),
                                      stderr: "", timedOut: false)
        let channel = KeePassXCCommandLineChannel(runner: tool)
        _ = try await channel.entry(at: "VPN/Work",
                                    unlock: unlock(password: "", keyFile: "/k.keyx"))
        #expect(tool.lastArguments.contains("--no-password"))
        #expect(tool.lastStdin == nil)
    }

    /// A touch-required slot leaves the tool waiting on a finger, so the deadline has
    /// to allow for one. Reporting a timeout while somebody is still reaching for
    /// their key is the failure this guards.
    @Test func aSecurityKeyGetsTheLongerDeadline() async throws {
        let tool = StubKeePassTool()
        tool.result = LocalToolResult(exitCode: 0, stdout: Data("a\nb\n".utf8),
                                      stderr: "", timedOut: false)
        let channel = KeePassXCCommandLineChannel(runner: tool)
        _ = try await channel.entry(at: "e", unlock: unlock())
        #expect(tool.lastDeadline == KeePassXCCLIRunner.defaultDeadline)
        _ = try await channel.entry(at: "e", unlock: unlock(slot: .two))
        #expect(tool.lastDeadline == KeePassXCCLIRunner.touchDeadline)
        #expect(KeePassXCCLIRunner.touchDeadline > KeePassXCCLIRunner.defaultDeadline)
    }

    // MARK: READ-ONLY, structurally

    /// The promise that matters most: a corrupted vault is unrecoverable and it is
    /// not our file. Every argument list this app builds must name a read-only
    /// subcommand, and the runner refuses anything else even if one slipped through.
    @Test func onlyReadOnlySubcommandsAreEverBuiltOrAccepted() throws {
        let show = KeePassXCCommandLineChannel.showArguments(entryPath: "e", unlock: unlock())
        let search = KeePassXCCommandLineChannel.searchArguments(term: "vpn", unlock: unlock())
        for arguments in [show, search] {
            let subcommand = try #require(arguments.first)
            #expect(KeePassXCCommandLineChannel.readOnlySubcommands.contains(subcommand))
        }
        // None of the mutating ones is in the allow-list, so none can be run.
        for mutating in ["add", "edit", "rm", "mv", "import", "db-create", "db-edit", "merge"] {
            #expect(!KeePassXCCommandLineChannel.readOnlySubcommands.contains(mutating))
        }
    }

    // MARK: Parsing — the output shapes `Show.cpp` really produces

    @Test func twoRequestedAttributesComeBackAsTwoValuesInOrder() {
        let entry = KeePassXCCommandLineChannel.parseShowOutput(Data("alice\nhunter2\n".utf8))
        #expect(entry?.username == "alice")
        #expect(entry?.password == "hunter2")
    }

    /// An entry with no username prints an EMPTY first line. Dropping empties while
    /// splitting would silently move the password into the username field, and the
    /// VPN would then be handed a username as its password.
    @Test func anEmptyUsernameIsAnEmptyLineAndNotAShiftedPassword() {
        let entry = KeePassXCCommandLineChannel.parseShowOutput(Data("\nhunter2\n".utf8))
        #expect(entry?.username == nil)
        #expect(entry?.password == "hunter2")
    }

    /// A password containing spaces or a trailing structure must survive verbatim —
    /// only the trailing newline the tool adds is removed.
    @Test func aPasswordWithSpacesSurvivesVerbatim() {
        let entry = KeePassXCCommandLineChannel.parseShowOutput(
            Data("alice\ncorrect horse battery staple \n".utf8))
        #expect(entry?.password == "correct horse battery staple ")
    }

    /// If a future release ever changed how protected attributes are gated, the
    /// literal word `PROTECTED` must never be handed to a VPN as a password.
    @Test func theLiteralWordPROTECTEDIsRefusedRatherThanUsed() {
        #expect(KeePassXCCommandLineChannel.parseShowOutput(Data("alice\nPROTECTED\n".utf8)) == nil)
    }

    @Test func oneLineOfOutputIsNotAnAnswer() {
        #expect(KeePassXCCommandLineChannel.parseShowOutput(Data("alice\n".utf8)) == nil)
        #expect(KeePassXCCommandLineChannel.parseShowOutput(Data()) == nil)
    }

    @Test func searchOutputIsEntryPathsOnePerLine() {
        let paths = KeePassXCCommandLineChannel.parseSearchOutput(
            Data("VPN/Work\nVPN/Home\n  Personal/Router  \n\n".utf8))
        #expect(paths == ["VPN/Work", "VPN/Home", "Personal/Router"])
    }

    // MARK: Classification — KeePassXC's own strings

    private func failure(_ stderr: String) -> LocalToolResult {
        LocalToolResult(exitCode: 1, stdout: Data(), stderr: stderr, timedOut: false)
    }

    @Test func wrongCredentialsAreClassifiedAndNameEveryFactorInPlay() {
        // Verbatim from Kdbx3Reader.cpp, prefixed by the tool's own prompt because the
        // prompt has no trailing newline — which is what really appears on stderr.
        let stderr = "Enter password to unlock /Users/me/Passwords.kdbx: "
            + "Invalid credentials were provided, please try again."
        let error = KeePassXCCommandLineChannel.classify(
            failure(stderr), unlock: unlock(), entryPath: "VPN/Work")
        guard case .unlockRefused(let factors) = error else {
            #expect(Bool(false), "expected a refused unlock, got \(error)")
            return
        }
        // The honest ambiguity: the database only knows the whole key was wrong, so
        // the message must not accuse the password alone.
        #expect(factors.contains { $0.contains("password") })
        #expect(factors.contains { $0.contains("key file") })
        #expect(factors.contains { $0.contains("security key") })
    }

    /// A configured key file changes the wording: nobody should be told to check a
    /// key file they never set, and nobody with one should be told to add one.
    @Test func theRefusalWordingFollowsWhatIsActuallyConfigured() {
        let without = KeePassXCCommandLineChannel.refusalPossibilities(unlock())
        #expect(without.contains { $0.contains("hasn\u{2019}t been given") })
        let with = KeePassXCCommandLineChannel.refusalPossibilities(
            unlock(keyFile: "/k.keyx", slot: .two))
        #expect(with.contains("the key file"))
        #expect(with.contains { $0.contains("security key\u{2019}s answer") })
        #expect(!with.contains { $0.contains("hasn\u{2019}t been told about") })
    }

    @Test func aSecurityKeyThatDidNotAnswerIsNotAWrongPassword() {
        // Kdbx3Reader.cpp: "Unable to issue challenge-response: %1"
        let error = KeePassXCCommandLineChannel.classify(
            failure("Unable to issue challenge-response: no YubiKey found"),
            unlock: unlock(slot: .two), entryPath: "e")
        #expect(error == .securityKeyDidNotAnswer)
    }

    @Test func aMissingEntryNamesTheEntryAndNotThePassword() {
        // Show.cpp: "Could not find entry with path %1."
        let error = KeePassXCCommandLineChannel.classify(
            failure("Could not find entry with path VPN/Wrok."),
            unlock: unlock(), entryPath: "VPN/Wrok")
        #expect(error == .entryNotFound("VPN/Wrok"))
    }

    @Test func theToolsOwnFormatAndFileErrorsMapToTheirOwnStates() {
        // KeePass2Reader.cpp / Database.cpp, verbatim.
        #expect(KeePassXCCommandLineChannel.classify(
            failure("Not a KeePass database."), unlock: unlock(), entryPath: "e")
                == .notAKeePassDatabase(.notKeePassAtAll))
        #expect(KeePassXCCommandLineChannel.classify(
            failure("The selected file is an old KeePass 1 database (.kdb)."),
            unlock: unlock(), entryPath: "e")
                == .notAKeePassDatabase(.keePass1Database))
        #expect(KeePassXCCommandLineChannel.classify(
            failure("Unsupported KeePass 2 database version."), unlock: unlock(), entryPath: "e")
                == .databaseTooNew("newer than this tool"))
        #expect(KeePassXCCommandLineChannel.classify(
            failure("File /Users/me/Passwords.kdbx does not exist."),
            unlock: unlock(), entryPath: "e")
                == .databaseMissing("/Users/me/Passwords.kdbx"))
    }

    @Test func aTimeoutIsATimeoutAndNotACredentialProblem() {
        let result = LocalToolResult(exitCode: -1, stdout: Data(), stderr: "", timedOut: true)
        #expect(KeePassXCCommandLineChannel.classify(result, unlock: unlock(), entryPath: "e")
                == .timedOut)
    }

    /// The documented limit, asserted rather than hoped for: when the marker is lost
    /// (a very long database path pushes it past the runner's 200-character cap) we
    /// fall through to the honest ambiguous answer instead of guessing.
    @Test func anUnrecognisedFailureFallsBackToTheHonestAmbiguity() {
        let error = KeePassXCCommandLineChannel.classify(
            failure("Enter password to unlock /Users/me/Library/Mobile Documents/"
                    + String(repeating: "a", count: 200)),
            unlock: unlock(), entryPath: "e")
        guard case .unlockRefused = error else {
            #expect(Bool(false), "expected the ambiguous answer, got \(error)")
            return
        }
    }

    @Test func aMissingToolIsSaidPlainly() {
        let channel = KeePassXCCommandLineChannel(runner: {
            let tool = StubKeePassTool(); tool.located = nil; return tool
        }())
        #expect(!channel.isReachable())
    }

    @Test func searchTreatsNoMatchesAsAnEmptyListRatherThanAnError() async throws {
        let tool = StubKeePassTool()
        tool.result = failure("Could not find entry with path nothing.")
        let channel = KeePassXCCommandLineChannel(runner: tool)
        let paths = try await channel.entryPaths(matching: "nothing", unlock: unlock())
        #expect(paths.isEmpty)
    }
}

// MARK: - The provider's pure rules

struct KeePassFileProviderRulesTests {

    @Test func anEntryWithoutAPasswordIsSaidPlainly() {
        let entry = KeePassFileEntry(username: "alice", password: nil)
        #expect(throws: KeePassFileError.entryHasNoPassword("VPN/Work")) {
            try KeePassFileProvider.credentials(from: entry, entryPath: "VPN/Work", wanted: "")
        }
    }

    @Test func theWantedUsernameIsAConfirmationAndAMismatchIsRefused() {
        let entry = KeePassFileEntry(username: "alice", password: "s3cret")
        #expect(throws: KeePassFileError.entryNotFound("VPN/Work")) {
            try KeePassFileProvider.credentials(from: entry, entryPath: "VPN/Work", wanted: "bob")
        }
        // …case-insensitively, because a username's case is not a password's.
        let ok = try? KeePassFileProvider.credentials(from: entry, entryPath: "VPN/Work",
                                                     wanted: "ALICE")
        #expect(ok?.username == "alice")
        #expect(ok?.password == "s3cret")
    }

    /// An entry with no username of its own falls back to what the VPN was told,
    /// which is the only sensible answer for a database whose entries carry the
    /// password but not the login.
    @Test func anEntryWithNoUsernameUsesTheOneTheVPNNames() throws {
        let entry = KeePassFileEntry(username: nil, password: "s3cret")
        let raw = try KeePassFileProvider.credentials(from: entry, entryPath: "e", wanted: "alice")
        #expect(raw.username == "alice")
    }

    /// The flag is a PROMISE ("Connect works with nothing typed"), and this source
    /// cannot keep it — `show -t` fails the whole run on an entry with no code.
    @Test func thisSourceDoesNotClaimToSupplyAVerificationCode() {
        #expect(!CredentialSourceKind.keePassFile.suppliesOTP)
        var inputs = ConnectInputs()
        inputs.managerKind = .keePassFile
        inputs.requiresOTP = true
        #expect(inputs.readiness == .needsCode)
        inputs.typedOTP = true
        #expect(inputs.readiness == .ready)
    }

    @Test func theStoredSourceRoundTripsAndCarriesNoSecret() throws {
        var source = CredentialSource()
        source.kind = .keePassFile
        source.reference = "VPN/Work"
        source.account = "alice"
        let blob = try #require(source.encodedBlob())
        // JSON escapes the separator, so the round trip is the honest check for the
        // reference; the raw text is what proves nothing secret is in there.
        let text = String(decoding: blob, as: UTF8.self)
        #expect(CredentialSource.decode(from: blob) == source)
        #expect(CredentialSource.decode(from: blob).reference == "VPN/Work")
        // The stored reference is an entry PATH and a username. Nothing that opens
        // anything: not the database's password, not a key file's contents. Note
        // "password" must not appear even as a KEY — there is no field for one.
        #expect(!text.lowercased().contains("password"))
        #expect(!text.contains("keyfile"))
        #expect(!text.contains(".kdbx"))
    }
}

// MARK: - The password box, and where it may live

struct KDBXPasswordTests {

    /// `KDBXPassword` is deliberately NOT a `SingleUseCode`: a database password is
    /// replayable, and one app run may unlock the same database a dozen times. What
    /// it borrows is the absence of every API through which a secret leaks into text.
    @Test func thePasswordBoxHasNoWayToBecomeText() {
        let password = KDBXPassword("hunter2")
        #expect(password.characterCount == 7)
        #expect(!password.isEmpty)
        // The only way out is the stdin bytes. There is no getter, no description and
        // no Codable — which is a compile-time property, so the assertion that
        // matters is that the ONE exit produces what the tool needs.
        #expect(password.stdinLine() == Data("hunter2\n".utf8))
    }

    /// `keepassxc-cli` reads exactly one line, so a password with a line break in it
    /// cannot be delivered at all. Detected up front, because "wrong password" would
    /// be the wrong thing to say about it.
    @Test func aPasswordWithALineBreakIsDetectedRatherThanTruncated() {
        #expect(KDBXPassword("two\nlines").containsNewline)
        #expect(!KDBXPassword("one line").containsNewline)
    }

    @Test func anEmptyPasswordIsARealStateAndNotAMissingOne() {
        #expect(KDBXPassword("").isEmpty)
    }

    /// The keychain account is a HASH of the path, not the path: a keychain item's
    /// account is visible in Keychain Access, and "/Users/me/Personal Passwords.kdbx"
    /// is not something to publish there.
    @Test func theKeychainAccountNamesNoPath() {
        let account = KDBXMasterPasswordStore.account(
            forDatabase: "/Users/me/Documents/Personal Passwords.kdbx")
        #expect(account.hasPrefix("kdbx:"))
        #expect(!account.contains("Personal"))
        #expect(!account.contains("/"))
        // Stable, so the item can be found again.
        #expect(account == KDBXMasterPasswordStore.account(
            forDatabase: "/Users/me/Documents/Personal Passwords.kdbx"))
        // …and per database.
        #expect(account != KDBXMasterPasswordStore.account(forDatabase: "/other.kdbx"))
    }

    @MainActor
    @Test func holdingForThisRunIsSessionOnlyAndForgettingReallyForgets() {
        let store = KDBXMasterPasswordStore()
        #expect(!store.isHeldForThisRun(database: "/db.kdbx"))
        store.holdForThisRun(KDBXPassword("x"), database: "/db.kdbx")
        #expect(store.isHeldForThisRun(database: "/db.kdbx"))
        #expect(store.heldDescription(database: "/db.kdbx").contains("until SimpleVPN quits"))
        store.forgetThisRun(database: "/db.kdbx")
        #expect(!store.isHeldForThisRun(database: "/db.kdbx"))
        #expect(store.heldDescription(database: "/db.kdbx").contains("Not held"))
    }

    @MainActor
    @Test func aPasswordHeldForOneDatabaseIsNotHeldForAnother() {
        let store = KDBXMasterPasswordStore()
        store.holdForThisRun(KDBXPassword("x"), database: "/one.kdbx")
        #expect(!store.isHeldForThisRun(database: "/two.kdbx"))
    }
}

// MARK: - The security-key check

struct KDBXSecurityKeyCheckTests {

    /// A stub `ykman`. Records argv, so the assertion that the CHALLENGE — and only
    /// the challenge — travels there is a test.
    final class StubYkman: YubiKeyToolRunning, @unchecked Sendable {
        var located: String? = "/opt/homebrew/bin/ykman"
        var result = LocalToolResult(exitCode: 0, stdout: Data(), stderr: "", timedOut: false)
        private(set) var lastArguments: [String] = []
        private(set) var lastDeadline: TimeInterval = 0

        func locate() -> String? { located }
        func run(_ arguments: [String], deadline: TimeInterval) async -> LocalToolResult {
            lastArguments = arguments
            lastDeadline = deadline
            return result
        }
    }

    private var facts: KDBXHeaderFacts {
        KDBXHeaderFacts(version: KDBXVersion(major: 4, minor: 1),
                        keyDerivation: .argon2id, kdfSeed: KDBXFixture.seed)
    }

    /// The whole point of the check, and of `YubiKeyChallengeResponse` being reused
    /// rather than reimplemented: the challenge is the database's KDF seed, padded
    /// KeePassXC's way. A 32-byte seed becomes 64 bytes of PKCS#7 (32 bytes of 0x20
    /// appended) — anything else produces a different response and fails to unlock a
    /// database that works everywhere else, with no error to explain why.
    @Test func theChallengeIsTheDatabaseSeedPaddedKeePassXCsWay() async {
        let ykman = StubYkman()
        // 20 hex bytes: `ykman otp calculate` prints the response as hex.
        ykman.result = LocalToolResult(
            exitCode: 0, stdout: Data("0123456789abcdef0123456789abcdef01234567\n".utf8),
            stderr: "", timedOut: false)
        let result = await KeePassSecurityKeyCheck.run(
            facts: facts, slot: .two, serial: "12345678",
            tool: YubiKeyManagerTool(runner: ykman))
        #expect(result == .answered(slot: .two))

        // The padded challenge, computed independently of the code under test.
        let expected = KDBXFixture.seed + Data(repeating: 32, count: 32)
        #expect(expected.count == 64)
        let hex = expected.map { String(format: "%02x", $0) }.joined()
        #expect(ykman.lastArguments.contains(hex))
        #expect(ykman.lastArguments.contains("calculate"))
        #expect(ykman.lastArguments.contains("2"))
        // A serial is printed on the key and is not a secret.
        #expect(ykman.lastArguments.contains("12345678"))
        // A touch-required slot must not be reported as a timeout while somebody is
        // still reaching for their key.
        #expect(ykman.lastDeadline == YkmanRunner.touchDeadline)
    }

    /// A header with no seed is not a broken key, and saying "your key didn't answer"
    /// about it would send somebody to buy a new one.
    @Test func aDatabaseWithNoFindableSeedIsNotAFailedKey() async {
        let none = KDBXHeaderFacts(version: KDBXVersion(major: 4, minor: 1), kdfSeed: nil)
        let result = await KeePassSecurityKeyCheck.run(
            facts: none, slot: .two, serial: nil, tool: YubiKeyManagerTool(runner: StubYkman()))
        #expect(result == .noChallengeAvailable)
        #expect(result.sentence.contains("nothing to check"))
        #expect(!result.succeeded)
    }

    @Test func withoutYkmanTheCheckSaysSoAndDoesNotBlameTheDatabase() async {
        let ykman = StubYkman()
        ykman.located = nil
        let result = await KeePassSecurityKeyCheck.run(
            facts: facts, slot: .two, serial: nil, tool: YubiKeyManagerTool(runner: ykman))
        guard case .cannotAsk = result else {
            #expect(Bool(false), "expected cannotAsk, got \(result)")
            return
        }
        // …and it must be clear this does not stop a connect: `keepassxc-cli` talks
        // to the key itself.
        #expect(result.sentence.contains("doesn\u{2019}t stop the database opening"))
    }

    /// What the check PROVES is possession, not correctness — only unlocking can
    /// prove the answer is right. The wording has to say that, or somebody whose
    /// database still refuses will think the check lied.
    @Test func theSuccessSentenceDoesNotOverclaim() {
        let sentence = KDBXSecurityKeyCheckResult.answered(slot: .two).sentence
        #expect(sentence.contains("only unlocking can tell you"))
    }
}

// MARK: - Availability: every not-working state, and its one fix

@MainActor
struct KeePassFileAvailabilityTests {

    /// A channel that is simply present or absent — availability never runs the tool.
    struct Reachability: KeePassFileChannel {
        var reachable: Bool
        func isReachable() -> Bool { reachable }
        func entry(at path: String, unlock: KDBXUnlock) async throws -> KeePassFileEntry {
            throw KeePassFileError.toolMissing
        }
        func entryPaths(matching term: String, unlock: KDBXUnlock) async throws -> [String] {
            throw KeePassFileError.toolMissing
        }
    }

    /// A defaults domain of its own, so nothing here touches the real one.
    private func store(database: String? = nil, keyFile: String? = nil,
                       slot: String? = nil) -> SignInSourceSettingsStore {
        let suite = UserDefaults(suiteName: "kdbx-tests-\(UUID().uuidString)")!
        if let database { suite.set(database, forKey: SignInSourceSettings.keePassDatabaseKey) }
        if let keyFile { suite.set(keyFile, forKey: SignInSourceSettings.keePassKeyFileKey) }
        if let slot { suite.set(slot, forKey: SignInSourceSettings.keePassSecurityKeySlotKey) }
        return SignInSourceSettingsStore(store: suite)
    }

    private func write(_ bytes: Data, named name: String = "Passwords.kdbx") throws -> String {
        let directory = URL(fileURLWithPath: NSTemporaryDirectory())
            .appendingPathComponent(UUID().uuidString)
        try FileManager.default.createDirectory(at: directory, withIntermediateDirectories: true)
        let url = directory.appendingPathComponent(name)
        try bytes.write(to: url)
        return url.path
    }

    /// Every file-shaped state, each mapping to a distinct block with its own fix.
    /// The lie this prevents is the one that matters: all five of these would
    /// otherwise be reported as "wrong password".
    @Test func everyFileStateIsItsOwnBlockWithItsOwnFix() throws {
        let cases: [(Data?, LocalVaultBlock)] = [
            (KDBXFixture.magic(major: 5, minor: 0), .vaultFileTooNew),
            (Data("not a vault".utf8), .vaultFileNotAKeePassDatabase),
            (KDBXFixture.magic(major: 3, minor: 1, signature2: 0xB54B_FB65)
                + Data(repeating: 0, count: 32), .vaultFileNotAKeePassDatabase),
        ]
        for (bytes, expected) in cases {
            let path = try write(bytes!)
            let state = KeePassDatabaseFile.classify(path: path)
            #expect(!state.isReadable)
            // …and the copy has a headline and a fix for that block.
            let copy = LocalVaultCopyBook.keePassFile
            #expect(!copy.headline(for: expected).isEmpty)
            #expect(!copy.steps(for: expected).isEmpty || copy.guidance(for: expected) != nil)
        }
        // A path pointing at nothing.
        #expect(KeePassDatabaseFile.classify(path: "/definitely/not/here.kdbx")
                == .missing(path: "/definitely/not/here.kdbx"))
        let copy = LocalVaultCopyBook.keePassFile
        #expect(!copy.steps(for: .vaultFileMissing).isEmpty)
        #expect(!copy.steps(for: .vaultFileNotDownloaded).isEmpty)
    }

    /// The tool missing is an ENABLEMENT state with an exact command — and SimpleVPN
    /// never runs it. The command is shown; the user runs it.
    @Test func aMissingToolCarriesTheCommandAndNeverRunsIt() {
        let guidance = LocalVaultCopyBook.keePassFile.guidance(for: .toolMissing)
        #expect(guidance?.example.first?.text == "brew install --cask keepassxc")
        #expect(guidance?.doc == VendorDocs.keePassXC)
        #expect(LocalVaultBlock.toolMissing.wantsEnablementBanner)
        // Its spoken form carries the command as CONTENT — nothing hover-only.
        #expect(guidance?.spokenSummary.contains("brew install --cask keepassxc") == true)
    }

    /// "Found at …, but not somewhere SimpleVPN will run it from" is a two-second fix
    /// and must never be reported as "not installed".
    @Test func theOutsideAllowListStateIsAnEnablementAndNamesThePath() {
        #expect(LocalVaultBlock.toolOutsideAllowList.wantsEnablementBanner)
        let guidance = LocalVaultCopyBook.keePassFile.guidance(
            for: .toolOutsideAllowList, foundAt: "/Users/me/.nix-profile/bin/keepassxc-cli")
        #expect(guidance?.benefit.contains("/Users/me/.nix-profile/bin/keepassxc-cli") == true)
    }

    /// A file state is NOT an enablement: there is no switch to flick, and putting
    /// "you can turn this on" wording on a moved file would be nonsense.
    @Test func fileProblemsAreNotEnablementStates() {
        #expect(!LocalVaultBlock.vaultFileMissing.wantsEnablementBanner)
        #expect(!LocalVaultBlock.vaultFileNotDownloaded.wantsEnablementBanner)
        #expect(!LocalVaultBlock.vaultFileNotReadable.wantsEnablementBanner)
        #expect(!LocalVaultBlock.vaultFileNotAKeePassDatabase.wantsEnablementBanner)
        #expect(!LocalVaultBlock.vaultFileTooNew.wantsEnablementBanner)
        // …but "you haven't chosen one" and "type your password" are.
        #expect(LocalVaultBlock.noVaultFile.wantsEnablementBanner)
        #expect(LocalVaultBlock.vaultLocked.wantsEnablementBanner)
        #expect(LocalVaultBlock.vaultPasswordRejected.wantsEnablementBanner)
    }

    /// "You haven't given me one" and "the one you gave me didn't work" are different
    /// sentences, and only one of them is a correction.
    @Test func aRefusedUnlockIsRememberedSeparatelyFromNeverHavingOne() {
        let memory = KeePassFileUnlockMemory.shared
        memory.clear(database: "/db.kdbx")
        #expect(!memory.wasRefused(database: "/db.kdbx"))
        memory.noteRefused(database: "/db.kdbx")
        #expect(memory.wasRefused(database: "/db.kdbx"))
        // Typing a new password retires the accusation — otherwise following the
        // advice would leave the row still complaining.
        memory.clear(database: "/db.kdbx")
        #expect(!memory.wasRefused(database: "/db.kdbx"))
        #expect(LocalVaultCopyBook.keePassFile.headline(for: .vaultLocked)
                != LocalVaultCopyBook.keePassFile.headline(for: .vaultPasswordRejected))
    }

    /// The row is not advertised at a person with nothing KeePass on their Mac: that
    /// would be pushing a file format at somebody who does not use one.
    @Test func withNoToolNoAppAndNoDatabaseTheRowIsNotOffered() {
        let adapter = KeePassFileVaultAdapter(channel: Reachability(reachable: false))
        // On THIS machine no KeePass app is installed and `keepassxc-cli` is absent,
        // so the honest answer is that there is nothing to offer. (If a KeePass app
        // were installed the answer would be `.blocked(.toolMissing)`, which is the
        // branch the copy test above covers.)
        let availability = adapter.quickScan()
        if KeePassFileVaultAdapter.isKeePassFormatAppInstalled {
            #expect(availability == .blocked(.toolMissing))
        } else {
            #expect(availability == .notInstalled)
        }
    }

    @Test func theConfigurationReadsTheThreeSettingsAndTreatsEmptyAsNone() throws {
        let path = try write(KDBXFixture.kdbx4())
        let configuration = KeePassFileConfiguration.current(
            store: store(database: path, slot: "2"))
        #expect(configuration.databasePath == path)
        #expect(configuration.isConfigured)
        #expect(configuration.slot == .two)
        // Empty means none — the whole reason there is no separate switch.
        let bare = KeePassFileConfiguration.current(store: store(database: path))
        #expect(bare.slot == nil)
        #expect(!bare.unlock(password: nil).usesSecurityKey)
        #expect(bare.unlock(password: nil).keyFilePath == nil)
    }

    /// A slot that is not 1 or 2 is a problem the field states, not something quietly
    /// dropped — a mistyped slot would otherwise fail the unlock with no explanation.
    @Test func theSlotFieldValidatesAndAnEmptyOneIsNotAFault() throws {
        let settings = store()
        let field = try #require(
            SignInSourceSettings.fields(for: .keePassFile).first { $0.kind == .securityKeySlot })
        #expect(settings.validate("2", field: field) == .ok)
        #expect(settings.validate("1", field: field) == .ok)
        #expect(settings.validate("3", field: field) == .badSecurityKeySlot)
        #expect(settings.validate("two", field: field) == .badSecurityKeySlot)
        #expect(settings.validate("", field: field) == .notSet(detected: nil))
        #expect(!VendorFieldValidation.notSet(detected: nil).isProblem)
        #expect(VendorFieldValidation.badSecurityKeySlot.isProblem)
    }

    /// The database field is the one field in the pane whose CONTENTS are checked,
    /// because the ways a chosen file can be the wrong file all look identical from a
    /// failed unlock.
    @Test func theDatabaseFieldValidatesTheFileItself() throws {
        let settings = store()
        let field = try #require(
            SignInSourceSettings.fields(for: .keePassFile).first {
                if case .vaultFile = $0.kind { return true } else { return false }
            })
        let good = try write(KDBXFixture.kdbx4())
        #expect(settings.validate(good, field: field) == .ok)

        // Long enough to hold a signature, so this is "not a KeePass file" rather
        // than "too small to tell" — two states with two different sentences.
        let notADatabase = try write(
            Data("hello, this is a text file and quite definitely not a vault".utf8),
            named: "notes.txt")
        guard case .notAReadableDatabase(let why) = settings.validate(notADatabase, field: field)
        else {
            #expect(Bool(false), "a text file must not validate as a database")
            return
        }
        #expect(why.contains(".kdbx"))

        #expect(settings.validate("relative/path.kdbx", field: field) == .notAbsolute)
        #expect(settings.validate("/nope/nothing.kdbx", field: field) == .missing)
    }

    /// NO GUESS for a database path, deliberately: finding one would mean reading
    /// somebody's file tree to work out where they keep their passwords.
    @Test func noDatabasePathIsEverSuggested() throws {
        let settings = store()
        for field in SignInSourceSettings.fields(for: .keePassFile) {
            switch field.kind {
            case .vaultFile, .keyFile:
                #expect(settings.detected(for: field) == nil)
                // …and the placeholder shows the SHAPE of an answer instead, as a
                // prompt and never as a value (the landmine this project shipped once).
                let shown = settings.presentation(for: field)
                #expect(shown.value.isEmpty)
                #expect(shown.prompt == field.example)
                #expect(!shown.isSet)
            case .toolBinary, .unixSocket, .daemonEndpoint, .securityKeySlot, .pkcs11Module,
                 .storeDirectory, .entryFieldName, .serverURL, .toolConfigFile,
                 .accountIdentifier:
                // Not kdbx fields — a password store's own, and 1Password's account,
                // are covered by their own tests.
                continue
            }
        }
    }
}

// MARK: - The chooser and the settings catalog

@MainActor
struct KeePassFileCatalogTests {

    private func bareMac() -> SignInSourceFacts {
        var facts = SignInSourceFacts()
        facts.vaults = Dictionary(uniqueKeysWithValues:
            LocalVaultVendor.allCases.map { ($0, LocalVaultAvailability.notInstalled) })
        return facts
    }

    @Test func theRowIsOnlyOfferedWhenItsVendorIsAvailable() throws {
        #expect(SignInSourceCatalog.vaultOption(.keePassFile, availability: .notInstalled) == nil)
        let option = try #require(
            SignInSourceCatalog.vaultOption(.keePassFile, availability: .ready))
        #expect(option.storedKind == .keePassFile)
        #expect(option.role == .fetches)
        #expect(option.configurableVendor == .keePassFile)
    }

    /// The one thing this row must say that no other row has to: SimpleVPN sees the
    /// database password. Hiding that would make the choice uninformed.
    @Test func theRowAdmitsThatSimpleVPNSeesTheDatabasePassword() {
        let copy = LocalVaultCopyBook.keePassFile
        #expect(copy.explanation.contains("does see your database\u{2019}s password"))
        #expect(copy.explanation.contains("never changes your database"))
        // …and points at the better option when it exists.
        #expect(copy.explanation.contains("KeePassXC row above"))
        // Strongbox and KeePassium users must find themselves in it by name.
        #expect(copy.explanation.contains("Strongbox"))
        #expect(copy.explanation.contains("KeePassium"))
    }

    /// Turning the vendor off means off: not offered AND not hinted.
    @Test func aSwitchedOffVendorIsNeitherOfferedNorHinted() {
        var facts = bareMac()
        facts.vaults[.keePassFile] = .ready
        facts.otherApps = [.init(bundleID: "com.markmcguill.strongbox.mac", name: "Strongbox")]
        facts.disabledVendors = [.keePassFile]
        let options = SignInSourceCatalog.options(facts)
        #expect(!options.contains { $0.id == .vault(.keePassFile) })
        // …and Strongbox must not reappear in the "other apps" list, which would be
        // the same app still being advertised in a worse place.
        #expect(!options.contains { $0.title == "Strongbox" })
    }

    /// Strongbox is never both a source and a pointer. Two rows for one product, one
    /// of them saying we cannot read it, is exactly the confusion the two classes
    /// exist to prevent.
    @Test func strongboxIsNeverBothASourceAndAPointer() {
        var facts = bareMac()
        facts.otherApps = [.init(bundleID: "com.markmcguill.strongbox.mac", name: "Strongbox"),
                           .init(bundleID: "com.keepassium.mac", name: "KeePassium")]
        facts.vaults[.keePassFile] = .ready
        let options = SignInSourceCatalog.options(facts)
        #expect(!options.contains { $0.title == "Strongbox" })
        #expect(!options.contains { $0.title == "KeePassium" })
        #expect(options.contains { $0.id == .vault(.keePassFile) })
    }

    /// With the file row NOT on offer, Strongbox is a pointer again — and its wording
    /// says how to turn the row on rather than "on the list", which is no longer true.
    @Test func withoutTheFileRowStrongboxPointsAtHowToEnableIt() throws {
        var facts = bareMac()
        facts.otherApps = [.init(bundleID: "com.markmcguill.strongbox.mac", name: "Strongbox")]
        let options = SignInSourceCatalog.options(facts)
        let pointer = try #require(options.first { $0.title == "Strongbox" })
        #expect(pointer.role == .hint)
        #expect(pointer.explanation.contains("brew install --cask keepassxc"))
        #expect(pointer.explanation.contains("KeePass database file"))
    }

    @Test func everyBlockThisVendorCanReportHasSomethingToSay() throws {
        let copy = LocalVaultCopyBook.keePassFile
        let reachable: [LocalVaultBlock] = [
            .toolMissing, .toolOutsideAllowList, .noVaultFile, .vaultFileMissing,
            .vaultFileNotDownloaded, .vaultFileNotReadable, .vaultFileNotAKeePassDatabase,
            .vaultFileTooNew, .vaultLocked, .vaultPasswordRejected,
        ]
        for block in reachable {
            let option = try #require(
                SignInSourceCatalog.vaultOption(.keePassFile, availability: .blocked(block)))
            guard case .needsSetup(let headline, _) = option.state else {
                #expect(Bool(false), "\(block) has no headline")
                continue
            }
            #expect(!headline.isEmpty)
            // An enablement block must carry guidance; a file problem must carry steps.
            if block.wantsEnablementBanner, block != .toolOutsideAllowList {
                #expect(option.guidance != nil, "\(block) is an enablement with no guidance")
            } else if block != .toolOutsideAllowList {
                #expect(!copy.steps(for: block).isEmpty, "\(block) has no steps")
            }
        }
    }

    /// Every one of this vendor's controls is a real spec — so app-wide search finds
    /// it, MDM and the CLI can address it, and its help button lands somewhere real.
    @Test func everyControlIsASpecInTheCredentialsCatalog() {
        let ids = Set(CredentialSourceSettings.all.map(\.id))
        #expect(ids.contains("creds.keepassfile.enabled"))
        #expect(ids.contains("creds.keepassfile.database"))
        #expect(ids.contains("creds.keepassfile.key-file"))
        #expect(ids.contains("creds.keepassfile.security-key-slot"))
        #expect(ids.contains("creds.keepassfile.tool-path"))
        #expect(ids.contains(SignInSourceSettings.keePassPasswordSettingID))
        #expect(ids.contains(SignInSourceSettings.keePassRememberPasswordSettingID))
        // …and each of them routes back to this vendor, so "Configure…" lands on it.
        for id in ids where id.hasPrefix("creds.keepassfile.") {
            #expect(CredentialSourceSettings.vendor(forSettingID: id) == .keePassFile)
        }
    }

    /// The tool belongs to THIS row, not to the KeePassXC socket row: the socket row
    /// needs no binary at all, and pointing the "found at …, but not somewhere
    /// SimpleVPN will run it from" sentence at it would put it on the one row it
    /// cannot help.
    @Test func theCommandLineToolIsRecordedAgainstTheFileVendor() throws {
        let tool = try #require(ToolCatalog.tool(named: "keepassxc-cli"))
        #expect(tool.vendor == .keePassFile)
        #expect(ToolCatalog.tools(for: .keePassFile).contains { $0.name == "keepassxc-cli" })
        // It ships inside the app bundle, which is why "the app is installed" already
        // means "the tool is available".
        #expect(tool.bundledCLIs.contains {
            $0.appBundleName == "KeePassXC.app"
                && $0.relativePath == "Contents/MacOS/keepassxc-cli"
        })
    }

    @Test func theRecoveryNoticeSendsPeopleWhereTheAnswerIs() {
        let headline = SignInFlow.unavailableHeadline(.keePassFile)
        #expect(headline.contains("Sign-In Sources"))
        // …and does NOT guess which of the five possible problems it is.
        #expect(!headline.lowercased().contains("wrong password"))
    }
}
