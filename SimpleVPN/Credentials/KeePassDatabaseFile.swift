// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
//  KeePassDatabaseFile.swift
//  Everything SimpleVPN can learn about a KeePass `.kdbx` database WITHOUT
//  unlocking it — and nothing more. No decryption, no key derivation, no XML: the
//  outer header of a KDBX file is plaintext by design, and reading it answers
//  every question the sign-in chooser needs to ask before anyone types a password.
//
//  WHY THIS EXISTS RATHER THAN "just run keepassxc-cli and see what happens".
//  Four of the states a user has to be told apart look identical from a failed
//  unlock — "that isn't a KeePass database", "that database is newer than the tool
//  can read", "the file has moved", "iCloud hasn't downloaded it yet" — and all
//  four would otherwise be reported as *wrong password*, which sends someone off
//  to retype a password that was never the problem. Each of them is decidable from
//  bytes we can read for free, so each of them gets its own sentence.
//
//  It also produces the ONE value the security-key path needs: the KDF seed.
//  KeePassXC's `CompositeKey::transform` passes `kdf.seed()` to every
//  challenge-response key, and that seed is the KDBX3 `TransformSeed` header field
//  or the KDBX4 KDF parameter `"S"` — both stored in CLEARTEXT in the outer
//  header. That is what makes `YubiKeyChallengeResponse.respond(toPublicChallenge:)`
//  legal on this path: the challenge is a public value, not a secret, so it may
//  ride argv. Anyone holding the file already has it.
//
//  PROVENANCE. Every constant and layout here is taken from KeePassXC's own
//  source, not from a blog post:
//    • `src/format/KeePass2.h` — SIGNATURE_1 = 0x9AA2D903, SIGNATURE_2 =
//      0xB54BFB67, FILE_VERSION_CRITICAL_MASK = 0xFFFF0000, FILE_VERSION_3_1 =
//      0x00030001, FILE_VERSION_4 = 0x00040000, FILE_VERSION_4_1 = 0x00040001,
//      and `HeaderFieldID` (TransformSeed = 5, KdfParameters = 11, EndOfHeader = 0).
//    • `src/format/KeePass2.cpp` — KDFPARAM_UUID = "$UUID", KDFPARAM_AES_SEED =
//      "S", KDFPARAM_ARGON2_SALT = "S", and the four KDF UUIDs.
//    • `src/format/Kdbx4Reader.cpp` — the KDBX4 header field layout (1-byte id,
//      uint32 length) and the VariantDictionary layout (uint16 version, then
//      per entry: 1-byte type, uint32 name length, name, uint32 value length,
//      value; terminated by a 0x00 type byte).
//    • `src/format/KdbxReader.cpp` — the three uint32s at the start of the file,
//      read little-endian (`KeePass2::BYTEORDER`).
//    • `src/keys/CompositeKey.cpp` — the challenge is `kdf.seed()`, and the
//      response is hashed AFTER every ordinary key.
//  KDBX3's header field length is a uint16 rather than a uint32; that is the only
//  structural difference between the two that matters here.
//
//  READ-ONLY, ABSOLUTELY. Nothing in this file opens a file for writing, and the
//  reader takes a bounded prefix rather than the whole database: a vault can be
//  hundreds of megabytes and none of it past the header is any of our business.
//

import Foundation
import os

// MARK: - What version we are looking at

/// A KDBX format version, as the two numbers the file carries.
nonisolated struct KDBXVersion: Sendable, Equatable, Comparable {
    var major: UInt16
    var minor: UInt16

    /// The raw uint32 as stored: major in the high half, minor in the low half.
    var rawValue: UInt32 { (UInt32(major) << 16) | UInt32(minor) }

    static func < (lhs: KDBXVersion, rhs: KDBXVersion) -> Bool {
        (lhs.major, lhs.minor) < (rhs.major, rhs.minor)
    }

    /// How it reads on screen. "4.1", never a hex word.
    var displayName: String { "\(major).\(minor)" }

    /// KeePassXC's `FILE_VERSION_CRITICAL_MASK` is 0xFFFF0000 — the MAJOR number
    /// alone decides whether a reader can cope. A 4.2 that hasn't been invented yet
    /// is readable by a 4.x reader; a 5.0 is not.
    static let highestSupportedMajor: UInt16 = 4

    var isSupported: Bool { major >= 3 && major <= Self.highestSupportedMajor }
}

/// Which key-derivation function the header names, when we recognise it. Reported
/// for the diagnostic value only — the unlock is `keepassxc-cli`'s job.
nonisolated enum KDBXKeyDerivation: String, Sendable, Equatable {
    case aesKDF
    case argon2d
    case argon2id
    case unrecognised

    /// The plain-language name, for a settings row that says what it found.
    var displayName: String {
        switch self {
        case .aesKDF: "AES-KDF"
        case .argon2d: "Argon2d"
        case .argon2id: "Argon2id"
        case .unrecognised: "an unfamiliar method"
        }
    }
}

// MARK: - The header, read

/// What the plaintext outer header says. NOTHING here is a secret: a version
/// number, the name of a key-derivation function, and a random seed that is
/// stored in the clear precisely so that anyone opening the file can use it.
nonisolated struct KDBXHeaderFacts: Sendable, Equatable {
    var version: KDBXVersion
    var keyDerivation: KDBXKeyDerivation = .unrecognised
    /// `kdf.seed()` — the KDBX3 transform seed, or the KDBX4 `"S"` KDF parameter.
    /// THE challenge a security-key unlock answers. Public by construction.
    var kdfSeed: Data?

    /// Whether a security-key challenge can even be computed for this database.
    /// A header with no seed we could find means we cannot pre-check the key, and
    /// saying so beats pretending the check passed.
    var canComputeSecurityKeyChallenge: Bool { !(kdfSeed?.isEmpty ?? true) }
}

// MARK: - Why a file isn't usable

/// The states a chosen database file can be in. Every case that is not
/// `.readable` names ONE thing the user can do about it, and they are deliberately
/// separate cases rather than one "couldn't read it": telling somebody their
/// password is wrong when their file is still in iCloud is the failure this whole
/// type exists to prevent.
nonisolated enum KDBXFileState: Sendable, Equatable {
    /// No database has been chosen yet.
    case notConfigured
    /// The path is set and there is nothing there.
    case missing(path: String)
    /// It is in iCloud Drive (or another file provider) and the contents are not on
    /// this Mac yet. NOT an error, and not a read failure: it becomes readable on
    /// its own once the download finishes.
    case notDownloaded(path: String)
    /// It is there and macOS will not let SimpleVPN read it.
    ///
    /// THE STATE THIS APP WOULD OTHERWISE GET WRONG. macOS protects `~/Desktop`,
    /// `~/Documents`, `~/Downloads` and iCloud Drive from every app, sandboxed or
    /// not, and a database in one of them needs the user's consent once. A denial
    /// lets `stat` through (metadata is not protected) and refuses `open` with
    /// EACCES — so without this case the file would be reported as an empty or
    /// truncated database, which is a sentence about the FILE for a problem that is
    /// entirely about PERMISSION.
    case permissionDenied(path: String)
    /// It is there, and it is not a KeePass 2 database.
    case notADatabase(path: String, reason: NotADatabaseReason)
    /// A real KDBX, of a generation newer than anything that can read it here.
    case tooNew(path: String, version: KDBXVersion)
    /// Readable, and here is what its header says.
    case readable(path: String, facts: KDBXHeaderFacts)

    /// The specific kind of "not a KeePass 2 database", because the fix differs.
    nonisolated enum NotADatabaseReason: Sendable, Equatable {
        /// A KeePass 1 `.kdb`. KeePassXC reads these only by IMPORTING them, which
        /// is a one-way conversion — and never something SimpleVPN would do to
        /// somebody's file.
        case keePass1Database
        /// The right first signature, the wrong second one: a KDBX 2 pre-release.
        case preReleaseFormat
        /// Not a KeePass file at all.
        case notKeePassAtAll
        /// Too short to hold even a signature.
        case truncated
        /// A directory, a symlink to nothing, a socket — anything but a file.
        case notARegularFile
    }

    var isReadable: Bool { if case .readable = self { true } else { false } }

    var facts: KDBXHeaderFacts? {
        if case .readable(_, let facts) = self { return facts }
        return nil
    }

    /// The path this state is about, when it is about one.
    var path: String? {
        switch self {
        case .notConfigured: nil
        case .missing(let path), .notDownloaded(let path), .tooNew(let path, _),
             .permissionDenied(let path), .readable(let path, _):
            path
        case .notADatabase(let path, _): path
        }
    }
}

// MARK: - Reading it

nonisolated enum KeePassDatabaseFile {

    private static let log = Logger(subsystem: "com.bragi0.SimpleVPN", category: "keepass-file")

    /// KeePassXC `src/format/KeePass2.h`.
    static let signature1: UInt32 = 0x9AA2_D903
    static let signature2: UInt32 = 0xB54B_FB67
    /// KeePass 1 (`.kdb`) and the KDBX 2 pre-release, recognised so each gets its
    /// own sentence instead of "not a KeePass database".
    static let signature2KeePass1: UInt32 = 0xB54B_FB65
    static let signature2PreRelease: UInt32 = 0xB54B_FB66

    /// How much of the file to read. The outer header of a real database is a few
    /// hundred bytes; a `PublicCustomData` field could in principle be larger, so
    /// this is generous — and it is a CEILING, which is the point. A vault is not
    /// something to pull into memory to look at its version number.
    static let headerReadLimit = 128 * 1024

    /// The suffix macOS gives an iCloud Drive file whose contents are not local.
    /// The visible name disappears and a small plist appears beside it, named
    /// `.<original>.icloud`.
    static let iCloudPlaceholderSuffix = ".icloud"

    // MARK: The whole answer for a path

    /// Classify the file at `path`, reading at most `headerReadLimit` bytes of it.
    ///
    /// The order is deliberate: existence, then "is it merely not downloaded", then
    /// shape, then contents. Each earlier answer would otherwise be reported as a
    /// later one, and the later ones all sound like the user's fault.
    static func classify(path rawPath: String,
                         fileManager: FileManager = .default) -> KDBXFileState {
        let path = rawPath.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !path.isEmpty else { return .notConfigured }

        var st = stat()
        if stat(path, &st) != 0 {
            // Not there — but "not there" and "iCloud has it and this Mac doesn't"
            // are completely different problems, and only one of them is worth
            // telling somebody to go and look for their file.
            return hasICloudPlaceholder(for: path, fileManager: fileManager)
                ? .notDownloaded(path: path)
                : .missing(path: path)
        }
        guard (st.st_mode & S_IFMT) == S_IFREG else {
            return .notADatabase(path: path, reason: .notARegularFile)
        }
        // A file provider that hasn't materialised the contents yet. Apple's own
        // providers answer this; a third-party one (Dropbox, OneDrive) generally
        // fetches on first read instead, which is why the read below has a ceiling
        // and the caller has a deadline rather than this being the only guard.
        if isAwaitingDownload(path: path) { return .notDownloaded(path: path) }
        // Asked BEFORE reading, because the two failures look the same from a nil
        // read and mean opposite things. macOS lets any app `stat` a file in a
        // protected folder and refuses to open it, so a database in ~/Documents that
        // has not been consented to would otherwise be reported as an empty one.
        guard access(path, R_OK) == 0 else { return .permissionDenied(path: path) }

        guard let prefix = readPrefix(path: path) else {
            return .notADatabase(path: path, reason: .truncated)
        }
        return classify(headerBytes: prefix, path: path)
    }

    /// The pure half: classify bytes. Every fixture test drives this, so the whole
    /// decision is testable without a filesystem.
    static func classify(headerBytes data: Data, path: String) -> KDBXFileState {
        guard data.count >= 12 else {
            return .notADatabase(path: path, reason: .truncated)
        }
        var cursor = Cursor(data)
        guard let sig1 = cursor.readUInt32(), let sig2 = cursor.readUInt32(),
              let rawVersion = cursor.readUInt32() else {
            return .notADatabase(path: path, reason: .truncated)
        }
        guard sig1 == signature1 else {
            return .notADatabase(path: path, reason: .notKeePassAtAll)
        }
        switch sig2 {
        case signature2:
            break
        case signature2KeePass1:
            return .notADatabase(path: path, reason: .keePass1Database)
        case signature2PreRelease:
            return .notADatabase(path: path, reason: .preReleaseFormat)
        default:
            return .notADatabase(path: path, reason: .notKeePassAtAll)
        }
        let version = KDBXVersion(major: UInt16(rawVersion >> 16),
                                  minor: UInt16(rawVersion & 0xFFFF))
        guard version.isSupported else {
            // A major number BELOW 3 is a format nothing current reads either, and
            // "newer than we can read" would be a lie about it. Both are dead ends
            // for us; only one of them is worth offering an update for.
            return version.major < 3
                ? .notADatabase(path: path, reason: .preReleaseFormat)
                : .tooNew(path: path, version: version)
        }
        var facts = KDBXHeaderFacts(version: version)
        readHeaderFields(&cursor, version: version, into: &facts)
        return .readable(path: path, facts: facts)
    }

    // MARK: Header fields

    /// Walk the outer header, picking up only what we are here for. An unreadable
    /// or truncated header stops the walk and leaves the facts as far as they got —
    /// deliberately, because "a KDBX whose seed we could not find" is still a KDBX
    /// and the only thing it costs is the ability to pre-check a security key.
    private static func readHeaderFields(_ cursor: inout Cursor, version: KDBXVersion,
                                        into facts: inout KDBXHeaderFacts) {
        // KDBX3 field lengths are uint16; KDBX4's are uint32. The only structural
        // difference between the two headers that matters here.
        let lengthIsWide = version.major >= 4
        while true {
            guard let fieldID = cursor.readUInt8() else { return }
            let length: Int?
            if lengthIsWide {
                length = cursor.readUInt32().map(Int.init)
            } else {
                length = cursor.readUInt16().map(Int.init)
            }
            guard let length, let payload = cursor.read(length) else { return }
            switch fieldID {
            case HeaderFieldID.endOfHeader:
                return
            case HeaderFieldID.transformSeed where version.major == 3:
                // KDBX3: the transform seed IS `kdf.seed()`.
                facts.kdfSeed = payload
                facts.keyDerivation = .aesKDF
            case HeaderFieldID.kdfParameters where version.major >= 4:
                if let parameters = VariantDictionary.parse(payload) {
                    facts.kdfSeed = parameters["S"]
                    facts.keyDerivation = keyDerivation(uuid: parameters["$UUID"])
                }
            default:
                continue
            }
        }
    }

    /// KeePassXC `src/format/KeePass2.h`, `HeaderFieldID`.
    nonisolated enum HeaderFieldID {
        static let endOfHeader: UInt8 = 0
        static let transformSeed: UInt8 = 5
        static let kdfParameters: UInt8 = 11
    }

    /// The four KDF UUIDs from `src/format/KeePass2.cpp`, as their raw 16 bytes.
    /// Compared as bytes rather than reformatted into a string: a UUID in a KDBX
    /// header is a byte array, and round-tripping it through text is one more place
    /// to get an endianness wrong.
    static func keyDerivation(uuid: Data?) -> KDBXKeyDerivation {
        guard let uuid, uuid.count == 16 else { return .unrecognised }
        let hex = uuid.map { String(format: "%02x", $0) }.joined()
        switch hex {
        // c9d9f39a-628a-4460-bf74-0d08c18a4fea — AES-KDF as KDBX3 wrote it, still
        // selectable in KDBX4.
        case "c9d9f39a628a4460bf740d08c18a4fea": return .aesKDF
        // 7c02bb82-79a7-4ac0-927d-114a00648238 — AES-KDF, KDBX4's own UUID.
        case "7c02bb8279a74ac0927d114a00648238": return .aesKDF
        // ef636ddf-8c29-444b-91f7-a9a403e30a0c
        case "ef636ddf8c29444b91f7a9a403e30a0c": return .argon2d
        // 9e298b19-56db-4773-b23d-fc3ec6f0a1e6
        case "9e298b1956db4773b23dfc3ec6f0a1e6": return .argon2id
        default: return .unrecognised
        }
    }

    // MARK: Bytes off disk

    /// A bounded prefix of the file. `FileHandle` rather than `Data(contentsOf:)`
    /// so a hundred-megabyte vault costs a hundred kilobytes of reading.
    static func readPrefix(path: String, limit: Int = headerReadLimit) -> Data? {
        guard let handle = FileHandle(forReadingAtPath: path) else { return nil }
        defer { try? handle.close() }
        guard let data = try? handle.read(upToCount: limit), !data.isEmpty else { return nil }
        return data
    }

    // MARK: File-provider placeholders

    /// Is there a `.name.icloud` placeholder where the file should be? That is
    /// exactly what iCloud Drive leaves behind for a file whose contents are not on
    /// this Mac, and it is the difference between "your database is gone" and
    /// "your database is on its way".
    static func hasICloudPlaceholder(for path: String,
                                    fileManager: FileManager = .default) -> Bool {
        let directory = (path as NSString).deletingLastPathComponent
        let name = (path as NSString).lastPathComponent
        guard !name.isEmpty else { return false }
        let placeholder = (directory as NSString)
            .appendingPathComponent(".\(name)\(iCloudPlaceholderSuffix)")
        return fileManager.fileExists(atPath: placeholder)
    }

    /// The file is there, and its contents are not. Apple's file providers report
    /// this through `ubiquitousItemDownloadingStatusKey`; a `nil` answer means the
    /// item is not in a provider we can ask, which is the common case and is not a
    /// problem.
    static func isAwaitingDownload(path: String) -> Bool {
        let url = URL(fileURLWithPath: path)
        guard let values = try? url.resourceValues(
            forKeys: [.isUbiquitousItemKey, .ubiquitousItemDownloadingStatusKey]),
              values.isUbiquitousItem == true else { return false }
        guard let status = values.ubiquitousItemDownloadingStatus else { return false }
        return status == .notDownloaded
    }

    // MARK: A cursor, because hand-rolled offsets are where parsers go wrong

    /// Bounds-checked little-endian reads over a `Data`. Every read answers nil
    /// rather than trapping: this parses a file somebody else wrote, and a
    /// truncated header must be a sentence on screen, not a crash.
    nonisolated struct Cursor {
        private let bytes: [UInt8]
        private(set) var offset = 0

        init(_ data: Data) { self.bytes = Array(data) }

        var remaining: Int { bytes.count - offset }

        mutating func read(_ count: Int) -> Data? {
            guard count >= 0, remaining >= count else { return nil }
            defer { offset += count }
            return Data(bytes[offset..<(offset + count)])
        }

        mutating func readUInt8() -> UInt8? {
            guard remaining >= 1 else { return nil }
            defer { offset += 1 }
            return bytes[offset]
        }

        mutating func readUInt16() -> UInt16? {
            guard remaining >= 2 else { return nil }
            defer { offset += 2 }
            return UInt16(bytes[offset]) | (UInt16(bytes[offset + 1]) << 8)
        }

        mutating func readUInt32() -> UInt32? {
            guard remaining >= 4 else { return nil }
            defer { offset += 4 }
            var value: UInt32 = 0
            for index in 0..<4 { value |= UInt32(bytes[offset + index]) << (8 * index) }
            return value
        }
    }

    // MARK: KDBX4's VariantDictionary

    /// The KDBX4 KDF-parameter dictionary. Parsed TYPE-AGNOSTICALLY on purpose:
    /// the only entry this app wants is `"S"` (the seed) and `"$UUID"` (which KDF),
    /// both of which are byte arrays, so decoding the integer and string types
    /// would be work in exchange for more ways to be wrong. Values come back as
    /// raw bytes and the caller interprets the ones it knows.
    nonisolated enum VariantDictionary {
        /// KeePassXC masks the version with `VARIANTMAP_CRITICAL_MASK` (0xFF00) and
        /// refuses a major it doesn't know. We only READ two known keys, so a newer
        /// minor is harmless; a newer MAJOR means the layout could have changed
        /// underneath us and we stop rather than guess.
        static let supportedMajorVersion: UInt16 = 0x0100

        static func parse(_ data: Data) -> [String: Data]? {
            var cursor = Cursor(data)
            guard let version = cursor.readUInt16() else { return nil }
            guard (version & 0xFF00) <= supportedMajorVersion else { return nil }
            var out: [String: Data] = [:]
            while true {
                guard let type = cursor.readUInt8() else { return out }
                if type == 0 { return out }                        // End
                guard let nameLength = cursor.readUInt32(),
                      let nameBytes = cursor.read(Int(nameLength)),
                      let valueLength = cursor.readUInt32(),
                      let value = cursor.read(Int(valueLength)) else { return out }
                out[String(decoding: nameBytes, as: UTF8.self)] = value
            }
        }
    }
}
