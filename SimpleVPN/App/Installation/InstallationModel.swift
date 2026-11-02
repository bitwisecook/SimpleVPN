// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only

import Foundation
import Security
import Darwin

/// Compiled into both the app and its installer. No VPN state is created by this code.
nonisolated enum Installation {
    static let appID = "com.bragi0.SimpleVPN"
    static let helperID = appID + ".Installer"
    static let helperPath = "Contents/Helpers/SimpleVPNInstaller.app"
    static let sessionPrefix = "SimpleVPN-install-"
    static let applications = URL(fileURLWithPath: "/Applications", isDirectory: true)
    static var userApplications: URL { FileManager.default.homeDirectoryForCurrentUser.appending(path: "Applications") }

    struct Version: Comparable, Sendable {
        let version: [UInt64]
        let build: [UInt64]

        init?(_ version: String, _ build: String) {
            func components(_ string: String) -> [UInt64]? {
                let parts = string.split(separator: ".", omittingEmptySubsequences: false)
                guard !parts.isEmpty else { return nil }
                var result: [UInt64] = []
                for part in parts {
                    guard !part.isEmpty, part.allSatisfy({ $0.isASCII && $0.isNumber }),
                          let number = UInt64(part) else { return nil }
                    result.append(number)
                }
                while result.last == 0 && result.count > 1 { result.removeLast() }
                return result
            }
            guard let v = components(version), let b = components(build) else { return nil }
            self.version = v; self.build = b
        }

        static func < (lhs: Self, rhs: Self) -> Bool {
            func compare(_ a: [UInt64], _ b: [UInt64]) -> ComparisonResult {
                for i in 0..<max(a.count, b.count) {
                    let left = i < a.count ? a[i] : 0, right = i < b.count ? b[i] : 0
                    if left != right { return left < right ? .orderedAscending : .orderedDescending }
                }
                return .orderedSame
            }
            let result = compare(lhs.version, rhs.version)
            return (result == .orderedSame ? compare(lhs.build, rhs.build) : result) == .orderedAscending
        }
    }

    struct AppInfo: Equatable, Sendable {
        let identifier: String
        let version: String
        let build: String
        var comparable: Version? { Version(version, build) }
        var description: String { "\(version) (build \(build))" }

        init(at url: URL) throws {
            let data = try Data(contentsOf: url.appending(path: "Contents/Info.plist"))
            guard let info = try PropertyListSerialization.propertyList(from: data, format: nil) as? [String: Any],
                  let id = info["CFBundleIdentifier"] as? String,
                  let version = info["CFBundleShortVersionString"] as? String,
                  let build = info["CFBundleVersion"] as? String else { throw Failure.invalidApp }
            self.identifier = id; self.version = version; self.build = build
        }
    }

    enum Action: String, Sendable {
        case install = "Install", upgrade = "Upgrade", reinstall = "Reinstall", downgrade = "Downgrade"

        static func choose(incoming: Version, installed: Version?) -> Self {
            guard let installed else { return .install }
            if incoming == installed { return .reinstall }
            return incoming > installed ? .upgrade : .downgrade
        }
    }

    /// Includes inode and metadata so another installer cannot silently change our target.
    struct Snapshot: Equatable, Sendable {
        let inode: UInt64
        let device: UInt64
        let modified: Date?
        let info: Data?

        init(at url: URL) throws {
            let attributes = try FileManager.default.attributesOfItem(atPath: url.path)
            guard attributes[.type] as? FileAttributeType == .typeDirectory else { throw Failure.destinationChanged }
            inode = (attributes[.systemFileNumber] as? NSNumber)?.uint64Value ?? 0
            device = (attributes[.systemNumber] as? NSNumber)?.uint64Value ?? 0
            modified = attributes[.modificationDate] as? Date
            info = try? Data(contentsOf: url.appending(path: "Contents/Info.plist"))
        }
    }

    struct DiskImage: Codable, Equatable, Sendable {
        let volume: URL
        let file: URL
    }

    struct Request: Codable, Sendable {
        let source: URL
        let image: DiskImage?
        let parentPID: Int32
        let parentLaunch: Date?
    }

    enum Failure: LocalizedError {
        case invalidApp, invalidSignature, destinationChanged, runningApp, parentRunning, invalidSession, commandFailed
        case rollback(URL)
        var errorDescription: String? {
            switch self {
            case .invalidApp: "SimpleVPN’s version information could not be read."
            case .invalidSignature: "SimpleVPN’s signature could not be verified. Download a fresh copy and try again."
            case .destinationChanged: "The app at the installation location changed. It has not been replaced. Open the installer again."
            case .runningApp: "SimpleVPN is still running. Finish quitting it before installing."
            case .parentRunning: "The copy of SimpleVPN you opened did not quit. Quit it and open the installer again."
            case .invalidSession: "The installer could not start safely. Open SimpleVPN from the disk image again."
            case .commandFailed: "The disk image could not be checked or ejected."
            case .rollback(let backup): "The installation could not be completed. Your previous app is preserved at \(backup.path). Move it back to Applications in Finder."
            }
        }
    }

    static func canonical(_ url: URL) -> String { url.resolvingSymlinksInPath().standardizedFileURL.path }

    static func isInstalled(_ url: URL, folders: [URL] = [applications, userApplications]) -> Bool {
        let parent = canonical(url.deletingLastPathComponent())
        return folders.contains { canonical($0) == parent }
    }

    /// Check both conventional names AND renamed bundles, without Launch Services choosing a DMG copy.
    static func installedCopies(in folders: [URL] = [applications, userApplications]) -> [URL] {
        let manager = FileManager.default
        return folders.flatMap { folder in
            let contents = (try? manager.contentsOfDirectory(at: folder, includingPropertiesForKeys: nil)) ?? []
            return contents.filter { url in
                guard url.pathExtension == "app",
                      (try? url.resourceValues(forKeys: [.isSymbolicLinkKey]).isSymbolicLink) != true else { return false }
                return (try? AppInfo(at: url).identifier) == appID
            }.sorted { $0.lastPathComponent < $1.lastPathComponent }
        }
    }

    static func diskImages(in data: Data) throws -> [DiskImage] {
        guard let plist = try PropertyListSerialization.propertyList(from: data, format: nil) as? [String: Any],
              let images = plist["images"] as? [[String: Any]] else { throw Failure.commandFailed }
        return images.flatMap { image -> [DiskImage] in
            guard let path = image["image-path"] as? String,
                  URL(fileURLWithPath: path).pathExtension.lowercased() == "dmg",
                  let entities = image["system-entities"] as? [[String: Any]] else { return [] }
            return entities.compactMap { entity in
                guard let mount = entity["mount-point"] as? String else { return nil }
                return DiskImage(volume: URL(fileURLWithPath: mount, isDirectory: true), file: URL(fileURLWithPath: path))
            }
        }
    }

    static func verify(_ url: URL, identifier: String = appID) throws {
        var code: SecStaticCode?
        var requirement: SecRequirement?
        // A valid signature by another developer (or an ad-hoc signature) is insufficient.
        let text = "anchor apple generic and identifier \"\(identifier)\" and certificate leaf[subject.OU] = \"QVUFB5676H\""
        guard SecRequirementCreateWithString(text as CFString, [], &requirement) == errSecSuccess,
              let requirement,
              SecStaticCodeCreateWithPath(url as CFURL, [], &code) == errSecSuccess, let code,
              SecStaticCodeCheckValidity(code, SecCSFlags(rawValue: kSecCSStrictValidate | kSecCSCheckNestedCode), requirement) == errSecSuccess
        else { throw Failure.invalidSignature }
    }

    /// The lock file stays in place: unlinking a held flock permits two independent lock owners.
    final class Lease {
        private let descriptor: Int32
        init?(at url: URL) throws {
            let fd = Darwin.open(url.path, O_CREAT | O_RDWR | O_NOFOLLOW | O_CLOEXEC, S_IRUSR | S_IWUSR)
            guard fd >= 0 else { throw Failure.invalidSession }
            var attributes = stat()
            guard fstat(fd, &attributes) == 0, attributes.st_uid == getuid(),
                  attributes.st_mode & S_IFMT == S_IFREG, attributes.st_nlink == 1 else {
                close(fd); throw Failure.invalidSession
            }
            guard flock(fd, LOCK_EX | LOCK_NB) == 0 else {
                let failure = errno
                close(fd)
                if failure == EWOULDBLOCK { return nil }
                throw Failure.invalidSession
            }
            descriptor = fd
        }
        deinit { close(descriptor) }
    }
}
