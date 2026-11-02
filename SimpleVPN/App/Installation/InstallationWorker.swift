// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only

import Foundation

nonisolated enum InstallationWorker {
    /// Run blocking file work off the main actor; the helper keeps its event loop responsive.
    @concurrent static func inventory() async throws -> [Installation.DiskImage] {
        try Installation.diskImages(in: command("/usr/bin/hdiutil", ["info", "-plist"]))
    }

    static func command(_ executable: String, _ arguments: [String], timeout: TimeInterval = 30) throws -> Data {
        let output = FileManager.default.temporaryDirectory.appending(path: UUID().uuidString)
        guard FileManager.default.createFile(atPath: output.path, contents: nil, attributes: [.posixPermissions: 0o600]) else {
            throw Installation.Failure.commandFailed
        }
        defer { try? FileManager.default.removeItem(at: output) }
        let handle = try FileHandle(forWritingTo: output)
        defer { try? handle.close() }
        let process = Process()
        process.executableURL = URL(fileURLWithPath: executable)
        process.arguments = arguments
        process.currentDirectoryURL = FileManager.default.temporaryDirectory
        process.standardInput = FileHandle.nullDevice
        process.standardOutput = handle
        process.standardError = FileHandle.nullDevice
        try process.run()
        let deadline = Date().addingTimeInterval(timeout)
        while process.isRunning && Date() < deadline { Thread.sleep(forTimeInterval: 0.05) }
        if process.isRunning { process.terminate(); throw Installation.Failure.commandFailed }
        process.waitUntilExit()
        guard process.terminationStatus == 0 else { throw Installation.Failure.commandFailed }
        return try Data(contentsOf: output)
    }

    /// Stage beside the destination so the final moves stay on one filesystem. Preserve a rollback
    /// bundle until the installed copy verifies. An old app goes to Trash only after success.
    static func replace(source: URL, destination: URL, expected: Installation.Snapshot?,
                        expectedSource: Installation.AppInfo? = nil,
                        validate: (URL) throws -> Void = { try Installation.verify($0) },
                        retire: (URL) throws -> Void = { try FileManager.default.trashItem(at: $0, resultingItemURL: nil) },
                        canReplace: () -> Bool) throws -> URL? {
        let manager = FileManager.default
        try validate(source)
        let incoming = try Installation.AppInfo(at: source)
        guard expectedSource == nil || expectedSource == incoming else { throw Installation.Failure.destinationChanged }
        let folder = destination.deletingLastPathComponent()
        try manager.createDirectory(at: folder, withIntermediateDirectories: true)
        let work = folder.appending(path: ".SimpleVPN-install-\(UUID().uuidString)", directoryHint: .isDirectory)
        try manager.createDirectory(at: work, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
        var preserveWork = false
        defer { if !preserveWork { try? manager.removeItem(at: work) } }
        let candidate = work.appending(path: "SimpleVPN.app")
        let backup = work.appending(path: "Previous SimpleVPN.app")
        try manager.copyItem(at: source, to: candidate)
        try validate(candidate)
        guard try Installation.AppInfo(at: candidate) == incoming else { throw Installation.Failure.invalidApp }
        guard canReplace() else { throw Installation.Failure.runningApp }
        let exists = manager.fileExists(atPath: destination.path)
        guard exists == (expected != nil), try !exists || Installation.Snapshot(at: destination) == expected else {
            throw Installation.Failure.destinationChanged
        }
        if exists { try manager.moveItem(at: destination, to: backup) }
        do {
            try manager.moveItem(at: candidate, to: destination)
            try validate(destination)
        } catch {
            // Keep the failed candidate for this scope only; never delete the only good old bundle.
            do {
                if manager.fileExists(atPath: destination.path) { try manager.moveItem(at: destination, to: candidate) }
                if exists { try manager.moveItem(at: backup, to: destination) }
            } catch {
                preserveWork = true
                throw Installation.Failure.rollback(backup)
            }
            throw error
        }
        guard exists else { return nil }
        do { try retire(backup); return nil }
        catch {
            preserveWork = true
            return backup // Installation succeeded; report the retained old app separately.
        }
    }

    @concurrent static func install(source: URL, destination: URL, expected: Installation.Snapshot?, incoming: Installation.AppInfo) async throws -> URL? {
        try replace(source: source, destination: destination, expected: expected, expectedSource: incoming, canReplace: {
            // Process inspection is a public, thread-safe workspace operation (no UI here).
            !InstallationRunningApps.hasCopy(at: destination)
        })
    }

    @concurrent static func eject(_ image: Installation.DiskImage) async throws {
        let current = try Installation.diskImages(in: command("/usr/bin/hdiutil", ["info", "-plist"]))
        guard current.contains(image) else { return } // Already ejected by the user.
        _ = try command("/usr/bin/hdiutil", ["detach", image.volume.path], timeout: 20)
    }
}
