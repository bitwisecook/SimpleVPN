// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only

import Foundation
import Testing
#if INSTALLATION_STANDALONE
@testable import InstallationSupport
#else
@testable import SimpleVPN
#endif

struct InstallationTests {
    @Test func versionsCompareNumericallyIncludingBuilds() throws {
        let version = Installation.Version.init
        #expect(try #require(version("1.9", "999")) < #require(version("1.10", "1")))
        #expect(try #require(version("1.0", "9")) < #require(version("1", "10")))
        #expect(version("1.0.0", "3.0") == version("1", "3"))
        for invalid in ["", "1..2", "1beta", "-1", "18446744073709551616", "١"] {
            #expect(version(invalid, "1") == nil)
        }
    }

    @Test func actionsIncludeReinstallAndExplicitDowngrade() throws {
        let old = try #require(Installation.Version("0.5", "400"))
        let new = try #require(Installation.Version("0.5", "411"))
        #expect(Installation.Action.choose(incoming: new, installed: nil) == .install)
        #expect(Installation.Action.choose(incoming: new, installed: old) == .upgrade)
        #expect(Installation.Action.choose(incoming: new, installed: new) == .reinstall)
        #expect(Installation.Action.choose(incoming: old, installed: new) == .downgrade)
    }

    @Test func discoveryFindsRenamedAppsInBothLocationsAndIgnoresImpostors() throws {
        try withDirectory { root in
            let local = root.appending(path: "Applications"), user = root.appending(path: "Home/Applications")
            let first = local.appending(path: "SimpleVPN Renamed.app"), second = user.appending(path: "SimpleVPN.app")
            try app(at: first, build: "1"); try app(at: second, build: "2")
            try app(at: local.appending(path: "Other.app"), build: "3", identifier: "other.app")
            let copies = Installation.installedCopies(in: [local, user])
            #expect(copies.map(Installation.canonical) == [first, second].map(Installation.canonical))
            #expect(Installation.isInstalled(second, folders: [local, user]))
            #expect(!Installation.isInstalled(root.appending(path: "ApplicationsElsewhere/SimpleVPN.app"), folders: [local, user]))
        }
    }

    @Test func imageInventoryMatchesExactMountAndBackingFile() throws {
        let data = try PropertyListSerialization.data(fromPropertyList: ["images": [
            ["image-path": "/Downloads/SimpleVPN.DMG", "system-entities": [["mount-point": "/Volumes/SimpleVPN"], ["dev-entry": "/dev/disk9"]]],
            ["image-path": "/Downloads/Other.sparseimage", "system-entities": [["mount-point": "/Volumes/Other"]]]
        ]], format: .xml, options: 0)
        let images = try Installation.diskImages(in: data)
        #expect(images.count == 1)
        #expect(images.first?.volume.path == "/Volumes/SimpleVPN")
        #expect(images.first?.file.path == "/Downloads/SimpleVPN.DMG")
    }

    @Test func failedCandidateVerificationLeavesOldBundleAlone() throws {
        try withApps { (source: URL, destination: URL) throws in
            let expected = try Installation.Snapshot(at: destination)
            #expect(throws: TestFailure.self) {
                try InstallationWorker.replace(source: source, destination: destination, expected: expected,
                    validate: { if $0 != source { throw TestFailure.injected } }, canReplace: { true })
            }
            #expect(try Installation.AppInfo(at: destination).build == "1")
            #expect(try Installation.Snapshot(at: destination) == expected)
        }
    }

    @Test func failedFinalVerificationRollsBackOldBundle() throws {
        try withApps { (source: URL, destination: URL) throws in
            #expect(throws: TestFailure.self) {
                try InstallationWorker.replace(source: source, destination: destination, expected: Installation.Snapshot(at: destination),
                    validate: { if $0 == destination { throw TestFailure.injected } }, canReplace: { true })
            }
            #expect(try Installation.AppInfo(at: destination).build == "1")
        }
    }

    @Test func runningAppOrChangedDestinationPreventsReplacement() throws {
        try withApps { (source: URL, destination: URL) throws in
            let expected = try Installation.Snapshot(at: destination)
            #expect(throws: Installation.Failure.self) {
                try InstallationWorker.replace(source: source, destination: destination, expected: expected, validate: { _ in }, canReplace: { false })
            }
            try app(at: destination, build: "9")
            #expect(throws: Installation.Failure.self) {
                try InstallationWorker.replace(source: source, destination: destination, expected: expected, validate: { _ in }, canReplace: { true })
            }
            #expect(try Installation.AppInfo(at: destination).build == "9")
        }
    }

    @Test func successRetiresOldAppOnlyAfterNewAppIsVerified() throws {
        try withApps { (source: URL, destination: URL) throws in
            var retired = false
            let backup = try InstallationWorker.replace(source: source, destination: destination,
                expected: Installation.Snapshot(at: destination), validate: { _ in }, retire: { old in
                    #expect(try Installation.AppInfo(at: destination).build == "2")
                    #expect(try Installation.AppInfo(at: old).build == "1")
                    retired = true
                    try FileManager.default.removeItem(at: old)
                }, canReplace: { true })
            #expect(retired); #expect(backup == nil)
            #expect(try Installation.AppInfo(at: source).build == "2")
        }
    }

    @Test func trashFailurePreservesPreviousBundleAndReportsItsPath() throws {
        try withApps { (source: URL, destination: URL) throws in
            let backup = try InstallationWorker.replace(source: source, destination: destination,
                expected: Installation.Snapshot(at: destination), validate: { _ in },
                retire: { _ in throw TestFailure.injected }, canReplace: { true })
            #expect(try Installation.AppInfo(at: #require(backup)).build == "1")
            #expect(try Installation.AppInfo(at: destination).build == "2")
        }
    }

    @Test func freshInstallDoesNotRetireAnythingOrOverwriteAnUnexpectedApp() throws {
        try withDirectory { root in
            let source = root.appending(path: "Source.app"), destination = root.appending(path: "Applications/SimpleVPN.app")
            try app(at: source, build: "2")
            let backup = try InstallationWorker.replace(source: source, destination: destination, expected: nil,
                validate: { _ in }, retire: { _ in Issue.record("A fresh install must not retire a bundle") }, canReplace: { true })
            #expect(backup == nil)
            #expect(try Installation.AppInfo(at: destination).build == "2")
            #expect(throws: Installation.Failure.self) {
                try InstallationWorker.replace(source: source, destination: destination, expected: nil,
                    validate: { _ in }, canReplace: { true })
            }
            #expect(try Installation.AppInfo(at: destination).build == "2")
        }
    }

    @Test func sourceChangedAfterConsentCannotInstallAnotherVersion() throws {
        try withApps { (source: URL, destination: URL) throws in
            let incoming = try Installation.AppInfo(at: source)
            try app(at: source, build: "3")
            #expect(throws: Installation.Failure.self) {
                try InstallationWorker.replace(source: source, destination: destination,
                    expected: Installation.Snapshot(at: destination), expectedSource: incoming,
                    validate: { _ in }, canReplace: { true })
            }
            #expect(try Installation.AppInfo(at: destination).build == "1")
        }
    }

    @Test func leaseExcludesSecondHelperAndBecomesAvailableAfterExit() throws {
        try withDirectory { root in
            let lock = root.appending(path: "installer.lock")
            do {
                let lease = try #require(try Installation.Lease(at: lock))
                #expect(try Installation.Lease(at: lock) == nil)
                withExtendedLifetime(lease) {}
            }
            #expect(try Installation.Lease(at: lock) != nil)
            #expect(FileManager.default.fileExists(atPath: lock.path))
        }
    }

    private enum TestFailure: Error { case injected }

    private func withDirectory(_ body: (URL) throws -> Void) throws {
        let root = FileManager.default.temporaryDirectory.appending(path: "SimpleVPN-install-test-" + UUID().uuidString)
        try FileManager.default.createDirectory(at: root, withIntermediateDirectories: false)
        defer { try? FileManager.default.removeItem(at: root) }
        try body(root)
    }

    private func withApps(_ body: (URL, URL) throws -> Void) throws {
        try withDirectory { root in
            let source = root.appending(path: "Source/SimpleVPN.app"), destination = root.appending(path: "Applications/SimpleVPN.app")
            try app(at: source, build: "2"); try app(at: destination, build: "1")
            try body(source, destination)
        }
    }

    private func app(at url: URL, build: String, identifier: String = Installation.appID) throws {
        try FileManager.default.createDirectory(at: url.appending(path: "Contents"), withIntermediateDirectories: true)
        let data = try PropertyListSerialization.data(fromPropertyList: ["CFBundleIdentifier": identifier,
            "CFBundleShortVersionString": "0.5", "CFBundleVersion": build], format: .xml, options: 0)
        try data.write(to: url.appending(path: "Contents/Info.plist"))
    }
}
