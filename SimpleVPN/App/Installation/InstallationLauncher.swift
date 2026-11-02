// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only

import AppKit

/// Runs before SwiftUI initializes stores, Sparkle, the control socket, or the tunnel manager.
@MainActor
enum InstallationLauncher {
    static func handleLaunch() -> Bool {
        let environment = ProcessInfo.processInfo.environment
        guard environment["XCTestConfigurationFilePath"] == nil, environment["XCTestBundlePath"] == nil else { return false }
        let source = Bundle.main.bundleURL.resolvingSymlinksInPath()
        if Installation.isInstalled(source) {
            // An installed copy opened during replacement must never initialize the VPN session.
            let lock = FileManager.default.temporaryDirectory.appending(path: "SimpleVPN-installer.lock")
            if let probe = try? Installation.Lease(at: lock) { withExtendedLifetime(probe) {}; return false }
            NSRunningApplication.runningApplications(withBundleIdentifier: Installation.helperID).first?.activate()
            return true
        }
        let translocated = source.path.contains("/AppTranslocation/")
        let volume = try? source.resourceValues(forKeys: [.volumeURLKey, .volumeIsReadOnlyKey])
        #if DEBUG
        // Ordinary Xcode/test builds remain runnable from DerivedData.
        guard translocated || volume?.volumeIsReadOnly == true else { return false }
        #endif
        NSApplication.shared.setActivationPolicy(.accessory)
        Task {
            do {
                let images = try await InstallationWorker.inventory()
                var original = source
                var image = images.first { Installation.canonical($0.volume) == volume?.volume.map(Installation.canonical) }
                if translocated {
                    // Public APIs only. A translocated DMG copy is matched to a unique mounted,
                    // signed bundle with identical metadata. Never guess a path in Downloads.
                    let info = try Installation.AppInfo(at: source)
                    let candidates = images.compactMap { mounted -> (URL, Installation.DiskImage)? in
                        let candidate = mounted.volume.appending(path: "SimpleVPN.app")
                        guard (try? Installation.AppInfo(at: candidate)) == info,
                              (try? Installation.verify(candidate)) != nil else { return nil }
                        return (candidate, mounted)
                    }
                    guard candidates.count == 1, let match = candidates.first else { throw Installation.Failure.invalidSession }
                    original = match.0; image = match.1
                }
                let request = Installation.Request(source: original, image: image,
                    parentPID: ProcessInfo.processInfo.processIdentifier,
                    parentLaunch: NSRunningApplication.current.launchDate)
                let helper = try await stage(request, bundledHelper: source.appending(path: Installation.helperPath))
                let configuration = NSWorkspace.OpenConfiguration()
                configuration.activates = false
                configuration.addsToRecentItems = false
                configuration.createsNewApplicationInstance = true
                do { _ = try await NSWorkspace.shared.openApplication(at: helper, configuration: configuration) }
                catch { try? FileManager.default.removeItem(at: helper.deletingLastPathComponent()); throw error }
            } catch {
                NSApplication.shared.setActivationPolicy(.regular)
                NSApplication.shared.activate()
                let alert = NSAlert()
                alert.messageText = "SimpleVPN Could Not Start the Installer"
                alert.informativeText = error.localizedDescription + "\n\nYou can also drag SimpleVPN.app to Applications in Finder."
                alert.addButton(withTitle: "Quit")
                alert.runModal()
            }
            // No app delegate/VPN session exists here. The helper waits for this exact process.
            NSApplication.shared.terminate(nil)
        }
        NSApplication.shared.run()
        return true
    }

    @concurrent private static func stage(_ request: Installation.Request, bundledHelper: URL) async throws -> URL {
        try Installation.verify(request.source)
        try Installation.verify(bundledHelper, identifier: Installation.helperID)
        let manager = FileManager.default
        let root = manager.temporaryDirectory.appending(path: Installation.sessionPrefix + UUID().uuidString, directoryHint: .isDirectory)
        try manager.createDirectory(at: root, withIntermediateDirectories: false, attributes: [.posixPermissions: 0o700])
        do {
            let helper = root.appending(path: "SimpleVPNInstaller.app")
            try manager.copyItem(at: bundledHelper, to: helper)
            try Installation.verify(helper, identifier: Installation.helperID)
            let data = try PropertyListEncoder().encode(request)
            try data.write(to: root.appending(path: "request.plist"), options: .atomic)
            return helper
        } catch { try? manager.removeItem(at: root); throw error }
    }
}

@main
@MainActor
enum SimpleVPNLauncher {
    static func main() {
        guard !InstallationLauncher.handleLaunch() else { return }
        SimpleVPNApp.main()
    }
}
