// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only

import AppKit

@main
@MainActor
enum InstallerApp {
    static func main() {
        let application = NSApplication.shared
        let delegate = InstallerDelegate()
        application.delegate = delegate
        // LSUIElement also prevents a Dock tile before main() is entered.
        application.setActivationPolicy(.accessory)
        withExtendedLifetime(delegate) { application.run() }
    }
}

@MainActor
final class InstallerDelegate: NSObject, NSApplicationDelegate {
    private var root: URL?
    private var lease: Installation.Lease?
    private var installing = false
    private var cancelled = false

    func applicationDidFinishLaunching(_ notification: Notification) {
        Task {
            do {
                let request = try readRequest()
                let lock = FileManager.default.temporaryDirectory.appending(path: "SimpleVPN-installer.lock")
                guard let lease = try Installation.Lease(at: lock) else {
                    NSRunningApplication.runningApplications(withBundleIdentifier: Installation.helperID)
                        .first { $0.processIdentifier != ProcessInfo.processInfo.processIdentifier }?.activate()
                    finish()
                    return
                }
                self.lease = lease
                try await waitForParent(request)
                removeAbandonedSessions()
                // Only the staged helper owns a Dock tile, and only after the launcher is gone.
                NSApp.setActivationPolicy(.regular)
                NSApp.activate()
                installMenu()
                try await run(request)
            } catch { notice("SimpleVPN Was Not Installed", error.localizedDescription) }
            finish()
        }
    }

    private func readRequest() throws -> Installation.Request {
        let manager = FileManager.default
        let session = Bundle.main.bundleURL.deletingLastPathComponent().resolvingSymlinksInPath()
        guard session.lastPathComponent.hasPrefix(Installation.sessionPrefix),
              Installation.canonical(session.deletingLastPathComponent()) == Installation.canonical(manager.temporaryDirectory),
              let attributes = try? manager.attributesOfItem(atPath: session.path),
              (attributes[.ownerAccountID] as? NSNumber)?.uint32Value == getuid(),
              (attributes[.posixPermissions] as? NSNumber)?.intValue == 0o700 else { throw Installation.Failure.invalidSession }
        root = session // Only a validated, private session may be removed at termination.
        let request = try PropertyListDecoder().decode(Installation.Request.self, from: Data(contentsOf: session.appending(path: "request.plist")))
        guard request.parentPID > 1, request.parentPID != ProcessInfo.processInfo.processIdentifier,
              !Installation.isInstalled(request.source) else { throw Installation.Failure.invalidSession }
        return request
    }

    private func waitForParent(_ request: Installation.Request) async throws {
        guard let parent = NSRunningApplication(processIdentifier: request.parentPID) else { return }
        // PID reuse must never cause an unrelated app to be waited on or terminated.
        guard parent.bundleIdentifier == Installation.appID, parent.launchDate == request.parentLaunch else { return }
        let deadline = Date().addingTimeInterval(30)
        while !parent.isTerminated && Date() < deadline { try await Task.sleep(for: .milliseconds(50)) }
        guard parent.isTerminated else { throw Installation.Failure.parentRunning }
    }

    private func installMenu() {
        let menu = NSMenu()
        let item = NSMenuItem()
        let app = NSMenu()
        app.addItem(withTitle: "Quit SimpleVPN Installer", action: #selector(NSApplication.terminate(_:)), keyEquivalent: "q")
        item.submenu = app; menu.addItem(item); NSApp.mainMenu = menu
    }

    private func run(_ request: Installation.Request) async throws {
        try await verifySource(request.source)
        let incoming = try Installation.AppInfo(at: request.source)
        guard let version = incoming.comparable else { throw Installation.Failure.invalidApp }
        let copies = Installation.installedCopies()
        let destination: URL
        if copies.count > 1 {
            let picker = NSAlert()
            picker.messageText = "Choose Which SimpleVPN to Replace"
            picker.informativeText = "More than one installed copy was found. Choose the copy to install over."
            let choices = NSPopUpButton(frame: NSRect(x: 0, y: 0, width: 430, height: 28))
            choices.addItems(withTitles: copies.map(\.path))
            picker.accessoryView = choices
            picker.addButton(withTitle: "Continue"); picker.addButton(withTitle: "Quit").keyEquivalent = "\u{1b}"
            guard picker.runModal() == .alertFirstButtonReturn else { return }
            destination = copies[choices.indexOfSelectedItem]
        } else {
            let folder = FileManager.default.isWritableFile(atPath: Installation.applications.path)
                ? Installation.applications : Installation.userApplications
            destination = copies.first ?? folder.appending(path: "SimpleVPN.app")
        }
        let exists = FileManager.default.fileExists(atPath: destination.path)
        let expected = exists ? try Installation.Snapshot(at: destination) : nil
        let installed = exists ? try Installation.AppInfo(at: destination) : nil
        guard installed == nil || installed?.identifier == Installation.appID else { throw Installation.Failure.destinationChanged }
        let action = Installation.Action.choose(incoming: version, installed: installed?.comparable)
        let alert = NSAlert()
        alert.messageText = "\(action.rawValue) SimpleVPN?"
        alert.informativeText = "\(action.rawValue) SimpleVPN \(incoming.description) at:\n\(destination.path)"
        if let installed { alert.informativeText += "\n\nInstalled version: \(installed.description)." }
        if action == .downgrade {
            alert.alertStyle = .warning
            alert.informativeText += "\n\nThis is an older version. Settings created by the newer app may not be supported."
        }
        let trash = NSButton(checkboxWithTitle: request.image == nil
            ? "Move the original app to Trash after installation"
            : "Move the disk image to Trash after installation", target: nil, action: nil)
        trash.state = .on
        alert.accessoryView = trash
        let proceed = alert.addButton(withTitle: action.rawValue)
        let quit = alert.addButton(withTitle: "Quit")
        quit.keyEquivalent = "\u{1b}"
        if action == .downgrade { proceed.keyEquivalent = ""; quit.keyEquivalent = "\r" }
        guard alert.runModal() == .alertFirstButtonReturn else { return }
        guard await quitInstalledCopy(at: destination) else { return }
        // Once file replacement starts, Cmd-Q is deferred until the transaction and cleanup finish.
        installing = true
        let progress = progressWindow()
        defer { progress.close(); installing = false }
        let retainedBackup = try await InstallationWorker.install(source: request.source, destination: destination, expected: expected, incoming: incoming)
        var cleanup: [String] = []
        if let retainedBackup { cleanup.append("The previous app could not be moved to Trash. It is at \(retainedBackup.path).") }
        if let image = request.image {
            do {
                try await InstallationWorker.eject(image)
                if trash.state == .on { try await trashItem(image.file) }
            } catch { cleanup.append("Eject the SimpleVPN disk image in Finder and move its download to Trash when you are ready.") }
        } else if trash.state == .on {
            do { try await trashItem(request.source) }
            catch { cleanup.append("The original app could not be moved to Trash. It is at \(request.source.path).") }
        }
        progress.close()
        if !cleanup.isEmpty { notice("SimpleVPN Is Installed", cleanup.joined(separator: "\n\n"), button: "Continue") }
        // Remove our Dock tile before the installed app gets its own tile.
        NSApp.setActivationPolicy(.accessory)
        lease = nil
        let configuration = NSWorkspace.OpenConfiguration()
        configuration.activates = true
        configuration.addsToRecentItems = false
        do { _ = try await NSWorkspace.shared.openApplication(at: destination, configuration: configuration) }
        catch {
            NSWorkspace.shared.activateFileViewerSelecting([destination])
            notice("SimpleVPN Is Installed", "Open SimpleVPN in Applications.\n\n" + error.localizedDescription)
        }
    }

    private func quitInstalledCopy(at destination: URL) async -> Bool {
        let peers = NSRunningApplication.runningApplications(withBundleIdentifier: Installation.appID).filter {
            !$0.isTerminated && $0.bundleURL.map { Installation.canonical($0) == Installation.canonical(destination) } == true
        }
        guard !peers.isEmpty else { return true }
        let alert = NSAlert()
        alert.messageText = "Quit SimpleVPN to Continue?"
        alert.informativeText = "Installing requires SimpleVPN to quit and disconnect its VPNs. SimpleVPN may ask you to confirm before disconnecting."
        alert.addButton(withTitle: "Quit SimpleVPN and Continue")
        alert.addButton(withTitle: "Cancel").keyEquivalent = "\u{1b}"
        guard alert.runModal() == .alertFirstButtonReturn else { return false }
        cancelled = false
        let waiting = progressWindow(message: "Waiting for SimpleVPN to quit…", cancellable: true)
        defer { waiting.close() }
        for peer in peers { _ = peer.terminate() }
        let deadline = Date().addingTimeInterval(60)
        while !cancelled && peers.contains(where: { !$0.isTerminated }) && Date() < deadline {
            try? await Task.sleep(for: .milliseconds(100))
        }
        guard !cancelled else { return false }
        guard peers.allSatisfy(\.isTerminated) else {
            notice("Installation Cancelled", "SimpleVPN is still running. Your installed app has not been replaced.")
            return false
        }
        return true
    }

    @concurrent private func verifySource(_ source: URL) async throws { try Installation.verify(source) }
    @concurrent private func trashItem(_ url: URL) async throws { try FileManager.default.trashItem(at: url, resultingItemURL: nil) }

    @objc private func cancelInstallation() { cancelled = true }

    private func progressWindow(message: String = "Installing SimpleVPN…", cancellable: Bool = false) -> NSWindow {
        let window = NSWindow(contentRect: NSRect(x: 0, y: 0, width: 380, height: 120), styleMask: [.titled], backing: .buffered, defer: false)
        window.isReleasedWhenClosed = false
        window.title = "Installing SimpleVPN"
        let label = NSTextField(labelWithString: message)
        let spinner = NSProgressIndicator()
        spinner.style = .spinning; spinner.startAnimation(nil)
        let stack = NSStackView(views: [spinner, label])
        stack.orientation = .vertical; stack.spacing = 12
        if cancellable {
            let cancel = NSButton(title: "Cancel Installation", target: self, action: #selector(cancelInstallation))
            cancel.keyEquivalent = "\u{1b}"
            stack.addArrangedSubview(cancel)
        }
        stack.translatesAutoresizingMaskIntoConstraints = false
        window.contentView?.addSubview(stack)
        if let content = window.contentView {
            NSLayoutConstraint.activate([stack.centerXAnchor.constraint(equalTo: content.centerXAnchor), stack.centerYAnchor.constraint(equalTo: content.centerYAnchor)])
        }
        window.center(); window.makeKeyAndOrderFront(nil)
        return window
    }

    private func notice(_ title: String, _ message: String, button: String = "Quit") {
        NSApp.setActivationPolicy(.regular); NSApp.activate()
        let alert = NSAlert()
        alert.messageText = title; alert.informativeText = message
        alert.addButton(withTitle: button).keyEquivalent = "\r"
        alert.runModal()
    }

    private func finish() {
        NSApp.setActivationPolicy(.accessory)
        NSApp.terminate(nil)
    }

    private func removeAbandonedSessions() {
        let manager = FileManager.default
        let active = NSRunningApplication.runningApplications(withBundleIdentifier: Installation.helperID)
            .compactMap { $0.bundleURL.map { Installation.canonical($0.deletingLastPathComponent()) } }
        let directories = (try? manager.contentsOfDirectory(at: manager.temporaryDirectory, includingPropertiesForKeys: nil)) ?? []
        for directory in directories where directory.lastPathComponent.hasPrefix(Installation.sessionPrefix) {
            guard !active.contains(Installation.canonical(directory)),
                  let attributes = try? manager.attributesOfItem(atPath: directory.path),
                  attributes[.type] as? FileAttributeType == .typeDirectory,
                  (attributes[.ownerAccountID] as? NSNumber)?.uint32Value == getuid(),
                  (attributes[.posixPermissions] as? NSNumber)?.intValue == 0o700,
                  let created = attributes[.creationDate] as? Date,
                  created < Date().addingTimeInterval(-86400) else { continue }
            try? manager.removeItem(at: directory)
        }
    }

    func applicationShouldTerminate(_ sender: NSApplication) -> NSApplication.TerminateReply {
        installing ? .terminateCancel : .terminateNow
    }

    func applicationWillTerminate(_ notification: Notification) {
        // macOS permits unlinking the running executable. There is no second cleanup process,
        // shell, delayed sleep, Dock tile, or dependency on the ejected volume.
        if let root { try? FileManager.default.removeItem(at: root) }
        lease = nil
    }
}
