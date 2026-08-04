// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
//  CLIInstaller.swift
//  The SimpleVPN ▸ Install CLI… menu action: symlinks the bundled `simplevpn`
//  tool (Contents/Helpers/simplevpn — NOT Contents/MacOS, where its name would
//  case-collide with the app binary) into /usr/local/bin so it's on the default
//  PATH. The VS Code "install 'code' command" pattern.
//
//  /usr/local/bin needs admin to write (and may not exist at all on a fresh
//  Apple Silicon Mac), so the link is made by one `osascript … with
//  administrator privileges` — macOS shows its own credible auth prompt naming
//  the app. A symlink (not a copy) means app updates update the CLI for free,
//  and dragging the app to the Trash leaves only a dead link behind (which we
//  also detect and offer to repair/remove).
//

import AppKit

@MainActor
enum CLIInstaller {
    static let linkPath = "/usr/local/bin/simplevpn"

    /// The bundled tool. nil in dev builds that predate the embed phase.
    static var bundledToolPath: String? {
        let path = Bundle.main.bundleURL
            .appendingPathComponent("Contents/Helpers/simplevpn").path
        return FileManager.default.isExecutableFile(atPath: path) ? path : nil
    }

    enum LinkState {
        case notInstalled
        case installed                // link exists and points at THIS app's tool
        case stale(current: String)   // link exists but points elsewhere (old copy, moved app)
    }

    static var state: LinkState {
        guard let dest = try? FileManager.default.destinationOfSymbolicLink(atPath: linkPath) else {
            // Not a symlink (or absent). A regular file here is somebody else's —
            // treat as stale so the flow asks before replacing it.
            return FileManager.default.fileExists(atPath: linkPath)
                ? .stale(current: linkPath) : .notInstalled
        }
        return dest == bundledToolPath ? .installed : .stale(current: dest)
    }

    /// The menu action: explain, authenticate, link, confirm. All feedback is
    /// modal alerts — this is a one-shot utility, not a status surface.
    static func install() {
        guard let tool = bundledToolPath else {
            alert("The command-line tool isn't in this copy of SimpleVPN.",
                  info: "This build was made without the bundled CLI. Reinstall SimpleVPN from a release build.")
            return
        }
        if case .installed = state {
            alert("The simplevpn command is already installed.",
                  info: "\(linkPath) already points at this copy of SimpleVPN. You're set — try `simplevpn list` in Terminal.")
            return
        }

        let confirm = NSAlert()
        confirm.messageText = "Install the simplevpn command?"
        confirm.informativeText = """
        This links \(linkPath) to the tool inside SimpleVPN, so you can run \
        `simplevpn` from Terminal. macOS will ask for an administrator password \
        to write to /usr/local/bin.
        """
        confirm.addButton(withTitle: "Install")
        confirm.addButton(withTitle: "Cancel")
        guard confirm.runModal() == .alertFirstButtonReturn else { return }

        // -h on chown-less ln? No: `ln -sfn` replaces an existing link atomically
        // enough for this purpose and creates the directory first. Quoting: the
        // tool path contains no user input beyond the app's install location;
        // single-quote it with the standard '\'' escape for safety anyway.
        let quotedTool = "'" + tool.replacingOccurrences(of: "'", with: "'\\''") + "'"
        let script = "do shell script \"mkdir -p /usr/local/bin && ln -sfn \(quotedTool) \(linkPath)\" with administrator privileges"

        var error: NSDictionary?
        NSAppleScript(source: script)?.executeAndReturnError(&error)
        if let error, (error[NSAppleScript.errorNumber] as? Int) != -128 {   // -128 = user cancelled
            alert("Couldn't install the simplevpn command.",
                  info: (error[NSAppleScript.errorMessage] as? String) ?? "Unknown error.")
            return
        }
        if case .installed = state {
            alert("The simplevpn command is installed.",
                  info: "Open a Terminal and try `simplevpn list`. It talks to SimpleVPN while the app is running.")
        }
    }

    private static func alert(_ message: String, info: String) {
        let a = NSAlert()
        a.messageText = message
        a.informativeText = info
        a.runModal()
    }
}
