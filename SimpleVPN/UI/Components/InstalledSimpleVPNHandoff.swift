// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only

import SwiftUI

struct InstalledSimpleVPNHandoff: View {
    @State private var isOpening = false
    @State private var showOpenError = false

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            LabeledContent("Opened from") {
                Text(Bundle.main.executableURL?.path ?? Bundle.main.bundlePath)
                    .textSelection(.enabled)
                    .fixedSize(horizontal: false, vertical: true)
            }
            Button("Open Installed SimpleVPN") {
                isOpening = true
                Task {
                    defer { isOpening = false }
                    let url = Installation.applications.appending(path: "SimpleVPN.app")
                    do {
                        let configuration = NSWorkspace.OpenConfiguration()
                        let app = try await NSWorkspace.shared.openApplication(at: url, configuration: configuration)
                        guard app.processIdentifier != ProcessInfo.processInfo.processIdentifier,
                              AppDelegate.isSameInstallation(ourBundleURL: url, otherBundleURL: app.bundleURL) else {
                            showOpenError = true
                            return
                        }
                        NSApp.terminate(nil)
                    } catch {
                        showOpenError = true
                    }
                }
            }
            .disabled(isOpening)
            .accessibilityHint("Opens the copy in Applications, then quits this copy.")
        }
        .alert("Couldn’t Open Installed SimpleVPN", isPresented: $showOpenError) {
            Button("OK", role: .cancel) {}
        } message: {
            Text("Check that SimpleVPN.app is in Applications and try again.")
        }
    }
}
