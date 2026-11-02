// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only

import AppKit

nonisolated enum InstallationRunningApps {
    static func hasCopy(at url: URL) -> Bool {
        NSRunningApplication.runningApplications(withBundleIdentifier: Installation.appID).contains {
            !$0.isTerminated && $0.bundleURL.map { Installation.canonical($0) == Installation.canonical(url) } == true
        }
    }
}
