// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
//  BrowserPicker.swift
//  Pick a browser (and, where the browser supports them, a profile) for SAML/SSO
//  sign-in. "System Default" defers to the OS default browser; picking a browser
//  reveals its profiles (Chromium `--profile-directory`, Firefox `-P`). Safari has
//  no CLI-selectable profile, so no profile row appears for it.
//

import SwiftUI

struct BrowserPicker: View {
    @Binding var selection: BrowserSelection
    /// When set, the "System Default" row shows what it resolves to (e.g. the app
    /// default) — used in a per-VPN picker to reveal the inherited choice.
    var systemDefaultLabel: String?

    private var installed: [InstalledBrowser] { BrowserCatalog.installed }
    private var chosen: InstalledBrowser? { BrowserCatalog.browser(selection.bundleID) }
    private var profiles: [BrowserProfile] { chosen.map { BrowserCatalog.profiles(for: $0) } ?? [] }

    var body: some View {
        Picker("Browser", selection: Binding(
            get: { selection.bundleID },
            set: { selection.bundleID = $0; selection.profile = nil })) {   // reset profile on browser change
            Text(systemDefaultLabel ?? "System Default (\(BrowserCatalog.osDefaultName))")
                .tag(String?.none)
            // In-app sign-in window — the default; no external browser needed.
            Text(BrowserCatalog.inAppName).tag(Optional(BrowserSelection.inAppBundleID))
            Divider()
            ForEach(installed) { b in Text(b.name).tag(Optional(b.bundleID)) }
        }

        if !profiles.isEmpty {
            Picker("Profile", selection: Binding(
                get: { selection.profile },
                set: { selection.profile = $0 })) {
                Text("Default").tag(String?.none)
                ForEach(profiles) { p in Text(p.name).tag(Optional(p.id)) }
            }
        }
    }
}
