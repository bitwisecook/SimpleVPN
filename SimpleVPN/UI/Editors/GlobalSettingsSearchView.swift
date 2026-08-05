// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
//  GlobalSettingsSearchView.swift
//  "Find a Setting…" (⌘⇧F, and the Manage VPNs toolbar) — search across EVERY
//  setting the app exposes, not just the editor you happen to have open.
//
//  This is the payoff of moving the catalogs into ControlPlane and registering
//  them as `SettingSurface`s: ~130 settings across eight surfaces, each result
//  addressed in full ("Tailscale ▸ Traffic ▸ Use Shared Networks"), and picking
//  one routes through the SAME `SettingsRouter` intent the related-settings links
//  use — select the VPN, select the tab, scroll, focus, pulse, announce.
//
//  It answers the question a per-editor search cannot: "SimpleVPN has a setting
//  for X — where is it?" You had to know which of six editors owned it first.
//

import SwiftUI
import AppKit

struct GlobalSettingsSearchView: View {
    @Environment(\.dismiss) private var dismiss
    @Environment(SettingsRouter.self) private var router: SettingsRouter?

    /// Deliberately NOT the editor's search: the catalog is every surface at once
    /// and picking a result routes instead of revealing.
    @State private var search = SettingsSearch.global()

    var body: some View {
        VStack(spacing: 0) {
            Form {
                Section {
                    SettingsSearchField(
                        search: search,
                        prompt: "Search every setting",
                        onPick: { pick($0) },
                        // The whole address, because a global hit has to say which
                        // editor it is about to open.
                        subtitle: { AllSettings.byID[$0.id]?.breadcrumb ?? $0.summary },
                        autofocus: true)
                } footer: {
                    Text("Searches every setting in every VPN editor, and SimpleVPN\u{2019}s own settings. Choosing one opens where it lives and jumps to it.")
                }
            }
            .formStyle(.grouped)
            Divider()
            HStack {
                Spacer()
                Button("Done") { dismiss() }
                    .keyboardShortcut(.cancelAction)
            }
            .padding(12)
        }
        .frame(width: 460, height: 340)
        .navigationTitle("Find a Setting")
    }

    private func pick(_ setting: any SearchableSetting) {
        dismiss()
        router?.go(to: setting.id)
        // An app-level hit lives in the Settings window, which nothing else here
        // would open. The router has already recorded which tab it wants.
        if SettingsRouter.isAppLevel(settingID: setting.id) {
            openAppSettings()
        }
    }

    /// Open SimpleVPN's own Settings window. There is no SwiftUI API for this that
    /// works from an arbitrary view, so it goes through the AppKit action the
    /// Settings scene installs.
    private func openAppSettings() {
        NSApp.sendAction(Selector(("showSettingsWindow:")), to: nil, from: nil)
    }
}
