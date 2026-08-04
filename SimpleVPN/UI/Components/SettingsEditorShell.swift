// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
//  SettingsEditorShell.swift
//  The plumbing every one of the six editors needs, once: publish the editor's
//  search model to its rows, select the right TAB for a reveal, and serve
//  incoming `SettingsRoute`s.
//
//  The tab part is why this exists. Every `TabView` in the app was built without
//  a selection binding, so no tab could be selected in code — which made "take me
//  to that setting" impossible across a tab boundary, and Custom Routing (a tab
//  in all six editors) unreachable from anything but a click. A binding plus this
//  modifier is the whole fix, and both the related-settings links and the
//  app-wide search ride the one path.
//

import SwiftUI

private struct SettingsEditorShell: ViewModifier {
    @Bindable var search: SettingsSearch
    @Binding var tab: SettingsTab
    /// Which surfaces this editor can serve a route for — its own plus Custom
    /// Routing, which every editor has.
    let surfaces: Set<SettingSurface>
    /// The VPN this editor is editing, so a route naming a specific profile is
    /// only served by that profile's editor.
    let profileID: String?

    @Environment(SettingsRouter.self) private var router: SettingsRouter?

    func body(content: Content) -> some View {
        content
            .environment(search)
            .onAppear { consume() }
            .onChange(of: router?.generation ?? 0) { consume() }
            .onChange(of: search.revealGeneration) {
                // A reveal may name a setting on the OTHER tab (a Traffic ↔ Custom
                // Routing relation, or a search hit). Select it, or the scroll
                // lands on a row nobody is looking at.
                guard let id = search.revealTargetID,
                      let wanted = SettingSurface.owning(id)?.tab else { return }
                if tab != wanted { tab = wanted }
            }
    }

    private func consume() {
        guard let route = router?.consume(surfaces: surfaces, profileID: profileID) else { return }
        tab = route.tab
        search.reveal(id: route.settingID)
    }
}

extension View {
    /// Wire an editor's TabView: publish `search` to its rows, follow reveals
    /// across tabs, and serve routes for `surfaces`.
    func settingsEditor(search: SettingsSearch, tab: Binding<SettingsTab>,
                        surfaces: Set<SettingSurface>, profileID: String? = nil) -> some View {
        modifier(SettingsEditorShell(search: search, tab: tab,
                                     surfaces: surfaces, profileID: profileID))
    }
}
