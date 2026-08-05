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
        // ONE HOP LATER. The host publishes its `SettingVisibility` from its own
        // `onAppear`, and SwiftUI does not order `onAppear` between siblings — so
        // revealing inline can consult a stale "everything is shown" and jump to a
        // row that this VPN's settings gate out of the form.
        Task { @MainActor in search.reveal(id: route.settingID) }
    }
}

extension View {
    /// Wire an editor's TabView: publish `search` to its rows, follow reveals
    /// across tabs, serve routes for `surfaces`, and — when the kind being edited
    /// is one nobody has been able to test — put the maturity banner above the
    /// whole editor.
    ///
    /// The banner rides HERE, at the one container all seven editors already share,
    /// rather than inside each editor: sixteen kinds are served by one insertion,
    /// the two editors with a Kind picker (subprocess, native) follow the picker for
    /// free, and flipping a kind to tested needs no view edit at all. `kind` is
    /// optional only so a host without one (previews) can still use the shell.
    func settingsEditor(search: SettingsSearch, tab: Binding<SettingsTab>,
                        surfaces: Set<SettingSurface>, profileID: String? = nil,
                        kind: VPNKind? = nil) -> some View {
        modifier(SettingsEditorShell(search: search, tab: tab,
                                     surfaces: surfaces, profileID: profileID))
            .modifier(MaturityBannerScaffold(kind: kind, profileID: profileID))
    }
}
