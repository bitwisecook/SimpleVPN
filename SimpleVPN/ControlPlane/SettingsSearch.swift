// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
//  SettingsSearch.swift
//  Fuzzy search over a setting catalog: type a few characters, jump to the
//  matching setting. Matching is subsequence-based (letters must appear in order,
//  gaps allowed) with bonuses for word starts and contiguous runs, over the
//  setting's name, plain-English summary, group title, and id — so "comp",
//  "voracle-ish" phrases, or "proxy pass" all land on the right row.
//
//  CATALOG-INJECTED, and generic over `SearchableSetting`. It used to name
//  `OpenVPNSettings.all` and `SettingDescriptor` in its own signatures, so the
//  one editor that instantiated it was the only editor in the app with a search
//  field — five surfaces' worth of settings (and the Custom Routing tab, which
//  every kind has) could only be found by scrolling. Each editor now builds one
//  of these over its own surfaces, and `AllSettings` builds one over every
//  surface at once for the app-wide search.
//
//  The model also owns the reveal flow the forms react to: expanding the section
//  that contains the hit, unhiding it, scrolling to it, pulsing it, moving
//  keyboard focus onto it and announcing where we landed. See
//  UI/Components/SettingReveal.swift for the row half.
//

import Foundation
import Observation

@MainActor
@Observable
final class SettingsSearch {

    var query = ""

    /// The row to highlight; cleared automatically once the reveal has finished.
    private(set) var highlightedID: String?
    /// Group that must expand to reveal the target (collapsed sections observe this).
    private(set) var revealGroup: SettingGroup?
    /// Target row for the scroll; bumping generation re-triggers even for the same row.
    private(set) var revealTargetID: String?
    private(set) var revealGeneration = 0

    /// THE ARRIVAL — the reveal has LANDED: whatever container held the row is open,
    /// and the scroll has stopped moving. Published by the scroll host
    /// (`revealsSettings()`), and the only thing the row's blue highlight and its
    /// keyboard focus key off.
    ///
    /// Separate from the reveal itself because the two are separated by a tab switch
    /// and a disclosure animation, neither of which reports when it is done. A
    /// highlight started with the reveal plays while the row is still travelling —
    /// or, across a tab boundary, before the row is on screen at all, which is
    /// exactly what a user saw as "it took me to the Options tab and did nothing".
    private(set) var arrivedID: String?
    private(set) var arrivedGeneration = 0

    /// Called by the scroll host once its scroll has settled on `id`. Ignores a
    /// stale generation, so a host still finishing a reveal that has been superseded
    /// cannot light up a row for it.
    func revealDidArrive(id: String, generation: Int) {
        guard generation == revealGeneration, id == revealTargetID,
              arrivedGeneration != generation else { return }
        arrivedID = id
        arrivedGeneration = generation
    }

    /// The settings this instance can find — one editor's surfaces, or every
    /// surface in the app for the global search.
    let catalog: [any SearchableSetting]
    /// The VPN kind whose editor owns this search, when one does. Decides which
    /// related links are reachable from here (a relation from `cr.route-rule`
    /// names every engine's routing control at once; only this kind's is a link
    /// the user can follow).
    ///
    /// Settable because one editor serves several kinds and lets you switch
    /// between them live: SubprocessTunnelView's Kind picker turns an SSH tunnel
    /// into a FortiGate one, and the related links have to follow.
    var kind: VPNKind?

    /// Which of this editor's settings are gated OUT of the form right now, and
    /// why (`SettingVisibility`). Pushed by the host editor from its draft.
    ///
    /// A reveal for one of these can't work — there is no row to scroll to, pulse
    /// or focus — and the flipping of the gate is not ours to do: it is a config
    /// value, and turning on "Use an exit node" because someone asked what the
    /// exit-node picker is would edit their VPN. So the reveal says the truth
    /// instead of pretending (`unavailable` below), which is the half of this that
    /// matters most: the announcement used to claim "Showing X, in Y" for every
    /// gated row in five of the six editors.
    var visibility = SettingVisibility.everythingShown

    /// Why `id` isn't on screen in this editor, or nil when it is (or when it
    /// isn't this editor's setting at all).
    func hiddenReason(_ id: String) -> String? { visibility.reason(id) }

    /// The last reveal that couldn't land, for the editor to show beside its
    /// search field. Cleared on the same timer as the pulse.
    private(set) var unavailable: UnavailableReveal?

    struct UnavailableReveal: Equatable, Sendable {
        let name: String
        let reason: String
    }

    private var byID: [String: any SearchableSetting]
    private var clearTask: Task<Void, Never>?
    private var unavailableTask: Task<Void, Never>?

    init(_ catalog: [any SearchableSetting], kind: VPNKind? = nil) {
        self.catalog = catalog
        self.kind = kind
        self.byID = Dictionary(catalog.map { ($0.id, $0) }, uniquingKeysWith: { first, _ in first })
    }

    /// The editor form: its own surface plus Custom Routing, which is a tab in
    /// every one of the six editors — so a search inside any editor finds the
    /// routing controls that editor also shows.
    convenience init(surfaces: [SettingSurface], kind: VPNKind?) {
        self.init(surfaces.flatMap(\.settings), kind: kind)
    }

    /// Every setting in the app (the ⌘⇧F global search).
    static func global() -> SettingsSearch {
        SettingsSearch(SettingSurface.allCases.flatMap(\.settings), kind: nil)
    }

    /// Whether this catalog holds the setting — the test a related link applies to
    /// decide "reveal it here" or "route to another editor".
    func contains(_ id: String) -> Bool { byID[id] != nil }

    func setting(_ id: String) -> (any SearchableSetting)? { byID[id] }

    var matches: [any SearchableSetting] {
        let q = query.trimmingCharacters(in: .whitespaces)
        guard q.count >= 2 else { return [] }
        return catalog
            .compactMap { d in Self.score(query: q, setting: d).map { (d, $0) } }
            .sorted { $0.1 > $1.1 }
            .prefix(6)
            .map(\.0)
    }

    // MARK: Where the user came from

    /// One step of history: the tab the user could see, and the row they were
    /// reading when they followed a link away from it.
    struct BackPoint: Equatable, Sendable {
        let tab: SettingsTab?
        /// The row to put back under the cursor. A help popover knows its own
        /// setting; a plain `SettingJumpLink` doesn't, and then the tab is the whole
        /// answer.
        let settingID: String?
    }

    /// Which tab the editor showing this search is on. Published by
    /// `SettingsEditorShell`; the history needs it and nothing else does.
    var activeTab: SettingsTab?

    private(set) var backStack: [BackPoint] = []
    var canGoBack: Bool { !backStack.isEmpty }

    /// What the back button says it will do — a setting's name where there is one,
    /// otherwise the tab's.
    var backDestination: String? {
        guard let top = backStack.last else { return nil }
        if let id = top.settingID, let setting = byID[id] { return setting.name }
        return top.tab?.title
    }

    /// A tab the model wants selected. Back navigation can name a tab that holds no
    /// setting to reveal (General, Configuration), which no reveal can express.
    private(set) var requestedTab: SettingsTab?
    private(set) var tabRequestGeneration = 0

    func goBack() {
        guard let point = backStack.popLast() else { return }
        if let tab = point.tab {
            requestedTab = tab
            tabRequestGeneration += 1
        }
        // Going back RE-REVEALS the row we left, so "back" restores the scroll
        // position and not just the tab. Recorded as history it is not: otherwise
        // back and forward would be the same button.
        if let id = point.settingID, let setting = byID[id] {
            performReveal(setting, origin: nil, recordHistory: false)
        }
    }

    private func pushBackPoint(origin: String?) {
        let point = BackPoint(tab: activeTab, settingID: origin ?? arrivedID)
        guard point.tab != nil || point.settingID != nil else { return }
        guard backStack.last != point else { return }
        backStack.append(point)
        // A user who follows twenty links wants the last few, not a transcript.
        if backStack.count > 16 { backStack.removeFirst() }
    }

    // MARK: Revealing

    /// Navigate to a setting: expand its section, unhide it, scroll to it, highlight
    /// it, focus it, and say so.
    ///
    /// …or, when the editor has gated the row out of the form entirely, say THAT
    /// and stop. A jump that lands nowhere while announcing that it landed is the
    /// worst of the three possible outcomes.
    ///
    /// `origin` is the setting the user was READING when they followed the link (a
    /// help popover knows it), so the back button can return them to it.
    func reveal(_ setting: any SearchableSetting, from origin: String? = nil) {
        performReveal(setting, origin: origin, recordHistory: true)
    }

    private func performReveal(_ setting: any SearchableSetting,
                               origin: String?, recordHistory: Bool) {
        query = ""
        if let why = hiddenReason(setting.id) {
            revealGroup = nil
            revealTargetID = nil
            highlightedID = nil
            unavailable = UnavailableReveal(name: setting.name, reason: why)
            AccessibilityAnnouncer.sayNow("\(setting.name) isn\u{2019}t shown for this VPN. \(why)")
            // A sentence to read, not a flash: it lives long enough to act on.
            unavailableTask?.cancel()
            unavailableTask = Task { [weak self] in
                try? await Task.sleep(for: .seconds(12))
                guard !Task.isCancelled else { return }
                self?.unavailable = nil
            }
            return
        }
        unavailableTask?.cancel()
        unavailable = nil
        // BEFORE the state below is replaced: the back point is where we are
        // LEAVING, and `arrivedID` is still the row the last reveal landed on.
        if recordHistory { pushBackPoint(origin: origin) }
        revealGroup = setting.canonicalGroup
        revealTargetID = setting.id
        arrivedID = nil
        revealGeneration += 1
        highlightedID = setting.id
        scheduleClear()
    }

    private func scheduleClear() {
        clearTask?.cancel()
        clearTask = Task { [weak self] in
            // Long enough for the whole choreography — select the tab, open the
            // container, scroll, hold the highlight for its second and a half, fade
            // — and no longer. It was 1.8s, which expired in the middle of a
            // cross-tab reveal and took the target with it.
            try? await Task.sleep(for: .seconds(4))
            guard !Task.isCancelled else { return }
            self?.highlightedID = nil
            // Cleared together: a row that is unhidden much later must not light up
            // for a reveal that already finished.
            self?.revealTargetID = nil
            self?.arrivedID = nil
        }
    }

    /// Reveal by id. Returns false when this catalog doesn't hold it — the caller
    /// (a related-settings link) then routes to the editor that does.
    @discardableResult
    func reveal(id: String, from origin: String? = nil) -> Bool {
        guard let setting = byID[id] else { return false }
        reveal(setting, from: origin)
        return true
    }

    // MARK: Fuzzy scoring

    /// nil = no match. Higher is better. Subsequence match with word-start and
    /// contiguity bonuses; name matches outrank summary/id matches.
    static func score(query: String, setting d: any SearchableSetting) -> Int? {
        let q = query.lowercased()
        var best: Int?
        for (weight, hay) in [(100, d.name), (40, d.canonicalGroup?.title ?? ""),
                              (30, d.summary), (60, d.id)] where !hay.isEmpty {
            if let s = fuzzyScore(q, in: hay.lowercased()) {
                let weighted = s + weight
                if weighted > (best ?? .min) { best = weighted }
            }
        }
        return best
    }

    /// Classic subsequence scorer: every query character must appear in order.
    /// +3 per char matched at a word start, +2 when contiguous with the previous
    /// match, +1 otherwise; a full substring hit earns an extra +10.
    private static func fuzzyScore(_ query: String, in text: String) -> Int? {
        if query.isEmpty { return nil }
        if text.contains(query) { return 10 + query.count * 3 }

        var score = 0
        var lastMatch: String.Index?
        var search = text.startIndex
        for ch in query {
            guard let found = text[search...].firstIndex(of: ch) else { return nil }
            if found == text.startIndex || text[text.index(before: found)] == " " {
                score += 3
            } else if let last = lastMatch, text.index(after: last) == found {
                score += 2
            } else {
                score += 1
            }
            lastMatch = found
            search = text.index(after: found)
        }
        return score
    }
}
