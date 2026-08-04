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

    /// The row to pulse; cleared automatically after the pulse duration.
    private(set) var highlightedID: String?
    /// Group that must expand to reveal the target (collapsed sections observe this).
    private(set) var revealGroup: SettingGroup?
    /// Target row for the scroll; bumping generation re-triggers even for the same row.
    private(set) var revealTargetID: String?
    private(set) var revealGeneration = 0

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

    /// Navigate to a setting: expand its section, unhide it, scroll to it, pulse
    /// it, focus it, and say so.
    ///
    /// …or, when the editor has gated the row out of the form entirely, say THAT
    /// and stop. A jump that lands nowhere while announcing that it landed is the
    /// worst of the three possible outcomes.
    func reveal(_ setting: any SearchableSetting) {
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
        revealGroup = setting.canonicalGroup
        revealTargetID = setting.id
        revealGeneration += 1
        highlightedID = setting.id
        scheduleClear()
    }

    private func scheduleClear() {
        clearTask?.cancel()
        clearTask = Task { [weak self] in
            try? await Task.sleep(for: .seconds(1.8))
            guard !Task.isCancelled else { return }
            self?.highlightedID = nil
            // Cleared together: a row that is unhidden much later must not pulse
            // for a reveal that already finished.
            self?.revealTargetID = nil
        }
    }

    /// Reveal by id. Returns false when this catalog doesn't hold it — the caller
    /// (a related-settings link) then routes to the editor that does.
    @discardableResult
    func reveal(id: String) -> Bool {
        guard let setting = byID[id] else { return false }
        reveal(setting)
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
