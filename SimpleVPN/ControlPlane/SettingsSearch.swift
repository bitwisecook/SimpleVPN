// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
//  SettingsSearch.swift
//  Fuzzy search over the OpenVPN setting descriptors: type a few characters,
//  jump to the matching setting. Matching is subsequence-based (letters must
//  appear in order, gaps allowed) with bonuses for word starts and contiguous
//  runs, over the setting's name, plain-English summary, group title, and id —
//  so "comp", "voracle-ish" phrases, or "proxy pass" all land on the right row.
//
//  The model also owns the reveal flow the form reacts to: expanding the
//  section that contains the hit, scrolling to it, and flashing a highlight.
//

import Foundation
import Observation

@MainActor
@Observable
final class SettingsSearch {

    var query = ""

    /// The row to flash; cleared automatically after the flash duration.
    private(set) var highlightedID: String?
    /// Group that must expand to reveal the target (collapsed sections observe this).
    private(set) var revealGroup: SettingGroup?
    /// Target row for the scroll; bumping generation re-triggers even for the same row.
    private(set) var revealTargetID: String?
    private(set) var revealGeneration = 0

    private var clearTask: Task<Void, Never>?

    var matches: [SettingDescriptor] {
        let q = query.trimmingCharacters(in: .whitespaces)
        guard q.count >= 2 else { return [] }
        return OpenVPNSettings.all
            .compactMap { d in Self.score(query: q, descriptor: d).map { (d, $0) } }
            .sorted { $0.1 > $1.1 }
            .prefix(6)
            .map(\.0)
    }

    /// Navigate to a setting: expand its section, scroll to it, flash it.
    func reveal(_ descriptor: SettingDescriptor) {
        revealGroup = descriptor.group
        revealTargetID = descriptor.id
        revealGeneration += 1
        highlightedID = descriptor.id
        query = ""

        clearTask?.cancel()
        clearTask = Task { [weak self] in
            try? await Task.sleep(for: .seconds(1.8))
            guard !Task.isCancelled else { return }
            self?.highlightedID = nil
        }
    }

    // MARK: Fuzzy scoring

    /// nil = no match. Higher is better. Subsequence match with word-start and
    /// contiguity bonuses; name matches outrank summary/id matches.
    static func score(query: String, descriptor d: SettingDescriptor) -> Int? {
        let q = query.lowercased()
        var best: Int?
        for (weight, hay) in [(100, d.name), (40, d.group.title), (30, d.summary), (60, d.id)] {
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
