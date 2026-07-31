// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
//  OnePasswordBrowse.swift
//  The two pieces of the 1Password pickers that aren't views: the search used to
//  narrow a vault/item list, and the remembered account name.
//
//  Search is deliberately forgiving — people type "grlab" for "GR Lab VPN" and
//  "wrk" for "Work Router" — but ranked, so the closest thing to what was typed
//  is the first row (and the one Return picks).
//
//  The account is remembered APP-WIDE: it names which 1Password account to ask,
//  which is a property of the person, not of a VPN. Typing it once per VPN was
//  the single biggest stumbling block in testing. It is a name, not a secret —
//  the same string 1Password shows at the top of its sidebar — so UserDefaults
//  is the right home for it; nothing about the vault's contents is stored.
//

import Foundation

/// Case- and accent-insensitive "does this look like what they typed" matching,
/// with a rank so results can be ordered by closeness.
nonisolated enum FuzzyMatch {
    /// Lower is closer. nil = no match at all.
    ///  0 exact · 1 starts with · 2 contains · 3 letters appear in order
    static func score(_ query: String, _ candidate: String) -> Int? {
        let q = normalize(query)
        guard !q.isEmpty else { return 0 }
        let c = normalize(candidate)
        if c == q { return 0 }
        if c.hasPrefix(q) { return 1 }
        if c.contains(q) { return 2 }
        return isSubsequence(q, of: c) ? 3 : nil
    }

    static func matches(_ query: String, in candidate: String) -> Bool {
        score(query, candidate) != nil
    }

    /// Filter + order in one pass. `keys` returns what a row can be matched on,
    /// most important first: a hit on the second key never outranks a hit on the
    /// first, so an item whose TITLE matches always sits above one whose vault
    /// name happens to. Ties keep the incoming order (which is alphabetical),
    /// so the list never reshuffles unpredictably as characters are typed.
    static func rank<T>(_ items: [T], query: String, keys: (T) -> [String]) -> [T] {
        let trimmed = query.trimmingCharacters(in: .whitespaces)
        guard !trimmed.isEmpty else { return items }
        let scored: [(item: T, score: Int, index: Int)] = items.enumerated().compactMap { index, item in
            var best: Int?
            for (position, key) in keys(item).enumerated() {
                guard let s = score(trimmed, key) else { continue }
                // Key position dominates: 4 is one more than the worst score.
                let weighted = s + position * 4
                if best == nil || weighted < best! { best = weighted }
            }
            guard let best else { return nil }
            return (item, best, index)
        }
        return scored.sorted {
            $0.score == $1.score ? $0.index < $1.index : $0.score < $1.score
        }.map(\.item)
    }

    /// Fold case and accents so "Résumé" is found by typing "resume", and trim
    /// the query's whitespace (typed searches pick up stray spaces constantly).
    static func normalize(_ s: String) -> String {
        s.trimmingCharacters(in: .whitespaces)
            .folding(options: [.caseInsensitive, .diacriticInsensitive], locale: nil)
    }

    /// Do the query's characters appear in order in the candidate (gaps allowed)?
    private static func isSubsequence(_ query: String, of candidate: String) -> Bool {
        var remaining = Substring(candidate)
        for character in query {
            guard let hit = remaining.firstIndex(of: character) else { return false }
            remaining = remaining[remaining.index(after: hit)...]
        }
        return true
    }
}

/// The 1Password account name to ask, remembered for the whole app.
///
/// Precedence is always: what THIS VPN says, then what we remember, then
/// nothing. A per-VPN value is an explicit choice and outranks the memory; the
/// memory only ever fills a blank.
nonisolated enum OnePasswordAccountMemory {
    static let defaultsKey = "onePassword.defaultAccount"

    static func remembered(in store: UserDefaults = .standard) -> String {
        (store.string(forKey: defaultsKey) ?? "").trimmingCharacters(in: .whitespaces)
    }

    /// Called after a lookup SUCCEEDS with this name — a name that worked is the
    /// only kind worth remembering.
    static func remember(_ account: String, in store: UserDefaults = .standard) {
        let name = account.trimmingCharacters(in: .whitespaces)
        guard shouldRemember(name, current: remembered(in: store)) else { return }
        store.set(name, forKey: defaultsKey)
    }

    /// Seed from a dragged item's account UUID. A 1Password drag names the
    /// account it came from, and the SDK takes a UUID as happily as a sidebar
    /// name — so one drag can answer "which account?" for someone who has never
    /// been able to type it. Only ever fills a BLANK: a name that has actually
    /// worked is more use to a human than a UUID, so it is never overwritten.
    @discardableResult
    static func seed(_ account: String, in store: UserDefaults = .standard) -> Bool {
        let name = account.trimmingCharacters(in: .whitespaces)
        guard !name.isEmpty, remembered(in: store).isEmpty else { return false }
        store.set(name, forKey: defaultsKey)
        return true
    }

    /// Pure precedence rule, so the order can be pinned by a test.
    static func effective(profile: String, remembered: String) -> String {
        let own = profile.trimmingCharacters(in: .whitespaces)
        return own.isEmpty ? remembered.trimmingCharacters(in: .whitespaces) : own
    }

    static func effectiveAccount(profile: String, in store: UserDefaults = .standard) -> String {
        effective(profile: profile, remembered: remembered(in: store))
    }

    /// Whether a success should update what we remember. Nothing to learn from
    /// an empty name, or from the one already stored.
    static func shouldRemember(_ account: String, current: String) -> Bool {
        let name = account.trimmingCharacters(in: .whitespaces)
        return !name.isEmpty && name != current.trimmingCharacters(in: .whitespaces)
    }

    /// What to try after 1Password says it doesn't know the account we asked
    /// for: the remembered default, but only when it's something we haven't
    /// already tried. nil ⇒ there is nothing new to try, so ask the user.
    static func retry(after tried: String, remembered: String) -> String? {
        let fallback = remembered.trimmingCharacters(in: .whitespaces)
        guard !fallback.isEmpty else { return nil }
        return fallback.caseInsensitiveCompare(tried.trimmingCharacters(in: .whitespaces)) == .orderedSame
            ? nil : fallback
    }

    static func retryAccount(after tried: String, in store: UserDefaults = .standard) -> String? {
        retry(after: tried, remembered: remembered(in: store))
    }
}
