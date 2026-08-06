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

    /// THE THREE-LEVEL PRECEDENCE, once 1Password has named CONNECTIONS rather than
    /// one remembered string. In order, and each step is a decision:
    ///
    ///  1. **What this VPN says** (`CredentialSource.account`). An explicit per-VPN
    ///     value is a choice somebody made about this VPN and outranks everything —
    ///     the same rule `effective(profile:remembered:)` has always had.
    ///  2. **The connection this VPN names** (level 2). This is the new step, and it
    ///     is the whole point: with a personal account and a work tenant set up, a
    ///     VPN pointing at the work one must ask the work one.
    ///  3. **What we remember** (the legacy app-wide string). Still consulted, and
    ///     not merely for politeness: it is where the value lives before
    ///     `SourceInstanceMigration` has run, and after migration it holds the same
    ///     string as connection #1 — so this can never contradict step 2, only
    ///     precede it in time.
    ///
    /// A connection that is GONE contributes nothing rather than falling through to
    /// another one. `SourceInstanceResolver` already refuses to substitute, and
    /// asking the wrong tenant for somebody's VPN password is precisely the silent
    /// failure that refusal exists to prevent — the caller surfaces
    /// `SourceInstanceResolution.chosenIsGone` instead.
    static func effective(profile: String, connection: String, remembered: String) -> String {
        let own = profile.trimmingCharacters(in: .whitespaces)
        if !own.isEmpty { return own }
        let named = connection.trimmingCharacters(in: .whitespaces)
        if !named.isEmpty { return named }
        return remembered.trimmingCharacters(in: .whitespaces)
    }

    /// The account for one profile's stored source, connection included. Reads the
    /// settings store, so it is main-actor bound like every other level-2 read
    /// (`KeePassFileConfiguration.current`, `PassboltConfiguration.current`).
    @MainActor
    static func effectiveAccount(for source: CredentialSource,
                                 store settings: SignInSourceSettingsStore = .shared,
                                 in store: UserDefaults = .standard) -> String {
        effective(profile: source.account,
                  connection: connectionAccount(source.selection.instance, store: settings),
                  remembered: remembered(in: store))
    }

    /// The account name held by ONE connection, or "" when the connection names
    /// nothing, does not exist any more, or none is chosen.
    @MainActor
    static func connectionAccount(_ wanted: SourceInstanceID?,
                                  store: SignInSourceSettingsStore = .shared) -> String {
        guard let instance = store.instanceStore.resolve(wanted, for: .onePassword).instance
        else { return "" }
        for field in SignInSourceSettings.fields(for: .onePassword) {
            guard case .accountIdentifier = field.kind else { continue }
            // Through `presentation` so an MDM-pinned account wins, exactly as it does
            // for a tool path or a database.
            let shown = store.presentation(for: field, instance: instance)
            let value = shown.value.trimmingCharacters(in: .whitespaces)
            if !value.isEmpty { return value }
        }
        return ""
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
