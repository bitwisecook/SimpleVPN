// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
//  SettingsSearchField.swift
//  THE settings search field, shared by every editor. It grew up inside
//  OpenVPNOptionsForm as a private `searchSection`, which is why exactly one of
//  the app's six editors could be searched: the field, the result list and the
//  empty state were all written into that one form.
//
//  Put it in a `Section` at the top of any editor's Form, with a `SettingsSearch`
//  in the environment; picking a result reveals it (scroll + pulse + focus +
//  announcement — see SettingReveal.swift). A result outside the current editor
//  routes through `SettingsRouter` instead, which is how the global search reuses
//  the same list.
//

import SwiftUI

struct SettingsSearchField: View {
    /// The model to query. Passed rather than read from the environment: the
    /// global search sheet owns one that is NOT the editor's.
    @Bindable var search: SettingsSearch
    /// Placeholder — an editor says "Search settings", the global sheet names the
    /// scope ("Search every setting").
    var prompt = "Search settings"
    /// What a picked result does. Defaults to revealing it in this editor.
    var onPick: ((any SearchableSetting) -> Void)?
    /// Shown under each result instead of the summary — the global search's
    /// "Tailscale ▸ Traffic" breadcrumb.
    var subtitle: ((any SearchableSetting) -> String)?
    /// Take keyboard focus on appear — the global search sheet does (you opened it
    /// to type), an editor's inline field does not (it would steal focus from the
    /// settings you came for).
    var autofocus = false

    @FocusState private var fieldFocused: Bool

    var body: some View {
        HStack(spacing: 6) {
            Image(systemName: "magnifyingglass").foregroundStyle(.secondary)
                .accessibilityHidden(true)
            TextField(prompt, text: $search.query)
                .textFieldStyle(.plain)
                .autocorrectionDisabled()
                .focused($fieldFocused)
                .onSubmit { if let first = search.matches.first { pick(first) } }
            if !search.query.isEmpty {
                Button { search.query = "" } label: {
                    Image(systemName: "xmark.circle.fill").foregroundStyle(.secondary)
                        .frame(width: 22, height: 22).contentShape(Rectangle())
                }
                .buttonStyle(.borderless)
                .accessibilityLabel("Clear search")
            }
        }
        .onAppear { if autofocus { fieldFocused = true } }
        ForEach(search.matches, id: \.id) { d in
            Button { pick(d) } label: {
                VStack(alignment: .leading, spacing: 1) {
                    HStack(spacing: 6) {
                        Text(d.name)
                        if subtitle == nil, let group = d.canonicalGroup?.title {
                            Text("· \(group)").foregroundStyle(.secondary).font(.callout)
                        }
                    }
                    Text(subtitle?(d) ?? d.summary)
                        .font(.callout).foregroundStyle(.secondary).lineLimit(1)
                }
                .frame(maxWidth: .infinity, alignment: .leading)
                .contentShape(Rectangle())
            }
            .buttonStyle(.plain)
            .accessibilityHint("Jump to this setting")
        }
        if search.query.trimmingCharacters(in: .whitespaces).count >= 2, search.matches.isEmpty {
            Text("No settings match \u{201C}\(search.query)\u{201D}")
                .font(.callout).foregroundStyle(.secondary)
        }
    }

    private func pick(_ d: any SearchableSetting) {
        if let onPick { onPick(d) } else { search.reveal(d) }
    }
}

/// The whole thing as one `Section`, which is how every editor uses it.
struct SettingsSearchSection: View {
    @Bindable var search: SettingsSearch

    var body: some View {
        Section {
            SettingsSearchField(search: search)
        }
    }
}
