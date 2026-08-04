// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
//  OnePasswordBrowsePopover.swift
//  The "Browse…" popover behind the 1Password item and vault fields: a search
//  box over a scrolling list of names.
//
//  It replaces a pair of bare ⟳ icon buttons that testing proved invisible —
//  the person looking straight at them reported there was "no way to select
//  them from a dropdown or fuzzy search". A labelled button and a real search
//  field say what they do without being explained.
//
//  Everything here is presentation: the lists are fetched by the caller (only
//  ever on a click), the matching lives in FuzzyMatch, and nothing but titles
//  and ids ever reaches this view.
//

import SwiftUI

/// One offered row. Ids and names only — a browse list never carries a value.
struct OnePasswordBrowseRow: Identifiable, Hashable, Sendable {
    var id: String
    var title: String
    /// Shown small, under the title: the vault an item lives in, an item's
    /// category — whatever tells two similar names apart.
    var subtitle: String = ""
}

struct OnePasswordBrowsePopover: View {
    let searchPrompt: String
    let rows: [OnePasswordBrowseRow]
    let loading: Bool
    /// A problem, or an explanation of an empty list. Shown in place of the list.
    let status: String?
    /// 1Password answered, but doesn't know which account to ask. Refresh alone
    /// is a dead end here — the same click can only fail the same way — so the
    /// popover asks for the name itself and retries with it.
    var needsAccount = false
    var onAccount: (String) -> Void = { _ in }
    let onPick: (OnePasswordBrowseRow) -> Void
    let onRefresh: () -> Void

    @State private var query = ""
    @FocusState private var searchFocused: Bool

    private var visible: [OnePasswordBrowseRow] {
        FuzzyMatch.rank(rows, query: query) { [$0.title, $0.subtitle] }
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            searchField
            Divider()
            if loading {
                HStack(spacing: 8) {
                    ProgressView().controlSize(.small)
                    Text("Asking 1Password\u{2026}").font(.callout).foregroundStyle(.secondary)
                }
                .frame(maxWidth: .infinity, alignment: .leading)
                .padding(.vertical, 6)
            } else if needsAccount, rows.isEmpty {
                VStack(alignment: .leading, spacing: 8) {
                    Text(OnePasswordPreflight.accountNudge)
                        .font(.callout).foregroundStyle(.secondary)
                        .fixedSize(horizontal: false, vertical: true)
                    OnePasswordAccountPrompt(showsCaption: false, onSubmit: onAccount)
                }
                .padding(.vertical, 6)
            } else if let status, rows.isEmpty {
                Text(status)
                    .font(.callout).foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
                    .padding(.vertical, 6)
            } else if visible.isEmpty {
                Text(rows.isEmpty
                     ? "Nothing to show yet."
                     : "Nothing matches \u{201C}\(query.trimmingCharacters(in: .whitespaces))\u{201D}.")
                    .font(.callout).foregroundStyle(.secondary)
                    .padding(.vertical, 6)
            } else {
                list
            }
            Divider()
            HStack {
                Button("Refresh", systemImage: "arrow.clockwise") { onRefresh() }
                    .buttonStyle(.borderless).font(.callout)
                Spacer()
                if !rows.isEmpty {
                    Text("\(visible.count) of \(rows.count)")
                        .font(.caption).foregroundStyle(.secondary).monospacedDigit()
                }
            }
        }
        .padding(12)
        .frame(width: 320)
    }

    private var searchField: some View {
        HStack(spacing: 6) {
            Image(systemName: "magnifyingglass").foregroundStyle(.secondary)
            TextField(searchPrompt, text: $query)
                .textFieldStyle(.plain)
                .autocorrectionDisabled()
                .focused($searchFocused)
                // Return takes the top match — the fast path once you've typed
                // enough to see what you wanted.
                .onSubmit { if let first = visible.first { onPick(first) } }
            if !query.isEmpty {
                Button { query = "" } label: { Image(systemName: "xmark.circle.fill") }
                    .buttonStyle(.borderless)
                    .foregroundStyle(.secondary)
                    .help("Clear the search")
                    .accessibilityLabel("Clear search")
            }
        }
        .padding(6)
        .background(.quaternary.opacity(0.5), in: RoundedRectangle(cornerRadius: 6))
        .task { searchFocused = true }
    }

    private var list: some View {
        ScrollView {
            LazyVStack(alignment: .leading, spacing: 0) {
                ForEach(visible) { row in
                    RowButton(row: row) { onPick(row) }
                }
            }
        }
        .frame(maxHeight: 260)
    }

    /// A list row that looks pressable: plain button plus a hover highlight,
    /// because a Mac list with no hover feedback reads as a static label.
    private struct RowButton: View {
        let row: OnePasswordBrowseRow
        let action: () -> Void
        @State private var hovering = false

        var body: some View {
            Button(action: action) {
                VStack(alignment: .leading, spacing: 1) {
                    Text(row.title).lineLimit(1)
                    if !row.subtitle.isEmpty {
                        Text(row.subtitle).font(.caption).foregroundStyle(.secondary).lineLimit(1)
                    }
                }
                .frame(maxWidth: .infinity, alignment: .leading)
                .padding(.vertical, 4)
                .padding(.horizontal, 6)
                .contentShape(Rectangle())
            }
            .buttonStyle(.plain)
            .background(hovering ? AnyShapeStyle(.selection) : AnyShapeStyle(.clear),
                        in: RoundedRectangle(cornerRadius: 5))
            .onHover { hovering = $0 }
            .accessibilityLabel(row.subtitle.isEmpty ? row.title : "\(row.title), \(row.subtitle)")
        }
    }
}
