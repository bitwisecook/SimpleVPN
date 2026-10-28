// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
//  CollapsibleSettingsSection.swift
//  THE collapsed-by-default settings section for every editor. Three different
//  "Advanced" idioms used to exist across five editors — `Section{DisclosureGroup}`
//  with a hand-rolled hit-target label (SubprocessTunnelView), this component
//  living privately inside OpenVPNOptionsForm, and a plain `Section("Advanced")`
//  (WireGuard, Native, Tailscale) that couldn't collapse at all. Promoted here and
//  made group-generic so every editor gets the same three behaviours for free:
//
//   • the whole header row is the hit target (not just the chevron and the word),
//   • an "n changed" badge, so a collapsed group never hides a changed setting,
//   • the search-reveal hook: a hit inside a closed group opens it (the
//     SettingsSearch environment object, when the host installs one).
//
//  It opens itself when it already contains changes, so nothing the user set is
//  ever behind a closed disclosure.
//

import SwiftUI

/// Keep the header a real, keyboard-operable Button. On macOS 27 the native
/// disclosure triangle can omit its accessibility action. Applying an action to
/// the entire group also changes descendant field roles; this style scopes the
/// action to the header and leaves the expanded controls independent.
struct AccessibleSettingsDisclosureStyle: DisclosureGroupStyle {
    @Environment(\.accessibilityReduceMotion) private var reduceMotion

    func makeBody(configuration: Configuration) -> some View {
        VStack(alignment: .leading, spacing: 0) {
            Button {
                withAnimation(reduceMotion ? nil : .snappy) {
                    configuration.isExpanded.toggle()
                }
            } label: {
                HStack(spacing: 6) {
                    Image(systemName: configuration.isExpanded ? "chevron.down" : "chevron.right")
                        .font(.caption.weight(.semibold))
                        .accessibilityHidden(true)
                    configuration.label.frame(maxWidth: .infinity, alignment: .leading)
                }
                .contentShape(Rectangle())
            }
            .buttonStyle(.plain)
            .accessibilityValue(configuration.isExpanded ? "Expanded" : "Collapsed")
            if configuration.isExpanded { configuration.content }
        }
    }
}

struct CollapsibleSettingsSection<Content: View, Footer: View>: View {
    /// Canonical taxonomy group (AGENTS.md "Config surfaces") — supplies the
    /// title AND the identity the search-reveal matches against.
    let group: SettingGroup
    /// How many settings in this group differ from their default. Drives the
    /// badge and the initial expansion.
    let changedCount: Int
    @ViewBuilder let content: Content
    @ViewBuilder let footer: Footer

    @Environment(\.accessibilityReduceMotion) private var reduceMotion
    @State private var expanded: Bool
    @Environment(SettingsSearch.self) private var search: SettingsSearch?

    init(group: SettingGroup, changedCount: Int = 0,
         @ViewBuilder content: () -> Content,
         @ViewBuilder footer: () -> Footer) {
        self.group = group
        self.changedCount = changedCount
        self.content = content()
        self.footer = footer()
        _expanded = State(initialValue: changedCount > 0)
    }

    var body: some View {
        Section {
            DisclosureGroup(isExpanded: $expanded.animation(reduceMotion ? nil : .snappy)) {
                content
                    .padding(.top, 4)
            } label: {
                HStack {
                    Text(group.title)
                    ChangeCountBadge(count: changedCount)
                    Spacer(minLength: 0)
                }
                .padding(.vertical, 4)
                .contentShape(Rectangle())
            }
            .disclosureGroupStyle(AccessibleSettingsDisclosureStyle())
        } footer: {
            footer.font(.callout).foregroundStyle(.secondary)
        }
        // A hit inside this group must never land on a closed disclosure. The shared
        // modifier (UI/Components/SettingReveal.swift) because it also has to fire on
        // `onAppear` — a CROSS-TAB reveal creates this section after the generation
        // changed, so an `onChange` alone never sees it, and the reveal then scrolled
        // to a row inside a shut disclosure.
        .expandsForReveal($expanded, holding: .group(group))
    }

}

extension CollapsibleSettingsSection where Footer == EmptyView {
    init(group: SettingGroup, changedCount: Int = 0, @ViewBuilder content: () -> Content) {
        self.init(group: group, changedCount: changedCount, content: content, footer: { EmptyView() })
    }
}
