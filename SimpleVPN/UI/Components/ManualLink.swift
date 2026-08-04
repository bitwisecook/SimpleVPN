// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
//  ManualLink.swift
//  The "?" beside every setting row — ~90 of them across six editors, the single
//  most repeated control in the app.
//
//  It used to be a one-way trip: click, and a separate manual window took over
//  the screen at the right anchor. That is the right destination for "explain
//  this to me properly", and the wrong one for the far commoner question, which
//  is "what is this, and what else does it touch?" — a question the app already
//  knew the answer to (the summary is in the spec; the relations were written
//  down as caveats and disabledReasons) but only ever answered in prose the user
//  had to act on by hand.
//
//  So it is a POPOVER now, in this order:
//   • the setting's name,
//   • its plain-English summary,
//   • "Related settings" — real links that jump, focus and pulse the target
//     (SettingReveal.swift) when it is in this editor, and route through
//     `SettingsRouter` when it lives in another tab or another editor,
//   • "Open the manual" — the old behaviour, unchanged, as the footer action.
//
//  The 22×22 hit target from the hitbox sweep is kept: the glyph is ~13pt and
//  this button repeats ~90 times, so it remains the biggest target-size win in
//  the app.
//

import SwiftUI

struct ManualLink: View {
    private let anchor: String
    private let settingName: String
    /// The stable setting id, when the caller has a spec. Without it the popover
    /// still shows the name and the manual action — it just has no summary to
    /// quote and no relations to look up.
    private let settingID: String?
    private let summary: String?

    /// Legacy call site: an anchor and a name, nothing else. Kept because a few
    /// links point at prose chapters rather than settings.
    init(anchor: String, settingName: String) {
        self.anchor = anchor
        self.settingName = settingName
        self.settingID = nil
        self.summary = nil
    }

    /// The form every setting row uses — everything comes from the spec, so the
    /// popover can never disagree with the row it sits beside.
    init(setting: any SearchableSetting) {
        self.anchor = setting.manualAnchor
        self.settingName = setting.name
        self.settingID = setting.id
        self.summary = setting.summary
    }

    @State private var showing = false
    @Environment(ManualRouter.self) private var manual: ManualRouter?
    @Environment(\.openWindow) private var openWindow
    /// The editor's own search model — its catalog is the test for "can I reveal
    /// this here, or does it need routing?", and its `kind` decides which
    /// relations are reachable at all.
    @Environment(SettingsSearch.self) private var search: SettingsSearch?
    @Environment(SettingsRouter.self) private var router: SettingsRouter?

    private var relations: [GlobalSetting] {
        guard let settingID else { return [] }
        return AllSettings.related(of: settingID, kind: search?.kind)
    }

    var body: some View {
        Button {
            showing = true
        } label: {
            Image(systemName: "questionmark.circle")
                .frame(width: 22, height: 22)
                .contentShape(Rectangle())
        }
        .buttonStyle(.borderless)
        .help("What \u{201C}\(settingName)\u{201D} does, and the settings it affects")
        .accessibilityLabel("Help for \(settingName)")
        .accessibilityHint("Shows what it does, the related settings, and a link to the manual")
        .popover(isPresented: $showing, arrowEdge: .trailing) {
            popoverBody
        }
    }

    @ViewBuilder private var popoverBody: some View {
        VStack(alignment: .leading, spacing: 10) {
            Text(settingName).font(.headline)
                .fixedSize(horizontal: false, vertical: true)
            if let summary {
                Text(summary)
                    .font(.callout).foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }
            if !relations.isEmpty {
                Divider()
                Text("Related settings")
                    .font(.subheadline.weight(.semibold))
                VStack(alignment: .leading, spacing: 2) {
                    ForEach(relations) { entry in
                        relatedLink(entry)
                    }
                }
            }
            Divider()
            Button {
                showing = false
                manual?.navigate(to: anchor)
                openWindow(id: "manual")
            } label: {
                Label("Open the manual", systemImage: "book")
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .contentShape(Rectangle())
            }
            .buttonStyle(.plain)
            .foregroundStyle(.tint)
            .help("Read the full section on \u{201C}\(settingName)\u{201D}")
        }
        .padding(14)
        .frame(width: 320)
    }

    /// One related-settings link. Same click either way from the user's point of
    /// view — the difference is only whether the target is in this editor (reveal
    /// it) or somewhere else (route to it), and both paths end in the same
    /// scroll + focus + pulse + announcement.
    @ViewBuilder private func relatedLink(_ entry: GlobalSetting) -> some View {
        let here = search?.contains(entry.setting.id) == true
        Button {
            showing = false
            if here {
                search?.reveal(id: entry.setting.id)
            } else {
                router?.go(to: entry.setting.id)
            }
        } label: {
            HStack(spacing: 6) {
                Image(systemName: here ? "arrow.turn.down.right" : "arrow.up.forward.square")
                    .font(.caption)
                    .accessibilityHidden(true)
                Text(entry.setting.name)
                    .multilineTextAlignment(.leading)
                Spacer(minLength: 0)
            }
            .frame(maxWidth: .infinity, alignment: .leading)
            .padding(.vertical, 3)
            .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
        .foregroundStyle(.tint)
        .help(entry.setting.summary)
        // The glyph distinguishes "in this editor" from "elsewhere" visually;
        // VoiceOver needs it in words, and needs the destination for the second.
        .accessibilityLabel(here ? entry.setting.name : "\(entry.setting.name), in \(entry.breadcrumb)")
        .accessibilityHint(here ? "Jump to this setting"
                                : "Opens the editor that has it and jumps to it")
    }
}
