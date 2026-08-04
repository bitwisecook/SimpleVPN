// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
//  CrossLinks.swift
//  The house idiom for "the thing this sentence is about lives over there".
//
//  A config audit turned up eleven places where the app named a destination in
//  prose and left the user to find it: "Enter its password in Options ▸ Sign-In",
//  "install it with: brew install openconnect", "approve it in System Settings ▸
//  General ▸ Login Items & Extensions", "they still have to be approved on the
//  admin page". Every one of those is an instruction the app could simply carry
//  out. These are the four shapes that turn them into controls:
//
//   • `TabJumpLink`      — another tab of the same editor.
//   • `WindowJumpLink`   — another window of the app (Routes).
//   • `SystemSettingsLink` — a System Settings pane, by x-apple.systempreferences.
//   • `CopyCommandLink`  — a shell command a non-terminal user can't type from a
//                          screenshot of a caption.
//
//  All four are plain-styled tinted labels, not buttons with borders: they sit in
//  captions and section footers, where a bordered button would read as the
//  section's primary action.
//

import SwiftUI
import AppKit

/// The one visual treatment for every cross-link below.
private struct CrossLinkLabel: View {
    let title: String
    let systemImage: String
    var body: some View {
        Label(title, systemImage: systemImage)
            .font(.callout)
            .multilineTextAlignment(.leading)
            .fixedSize(horizontal: false, vertical: true)
            .frame(maxWidth: .infinity, alignment: .leading)
            .contentShape(Rectangle())
    }
}

/// Jump to a specific SETTING — on this tab, another tab of this editor, or
/// another editor entirely. The caller names the id and nothing else: the editor's
/// `SettingsSearch` reveals it if it holds it (and `SettingsEditorShell` selects
/// the tab it lives on), otherwise `SettingsRouter` opens the editor that does.
/// One control for every "that setting is over there" link in the app.
struct SettingJumpLink: View {
    let title: String
    let settingID: String
    var systemImage = "arrow.up.forward.square"
    /// Spoken form when the visible title is a sentence with punctuation a screen
    /// reader shouldn't have to interpret.
    var accessibilityLabel: String? = nil

    @Environment(SettingsSearch.self) private var search: SettingsSearch?
    @Environment(SettingsRouter.self) private var router: SettingsRouter?

    var body: some View {
        Button {
            if search?.reveal(id: settingID) != true { router?.go(to: settingID) }
        } label: {
            CrossLinkLabel(title: title, systemImage: systemImage)
        }
        .buttonStyle(.plain)
        .foregroundStyle(.tint)
        .help(AllSettings.byID[settingID]?.setting.summary ?? title)
        .accessibilityLabel(accessibilityLabel ?? title)
        .accessibilityHint("Jumps to that setting")
    }
}

/// The Traffic group's own cross-links, in every editor: the Custom Routing tab
/// (which rewrites exactly what this group produces) and the Routes window (which
/// shows what actually ended up installed). Plus the gateway role, because
/// "does this VPN carry everything right now" is the question a Traffic group
/// answers only in theory.
struct TrafficCrossLinks: View {
    /// "This VPN carries all traffic right now." — nil when not connected, or when
    /// the kind can never own the default route (GatewayPolicy decides that, and
    /// claiming otherwise would be worse than saying nothing).
    var gatewayNote: String? = nil

    var body: some View {
        VStack(alignment: .leading, spacing: 6) {
            if let gatewayNote {
                Label(gatewayNote, systemImage: "arrow.triangle.branch")
                    .font(.callout).foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }
            SettingJumpLink(title: "Custom Routing \u{2014} change the routes and DNS this VPN offers",
                            settingID: "cr.route-rule",
                            systemImage: "arrow.triangle.branch",
                            accessibilityLabel: "Custom Routing: change the routes and DNS this VPN offers")
            WindowJumpLink(title: "Routes \u{2014} see what this VPN actually installed",
                           windowID: "routes", systemImage: "point.topleft.down.to.point.bottomright.curvepath",
                           accessibilityLabel: "Routes: see what this VPN actually installed")
        }
    }
}

/// Open one of the app's own windows (Routes, the manual, Network Tools).
struct WindowJumpLink: View {
    let title: String
    let windowID: String
    var systemImage = "arrow.up.forward.square"
    var accessibilityLabel: String? = nil

    @Environment(\.openWindow) private var openWindow

    var body: some View {
        Button {
            openWindow(id: windowID)
        } label: {
            CrossLinkLabel(title: title, systemImage: systemImage)
        }
        .buttonStyle(.plain)
        .foregroundStyle(.tint)
        .help(title)
        .accessibilityLabel(accessibilityLabel ?? title)
        .accessibilityHint("Opens that window")
    }
}

/// Open a System Settings pane. The URLs are Apple's own
/// `x-apple.systempreferences:` scheme; `SystemSettingsPane` keeps the handful
/// this app needs in one place rather than as string literals in six views.
struct SystemSettingsLink: View {
    let title: String
    let pane: SystemSettingsPane
    var systemImage = "gearshape"
    var accessibilityLabel: String? = nil

    var body: some View {
        Button {
            pane.open()
        } label: {
            CrossLinkLabel(title: title, systemImage: systemImage)
        }
        .buttonStyle(.plain)
        .foregroundStyle(.tint)
        .help(title)
        .accessibilityLabel(accessibilityLabel ?? title)
        .accessibilityHint("Opens System Settings")
    }
}

/// The System Settings panes this app sends people to. Deep links, not
/// directions: "System Settings ▸ General ▸ Login Items & Extensions ▸ Network
/// Extensions" is four levels of navigation to describe and one click to do.
enum SystemSettingsPane {
    /// General ▸ Login Items & Extensions — where the system extension and
    /// Tailscale's own login item are approved.
    case loginItems
    /// Network ▸ VPN — where an installed L2TP configuration profile appears,
    /// and where its unexported options (crypto, on-demand) have to be set.
    case networkVPN
    /// Privacy & Security ▸ Profiles — where a just-installed .mobileconfig is
    /// reviewed and approved.
    case profiles

    var url: URL? {
        switch self {
        case .loginItems:
            URL(string: "x-apple.systempreferences:com.apple.LoginItems-Settings.extension")
        case .networkVPN:
            URL(string: "x-apple.systempreferences:com.apple.Network-Settings.extension")
        case .profiles:
            URL(string: "x-apple.systempreferences:com.apple.settings.PrivacySecurity.extension?Profiles")
        }
    }

    func open() {
        if let url { NSWorkspace.shared.open(url) }
    }
}

/// Copy a shell command to the clipboard. The install hints ("Install with: brew
/// install openconnect") were text in a caption — readable, and unusable to
/// anyone who doesn't already live in a terminal, because there was nothing to
/// click and nothing to copy without selecting the right half of a sentence.
struct CopyCommandLink: View {
    let command: String
    var title = "Copy Install Command"

    @State private var copied = false

    var body: some View {
        Button {
            NSPasteboard.general.clearContents()
            NSPasteboard.general.setString(command, forType: .string)
            copied = true
            Task { @MainActor in
                try? await Task.sleep(for: .seconds(2))
                copied = false
            }
        } label: {
            // The confirmation is the point: a copy that changes nothing on
            // screen reads as one that didn't happen (the Save→Saved rule).
            Label(copied ? "Copied" : title,
                  systemImage: copied ? "checkmark" : "doc.on.doc")
                .font(.callout)
        }
        .buttonStyle(.plain)
        .foregroundStyle(.tint)
        .help("Copy \u{201C}\(command)\u{201D} to the clipboard, then paste it into Terminal")
        .accessibilityLabel(copied ? "Copied \(command)" : "\(title): \(command)")
    }
}
