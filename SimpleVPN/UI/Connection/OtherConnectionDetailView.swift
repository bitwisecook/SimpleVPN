// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
//  OtherConnectionDetailView.swift
//  THE DETAIL PANE for the connections that are not NE profiles — the subprocess
//  tunnels (SSH and the seven OpenConnect SSL-VPNs) and the native personal VPNs.
//
//  WHY IT EXISTS. Until now these rows could not be selected in the connect list,
//  and were only LISTED while already running (see `ConnectionView`'s history) — so
//  a profile the user had just created could not be found, could not be selected,
//  and could not be connected from the window whose whole job is connecting. This
//  pane is the other half of fixing that: the row now selects, and what it selects
//  says what state the connection is in, what is stopping it, and takes you to the
//  field that fixes it.
//
//  DELIBERATELY SMALL. It is not `ConnectionDetailView` — there is no throughput
//  graph, map or inspector here, because there is no per-flow telemetry behind a
//  subprocess tunnel to draw. What it owns is exactly what the connect window is
//  for: the status, the one action, and the honest reason the action is dead.
//

import SwiftUI

// MARK: - The banner

/// WHAT IS MISSING, AND THE WAY TO IT. The banner the Q4 requirement asks for:
/// never hide a profile the user created — show it, disable the action, explain why,
/// and link to the exact place to fix it.
///
/// The sentence and the destination both come from `ConnectNeed`, which is derived
/// from the same rules the editor's own dead Connect button reads. So this cannot
/// drift into a second opinion about whether a VPN is configured — the divergence
/// that was just removed from the connect path.
///
/// COLOUR CARRIES THE DEGREE, not the whole message. Orange for "it cannot work as
/// set up" and the quieter accent for "it is set up and something has to be
/// supplied" — a missing password is an ordinary state, and dressing it as a fault
/// teaches people to ignore the orange triangle.
struct NotConfiguredBanner: View {
    let vpnName: String
    let need: ConnectNeed
    /// Take me to the field. nil when the need names no single setting (a tool that
    /// isn't installed), in which case no button is offered rather than a dead one.
    let reveal: (() -> Void)?
    /// Open this VPN's own settings — always available, because there is always
    /// somewhere to go even when no one field is at fault.
    let openSettings: () -> Void

    private var isHardProblem: Bool { need.readiness == .blocked }

    private var headline: String {
        isHardProblem ? "\(vpnName) can\u{2019}t connect as it\u{2019}s set up"
                      : "\(vpnName) needs one more thing before it can connect"
    }

    private var tint: Color { isHardProblem ? .orange : .accentColor }

    var body: some View {
        HStack(alignment: .top, spacing: 10) {
            Image(systemName: isHardProblem ? "exclamationmark.triangle.fill" : "pencil.and.list.clipboard")
                .font(.title3).foregroundStyle(tint)
                .accessibilityHidden(true)   // the combined label below says it
            VStack(alignment: .leading, spacing: 3) {
                Text(headline).font(.callout.weight(.semibold))
                Text(need.sentence)
                    .font(.callout).foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }
            Spacer(minLength: 8)
            VStack(spacing: 6) {
                if let reveal {
                    // "Take me to the empty field" — the strong version of the ask.
                    // `SettingReveal` expands the row's section, scrolls it to centre
                    // and highlights it, so this lands somewhere usable rather than
                    // merely opening a window.
                    Button("Fix This\u{2026}", action: reveal)
                        .buttonStyle(.glassProminent)
                        .help("Open the setting that\u{2019}s missing and highlight it")
                        .accessibilityLabel("Fix this")
                        .accessibilityHint("Opens this VPN\u{2019}s settings and highlights the setting that\u{2019}s missing")
                } else {
                    Button("Settings\u{2026}", action: openSettings)
                        .buttonStyle(.glassProminent)
                        .accessibilityLabel("Open \(vpnName) settings")
                }
            }
        }
        .padding(12)
        .background(tint.opacity(0.12), in: RoundedRectangle(cornerRadius: 10))
        // `.contain`: the action must stay reachable (the accessibility rule the
        // other banners in this window follow).
        .accessibilityElement(children: .contain)
        .accessibilityLabel("\(headline). \(need.sentence)")
    }
}

// MARK: - The pane

struct OtherConnectionDetailView: View {
    let name: String
    let kind: VPNKind
    /// Where this connection is, in the ONE status vocabulary (`DotState`), so it
    /// cannot disagree with the sidebar dot or the menu bar.
    let dot: DotState
    let isActive: Bool
    /// What is still missing, or nil when a click connects.
    let need: ConnectNeed?
    /// Anything the engine said last time — a failure message or a caution.
    let engineNote: String?

    let connect: () -> Void
    let stop: () -> Void
    let reveal: (String) -> Void
    let openSettings: () -> Void

    private var maturity: MaturityNotice? { kind.maturityNotice }

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 16) {
                header
                if let need {
                    NotConfiguredBanner(
                        vpnName: name, need: need,
                        reveal: need.settingID.map { id in { reveal(id) } },
                        openSettings: openSettings)
                }
                if let engineNote {
                    Label(engineNote, systemImage: "exclamationmark.circle.fill")
                        .font(.callout).foregroundStyle(.orange)
                        .fixedSize(horizontal: false, vertical: true)
                        .accessibilityLabel("From the connection: \(engineNote)")
                }
                // A kind nobody has proven yet says so here as well as in the
                // sidebar chip: this is the screen somebody is looking at when they
                // decide whether to trust it (availability and maturity are two
                // different axes — ONTOLOGY.md).
                if let maturity {
                    MaturityBadge(notice: maturity)
                }
                Spacer(minLength: 0)
            }
            .padding(20)
            .frame(maxWidth: .infinity, alignment: .leading)
        }
        .navigationTitle(name)
    }

    @ViewBuilder private var header: some View {
        HStack(spacing: 12) {
            StatusDot(state: dot)
                .accessibilityHidden(true)   // spoken through the row below
            VStack(alignment: .leading, spacing: 2) {
                Text(name).font(.title2.weight(.semibold)).lineLimit(1)
                Text("\(kind.displayName) \u{00B7} \(dot.accessibilityDescription)")
                    .font(.callout).foregroundStyle(.secondary)
            }
            .accessibilityElement(children: .combine)
            .accessibilityLabel("\(name), \(kind.displayName), \(dot.accessibilityDescription)")
            Spacer(minLength: 12)
            action
        }
    }

    @ViewBuilder private var action: some View {
        if isActive {
            Button("Disconnect", action: stop)
                .buttonStyle(.bordered).tint(.red)
                // NAMED WITH THE CONNECTION, like the sidebar's per-row controls and
                // unlike the detail header of an NE profile. That difference is
                // load-bearing: `VPNCommands`' VPN ▸ Disconnect acts on the SELECTED
                // NE PROFILE and cannot stop a subprocess tunnel, so a bare
                // "Disconnect" here would claim the menu item's scope while meaning
                // something else (VoiceOverWalkthroughTests step 8 reads exactly that
                // distinction).
                .accessibilityLabel("Disconnect \(name)")
                .accessibilityValue(dot.accessibilityDescription)
        } else {
            // DISABLED, NEVER ABSENT. An absent button is indistinguishable from a
            // broken layout — and the reason rides `.help` and the accessibility
            // value, so a dead control always says why (AGENTS.md rule 4).
            Button("Connect", action: connect)
                .buttonStyle(.glassProminent)
                .disabled(need != nil)
                .accessibilityLabel("Connect \(name)")
                .help(need?.sentence ?? "Connect \(name)")
                // The status word from the ONE vocabulary first, then the reason —
                // every Connect control in this window reports the live state in its
                // value, and `ConnectNeed.spokenValue` is the single place that
                // sentence is composed.
                .accessibilityValue(need?.spokenValue ?? dot.accessibilityDescription)
        }
    }
}
