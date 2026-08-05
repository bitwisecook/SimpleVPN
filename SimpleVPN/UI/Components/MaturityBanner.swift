// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
//  MaturityBanner.swift
//  The one way the app says "nobody has proven this yet": a banner where there is
//  room for the paragraph, and a chip where there isn't. Both are pure functions
//  of a `MaturityNotice` (the registry in ControlPlane/), so the wording and
//  the claim live in the registry and this file only draws them. Flipping a kind
//  to tested touches the registry and nothing here.
//
//  WHY IT LOOKS LIKE THIS
//   • Same SHAPE as every other banner in the app (ConnectionBanners.swift):
//     icon, bold line, paragraph, action on the right, 12pt padding, 10pt corner.
//     A third visual idiom for "notice" was not needed and would have cost the
//     user the recognition the other two already earn.
//   • QUIET colour, on purpose. The status/dot vocabulary (`DotState`) is about
//     the CONNECTION — orange means degraded, red means paused-and-leaking, green
//     means connected — and untested code is none of those things. Borrowing
//     orange would say "something is wrong" about a VPN that is working fine.
//     So this reuses the neutral register the enablement banner already
//     established (`.quaternary`, secondary text): informational, not alarming,
//     and unmistakably not a fault.
//   • Colour is never the only carrier anyway: the badge always shows its WORD
//     (“Untested” / “Partly tested”) beside a per-state symbol, so Differentiate
//     Without Color has nothing to fix.
//
//  COLLAPSIBLE, NEVER DISMISSIBLE. Hiding the paragraph is reasonable — you read
//  it once. Hiding the STATE is not: the collapsed form is the badge plus the way
//  back, which is exactly as much as a list row shows. There is no "don't show
//  again" and no close box, and the collapsed flag is per-subject so putting
//  IKEv2's away leaves GlobalProtect's alone.
//
//  ACCESSIBILITY. Content, not decoration, and never hover-only. The banner holds
//  buttons, so it is a `.contain` container whose own label is the whole notice
//  (rule 4 in Docs/Accessibility.md — a row-wide `.combine` would swallow the
//  report button). The chip is `accessibilityHidden` when it sits inside a row
//  that already speaks: its words ride that row's value instead, the same way
//  status dots do. Expanding and collapsing is announced, because the change is
//  otherwise only visible.
//

import SwiftUI

// MARK: - The banner

/// "This hasn't been tested" with room to explain, and the one action that
/// changes the situation: telling us what happened.
struct MaturityBanner: View {
    let notice: MaturityNotice
    /// What the report button asks for. Built by the caller so the request names
    /// the profile it came from; the reason distinguishes a VPN kind from a
    /// sign-in source.
    let request: DiagnosticReportRequest

    @AppStorage private var collapsed: Bool
    @Environment(\.accessibilityReduceMotion) private var reduceMotion

    init(notice: MaturityNotice, request: DiagnosticReportRequest) {
        self.notice = notice
        self.request = request
        // Per-subject, so collapsing one banner says nothing about any other.
        _collapsed = AppStorage(wrappedValue: false, "maturityBannerCollapsed.\(notice.key)")
    }

    var body: some View {
        HStack(alignment: .top, spacing: 10) {
            Image(systemName: notice.symbolName)
                .font(.title3).foregroundStyle(.secondary)
                .accessibilityHidden(true)   // the words carry it
            VStack(alignment: .leading, spacing: 3) {
                if collapsed {
                    // Collapsed is the chip plus what it is ABOUT — exactly as much
                    // as a list row shows, and the "a small badge always remains"
                    // promise kept literally. One line, and never nothing.
                    HStack(spacing: 6) {
                        MaturityBadge(notice: notice)
                        Text(notice.subject).font(.callout)
                    }
                } else {
                    Text(notice.title).font(.callout.weight(.semibold))
                    Text(notice.detail)
                        .font(.callout).foregroundStyle(.secondary)
                        .fixedSize(horizontal: false, vertical: true)
                }
            }
            Spacer(minLength: 8)
            VStack(alignment: .trailing, spacing: 6) {
                if !collapsed {
                    Button("Tell Us What Happened\u{2026}") {
                        DiagnosticReportCoordinator.shared.presentReport(request)
                    }
                    .buttonStyle(.glass)
                    .help("Report whether \(notice.subject) worked \u{2014} that is what gets this notice removed")
                    .accessibilityLabel("Tell us what happened with \(notice.subject)")
                    .accessibilityHint("Opens a report you can send. Saying it worked is as "
                                       + "useful as saying it didn\u{2019}t.")
                    .accessibilityIdentifier("maturity-report-\(notice.key)")
                }
                Button(collapsed ? "Details\u{2026}" : "Hide") {
                    collapsed.toggle()
                    // A collapse or an expand is otherwise only visible, so it is
                    // spoken — and what is spoken is what is now on screen.
                    AccessibilityAnnouncer.sayNow(collapsed ? notice.spokenValue
                                                            : notice.spokenSummary)
                }
                .buttonStyle(.borderless)
                .controlSize(.small)
                .help(collapsed ? "Show what \u{201C}\(notice.badgeText)\u{201D} means here"
                                : "Keep the \u{201C}\(notice.badgeText)\u{201D} label, hide the explanation")
                .accessibilityLabel(collapsed ? "Show the details of this notice"
                                              : "Hide the details of this notice")
                .accessibilityHint("The \u{201C}\(notice.badgeText)\u{201D} label stays either way.")
                .accessibilityIdentifier("maturity-disclose-\(notice.key)")
            }
        }
        .padding(12)
        .background(.quaternary.opacity(0.5), in: RoundedRectangle(cornerRadius: 10))
        .animation(reduceMotion ? nil : .snappy(duration: 0.22), value: collapsed)
        // Holds two buttons: a container with its own sentence, never .combine.
        .accessibilityElement(children: .contain)
        // What is read is what is shown: the clause when collapsed, the whole
        // notice when not.
        .accessibilityLabel(collapsed ? notice.spokenValue : notice.spokenSummary)
        .accessibilityIdentifier("maturity-banner-\(notice.key)")
    }
}

// MARK: - The chip

/// The compact form: a word and a symbol, for a list row or a row title. Small,
/// but never wordless — a symbol alone would be exactly the hover-only failure
/// this app doesn't ship.
struct MaturityBadge: View {
    let notice: MaturityNotice
    /// True (the default) when the badge sits inside a row whose own combined
    /// sentence already says the same thing — then the chip must be hidden, or
    /// VoiceOver says it twice. False when the chip is the only carrier, e.g.
    /// beside a title in a form.
    var spokenElsewhere = true

    var body: some View {
        HStack(spacing: 3) {
            Image(systemName: notice.symbolName).font(.caption2)
            Text(notice.badgeText).font(.caption2.weight(.medium))
        }
        .foregroundStyle(.secondary)
        .padding(.horizontal, 6).padding(.vertical, 2)
        .background(.quaternary.opacity(0.6), in: .capsule)
        .help(notice.spokenSummary)
        .accessibilityElement(children: .combine)
        .accessibilityLabel(notice.badgeText)
        .accessibilityValue(notice.spokenValue)
        // Outermost, so it hides the whole combined element rather than a child.
        .accessibilityHidden(spokenElsewhere)
    }
}

// MARK: - The editor insertion point

/// Puts the banner above an editor's whole `TabView`, keyed by the kind being
/// edited. Applied by `settingsEditor(kind:…)` so the sixteen kinds are served by
/// ONE insertion rather than sixteen edited editor files — and so a kind that
/// switches maturity, or an editor whose Kind picker changes mid-edit (the
/// subprocess and native editors both have one), follows automatically.
struct MaturityBannerScaffold: ViewModifier {
    let kind: VPNKind?
    let profileID: String?

    @ViewBuilder func body(content: Content) -> some View {
        if let kind, let notice = kind.maturityNotice {
            VStack(spacing: 8) {
                MaturityBanner(notice: notice,
                               request: .init(kind: kind, profileID: profileID,
                                              reason: .untestedKind))
                    .padding(.horizontal, 20)
                content
            }
        } else {
            content
        }
    }
}
