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

// MARK: - The paragraph, and the floor under it

/// THE EXPLANATORY PARAGRAPH IN A BANNER — and the one place the floor under its
/// width is stated, because the floor is what stops a banner emptying a window.
///
/// THE BUG THIS EXISTS TO KILL (`EditorPaneHeightTests`). `fixedSize(horizontal:
/// false, vertical: true)` means "be as tall as this paragraph needs at whatever
/// width you are given" — right on screen, and a trap off it. SwiftUI measures the
/// two axes independently, so the MINIMUM-height query arrives with a width proposal
/// of nearly nothing, and a paragraph that is never drawn narrower than 500 points
/// answers with its height at ONE WORD PER LINE. For the F5 BIG-IP APM notice that
/// was 4,527 points.
///
/// That number reached the window because these banners are mounted OUTSIDE the
/// editor's scroll container — `MaturityBannerScaffold` puts one above the whole
/// `TabView`, which is the point of it — so the paragraph's minimum height is the
/// minimum height of the entire detail pane. `NavigationSplitView` gives both of its
/// columns the same height, a 4,627pt column in a 612pt window is laid out CENTRED,
/// and every row of the Manage VPNs sidebar ended up about 1,800 points above the top
/// of the window: blank, unscrollable, and persisted by AppKit into the split view's
/// saved subview frames so that reopening the window brought it straight back.
///
/// A FLOOR ON THE WIDTH IS THE HONEST FIX, because it states something that is true:
/// this paragraph is never drawn in a column narrower than this. The narrowest window
/// that shows one is 760 points wide less a 200pt sidebar, so the floor is never
/// reached in a real layout and nothing on screen moves — it only answers the
/// measuring question sensibly.
struct NoticeParagraph: View {
    let text: String
    /// `.callout` for the explanation, `.caption` for the smaller line under it.
    /// A parameter rather than a second view, because the FLOOR is the whole point
    /// of this type: a second paragraph styled by hand would reintroduce the bug
    /// above at one font size down.
    var font: Font = .callout

    /// The narrowest column this paragraph is ever measured for. Not a design
    /// decision about line length — a statement about the smallest editor pane the
    /// app can produce, kept well below it so this can never clip anything.
    static let minimumWidth: CGFloat = 320

    var body: some View {
        Text(text)
            .font(font).foregroundStyle(.secondary)
            .fixedSize(horizontal: false, vertical: true)
            .frame(minWidth: Self.minimumWidth, alignment: .leading)
    }
}

// MARK: - What the two buttons in a notice banner do

/// THE LINE THAT SAYS WHAT CLICKING DOES, shared by both banners because both have
/// the same two buttons.
///
/// WHY IT IS ON SCREEN rather than in a tooltip. Reported as: "there was some sort
/// of banner at the top about untested, it wasn't clear, i clicked on it, it scrolled
/// to the bottom". Everything that answered "what happens if I click this" lived in
/// `.help` and in an accessibility hint — i.e. nowhere, for the person who clicks
/// first. The sentence a reader needs before clicking is that NEITHER button touches
/// the VPN: one folds the explanation away and keeps the label, the other opens a
/// report they can read before it is sent.
///
/// `label` is the report button's own title, passed in rather than repeated, so the
/// sentence can never name a button that isn't there.
struct NoticeActionsCaption: View {
    /// The disclosure button's title, e.g. "Hide Details".
    let hideTitle: String
    /// The report button's title, without its ellipsis.
    let reportTitle: String
    /// What stays behind after the explanation is folded away, as a noun phrase —
    /// the badge word for a maturity notice, the notice line itself for the other.
    let keeps: String

    /// The one sentence, also used as this caption's spoken form so VoiceOver hears
    /// exactly what is on screen.
    var sentence: String {
        "Neither button changes this VPN: \u{201C}\(hideTitle)\u{201D} folds this explanation away "
            + "and keeps \(keeps), and \u{201C}\(reportTitle)\u{201D} opens a report you can read "
            + "and edit before anything is sent."
    }

    var body: some View {
        NoticeParagraph(text: sentence, font: .caption)
    }
}

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

    /// The button titles, written once, so the on-screen sentence that says what each
    /// button does and the buttons themselves cannot drift apart.
    static let reportTitle = "Tell Us What Happened"
    static let showTitle = "Show Details"
    static let hideTitle = "Hide Details"

    /// The "neither button changes this VPN" line, for the screen and for VoiceOver.
    private var actionsCaption: NoticeActionsCaption {
        NoticeActionsCaption(hideTitle: Self.hideTitle, reportTitle: Self.reportTitle,
                             keeps: "the \u{201C}\(notice.badgeText)\u{201D} label")
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
                    NoticeParagraph(text: notice.detail)
                    // Says what clicking does, on screen — see NoticeActionsCaption.
                    actionsCaption
                }
            }
            Spacer(minLength: 8)
            VStack(alignment: .trailing, spacing: 6) {
                if !collapsed {
                    Button("\(Self.reportTitle)\u{2026}") {
                        DiagnosticReportCoordinator.shared.presentReport(request)
                    }
                    .buttonStyle(.glass)
                    .help("Report whether \(notice.subject) worked \u{2014} that is what gets this notice removed")
                    .accessibilityLabel("Tell us what happened with \(notice.subject)")
                    .accessibilityHint("Opens a report you can read and edit before sending. Saying "
                                       + "it worked is as useful as saying it didn\u{2019}t.")
                    .accessibilityIdentifier("maturity-report-\(notice.key)")
                }
                // "Details…" promised a dialog (an ellipsis means "more input is
                // needed") and "Hide" did not say WHAT it hid — which is the button
                // that got clicked when the banner "wasn't clear". Both now name the
                // thing they show and fold away.
                Button(collapsed ? Self.showTitle : Self.hideTitle) {
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
        // notice PLUS the what-the-buttons-do line when not.
        .accessibilityLabel(collapsed ? notice.spokenValue
                                      : "\(notice.spokenSummary) \(actionsCaption.sentence)")
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

// MARK: - "We don't do this" — the same shape, a different claim

/// The banner for a capability SimpleVPN does NOT implement
/// (`FeatureRequestNotice`), asking for the use case.
///
/// WHY IT IS A SEPARATE VIEW rather than a `MaturityBanner` with different strings:
/// `MaturityBanner` draws a `MaturityNotice`, and every `MaturityNotice` carries a
/// maturity whose badge word says the code is THERE and merely unproven. Handing
/// this subject to that view would put "nobody has confirmed smartcard sign-in
/// working yet" on screen, which is a promise that there is something to confirm.
/// (The registry that owns those words is deliberately not named here — this file
/// draws notices and decides nothing.)
///
/// Everything else is deliberately identical — the same icon/bold-line/paragraph/
/// action-on-the-right layout, the same 12pt padding and 10pt corner, the same quiet
/// `.quaternary` register, the same collapse-but-never-dismiss rule, the same
/// `.contain` accessibility container holding two buttons. A third visual idiom for
/// "notice" would cost the recognition the other two already earn.
///
/// THE ACTION IS THE EXISTING FEEDBACK FLOW: the same `DiagnosticReportCoordinator`
/// dialog, with a `Reason` that asks for the use case. There is no second submission
/// path and nothing is sent without being read.
struct FeatureRequestBanner: View {
    let notice: FeatureRequestNotice
    /// Which VPN this was reached from, so the report says which kind of gateway is
    /// involved without the reporter having to describe it.
    var kind: VPNKind?
    var profileID: String?

    @AppStorage private var collapsed: Bool
    @Environment(\.accessibilityReduceMotion) private var reduceMotion

    init(notice: FeatureRequestNotice, kind: VPNKind? = nil, profileID: String? = nil) {
        self.notice = notice
        self.kind = kind
        self.profileID = profileID
        // Per-subject, so putting the smartcard one away says nothing about the other.
        _collapsed = AppStorage(wrappedValue: false, "featureRequestBannerCollapsed.\(notice.key)")
    }

    /// Same three titles as `MaturityBanner`, for the same reason — the sentence that
    /// says what clicking does names them, so they are written once.
    static let reportTitle = "Tell Us What You Need"
    static let showTitle = MaturityBanner.showTitle
    static let hideTitle = MaturityBanner.hideTitle

    /// What stays behind here is the notice line itself, not a badge word — the
    /// collapsed form still states the absence.
    private var actionsCaption: NoticeActionsCaption {
        NoticeActionsCaption(hideTitle: Self.hideTitle, reportTitle: Self.reportTitle,
                             keeps: "the notice itself")
    }

    var body: some View {
        HStack(alignment: .top, spacing: 10) {
            Image(systemName: notice.symbolName)
                .font(.title3).foregroundStyle(.secondary)
                .accessibilityHidden(true)   // the words carry it
            VStack(alignment: .leading, spacing: 3) {
                if collapsed {
                    // Collapsed still states the ABSENCE. Hiding the paragraph is
                    // reasonable; hiding "SimpleVPN doesn't do this" is not, because
                    // that is the fact somebody came to the row to learn.
                    Text(notice.title).font(.callout)
                } else {
                    Text(notice.title).font(.callout.weight(.semibold))
                    NoticeParagraph(text: notice.detail)
                    // Says what clicking does, on screen — see NoticeActionsCaption.
                    actionsCaption
                }
            }
            Spacer(minLength: 8)
            VStack(alignment: .trailing, spacing: 6) {
                if !collapsed {
                    // "Tell Us What You Need" rather than "Request This Feature": the
                    // button asks for a situation, and its label should not read as a
                    // queue somebody is joining.
                    Button("\(Self.reportTitle)\u{2026}") {
                        DiagnosticReportCoordinator.shared.presentReport(
                            .init(kind: kind, profileID: profileID, reason: notice.reason))
                    }
                    .buttonStyle(.glass)
                    .help("Describe what your gateway requires \u{2014} that is what this decision turns on")
                    .accessibilityLabel("Describe what you need from \(notice.subject)")
                    .accessibilityHint("Opens a report you can read and edit before sending. "
                                       + "Nothing is promised in return.")
                    .accessibilityIdentifier("feature-request-\(notice.key)")
                }
                Button(collapsed ? Self.showTitle : Self.hideTitle) {
                    collapsed.toggle()
                    AccessibilityAnnouncer.sayNow(collapsed ? notice.title : notice.spokenSummary)
                }
                .buttonStyle(.borderless)
                .controlSize(.small)
                .help(collapsed ? "Show why, and how to ask for it"
                                : "Keep the notice, hide the explanation")
                .accessibilityLabel(collapsed ? "Show the details of this notice"
                                              : "Hide the details of this notice")
                .accessibilityIdentifier("feature-request-disclose-\(notice.key)")
            }
        }
        .padding(12)
        .background(.quaternary.opacity(0.5), in: RoundedRectangle(cornerRadius: 10))
        .animation(reduceMotion ? nil : .snappy(duration: 0.22), value: collapsed)
        .accessibilityElement(children: .contain)
        .accessibilityLabel(collapsed ? notice.title
                                      : "\(notice.spokenSummary) \(actionsCaption.sentence)")
        .accessibilityIdentifier("feature-request-banner-\(notice.key)")
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
