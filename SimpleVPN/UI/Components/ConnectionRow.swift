// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
//  ConnectionRow.swift
//  THE ONE SIDEBAR ROW — its metrics, its caption rule, its one spoken sentence, and
//  the non-interactive layout that assembles them.
//
//  WHY IT EXISTS. Two windows list the same connections, and until now they did it with
//  FOUR row builders: `VPNSidebarRow` and `ConnectionView.otherConnectionRow` in the main
//  window, and `profileRow` / `tunnelRow` / `nativeRow` in Manage VPNs. `7df48eb` merged
//  the main window's two sections into one and said so in its own note — "lifted into
//  profileRow/tunnelRow/nativeRow verbatim, no layout restructure" — so Manage VPNs kept
//  three row shapes under a heading that no longer divides them. What the user saw, in one
//  section, was: two icon styles (a logo badge on one row, a bare kind glyph on the next),
//  two row heights, a subtitle on some rows and not others, a status dot in two different
//  places, and a maturity chip squeezed to "Untest…". (Neither the badge word nor the
//  maturity type is spelled out even in these comments — a sibling structural guard,
//  `noViewContainsAMaturityDecision`, forbids both in a view source so that flipping a
//  kind to tested can never need a view edit.)
//
//  Every one of those is the same defect: a shared thing written out five times drifts.
//  `Docs/Drift.md` is the register of every such pair in this repo and what was decided
//  about each; `SidebarRowDisciplineTests` fails when a sixth row builder appears.
//
//  THE DECOMPOSITION, and why it is three pieces rather than one view. A row that carries
//  live transport controls (`VPNSidebarRow`: play / pause / stop, and an endpoint picker
//  in place of its caption) genuinely cannot be the same VIEW as a configuration row that
//  carries none — forcing it would mean a builder with an empty-closure escape hatch,
//  which is how the last unification came apart. So what is shared is what actually
//  drifted:
//
//   * `ConnectionRowMetrics` — the numbers. One section is one list only if every row in
//     it is the same height.
//   * `ConnectionRowCaption` — what the line under the name says, INCLUDING when it says
//     nothing. A native VPN created from the + menu is named after its kind, so a caption
//     of `c.kind.displayName` rendered "IKEv2" under "IKEv2".
//   * `ConnectionRowSentence` — the row as one sentence for VoiceOver, from `DotState`
//     rather than from a word typed at the call site (Docs/Accessibility.md: the dot is
//     hidden everywhere, so its state reaches VoiceOver only here).
//   * `ConnectionRowLayout` — the assembled non-interactive row, for every list that has
//     no transport control in it.
//

import SwiftUI
import NetworkExtension

// MARK: - The numbers

/// THE SIDEBAR ROW'S METRICS. One section is one list only when every row in it is the
/// same height, and the height is set by the badge and the padding rather than by the
/// text. Read by `ConnectionRowLayout` and by `VPNSidebarRow`, which draws its own layout
/// (it holds controls) but must not have its own size.
nonisolated enum ConnectionRowMetrics {
    /// Badge to text, and text to the trailing column.
    static let spacing: CGFloat = 10
    /// The logo badge's frame. `LogoBadge` draws a 22pt tile, so it is scaled up to fill
    /// this rather than redrawn at a second size.
    static let badgeSide: CGFloat = 26
    static let badgeScale: CGFloat = 1.15
    /// The gap the name is allowed to shrink to before the trailing column gives ground.
    static let gutter: CGFloat = 6
    static let verticalPadding: CGFloat = 6
    /// The row height every list in the app agrees on.
    static let minHeight: CGFloat = 52
}

// MARK: - The line under the name

/// WHAT A ROW SAYS UNDER ITS NAME — and, as often, that it says nothing.
///
/// Three rules, and the third is the one that was missing:
///
///  1. The kind, because the section headings no longer carry it. "Whole-Mac VPNs" answers
///     what connecting the row DOES (`ConnectionScope`); which of the sixteen kinds it is
///     is now the row's job to say, and Manage VPNs is exactly where somebody is choosing
///     which VPN to set up next.
///  2. Then the one fact the heading cannot give: a local port's actual port
///     (`ConnectListing.portSummary`), or a failure.
///  3. **Never a caption that only repeats the name.** `newNative(_:)` and `newTunnel(_:)`
///     name a fresh VPN after its kind, so "IKEv2 / IKEv2" and "SSH / SSH" were the
///     commonest rows in the list. A line that repeats the line above it is not a subtitle,
///     it is noise, and it made the rows that DID carry a port harder to spot.
nonisolated enum ConnectionRowCaption {

    /// The ordinary caption: the kind, and any fact worth the space. `nil` when the kind
    /// is all there is and the name already said it.
    static func of(name: String, kind: VPNKind, fact: String? = nil) -> String? {
        let fact = fact?.trimmingCharacters(in: .whitespaces)
        let kindName = kind.displayName
        if fact == nil || fact?.isEmpty == true {
            // Rule 3. Compared case- and whitespace-insensitively because the name is
            // the user's to edit and "ikev2" is the same claim as "IKEv2".
            let trimmed = name.trimmingCharacters(in: .whitespaces)
            if trimmed.caseInsensitiveCompare(kindName) == .orderedSame { return nil }
            return kindName
        }
        return "\(kindName) \u{00B7} \(fact!)"
    }

    /// The caption for a row with something wrong with it. ALWAYS shown, even when it
    /// would repeat the name: rule 3 exists to remove noise, and a problem is never noise.
    static func problem(kind: VPNKind, _ text: String) -> String {
        "\(kind.displayName) \u{00B7} \(text)"
    }
}

// MARK: - The row as one sentence

/// THE ROW'S ONE SPOKEN SENTENCE — "Tig Lab, OpenVPN, connected, Lab", plus the maturity
/// clause when the kind carries one.
///
/// `Docs/Accessibility.md` requires a row to read as one sentence rather than five
/// fragments, and every status dot in this app is `accessibilityHidden` — so this is the
/// only route by which a dot's state reaches VoiceOver. It takes a `DotState` and not a
/// `String` on purpose: the state must come from the ONE status vocabulary, and a
/// parameter that cannot hold a hand-typed word is a stronger guarantee than a rule
/// nobody re-reads. `SidebarRowDisciplineTests` holds every row builder to calling this.
///
/// THE ORDER IS FIXED, because it is what a person arrowing down a list hears repeatedly:
/// name, kind, the row's own fact, its live state, any note about that state, the user's
/// labels, and — last, because it is the least urgent — whether the kind is proven.
/// (Not `nonisolated`: `DotState` lives with the rest of the status language in
/// `ContentView.swift`, under the app target's `MainActor` default. Taking the enum is
/// worth more than being callable off the main actor.)
enum ConnectionRowSentence {

    /// `stateInWords` is for the one row that knows MORE than its dot does: the main
    /// window's, whose "Paused — traffic outside VPN", "Sign-in needed" and "applying
    /// changes" are states `DotState` has no case for. It must still come from the status
    /// vocabulary (`VPNController.statusText`, `ConnectNeed.statusWord`,
    /// `DotState.accessibilityDescription`) and never be a phrase invented at the call
    /// site — passing `nil`, which every other row does, makes that impossible.
    /// `kind` is optional for the one row that has none: a COMPOSITION is a group of VPNs
    /// rather than a connection, so it has no kind and no maturity — but it is still a row
    /// in the same sidebar, and it still has to read as one sentence in the same order.
    static func make(name: String,
                     kind: VPNKind?,
                     fact: String? = nil,
                     dot: DotState,
                     stateInWords: String? = nil,
                     notes: [String] = [],
                     labels: [String] = [],
                     maturity: MaturityNotice? = nil) -> String {
        var bits = [name]
        if let kind { bits.append(kind.displayName) }
        if let fact, !fact.isEmpty { bits.append(fact) }
        bits.append(stateInWords.flatMap { $0.isEmpty ? nil : $0 }
                    ?? dot.accessibilityDescription)
        bits.append(contentsOf: notes.filter { !$0.isEmpty })
        bits.append(contentsOf: labels.filter { !$0.isEmpty })
        if let maturity, !maturity.spokenValue.isEmpty { bits.append(maturity.spokenValue) }
        return bits.joined(separator: ", ")
    }
}

// MARK: - The assembled row

/// THE NON-INTERACTIVE SIDEBAR ROW: badge, name, caption, labels, maturity chip, and
/// whatever warning accessories the list adds on the trailing edge.
///
/// THE BADGE IS THE SAME FOR EVERY KIND, and that is a naming decision rather than a
/// cosmetic one. Manage VPNs used to draw `LogoBadge` for an NE profile and a bare
/// `Image(systemName: kind.systemImage)` for a subprocess tunnel or a native VPN — which
/// is our transport split showing through the icons after it had been taken out of the
/// headings (ONTOLOGY.md rule 1: we do not name, or draw, things after the implementation
/// that happens to serve them). One badge, and the fallback glyph is the KIND's, so a row
/// with no logo says what it is instead of showing a globe that says nothing.
///
/// THE DOT HAS ONE POSITION: inside the badge, bottom-trailing. It used to be there for
/// profiles and a separate leading `StatusDot` for everything else, so one section showed
/// the same state in two places.
///
/// THE ACCESSORY IS OUTSIDE THE COMBINED ELEMENT, deliberately: `.combine` flattens its
/// children, so an interactive accessory inside it would stop being reachable. Everything
/// the combine covers is text or is `accessibilityHidden`.
struct ConnectionRowLayout<Accessory: View>: View {
    /// The id a logo is stored under — a profile id, or a tunnel/native config id (NOT the
    /// prefixed sidebar tag).
    let id: String
    let name: String
    let kind: VPNKind
    /// Only for `LogoBadge`'s own fallback; `dot` is what is actually drawn.
    var status: NEVPNStatus = .disconnected
    let dot: DotState
    var caption: String?
    /// Whether the caption is a problem rather than a description — amber instead of grey.
    var captionIsProblem = false
    var labels: [LabelDef] = []
    /// Anything the spoken sentence must carry that the caption does not (a failure's own
    /// words, "owns the default route").
    var spokenNotes: [String] = []
    /// The state in words for a focused row, when the list has one to give.
    var spokenValue: String = ""
    @ViewBuilder var accessory: () -> Accessory

    private var maturityNotice: MaturityNotice? { kind.maturityNotice }

    var body: some View {
        HStack(spacing: ConnectionRowMetrics.spacing) {
            HStack(spacing: ConnectionRowMetrics.spacing) {
                LogoBadge(id: id, status: status, dotState: dot,
                          fallbackSymbol: kind.systemImage)
                    .scaleEffect(ConnectionRowMetrics.badgeScale)
                    .frame(width: ConnectionRowMetrics.badgeSide,
                           height: ConnectionRowMetrics.badgeSide)

                VStack(alignment: .leading, spacing: 2) {
                    Text(name).lineLimit(1).truncationMode(.tail)
                    if let caption {
                        Text(caption).font(.caption).lineLimit(1)
                            .foregroundStyle(captionIsProblem ? AnyShapeStyle(.orange)
                                                              : AnyShapeStyle(.secondary))
                    }
                    if !labels.isEmpty {
                        HStack(spacing: 4) { ForEach(labels) { LabelPill(label: $0) } }
                    }
                }

                Spacer(minLength: ConnectionRowMetrics.gutter)

                // `.fixedSize()` IS THE FIX FOR "Untest…". Both the name and the chip hold
                // flexible `Text`, so in a 200pt sidebar SwiftUI compressed whichever it
                // liked and it chose the chip — leaving a five-character stub of a word
                // whose entire job is to invite a report on a VPN kind nobody has tried.
                // The name truncates instead (it has `.truncationMode(.tail)` and a person
                // can still recognise their own VPN from its first characters); the chip
                // never does.
                if let maturityNotice {
                    MaturityBadge(notice: maturityNotice).fixedSize()
                }
            }
            // One element, one sentence — the badge and the chip are hidden, so this is
            // where everything they show reaches VoiceOver.
            .accessibilityElement(children: .combine)
            .accessibilityLabel(ConnectionRowSentence.make(
                name: name, kind: kind, fact: caption.flatMap { stripKind($0) },
                dot: dot, notes: spokenNotes,
                labels: labels.map(\.name), maturity: maturityNotice))
            .accessibilityValue(spokenValue)

            accessory()
        }
        .padding(.vertical, ConnectionRowMetrics.verticalPadding)
        .frame(minHeight: ConnectionRowMetrics.minHeight)
    }

    /// The caption without its leading kind name — the sentence says the kind itself, and
    /// hearing "F5 BIG-IP APM, F5 BIG-IP APM · SOCKS on 127.0.0.1:1080" is the fragmenting
    /// this element exists to stop. Returns nil when the caption was only the kind.
    private func stripKind(_ caption: String) -> String? {
        let prefix = kind.displayName + " \u{00B7} "
        guard caption.hasPrefix(prefix) else {
            return caption == kind.displayName ? nil : caption
        }
        return String(caption.dropFirst(prefix.count))
    }
}

extension ConnectionRowLayout where Accessory == EmptyView {
    /// A row with nothing on its trailing edge.
    init(id: String, name: String, kind: VPNKind, status: NEVPNStatus = .disconnected,
         dot: DotState, caption: String? = nil, captionIsProblem: Bool = false,
         labels: [LabelDef] = [], spokenNotes: [String] = [], spokenValue: String = "") {
        self.init(id: id, name: name, kind: kind, status: status, dot: dot,
                  caption: caption, captionIsProblem: captionIsProblem, labels: labels,
                  spokenNotes: spokenNotes, spokenValue: spokenValue) { EmptyView() }
    }
}
