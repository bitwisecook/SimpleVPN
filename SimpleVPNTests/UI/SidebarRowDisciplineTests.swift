// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
//  SidebarRowDisciplineTests.swift
//  ONE SIDEBAR ROW — its metrics, its caption rule, its spoken sentence and its dot's
//  position. `Docs/Drift.md` §3 is the story; this is the part of it that fails a build.
//
//  WHAT WENT WRONG, so a future reader knows what these are protecting. `7df48eb` merged
//  the main window's two SECTIONS — "VPNs" and "Other Connections", which was our
//  transport split showing through the headings — into scopes a person can check against
//  their own Mac. It scoped itself to regrouping and said so: Manage VPNs' three row
//  builders were "lifted into profileRow/tunnelRow/nativeRow verbatim, no layout
//  restructure". So the headings stopped dividing rows by transport and the ROWS carried
//  on doing it: under one heading, a logo badge on one row and a bare kind glyph on the
//  next, two heights, a dot in two places, a subtitle on some rows only, and a maturity
//  chip squeezed to "Untest…".
//
//  Every one of those is invisible in a screenshot of the row you are looking at and
//  obvious in the one beside it, which is why these walk the SOURCE — the property at
//  stake is how a row is CONSTRUCTED, and a `View`'s body cannot be enumerated without
//  building and driving the whole hierarchy (the idiom `SettingAlignmentTests` and
//  `RuleListReachabilityTests` established).
//

import Foundation
import Testing
@testable import SimpleVPN

@MainActor
struct SidebarRowDisciplineTests {

    // MARK: The caption rule — the one piece that is a pure function

    /// A caption that only repeats the name is not a subtitle, it is noise. `newNative(_:)`
    /// and `newTunnel(_:)` name a fresh VPN after its kind, so "IKEv2" under "IKEv2" was
    /// the commonest row in the list — and it made the rows that DID carry a port harder
    /// to spot, which is the opposite of what a caption is for.
    @Test func aCaptionThatWouldOnlyRepeatTheNameIsNotDrawn() {
        #expect(ConnectionRowCaption.of(name: "IKEv2", kind: .ikev2) == nil)
        // The name is the user's to edit, so the comparison ignores case and padding.
        #expect(ConnectionRowCaption.of(name: "  ikev2 ", kind: .ikev2) == nil)
        // …and a name of their own gets the kind, because the section heading no longer
        // says which of the sixteen kinds this is.
        #expect(ConnectionRowCaption.of(name: "Work VPN", kind: .ikev2) == "IKEv2")
    }

    /// The suppression is about repetition ONLY. A row with a fact to give says both, even
    /// when the name repeats the kind — the fact is why the caption exists.
    @Test func aFactIsAlwaysWorthTheLineEvenWhenTheNameRepeatsTheKind() {
        let caption = ConnectionRowCaption.of(name: "SSH", kind: .ssh,
                                              fact: "SOCKS on 127.0.0.1:1080")
        #expect(caption == "SSH \u{00B7} SOCKS on 127.0.0.1:1080")
        // An empty or whitespace fact is not a fact.
        #expect(ConnectionRowCaption.of(name: "SSH", kind: .ssh, fact: "  ") == nil)
    }

    /// A problem is NEVER suppressed. The repetition rule exists to remove noise, and
    /// something wrong with a connection is never noise.
    @Test func aProblemCaptionIsShownEvenWhenItRepeatsTheName() {
        #expect(ConnectionRowCaption.problem(kind: .ikev2, "Not configured")
                == "IKEv2 \u{00B7} Not configured")
    }

    // MARK: The spoken sentence — one order, from the status vocabulary

    /// A person arrowing down a list hears this shape over and over, so every row in the
    /// list has to use the same one. Four row builders each joined their own bits in their
    /// own order before this existed.
    @Test func theRowSentenceIsNameKindFactStateLabelsMaturity() {
        let sentence = ConnectionRowSentence.make(
            name: "Lab", kind: .openVPN, fact: "SOCKS on 127.0.0.1:1080",
            dot: .connected, labels: ["Work"])
        #expect(sentence == "Lab, OpenVPN, SOCKS on 127.0.0.1:1080, connected, Work")
    }

    /// The dot is `accessibilityHidden` in every row in this app, so the sentence is the
    /// ONLY route by which its state reaches VoiceOver. Taking a `DotState` rather than a
    /// `String` is what stops a call site inventing a synonym for a state that already has
    /// a word.
    @Test func theStateInTheSentenceComesFromDotState() {
        for dot: DotState in [.off, .busy, .connected, .paused, .degraded, .captivePortal] {
            let sentence = ConnectionRowSentence.make(name: "Lab", kind: .openVPN, dot: dot)
            #expect(sentence.contains(dot.accessibilityDescription),
                    "the sentence for \(dot) does not carry its own words")
        }
    }

    /// Empty bits are dropped rather than joined, or a row with no labels reads "Lab,
    /// OpenVPN, connected, , ," — five fragments again, in a single string.
    @Test func emptyBitsAreNeverJoinedIntoTheSentence() {
        let sentence = ConnectionRowSentence.make(
            name: "Lab", kind: .openVPN, fact: "", dot: .off, notes: ["", "owns the default route"],
            labels: [""])
        #expect(sentence == "Lab, OpenVPN, disconnected, owns the default route")
    }

    // MARK: The source scans

    /// The repo root, from this file's own compile-time path.
    private static let repoRoot: URL = URL(fileURLWithPath: #filePath)
        .deletingLastPathComponent()      // UI/
        .deletingLastPathComponent()      // SimpleVPNTests/
        .deletingLastPathComponent()      // repo root

    /// The files that draw a row in a list of connections. Adding a row builder means
    /// adding a file here — which is the point: the invariant is about the SHAPE of a
    /// connection row, not about these four.
    private static let rowHosts = [
        "SimpleVPN/UI/Editors/ManageVPNsView.swift",
        "SimpleVPN/UI/Connection/ConnectionView.swift",
        "SimpleVPN/UI/Connection/VPNSidebarRow.swift",
    ]

    /// Where the one row lives.
    private static let sharedRow = "SimpleVPN/UI/Components/ConnectionRow.swift"

    private static func source(_ relative: String) throws -> String {
        let url = repoRoot.appendingPathComponent(relative)
        let text = try String(contentsOf: url, encoding: .utf8)
        #expect(!text.isEmpty, "no source at \(url.path)")
        return text
    }

    /// Lines of a file, numbered, with prose dropped — a comment ABOUT a rule is not the
    /// rule, and every one of these files documents the bug it used to have.
    private static func codeLines(_ text: String) -> [(number: Int, text: String)] {
        text.components(separatedBy: "\n").enumerated().compactMap { i, line in
            let trimmed = line.trimmingCharacters(in: .whitespaces)
            guard !trimmed.hasPrefix("//") else { return nil }
            return (i + 1, line)
        }
    }

    /// **NO ROW BUILDER DRAWS ITS OWN STATUS DOT.**
    ///
    /// The dot had two positions in one section: inside the badge (bottom-trailing) for an
    /// NE profile, and a separate leading `StatusDot` for the tunnel or native VPN next to
    /// it. One state, two places, in a list whose headings had just stopped distinguishing
    /// them. `LogoBadge` owns the dot now; a bare `StatusDot` in a row file is the old
    /// shape coming back.
    @Test func noRowBuilderDrawsItsOwnStatusDot() throws {
        var offenders: [String] = []
        for host in Self.rowHosts {
            for line in Self.codeLines(try Self.source(host)) where line.text.contains("StatusDot(") {
                offenders.append("\(host):\(line.number)")
            }
        }
        #expect(offenders.isEmpty, """
            a connection row draws its own StatusDot, so the same state appears in two \
            positions in one section \u{2014} let LogoBadge carry it \
            (ConnectionRowLayout does): \(offenders.joined(separator: ", "))
            """)
    }

    /// **NO ROW BUILDER DRAWS THE KIND'S GLYPH INSTEAD OF THE BADGE.**
    ///
    /// `Image(systemName: kind.systemImage)` beside `LogoBadge` in the same section is our
    /// transport split showing through the icons after it had been taken out of the words
    /// — the user can still see which rows are "the other kind", just without a heading
    /// admitting it. ONTOLOGY.md rule 1. The badge takes the kind's glyph as its FALLBACK,
    /// which is the same information without the split.
    @Test func noRowBuilderSubstitutesTheKindGlyphForTheBadge() throws {
        var offenders: [String] = []
        for host in Self.rowHosts {
            for line in Self.codeLines(try Self.source(host))
            where line.text.contains("Image(systemName:") && line.text.contains(".systemImage") {
                offenders.append("\(host):\(line.number)")
            }
        }
        #expect(offenders.isEmpty, """
            a connection row draws the kind's glyph directly instead of LogoBadge, which \
            is the transport split drawn back in after it was taken out of the headings \
            (ONTOLOGY.md rule 1): \(offenders.joined(separator: ", "))
            """)
    }

    /// **NO ROW BUILDER PINS ITS OWN HEIGHT.**
    ///
    /// One section is one list only when every row in it is the same height. Two of them
    /// carried `.frame(minHeight: 52)` and `.padding(.vertical, 6)` as literals and a
    /// third carried neither, so the numbers agreed by copying rather than by
    /// construction. `ConnectionRowMetrics` owns them.
    @Test func noRowBuilderPinsItsOwnRowMetrics() throws {
        var offenders: [String] = []
        for host in Self.rowHosts + [Self.sharedRow] {
            for line in Self.codeLines(try Self.source(host)) {
                let pinsHeight = line.text.contains(".frame(minHeight:")
                    && !line.text.contains("ConnectionRowMetrics")
                // The row's own padding, by its value. A different number elsewhere in
                // one of these files is a different thing (an empty-state page's inset),
                // and pretending otherwise would make this a nuisance rather than a guard.
                let padsRow = line.text.contains(".padding(.vertical, 6)")
                if pinsHeight || padsRow { offenders.append("\(host):\(line.number)") }
            }
        }
        #expect(offenders.isEmpty, """
            a connection row sets its own height or vertical padding instead of reading \
            ConnectionRowMetrics, which is how one section came to hold two row heights: \
            \(offenders.joined(separator: ", "))
            """)
    }

    /// **NO ROW BUILDER ASSEMBLES ITS OWN SPOKEN SENTENCE.**
    ///
    /// Four rows, four join orders, four sets of bits — and the maturity chip reached
    /// VoiceOver in three of them and not the fourth. `ConnectionRowSentence` is the one
    /// assembler; a row file may still COMPUTE a bit (a failure's words, "owns the default
    /// route") and passes it in.
    ///
    /// The tell is an `.accessibilityLabel` whose literal contains `", "` between two
    /// interpolations — that is a sentence being joined by hand.
    @Test func noRowBuilderAssemblesItsOwnRowSentence() throws {
        var offenders: [String] = []
        for host in Self.rowHosts {
            for line in Self.codeLines(try Self.source(host))
            where line.text.contains(".accessibilityLabel(\"")
                && line.text.contains(", \\(")
                // A row NAMES itself and then says one more thing ("Actions for X",
                // "Connect X") without claiming to be the row's whole sentence; the tell
                // of the whole sentence is TWO joins.
                && line.text.components(separatedBy: ", \\(").count > 2 {
                offenders.append("\(host):\(line.number)")
            }
        }
        #expect(offenders.isEmpty, """
            a connection row joins its own accessibility sentence instead of calling \
            ConnectionRowSentence.make \u{2014} four row builders each had their own order, \
            and the maturity chip reached VoiceOver in three of them: \
            \(offenders.joined(separator: ", "))
            """)
    }

    /// **THE MATURITY CHIP CANNOT BE COMPRESSED.**
    ///
    /// THE "Untest…" BUG, pinned. The chip holds a flexible `Text` and so does the row's
    /// name, so in a 200pt sidebar SwiftUI compressed whichever it liked and it chose the
    /// chip — leaving a five-character stub of a word whose entire job is to invite a
    /// report on a VPN kind nobody has tried. Unreadable, it cannot do that job. Every
    /// `MaturityBadge` in a sidebar row carries `.fixedSize()`; the name truncates
    /// instead, and a person can still recognise their own VPN from its first characters.
    @Test func everySidebarMaturityChipIsFixedSize() throws {
        var offenders: [String] = []
        for host in Self.rowHosts + [Self.sharedRow] {
            let lines = Self.codeLines(try Self.source(host))
            for (index, line) in lines.enumerated() where line.text.contains("MaturityBadge(") {
                // The modifier may sit on the same line or the next one.
                let window = lines[index..<min(index + 2, lines.count)]
                    .map(\.text).joined(separator: "\n")
                if !window.contains(".fixedSize()") { offenders.append("\(host):\(line.number)") }
            }
        }
        #expect(offenders.isEmpty, """
            a sidebar row's MaturityBadge has no .fixedSize(), so it can be compressed to \
            \u{201C}Untest\u{2026}\u{201D} \u{2014} a badge that exists to invite a report \
            on an untried VPN kind cannot do that unreadable: \
            \(offenders.joined(separator: ", "))
            """)
    }

    /// **MANAGE VPNS' THREE ROW BUILDERS ARE ONE ROW.**
    ///
    /// Each may keep its own function — they read from three different stores and offer
    /// three different context menus — but none may build the row itself again. That is
    /// what let one heading show two icon styles and two heights at the same time.
    @Test func manageVPNsThreeRowBuildersAllUseTheSharedRow() throws {
        let text = try Self.source("SimpleVPN/UI/Editors/ManageVPNsView.swift")
        let lines = text.components(separatedBy: "\n")
        for builder in ["private func profileRow(", "private func tunnelRow(",
                        "private func nativeRow("] {
            let start = try #require(lines.firstIndex { $0.contains(builder) }, """
                \(builder) is gone \u{2014} if the three were merged outright, update this \
                test and Docs/Drift.md \u{00A7}3
                """)
            let body = lines[start..<min(start + 18, lines.count)].joined(separator: "\n")
            #expect(body.contains("ConnectionRowLayout("), """
                \(builder) builds its own row instead of using ConnectionRowLayout \u{2014} \
                that is exactly the state Docs/Drift.md \u{00A7}3 describes
                """)
        }
    }

    /// **THE EXCLUSION IS IN THE TEST RUN, NOT IN A COMMIT MESSAGE** (`Docs/Drift.md` §2,
    /// and the AGENTS.md rule it produced).
    ///
    /// `SubprocessTunnelView` was excluded from the row unification because another agent
    /// held the file, and the exclusion was recorded honestly in a commit message — which
    /// is not a place anybody looks. It is the source of three separate defects now.
    ///
    /// This test PASSES while the file is still excluded and FAILS the moment it stops
    /// being: whoever finally brings that editor into the shared rows has to come here and
    /// to `Docs/Drift.md` §2 and close the entry. An exclusion that surfaces is the whole
    /// difference between this and a sentence nobody re-reads.
    @Test func subprocessTunnelViewIsStillOutsideTheSharedRows() throws {
        let text = try Self.source("SimpleVPN/UI/Editors/SubprocessTunnelView.swift")
        #expect(!text.contains("ConnectionRowLayout("), """
            SubprocessTunnelView now uses the shared row \u{2014} which is good news, and \
            means this deliberately-failing marker has done its job. Close Docs/Drift.md \
            \u{00A7}2, add the file to `rowHosts` above so the other scans cover it, and \
            delete this test.
            """)
    }
}
