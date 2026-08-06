// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
//  RuleListReachabilityTests.swift
//  "Every action must produce a perceptible result, and every feature must be
//  REACHABLE" (AGENTS.md). Four shipped bugs in this app were the same bug wearing
//  different clothes — the code worked and the presentation hid it — and the Custom
//  Routing one was purely geometric: "Add Route Rule" sat BELOW a `.frame(height: 300)`
//  scroll region, so in the empty state the viewport claimed 300 points of near-blank
//  space and pushed the section's only way to add a rule off-screen. The user asked
//  how to add routes while disconnected; the answer was that they always could, and
//  could not see the button.
//
//  So this pins the two halves of the fix, because a test that says "the action is
//  reachable" is worth more than the fix itself:
//
//  1. The viewport sizes to its CONTENT up to the cap, instead of always claiming it
//     (`routesViewportHeight` — a pure function precisely so it can be asserted).
//  2. Every rule list's primary action sits ABOVE that region and its rows, and the
//     empty state carries the same action rather than being a dead end.
//
//  (2) walks the SOURCE, like `SettingRenderingTests` and for the same reason: a
//  `View`'s body cannot be enumerated without building and driving the whole
//  hierarchy, and the property at stake is about ORDER of declaration, which is
//  exactly what the source records.
//

import Foundation
import Testing
@testable import SimpleVPN

@MainActor
struct RuleListReachabilityTests {

    // MARK: 1 — the viewport sizes to content, not to its cap

    /// The actual regression: an empty list's body is short, so the viewport must be
    /// short. 300 points of blank space is what buried the action.
    @Test func anEmptyListDoesNotClaimTheWholeViewport() {
        let shortBody: CGFloat = 130          // "No rules yet" + the pushed reference
        #expect(CustomRoutingTabView.routesViewportHeight(contentHeight: shortBody) == shortBody)
        #expect(CustomRoutingTabView.routesViewportHeight(contentHeight: shortBody)
                < CustomRoutingTabView.routesViewportMaxHeight)
    }

    /// …and the cap still holds, because the arrow overlay clamps endpoints against
    /// this viewport and needs it BOUNDED (see CustomRoutingTabView's header). Sizing
    /// to content must not become "grow forever".
    @Test func aLongListIsStillCappedSoTheArrowKeepsItsBound() {
        let cap = CustomRoutingTabView.routesViewportMaxHeight
        #expect(CustomRoutingTabView.routesViewportHeight(contentHeight: 4000) == cap)
        #expect(CustomRoutingTabView.routesViewportHeight(contentHeight: cap) == cap)
        #expect(CustomRoutingTabView.routesViewportHeight(contentHeight: cap + 1) == cap)
    }

    /// Before the content has reported anything — and against a garbage measurement —
    /// the viewport is the floor, never 0. A 0pt viewport renders nothing, so it could
    /// never measure its way back out, and the whole list would vanish instead of
    /// merely being hidden. That is a worse bug than the one being fixed.
    @Test func anUnmeasuredViewportIsNeverZero() {
        let floor = CustomRoutingTabView.routesViewportMinHeight
        #expect(floor > 0)
        for bad: CGFloat in [0, -1, -1000, .nan, .infinity] {
            #expect(CustomRoutingTabView.routesViewportHeight(contentHeight: bad) == floor,
                    "a content height of \(bad) must fall back to the floor, not collapse")
        }
        // The floor is a floor, not a second cap.
        #expect(CustomRoutingTabView.routesViewportHeight(contentHeight: floor / 2) == floor)
        #expect(CustomRoutingTabView.routesViewportHeight(contentHeight: floor * 2) == floor * 2)
    }

    // MARK: 2 — the action sits above the region, and the empty state carries it

    /// One editable rule list on the Custom Routing tab. Adding a list means adding a
    /// row here — which is the point: the invariant is about the SHAPE of a rule list,
    /// not about these two.
    private struct RuleList {
        /// For failure messages.
        let name: String
        /// The `// MARK:` comments that open and close this list's stretch of source.
        let opensAt: String
        let closesAt: String
        /// The header call carrying the primary action. Must come first.
        let addAction: String
        /// The row loop the action must precede.
        let rowLoop: String
        /// The empty-state guard, which must be answered by the shared empty-state
        /// view — whose signature makes the action mandatory.
        let emptyGuard: String
        /// The action's visible words.
        let title: String
    }

    private static let ruleLists: [RuleList] = [
        RuleList(name: "Custom Routing \u{2014} Routes",
                 opensAt: "// MARK: Routes",
                 closesAt: "// MARK: Arrow overlay",
                 addAction: "addTitle: Self.addRouteRuleTitle",
                 rowLoop: "ForEach($profile.routes.rules)",
                 emptyGuard: "if profile.routes.rules.isEmpty {",
                 title: CustomRoutingTabView.addRouteRuleTitle),
        RuleList(name: "Custom Routing \u{2014} DNS",
                 opensAt: "// MARK: DNS",
                 closesAt: "// MARK: Proxy",
                 addAction: "addTitle: Self.addResolverRuleTitle",
                 rowLoop: "ForEach($profile.dns.resolverRules)",
                 emptyGuard: "if profile.dns.resolverRules.isEmpty {",
                 title: CustomRoutingTabView.addResolverRuleTitle),
    ]

    /// The repo root, from this file's own compile-time path (the idiom
    /// `SettingRenderingTests` established).
    private static let repoRoot: URL = URL(fileURLWithPath: #filePath)
        .deletingLastPathComponent()      // ControlPlane/
        .deletingLastPathComponent()      // SimpleVPNTests/
        .deletingLastPathComponent()      // repo root

    private static let viewPath = "SimpleVPN/UI/Editors/CustomRoutingTabView.swift"

    private func source() throws -> [String] {
        let url = Self.repoRoot.appendingPathComponent(Self.viewPath)
        let text = try String(contentsOf: url, encoding: .utf8)
        #expect(!text.isEmpty, "no source at \(url.path)")
        return text.components(separatedBy: "\n")
    }

    /// The lines of one list's section, and their offsets in the whole file.
    private func lines(of list: RuleList, in all: [String]) throws -> [(number: Int, text: String)] {
        let start = try #require(all.firstIndex { $0.contains(list.opensAt) },
                                 "\(list.name): no \u{201C}\(list.opensAt)\u{201D} marker")
        let end = try #require(all[start...].firstIndex { $0.contains(list.closesAt) },
                               "\(list.name): no \u{201C}\(list.closesAt)\u{201D} marker")
        return all[start..<end].enumerated().map { (number: start + $0.offset + 1, text: $0.element) }
    }

    private func firstLine(containing needle: String,
                           in section: [(number: Int, text: String)]) -> Int? {
        section.first { $0.text.contains(needle) }?.number
    }

    /// THE regression test. A list's primary action must be declared before its scroll
    /// region and before its rows — "above", in a `Section`, is source order. Below a
    /// bounded scroll region the action can be scrolled out of existence; below the
    /// rows it walks further down the pane with every rule added.
    @Test func everyRuleListsAddActionIsDeclaredAboveItsRowsAndAnyScrollRegion() throws {
        let all = try source()
        for list in Self.ruleLists {
            let section = try lines(of: list, in: all)
            let action = try #require(firstLine(containing: list.addAction, in: section),
                                      "\(list.name): no primary action (\(list.addAction)) in its section at all")
            let rows = try #require(firstLine(containing: list.rowLoop, in: section),
                                    "\(list.name): no row loop (\(list.rowLoop)) in its section")
            #expect(action < rows,
                    "\(list.name): \u{201C}\(list.title)\u{201D} is declared at line \(action), below its rows at \(rows) \u{2014} it must be above them")
            if let scroll = firstLine(containing: "ScrollView {", in: section) {
                #expect(action < scroll,
                        "\(list.name): \u{201C}\(list.title)\u{201D} is declared at line \(action), below the scroll region at \(scroll) \u{2014} that is the bug this test exists for")
            }
        }
    }

    /// "No rules yet" with no way forward is a dead end, and it is the state a new
    /// profile is always in. Each list answers its own empty guard with the shared
    /// `emptyRuleList`, whose `addTitle`/`add` parameters are NON-optional — so the
    /// action can't be dropped from an empty state without the compiler noticing.
    @Test func everyRuleListsEmptyStateCarriesItsAddAction() throws {
        let all = try source()
        for list in Self.ruleLists {
            let section = try lines(of: list, in: all)
            let guardLine = try #require(firstLine(containing: list.emptyGuard, in: section),
                                         "\(list.name): no empty state at all \u{2014} an untouched list must say what it does and offer the way in")
            let body = section.filter { $0.number > guardLine && $0.number <= guardLine + 4 }
                .map(\.text).joined(separator: "\n")
            #expect(body.contains("emptyRuleList("),
                    "\(list.name): its empty state doesn't use emptyRuleList, so nothing forces it to carry \u{201C}\(list.title)\u{201D}")
            #expect(body.contains("addTitle:"),
                    "\(list.name): its empty state passes no action")
        }
        // Exactly one empty state per list — no list quietly loses its own.
        let uses = all.filter { $0.contains("emptyRuleList(") && !$0.contains("func emptyRuleList") }
        #expect(uses.count == Self.ruleLists.count,
                "expected one emptyRuleList call per rule list (\(Self.ruleLists.count)), found \(uses.count)")
    }

    /// The scroll region must be sized by `routesViewportHeight`, never by a constant.
    /// A constant is how it came to claim 300 points it had nothing to put in.
    @Test func noRuleListViewportIsAConstantHeight() throws {
        let all = try source()
        for list in Self.ruleLists {
            let section = try lines(of: list, in: all)
            guard firstLine(containing: "ScrollView {", in: section) != nil else { continue }
            // Prose about the old constant is not the old constant.
            let frames = section.filter {
                $0.text.contains(".frame(height:")
                    && !$0.text.trimmingCharacters(in: .whitespaces).hasPrefix("//")
            }
            #expect(!frames.isEmpty, "\(list.name): its scroll region has no height at all")
            for frame in frames {
                #expect(frame.text.contains("routesViewportHeight"),
                        "\(list.name): line \(frame.number) pins the viewport to a constant (\(frame.text.trimmingCharacters(in: .whitespaces))) \u{2014} it must size to content up to the cap")
            }
        }
    }
}
