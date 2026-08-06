// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
//  ReorderTests.swift
//  The shared reorder affordance, pinned at the level a unit test can actually
//  reach: the index maths, the words, and the decisions `ReorderCommands` makes
//  about when a move is refused and why.
//
//  WHAT THESE TESTS DELIBERATELY DO NOT COVER. A drag is a pointer gesture inside
//  AppKit's own drag session (for the `Table`) or SwiftUI's drop machinery (for the
//  rule lists); no unit test picks a row up. So the gesture is split from its
//  meaning on purpose: `Reorder.moved` is where the meaning lives and is total and
//  pure, `ReorderCommands.drop` routes a drop through exactly the same function and
//  the same announcement as the buttons, and everything below tests those. What is
//  left for a human with a trackpad is listed in the reorder section of the report:
//  that the drag starts at all, that the insertion line appears where the pointer
//  is, and that the preview under the pointer is text rather than a live control.
//

import Foundation
import Testing
@testable import SimpleVPN

struct ReorderMathsTests {

    // MARK: The one function every reorder in the app goes through

    @Test func movingDownAndUpAreInverses() {
        let items = ["a", "b", "c", "d"]
        #expect(Reorder.moved(items, from: 0, to: 1) == ["b", "a", "c", "d"])
        #expect(Reorder.moved(Reorder.moved(items, from: 0, to: 1), from: 1, to: 0) == items)
        #expect(Reorder.moved(items, from: 3, to: 0) == ["d", "a", "b", "c"])
        #expect(Reorder.moved(items, from: 0, to: 3) == ["b", "c", "d", "a"])
    }

    /// The destination is in RESULT coordinates — the whole reason this function
    /// exists rather than `Array.move(fromOffsets:toOffset:)`, whose destination is
    /// in pre-removal coordinates and is off by one for every downward move.
    @Test func theDestinationIsWhereTheItemEndsUp() {
        let items = [0, 1, 2, 3, 4]
        for to in items.indices {
            let moved = Reorder.moved(items, from: 0, to: to)
            #expect(moved.firstIndex(of: 0) == to)
        }
    }

    /// Total over nonsense. A reorder driven by a stale index, an empty list or a
    /// drop past the end must be a no-op, never a trap.
    @Test func badIndicesLeaveTheListAlone() {
        let items = ["a", "b", "c"]
        #expect(Reorder.moved(items, from: -1, to: 0) == items)
        #expect(Reorder.moved(items, from: 3, to: 0) == items)
        #expect(Reorder.moved(items, from: 99, to: 99) == items)
        #expect(Reorder.moved(items, from: 0, to: -5) == ["a", "b", "c"])   // clamped to 0
        #expect(Reorder.moved(items, from: 0, to: 99) == ["b", "c", "a"])   // clamped to last
        #expect(Reorder.moved(items, from: 1, to: 1) == items)
        #expect(Reorder.moved([String](), from: 0, to: 0).isEmpty)
        #expect(Reorder.moved(["only"], from: 0, to: 0) == ["only"])
    }

    /// The drop shape: "land where this row is now". Dragging downwards has to
    /// account for the row's own removal, which is the classic off-by-one.
    @Test func insertingBeforeARowLandsThere() {
        let items = ["a", "b", "c", "d"]
        // b before a
        #expect(Reorder.moved(items, from: 1, insertingBefore: 0) == ["b", "a", "c", "d"])
        // a before c: a comes out first, so it lands at index 1, not 2
        #expect(Reorder.moved(items, from: 0, insertingBefore: 2) == ["b", "a", "c", "d"])
        // a to the end (target == count)
        #expect(Reorder.moved(items, from: 0, insertingBefore: 4) == ["b", "c", "d", "a"])
        // dropping a row on itself changes nothing
        #expect(Reorder.moved(items, from: 2, insertingBefore: 2) == items)
        #expect(Reorder.moved(items, from: 2, insertingBefore: 3) == items)
        // and nonsense is still a no-op
        #expect(Reorder.moved(items, from: 9, insertingBefore: 1) == items)
        #expect(Reorder.moved(items, from: 0, insertingBefore: -3) == items)
    }

    /// Nowhere to go is nil, not arithmetic on an index that doesn't exist. This is
    /// what makes Move Up on the first row and Move Down on the last a no-op.
    @Test func thereIsNowhereToGoAtTheEnds() {
        #expect(Reorder.destination(from: 0, delta: -1, count: 3) == nil)
        #expect(Reorder.destination(from: 2, delta: 1, count: 3) == nil)
        #expect(Reorder.destination(from: 0, delta: 1, count: 3) == 1)
        #expect(Reorder.destination(from: 2, delta: -1, count: 3) == 1)
        // A one-row list has no order to change.
        #expect(Reorder.destination(from: 0, delta: 1, count: 1) == nil)
        #expect(Reorder.destination(from: 0, delta: -1, count: 1) == nil)
        // …and neither does an empty one, or a stale index into either.
        #expect(Reorder.destination(from: 0, delta: 1, count: 0) == nil)
        #expect(Reorder.destination(from: -1, delta: 1, count: 3) == nil)
        #expect(Reorder.destination(from: 5, delta: -1, count: 3) == nil)
    }
}

struct ReorderCopyTests {

    /// A move says WHERE IT LANDED. "Moved" alone tells a screen-reader user that
    /// something happened and nothing about the outcome — which in a first-match-wins
    /// list is the only part that matters.
    @Test func theAnnouncementNamesWhatMovedAndWhereItLanded() {
        let said = ReorderCopy.landed("the Ignore 10.0.0.0/8 rule", at: 1, of: 4)
        #expect(said == "Moved the Ignore 10.0.0.0/8 rule to 2 of 4")
        #expect(said.contains("2 of 4"))
        #expect(ReorderCopy.position(0, of: 1) == "1 of 1")
    }

    @Test func theCommandsAreNamedForWhatTheyMove() {
        #expect(ReorderCopy.moveUp("London") == "Move London up")
        #expect(ReorderCopy.moveDown("London") == "Move London down")
        // Apple's own wording for the menu items, with no arrows in the words.
        #expect(ReorderCopy.moveUpTitle == "Move Up")
        #expect(ReorderCopy.moveDownTitle == "Move Down")
    }

    /// A control that can't run says why (Docs/Accessibility.md rule 5), and the
    /// reason names the row so it isn't ambient.
    @Test func theEndsOfTheListExplainThemselves() {
        #expect(ReorderCopy.alreadyFirst("London").contains("London"))
        #expect(ReorderCopy.alreadyLast("London").contains("London"))
        #expect(!ReorderCopy.nothingSelected.isEmpty)
        #expect(!ReorderCopy.onlyOne.isEmpty)
    }

    /// Nothing here may say "credential" (ONTOLOGY.md), and nothing may leak
    /// internal jargon into a spoken string.
    @Test func theWordsFollowTheOntology() {
        let everything = [
            ReorderCopy.moveUpTitle, ReorderCopy.moveDownTitle,
            ReorderCopy.moveUp("x"), ReorderCopy.moveDown("x"),
            ReorderCopy.landed("x", at: 0, of: 2),
            ReorderCopy.alreadyFirst("x"), ReorderCopy.alreadyLast("x"),
            ReorderCopy.nothingSelected, ReorderCopy.onlyOne,
            ReorderCopy.gripHelp("x"), ReorderCopy.gripHelp("x", position: 0, count: 2),
            ServersTableCopy.moveDraftBlocked, ServersTableCopy.moveNothingSelected,
            ServersTableCopy.automaticOrderLabel, ServersTableCopy.automaticOrderHelp,
            ServersTableCopy.automaticOrderRestored, ServersTableCopy.dragHint,
            CustomRoutingTabView.firstMatchWins,
        ]
        for s in everything {
            #expect(!s.isEmpty)
            for banned in ["credential", "Credential", "endpoint", "Endpoint", "index", "IndexSet"] {
                #expect(!s.contains(banned), "\u{201C}\(s)\u{201D} uses \u{201C}\(banned)\u{201D}")
            }
        }
    }

    /// The rule lists say what the order MEANS, beside the rules, not only in the
    /// manual: reordering them changes where traffic goes.
    @Test func theRuleListsSayFirstMatchWins() {
        let s = CustomRoutingTabView.firstMatchWins.lowercased()
        #expect(s.contains("first"))
        #expect(s.contains("matches"))
        #expect(s.contains("top"))
    }
}

@MainActor
struct ReorderCommandsTests {

    private func commands(index: Int?, count: Int, blocked: String? = nil,
                          into log: Log) -> ReorderCommands {
        ReorderCommands(subject: "the Accept rule", index: index, count: count,
                        blocked: blocked) { from, to in log.moves.append((from, to)) }
    }

    final class Log { var moves: [(Int, Int)] = [] }

    @Test func aMoveGoesThroughTheListsOwnClosure() {
        let log = Log()
        commands(index: 1, count: 3, into: log).moveUp()
        commands(index: 1, count: 3, into: log).moveDown()
        #expect(log.moves.map { [$0.0, $0.1] } == [[1, 0], [1, 2]])
    }

    /// The two no-ops the brief calls out by name: Move Up on the first row and
    /// Move Down on the last do nothing, and say why rather than being silently
    /// inert.
    @Test func moveUpOnTheFirstRowAndMoveDownOnTheLastAreNoOps() {
        let log = Log()
        let first = commands(index: 0, count: 3, into: log)
        let last = commands(index: 2, count: 3, into: log)
        first.moveUp()
        last.moveDown()
        #expect(log.moves.isEmpty)
        #expect(first.upReason == ReorderCopy.alreadyFirst("the Accept rule"))
        #expect(first.downReason == nil)
        #expect(last.downReason == ReorderCopy.alreadyLast("the Accept rule"))
        #expect(last.upReason == nil)
    }

    @Test func nothingSelectedAndOneRowBothExplainThemselves() {
        let log = Log()
        let none = commands(index: nil, count: 3, into: log)
        #expect(none.upReason == ReorderCopy.nothingSelected)
        #expect(none.downReason == ReorderCopy.nothingSelected)
        none.moveUp(); none.moveDown()

        let single = commands(index: 0, count: 1, into: log)
        #expect(single.upReason == ReorderCopy.onlyOne)
        single.moveUp(); single.moveDown()
        #expect(log.moves.isEmpty)
    }

    /// A blocked row cannot be moved by ANY path — the buttons, the menu, or a drop.
    /// This is the invariant behind "a locked row cannot be moved illegitimately":
    /// whatever reason a list gives, one check refuses all three.
    @Test func aBlockedRowCannotBeMovedByAnyPath() {
        let log = Log()
        let blocked = commands(index: 1, count: 3, blocked: "Not yet.", into: log)
        #expect(blocked.upReason == "Not yet.")
        #expect(blocked.downReason == "Not yet.")
        blocked.moveUp()
        blocked.moveDown()
        blocked.drop(from: 1, insertingBefore: 0)
        #expect(log.moves.isEmpty)
    }

    /// A drop lands where the row it was dropped on is now, and goes through the
    /// same closure the buttons do — so a list has one persistence path, not two.
    @Test func aDropRoutesThroughTheSameClosure() {
        let log = Log()
        commands(index: 0, count: 4, into: log).drop(from: 0, insertingBefore: 2)
        commands(index: 0, count: 4, into: log).drop(from: 0, insertingBefore: 4)
        // A drop onto itself, and a drop with a stale index, change nothing.
        commands(index: 2, count: 4, into: log).drop(from: 2, insertingBefore: 2)
        commands(index: 9, count: 4, into: log).drop(from: 9, insertingBefore: 0)
        #expect(log.moves.map { [$0.0, $0.1] } == [[0, 1], [0, 3]])
    }
}
