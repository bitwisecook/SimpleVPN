// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
//  ConnectOrder.swift
//  THE ORDER OF THE VPN LIST — one order, one value, read and written the same way by
//  the main window's sidebar and by Manage VPNs'.
//
//  WHY THIS EXISTS AT ALL RATHER THAN TWO `onMove` CLOSURES. The user asked for
//  drag-to-reorder in the main window and said what it has to mean: "it should be in
//  sync with the vpn configs window". Two lists that each remembered their own order
//  would be worse than neither being reorderable — you would arrange your VPNs, open
//  the other window, and find a different list. So there is one arrangement, and this
//  is it: both windows build a `ConnectOrder` from the same three stores through
//  `of(vpn:tunnels:native:)`, ask it for the rows under each heading, and hand every
//  move — pointer, keyboard or context menu — back to the same closure.
//
//  WHERE THE ORDER IS STORED, AND WHY IT IS A RANK PER VPN. Each VPN carries its own
//  position: `VPNUIPrefs.order` for an NE profile, `SubprocessTunnelConfig.order` for
//  a subprocess tunnel, `NativeVPNConfig.order` for a native personal VPN. The
//  obvious alternative — one app-level list of ids in the order they should appear —
//  was rejected on a fact from the far end of the app: `ConfigImport` gives every
//  imported VPN A NEW ID, so a stored list of ids would arrive on the second Mac
//  naming nothing at all, and the arrangement would be lost by the one path that
//  exists to carry a setup between Macs. A rank each VPN carries survives that, and
//  it is the shape `VPNEndpoint.order` already uses for a hand-made server order one
//  level down.
//
//  THE RANK SPACE IS GLOBAL; THE SECTIONS ARE A FILTER. A move renumbers EVERY row,
//  in both sections, 0…N−1 in the order they are drawn. That is the answer to the
//  awkward question this list poses and the servers table does not: a row's section
//  follows its CONFIGURATION (`ConnectionScope`), so an SSL VPN moves from "Local
//  Ports" to "Whole-Mac VPNs" the moment "Run In-Process" is turned on, and it must
//  land somewhere sensible rather than at a stale index. With one global rank space
//  it keeps every above/below relationship it had with every row it never moved past
//  — it arrives in its new section in the place its rank has always implied. Ranks
//  numbered 0…n−1 WITHIN each section would instead collide across sections and give
//  a row that changed section the position of whichever row shared its number.
//
//  WHAT THE USER IS EXPRESSING IS STILL A WITHIN-SECTION ORDER, and `sections()`
//  sorts inside each heading, so nothing about the global numbering is visible.
//
//  A DRAG CANNOT TAKE A ROW OUT OF ITS SECTION, and it is refused STRUCTURALLY rather
//  than by a check that could be forgotten: `positions(after:movingIn:from:to:)`
//  takes a section and section-local indices, and `Reorder.moved` clamps to that
//  section's own bounds, so a cross-section move is not expressible. On screen the
//  same thing holds for the same reason — each section is one `ForEach` with its own
//  `onMove`, which is the unit AppKit will drop into. That matters more than tidiness:
//  a row's section says WHAT CONNECTING IT DOES TO THE MAC (whole-Mac traffic, or a
//  port nothing uses until you aim something at it), so a gesture that moved a row
//  between them would be a security-determining change made by dragging. The way to
//  change it is the setting that decides it, which is what the heading's own
//  explanation says.
//
//  NOTHING HERE ANIMATES A LIVE CONTROL. These rows hold a `SidebarActionCircle` and
//  a status dot, and the house rule (AGENTS.md, the layout-loop crash) keeps
//  platform-backed views out of transform-animated containers. So the drag is the
//  `List`'s own — AppKit snapshots the row to a static image before the drag begins —
//  and there is no hand-rolled hit-test, no custom preview and no `.draggable` on
//  these rows at all.
//

import Foundation

/// Every string the VPN list's reorder says that `ReorderCopy` does not already own.
/// Pure and separate so a test can hold the words without building a window.
nonisolated enum ConnectOrderCopy {

    /// What Move Up / Move Down say when the sidebar has nothing selected. The
    /// house default says "row"; this list's rows are VPNs and says so.
    static let nothingSelected = "Choose a VPN first, then move it."

    /// The subject when there is no selection to name. Never rendered as a sentence
    /// on its own — it only fills the label of a control that is disabled anyway.
    static let noSubject = "the selected VPN"

    /// The tooltip on the Move Up / Move Down pair, which is where somebody who has
    /// just tried to drag a VPN into the other section goes looking for an answer.
    /// Says what a move can do and where the group comes from — never "section",
    /// which is a word about our layout rather than about their Mac.
    static let scopeHelp = "Move the selected VPN up or down within its own group. "
        + "Which group a VPN is in follows its own settings \u{2014} what connecting it does to this Mac \u{2014} "
        + "so moving it here never changes that."
}

/// THE VPN LIST'S ORDER, as a value: the rows under each heading, what each one is
/// called, and how a move is written down.
///
/// Built fresh in `body` from whatever the window already knows — the same rule
/// `ReorderCommands` states for itself — so it can never hold a stale index.
@MainActor
struct ConnectOrder {

    /// The headings and their rows, in the order they are drawn.
    let sections: [(scope: ConnectionScope, tags: [String])]

    /// What each row is called, keyed by its selection tag. The subject of every
    /// label and of the spoken confirmation, so it has to read as a noun phrase —
    /// which a VPN's name does.
    let names: [String: String]

    /// Write a new arrangement down: tag → its position among ALL rows. Supplied by
    /// `of(vpn:tunnels:native:)` and by nothing else, so neither window has a
    /// persistence path of its own to diverge with.
    let persist: ([String: Int]) -> Void

    init(profiles: [ConnectListing.Profile],
         tunnels: [SubprocessTunnelConfig],
         native: [NativeVPNConfig],
         names: [String: String],
         persist: @escaping ([String: Int]) -> Void) {
        self.sections = ConnectListing.sections(profiles: profiles, tunnels: tunnels, native: native)
        self.names = names
        self.persist = persist
    }

    /// The rows under one heading, in the order the user arranged them. Empty when
    /// the heading has nothing in it, which is how the view knows to draw no section.
    func tags(in scope: ConnectionScope) -> [String] {
        sections.first { $0.scope == scope }?.tags ?? []
    }

    /// Every row, in sidebar order — the concatenation of the sections, exactly as
    /// `ConnectListing.rowTags` defines it.
    var allTags: [String] { sections.flatMap(\.tags) }

    /// Which heading holds this row, where it sits in that heading, and how many rows
    /// share it. nil when the tag names nothing on screen.
    func place(of tag: String) -> (scope: ConnectionScope, index: Int, count: Int)? {
        for section in sections {
            if let i = section.tags.firstIndex(of: tag) {
                return (section.scope, i, section.tags.count)
            }
        }
        return nil
    }

    /// Move Up / Move Down for one row — nil meaning "whatever is selected, and
    /// nothing is". The whole affordance comes back from this: the toolbar buttons,
    /// the context-menu items, the announcement, and the reasons a move is refused.
    func commands(for tag: String?) -> ReorderCommands {
        let spot = tag.flatMap { place(of: $0) }
        return ReorderCommands(
            subject: tag.flatMap { names[$0] } ?? ConnectOrderCopy.noSubject,
            index: spot?.index,
            // WITH NOTHING SELECTED THE COUNT IS EVERY ROW, not zero: a zero would
            // make the buttons say "there is only one row" to somebody who simply
            // hasn't chosen one yet. With one VPN in total that IS the honest answer,
            // and this reports it.
            count: spot?.count ?? allTags.count,
            // No `blocked` reason, and that is a decision rather than an omission. A
            // position is not a connection setting: it never reaches an engine, and
            // the servers table settled the same question the same way (an MDM lock
            // and a configuration-owned row are about EXISTENCE, not order). The only
            // rows that cannot move are the ones with nowhere to go, which the ends
            // of the list explain for themselves.
            within: spot?.scope.sectionTitle,
            nothingSelected: ConnectOrderCopy.nothingSelected,
            move: { [self] from, to in
                guard let scope = spot?.scope,
                      let positions = Self.positions(after: sections, movingIn: scope,
                                                     from: from, to: to) else { return }
                persist(positions)
            })
    }

    /// The platform's own reorder — `List`'s `onMove`, which is what an AppKit drag
    /// of these rows produces.
    ///
    /// IT GOES THROUGH `ReorderCommands.drop`, which is the point: the announcement,
    /// the refusals and the index maths are then identical to the buttons' rather than
    /// a second implementation that happens to agree. SwiftUI states `to` in
    /// PRE-REMOVAL coordinates ("insert before the row currently at this index"),
    /// which is exactly what `insertingBefore:` means and exactly the off-by-one a
    /// hand-written `move(fromOffsets:toOffset:)` gets wrong.
    func move(in scope: ConnectionScope, from offsets: IndexSet, to offset: Int) {
        // One row at a time: this list's selection is a single tag, so a multi-row
        // drag cannot be made — and guessing at what one would mean is how a reorder
        // comes to move a row nobody picked up.
        guard offsets.count == 1, let from = offsets.first else { return }
        let tags = tags(in: scope)
        guard tags.indices.contains(from) else { return }
        commands(for: tags[from]).drop(from: from, insertingBefore: offset)
    }

    // MARK: - The maths (pure, and the part the tests pin)

    /// The new position of EVERY row after moving one row inside its own section, or
    /// nil when the move changes nothing (which includes a nonsense index and a drop
    /// on the row itself).
    ///
    /// `from` and `to` are section-local. That is the cross-section refusal: there is
    /// no way to name a row in another section, and `Reorder.moved` clamps `to` to
    /// this section's own bounds, so "drag it past the last whole-Mac VPN" lands it
    /// last among the whole-Mac VPNs and never in Local Ports.
    nonisolated static func positions(after sections: [(scope: ConnectionScope, tags: [String])],
                                      movingIn scope: ConnectionScope,
                                      from: Int, to: Int) -> [String: Int]? {
        guard let s = sections.firstIndex(where: { $0.scope == scope }) else { return nil }
        let moved = Reorder.moved(sections[s].tags, from: from, to: to)
        guard moved != sections[s].tags else { return nil }
        var flat: [String] = []
        for (i, section) in sections.enumerated() { flat += (i == s ? moved : section.tags) }
        // Built by hand rather than with `Dictionary(uniqueKeysWithValues:)`, which
        // traps on a duplicate key: tags are unique today (`ConnectListingTests`) and
        // a reorder is not the place to find out that they stopped being.
        var out: [String: Int] = [:]
        for (rank, tag) in flat.enumerated() { out[tag] = rank }
        return out
    }
}

// MARK: - From the three stores

extension ConnectOrder {

    /// EVERYTHING THE TWO SIDEBARS NEED, from the three stores — the one builder.
    ///
    /// Both windows call this and nothing else, which is what makes "one order" true
    /// by construction rather than by two views being written to match.
    static func of(vpn: VPNController,
                   tunnels: SubprocessTunnelStore?,
                   native: NativeVPNManager?) -> ConnectOrder {
        let tunnelConfigs = tunnels?.tunnels ?? []
        let nativeConfigs = native?.configs ?? []
        var names: [String: String] = [:]
        for p in vpn.profiles { names[p.id] = p.name }
        for t in tunnelConfigs { names[ConnectListing.tag(forTunnel: t.id)] = t.name }
        for c in nativeConfigs { names[ConnectListing.tag(forNative: c.id)] = c.name }
        return ConnectOrder(
            profiles: vpn.profiles.map {
                .init(id: $0.id, kind: $0.kind, order: vpn.uiPrefs(for: $0.id).order)
            },
            tunnels: tunnelConfigs,
            native: nativeConfigs,
            names: names,
            persist: { [weak vpn, weak tunnels, weak native] positions in
                let split = Self.split(positions)
                // The two UserDefaults-backed stores take their whole batch in one
                // write each. The NE profiles cannot — every one is its own
                // `NEVPNManager` — so `setSidebarOrder` seeds the cache the sidebar
                // reads before it starts saving, and the rows land in one step.
                tunnels?.setOrder(split.tunnels)
                native?.setOrder(split.native)
                if let vpn { Task { await vpn.setSidebarOrder(split.profiles) } }
            })
    }

    /// A tag-keyed arrangement, split into the three id-keyed ones the stores want.
    /// Prefixes are stripped here rather than by each store, so nothing but
    /// `ConnectListing` ever has to know how a tag is spelled.
    static func split(_ positions: [String: Int])
        -> (profiles: [String: Int], tunnels: [String: Int], native: [String: Int]) {
        var profiles: [String: Int] = [:]
        var tunnels: [String: Int] = [:]
        var native: [String: Int] = [:]
        for (tag, rank) in positions {
            if tag.hasPrefix(ConnectListing.tunnelTag) {
                tunnels[ConnectListing.configID(from: tag)] = rank
            } else if tag.hasPrefix(ConnectListing.nativeTag) {
                native[ConnectListing.configID(from: tag)] = rank
            } else {
                profiles[tag] = rank
            }
        }
        return (profiles, tunnels, native)
    }
}
