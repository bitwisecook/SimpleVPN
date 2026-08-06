// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
//  ConnectOrderTests.swift
//  THE VPN LIST'S ORDER, pinned at the level a test can reach — which is its MEANING
//  and not the gesture. Nothing here picks a row up: an AppKit `List` reorder is a
//  drag session inside NSTableView, so what a test can hold is what a move DOES.
//
//  The five things asserted, each of them something that would be a real bug:
//   • THE ORDER PERSISTS — a rank written on each VPN is what the list is sorted by,
//     and a Mac with no arrangement still sees the store order it always did.
//   • BOTH WINDOWS AGREE — the arrangement is a pure function of the three stores, so
//     the connect window and Manage VPNs cannot show different lists. The user asked
//     for exactly this ("it should be in sync with the vpn configs window"), and two
//     lists disagreeing would be worse than neither being reorderable.
//   • A REORDER CHANGES NO TAG — both sidebars select by tag, so a move that renamed
//     one would lose the selection and break every settings route between the windows.
//   • A ROW CANNOT LEAVE ITS SECTION — a row's heading says what connecting it does to
//     this Mac, which a drag may not change.
//   • EVERY VPN STILL APPEARS EXACTLY ONCE — the invariant `ConnectListingTests` is
//     built on, restated against an arranged list rather than an unarranged one.
//
//  WHAT IS LEFT FOR A HUMAN WITH A TRACKPAD: that the drag starts, that AppKit draws
//  its insertion line between the right two rows, that it refuses to drop into the
//  other heading, and that the row that comes back under the pointer is the platform's
//  own snapshot rather than a live Connect button.
//

import Foundation
import Testing
@testable import SimpleVPN

@MainActor
struct ConnectOrderTests {

    // MARK: - Fixtures

    /// One arranged world: what the three stores hold, and the arrangement built from
    /// them. Deliberately the same shape both windows have — three stores and nothing
    /// else — so a test cannot pass by knowing something a sidebar doesn't.
    private struct World {
        var profiles: [ConnectListing.Profile] = []
        var tunnels: [SubprocessTunnelConfig] = []
        var natives: [NativeVPNConfig] = []
        /// Everything `persist` was handed, so a test can assert what a move wrote
        /// rather than only what it drew.
        let written = Written()

        final class Written { var positions: [String: Int]? }

        var order: ConnectOrder {
            var names: [String: String] = [:]
            for p in profiles { names[p.id] = "VPN \(p.id)" }
            for t in tunnels { names[ConnectListing.tag(forTunnel: t.id)] = t.name }
            for c in natives { names[ConnectListing.tag(forNative: c.id)] = c.name }
            let box = written
            return ConnectOrder(profiles: profiles, tunnels: tunnels, native: natives,
                                names: names, persist: { box.positions = $0 })
        }

        /// Write an arrangement onto the records, exactly as the three stores do —
        /// `VPNUIPrefs.order`, `SubprocessTunnelConfig.order`, `NativeVPNConfig.order`.
        /// This is what makes the round trip real: a move is only persisted if reading
        /// the stores back reproduces the list the move produced.
        mutating func apply(_ positions: [String: Int]) {
            let split = ConnectOrder.split(positions)
            profiles = profiles.map {
                .init(id: $0.id, kind: $0.kind, order: split.profiles[$0.id] ?? $0.order)
            }
            for i in tunnels.indices {
                if let r = split.tunnels[tunnels[i].id] { tunnels[i].order = r }
            }
            for i in natives.indices {
                if let r = split.native[natives[i].id] { natives[i].order = r }
            }
        }
    }

    /// A tunnel that lands in a KNOWN section. `.ssh` in SOCKS mode is a local port;
    /// `.ssh` asking for a network tunnel is whole-Mac. Both are decided by the config
    /// rather than by the kind, which is the fact the section test turns on.
    private func sshTunnel(_ id: String, _ mode: SSHMode, order: Int? = nil) -> SubprocessTunnelConfig {
        var t = SubprocessTunnelConfig()
        t.id = id
        t.name = "SSH \(id)"
        t.kind = .ssh
        t.sshMode = mode
        t.order = order
        return t
    }

    private func native(_ id: String, order: Int? = nil) -> NativeVPNConfig {
        var c = NativeVPNConfig()
        c.id = id
        c.name = "IKEv2 \(id)"
        c.kind = .ikev2
        c.order = order
        return c
    }

    /// Two whole-Mac VPNs from two different stores plus two local ports, none of them
    /// arranged — the state every Mac is in before the first drag.
    private func unarrangedWorld() -> World {
        World(profiles: [.init(id: "ovpn", kind: .openVPN), .init(id: "wg", kind: .wireGuard)],
              tunnels: [sshTunnel("socks-a", .socks), sshTunnel("socks-b", .socks)],
              natives: [native("ike")])
    }

    // MARK: - The order persists, and an unarranged Mac is unchanged

    /// With no arrangement anywhere, the list is exactly what it has always been:
    /// profiles, then subprocess tunnels, then native VPNs, inside each heading. A
    /// reorder feature that quietly reshuffled everybody's sidebar on first launch
    /// would be a regression dressed as a feature.
    @Test func withNoArrangementTheStoreOrderStands() {
        let w = unarrangedWorld()
        #expect(w.order.tags(in: .wholeMac) == ["ovpn", "wg", ConnectListing.tag(forNative: "ike")])
        #expect(w.order.tags(in: .localPort) == [ConnectListing.tag(forTunnel: "socks-a"),
                                                 ConnectListing.tag(forTunnel: "socks-b")])
    }

    /// A rank on each VPN is what the list is sorted by — including across stores,
    /// which is the whole point: a native VPN can be dragged above an NE profile
    /// because the sidebar stopped showing which transport carries a connection.
    @Test func theArrangementIsWhatTheListIsSortedBy() {
        let w = World(profiles: [.init(id: "ovpn", kind: .openVPN, order: 2)],
                      tunnels: [sshTunnel("netA", .netTunnel, order: 0)],
                      natives: [native("ike", order: 1)])
        #expect(w.order.tags(in: .wholeMac) == [ConnectListing.tag(forTunnel: "netA"),
                                                ConnectListing.tag(forNative: "ike"),
                                                "ovpn"])
    }

    /// A VPN added today has no rank, so it goes to the END of its heading rather than
    /// taking somebody's first-choice slot — the same rule the servers table applies to
    /// a server that turns up in a re-imported configuration.
    @Test func anUnarrangedRowSortsLastInItsHeading() {
        let w = World(profiles: [.init(id: "new", kind: .openVPN),
                                 .init(id: "placed", kind: .openVPN, order: 7)])
        #expect(w.order.tags(in: .wholeMac) == ["placed", "new"])
    }

    /// One move, stated plainly: the row lands where the command said, and the
    /// arrangement that was written down reproduces it. This is the only honest form of
    /// "the order persists" — the move is applied to the records the way the three
    /// stores apply it, and the list is then read back from those records.
    @Test func oneMoveUpLandsTheRowOneHigherAndIsWrittenDown() throws {
        var w = unarrangedWorld()
        w.order.commands(for: "wg").moveUp()
        w.apply(try #require(w.written.positions))
        #expect(w.order.tags(in: .wholeMac) == ["wg", "ovpn", ConnectListing.tag(forNative: "ike")])
    }

    /// Two moves in a row, each applied before the next is made — which is what the
    /// sidebar does, because the arrangement is rebuilt from the stores on every
    /// redraw. A row can therefore be walked from the bottom of its heading to the top
    /// with the keyboard alone.
    @Test func repeatedMovesWalkARowToTheTopOfItsHeading() throws {
        var w = unarrangedWorld()
        let subject = ConnectListing.tag(forNative: "ike")
        #expect(w.order.tags(in: .wholeMac).last == subject)
        for _ in 0..<2 {
            w.order.commands(for: subject).moveUp()
            w.apply(try #require(w.written.positions))
        }
        #expect(w.order.tags(in: .wholeMac) == [subject, "ovpn", "wg"])
        // …and it is now first, so Move Up says why rather than doing nothing.
        #expect(w.order.commands(for: subject).upReason != nil)
    }

    // MARK: - Both windows agree

    /// The arrangement is a pure function of the three stores, so two windows reading
    /// the same stores cannot draw different lists. Stated as an identity, which is the
    /// only way it stays true: there is no per-window state to diverge.
    @Test func theSameStoresGiveTheSameListEveryTime() throws {
        var w = unarrangedWorld()
        let order = w.order
        order.commands(for: "wg").moveUp()
        w.apply(try #require(w.written.positions))

        // Two independently built arrangements over the same records — which is exactly
        // what the two windows are.
        let a = w.order
        let b = w.order
        #expect(a.allTags == b.allTags)
        #expect(a.tags(in: .wholeMac) == b.tags(in: .wholeMac))
        #expect(a.tags(in: .localPort) == b.tags(in: .localPort))
        // And it is the concatenation of the sections, so the list the connect window
        // draws and the list `ConnectListing.rowTags` reports are the same list.
        #expect(a.allTags == ConnectListing.rowTags(profiles: w.profiles,
                                                    tunnels: w.tunnels,
                                                    native: w.natives))
    }

    // MARK: - A reorder changes no tag, and loses no row

    /// Both sidebars select by tag, and a settings route between the two windows is
    /// resolved by tag. A move that renamed one would lose the selection and send a
    /// route to nothing.
    @Test func aReorderChangesNoTag() {
        var w = unarrangedWorld()
        let before = Set(w.order.allTags)
        for _ in 0..<3 {
            let tags = w.order.tags(in: .wholeMac)
            let order = w.order
            order.commands(for: tags.last!).moveUp()
            if let p = w.written.positions { w.apply(p) }
        }
        #expect(Set(w.order.allTags) == before)
        #expect(w.order.allTags.count == before.count, "a reorder must not duplicate a row either")
    }

    /// EVERY VPN STILL APPEARS EXACTLY ONCE. Sorting is the operation most likely to
    /// lose a row — one dropped by a comparator would simply not be drawn — so the
    /// invariant `ConnectListingTests` holds for an unarranged list is restated here
    /// for an arranged one.
    @Test func everyVPNAppearsExactlyOnceHoweverItIsArranged() {
        var w = unarrangedWorld()
        // A deliberately awkward arrangement: duplicate ranks, a negative one, a huge
        // one, and two rows with none at all.
        w.profiles = [.init(id: "ovpn", kind: .openVPN, order: 5),
                      .init(id: "wg", kind: .wireGuard, order: 5)]
        w.tunnels = [sshTunnel("socks-a", .socks, order: -3), sshTunnel("socks-b", .socks)]
        w.natives = [native("ike", order: Int.max)]
        let tags = w.order.allTags
        #expect(tags.count == 5)
        #expect(Set(tags).count == 5)
        for expected in ["ovpn", "wg", ConnectListing.tag(forTunnel: "socks-a"),
                         ConnectListing.tag(forTunnel: "socks-b"), ConnectListing.tag(forNative: "ike")] {
            #expect(tags.contains(expected))
        }
    }

    // MARK: - A row cannot leave its section

    /// THE REFUSAL, and it is structural rather than a check: `positions` takes a
    /// section and section-local indices, and `Reorder.moved` clamps to that section's
    /// own bounds. So "drag it far past the end" lands the row last among its OWN
    /// heading's rows and never in the other one.
    ///
    /// It matters because a row's heading says what connecting it does to this Mac —
    /// whole-Mac traffic, or a port nothing uses until something is aimed at it — so a
    /// gesture that moved a row between them would be a security-determining change
    /// made by dragging.
    @Test func aRowCannotBeDraggedIntoTheOtherHeading() throws {
        let w = unarrangedWorld()
        let sections = w.order.sections
        let localBefore = w.order.tags(in: .localPort)

        // Push the first whole-Mac row as far down as any index can name.
        let positions = try #require(ConnectOrder.positions(after: sections, movingIn: .wholeMac,
                                                            from: 0, to: 99))
        var moved = w
        moved.apply(positions)
        #expect(moved.order.tags(in: .wholeMac).last == "ovpn")
        #expect(moved.order.tags(in: .localPort) == localBefore,
                "moving a whole-Mac VPN must not touch the local ports")
        #expect(moved.order.tags(in: .wholeMac).count == 3)

        // And the same upwards, from the other heading.
        let up = try #require(ConnectOrder.positions(after: sections, movingIn: .localPort,
                                                     from: 1, to: -99))
        var moved2 = w
        moved2.apply(up)
        #expect(moved2.order.tags(in: .localPort).first == ConnectListing.tag(forTunnel: "socks-b"))
        #expect(moved2.order.tags(in: .wholeMac) == w.order.tags(in: .wholeMac))
    }

    /// A heading that isn't on screen names no rows, so a move inside it is nothing —
    /// not a crash, and not a write.
    @Test func aMoveInAHeadingThatIsNotThereIsNothing() {
        let w = World(profiles: [.init(id: "ovpn", kind: .openVPN)])
        #expect(w.order.tags(in: .localPort).isEmpty)
        #expect(ConnectOrder.positions(after: w.order.sections, movingIn: .localPort,
                                       from: 0, to: 1) == nil)
        // …and a move that changes nothing writes nothing, so the sidebar doesn't
        // announce a move that didn't happen.
        #expect(ConnectOrder.positions(after: w.order.sections, movingIn: .wholeMac,
                                       from: 0, to: 0) == nil)
        #expect(ConnectOrder.positions(after: w.order.sections, movingIn: .wholeMac,
                                       from: 9, to: 0) == nil)
    }

    /// A ROW WHOSE SECTION CHANGES LATER LANDS SOMEWHERE SENSIBLE. This is why the
    /// ranks are global rather than 0…n−1 within each heading: turn an SSH tunnel from
    /// a local port into a whole-Mac VPN — which its own settings do, not the sidebar —
    /// and it arrives in the place its rank has always implied relative to the rows it
    /// never moved past, instead of at whatever index it happened to hold in the
    /// heading it left.
    @Test func aRowThatChangesHeadingKeepsItsRelativePlace() {
        var w = unarrangedWorld()
        // Arrange everything: whole-Mac ranks 0…2, local ports 3…4.
        let all = w.order.allTags
        var positions: [String: Int] = [:]
        for (i, tag) in all.enumerated() { positions[tag] = i }
        w.apply(positions)
        let socksB = ConnectListing.tag(forTunnel: "socks-b")
        #expect(w.order.tags(in: .localPort).last == socksB)

        // Now its own settings move it across the line.
        for i in w.tunnels.indices where w.tunnels[i].id == "socks-b" {
            w.tunnels[i].sshMode = .netTunnel
        }
        let whole = w.order.tags(in: .wholeMac)
        #expect(whole.contains(socksB))
        // It came from below every whole-Mac row, and it still is: nothing else moved,
        // and it did not land on top of somebody's first-choice slot.
        #expect(whole.last == socksB)
        #expect(whole.dropLast() == ["ovpn", "wg", ConnectListing.tag(forNative: "ike")])
    }

    // MARK: - The keyboard path, and the ends of the list

    /// Move Up on the first row of a heading and Move Down on the last are no-ops that
    /// SAY WHY — and say it with the heading's name, because "already last" said to
    /// somebody looking at rows below it would be a lie about what the command does.
    @Test func theEndsOfAHeadingExplainThemselves() {
        let w = unarrangedWorld()
        let whole = w.order.tags(in: .wholeMac)
        let first = w.order.commands(for: whole.first!)
        let last = w.order.commands(for: whole.last!)

        #expect(first.upReason == ReorderCopy.alreadyFirst("VPN ovpn", in: ConnectionScope.wholeMac.sectionTitle))
        #expect(first.upReason?.contains("Whole-Mac VPNs") == true)
        #expect(first.downReason == nil)
        #expect(last.downReason?.contains("Whole-Mac VPNs") == true)
        #expect(last.upReason == nil)
        // And neither of them writes anything.
        first.moveUp()
        last.moveDown()
        #expect(w.written.positions == nil)
    }

    /// A heading with one row in it says so — naming the heading, because the list as a
    /// whole may be long while this part of it is a single row.
    @Test func aHeadingWithOneRowSaysThereIsNoOrderToChange() {
        let w = World(profiles: [.init(id: "ovpn", kind: .openVPN)],
                      tunnels: [sshTunnel("socks-a", .socks)])
        let commands = w.order.commands(for: "ovpn")
        #expect(commands.upReason == ReorderCopy.onlyOne(in: ConnectionScope.wholeMac.sectionTitle))
        #expect(commands.downReason?.contains("Whole-Mac VPNs") == true)
        commands.moveUp()
        #expect(w.written.positions == nil)
    }

    /// Nothing chosen is not the same as nothing to move: with two VPNs and no
    /// selection the buttons ask for a choice, and they say VPN rather than "row".
    @Test func withNothingSelectedTheButtonsAskForAChoice() {
        let w = unarrangedWorld()
        let commands = w.order.commands(for: nil)
        #expect(commands.upReason == ConnectOrderCopy.nothingSelected)
        #expect(commands.downReason == ConnectOrderCopy.nothingSelected)
        #expect(commands.index == nil)
        // The count is every row, so a list of many does not claim to be a list of one.
        #expect(commands.count == 5)
        commands.moveUp(); commands.moveDown()
        #expect(w.written.positions == nil)
    }

    /// With exactly ONE VPN in total and nothing selected, "there is only one" IS the
    /// honest answer, and it is the one given.
    @Test func oneVPNInTotalHasNoOrderToChange() {
        let w = World(profiles: [.init(id: "only", kind: .openVPN)])
        #expect(w.order.commands(for: nil).upReason == ReorderCopy.onlyOne)
    }

    /// A tag that names nothing on screen — a stale selection — moves nothing and
    /// crashes nothing.
    @Test func aStaleSelectionMovesNothing() {
        let w = unarrangedWorld()
        let commands = w.order.commands(for: "deleted-yesterday")
        #expect(commands.index == nil)
        commands.moveUp(); commands.moveDown()
        commands.drop(from: 0, insertingBefore: 1)
        #expect(w.written.positions == nil)
    }

    // MARK: - The platform's own drag goes through the same closure

    /// `List`'s `onMove` states its destination in PRE-REMOVAL coordinates, which is
    /// the classic off-by-one. It is routed through `ReorderCommands.drop` — the shape
    /// that means "insert before the row currently there" — so the drag and the buttons
    /// cannot disagree by one.
    @Test func theListsOwnMoveLandsWhereTheDropIndicatorWas() throws {
        var w = unarrangedWorld()
        // Drag the first whole-Mac row (ovpn) to just past the second (wg): SwiftUI
        // says `to: 2`, and the row must end up at index 1, not 2.
        w.order.move(in: .wholeMac, from: IndexSet(integer: 0), to: 2)
        w.apply(try #require(w.written.positions))
        #expect(w.order.tags(in: .wholeMac) == ["wg", "ovpn", ConnectListing.tag(forNative: "ike")])
    }

    /// A multi-row drag is refused rather than guessed at: this list's selection is a
    /// single tag, so two offsets cannot come from the user.
    @Test func aMultiRowMoveIsRefused() {
        let w = unarrangedWorld()
        w.order.move(in: .wholeMac, from: IndexSet([0, 1]), to: 3)
        #expect(w.written.positions == nil)
    }

    // MARK: - What is written, and to which store

    /// The arrangement is tag-keyed; the stores are id-keyed. The split is where the
    /// prefixes come off, so nothing but `ConnectListing` knows how a tag is spelled.
    @Test func theArrangementIsSplitToTheStoreThatOwnsEachRow() {
        let split = ConnectOrder.split([
            "plain-profile": 0,
            ConnectListing.tag(forTunnel: "t1"): 1,
            ConnectListing.tag(forNative: "n1"): 2,
        ])
        #expect(split.profiles == ["plain-profile": 0])
        #expect(split.tunnels == ["t1": 1])
        #expect(split.native == ["n1": 2])
    }

    /// A move renumbers EVERY row, in both headings — that is what makes the rank
    /// space global, and it is what a later section change relies on.
    @Test func aMoveRenumbersEveryRowNotJustItsOwnHeading() throws {
        let w = unarrangedWorld()
        let positions = try #require(ConnectOrder.positions(after: w.order.sections,
                                                            movingIn: .wholeMac, from: 0, to: 1))
        #expect(Set(positions.keys) == Set(w.order.allTags))
        #expect(Set(positions.values) == Set(0..<w.order.allTags.count),
                "the ranks are a permutation of 0…N−1, so no two rows share one")
    }

    // MARK: - It survives being carried to another Mac

    /// THE ARRANGEMENT IS EXPORTED, and this asserts it rather than assuming it.
    ///
    /// The three ranks reach the file by three different routes, which is why all
    /// three are checked: an NE profile's rides the `interface` block, which
    /// `ConfigDocument` writes STRUCTURALLY (every field of `VPNUIPrefs`, by
    /// reflection), so it costs no export code at all; a subprocess tunnel's and a
    /// native VPN's ride their own settings maps as `ssh.order` / `oc.order` /
    /// `native.order`, which is why those three ids are listed in
    /// `ConfigFormatTests.idsWithNoDescriptor`.
    ///
    /// A field at its default is omitted from the file, so an unarranged VPN carries
    /// nothing — which is right: it has nothing to say.
    @Test func theArrangementIsCarriedByAnExport() throws {
        var snapshot = ConfigSnapshot()

        var profile = ConfigSnapshot.VPN(id: "p", name: "P", kind: .openVPN, server: "s")
        var prefs = VPNUIPrefs()
        prefs.order = 3
        profile.uiPrefs = prefs
        snapshot.vpns.append(profile)

        var tunnel = ConfigSnapshot.VPN(id: "t", name: "T", kind: .ssh, server: "s")
        var tc = SubprocessTunnelConfig()
        tc.id = "t"
        tc.kind = .ssh
        tc.order = 1
        tunnel.subprocess = tc
        snapshot.vpns.append(tunnel)

        var nativeVPN = ConfigSnapshot.VPN(id: "n", name: "N", kind: .ikev2, server: "s")
        var nc = NativeVPNConfig()
        nc.id = "n"
        nc.kind = .ikev2
        nc.order = 2
        nativeVPN.native = nc
        snapshot.vpns.append(nativeVPN)

        let (root, _) = ConfigDocument.build(from: snapshot)
        let vpns = try #require(root[ConfigDocumentKeys.vpns]?.listValue)
        #expect(vpns.count == 3)

        let prefsBlock = try #require(vpns[0].mapValue?[ConfigDocumentKeys.interfacePrefs]?.mapValue)
        #expect(prefsBlock["order"]?.intValue == 3)

        let tunnelSettings = try #require(vpns[1].mapValue?[ConfigDocumentKeys.settings]?.mapValue)
        #expect(tunnelSettings["ssh.order"]?.intValue == 1)

        let nativeSettings = try #require(vpns[2].mapValue?[ConfigDocumentKeys.settings]?.mapValue)
        #expect(nativeSettings["native.order"]?.intValue == 2)
    }

    /// And it comes back. Import applies a settings map onto the struct's own decoder,
    /// so the rank arrives as a rank — which is what makes the arrangement survive the
    /// one path that carries a setup between Macs. (An imported VPN gets a NEW id, which
    /// is precisely why the rank rides the VPN instead of an app-level list of ids.)
    @Test func theArrangementComesBackFromAnImport() throws {
        var settings = ConfigMap()
        settings.put("ssh.order", .int(4))
        let tunnel = try ConfigImport.apply(settings, onto: SubprocessTunnelConfig(), namespace: "ssh.")
        #expect(tunnel.order == 4)

        var nativeSettings = ConfigMap()
        nativeSettings.put("native.order", .int(5))
        let native = try ConfigImport.apply(nativeSettings, onto: NativeVPNConfig(), namespace: "native.")
        #expect(native.order == 5)

        // An unarranged VPN says nothing and arrives unarranged.
        #expect(try ConfigImport.apply(ConfigMap(), onto: SubprocessTunnelConfig(),
                                       namespace: "ssh.").order == nil)
    }

    // MARK: - The words

    /// What VoiceOver hears after a move: what moved, where it landed, and WHICH
    /// HEADING — because "2 of 5" is a position within the heading, and without the
    /// heading the number would appear to contradict the list on screen.
    @Test func theAnnouncementNamesTheHeadingItLandedIn() {
        let said = ReorderCopy.landed("London", at: 1, of: 3, in: "Whole-Mac VPNs")
        #expect(said == "Moved London to 2 of 3 in Whole-Mac VPNs")
    }

    /// Nothing this list says may use a banned word, and nothing may leak our own
    /// vocabulary ("section", "tag", "index") into something spoken.
    @Test func theWordsFollowTheOntology() {
        let everything = [
            ConnectOrderCopy.nothingSelected,
            ConnectOrderCopy.noSubject,
            ConnectOrderCopy.scopeHelp,
            ReorderCopy.alreadyFirst("London", in: "Local Ports"),
            ReorderCopy.alreadyLast("London", in: "Local Ports"),
            ReorderCopy.onlyOne(in: "Local Ports"),
            ReorderCopy.landed("London", at: 0, of: 2, in: "Local Ports"),
        ]
        for s in everything {
            #expect(!s.isEmpty)
            for banned in ["credential", "Credential", "section", "Section", "tag", "index"] {
                #expect(!s.contains(banned), "\u{201C}\(s)\u{201D} uses \u{201C}\(banned)\u{201D}")
            }
        }
    }
}
