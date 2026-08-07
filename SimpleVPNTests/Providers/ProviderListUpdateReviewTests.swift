// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
//  ProviderListUpdateReviewTests.swift
//  THE APPROVAL FLOW, PINNED WHERE IT CAN BE.
//
//  `ProviderServerListDiffTests` already proves the update is HELD. These prove the
//  two things the sheet built on top of it must never get wrong:
//
//   • IT LEADS WITH THE DANGEROUS ONE. A moved public key on a server the user holds
//     ranks above everything, because WireGuard has no certificate behind it — the
//     key IS the authentication and it arrived in the same download as the address it
//     vouches for. An alphabetical list would put it wherever the alphabet left it.
//   • A HELD DIFF CANNOT BE APPLIED WITHOUT AN EXPLICIT ACTION, and declining leaves
//     the stored list BYTE-IDENTICAL — asserted on the bytes that would go to disk,
//     not on a value comparison, because "byte-identical" is the promise the copy
//     makes to the user.
//
//  Every removal gets a row of its own here too. A vanished server is retired, not
//  deleted, and a tidy-up that lost a third of the list is the whole reason the
//  update is being shown at all.
//

import Foundation
import Testing
@testable import SimpleVPN

struct ProviderListUpdateReviewTests {

    // MARK: Fixtures

    private static let keyA = "ofyfRvMPB0PPIGGItNL+5tNdvTKXuWye5CfjPgPNvQ8="
    private static let keyB = "V1WC7wt34kcSDyqPuUhN56NJ0v+GlqY9TwZR5WlzzB4="

    private func server(_ name: String, ipv4: String = "10.0.0.1",
                        key: String? = keyA) -> ProviderServer {
        ProviderServer(
            hostname: ProviderHostname("\(name).relays.mullvad.net",
                                       allowedSuffix: ".relays.mullvad.net")!,
            ipv4: ipv4, ipv6: nil, countryCode: "al", cityCode: "tia",
            cityName: "Tirana", peerKey: key.flatMap(ProviderPeerKey.init), active: true)
    }

    private func list(_ servers: [ProviderServer]) -> ProviderServerList {
        ProviderServerList(providerID: .mullvad, servers: servers, dropped: 0,
                           fetchedAt: Date(timeIntervalSince1970: 0))
    }

    private var mullvad: VPNServiceProvider { VPNServiceProviderCatalog.provider(.mullvad) }

    private func host(_ name: String) -> String { "\(name).relays.mullvad.net" }

    // MARK: - The ranking IS the design

    /// THE ONE THAT MATTERS. A moved public key on a server the user HOLDS comes
    /// first, ahead of a moved key on one they do not, ahead of a moved address,
    /// ahead of a removal, ahead of an arrival — whatever the alphabet says.
    @Test("the review leads with a moved public key on a server the user holds")
    func theDangerousChangeLeads() throws {
        // Named so the alphabet would produce the exact opposite order.
        let stored = list([server("aaa-address", ipv4: "10.0.0.1"),
                           server("mmm-gone"),
                           server("zzz-key", ipv4: "10.0.0.9")])
        let incoming = list([server("aaa-address", ipv4: "10.0.0.2"),
                             server("zzz-key", ipv4: "10.0.0.9", key: Self.keyB),
                             server("bbb-new")])
        let diff = ProviderServerListDiff.between(stored: stored, incoming: incoming)
        #expect(diff.needsConfirmation)

        let rows = ProviderListUpdateReview.rows(
            diff, heldHostnames: [host("aaa-address"), host("zzz-key"), host("mmm-gone")])
        #expect(rows.map(\.hostname) == [host("zzz-key"), host("aaa-address"),
                                         host("mmm-gone"), host("bbb-new")])
        #expect(ProviderListUpdateReview.hasMovedKeyOnHeldServer(rows))
        #expect(rows[0].isTheDangerousOne)
    }

    /// The same key change on a relay the user has never chosen still shows — it is a
    /// fact about the fleet — but it does not outrank a change to one they use, and
    /// it does not raise the leading warning on its own.
    @Test("a key change on a server the user does not hold ranks below one they do")
    func heldOutranksNotHeld() {
        let stored = list([server("a"), server("b")])
        let incoming = list([server("a", key: Self.keyB), server("b", key: Self.keyB)])
        let diff = ProviderServerListDiff.between(stored: stored, incoming: incoming)

        let onlyB = ProviderListUpdateReview.rows(diff, heldHostnames: [host("b")])
        #expect(onlyB.first?.hostname == host("b"))
        #expect(ProviderListUpdateReview.hasMovedKeyOnHeldServer(onlyB))

        let none = ProviderListUpdateReview.rows(diff, heldHostnames: [])
        #expect(!ProviderListUpdateReview.hasMovedKeyOnHeldServer(none),
                "the leading warning is about a server the user actually uses")
    }

    /// Same servers in, same rows out, every time — the hostname is a TIE-BREAK so
    /// two runs of one review cannot disagree, never the sort itself.
    @Test("the order is stable")
    func orderIsStable() {
        let stored = list([server("a"), server("b"), server("c")])
        let incoming = list([server("a", ipv4: "10.0.0.2"),
                             server("b", ipv4: "10.0.0.3"),
                             server("c", ipv4: "10.0.0.4")])
        let diff = ProviderServerListDiff.between(stored: stored, incoming: incoming)
        let once = ProviderListUpdateReview.rows(diff, heldHostnames: [])
        let twice = ProviderListUpdateReview.rows(diff, heldHostnames: [])
        #expect(once == twice)
        #expect(once.map(\.hostname) == [host("a"), host("b"), host("c")])
    }

    // MARK: - Removal is a change, not a tidy-up

    @Test("a vanished server gets its own row and says it is kept, not deleted")
    func removalIsShownAsRetained() throws {
        let stored = list([server("a"), server("b"), server("c"), server("d")])
        let incoming = list([server("a")])
        let diff = ProviderServerListDiff.between(stored: stored, incoming: incoming)
        #expect(diff.lostTooMany)

        let rows = ProviderListUpdateReview.rows(diff, heldHostnames: [host("b")])
        let removed = rows.filter { $0.change == .removed }
        #expect(removed.count == 3)
        for row in removed {
            let line = ProviderListUpdateCopy.sentence(row)
            #expect(line.contains("retired"))
            #expect(line.lowercased().contains("never deleted"))
        }
        // …and the "you have this one" clause is on the one the user actually holds.
        #expect(ProviderListUpdateCopy.sentence(try #require(rows.first { $0.hostname == host("b") }))
            .contains("You have this server"))
        let warning = ProviderListUpdateCopy.lostTooManyWarning(mullvad, retired: 3, stored: 4)
        #expect(warning.contains("3 of 4"))
        #expect(warning.contains("retired"))
    }

    /// Once an update is held, the WHOLE payload is what is being decided about — so
    /// the arrivals are listed too rather than slipped in beside the frightening half.
    @Test("new servers are listed as part of the same decision")
    func arrivalsAreListedToo() {
        let stored = list([server("a")])
        let incoming = list([server("a", key: Self.keyB), server("new")])
        let diff = ProviderServerListDiff.between(stored: stored, incoming: incoming)
        let rows = ProviderListUpdateReview.rows(diff, heldHostnames: [host("a")])
        #expect(rows.contains { $0.hostname == host("new") && $0.change == .added })
        #expect(rows.last?.hostname == host("new"), "arrivals come last, never first")
    }

    // MARK: - Nothing applies without an explicit action

    /// THE INVARIANT THE SHEET RESTS ON. Producing a review changes nothing, and the
    /// apply the fetch performs (`confirmed: false`) hands back what was stored.
    @Test("reviewing a held update applies none of it")
    func reviewingAppliesNothing() throws {
        let stored = list([server("a"), server("b")])
        let incoming = list([server("a", key: Self.keyB), server("b")])
        let diff = ProviderServerListDiff.between(stored: stored, incoming: incoming)
        #expect(diff.needsConfirmation)
        _ = ProviderListUpdateReview.rows(diff, heldHostnames: [host("a")])

        let unconfirmed = ProviderServerListUpdate.apply(diff, stored: stored,
                                                         incoming: incoming, confirmed: false)
        #expect(unconfirmed == stored)
    }

    /// DECLINING LEAVES THE STORED LIST BYTE-IDENTICAL — asserted on the bytes that
    /// would reach disk, because that is the promise `keepTitle`'s help text makes.
    @Test("declining leaves the stored list byte-identical")
    func decliningChangesNoByte() throws {
        let stored = list([server("a"), server("b", key: Self.keyA)])
        let incoming = list([server("a", ipv4: "10.9.9.9"), server("b", key: Self.keyB)])
        let diff = ProviderServerListDiff.between(stored: stored, incoming: incoming)
        #expect(diff.needsConfirmation)

        let encoder = JSONEncoder()
        encoder.outputFormatting = [.sortedKeys]
        let before = try encoder.encode(stored.stored)
        // Declining is "do not call apply at all"; the fetch's own unconfirmed apply
        // is the belt to that braces, and neither may change a byte.
        let after = try encoder.encode(
            ProviderServerListUpdate.apply(diff, stored: stored, incoming: incoming,
                                           confirmed: false).stored)
        #expect(before == after)
    }

    /// …and the accepting button, which is the ONE place `confirmed: true` is reached,
    /// applies the whole payload — including keeping every retired server rather than
    /// deleting it.
    @Test("accepting applies the whole update and keeps the retired servers")
    func acceptingAppliesEverything() {
        let stored = list([server("a"), server("b"), server("c")])
        let incoming = list([server("a", key: Self.keyB)])
        let diff = ProviderServerListDiff.between(stored: stored, incoming: incoming)
        let applied = ProviderServerListUpdate.apply(diff, stored: stored,
                                                     incoming: incoming, confirmed: true)
        #expect(applied.servers.count == 3, "nothing is ever deleted by an update")
        #expect(applied.server(host("a"))?.peerKey?.base64 == Self.keyB)
        #expect(applied.server(host("b"))?.active == false)
        #expect(applied.server(host("c"))?.active == false)
    }

    // MARK: - There is exactly one way to say yes

    private static let repoRoot: URL = URL(fileURLWithPath: #filePath)
        .deletingLastPathComponent()      // Providers/
        .deletingLastPathComponent()      // SimpleVPNTests/
        .deletingLastPathComponent()      // repo root

    /// A HELD DIFF CANNOT BE APPLIED WITHOUT AN EXPLICIT ACTION, asserted the only way
    /// a test can assert it about a whole app: `confirmed: true` is reachable from
    /// exactly one place in the shipping sources, and that place is the approval
    /// sheet's own button. A second call site — a "just apply it" convenience, a
    /// retry path, a migration — would make the gate decorative, and it would look
    /// entirely reasonable in review.
    @Test("only the approval sheet can confirm a held list update")
    func exactlyOneWayToConfirm() throws {
        let root = Self.repoRoot.appendingPathComponent("SimpleVPN")
        var sites: [String] = []
        let files = FileManager.default.enumerator(at: root, includingPropertiesForKeys: nil)
        while let url = files?.nextObject() as? URL {
            guard url.pathExtension == "swift",
                  let text = try? String(contentsOf: url, encoding: .utf8) else { continue }
            for line in text.components(separatedBy: "\n") {
                let trimmed = line.trimmingCharacters(in: .whitespaces)
                // Comments talk ABOUT the rule; only code can break it.
                guard !trimmed.hasPrefix("//"), !trimmed.hasPrefix("///"),
                      trimmed.contains("confirmed: true") else { continue }
                sites.append(url.lastPathComponent)
            }
        }
        #expect(sites == ["ProviderListUpdateSheet.swift"],
                "`confirmed: true` must be reachable from the approval sheet and nowhere else; found \(sites)")
    }

    // MARK: - The words

    @Test("the summary counts key changes separately from address changes")
    func summaryDoesNotFlattenTheDangerousCount() {
        let stored = list([server("a"), server("b"), server("gone")])
        let incoming = list([server("a", key: Self.keyB),
                             server("b", ipv4: "10.0.0.5"),
                             server("new")])
        let diff = ProviderServerListDiff.between(stored: stored, incoming: incoming)
        let summary = ProviderListUpdateCopy.summary(diff)
        #expect(summary.contains("1 server changed public key"))
        #expect(summary.contains("1 changed address"))
        #expect(summary.contains("1 no longer listed"))
        #expect(summary.contains("1 new"))
    }

    /// The one warning that leads says what a public key IS before it says what
    /// changed — "the peer key rotated" means nothing to somebody who has never had
    /// to know WireGuard has no certificate behind it.
    @Test("the leading warning explains what a public key is for")
    func theWarningExplainsItself() {
        let text = ProviderListUpdateCopy.movedKeyWarning(mullvad)
        #expect(text.contains("no certificate"))
        #expect(text.contains("public key"))
        #expect(text.contains("Mullvad"))
    }

    /// There is no per-row choice, and the sheet says why where somebody would look
    /// for one.
    @Test("the all-or-nothing rule is stated, not merely implemented")
    func allOrNothingIsSaid() {
        #expect(ProviderListUpdateCopy.allOrNothing.lowercased().contains("whole list"))
        #expect(ProviderListUpdateCopy.allOrNothing.lowercased().contains("nothing to tick"))
    }

    /// The sheet's first sentence is that nothing has happened — the thing a person
    /// most needs and the thing a diff view usually leaves out.
    @Test("the sheet says nothing has been changed before it says what would be")
    func nothingAppliedYetIsSaidFirst() {
        #expect(ProviderListUpdateCopy.nothingAppliedYet.contains("Nothing has been changed"))
        #expect(ProviderListUpdateCopy.keepHelp(mullvad).contains("exactly as they are"))
        #expect(ProviderListUpdateCopy.declined(mullvad).contains("exactly as they were"))
    }

    /// Every string the sheet can say, held to ONTOLOGY.md — same treatment as
    /// `ProviderPickerCopyTests`, and for the same reason: a picker acquires a noun
    /// for the thing it installs the moment nobody is watching.
    @Test("the approval copy keeps the house vocabulary")
    func houseVocabulary() {
        let stored = list([server("a"), server("b"), server("c")])
        let incoming = list([server("a", key: Self.keyB), server("d")])
        let diff = ProviderServerListDiff.between(stored: stored, incoming: incoming)
        let rows = ProviderListUpdateReview.rows(diff, heldHostnames: [host("a")])
        var copy = [ProviderListUpdateCopy.title(mullvad),
                    ProviderListUpdateCopy.nothingAppliedYet,
                    ProviderListUpdateCopy.summary(diff),
                    ProviderListUpdateCopy.movedKeyWarning(mullvad),
                    ProviderListUpdateCopy.lostTooManyWarning(mullvad, retired: 2, stored: 3),
                    ProviderListUpdateCopy.allOrNothing,
                    ProviderListUpdateCopy.keepTitle,
                    ProviderListUpdateCopy.acceptTitle(mullvad),
                    ProviderListUpdateCopy.keepHelp(mullvad),
                    ProviderListUpdateCopy.acceptHelp(mullvad),
                    ProviderListUpdateCopy.accepted(mullvad, total: 3),
                    ProviderListUpdateCopy.declined(mullvad)]
        for row in rows {
            copy += [ProviderListUpdateCopy.rowTitle(row),
                     ProviderListUpdateCopy.sentence(row),
                     ProviderListUpdateCopy.spoken(row),
                     ProviderListUpdateCopy.heading(row)]
        }
        for text in copy {
            let lower = text.lowercased()
            for banned in ["credential", "log in", "login", "logon",
                           "bundle", "preset", "relay list", "endpoint"] {
                #expect(!lower.contains(banned),
                        "\(text.debugDescription) uses \(banned.debugDescription) \u{2014} see ONTOLOGY.md")
            }
        }
        // Nothing spoken may be empty: a row VoiceOver reads as its hostname alone
        // says that something changed and nothing about what.
        for row in rows {
            #expect(ProviderListUpdateCopy.spoken(row).contains(row.hostname))
            #expect(ProviderListUpdateCopy.spoken(row)
                .contains(ProviderListUpdateCopy.sentence(row)))
            #expect(!ProviderListUpdateCopy.heading(row).isEmpty)
        }
    }
}
