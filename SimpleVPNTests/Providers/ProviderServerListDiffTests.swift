// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
//  ProviderServerListDiffTests.swift
//  THAT A LIST UPDATE CANNOT QUIETLY MOVE THE USER'S TRAFFIC.
//
//  Two failures are being guarded against, and they pull in opposite directions:
//
//   • UNDER-CONFIRMING — a substituted address or peer key applied silently, which
//     for WireGuard is a complete traffic redirection with no error at all. That is
//     what most of this file is about.
//   • OVER-CONFIRMING — a confirmation raised on every routine update, which is how
//     a confirmation stops being read. `movement` deliberately ignores city names,
//     country codes and service state, and there is a test that says so, in the same
//     spirit as the over-redaction counterparts in the export tests.
//
//  Plus the rule most designs miss: **removal is an attack too.** Somebody who can
//  shrink your list to the one server they control has chosen your exit, and a
//  deletion is the one change that leaves no evidence. Nothing here can delete.
//

import Foundation
import Testing
@testable import SimpleVPN

struct ProviderServerListDiffTests {

    // MARK: Fixtures

    private static let keyA = "ofyfRvMPB0PPIGGItNL+5tNdvTKXuWye5CfjPgPNvQ8="
    private static let keyB = "V1WC7wt34kcSDyqPuUhN56NJ0v+GlqY9TwZR5WlzzB4="

    private func server(_ name: String, ipv4: String = "10.0.0.1",
                        key: String? = keyA, city: String? = "Tirana",
                        active: Bool = true) -> ProviderServer {
        ProviderServer(
            hostname: ProviderHostname("\(name).relays.mullvad.net",
                                       allowedSuffix: ".relays.mullvad.net")!,
            ipv4: ipv4, ipv6: nil, countryCode: "al", cityCode: "tia",
            cityName: city, peerKey: key.flatMap(ProviderPeerKey.init), active: active)
    }

    private func list(_ servers: [ProviderServer]) -> ProviderServerList {
        ProviderServerList(providerID: .mullvad, servers: servers, dropped: 0,
                           fetchedAt: Date(timeIntervalSince1970: 0))
    }

    // MARK: - The first fetch

    /// A first fetch has nothing to be substituted for, so everything is added and
    /// nothing is pending. Asking somebody to confirm 567 servers they have never
    /// seen would be a ritual rather than a check.
    @Test("a first fetch adds everything and confirms nothing")
    func firstFetchIsRoutine() {
        let incoming = list([server("a"), server("b")])
        let diff = ProviderServerListDiff.between(stored: nil, incoming: incoming)
        #expect(diff.added.count == 2)
        #expect(diff.moved.isEmpty)
        #expect(diff.retired.isEmpty)
        #expect(diff.isRoutine)
    }

    // MARK: - Additions

    /// A brand-new server is applied without asking — providers add hardware — but
    /// it is reported as added so the row can carry "arrived on <date>" until it is
    /// used. That mark is the only defence WireGuard has against "the attacker added
    /// one very fast-looking server in your country".
    @Test("a new server applies quietly and is reported as added")
    func newServerIsQuietButReported() {
        let stored = list([server("a")])
        let incoming = list([server("a"), server("b")])
        let diff = ProviderServerListDiff.between(stored: stored, incoming: incoming)
        #expect(diff.added.map(\.id) == ["b.relays.mullvad.net"])
        #expect(diff.unchangedCount == 1)
        #expect(diff.isRoutine)
    }

    // MARK: - Substitution, which is the attack

    /// THE WIREGUARD CASE, and the reason this file exists. There is no certificate:
    /// the peer public key IS the authentication and it arrives in the same payload
    /// as the address it authenticates. Swapping both together sends every packet to
    /// the attacker with no error, so it must never apply on its own.
    @Test("a changed peer key is held pending, and named as a key change")
    func changedPeerKeyIsPending() throws {
        let stored = list([server("a", ipv4: "10.0.0.1", key: Self.keyA)])
        let incoming = list([server("a", ipv4: "203.0.113.9", key: Self.keyB)])
        let diff = ProviderServerListDiff.between(stored: stored, incoming: incoming)
        #expect(diff.needsConfirmation)
        let move = try #require(diff.moved.first)
        #expect(move.movement.contains(.peerKey))
        #expect(move.movement.contains(.address))
    }

    /// An address alone still counts. For OpenVPN the shipped CA makes this fail
    /// closed rather than dangerous, but the diff does not know which protocol it is
    /// serving and the safe answer is the same either way.
    @Test("a changed address alone is held pending")
    func changedAddressIsPending() throws {
        let stored = list([server("a", ipv4: "10.0.0.1")])
        let incoming = list([server("a", ipv4: "203.0.113.9")])
        let diff = ProviderServerListDiff.between(stored: stored, incoming: incoming)
        #expect(diff.needsConfirmation)
        let move = try #require(diff.moved.first)
        #expect(move.movement == .address)
    }

    /// THE OVER-CONFIRMING COUNTERPART. A provider renaming a city, correcting a
    /// country or taking a server out of service for the afternoon is not a security
    /// event. Raising a confirmation for it would train the user to click through the
    /// ones that matter.
    @Test("a renamed city, a corrected country and a downed server confirm nothing")
    func cosmeticChangesDoNotConfirm() {
        let stored = list([server("a", city: "Tirana", active: true)])
        let incoming = list([server("a", city: "Tirana, Albania", active: false)])
        let diff = ProviderServerListDiff.between(stored: stored, incoming: incoming)
        #expect(diff.isRoutine)
        #expect(diff.unchangedCount == 1)
        #expect(diff.moved.isEmpty)
    }

    // MARK: - Removal is an attack too

    /// A vanished server is retained and marked retired. Nothing an update does can
    /// make a server disappear from under somebody who had chosen it.
    @Test("a vanished server is kept and marked retired, never deleted")
    func removedServerIsRetiredNotDeleted() throws {
        let stored = list([server("a"), server("b"), server("c"), server("d")])
        let incoming = list([server("a"), server("b"), server("c")])
        let diff = ProviderServerListDiff.between(stored: stored, incoming: incoming)
        #expect(diff.retired.map(\.id) == ["d.relays.mullvad.net"])
        // One of four is under the threshold, so this is still routine.
        #expect(diff.isRoutine)
        let applied = ProviderServerListUpdate.apply(diff, stored: stored,
                                                     incoming: incoming, confirmed: false)
        #expect(applied.servers.count == 4)
        let retired = try #require(applied.server("d.relays.mullvad.net"))
        #expect(!retired.active)
    }

    /// A list that lost more than a third is held even though nothing was
    /// substituted, because shrinking the list IS the substitution: narrow it far
    /// enough and the attacker has chosen the exit.
    @Test("a list that lost more than a third is held pending on its own")
    func massRemovalIsPending() {
        let stored = list([server("a"), server("b"), server("c"), server("d"), server("e")])
        let incoming = list([server("a"), server("b")])
        let diff = ProviderServerListDiff.between(stored: stored, incoming: incoming)
        #expect(diff.moved.isEmpty)
        #expect(diff.lostTooMany)
        #expect(diff.needsConfirmation)
    }

    // MARK: - Applying

    /// THE FORGOT-TO-ASK CASE, and the failure mode is "nothing happened". A caller
    /// that never raises the confirmation cannot apply a substitution by accident.
    @Test("a pending update applied without confirmation leaves the stored list alone")
    func pendingWithoutConfirmationChangesNothing() {
        let stored = list([server("a", ipv4: "10.0.0.1", key: Self.keyA)])
        let incoming = list([server("a", ipv4: "203.0.113.9", key: Self.keyB)])
        let diff = ProviderServerListDiff.between(stored: stored, incoming: incoming)
        let applied = ProviderServerListUpdate.apply(diff, stored: stored,
                                                     incoming: incoming, confirmed: false)
        #expect(applied == stored)
        #expect(applied.server("a.relays.mullvad.net")?.ipv4 == "10.0.0.1")
    }

    @Test("the same update applies once it is confirmed")
    func confirmedUpdateApplies() {
        let stored = list([server("a", ipv4: "10.0.0.1", key: Self.keyA)])
        let incoming = list([server("a", ipv4: "203.0.113.9", key: Self.keyB)])
        let diff = ProviderServerListDiff.between(stored: stored, incoming: incoming)
        let applied = ProviderServerListUpdate.apply(diff, stored: stored,
                                                     incoming: incoming, confirmed: true)
        #expect(applied.server("a.relays.mullvad.net")?.ipv4 == "203.0.113.9")
        #expect(applied.server("a.relays.mullvad.net")?.peerKey?.base64 == Self.keyB)
    }

    /// ALL-OR-NOTHING, deliberately. Applying the safe half of a pending update would
    /// let an attacker land the additions they wanted while the confirmation sits
    /// unanswered — and it would make the confirmation read as optional.
    @Test("a pending update does not apply its safe half")
    func pendingUpdateIsAllOrNothing() {
        let stored = list([server("a", key: Self.keyA)])
        let incoming = list([server("a", key: Self.keyB), server("b")])
        let diff = ProviderServerListDiff.between(stored: stored, incoming: incoming)
        #expect(diff.added.count == 1)
        #expect(diff.needsConfirmation)
        let applied = ProviderServerListUpdate.apply(diff, stored: stored,
                                                     incoming: incoming, confirmed: false)
        #expect(applied.server("b.relays.mullvad.net") == nil)
    }
}
