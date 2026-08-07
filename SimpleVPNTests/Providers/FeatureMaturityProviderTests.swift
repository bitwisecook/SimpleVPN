// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
//  FeatureMaturityProviderTests.swift
//  THAT THE FOURTH MATURITY TABLE CANNOT LEAVE A PROVIDER UNCLAIMED, and that
//  flipping one is still a one-line change with no view edit — the rule
//  `FeatureMaturity.swift` exists to enforce, now applied to a fourth kind of
//  subject.
//
//  The claim being defended is narrow and easy to lose: **reading a provider's list
//  is not connecting to that provider.** Every one of these four gates the last mile
//  on an account SimpleVPN deliberately never touches, so "we fetched Mullvad's
//  list" must never quietly become "Mullvad works".
//

import Foundation
import Testing
@testable import SimpleVPN

struct FeatureMaturityProviderTests {

    /// Totality, with the one deliberate exemption spelled out. A provider SimpleVPN
    /// INTENDS to read must carry a claim; a provider it refuses outright must not,
    /// because its row states an absence and has nothing to qualify.
    ///
    /// The predicate is `blocked == nil` and deliberately NOT `canFetch`, and the
    /// first version of this test got that wrong. `canFetch` is additionally false
    /// while a provider's CA fingerprint is unpinned — a build-completeness state, not
    /// a decision about the provider — so keying the claim off it would silently
    /// un-claim NordVPN and IPVanish the moment somebody removed a pin, which is
    /// exactly the "unclaimed by omission" failure this registry exists to prevent.
    @Test("every provider we intend to read has a claim, and only those")
    func everyReadableProviderIsClaimed() {
        for p in VPNServiceProviderCatalog.all {
            let listed = FeatureMaturityRegistry.providers[p.id] != nil
            let intended = p.blocked == nil
            #expect(listed == intended,
                    "\(p.displayName): intended=\(intended) but listed=\(listed)")
        }
    }

    /// Nothing here is `.tested`. Nobody has connected to a server chosen from any of
    /// these lists, on this machine or any other, and a green badge would be the one
    /// dishonest thing this whole feature could ship.
    @Test("no provider claims to be tested")
    func nothingClaimsTested() {
        for (id, maturity) in FeatureMaturityRegistry.providers {
            #expect(maturity != .tested, "\(id.rawValue) claims to be tested")
        }
    }

    /// Mullvad is `.partlyVerified` because something real WAS proven — its live list
    /// was fetched and parsed — and `.untested` would throw that away as surely as
    /// `.tested` would overstate it.
    @Test("Mullvad is partly verified, and the clause says what was actually read")
    func mullvadIsPartlyVerified() throws {
        let maturity = FeatureMaturityRegistry.maturity(ofProvider: .mullvad)
        guard case .partlyVerified(let checked) = maturity else {
            Issue.record("Mullvad should be partly verified, got \(maturity)")
            return
        }
        #expect(checked.contains("fetched"))
        #expect(maturity.needsNotice)
    }

    /// A provider SimpleVPN cannot read produces NO notice — not an untested one.
    /// A banner on top of "this does not work here" is noise on top of a refusal.
    @Test("a provider that cannot be read carries no maturity notice")
    func unreadableProviderHasNoNotice() {
        #expect(VPNServiceProviderCatalog.protonVPN.maturityNotice == nil)
    }

    /// The notice is DERIVED, so flipping a claim is one line in the registry and no
    /// view edit anywhere — asserted by handing in a table with one entry changed,
    /// exactly as the other three subjects are tested.
    @Test("flipping a claim changes the whole notice with no view involved")
    func flippingAClaimIsTheWholeChange() throws {
        let mullvad = VPNServiceProviderCatalog.mullvad
        let untested = MaturityNotice.forProvider(mullvad, in: [.mullvad: .untested])
        let notice = try #require(untested)
        #expect(notice.badgeText == "Untested")
        #expect(notice.title.contains("never been tested"))
        #expect(MaturityNotice.forProvider(mullvad, in: [.mullvad: .tested]) == nil)
    }

    /// Every notice names its provider, says what would clear it, and — the clause
    /// this feature specifically needs — does not imply SimpleVPN signs anyone in.
    @Test("every provider notice names the provider and asks for a report")
    func noticeCopyIsComplete() throws {
        for p in VPNServiceProviderCatalog.all {
            guard let notice = p.maturityNotice else { continue }
            #expect(notice.title.contains(p.displayName))
            #expect(notice.detail.contains(p.displayName))
            #expect(notice.detail.lowercased().contains("telling us"),
                    "\(p.displayName)'s notice does not say what clears it")
            #expect(notice.key == "provider.\(p.id.rawValue)")
            #expect(!notice.spokenValue.isEmpty)
        }
    }

    /// The failure this table could produce that nothing else would catch: a notice
    /// that reads as though SimpleVPN could sign the user in to the provider.
    @Test("no provider notice suggests SimpleVPN signs anyone in")
    func noticesDoNotPromiseASignIn() {
        for p in VPNServiceProviderCatalog.all {
            guard let notice = p.maturityNotice else { continue }
            let copy = notice.detail.lowercased()
            for forbidden in ["log in", "login", "we sign you in"] where copy.contains(forbidden) {
                Issue.record("\(p.displayName)'s notice uses \(forbidden.debugDescription)")
            }
        }
    }
}
