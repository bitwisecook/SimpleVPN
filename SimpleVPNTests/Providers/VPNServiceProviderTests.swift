// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
//  VPNServiceProviderTests.swift
//  THAT THE PROVIDER CATALOGUE STAYS HONEST — which is a naming and copy problem
//  before it is a code problem, and is the single most likely way this feature gets
//  built wrong.
//
//  THE RULE BEING ENFORCED: a server list is not a working configuration. Every
//  provider that can be used must say, before anything is fetched, what the user
//  still has to supply; and every provider that cannot be used must say why rather
//  than being absent. A row that looks like it should just connect and cannot is
//  worse than no row at all.
//
//  The second half of the file holds the naming rule from ONTOLOGY.md, because
//  "bundle", "pack" and "preset" all promise a completeness none of these four can
//  deliver — the last mile is an account SimpleVPN deliberately does not touch.
//

import Foundation
import Testing
@testable import SimpleVPN

struct VPNServiceProviderTests {

    // MARK: Totality

    /// Every case has an entry. The lookup would otherwise fall back silently, and a
    /// silent fallback in a catalogue that names companies is a row claiming to be
    /// Proton while holding Mullvad's URL.
    @Test("every provider id has exactly one catalogue entry")
    func catalogueIsTotal() {
        for id in VPNServiceProviderID.allCases {
            #expect(VPNServiceProviderCatalog.provider(id).id == id)
        }
        #expect(VPNServiceProviderCatalog.all.count == VPNServiceProviderID.allCases.count)
    }

    // MARK: The honesty rule

    /// THE CENTRAL TEST. Either a provider states what the user must still supply, or
    /// it states why it cannot be used. Never neither, and never both.
    @Test("a provider either says what you still need, or says why it cannot be used")
    func everyProviderIsHonestAboutTheGap() {
        for p in VPNServiceProviderCatalog.all {
            if p.blocked == nil {
                #expect(!p.stillNeeded.isEmpty, "\(p.displayName) offers a list with no caveat")
                #expect(p.listURL != nil, "\(p.displayName) is unblocked with no list URL")
                #expect(p.kind != nil, "\(p.displayName) is unblocked with no protocol")
            } else {
                #expect(p.stillNeeded.isEmpty,
                        "\(p.displayName) is blocked; a 'you still need' line would read as a path forward")
                #expect(!p.canFetch)
            }
        }
    }

    /// The caveat has to name an account. All four providers gate the last mile on
    /// one, so a sentence that does not mention it is a sentence that has drifted.
    @Test("every caveat names the account the user must already have")
    func caveatsNameTheAccount() {
        for p in VPNServiceProviderCatalog.all where p.blocked == nil {
            #expect(p.stillNeeded.lowercased().contains("account"),
                    "\(p.displayName)'s caveat does not mention an account")
        }
    }

    /// And it must not imply we sign anyone in. No account integration of any kind
    /// was the scope decision; the copy is where that decision either holds or leaks.
    @Test("no caveat promises SimpleVPN will sign the user in")
    func nothingPromisesASignIn() {
        for p in VPNServiceProviderCatalog.all {
            let copy = (p.stillNeeded + " " + (p.blocked ?? "")).lowercased()
            for forbidden in ["we will sign you in", "signs you in automatically",
                              "log in", "login", "logon"] {
                #expect(!copy.contains(forbidden),
                        "\(p.displayName) uses \(forbidden.debugDescription)")
            }
        }
    }

    // MARK: Naming (ONTOLOGY.md)

    /// "Bundle", "pack" and "preset" are banned as our label, and this is the surface
    /// most likely to acquire one, because the request that started the feature used
    /// the word. The concept is real; the noun over-promises.
    @Test("no provider copy calls anything a bundle, a pack or a preset")
    func noBundleVocabulary() {
        for p in VPNServiceProviderCatalog.all {
            let copy = (p.displayName + " " + p.stillNeeded + " " + (p.blocked ?? "")).lowercased()
            for banned in ["bundle", "preset", " pack", "profile template"] {
                #expect(!copy.contains(banned),
                        "\(p.displayName) uses \(banned.debugDescription) \u{2014} see ONTOLOGY.md")
            }
        }
    }

    // MARK: Fail-closed

    /// A provider whose protocol involves a certificate cannot be fetched until its
    /// CA is pinned. A missing pin FAILS CLOSED — the alternative is fetching a CA
    /// nothing checks, which is the whole attack.
    @Test("an OpenVPN provider with no pinned CA cannot be fetched")
    func openVPNProvidersFailClosedWithoutAPin() {
        for p in VPNServiceProviderCatalog.all where p.kind == .openVPN {
            if p.caFingerprintSHA256 == nil {
                #expect(!p.canFetch, "\(p.displayName) would fetch with no CA pin")
            }
        }
    }

    // MARK: The measured facts

    /// Mullvad is WireGuard and not OpenVPN, and that is a measurement rather than a
    /// preference: `api.mullvad.net/www/relays/all/` returned 567 WireGuard relays,
    /// 13 bridges and zero OpenVPN on 2026-08-07, and `/www/relays/openvpn/` 404s. A
    /// future edit that offers a Mullvad `.ovpn` should fail here first.
    @Test("Mullvad is a WireGuard provider")
    func mullvadIsWireGuard() {
        #expect(VPNServiceProviderCatalog.mullvad.kind == .wireGuard)
        #expect(VPNServiceProviderCatalog.mullvad.canFetch)
    }

    /// Proton is blocked, and the row exists to say so. `ConnectListing`'s rule —
    /// never hide something the user came looking for — applies to a provider picker
    /// exactly as it applies to a profile, and an absent row is indistinguishable
    /// from a bug.
    @Test("Proton VPN is present, blocked, and names what does work instead")
    func protonIsPresentAndBlocked() throws {
        let proton = VPNServiceProviderCatalog.protonVPN
        #expect(!proton.canFetch)
        #expect(proton.listURL == nil)
        let why = try #require(proton.blocked)
        #expect(why.lowercased().contains("import"),
                "a blocked provider must name the path that does work")
    }

    /// Suffixes are the cheapest control in the feature, so every usable provider has
    /// one and it starts with a dot — `"x.evilipvanish.com"` must not pass a suffix
    /// written as `"ipvanish.com"`.
    @Test("every suffix is dot-anchored")
    func suffixesAreDotAnchored() {
        for p in VPNServiceProviderCatalog.all {
            #expect(p.hostnameSuffix.hasPrefix("."), "\(p.displayName) has an unanchored suffix")
            #expect(p.hostnameSuffix.count > 4)
        }
    }

    /// Every list URL is HTTPS. There is no option to make it otherwise and there
    /// must never be one.
    @Test("every list URL is https")
    func urlsAreHTTPS() {
        for p in VPNServiceProviderCatalog.all {
            guard let url = p.listURL else { continue }
            #expect(url.scheme == "https", "\(p.displayName) is not https")
        }
    }
}
