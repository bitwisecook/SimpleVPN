// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
//  ProviderPickerCopyTests.swift
//  THE NAMING RULE, EXTENDED TO THE SURFACE THAT WOULD BREAK IT.
//
//  `VPNServiceProviderTests` already holds the catalogue to ONTOLOGY.md §7. But the
//  catalogue is not where the word "bundle" would actually appear — a BUTTON is, and
//  the buttons did not exist when that test was written. This file closes that gap,
//  because the request that started the whole feature used the banned word and the
//  first thing a picker acquires is a noun for the thing it installs.
//

import Foundation
import Testing
@testable import SimpleVPN

struct ProviderPickerCopyTests {

    /// Every string the picker can show, so a new one cannot be added outside the
    /// checks below without being listed here.
    static var allCopy: [String] {
        var out = [ProviderPickerCopy.sectionTitle,
                   ProviderPickerCopy.sectionDetail,
                   ProviderPickerCopy.firstRunDetail,
                   ProviderPickerCopy.nothingMatches,
                   ProviderPickerCopy.applyTitle(count: 1),
                   ProviderPickerCopy.applyTitle(count: 12)]
        for p in VPNServiceProviderCatalog.all {
            out += [ProviderPickerCopy.title(p),
                    ProviderPickerCopy.actionTitle(p),
                    ProviderPickerCopy.detail(p),
                    ProviderPickerCopy.consentTitle(p),
                    ProviderPickerCopy.consentConfirm(p),
                    ProviderPickerCopy.consentMessage(p, throughTunnel: true),
                    ProviderPickerCopy.consentMessage(p, throughTunnel: false),
                    ProviderPickerCopy.applied(count: 3, provider: p, vpn: "Work")]
            if let size = ProviderPickerCopy.downloadSize(p) { out.append(size) }
        }
        return out
    }

    // MARK: ONTOLOGY.md §7

    /// THERE IS NO USER-FACING NOUN FOR THE THING BEING INSTALLED. Every one of these
    /// words promises a completeness the feature cannot deliver, because the last
    /// mile is an account SimpleVPN deliberately does not touch.
    @Test("no picker copy calls anything a bundle, a pack or a preset")
    func noBundleVocabulary() {
        for text in Self.allCopy {
            let lower = text.lowercased()
            for banned in ["bundle", "preset", " pack", "profile template"] {
                #expect(!lower.contains(banned),
                        "\(text.debugDescription) uses \(banned.debugDescription) \u{2014} see ONTOLOGY.md")
            }
        }
    }

    /// The house vocabulary the rest of the app is held to. "Credential" is banned
    /// from UI copy and so is every spelling of "log in" — and this surface is
    /// unusually likely to acquire one, since three of the four providers gate on a
    /// sign-in.
    @Test("picker copy follows the house vocabulary")
    func houseVocabulary() {
        for text in Self.allCopy {
            let lower = text.lowercased()
            for banned in ["credential", "log in", "login", "logon"] {
                // "service credentials" is Nord's OWN name for the thing, quoted from
                // them, and ONTOLOGY rule 2 permits a vendor's proper noun. It comes
                // from the catalogue, which its own test governs.
                if banned == "credential", text.contains("service credentials") { continue }
                #expect(!lower.contains(banned), "\(text.debugDescription) uses \(banned.debugDescription)")
            }
        }
    }

    /// No copy may promise a sign-in. That was the scope decision, and copy is where
    /// it either holds or leaks.
    ///
    /// THE NEGATIONS ARE REMOVED BEFORE MATCHING, and getting that wrong is what the
    /// first version of this test did: "SimpleVPN never signs you in" is the sentence
    /// the rule EXISTS to produce, and a check that banned the phrase outright failed
    /// on the very copy it was meant to protect. So the disclaimers are stripped
    /// first, and what is left must contain no affirmative claim at all.
    @Test("nothing promises SimpleVPN will sign the user in")
    func nothingPromisesASignIn() {
        let disclaimers = ["never signs you in", "cannot sign you in", "does not sign you in",
                           "won\u{2019}t sign you in", "not sign anyone in"]
        for text in Self.allCopy {
            var lower = text.lowercased()
            for disclaimer in disclaimers {
                lower = lower.replacingOccurrences(of: disclaimer, with: "")
            }
            for forbidden in ["sign you in", "signs you in", "signing you in"] {
                #expect(!lower.contains(forbidden),
                        "\(text.debugDescription) promises a sign-in")
            }
        }
    }

    /// …and the disclaimer is not merely permitted, it is REQUIRED where it matters.
    /// The consent sheet is the last thing a person reads before a provider is
    /// contacted, so that is where the promise has to be stated rather than implied.
    @Test("the consent sheet states outright that SimpleVPN cannot sign you in")
    func consentStatesTheLimit() {
        for p in VPNServiceProviderCatalog.all where p.blocked == nil {
            for throughTunnel in [true, false] {
                #expect(ProviderPickerCopy.consentMessage(p, throughTunnel: throughTunnel)
                    .contains("cannot sign you in"),
                        "\(p.displayName)'s sheet does not say SimpleVPN cannot sign you in")
            }
        }
    }

    // MARK: The honesty rules, per provider

    /// THE CENTRAL ONE. A working provider's row states what the user must still
    /// supply, BEFORE anything is fetched — because a row that looks like it should
    /// just connect and cannot is worse than no row at all.
    @Test("every working provider's row states the gap before the fetch")
    func everyRowStatesTheGap() {
        for p in VPNServiceProviderCatalog.all where p.blocked == nil {
            let detail = ProviderPickerCopy.detail(p)
            #expect(detail.contains(p.stillNeeded),
                    "\(p.displayName)'s row does not say what the user still needs")
            #expect(detail.lowercased().contains("account"))
        }
    }

    /// The protocol is named, because it decides WHICH thing the user needs to have:
    /// a WireGuard provider wants a key and a tunnel address, an OpenVPN one wants a
    /// username and a password, and somebody who has one and not the other should be
    /// able to tell from the row.
    @Test("the row names the protocol, since that decides what you need")
    func rowsNameTheProtocol() {
        #expect(ProviderPickerCopy.detail(VPNServiceProviderCatalog.mullvad)
            .contains("WireGuard"))
        for p in [VPNServiceProviderCatalog.nordVPN, VPNServiceProviderCatalog.ipVanish] {
            #expect(ProviderPickerCopy.detail(p).contains("OpenVPN"))
        }
    }

    /// NORD'S ROW MUST SAY THE CREDENTIALS ARE NOT THE ACCOUNT LOGIN. That distinction
    /// is the single commonest thing Nord users get wrong, and a row that omitted it
    /// would send somebody to type their NordAccount password and get an auth failure
    /// with no explanation.
    @Test("Nord's row distinguishes service credentials from the account sign-in")
    func nordNamesServiceCredentials() {
        let detail = ProviderPickerCopy.detail(VPNServiceProviderCatalog.nordVPN).lowercased()
        #expect(detail.contains("service credentials"))
        #expect(detail.contains("not the email and password"))
    }

    /// Mullvad's row says the configuration has to be downloaded FIRST — the list
    /// turns one relay into 567, and can do nothing at all before that one exists.
    @Test("Mullvad's row says a configuration must be imported first")
    func mullvadNamesTheDownloadedConfiguration() {
        let detail = ProviderPickerCopy.detail(VPNServiceProviderCatalog.mullvad)
        #expect(detail.contains("mullvad.net"))
        #expect(detail.lowercased().contains("import"))
    }

    /// PROTON'S BUTTON MUST NOT PRETEND. Its row exists (an absent row is
    /// indistinguishable from a bug), states the absence, and names the thing that
    /// does work — and its action is an import, never a fetch.
    @Test("Proton's row states the absence and offers the import that works")
    func protonOffersTheImport() {
        let proton = VPNServiceProviderCatalog.protonVPN
        #expect(ProviderPickerCopy.detail(proton).lowercased().contains("import"))
        #expect(ProviderPickerCopy.actionTitle(proton).contains("Import"))
        // …and never offers to fetch, which is the thing that would fail.
        #expect(!ProviderPickerCopy.actionTitle(proton).lowercased().contains("get"))
        // No size, because nothing is downloaded.
        #expect(ProviderPickerCopy.downloadSize(proton) == nil)
    }

    /// The actions are VERBS naming what happens, never "Add Mullvad" or "Set up
    /// Mullvad" — both of which promise a working VPN.
    @Test("the actions are verbs about a server list, not about getting a VPN")
    func actionsAreVerbs() {
        for p in VPNServiceProviderCatalog.all where p.blocked == nil {
            let action = ProviderPickerCopy.actionTitle(p)
            #expect(action.contains("server list"), "\(action) does not say what it fetches")
            #expect(!action.lowercased().hasPrefix("add \(p.displayName.lowercased())"))
            #expect(!action.lowercased().hasPrefix("set up"))
        }
    }

    // MARK: The consent sheet

    /// THE HOST IS NAMED BEFORE IT IS CONTACTED. That is the whole reason the sheet
    /// exists rather than a spinner.
    @Test("the first-fetch sheet names the host it will contact")
    func consentNamesTheHost() throws {
        for p in VPNServiceProviderCatalog.all where p.blocked == nil {
            let host = try #require(p.listURL?.host())
            #expect(ProviderPickerCopy.consentMessage(p, throughTunnel: false).contains(host),
                    "\(p.displayName)'s sheet does not name \(host)")
        }
    }

    /// It says what the provider learns, and the answer differs depending on whether
    /// the request goes out through their own tunnel — which is the one place this
    /// feature can be meaningfully better than a browser.
    @Test("the sheet says what the provider learns, and it differs through the tunnel")
    func consentSaysWhatTheyLearn() {
        let p = VPNServiceProviderCatalog.mullvad
        let outside = ProviderPickerCopy.consentMessage(p, throughTunnel: false)
        let inside = ProviderPickerCopy.consentMessage(p, throughTunnel: true)
        #expect(outside.contains("real address"))
        #expect(inside.contains("their own network"))
        #expect(outside != inside)
        // Both say what will NOT happen, because "will this sign me in?" is the
        // question somebody actually has.
        for text in [outside, inside] {
            #expect(text.contains("Nothing about you is sent"))
            #expect(text.contains("cannot sign you in"))
        }
    }

    /// One provider per sheet. Agreeing to Mullvad is not agreeing to Nord, so the
    /// title names a company rather than the feature.
    @Test("the sheet asks about one named provider, never about the feature")
    func consentIsPerProvider() {
        for p in VPNServiceProviderCatalog.all {
            #expect(ProviderPickerCopy.consentTitle(p).contains(p.displayName))
            #expect(ProviderPickerCopy.consentConfirm(p).contains(p.displayName))
        }
    }

    /// The confirming button says what it will do. Never "OK".
    @Test("the confirming button is not OK")
    func confirmButtonSaysWhatItDoes() {
        for p in VPNServiceProviderCatalog.all {
            let title = ProviderPickerCopy.consentConfirm(p)
            #expect(title != "OK" && title != "Continue")
            #expect(title.hasPrefix("Ask "))
        }
    }

    // MARK: The size, before agreeing to it

    /// Nord's list is about 9 MB and that is worth knowing before agreeing to it —
    /// the sizes were measured, not guessed (see `VPNServiceProvider.approximateBytes`).
    @Test("the download size is stated for every provider that downloads anything")
    func downloadSizeIsStated() {
        for p in VPNServiceProviderCatalog.all where p.blocked == nil {
            #expect(ProviderPickerCopy.downloadSize(p) != nil,
                    "\(p.displayName) does not say how big its list is")
        }
        // Nord is the big one, and the sheet says so before asking.
        #expect(ProviderPickerCopy.consentMessage(VPNServiceProviderCatalog.nordVPN,
                                                  throughTunnel: true).contains("MB"))
    }

    /// The first-run page's wording carries the extra caveat that page needs: with no
    /// VPNs at all, somebody could reasonably read four company names as a way to GET
    /// a VPN. It is not.
    @Test("the first-run wording says this is not a way to buy or sign in to a VPN")
    func firstRunSaysWhatThisIsNot() {
        let text = ProviderPickerCopy.firstRunDetail.lowercased()
        #expect(text.contains("not a way to buy"))
        #expect(text.contains("account"))
    }
}
