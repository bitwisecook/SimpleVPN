// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
//  ProviderListFetchTests.swift
//  THAT THE FETCH ASKS PERMISSION, ASKS THE RIGHT HOST, AND SAYS SO — none of which
//  needs a network, because all of it is decided before a socket is opened.
//
//  The transport itself is not tested here and cannot honestly be: it needs Mullvad
//  to answer. What IS tested is every decision the transport is wrapped in, which is
//  where the mistakes would be.
//

import Foundation
import Testing
@testable import SimpleVPN

struct ProviderListFetchPolicyTests {

    /// Everything permitted — the baseline the other cases turn one thing off from.
    static func allowed(_ connected: Set<VPNServiceProviderID> = [.mullvad])
        -> ProviderListFetchPolicy.Conditions {
        .init(enabled: true, managedForbids: false, onlyWhenConnected: true,
              hasConsented: true, connectedProviders: connected)
    }

    // MARK: Off by default

    /// The feature is off until somebody turns it on, and that is the DEFAULT rather
    /// than a state a first run has to reach. Asking a provider for its list tells
    /// them somebody at your address runs this app.
    @Test("the whole feature is off unless it has been turned on")
    func offByDefault() {
        var c = Self.allowed()
        c.enabled = false
        let refusal = ProviderListFetchPolicy.refusal(for: VPNServiceProviderCatalog.mullvad, c)
        #expect(refusal == .turnedOff)
        // …and the sentence names where to turn it on, rather than just refusing.
        #expect(refusal?.sentence.contains("Settings") == true)
    }

    /// "Only while connected" is ON by default, so the ordinary path routes the
    /// request through the provider's own exit — where they learn essentially nothing
    /// new, because they are already carrying the traffic.
    @Test("waiting for the tunnel is the default, and it says why")
    func waitsForTheTunnelByDefault() {
        let c = Self.allowed([])          // nothing connected
        let refusal = ProviderListFetchPolicy.refusal(for: VPNServiceProviderCatalog.mullvad, c)
        #expect(refusal == .waitingForTunnel)
        #expect(refusal?.sentence.contains("your own address") == true)
    }

    /// Connected to that provider ⇒ nothing in the way.
    @Test("connected to the provider, the fetch goes ahead")
    func connectedFetchesThroughTheTunnel() {
        #expect(ProviderListFetchPolicy.refusal(for: VPNServiceProviderCatalog.mullvad,
                                                Self.allowed([.mullvad])) == nil)
    }

    /// Connected to a DIFFERENT provider is not connected to this one. Fetching
    /// Mullvad's list down a Nord tunnel tells Nord you use Mullvad, which is worse
    /// than doing it in the clear.
    @Test("a tunnel to another provider does not count")
    func anotherProvidersTunnelDoesNotCount() {
        #expect(ProviderListFetchPolicy.refusal(for: VPNServiceProviderCatalog.mullvad,
                                                Self.allowed([.nordVPN])) == .waitingForTunnel)
    }

    // MARK: One provider at a time

    /// Consenting to Mullvad is not consenting to Nord, so the record is per provider
    /// and the refusal is `needsConsent` rather than an error — it is the sheet that
    /// names the host BEFORE anything is contacted.
    @Test("a provider never contacted before needs its own yes")
    func consentIsPerProvider() {
        var c = Self.allowed()
        c.hasConsented = false
        #expect(ProviderListFetchPolicy.refusal(for: VPNServiceProviderCatalog.mullvad, c)
                == .needsConsent)
    }

    // MARK: Fail closed

    /// An OpenVPN provider with no shipped CA fingerprint cannot be fetched at all.
    /// Fetching a certificate authority that nothing checks is the entire attack, so
    /// a missing pin is a refusal rather than an unpinned fetch.
    @Test("an OpenVPN provider with no pinned CA is refused, not fetched unpinned")
    func unpinnedOpenVPNProviderFailsClosed() {
        for p in [VPNServiceProviderCatalog.nordVPN, VPNServiceProviderCatalog.ipVanish]
        where p.caFingerprintSHA256 == nil {
            #expect(ProviderListFetchPolicy.refusal(for: p, Self.allowed([p.id])) == .notPinned)
        }
    }

    /// Proton's impossibility comes FIRST, before any switch. Telling somebody to
    /// flip a setting that cannot help is worse than silence — and the sentence
    /// carries the path that does work.
    @Test("Proton is refused for its own reason, whatever the settings say")
    func protonIsRefusedForItsOwnReason() throws {
        var c = Self.allowed()
        c.enabled = false
        c.managedForbids = true
        let refusal = try #require(ProviderListFetchPolicy.refusal(
            for: VPNServiceProviderCatalog.protonVPN, c))
        guard case .blocked(let why) = refusal else {
            Issue.record("Proton must be refused as blocked, not as a settings problem")
            return
        }
        #expect(why.lowercased().contains("import"))
    }

    /// An administrator's no outranks the user's yes.
    @Test("MDM can forbid the whole feature")
    func mdmWins() {
        var c = Self.allowed()
        c.managedForbids = true
        #expect(ProviderListFetchPolicy.refusal(for: VPNServiceProviderCatalog.mullvad, c)
                == .managed)
    }

    // MARK: Which host counts as "connected to this provider"

    /// Matched on the SHIPPED suffix, so a hostname a payload supplied can never
    /// widen what counts as being connected to Mullvad.
    @Test("connected providers are recognised by the shipped hostname suffix")
    func connectedProvidersComeFromTheSuffix() {
        #expect(ProviderListFetchPolicy.connected(hosts: ["se-got-wg-001.relays.mullvad.net"])
                == [.mullvad])
        #expect(ProviderListFetchPolicy.connected(hosts: ["US5063.NordVPN.com"]) == [.nordVPN])
        // A look-alike domain is not the provider.
        #expect(ProviderListFetchPolicy.connected(hosts: ["relays.mullvad.net.evil.example"])
            .isEmpty)
        #expect(ProviderListFetchPolicy.connected(hosts: ["vpn.example.com"]).isEmpty)
    }

    // MARK: Transport rules

    /// HTTPS, the catalogue's host, and nothing else — including no port of its own.
    /// A provider that starts publishing elsewhere is a deliberate catalogue change,
    /// not something a redirect gets to decide.
    @Test("only the catalogue's own https host is acceptable")
    func onlyTheDeclaredHostIsAcceptable() throws {
        let mullvad = VPNServiceProviderCatalog.mullvad
        let ok = try #require(mullvad.listURL)
        #expect(ProviderListFetchPolicy.isAcceptable(ok, for: mullvad))

        for bad in ["http://api.mullvad.net/www/relays/all/",
                    "https://api.mullvad.net.evil.example/www/relays/all/",
                    "https://evil.example/www/relays/all/",
                    "https://api.mullvad.net:8443/www/relays/all/"] {
            #expect(!ProviderListFetchPolicy.isAcceptable(URL(string: bad)!, for: mullvad),
                    "\(bad) was accepted")
        }
    }

    /// A non-2xx, or an answer that came from somewhere else, is refused WITH the
    /// promise that nothing changed — which is the first thing somebody wants to know
    /// when an update does not land.
    @Test("a bad response is refused and says nothing has been changed")
    func badResponsesSayNothingChanged() throws {
        let mullvad = VPNServiceProviderCatalog.mullvad
        let url = try #require(mullvad.listURL)
        let notFound = HTTPURLResponse(url: url, statusCode: 404,
                                       httpVersion: nil, headerFields: nil)!
        let problem = try #require(ProviderListFetchPolicy.responseProblem(notFound,
                                                                          provider: mullvad))
        #expect(problem.contains("404"))
        #expect(problem.lowercased().contains("nothing has been changed"))

        // A 200 that arrived from another host — i.e. a redirect that was followed —
        // is refused on the URL rather than on the status.
        let elsewhere = HTTPURLResponse(url: URL(string: "https://evil.example/x")!,
                                        statusCode: 200, httpVersion: nil, headerFields: nil)!
        #expect(ProviderListFetchPolicy.responseProblem(elsewhere, provider: mullvad) != nil)

        let good = HTTPURLResponse(url: url, statusCode: 200, httpVersion: nil, headerFields: nil)!
        #expect(ProviderListFetchPolicy.responseProblem(good, provider: mullvad) == nil)
    }

    /// The cap is above every measured payload and far below what would hurt. Nord's
    /// is the big one at ~9 MB.
    @Test("the size cap clears every real payload with room to spare")
    func theCapClearsRealPayloads() {
        for p in VPNServiceProviderCatalog.all {
            #expect(p.approximateBytes < ProviderListFetchPolicy.maximumPayloadBytes,
                    "\(p.displayName) would not fit under the cap")
        }
        #expect(ProviderListFetchPolicy.maximumPayloadBytes == 32 * 1024 * 1024)
    }

    /// MEASURED 2026-08-07, and recorded as a test because the sizes are what the
    /// user is told before agreeing to a download. Nord is the one worth watching:
    /// its v1 endpoint would have been 30 MB, and with no `limit` it answers with a
    /// hundred servers instead of seven thousand.
    @Test("Nord's URL asks for the whole list, from the endpoint that is 3x smaller")
    func nordAsksV2WithAnExplicitLimit() throws {
        let url = try #require(VPNServiceProviderCatalog.nordVPN.listURL)
        #expect(url.absoluteString.contains("/v2/"),
                "v1 is 30 MB for the same servers v2 gives in 9 MB")
        #expect(url.query()?.contains("limit=") == true,
                "with no limit Nord answers with 100 servers and says nothing about it")
    }
}

// MARK: - Progress

struct ProviderFetchProgressTests {

    /// A proportion is shown ONLY when the server declared a length. A percentage
    /// computed against a guess is a lie that looks like data.
    @Test("a proportion appears only with a real Content-Length, during the download")
    func determinateOnlyWithADeclaredLength() {
        #expect(ProviderFetchProgress(stage: .downloading, received: 50, expected: 100)
            .fraction == 0.5)
        #expect(ProviderFetchProgress(stage: .downloading, received: 50, expected: nil)
            .fraction == nil)
        // Not during the other stages: there is nothing being measured.
        #expect(ProviderFetchProgress(stage: .checking, received: 100, expected: 100)
            .fraction == nil)
        #expect(ProviderFetchProgress(stage: .contacting).fraction == nil)
    }

    /// A server that under-declares its length must not produce a bar that runs off
    /// the end.
    @Test("the proportion is clamped")
    func fractionIsClamped() {
        #expect(ProviderFetchProgress(stage: .downloading, received: 300, expected: 100)
            .fraction == 1)
    }

    /// The contacting line names the HOST, because that is the fact somebody can act
    /// on — "couldn't reach api.mullvad.net" is actionable and "update failed" is not.
    @Test("the first stage names the host it is about to contact")
    func contactingNamesTheHost() {
        let s = ProviderFetchProgress(stage: .contacting)
            .sentence(provider: VPNServiceProviderCatalog.mullvad)
        #expect(s.contains("api.mullvad.net"))
    }

    /// Every stage says something, and the comparison stage exists precisely so a
    /// pause after 100% is explained rather than read as a hang.
    @Test("every stage has words, and the comparison stage is one of them")
    func everyStageHasWords() {
        for stage in ProviderFetchProgress.Stage.allCases {
            let s = ProviderFetchProgress(stage: stage)
                .sentence(provider: VPNServiceProviderCatalog.nordVPN)
            #expect(!s.isEmpty, "\(stage) has no words")
        }
        #expect(ProviderFetchProgress(stage: .comparing)
            .sentence(provider: VPNServiceProviderCatalog.nordVPN)
            .lowercased().contains("comparing"))
    }

    /// VoiceOver gets the stage in words plus a spoken percentage where there is a
    /// real one — a progress indicator whose only content is motion tells a listener
    /// nothing (Docs/Accessibility.md).
    @Test("VoiceOver hears the stage, and a percentage only when there is one")
    func spokenProgressCarriesTheStage() {
        let determinate = ProviderFetchProgress(stage: .downloading, received: 45, expected: 100)
        #expect(determinate.spoken(provider: VPNServiceProviderCatalog.nordVPN)
            .contains("45 percent"))
        let indeterminate = ProviderFetchProgress(stage: .downloading, received: 45, expected: nil)
        #expect(!indeterminate.spoken(provider: VPNServiceProviderCatalog.nordVPN)
            .contains("percent"))
    }

    /// Under about a second nothing is drawn: an indicator that flashes reads as a
    /// glitch rather than as work, and Mullvad's 300 KB usually beats it.
    @Test("the indicator waits a beat before appearing")
    func theIndicatorWaitsABeat() {
        #expect(ProviderFetchProgress.indicatorDelay == .seconds(1))
    }

    /// A cancel has to answer "did that leave things half-done?" — and the answer is
    /// in the sentence, not in a support article.
    @Test("cancelling says, in words, that nothing was changed")
    func cancellingPromisesNothingChanged() {
        let s = ProviderFetchOutcome.cancelled.sentence(provider: VPNServiceProviderCatalog.mullvad)
        #expect(s.lowercased().contains("nothing has been changed"))
    }

    /// A held update says what is waiting and that none of it has been applied.
    @Test("a held update names what changed and says none of it is in use yet")
    func heldUpdateNamesWhatChanged() {
        let s = ProviderFetchOutcome.needsConfirmation(moved: 2, retired: 5)
            .sentence(provider: VPNServiceProviderCatalog.mullvad)
        #expect(s.contains("2"))
        #expect(s.contains("5"))
        #expect(s.lowercased().contains("nothing has been changed yet"))
    }
}
