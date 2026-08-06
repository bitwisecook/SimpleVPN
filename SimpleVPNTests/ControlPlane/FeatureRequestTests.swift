// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
//  FeatureRequestTests.swift
//  THE COPY IS THE FEATURE HERE, so the copy is what is tested.
//
//  `FeatureRequestNotice` exists because two capabilities were REMOVED and the rows
//  they lived in were kept as a request for use cases. That only works if the wording
//  does two things and never a third: it must state the absence plainly, it must ask
//  for the situation rather than for a vote, and it must NOT imply the feature is
//  coming. The third is the one a well-meaning edit breaks — "not supported yet" reads
//  as a promise, and a promise to somebody holding a card their employer issued is
//  worse than saying nothing.
//
//  So this file pins the wording rules, the derivation of the connect-time refusal
//  from the same notice (one wording, two readers), and the fact that neither refusal
//  ever tells the user to sign in some other way.
//

import Foundation
import Testing
@testable import SimpleVPN

@MainActor
struct FeatureRequestTests {

    private func config(_ mutate: (inout SubprocessTunnelConfig) -> Void)
        -> SubprocessTunnelConfig {
        var c = SubprocessTunnelConfig()
        c.kind = .fortinet
        c.server = "vpn.example.com"
        c.username = "alex"
        mutate(&c)
        return c
    }

    /// THE ONE RULE THAT MATTERS: no promise, in any string a user reads. Every word
    /// below turns "we don't do this" into "we don't do this *yet*", which is a
    /// commitment nobody has made.
    @Test func nothingInTheCopyPromisesTheFeature() {
        let promises = ["yet", "soon", "coming", "planned", "roadmap", "will be added",
                        "in a future", "we intend", "next release", "on the list"]
        for notice in FeatureRequestNotice.all {
            let prose = [notice.title, notice.detail, notice.subject,
                         notice.blockedConnectReason,
                         notice.reason.invitation, notice.reason.prompt,
                         notice.reason.titlePrefix].joined(separator: " ").lowercased()
            for promise in promises {
                #expect(!prose.contains(promise),
                        "\(notice.key) says \u{201C}\(promise)\u{201D}, which reads as a commitment")
            }
        }
    }

    /// The house vocabulary applies to this copy like any other (ONTOLOGY.md):
    /// "credential" is banned outright, and so is every spelling of "log in".
    @Test func theCopyFollowsTheHouseVocabulary() {
        let forbidden = ["credential", "log in", "login", "logon", "authenticate",
                         "one-time passcode"]
        for notice in FeatureRequestNotice.all {
            let prose = [notice.title, notice.detail, notice.subject,
                         notice.blockedConnectReason,
                         notice.reason.invitation, notice.reason.prompt].joined(separator: " ")
                .lowercased()
            for word in forbidden {
                #expect(!prose.contains(word), "\(notice.key) says \u{201C}\(word)\u{201D}")
            }
        }
    }

    /// THE ASK IS FOR A USE CASE, and the question names its parts. "Would you like
    /// smartcards?" gets a yes and tells us nothing, so the prompt has to ask which
    /// gateway, which device, and what the organisation requires.
    @Test func theSmartcardAskNamesWhatWouldDecideIt() {
        let prompt = DiagnosticReportRequest.Reason.smartcardRequest.prompt.lowercased()
        #expect(prompt.contains("which gateway"))
        #expect(prompt.contains("organisation"))
        #expect(prompt.contains("card") || prompt.contains("key"))
        // And the other one asks its own question rather than the same one.
        let token = DiagnosticReportRequest.Reason.verificationCodeTokenRequest.prompt.lowercased()
        #expect(token.contains("gateway"))
        #expect(token.contains("code"))
        #expect(token != prompt)
        // The issue title says "use case", not "feature request": it is filed as
        // evidence about a situation.
        #expect(DiagnosticReportRequest.Reason.smartcardRequest.titlePrefix
            .lowercased().contains("use case"))
    }

    /// Both notices say what DOES work, so the page is not a dead end.
    @Test func eachNoticeNamesSomethingThatWorksInstead() {
        #expect(FeatureRequestNotice.smartcardSignIn.detail.lowercased().contains("file"))
        #expect(FeatureRequestNotice.smartcardSignIn.detail.lowercased().contains("single sign-on"))
        #expect(FeatureRequestNotice.verificationCodeToken.detail.lowercased().contains("password app"))
    }

    // MARK: The connect-time refusal, derived from the same notice

    /// ONE WORDING, TWO READERS. The banner in the editor and the refusal on Connect
    /// have to agree about what happened and what to do next; a refusal that said
    /// something different from the row above it is how a user concludes one of the two
    /// is lying. So `blockedConnectReason` is derived from the notice, and
    /// `sslAuthBlockReason` returns exactly that.
    @Test func theConnectRefusalIsTheNoticesOwnWording() {
        #expect(SubprocessTunnelManager.sslAuthBlockReason(config { $0.authMode = "token" })
                == FeatureRequestNotice.smartcardSignIn.blockedConnectReason)
        #expect(SubprocessTunnelManager.sslAuthBlockReason(config { $0.tokenMode = "totp" })
                == FeatureRequestNotice.verificationCodeToken.blockedConnectReason)
    }

    /// THE ONE UNACCEPTABLE ANSWER, ruled out by test: a stored smartcard or token
    /// profile must never be quietly turned into a password sign-in. It is refused, the
    /// stored fields are left exactly as they are, and the refusal does not advise
    /// switching method — the profile was set up by somebody who knew what the gateway
    /// wanted, and a gateway that demands a card may refuse a password outright.
    @Test func aStoredProfileIsRefusedRatherThanConverted() throws {
        let smartcard = config { $0.authMode = "token" }
        // Not converted, on any path a save or a load goes through.
        #expect(smartcard.normalized().authMode == "token")
        #expect(SubprocessTunnelStore.migrated([smartcard]).list[0].authMode == "token")
        // Refused, as `.blocked` — "it cannot work as set up" — rather than as a
        // sign-in that merely needs something supplied.
        let need = try #require(SubprocessTunnelReadiness.need(
            for: smartcard, facts: .init(installedTools: Set(TunnelCLI.allCases))))
        #expect(need.readiness == .blocked)
        // …and with no row to reveal, because there is no longer a row that is wrong.
        #expect(need.settingID == nil)
        for advice in ["choose password", "switch to a password", "use a password instead"] {
            #expect(!need.sentence.lowercased().contains(advice))
        }

        let token = config { $0.tokenMode = "totp" }
        let tokenNeed = try #require(SubprocessTunnelReadiness.need(
            for: token, facts: .init(installedTools: Set(TunnelCLI.allCases), hasPassword: true)))
        #expect(tokenNeed.readiness == .blocked)
        #expect(tokenNeed.settingID == nil)
    }

    /// AND THE SETTINGS REALLY ARE GONE — asserted so they cannot come back by
    /// accident with nothing behind them. Removing the descriptors is what removed the
    /// rows, the manual pages, the CLI/MDM names and the search entries in one go.
    @Test func theRemovedSettingsHaveNoDescriptorsLeft() {
        let ids = Set(OpenConnectSettings.all.map(\.id))
        for gone in ["oc.pkcs11-module", "oc.pkcs11-certificate", "oc.pkcs11-key",
                     "oc.pkcs11-pin", "oc.pkcs11-remember-pin",
                     "oc.token-mode", "oc.token-secret"] {
            #expect(!ids.contains(gone), "\(gone) is back without a feature behind it")
        }
        // The sign-in method picker's own value is NOT gone, and that is the point:
        // an existing profile still says what it is, and somebody looking for
        // smartcard finds the notice instead of finding nothing.
        #expect(SubprocessTunnelManager.openconnectAuthMode(config { $0.authMode = "token" })
                == "token")
    }
}
