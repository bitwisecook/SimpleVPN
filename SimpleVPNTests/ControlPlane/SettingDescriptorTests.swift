// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
//  SettingDescriptorTests.swift
//  The descriptor registry is the single source of truth for setting ids,
//  grouping, availability rules, and overridden-state tracking — pin its shape.
//

import Foundation
import Testing
@testable import SimpleVPN

@MainActor
struct SettingDescriptorTests {

    private func context(draft: OpenVPNOverrides = .init(),
                         evaluation: ProfileEvaluation? = nil,
                         policy: Policy = .init()) -> SettingsContext {
        SettingsContext(evaluation: evaluation, draft: draft, policy: policy)
    }

    @Test func idsAreUniqueAndNamespaced() {
        let ids = OpenVPNSettings.all.map(\.id)
        #expect(Set(ids).count == ids.count)
        #expect(ids.allSatisfy { $0.hasPrefix("openvpn.") })
    }

    @Test func manualAnchorsAreWellFormed() {
        for d in OpenVPNSettings.all {
            #expect(!d.manualAnchor.contains("."))
            #expect(d.manualAnchor.hasPrefix("openvpn-"))
        }
    }

    @Test func everyGroupHasDescriptors() {
        for group in SettingGroup.allCases {
            #expect(!OpenVPNSettings.descriptors(in: group).isEmpty)
        }
    }

    @Test func isSetAndResetTrackTheirField() {
        var o = OpenVPNOverrides()
        let d = OpenVPNSettings.byID["openvpn.compression"]!
        #expect(!d.isSet(o))
        o.compression = .yes
        #expect(d.isSet(o))
        d.reset(&o)
        #expect(o.compression == nil)
        #expect(!d.isSet(o))
    }

    @Test func overriddenCountCountsPerGroup() {
        var o = OpenVPNOverrides()
        o.tunPersist = true
        o.retryOnAuthFailed = true
        o.compression = .asym
        #expect(OpenVPNSettings.overriddenCount(in: .reliability, for: o) == 2)
        #expect(OpenVPNSettings.overriddenCount(in: .security, for: o) == 1)
        #expect(OpenVPNSettings.overriddenCount(in: .connection, for: o) == 0)
    }

    @Test func autologinSessionsHiddenForCredentialProfiles() {
        let d = OpenVPNSettings.byID["openvpn.autologin-sessions"]!
        var eval = ProfileEvaluation()
        eval.autologin = false
        #expect(d.availability(in: context(evaluation: eval)) == .hidden)
        eval.autologin = true
        #expect(d.availability(in: context(evaluation: eval)) == .available)
        // No evaluation at all (broken profile) → hidden, not crashing.
        #expect(d.availability(in: context()) == .hidden)
    }

    @Test func proxySubSettingsRequireHostThenUsername() {
        var draft = OpenVPNOverrides()
        let port = OpenVPNSettings.byID["openvpn.proxy-port"]!
        let cleartext = OpenVPNSettings.byID["openvpn.proxy-cleartext-auth"]!

        guard case .disabled = port.availability(in: context(draft: draft)) else {
            Issue.record("proxy port should be disabled without a host"); return
        }
        draft.proxyHost = "proxy.local"
        #expect(port.availability(in: context(draft: draft)) == .available)

        guard case .disabled = cleartext.availability(in: context(draft: draft)) else {
            Issue.record("cleartext auth should be disabled without a username"); return
        }
        draft.proxyUsername = "u"
        #expect(cleartext.availability(in: context(draft: draft)) == .available)
    }

    @Test func policyForcedValueDisablesRegardlessOfOtherRules() {
        var policy = Policy()
        policy.forcedSettings["openvpn.compression"] = .string("no")
        let d = OpenVPNSettings.byID["openvpn.compression"]!
        #expect(d.availability(in: context(policy: policy))
                == .disabled(reason: "Managed by your organisation"))
    }
}
