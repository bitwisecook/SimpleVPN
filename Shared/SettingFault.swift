// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
//  SettingFault.swift
//  ONE missing or malformed setting, named and attributed to the field that owns it.
//
//  WHY IT EXISTS. Three of the packet-tunnel config types already had a single
//  connect gate — `WireGuardConfig.connectProblem`, and the same property on
//  `ProxyTunnelConfig` and `SSHNetworkTunnelConfig` — which answered "why can't this
//  connect?" with a sentence and nothing else. The editors then needed the same
//  answer with a FIELD attached, so a row that has to be filled in could mark itself
//  in red (`SettingNeeds`).
//
//  The hazard is two answers: the connect path saying one field is missing while the
//  editor reddens another. So the gate is expressed as a fault WITH an id, and
//  `connectProblem` is derived from it — `connectFault?.sentence`. One derivation,
//  two consumers, and no way for them to disagree. This is the same shape
//  `ConnectNeed` (SimpleVPN/ControlPlane/ConnectListing.swift) already has for the
//  subprocess and native kinds; it lives in Shared because these three gates do, and
//  the packet-tunnel extension links them.
//
//  `settingID` is the CLI/MDM/manual-anchor contract id ("wg.endpoint"), which is
//  also what the reveal machinery scrolls to and what the manual anchors are built
//  from. It is nil for a fault no single field owns.
//

import Foundation

nonisolated struct SettingFault: Equatable, Sendable {
    /// The setting to blame and land on, or nil when nothing on screen is at fault.
    var settingID: String?
    /// What is missing or wrong and what clears it, in the user's terms
    /// (ONTOLOGY.md: "Failure text names the fix").
    var sentence: String

    init(_ settingID: String?, _ sentence: String) {
        self.settingID = settingID
        self.sentence = sentence
    }
}
