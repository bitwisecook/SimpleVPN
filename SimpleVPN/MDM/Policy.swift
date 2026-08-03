// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
//  Policy.swift
//  Management policy seam. Always-permissive today; when MDM support lands this is
//  the one file that grows a reader for managed app configuration (the
//  "com.apple.configuration.managed" defaults domain) plus change notifications.
//  Every enable/disable/edit decision in the app already routes through it:
//  setting rows check forcedSettings, the editor/save/delete paths check
//  lockedProfileIDs, and import/kind choices check allowedKinds.
//

import Foundation

/// A concrete value an administrator can force for a setting (keyed by the
/// setting descriptor's stable id, e.g. "openvpn.compression").
enum PolicyValue: Equatable, Sendable {
    case bool(Bool)
    case int(Int)
    case string(String)
}

struct Policy: Sendable, Equatable {
    /// VPN kinds the user may create/import. nil = all kinds allowed.
    var allowedKinds: Set<VPNKind>? = nil
    /// Profiles that cannot be edited or deleted.
    var lockedProfileIDs: Set<String> = []
    /// Settings pinned by management, keyed by descriptor id.
    var forcedSettings: [String: PolicyValue] = [:]

    func allows(_ kind: VPNKind) -> Bool {
        allowedKinds?.contains(kind) ?? true
    }
    func isLocked(profileID: String) -> Bool {
        lockedProfileIDs.contains(profileID)
    }
    func forcedValue(for settingID: String) -> PolicyValue? {
        forcedSettings[settingID]
    }
}

@Observable
final class PolicyStore {
    private(set) var policy = Policy()
}
