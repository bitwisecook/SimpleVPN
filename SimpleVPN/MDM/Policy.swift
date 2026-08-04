// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
//  Policy.swift
//  The FINE-GRAINED management policy seam: per-setting forced values, per-profile
//  locks, and an allow-list of kinds.
//
//  NOT the landed MDM reader — that is `ManagedPolicy.swift`, which reads forced
//  defaults (`objectIsForced(forKey:)`) and is what the editors, Settings and the
//  VPNController lifecycle actually consult today. Docs/MDM.md documents that one.
//
//  Honest state of THIS file: `forcedValue`/`forcedSettings` has exactly one
//  production call site (`OpenVPNSettingDescriptors.swift`, the OpenVPN options
//  form), and `lockedProfileIDs`/`allowedKinds` have NO call sites at all — nothing
//  populates `PolicyStore.policy` yet either. It is the shape a future managed-app-
//  configuration reader ("com.apple.configuration.managed" + change notifications)
//  fills in; do not describe it as if every gate already routed through it.
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
