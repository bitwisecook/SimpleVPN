// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
//  ManagedPolicy.swift
//  Organization policy pushed by MDM. A configuration profile that writes to
//  SimpleVPN's preference domain (com.bragi0.SimpleVPN) lands in the app's
//  UserDefaults as *forced* (read-only) values; we read them here and both gate
//  the UI and enforce at connect, so a managed connection can't be weakened.
//
//  MDM keys (all Boolean, all optional — absent = user is free):
//    ForceKeepInsideVPN   — keep-everything-inside-VPN is on and locked; no
//                           "send this outside the VPN" divert rules allowed.
//    DisableDivertRules   — no divert rules of any kind (outside or over-another-VPN).
//    LockProxySettings    — proxy configuration is read-only.
//    LockConfiguration    — a connection's configuration/overrides can't be edited.
//    DisableProviderLists — SimpleVPN may not ask a VPN company (Mullvad, NordVPN,
//                           IPVanish) for its published server list. A managed Mac
//                           may not be permitted to make that request at all, and
//                           the request is one this app initiates rather than one
//                           the user's own traffic makes, so it is the app's to
//                           forbid.
//
//  See Docs/MDM.md for a sample .mobileconfig payload.
//

import Foundation

enum ManagedPolicy {

    // MARK: Keys

    private static let forceKeepInsideVPNKey = "ForceKeepInsideVPN"
    private static let disableDivertRulesKey = "DisableDivertRules"
    private static let lockProxySettingsKey  = "LockProxySettings"
    private static let lockConfigurationKey  = "LockConfiguration"
    private static let disableProviderListsKey = "DisableProviderLists"

    private static let allKeys = [
        forceKeepInsideVPNKey, disableDivertRulesKey, lockProxySettingsKey, lockConfigurationKey,
        disableProviderListsKey,
    ]

    // MARK: Policy

    /// Keep everything inside the VPN — block-outside forced on and locked.
    static var forceKeepInsideVPN: Bool { UserDefaults.standard.bool(forKey: forceKeepInsideVPNKey) }
    /// No divert rules at all.
    static var disableDivertRules: Bool { UserDefaults.standard.bool(forKey: disableDivertRulesKey) }
    /// Proxy settings are read-only.
    static var lockProxySettings: Bool { UserDefaults.standard.bool(forKey: lockProxySettingsKey) }
    /// Connection configuration/overrides are read-only.
    static var lockConfiguration: Bool { UserDefaults.standard.bool(forKey: lockConfigurationKey) }
    /// SimpleVPN may not ask a VPN company for its published server list.
    static var disableProviderLists: Bool {
        UserDefaults.standard.bool(forKey: disableProviderListsKey)
    }

    /// May the user send a destination *outside* the VPN?
    static var allowDivertOutside: Bool { !forceKeepInsideVPN && !disableDivertRules }
    /// May the user route a destination over *another* VPN?
    static var allowDivertOverVPN: Bool { !disableDivertRules }

    /// Any managed key is actually being forced by MDM (not just a stray default).
    static var isManaged: Bool {
        allKeys.contains { UserDefaults.standard.objectIsForced(forKey: $0) }
    }

    /// Human summary of the active locks, for the Settings "Managed" section.
    static var activeSummary: [String] {
        var out: [String] = []
        if forceKeepInsideVPN { out.append("Internet only goes through the VPN.") }
        if disableDivertRules { out.append("Diverting traffic around the VPN is turned off.") }
        if lockProxySettings  { out.append("Proxy settings are locked.") }
        if lockConfiguration  { out.append("Connection settings can't be changed.") }
        if disableProviderLists {
            out.append("Getting server lists from VPN providers is turned off.")
        }
        return out
    }
}
