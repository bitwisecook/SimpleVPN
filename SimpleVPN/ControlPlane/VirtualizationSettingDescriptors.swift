// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
//  VirtualizationSettingDescriptors.swift
//  The `vm.` catalog: whether SimpleVPN looks for virtual machines and containers
//  on this Mac, and whether it warns before a VPN swallows one of their networks.
//
//  An APP-LEVEL surface, like `creds.` — these are not any one VPN's settings.
//  They are registered here for the same reason every other catalog is: being in a
//  catalog is what makes global search, the manual anchors and CLI/MDM addressing
//  total, and a setting nobody registered is one search cannot find.
//
//  THERE IS DELIBERATELY NO "EXCLUDE THEM AUTOMATICALLY" SETTING. Keeping a subnet
//  out of a tunnel is a split-tunnel decision with real consequences — traffic to
//  it leaves the VPN — so it stays a deliberate, visible, per-profile choice made
//  through the excluded-routes list a profile already has. A switch that did it
//  silently for every VPN is exactly the thing this feature must not become.
//

import Foundation

@MainActor
enum VirtualizationSettings {

    /// The master switch for the local scan. On by default: it reads the
    /// filesystem and the interface list, executes nothing, wakes no virtualization
    /// daemon and sends nothing anywhere — and a detection feature that defaults to
    /// not detecting is inert.
    static let detect = EngineSettingSpec(
        id: "vm.detect",
        name: "Look for Virtual Machines on This Mac",
        summary: "Lets SimpleVPN notice the virtual machines and containers you run, and which of "
            + "their networks are live, so it can warn you before a VPN cuts one off. It only reads "
            + "this Mac \u{2014} nothing is run, no virtual machine is started, and nothing is sent "
            + "anywhere.",
        group: .traffic,
        default: true)

    /// The warning itself. Separate from detection because "notice it" and "say
    /// something about it" are different consents: someone may want the facts in a
    /// diagnostic report without a banner every time they connect.
    static let warnOnConnect = EngineSettingSpec(
        id: "vm.warn-on-connect",
        name: "Warn Before a VPN Captures Them",
        summary: "When a VPN you are connecting would swallow a running virtual machine\u{2019}s "
            + "network, say so and offer to keep that network out of the tunnel. SimpleVPN never "
            + "changes routing on its own.",
        group: .traffic,
        default: true)

    static let all: [EngineSettingSpec] = [detect, warnOnConnect]

    static let catalog = EngineSettingCatalog(all)

    /// Defaults keys, so the UI and the diagnostic report read one spelling of each
    /// switch rather than two.
    /// `nonisolated` so the off-main scan and its gate can read them (see `isEnabled`).
    nonisolated static let detectDefaultsKey = "vm.detect"
    nonisolated static let warnOnConnectDefaultsKey = "vm.warn-on-connect"

    /// Both switches default ON, so a `UserDefaults` that has never been written
    /// must read as true — `bool(forKey:)` alone would read as false and silently
    /// disable a feature nobody turned off.
    ///
    /// `nonisolated`, unlike the specs above: the scan these gate runs OFF the main actor
    /// (`VirtualizationDiscovery.snapshotOffMain`), and it must read the switch as it is
    /// NOW. Capturing the value at wiring time instead would freeze it at launch, so
    /// turning detection off would not take effect until the next relaunch. `UserDefaults`
    /// is thread-safe, so there is nothing to serialise here.
    nonisolated static func isEnabled(_ key: String, store: UserDefaults = .standard) -> Bool {
        store.object(forKey: key) as? Bool ?? true
    }

    nonisolated static var detectionEnabled: Bool { isEnabled(detectDefaultsKey) }
    nonisolated static var warningEnabled: Bool { isEnabled(warnOnConnectDefaultsKey) }
}
