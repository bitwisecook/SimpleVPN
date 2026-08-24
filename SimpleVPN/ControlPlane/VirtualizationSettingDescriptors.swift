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

    /// The master switch for the ordinary local scan. It deliberately excludes
    /// protected data owned by another app; that is a separately chosen option.
    static let detect = EngineSettingSpec(
        id: "vm.detect",
        name: "Look for Virtual Machines on This Mac",
        summary: "Lets SimpleVPN notice local virtual-network interfaces and virtualization apps so it "
            + "can warn before a VPN cuts off a live guest network. It does not open another app’s "
            + "data; nothing is run, no virtual machine is started, and nothing leaves this Mac.",
        group: .traffic,
        default: true)

    /// UTM keeps its VM bundles inside its sandboxed Documents container. macOS
    /// treats that as protected app data, so it must never be entered by a background
    /// discovery pass or a Connect click.
    static let readUTMConfigurations = EngineSettingSpec(
        id: "vm.read-utm-configurations",
        name: "Read UTM Virtual-Machine Configurations",
        summary: "Lets SimpleVPN read UTM’s saved virtual-machine names and network modes, so it can "
            + "describe UTM guests more precisely. When you turn this on, SimpleVPN explains why and "
            + "then macOS asks once for access. Off means UTM’s own data is never opened.",
        group: .traffic,
        default: false)

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

    static let all: [EngineSettingSpec] = [detect, readUTMConfigurations, warnOnConnect]

    static let catalog = EngineSettingCatalog(all)

    /// Defaults keys, so the UI and the diagnostic report read one spelling of each
    /// switch rather than two.
    /// `nonisolated` so the off-main scan and its gate can read them (see `isEnabled`).
    nonisolated static let detectDefaultsKey = "vm.detect"
    nonisolated static let readUTMConfigurationsDefaultsKey = "vm.read-utm-configurations"
    nonisolated static let warnOnConnectDefaultsKey = "vm.warn-on-connect"

    /// UI tests must never reach macOS's Files and Folders consent sheet.  The UTM
    /// integration is already opt-in, and this process-local guard makes that
    /// invariant explicit for test launchers too.
    nonisolated static let suppressProtectedFileScanEnvironmentKey =
        "SIMPLEVPN_UI_TEST_SUPPRESS_PROTECTED_FILE_SCAN"

    /// The ordinary switches default ON, so a `UserDefaults` that has never been written
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

    nonisolated static func effectiveDetectionEnabled(
        environment: [String: String] = ProcessInfo.processInfo.environment,
        store: UserDefaults = .standard
    ) -> Bool {
        _ = environment // kept in the signature for source compatibility with UI tests.
        return isEnabled(detectDefaultsKey, store: store)
    }

    nonisolated static func protectedUTMConfigurationAccessEnabled(
        environment: [String: String] = ProcessInfo.processInfo.environment,
        store: UserDefaults = .standard
    ) -> Bool {
        guard environment[suppressProtectedFileScanEnvironmentKey] != "1" else { return false }
        return store.object(forKey: readUTMConfigurationsDefaultsKey) as? Bool ?? false
    }

    nonisolated static var detectionEnabled: Bool { effectiveDetectionEnabled() }
    nonisolated static var protectedUTMConfigurationAccessEnabled: Bool {
        protectedUTMConfigurationAccessEnabled()
    }
    nonisolated static var warningEnabled: Bool { isEnabled(warnOnConnectDefaultsKey) }
}
