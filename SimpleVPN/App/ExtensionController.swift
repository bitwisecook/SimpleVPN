// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
//  ExtensionController.swift
//  Shared system-extension state (status + versions) so the Settings window and the
//  launch-time activation share one source of truth.
//

import Foundation
import Observation

@MainActor
@Observable
final class ExtensionController {
    private let manager = SystemExtensionManager()
    private(set) var status = "Not activated"
    private(set) var isActivated = false
    private(set) var needsApproval = false
    private(set) var needsApplicationsInstallation = false
    private(set) var isRemoving = false

    var bundledVersion: String { SystemExtensionManager.bundledExtensionVersion }

    func activate() async {
        guard SystemExtensionManager.isEligibleForActivation else {
            isActivated = false
            needsApproval = false
            needsApplicationsInstallation = true
            status = "Open the copy of SimpleVPN in Applications before enabling VPN connections."
            return
        }
        needsApplicationsInstallation = false
        manager.onNeedsApproval = { [weak self] in
            Task { @MainActor in
                self?.needsApproval = true
                self?.status = "Waiting for approval in System Settings ▸ General ▸ Login Items & Extensions"
            }
        }
        status = "Activating…"
        do {
            try await manager.activate()
            isActivated = true; needsApproval = false
            status = "Activated · bundled \(bundledVersion)"
        } catch {
            isActivated = false
            status = "Failed: \(error.localizedDescription)"
        }
    }

    /// Explicit user-requested removal.  This never deletes VPN configurations
    /// or credentials; it only asks macOS to deactivate SimpleVPN's own engine.
    /// macOS may require confirmation or a restart to finish the removal.
    func removeVPNEngine() async {
        guard !isRemoving else { return }
        isRemoving = true
        defer { isRemoving = false }
        status = "Removing VPN engine…"
        do {
            try await SystemExtensionManager.deactivate()
            isActivated = false
            needsApproval = false
            status = "VPN engine removal requested. macOS may finish it after a restart."
        } catch {
            status = "Couldn't remove the VPN engine: \(error.localizedDescription)"
        }
    }
}
