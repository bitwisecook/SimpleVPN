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

    var bundledVersion: String { SystemExtensionManager.bundledExtensionVersion }

    func activate() async {
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
}
