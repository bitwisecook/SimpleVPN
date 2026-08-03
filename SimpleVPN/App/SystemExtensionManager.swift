// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only

//
//  SystemExtensionManager.swift
//  Activates the packet-tunnel system extension (required before the tunnel can run).
//

import Foundation
import SystemExtensions
import os

/// Activates `com.bragi0.SimpleVPN.PacketTunnel` as a system extension.
/// Delegate callbacks arrive on `.main` (we pass that queue), so touching
/// `cont` from them is safe; marked @unchecked Sendable for that contract.
final class SystemExtensionManager: NSObject, OSSystemExtensionRequestDelegate, @unchecked Sendable {

    static let extensionIdentifier = "com.bragi0.SimpleVPN.PacketTunnel"
    private static let log = Logger(subsystem: "com.bragi0.SimpleVPN", category: "sysext")

    /// Version of the .systemextension bundled inside this app (what activation installs).
    /// nonisolated so both the app (MainActor) and this manager can read it.
    static var bundledExtensionVersion: String {
        let url = Bundle.main.bundleURL.appendingPathComponent(
            "Contents/Library/SystemExtensions/\(extensionIdentifier).systemextension/Contents/Info.plist")
        guard let d = NSDictionary(contentsOf: url) else { return "unknown" }
        let v = d["CFBundleShortVersionString"] as? String ?? "?"
        let b = d["CFBundleVersion"] as? String ?? "?"
        return "v\(v) (build \(b))"
    }

    private var cont: CheckedContinuation<Void, Error>?
    /// Called (on main) when the system asks the user to approve in System Settings.
    var onNeedsApproval: (() -> Void)?

    func activate() async throws {
        try await withCheckedThrowingContinuation { (c: CheckedContinuation<Void, Error>) in
            cont = c
            let req = OSSystemExtensionRequest.activationRequest(
                forExtensionWithIdentifier: Self.extensionIdentifier, queue: .main)
            req.delegate = self
            OSSystemExtensionManager.shared.submitRequest(req)
        }
    }

    // MARK: OSSystemExtensionRequestDelegate (on .main)

    func request(_ request: OSSystemExtensionRequest,
                 actionForReplacingExtension existing: OSSystemExtensionProperties,
                 withExtension ext: OSSystemExtensionProperties) -> OSSystemExtensionRequest.ReplacementAction {
        .replace
    }

    func requestNeedsUserApproval(_ request: OSSystemExtensionRequest) {
        Self.log.log("system extension needs user approval")
        onNeedsApproval?()
    }

    func request(_ request: OSSystemExtensionRequest,
                 didFinishWithResult result: OSSystemExtensionRequest.Result) {
        // result 0 = completed, 1 = will complete after reboot
        Self.log.log("system extension activated: result=\(result.rawValue) bundled=\(Self.bundledExtensionVersion, privacy: .public)")
        cont?.resume(); cont = nil
    }

    func request(_ request: OSSystemExtensionRequest, didFailWithError error: Error) {
        Self.log.error("system extension failed: \(error.localizedDescription, privacy: .public)")
        cont?.resume(throwing: error); cont = nil
    }
}
