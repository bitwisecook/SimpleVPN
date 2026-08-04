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

    // MARK: One-shot requests for the ExtensionDoctor (properties, deactivation)

    /// Ask systemextensionsd what copy of our extension is on the system, in
    /// the same format as `bundledExtensionVersion` so the doctor can compare
    /// them directly. nil when none is installed — the doctor must then stay
    /// quiet rather than raise an activation (and its approval dialog) uninvited.
    static func installedExtensionVersion() async -> String? {
        let driver = OneShotRequest()
        return (try? await driver.run(
            OSSystemExtensionRequest.propertiesRequest(
                forExtensionWithIdentifier: extensionIdentifier, queue: .main))) ?? nil
    }

    /// Remove the extension — the doctor's engine restart (deactivate → activate),
    /// always consent-gated upstream. macOS may ask for an admin password.
    static func deactivate() async throws {
        let driver = OneShotRequest()
        _ = try await driver.run(
            OSSystemExtensionRequest.deactivationRequest(
                forExtensionWithIdentifier: extensionIdentifier, queue: .main))
    }

    /// One-shot driver for the delegate flows above. Separate from the shared
    /// manager because that keeps a single activation continuation — a doctor
    /// probe mid-activation must not clobber it. Same thread contract as the
    /// manager: callbacks on `.main`, hence the @unchecked Sendable.
    private final class OneShotRequest: NSObject, OSSystemExtensionRequestDelegate, @unchecked Sendable {
        private var cont: CheckedContinuation<String?, Error>?

        /// Resolves to the found extension's version string (properties
        /// request), or nil (deactivation, or nothing installed).
        func run(_ request: OSSystemExtensionRequest) async throws -> String? {
            try await withCheckedThrowingContinuation { c in
                cont = c
                request.delegate = self
                OSSystemExtensionManager.shared.submitRequest(request)
            }
        }

        func request(_ request: OSSystemExtensionRequest,
                     foundProperties properties: [OSSystemExtensionProperties]) {
            // Answer extracted HERE: OSSystemExtensionProperties is not
            // Sendable, so a string crosses the continuation, not the objects.
            // Prefer the enabled copy — a superseded one awaiting cleanup is
            // not what's answering IPC.
            let best = properties.first { $0.isEnabled } ?? properties.first
            cont?.resume(returning: best.map { "v\($0.bundleShortVersion) (build \($0.bundleVersion))" })
            cont = nil
        }

        func request(_ request: OSSystemExtensionRequest,
                     actionForReplacingExtension existing: OSSystemExtensionProperties,
                     withExtension ext: OSSystemExtensionProperties) -> OSSystemExtensionRequest.ReplacementAction {
            .replace
        }

        func requestNeedsUserApproval(_ request: OSSystemExtensionRequest) {
            SystemExtensionManager.log.log("one-shot sysext request needs user approval")
        }

        func request(_ request: OSSystemExtensionRequest,
                     didFinishWithResult result: OSSystemExtensionRequest.Result) {
            // Deactivation lands here (properties requests answer above).
            cont?.resume(returning: nil); cont = nil
        }

        func request(_ request: OSSystemExtensionRequest, didFailWithError error: Error) {
            cont?.resume(throwing: error); cont = nil
        }
    }
}
