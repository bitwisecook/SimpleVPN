// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
//  OpenConnectProfileStore.swift
//  Bridges an SSL-VPN SubprocessTunnelConfig to an on-demand NETunnelProviderManager
//  so it runs *in-process* through the packet-tunnel extension's OpenConnectBridge
//  (Stage 2) instead of the `openconnect` subprocess. Creds ride startTunnel options
//  (the root extension can't read the keychain). This is the opt-in in-process path;
//  the subprocess remains the default and the fallback.
//

import Foundation
@preconcurrency import NetworkExtension
import os

@MainActor
enum OpenConnectProfileStore {
    private static let log = Logger(subsystem: "com.bragi0.SimpleVPN", category: "openconnect-ne")
    private static let providerBundleID = "com.bragi0.SimpleVPN.PacketTunnel"

    /// Create/reuse the NE profile for this config and start it in-process.
    /// Returns false if NE setup fails (caller falls back to the subprocess).
    static func start(_ config: SubprocessTunnelConfig, password: String?) async -> Bool {
        guard config.kind.isSSLVPN else { return false }
        let type = config.kind.rawValue   // provider resolves it via VPNKind.openconnectProtocol
        do {
            let all = (try? await NETunnelProviderManager.loadAllFromPreferences()) ?? []
            let mgr = all.first {
                (($0.protocolConfiguration as? NETunnelProviderProtocol)?
                    .providerConfiguration?["profile"] as? String) == config.id
            } ?? NETunnelProviderManager()

            let proto = NETunnelProviderProtocol()
            proto.providerBundleIdentifier = providerBundleID
            proto.serverAddress = config.server
            var conf: [String: Any] = ["profile": config.id, "vpnType": type, "server": config.server]
            if !config.realm.isEmpty { conf["realm"] = config.realm }
            if !config.trustedCertSHA256.isEmpty { conf["serverCert"] = config.trustedCertSHA256 }
            if !config.samlBrowser.isEmpty { conf["samlBrowser"] = config.samlBrowser }
            proto.providerConfiguration = conf
            mgr.protocolConfiguration = proto
            mgr.localizedDescription = config.name
            mgr.isEnabled = true

            try await mgr.saveToPreferences()
            try await mgr.loadFromPreferences()

            let options: [String: NSObject] = [
                "username": config.username as NSString,
                "password": (password ?? "") as NSString,
            ]
            try (mgr.connection as? NETunnelProviderSession)?.startTunnel(options: options)
            log.log("started in-process OpenConnect for \(config.id, privacy: .public) (\(type, privacy: .public))")
            return true
        } catch {
            log.error("in-process OpenConnect setup failed: \(error.localizedDescription, privacy: .public)")
            return false
        }
    }

    static func stop(_ configID: String) async {
        let all = (try? await NETunnelProviderManager.loadAllFromPreferences()) ?? []
        for mgr in all where (((mgr.protocolConfiguration as? NETunnelProviderProtocol)?
            .providerConfiguration?["profile"] as? String) == configID) {
            mgr.connection.stopVPNTunnel()
        }
    }
}
