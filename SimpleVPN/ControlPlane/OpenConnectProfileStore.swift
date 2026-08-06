// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
//  OpenConnectProfileStore.swift
//  Bridges an SSL-VPN SubprocessTunnelConfig to an on-demand NETunnelProviderManager
//  so it runs *in-process* through the packet-tunnel extension's OpenConnectBridge
//  instead of the `openconnect` subprocess. Creds ride startTunnel options
//  (the root extension can't read the keychain). This is now the DEFAULT path for a
//  new SSL VPN; the subprocess survives for the settings the bridge genuinely can't
//  carry (`SubprocessTunnelManager.inProcessOpenConnectSupports`) and as the fallback
//  when the extension refuses to start.
//

import Foundation
@preconcurrency import NetworkExtension
import os

@MainActor
enum OpenConnectProfileStore {
    private static let log = Logger(subsystem: "com.bragi0.SimpleVPN", category: "openconnect-ne")
    private static let providerBundleID = "com.bragi0.SimpleVPN.PacketTunnel"

    /// The in-process tunnel's lifecycle, mapped from NEVPNStatus. `failed` is a
    /// disconnect that happened before the tunnel ever came up — a sign-in /
    /// gateway refusal, not a user disconnect.
    enum Event: Sendable {
        case connecting, connected, disconnected
        case failed(String)
    }

    private static var observers: [String: NSObjectProtocol] = [:]
    private static var lastStatus: [String: NEVPNStatus] = [:]

    /// Create/reuse the NE profile for this config and start it in-process.
    /// Returns false if NE setup fails (caller falls back to the subprocess).
    /// Connection progress arrives via `onEvent` (NEVPNStatusDidChange) — a true
    /// return means "started", NOT "connected".
    ///
    /// `auth` carries a session ocauth-helper already signed in (SSO): its
    /// cookie + exact certificate + connect URL ride startTunnel options in
    /// memory — same invariant as every credential, NEVER providerConfiguration
    /// (which persists) — and the extension skips its own sign-in.
    static func start(_ config: SubprocessTunnelConfig, password: String?,
                      auth: OCAuthDone? = nil,
                      onEvent: @escaping @MainActor (Event) -> Void) async -> Bool {
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
            // EVERY non-secret setting the bridge carries, from the one mapping that
            // `inProcessOpenConnectSupports` is held to. This used to be four keys
            // written by hand here, which is how "the built-in engine can't take a CA
            // file" came to be believed: the bridge had always called
            // openconnect_set_cafile, and nothing had ever passed it a path.
            proto.providerConfiguration = SubprocessTunnelManager.inProcessConfiguration(config)
            mgr.protocolConfiguration = proto
            mgr.localizedDescription = config.name
            mgr.isEnabled = true

            try await mgr.saveToPreferences()
            try await mgr.loadFromPreferences()

            var options: [String: NSObject] = [
                "username": config.username as NSString,
                "password": (password ?? "") as NSString,
            ]
            // The secret half: a client key's passphrase and a proxy password, read
            // from the keychain here (the extension is root and cannot) and carried
            // in memory only — never providerConfiguration, which persists.
            options.merge(SubprocessTunnelManager.inProcessSecrets(config)) { current, _ in current }
            // Org policy travels with the session, like every other kind's start
            // path (VPNController+WireGuard and friends). ForceKeepInsideVPN is
            // enforced in the EXTENSION — that is the one place a stale profile
            // cannot route around — so it has to be told, or the local-network
            // carve-out below would escape a policy that says everything stays
            // inside the VPN.
            if ManagedPolicy.forceKeepInsideVPN { options["policyKeepInside"] = true as NSNumber }
            // "Allow local network access": the prefixes this Mac's own interfaces
            // are on, computed HERE because the app is unsandboxed and an empty
            // enumeration inside the sysext would be a carve-out that looks applied
            // and is not. Absent ⇒ no carve-out (fail closed).
            if config.allowsLocalNetworkAccess {
                let local = LocalNetworkCarveOut.live()
                if !local.isEmpty { options[LocalNetworkCarveOut.optionKey] = local as NSArray }
            }
            if let auth {
                options["cookie"] = auth.cookie as NSString
                options["servercert"] = auth.servercert as NSString
                if !auth.connectURL.isEmpty { options["connectURL"] = auth.connectURL as NSString }
            }
            try (mgr.connection as? NETunnelProviderSession)?.startTunnel(options: options)
            observe(mgr.connection, id: config.id, onEvent: onEvent)
            log.log("started in-process OpenConnect for \(config.id, privacy: .public) (\(type, privacy: .public))")
            return true
        } catch {
            log.error("in-process OpenConnect setup failed: \(error.localizedDescription, privacy: .public)")
            return false
        }
    }

    static func stop(_ configID: String) async {
        stopObserving(configID)
        let all = (try? await NETunnelProviderManager.loadAllFromPreferences()) ?? []
        for mgr in all where (((mgr.protocolConfiguration as? NETunnelProviderProtocol)?
            .providerConfiguration?["profile"] as? String) == configID) {
            mgr.connection.stopVPNTunnel()
        }
    }

    // MARK: NEVPNStatus → Event

    private static func observe(_ connection: NEVPNConnection, id: String,
                                onEvent: @escaping @MainActor (Event) -> Void) {
        stopObserving(id)
        lastStatus[id] = connection.status
        // The notification only fires for this `connection` (registered as `object`),
        // and the block runs on `.main`, so we touch `conn` only on the main actor.
        // `nonisolated(unsafe)` silences the Sendable check on the capture (NEVPNConnection
        // isn't Sendable); using the captured value avoids sending the non-Sendable `note`.
        nonisolated(unsafe) let conn = connection
        let token = NotificationCenter.default.addObserver(
            forName: .NEVPNStatusDidChange, object: connection, queue: .main) { _ in
            // queue: .main ⇒ we're on the main thread; hop into the actor cheaply.
            MainActor.assumeIsolated {
                handleStatusChange(conn, id: id, onEvent: onEvent)
            }
        }
        observers[id] = token
    }

    private static func handleStatusChange(_ conn: NEVPNConnection, id: String,
                                           onEvent: @escaping @MainActor (Event) -> Void) {
        let was = lastStatus[id]
        let now = conn.status
        lastStatus[id] = now
        switch now {
        case .connecting, .reasserting:
            onEvent(.connecting)
        case .connected:
            onEvent(.connected)
        case .disconnected, .invalid:
            stopObserving(id)
            // Dropped without ever connecting ⇒ sign-in / gateway refusal, not a
            // user disconnect. Ask NE for the provider's actual reason.
            if was == .connecting || was == .reasserting {
                let fallback = "The tunnel exited during sign-in — check the credentials and gateway settings."
                if let session = conn as? NETunnelProviderSession {
                    session.fetchLastDisconnectError { err in
                        let why = err?.localizedDescription
                        Task { @MainActor in onEvent(.failed(why ?? fallback)) }
                    }
                } else {
                    onEvent(.failed(fallback))
                }
            } else {
                onEvent(.disconnected)
            }
        default:
            break   // .disconnecting — transient, nothing to report yet
        }
    }

    private static func stopObserving(_ id: String) {
        if let token = observers.removeValue(forKey: id) {
            NotificationCenter.default.removeObserver(token)
        }
        lastStatus[id] = nil
    }
}
