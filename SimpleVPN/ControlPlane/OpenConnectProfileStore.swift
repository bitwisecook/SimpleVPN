// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
//  OpenConnectProfileStore.swift
//  Bridges an SSL-VPN SubprocessTunnelConfig to an on-demand NETunnelProviderManager
//  so it runs *in-process* through the packet-tunnel extension's OpenConnectBridge
//  instead of the `openconnect` subprocess. Creds ride startTunnel options
//  (the root extension can't read the keychain). This is now the DEFAULT path for a
//  new SSL VPN; the subprocess survives for the settings the bridge genuinely can't
//  carry (`SubprocessTunnelManager.inProcessOpenConnectSupports`)
//  when the extension refuses to start.
//

import Foundation
import Darwin
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

    enum StartResult: Equatable {
        case started
        case refused(String)
    }

    /// A stale tunnel draft cannot remove rules from its system-startable NE copy.
    static func configurationForStart(_ config: SubprocessTunnelConfig, previous: [String: Any]?) throws -> [String: Any] {
        let sameProfile = previous?["profile"] as? String == config.id
        if sameProfile, let previous, try StandalonePacketPolicyConfiguration.source(in: previous) != nil,
           config.routingEventSource == nil {
            throw ProfilePacketPolicy.failure("The saved tunnel still requires traffic event handlers. Save its routing settings before connecting.")
        }
        var settings: [String: Any]
        if config.kind == .ssh {
            guard let tun = config.sshTunConfiguration else { throw ProfilePacketPolicy.failure(config.sshTunProblem ?? "Check the SSH tunnel settings.") }
            settings = ["profile": config.id, "vpnType": config.kind.rawValue, "sshTun": try JSONEncoder().encode(tun)]
            if sameProfile {
                for key in ["routingRules", "customrouting"] {
                    settings[key] = previous?[key] as? Data
                }
            }
        } else { settings = SubprocessTunnelManager.inProcessConfiguration(config, previous: previous) }
        try StandalonePacketPolicyConfiguration.store(config.routingEventSource, in: &settings)
        return settings
    }

    private static var observers: [String: NSObjectProtocol] = [:]
    private static var lastStatus: [String: NEVPNStatus] = [:]

    /// Create/reuse the NE profile for this config and start it in-process.
    /// Setup errors remain on the selected packet transport and are shown to the user.
    /// Connection progress arrives via `onEvent` (NEVPNStatusDidChange) — a true
    /// return means "started", NOT "connected".
    ///
    /// `auth` carries a session ocauth-helper already signed in (SSO): its
    /// cookie + exact certificate + connect URL ride startTunnel options in
    /// memory — same invariant as every credential, NEVER providerConfiguration
    /// (which persists) — and the extension skips its own sign-in.
    static func start(_ config: SubprocessTunnelConfig, password: String?,
                      oneTimeCode: String? = nil,
                      auth: OCAuthDone? = nil, coordinator: VPNController?, stillCurrent: @escaping @MainActor () -> Bool = { true },
                      onEvent: @escaping @MainActor (Event) -> Void) async -> StartResult {
        guard config.kind.isSSLVPN || config.sshTunConfiguration != nil else { return .refused(ProfilePacketPolicy.unsupported) }
        guard let coordinator, stillCurrent(), coordinator.virtualManager(for: config.id) == nil,
              let attempt = coordinator.connectionReservations.reserve(owner: "packet." + config.id, members: [config.id]) else {
            return .refused("This VPN is already starting or belongs to an active routed connection.")
        }
        defer { coordinator.connectionReservations.finish(attempt) }
        func checkCurrent() throws {
            guard stillCurrent(), !Task.isCancelled, coordinator.connectionReservations.isCurrent(attempt) else { throw CancellationError() }
        }
        if config.routingEventSource != nil || config.kind == .ssh {
            if let ensure = coordinator.ensureExtensionReady, !(await ensure()) {
                return .refused("Approve SimpleVPN’s network extension in System Settings before connecting this VPN.")
            }
            do { try await SystemExtensionManager.requireCurrentProvider() }
            catch { return .refused(error.localizedDescription) }
        }
        let type = config.kind.rawValue   // provider resolves it via VPNKind.openconnectProtocol
        do {
            let all = try await NETunnelProviderManager.loadAllFromPreferences()
            try checkCurrent()
            let mgr = all.first {
                guard let proto = $0.protocolConfiguration as? NETunnelProviderProtocol,
                      proto.providerBundleIdentifier == providerBundleID else { return false }
                return proto.providerConfiguration?["profile"] as? String == config.id
            } ?? NETunnelProviderManager()
            if UI.isActive(mgr.connection.status) { return .refused("This VPN is already connected or connecting.") }

            let proto = NETunnelProviderProtocol()
            proto.providerBundleIdentifier = providerBundleID
            proto.serverAddress = config.server
            // EVERY non-secret setting the bridge carries, from the one mapping that
            // `inProcessOpenConnectSupports` is held to. This used to be four keys
            // written by hand here, which is how "the built-in engine can't take a CA
            // file" came to be believed: the bridge had always called
            // openconnect_set_cafile, and nothing had ever passed it a path.
            let previous = (mgr.protocolConfiguration as? NETunnelProviderProtocol)?.providerConfiguration
            do {
                var settings = try configurationForStart(config, previous: previous)
                if settings["customrouting"] == nil {
                    settings["customrouting"] = coordinator.customRouting(for: config.id).encodedBlob()
                }
                proto.providerConfiguration = settings
            }
            catch { return .refused(error.localizedDescription) }
            mgr.protocolConfiguration = proto
            mgr.localizedDescription = config.name
            mgr.isEnabled = true

            try await mgr.saveToPreferences()
            try await mgr.loadFromPreferences()

            var options: [String: NSObject] = [:]
            if config.kind == .ssh {
                options["sshTunCredentials"] = try await sshTunCredentials(config, password: password) as NSDictionary
            } else {
                options = [
                    "username": config.username as NSString,
                    "password": (password ?? "") as NSString,
                ]
                if let oneTimeCode, !oneTimeCode.isEmpty {
                    options["oneTimeCode"] = oneTimeCode as NSString
                }
                // The secret half: a client key's passphrase and a proxy password, read
                // from the keychain here (the extension is root and cannot) and carried
                // in memory only — never providerConfiguration, which persists.
                options.merge(SubprocessTunnelManager.inProcessSecrets(config)) { current, _ in current }
            }
            // Org policy travels with the session, like every other kind's start
            // path (VPNController+WireGuard and friends). ForceKeepInsideVPN is
            // enforced in the EXTENSION — that is the one place a stale profile
            // cannot route around — so it has to be told, or the local-network
            // carve-out below would escape a policy that says everything stays
            // inside the VPN.
            if ManagedPolicy.disableDivertRules { options["policyNoDiverts"] = true as NSNumber }
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
                if let resolve = auth.resolve {
                    options["resolveHost"] = resolve.host as NSString
                    options["resolveIP"] = resolve.ip as NSString
                }
            }
            try checkCurrent()
            guard let session = mgr.connection as? NETunnelProviderSession else { return .refused("The packet tunnel could not start. Check the network extension in Settings.") }
            if coordinator.managers[config.id] == nil {
                await coordinator.registerCreatedManager(mgr, id: config.id)
            }
            try checkCurrent()
            try coordinator.startWithInitialGateway(session, profile: config.id, options: options)
            observe(mgr.connection, id: config.id, onEvent: onEvent)
            log.log("started in-process OpenConnect for \(config.id, privacy: .public) (\(type, privacy: .public))")
            return .started
        } catch {
            log.error("in-process OpenConnect setup failed: \(error.localizedDescription, privacy: .public)")
            return .refused(error.localizedDescription)
        }
    }

    static func sshTunCredentials(_ config: SubprocessTunnelConfig, password: String?) async throws -> [String: Data] {
        guard let tun = config.sshTunConfiguration else { throw ProfilePacketPolicy.failure(config.sshTunProblem ?? "Check the SSH tunnel settings.") }
        return try await Task.detached {
            func file(_ path: String) throws -> Data {
                let limit = 1_048_576
                guard !path.utf8.contains(0) else { throw ProfilePacketPolicy.failure("Check the SSH credential file path.") }
                let fd = Darwin.open((path as NSString).expandingTildeInPath, O_RDONLY | O_CLOEXEC | O_NONBLOCK)
                guard fd >= 0 else { throw POSIXError(POSIXErrorCode(rawValue: errno) ?? .EIO) }
                let input = FileHandle(fileDescriptor: fd, closeOnDealloc: true)
                defer { try? input.close() }
                var stat = Darwin.stat()
                guard fstat(fd, &stat) == 0, stat.st_mode & S_IFMT == S_IFREG, (1...Int64(limit)).contains(stat.st_size),
                      let data = try input.read(upToCount: limit + 1), data.count == stat.st_size,
                      !data.contains(0), String(data: data, encoding: .utf8) != nil else {
                    throw ProfilePacketPolicy.failure("The SSH key or certificate must be a UTF-8 text file of 1 MiB or less.")
                }
                return data
            }
            var result = [String: Data]()
            let secret: String?
            if let password { secret = password }
            else { secret = try KeychainCredentialStore.credentialsForExport(profile: "tunnel." + config.id)?.password }
            if let secret, !secret.isEmpty { result["password"] = Data(secret.utf8) }
            switch tun.authMethod {
            case "keychain":
                guard let key = KeychainCredentialStore.loadSSHPrivateKey(profile: config.id), !key.isEmpty else {
                    throw ProfilePacketPolicy.failure("Unlock or import the SSH private key in the user Keychain.")
                }
                result["key"] = Data(key.utf8)
            case "key", "certificate":
                result["key"] = try file(config.identityFile)
                if tun.authMethod == "certificate" { result["certificate"] = try file(config.sshCertificateFile ?? "") }
            default:
                guard result["password"] != nil else { throw ProfilePacketPolicy.failure("Enter the SSH password before connecting.") }
            }
            return result
        }.value
    }

    static func updatePacketPolicy(_ source: String?, id: String) async throws {
        for manager in try await mirrors(for: id) {
            try await VPNController.writePacketPolicy(source, to: manager)
        }
    }

    /// An OpenConnect tunnel remains startable from System Settings until its
    /// provider preference is removed. Retire all copies before deleting the owner.
    static func removeMirrors(for id: String) async throws {
        for manager in try await mirrors(for: id) {
            manager.connection.stopVPNTunnel()
            try await manager.removeFromPreferences()
        }
    }

    private static func mirrors(for id: String) async throws -> [NETunnelProviderManager] {
        try await NETunnelProviderManager.loadAllFromPreferences().filter { manager in
            guard let proto = manager.protocolConfiguration as? NETunnelProviderProtocol,
                  proto.providerBundleIdentifier == providerBundleID,
                  let raw = proto.providerConfiguration?["vpnType"] as? String,
                  (VPNKind(rawValue: raw)?.isSSLVPN == true || (raw == VPNKind.ssh.rawValue && proto.providerConfiguration?["sshTun"] is Data)) else { return false }
            return proto.providerConfiguration?["profile"] as? String == id
        }
    }

    static func stop(_ configID: String, stillCurrent: @MainActor () -> Bool = { true }) async {
        guard stillCurrent() else { return }
        stopObserving(configID)
        let all = (try? await NETunnelProviderManager.loadAllFromPreferences()) ?? []
        guard stillCurrent() else { return }
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
