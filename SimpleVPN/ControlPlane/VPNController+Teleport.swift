// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only

import Foundation

extension VPNController {
    nonisolated static func teleportKeyProfile(_ id: String) -> String { "teleport.\(id)" }

    func teleportSession(for id: String) -> TeleportSession? {
        _ = teleportAccessRevision
        guard let credentials = KeychainCredentialStore.loadCredentials(profile: Self.teleportKeyProfile(id)),
              let data = credentials.password.data(using: .utf8),
              let session = try? JSONDecoder().decode(TeleportSession.self, from: data), session.isValid else { return nil }
        return session
    }

    /// Pairing is an explicit action, not a field's live-save side effect: an
    /// invite can be consumed once. The bundled helper shares the engine's API
    /// code, receives the invite over stdin and returns credentials over stdout.
    func pairTeleport(id: String, invite: String) async throws {
        guard !ManagedPolicy.lockConfiguration else { throw Self.configLocked }
        guard wireGuardConfig(for: id).usesTeleport else { throw err("Choose a Teleport VPN first.") }
        if let problem = TeleportSession.inviteProblem(invite) { throw err(problem) }
        guard let attempt = connectionReservations.reserve(owner: "teleport-pair." + id, members: [id]) else {
            throw err("This VPN is already preparing a connection or pairing request.")
        }
        defer { connectionReservations.finish(attempt); resyncStatuses() }

        let helper = Bundle.main.bundleURL.appendingPathComponent("Contents/Helpers/teleport-pair")
        let request = try JSONSerialization.data(withJSONObject: [
            "invite": invite.trimmingCharacters(in: .whitespacesAndNewlines),
            "name": "SimpleVPN"
        ])
        let reply = await LocalToolRunner.run(executable: helper.path, arguments: [], deadline: 160, stdin: request)
        try Task.checkCancellation()
        guard reply.exitCode == 0,
              let session = try? JSONDecoder().decode(TeleportSession.self, from: reply.stdout), session.isValid else {
            throw err("Teleport could not pair. Check that the invite is fresh and the console is online, then try again.")
        }
        guard connectionReservations.isCurrent(attempt), !ManagedPolicy.lockConfiguration, managers[id] != nil,
              wireGuardConfig(for: id).usesTeleport else { throw err("This Teleport VPN was removed or locked while pairing.") }
        let credentials = KeychainCredentialStore.Credentials(username: "teleport",
            password: String(decoding: try JSONEncoder().encode(session), as: UTF8.self))
        try KeychainCredentialStore.saveCredentials(profile: Self.teleportKeyProfile(id), credentials)
        guard try KeychainCredentialStore.credentialsForExport(profile: Self.teleportKeyProfile(id))?.password == credentials.password else {
            throw err("The Teleport session could not be verified in Keychain. Keep this VPN and try pairing again.")
        }
        teleportAccessRevision &+= 1
    }

    /// Shared by ordinary and virtual connections; secrets never enter a saved
    /// WireGuardConfig or providerConfiguration.
    func wireGuardStartConfig(for id: String, config: WireGuardConfig) throws -> WireGuardStartConfig {
        if config.usesTeleport {
            guard let session = teleportSession(for: id) else { throw err("Pair this Teleport VPN with an invite first.") }
            var start = WireGuardStartConfig(config: config, privateKey: "", presharedKey: "")
            start.teleport = session
            start.clientName = "SimpleVPN"
            return start
        }
        let keys = wireGuardSecrets(for: id)
        guard !keys.privateKey.isEmpty else { throw err("Set this tunnel's private key first.") }
        if let problem = WireGuardConfig.keyProblem(keys.privateKey) { throw err(problem) }
        if let problem = WireGuardConfig.keyProblem(keys.presharedKey) { throw err(problem) }
        return WireGuardStartConfig(config: config, privateKey: keys.privateKey, presharedKey: keys.presharedKey)
    }
}
