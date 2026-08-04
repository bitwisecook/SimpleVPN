// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
//  VPNController+SSHNetworkTunnel.swift
//  The SSH Network Tunnel face of VPNController. Like Tailscale, the Proxy Tunnel
//  and WireGuard, it is an ordinary packet-tunnel profile — sidebar, status dots,
//  telemetry and map come for free — so only the settings blob, the credential
//  handling, the host-key ladder and the connect flow differ, and they live here.
//  Stored state (the observable config/status mirrors) lives in VPNController.swift.
//
//  Secrets invariant: the password, private key and certificate live in the
//  keychain under "sshnet.<id>" and ride startTunnel(options:) in memory at
//  connect — NEVER in providerConfiguration. Only the login name is persisted,
//  because a login name is not a secret.
//
//  ── WHO DECIDES TO TRUST THE SERVER ──
//  The extension is PIN-ONLY and cannot ask anyone anything (no UI, no user
//  session, and root+sandbox means no known_hosts to read or write). So the
//  ladder runs HERE, where there is a user, a keychain and ~/.ssh:
//
//    pin set          → use it, and nothing else connects.
//    known_hosts hit  → use the key on record.
//    known_hosts miss → "Only known hosts" refuses; "Trust on first use" needs
//                       the user to press "Check and Trust" in the editor, which
//                       fetches the key, shows it, and — only on their say-so —
//                       pins it. Logged at .notice.
//
//  Trust on first use is therefore an ACTION SOMEONE TAKES, never something that
//  happens while they are looking elsewhere. `SSHHostKeyDecision` is the pure
//  function that makes the call, so the one security decision here is unit-tested
//  rather than inferred from the shape of this file.
//

import Foundation
@preconcurrency import NetworkExtension
import os

extension VPNController {

    // MARK: SSH Network Tunnel

    func isSSHNetworkTunnel(_ id: String) -> Bool {
        profiles.first { $0.id == id }?.kind == .sshNetworkTunnel
    }

    func sshNetworkTunnelConfig(for id: String) -> SSHNetworkTunnelConfig {
        if let c = sshNetworkTunnelConfigs[id] { return c }
        let proto = managers[id]?.protocolConfiguration as? NETunnelProviderProtocol
        return SSHNetworkTunnelConfig.decode(from: proto?.providerConfiguration?["sshnet"] as? Data)
    }

    /// Create a new SSH Network Tunnel. Starts full-tunnel with trust-on-first-use,
    /// which the editor then refines.
    @discardableResult
    func createSSHNetworkTunnel(name: String = "SSH Network Tunnel") async throws -> String {
        guard !ManagedPolicy.lockConfiguration else { throw Self.configLocked }
        let id = UUID().uuidString
        var config = SSHNetworkTunnelConfig()
        // The Mac account name is right far more often than empty is, and it is
        // what ssh(1) would default to.
        config.username = NSUserName()
        let mgr = NETunnelProviderManager()
        let proto = NETunnelProviderProtocol()
        proto.providerBundleIdentifier = Self.providerBundleID
        // serverAddress is what macOS shows in Network settings and what the
        // probe/endpoint machinery dials: the SSH server (empty until set).
        proto.serverAddress = config.server.isEmpty ? "ssh" : config.server
        var conf: [String: Any] = ["profile": id, "vpnType": VPNKind.sshNetworkTunnel.rawValue]
        if let blob = config.encodedBlob() { conf["sshnet"] = blob }
        proto.providerConfiguration = conf
        mgr.protocolConfiguration = proto
        mgr.localizedDescription = name
        mgr.isEnabled = true
        try await mgr.saveToPreferences()
        try await mgr.loadFromPreferences()
        await loadAll()
        selectedID = id
        Self.log.log("created ssh network tunnel id=\(id, privacy: .public)")
        return id
    }

    func setSSHNetworkTunnelConfig(_ raw: SSHNetworkTunnelConfig, for id: String) async throws {
        guard !ManagedPolicy.lockConfiguration else { throw Self.configLocked }
        guard let mgr = managers[id],
              let proto = mgr.protocolConfiguration as? NETunnelProviderProtocol else { return }
        // normalized() on every save path (the OpenVPNOverrides rule).
        let config = raw.normalized()
        var conf = proto.providerConfiguration ?? [:]
        conf["profile"] = id
        conf["vpnType"] = VPNKind.sshNetworkTunnel.rawValue
        if let blob = config.encodedBlob() { conf["sshnet"] = blob }
        proto.providerConfiguration = conf
        proto.serverAddress = config.server.isEmpty ? "ssh" : config.server
        mgr.protocolConfiguration = proto
        try await mgr.saveToPreferences()
        try await mgr.loadFromPreferences()
        sshNetworkTunnelConfigs[id] = config
        await loadAll()
    }

    // MARK: Secrets (keychain "sshnet.<id>", never providerConfiguration)

    /// Keychain namespace for a profile's SSH material. A namespace of its own so
    /// an SSH Network Tunnel and an `.ssh` profile with the same id could never
    /// read each other's secrets.
    nonisolated static func sshNetKeyProfile(_ id: String) -> String { "sshnet.\(id)" }

    /// The stored material. `password` doubles as the key passphrase (libssh
    /// conflates them, and so does the bridge).
    func sshNetworkTunnelSecrets(for id: String)
        -> (password: String, privateKeyPEM: String, certificatePEM: String) {
        let c = KeychainCredentialStore.loadCredentials(profile: Self.sshNetKeyProfile(id))
        return (c?.password ?? "", c?.proxyPassword ?? "", c?.privateKeyPassword ?? "")
    }

    /// Store (or update) the material. nil = leave that field alone (the editor's
    /// write-only fields send nil when untouched); a value — including "" —
    /// replaces it, so clearing a field really clears it. All empty deletes it.
    func setSSHNetworkTunnelSecrets(password: String?, privateKeyPEM: String?,
                                    certificatePEM: String?, for id: String) {
        let existing = sshNetworkTunnelSecrets(for: id)
        let newPassword = password ?? existing.password
        let newKey = privateKeyPEM.map { $0.trimmingCharacters(in: .whitespacesAndNewlines) }
            ?? existing.privateKeyPEM
        let newCert = certificatePEM.map { $0.trimmingCharacters(in: .whitespacesAndNewlines) }
            ?? existing.certificatePEM
        guard newPassword != existing.password || newKey != existing.privateKeyPEM
                || newCert != existing.certificatePEM else { return }
        if newPassword.isEmpty && newKey.isEmpty && newCert.isEmpty {
            KeychainCredentialStore.deleteCredentials(profile: Self.sshNetKeyProfile(id))
            return
        }
        try? KeychainCredentialStore.saveCredentials(
            profile: Self.sshNetKeyProfile(id),
            .init(username: "sshnet", password: newPassword,
                  proxyPassword: newKey.isEmpty ? nil : newKey,
                  privateKeyPassword: newCert.isEmpty ? nil : newCert))
    }

    /// Whether a private key is stored — the connect gate for key/certificate
    /// sign-in.
    func sshNetworkTunnelHasPrivateKey(_ id: String) -> Bool {
        !sshNetworkTunnelSecrets(for: id).privateKeyPEM.isEmpty
    }

    // MARK: Host-key trust (the ladder the extension cannot run)

    /// What "Check and Trust" found, for the editor to show. Observable so the
    /// button can report without a sheet of its own.
    struct SSHNetHostKeyReport: Sendable, Equatable {
        var fingerprint = ""
        var keyType = ""
        var message = ""
        var trusted = false
    }

    /// Fetch the server's host key, run the ladder, and — when the ladder says
    /// the user has to decide — PIN it, because pressing this button IS the
    /// decision. Nothing here writes known_hosts: the pin is what the extension
    /// uses, so recording it on the profile is both sufficient and auditable
    /// (it is visible in the editor, unlike a line appended to a file).
    @discardableResult
    func checkAndTrustSSHNetworkTunnelHostKey(id: String) async -> SSHNetHostKeyReport {
        let config = sshNetworkTunnelConfig(for: id)
        var report = SSHNetHostKeyReport()
        guard config.serverProblem == nil else {
            report.message = config.serverProblem ?? "Enter the server address first."
            return report
        }
        let resolved = await resolveSSHNetHostKey(config: config)
        report.fingerprint = resolved.fingerprint
        report.keyType = resolved.keyType

        switch resolved.decision {
        case .trusted(let pin):
            report.trusted = true
            report.message = "This server's host key is already trusted."
            if config.normalizedPin != pin {
                var updated = config
                updated.pinnedHostKeySHA256 = pin
                try? await setSSHNetworkTunnelConfig(updated, for: id)
            }
        case .askUser(let fingerprint, let keyType):
            var updated = config
            updated.pinnedHostKeySHA256 = fingerprint
            do {
                try await setSSHNetworkTunnelConfig(updated, for: id)
                report.trusted = true
                report.message = "Trusted \(keyType) SHA256:\(fingerprint) for \(config.server)."
                // TOFU is NEVER silent: this is the audit record, at .notice so it
                // persists (unlike .debug, which os_log discards).
                Self.log.notice("""
                    Trusted a new SSH host key on the user's explicit confirmation for \
                    \(config.server, privacy: .public):\(config.effectivePort) — \
                    \(keyType, privacy: .public) SHA256:\(fingerprint, privacy: .public)
                    """)
            } catch {
                report.message = error.localizedDescription
            }
        case .refused(let reason):
            report.message = reason
        }
        return report
    }

    /// Probe the server and run the pure decision. Never writes anything: the
    /// probe session checks known_hosts READ-ONLY (that is the whole reason
    /// SSHProbeSession exists) so a diagnostic can never rubber-stamp a new key.
    private func resolveSSHNetHostKey(config: SSHNetworkTunnelConfig) async
        -> (decision: SSHHostKeyDecision, fingerprint: String, keyType: String) {
        let probe = SSHProbeSession()
        // Nothing is left running on the far end: the probe opens no channel and
        // submits no credential, and the session goes as soon as we have the key.
        defer { probe.disconnect() }
        let handshake = await probe.connect(host: config.server, port: config.effectivePort,
                                            timeout: 10)
        guard case .success(let facts) = handshake else {
            var message = "SimpleVPN couldn't reach the SSH server to check its identity."
            if case .failure(let f) = handshake, !f.message.isEmpty { message = f.message }
            return (.refused(reason: message), "", "")
        }
        let fingerprint = SSHHostKeyDecision.normalize(facts.fingerprint ?? "")
        let keyType = facts.keyType ?? ""
        let knownHostsPath = ("~/.ssh/known_hosts" as NSString).expandingTildeInPath
        // No pin passed here: this call must report what KNOWN_HOSTS says, and the
        // pure decision applies the pin itself (pin first, ahead of known_hosts,
        // so a stale or appended entry can never override an explicit pin).
        let answer = await probe.checkHostKey(knownHostsPath: knownHostsPath, pin: nil)
        let mapped: SSHKnownHostsAnswer
        switch answer {
        case .match: mapped = .match
        case .mismatch: mapped = .mismatch
        case .notFound: mapped = .notFound
        case .unavailable: mapped = .unavailable
        }
        let decision = SSHHostKeyDecision.decide(policy: config.hostKeyPolicy,
                                                 configuredPin: config.pinnedHostKeySHA256,
                                                 presentedFingerprint: fingerprint,
                                                 keyType: keyType,
                                                 knownHosts: mapped)
        return (decision, fingerprint, keyType)
    }

    // MARK: Connect

    /// Connect an SSH Network Tunnel. Everything secret is read here and handed
    /// over in memory; the host key is resolved here too, because the extension
    /// accepts exactly one fingerprint and can neither prompt nor look one up.
    func connectSSHNetworkTunnel(id: String) async throws {
        guard let mgr = managers[id],
              mgr.protocolConfiguration is NETunnelProviderProtocol else { throw err("no such profile") }
        if let ensureExtensionReady, !(await ensureExtensionReady()) {
            throw err("SimpleVPN needs its network extension approved before it can connect. Open System Settings ▸ General ▸ Login Items & Extensions ▸ Network Extensions and allow SimpleVPN.")
        }
        let config = sshNetworkTunnelConfig(for: id)
        if let problem = config.connectProblem { throw err(problem) }

        let secrets = sshNetworkTunnelSecrets(for: id)
        if config.needsPrivateKey, secrets.privateKeyPEM.isEmpty {
            throw err("Set this tunnel's private key first (Manage VPNs ▸ this VPN ▸ Sign-In ▸ Set / Replace Key).")
        }
        if config.needsCertificate, secrets.certificatePEM.isEmpty {
            throw err("Certificate sign-in needs the certificate as well as the key — paste the contents of your \u{2026}-cert.pub.")
        }
        if config.authMethod == .password, secrets.password.isEmpty {
            throw err("Enter the password for \(config.username) on \(config.server), or switch this tunnel to key sign-in.")
        }

        // The pin, resolved BEFORE the tunnel starts. An empty pin is a refusal,
        // not a permissive default: the extension would hand the sign-in to
        // whatever answered.
        let pin = try await resolvedPinForConnect(id: id, config: config)

        var options: [String: NSObject] = [
            "sshUsername": config.username as NSString,
            "sshExpectedHostKeySHA256": pin as NSString,
        ]
        if !secrets.password.isEmpty { options["sshPassword"] = secrets.password as NSString }
        if !secrets.privateKeyPEM.isEmpty {
            options["sshPrivateKeyPEM"] = secrets.privateKeyPEM as NSString
        }
        if config.needsCertificate, !secrets.certificatePEM.isEmpty {
            options["sshCertificatePEM"] = secrets.certificatePEM as NSString
        }
        if ManagedPolicy.forceKeepInsideVPN { options["policyKeepInside"] = true as NSNumber }
        // Establish-time default-gateway ownership, same as OpenVPN (RC3).
        options["gatewayOwned"] = predictedGatewayOwned(id) as NSNumber

        mgr.isEnabled = true
        try await mgr.saveToPreferences()
        try await mgr.loadFromPreferences()
        guard let session = mgr.connection as? NETunnelProviderSession else {
            throw err("The VPN configuration isn't ready — try removing and re-creating it.")
        }
        try session.startTunnel(options: options)
        Self.log.log("ssh network tunnel startTunnel dispatched for \(id, privacy: .public)")
        resyncStatuses()
    }

    /// The one fingerprint this connect will accept, or a refusal explaining what
    /// the user has to do. A saved pin short-circuits the probe entirely — the
    /// common case, and the one that must not add a round trip to every connect.
    private func resolvedPinForConnect(id: String, config: SSHNetworkTunnelConfig) async throws -> String {
        let saved = config.normalizedPin
        if !saved.isEmpty { return saved }
        if config.hostKeyPolicy == .pinned {
            throw err("This tunnel accepts only a pinned host key, but none is saved. Use \u{201C}Check and Trust\u{201D} in its Security settings, or paste the fingerprint.")
        }
        let resolved = await resolveSSHNetHostKey(config: config)
        switch resolved.decision {
        case .trusted(let pin):
            // Record it so the next connect needs no probe, and so the user can
            // see exactly what is trusted.
            var updated = config
            updated.pinnedHostKeySHA256 = pin
            try? await setSSHNetworkTunnelConfig(updated, for: id)
            return pin
        case .askUser(let fingerprint, let keyType):
            // NEVER trust silently at connect time. The user has to look at the
            // key once — that is the entire value of trust-on-first-use, and doing
            // it invisibly here would be trust-on-no-use.
            throw err("""
                SimpleVPN hasn't met \(config.server) before. It offers \(keyType) \
                SHA256:\(fingerprint). Open this VPN's Security settings and press \
                \u{201C}Check and Trust\u{201D} if that is the right server.
                """)
        case .refused(let reason):
            throw err(reason)
        }
    }

    /// Refresh (and publish) the engine status for a connected SSH Network Tunnel.
    @discardableResult
    func refreshSSHNetworkTunnelStatus(id: String) async -> SSHNetworkTunnelStatus? {
        guard let data = await sendMessageData("sshnetstatus", to: id),
              let status = try? JSONDecoder().decode(SSHNetworkTunnelStatus.self, from: data) else {
            return nil
        }
        sshNetworkTunnelStatuses[id] = status
        return status
    }
}
