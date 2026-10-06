// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
import Foundation
@preconcurrency import NetworkExtension

extension VPNController {
    nonisolated static func tailscaleNodeStateProfile(_ id: String) -> String { "tailscale.state.\(id)" }

    func migrateLegacyTailscaleIdentity(_ id: String) async {
        if let pending = tailscaleIdentityMigrations[id] { await pending.value; return }
        guard !locallyRemovedProfileIDs.contains(id) else { return }
        let task = Task { await performLegacyTailscaleMigration(id) }
        tailscaleIdentityMigrations[id] = task
        await task.value
        tailscaleIdentityMigrations[id] = nil
    }

    private func performLegacyTailscaleMigration(_ id: String) async {
        guard let session = managers[id]?.connection as? NETunnelProviderSession,
              session.status == .disconnected || session.status == .invalid,
              let bytes = await sendSessionMessageData(Data("tslegacy".utf8), session: session, timeout: 2),
              let state = try? JSONDecoder().decode(TailscaleLegacyNodeState.self, from: bytes), state.isValid,
              !Task.isCancelled, !locallyRemovedProfileIDs.contains(id),
              session.status == .disconnected || session.status == .invalid else { return }
        do {
            try await Task.detached {
                let account = Self.tailscaleNodeStateProfile(id)
                // An already migrated Keychain identity is authoritative. Never
                // replace it with a stale leftover file from an earlier version.
                if let existing = try KeychainCredentialStore.credentialsForExport(profile: account) {
                    guard TailscaleNodeState(revision: 0, data: existing.password).isValid else {
                        throw NSError(domain: "SimpleVPN.Keychain", code: 1)
                    }
                } else {
                    try KeychainCredentialStore.saveCredentials(profile: account, .init(username: "node-state", password: state.data))
                    guard try KeychainCredentialStore.credentialsForExport(profile: account)?.password == state.data else {
                        throw NSError(domain: "SimpleVPN.Keychain", code: 1)
                    }
                }
            }.value
            guard !Task.isCancelled else { return }
            let reply = await sendSessionMessageData(Data("tslegacy:ack:\(state.checksum)".utf8), session: session, timeout: 2)
            if reply.flatMap({ String(data: $0, encoding: .utf8) }) != "ok" {
                lastError = "This VPN's identity is in your Keychain, but its previous plaintext copy could not be removed."
            }
        } catch {
            lastError = "This VPN's previous identity could not be moved to your Keychain. Its original copy was kept."
        }
    }

    /// Cancel and drain the previous writer before starting/deleting this node.
    /// A cancelled in-flight SecItemUpdate must never overwrite a newer session.
    func drainTailscaleStateBroker(_ id: String) async {
        tailscaleStateBrokerEpochs[id] = nil
        let task = tailscaleStateBrokers.removeValue(forKey: id)
        task?.cancel()
        await task?.value
    }

    func watchTailscaleNodeState(_ id: String, session: NETunnelProviderSession) {
        guard tailscaleStateBrokers[id] == nil else { return }
        let epoch = UUID()
        tailscaleStateBrokerEpochs[id] = epoch
        tailscaleStateBrokers[id] = Task { [weak self] in
            defer {
                if self?.tailscaleStateBrokerEpochs[id] == epoch {
                    self?.tailscaleStateBrokers[id] = nil
                    self?.tailscaleStateBrokerEpochs[id] = nil
                }
            }
            var acknowledged: UInt64?
            var misses = 0
            let started = Date()
            var observedActive = false
            while !Task.isCancelled {
                guard let self else { return }
                if UI.isActive(session.status) { observedActive = true }
                if (session.status == .disconnected || session.status == .invalid),
                   observedActive || Date().timeIntervalSince(started) > 12 { return }
                guard let bytes = await self.sendSessionMessageData(Data("tsstate".utf8), session: session, timeout: 2), !Task.isCancelled,
                      let state = try? JSONDecoder().decode(TailscaleNodeState.self, from: bytes), state.isValid else {
                    misses += 1
                    if misses >= 5 {
                        self.lastError = "The VPN could not save its identity in your Keychain. The connection was stopped."
                        session.stopVPNTunnel(); return
                    }
                    do { try await Task.sleep(for: .milliseconds(250)) } catch { return }
                    continue
                }
                misses = 0
                if acknowledged != state.revision {
                    do {
                        try await Task.detached {
                            let account = Self.tailscaleNodeStateProfile(id)
                            try KeychainCredentialStore.saveCredentials(profile: account, .init(username: "node-state", password: state.data))
                            guard try KeychainCredentialStore.credentialsForExport(profile: account)?.password == state.data else {
                                throw NSError(domain: "SimpleVPN.Keychain", code: 1,
                                    userInfo: [NSLocalizedDescriptionKey: "The saved VPN identity could not be verified."])
                            }
                        }.value
                        guard !Task.isCancelled else { return }
                        let ack = await self.sendSessionMessageData(Data("tsstate:ack:\(state.revision)".utf8), session: session, timeout: 2)
                        if ack.flatMap({ String(data: $0, encoding: .utf8) }) == "ok" {
                            acknowledged = state.revision
                        }
                    } catch {
                        self.lastError = "Your Keychain could not save this VPN's identity. Unlock your Keychain before reconnecting."
                        session.stopVPNTunnel(); return
                    }
                }
                do { try await Task.sleep(for: .milliseconds(250)) } catch { return }
            }
        }
    }
}
