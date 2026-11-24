// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
import AppKit
import Foundation
import Security
@preconcurrency import NetworkExtension

/// Only operation names and Security status codes may leave the private channel.
nonisolated struct TailscaleIdentitySaveError: LocalizedError {
    enum Step: String { case read, save, verify }
    let step: Step
    let status: OSStatus?

    init(_ step: Step, cause: Error? = nil) {
        self.step = step
        if let error = cause as NSError?, error.domain == NSOSStatusErrorDomain {
            status = OSStatus(exactly: error.code)
        } else { status = nil }
    }

    var canRetry: Bool {
        status != errSecAuthFailed && status != errSecUserCanceled && status != errSecInteractionNotAllowed
    }

    var errorDescription: String? {
        let summary = "SimpleVPN couldn’t \(step.rawValue) this VPN’s identity in your login keychain."
        switch status {
        case errSecInteractionNotAllowed:
            return summary + " Open Keychain Access, check that the login keychain is unlocked, then reconnect."
        case errSecAuthFailed, errSecUserCanceled:
            return summary + " macOS didn’t grant access. Reconnect and allow SimpleVPN to use the saved identity."
        case let code?:
            let detail = SecCopyErrorMessageString(code, nil) as String? ?? "Keychain error"
            return summary + " \(detail) (OSStatus \(code))."
        case nil:
            return summary + (step == .verify ? " The saved copy could not be confirmed." : "")
        }
    }
}

nonisolated enum TailscaleIdentityPersistence {
    /// Reattaching to the same snapshot only needs a read. Never acknowledge
    /// a new value until a separate Keychain read returns the exact bytes.
    static func persist(_ state: String, checkingExisting: Bool,
                        read: () throws -> String?, write: (String) throws -> Void) throws {
        if checkingExisting {
            do {
                if let existing = try read(), existing.utf8.elementsEqual(state.utf8) { return }
            } catch { throw TailscaleIdentitySaveError(.read, cause: error) }
        }
        do { try write(state) } catch { throw TailscaleIdentitySaveError(.save, cause: error) }
        let confirmed: String?
        do { confirmed = try read() } catch { throw TailscaleIdentitySaveError(.verify, cause: error) }
        guard let confirmed, confirmed.utf8.elementsEqual(state.utf8) else { throw TailscaleIdentitySaveError(.verify) }
    }
}

extension VPNController {
    nonisolated static func tailscaleNodeStateProfile(_ id: String) -> String { "tailscale.state.\(id)" }

    func tailscaleIdentityLease(_ id: String) throws -> Installation.Lease {
        guard Self.permitsLiveCredentialBrokers else {
            throw err("This test instance cannot manage a live VPN identity.")
        }
        return try tailscaleBrokerLeases.acquire(id)
    }

    /// An extension may return nil while its engine starts. Probe off the
    /// profile-loading path and keep a single probe in flight per profile.
    func attachTailscaleNodeState(_ id: String) {
        guard Self.permitsLiveCredentialBrokers, !tailscaleStartingIDs.contains(id),
              tailscaleStateBrokers[id] == nil, !locallyRemovedProfileIDs.contains(id),
              !tailscaleProbingIDs.contains(id) else { return }
        if virtualManager(for: id) != nil { beginVirtualTailscaleStateSync(for: id); return }
        let lease: Installation.Lease
        do { lease = try tailscaleIdentityLease(id) }
        catch TailscaleBrokerLeases.BrokerError.owned {
            // Close the race where the owner exits just before registration.
            if watchTailscalePeerExit() { attachTailscaleNodeState(id) }
            return
        }
        catch { return }
        tailscaleProbingIDs.insert(id)
        Task { [weak self] in
            guard let self else { return }
            defer { tailscaleProbingIDs.remove(id) }
            let deadline = ContinuousClock.now + .seconds(8)
            repeat {
                guard let session = managers[id]?.connection as? NETunnelProviderSession,
                      UI.isActive(session.status), !locallyRemovedProfileIDs.contains(id),
                      !tailscaleStartingIDs.contains(id), tailscaleStateBrokers[id] == nil else { return }
                if let bytes = await sendSessionMessageData(TailscaleNodeState.request(after: nil), session: session, timeout: 2),
                   TailscaleNodeState.decodeReply(bytes, after: nil) != nil,
                   managers[id]?.connection === session, UI.isActive(session.status),
                   !locallyRemovedProfileIDs.contains(id), !tailscaleStartingIDs.contains(id) {
                    watchTailscaleNodeState(id, session: session, lease: lease)
                    return
                }
                do { try await Task.sleep(for: .milliseconds(350)) } catch { return }
            } while ContinuousClock.now < deadline
        }
    }

    /// If a competing owner crashes while this app is open, NE may continue to
    /// show Connected. Its process-exit notification is the handoff trigger.
    private func watchTailscalePeerExit() -> Bool {
        guard tailscalePeerExitObserver == nil, let bundleID = Bundle.main.bundleIdentifier else { return false }
        let applicationKey = NSWorkspace.applicationUserInfoKey
        tailscalePeerExitObserver = NSWorkspace.shared.notificationCenter.addObserver(
            forName: NSWorkspace.didTerminateApplicationNotification, object: nil, queue: .main
        ) { [weak self] notification in
            guard let app = notification.userInfo?[applicationKey] as? NSRunningApplication,
                  app.bundleIdentifier == bundleID else { return }
            MainActor.assumeIsolated {
                guard let self else { return }
                for profile in self.profiles where profile.kind == .tailscale && UI.isActive(profile.status) {
                    self.attachTailscaleNodeState(profile.id)
                }
            }
        }
        return true
    }

    func migrateLegacyTailscaleIdentity(_ id: String) async {
        if let pending = tailscaleIdentityMigrations[id] { await pending.value; return }
        guard !locallyRemovedProfileIDs.contains(id), let lease = try? tailscaleIdentityLease(id) else { return }
        let task = Task {
            defer { withExtendedLifetime(lease) {} }
            await performLegacyTailscaleMigration(id)
        }
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

    private func sendNodeBrokerMessage(_ message: Data, member: String?, session: NETunnelProviderSession) async -> Data? {
        guard let member else { return await sendSessionMessageData(message, session: session, timeout: 2) }
        guard let command = String(data: message, encoding: .utf8),
              let envelope = try? JSONEncoder().encode(VirtualRoutingMessage(profile: member, message: command)) else { return nil }
        return await sendSessionMessageData(Data("router:message:".utf8) + envelope, session: session, timeout: 2)
    }

    func virtualTailscaleOptions(for id: String, config: TailscaleConfig) async throws -> [String: Data] {
        guard pendingVirtualNodeLeases[id] == nil, tailscaleStateBrokers[id] == nil else {
            throw err("This Tailscale identity is already in use.")
        }
        let lease = try tailscaleIdentityLease(id)
        await migrateLegacyTailscaleIdentity(id)
        if let issue = config.controlURLProblem ?? config.exitNodeSelectionProblem ?? TailscaleConfig.routesProblem(config.advertiseRoutes) {
            throw err(issue)
        }
        let state = try await Task.detached {
            try KeychainCredentialStore.credentialsForExport(profile: Self.tailscaleNodeStateProfile(id))?.password
        }.value
        var options = ["broker": Data([1])]
        if let state {
            guard TailscaleNodeState(revision: 0, data: state).isValid else { throw err("The saved Tailscale identity is invalid.") }
            options["nodeState"] = Data(state.utf8)
        }
        let key = tailscaleAuthKey(for: id)
        if !key.isEmpty { options["authKey"] = Data(key.utf8) }
        pendingVirtualNodeLeases[id] = lease
        return options
    }

    func discardVirtualTailscaleSetup(for id: String) { pendingVirtualNodeLeases[id] = nil }

    func beginVirtualTailscaleStateSync(for id: String) {
        guard Self.permitsLiveCredentialBrokers, tailscaleStateBrokers[id] == nil, !virtualStoppedMembers.contains(id),
              let session = virtualManager(for: id)?.connection as? NETunnelProviderSession else { return }
        let lease: Installation.Lease
        do { lease = try pendingVirtualNodeLeases.removeValue(forKey: id) ?? tailscaleIdentityLease(id) }
        catch TailscaleBrokerLeases.BrokerError.owned {
            if watchTailscalePeerExit() { attachTailscaleNodeState(id) }
            return
        } catch { return }
        watchTailscaleNodeState(id, session: session, lease: lease, member: true)
        watchTailscaleSignIn(id: id, lease: lease)
    }

    func watchTailscaleNodeState(_ id: String, session: NETunnelProviderSession, lease: Installation.Lease, member: Bool = false) {
        guard tailscaleStateBrokers[id] == nil else { return }
        let epoch = UUID()
        tailscaleStateBrokerEpochs[id] = epoch
        tailscaleStateBrokers[id] = Task { [weak self] in
            defer { withExtendedLifetime(lease) {} }
            defer {
                if self?.tailscaleStateBrokerEpochs[id] == epoch {
                    self?.tailscaleStateBrokers[id] = nil
                    self?.tailscaleStateBrokerEpochs[id] = nil
                }
            }
            var acknowledged: TailscaleNodeState.Cursor?
            var verified: TailscaleNodeState.Cursor?
            var saveFailures = 0
            var requestFullSnapshot = false
            let clock = ContinuousClock()
            let started = clock.now
            var lastReply = started
            var warnedAboutTransport = false
            var observedActive = false
            while !Task.isCancelled {
                guard let self, self.tailscaleStateBrokerEpochs[id] == epoch else { return }
                if member {
                    guard self.virtualManager(for: id)?.connection === session, !self.virtualStoppedMembers.contains(id) else { return }
                }
                if UI.isActive(session.status) { observedActive = true }
                if session.status == .disconnecting { return }
                if session.status == .disconnected || session.status == .invalid,
                   observedActive || clock.now - started > .seconds(12) { return }

                let requestedCursor = requestFullSnapshot ? nil : acknowledged
                let request = TailscaleNodeState.request(after: requestedCursor)
                let bytes = await self.sendNodeBrokerMessage(request, member: member ? id : nil, session: session)
                guard !Task.isCancelled, self.tailscaleStateBrokerEpochs[id] == epoch else { return }
                let response = bytes.flatMap { TailscaleNodeState.decodeReply($0, after: requestedCursor) }
                requestFullSnapshot = response == nil || response == .starting
                var delay = Duration.milliseconds(250)
                switch response {
                case .snapshot(let state):
                    lastReply = clock.now
                    warnedAboutTransport = false
                    let cursor = state.cursor
                    if verified != cursor {
                        let checkExisting = verified == nil
                        let account = Self.tailscaleNodeStateProfile(id)
                        do {
                            try await Task.detached {
                                try TailscaleIdentityPersistence.persist(state.data, checkingExisting: checkExisting) {
                                    try KeychainCredentialStore.credentialsForExport(profile: account)?.password
                                } write: { data in
                                    try KeychainCredentialStore.saveCredentials(profile: account, .init(username: "node-state", password: data))
                                }
                            }.value
                            verified = cursor
                            saveFailures = 0
                        } catch {
                            guard !Task.isCancelled, self.tailscaleStateBrokerEpochs[id] == epoch,
                                  UI.isActive(session.status) else { return }
                            let failure = error as? TailscaleIdentitySaveError ?? TailscaleIdentitySaveError(.save)
                            Self.log.error("Tailscale identity \(failure.step.rawValue, privacy: .public) failed, OSStatus \(failure.status.map(String.init) ?? "unavailable", privacy: .public)")
                            saveFailures += 1
                            if !failure.canRetry || saveFailures >= 3 {
                                self.report(failure, profile: id)
                                if member, await self.sendNodeBrokerMessage(Data("router:stop-port".utf8), member: id, session: session) == Data("ok".utf8) {
                                    self.virtualStoppedMembers.insert(id)
                                    self.resyncStatuses()
                                } else {
                                    // The provider could not confirm revoking the unsaved identity.
                                    session.stopVPNTunnel()
                                }
                                return
                            }
                        }
                    }
                    guard !Task.isCancelled, self.tailscaleStateBrokerEpochs[id] == epoch else { return }
                    if verified == cursor, acknowledged != cursor {
                        let ack = await self.sendNodeBrokerMessage(state.acknowledgement, member: member ? id : nil, session: session)
                        if ack == Data("ok".utf8) { acknowledged = cursor }
                    } else if acknowledged == cursor { delay = .seconds(1) }
                case .unchanged:
                    lastReply = clock.now
                    warnedAboutTransport = false
                    delay = .seconds(1)
                case .starting, nil:
                    // A startup or transport delay says nothing about Keychain.
                    // The engine itself enforces the deadline on a pending write.
                    if clock.now - lastReply >= .seconds(15) {
                        if !warnedAboutTransport {
                            Self.log.error("Tailscale extension has not supplied its identity snapshot; retrying")
                            warnedAboutTransport = true
                        }
                        delay = .seconds(1)
                    }
                }
                do { try await Task.sleep(for: delay) } catch { return }
            }
        }
    }
}
