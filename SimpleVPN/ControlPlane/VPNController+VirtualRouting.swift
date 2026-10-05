// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only

import Foundation
@preconcurrency import NetworkExtension

extension VPNController {
    var virtualDefaultCaptureBlocked: Bool {
        pushedNetworkStats.contains { routeVirtualProfileIDs.contains($0.key) && $0.value.defaultCaptureBlocked == true }
    }
    var routeVirtualProfileIDs: Set<String> {
        Set(virtualMembers.keys.filter { virtualManager(for: $0) != nil })
    }

    func routeApplyVirtualPlan(_ plan: RoutePlan) async -> Bool {
        let sessions = Set(routeVirtualProfileIDs.compactMap { virtualMembers[$0] }).sorted()
        // Release a previous virtual owner before promoting a different session.
        let ordered = sessions.sorted {
            let aOwns = plan.owner.flatMap { virtualMembers[$0] } == $0
            let bOwns = plan.owner.flatMap { virtualMembers[$0] } == $1
            return aOwns == bOwns ? $0 < $1 : !aOwns
        }
        for sessionID in ordered {
            let ids = routeVirtualProfileIDs.filter { virtualMembers[$0] == sessionID }
            guard let recipient = ids.sorted().first(where: { !virtualStoppedMembers.contains($0) }) else { continue }
            let request = VirtualRouteApplyRequest(owner: ids.contains(plan.owner ?? "") ? plan.owner! : "",
                retainUnavailableDefault: plan.owner == nil && !plan.userChoseDirect,
                routes: plan.routeRequests.filter { ids.contains($0.key) })
            guard let data = try? JSONEncoder().encode(request), let text = String(data: data, encoding: .utf8),
                  await sendMessage("router:apply-plan:\(text)", to: recipient) == "ok" else { return false }
        }
        return true
    }

    func virtualCompositionProblem(_ composition: VPNComposition) -> String? {
        if let problem = composition.validationProblem { return problem }
        if !(2...16).contains(composition.members.count) { return "Choose between two and sixteen VPNs." }
        if composition.fullTunnelConflict { return "Choose one full tunnel." }
        if composition.members.contains(where: { $0.dependsOn != nil }) { return "Chained VPNs are unavailable through this virtual interface." }
        if !composition.members.allSatisfy({ member in profiles.first { $0.id == member.profileID }?.kind == .wireGuard }) {
            return "This virtual interface currently supports WireGuard VPNs."
        }
        if isCompositionActive(composition) { return "Disconnect the composition first." }
        return nil
    }

    func connectThroughVirtualInterface(_ composition: VPNComposition) async {
        do { try await connectVirtualComposition(composition) }
        catch is CancellationError { }
        catch { lastError = error.localizedDescription }
    }
    /// WireGuard compositions use a separate capture configuration. Original
    /// profiles keep their settings and user-Keychain identities for ordinary
    /// connections; a routing session never persists their private keys.
    func connectVirtualComposition(_ composition: VPNComposition) async throws {
        if let problem = virtualCompositionProblem(composition) { throw err(problem) }
        let ids = Set(composition.members.map(\.profileID))
        guard let attempt = connectionReservations.reserve(owner: "virtual." + composition.id, members: ids) else {
            throw err("A member of this composition is already preparing a connection.")
        }
        defer { connectionReservations.finish(attempt); resyncStatuses() }
        // Validate the initial state before publishing a pending connection.
        guard composition.members.allSatisfy({ member in
            profiles.first { $0.id == member.profileID }.map { !UI.isActive($0.status) } == true
        }) else { throw err("Disconnect the composition's VPNs before connecting them through one virtual interface.") }
        resyncStatuses()
        await wireGuardConfigurationOperations.acquire()
        defer { wireGuardConfigurationOperations.release() }
        guard connectionReservations.isCurrent(attempt), !Task.isCancelled else { throw CancellationError() }
        if let ensureExtensionReady, !(await ensureExtensionReady()) {
            throw err("Allow SimpleVPN's network extension before connecting this composition.")
        }
        guard connectionReservations.isCurrent(attempt), !Task.isCancelled else { throw CancellationError() }
        var members: [VirtualRoutingConfig.Member] = []
        var startMembers: [VirtualRoutingStartConfig.Member] = []
        var owner = ""
        for member in composition.members {
            let id = member.profileID
            if let why = controlDenied(.connect(profile: id)) { throw err(why) }
            guard let profile = profiles.first(where: { $0.id == id }), profile.kind == .wireGuard,
                  let individual = managers[id], !UI.isActive(individual.connection.status),
                  virtualManager(for: id) == nil else { throw err("Disconnect the composition's VPNs before connecting them through one virtual interface.") }
            let config = wireGuardConfig(for: id)
            let custom = customRouting(for: id)
            guard !config.allowLocalNetworkAccess, custom.dns.isIdentity, custom.proxy.isIdentity else {
                throw err("This virtual connection supports custom routes. Local network exclusions and custom DNS or proxy settings need independent connections for now.")
            }
            let intent = custom.routes.apply(to: .init(engine: id,
                advertisedPrefixes: config.allowedIPs.filter { TailscaleNetworkSettings.parse($0)?.isDefaultRoute == false }, wantsDefault: config.isFullTunnel,
                canOwnDefault: config.isFullTunnel))
            if member.role == .full {
                guard intent.canOwnDefault else { throw err("\(profile.name) cannot carry the full tunnel role with these custom routes.") }
                owner = id
            }
            let secrets = wireGuardSecrets(for: id)
            guard !secrets.privateKey.isEmpty, WireGuardConfig.keyProblem(secrets.privateKey) == nil,
                  WireGuardConfig.keyProblem(secrets.presharedKey) == nil else { throw err("Set a valid private key for \(profile.name).") }
            members.append(.init(id: id, wireGuard: config.redactedForStorage(), prefixes: intent.advertisedPrefixes))
            startMembers.append(.init(id: id, addresses: config.addresses,
                wireGuard: .init(config: config, privateKey: secrets.privateKey, presharedKey: secrets.presharedKey)))
        }
        if ManagedPolicy.forceKeepInsideVPN, owner.isEmpty { throw err("Your organization requires a full tunnel for this connection.") }
        var policy = VirtualRoutingPolicy(defaultOwner: owner)
        policy.rules = members.flatMap { member in member.prefixes.map { .init(prefix: $0, port: member.id) } }
        if let dnsMember = members.first(where: { $0.id == owner }) {
            policy.rules.insert(contentsOf: dnsMember.wireGuard.dns.filter(WireGuardConfig.isIPLiteral).map {
                .init(prefix: $0 + ($0.contains(":") ? "/128" : "/32"), port: owner)
            }, at: 0)
        }
        let config = VirtualRoutingConfig(id: composition.id, members: members, policy: policy)
        if let problem = config.problem { throw err(problem) }
        let manager = virtualManagers[composition.id] ?? NETunnelProviderManager()
        guard !UI.isActive(manager.connection.status) else { throw err("This virtual connection is already active.") }
        let proto = NETunnelProviderProtocol()
        proto.providerBundleIdentifier = Self.providerBundleID
        proto.serverAddress = composition.name
        proto.providerConfiguration = ["profile": "virtual.\(composition.id)", "routingSession": try JSONEncoder().encode(config)]
        manager.protocolConfiguration = proto
        manager.localizedDescription = composition.name
        manager.isEnabled = true
        try await manager.saveToPreferences()
        // Retain the saved manager even if cancellation stops the attempt here,
        // so removal can delete the configuration after this write has drained.
        virtualManagers[composition.id] = manager
        guard connectionReservations.isCurrent(attempt), !Task.isCancelled else { throw CancellationError() }
        try await manager.loadFromPreferences()
        guard connectionReservations.isCurrent(attempt), !Task.isCancelled,
              ids.allSatisfy({ managers[$0] != nil && !locallyRemovedProfileIDs.contains($0) }) else { throw CancellationError() }
        guard let session = manager.connection as? NETunnelProviderSession else { throw err("The virtual connection is not ready.") }
        let start = VirtualRoutingStartConfig(members: startMembers, policy: policy)
        try session.startTunnel(options: ["routingStart": try JSONEncoder().encode(start) as NSData])
        virtualManagers[composition.id] = manager
        virtualStarts[composition.id] = Date()
        virtualObservedActive.remove(composition.id)
        for member in members {
            virtualMembers[member.id] = composition.id
            virtualStoppedMembers.remove(member.id)
            compositionRouteRoles[member.id] = member.id == owner ? .full : .split
        }
        resyncStatuses()
        await setDefaultGateway(to: owner.isEmpty ? nil : owner)
    }

    func virtualManager(for id: String) -> NETunnelProviderManager? {
        guard let sessionID = virtualMembers[id], let manager = virtualManagers[sessionID],
              (manager.connection.status != .disconnected && manager.connection.status != .invalid)
                || virtualStarts[sessionID].map({ Date().timeIntervalSince($0) <= 12 }) == true else { return nil }
        return manager
    }

    func rememberVirtualManager(_ manager: NETunnelProviderManager, config: VirtualRoutingConfig) {
        virtualManagers[config.id] = manager
        guard UI.isActive(manager.connection.status) || virtualStarts[config.id] != nil else { return }
        for member in config.members {
            virtualMembers[member.id] = config.id
            compositionRouteRoles[member.id] = member.id == config.policy.defaultOwner ? .full : .split
        }
    }

    func disconnectVirtualMember(_ id: String) -> Bool {
        guard let manager = virtualManager(for: id), let sessionID = virtualMembers[id] else { return false }
        Task {
            guard await sendMessage("router:stop-port", to: id) == "ok" else {
                lastError = "The virtual connection did not acknowledge stopping this VPN."; return
            }
            virtualStoppedMembers.insert(id)
            if !virtualMembers.contains(where: { $0.value == sessionID && !virtualStoppedMembers.contains($0.key) }) {
                manager.connection.stopVPNTunnel()
            }
            resyncStatuses()
        }
        return true
    }

    func clearVirtualMembers(_ sessionID: String) {
        let members = virtualMembers.filter { $0.value == sessionID }.map(\.key)
        for id in members {
            virtualMembers[id] = nil; virtualStoppedMembers.remove(id); compositionRouteRoles[id] = nil
        }
        virtualStarts[sessionID] = nil; virtualObservedActive.remove(sessionID)
    }

    func removeVirtualComposition(_ id: String) async throws {
        guard !ManagedPolicy.lockConfiguration else { throw Self.configLocked }
        connectionReservations.cancel(owner: "virtual." + id)
        resyncStatuses()
        await wireGuardConfigurationOperations.acquire()
        defer { wireGuardConfigurationOperations.release() }
        guard let manager = virtualManagers[id] else { return }
        manager.connection.stopVPNTunnel()
        for _ in 0..<100 {
            if manager.connection.status == .disconnected || manager.connection.status == .invalid { break }
            try await Task.sleep(for: .milliseconds(100))
        }
        guard manager.connection.status == .disconnected || manager.connection.status == .invalid else {
            throw err("The virtual connection is still disconnecting. Try removing the composition again.")
        }
        try await manager.removeFromPreferences()
        clearVirtualMembers(id); virtualManagers[id] = nil
        resyncStatuses()
    }
}
