// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only

import Foundation
@preconcurrency import NetworkExtension

extension VPNController {
    func routingInspection(memberID: String, request: RoutingInspectionRequest) async -> RoutingInspectionPage? {
        guard request.isValid, let manager = virtualManager(for: memberID),
              let data = try? JSONEncoder().encode(request), let text = String(data: data, encoding: .utf8),
              let reply = await sendMessageData("router:inspect:" + text, to: memberID, timeout: 3),
              !Task.isCancelled, virtualManager(for: memberID) === manager, reply.count <= 1_048_576,
              let page = try? JSONDecoder().decode(RoutingInspectionPage.self, from: reply), page.table == request.table
        else { return nil }
        return page
    }

    func routingSourceName(memberID: String, sourceID: String) -> String? {
        guard let session = virtualMembers[memberID] else { return nil }
        return virtualSourceNames[session]?[sourceID]
    }

    var virtualDefaultCaptureBlocked: Bool {
        pushedNetworkState.contains { routeVirtualProfileIDs.contains($0.key) && $0.value.defaultCaptureBlocked == true }
    }
    func isApplicationRouted(_ id: String) -> Bool {
        preparingAppRouteMembers.contains(id) || virtualMembers[id].flatMap { virtualManagers[$0] }?.routingMethod == .sourceApplication
    }

    var routeVirtualProfileIDs: Set<String> {
        Set(virtualMembers.keys.filter { virtualManager(for: $0) != nil && !isApplicationRouted($0) })
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
            guard let recipient = ids.min() else { continue }
            let request = VirtualRouteApplyRequest(owner: plan.owner.flatMap { ids.contains($0) ? $0 : nil } ?? "",
                retainUnavailableDefault: plan.owner == nil && !plan.userChoseDirect,
                routes: plan.routeRequests.filter { ids.contains($0.key) },
                dnsFilters: Dictionary(uniqueKeysWithValues: ids.compactMap { id in
                    let filter = customRouting(for: id).dns.nativeSettings
                    return filter.isIdentity ? nil : (id, filter)
                }))
            guard let data = try? JSONEncoder().encode(request), let text = String(data: data, encoding: .utf8),
                  await sendMessage("router:apply-plan:\(text)", to: recipient) == "ok" else { return false }
        }
        return true
    }

    /// Includes saved native profile identities before they have created a packet-provider mirror.
    var compositionProfiles: [Profile] {
        let native = (nativeConfigStore?.configs ?? []).compactMap { config -> Profile? in
            guard !profiles.contains(where: { $0.id == config.id }) else { return nil }
            let status = virtualMemberStatus(for: config.id)
                ?? (nativeConfigStore?.activeConfigID == config.id ? nativeConfigStore?.status : nil) ?? .disconnected
            return Profile(id: config.id, name: config.name, server: config.server, status: status, kind: config.kind)
        }
        let known = Set(profiles.map(\.id) + native.map(\.id))
        let ssl = (subprocessSessionStore?.configurationStore?.tunnels ?? []).compactMap { config -> Profile? in
            guard config.kind.isSSLVPN || (config.kind == .ssh && config.sshMode == .netTunnel), !known.contains(config.id) else { return nil }
            let status: NEVPNStatus
            switch subprocessSessionStore?.status(config.id) {
            case .connected: status = .connected
            case .connecting: status = .connecting
            default: status = .disconnected
            }
            return Profile(id: config.id, name: config.name, server: config.server, status: status, kind: config.kind)
        }
        return profiles + native + ssl
    }

    func virtualMemberStatus(for id: String) -> NEVPNStatus? {
        guard let manager = virtualManager(for: id) else { return nil }
        return virtualStoppedMembers.contains(id) ? .disconnected : manager.connection.status
    }

    func virtualCompositionProblem(_ composition: VPNComposition) -> String? {
        if let problem = composition.validationProblem { return problem }
        if composition.applicationRoutes != nil {
            if let problem = composition.applicationRouteProblem(temporary: temporaryProcessRoutes[composition.id] ?? []) { return problem }
            if !(1...16).contains(composition.members.count) { return "Choose between one and sixteen VPNs." }
            if ManagedPolicy.forceKeepInsideVPN { return "Your organization requires a whole-Mac VPN." }
        } else {
            if !(1...16).contains(composition.members.count) { return "Choose between one and sixteen VPNs." }
            if composition.fullTunnelConflict { return "Choose one full tunnel." }
        }
        if composition.members.contains(where: { $0.dependsOn != nil }) { return "Chained VPNs are unavailable through this virtual interface." }
        if !ManagedPolicy.disableDivertRules {
            let memberIDs = Set(composition.members.map(\.profileID))
            for profile in profiles {
                let hasDivert = routingRules(for: profile.id).contains { rule in
                    guard rule.enabled, rule.isValidDivert else { return false }
                    switch rule.action {
                    case .outside: return !ManagedPolicy.forceKeepInsideVPN && memberIDs.contains(profile.id)
                    case .overVPN(let target): return memberIDs.contains(profile.id) || memberIDs.contains(target)
                    }
                }
                if hasDivert { return "Saved destination diverts require independent connections. Use the routed connection’s rules for these destinations." }
            }
        }
        for member in composition.members {
            guard let profile = compositionProfiles.first(where: { $0.id == member.profileID }) else { return "A composition member is unavailable." }
            if let reason = virtualMemberProblem(for: profile) { return reason }
        }
        if isCompositionActive(composition) { return "Disconnect the composition first." }
        return nil
    }

    func virtualMemberProblem(for profile: Profile) -> String? {
        switch profile.kind {
        case .wireGuard: nil
        case .proxyTunnel: proxyTunnelConfig(for: profile.id).virtualMemberProblem
        case let kind where kind.supportsSharedOpenConnect:
            if let cfg = subprocessSessionStore?.configurationStore?.tunnels.first(where: { $0.id == profile.id }) {
                SubprocessTunnelManager.virtualOpenConnectProblem(cfg)
            } else { "Open the original SSL VPN profile to authenticate its shared connection." }
        case .ssh:
            if let cfg = subprocessSessionStore?.configurationStore?.tunnels.first(where: { $0.id == profile.id }) { cfg.sshTunProblem }
            else { "Open the original point-to-point SSH profile to share this connection." }
        case .openVPN: virtualOpenVPNProblem(profile.id)
        case .sshNetworkTunnel: sshNetworkTunnelConfig(for: profile.id).virtualMemberProblem
        case .tailscale: tailscaleConfig(for: profile.id).virtualMemberProblem
        case .ikev2, .ipsec, .l2tp:
            if let config = nativeConfigStore?.configs.first(where: { $0.id == profile.id }),
               let owned = config.ownedIPsec, WireGuardConfig.isIPLiteral(owned.server) {
                nil
            } else { "A shared IPsec member requires a built-in-compatible profile with a numeric gateway." }
        default: "This VPN does not have a shared-interface transport. Connect it independently."
        }
    }

    private func virtualOpenVPNProblem(_ id: String) -> String? {
        guard let evaluation = profileEvaluation(for: id), !evaluation.error,
              !evaluation.externalPki, !evaluation.usesPKCS11 else {
            return "A shared OpenVPN member needs a valid profile with a built-in sign-in method."
        }
        let overrides = overrides(for: id)
        if overrides.allowLocalLanAccess == true || overrides.proxyHost != nil {
            return "Local network access and OpenVPN carrier proxies require an independent connection."
        }
        return nil
    }

    private func virtualOpenVPNOptions(_ id: String) async throws -> [String: Data] {
        if let problem = virtualOpenVPNProblem(id) { throw err(problem) }
        let raw: RawCredentials
        if isAutologin(id) {
            raw = RawCredentials()
        } else {
            guard case .value(let credentials) = try await authPlan(for: id, typedOTP: transientCredentials(for: id).otp) else {
                throw err("Supply the sign-in for this OpenVPN profile before connecting the composition.")
            }
            if requiresOTP(for: id), credentials.otp?.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty != false {
                throw err("Enter the OpenVPN profile’s current verification code before connecting the composition.")
            }
            raw = credentials
        }
        let gate = openVPNConfigurationGate(for: id)
        await gate.acquire()
        defer { gate.release() }
        if let problem = virtualOpenVPNProblem(id) { throw err(problem) }
        guard let stored = storedOVPNText(id: id), !stored.isEmpty,
              !locallyRemovedProfileIDs.contains(id) else { throw err("The OpenVPN profile is unavailable.") }
        let (inline, secrets) = try await Task.detached {
            (try KeychainCredentialStore.ovpnInlineSecretsForExport(profile: id),
             try KeychainCredentialStore.profileSecretsForExport(profile: id))
        }.value
        guard OVPNSecretMaterial.markedTags(in: stored).isSubset(of: inline.keys) else { throw OpenVPNConfigurationEdit.Failure.missing }
        let source = OVPNSecretMaterial.merge(stored, secrets: inline)
        var effective = overrides(for: id)
        if ManagedPolicy.forceKeepInsideVPN { effective.allowLocalLanAccess = false; effective.allowUnusedAddrFamilies = .block }
        let signIn = try openVPNSignIn(id: id, raw: raw, request: effectiveAuthConfig(for: id).request)
        var options = [VirtualRoutingStartConfig.openVPNProfileOption: Data(source.utf8), "overrides": try JSONEncoder().encode(effective)]
        options["username"] = Data(signIn.credentials.username.utf8)
        options["password"] = Data(signIn.credentials.password.utf8)
        if let response = signIn.response { options["challengeResponse"] = Data(response.utf8) }
        let typedPassphrase = raw.privateKeyPassphrase.flatMap { $0.isEmpty ? nil : $0 }
        if let password = typedPassphrase ?? secrets?.privateKeyPassword { options["privateKeyPassword"] = Data(password.utf8) }
        if profileEvaluation(for: id)?.privateKeyPasswordRequired == true && (options["privateKeyPassword"]?.isEmpty ?? true) {
            throw err("Save the private key passphrase before connecting this OpenVPN member.")
        }
        return options
    }

    /// Authenticate the selected saved identity before installing the composition's routes.
    /// The helper uses the same server trust, realm, path and sign-in settings as the profile.
    private func virtualOpenConnectOptions(_ config: SubprocessTunnelConfig) async throws -> [String: Data] {
        if let reason = SubprocessTunnelManager.virtualOpenConnectProblem(config) { throw err(reason) }
        let mode = SubprocessTunnelManager.openconnectAuthMode(config)
        var auth = SubprocessTunnelManager.authStart(for: config)
        if mode != "certificate" {
            auth.params.certFile = nil; auth.params.keyFile = nil; auth.params.keyPassword = nil
        }
        let password = mode != "certificate"
            ? try await Task.detached { try KeychainCredentialStore.credentialsForExport(profile: "tunnel." + config.id)?.password }.value : nil
        let browser = BrowserDefaults.resolve(config.browser)
        let handlers = OpenConnectAuthClient.Handlers(answerForm: { form in
            let answers = OCAuthFormAutofill.fill(form, username: config.username, password: password,
                                                  realm: config.realm, vpnProtocol: config.kind.openconnectProtocol)
            return answers.unanswered.isEmpty ? .answers(answers.answers) : .cancel(unanswered: answers.unanswered.map(\.label))
        }, openURL: { raw in
            guard mode == "sso", let url = URL(string: raw), ["http", "https"].contains(url.scheme?.lowercased() ?? "") else {
                throw ProfilePacketPolicy.failure("Choose browser sign-in for this SSL VPN and try again.")
            }
            await MainActor.run { BrowserCatalog.open(url, using: browser) }
        })
        let done = try await OpenConnectAuthClient.authenticate(start: auth, handlers: handlers, killAfter: mode == "sso" ? 180 : 90)
        guard !done.cookie.isEmpty, !done.servercert.isEmpty, let url = URLComponents(string: done.connectURL),
              url.scheme?.lowercased() == "https", let host = url.host, url.user == nil, url.password == nil else {
            throw err("The authenticated SSL VPN did not supply a secure gateway and session certificate.")
        }
        var session: [String: Any] = ["cookie": done.cookie, "servercert": done.servercert, "connectURL": done.connectURL]
        if let resolve = done.resolve, resolve.host.caseInsensitiveCompare(host) == .orderedSame, WireGuardConfig.isIPLiteral(resolve.ip) {
            session["resolveHost"] = resolve.host; session["resolveIP"] = resolve.ip
        } else if !WireGuardConfig.isIPLiteral(host.trimmingCharacters(in: CharacterSet(charactersIn: "[]"))) {
            throw err("The SSL VPN sign-in did not identify its gateway’s numeric carrier address.")
        }
        let settings = SubprocessTunnelManager.inProcessConfiguration(config)
        return ["configuration": try PropertyListSerialization.data(fromPropertyList: settings, format: .binary, options: 0),
                "startOptions": try PropertyListSerialization.data(fromPropertyList: session, format: .binary, options: 0)]
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
        // Freeze the draft at the start of this transaction. Only the start
        // options carry live process tokens across the provider boundary.
        let processes = composition.applicationRoutes == nil ? [] : temporaryProcessRoutes[composition.id] ?? []
        var applicationCapture = composition.applicationRoutes.map {
            VPNApplicationCapture(routes: processes.map(\.route) + $0, processRouteIDs: Set(processes.map { $0.route.id }))
        }
        var tokens: [String: Data] = [:]
        for instance in processes { tokens[instance.route.id] = instance.auditToken }
        if let applicationCapture,
           !applicationCapture.isValid(memberIDs: ids) || !applicationCapture.accepts(processTokens: tokens) {
            throw err("Select the apps and running processes again before connecting.")
        }
        guard let attempt = connectionReservations.reserve(owner: "virtual." + composition.id, members: ids) else {
            throw err("A member of this composition is already preparing a connection.")
        }
        if applicationCapture != nil { preparingAppRouteMembers.formUnion(ids) }
        defer {
            if applicationCapture != nil { preparingAppRouteMembers.subtract(ids) }
            for id in ids { discardVirtualTailscaleSetup(for: id) }
            connectionReservations.finish(attempt)
            resyncStatuses()
        }
        // Validate the initial state before publishing a pending connection.
        guard composition.members.allSatisfy({ member in
            compositionProfiles.first { $0.id == member.profileID }.map { !UI.isActive($0.status) } == true
        }) else { throw err("Disconnect the composition's VPNs before connecting them through one virtual interface.") }
        resyncStatuses()
        await wireGuardConfigurationOperations.acquire()
        defer { wireGuardConfigurationOperations.release() }
        guard connectionReservations.isCurrent(attempt), !Task.isCancelled else { throw CancellationError() }
        for selection in processes {
            guard let generation = SourceProcessInstance.processGeneration(auditToken: selection.auditToken),
                  let current = try? await SourceIdentityService.runningProcess(pid: Int32(generation >> 32)),
                  current.matches(auditToken: selection.auditToken),
                  current.signingIdentity.signingIdentifier == selection.route.signingIdentifier,
                  current.signingIdentity.designatedRequirement == selection.route.designatedRequirement else {
                throw err("\(selection.route.name) has exited, changed, or is no longer accessible. Choose the process again.")
            }
            guard connectionReservations.isCurrent(attempt), !Task.isCancelled else { throw CancellationError() }
        }
        if let capture = applicationCapture, capture.requiresLauncherRules {
            applicationCapture = try await capture.preparingLauncherRules { try await SourceIdentityService.signedApplication(at: $0) }
            guard connectionReservations.isCurrent(attempt), !Task.isCancelled else { throw CancellationError() }
        }
        if let ensureExtensionReady, !(await ensureExtensionReady()) {
            throw err("Allow SimpleVPN's network extension before connecting this composition.")
        }
        try await SystemExtensionManager.requireCurrentProvider()
        guard connectionReservations.isCurrent(attempt), !Task.isCancelled else { throw CancellationError() }
        var members: [VirtualRoutingConfig.Member] = []
        var startMembers: [VirtualRoutingStartConfig.Member] = []
        var childOptions = [String: [String: Data]]()
        var agentSockets = [String: String]()
        var sslSnapshots = [String: SubprocessTunnelConfig]()
        var owner = ""
        for member in composition.members {
            let id = member.profileID
            if let why = controlDenied(.connect(profile: id)) { throw err(why) }
            guard let profile = compositionProfiles.first(where: { $0.id == id }),
                  !UI.isActive(managers[id]?.connection.status ?? .disconnected),
                  virtualManager(for: id) == nil else { throw err("Disconnect the composition's VPNs before connecting them through one virtual interface.") }
            var saved: VirtualRoutingConfig.Member
            var start: VirtualRoutingStartConfig.Member
            if let native = nativeConfigStore?.configs.first(where: { $0.id == id }) {
                guard let cfg = native.ownedIPsec, let adapter = cfg.adapterID,
                      let store = nativeConfigStore, (store.activeConfigID != id || !UI.isActive(store.status)) else { throw err("Disconnect this built-in IPsec profile before using it as a shared port.") }
                try await store.prepareVirtualMember(native)
                guard connectionReservations.isCurrent(attempt), !Task.isCancelled else { throw CancellationError() }
                let secrets = NativeVPNReadiness.storedSecrets(for: native)
                let primary = native.kind == .ipsec ? secrets.groupPSK : secrets.base
                guard !primary.isEmpty, !cfg.usesXAuth || !secrets.base.isEmpty,
                      cfg.usesL2TP != true || OwnedIPsecConfiguration.validPPPCredential(secrets.pppPassword) else { throw err("Save the required IPsec and PPP credentials before connecting.") }
                let key = cfg.usesEAP == true ? OwnedIPsecConfiguration.eapPasswordOption : OwnedIPsecConfiguration.pskOption
                var credentials = [key: Data(primary.utf8)]
                if cfg.usesXAuth { credentials[OwnedIPsecConfiguration.xauthPasswordOption] = Data(secrets.base.utf8) }
                if cfg.usesL2TP == true { credentials[OwnedIPsecConfiguration.pppPasswordOption] = Data(secrets.pppPassword.utf8) }
                childOptions[id] = credentials
                saved = .init(id: id, ownedIPsec: cfg, prefixes: [])
                start = .init(id: id, addresses: [], external: .init(adapter: adapter, generation: 1))
            } else if profile.kind == .ssh {
                guard let cfg = subprocessSessionStore?.configurationStore?.tunnels.first(where: { $0.id == id }),
                      let tun = cfg.sshTunConfiguration, subprocessSessionStore?.isActive(id) == false else {
                    throw err("Disconnect the SSH point-to-point VPN and check its address and destination settings.")
                }
                childOptions[id] = try await OpenConnectProfileStore.sshTunCredentials(cfg, password: nil)
                saved = .init(id: id, sshTun: tun, prefixes: [])
                start = .init(id: id, addresses: [], external: .init(adapter: "ssh-tun", generation: 1))
                sslSnapshots[id] = cfg
            } else if profile.kind.isSSLVPN {
                guard let cfg = subprocessSessionStore?.configurationStore?.tunnels.first(where: { $0.id == id && $0.kind == profile.kind }),
                      subprocessSessionStore?.isActive(id) == false else {
                    throw err("Disconnect this SSL VPN and use its negotiated routes before sharing its interface.")
                }
                childOptions[id] = try await virtualOpenConnectOptions(cfg)
                saved = .init(id: id, openConnect: cfg.kind, prefixes: [])
                start = .init(id: id, addresses: [], external: .init(adapter: "openconnect-packet", generation: 1))
                sslSnapshots[id] = cfg
            } else if profile.kind == .openVPN {
                childOptions[id] = try await virtualOpenVPNOptions(id)
                saved = .init(id: id, openVPN: true, prefixes: [])
                start = .init(id: id, addresses: [], external: .init(adapter: "openvpn3", generation: 1))
            } else if profile.kind == .sshNetworkTunnel {
                var cfg = sshNetworkTunnelConfig(for: id)
                if let issue = cfg.virtualMemberProblem { throw err(issue) }
                let secrets = sshNetworkTunnelSecrets(for: id)
                var options = [String: Data]()
                if cfg.authMethod != .agent, !secrets.password.isEmpty { options["password"] = Data(secrets.password.utf8) }
                if cfg.needsPrivateKey { options["key"] = Data(secrets.privateKeyPEM.utf8) }
                if cfg.needsCertificate { options["certificate"] = Data(secrets.certificatePEM.utf8) }
                _ = try cfg.sharedCredentials(options: options)
                if cfg.authMethod == .agent {
                    let path = cfg.agentSocketPath
                    let state = await Task.detached { SSHAgentProbe().probe(configuredSocketPath: path) }.value
                    guard state.canSignIn, let socket = state.socketPath else { throw err(state.summary) }
                    agentSockets[id] = socket
                }
                cfg.agentSocketPath = ""
                childOptions[id] = options
                saved = .init(id: id, sshNetwork: cfg, prefixes: [])
                start = .init(id: id, addresses: [], external: .init(adapter: "sshnet", generation: 1))
            } else if profile.kind == .tailscale {
                let cfg = tailscaleConfig(for: id)
                if let issue = cfg.virtualMemberProblem { throw err(issue) }
                childOptions[id] = try await virtualTailscaleOptions(for: id, config: cfg)
                saved = .init(id: id, tailscale: cfg, prefixes: [])
                start = .init(id: id, addresses: [], external: .init(adapter: "tailscale-node", generation: 1))
            } else if profile.kind == .proxyTunnel {
                let config = proxyTunnelConfig(for: id)
                if let issue = config.virtualMemberProblem { throw err(issue) }
                saved = .init(id: id, proxy: config, prefixes: [])
                let credentials = config.requiresAuth ? proxyTunnelCredentials(for: id) : (username: "", password: "")
                if let issue = ProxyTunnelStartConfig.authenticationProblem(config: config, username: credentials.username, password: credentials.password) {
                    throw err("\(profile.name): \(issue)")
                }
                start = .init(id: id, addresses: saved.addresses,
                              proxy: .init(config: config, username: credentials.username, password: credentials.password), allowed: saved.allowed)
            } else {
                guard profile.kind == .wireGuard else { throw err("This VPN cannot share the capture interface.") }
                let config = wireGuardConfig(for: id)
                guard !config.allowLocalNetworkAccess else { throw err("Local network exclusions need an independent connection.") }
                saved = .init(id: id, wireGuard: config.redactedForStorage(), prefixes: [])
                start = .init(id: id, addresses: config.addresses, wireGuard: try wireGuardStartConfig(for: id, config: config))
            }
            let custom = customRouting(for: id)
            guard custom.proxy.isIdentity else { throw err("Custom proxy settings need an independent connection.") }
            if !custom.routes.isIdentity { saved.routeFilter = custom.routes }
            let dnsFilter = custom.dns.nativeSettings
            if !dnsFilter.isIdentity { saved.dnsFilter = dnsFilter }
            let source: String?
            if saved.ownedIPsec != nil {
                source = nativeConfigStore?.configs.first { $0.id == id }?.routingEventSource
            } else if let ssl = sslSnapshots[id] { source = ssl.routingEventSource }
            else {
                let settings = (managers[id]?.protocolConfiguration as? NETunnelProviderProtocol)?.providerConfiguration ?? [:]
                source = try StandalonePacketPolicyConfiguration.source(in: settings)
            }
            if let source {
                try await ProfilePacketPolicy.validate(source, adapter: saved.transportAdapter)
                saved.eventSource = source; saved.adapter = saved.transportAdapter; saved.vpnKind = saved.transportKind?.rawValue
                start.eventSource = source; start.adapter = saved.adapter; start.vpnKind = saved.vpnKind
            }
            let configuredRoutes = saved.sshTun?.network.routes ?? saved.allowed
            let full = !RoutePrefixMath.defaultRoutePrefixes(in: configuredRoutes).isEmpty || saved.openVPN == true || saved.openConnect != nil || saved.ownedIPsec != nil || saved.sshNetwork?.includeDefaultRoute == true || saved.tailscale?.useExitNode == true
            let intent = custom.routes.apply(to: .init(engine: id,
                advertisedPrefixes: RoutePrefixMath.specificRoutes(in: saved.allowed),
                wantsDefault: full, canOwnDefault: full))
            if applicationCapture != nil, !custom.routes.isIdentity {
                throw err("\(profile.name) has custom destination rules. App routing uses the member’s permitted destinations.")
            }
            if applicationCapture == nil, member.role == .full {
                guard intent.canOwnDefault else { throw err("\(profile.name) cannot carry the full tunnel role with these custom routes.") }
                owner = id
            }
            if saved.externalAdapter == nil { saved.prefixes = intent.advertisedPrefixes }
            members.append(saved)
            startMembers.append(start)
        }
        if ManagedPolicy.forceKeepInsideVPN, owner.isEmpty { throw err("Your organization requires a full tunnel for this connection.") }
        var policy = VirtualRoutingPolicy(defaultOwner: owner)
        policy.rules = members.flatMap { member in member.prefixes.map { .init(prefix: $0, port: member.id) } }
        if let applicationCapture {
            policy = VirtualRoutingPolicy(sourceRules: applicationCapture.sourceRules, captureDefault: true)
        }
        if let source = composition.eventSource {
            policy.version = 2
            policy.eventSource = source
        }
        let config = VirtualRoutingConfig(version: VirtualRoutingConfig.requiredVersion(capture: applicationCapture, eventSource: composition.eventSource, usesProxyPorts: members.contains { $0.proxy != nil }, usesChildPorts: !childOptions.isEmpty, usesMemberRules: members.contains { $0.eventSource != nil }, singleDestination: members.count == 1 && applicationCapture == nil, usesFilters: members.contains { $0.routeFilter != nil || $0.dnsFilter != nil }), id: composition.id, members: members,
                                          policy: policy, applicationCapture: applicationCapture)
        if let problem = config.problem { throw err(problem) }
        var previous = virtualManagers[composition.id]
        if let old = previous {
            guard !UI.isActive(old.connection.status) else { throw err("This virtual connection is already active.") }
            // NE fixes the routing method at creation. This preferences entry
            // is generated from the composition each time it connects.
            if (old.routingMethod == .sourceApplication) != (applicationCapture != nil) {
                try await old.removeFromPreferences()
                virtualManagers[composition.id] = nil
                previous = nil
            }
        }
        guard connectionReservations.isCurrent(attempt), !Task.isCancelled else { throw CancellationError() }
        let manager = previous ?? (applicationCapture == nil ? NETunnelProviderManager() : .forPerAppVPN())
        if let applicationCapture {
            let rules = applicationCapture.makeAppRules()
            guard !rules.isEmpty else { throw err("The signed app capture rules could not be prepared.") }
            manager.appRules = rules
            manager.isOnDemandEnabled = false
        }
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
        rememberSourceNames(in: config)
        guard connectionReservations.isCurrent(attempt), !Task.isCancelled else { throw CancellationError() }
        try await manager.loadFromPreferences()
        guard connectionReservations.isCurrent(attempt), !Task.isCancelled,
              members.allSatisfy({ member in
                  if let snapshot = sslSnapshots[member.id] {
                      return subprocessSessionStore?.configurationStore?.tunnels.first(where: { $0.id == member.id }) == snapshot
                          && subprocessSessionStore?.isActive(member.id) == false
                  }
                  return !locallyRemovedProfileIDs.contains(member.id) && (member.ownedIPsec.map { owned in
                      nativeConfigStore?.configs.first { $0.id == member.id }?.ownedIPsec == owned
                  } ?? (managers[member.id] != nil))
              }) else { throw CancellationError() }
        guard let session = manager.connection as? NETunnelProviderSession else { throw err("The virtual connection is not ready.") }
        let start = VirtualRoutingStartConfig(childOptions: childOptions.isEmpty ? nil : childOptions, version: config.wireVersion, members: startMembers, policy: policy,
                                              processTokens: applicationCapture == nil ? nil : tokens)
        let payload = try JSONEncoder().encode(start) as NSData
        if let applicationCapture {
            guard manager.routingMethod == .sourceApplication, applicationCapture.matchesInstalledRules(manager.appRules) else {
                throw err("macOS did not install the selected app rules. The connection could not start.")
            }
            try session.startTunnel(options: ["routingStart": payload])
        } else {
            try routes.startWithGateway(for: owner, members: ids, wantsDefault: !owner.isEmpty) { owned in
                try session.startTunnel(options: ["routingStart": payload, "gatewayOwned": owned as NSNumber])
            }
        }
        virtualManagers[composition.id] = manager
        rememberSourceNames(in: config)
        virtualStarts[composition.id] = Date()
        virtualObservedActive.remove(composition.id)
        for member in members {
            virtualMembers[member.id] = composition.id
            virtualStoppedMembers.remove(member.id)
            if member.openVPN == true { transientCreds[member.id]?.otp = "" }
            if member.tailscale != nil { beginVirtualTailscaleStateSync(for: member.id) }
            if let socket = agentSockets[member.id] { watchSSHAgentSigning(member.id, session: session, socket: socket, virtual: true) }
            compositionRouteRoles[member.id] = member.id == owner ? .full : .split
        }
        resyncStatuses()
        if applicationCapture == nil { await setDefaultGateway(to: owner.isEmpty ? nil : owner) }
    }

    func virtualManager(for id: String) -> NETunnelProviderManager? {
        guard let sessionID = virtualMembers[id], let manager = virtualManagers[sessionID],
              (manager.connection.status != .disconnected && manager.connection.status != .invalid)
                || virtualStarts[sessionID].map({ Date().timeIntervalSince($0) <= 12 }) == true else { return nil }
        return manager
    }

    private func rememberSourceNames(in config: VirtualRoutingConfig) {
        virtualSourceNames[config.id] = config.applicationCapture.map {
            Dictionary($0.routes.map { ($0.id, $0.name) }, uniquingKeysWith: { first, _ in first })
        }
    }

    func rememberVirtualManager(_ manager: NETunnelProviderManager, config: VirtualRoutingConfig) {
        virtualManagers[config.id] = manager
        guard UI.isActive(manager.connection.status) || virtualStarts[config.id] != nil else { return }
        rememberSourceNames(in: config)
        for member in config.members {
            virtualMembers[member.id] = config.id
            if member.tailscale != nil { beginVirtualTailscaleStateSync(for: member.id) }
            if member.sshNetwork?.authMethod == .agent, sshNetworkAgentBrokers[member.id] == nil {
                Task { await restoreSSHAgentSigning(member.id) }
            }
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
        virtualSourceNames[sessionID] = nil
        let members = virtualMembers.filter { $0.value == sessionID }.map(\.key)
        for id in members {
            discardVirtualTailscaleSetup(for: id)
            sshNetworkAgentBrokers.removeValue(forKey: id)?.cancel()
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
        temporaryProcessRoutes[id] = nil
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
