// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only

//
//  PacketTunnelProvider.swift
//  SimpleVPN system extension — drives the OpenVPN 3 engine via OpenVPN3Bridge.
//

import NetworkExtension
import os

final class PacketTunnelProvider: NEPacketTunnelProvider, OpenVPN3BridgeDelegate, OpenConnectBridgeDelegate, TailscaleEngineDelegate, ProxyTunnelEngineDelegate, @unchecked Sendable {

    private static let log = Logger(subsystem: "com.bragi0.SimpleVPN.PacketTunnel", category: "tunnel")

    // Accessed from the NE thread and the bridge's callback queue; guarded by `lock`.
    nonisolated(unsafe) private var bridge: OpenVPN3Bridge?
    nonisolated(unsafe) private var ocBridge: OpenConnectBridge?      // OpenConnect SSL-VPN engine
    nonisolated(unsafe) private var tsEngine: TailscaleEngine?        // Tailscale / Headscale engine
    nonisolated(unsafe) private var pxEngine: ProxyTunnelEngine?      // tun2socks proxy-tunnel engine
    nonisolated(unsafe) private var pxProxyHost = ""                  // for stats/topology (no secret)
    nonisolated(unsafe) private var pxConfig: ProxyTunnelConfig?      // kept for live default-gateway re-apply
    nonisolated(unsafe) private var pxSuppressDefault = false         // gateway demotion state for the proxy tunnel
    nonisolated(unsafe) private var pxProxySettings: NEProxySettings? // app-arbitrated system proxy for the proxy tunnel (Proxy mediator applier)
    nonisolated(unsafe) private var startCompletion: ((Error?) -> Void)?
    private let lock = NSLock()

    nonisolated(unsafe) private var profileID = "default"
    nonisolated(unsafe) private var connectedSince: Double = 0
    nonisolated(unsafe) private var reconnects = 0
    private let statsQueue = DispatchQueue(label: "com.bragi0.SimpleVPN.stats")

    override func startTunnel(options: [String: NSObject]?,
                              completionHandler: @escaping (Error?) -> Void) {
        let info = Bundle.main.infoDictionary
        let ver = "\(info?["CFBundleShortVersionString"] as? String ?? "?") (build \(info?["CFBundleVersion"] as? String ?? "?"))"
        Self.log.log("startTunnel — PacketTunnel v\(ver, privacy: .public)")

        let proto = protocolConfiguration as? NETunnelProviderProtocol
        let conf = proto?.providerConfiguration

        let profile = (conf?["profile"] as? String) ?? "default"
        lock.lock(); profileID = profile; lock.unlock()

        // Engine dispatch FIRST, config validation per-engine after. The "ovpn"
        // key only exists for the OpenVPN kind — checking for it before the
        // dispatch rejected every non-OpenVPN in-process kind with "missing ovpn
        // configuration" before its engine was ever reached.
        let kind = (conf?["vpnType"] as? String).flatMap(VPNKind.init(rawValue:)) ?? .openVPN

        // WireGuard has no engine linked into this build yet (the UI is honest
        // about that and offers Export instead of Connect) — fail clearly here
        // rather than falling through to the OpenVPN branch below, which would
        // report the unrelated "missing ovpn configuration".
        if kind == .wireGuard {
            completionHandler(NSError(domain: "PacketTunnel", code: 3,
                userInfo: [NSLocalizedDescriptionKey: "WireGuard isn't supported in this build yet."]))
            return
        }

        // The OpenConnect SSL-VPN kinds (anyconnect / nc / gp / pulse / f5 /
        // fortinet / array) run in-process via libopenconnect. VPNKind is the
        // single source of truth for the protocol token.
        if let ocProto = kind.openconnectProtocol {
            startOpenConnect(conf: conf, options: options, profile: profile,
                             protocol: ocProto, completionHandler: completionHandler)
            return
        }

        // Tailscale / Headscale: one kind, in-process via the Go engine.
        if kind == .tailscale {
            startTailscale(conf: conf, options: options, profile: profile,
                           completionHandler: completionHandler)
            return
        }

        // Proxy Tunnel: one kind, in-process via the Go tun2socks engine.
        if kind == .proxyTunnel {
            startProxyTunnel(conf: conf, options: options, profile: profile,
                             completionHandler: completionHandler)
            return
        }

        // Config comes via providerConfiguration; credentials come via the shared keychain
        // (a read-once session secret the app wrote just before starting the tunnel).
        guard let ovpn = conf?["ovpn"] as? String, !ovpn.isEmpty else {
            completionHandler(NSError(domain: "PacketTunnel", code: 1,
                userInfo: [NSLocalizedDescriptionKey: "missing ovpn configuration"]))
            return
        }

        // Per-VPN engine overrides. A missing or corrupt blob degrades to "no
        // overrides" — a settings problem must never break connecting.
        var overrides = OpenVPNOverrides.decode(from: conf?["overrides"] as? Data)

        // Org policy travels with the session (startTunnel options), so the
        // extension enforces it independently of whatever the persisted config
        // says — a stale profile saved before the policy was pushed can't leak.
        let policyKeepInside = (options?["policyKeepInside"] as? NSNumber)?.boolValue ?? false
        let policyNoDiverts  = (options?["policyNoDiverts"]  as? NSNumber)?.boolValue ?? false
        if policyKeepInside { overrides.allowUnusedAddrFamilies = .block }
        Self.log.log("overrides: \(overrides.logDescription, privacy: .public) policyKeepInside=\(policyKeepInside) policyNoDiverts=\(policyNoDiverts)")

        // Session credentials arrive in-memory via startTunnel options — this
        // extension runs as root in the SYSTEM context and cannot see the user's
        // keychain, so a keychain handoff can never work from here. (Keychain
        // fallback kept for an older app briefly driving a newer extension.)
        let username: String
        let password: String
        var proxyPassword = options?["proxyPassword"] as? String
        var privateKeyPassword = options?["privateKeyPassword"] as? String
        if let u = options?["username"] as? String, let p = options?["password"] as? String {
            username = u
            password = p
        } else if let creds = KeychainCredentialStore.takeSession(profile: profile) {
            username = creds.username
            password = creds.password
            proxyPassword = proxyPassword ?? creds.proxyPassword
            privateKeyPassword = privateKeyPassword ?? creds.privateKeyPassword
        } else {
            Self.log.error("startTunnel: no credentials in options for \(profile, privacy: .public)")
            completionHandler(NSError(domain: "PacketTunnel", code: 2,
                userInfo: [NSLocalizedDescriptionKey: "no credentials available"]))
            return
        }
        var settings = overrides.bridgeSettings(proxyPassword: proxyPassword,
                                                privateKeyPassword: privateKeyPassword)
        // static-challenge profiles: the one-time code arrives as its own
        // option and reaches the engine as ProvideCreds.response — never
        // concatenated into the password (that stays the non-challenge path).
        if let response = options?["challengeResponse"] as? String, !response.isEmpty {
            let s = settings ?? OVPNClientSettings()
            s.challengeResponse = response
            settings = s
        }

        let b = OpenVPN3Bridge(provider: self, delegate: self)
        lock.lock(); bridge = b; startCompletion = completionHandler; lock.unlock()

        // Default-gateway ownership travels with the session so the ≤1-owner
        // invariant holds at the very first establish, before (or without) the app
        // reconciling live (RC3). Absent ⇒ leave the engine's natural role (a
        // server-pushed default stays owned) — an older app driving this extension.
        if let owned = options?["gatewayOwned"] as? NSNumber {
            b.setInitialDefaultRouteOwned(owned.boolValue)
            Self.log.log("gateway ownership at establish: owned=\(owned.boolValue)")
        }

        // Divert rules. Only *.outside* destinations leave this tunnel (excluded
        // routes). The source side of *.overVPN* is deliberately NOT excluded here:
        // excluding it would push that traffic out the physical interface in
        // CLEARTEXT whenever the target VPN is down. Left in this tunnel it stays
        // encrypted (fail-closed); when the target VPN is up, its more-specific
        // included route wins and pulls the destination over the target instead.
        // routeDest also rejects malformed / default-route (prefix 0) destinations,
        // so a divert can never swallow the whole default route (full bypass).
        let rules = RoutingRuleStore.decode(from: conf?["routingRules"] as? Data)
        // Under ForceKeepInsideVPN or DisableDivertRules, no traffic may be sent
        // around the VPN — drop every .outside divert regardless of stored rules.
        let diverted: [[String: Any]] = (policyKeepInside || policyNoDiverts) ? [] : rules.compactMap { rule in
            guard rule.enabled, case .outside = rule.action, let d = rule.routeDest else { return nil }
            return d.dictionary
        }
        if !diverted.isEmpty {
            b.setDivertedDestinations(diverted)
            Self.log.log("divert: \(diverted.count) destination(s) routed around the VPN")
        }
        // Destinations other VPNs route *into* this one (the target side of
        // .overVPN, materialised by the app) → included routes. DisableDivertRules
        // forbids over-VPN diverts too (ForceKeepInside still permits them — the
        // traffic stays inside a VPN).
        let includes = policyNoDiverts ? [] : RouteDestStore.decode(from: conf?["routingIncludes"] as? Data)
        if !includes.isEmpty {
            b.setIncludedDestinations(includes.map(\.dictionary))
            Self.log.log("route-in: \(includes.count) destination(s) routed into this VPN")
        }

        do {
            try b.connect(withProfile: ovpn, username: username, password: password,
                          settings: settings)
            Self.log.log("openvpn3 connect() started")
        } catch {
            Self.log.error("connect failed: \(error.localizedDescription, privacy: .public)")
            finishStart(with: error)
        }
    }

    /// Bring up an OpenConnect SSL-VPN in-process. Credentials ride startTunnel
    /// options (root can't read the keychain), same as OpenVPN.
    private func startOpenConnect(conf: [String: Any]?, options: [String: NSObject]?,
                                  profile: String, protocol ocProto: String,
                                  completionHandler: @escaping (Error?) -> Void) {
        let s = OCClientSettings()
        s.server = (conf?["server"] as? String) ?? (protocolConfiguration.serverAddress ?? "")
        s.protocol = ocProto
        s.username = (options?["username"] as? String) ?? ""
        s.password = options?["password"] as? String
        s.realm = conf?["realm"] as? String
        s.serverCertSHA256 = conf?["serverCert"] as? String
        s.externalBrowser = conf?["samlBrowser"] as? String
        s.userAgent = "SimpleVPN"

        let b = OpenConnectBridge(provider: self, delegate: self)
        lock.lock(); ocBridge = b; startCompletion = completionHandler; lock.unlock()

        // Default-gateway ownership travels with the session so the ≤1-owner
        // invariant holds at the very first tun build, before (or without) the app
        // reconciling live (RC3). Absent ⇒ owner (the stock single-VPN behaviour).
        if let owned = options?["gatewayOwned"] as? NSNumber {
            b.setInitialDefaultRouteOwned(owned.boolValue)
            Self.log.log("gateway ownership at establish (openconnect): owned=\(owned.boolValue)")
        }

        do {
            try b.connect(with: s)
            Self.log.log("openconnect connect() started (\(ocProto, privacy: .public))")
        } catch {
            finishStart(with: error)
        }
    }

    /// Bring up a Tailscale / Headscale node in-process. The auth key (when
    /// there is one) rides startTunnel options in memory, same invariant as
    /// every other credential — it is never in providerConfiguration.
    private func startTailscale(conf: [String: Any]?, options: [String: NSObject]?,
                                profile: String, completionHandler: @escaping (Error?) -> Void) {
        let config = TailscaleConfig.decode(from: conf?["tailscale"] as? Data)
        // The engine validates too, but catching it here turns a start failure
        // into a settings message before any state is created on disk.
        if let problem = config.controlURLProblem {
            let error = TailscaleEngineError.engine(kind: "badRequest", message: problem)
            writeIncident(profile: profile, error: error)
            completionHandler(error)
            return
        }
        // "password" is the generic credential slot the connect flow fills; a
        // Tailscale auth key is optional, and its absence means browser sign-in.
        let authKey = (options?["tailscaleAuthKey"] as? String)
            ?? (options?["password"] as? String) ?? ""

        let engine = TailscaleEngine(provider: self, delegate: self)
        lock.lock(); tsEngine = engine; startCompletion = completionHandler; lock.unlock()

        let start = TailscaleStartConfig(config: config, authKey: authKey,
                                         stateDir: Self.tailscaleStateDir(profile: profile))
        engine.start(config: start) { [weak self] error in
            guard let self else { return }
            if let error {
                Self.log.error("tailscale start failed: \(error.localizedDescription, privacy: .public)")
                self.writeIncident(profile: profile, error: error)
            } else {
                lock.lock()
                if connectedSince == 0 { connectedSince = Date().timeIntervalSince1970 }
                lock.unlock()
                TunnelIncidentStore.clear(profile: profile)
            }
            self.finishStart(with: error)
        }
    }

    /// Bring up a proxy tunnel (tun2socks) in-process. The stack is composed
    /// synchronously (no control-plane handshake); on success we apply the
    /// utun's network settings from the saved config and start the packet pump.
    /// Credentials ride startTunnel options in memory, same invariant as every
    /// other kind — never in providerConfiguration.
    private func startProxyTunnel(conf: [String: Any]?, options: [String: NSObject]?,
                                  profile: String, completionHandler: @escaping (Error?) -> Void) {
        let config = ProxyTunnelConfig.decode(from: conf?["proxytunnel"] as? Data)
        // Catch a bad upstream here so it becomes a settings message before any
        // stack is composed.
        if let problem = config.upstreamProblem {
            let error = ProxyTunnelEngineError.engine(kind: "badRequest", message: problem)
            writeProxyIncident(profile: profile, error: error)
            completionHandler(error)
            return
        }
        // "password"/"username" are the generic credential slots the connect flow
        // fills; both are optional (a no-auth proxy needs neither).
        let username = (options?["username"] as? String) ?? ""
        let password = (options?["password"] as? String) ?? ""

        // Default-gateway ownership at establish (RC3): the app passes the desired
        // role so a non-owner proxy tunnel comes up already demoted to split.
        // Absent ⇒ owner (the stock single-VPN behaviour).
        let ownedAtEstablish = (options?["gatewayOwned"] as? NSNumber)?.boolValue ?? true

        let engine = ProxyTunnelEngine(provider: self, delegate: self)
        lock.lock(); pxEngine = engine; pxProxyHost = config.proxyHost
        pxConfig = config; pxSuppressDefault = !ownedAtEstablish
        startCompletion = completionHandler; lock.unlock()

        let start = ProxyTunnelStartConfig(config: config, username: username, password: password)
        if let error = engine.start(config: start) {
            Self.log.error("proxy tunnel start failed: \(error.localizedDescription, privacy: .public)")
            writeProxyIncident(profile: profile, error: error)
            finishStart(with: error)
            return
        }

        // Stack is up: apply the utun addresses/routes/DNS the config describes,
        // then start pumping packets (the flow has no addresses before this).
        // Honour the establish-time ownership so a non-owner proxy never installs
        // 0.0.0.0/0 in the first place (RC3).
        let px = lock.withLock { pxProxySettings }
        let settings = ProxyTunnelNetworkSettings.settings(for: config,
                                                           suppressDefaultRoute: !ownedAtEstablish,
                                                           proxySettings: px)
        setTunnelNetworkSettings(settings) { [weak self] error in
            guard let self else { return }
            if let error {
                Self.log.error("proxy tunnel settings failed: \(error.localizedDescription, privacy: .public)")
                self.writeProxyIncident(profile: profile, error: error)
                engine.stop()
                self.finishStart(with: error)
                return
            }
            self.lock.lock()
            if self.connectedSince == 0 { self.connectedSince = Date().timeIntervalSince1970 }
            self.lock.unlock()
            TunnelIncidentStore.clear(profile: profile)
            engine.startPump()
            Self.log.log("proxy tunnel up: routes applied, pump started")
            self.finishStart(with: nil)
        }
    }

    private func writeProxyIncident(profile: String, error: Error) {
        let event: String
        let category: IncidentCategory
        if let pe = error as? ProxyTunnelEngineError {
            event = pe.incidentEvent
            category = pe.incidentCategory
        } else {
            event = "PX_ERROR"
            category = .unknown
        }
        TunnelIncidentStore.write(TunnelIncident(profile: profile, category: category,
                                                 event: event, info: error.localizedDescription,
                                                 fatal: true))
    }

    // MARK: ProxyTunnelEngineDelegate (called on the engine's Go callback threads)

    func proxyTunnelEngine(_ engine: ProxyTunnelEngine, didFailWithError error: Error) {
        Self.log.error("proxy tunnel engine error: \(error.localizedDescription, privacy: .public)")
        lock.lock(); let p = profileID; lock.unlock()
        writeProxyIncident(profile: p, error: error)
        finishStart(with: error)
        cancelTunnelWithError(error)
    }

    func proxyTunnelEngine(_ engine: ProxyTunnelEngine, didLog line: String) {
        Self.log.log("px: \(line, privacy: .public)")
    }

    /// Where a Tailscale node's identity lives. This extension runs as root in
    /// the system context, so its state belongs in the machine-wide tree (the
    /// same place TunnelIncidentStore writes); 0700 because the node key in
    /// there is as good as the machine's identity on the tailnet. Per-profile,
    /// so two saved networks are two independent nodes, and stable across
    /// relaunches so the node key survives.
    private static func tailscaleStateDir(profile: String) -> String {
        let safe = profile.addingPercentEncoding(withAllowedCharacters: .alphanumerics) ?? "profile"
        let system = "/Library/Application Support/SimpleVPN/tailscale/\(safe)"
        let fm = FileManager.default
        if (try? fm.createDirectory(atPath: system, withIntermediateDirectories: true,
                                    attributes: [.posixPermissions: 0o700])) != nil {
            return system
        }
        // The sandbox profile, not root-ness, is what can refuse this path. Fall
        // back to whatever Application Support resolves to for THIS process —
        // inside a container when sandboxed — rather than failing to connect.
        // The node key is equally protected either way (0700, our uid only);
        // the only loss is that the app's `tsforget` has a different path to
        // shred, which it asks this same function for.
        let fallback = (fm.urls(for: .applicationSupportDirectory, in: .userDomainMask).first
                        ?? URL(fileURLWithPath: NSTemporaryDirectory()))
            .appendingPathComponent("SimpleVPN/tailscale/\(safe)", isDirectory: true)
        Self.log.log("tailscale state falling back to the extension's own container")
        return fallback.path
    }

    private func writeIncident(profile: String, error: Error) {
        let event: String
        let category: IncidentCategory
        if let te = error as? TailscaleEngineError {
            event = te.incidentEvent
            category = te.incidentCategory
        } else {
            event = "TS_ERROR"
            category = .unknown
        }
        TunnelIncidentStore.write(TunnelIncident(profile: profile, category: category,
                                                 event: event, info: error.localizedDescription,
                                                 fatal: true))
    }

    // MARK: TailscaleEngineDelegate (called on the engine's Go callback threads)

    func tailscaleEngine(_ engine: TailscaleEngine, didChange state: TailscaleBackendState,
                         event: TailscaleStateEvent) {
        lock.lock(); let p = profileID; lock.unlock()
        switch state {
        case .running:
            lock.lock(); if connectedSince == 0 { connectedSince = Date().timeIntervalSince1970 }; lock.unlock()
            TunnelIncidentStore.clear(profile: p)
        case .stopped:
            // Stopped after we were up means the control plane logged this node
            // out (key expiry, node removed, tailnet policy) — a failure the
            // user has to see, not a quiet idle.
            lock.lock(); let wasUp = connectedSince > 0; lock.unlock()
            if wasUp {
                TunnelIncidentStore.write(TunnelIncident(
                    profile: p, category: .auth, event: "TS_STOPPED",
                    info: event.message.isEmpty
                        ? "This Mac was signed out of the network."
                        : event.message,
                    fatal: true))
            }
        case .needsMachineAuth:
            TunnelIncidentStore.write(TunnelIncident(
                profile: p, category: .auth, event: "TS_NEEDS_APPROVAL",
                info: "This Mac is waiting to be approved by a network administrator.",
                fatal: false))
        case .inUseOtherUser:
            TunnelIncidentStore.write(TunnelIncident(
                profile: p, category: .conflict, event: "TS_IN_USE",
                info: event.message.isEmpty ? "Another user is signed in to this network." : event.message,
                fatal: true))
        default:
            break
        }
    }

    func tailscaleEngine(_ engine: TailscaleEngine, needsSignIn url: String) {
        // The extension cannot push to the app; the app polls "tsauth" while a
        // Tailscale VPN is coming up and opens the sign-in window itself.
        Self.log.log("tailscale: waiting for browser sign-in")
    }

    func tailscaleEngine(_ engine: TailscaleEngine, didFailWithError error: Error) {
        Self.log.error("tailscale engine error: \(error.localizedDescription, privacy: .public)")
        lock.lock(); let p = profileID; lock.unlock()
        writeIncident(profile: p, error: error)
        finishStart(with: error)
        cancelTunnelWithError(error)
    }

    func tailscaleEngine(_ engine: TailscaleEngine, didLog line: String) {
        Self.log.log("ts: \(line, privacy: .public)")
    }

    // MARK: OpenConnectBridgeDelegate

    func ocBridge(_ bridge: OpenConnectBridge, didChange status: OCStatus, event name: String, info: String) {
        Self.log.log("oc status=\(status.rawValue) event=\(name, privacy: .public)")
        switch status {
        case .connected:
            // connectedSince/reconnects are documented as lock-guarded (the stats
            // reader takes `lock`); the OVPN path does the same. Keep the OC path
            // consistent so the counters aren't torn/lost across executors.
            lock.lock(); let c = startCompletion; startCompletion = nil
            connectedSince = Date().timeIntervalSince1970; lock.unlock()
            c?(nil)   // tunnel settings were applied inside the bridge's setup-tun
        case .reconnecting:
            lock.lock(); reconnects += 1; lock.unlock()
        default:
            break
        }
    }

    func ocBridge(_ bridge: OpenConnectBridge, didFailWithError error: Error) {
        Self.log.error("oc failed: \(error.localizedDescription, privacy: .public)")
        lock.lock(); let p = profileID; lock.unlock()
        TunnelIncidentStore.write(TunnelIncident(profile: p, category: .unknown,
            event: "OC_FAILED", info: error.localizedDescription, fatal: true))
        // finishStart only fires the *start* completion, which is already nil once
        // connected — so a post-connect failure (gateway drop) must also tell NE to
        // tear the tunnel down, or it lingers as a zombie showing "connected".
        finishStart(with: error)
        cancelTunnelWithError(error)
    }

    func ocBridge(_ bridge: OpenConnectBridge, didLog line: String) {
        Self.log.log("oc: \(line, privacy: .public)")
    }

    override func stopTunnel(with reason: NEProviderStopReason,
                             completionHandler: @escaping () -> Void) {
        Self.log.log("stopTunnel reason=\(reason.rawValue)")
        lock.lock(); let b = bridge; let oc = ocBridge; let ts = tsEngine; let px = pxEngine; let p = profileID; lock.unlock()
        // System-initiated stops the user didn't ask for become incidents too —
        // notably .superceded: another VPN configuration took over.
        switch reason {
        case .userInitiated, .none:
            break
        case .superceded:
            TunnelIncidentStore.write(TunnelIncident(
                profile: p, category: .conflict, event: "STOP_SUPERCEDED",
                info: "Another VPN configuration was started.", fatal: true))
        default:
            TunnelIncidentStore.write(TunnelIncident(
                profile: p, category: .unknown, event: "STOP_\(reason.rawValue)",
                info: "The system stopped the tunnel.", fatal: true))
        }
        b?.disconnect()
        oc?.disconnect()
        ts?.stop()
        px?.stop()
        completionHandler()
    }

    /// The NE reply block for `handleAppMessage`. Apple's signature is not
    /// `@Sendable`, but the block IS documented as callable from any thread and
    /// every reply below is made exactly once — so the only thing missing is a
    /// way to say that. This box says it in one place, with a name, instead of
    /// scattering unchecked conformances (or forcing every engine read onto the
    /// provider's own queue, where a slow engine call would stall the tunnel).
    private struct AppMessageReply: @unchecked Sendable {
        let block: ((Data?) -> Void)?
        func callAsFunction(_ data: Data?) { block?(data) }
        func callAsFunction(_ text: String) { block?(Data(text.utf8)) }
        func encode(_ value: some Encodable) { block?(try? JSONEncoder().encode(value)) }
    }

    override func handleAppMessage(_ messageData: Data, completionHandler: ((Data?) -> Void)?) {
        let message = String(data: messageData, encoding: .utf8) ?? ""
        let reply = AppMessageReply(block: completionHandler)
        switch message {
        case "version":
            // Reply with this running extension's version (the app's staleness check).
            let info = Bundle.main.infoDictionary
            let v = "v\(info?["CFBundleShortVersionString"] as? String ?? "?") (build \(info?["CFBundleVersion"] as? String ?? "?"))"
            reply(v)

        case "stats":
            // Telemetry rides this IPC — app-group UserDefaults/files can't cross
            // the root(system-context) ↔ user boundary, so the app polls instead.
            if let ts = lock.withLock({ tsEngine }) {
                lock.lock(); let p = profileID; let since = connectedSince; let rc = reconnects; lock.unlock()
                statsQueue.async {
                    reply.encode(ts.stats(profile: p, connectedSince: since, reconnects: rc))
                }
                return
            }
            if let px = lock.withLock({ pxEngine }) {
                lock.lock(); let p = profileID; let since = connectedSince; let rc = reconnects
                let host = pxProxyHost; let suppress = pxSuppressDefault
                let hasDefault = pxConfig?.includeDefaultRoute ?? false; lock.unlock()
                statsQueue.async {
                    var s = px.stats(profile: p, connectedSince: since, reconnects: rc, proxyHost: host)
                    // Same ground-truth report as OpenVPN, cheaply (RC4): the proxy
                    // owns the default when its config carries it AND it isn't demoted.
                    s.suppressDefaultRoute = suppress
                    s.effectiveDefaultOwned = hasDefault && !suppress
                    reply.encode(s)
                }
                return
            }
            if let oc = lock.withLock({ ocBridge }) {
                statsQueue.async { [weak self] in
                    guard let self else { reply(nil); return }
                    reply.encode(self.buildOCStats(bridge: oc))
                }
                return
            }
            let b = lock.withLock { bridge }
            guard let b else { reply(nil); return }
            statsQueue.async { [weak self] in
                guard let self else { reply(nil); return }
                reply.encode(self.buildStats(bridge: b))
            }

        case "flows":
            // Per-VPN traffic log: the flows the bridge observed (IP/L4 headers
            // only). Same IPC channel as stats — serialized to JSON for the app.
            // (Neither the OpenConnect nor the Tailscale engine has flow
            // accounting yet → empty list.)
            let b = lock.withLock { bridge }
            guard let b else { reply.encode([TrafficFlow]()); return }
            statsQueue.async {
                reply.encode(b.flowStats().compactMap { TrafficFlow(dictionary: $0) })
            }

        case "pause:hold", "pause:bypass":
            // Engine pauses (transport closed, TLS session kept — resume needs no
            // re-auth). Hold keeps routes so traffic blackholes (safe default);
            // bypass strips routes/DNS so traffic uses the physical interface.
            withBridge(reply: reply) { b in
                b.pause(withReason: "user-pause")
                let ok = message == "pause:hold" ? true : b.reapplyTunSettings(includingRoutes: false)
                Self.log.log("paused (\(message, privacy: .public)) ok=\(ok)")
                return ok
            }

        case "resume":
            withBridge(reply: reply) { b in
                let ok = b.reapplyTunSettings(includingRoutes: true)
                b.resume()
                Self.log.log("resumed ok=\(ok)")
                return ok
            }

        case "gateway:full", "gateway:split":
            // Default-gateway ownership (PolicyRouting.md Tier 2). Routed per the
            // ACTIVE in-process engine — at most one is non-nil. "full" ⇒ this
            // tunnel owns 0.0.0.0/0; "split" ⇒ its default route is suppressed
            // (specific pushed subnets stay). Every in-process engine (openvpn3,
            // proxy tunnel, openconnect) now re-applies live with no reconnect; the
            // "needs-reconnect" reply survives as the coordinator's fallback for any
            // engine that genuinely can't re-apply routes live.
            let owned = message == "gateway:full"
            if let b = lock.withLock({ bridge }) {                 // openvpn3
                statsQueue.async {
                    reply(b.setDefaultRouteOwned(owned) ? "ok" : "error: settings apply failed")
                }
            } else if let px = lock.withLock({ pxEngine }) {       // proxy tunnel
                _ = px   // engine keeps running; only the utun's routes change
                lock.lock(); pxSuppressDefault = !owned; let cfg = pxConfig; let px = pxProxySettings; lock.unlock()
                guard let cfg else { reply("error: not connected"); return }
                let settings = ProxyTunnelNetworkSettings.settings(for: cfg, suppressDefaultRoute: !owned,
                                                                   proxySettings: px)
                setTunnelNetworkSettings(settings) { error in
                    Self.log.log("gateway \(owned ? "full" : "split", privacy: .public) (proxy) ok=\(error == nil)")
                    reply(error == nil ? "ok" : "error: settings apply failed")
                }
            } else if let oc = lock.withLock({ ocBridge }) {       // openconnect
                // OpenConnect now demotes live like openvpn3: it rebuilds and
                // re-applies the captured tun settings with the default-route gate
                // flipped, no reconnect. (setDefaultRouteOwned: blocks on the
                // settings completion, so run it off the message queue.)
                statsQueue.async {
                    reply(oc.setDefaultRouteOwned(owned) ? "ok" : "error: settings apply failed")
                }
            } else if lock.withLock({ tsEngine }) != nil {         // tailscale
                // Tailscale ownership is exit-node state, driven app-side through
                // the existing "tsprefs:" path — nothing to do here.
                reply("ok")
            } else {
                reply("error: not connected")
            }

        case "tsauth":
            // Interactive sign-in hand-off. The extension has no way to push to
            // the app (it is a different security context), so the app polls
            // this while a Tailscale VPN is coming up and opens the sign-in
            // window when a URL appears. Empty reply = nothing to sign in to.
            guard let ts = lock.withLock({ tsEngine }) else { reply(Data()); return }
            statsQueue.async { reply(ts.authURL()) }

        case "tsstatus":
            // Full engine status for the connection panel and the exit-node
            // picker (which needs the peer list this session actually sees).
            guard let ts = lock.withLock({ tsEngine }) else { reply(nil); return }
            statsQueue.async { reply.encode(ts.status()) }

        case "pxstatus":
            // Proxy-tunnel engine status for the connection panel: flow counts,
            // DNS queries, the last per-flow error. No secrets in it.
            guard let px = lock.withLock({ pxEngine }) else { reply(nil); return }
            statsQueue.async { reply.encode(px.status()) }

        case "tsforget":
            // The user deleted this VPN. Its node key is this Mac's identity on
            // that network, so it must not outlive the profile — and only this
            // (root) process can remove a root-owned 0700 directory, hence the
            // round trip. Best effort by construction: a VPN deleted while
            // disconnected has no session to ask, and its directory is then
            // left behind — a known gap, recorded rather than papered over.
            lock.lock(); let p = profileID; lock.unlock()
            let dir = Self.tailscaleStateDir(profile: p)
            try? FileManager.default.removeItem(atPath: dir)
            Self.log.log("tailscale state removed for \(p, privacy: .public)")
            reply("ok")

        case "proxy:clear":
            // Sole-writer proxy applier (Proxy mediator P3): clear the system proxy on
            // this (owner) tunnel. Only the in-process engines that build their own
            // NEPacketTunnelNetworkSettings apply here; native kinds are OS-owned.
            applyProxy(nil as ProxyApplyRequest?, reply: reply)

        case "dns:clear":
            // Sole-writer DNS applier (DNS mediator, Docs/StateMediators.md): clear this
            // engine's per-tunnel DNS override, restoring its captured/pushed DNS.
            applyDNS(nil as DNSApplyRequest?, reply: reply)

        default:
            if message.hasPrefix("proxy:apply:") {
                // Sole-writer proxy applier (Proxy mediator P3, Docs/StateMediators.md):
                // set the arbitrated system proxy on this OWNER tunnel's live
                // NEProxySettings. Payload is a JSON `ProxyApplyRequest`.
                let json = String(message.dropFirst("proxy:apply:".count))
                guard let req = try? JSONDecoder().decode(ProxyApplyRequest.self, from: Data(json.utf8)) else {
                    reply("error: bad proxy request"); return
                }
                applyProxy(req, reply: reply)
                return
            }
            if message.hasPrefix("dns:apply:") {
                // Sole-writer DNS applier (DNS mediator, Docs/StateMediators.md): set this
                // engine's arbitrated per-tunnel DNS slice on its live NEDNSSettings.
                // Payload is a JSON `DNSApplyRequest`.
                let json = String(message.dropFirst("dns:apply:".count))
                guard let req = try? JSONDecoder().decode(DNSApplyRequest.self, from: Data(json.utf8)) else {
                    reply("error: bad dns request"); return
                }
                applyDNS(req, reply: reply)
                return
            }
            if message.hasPrefix("tsprefs:") {
                // Live prefs edit (exit node / accept-routes / accept-DNS /
                // advertised routes) — avoids a reconnect just to change which
                // machine carries your internet traffic.
                guard let ts = lock.withLock({ tsEngine }) else {
                    reply("error: not connected"); return
                }
                let json = String(message.dropFirst("tsprefs:".count))
                statsQueue.async {
                    guard let patch = try? JSONDecoder().decode(TailscalePrefsPatch.self,
                                                                from: Data(json.utf8)) else {
                        reply("error: bad prefs"); return
                    }
                    reply(ts.updatePrefs(patch).map { "error: \($0)" } ?? "ok")
                }
                return
            }
            reply(nil)
        }
    }

    /// Snapshot the bridge under the lock and run `body` on the work queue,
    /// replying "ok"/"error: …" — replies "error: not connected" when there is
    /// no bridge. (The Swift shape for what would be a C macro: a higher-order
    /// function owning the lock, the guard, and the reply protocol.)
    private func withBridge(reply: AppMessageReply,
                            _ body: @escaping @Sendable (OpenVPN3Bridge) -> Bool) {
        let b = lock.withLock { bridge }
        guard let b else { reply("error: not connected"); return }
        statsQueue.async {
            reply(body(b) ? "ok" : "error: settings apply failed")
        }
    }

    /// Apply (or clear, when nil) the arbitrated system proxy on the active engine's
    /// tunnel settings — the sole-writer path for the Proxy mediator (P3). Dispatched to
    /// WHICHEVER in-process engine is active (mirrors the gateway IPC): openvpn3 and
    /// OpenConnect store + live-reapply via their bridges; the proxy-tunnel and Tailscale
    /// engines rebuild their built settings with the proxy and re-apply. Native kinds are
    /// OS-owned and never reach here. NEProxySettings isn't Sendable, so it is always
    /// built from the Codable/Sendable `request` INSIDE the work-queue closure.
    private func applyProxy(_ request: ProxyApplyRequest?, reply: AppMessageReply) {
        if let b = lock.withLock({ bridge }) {                       // openvpn3
            statsQueue.async {
                reply(b.applyProxySettings(request?.makeNEProxySettings()) ? "ok" : "error: settings apply failed")
            }
            return
        }
        if let oc = lock.withLock({ ocBridge }) {                    // openconnect
            statsQueue.async {
                reply(oc.applyProxySettings(request?.makeNEProxySettings()) ? "ok" : "error: settings apply failed")
            }
            return
        }
        if lock.withLock({ pxEngine }) != nil {                      // proxy tunnel
            statsQueue.async { [weak self] in
                guard let self else { reply("error: not connected"); return }
                let proxy = request?.makeNEProxySettings()
                self.lock.lock()
                self.pxProxySettings = proxy
                let cfg = self.pxConfig; let suppress = self.pxSuppressDefault
                self.lock.unlock()
                guard let cfg else { reply("error: not connected"); return }
                let settings = ProxyTunnelNetworkSettings.settings(for: cfg, suppressDefaultRoute: suppress,
                                                                   proxySettings: proxy)
                self.setTunnelNetworkSettings(settings) { error in
                    reply(error == nil ? "ok" : "error: settings apply failed")
                }
            }
            return
        }
        if let ts = lock.withLock({ tsEngine }) {                    // tailscale
            statsQueue.async {
                reply(ts.applyProxySettings(request?.makeNEProxySettings()) ? "ok" : "error: settings apply failed")
            }
            return
        }
        reply("ok")
    }

    /// Apply (or clear, when nil) this engine's arbitrated per-tunnel DNS slice — the
    /// sole-writer path for the DNS mediator (Docs/StateMediators.md). Only the
    /// in-process bridges (openvpn3, OpenConnect) have a LIVE DNS applier; they store the
    /// override and re-apply the captured settings with no reconnect. The proxy-tunnel
    /// and Tailscale engines can't hot-swap DNS without rebuilding from their own config,
    /// so they get NO live applier here — the reply is `nil`, the app's signal to fall
    /// back to its reconnect re-assert lever. Native kinds never reach here (no session).
    /// NEDNSSettings isn't Sendable, so it is built from the request inside the closure.
    private func applyDNS(_ request: DNSApplyRequest?, reply: AppMessageReply) {
        if let b = lock.withLock({ bridge }) {                       // openvpn3
            statsQueue.async {
                reply(b.applyDNSSettings(request?.makeNEDNSSettings()) ? "ok" : "error: settings apply failed")
            }
            return
        }
        if let oc = lock.withLock({ ocBridge }) {                    // openconnect
            statsQueue.async {
                reply(oc.applyDNSSettings(request?.makeNEDNSSettings()) ? "ok" : "error: settings apply failed")
            }
            return
        }
        if lock.withLock({ pxEngine != nil || tsEngine != nil }) {   // no live DNS applier
            reply(nil as Data?)   // → app reconnects this engine to re-push its DNS
            return
        }
        reply("ok")   // nothing connected
    }

    private func finishStart(with error: Error?) {
        lock.lock(); let done = startCompletion; startCompletion = nil; lock.unlock()
        done?(error)
    }

    // MARK: Telemetry (on demand — the app polls via the "stats" message; no
    // shared-storage channel exists between this root/system-context process
    // and the user's app)

    /// Snapshot the current sample. Called on statsQueue.
    private func buildStats(bridge b: OpenVPN3Bridge) -> TunnelStats {
        lock.lock()
        let p = profileID; let since = connectedSince; let rc = reconnects
        lock.unlock()

        var bin: Int64 = 0, bout: Int64 = 0
        b.transportBytes(in: &bin, bytesOut: &bout)
        let info = b.connectionInfo()

        var stats = TunnelStats(
            profile: p,
            timestamp: Date().timeIntervalSince1970,
            connectedSince: since,
            reconnects: rc,
            bytesIn: bin,
            bytesOut: bout,
            serverEndpoint: info["server"] as? String ?? "",
            tunnelIPv4: info["tunnelIP"] as? String ?? "",
            dnsServers: info["dns"] as? [String] ?? [],
            proxies: info["proxies"] as? [String] ?? []
        )
        stats.tunnelIPv6 = info["tunnelIPv6"] as? String
        stats.gateway4 = info["gateway4"] as? String
        stats.gateway6 = info["gateway6"] as? String
        stats.serverIP = info["serverIP"] as? String
        stats.serverPort = info["serverPort"] as? String
        stats.serverProto = info["serverProto"] as? String
        stats.searchDomains = info["searchDomains"] as? [String]
        stats.mtu = (info["mtu"] as? NSNumber)?.intValue
        // Structured pushed-proxy capture (Proxy mediator P3) — the machine-usable
        // detail alongside the display strings in `proxies`.
        if let h = info["proxyHTTPHost"] as? String, !h.isEmpty {
            stats.proxyHTTPHost = h
            stats.proxyHTTPPort = (info["proxyHTTPPort"] as? NSNumber)?.intValue
        }
        if let h = info["proxyHTTPSHost"] as? String, !h.isEmpty {
            stats.proxyHTTPSHost = h
            stats.proxyHTTPSPort = (info["proxyHTTPSPort"] as? NSNumber)?.intValue
        }
        if let pac = info["proxyPAC"] as? String, !pac.isEmpty { stats.proxyPACURL = pac }
        if let bypass = info["proxyBypass"] as? [String], !bypass.isEmpty { stats.proxyBypass = bypass }
        // Default-route ownership ground truth — the app seeds its applied-role
        // cache and the traffic-path UI from this (RC1/RC4).
        stats.defaultRouteV4 = (info["defaultV4"] as? NSNumber)?.boolValue
        stats.defaultRouteV6 = (info["defaultV6"] as? NSNumber)?.boolValue
        stats.suppressDefaultRoute = (info["suppressDefault"] as? NSNumber)?.boolValue
        stats.effectiveDefaultOwned = (info["effectiveDefaultOwned"] as? NSNumber)?.boolValue
        return stats
    }

    /// Stats snapshot for an OpenConnect session (no flow accounting yet).
    private func buildOCStats(bridge oc: OpenConnectBridge) -> TunnelStats {
        lock.lock(); let p = profileID; let since = connectedSince; let rc = reconnects; lock.unlock()
        var bin: Int64 = 0, bout: Int64 = 0
        oc.transportBytes(in: &bin, bytesOut: &bout)
        let info = oc.connectionInfo()
        var stats = TunnelStats(
            profile: p, timestamp: Date().timeIntervalSince1970,
            connectedSince: since, reconnects: rc, bytesIn: bin, bytesOut: bout,
            serverEndpoint: info["server"] as? String ?? "",
            tunnelIPv4: info["tunnelIP"] as? String ?? "",
            dnsServers: info["dns"] as? [String] ?? [], proxies: [])
        stats.tunnelIPv6 = info["tunnelIPv6"] as? String
        stats.mtu = (info["mtu"] as? NSNumber)?.intValue
        // Ground-truth default-route ownership (RC4), same channel as OpenVPN:
        // feeds the mediator's applied-role cache and the traffic-path UI.
        stats.suppressDefaultRoute = (info["suppressDefault"] as? NSNumber)?.boolValue
        stats.effectiveDefaultOwned = (info["effectiveDefaultOwned"] as? NSNumber)?.boolValue
        return stats
    }

    // MARK: OpenVPN3BridgeDelegate (called on the bridge's callback queue)

    func bridge(_ bridge: OpenVPN3Bridge, didChange status: OVPNStatus,
                event name: String, info: String) {
        Self.log.log("event \(name, privacy: .public) \(info, privacy: .public)")
        switch status {
        case .connected:
            lock.lock()
            if connectedSince == 0 { connectedSince = Date().timeIntervalSince1970 }
            let p = profileID
            lock.unlock()
            TunnelIncidentStore.clear(profile: p)   // this session is healthy
            finishStart(with: nil)
        case .reconnecting:
            lock.lock(); reconnects += 1; lock.unlock()
        default:
            break
        }
    }

    func bridge(_ bridge: OpenVPN3Bridge, didFailWithError error: Error) {
        Self.log.error("engine error: \(error.localizedDescription, privacy: .public)")
        // Publish a classified incident so the app can explain the failure.
        let ns = error as NSError
        let event = (ns.userInfo[OVPNErrorEventNameKey] as? String) ?? "ERROR"
        let info = (ns.userInfo[OVPNErrorEventInfoKey] as? String) ?? ns.localizedDescription
        lock.lock(); let p = profileID; lock.unlock()
        TunnelIncidentStore.write(TunnelIncident(
            profile: p,
            category: TunnelIncident.classify(event: event, info: info),
            event: event, info: info, fatal: true))
        finishStart(with: error)
        cancelTunnelWithError(error)
    }

    func bridge(_ bridge: OpenVPN3Bridge, didLog line: String) {
        // NOT .debug: os_log debug messages are not persisted to disk, so `log show`
        // after the fact returns nothing for them unless debug logging was enabled for
        // this subsystem beforehand. That silently emptied the diagnostics bundle of the
        // single most useful thing in it — the OpenVPN handshake. Default level is
        // persisted, and openvpn3's own verbosity keeps the volume reasonable.
        Self.log.log("ovpn: \(line, privacy: .public)")
    }
}
