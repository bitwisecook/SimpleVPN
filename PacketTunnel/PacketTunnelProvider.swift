// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only

//
//  PacketTunnelProvider.swift
//  SimpleVPN system extension — drives the OpenVPN 3 engine via OpenVPN3Bridge.
//

import NetworkExtension
import os

final class PacketTunnelProvider: NEPacketTunnelProvider, OpenVPN3BridgeDelegate, OpenConnectBridgeDelegate, @unchecked Sendable {

    private static let log = Logger(subsystem: "com.bragi0.SimpleVPN.PacketTunnel", category: "tunnel")

    // Accessed from the NE thread and the bridge's callback queue; guarded by `lock`.
    nonisolated(unsafe) private var bridge: OpenVPN3Bridge?
    nonisolated(unsafe) private var ocBridge: OpenConnectBridge?      // OpenConnect SSL-VPN engine
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

        // Config comes via providerConfiguration; credentials come via the shared keychain
        // (a read-once session secret the app wrote just before starting the tunnel).
        guard let ovpn = conf?["ovpn"] as? String, !ovpn.isEmpty else {
            completionHandler(NSError(domain: "PacketTunnel", code: 1,
                userInfo: [NSLocalizedDescriptionKey: "missing ovpn configuration"]))
            return
        }
        let profile = (conf?["profile"] as? String) ?? "default"
        lock.lock(); profileID = profile; lock.unlock()

        // Engine dispatch: the OpenConnect SSL-VPN kinds (anyconnect / nc / gp /
        // pulse / f5 / fortinet / array) run in-process via libopenconnect;
        // everything else is OpenVPN below. VPNKind is the single source of truth
        // for the protocol token.
        if let vpnType = conf?["vpnType"] as? String,
           let ocProto = VPNKind(rawValue: vpnType)?.openconnectProtocol {
            startOpenConnect(conf: conf, options: options, profile: profile,
                             protocol: ocProto, completionHandler: completionHandler)
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
        let settings = overrides.bridgeSettings(proxyPassword: proxyPassword,
                                                privateKeyPassword: privateKeyPassword)

        let b = OpenVPN3Bridge(provider: self, delegate: self)
        lock.lock(); bridge = b; startCompletion = completionHandler; lock.unlock()

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

        do {
            try b.connect(with: s)
            Self.log.log("openconnect connect() started (\(ocProto, privacy: .public))")
        } catch {
            finishStart(with: error)
        }
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
        lock.lock(); let b = bridge; let oc = ocBridge; let p = profileID; lock.unlock()
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
        completionHandler()
    }

    override func handleAppMessage(_ messageData: Data, completionHandler: ((Data?) -> Void)?) {
        let message = String(data: messageData, encoding: .utf8) ?? ""
        switch message {
        case "version":
            // Reply with this running extension's version (the app's staleness check).
            let info = Bundle.main.infoDictionary
            let v = "v\(info?["CFBundleShortVersionString"] as? String ?? "?") (build \(info?["CFBundleVersion"] as? String ?? "?"))"
            completionHandler?(Data(v.utf8))

        case "stats":
            // Telemetry rides this IPC — app-group UserDefaults/files can't cross
            // the root(system-context) ↔ user boundary, so the app polls instead.
            if let oc = lock.withLock({ ocBridge }) {
                statsQueue.async { [weak self] in
                    guard let self else { completionHandler?(nil); return }
                    completionHandler?(try? JSONEncoder().encode(self.buildOCStats(bridge: oc)))
                }
                return
            }
            let b = lock.withLock { bridge }
            guard let b else { completionHandler?(nil); return }
            statsQueue.async { [weak self] in
                guard let self else { completionHandler?(nil); return }
                completionHandler?(try? JSONEncoder().encode(self.buildStats(bridge: b)))
            }

        case "flows":
            // Per-VPN traffic log: the flows the bridge observed (IP/L4 headers
            // only). Same IPC channel as stats — serialized to JSON for the app.
            // (The OpenConnect engine has no flow accounting yet → empty list.)
            let b = lock.withLock { bridge }
            guard let b else { completionHandler?(try? JSONEncoder().encode([TrafficFlow]())); return }
            statsQueue.async {
                let flows = b.flowStats().compactMap { TrafficFlow(dictionary: $0) }
                completionHandler?(try? JSONEncoder().encode(flows))
            }

        case "pause:hold", "pause:bypass":
            // Engine pauses (transport closed, TLS session kept — resume needs no
            // re-auth). Hold keeps routes so traffic blackholes (safe default);
            // bypass strips routes/DNS so traffic uses the physical interface.
            withBridge(reply: completionHandler) { b in
                b.pause(withReason: "user-pause")
                let ok = message == "pause:hold" ? true : b.reapplyTunSettings(includingRoutes: false)
                Self.log.log("paused (\(message, privacy: .public)) ok=\(ok)")
                return ok
            }

        case "resume":
            withBridge(reply: completionHandler) { b in
                let ok = b.reapplyTunSettings(includingRoutes: true)
                b.resume()
                Self.log.log("resumed ok=\(ok)")
                return ok
            }

        default:
            completionHandler?(nil)
        }
    }

    /// Snapshot the bridge under the lock and run `body` on the work queue,
    /// replying "ok"/"error: …" — replies "error: not connected" when there is
    /// no bridge. (The Swift shape for what would be a C macro: a higher-order
    /// function owning the lock, the guard, and the reply protocol.)
    private func withBridge(reply: ((Data?) -> Void)?,
                            _ body: @escaping (OpenVPN3Bridge) -> Bool) {
        let b = lock.withLock { bridge }
        guard let b else { reply?(Data("error: not connected".utf8)); return }
        statsQueue.async {
            let ok = body(b)
            reply?(Data((ok ? "ok" : "error: settings apply failed").utf8))
        }
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
