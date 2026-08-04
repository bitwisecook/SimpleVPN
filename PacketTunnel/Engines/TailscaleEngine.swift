// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
//  TailscaleEngine.swift
//  Drives the in-process Tailscale/Headscale engine (libtsengine.a — see
//  Vendor/tailscale-engine/src/main.go) from the packet-tunnel system
//  extension: owns the packet pump between NEPacketTunnelFlow and the Go TUN,
//  turns the engine's netmap callbacks into NEPacketTunnelNetworkSettings, and
//  reports state/auth/failures to the provider.
//
//  PACKET PUMP — no PF header here. The openvpn3 path prepends/strips the
//  4-byte protocol-family header because openvpn3 sets tun_prefix on macOS
//  (see AGENTS.md); the Go TUN in this engine deals in RAW IP packets in both
//  directions, so this pump must NOT add one. The packet's own IP version
//  nibble is what tells us which protocol number to hand NEPacketTunnelFlow.
//
//  CALLBACK CONTEXT — the engine's callbacks are plain C function pointers,
//  which by construction cannot capture Swift context. Exactly one tunnel runs
//  per provider process, so the callbacks route through a single lock-guarded
//  static reference rather than through a context pointer we would have to
//  keep alive and cast by hand.
//

import Foundation
import NetworkExtension
import os

protocol TailscaleEngineDelegate: AnyObject {
    /// The engine reached a new backend state (ipn.State names).
    func tailscaleEngine(_ engine: TailscaleEngine, didChange state: TailscaleBackendState, event: TailscaleStateEvent)
    /// Interactive sign-in is required; this URL must reach the user.
    func tailscaleEngine(_ engine: TailscaleEngine, needsSignIn url: String)
    /// A failure the session cannot recover from.
    func tailscaleEngine(_ engine: TailscaleEngine, didFailWithError error: Error)
    /// Engine diagnostics for os_log.
    func tailscaleEngine(_ engine: TailscaleEngine, didLog line: String)
}

final class TailscaleEngine: @unchecked Sendable {

    private static let log = Logger(subsystem: "com.bragi0.SimpleVPN.PacketTunnel", category: "tailscale")

    /// How long we wait for the engine to either come up or ask for sign-in
    /// before failing the start. NE kills a provider that never calls its
    /// start completion, so this must fire comfortably inside that window.
    private static let startGrace: TimeInterval = 45

    private weak var provider: NEPacketTunnelProvider?
    private weak var delegate: (any TailscaleEngineDelegate)?

    private let lock = NSLock()
    /// Serialises settings applies and the start/stop lifecycle off the Go
    /// callback threads.
    private let work = DispatchQueue(label: "com.bragi0.SimpleVPN.tailscale")

    private var startCompletion: ((Error?) -> Void)?
    private var pumpRunning = false
    private var lastConfig: TailscaleTunnelConfig?
    /// App-arbitrated system proxy (Proxy mediator applier — Docs/StateMediators.md).
    /// Guarded by `lock` like the rest of the mutable session state; merged into the
    /// settings built from every netmap and by `applyProxySettings(_:)`.
    private var proxySettings: NEProxySettings?
    /// This VPN's `.outside` divert destinations as CIDRs (`DivertPlan.outsideCIDRs`):
    /// carve-outs the CONNECT decided, merged into every settings build alongside the
    /// engine's own `localRoutes`. Set once before `start`; `lock`-guarded like the
    /// rest of the session state because the netmap callback reads it.
    var extraExcludedRoutes: [String] {
        get { lock.lock(); defer { lock.unlock() }; return storedExtraExcludedRoutes }
        set { lock.lock(); storedExtraExcludedRoutes = newValue; lock.unlock() }
    }
    private var storedExtraExcludedRoutes: [String] = []
    private var lastState: TailscaleBackendState = .noState
    private var pendingAuthURL: String = ""
    private var startTimer: DispatchSourceTimer?
    private var stopped = false

    /// The engine currently wired to the C callbacks.
    private static let currentLock = NSLock()
    nonisolated(unsafe) private static var current: TailscaleEngine?

    private static func active() -> TailscaleEngine? {
        currentLock.lock(); defer { currentLock.unlock() }
        return current
    }

    init(provider: NEPacketTunnelProvider, delegate: any TailscaleEngineDelegate) {
        self.provider = provider
        self.delegate = delegate
    }

    // MARK: - Lifecycle

    /// Compose and start the node. Returns immediately on a configuration
    /// error; otherwise `completion` fires when the tunnel is usable, when the
    /// engine asks for interactive sign-in, or when the grace period expires.
    func start(config: TailscaleStartConfig, completion: @escaping (Error?) -> Void) {
        lock.lock(); startCompletion = completion; lock.unlock()

        Self.currentLock.lock(); Self.current = self; Self.currentLock.unlock()
        TSSetCallbacks(Self.packetOut, Self.stateChanged, Self.browseToURL, Self.netmapChanged, Self.logLine)

        Self.log.log("tailscale start: \(config.redactedJSONString(), privacy: .public)")

        // Grace timer first: if TSStart wedges inside the Go runtime we still
        // fail the start rather than letting NE reap the whole extension.
        armStartTimer()

        let reply = config.jsonString().withCString { TSStart($0) }
        let response = Self.takeString(reply)
        if let err = Self.engineError(from: response, fallback: "Tailscale could not start.") {
            cancelStartTimer()
            finishStart(with: err)
            return
        }
    }

    /// Tear the node down. Safe to call more than once, and safe to call after
    /// a failed start.
    func stop() {
        lock.lock()
        if stopped { lock.unlock(); return }
        stopped = true
        lock.unlock()

        cancelStartTimer()
        _ = Self.takeString(TSStop())
        Self.currentLock.lock()
        if Self.current === self { Self.current = nil }
        Self.currentLock.unlock()
        // Drop the callbacks last: a packet already inside the Go writer would
        // otherwise land on a torn-down flow.
        TSSetCallbacks(nil, nil, nil, nil, nil)
        Self.log.log("tailscale stopped")
    }

    // MARK: - Status

    /// Current engine status, or an empty status when the engine is not up.
    func status() -> TailscaleStatus {
        guard let json = Self.takeString(TSStatus()), let s = TailscaleStatus.decode(json: json) else {
            return TailscaleStatus()
        }
        return s
    }

    /// The sign-in URL the engine last asked for, if the user has not been sent
    /// to it yet. The app polls for this — the extension cannot push.
    func authURL() -> String {
        lock.lock(); let pending = pendingAuthURL; lock.unlock()
        if !pending.isEmpty { return pending }
        return status().authURL
    }

    /// Apply a live prefs change (exit node / accept-routes / accept-DNS /
    /// advertised routes). Returns nil on success or a message on failure.
    func updatePrefs(_ patch: TailscalePrefsPatch) -> String? {
        let reply = patch.jsonString().withCString { TSUpdatePrefs($0) }
        guard let response = Self.takeString(reply) else { return "The engine did not answer." }
        return Self.engineError(from: response, fallback: "The change could not be applied.")?.localizedDescription
    }

    /// Telemetry sample for the app's 1 Hz poll.
    ///
    /// `serverEndpoint`/`serverIP` are deliberately left EMPTY. A Tailscale
    /// node has no server: traffic goes peer-to-peer, or via whichever DERP
    /// relay each peer happens to use. Reporting one of those as "the VPN
    /// server" would put a meaningless pin on the map and a wrong address in
    /// the connection details. The node's own address is the honest topology.
    func stats(profile: String, connectedSince: Double, reconnects: Int) -> TunnelStats {
        let s = status()
        var out = TunnelStats(
            profile: profile,
            timestamp: Date().timeIntervalSince1970,
            connectedSince: connectedSince,
            reconnects: reconnects,
            bytesIn: s.rxBytes,
            bytesOut: s.txBytes,
            serverEndpoint: "",
            tunnelIPv4: s.primaryIPv4,
            dnsServers: s.config?.dns.nameservers ?? [],
            proxies: [])
        out.tunnelIPv6 = s.primaryIPv6.isEmpty ? nil : s.primaryIPv6
        out.searchDomains = s.config?.dns.searchDomains
        out.mtu = s.config?.mtu
        return out
    }

    // MARK: - Packet pump

    /// flow → engine. One outstanding read at a time; the handler re-arms
    /// itself, which is the documented NEPacketTunnelFlow pattern.
    private func startPump() {
        lock.lock()
        if pumpRunning { lock.unlock(); return }
        pumpRunning = true
        lock.unlock()
        readMore()
    }

    private func readMore() {
        guard let flow = provider?.packetFlow else { return }
        flow.readPackets { [weak self] packets, _ in
            guard let self else { return }
            for packet in packets {
                // Raw IP packet straight through — no PF header on this
                // boundary. A full queue drops (TSPacketIn returns 0), which is
                // correct: a VPN must shed load, never stall the flow reader.
                packet.withUnsafeBytes { raw in
                    guard let base = raw.baseAddress, !raw.isEmpty else { return }
                    _ = TSPacketIn(base, Int32(raw.count))
                }
            }
            self.lock.lock(); let running = self.pumpRunning && !self.stopped; self.lock.unlock()
            if running { self.readMore() }
        }
    }

    /// engine → flow. Called from a Go goroutine; NEPacketTunnelFlow's write is
    /// thread-safe, so no hop is needed (and a hop would add latency to every
    /// packet).
    fileprivate func deliver(_ packet: Data) {
        guard let flow = provider?.packetFlow, let first = packet.first else { return }
        // IP version nibble decides the protocol number NE carries alongside
        // the packet — the packet itself stays raw.
        let proto: Int32 = (first >> 4) == 6 ? AF_INET6 : AF_INET
        flow.writePackets([packet], withProtocols: [NSNumber(value: proto)])
    }

    // MARK: - Engine events

    fileprivate func handleState(_ json: String) {
        guard let event = TailscaleStateEvent.decode(json: json) else { return }
        let state = TailscaleBackendState(engineName: event.state)
        lock.lock()
        let changed = state != lastState
        lastState = state
        lock.unlock()
        guard changed || !event.message.isEmpty else { return }
        Self.log.log("tailscale state=\(event.state, privacy: .public) \(event.message, privacy: .public)")
        delegate?.tailscaleEngine(self, didChange: state, event: event)

        // Waiting for the user is a legitimate resting state, not a failure —
        // but the NE session has to be alive for the app to show the sign-in
        // window, so finish the start now and let the state reporting carry the
        // truth.
        if state.needsUserAction { finishStart(with: nil) }
    }

    fileprivate func handleBrowseToURL(_ url: String) {
        guard !url.isEmpty else { return }
        lock.lock(); pendingAuthURL = url; lock.unlock()
        Self.log.log("tailscale sign-in required")   // the URL itself is a bearer secret
        delegate?.tailscaleEngine(self, needsSignIn: url)
        finishStart(with: nil)
    }

    fileprivate func handleNetmap(_ json: String) {
        guard let config = TailscaleTunnelConfig.decode(json: json) else { return }
        work.async { [weak self] in
            guard let self, let provider = self.provider else { return }
            self.lock.lock()
            let unchanged = self.lastConfig == config
            self.lastConfig = config
            self.lock.unlock()
            guard !unchanged else { return }

            let (px, carveOuts) = { self.lock.lock(); defer { self.lock.unlock() }
                                    return (self.proxySettings, self.storedExtraExcludedRoutes) }()
            guard let settings = TailscaleNetworkSettings.settings(for: config, proxySettings: px,
                                                                   extraExcludedRoutes: carveOuts) else {
                // No addresses yet: the node is registered but the control
                // plane has not handed out an IP. Nothing to apply, and
                // applying empty settings would drop what is already there.
                return
            }
            provider.setTunnelNetworkSettings(settings) { [weak self] error in
                guard let self else { return }
                if let error {
                    Self.log.error("tailscale settings failed: \(error.localizedDescription, privacy: .public)")
                    self.delegate?.tailscaleEngine(self, didFailWithError: error)
                    self.finishStart(with: error)
                    return
                }
                Self.log.log("tailscale settings applied: \(config.localAddrs.joined(separator: ","), privacy: .public) routes=\(config.routes.count) dns=\(config.dns.nameservers.count)")
                // The flow only exists once settings are applied; starting the
                // pump earlier reads from a flow with no addresses.
                self.startPump()
                self.lock.lock(); self.pendingAuthURL = ""; self.lock.unlock()
                self.finishStart(with: nil)
            }
        }
    }

    fileprivate func handleLog(_ line: String) {
        delegate?.tailscaleEngine(self, didLog: line)
    }

    // MARK: - Proxy mediator applier (Docs/StateMediators.md)

    /// Store the arbitrated system proxy and re-apply the last netmap's settings live
    /// (no reconnect); nil clears it. Returns NO when there is no netmap to rebuild from
    /// yet (the stored proxy is honoured at the next netmap) or the apply fails.
    /// Synchronous — the provider calls it off its message queue like the other appliers.
    func applyProxySettings(_ proxy: NEProxySettings?) -> Bool {
        lock.lock()
        proxySettings = proxy
        let config = lastConfig
        let carveOuts = storedExtraExcludedRoutes
        lock.unlock()
        Self.log.log("tailscale applyProxySettings: \(proxy != nil ? "set" : "cleared", privacy: .public)")
        guard let provider, let config,
              let settings = TailscaleNetworkSettings.settings(for: config, proxySettings: proxy,
                                                              extraExcludedRoutes: carveOuts)
        else { return true }   // no netmap yet: honoured at the next netmapChanged
        // The semaphore establishes happens-before between the completion and the wait,
        // so the result is safe to hand back through a small unchecked-Sendable box
        // (Swift 6 can't prove that of a captured `var`).
        final class ResultBox: @unchecked Sendable { var ok = false }
        let box = ResultBox()
        let done = DispatchSemaphore(value: 0)
        provider.setTunnelNetworkSettings(settings) { error in
            box.ok = (error == nil)
            if let error { Self.log.error("tailscale proxy apply failed: \(error.localizedDescription, privacy: .public)") }
            done.signal()
        }
        _ = done.wait(timeout: .now() + 15)
        return box.ok
    }

    // MARK: - Start completion

    private func armStartTimer() {
        let timer = DispatchSource.makeTimerSource(queue: work)
        timer.schedule(deadline: .now() + Self.startGrace)
        timer.setEventHandler { [weak self] in
            guard let self else { return }
            self.finishStart(with: TailscaleEngineError.startTimedOut)
        }
        lock.lock(); startTimer?.cancel(); startTimer = timer; lock.unlock()
        timer.resume()
    }

    private func cancelStartTimer() {
        lock.lock(); let t = startTimer; startTimer = nil; lock.unlock()
        t?.cancel()
    }

    private func finishStart(with error: Error?) {
        lock.lock(); let done = startCompletion; startCompletion = nil; lock.unlock()
        guard let done else { return }
        cancelStartTimer()
        done(error)
    }

    // MARK: - C boundary helpers

    /// Take ownership of a malloc'd engine string, converting and freeing it.
    private static func takeString(_ p: UnsafeMutablePointer<CChar>?) -> String? {
        guard let p else { return nil }
        defer { TSFree(p) }
        return String(cString: p)
    }

    /// Decode `{"error":{"kind","message"}}` into a UserFacingError-friendly
    /// NSError, or nil when the response was `{"ok":true}`. Everything the
    /// engine can refuse lands here rather than in silence.
    private static func engineError(from json: String?, fallback: String) -> Error? {
        guard let json, let data = json.data(using: .utf8) else {
            return TailscaleEngineError.engine(kind: "other", message: fallback)
        }
        guard let obj = try? JSONSerialization.jsonObject(with: data) as? [String: Any] else {
            return TailscaleEngineError.engine(kind: "other", message: fallback)
        }
        if let e = obj["error"] as? [String: Any] {
            return TailscaleEngineError.engine(kind: (e["kind"] as? String) ?? "other",
                                               message: (e["message"] as? String) ?? fallback)
        }
        if obj["ok"] as? Bool == true { return nil }
        return TailscaleEngineError.engine(kind: "other", message: fallback)
    }

    // MARK: - C callbacks
    //
    // These are `@convention(c)` by inference: none of them captures anything,
    // which is what lets them be handed to the Go side as function pointers.

    private static let packetOut: TSPacketCallback = { bytes, length in
        guard let bytes, length > 0 else { return }
        let data = Data(bytes: bytes, count: Int(length))
        active()?.deliver(data)
    }

    private static let stateChanged: TSStringCallback = { text in
        guard let text else { return }
        let s = String(cString: text)
        active()?.handleState(s)
    }

    private static let browseToURL: TSStringCallback = { text in
        guard let text else { return }
        let s = String(cString: text)
        active()?.handleBrowseToURL(s)
    }

    private static let netmapChanged: TSStringCallback = { text in
        guard let text else { return }
        let s = String(cString: text)
        active()?.handleNetmap(s)
    }

    private static let logLine: TSStringCallback = { text in
        guard let text else { return }
        let s = String(cString: text)
        active()?.handleLog(s)
    }
}

/// Failures the Tailscale engine can produce. Messages are plain prose so
/// UserFacingError's generic classifier makes a usable sheet out of them
/// without a bespoke branch.
enum TailscaleEngineError: LocalizedError {
    case engine(kind: String, message: String)
    case startTimedOut

    var errorDescription: String? {
        switch self {
        case .engine(let kind, let message):
            switch kind {
            case "badRequest":
                return "This VPN's settings are not usable. \(message)"
            case "stateDir":
                return "SimpleVPN could not save this network's sign-in details. \(message)"
            case "alreadyRunning":
                return "This network is already connected."
            default:
                return message.isEmpty ? "The Tailscale engine reported a problem." : message
            }
        case .startTimedOut:
            return "Tailscale did not finish connecting in time. Check the control server address and try again."
        }
    }

    /// How this failure is filed for the incident card.
    var incidentEvent: String {
        switch self {
        case .engine(let kind, _): "TS_\(kind.uppercased())"
        case .startTimedOut: "TS_START_TIMEOUT"
        }
    }

    var incidentCategory: IncidentCategory {
        switch self {
        case .engine(let kind, _):
            switch kind {
            case "badRequest": .tunSetup
            case "stateDir": .tunSetup
            case "backend": .auth
            default: .network
            }
        case .startTimedOut: .timeout
        }
    }
}
