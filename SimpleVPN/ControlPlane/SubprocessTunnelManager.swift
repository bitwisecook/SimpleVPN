// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
//  SubprocessTunnelManager.swift
//  Owns the command-line VPN kinds (SSH SOCKS / port forwards, and the OpenConnect /
//  SSL-VPNs — FortiGate, F5 BIG-IP APM, …) — but `start` no longer means
//  "spawn a child" for all of them. Three cases are dispatched away from any subprocess:
//    • SSH SOCKS            → the in-process libssh engine (`connectInProcessSSH`),
//                             when `inProcessSSHSupports` accepts the config (no jump
//                             host, no raw extra-options).
//    • SSL-VPN SSO          → `connectSSO` / ocauth-helper; the old
//                             `openconnect --external-browser` subprocess is retired.
//    • OpenConnect opted in → `connectInProcessOpenConnect`, the packet-tunnel
//                             extension's in-process bridge (`willRunInProcess`). That
//                             is a FULL-ROUTES path and needs no privileged helper —
//                             NetworkExtension is the privilege. ALL SEVEN SSL-VPN
//                             kinds go this way; the extension dispatches on
//                             `VPNKind.openconnectProtocol` and always has.
//  Everything else is one child process: we build its argv, feed the password headlessly
//  (SSH via a private one-shot FIFO for each hop, OpenConnect via --passwd-on-stdin), watch
//  its output for the "up" signal, keep a rolling log, and — for SOCKS kinds — optionally
//  point the active network service's SOCKS proxy at the local port while connected
//  (restored on disconnect).
//
//  The subprocess SOCKS path needs no root either: `ssh -D` and `openconnect
//  --script-tun --script "ocproxy -D <port>"` both expose a userspace proxy.
//  ocproxy is NOT optional on that path — without it `openconnect` goes looking for a
//  real tun device it has no privilege to make. `sslTransportBlockReason` refuses the
//  connect in that case and names the in-process toggle as the fix, because the
//  bundled engine needs no tool at all. See Docs/Networking.md §3.3.
//

import Foundation
import Observation
import os
import SystemConfiguration

/// The helper's first form is a reply on a separate task. Keeping it in an actor
/// lets a discovery run cancel cleanly after the gateway has told us what it asks
/// for, without sharing mutable state across the helper callback.
private actor OpenConnectFormCapture {
    private var value: OCAuthFormSpec?
    func set(_ form: OCAuthFormSpec) { value = form }
    func get() -> OCAuthFormSpec? { value }
}

@MainActor
@Observable
final class SubprocessTunnelManager {

    enum Status: Equatable, Sendable {
        case disconnected, connecting, connected, failed(String)
        var isFailed: Bool { if case .failed = self { return true } else { return false } }
        var failureText: String? { if case .failed(let m) = self { return m } else { return nil } }
    }

    /// One live forward's lifecycle while the tunnel is connected.
    enum ForwardPhase: Equatable, Sendable {
        case pending          // requested, not yet confirmed
        case active           // listening / established
        case failed(String)   // refused (port bound, invalid spec, …) — the reason
    }

    struct Live: Sendable {
        var status: Status = .disconnected
        var socksPort: Int? = nil
        var log: [String] = []
        /// Per-forward status keyed by `forwardKey(line)` — drives the editor's
        /// live row badges while connected.
        var forwardStates: [String: ForwardPhase] = [:]
        /// A system SOCKS proxy change that needs attention.
        var caution: String? = nil
    }

    @ObservationIgnored weak var gatewayCoordinator: VPNController?
    @ObservationIgnored weak var configurationStore: SubprocessTunnelStore?
    private var editingPacketPolicy = Set<String>()
    func beginPacketPolicyEdit(_ id: String) -> Bool { !isActive(id) && editingPacketPolicy.insert(id).inserted }
    func finishPacketPolicyEdit(_ id: String) { editingPacketPolicy.remove(id) }
    func hasPacketSession(_ id: String) -> Bool { inProcessNE.contains(id) }
    func hasProxyPacketSession(_ id: String) -> Bool { tasks[id]?.isProxyRelay == true && status(id) == .connected }
    func proxyPacketStatus(_ id: String) async -> Data? { await tasks[id]?.proxySnapshot() }
    func hasSSHChannelSession(_ id: String) -> Bool { sshEngines[id] != nil || reverseSessions[id] != nil }
    func sshChannelCounters(_ id: String) async -> SSHChannelCounters? {
        if let reverse = reverseSessions[id] { return await reverse.snapshot() }
        return await sshEngines[id]?.channelCounters()
    }
    var dnsQueryStatusDidChange: (@MainActor () -> Void)?
    private(set) var live: [String: Live] = [:] { didSet { dnsQueryStatusDidChange?() } }

    private var reverseSessions: [String: OpenSSHReverseDelivery] = [:]
    private var tasks: [String: TunnelProcess] = [:]
    private var sshEngines: [String: SSHTunnelEngine] = [:]   // in-process libssh (SOCKS)
    private var packetAttempts: [String: UUID] = [:]
    private var inProcessNE: Set<String> = []                 // SSL VPNs running via the NE OpenConnect engine
    private var authTasks: [String: Task<Void, Never>] = [:]  // in-flight ocauth-helper sign-ins (SSO)
    @ObservationIgnored private lazy var systemSOCKS = SystemSOCKSProxy { [weak self] id, error in
        guard let self, live[id]?.caution != error else { return }
        live[id]?.caution = error
    }
    private var proxyToggleWhileConnecting: [String: Bool] = [:]
    private var controlSockets: [String: String] = [:]       // ssh ControlMaster socket per tunnel (live -O ops)
    private static let log = Logger(subsystem: "com.bragi0.SimpleVPN", category: "subprocess")

    func status(_ id: String) -> Status {
        if let status = gatewayCoordinator?.virtualMemberStatus(for: id) {
            switch status {
            case .connected: return .connected
            case .connecting, .reasserting: return .connecting
            default: return .disconnected
            }
        }
        return live[id]?.status ?? .disconnected
    }
    func isActive(_ id: String) -> Bool {
        switch status(id) { case .connected, .connecting: true; default: false }
    }
    /// Ids of tunnels currently connecting/connected — for the live surfaces.
    var activeIDs: [String] { live.compactMap { isActive($0.key) ? $0.key : nil } }
    var hasActive: Bool { live.values.contains { $0.status == .connected || $0.status == .connecting } }

    // MARK: Connect / disconnect

    /// Prefer the linked in-process engine where we have one; otherwise the
    /// subprocess path. SSH SOCKS runs on libssh (no /usr/bin/ssh); if it can't
    /// start, we fall back to the subprocess so nothing regresses.
    func connect(_ config: SubprocessTunnelConfig, password: String?,
                 oneTimeCode: String? = nil) {
        guard !editingPacketPolicy.contains(config.id), gatewayCoordinator?.virtualManager(for: config.id) == nil,
              gatewayCoordinator?.connectionReservations.isReserved(config.id) != true else { return }
        var config = config
        if let stored = configurationStore?.tunnels.first(where: { $0.id == config.id }) {
            config.routingEventSource = stored.routingEventSource
        }
        guard tasks[config.id] == nil, sshEngines[config.id] == nil,
              !inProcessNE.contains(config.id), authTasks[config.id] == nil else { return }
        if config.kind == .ssh, config.sshMode == .netTunnel, let issue = config.sshTunProblem {
            live[config.id] = Live(status: .failed(issue))
            return
        }
        if config.routingEventSource != nil && ProfilePacketPolicy.adapter(for: config) == nil {
            live[config.id] = Live(status: .failed(ProfilePacketPolicy.unsupported))
            return
        }
        proxyToggleWhileConnecting[config.id] = nil
        // A password embedded in the server or proxy address would be persisted
        // unencrypted in the profile.
        if let reason = Self.addressCredentialReason(config) {
            live[config.id] = Live(status: .failed(reason))
            return
        }
        // The chosen SSL-VPN sign-in method missing its material: refuse with the
        // fix rather than let openconnect fail opaquely (the SSH rule, applied
        // to the openconnect surface too).
        if let reason = Self.sslAuthBlockReason(config) {
            live[config.id] = Live(status: .failed(reason))
            return
        }
        // …and the transport it would use can't carry traffic without root. Read
        // BEFORE the dispatch below, because the dispatch is what this predicts.
        if let reason = Self.sslTransportBlockReason(config) {
            live[config.id] = Live(status: .failed(reason))
            return
        }
        // A pinned host key is enforced by the in-process engine only —
        // /usr/bin/ssh has no pin-by-hash option, so a pinned config must never
        // silently route to the subprocess (that would connect unpinned).
        if config.kind == .ssh, let reason = Self.sshPinBlockReason(config) {
            live[config.id] = Live(status: .failed(reason))
            return
        }
        // An explicit sign-in method missing its material would fail deep in
        // the engine — fail fast with the actual fix instead.
        if config.kind == .ssh, let reason = Self.sshAuthBlockReason(config) {
            live[config.id] = Live(status: .failed(reason))
            return
        }
        // A forward line neither path can honour. Checked HERE, before the dispatch,
        // because both paths need it now: it used to live in `connectSubprocess`,
        // which was the only place a port-forward tunnel could go. The in-process
        // engine is handed already-parsed specs, so an unparseable line would
        // otherwise be silently dropped rather than reported.
        if config.kind == .ssh && config.sshMode == .netTunnel {
            connectInProcessOpenConnect(config, password: password, oneTimeCode: nil)
            return
        }
        if config.kind == .ssh, config.sshMode == .portForward,
           let bad = Self.invalidForwardLine(config.forwards) {
            live[config.id] = Live(status: .failed(
                "Invalid forward “\(bad)” — use “L localPort:host:port”, “R remotePort:host:port” or “D port”."))
            return
        }
        if Self.willRunInProcessSSH(config) {
            connectInProcessSSH(config, password: password)
            return
        }
        // SSO signs in through the bundled ocauth-helper (libopenconnect in user
        // context — the browser needs the user session, which the root extension
        // doesn't have). The helper's cookie then rides to the connect path; the
        // old `openconnect --external-browser` subprocess sign-in is retired.
        if config.kind.isSSLVPN, config.authMode == "sso", config.kind.supportsExternalBrowserSSO {
            connectSSO(config, password: password)
            return
        }
        // Configs using settings the in-process bridge doesn't carry route to the
        // subprocess path (see inProcessOpenConnectSupports).
        //
        // ONE PREDICATE, `willRunInProcess`, and this is the only place that decides.
        // It used to be three spellings and two were wrong: the editor promised
        // in-process for every SSL-VPN kind, this dispatch named
        // `[.fortinet, .f5apm, .ciscoAnyConnect]`, and the cookie path checked nothing
        // — so a GlobalProtect / Juniper / Pulse / Array tunnel was told it would run
        // in-process and silently ran as an `openconnect` subprocess, needing ocproxy
        // and therefore Homebrew for no reason. The extension has never had that limit:
        // `PacketTunnelProvider.startTunnel` dispatches on `VPNKind.openconnectProtocol`,
        // which is non-nil for all seven.
        if config.authMode != "sso", Self.willRunInProcess(config) {
            connectInProcessOpenConnect(config, password: password, oneTimeCode: oneTimeCode)
            return
        }
        connectSubprocess(config, password: passwordForSubprocess(config, password: password,
                                                                    oneTimeCode: oneTimeCode))
    }

    /// The in-process OpenConnect bridge only carries server + realm + pinned
    /// cert + SAML browser + credentials (OpenConnectProfileStore). Any config
    /// using a knob it can't express must run through the subprocess instead —
    /// silently dropping a CA file, client cert, proxy, posture wrapper or token
    /// would connect with weaker (or simply broken) settings than configured.
    /// Mirrors `inProcessSSHSupports`.

    /// Whether "Run In-Process" will ACTUALLY be honoured for this config — the
    /// single honesty gate behind the editor's caveats, in the shape
    /// `sshPinBlockReason` established. The toggle asking for it is not the same
    /// as getting it: any option the bridge can't express sends the connection
    /// back to the subprocess (with its SOCKS proxy), and the editor says which.
    ///
    /// IT WAS LYING FOR FOUR KINDS, and this is the fix. It answered
    /// `kind.isSSLVPN && preferInProcess && supports`, while `connect` additionally
    /// required the kind to be one of the three the bridge is wired for — so a
    /// GlobalProtect, Juniper, Pulse or Array config with the toggle on was told, by the
    /// editor's own caveat, that it "is carried as a full system tunnel — no SOCKS proxy
    /// is opened", and then ran as an `openconnect` subprocess with a SOCKS proxy. Found
    /// by grouping the connect list on what a connection does to the Mac: the grouping
    /// asks this predicate, and the answer disagreed with the connect path.
    ///
    /// THERE IS NO PER-KIND ALLOW-LIST, and adding one back would re-introduce the bug.
    /// The narrowing that used to live in `connect` was never a statement about what the
    /// engine can carry — `PacketTunnelProvider.startTunnel` dispatches on
    /// `VPNKind.openconnectProtocol`, which is non-nil for all seven SSL-VPN kinds, so the
    /// extension has always handled every one of them. The three-kind list was simply a
    /// stale hand-maintained copy of "which kinds we got round to", and it is what made
    /// GlobalProtect, Juniper, Pulse and Array demand Homebrew for nothing. What the
    /// bridge genuinely cannot carry is a matter of SETTINGS, not kinds, and that is
    /// `inProcessOpenConnectSupports`'s job alone.
    ///
    /// Older profiles can request browser sign-in for a protocol that only supports
    /// password sign-in. The connect dispatcher uses the tool for that fallback.
    static func willRunInProcess(_ c: SubprocessTunnelConfig) -> Bool {
        c.kind.isSSLVPN && c.runsInProcess && inProcessOpenConnectSupports(c)
            && (c.authMode != "sso" || c.kind.supportsExternalBrowserSSO)
    }

    static func virtualOpenConnectProblem(_ config: SubprocessTunnelConfig) -> String? {
        guard config.kind.supportsSharedOpenConnect, willRunInProcess(config) else {
            return "Choose a shared-interface transport supported by this SSL VPN profile."
        }
        if config.kind != .ciscoAnyConnect && !config.disableDTLS {
            return "Turn off UDP transport to route this SSL VPN over HTTPS on a shared interface."
        }
        if [.juniper, .pulse, .arrayNetworks].contains(config.kind), openconnectAuthMode(config) != "password" {
            return "This shared SSL VPN requires password sign-in. Connect the profile independently for other methods."
        }
        if config.kind == .arrayNetworks && config.realm.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
            return "Enter the Array VPN authentication realm before sharing this connection."
        }
        if let reason = addressCredentialReason(config) ?? sslAuthBlockReason(config) { return reason }
        let mode = openconnectAuthMode(config)
        guard ["password", "certificate", "sso"].contains(mode), config.authMode != "sso" || mode == "sso", !config.needsOneTimeCode || mode == "sso",
              !config.allowsLocalNetworkAccess, inProcessProxyURL(for: config) == nil, !config.enablePFS else {
            return "This SSL VPN’s sign-in, proxy, local network or forward-secrecy settings require an independent connection."
        }
        return nil
    }

    /// An enabled built-in profile can fall back to ocproxy at connection time.
    /// A profile present only in NetworkExtension uses its saved packet tunnel.
    static func openConnectRouteTargetProblem(config: SubprocessTunnelConfig?, session: Live?) -> String? {
        if let session, session.socksPort != nil, session.status == .connecting || session.status == .connected {
            return "This connection uses a SOCKS proxy. Reconnect with the built-in VPN engine to route destinations through it."
        }
        if let config, !willRunInProcess(config) {
            return "These settings use a SOCKS proxy. Choose settings supported by the built-in VPN engine to route destinations through it."
        }
        return nil
    }

    /// The settings the bridge can't carry — and ONLY those. Eleven clauses used to
    /// live here, and eight of them were not statements about libopenconnect at all:
    /// they were settings nobody had plumbed through `OCClientSettings`. Each one
    /// cost the whole routing story, because the fallback (`ocproxy -D <port>`) is a
    /// SOCKS listener with no interface, no routes and no DNS. They are plumbed now
    /// — `OpenConnectProfileStore.start` → `PacketTunnelProvider.startOpenConnect` →
    /// `OpenConnectBridge.runSession`, one `openconnect_set_*` call each — and
    /// `InProcessOpenConnectCoverageTests` proves every one reaches the bridge.
    ///
    /// THREE REMAIN, and each is a real limit rather than unfinished work:
    ///
    ///  1. **Host checker / endpoint posture** (`csdWrapper`, `disableCSD`).
    ///     `openconnect_setup_csd` exists, but it works by *forking a child* — the
    ///     gateway's trojan, or the wrapper standing in for it. The packet-tunnel
    ///     extension is `com.apple.security.app-sandbox` AND runs as root, so this
    ///     would mean executing a user-nominated script as root from inside the
    ///     sandbox. Not a plumbing job; a decision with an entitlement attached.
    ///  2. **Base MTU** (`baseMTU`) and **HTTP keepalive off** (`noHTTPKeepalive`).
    ///     `--base-mtu` and `--no-http-keepalive` write `vpninfo->basemtu` /
    ///     `->no_http_keepalive` directly from OpenConnect's own CLI. The library
    ///     header exposes no setter for either (`openconnect_set_reqmtu` is `--mtu`,
    ///     a different number — see the MTU pair in `SettingRelations`).
    ///  3. **Extra arguments** (`extraArgs`). Arbitrary argv has no in-process
    ///     equivalent by construction: the escape hatch's whole value is that it
    ///     passes through un-interpreted, and parsing "a known subset" would mean
    ///     silently ignoring the rest — the one thing this predicate exists to
    ///     prevent. It stays a documented fallback to the tool.
    ///
    /// **SMARTCARD SIGN-IN USED TO BE CLAUSE 1**, and it was the reason the
    /// subprocess path existed for SSL VPNs at all: it was the one thing the tool
    /// could do that the engine could not, whatever the xcframework was configured
    /// with. It is gone — the feature was removed rather than fixed, because it was
    /// built against no real token and no real gateway — so a smartcard profile is
    /// now refused by `sslAuthBlockReason` before this predicate is ever asked, and
    /// the subprocess is a fallback for four ordinary settings and nothing more.
    /// `Docs/AuthSecPKCS11.md` is the record of why, including why a GnuTLS/p11-kit
    /// rebuild would not have helped (AMFI forbids the `dlopen` p11-kit exists to do).
    /// The soft-token seed (`tokenMode`) was the other, for its own reasons, and it
    /// is refused in the same place.
    ///
    /// A clause may only be deleted once the setting is genuinely CARRIED. Dropping
    /// a CA file, a client certificate or a proxy silently would connect with
    /// weaker — or simply broken — settings than the profile asks for.
    private static func inProcessOpenConnectSupports(_ c: SubprocessTunnelConfig) -> Bool {
        if c.disableCSD || !c.csdWrapper.isEmpty { return false }
        if c.baseMTU != nil || c.noHTTPKeepalive { return false }
        // A compression mode OpenConnect hasn't got. The tool refuses it at startup
        // too; the engine declines to guess which of the three it meant.
        if SubprocessTunnelConfig.compressionProblem(c.ocCompression) != nil { return false }
        // A reported OS the library would refuse — same reasoning.
        if SubprocessTunnelConfig.spoofOSProblem(c.spoofOS) != nil { return false }
        if c.extraArgs.contains(where: { !$0.trimmingCharacters(in: .whitespaces).isEmpty }) { return false }
        return true
    }

    // MARK: What the in-process engine is told
    //
    // ONE PLACE that maps a config onto the bridge's settings, split by whether a
    // value is a secret. Everything non-secret rides `providerConfiguration` (which
    // PERSISTS in NE preferences, so it may hold paths, hostnames and usernames —
    // the same class of thing `server` and `realm` already do, and nothing more);
    // every secret rides `startTunnel(options:)` in memory only, because the
    // extension is root and cannot read the user's keychain. That split is the
    // invariant in Docs/Networking.md §1 and it is not negotiable per setting.
    //
    // Why here rather than in OpenConnectProfileStore: `inProcessOpenConnectSupports`
    // decides which settings must be carried, and a mapping that lives beside it can
    // be held to it by one test (`InProcessOpenConnectCoverageTests`). When the two
    // were apart, the gate said "the bridge can't take a CA file" while the bridge
    // had called `openconnect_set_cafile` for months — nobody had passed it one.

    /// The non-secret half of an in-process session, as `providerConfiguration`.
    /// Keys are consumed by `PacketTunnelProvider.startOpenConnect`.
    static func inProcessConfiguration(_ c: SubprocessTunnelConfig, previous: [String: Any]? = nil) -> [String: Any] {
        var conf: [String: Any] = ["profile": c.id,
                                   "vpnType": c.kind.rawValue,
                                   // The port lives INSIDE the address: the bridge
                                   // hands this to `openconnect_parse_url`, which
                                   // takes `host:port` (and `openconnect_get_port`
                                   // reads it back). There is no separate setter.
                                   "server": serverURL(for: c)]
        if previous?["profile"] as? String == c.id {
            for key in ["routingRules", "routingIncludes", "customrouting"] {
                if let routes = previous?[key] as? Data { conf[key] = routes }
            }
        }
        func put(_ key: String, _ value: String) {
            let t = value.trimmingCharacters(in: .whitespacesAndNewlines)
            if !t.isEmpty { conf[key] = t }
        }
        func path(_ key: String, _ value: String) {
            let t = value.trimmingCharacters(in: .whitespacesAndNewlines)
            if !t.isEmpty { conf[key] = (t as NSString).expandingTildeInPath }
        }
        put("realm", c.realm)
        put("serverCert", c.trustedCertSHA256)
        put("samlBrowser", c.samlBrowser)
        path("caFile", c.caFile)
        // `--usergroup` is the URL PATH openconnect appends — GlobalProtect's
        // portal-vs-gateway choice, the path Juniper and Pulse expect. Hence
        // `openconnect_set_urlpath`, not a setting of its own.
        put("urlPath", c.usergroup)
        put("reportedOS", c.spoofOS)
        put("versionString", c.versionString)
        put("localName", c.localHostname)
        put("userAgent", c.userAgent)
        // Certificate sign-in only, exactly as the argv builder gates it: a stale
        // path must not turn a password tunnel into certificate auth.
        if openconnectAuthMode(c) == "certificate" {
            path("clientCert", c.clientCertFile)
            path("clientKey", c.clientKeyFile)
        }
        // The proxy the gateway is reached THROUGH. `.systemDefault` is resolved
        // here, in the user's context, because the root extension sees a different
        // SystemConfiguration view — and because leaving it unresolved is how the
        // in-process path came to ignore the app's own default proxy mode entirely.
        if let proxy = inProcessProxyURL(for: c) {
            conf["proxy"] = proxy
            put("proxyUsername", c.proxyUsername)
        }
        if !c.ocCompression.isEmpty { conf["compression"] = c.ocCompression }
        if c.enablePFS { conf["pfs"] = true }
        if c.disableIPv6 { conf["disableIPv6"] = true }
        if c.disableDTLS { conf["disableDTLS"] = true }
        if let m = c.ocMTU { conf["mtu"] = m }
        if let d = c.forceDPD { conf["dpd"] = d }
        if let t = c.reconnectTimeout { conf["reconnectTimeout"] = t }
        // "Allow local network access". The TOGGLE travels in the (persisted)
        // provider configuration; the PREFIXES travel in the session, because they
        // are a fact about which networks this Mac is on right now and the extension
        // is sandboxed (Docs/Networking.md §4.2.1). Only written when on, so the
        // absent key means "off" in the extension exactly as `nil` does here.
        if c.allowsLocalNetworkAccess { conf["localLan"] = true }
        return conf
    }

    /// The secret half, as `startTunnel(options:)`. Read from the keychain at
    /// connect time and never retained.
    ///
    /// The saved proxy password opt-in applies to the external tool. The built-in
    /// engine receives the saved password in its private session options.
    static func inProcessSecrets(_ c: SubprocessTunnelConfig) -> [String: NSObject] {
        var options: [String: NSObject] = [:]
        if openconnectAuthMode(c) == "certificate",
           let kp = KeychainCredentialStore.loadCredentials(profile: "tunnel.\(c.id).privateKey")?.password,
           !kp.isEmpty {
            options["privateKeyPassword"] = kp as NSString
        }
        if inProcessProxyURL(for: c) != nil, !c.proxyUsername.isEmpty,
           let pw = KeychainCredentialStore.loadCredentials(profile: "tunnel.\(c.id).proxy")?.password,
           !pw.isEmpty {
            options["proxyPassword"] = pw as NSString
        }
        return options
    }

    /// The proxy URL for the in-process path — credentials NEVER inside it (they go
    /// through `openconnect_set_proxy_auth`-adjacent fields separately), unlike
    /// `proxyArgument(for:)` which has no choice.
    private static func inProcessProxyURL(for c: SubprocessTunnelConfig) -> String? {
        switch c.proxyMode {
        case .none: return nil
        case .manual:
            let raw = c.proxyURL.trimmingCharacters(in: .whitespacesAndNewlines)
            return raw.isEmpty ? nil : raw
        case .systemDefault: return systemProxyURL()
        }
    }

    /// The bundled engine can answer password and token form fields separately.
    /// The legacy command-line fallback only has one stdin secret; if a code was
    /// supplied it receives the conventional combined value. F5's distinct fields
    /// therefore stay distinct on the normal in-process path.
    private func passwordForSubprocess(_ config: SubprocessTunnelConfig,
                                       password: String?, oneTimeCode: String?) -> String? {
        guard let password, let oneTimeCode,
              !oneTimeCode.isEmpty else { return password }
        return password + oneTimeCode
    }

    private func connectInProcessOpenConnect(_ config: SubprocessTunnelConfig, password: String?,
                                             oneTimeCode: String?) {
        let attempt = UUID()
        packetAttempts[config.id] = attempt
        inProcessNE.insert(config.id)
        live[config.id] = Live(status: .connecting)
        Task { [weak self] in
            // `true` means "started", not "connected" — real progress (connecting /
            // connected / auth failure) arrives via NEVPNStatusDidChange events.
            let result = await OpenConnectProfileStore.start(config, password: password,
                                                          oneTimeCode: oneTimeCode, coordinator: self?.gatewayCoordinator, stillCurrent: { [weak self] in self?.packetAttempts[config.id] == attempt }) { [weak self] event in
                guard self?.packetAttempts[config.id] == attempt else { return }
                self?.handleInProcessEvent(config.id, event)
            }
            guard let self, packetAttempts[config.id] == attempt else { return }
            if case .refused(let reason) = result {
                packetAttempts.removeValue(forKey: config.id)
                self.inProcessNE.remove(config.id)
                self.live[config.id] = Live(status: .failed(reason))
            }
        }
    }

    private func handleInProcessEvent(_ id: String, _ event: OpenConnectProfileStore.Event) {
        // The user may have disconnected while an event was in flight — don't
        // resurrect state for a session we already tore down.
        guard inProcessNE.contains(id) else { return }
        var l = live[id] ?? Live()
        switch event {
        case .connecting:
            l.status = .connecting
        case .connected:
            l.status = .connected
        case .disconnected:
            l.status = .disconnected
            inProcessNE.remove(id)
            packetAttempts.removeValue(forKey: id)
        case .failed(let why):
            l.status = .failed(why)
            inProcessNE.remove(id)
            packetAttempts.removeValue(forKey: id)
        }
        live[id] = l
    }

    // MARK: SSO sign-in via ocauth-helper

    /// Sign in through the bundled `ocauth-helper` (conversational libopenconnect
    /// in user context), then connect with the returned cookie. Stored
    /// credentials answer gateway forms silently where they match; the SSO URL
    /// opens in the profile's chosen browser; an unverifiable server certificate
    /// is refused (never auto-accepted) with pinning guidance in the failure.
    private func connectSSO(_ config: SubprocessTunnelConfig, password: String?) {
        guard OpenConnectAuthClient.helperURL != nil else {
            live[config.id] = Live(status: .failed(OpenConnectAuthError.helperMissing.localizedDescription))
            return
        }
        live[config.id] = Live(status: .connecting)
        let storedPassword = password
            ?? KeychainCredentialStore.loadCredentials(profile: "tunnel.\(config.id)")?.password
        let username = config.username
        let browser = BrowserDefaults.resolve(config.browser)
        let handlers = OpenConnectAuthClient.Handlers(
            answerForm: { form in
                let filled = OCAuthFormAutofill.fill(form, username: username, password: storedPassword,
                                                      realm: config.realm, vpnProtocol: config.kind.openconnectProtocol)
                guard filled.unanswered.isEmpty else {
                    return .cancel(unanswered: filled.unanswered.map(\.label))
                }
                return .answers(filled.answers)
            },
            openURL: { url in
                await MainActor.run {
                    guard let target = URL(string: url) else { return }
                    BrowserCatalog.open(target, using: browser)
                }
            },
            // decideCert keeps its default: REFUSE. authenticate() turns the
            // refusal into a certUntrusted failure naming the pin to configure.
            progress: { [weak self] line in
                Task { @MainActor [weak self] in self?.appendLog(config.id, line) }
            })
        let task = Task { [weak self] in
            do {
                let done = try await OpenConnectAuthClient.authenticate(
                    start: Self.authStart(for: config), handlers: handlers)
                guard let self, !Task.isCancelled, self.authTasks[config.id] != nil else { return }
                self.authTasks[config.id] = nil
                self.connectWithCookie(config, auth: done)
            } catch {
                guard let self, !Task.isCancelled, self.authTasks[config.id] != nil else { return }
                self.authTasks[config.id] = nil
                var l = self.live[config.id] ?? Live()
                l.status = .failed(error.localizedDescription)
                self.live[config.id] = l
            }
        }
        authTasks[config.id] = task
    }

    /// Fetch the gateway's first real authentication form without attempting a
    /// sign-in. `ocauth-helper` drives libopenconnect through the same HTTPS and
    /// certificate checks as a connection, stops once it receives `oc_auth_form`,
    /// and returns its labels/types to the main-window sign-in card. This is how an
    /// F5 APM profile learns whether it has a separate token field instead of
    /// relying on a remembered checkbox.
    func discoverSignInForm(for config: SubprocessTunnelConfig) async throws -> OCAuthFormSpec {
        guard config.kind.isSSLVPN else { throw OpenConnectAuthError.badReply }
        let capture = OpenConnectFormCapture()
        let handlers = OpenConnectAuthClient.Handlers(
            answerForm: { form in
                await capture.set(form)
                return .cancel(unanswered: form.fields.map(\.label))
            },
            openURL: { _ in },
            progress: { [weak self] line in
                Task { @MainActor [weak self] in self?.appendLog(config.id, line) }
            })
        do {
            _ = try await OpenConnectAuthClient.authenticate(
                start: Self.authStart(for: config), handlers: handlers)
        } catch {
            if let form = await capture.get() { return form }
            throw error
        }
        guard let form = await capture.get() else { throw OpenConnectAuthError.badReply }
        return form
    }

    private func appendLog(_ id: String, _ line: String) {
        guard var l = live[id] else { return }
        l.log.append(line)
        if l.log.count > 300 { l.log.removeFirst(l.log.count - 300) }
        live[id] = l
    }

    /// The helper's start request for a config — the same auth-time knobs the
    /// retired `openconnect --external-browser` argv carried, now over the
    /// helper's private stdin (so even the proxy URL's credentials stay off argv).
    static func authStart(for c: SubprocessTunnelConfig) -> OCAuthStart {
        var p = OCAuthParams()
        func set(_ keyPath: WritableKeyPath<OCAuthParams, String?>, _ value: String) {
            if !value.isEmpty { p[keyPath: keyPath] = value }
        }
        set(\.username, c.username)
        set(\.realm, c.realm)
        set(\.usergroup, c.usergroup)
        set(\.servercert, c.trustedCertSHA256)
        set(\.cafile, (c.caFile as NSString).expandingTildeInPath)
        set(\.useragent, c.userAgent)
        set(\.reportedOS, c.spoofOS)
        set(\.versionString, c.versionString)
        set(\.localHostname, c.localHostname)
        if let proxy = proxyArgument(for: c) { p.proxy = proxy }
        if !c.clientCertFile.isEmpty || !c.clientKeyFile.isEmpty {
            set(\.certFile, (c.clientCertFile as NSString).expandingTildeInPath)
            set(\.keyFile, (c.clientKeyFile as NSString).expandingTildeInPath)
            set(\.keyPassword,
                KeychainCredentialStore.loadCredentials(profile: "tunnel.\(c.id).privateKey")?.password ?? "")
        }
        return OCAuthStart(server: serverURL(for: c),
                           vpnProtocol: c.kind.openconnectProtocol ?? "anyconnect",
                           params: p)
    }

    /// Carry a signed-in session (cookie + exact cert + connect URL) to a
    /// transport: the in-process NE engine when the config opted in and the
    /// bridge covers its settings, otherwise the openconnect subprocess with
    /// `--cookie-on-stdin` (no sign-in left to do — and no sysext required,
    /// preserving the no-root SOCKS path SSO configs had before).
    private func connectWithCookie(_ config: SubprocessTunnelConfig, auth: OCAuthDone) {
        // The same one predicate as the password path — see `willRunInProcess`. Reached
        // only with `authMode == "sso"` on a kind that really does browser sign-in, which
        // is why no SSO clause is needed inside the predicate itself.
        if Self.willRunInProcess(config) {
            let attempt = UUID()
            packetAttempts[config.id] = attempt
            inProcessNE.insert(config.id)
            var l = live[config.id] ?? Live()
            l.status = .connecting
            live[config.id] = l
            Task { [weak self] in
                let result = await OpenConnectProfileStore.start(config, password: nil, auth: auth, coordinator: self?.gatewayCoordinator, stillCurrent: { [weak self] in self?.packetAttempts[config.id] == attempt }) { [weak self] event in
                    guard self?.packetAttempts[config.id] == attempt else { return }
                    self?.handleInProcessEvent(config.id, event)
                }
                guard let self, packetAttempts[config.id] == attempt else { return }
                if case .refused(let reason) = result {
                    packetAttempts.removeValue(forKey: config.id)
                    self.inProcessNE.remove(config.id)
                    self.live[config.id] = Live(status: .failed(reason))
                }
            }
            return
        }
        connectSubprocess(config, password: nil, command: Self.cookieCommand(for: config, auth: auth))
    }

    /// The in-process libssh engine speaks plain host + auth + local listeners. Any
    /// knob it can't express must route to /usr/bin/ssh instead — silently
    /// dropping a jump host would dial the target directly and bypass the
    /// bastion, and raw ssh_config options would just be ignored.
    /// (Certificate, Kerberos, kex preference and the host-key pin all ride
    /// in-process since the libssh migration; keepalive and compression now do
    /// too — `SSHTunnelEngine.Config.keepaliveInterval` / `.compression` — so
    /// neither forces the subprocess any more.)
    ///
    /// TWO CLAUSES, and they are different in kind. A **jump host** is missing work
    /// with a known shape: a nested session (authenticate to the bastion, open a
    /// direct-tcpip channel to the target, hand that channel's fd to a second
    /// session through `SSH_OPTIONS_FD`). **`sshExtraOptions`** is not missing work
    /// at all — arbitrary ssh_config keywords have no in-process equivalent by
    /// construction, exactly as `extraArgs` has none for OpenConnect: honouring "a
    /// known subset" would mean silently ignoring the rest, which is the one thing
    /// this predicate exists to prevent. Both of them can change the DATA path (a
    /// bastion is where the bytes go; `ProxyCommand`, `Tunnel`, `Ciphers` rewrite
    /// how they get there), which is why neither may be waved through.
    ///
    /// Mode is deliberately NOT considered here — see `willRunInProcessSSH`, which
    /// composes this with the per-mode question and is what callers should ask.
    static func inProcessSSHSupports(_ c: SubprocessTunnelConfig) -> Bool {
        if c.useJumpHost, !c.jumpHost.isEmpty { return false }
        if c.sshExtraOptions.contains(where: { !$0.trimmingCharacters(in: .whitespaces).isEmpty }) { return false }
        return true
    }

    /// Whether an SSH tunnel will ACTUALLY be carried by the in-process libssh
    /// engine — the single rule `connect` dispatches on and `sshPinBlockReason`
    /// refuses by, in the shape `willRunInProcess` established for the SSL kinds.
    /// One predicate, because two spellings of "will this run in-process?" is how
    /// the OpenConnect surface came to tell users one thing and do another.
    ///
    /// Per mode:
    ///  • `.socks` — always, since the libssh migration.
    ///  • `.portForward` — yes for **-L** and **-D**, which are the same direct-tcpip
    ///    pump the SOCKS path uses and the same code the live add/remove path has run
    ///    for months. NOT for **-R**, which is not supported in-process yet: a reverse
    ///    forward has the SERVER listening on our behalf, needing
    ///    `ssh_channel_listen_forward` / `ssh_channel_open_forward_port` in `SSHBridge`
    ///    plus an accept poll on the session queue, and the bridge has neither. Such a
    ///    profile keeps running /usr/bin/ssh, which really does support it — a routing
    ///    decision, not a silent downgrade.
    ///  • `.netTunnel` — OpenSSH opens a separate tunnel device. Both the UI and
    ///    the manager refuse the mode, including programmatic connection attempts.
    ///
    /// An UNPARSEABLE forward line answers false so the config reaches the one place
    /// that refuses it by name (`connect`'s `invalidForwardLine` guard) rather than
    /// being quietly skipped by an engine that only sees parsed specs.
    static func willRunInProcessSSH(_ c: SubprocessTunnelConfig) -> Bool {
        guard c.kind == .ssh else { return false }
        switch c.sshMode {
        case .socks:
            break
        case .portForward:
            for line in c.forwards {
                let t = line.trimmingCharacters(in: .whitespaces)
                guard !t.isEmpty else { continue }
                guard let fw = parseForward(t) else { return false }
                if fw.flag == "R" { return false }
            }
        case .netTunnel:
            return false
        }
        return inProcessSSHSupports(c)
    }

    /// The tunnel's sign-in method, normalized: "" = automatic.
    static func sshAuthMethod(_ c: SubprocessTunnelConfig) -> String {
        (c.sshAuthMethod ?? "").trimmingCharacters(in: .whitespaces)
    }

    /// The agent socket this tunnel should ask, tilde-expanded, or nil for
    /// "whatever this process inherited". BOTH connect paths need it and neither
    /// may guess: in-process it becomes libssh's `SSH_OPTIONS_IDENTITY_AGENT`, and
    /// for /usr/bin/ssh it becomes the child's `SSH_AUTH_SOCK` (ssh has no
    /// command-line form of `IdentityAgent`, only the config keyword).
    static func sshAgentSocket(_ c: SubprocessTunnelConfig) -> String? {
        let raw = (c.sshAgentSocket ?? "").trimmingCharacters(in: .whitespacesAndNewlines)
        return raw.isEmpty ? nil : (raw as NSString).expandingTildeInPath
    }

    /// Why the chosen sign-in method can't work as configured, or nil. The
    /// single rule the editor's Connect button and connect() both consult, so
    /// a doomed sign-in is refused with its fix rather than failing downstream.
    static func sshAuthBlockReason(_ c: SubprocessTunnelConfig) -> String? {
        // A malformed agent socket path blocks the existing CLI-capable methods: automatic
        // sign-in asks the agent too, so a path neither connect path can use is a
        // problem before the method is even considered.
        // Keychain sign-in is in-process only and never uses the disabled agent row.
        if sshAuthMethod(c) != "keychain",
           let problem = SubprocessTunnelConfig.agentSocketProblem(c.sshAgentSocket ?? "") {
            return problem
        }
        switch sshAuthMethod(c) {
        case "keychain":
            guard willRunInProcessSSH(c) || c.sshTunConfiguration != nil else {
                return "Keychain keys require SOCKS proxy or local/dynamic port forwards without a jump host or extra SSH arguments."
            }
            guard let pem = KeychainCredentialStore.loadSSHPrivateKey(profile: c.id), !pem.isEmpty else {
                return "Import a private key into the user Keychain under Sign-In."
            }
            return nil
        case "key" where c.identityFile.trimmingCharacters(in: .whitespaces).isEmpty:
            return "Key sign-in needs an identity file — set it under Sign-In."
        case "certificate" where c.identityFile.trimmingCharacters(in: .whitespaces).isEmpty
            || (c.sshCertificateFile ?? "").trimmingCharacters(in: .whitespaces).isEmpty:
            return "Certificate sign-in needs both an identity file and a certificate file — set them under Sign-In."
        default:
            return nil
        }
    }

    /// The pinned host key, normalized to the bare lowercase hex the bridge
    /// compares — tolerates "SHA256:"/"sha256:" prefixes and stray whitespace.
    static func sshPinnedKey(_ c: SubprocessTunnelConfig) -> String? {
        guard var pin = c.sshPinnedHostKey?.trimmingCharacters(in: .whitespacesAndNewlines),
              !pin.isEmpty else { return nil }
        if let colon = pin.range(of: ":", options: .backwards) {
            pin = String(pin[colon.upperBound...])
        }
        return pin.lowercased()
    }

    /// Why a pinned-host-key config can't connect right now, or nil when it can.
    /// The single rule the editor's caveat, the connect list and `connect` all use.
    ///
    /// THE REASON THIS GATE EXISTS is one fact about the other path, and it is worth
    /// stating because the gate looks like paranoia otherwise: **/usr/bin/ssh has no
    /// pin-by-hash option**. There is no `-o FingerprintSHA256=…`; the only trust
    /// input it takes is a known_hosts file. So a pinned profile that routed to the
    /// subprocess would connect with the pin UNCHECKED while the editor showed a pin
    /// — a security control that silently isn't one, which is strictly worse than
    /// not offering it. (`sshCommonOptions` says the same thing from the other side:
    /// the pin is deliberately absent from the argv it builds.) The in-process
    /// engine does check it, in `SSHBridge.verifyHostKeyWithKnownHosts:pin:strict:`,
    /// before authenticating.
    ///
    /// WHICH MAKES THE GATE EXACTLY "will this run in-process?" — nothing more. It
    /// used to spell that as `sshMode != .socks`, which was true only because
    /// port-forward mode had no in-process entry point; now that `.portForward`
    /// runs on the engine for -L/-D, an -L profile with a pin is enforceable and is
    /// no longer refused. The clause was never about SOCKS, and relaxing it here is
    /// correct precisely BECAUSE the premise ("the subprocess can't check a pin")
    /// still holds for everything it still refuses.
    static func sshPinBlockReason(_ c: SubprocessTunnelConfig) -> String? {
        guard c.kind == .ssh, sshPinnedKey(c) != nil else { return nil }
        guard !willRunInProcessSSH(c) else { return nil }
        // Which of the reasons it was, so the message names the setting to change.
        if c.sshMode == .netTunnel {
            return c.sshTunProblem
        }
        if !inProcessSSHSupports(c) {
            return "A pinned host key can't be combined with a jump host or extra options — those run through /usr/bin/ssh, which can't check the pin. Clear the pin under Security, or remove the conflicting option."
        }
        if c.sshMode == .portForward, invalidForwardLine(c.forwards) != nil {
            return "A pinned host key can't be enforced while a forward is invalid — fix the forward under Traffic, or clear the pin under Security."
        }
        return "A pinned host key can't be combined with a reverse forward (-R) — those aren't supported by the built-in engine yet, so the tunnel runs through /usr/bin/ssh, which has no pin-by-hash option. Remove the reverse forward, or clear the pin under Security."
    }

    private func connectInProcessSSH(_ config: SubprocessTunnelConfig, password: String?) {
        let engine = SSHTunnelEngine()
        sshEngines[config.id] = engine
        // WHAT THE TUNNEL OFFERS THE MAC, per mode — and only SOCKS mode offers a
        // port. `socksPort` is what surfaces the proxy in the UI and what
        // `setSystemProxyLive` points the system at, so setting it for a
        // port-forward tunnel would advertise a listener that was never opened.
        let inSOCKSMode = config.sshMode == .socks
        // Seed the per-forward states so the editor's row badges show the initial
        // set as pending until the engine confirms them. This is item 3 of the
        // in-process port-forward work: the subprocess path derives these by
        // SCRAPING ssh's output (`onLine`'s readiness marker flips pending→active),
        // and there is no output to scrape in-process, so the engine's own result
        // sets them directly below.
        let forwards: [(flag: String, spec: String)] = inSOCKSMode ? [] :
            config.forwards.compactMap { Self.parseForward($0.trimmingCharacters(in: .whitespaces)) }
        var initialForwards: [String: ForwardPhase] = [:]
        for fw in forwards { initialForwards["\(fw.flag) \(fw.spec)"] = .pending }
        live[config.id] = Live(status: .connecting,
                               socksPort: inSOCKSMode ? config.socksPort : nil,
                               forwardStates: initialForwards)
        var cfg = SSHTunnelEngine.Config(
            host: config.server, port: config.port ?? 22,
            // ssh defaults a blank user to the local account; authenticating as
            // "" would burn the whole in-process fallback timeout for nothing.
            username: config.username.isEmpty ? NSUserName() : config.username,
            password: password, identityFile: config.identityFile.isEmpty ? nil : config.identityFile,
            privateKeyPEM: Self.sshAuthMethod(config) == "keychain"
                ? KeychainCredentialStore.loadSSHPrivateKey(profile: config.id) : nil,
            certificateFile: (config.sshCertificateFile?.isEmpty == false) ? config.sshCertificateFile : nil,
            socksPort: config.socksPort,
            pinnedHostKeySHA256: Self.sshPinnedKey(config),
            strictHostKey: config.strictHostKey,
            connectTimeout: config.connectTimeout ?? 15,
            authMethod: Self.sshAuthMethod(config).isEmpty ? nil : Self.sshAuthMethod(config),
            agentSocketPath: Self.sshAgentSocket(config),
            kexAlgorithms: (config.sshKexAlgorithms?.trimmingCharacters(in: .whitespaces)).flatMap { $0.isEmpty ? nil : $0 },
            // ssh.keepalive and ssh.compression are honoured HERE now, not only by
            // /usr/bin/ssh: the engine arms a keepalive timer on its session queue
            // and asks for zlib at key exchange.
            keepaliveInterval: config.serverAliveInterval,
            compression: config.compression)
        cfg.routingEventSource = config.routingEventSource
        let configuration = cfg
        Task { [weak self] in
            do {
                // The ONLY difference between the two modes: which listeners the
                // engine opens once the session is up.
                if inSOCKSMode {
                    try await engine.startSOCKS(configuration)
                } else {
                    try await engine.startPortForwards(configuration, forwards: forwards)
                }
                guard let self else { return }
                // If the user disconnected while we were connecting, `disconnect`
                // already cleared the engine — don't resurrect a .connected status
                // (or a system-proxy pointing at) an orphaned listener.
                guard self.sshEngines[config.id] === engine else { engine.stop(); return }
                var l = self.live[config.id] ?? Live()
                l.status = .connected
                // `startPortForwards` is all-or-nothing (ssh's
                // ExitOnForwardFailure=yes), so reaching here means every seeded
                // row bound. Set them directly — the subprocess path reaches the
                // same state by scraping a readiness line off stdout.
                l.forwardStates = l.forwardStates.mapValues { $0 == .pending ? .active : $0 }
                if inSOCKSMode, self.wantsSystemProxy(config) {
                    self.systemSOCKS.request(config.id, port: config.socksPort)
                }
                self.live[config.id] = l
            } catch {
                // In-process failed → clean up and fall back to /usr/bin/ssh.
                guard let self else { return }
                engine.stop()
                // Only fall back if this engine is still the active one; a user
                // disconnect during connect must not spawn a zombie subprocess.
                guard self.sshEngines[config.id] === engine else { return }
                self.sshEngines[config.id] = nil
                // A pinned host key exists ONLY in-process — falling back to
                // /usr/bin/ssh would connect without checking the pin. Fail
                // with the engine's real reason instead.
                if Self.sshPinnedKey(config) != nil {
                    Self.log.error("in-process SSH failed with a pinned host key — not falling back: \(error.localizedDescription, privacy: .public)")
                    self.live[config.id] = Live(status: .failed(error.localizedDescription))
                    return
                }
                Self.log.error("in-process SSH failed, falling back to subprocess: \(error.localizedDescription, privacy: .public)")
                self.live[config.id] = nil
                self.connectSubprocess(config, password: password)
            }
        }
    }

    /// `command` overrides the built argv — the cookie transport
    /// (`cookieCommand(for:auth:)`) supplies its own; everything else (readiness
    /// markers, log, SOCKS surfacing, exit handling) is shared.
    private func connectSubprocess(_ config: SubprocessTunnelConfig, password: String?,
                                   command: (String, [String], Data?)? = nil,
                                   reverse: OpenSSHReverseDelivery? = nil) {
        guard tasks[config.id] == nil else { reverse?.stop(); return }
        if config.kind == .ssh, reverse == nil {
            let source = config.routingEventSource ?? ""
            guard let layout = OpenSSHReverseDelivery.layout(for: config) else {
                live[config.id] = Live(status: .failed("This SSH profile cannot route its forwards. Use fixed local, dynamic, or fixed remote TCP forwards and remove extra options that open channels or run commands."))
                return
            }
            live[config.id] = Live(status: .connecting)
            authTasks[config.id] = Task { [weak self] in
                do {
                    let prepared = try await Task.detached(priority: .userInitiated) {
                        let session = try OpenSSHReverseDelivery(layout: layout, source: source)
                        try await session.startListeners()
                        return session
                    }.value
                    guard let self, !Task.isCancelled else { prepared.stop(); return }
                    self.authTasks[config.id] = nil
                    self.connectSubprocess(config, password: password, reverse: prepared)
                } catch {
                    guard let self, !Task.isCancelled else { return }
                    self.authTasks[config.id] = nil
                    self.live[config.id] = Live(status: .failed(error.localizedDescription))
                }
            }
            return
        }
        // (An invalid forward line is refused in `connect`, before the dispatch —
        // both paths need that check now, so it lives in the one place both reach.)
        guard let (path, baseArgs, stdin) = command
                ?? Self.command(for: config, password: password) else {
            // Name the tool and the fix — "the required command-line tool" sends
            // nobody anywhere (ONTOLOGY: failure text names the fix).
            reverse?.stop()
            live[config.id] = Live(status: .failed(Self.missingToolReason(config)))
            return
        }
        var args = baseArgs
        if let reverse {
            // Explicit profile settings only. No inherited forwards or shared
            // master may bypass the private endpoints authorized by the policy.
            args = ["-F", "/dev/null", "-N", "-S", "none", "-o", "ControlMaster=no"]
                + Self.sshCommonOptions(config) + reverse.forwardArguments + ["--", Self.sshTarget(config)]
        }
        var privateConfig: Data?
        if config.kind.isSSLVPN {
            let passphrase = command == nil && Self.openconnectAuthMode(config) == "certificate"
                ? KeychainCredentialStore.loadCredentials(profile: "tunnel.\(config.id).privateKey")?.password : nil
            do {
                privateConfig = try Self.openconnectPrivateConfig(keyPassphrase: passphrase,
                                                                 proxy: Self.proxyArgument(for: config))
            } catch {
                live[config.id] = Live(status: .failed(error.localizedDescription))
                return
            }
            if privateConfig != nil { args.insert("--config=/dev/fd/2", at: 0) }
        }
        // SSH runs as a ControlMaster so forwards can be added/cancelled live
        // (`ssh -S <socket> -O forward/cancel …`) without a reconnect.
        if config.kind == .ssh, reverse == nil, let socket = Self.makeControlSocketPath() {
            controlSockets[config.id] = socket
            args = ["-M", "-S", socket] + args
        }
        // Seed per-forward states so the editor shows the initial set as pending
        // until the session reports ready. (All lines are valid — see the guard.)
        var initialForwards: [String: ForwardPhase] = [:]
        if config.kind == .ssh, config.sshMode == .portForward {
            for line in config.forwards where !line.trimmingCharacters(in: .whitespaces).isEmpty {
                initialForwards[Self.forwardKey(line)] = .pending
            }
        }
        // Visible note when a stale SSO config lands here — the builder already
        // fell back to password (see command(for:)), say so instead of failing.
        var initialLog: [String] = live[config.id]?.log ?? []   // keep the sign-in conversation's log
        if command == nil, config.authMode == "sso", !config.kind.supportsExternalBrowserSSO {
            initialLog.append("Single sign-on isn't available for \(config.kind.displayName) — signing in with the saved password instead.")
        }
        live[config.id] = Live(status: .connecting,
                               socksPort: (config.kind == .ssh && config.sshMode == .socks) || usesOcproxy(config) ? config.socksPort : nil,
                               log: initialLog,
                               forwardStates: initialForwards)

        var askpass: SSHAskpass?
        var askpassPath: String?
        if config.kind == .ssh {
            func credential(_ user: String, _ host: String, _ secret: String?) -> SSHAskpass.Credential? {
                guard let secret, !secret.isEmpty else { return nil }
                let identity = (user.isEmpty ? NSUserName() : user) + "@" + host
                return SSHAskpass.Credential(identity: identity, password: secret)
            }
            let target = credential(config.username, config.server, password)
            let jump = config.useJumpHost && !config.jumpHost.isEmpty
                ? credential(config.jumpUsername, config.jumpHost, KeychainCredentialStore.loadCredentials(
                    profile: "tunnel.\(config.id).jump")?.password) : nil
            if target != nil || jump != nil {
                do {
                    guard let tool = CLIInstaller.bundledToolPath else { throw POSIXError(.ENOENT) }
                    askpassPath = tool
                    askpass = try SSHAskpass(target: target, jump: jump)
                } catch {
                    reverse?.stop()
                    removeControlSocket(config.id)
                    live[config.id] = Live(status: .failed("Couldn't prepare a private password prompt for SSH: \(error.localizedDescription)"))
                    return
                }
            }
        }

        var executable = path
        if reverse != nil {
            let client = Bundle.main.bundleURL.appendingPathComponent("Contents/Helpers/ssh")
            do { try Installation.verify(client, identifier: "com.bragi0.SimpleVPN.ssh") }
            catch {
                reverse?.stop()
                live[config.id] = Live(status: .failed("SimpleVPN could not verify its OpenSSH client. Reinstall SimpleVPN."))
                return
            }
            executable = client.path
        }
        var input = stdin
        var proxyReady: String?
        if config.kind.isSSLVPN {
            guard let proxy = TunnelCLI.ocproxy.resolvedPath else {
                live[config.id] = Live(status: .failed("Install ocproxy to open this connection’s local SOCKS port."))
                return
            }
            do {
                let relay = try Self.superviseOpenConnect(config, client: path, proxy: proxy, args: args, input: stdin)
                executable = relay.path
                args = relay.args
                input = relay.input
                proxyReady = relay.ready
            } catch {
                live[config.id] = Live(status: .failed(error.localizedDescription))
                return
            }
        }
        let proc = TunnelProcess(
            path: executable, args: args, stdin: input, privateConfig: privateConfig,
            askpass: askpass, askpassPath: askpassPath, requireRemoteForwardAck: reverse?.needsRemoteAcknowledgement == true, proxyReady: proxyReady,
            onOutput: { [weak self] process, lines, isReady in
                guard let self, self.tasks[config.id] === process else { return }
                var l = self.live[config.id] ?? Live()
                l.log.append(contentsOf: lines)
                if l.log.count > 300 { l.log.removeFirst(l.log.count - 300) }
                if isReady, l.status == .connecting {
                    l.status = .connected
                    // The initial argv forwards live or die with the session
                    // (ExitOnForwardFailure=yes) — ready means they all bound.
                    l.forwardStates = l.forwardStates.mapValues { $0 == .pending ? .active : $0 }
                    if let port = l.socksPort, self.wantsSystemProxy(config) {
                        self.systemSOCKS.request(config.id, port: port)
                    }
                }
                self.live[config.id] = l
            },
            onExit: { [weak self] process, code in
                guard let self, self.tasks[config.id] === process else { return }
                var l = self.live[config.id] ?? Live()
                // Restore only if WE pointed the system at this tunnel (and a
                // manual disconnect hasn't already restored it).
                self.systemSOCKS.request(config.id, port: nil)
                switch l.status {
                case .connecting:
                    l.status = .failed("Exited before connecting (code \(code)). Check the log.")
                case .connected:  l.status = .disconnected
                default: break
                }
                l.forwardStates = [:]
                self.live[config.id] = l
                self.tasks[config.id] = nil
                self.reverseSessions.removeValue(forKey: config.id)?.stop()
                self.removeControlSocket(config.id)
            })
        tasks[config.id] = proc
        if let reverse { reverseSessions[config.id] = reverse }
        proc.start()
        if let reverse, let process = proc.runningProcess, !reverse.authorize(process) {
            disconnect(config.id)
            live[config.id] = Live(status: .failed("Could not verify the OpenSSH process for the protected forwards."))
        }
    }

    func disconnect(_ id: String) {
        if let vpn = gatewayCoordinator, vpn.virtualManager(for: id) != nil {
            vpn.disconnect(id: id)
            return
        }
        // A sign-in still in flight: cancelling the task kills the helper
        // (OpenConnectAuthClient's cancellation handler), which also abandons
        // any browser page still waiting on the gateway.
        if let auth = authTasks.removeValue(forKey: id) { auth.cancel() }
        proxyToggleWhileConnecting[id] = nil
        systemSOCKS.request(id, port: nil)
        reverseSessions.removeValue(forKey: id)?.stop()
        tasks[id]?.stop()
        tasks[id] = nil
        sshEngines[id]?.stop()
        sshEngines[id] = nil
        if inProcessNE.remove(id) != nil {
            packetAttempts.removeValue(forKey: id)
            Task { [weak self] in
                await OpenConnectProfileStore.stop(id) { self?.packetAttempts[id] == nil }
            }
        }
        removeControlSocket(id)
        if var l = live[id] { l.status = .disconnected; l.forwardStates = [:]; live[id] = l }
    }

    /// Every OpenConnect kind gets `--script-tun --script "ocproxy -D <port>"`
    /// when ocproxy is installed (command(for:)) — so every one of them surfaces
    /// its SOCKS port, not just the original three.
    private func usesOcproxy(_ c: SubprocessTunnelConfig) -> Bool {
        c.kind.isSSLVPN && TunnelCLI.ocproxy.isAvailable
    }

    // MARK: Live forwards (edit while connected — no reconnect)

    /// Reconcile the live tunnel's forwards with `config.forwards`: adds new
    /// specs, cancels removed ones, retries failed ones. Invalid lines get a
    /// per-row `.failed` and never reach argv (same `parseForward` rules as
    /// connect). No-op unless the tunnel is connected SSH.
    func applyForwards(_ config: SubprocessTunnelConfig) {
        let id = config.id
        guard config.kind == .ssh, status(id) == .connected, var l = live[id] else { return }

        // The private endpoints and local targets form one immutable authorization
        // plan for this session. Never add a raw forward to its OpenSSH process.
        if reverseSessions[id] != nil {
            let desired = Set(config.forwards.filter { !$0.trimmingCharacters(in: .whitespaces).isEmpty }.map(Self.forwardKey))
            if desired != Set(l.forwardStates.keys) {
                disconnect(id)
                live[id] = Live(status: .failed("The protected reverse forwards changed. Reconnect to apply the new destinations."))
            }
            return
        }
        let previous = l.forwardStates
        var desired: [String: (flag: String, spec: String)] = [:]
        var states: [String: ForwardPhase] = [:]
        for line in config.forwards {
            let t = line.trimmingCharacters(in: .whitespaces)
            guard !t.isEmpty else { continue }
            if let fw = Self.parseForward(t) {
                let key = "\(fw.flag) \(fw.spec)"
                desired[key] = fw
                states[key] = previous[key] ?? .pending
            } else {
                states[t] = .failed("Invalid — “L localPort:host:port”, “R remotePort:host:port” or “D port”.")
            }
        }
        l.forwardStates = states
        live[id] = l

        // Cancel what's live but no longer wanted…
        for (key, phase) in previous where desired[key] == nil {
            guard phase == .active || phase == .pending, let fw = Self.parseForward(key) else { continue }
            cancelForward(config, fw)
        }
        // …and establish what's wanted but not yet live (retrying failures).
        for (key, fw) in desired {
            switch previous[key] {
            case .active, .pending: continue   // already live or in flight
            case .failed, nil: establishForward(config, fw, key: key)
            }
        }
    }

    private func wantsSystemProxy(_ config: SubprocessTunnelConfig) -> Bool {
        proxyToggleWhileConnecting.removeValue(forKey: config.id) ?? config.setSystemProxy
    }

    func setSystemProxyLive(_ config: SubprocessTunnelConfig, enabled: Bool) {
        let id = config.id
        if status(id) == .connecting {
            proxyToggleWhileConnecting[id] = enabled
        } else if status(id) == .connected, let port = live[id]?.socksPort {
            systemSOCKS.request(id, port: enabled ? port : nil)
        }
    }

    func recoverSystemProxyAfterCrash() async -> String? { await systemSOCKS.restore(afterCrash: true) }
    func restoreSystemProxyForQuit() async -> String? { await systemSOCKS.restore(afterCrash: false) }

    /// Canonical state key for a forward line: normalized "FLAG spec" when it
    /// parses, the trimmed line itself otherwise (so an invalid row can still
    /// carry its own error). The view uses the same key for row badges.
    static func forwardKey(_ line: String) -> String {
        let t = line.trimmingCharacters(in: .whitespaces)
        guard let fw = parseForward(t) else { return t }
        return "\(fw.flag) \(fw.spec)"
    }

    private func setForwardPhase(_ id: String, key: String, _ phase: ForwardPhase) {
        // The row may have been deleted while the op ran — don't resurrect it.
        guard var l = live[id], l.forwardStates[key] != nil else { return }
        l.forwardStates[key] = phase
        live[id] = l
    }

    private func establishForward(_ config: SubprocessTunnelConfig,
                                  _ fw: (flag: String, spec: String), key: String) {
        setForwardPhase(config.id, key: key, .pending)
        if let engine = sshEngines[config.id] {
            // In-process engine: -L/-D live; -R throws its "reconnect" message.
            Task { [weak self] in
                do {
                    try await engine.addForward(flag: fw.flag, spec: fw.spec)
                    guard let self else { engine.removeForward(key: key); return }
                    if self.live[config.id]?.forwardStates[key] != nil {
                        self.setForwardPhase(config.id, key: key, .active)
                    } else {
                        engine.removeForward(key: key)   // row deleted mid-flight — undo
                    }
                } catch {
                    self?.setForwardPhase(config.id, key: key, .failed(error.localizedDescription))
                }
            }
            return
        }
        guard let socket = controlSockets[config.id] else {
            setForwardPhase(config.id, key: key,
                            .failed("This session can't change forwards live — reconnect to apply."))
            return
        }
        let target = Self.sshTarget(config)
        Task { [weak self] in
            let r = await Task.detached {
                Self.controlOp(["-O", "forward", "-\(fw.flag)", fw.spec, "--", target], socket: socket)
            }.value
            if r.code == 0 {
                guard let self else { return }
                if self.live[config.id]?.forwardStates[key] != nil {
                    self.setForwardPhase(config.id, key: key, .active)
                } else {
                    self.cancelForward(config, fw)   // row deleted mid-flight — undo
                }
            } else {
                // Distinguish "forward refused" (port bound, bad spec) from
                // "control connection gone" for an honest row message.
                let alive = await Task.detached {
                    Self.controlOp(["-O", "check", "--", target], socket: socket).code == 0
                }.value
                let detail = r.output.split(whereSeparator: \.isNewline).last.map(String.init)
                let why = alive
                    ? (detail ?? "ssh refused the forward (exit \(r.code)).")
                    : "The SSH control connection isn't responding — reconnect."
                self?.setForwardPhase(config.id, key: key, .failed(why))
            }
        }
    }

    private func cancelForward(_ config: SubprocessTunnelConfig, _ fw: (flag: String, spec: String)) {
        if let engine = sshEngines[config.id] {
            engine.removeForward(key: "\(fw.flag) \(fw.spec)")
            return
        }
        guard let socket = controlSockets[config.id] else { return }
        let target = Self.sshTarget(config)
        Task {
            let r = await Task.detached {
                Self.controlOp(["-O", "cancel", "-\(fw.flag)", fw.spec, "--", target], socket: socket)
            }.value
            if r.code != 0 {
                Self.log.error("ssh -O cancel -\(fw.flag, privacy: .public) \(fw.spec, privacy: .public) failed: \(r.output, privacy: .public)")
            }
        }
    }

    // MARK: ControlMaster plumbing

    /// A short socket path (AF_UNIX caps paths around 104 bytes) inside a
    /// private 0700 directory; nil if it can't be created or is still too long.
    private static func makeControlSocketPath() -> String? {
        var template = Array("/private/tmp/svpn-cm.XXXXXX".utf8CString)
        guard let directory = mkdtemp(&template) else { return nil }
        return String(cString: directory) + "/ctl"
    }

    private func removeControlSocket(_ id: String) {
        guard let socket = controlSockets.removeValue(forKey: id) else { return }
        unlink(socket)
        rmdir((socket as NSString).deletingLastPathComponent)
    }

    /// Run `ssh -S <socket> -O …` against the ControlMaster and return its exit
    /// status + combined output. Mux ops answer over the local socket, but the
    /// callers still hop off the main actor (Task.detached) to run it.
    nonisolated private static func controlOp(_ args: [String], socket: String)
        -> (code: Int32, output: String) {
        guard let ssh = TunnelCLI.ssh.resolvedPath else { return (-1, "ssh isn't installed.") }
        let p = Process()
        p.executableURL = URL(fileURLWithPath: ssh)
        p.arguments = ["-S", socket] + args
        let pipe = Pipe()
        p.standardOutput = pipe
        p.standardError = pipe
        guard (try? p.run()) != nil else { return (-1, "Couldn't run ssh -O.") }
        let data = pipe.fileHandleForReading.readDataToEndOfFile()
        p.waitUntilExit()
        let text = (String(data: data, encoding: .utf8) ?? "")
            .trimmingCharacters(in: .whitespacesAndNewlines)
        return (p.terminationStatus, text)
    }

    // MARK: Command construction

    /// Returns (executable, argv, stdin-to-write) or nil when the tool is missing.
    ///
    /// The only secret in the return value is the stdin `Data` — the password, for
    /// the one mode that pipes one. It is never formatted into argv, never put in the
    /// environment and never written to a file. `TunnelProcess.start()` writes that
    /// data and closes the pipe immediately, so it exists in this process for the
    /// length of one `write(2)`.
    static func command(for c: SubprocessTunnelConfig, password: String?)
        -> (String, [String], Data?)? {

        switch c.kind {
        case .ssh:
            guard let ssh = TunnelCLI.ssh.resolvedPath else { return nil }
            var a = ["-N"] + sshCommonOptions(c)
            switch c.sshMode {
            case .socks:
                a += ["-D", "\(c.socksPort)"]
            case .portForward:
                for f in c.forwards where !f.trimmingCharacters(in: .whitespaces).isEmpty {
                    // Lines like "L 8080:internal:80" or "R 9090:localhost:9090".
                    // Invalid lines were rejected with a visible error before we
                    // got here (connectSubprocess); skip defensively regardless.
                    guard let fw = parseForward(f) else { continue }
                    a += ["-\(fw.flag)", fw.spec]
                }
            case .netTunnel:
                return nil // OpenSSH owns its device; the app only receives NE packet batches.
            }
            a += ["--", sshTarget(c)]
            return (ssh, a, nil)

        case _ where c.kind.isSSLVPN:
            // OpenConnect covers every SSL-VPN protocol (anyconnect / nc / gp /
            // pulse / f5 / fortinet / array), no root via ocproxy.
            if let oc = TunnelCLI.openconnect.resolvedPath {
                // The password is written to stdin ONLY when the argv asked for
                // it. In certificate mode nothing reads stdin, and that unread
                // write is what used to hang the connect (or surface as an
                // opaque certificate error).
                //
                let stdin: Data? = openconnectAuthMode(c) == "password"
                    ? password.map { Data(($0 + "\n").utf8) } : nil
                return (oc, openconnectArgs(for: c), stdin)
            }
            // No `openfortivpn` fallback for FortiGate any more, and it was never
            // reachable: `sslTransportBlockReason` refuses that exact combination
            // (pppd needs administrator rights this app doesn't take) *before* the
            // dispatch that would have got here. `libopenconnect` carries the
            // `fortinet` protocol in-process regardless — see the note on TunnelCLI.
            return nil

        default:
            return nil
        }
    }

    // MARK: OpenConnect sign-in method (the chosen method is the one used)

    /// The sign-in method the openconnect argv is built for, normalized:
    /// "password" | "certificate" | "sso". The picker's choice is authoritative —
    /// the builder no longer infers auth from whatever file paths happen to be
    /// filled in, which is what let stale certificate paths silently turn a
    /// "Password" tunnel into certificate authentication.
    ///
    /// "sso" only survives for kinds whose browser flow exists, and those never
    /// reach the builder (connect() routes them through the bundled
    /// ocauth-helper, and the signed-in session has its own `cookieCommand`
    /// argv). A stale "sso" on a kind without that flow falls back to password —
    /// connectSubprocess logs the fallback.
    static func openconnectAuthMode(_ c: SubprocessTunnelConfig) -> String {
        switch c.authMode {
        case "certificate": "certificate"
        case "token": "token"
        case "sso" where c.kind.supportsExternalBrowserSSO: "sso"
        default: "password"
        }
    }

    /// Why the chosen SSL-VPN sign-in method can't work as configured, or nil —
    /// the twin of `sshAuthBlockReason`: the editor's Connect button and
    /// connect() consult the same rule, so a doomed sign-in is refused with its
    /// fix instead of failing opaquely inside openconnect.
    static func sslAuthBlockReason(_ c: SubprocessTunnelConfig) -> String? {
        guard c.kind.isSSLVPN else { return nil }
        // TWO SIGN-IN SHAPES SIMPLEVPN NO LONGER IMPLEMENTS, refused here rather
        // than converted. Both are stored values somebody chose, so the profile is
        // left exactly as it is and Connect says what happened — the one answer
        // ruled out was quietly turning either into a password prompt, which would
        // send a password to a gateway the profile never asked to send one to.
        //
        // The wording is `FeatureRequestNotice`'s, because the banner in the editor
        // and this sentence have to agree about what the user should do next: open
        // an issue with the use case. Neither of them promises the feature.
        if openconnectAuthMode(c) == "token" {
            return FeatureRequestNotice.smartcardSignIn.blockedConnectReason
        }
        if !c.tokenMode.trimmingCharacters(in: .whitespaces).isEmpty {
            return FeatureRequestNotice.verificationCodeToken.blockedConnectReason
        }
        guard openconnectAuthMode(c) == "certificate" else { return nil }
        if c.clientCertFile.trimmingCharacters(in: .whitespaces).isEmpty {
            return "Certificate sign-in needs a client certificate file — set it under Sign-In."
        }
        // FortiGate used to be refused here when only `openfortivpn` was installed,
        // because that tool signs in with a password on stdin and carries no
        // certificate flags — it would have authenticated one way while the picker
        // said another. The fallback is gone, so every kind now reaches either
        // `openconnect` or the built-in engine, and both present a certificate.
        return nil
    }

    /// The tool `command(for:)` couldn't find, and how to get it. An SSL VPN that
    /// could go in-process is told about the toggle first — it is bundled, and it
    /// is the answer that needs no package manager at all.
    static func missingToolReason(_ c: SubprocessTunnelConfig) -> String {
        if c.kind == .ssh { return "/usr/bin/ssh is missing from this Mac — it ships with macOS, so reinstall the command line tools." }
        guard c.kind.isSSLVPN else { return "The command-line tool this VPN needs isn't installed." }
        if inProcessOpenConnectSupports(c), !c.runsInProcess {
            return "openconnect isn't installed. Turn on Run In-Process under Advanced to carry this VPN with SimpleVPN's built-in engine instead — or install the tool with: brew install openconnect"
        }
        return "openconnect isn't installed. \(TunnelCLI.openconnect.installHint)"
    }

    /// Why an SSL VPN that is going to run as a **subprocess** can't carry traffic
    /// on this Mac, or nil — the transport twin of `sslAuthBlockReason`.
    ///
    /// `openconnect` configures a real tun device, which needs root, and SimpleVPN
    /// deliberately never takes root in the user's
    /// context. The no-root subprocess path is `--script-tun --script "ocproxy -D
    /// <port>"`, appended by `openconnectArgs` only when ocproxy resolves — so with
    /// ocproxy absent the argv quietly omitted it and the tool went off to make a
    /// tun it cannot make. Nothing refused the connect and nothing said why; the
    /// user got whatever the tool printed, or a hang. That was the defect.
    ///
    /// **The first fix named is the toggle, not Homebrew.** The in-process engine
    /// has no privilege problem at all — the packet-tunnel extension already runs
    /// as root and already owns a utun, so NetworkExtension *is* the privilege —
    /// and it is bundled. Homebrew is only named when the config uses something the
    /// bridge can't carry (a host-checker script above all), because then the toggle would be
    /// a lie: `willRunInProcess` would still be false with it on.
    ///
    /// Availability is injected so this is testable on a Mac that happens to have
    /// (or not have) the tool. `inProcess: false` asks the question as the *fallback*
    /// would face it: the in-process engine was chosen and then failed to start, so
    /// the answer must ignore `willRunInProcess` and judge the subprocess on its own
    /// merits.
    ///
    /// `openconnectAvailable` USED TO BE A SECOND PARAMETER, for one FortiGate clause
    /// about `openfortivpn` needing administrator rights. That tool is gone — it was
    /// unreachable, because this very function refused the combination before anything
    /// could spawn it — so FortiGate is now exactly like the other six kinds, a
    /// missing `openconnect` is `missingToolReason`'s subject, and `ocproxy` is the
    /// only tool this function has an opinion about.
    static func sslTransportBlockReason(
        _ c: SubprocessTunnelConfig,
        inProcess: Bool? = nil,
        ocproxyAvailable: Bool = TunnelCLI.ocproxy.isAvailable
    ) -> String? {
        guard c.kind.isSSLVPN else { return nil }
        // Going in-process: no tool, no tun of ours to make, nothing to install.
        if inProcess ?? willRunInProcess(c) { return nil }
        // Offer the toggle only when turning it on would actually change the
        // answer: the bridge must be able to carry the config AND the toggle must
        // still be off. "Turn on the thing you already turned on" is the shape of
        // advice that makes people stop reading error messages.
        let theToggleWouldFixIt = inProcessOpenConnectSupports(c) && !c.runsInProcess
        if ocproxyAvailable { return nil }
        if theToggleWouldFixIt {
            return "Running this VPN with the openconnect tool needs ocproxy to carry it without administrator rights, and ocproxy isn't installed. Turn on Run In-Process under Advanced to use SimpleVPN's built-in engine instead — or install ocproxy (brew install ocproxy)."
        }
        // The toggle is already on and the engine couldn't take it: `ocproxy` is
        // the only remaining way for the tool to carry traffic without root.
        if c.runsInProcess, inProcessOpenConnectSupports(c) {
            return "The openconnect tool needs ocproxy to carry this VPN without administrator rights, and ocproxy isn't installed. Install it with: brew install ocproxy"
        }
        return "This VPN has to run with the openconnect tool — \(inProcessRefusalNoun(c)) — and that needs ocproxy to carry traffic without administrator rights. Install it with: brew install ocproxy"
    }

    /// The reason `inProcessOpenConnectSupports` said no, as a clause that fits
    /// mid-sentence. Named rather than generic because "some setting" sends the
    /// user hunting through five tabs.
    /// Kept in step with `inProcessOpenConnectSupports` clause for clause — every
    /// setting that still refuses the bridge names itself here, and nothing that no
    /// longer refuses is named at all. When the gates moved, eight of these
    /// sentences became lies (they described settings the bridge now carries), which
    /// is why the two live next to each other.
    static func inProcessRefusalNoun(_ c: SubprocessTunnelConfig) -> String {
        if !c.csdWrapper.isEmpty || c.disableCSD { return "the built-in engine can't run a host-checker script" }
        if c.baseMTU != nil { return "the built-in engine can't take a base MTU" }
        if c.noHTTPKeepalive { return "the built-in engine can't turn HTTP keepalive off" }
        if let why = SubprocessTunnelConfig.compressionProblem(c.ocCompression), !why.isEmpty {
            return "\u{201C}\(c.ocCompression)\u{201D} isn't a compression mode OpenConnect has"
        }
        if SubprocessTunnelConfig.spoofOSProblem(c.spoofOS) != nil {
            return "\u{201C}\(c.spoofOS)\u{201D} isn't a reported OS OpenConnect has"
        }
        if !c.extraArgs.filter({ !$0.trimmingCharacters(in: .whitespaces).isEmpty }).isEmpty {
            return "the built-in engine can't take extra arguments"
        }
        return "a setting on this VPN needs the tool (the Run In-Process row names which)"
    }

    /// The two settings the built-in engine cannot carry that a user is likely to
    /// reach for without meaning to give up the whole-Mac tunnel.
    ///
    /// A host-checker script and extra arguments are on the same gate, but both
    /// already say what they are for on their own rows and neither is set by
    /// accident. These two look like ordinary tuning — a number and a checkbox —
    /// so the cost has to be stated where they are chosen, not discovered later
    /// when the routes never arrive. Adding the setters to the vendored library
    /// would retire this type; that patch is deliberately deferred
    /// (`Docs/Networking.md` §3).
    enum ToolOnlySetting: String, CaseIterable, Sendable {
        case baseMTU = "oc.base-mtu"
        case noHTTPKeepalive = "oc.no-http-keepalive"

        /// Whether this profile actually sets it. A caveat on an untouched field
        /// is noise, and both of these are opt-in: most profiles never carry one.
        func isSet(_ c: SubprocessTunnelConfig) -> Bool {
            switch self {
            case .baseMTU: c.baseMTU != nil
            case .noHTTPKeepalive: c.noHTTPKeepalive
            }
        }

        /// A config carrying THIS setting and nothing else, so the shared refusal
        /// clause names this row rather than whichever gate happens to be first
        /// when a profile trips several.
        fileprivate var alone: SubprocessTunnelConfig {
            var probe = SubprocessTunnelConfig()
            switch self {
            case .baseMTU: probe.baseMTU = 1400
            case .noHTTPKeepalive: probe.noHTTPKeepalive = true
            }
            return probe
        }

        /// How to get the whole-Mac tunnel back, in the row's own terms.
        fileprivate var undo: String {
            switch self {
            case .baseMTU: "Leave it empty to keep the whole-Mac tunnel."
            case .noHTTPKeepalive: "Turn it off to keep the whole-Mac tunnel."
            }
        }
    }

    /// What this setting costs, said on its own row at the point of choice — or
    /// nil when the profile doesn't set it and there is nothing to warn about.
    ///
    /// The clause naming the setting is `inProcessRefusalNoun`, the same sentence
    /// the connect path uses, so the editor and the connect-time message cannot
    /// drift apart. The rest is the consequence rather than the mechanism: the
    /// tool offers a port, not an interface, so the routing story is off and the
    /// row moves sidebar section.
    static func toolOnlyCaveat(_ setting: ToolOnlySetting, _ c: SubprocessTunnelConfig) -> String? {
        guard c.kind.isSSLVPN, setting.isSet(c) else { return nil }
        return "Setting this runs the VPN with the openconnect tool — \(inProcessRefusalNoun(setting.alone)) — which only offers a SOCKS proxy on 127.0.0.1:\(c.socksPort): no interface, no routes and no DNS of its own, and the VPN is listed under Local Ports instead of Whole-Mac VPNs. \(setting.undo)"
    }

    /// Why this profile is being offered the built-in engine, or nil when there is
    /// nothing to offer. THE OTHER HALF OF THE MIGRATION: a profile that predates
    /// the default carries a stored `preferInProcess == false`, so it keeps the tool
    /// — correct, because something may be pointed at its SOCKS port — but it is not
    /// told, and the whole routing story stays switched off for it forever. This is
    /// the sentence that tells it, on the toggle's own row.
    ///
    /// It cannot distinguish "carried forward from before the default moved" from
    /// "deliberately turned off afterwards" — both store `false`, and adding a field
    /// to tell them apart would be a third representation of one decision. So the
    /// wording is an OFFER, true either way, never a correction.
    static func inProcessOfferReason(_ c: SubprocessTunnelConfig) -> String? {
        guard c.kind.isSSLVPN, !c.runsInProcess, inProcessOpenConnectSupports(c) else { return nil }
        return "This VPN runs the openconnect tool, which can only give you a SOCKS proxy on port \(c.socksPort) — no interface, no routes and no DNS of its own. SimpleVPN's built-in engine carries it as a full system tunnel instead, and needs nothing installed. Turning this on closes port \(c.socksPort), so check nothing is pointed at it first."
    }

    /// Why an address in this config can't be used, or nil. These configs are
    /// persisted unencrypted (UserDefaults),
    /// so a password embedded in one is refused, the same rule (and reason) as
    /// `ProxyTunnelConfig.upstreamProblem`. For the proxy it would also defeat
    /// the opt-in to send the saved password to the external tool.
    static func addressCredentialReason(_ c: SubprocessTunnelConfig) -> String? {
        if SubprocessTunnelConfig.passwordInAddress(c.server) {
            return "Take the password out of the server address — put it in the Password field under Sign-In."
        }
        if SubprocessTunnelConfig.passwordInAddress(c.proxyURL) {
            return "Take the password out of the proxy address — put it in the proxy password field under Connection."
        }
        return nil
    }

    /// The openconnect argv for a config (everything after the executable),
    /// split out from `command(for:)` so the flag set is testable without
    /// openconnect installed.
    /// The supervisor consumes exactly one bounded frame before openconnect inherits
    /// the remaining stdin. Passwords, cookies and private config keep their original channels.
    static func superviseOpenConnect(_ c: SubprocessTunnelConfig, client: String, proxy: String,
                                     args: [String], input: Data?) throws -> (path: String, args: [String], input: Data, ready: String) {
        let helper = Bundle.main.bundleURL.appendingPathComponent("Contents/Helpers/routecheck")
        do { try Installation.verify(helper, identifier: "com.bragi0.SimpleVPN.routecheck") } catch {
            throw ProfilePacketPolicy.failure("SimpleVPN could not verify its OpenConnect packet helper. Reinstall SimpleVPN.")
        }
        guard (1...65535).contains(c.socksPort), let script = args.firstIndex(of: "--script-tun"),
              script + 2 < args.count, args[script + 1] == "--script",
              args[script + 2] == "\(proxy) -D \(c.socksPort)", args.dropLast().last == "--" else {
            throw ProfilePacketPolicy.failure("OpenConnect needs a managed script tunnel and a valid local SOCKS port.")
        }
        // The generated hook is always the last option before the server delimiter.
        // OpenConnect uses getopt_long, including unambiguous long option prefixes.
        let reserved = ["--script", "--script-tun", "--background", "--interface"]
        if c.extraArgs.contains(where: { arg in
            let flag = String(arg.prefix { $0 != "=" })
            return flag == "--" || (flag.hasPrefix("--") && reserved.contains { $0.hasPrefix(flag) }) ||
                   (!flag.hasPrefix("--") && ["-b", "-s", "-S", "-i"].contains(where: { flag.hasPrefix($0) }))
        }) {
            throw ProfilePacketPolicy.failure("SimpleVPN manages OpenConnect’s tunnel script, foreground process and interface. Remove switches that replace those settings.")
        }
        var options = args
        options.removeSubrange(script...script + 2)
        let nonce = UUID().uuidString
        let settings: [String: Any] = ["client": client, "proxy": proxy, "port": c.socksPort, "nonce": nonce,
                                       "profile": c.id, "kind": c.kind.rawValue, "source": c.routingEventSource ?? "",
                                       "authLength": input?.count ?? 0]
        let body = try JSONSerialization.data(withJSONObject: settings)
        var count = UInt32(body.count).bigEndian
        var frame = withUnsafeBytes(of: &count) { Data($0) }
        frame.append(body)
        if let input { frame.append(input) }
        return (helper.path, ["--ocproxy-supervise"] + options, frame, "SimpleVPN proxy ready " + nonce)
    }

    static func openconnectArgs(for c: SubprocessTunnelConfig) -> [String] {
        let proto = c.kind.openconnectProtocol ?? "anyconnect"
        let mode = openconnectAuthMode(c)
        var a = ["--protocol=\(proto)", "--non-inter"]
        // Password mode: the password rides stdin and NO certificate flag is
        // passed. openconnect prefers a certificate when one is configured, so
        // a stale cert path used to win over the piped password — certificate
        // auth while the UI said "Password".
        //
        // A `"token"` (smartcard) profile NEVER REACHES HERE: `sslAuthBlockReason`
        // refuses it before the dispatch, because SimpleVPN no longer implements
        // smartcard sign-in. Nothing below has a token branch, deliberately — a
        // half-built argv for a mode that is refused upstream is the shape of thing
        // that comes back to life by accident.
        if mode == "password" { a.append("--passwd-on-stdin") }
        if !c.username.isEmpty { a += ["--user=\(c.username)"] }
        // TODO(fortinet): verify --authgroup actually carries the Fortinet
        // realm (vs a portal path / --usergroup) — needs a real gateway.
        if !c.realm.isEmpty { a += ["--authgroup=\(c.realm)"] }
        if !c.usergroup.isEmpty { a += ["--usergroup=\(c.usergroup)"] }
        // The prefix comes from the pin's own form — a `sha256:<hex>` pin used to
        // be turned into `pin-sha256:sha256:<hex>` here and refused at startup.
        if !c.trustedCertSHA256.isEmpty {
            a += ["--servercert=\(SubprocessTunnelConfig.serverCertArgument(c.trustedCertSHA256))"]
        }
        if !c.caFile.isEmpty { a += ["--cafile=\((c.caFile as NSString).expandingTildeInPath)"] }
        if !c.spoofOS.isEmpty { a += ["--os=\(c.spoofOS)"] }
        if !c.localHostname.isEmpty { a += ["--local-hostname=\(c.localHostname)"] }
        if !c.userAgent.isEmpty { a += ["--useragent=\(c.userAgent)"] }
        if !c.versionString.isEmpty { a += ["--version-string=\(c.versionString)"] }
        if !c.ocCompression.isEmpty { a += ["--compression=\(c.ocCompression)"] }
        if c.enablePFS { a.append("--pfs") }
        if c.disableIPv6 { a.append("--disable-ipv6") }
        if c.noHTTPKeepalive { a.append("--no-http-keepalive") }
        if c.disableDTLS { a.append("--no-dtls") }
        // Certificate mode ONLY: the client certificate (PEM / PKCS#12), its
        // optional separate key, and the key's passphrase — never alongside
        // --passwd-on-stdin.
        if mode == "certificate" {
            if !c.clientCertFile.isEmpty { a += ["--certificate=\((c.clientCertFile as NSString).expandingTildeInPath)"] }
            if !c.clientKeyFile.isEmpty { a += ["--sslkey=\((c.clientKeyFile as NSString).expandingTildeInPath)"] }

        }
        // Host-checker / endpoint posture (F5 EPA, Cisco CSD, GP/NC trojan):
        // a real wrapper wins over the skip; otherwise "disable" stubs it out.
        // (The editor disables the skip toggle and names the wrapper, so the
        // override is visible rather than silent.)
        if !c.csdWrapper.isEmpty { a += ["--csd-wrapper=\((c.csdWrapper as NSString).expandingTildeInPath)"] }
        else if c.disableCSD { a += ["--csd-wrapper=/usr/bin/true"] }
        if let t = c.reconnectTimeout { a += ["--reconnect-timeout=\(t)"] }
        if let d = c.forceDPD { a += ["--force-dpd=\(d)"] }
        if let m = c.ocMTU { a += ["--mtu=\(m)"] }
        if let bm = c.baseMTU { a += ["--base-mtu=\(bm)"] }
        if let ocproxy = TunnelCLI.ocproxy.resolvedPath {
            a += ["--script-tun", "--script", "\(ocproxy) -D \(c.socksPort)"]
        }
        a += c.extraArgs
        a += ["--", serverURL(for: c)]
        return a
    }

    /// Transport argv for a session ocauth-helper already signed in: connect to
    /// the exact URL and certificate the sign-in produced (`--resolve` defeats
    /// round-robin DNS), with the cookie on stdin — never argv. Auth-time flags
    /// (user, authgroup, CSD) are gone; only transport knobs remain.
    static func cookieCommand(for c: SubprocessTunnelConfig, auth: OCAuthDone)
        -> (String, [String], Data?)? {
        guard let oc = TunnelCLI.openconnect.resolvedPath else { return nil }
        let proto = c.kind.openconnectProtocol ?? "anyconnect"
        var a = ["--protocol=\(proto)", "--non-inter", "--cookie-on-stdin"]
        if !auth.servercert.isEmpty { a += ["--servercert=\(auth.servercert)"] }
        if let r = auth.resolve { a += ["--resolve=\(r.host):\(r.ip)"] }
        if !c.spoofOS.isEmpty { a += ["--os=\(c.spoofOS)"] }
        if !c.localHostname.isEmpty { a += ["--local-hostname=\(c.localHostname)"] }
        if !c.userAgent.isEmpty { a += ["--useragent=\(c.userAgent)"] }
        if !c.versionString.isEmpty { a += ["--version-string=\(c.versionString)"] }
        if !c.ocCompression.isEmpty { a += ["--compression=\(c.ocCompression)"] }
        if c.enablePFS { a.append("--pfs") }
        if c.disableIPv6 { a.append("--disable-ipv6") }
        if c.noHTTPKeepalive { a.append("--no-http-keepalive") }
        if c.disableDTLS { a.append("--no-dtls") }
        if let t = c.reconnectTimeout { a += ["--reconnect-timeout=\(t)"] }
        if let d = c.forceDPD { a += ["--force-dpd=\(d)"] }
        if let m = c.ocMTU { a += ["--mtu=\(m)"] }
        if let bm = c.baseMTU { a += ["--base-mtu=\(bm)"] }
        if let ocproxy = TunnelCLI.ocproxy.resolvedPath {
            a += ["--script-tun", "--script", "\(ocproxy) -D \(c.socksPort)"]
        }
        a += c.extraArgs
        a += ["--", auth.connectURL.isEmpty ? serverURL(for: c) : auth.connectURL]
        return (oc, a, Data((auth.cookie + "\n").utf8))
    }

    /// Shell-quote a value for safe interpolation into a `/bin/sh -c` command
    /// (ssh runs ProxyCommand through the shell). Wraps in single quotes and
    /// escapes embedded single quotes.
    private static func shellQuote(_ s: String) -> String {
        "'" + s.replacingOccurrences(of: "%", with: "%%").replacingOccurrences(of: "'", with: "'\\''") + "'"
    }

    /// openconnect's line-oriented config reader trims leading spaces/tabs from
    /// values. Reject unrepresentable secrets before launching or logging the tool.
    static func openconnectPrivateConfig(keyPassphrase: String?, proxy: String?) throws -> Data? {
        var lines = ""
        for (option, value) in [("key-password", keyPassphrase), ("proxy", proxy)] {
            guard let value, !value.isEmpty else { continue }
            guard value.first != " ", value.first != "\t",
                  !value.utf8.contains(where: { [0, 10, 13].contains($0) }) else {
                throw NSError(domain: "OpenConnect", code: 1, userInfo: [NSLocalizedDescriptionKey:
                    "The openconnect tool cannot read this \(option == "proxy" ? "proxy address" : "key passphrase") from its private configuration. Remove leading spaces or tabs and line breaks, or use the built-in engine."])
            }
            lines += "\(option)=\(value)\n"
        }
        guard lines.utf8.count <= 16_384 else {
            throw NSError(domain: "OpenConnect", code: 2, userInfo: [NSLocalizedDescriptionKey:
                "The proxy and key settings are too large for the openconnect tool’s private configuration."])
        }
        return lines.isEmpty ? nil : Data(lines.utf8)
    }

    private static func proxyArgument(for c: SubprocessTunnelConfig) -> String? {
        switch c.proxyMode {
        case .none:
            return nil
        case .manual:
            let raw = c.proxyURL.trimmingCharacters(in: .whitespaces)
            guard !raw.isEmpty else { return nil }
            guard !c.proxyUsername.isEmpty else { return raw }
            let pw = c.proxyPasswordInArgv == true
                ? KeychainCredentialStore.loadCredentials(profile: "tunnel.\(c.id).proxy")?.password : nil
            let credentialCharacters = CharacterSet(charactersIn: "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~")
            guard let user = c.proxyUsername.addingPercentEncoding(withAllowedCharacters: credentialCharacters),
                  let pass = (pw ?? "").addingPercentEncoding(withAllowedCharacters: credentialCharacters) else { return nil }
            let cred = pass.isEmpty ? user : "\(user):\(pass)"
            if let sep = raw.range(of: "://") {
                return raw.replacingCharacters(in: sep.upperBound..<sep.upperBound, with: "\(cred)@")
            }
            return "http://\(cred)@\(raw)"
        case .systemDefault:
            return systemProxyURL()
        }
    }

    /// The Mac's configured web proxy as a URL, if one is enabled (SystemConfiguration).
    private static func systemProxyURL() -> String? {
        guard let proxies = SCDynamicStoreCopyProxies(nil) as? [String: Any] else { return nil }
        func on(_ k: String) -> Bool { (proxies[k] as? Int) == 1 }
        if on("HTTPSEnable"), let h = proxies["HTTPSProxy"] as? String, let p = proxies["HTTPSPort"] as? Int {
            return "http://\(h):\(p)"
        }
        if on("HTTPEnable"), let h = proxies["HTTPProxy"] as? String, let p = proxies["HTTPPort"] as? Int {
            return "http://\(h):\(p)"
        }
        if on("SOCKSEnable"), let h = proxies["SOCKSProxy"] as? String, let p = proxies["SOCKSPort"] as? Int {
            return "socks5://\(h):\(p)"
        }
        return nil
    }

    /// Parse one forward line — "L 8080:host:80", "-D 1080", "R 9090:localhost:9090",
    /// or a bare "8080:host:80" (treated as -L) — into its ssh flag letter + spec.
    /// Anything else is nil: a typed "-L 8080:h:80" must not become argv "--L",
    /// and a stray letter must never turn into an arbitrary ssh -X flag.
    static func parseForward(_ line: String) -> (flag: String, spec: String)? {
        var t = line.trimmingCharacters(in: .whitespaces)
        if t.hasPrefix("-") { t = String(t.dropFirst()) }
        let parts = t.split(separator: " ", omittingEmptySubsequences: true).map(String.init)
        let flag: String, spec: String
        switch parts.count {
        case 1: flag = "L"; spec = parts[0]
        case 2: flag = parts[0].uppercased(); spec = parts[1]
        default: return nil
        }
        guard ["L", "R", "D"].contains(flag) else { return nil }
        // Plausibility: colon-joined host/port fields only. D takes [bind:]port,
        // L/R take [bind:]port:host:hostport; bracketed IPv6 binds defeat the
        // colon count, so their presence relaxes it.
        let allowed = CharacterSet(charactersIn:
            "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789.:-_[]*%")
        guard !spec.isEmpty, spec.unicodeScalars.allSatisfy({ allowed.contains($0) }) else { return nil }
        let colons = spec.filter { $0 == ":" }.count
        let bracketed = spec.contains("[")
        switch flag {
        case "D": guard bracketed || colons <= 1 else { return nil }
        default:  guard bracketed || (2...3).contains(colons) else { return nil }
        }
        return (flag, spec)
    }

    /// The first non-empty forward line that isn't a valid L/R/D spec, or nil.
    static func invalidForwardLine(_ forwards: [String]) -> String? {
        forwards.first {
            let t = $0.trimmingCharacters(in: .whitespaces)
            return !t.isEmpty && parseForward(t) == nil
        }
    }

    private static func sshCommonOptions(_ c: SubprocessTunnelConfig) -> [String] {
        var a = ["-o", "ExitOnForwardFailure=yes",
                 "-o", "ServerAliveInterval=\(max(0, c.serverAliveInterval))",
                 "-o", "StrictHostKeyChecking=\(c.strictHostKey)"]
        if let p = c.port { a += ["-p", "\(p)"] }
        // Sign-in method → ssh options. An explicit method PINS ssh to it
        // (PreferredAuthentications), otherwise OpenSSH's default order would
        // contradict the UI — a lingering agent key silently "winning" over the
        // password the user chose, or vice versa. IdentitiesOnly=yes stops ssh
        // trying ~/.ssh/id_* defaults beyond the configured key.
        // (The host-key PIN is deliberately absent throughout: ssh has no
        // pin-by-hash option, and pinned configs never reach this builder —
        // see sshPinBlockReason.)
        let method = sshAuthMethod(c)
        switch method {
        case "password":
            // keyboard-interactive included: many servers deliver their
            // password prompt through it. The askpass answers those prompts
            // with the stored password — the editor caveats the MFA case.
            a += ["-o", "PreferredAuthentications=password,keyboard-interactive",
                  "-o", "PubkeyAuthentication=no"]
        case "key", "certificate":
            a += ["-o", "PreferredAuthentications=publickey",
                  "-o", "IdentitiesOnly=yes"]
        case "agent":
            // Agent keys only: publickey without -i (and without IdentitiesOnly,
            // which would restrict ssh to explicitly-listed identities).
            a += ["-o", "PreferredAuthentications=publickey"]
        case "kerberos":
            a += ["-o", "GSSAPIAuthentication=yes",
                  "-o", "PreferredAuthentications=gssapi-with-mic"]
        default:
            break   // automatic — OpenSSH's default order
        }
        // The identity file rides along for automatic, key and certificate
        // sign-in; the other explicit methods never use one.
        if !c.identityFile.isEmpty, ["", "key", "certificate"].contains(method) {
            a += ["-i", (c.identityFile as NSString).expandingTildeInPath]
        }
        if method == "certificate", let cert = c.sshCertificateFile, !cert.isEmpty {
            a += ["-o", "CertificateFile=\((cert as NSString).expandingTildeInPath)"]
        }
        // Which agent to ask, when one is in play (automatic and agent sign-in).
        // ssh has no command-line flag for this — only the ssh_config keyword —
        // and the value MUST be quoted because the paths that matter contain
        // spaces ("~/Library/Group Containers/…"): verified against
        // OpenSSH 10.3p1 with `ssh -G -o 'IdentityAgent="/tmp/a b/agent.sock"'`,
        // which reports `identityagent /tmp/a b/agent.sock`.
        if ["", "agent"].contains(method), let socket = sshAgentSocket(c),
           SubprocessTunnelConfig.agentSocketProblem(socket) == nil {
            a += ["-o", "IdentityAgent=\"\(socket)\""]
        }
        if let kex = c.sshKexAlgorithms?.trimmingCharacters(in: .whitespaces), !kex.isEmpty {
            a += ["-o", "KexAlgorithms=\(kex)"]
        }
        if c.useJumpHost, !c.jumpHost.isEmpty {
            // ProxyCommand (not -J) so the jump hop can use its own key. Its
            // password, if any, is matched by the host-aware askpass.
            // ssh runs ProxyCommand via /bin/sh -c, so every interpolated field must
            // be shell-quoted or a jump-host value like "x; curl … | sh" is RCE.
            // The jump hop gets the same host-key policy as the tunnel itself —
            // a hardcoded accept-new would silently weaken a "yes" config.
            var inner = "/usr/bin/env \(SSHAskpass.hopKey)=jump /usr/bin/ssh -F /dev/null -S none -o ClearAllForwardings=yes -o \(Self.shellQuote("StrictHostKeyChecking=\(c.strictHostKey)"))"
            if !c.jumpIdentityFile.isEmpty {
                // IdentitiesOnly so the CONFIGURED jump key is the one used —
                // not whatever ~/.ssh/id_* or agent key happens to match first.
                inner += " -i \(Self.shellQuote((c.jumpIdentityFile as NSString).expandingTildeInPath))"
                inner += " -o IdentitiesOnly=yes"
            }
            if let jp = c.jumpPort { inner += " -p \(jp)" }
            let jumpTarget = c.jumpUsername.isEmpty ? c.jumpHost : "\(c.jumpUsername)@\(c.jumpHost)"
            // Quote the configured destination as a value. OpenSSH substitutes %h
            // after building ProxyCommand, too late to shell-escape its contents.
            let forwardHost = c.server.hasPrefix("[") ? c.server : "[\(c.server)]"
            inner += " -W \(Self.shellQuote("\(forwardHost):\(c.port ?? 22)")) -- \(Self.shellQuote(jumpTarget))"
            a += ["-o", "ProxyCommand=\(inner)"]
        }
        if c.compression { a.append("-C") }
        if let t = c.connectTimeout { a += ["-o", "ConnectTimeout=\(t)"] }
        for opt in c.sshExtraOptions where !opt.trimmingCharacters(in: .whitespaces).isEmpty {
            a += ["-o", opt]
        }
        return a
    }

    private static func sshTarget(_ c: SubprocessTunnelConfig) -> String {
        c.username.isEmpty ? c.server : "\(c.username)@\(c.server)"
    }
    /// The exact web gateway address handed to libopenconnect.  Keep a policy path
    /// in a pasted URL intact, and put an explicitly selected port in the URL's
    /// authority (not after `/my.policy`).  The same answer feeds the helper, the
    /// in-process bridge and the CLI, so the three transports cannot disagree.
    static func serverURL(for c: SubprocessTunnelConfig) -> String {
        let raw = c.server.trimmingCharacters(in: .whitespacesAndNewlines)
        guard let port = c.port else { return raw }

        if var parts = URLComponents(string: raw), parts.scheme != nil, parts.host != nil {
            parts.port = port
            return parts.string ?? raw
        }

        // Existing bare host:port profiles remain accepted.  When the dedicated
        // Port row is set, it is the explicit choice and replaces that legacy port.
        if var parts = URLComponents(string: "https://\(raw)"),
           parts.host != nil, parts.path.isEmpty {
            parts.port = port
            guard var authority = parts.string else { return raw }
            authority.removeFirst("https://".count)
            return authority
        }
        // Invalid input is held and explained by the readiness gate; preserve it
        // verbatim here rather than silently clearing an editor field.
        return raw
    }


}

/// One supervised child process, reading merged stdout+stderr line-by-line and
/// reporting the "connected" moment via a per-kind readiness marker. nonisolated:
/// it lives on process/pipe callback threads, hopping to the MainActor only to
/// deliver output and exit events.
nonisolated final class TunnelProcess: @unchecked Sendable {
    private let path: String
    private let args: [String]
    private var stdin: Data?
    private var privateConfig: Data?
    let isProxyRelay: Bool
    private var proxyControl: FileHandle?
    @MainActor private var pendingProxyStats: [CheckedContinuation<Data?, Never>] = []
    @MainActor private var proxyTimeout: Task<Void, Never>?
    @MainActor func proxySnapshot() async -> Data? {
        guard isProxyRelay, let proxyControl, pendingProxyStats.count < 16 else { return nil }
        return await withCheckedContinuation { waiter in
            pendingProxyStats.append(waiter)
            guard pendingProxyStats.count == 1 else { return }
            do { try proxyControl.write(contentsOf: Data([83])) } catch { receiveProxyStats(nil); return }
            proxyTimeout = Task { @MainActor [weak self] in
                do { try await Task.sleep(for: .seconds(1)) } catch { return }
                self?.receiveProxyStats(nil)
            }
        }
    }
    @MainActor private func receiveProxyStats(_ data: Data?) {
        proxyTimeout?.cancel()
        proxyTimeout = nil
        let waiters = pendingProxyStats
        pendingProxyStats.removeAll(keepingCapacity: true)
        for waiter in waiters { waiter.resume(returning: data) }
    }
    private var outputReader: FileHandle?
    private var askpass: SSHAskpass?
    private let askpassPath: String?
    private let onOutput: @MainActor (TunnelProcess, [String], Bool) -> Void
    private let output: OSAllocatedUnfairLock<OutputBuffer>
    private let onExit: @MainActor (TunnelProcess, Int32) -> Void
    private var process: Process?
    var runningProcess: Process? { process }

    init(path: String, args: [String], stdin: Data?, privateConfig: Data?, askpass: SSHAskpass?, askpassPath: String?,
         requireRemoteForwardAck: Bool = false, proxyReady: String? = nil, onOutput: @escaping @MainActor (TunnelProcess, [String], Bool) -> Void,
         onExit: @escaping @MainActor (TunnelProcess, Int32) -> Void) {
        output = OSAllocatedUnfairLock(initialState: OutputBuffer(requireRemoteForwardAck: requireRemoteForwardAck, proxyReady: proxyReady))
        isProxyRelay = proxyReady != nil
        self.path = path; self.args = args; self.stdin = stdin
        self.privateConfig = privateConfig
        self.askpass = askpass
        self.askpassPath = askpassPath
        self.onOutput = onOutput; self.onExit = onExit
    }

    /// Readiness signatures across the tools we drive. The openconnect markers
    /// are all POST-auth: "Connected to HTTPS on" fires after the bare TLS
    /// handshake, before sign-in — keying on it showed "connected" during the
    /// password/SSO dance and swallowed auth failures as plain disconnects.
    private static let readyMarkers = [
        "Local forwarding listening",             // ssh -v
        "Entering interactive session",           // ssh
        "debug1: Entering interactive",           // ssh -v
        "Configured as",                          // openconnect ≥9, after auth + tunnel config
        "Got CONNECT response: HTTP/1.1 200",     // openconnect, tunnel accepted post-auth
        "Got CONNECT response: HTTP/1.0 200",     // openconnect (F5/PPP kinds use HTTP/1.0)
        "Established DTLS connection",            // openconnect
        "Session authentication will expire",     // openconnect, post-auth banner
    ]

    /// A pipe read can split both a UTF-8 scalar and a log line. Bound the partial
    /// line and the pending main-actor delivery independently of the child's rate.
    struct OutputBuffer: Sendable {
        private let requireRemoteForwardAck: Bool
        private let proxyReady: String?
        private let proxyStatsPrefix: String?
        private var latestStats: Data?
        init(requireRemoteForwardAck: Bool = false, proxyReady: String? = nil) {
            self.requireRemoteForwardAck = requireRemoteForwardAck
            self.proxyReady = proxyReady
            proxyStatsPrefix = proxyReady.map { $0.replacingOccurrences(of: "proxy ready ", with: "proxy stats ") + " " }
        }

        private var partial = Data()
        private var skippingLongLine = false
        private var extendedStatsLine = false
        private var queued: [String] = []
        private var ready = false
        private var deliveryScheduled = false
        private let scrubber = SecretScrubber(policy: .errorDetail)

        mutating func append(_ chunk: Data) -> Bool {
            func finishLine() {
                if !partial.isEmpty && !skippingLongLine {
                    let raw = String(decoding: partial, as: UTF8.self)
                    if let proxyStatsPrefix, raw.hasPrefix(proxyStatsPrefix) {
                        latestStats = Data(raw.dropFirst(proxyStatsPrefix.count).utf8)
                        partial.removeAll(keepingCapacity: true)
                        extendedStatsLine = false
                        return
                    }
                    let line = raw.contains("://") && raw.contains("@") ? scrubber.redactCredentialedURLs(raw) : raw
                    if let proxyReady {
                        ready = ready || line == proxyReady
                    } else if requireRemoteForwardAck {
                        // ssh -v enters its "interactive session" before the remote
                        // server has answered even the first listen request.
                        ready = ready || line == "debug1: forwarding_success: all expected forwarding replies received"
                    } else {
                        ready = ready || TunnelProcess.readyMarkers.contains { line.contains($0) }
                    }
                    queued.append(line == proxyReady ? "Local SOCKS proxy is ready." : line)
                }
                partial.removeAll(keepingCapacity: true)
                skippingLongLine = false
                extendedStatsLine = false
            }
            for byte in chunk {
                if byte == 10 || byte == 13 { finishLine() }
                else if !skippingLongLine {
                    if partial.count == 8192, let proxyStatsPrefix {
                        extendedStatsLine = partial.starts(with: proxyStatsPrefix.utf8)
                    }
                    if partial.count < (extendedStatsLine ? 512 * 1024 : 8192) { partial.append(byte) }
                    else { partial.removeAll(keepingCapacity: true); skippingLongLine = true }
                }
            }
            if chunk.isEmpty { finishLine() }
            if queued.count > 300 { queued.removeFirst(queued.count - 300) }
            guard !queued.isEmpty || latestStats != nil, !deliveryScheduled else { return false }
            deliveryScheduled = true
            return true
        }

        mutating func take() -> (lines: [String], ready: Bool, stats: Data?) {
            defer { latestStats = nil }
            let batch = (queued, ready, latestStats)
            queued = []
            ready = false
            deliveryScheduled = false
            return batch
        }
    }

    @MainActor private func deliverOutput() {
        let batch = output.withLock { $0.take() }
        if batch.ready { askpass = nil }
        if let stats = batch.stats { receiveProxyStats(stats) }
        if !batch.lines.isEmpty { onOutput(self, batch.lines, batch.ready) }
    }

    func start() {
        let p = Process()
        p.executableURL = URL(fileURLWithPath: path)
        var argv = args
        var env = ProcessInfo.processInfo.environment

        if path.hasSuffix("ssh") {
            argv = ["-v"] + argv
            if let askpass, let askpassPath {
                env.merge(askpass.environment) { _, current in current }
                env["SSH_ASKPASS"] = askpassPath
                env["SSH_ASKPASS_REQUIRE"] = "force"
                env["DISPLAY"] = ":0"
            }
        }
        p.arguments = argv
        p.environment = env

        let inPipe = Pipe()
        p.standardInput = inPipe
        var childOutput: FileHandle?
        let reader: FileHandle
        if let privateConfig {
            do {
                // Darwin's /dev/fd/2 duplicates stderr. The socket is full duplex:
                // the tool reads config up to EOF while its output travels back.
                // stdin stays free for --passwd-on-stdin or --cookie-on-stdin.
                let channel = try Self.configChannel(privateConfig)
                reader = channel.reader
                childOutput = channel.child
                p.standardOutput = channel.child
                p.standardError = channel.child
            } catch {
                Task { @MainActor in self.onOutput(self, ["Couldn't prepare private VPN settings."], false); self.onExit(self, -1) }
                return
            }
            self.privateConfig = nil
        } else {
            let outPipe = Pipe()
            p.standardOutput = outPipe
            p.standardError = outPipe
            reader = outPipe.fileHandleForReading
        }
        outputReader = reader
        reader.readabilityHandler = { [weak self] handle in
            let chunk = handle.availableData
            if chunk.isEmpty { handle.readabilityHandler = nil }
            guard let self, self.output.withLock({ $0.append(chunk) }) else { return }
            Task { @MainActor in self.deliverOutput() }
        }
        p.terminationHandler = { [weak self] proc in
            let code = proc.terminationStatus
            Task { @MainActor in
                guard let self else { return }
                self.deliverOutput()
                if self.isProxyRelay {
                    try? self.proxyControl?.close()
                    self.proxyControl = nil
                    self.receiveProxyStats(nil)
                }
                self.onExit(self, code)
            }
        }

        do {
            try p.run()
            askpass?.authorize(p)
            try? childOutput?.close()
            if let data = stdin {
                guard fcntl(inPipe.fileHandleForWriting.fileDescriptor, F_SETNOSIGPIPE, 1) == 0 else { throw POSIXError(.EIO) }
                try inPipe.fileHandleForWriting.write(contentsOf: data)
            }
            if isProxyRelay { proxyControl = inPipe.fileHandleForWriting }
            else { try? inPipe.fileHandleForWriting.close() }
            process = p
            stdin = nil
        } catch {
            reader.readabilityHandler = nil
            if p.isRunning { p.terminate() }
            stdin = nil
            askpass = nil
            Task { @MainActor in self.onOutput(self, ["Failed to launch: \(error.localizedDescription)"], false); self.onExit(self, -1) }
        }
    }

    static func configChannel(_ config: Data) throws -> (reader: FileHandle, child: FileHandle) {
        var fds: [Int32] = [-1, -1]
        guard socketpair(AF_UNIX, SOCK_STREAM, 0, &fds) == 0 else { throw POSIXError(.EIO) }
        let reader = FileHandle(fileDescriptor: fds[0], closeOnDealloc: true)
        let child = FileHandle(fileDescriptor: fds[1], closeOnDealloc: true)
        guard fcntl(fds[0], F_SETFD, FD_CLOEXEC) == 0,
              fcntl(fds[1], F_SETFD, FD_CLOEXEC) == 0,
              config.withUnsafeBytes({ send(fds[0], $0.baseAddress, $0.count, MSG_DONTWAIT) }) == config.count,
              shutdown(fds[0], SHUT_WR) == 0 else { throw POSIXError(.EIO) }
        return (reader, child)
    }

    func stop() {
        try? proxyControl?.close()
        proxyControl = nil
        process?.terminationHandler = nil
        process?.interrupt()
        // SIGINT lets openconnect log out of the gateway cleanly;
        // give it a couple of seconds before the SIGTERM backstop. `process`
        // stays set until then so the escalation can find it (instances are
        // one-shot — nothing restarts on this object).
        DispatchQueue.global().asyncAfter(deadline: .now() + 2) { [self] in
            if let p = process, p.isRunning { p.terminate() }
            process = nil
        }
        askpass = nil
    }


}
