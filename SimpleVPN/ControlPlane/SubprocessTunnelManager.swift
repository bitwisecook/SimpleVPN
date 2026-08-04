// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
//  SubprocessTunnelManager.swift
//  Runs and supervises the command-line VPN kinds (SSH SOCKS / port forwards,
//  and the OpenConnect / openfortivpn SSL-VPNs — FortiGate, F5 BIG-IP APM, …).
//  Each tunnel is one child process; we build its argv, feed the password
//  headlessly (SSH via a locked-down SSH_ASKPASS script, OpenConnect via
//  --passwd-on-stdin), watch its output for the "up" signal, keep a rolling log,
//  and — for SOCKS kinds — optionally point the active network service's SOCKS
//  proxy at the local port while connected (restored on disconnect).
//
//  The SOCKS path needs no root: `ssh -D` and `openconnect --script-tun --script
//  "ocproxy -D <port>"` both expose a userspace proxy. (A full-routes path would
//  need a privileged helper; that's a later addition — see connect notes.)
//

import Foundation
import Observation
import os
import SystemConfiguration

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
    }

    private(set) var live: [String: Live] = [:]

    private var tasks: [String: TunnelProcess] = [:]
    private var sshEngines: [String: SSHTunnelEngine] = [:]   // in-process libssh (SOCKS)
    private var inProcessNE: Set<String> = []                 // SSL VPNs running via the NE OpenConnect engine
    private var authTasks: [String: Task<Void, Never>] = [:]  // in-flight ocauth-helper sign-ins (SSO)
    private var proxiedIDs: Set<String> = []                  // ids whose SOCKS proxy we pointed the system at
    private var controlSockets: [String: String] = [:]       // ssh ControlMaster socket per tunnel (live -O ops)
    private static let log = Logger(subsystem: "com.bragi0.SimpleVPN", category: "subprocess")

    func status(_ id: String) -> Status { live[id]?.status ?? .disconnected }
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
    func connect(_ config: SubprocessTunnelConfig, password: String?) {
        guard tasks[config.id] == nil, sshEngines[config.id] == nil,
              !inProcessNE.contains(config.id), authTasks[config.id] == nil else { return }
        // A password embedded in the server or proxy address would be persisted
        // unencrypted AND handed to the tool on its command line (`ps`-readable).
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
        // Token mode without a stored seed would just let openconnect die under
        // --non-inter — fail fast with the actual fix instead.
        // (Not under SSO: the token never reaches the argv there — the identity
        // provider asks for the code in the browser.)
        // (Not for yubioath either: the code comes off the YubiKey, so there is
        // no seed to store and requiring one would block a working setup.)
        if config.kind.isSSLVPN, SubprocessTunnelConfig.tokenModeRequiresSecret(config.tokenMode),
           Self.openconnectAuthMode(config) != "sso",
           (KeychainCredentialStore.loadCredentials(profile: "tunnel.\(config.id).token")?.password ?? "").isEmpty {
            live[config.id] = Live(status: .failed(
                "Verification-code token is set to \(config.tokenMode.uppercased()) but no token secret is stored — add it under Sign-In ▸ Token secret and save."))
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
        if config.kind == .ssh, config.sshMode == .socks, Self.inProcessSSHSupports(config) {
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
        if config.preferInProcess, config.authMode != "sso",
           [.fortinet, .f5apm, .ciscoAnyConnect].contains(config.kind),
           Self.inProcessOpenConnectSupports(config) {
            connectInProcessOpenConnect(config, password: password)
            return
        }
        connectSubprocess(config, password: password)
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
    static func willRunInProcess(_ c: SubprocessTunnelConfig) -> Bool {
        c.kind.isSSLVPN && c.preferInProcess && inProcessOpenConnectSupports(c)
    }

    private static func inProcessOpenConnectSupports(_ c: SubprocessTunnelConfig) -> Bool {
        if c.port != nil { return false }               // the bridge gets the bare server string only
        if !c.caFile.isEmpty || !c.usergroup.isEmpty || !c.spoofOS.isEmpty { return false }
        if !c.clientCertFile.isEmpty || !c.clientKeyFile.isEmpty || !c.tokenMode.isEmpty { return false }
        if c.disableCSD || !c.csdWrapper.isEmpty { return false }
        if c.proxyMode == .manual { return false }
        if !c.ocCompression.isEmpty || c.enablePFS || c.disableIPv6 || c.noHTTPKeepalive || c.disableDTLS { return false }
        if !c.localHostname.isEmpty || !c.userAgent.isEmpty || !c.versionString.isEmpty { return false }
        if c.reconnectTimeout != nil || c.forceDPD != nil || c.ocMTU != nil || c.baseMTU != nil { return false }
        if c.extraArgs.contains(where: { !$0.trimmingCharacters(in: .whitespaces).isEmpty }) { return false }
        return true
    }

    private func connectInProcessOpenConnect(_ config: SubprocessTunnelConfig, password: String?) {
        inProcessNE.insert(config.id)
        live[config.id] = Live(status: .connecting)
        Task { [weak self] in
            // `true` means "started", not "connected" — real progress (connecting /
            // connected / auth failure) arrives via NEVPNStatusDidChange events.
            let ok = await OpenConnectProfileStore.start(config, password: password) { [weak self] event in
                self?.handleInProcessEvent(config.id, event)
            }
            guard let self else { return }
            if !ok {
                Self.log.error("in-process OpenConnect failed, falling back to subprocess")
                self.inProcessNE.remove(config.id); self.live[config.id] = nil
                self.connectSubprocess(config, password: password)
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
        case .failed(let why):
            l.status = .failed(why)
            inProcessNE.remove(id)
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
                let filled = OCAuthFormAutofill.fill(form, username: username, password: storedPassword)
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
        return OCAuthStart(server: serverURL(c),
                           vpnProtocol: c.kind.openconnectProtocol ?? "anyconnect",
                           params: p)
    }

    /// Carry a signed-in session (cookie + exact cert + connect URL) to a
    /// transport: the in-process NE engine when the config opted in and the
    /// bridge covers its settings, otherwise the openconnect subprocess with
    /// `--cookie-on-stdin` (no sign-in left to do — and no sysext required,
    /// preserving the no-root SOCKS path SSO configs had before).
    private func connectWithCookie(_ config: SubprocessTunnelConfig, auth: OCAuthDone) {
        if config.preferInProcess, Self.inProcessOpenConnectSupports(config) {
            inProcessNE.insert(config.id)
            var l = live[config.id] ?? Live()
            l.status = .connecting
            live[config.id] = l
            Task { [weak self] in
                let ok = await OpenConnectProfileStore.start(config, password: nil, auth: auth) { [weak self] event in
                    self?.handleInProcessEvent(config.id, event)
                }
                guard let self else { return }
                if !ok {
                    Self.log.error("in-process OpenConnect (cookie) failed, falling back to subprocess")
                    self.inProcessNE.remove(config.id)
                    self.connectSubprocess(config, password: nil, command: Self.cookieCommand(for: config, auth: auth))
                }
            }
            return
        }
        connectSubprocess(config, password: nil, command: Self.cookieCommand(for: config, auth: auth))
    }

    /// The in-process libssh engine speaks plain host + auth + SOCKS only. Any
    /// knob it can't express must route to /usr/bin/ssh instead — silently
    /// dropping a jump host would dial the target directly and bypass the
    /// bastion; compression and raw ssh_config options would just be ignored.
    /// (Certificate, Kerberos, kex preference and the host-key pin all ride
    /// in-process since the libssh migration.)
    static func inProcessSSHSupports(_ c: SubprocessTunnelConfig) -> Bool {
        if c.useJumpHost, !c.jumpHost.isEmpty { return false }
        if c.compression { return false }
        if c.sshExtraOptions.contains(where: { !$0.trimmingCharacters(in: .whitespaces).isEmpty }) { return false }
        return true
    }

    /// The tunnel's sign-in method, normalized: "" = automatic.
    static func sshAuthMethod(_ c: SubprocessTunnelConfig) -> String {
        (c.sshAuthMethod ?? "").trimmingCharacters(in: .whitespaces)
    }

    /// Why the chosen sign-in method can't work as configured, or nil. The
    /// single rule the editor's Connect button and connect() both consult, so
    /// a doomed sign-in is refused with its fix rather than failing downstream.
    static func sshAuthBlockReason(_ c: SubprocessTunnelConfig) -> String? {
        switch sshAuthMethod(c) {
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
    /// The pin is only enforceable by the in-process engine (SOCKS mode, no
    /// jump host / compression / extra options); anything else must be refused
    /// honestly — the single rule the editor's caveat and connect() both use.
    static func sshPinBlockReason(_ c: SubprocessTunnelConfig) -> String? {
        guard c.kind == .ssh, sshPinnedKey(c) != nil else { return nil }
        if c.sshMode != .socks {
            return "A pinned host key is only enforced in SOCKS proxy mode (the built-in SSH engine). Switch the mode, or clear the pin under Security."
        }
        if !inProcessSSHSupports(c) {
            return "A pinned host key can't be combined with a jump host, compression, or extra options — those run through /usr/bin/ssh, which can't check the pin. Clear the pin under Security, or remove the conflicting option."
        }
        return nil
    }

    private func connectInProcessSSH(_ config: SubprocessTunnelConfig, password: String?) {
        let engine = SSHTunnelEngine()
        sshEngines[config.id] = engine
        live[config.id] = Live(status: .connecting, socksPort: config.socksPort)
        let cfg = SSHTunnelEngine.Config(
            host: config.server, port: config.port ?? 22,
            // ssh defaults a blank user to the local account; authenticating as
            // "" would burn the whole in-process fallback timeout for nothing.
            username: config.username.isEmpty ? NSUserName() : config.username,
            password: password, identityFile: config.identityFile.isEmpty ? nil : config.identityFile,
            certificateFile: (config.sshCertificateFile?.isEmpty == false) ? config.sshCertificateFile : nil,
            socksPort: config.socksPort,
            pinnedHostKeySHA256: Self.sshPinnedKey(config),
            strictHostKey: config.strictHostKey,
            connectTimeout: config.connectTimeout ?? 15,
            authMethod: Self.sshAuthMethod(config).isEmpty ? nil : Self.sshAuthMethod(config),
            kexAlgorithms: (config.sshKexAlgorithms?.trimmingCharacters(in: .whitespaces)).flatMap { $0.isEmpty ? nil : $0 })
        Task { [weak self] in
            do {
                try await engine.startSOCKS(cfg)
                guard let self else { return }
                // If the user disconnected while we were connecting, `disconnect`
                // already cleared the engine — don't resurrect a .connected status
                // (or a system-proxy pointing at) an orphaned listener.
                guard self.sshEngines[config.id] === engine else { engine.stop(); return }
                var l = self.live[config.id] ?? Live()
                l.status = .connected
                if config.setSystemProxy {
                    Self.setSystemSOCKS(port: config.socksPort, enabled: true)
                    self.proxiedIDs.insert(config.id)
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
                                   command: (String, [String], Data?)? = nil) {
        guard tasks[config.id] == nil else { return }
        if config.kind == .ssh, config.sshMode == .portForward,
           let bad = Self.invalidForwardLine(config.forwards) {
            live[config.id] = Live(status: .failed(
                "Invalid forward “\(bad)” — use “L localPort:host:port”, “R remotePort:host:port” or “D port”."))
            return
        }
        guard let (path, baseArgs, stdin) = command ?? Self.command(for: config, password: password) else {
            live[config.id] = Live(status: .failed("The required command-line tool isn't installed."))
            return
        }
        var args = baseArgs
        // SSH runs as a ControlMaster so forwards can be added/cancelled live
        // (`ssh -S <socket> -O forward/cancel …`) without a reconnect.
        if config.kind == .ssh, let socket = Self.makeControlSocketPath(id: config.id) {
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

        // SSH may prompt for two hosts (jump + target); a host-aware askpass
        // returns the right password for whichever prompt ssh raises.
        var askpass: [String: String] = [:]
        if config.kind == .ssh {
            if let pw = password, !pw.isEmpty { askpass[config.server] = pw }
            if config.useJumpHost, !config.jumpHost.isEmpty,
               let jpw = KeychainCredentialStore.loadCredentials(profile: "tunnel.\(config.id).jump")?.password,
               !jpw.isEmpty {
                askpass[config.jumpHost] = jpw
            }
        }

        let proc = TunnelProcess(
            path: path, args: args, stdin: stdin,
            askpassHostPasswords: askpass.isEmpty ? nil : askpass,
            onLine: { [weak self] line, isReady in
                guard let self else { return }
                var l = self.live[config.id] ?? Live()
                l.log.append(line)
                if l.log.count > 300 { l.log.removeFirst(l.log.count - 300) }
                // The tunnel is up ⇒ openconnect has read its --token-secret file.
                if isReady { Self.removeTokenSecretFile(config.id) }
                if isReady, l.status == .connecting {
                    l.status = .connected
                    // The initial argv forwards live or die with the session
                    // (ExitOnForwardFailure=yes) — ready means they all bound.
                    l.forwardStates = l.forwardStates.mapValues { $0 == .pending ? .active : $0 }
                    if l.socksPort != nil && config.setSystemProxy {
                        Self.setSystemSOCKS(port: config.socksPort, enabled: true)
                        self.proxiedIDs.insert(config.id)
                    }
                }
                self.live[config.id] = l
            },
            onExit: { [weak self] code in
                guard let self else { return }
                Self.removeTokenSecretFile(config.id)
                var l = self.live[config.id] ?? Live()
                // Restore only if WE pointed the system at this tunnel (and a
                // manual disconnect hasn't already restored it).
                if self.proxiedIDs.remove(config.id) != nil { Self.setSystemSOCKS(enabled: false) }
                switch l.status {
                case .connecting: l.status = .failed("Exited before connecting (code \(code)). Check the log.")
                case .connected:  l.status = .disconnected
                default: break
                }
                l.forwardStates = [:]
                self.live[config.id] = l
                self.tasks[config.id] = nil
                self.removeControlSocket(config.id)
            })
        tasks[config.id] = proc
        proc.start()
    }

    func disconnect(_ id: String) {
        // A sign-in still in flight: cancelling the task kills the helper
        // (OpenConnectAuthClient's cancellation handler), which also abandons
        // any browser page still waiting on the gateway.
        if let auth = authTasks.removeValue(forKey: id) { auth.cancel() }
        // Restore the system SOCKS proxy first: TunnelProcess.stop() clears the
        // termination handler, so onExit never runs for a manual disconnect —
        // this is the only restore on that path (and the in-process engine has
        // no exit path at all). proxiedIDs makes exit-path restores a no-op
        // afterwards, so nothing double-toggles.
        if proxiedIDs.remove(id) != nil { Self.setSystemSOCKS(enabled: false) }
        tasks[id]?.stop()
        tasks[id] = nil
        sshEngines[id]?.stop()
        sshEngines[id] = nil
        if inProcessNE.remove(id) != nil { Task { await OpenConnectProfileStore.stop(id) } }
        removeControlSocket(id)
        Self.removeTokenSecretFile(id)   // stop() suppresses onExit — clean up here too
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

    /// Apply the system-proxy toggle to an already-connected SOCKS tunnel (the
    /// setting normally only takes effect at connect time).
    func setSystemProxyLive(_ config: SubprocessTunnelConfig, enabled: Bool) {
        let id = config.id
        guard status(id) == .connected, let port = live[id]?.socksPort else { return }
        if enabled {
            Self.setSystemSOCKS(port: port, enabled: true)
            proxiedIDs.insert(id)
        } else if proxiedIDs.remove(id) != nil {
            Self.setSystemSOCKS(enabled: false)
        }
    }

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
                Self.controlOp(["-O", "forward", "-\(fw.flag)", fw.spec, target], socket: socket)
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
                    Self.controlOp(["-O", "check", target], socket: socket).code == 0
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
                Self.controlOp(["-O", "cancel", "-\(fw.flag)", fw.spec, target], socket: socket)
            }.value
            if r.code != 0 {
                Self.log.error("ssh -O cancel -\(fw.flag, privacy: .public) \(fw.spec, privacy: .public) failed: \(r.output, privacy: .public)")
            }
        }
    }

    // MARK: ControlMaster plumbing

    /// A short socket path (AF_UNIX caps paths around 104 bytes) inside a
    /// private 0700 directory; nil if it can't be created or is still too long.
    private static func makeControlSocketPath(id: String) -> String? {
        let dir = FileManager.default.temporaryDirectory
            .appendingPathComponent("svpn-cm-\(id.prefix(8))", isDirectory: true)
        guard (try? FileManager.default.createDirectory(
            at: dir, withIntermediateDirectories: true,
            attributes: [.posixPermissions: 0o700])) != nil else { return nil }
        let path = dir.appendingPathComponent("ctl").path
        try? FileManager.default.removeItem(atPath: path)   // a stale socket blocks -M
        return path.utf8.count <= 100 ? path : nil
    }

    private func removeControlSocket(_ id: String) {
        guard let socket = controlSockets.removeValue(forKey: id) else { return }
        try? FileManager.default.removeItem(atPath: (socket as NSString).deletingLastPathComponent)
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
                // Point-to-point tun (needs root here + PermitTunnel on the server).
                a += ["-o", "Tunnel=point-to-point", "-w", "any:any"]
            }
            a.append(sshTarget(c))
            return (ssh, a, nil)

        case _ where c.kind.isSSLVPN:
            // OpenConnect covers every SSL-VPN protocol (anyconnect / nc / gp /
            // pulse / f5 / fortinet / array), no root via ocproxy. openfortivpn is
            // the Fortinet-only fallback (needs root).
            if let oc = TunnelCLI.openconnect.resolvedPath {
                // The password is written to stdin ONLY when the argv asked for
                // it. In certificate mode nothing reads stdin, and that unread
                // write is what used to hang the connect (or surface as an
                // opaque certificate error).
                let stdin = openconnectAuthMode(c) == "password"
                    ? password.map { Data(($0 + "\n").utf8) } : nil
                return (oc, openconnectArgs(for: c), stdin)
            }
            if c.kind == .fortinet, let ofv = TunnelCLI.openfortivpn.resolvedPath {
                var a = [serverURL(c), "--username=\(c.username)"]
                if !c.trustedCertSHA256.isEmpty { a += ["--trusted-cert", c.trustedCertSHA256] }
                a += c.extraArgs
                return (ofv, a, password.map { Data(($0 + "\n").utf8) })   // openfortivpn reads pw on stdin
            }
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
        guard openconnectAuthMode(c) == "certificate" else { return nil }
        if c.clientCertFile.trimmingCharacters(in: .whitespaces).isEmpty {
            return "Certificate sign-in needs a client certificate file — set it under Sign-In."
        }
        // The Fortinet-only openfortivpn fallback is driven with a password on
        // stdin and carries no certificate flags — it would sign in with a
        // password while the picker said certificate.
        if c.kind == .fortinet, !TunnelCLI.openconnect.isAvailable {
            return "Certificate sign-in needs openconnect — the openfortivpn fallback can't present a client certificate. \(TunnelCLI.openconnect.installHint)"
        }
        return nil
    }

    /// Whether an address carries a PASSWORD in its userinfo
    /// ("https://user:secret@host"). A bare username ("alex@host", which ssh
    /// accepts as a target) is not a secret and stays allowed.
    static func passwordInAddress(_ raw: String) -> Bool {
        var s = raw.trimmingCharacters(in: .whitespacesAndNewlines)
        if let scheme = s.range(of: "://") { s = String(s[scheme.upperBound...]) }
        let authority = s.prefix { $0 != "/" }
        guard let at = authority.lastIndex(of: "@") else { return false }
        return authority[..<at].contains(":")
    }

    /// Why an address in this config can't be used, or nil. These configs are
    /// persisted unencrypted (UserDefaults) and the address is handed to the
    /// tool on its command line, where any local process can read it with `ps` —
    /// so a password embedded in one is refused, the same rule (and reason) as
    /// `ProxyTunnelConfig.upstreamProblem`. For the proxy it would also defeat
    /// the explicit "include proxy password in process arguments" opt-in.
    static func addressCredentialReason(_ c: SubprocessTunnelConfig) -> String? {
        if passwordInAddress(c.server) {
            return "Take the password out of the server address — put it in the Password field under Sign-In."
        }
        if c.proxyMode == .manual, passwordInAddress(c.proxyURL) {
            return "Take the password out of the proxy address — put it in the proxy password field under Connection."
        }
        return nil
    }

    /// The openconnect argv for a config (everything after the executable),
    /// split out from `command(for:)` so the flag set is testable without
    /// openconnect installed.
    static func openconnectArgs(for c: SubprocessTunnelConfig) -> [String] {
        let proto = c.kind.openconnectProtocol ?? "anyconnect"
        let mode = openconnectAuthMode(c)
        var a = ["--protocol=\(proto)", "--non-inter"]
        // Password mode: the password rides stdin and NO certificate flag is
        // passed. openconnect prefers a certificate when one is configured, so
        // a stale cert path used to win over the piped password — certificate
        // auth while the UI said "Password".
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
            // Encrypted key / PKCS#12: the passphrase the editor stored under
            // "tunnel.<id>.privateKey". --key-password is openconnect's only
            // non-interactive way to take it (no stdin/file variant exists).
            if let kp = KeychainCredentialStore.loadCredentials(profile: "tunnel.\(c.id).privateKey")?.password,
               !kp.isEmpty {
                a += ["--key-password=\(kp)"]
            }
        }
        // Software token (OTP): mode + secret. The secret is the long-lived
        // TOTP/HOTP seed — never place it on argv (world-readable via `ps`).
        // openconnect accepts --token-secret=@FILE; we pass a 0600 temp file.
        // Not under SSO: the identity provider asks for the code itself.
        if mode != "sso", !c.tokenMode.isEmpty {
            a += ["--token-mode=\(c.tokenMode)"]
            if let ref = Self.tokenSecretFileArgument(for: c) { a += ["--token-secret=\(ref)"] }
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
        if let proxy = proxyArgument(for: c) { a += ["--proxy=\(proxy)"] }
        if let ocproxy = TunnelCLI.ocproxy.resolvedPath {
            a += ["--script-tun", "--script", "\(ocproxy) -D \(c.socksPort)"]
        }
        a += c.extraArgs
        a.append(serverURL(c))
        return a
    }

    /// Transport argv for a session ocauth-helper already signed in: connect to
    /// the exact URL and certificate the sign-in produced (`--resolve` defeats
    /// round-robin DNS), with the cookie on stdin — never argv. Auth-time flags
    /// (user, authgroup, token, CSD) are gone; only transport knobs remain.
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
        if let proxy = proxyArgument(for: c) { a += ["--proxy=\(proxy)"] }
        if let ocproxy = TunnelCLI.ocproxy.resolvedPath {
            a += ["--script-tun", "--script", "\(ocproxy) -D \(c.socksPort)"]
        }
        a += c.extraArgs
        a.append(auth.connectURL.isEmpty ? serverURL(c) : auth.connectURL)
        return (oc, a, Data((auth.cookie + "\n").utf8))
    }

    /// Shell-quote a value for safe interpolation into a `/bin/sh -c` command
    /// (ssh runs ProxyCommand through the shell). Wraps in single quotes and
    /// escapes embedded single quotes.
    private static func shellQuote(_ s: String) -> String {
        "'" + s.replacingOccurrences(of: "'", with: "'\\''") + "'"
    }

    /// Write the OTP token secret to a private 0600 temp file and return the
    /// `@path` reference openconnect reads, so the seed never appears on argv.
    /// The file is deleted on the first "ready" line, on process exit, or on a
    /// manual disconnect — whichever comes first (see `removeTokenSecretFile`).
    private static func tokenSecretFileArgument(for c: SubprocessTunnelConfig) -> String? {
        guard let secret = KeychainCredentialStore.loadCredentials(profile: "tunnel.\(c.id).token")?.password,
              !secret.isEmpty, let data = secret.data(using: .utf8) else { return nil }
        let url = FileManager.default.temporaryDirectory
            .appendingPathComponent("svpn-tok-\(c.id)-\(UUID().uuidString)")
        do {
            try data.write(to: url, options: .completeFileProtection)
            try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: url.path)
        } catch { return nil }
        removeTokenSecretFile(c.id)   // a stale one from an aborted connect
        tokenSecretFiles[c.id] = url
        return "@\(url.path)"
    }

    /// Token-secret temp files awaiting cleanup, keyed by tunnel id.
    private static var tokenSecretFiles: [String: URL] = [:]
    private static func removeTokenSecretFile(_ id: String) {
        guard let url = tokenSecretFiles.removeValue(forKey: id) else { return }
        try? FileManager.default.removeItem(at: url)
    }

    /// The OpenConnect `--proxy` value for the config's proxy mode, or nil for
    /// a direct connection (mode .none, or .systemDefault with none configured).
    /// NOTE: openconnect's CLI only accepts proxy credentials embedded in the URL,
    /// which any local process can read via `ps` — so the password rides argv ONLY
    /// when the user opted in (proxyPasswordInArgv). Otherwise username-only: an
    /// authenticating proxy will refuse with a clear 407 rather than leak the
    /// password. The in-process engine (preferInProcess) never execs at all.
    private static func proxyArgument(for c: SubprocessTunnelConfig) -> String? {
        switch c.proxyMode {
        case .none:
            return nil
        case .manual:
            let raw = c.proxyURL.trimmingCharacters(in: .whitespaces)
            guard !raw.isEmpty else { return nil }
            guard !c.proxyUsername.isEmpty else { return raw }
            // Inject user[:pass] after the scheme. Password from the keychain,
            // and only with the explicit "include on argv" opt-in.
            let pw = c.proxyPasswordInArgv == true
                ? (KeychainCredentialStore.loadCredentials(profile: "tunnel.\(c.id).proxy")?.password ?? "")
                : ""
            let cred = pw.isEmpty ? c.proxyUsername : "\(c.proxyUsername):\(pw)"
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
            var inner = "ssh -o \(Self.shellQuote("StrictHostKeyChecking=\(c.strictHostKey)"))"
            if !c.jumpIdentityFile.isEmpty {
                // IdentitiesOnly so the CONFIGURED jump key is the one used —
                // not whatever ~/.ssh/id_* or agent key happens to match first.
                inner += " -i \(Self.shellQuote((c.jumpIdentityFile as NSString).expandingTildeInPath))"
                inner += " -o IdentitiesOnly=yes"
            }
            if let jp = c.jumpPort { inner += " -p \(jp)" }
            let jumpTarget = c.jumpUsername.isEmpty ? c.jumpHost : "\(c.jumpUsername)@\(c.jumpHost)"
            inner += " \(Self.shellQuote(jumpTarget)) -W %h:%p"
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
    private static func serverURL(_ c: SubprocessTunnelConfig) -> String {
        if let p = c.port { return "\(c.server):\(p)" }
        return c.server
    }

    // MARK: System SOCKS proxy (needs admin — networksetup will prompt)

    private static func setSystemSOCKS(port: Int = 0, enabled: Bool) {   // port unused when disabling
        guard let ns = TunnelCLI.networksetup.resolvedPath,
              let service = primaryNetworkService(ns) else { return }
        let p = Process()
        p.executableURL = URL(fileURLWithPath: ns)
        p.arguments = enabled
            ? ["-setsocksfirewallproxy", service, "127.0.0.1", "\(port)"]
            : ["-setsocksfirewallproxystate", service, "off"]
        try? p.run(); p.waitUntilExit()
    }

    private static func primaryNetworkService(_ ns: String) -> String? {
        // The service backing the default route — best-effort via the ordered list.
        let p = Process()
        p.executableURL = URL(fileURLWithPath: ns)
        p.arguments = ["-listallnetworkservices"]
        let pipe = Pipe(); p.standardOutput = pipe
        guard (try? p.run()) != nil else { return nil }
        let data = pipe.fileHandleForReading.readDataToEndOfFile(); p.waitUntilExit()
        let lines = (String(data: data, encoding: .utf8) ?? "")
            .split(separator: "\n").map(String.init)
            .filter { !$0.hasPrefix("An asterisk") && !$0.hasPrefix("*") }
        return lines.first { $0.contains("Wi-Fi") } ?? lines.first
    }
}

/// One supervised child process, reading merged stdout+stderr line-by-line and
/// reporting the "connected" moment via a per-kind readiness marker. nonisolated:
/// it lives on process/pipe callback threads, hopping to the MainActor only to
/// deliver onLine/onExit.
nonisolated final class TunnelProcess: @unchecked Sendable {
    private let path: String
    private let args: [String]
    private let stdin: Data?
    private let askpassHostPasswords: [String: String]?
    private let onLine: @MainActor (String, Bool) -> Void
    private let onExit: @MainActor (Int32) -> Void
    private var process: Process?
    private var askpassURL: URL?

    init(path: String, args: [String], stdin: Data?, askpassHostPasswords: [String: String]?,
         onLine: @escaping @MainActor (String, Bool) -> Void,
         onExit: @escaping @MainActor (Int32) -> Void) {
        self.path = path; self.args = args; self.stdin = stdin
        self.askpassHostPasswords = askpassHostPasswords
        self.onLine = onLine; self.onExit = onExit
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
        "Tunnel is up and running",               // openfortivpn
    ]

    func start() {
        let p = Process()
        p.executableURL = URL(fileURLWithPath: path)
        var argv = args
        var env = ProcessInfo.processInfo.environment

        // SSH password without a TTY: an askpass script that prints the password,
        // forced on with SSH_ASKPASS_REQUIRE=force. Created 0700 atomically
        // (O_CREAT|O_EXCL) and kept for the whole session — a jump-host chain may
        // prompt well after start — then removed on exit/stop.
        if let map = askpassHostPasswords, !map.isEmpty {
            if let url = Self.writeAskpass(map) {
                askpassURL = url
                env["SSH_ASKPASS"] = url.path
                env["SSH_ASKPASS_REQUIRE"] = "force"
                env["DISPLAY"] = ":0"
                argv = ["-v"] + argv   // -v so the readiness markers appear
            }
        } else if path.hasSuffix("ssh") {
            argv = ["-v"] + argv
        }
        p.arguments = argv
        p.environment = env

        let outPipe = Pipe(), inPipe = Pipe()
        p.standardOutput = outPipe
        p.standardError = outPipe
        p.standardInput = inPipe

        outPipe.fileHandleForReading.readabilityHandler = { [weak self] handle in
            guard let self else { return }
            let chunk = handle.availableData
            guard !chunk.isEmpty, let text = String(data: chunk, encoding: .utf8) else { return }
            for raw in text.split(whereSeparator: \.isNewline) {
                let line = String(raw)
                let ready = Self.readyMarkers.contains { line.contains($0) }
                Task { @MainActor in self.onLine(line, ready) }
            }
        }
        p.terminationHandler = { [weak self] proc in
            self?.cleanupAskpass()
            let code = proc.terminationStatus
            Task { @MainActor in self?.onExit(code) }
        }

        do {
            try p.run()
            if let data = stdin {
                inPipe.fileHandleForWriting.write(data)
            }
            try? inPipe.fileHandleForWriting.close()
            process = p
            // Askpass persists for the session (0700 in the user's temp dir) — a
            // jump-host chain may prompt well after start; it's removed on exit.
        } catch {
            cleanupAskpass()
            Task { @MainActor in self.onLine("Failed to launch: \(error.localizedDescription)", false); self.onExit(-1) }
        }
    }

    func stop() {
        process?.terminationHandler = nil
        process?.interrupt()
        // SIGINT lets openconnect/openfortivpn log out of the gateway cleanly;
        // give it a couple of seconds before the SIGTERM backstop. `process`
        // stays set until then so the escalation can find it (instances are
        // one-shot — nothing restarts on this object).
        DispatchQueue.global().asyncAfter(deadline: .now() + 2) { [self] in
            if let p = process, p.isRunning { p.terminate() }
            process = nil
        }
        cleanupAskpass()
    }

    /// A one-shot askpass keyed by host: ssh passes the prompt (which contains
    /// "user@host") as $1, so we return the password for whichever host matches —
    /// giving the jump hop and the target independent passwords. Single-entry
    /// maps just return that password regardless of prompt.
    private static func writeAskpass(_ hostPasswords: [String: String]) -> URL? {
        func sq(_ s: String) -> String { "'" + s.replacingOccurrences(of: "'", with: "'\\''") + "'" }
        var body = "#!/bin/sh\nprompt=\"$*\"\n"
        if hostPasswords.count == 1, let only = hostPasswords.values.first {
            body += "printf %s \(sq(only))\n"
        } else {
            for (host, pw) in hostPasswords where !host.isEmpty {
                body += "case \"$prompt\" in *\(sq(host))*) printf %s \(sq(pw)); exit 0;; esac\n"
            }
            // Fallback: first entry, so a mismatched prompt still yields something.
            if let first = hostPasswords.values.first { body += "printf %s \(sq(first))\n" }
        }
        let dir = FileManager.default.temporaryDirectory
        let url = dir.appendingPathComponent("svpn-askpass-\(UUID().uuidString).sh")
        // Create with mode 0700 atomically (O_EXCL) — a write-then-chmod would
        // leave a umask-permissions window while the password is already inside.
        // fchmod after open covers a restrictive umask stripping the exec bit.
        let fd = open(url.path, O_WRONLY | O_CREAT | O_EXCL, 0o700)
        guard fd >= 0 else { return nil }
        fchmod(fd, 0o700)
        let data = Data(body.utf8)
        let wrote = data.withUnsafeBytes { raw in write(fd, raw.baseAddress, raw.count) == raw.count }
        close(fd)
        guard wrote else { try? FileManager.default.removeItem(at: url); return nil }
        return url
    }
    private func cleanupAskpass() {
        if let url = askpassURL { try? FileManager.default.removeItem(at: url); askpassURL = nil }
    }
}
