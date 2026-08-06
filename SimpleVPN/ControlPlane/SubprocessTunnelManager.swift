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
//  (SSH via a locked-down SSH_ASKPASS script, OpenConnect via --passwd-on-stdin), watch
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
        /// Smartcard sign-in only: what the tool's output said about the token, so
        /// the exit message can be "that PIN was refused, one attempt left" instead
        /// of "exited before connecting (code 1)".
        var pkcs11: PKCS11ConnectWatcher? = nil
        /// A non-fatal caution to keep visible even once connected (a certificate
        /// about to expire, a PIN counter running down).
        var caution: String? = nil
    }

    private(set) var live: [String: Live] = [:]

    private var tasks: [String: TunnelProcess] = [:]
    private var sshEngines: [String: SSHTunnelEngine] = [:]   // in-process libssh (SOCKS)
    private var inProcessNE: Set<String> = []                 // SSL VPNs running via the NE OpenConnect engine
    private var authTasks: [String: Task<Void, Never>] = [:]  // in-flight ocauth-helper sign-ins (SSO)
    private var proxiedIDs: Set<String> = []                  // ids whose SOCKS proxy we pointed the system at
    private var controlSockets: [String: String] = [:]       // ssh ControlMaster socket per tunnel (live -O ops)
    /// The last token reading per tunnel, from `surveyPKCS11(_:)`. Observed by the
    /// editor (so the PIN-retry warning is on screen BEFORE Connect is pressed) and
    /// read by `connectSubprocess` to seed the output watcher. No PIN is involved in
    /// producing it: enumeration never logs in.
    private(set) var pkcs11TokenStatus: [String: PKCS11TokenStatus] = [:]
    private static let log = Logger(subsystem: "com.bragi0.SimpleVPN", category: "subprocess")

    // MARK: PKCS#11 (smartcard) survey
    //
    // Kept on the manager rather than in the view so the editor and the connect path
    // read the SAME reading — a warning the user saw and a decision we then make on
    // different information is the bug this avoids.

    /// Read the modules on this Mac, and — when a module is chosen — the tokens and
    /// certificates it can see. Never asks for or uses a PIN.
    func surveyPKCS11(_ c: SubprocessTunnelConfig) async -> PKCS11Survey {
        let discovery = PKCS11ModuleDiscovery()
        let enumerator = PKCS11Enumerator.live()
        var survey = PKCS11Survey(modules: discovery.modules(),
                                  toolsAvailable: enumerator.hasAnyTool)
        let module = (c.pkcs11ModulePath ?? "").trimmingCharacters(in: .whitespacesAndNewlines)
        guard !module.isEmpty, enumerator.hasAnyTool else {
            if survey.modules.isEmpty { survey.failure = .noModuleInstalled }
            return survey
        }
        let expanded = (module as NSString).expandingTildeInPath
        switch await enumerator.tokens(module: expanded) {
        case .failure(let failure):
            survey.failure = failure
            pkcs11TokenStatus[c.id] = nil
            return survey
        case .success(let tokens):
            survey.tokens = tokens
            // The token the configured certificate URI points at, when it names one;
            // otherwise the only token there is.
            let scope = (c.pkcs11CertificateURI).flatMap { PKCS11URI.parse($0)?.tokenScope }
            let chosen = tokens.first { token in
                guard let scope, let wanted = PKCS11URI.parse(scope)?.value("serial"),
                      let have = PKCS11URI.parse(token.uri)?.value("serial") else { return false }
                return wanted == have
            } ?? (tokens.count == 1 ? tokens[0] : nil)
            pkcs11TokenStatus[c.id] = chosen
        }
        let scope = (c.pkcs11CertificateURI).flatMap { PKCS11URI.parse($0)?.tokenScope }
        switch await enumerator.certificates(module: expanded, tokenScope: scope) {
        case .failure(let failure):
            // A token with no matching certificate is worth saying, but it must not
            // erase the token reading (which carries the PIN warning).
            survey.failure = failure
        case .success(let certs):
            survey.certificates = certs
        }
        return survey
    }

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
    /// `tokenPIN` is the smartcard PIN for a `authMode == "token"` tunnel, and is
    /// kept a SEPARATE parameter from `password` on purpose: the two travel to
    /// different places, and overloading one slot is how a PIN ends up in a
    /// keychain item named "password" or in an argv built for the other mode. It
    /// exists only for the duration of this call and the `Data` written to the
    /// child's stdin — nothing here retains it.
    func connect(_ config: SubprocessTunnelConfig, password: String?, tokenPIN: String? = nil) {
        guard tasks[config.id] == nil, sshEngines[config.id] == nil,
              !inProcessNE.contains(config.id), authTasks[config.id] == nil else { return }
        // Smartcard sign-in with no PIN anywhere: openconnect would prompt, find the
        // pipe closed and die with "user input required". Say the actual fix.
        if Self.openconnectAuthMode(config) == "token",
           (tokenPIN ?? "").isEmpty,
           (Self.storedPKCS11PIN(config) ?? "").isEmpty {
            live[config.id] = Live(status: .failed(
                "Enter the token's PIN to connect. (Turn on \u{201C}Remember PIN\u{201D} under Sign-In to keep it in your login keychain instead.)"))
            return
        }
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
        // …and the transport it would use can't carry traffic without root. Read
        // BEFORE the dispatch below, because the dispatch is what this predicts.
        if let reason = Self.sslTransportBlockReason(config) {
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
            connectInProcessOpenConnect(config, password: password)
            return
        }
        connectSubprocess(config, password: password, tokenPIN: tokenPIN)
    }

    /// The token PIN the editor saved, when "Remember PIN" is on. Read once per
    /// connect and never cached on this object.
    static func storedPKCS11PIN(_ c: SubprocessTunnelConfig) -> String? {
        guard c.pkcs11RemembersPIN else { return nil }
        let pin = KeychainCredentialStore.loadCredentials(profile: "tunnel.\(c.id).pkcs11")?.password
        return (pin?.isEmpty ?? true) ? nil : pin
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
    /// No SSO clause is needed either. Browser sign-in ends in a cookie, and
    /// `connectWithCookie` has no per-protocol sign-in code left to run, so it carries any
    /// protocol whose settings the bridge covers — and it is only reached for a kind whose
    /// `supportsExternalBrowserSSO` is already true.
    static func willRunInProcess(_ c: SubprocessTunnelConfig) -> Bool {
        c.kind.isSSLVPN && c.runsInProcess && inProcessOpenConnectSupports(c)
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
    /// FOUR REMAIN, and each is a real limit rather than unfinished work:
    ///
    ///  1. **Smartcard sign-in** (`authMode == "token"`, or a `pkcs11:` URI). Our
    ///     libopenconnect is `--with-openssl --without-gnutls`
    ///     (Tools/build-openconnect-xcframework.sh) and OpenConnect's PKCS#11
    ///     support lives only in its GnuTLS/p11-kit backend. Rebuilding with GnuTLS
    ///     would not help: p11-kit's whole job is to `dlopen` a third-party provider
    ///     module, and that `dlopen` is what AMFI refuses inside a sysext-embedding
    ///     app (commit a86046f · Docs/AuthSecPKCS11.md).
    ///  2. **Host checker / endpoint posture** (`csdWrapper`, `disableCSD`).
    ///     `openconnect_setup_csd` exists, but it works by *forking a child* — the
    ///     gateway's trojan, or the wrapper standing in for it. The packet-tunnel
    ///     extension is `com.apple.security.app-sandbox` AND runs as root, so this
    ///     would mean executing a user-nominated script as root from inside the
    ///     sandbox. Not a plumbing job; a decision with an entitlement attached.
    ///  3. **Base MTU** (`baseMTU`) and **HTTP keepalive off** (`noHTTPKeepalive`).
    ///     `--base-mtu` and `--no-http-keepalive` write `vpninfo->basemtu` /
    ///     `->no_http_keepalive` directly from OpenConnect's own CLI. The library
    ///     header exposes no setter for either (`openconnect_set_reqmtu` is `--mtu`,
    ///     a different number — see the MTU pair in `SettingRelations`).
    ///  4. **Extra arguments** (`extraArgs`). Arbitrary argv has no in-process
    ///     equivalent by construction: the escape hatch's whole value is that it
    ///     passes through un-interpreted, and parsing "a known subset" would mean
    ///     silently ignoring the rest — the one thing this predicate exists to
    ///     prevent. It stays a documented fallback to the tool.
    ///
    /// A clause may only be deleted once the setting is genuinely CARRIED. Dropping
    /// a CA file, a client certificate or a proxy silently would connect with
    /// weaker — or simply broken — settings than the profile asks for.
    private static func inProcessOpenConnectSupports(_ c: SubprocessTunnelConfig) -> Bool {
        if c.authMode == "token" { return false }
        if c.pkcs11CertificateURI != nil || c.pkcs11KeyURI != nil { return false }
        // The software-token seed (TOTP/HOTP/…) is a long-lived secret with no
        // channel to the extension yet, and `yubioath`/`rsa` need libpcsclite /
        // libstoken, which this build has not got.
        if !c.tokenMode.isEmpty { return false }
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
    static func inProcessConfiguration(_ c: SubprocessTunnelConfig) -> [String: Any] {
        var conf: [String: Any] = ["profile": c.id,
                                   "vpnType": c.kind.rawValue,
                                   // The port lives INSIDE the address: the bridge
                                   // hands this to `openconnect_parse_url`, which
                                   // takes `host:port` (and `openconnect_get_port`
                                   // reads it back). There is no separate setter.
                                   "server": serverURL(c)]
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
        return conf
    }

    /// The secret half, as `startTunnel(options:)`. Read from the keychain at
    /// connect time and never retained.
    ///
    /// NOTE the asymmetry with the subprocess, and it is in the user's favour:
    /// `openconnect`'s CLI can only take a proxy password embedded in the `--proxy`
    /// URL, where `ps` reads it, which is why `proxyPasswordInArgv` is an explicit
    /// opt-in. In-process there is no argv, so the password travels in memory and
    /// the opt-in is simply not consulted.
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
                self.inProcessNE.remove(config.id); self.live[config.id] = nil
                // The fallback is only a fallback if it can actually carry traffic.
                // `sslTransportBlockReason` was nil at connect() precisely BECAUSE
                // this path was chosen, so re-ask it as a subprocess would: with
                // ocproxy absent, falling back here would spawn `openconnect` to go
                // hunting for a tun device it cannot make. Report, don't fall back.
                if let reason = Self.sslTransportBlockReason(config, inProcess: false) {
                    Self.log.error("in-process OpenConnect failed and the subprocess can't carry it")
                    self.live[config.id] = Live(status: .failed(
                        "SimpleVPN's built-in engine couldn't start this VPN. \(reason)"))
                    return
                }
                Self.log.error("in-process OpenConnect failed, falling back to subprocess")
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
        // The same one predicate as the password path — see `willRunInProcess`. Reached
        // only with `authMode == "sso"` on a kind that really does browser sign-in, which
        // is why no SSO clause is needed inside the predicate itself.
        if Self.willRunInProcess(config) {
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
                    self.inProcessNE.remove(config.id)
                    // Same rule as connectInProcessOpenConnect: `cookieCommand`
                    // appends ocproxy conditionally too, so a fallback without it
                    // would be the silent no-privilege failure again.
                    if let reason = Self.sslTransportBlockReason(config, inProcess: false) {
                        Self.log.error("in-process OpenConnect (cookie) failed and the subprocess can't carry it")
                        self.live[config.id] = Live(status: .failed(
                            "You are signed in, but SimpleVPN's built-in engine couldn't start the tunnel. \(reason)"))
                        return
                    }
                    Self.log.error("in-process OpenConnect (cookie) failed, falling back to subprocess")
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
    /// bastion, and raw ssh_config options would just be ignored.
    /// (Certificate, Kerberos, kex preference and the host-key pin all ride
    /// in-process since the libssh migration; keepalive and compression now do
    /// too — `SSHTunnelEngine.Config.keepaliveInterval` / `.compression` — so
    /// neither forces the subprocess any more.)
    static func inProcessSSHSupports(_ c: SubprocessTunnelConfig) -> Bool {
        if c.useJumpHost, !c.jumpHost.isEmpty { return false }
        if c.sshExtraOptions.contains(where: { !$0.trimmingCharacters(in: .whitespaces).isEmpty }) { return false }
        return true
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
        // A malformed agent socket path blocks whatever the method is: automatic
        // sign-in asks the agent too, so a path neither connect path can use is a
        // problem before the method is even considered.
        if let problem = SubprocessTunnelConfig.agentSocketProblem(c.sshAgentSocket ?? "") {
            return problem
        }
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
            return "A pinned host key can't be combined with a jump host or extra options — those run through /usr/bin/ssh, which can't check the pin. Clear the pin under Security, or remove the conflicting option."
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
            agentSocketPath: Self.sshAgentSocket(config),
            kexAlgorithms: (config.sshKexAlgorithms?.trimmingCharacters(in: .whitespaces)).flatMap { $0.isEmpty ? nil : $0 },
            // ssh.keepalive and ssh.compression are honoured HERE now, not only by
            // /usr/bin/ssh: the engine arms a keepalive timer on its session queue
            // and asks for zlib at key exchange.
            keepaliveInterval: config.serverAliveInterval,
            compression: config.compression)
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
                                   command: (String, [String], Data?)? = nil,
                                   tokenPIN: String? = nil) {
        guard tasks[config.id] == nil else { return }
        if config.kind == .ssh, config.sshMode == .portForward,
           let bad = Self.invalidForwardLine(config.forwards) {
            live[config.id] = Live(status: .failed(
                "Invalid forward “\(bad)” — use “L localPort:host:port”, “R remotePort:host:port” or “D port”."))
            return
        }
        guard let (path, baseArgs, stdin) = command
                ?? Self.command(for: config, password: password,
                                pin: tokenPIN ?? Self.storedPKCS11PIN(config)) else {
            // Name the tool and the fix — "the required command-line tool" sends
            // nobody anywhere (ONTOLOGY: failure text names the fix).
            live[config.id] = Live(status: .failed(Self.missingToolReason(config)))
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
        // Smartcard sign-in gets an output watcher, seeded with whatever the
        // pre-flight token reading knew — that seed is what lets "Wrong PIN" become
        // "that PIN was refused, and one attempt remains".
        let watcher: PKCS11ConnectWatcher? = Self.openconnectAuthMode(config) == "token"
            ? PKCS11ConnectWatcher(tokenStatus: pkcs11TokenStatus[config.id], pinSupplied: true)
            : nil
        live[config.id] = Live(status: .connecting,
                               socksPort: (config.kind == .ssh && config.sshMode == .socks) || usesOcproxy(config) ? config.socksPort : nil,
                               log: initialLog,
                               forwardStates: initialForwards,
                               pkcs11: watcher)

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
                // Smartcard sign-in: read the token's own verdict out of the tool's
                // output while it happens, so the failure can be explained instead
                // of reported as an exit code.
                if l.pkcs11 != nil {
                    l.pkcs11?.observe(line)
                    if let caution = l.pkcs11?.caution { l.caution = caution }
                }
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
                case .connecting:
                    // One actionable sentence beats an exit code. The watcher answers
                    // "which of the six token failures was this?" from the tool's own
                    // words; only when it can't does the generic message stand.
                    l.status = .failed(l.pkcs11?.failureMessage()
                                       ?? "Exited before connecting (code \(code)). Check the log.")
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
    ///
    /// `pin` is the smartcard PIN, and it appears in exactly one place in the whole
    /// return value: the stdin `Data`. It is never formatted into argv, never put in
    /// the environment and never written to a file. `TunnelProcess.start()` writes
    /// that data and closes the pipe immediately, so it exists in this process for
    /// the length of one `write(2)`.
    static func command(for c: SubprocessTunnelConfig, password: String?, pin: String? = nil)
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
            // pulse / f5 / fortinet / array), no root via ocproxy.
            if let oc = TunnelCLI.openconnect.resolvedPath {
                // The password is written to stdin ONLY when the argv asked for
                // it. In certificate mode nothing reads stdin, and that unread
                // write is what used to hang the connect (or surface as an
                // opaque certificate error).
                //
                // Token mode writes the PIN down the SAME pipe: the argv carries
                // --passwd-on-stdin, and OpenConnect gives that value to the first
                // password-type form field it meets, which is the PKCS#11 PIN prompt
                // raised while the certificate is loaded (see openconnectArgs).
                let stdin: Data?
                switch openconnectAuthMode(c) {
                case "password": stdin = password.map { Data(($0 + "\n").utf8) }
                case "token":    stdin = pin.map { Data(($0 + "\n").utf8) }
                default:         stdin = nil
                }
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
        if openconnectAuthMode(c) == "token" {
            // A malformed module path or URI, or a missing one.
            if let reason = SubprocessTunnelConfig.pkcs11Problem(c) { return reason }
            // The vendored in-process engine and `ocauth-helper` are both built
            // `--with-openssl --without-gnutls --without-libpcsclite`
            // (Tools/build-openconnect-xcframework.sh), and OpenConnect's PKCS#11
            // support lives entirely in its GnuTLS/p11-kit backend. So a token
            // tunnel is the ONE case that can only run on the installed tool — the
            // mirror image of `sshPinBlockReason`, which can only run in-process.
            if !TunnelCLI.openconnect.isAvailable {
                return "Smartcard sign-in needs the openconnect tool — SimpleVPN's built-in engine is built without smartcard support. \(TunnelCLI.openconnect.installHint)"
            }
            // openconnect resolves a pkcs11: URI through p11-kit, which only loads
            // modules the registry declares — see PKCS11Module.registeredWithP11Kit.
            // An unregistered module fails with "no certificate found", which reads
            // like a wrong URI and isn't. Block with the fix instead.
            if let reason = pkcs11RegistrationBlockReason(c) { return reason }
            return nil
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
    /// bridge can't carry (a smartcard above all), because then the toggle would be
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
    private static func inProcessRefusalNoun(_ c: SubprocessTunnelConfig) -> String {
        if openconnectAuthMode(c) == "token" || c.pkcs11CertificateURI != nil || c.pkcs11KeyURI != nil {
            return "SimpleVPN's built-in engine is built without smartcard support"
        }
        if !c.tokenMode.isEmpty { return "the built-in engine can't hold a verification-code token seed" }
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

    /// Why the chosen PKCS#11 module can't be reached by `openconnect`, or nil.
    /// Split out from `sslAuthBlockReason` so the editor can pair it with a
    /// copy-to-clipboard button for `pkcs11RegistrationCommand(_:)`.
    static func pkcs11RegistrationBlockReason(_ c: SubprocessTunnelConfig,
                                             discovery: PKCS11ModuleDiscovery = .init()) -> String? {
        guard openconnectAuthMode(c) == "token",
              let module = discovery.module(atUserPath: c.pkcs11ModulePath ?? ""),
              !module.registeredWithP11Kit else { return nil }
        return "\u{201C}\((module.path as NSString).lastPathComponent)\u{201D} isn't registered with p11-kit, so openconnect can't load it. Run the one-line command below (no admin rights needed), then connect."
    }

    /// The command the editor offers to copy when the module isn't registered.
    static func pkcs11RegistrationCommand(_ c: SubprocessTunnelConfig,
                                          discovery: PKCS11ModuleDiscovery = .init()) -> String? {
        guard openconnectAuthMode(c) == "token",
              let module = discovery.module(atUserPath: c.pkcs11ModulePath ?? ""),
              !module.registeredWithP11Kit else { return nil }
        return module.registrationCommand
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
        //
        // TOKEN MODE USES THE SAME PIPE, and that is the whole PIN story. OpenConnect
        // raises the PKCS#11 PIN as an ordinary password-type form field (its
        // `gnutls_pin_callback` builds a form with auth_id "pkcs11_pin"), and its CLI
        // hands a `--passwd-on-stdin` value to the FIRST password field it meets. The
        // token's PIN is asked for while the certificate is being loaded, before any
        // gateway form, so it is that first field. The alternatives were all worse:
        // `--key-password=<PIN>` and a `pin-value=`/`pin-source=` URI attribute both
        // put the PIN (or a path to it) on a command line every local process can
        // read with `ps`. `--passwd-on-stdin` also sets OpenConnect's own
        // `allow_stdin_read`, so a SECOND prompt reads the (already closed) pipe,
        // gets EOF and fails immediately instead of hanging — and, importantly, is
        // never answered with a second wrong PIN attempt.
        if mode == "password" || mode == "token" { a.append("--passwd-on-stdin") }
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
        // Token mode ONLY: the certificate lives on a smartcard / security key, so
        // `--certificate` takes a PKCS#11 URI instead of a path. OpenConnect 7.01+
        // derives the matching private key from the same URI (adding `type=cert` and
        // `type=private` itself), which is why `--sslkey` is passed only when the
        // user gave an explicit key URI for a token that labels the two differently.
        // NO `--key-password` here: the PIN is on stdin (see --passwd-on-stdin above).
        if mode == "token" {
            if let cert = c.pkcs11CertificateURI, !cert.trimmingCharacters(in: .whitespaces).isEmpty {
                a += ["--certificate=\(SubprocessTunnelConfig.pkcs11Argument(cert))"]
            }
            if let key = c.pkcs11KeyURI, !key.trimmingCharacters(in: .whitespaces).isEmpty {
                a += ["--sslkey=\(SubprocessTunnelConfig.pkcs11Argument(key))"]
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
        // SIGINT lets openconnect log out of the gateway cleanly;
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
