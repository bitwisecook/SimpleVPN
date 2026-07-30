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

    struct Live: Sendable {
        var status: Status = .disconnected
        var socksPort: Int? = nil
        var log: [String] = []
    }

    private(set) var live: [String: Live] = [:]

    private var tasks: [String: TunnelProcess] = [:]
    private var sshEngines: [String: SSHTunnelEngine] = [:]   // in-process libssh2 (SOCKS)
    private var inProcessNE: Set<String> = []                 // SSL VPNs running via the NE OpenConnect engine
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
    /// subprocess path. SSH SOCKS runs on libssh2 (no /usr/bin/ssh); if it can't
    /// start, we fall back to the subprocess so nothing regresses.
    func connect(_ config: SubprocessTunnelConfig, password: String?) {
        guard tasks[config.id] == nil, sshEngines[config.id] == nil,
              !inProcessNE.contains(config.id) else { return }
        if config.kind == .ssh, config.sshMode == .socks {
            connectInProcessSSH(config, password: password)
            return
        }
        // SSO needs a browser, which only the user-context subprocess can open (the
        // system extension runs as root and can't launch a GUI browser) — so SSO
        // SSL-VPNs skip the in-process engine and use the subprocess path.
        if config.preferInProcess, config.authMode != "sso",
           [.fortinet, .f5apm, .ciscoAnyConnect].contains(config.kind) {
            connectInProcessOpenConnect(config, password: password)
            return
        }
        connectSubprocess(config, password: password)
    }

    private func connectInProcessOpenConnect(_ config: SubprocessTunnelConfig, password: String?) {
        inProcessNE.insert(config.id)
        live[config.id] = Live(status: .connecting)
        Task { [weak self] in
            let ok = await OpenConnectProfileStore.start(config, password: password)
            guard let self else { return }
            if ok {
                var l = self.live[config.id] ?? Live(); l.status = .connected; self.live[config.id] = l
            } else {
                Self.log.error("in-process OpenConnect failed, falling back to subprocess")
                self.inProcessNE.remove(config.id); self.live[config.id] = nil
                self.connectSubprocess(config, password: password)
            }
        }
    }

    private func connectInProcessSSH(_ config: SubprocessTunnelConfig, password: String?) {
        let engine = SSHTunnelEngine()
        sshEngines[config.id] = engine
        live[config.id] = Live(status: .connecting, socksPort: config.socksPort)
        let cfg = SSHTunnelEngine.Config(
            host: config.server, port: config.port ?? 22, username: config.username,
            password: password, identityFile: config.identityFile.isEmpty ? nil : config.identityFile,
            socksPort: config.socksPort,
            strictHostKey: config.strictHostKey)
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
                if config.setSystemProxy { Self.setSystemSOCKS(port: config.socksPort, enabled: true) }
                self.live[config.id] = l
            } catch {
                // In-process failed → clean up and fall back to /usr/bin/ssh.
                guard let self else { return }
                engine.stop()
                // Only fall back if this engine is still the active one; a user
                // disconnect during connect must not spawn a zombie subprocess.
                guard self.sshEngines[config.id] === engine else { return }
                Self.log.error("in-process SSH failed, falling back to subprocess: \(error.localizedDescription, privacy: .public)")
                self.sshEngines[config.id] = nil
                self.live[config.id] = nil
                self.connectSubprocess(config, password: password)
            }
        }
    }

    private func connectSubprocess(_ config: SubprocessTunnelConfig, password: String?) {
        guard tasks[config.id] == nil else { return }
        guard let (path, args, stdin) = Self.command(for: config, password: password) else {
            live[config.id] = Live(status: .failed("The required command-line tool isn't installed."))
            return
        }
        live[config.id] = Live(status: .connecting,
                               socksPort: (config.kind == .ssh && config.sshMode == .socks) || usesOcproxy(config) ? config.socksPort : nil)

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
                if isReady, l.status == .connecting {
                    l.status = .connected
                    if l.socksPort != nil && config.setSystemProxy {
                        Self.setSystemSOCKS(port: config.socksPort, enabled: true)
                    }
                }
                self.live[config.id] = l
            },
            onExit: { [weak self] code in
                guard let self else { return }
                var l = self.live[config.id] ?? Live()
                if config.setSystemProxy { Self.setSystemSOCKS(port: config.socksPort, enabled: false) }
                switch l.status {
                case .connecting: l.status = .failed("Exited before connecting (code \(code)). Check the log.")
                case .connected:  l.status = .disconnected
                default: break
                }
                self.live[config.id] = l
                self.tasks[config.id] = nil
            })
        tasks[config.id] = proc
        proc.start()
    }

    func disconnect(_ id: String) {
        tasks[id]?.stop()
        tasks[id] = nil
        sshEngines[id]?.stop()
        sshEngines[id] = nil
        if inProcessNE.remove(id) != nil { Task { await OpenConnectProfileStore.stop(id) } }
        if var l = live[id] { l.status = .disconnected; live[id] = l }
    }

    private func usesOcproxy(_ c: SubprocessTunnelConfig) -> Bool {
        [.fortinet, .f5apm, .ciscoAnyConnect].contains(c.kind) && TunnelCLI.ocproxy.isAvailable
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
                    let parts = f.split(separator: " ", maxSplits: 1).map(String.init)
                    if parts.count == 2 { a += ["-\(parts[0].uppercased())", parts[1]] }
                    else { a += ["-L", f] }
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
                let proto = c.kind.openconnectProtocol ?? "anyconnect"
                let sso = c.authMode == "sso"
                var a = ["--protocol=\(proto)", "--non-inter"]
                if !c.username.isEmpty { a += ["--user=\(c.username)"] }
                if !sso { a += ["--passwd-on-stdin"] }   // SSO: the browser signs in, no password on stdin
                if !c.realm.isEmpty { a += ["--authgroup=\(c.realm)"] }
                if !c.usergroup.isEmpty { a += ["--usergroup=\(c.usergroup)"] }
                if !c.trustedCertSHA256.isEmpty { a += ["--servercert=pin-sha256:\(c.trustedCertSHA256)"] }
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
                // Client-certificate auth (PEM / PKCS#12) + optional separate key.
                if !c.clientCertFile.isEmpty { a += ["--certificate=\((c.clientCertFile as NSString).expandingTildeInPath)"] }
                if !c.clientKeyFile.isEmpty { a += ["--sslkey=\((c.clientKeyFile as NSString).expandingTildeInPath)"] }
                // Software token (OTP): mode + secret. The secret is the long-lived
                // TOTP/HOTP seed — never place it on argv (world-readable via `ps`).
                // openconnect accepts --token-secret=@FILE; we pass a 0600 temp file.
                if !c.tokenMode.isEmpty {
                    a += ["--token-mode=\(c.tokenMode)"]
                    if let ref = Self.tokenSecretFileArgument(for: c) { a += ["--token-secret=\(ref)"] }
                }
                // SAML/SSO webview browser (F5 / GP / AnyConnect / Pulse). Empty ⇒
                // OpenConnect's default (the system default browser).
                // SSO browser: per-VPN choice → app default → OS default. A chosen
                // browser+profile gets a generated launcher for --external-browser;
                // OS default emits no flag (OpenConnect opens the default browser).
                let browser = BrowserDefaults.resolve(c.browser)
                if let script = BrowserCatalog.externalBrowserScript(for: browser, id: c.id) {
                    a += ["--external-browser=\(script)"]
                } else if !c.samlBrowser.isEmpty {   // legacy custom command
                    a += ["--external-browser=\((c.samlBrowser as NSString).expandingTildeInPath)"]
                }
                // Host-checker / endpoint posture (F5 EPA, Cisco CSD, GP/NC trojan):
                // a real wrapper wins over the skip; otherwise "disable" stubs it out.
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
                return (oc, a, sso ? nil : password.map { Data(($0 + "\n").utf8) })
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

    /// Shell-quote a value for safe interpolation into a `/bin/sh -c` command
    /// (ssh runs ProxyCommand through the shell). Wraps in single quotes and
    /// escapes embedded single quotes.
    private static func shellQuote(_ s: String) -> String {
        "'" + s.replacingOccurrences(of: "'", with: "'\\''") + "'"
    }

    /// Write the OTP token secret to a private 0600 temp file and return the
    /// `@path` reference openconnect reads, so the seed never appears on argv.
    /// The file is removed shortly after the process has read it at startup.
    private static func tokenSecretFileArgument(for c: SubprocessTunnelConfig) -> String? {
        guard let secret = KeychainCredentialStore.loadCredentials(profile: "tunnel.\(c.id).token")?.password,
              !secret.isEmpty, let data = secret.data(using: .utf8) else { return nil }
        let url = FileManager.default.temporaryDirectory
            .appendingPathComponent("svpn-tok-\(c.id)-\(UUID().uuidString)")
        do {
            try data.write(to: url, options: .completeFileProtection)
            try FileManager.default.setAttributes([.posixPermissions: 0o600], ofItemAtPath: url.path)
        } catch { return nil }
        Task.detached {
            try? await Task.sleep(nanoseconds: 15_000_000_000)
            try? FileManager.default.removeItem(at: url)
        }
        return "@\(url.path)"
    }

    /// The OpenConnect `--proxy` value for the config's proxy mode, or nil for
    /// a direct connection (mode .none, or .systemDefault with none configured).
    /// NOTE: openconnect's CLI only accepts proxy credentials embedded in the URL,
    /// so a proxy password unavoidably appears on argv on this *fallback* path. The
    /// primary in-process OpenConnect engine (preferInProcess) does not exec at all
    /// and never exposes it; prefer that path when a proxy password is configured.
    private static func proxyArgument(for c: SubprocessTunnelConfig) -> String? {
        switch c.proxyMode {
        case .none:
            return nil
        case .manual:
            let raw = c.proxyURL.trimmingCharacters(in: .whitespaces)
            guard !raw.isEmpty else { return nil }
            guard !c.proxyUsername.isEmpty else { return raw }
            // Inject user[:pass] after the scheme. Password from the keychain.
            let pw = KeychainCredentialStore.loadCredentials(profile: "tunnel.\(c.id).proxy")?.password ?? ""
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

    private static func sshCommonOptions(_ c: SubprocessTunnelConfig) -> [String] {
        var a = ["-o", "ExitOnForwardFailure=yes",
                 "-o", "ServerAliveInterval=\(max(0, c.serverAliveInterval))",
                 "-o", "StrictHostKeyChecking=\(c.strictHostKey)"]
        if let p = c.port { a += ["-p", "\(p)"] }
        if !c.identityFile.isEmpty { a += ["-i", (c.identityFile as NSString).expandingTildeInPath] }
        if c.useJumpHost, !c.jumpHost.isEmpty {
            // ProxyCommand (not -J) so the jump hop can use its own key. Its
            // password, if any, is matched by the host-aware askpass.
            // ssh runs ProxyCommand via /bin/sh -c, so every interpolated field must
            // be shell-quoted or a jump-host value like "x; curl … | sh" is RCE.
            var inner = "ssh -o StrictHostKeyChecking=accept-new"
            if !c.jumpIdentityFile.isEmpty {
                inner += " -i \(Self.shellQuote((c.jumpIdentityFile as NSString).expandingTildeInPath))"
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

    private static func setSystemSOCKS(port: Int, enabled: Bool) {
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

    /// Readiness signatures across the tools we drive.
    private static let readyMarkers = [
        "Local forwarding listening",         // ssh -v
        "Entering interactive session",       // ssh
        "debug1: Entering interactive",       // ssh -v
        "Connected to HTTPS on",              // openconnect
        "Established DTLS connection",        // openconnect
        "Configured as",                      // openconnect tun
        "Tunnel is up and running",           // openfortivpn
    ]

    func start() {
        let p = Process()
        p.executableURL = URL(fileURLWithPath: path)
        var argv = args
        var env = ProcessInfo.processInfo.environment

        // SSH password without a TTY: a one-shot askpass script that prints the
        // password, forced on with SSH_ASKPASS_REQUIRE=force. File is 0700 and
        // deleted as soon as the process starts.
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
        process?.terminate()
        process = nil
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
        guard (try? body.write(to: url, atomically: true, encoding: .utf8)) != nil else { return nil }
        try? FileManager.default.setAttributes([.posixPermissions: 0o700], ofItemAtPath: url.path)
        return url
    }
    private func cleanupAskpass() {
        if let url = askpassURL { try? FileManager.default.removeItem(at: url); askpassURL = nil }
    }
}
