// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
//  SubprocessTunnel.swift
//  Config for the "command-line" VPN kinds: SSH (dynamic SOCKS `-D`, or `-L/-R` port
//  forwards) and the SSL-VPNs reachable through OpenConnect (FortiGate,
//  F5 BIG-IP APM, and friends). "Command-line" is now about the CONFIG's origin, not
//  the runtime: the same config drives an in-process path wherever the engine can
//  express it — libssh for SOCKS (`inProcessSSHSupports`) and the packet-tunnel
//  extension for OpenConnect, which is now the DEFAULT for a new SSL VPN
//  (`preferInProcess` is Optional; absent means in-process). Genuinely
//  subprocess-only: `.netTunnel`, SSH configs with a jump host or raw extra-options,
//  SSH port forwards, smartcard sign-in, and the four settings
//  `inProcessOpenConnectSupports` still can't carry.
//  The no-root subprocess path exposes a local SOCKS proxy (ssh -D, or
//  `openconnect --script-tun --script "ocproxy -D <port>"`), which SimpleVPN can
//  optionally wire in as the system SOCKS proxy. Secrets live in the keychain
//  (CredentialSource), never here.
//

import Foundation

/// SSH is one kind that can carry traffic three ways.
enum SSHMode: String, Codable, Sendable, CaseIterable {
    case socks        // -D dynamic SOCKS proxy
    case portForward  // -L / -R port forwards
    case netTunnel    // -w point-to-point tun device (needs admin + server PermitTunnel)

    var label: String {
        switch self {
        case .socks: "SOCKS proxy"
        case .portForward: "Port forwards"
        case .netTunnel: "Network tunnel"
        }
    }
}

/// How a TLS-riding SSL-VPN reaches its gateway through any local web proxy.
enum ProxyMode: String, Codable, Sendable, CaseIterable {
    case systemDefault  // honor the Mac's configured proxy (default)
    case none           // ignore any system proxy, connect directly
    case manual         // a specific proxy the user gives here

    var label: String {
        switch self {
        case .systemDefault: "Use system proxy"
        case .none: "Direct (no proxy)"
        case .manual: "Specific proxy"
        }
    }
}

struct SubprocessTunnelConfig: Codable, Sendable, Equatable, Identifiable {
    var id: String = UUID().uuidString
    var name: String = "New Tunnel"
    var kind: VPNKind = .ssh

    // Common
    var server = ""             // host or host:port (SSH), or https URL (SSL-VPN)
    var port: Int? = nil        // SSH port (default 22) / SSL-VPN port
    var username = ""

    // SSH
    var sshMode: SSHMode = .socks
    var socksPort = 1080
    var setSystemProxy = false  // (SOCKS mode) point the active network service's SOCKS at us

    // SSH port forwards ("-L 8080:internal:80", one per line, L or R)
    var forwards: [String] = []

    // SSH — comprehensive knobs (ssh_config / -o)
    var identityFile = ""          // -i <key path> for the TARGET hop
    var compression = false        // -C

    // Jump host (bastion) — its own auth, independent of the target's. Reached
    // via a ProxyCommand inner ssh so its key differs from the target's; its
    // password (keychain "tunnel.<id>.jump") is matched by a host-aware askpass.
    var useJumpHost = false
    var jumpHost = ""
    var jumpUsername = ""
    var jumpPort: Int? = nil
    var jumpIdentityFile = ""
    var serverAliveInterval = 30   // -o ServerAliveInterval
    var connectTimeout: Int? = nil // -o ConnectTimeout
    var strictHostKey = "accept-new" // -o StrictHostKeyChecking: accept-new | yes | no
    var sshExtraOptions: [String] = []  // extra "-o Key=Value" lines

    // SSH — libssh-era additions. All Optional so configs saved before the
    // fields existed still decode (the proxyPasswordInArgv precedent); nil
    // means "off / engine default".
    //
    // How this tunnel signs in. nil = automatic (key file → agent → password,
    // the historical chain). Explicit values pin ONE method — both connect
    // paths then use exactly that method and nothing else (PreferredAuthentications
    // on the subprocess, a single bridge call in-process):
    //   "password" | "key" | "certificate" | "agent" | "kerberos"
    // Kerberos (gssapi-with-mic) is never tried unless chosen — opt-in.
    var sshAuthMethod: String? = nil
    var sshCertificateFile: String? = nil // OpenSSH certificate (…-cert.pub) presented with the key
    // Which SSH agent to ask when signing in through one (OpenSSH's
    // `IdentityAgent`; libssh's SSH_OPTIONS_IDENTITY_AGENT). nil/empty means
    // "whatever SSH_AUTH_SOCK says" — which for an app launched from the Dock is
    // macOS's own ssh-agent, NOT the vendor agent a shell profile points at. A
    // path is therefore how 1Password's or Secretive's keys become reachable at
    // all. See Docs/AuthSecSSHAgent.md.
    var sshAgentSocket: String? = nil
    // SHA-256 host-key pin (hex, optional "SHA256:" prefix). Enforced by the
    // in-process libssh engine ONLY — /usr/bin/ssh has no pin-by-hash option,
    // so a pinned config must never silently route to the subprocess
    // (SubprocessTunnelManager.sshPinBlockReason is the single gate).
    var sshPinnedHostKey: String? = nil
    var sshKexAlgorithms: String? = nil   // KexAlgorithms / SSH_OPTIONS_KEY_EXCHANGE list

    // SSL-VPN (OpenConnect). The --protocol value comes from
    // `kind.openconnectProtocol` — the kind IS the protocol, nothing stored here.
    // How the SSL-VPN authenticates: password, a client certificate, a certificate
    // held on a smartcard/security key (PKCS#11), or single sign-on in the browser
    // (SAML/SSO — this is the passkey/WebAuthn path, since the identity provider's
    // page does the passkey ceremony).
    var authMode = "password"    // "password" | "certificate" | "token" | "sso"
    var realm = ""               // optional auth realm/group (--authgroup)
    var trustedCertSHA256 = ""   // pin the server cert (openconnect --servercert)
    var caFile = ""              // --cafile <path>
    var spoofOS = ""             // --os=<win/mac-intel/…> reported to the gateway
    // Web proxy to the gateway (TLS-riding kinds). manual → proxyURL (+ optional
    // proxyUsername; its password lives in the keychain as "tunnel.<id>.proxy").
    var proxyMode: ProxyMode = .systemDefault
    var proxyURL = ""            // e.g. http://proxy:8080 or socks5://proxy:1080
    var proxyUsername = ""
    // openconnect only accepts proxy credentials embedded in the --proxy URL,
    // which any local process can read via `ps`. Off (nil/false, the default) the
    // password is withheld from argv; the user opts in explicitly. Optional so
    // configs saved before the field existed still decode.
    var proxyPasswordInArgv: Bool? = nil
    var disableDTLS = false      // --no-dtls (force TLS transport)
    var reconnectTimeout: Int? = nil  // --reconnect-timeout <seconds>
    var disableCSD = false       // --csd-wrapper /usr/bin/true (skip host-checker)
    var csdWrapper = ""          // --csd-wrapper <path>: a real host-checker/EPA wrapper (overrides disableCSD)
    // SAML / SSO: which browser (+ profile) opens for the sign-in webview.
    // Defaults to OS default; falls back to the app-wide default (BrowserDefaults).
    var browser = BrowserSelection()
    // Legacy custom external-browser command path (used only if `browser` is the OS
    // default and this is non-empty). Kept for back-compat / power users.
    var samlBrowser = ""         // --external-browser=<path>
    var ocMTU: Int? = nil        // --mtu <bytes>
    var extraArgs: [String] = [] // escape hatch for site-specific flags

    // OpenConnect — fuller option surface (each applies where its protocol uses it;
    // ignored otherwise). Covers the meaningful flags across anyconnect/nc/gp/pulse/
    // f5/fortinet/array.
    var usergroup = ""           // --usergroup (GP portal-vs-gateway, NC/pulse URL path)
    var tokenMode = ""           // --token-mode: "" | totp | hotp | oidc  (secret in keychain "tunnel.<id>.token")
    var clientCertFile = ""      // --certificate (PEM/PKCS#12 client cert for cert auth)
    var clientKeyFile = ""       // --sslkey (client private key; passphrase in keychain "…privateKey")
    var ocCompression = ""       // --compression: "" | stateful | none | all
    var baseMTU: Int? = nil      // --base-mtu
    var forceDPD: Int? = nil     // --force-dpd <sec>
    var enablePFS = false        // --pfs (require perfect forward secrecy)
    var disableIPv6 = false      // --disable-ipv6
    var noHTTPKeepalive = false  // --no-http-keepalive (some buggy proxies)
    var localHostname = ""       // --local-hostname (reported to the gateway)
    var userAgent = ""           // --useragent
    var versionString = ""       // --version-string (spoof the client version)

    // MARK: Which transport carries this SSL-VPN
    //
    // Run the SSL-VPN through the in-process OpenConnect engine (packet-tunnel
    // extension) instead of the `openconnect` subprocess. In-process is a FULL
    // system tunnel — real interface, real routes, real DNS. The subprocess is
    // `ocproxy -D <port>`: a SOCKS listener on the loopback with no interface, no
    // routes and no DNS control at all.
    //
    // OPTIONAL, AND THAT IS THE WHOLE MIGRATION. `nil` means "nobody ever chose",
    // and its EFFECTIVE value is `true` — a profile made from here on runs
    // in-process, which is what the rest of this app is built around. A stored
    // `false` means "this profile is on the tool", and it is honoured.
    //
    // Why not simply flip a `Bool` default: every config saved before today has
    // `"preferInProcess": false` written into it, because a non-Optional Bool is
    // encoded unconditionally whether or not the user ever saw the toggle. So the
    // stored `false` cannot be told from a chosen `false` — and flipping the
    // default would move every existing SSL VPN onto a different transport on the
    // next launch. Anything pointed at that profile's SOCKS port (a browser
    // profile, a `curl` alias, a colleague's script) would find it gone with
    // nothing on screen explaining why. The same rule the SOCKS port itself
    // follows: a stored value other things point at is not rewritten silently.
    //
    // So: absent ⇒ in-process (new profiles, and any imported/MDM config that
    // doesn't mention a transport); present ⇒ exactly what it says. Existing
    // profiles keep the tool, and `inProcessOfferReason` is how they are told
    // there is something better one toggle away.
    var preferInProcess: Bool? = nil

    /// The transport this profile actually asks for. The ONE reader — nothing
    /// should unwrap `preferInProcess` itself, or "never chose" starts meaning
    /// "chose the old thing" again in a second place.
    var runsInProcess: Bool { preferInProcess ?? true }

    /// Whether a transport was ever chosen for this profile. False only for
    /// profiles created after the default moved (and for configs imported without
    /// the key), which is exactly when the modern default should apply.
    var transportWasChosen: Bool { preferInProcess != nil }

    // MARK: PKCS#11 / smartcard sign-in (`authMode == "token"`)
    //
    // All Optional (the `proxyPasswordInArgv` precedent) so tunnels saved before
    // these fields existed still decode. The token PIN is NOT here and never will
    // be: it lives in the login keychain under "tunnel.<id>.pkcs11" when the user
    // asks it to be remembered, and is typed at connect time otherwise. Either way
    // it reaches openconnect on a private pipe — see
    // `SubprocessTunnelManager.openconnectArgs`.

    /// Absolute path to the PKCS#11 provider module (`libykcs11.dylib`,
    /// `opensc-pkcs11.so`, …). Always absolute and always the user's choice: we do
    /// not let the dynamic-loader search order decide which library reads the key.
    var pkcs11ModulePath: String? = nil
    /// RFC 7512 URI naming the CERTIFICATE on the token. openconnect derives the
    /// matching private key from it (`--certificate=pkcs11:…`, no `--sslkey`).
    var pkcs11CertificateURI: String? = nil
    /// An explicit URI for the private key, for the tokens whose key is labelled
    /// differently from its certificate and openconnect's heuristic misses.
    var pkcs11KeyURI: String? = nil
    /// Where the PIN comes from: nil/"ask" = typed at each connect (nothing stored),
    /// "keychain" = the login keychain item saved by the editor.
    var pkcs11PINSource: String? = nil

    var isDefault: Bool { self == SubprocessTunnelConfig(id: id) }

    // MARK: Legal ranges & closed value sets
    //
    // Single source of truth for UI validation, mirroring OpenVPNOverrides's
    // block: the editor's bound and the stored bound are the same constant, so
    // they cannot drift. Every bound below is the tool's own — ssh_config(5) for
    // the ssh.* fields, openconnect(8) for the oc.* ones.

    /// Any TCP port. 0 is not "auto" here — ssh would refuse it.
    static let portRange = 1...65535
    /// The local SOCKS listener binds without root, so the floor is 1024.
    static let socksPortRange = 1024...65535
    /// `-o ConnectTimeout`. 0 means "the system's own", which ssh spells by
    /// leaving the option out — so the floor is 1, and empty means default.
    static let connectTimeoutRange = 1...600
    /// `-o ServerAliveInterval`. 0 turns keepalives off.
    static let keepaliveRange = 0...86_400
    /// `--mtu`: the TUNNEL's MTU. Floor is IPv4's minimum reassembly buffer
    /// (RFC 791); ceiling is standard Ethernet — the tunnel rides an IP path.
    static let ocMTURange = 576...1500
    /// `--base-mtu`: the MTU of the PATH, which may be a jumbo-frame link.
    static let baseMTURange = 576...9000
    /// `--reconnect-timeout`, seconds. 0 = give up immediately.
    static let reconnectTimeoutRange = 0...86_400
    /// `--force-dpd`, seconds. 0 = leave the protocol's own rate.
    static let forceDPDRange = 0...3600

    /// Exactly what `--os=` accepts (openconnect's `openconnect_set_reported_os`).
    /// Free text here meant a typo was accepted and then rejected by the tool at
    /// startup with an opaque error.
    static let spoofOSValues = ["linux", "linux-64", "win", "mac-intel", "android", "apple-ios"]
    /// Exactly what `--token-mode=` accepts, minus "" (= none).
    static let tokenModeValues = ["totp", "hotp", "oidc", "rsa", "yubioath"]
    /// Exactly the three compression modes OpenConnect has, minus "" (= the
    /// engine's own default). These are `oc_compression_mode_t`'s only members
    /// (`Vendor/openconnect-include/openconnect.h`): NONE, STATELESS, ALL.
    ///
    /// "stateful" is NOT among them and never was — the picker used to offer it,
    /// and `--compression=stateful` is refused by the tool at startup. Stored
    /// values are not rewritten (the `spoofOS` rule), so an existing profile
    /// carrying it is CAVEATED by `compressionProblem` instead, and the built-in
    /// engine declines to guess what it meant.
    static let compressionValues = ["none", "stateless", "all"]

    /// Whether a token mode needs a stored seed. `yubioath` reads the code off
    /// the YubiKey itself — requiring a seed for it would block a working
    /// configuration, which is the other half of the validation rule.
    static func tokenModeRequiresSecret(_ mode: String) -> Bool {
        !mode.isEmpty && mode != "yubioath"
    }

    /// Trim, and collapse out-of-range numbers back to "tool default" (nil) or
    /// the documented fallback. Called from every save path, the same shape as
    /// `OpenVPNOverrides.normalized()`.
    func normalized() -> SubprocessTunnelConfig {
        var n = self
        func clean(_ s: String) -> String { s.trimmingCharacters(in: .whitespacesAndNewlines) }
        n.name = clean(name)
        n.server = clean(server)
        n.username = clean(username)
        n.jumpHost = clean(jumpHost)
        n.jumpUsername = clean(jumpUsername)
        n.identityFile = clean(identityFile)
        n.jumpIdentityFile = clean(jumpIdentityFile)
        n.realm = clean(realm)
        n.caFile = clean(caFile)
        n.clientCertFile = clean(clientCertFile)
        n.clientKeyFile = clean(clientKeyFile)
        n.csdWrapper = clean(csdWrapper)
        n.proxyURL = clean(proxyURL)
        n.proxyUsername = clean(proxyUsername)
        n.trustedCertSHA256 = clean(trustedCertSHA256)
        n.usergroup = clean(usergroup)
        n.localHostname = clean(localHostname)
        n.userAgent = clean(userAgent)
        n.versionString = clean(versionString)
        // Trim, and collapse an Optional field that is only whitespace back to nil so
        // "not set" has exactly one representation. For the agent socket that matters
        // twice over: libssh rejects an empty IdentityAgent outright, so a blank must
        // never reach it as a path — nil means "use the inherited agent".
        func cleanOptional(_ s: String?) -> String? {
            guard let t = s?.trimmingCharacters(in: .whitespacesAndNewlines), !t.isEmpty else { return nil }
            return t
        }
        n.sshAgentSocket = cleanOptional(sshAgentSocket)
        n.pkcs11ModulePath = cleanOptional(pkcs11ModulePath)
        n.pkcs11CertificateURI = cleanOptional(pkcs11CertificateURI)
        n.pkcs11KeyURI = cleanOptional(pkcs11KeyURI)
        n.pkcs11PINSource = cleanOptional(pkcs11PINSource)
        n.forwards = forwards.map(clean).filter { !$0.isEmpty }
        n.sshExtraOptions = sshExtraOptions.map(clean).filter { !$0.isEmpty }
        n.extraArgs = extraArgs.map(clean).filter { !$0.isEmpty }

        if let v = n.port, !Self.portRange.contains(v) { n.port = nil }
        if let v = n.jumpPort, !Self.portRange.contains(v) { n.jumpPort = nil }
        if let v = n.connectTimeout, !Self.connectTimeoutRange.contains(v) { n.connectTimeout = nil }
        if !Self.keepaliveRange.contains(n.serverAliveInterval) { n.serverAliveInterval = 30 }
        // The SOCKS port is DELIBERATELY not rewritten. It is a STORED value other
        // things point at — apps configured against it, a browser profile, a
        // colleague's notes — so silently moving it to 1080 on an unrelated save
        // breaks them and makes the number appear to change by itself. The editor
        // blocks Save with `socksPortError` instead (the field already knows), so
        // an out-of-range value can only arrive from an import/CLI/MDM, and
        // `socksPortProblem` is what surfaces it there.
        if let v = n.ocMTU, !Self.ocMTURange.contains(v) { n.ocMTU = nil }
        if let v = n.baseMTU, !Self.baseMTURange.contains(v) { n.baseMTU = nil }
        if let v = n.reconnectTimeout, !Self.reconnectTimeoutRange.contains(v) { n.reconnectTimeout = nil }
        if let v = n.forceDPD, !Self.forceDPDRange.contains(v) { n.forceDPD = nil }
        // NOT blanked. Both are stored values a user (or an importer) put there on
        // purpose, and quietly emptying one on an unrelated save loses it with no
        // trace — the same rule the SOCKS port now follows. The tool would reject
        // the value at startup, so it is CAVEATED on its row instead
        // (`spoofOSProblem` / `tokenModeProblem`), where it can be seen and fixed.
        return n
    }

    /// Why this reported OS isn't one `--os=` accepts, or nil. Non-blocking (the
    /// row shows it as a caveat): the value is the user's, and it may be one a
    /// newer openconnect knows about.
    static func spoofOSProblem(_ raw: String) -> String? {
        let s = raw.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !s.isEmpty, !spoofOSValues.contains(s) else { return nil }
        return "OpenConnect only reports one of \(spoofOSValues.joined(separator: ", ")) — it refuses \u{201C}\(s)\u{201D} at startup. Pick one above, or clear it to report this Mac as it is."
    }

    /// Why this compression mode isn't one OpenConnect has, or nil. Same
    /// non-blocking treatment as `spoofOSProblem` — the value is the user's, and
    /// blanking it on an unrelated save would lose it without a trace.
    static func compressionProblem(_ raw: String) -> String? {
        let s = raw.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !s.isEmpty, !compressionValues.contains(s) else { return nil }
        return "OpenConnect has three compression modes — \(compressionValues.joined(separator: ", ")) — and refuses \u{201C}\(s)\u{201D} at startup. Pick one above, or clear it to leave the engine's default."
    }

    /// Why this token mode isn't one `--token-mode=` accepts, or nil. Same
    /// non-blocking treatment as `spoofOSProblem`.
    static func tokenModeProblem(_ raw: String) -> String? {
        let s = raw.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !s.isEmpty, !tokenModeValues.contains(s) else { return nil }
        return "OpenConnect only accepts one of \(tokenModeValues.joined(separator: ", ")) — it refuses \u{201C}\(s)\u{201D} at startup. Pick one above, or choose \u{201C}None\u{201D}."
    }

    /// Why this SOCKS port can't be used, or nil. BLOCKING (the editor's Save):
    /// the listener would fail to bind, and the alternative — quietly resetting a
    /// stored port to 1080 — breaks whatever was pointed at the old one.
    static func socksPortProblem(_ port: Int) -> String? {
        guard !socksPortRange.contains(port) else { return nil }
        return "Use a SOCKS port between \(socksPortRange.lowerBound) and \(socksPortRange.upperBound) \u{2014} ports below 1024 need root."
    }

    /// The longest AF_UNIX path macOS can connect to: `sockaddr_un.sun_path` is
    /// 104 bytes including its terminator. Vendor agents live deep inside
    /// containers, so this ceiling is reachable in practice rather than theory.
    static let agentSocketPathLimit = 103

    /// Why this SSH agent socket path can't be used, or nil. BLOCKING, because
    /// both connect paths would otherwise fail obscurely: libssh rejects the
    /// option, and `/usr/bin/ssh` needs the value quoted in an `-o
    /// IdentityAgent="…"` line, which a path containing a quote character would
    /// break open. (Existence is deliberately NOT checked here — an agent may not
    /// be running yet, and the editor reports that separately as live status.)
    static func agentSocketProblem(_ path: String) -> String? {
        let p = path.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !p.isEmpty else { return nil }
        if p.contains("\"") || p.contains("\\") {
            return "An SSH agent socket path can't contain a quote or a backslash."
        }
        if !p.hasPrefix("/") && !p.hasPrefix("~") {
            return "Give the full path to the agent's socket, starting with / or ~."
        }
        let expanded = (p as NSString).expandingTildeInPath
        if expanded.utf8.count > agentSocketPathLimit {
            return "That path is too long for macOS to connect to (\(expanded.utf8.count) characters; the limit is \(agentSocketPathLimit))."
        }
        return nil
    }

    /// Non-blocking: a path that isn't there. The tool fails at startup with an
    /// opaque error, so saying it here is cheap and high-signal — but it is a
    /// WARNING, never a block: the file may be created, mounted or synced
    /// between now and the next connect.
    static func missingFileWarning(_ path: String) -> String? {
        let p = path.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !p.isEmpty else { return nil }
        return FileManager.default.fileExists(atPath: (p as NSString).expandingTildeInPath)
            ? nil : "No file at that path."
    }

    /// The SSH key types that live on a hardware security key (FIDO2/U2F): the
    /// private "key file" is only a handle — the signature is made by the device,
    /// which is why connecting needs a physical touch.
    /// `nonisolated`: also consulted off the main actor — SSHTunnelEngine's
    /// sign-in runs on its own serial queue and needs to know a security key when
    /// it sees one (see `securityKeyAdvice`).
    nonisolated static let securityKeyTypes = ["sk-ssh-ed25519@openssh.com",
                                              "sk-ecdsa-sha2-nistp256@openssh.com"]

    /// A note for an identity file that is a SECURITY KEY, or nil for an ordinary
    /// key (and for anything unreadable — this is informational, never blocking).
    ///
    /// Why it exists: `sk-` keys work in-process now (the vendored libssh is built
    /// WITH_FIDO2 — see Tools/build-libssh-xcframework.sh), but connecting stops
    /// dead waiting for a touch nobody was told about. Detected from the public
    /// half (`<path>.pub`), whose first field is the key type in clear text; the
    /// private file is an encrypted blob and is never read for this.
    nonisolated static func securityKeyNote(_ path: String) -> String? {
        let p = path.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !p.isEmpty else { return nil }
        var expanded = (p as NSString).expandingTildeInPath
        if !expanded.hasSuffix(".pub") { expanded += ".pub" }
        guard let data = FileManager.default.contents(atPath: expanded),
              let text = String(data: data.prefix(256), encoding: .utf8) else { return nil }
        let type = text.split(separator: " ", maxSplits: 1).first.map(String.init) ?? ""
        guard securityKeyTypes.contains(type) else { return nil }
        return "This is a hardware security key — you'll be asked to touch it each time this tunnel connects."
    }

    /// Why this pinned SSH host key isn't a fingerprint the in-process engine could
    /// compare, or nil when it is (or the field is empty). BLOCKING, for the same
    /// reason as `serverCertPinProblem`: a mistyped pin is not a warning but a
    /// connection that always fails, a long way from the field that caused it.
    ///
    /// Lives here rather than in the editor because BOTH the editor's inline error
    /// and the connect list's dead-Connect reason ask it (`SubprocessTunnelReadiness`),
    /// and two spellings of one format rule is how they come to disagree.
    static func sshPinnedHostKeyProblem(_ raw: String?) -> String? {
        guard let pin = raw?.trimmingCharacters(in: .whitespacesAndNewlines),
              !pin.isEmpty else { return nil }
        // The stored form tolerates a "SHA256:" / "sha256:" prefix.
        let body = pin.range(of: ":", options: .backwards)
            .map { String(pin[$0.upperBound...]) } ?? pin
        guard body.count != 64 || body.filter(\.isHexDigit).count != 64 else { return nil }
        return "A pinned key is the SHA-256 fingerprint: 64 hex characters (an optional \u{201C}SHA256:\u{201D} prefix is fine)."
    }

    // MARK: The pinned server certificate (the ONE server-identity check)

    /// Why the pinned server certificate isn't a fingerprint OpenConnect would
    /// accept, or nil when it is (or the field is empty). BLOCKING, unlike
    /// `missingFileWarning`: a mistyped pin is not a warning but a connection
    /// that always fails, with an opaque certificate error a long way from the
    /// field that caused it.
    ///
    /// Two forms, exactly the two `--servercert` prints and documents:
    ///  • `pin-sha256:` + base64 of a 32-byte digest (44 characters, ends "="),
    ///    with the prefix optional — this is what OpenConnect itself echoes, so
    ///    it is what a user pastes;
    ///  • `sha256:` + 64 hex characters, the certificate's own digest.
    ///
    /// OpenConnect also accepts `sha1:`; it is deliberately refused here. A
    /// SHA-1 pin is not a fingerprint worth pinning to, and the row is named for
    /// SHA-256.
    static func serverCertPinProblem(_ pin: String) -> String? {
        let p = pin.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !p.isEmpty else { return nil }
        let complaint = "A pinned certificate is either the 44-character key pin OpenConnect prints (ending in \u{201C}=\u{201D}, optionally prefixed \u{201C}pin-sha256:\u{201D}), or \u{201C}sha256:\u{201D} followed by 64 hex characters."
        func isBase64Digest(_ s: String) -> Bool {
            s.count == 44 && s.hasSuffix("=") && Data(base64Encoded: s)?.count == 32
        }
        func isHexDigest(_ s: String) -> Bool {
            s.count == 64 && s.allSatisfy(\.isHexDigit)
        }
        guard let colon = p.lastIndex(of: ":") else { return isBase64Digest(p) ? nil : complaint }
        let prefix = p[p.startIndex..<colon].lowercased()
        let body = String(p[p.index(after: colon)...])
        switch prefix {
        case "pin-sha256": return isBase64Digest(body) ? nil : complaint
        case "sha256":     return isHexDigest(body) ? nil : complaint
        default:           return complaint
        }
    }

    // MARK: PKCS#11 sign-in (the token half of "who are you?")

    /// Whether the PIN is remembered in the login keychain (`"keychain"`) rather
    /// than typed at each connect. Absent/anything else means "ask every time",
    /// which is the default and the safer one.
    var pkcs11RemembersPIN: Bool { pkcs11PINSource == "keychain" }

    /// Why this tunnel's token sign-in can't work as configured, or nil. BLOCKING
    /// (the `serverCertPinProblem` treatment): every one of these fails inside
    /// openconnect with a message about a certificate, a long way from the field
    /// that was actually wrong.
    static func pkcs11Problem(_ c: SubprocessTunnelConfig) -> String? {
        guard c.authMode == "token" else { return nil }
        let module = c.pkcs11ModulePath?.trimmingCharacters(in: .whitespaces) ?? ""
        if module.isEmpty {
            return "Choose the PKCS#11 provider module that reads your token — set it under Sign-In."
        }
        if !module.hasPrefix("/") && !module.hasPrefix("~") {
            return "The provider module needs its full path, starting with \u{201C}/\u{201D}."
        }
        let cert = c.pkcs11CertificateURI?.trimmingCharacters(in: .whitespaces) ?? ""
        if cert.isEmpty {
            return "Pick the certificate on your token — use \u{201C}Find Certificates\u{201D} under Sign-In."
        }
        if let problem = PKCS11URI.problem(cert) { return problem }
        if let key = c.pkcs11KeyURI?.trimmingCharacters(in: .whitespaces), !key.isEmpty,
           let problem = PKCS11URI.problem(key) { return problem }
        return nil
    }

    /// The value to hand `--certificate`. The URI's query is dropped (it can only
    /// carry the two PIN attributes we refuse, or a module path that would fight the
    /// one chosen above); the path attributes pass through UNTOUCHED, because
    /// OpenConnect 7.01+ adds `type=cert`/`type=private` itself and strips the label
    /// when it has to hunt for the key. Rewriting a user's URI to "help" is how a
    /// working configuration stops working.
    static func pkcs11Argument(_ raw: String) -> String {
        PKCS11URI.parse(raw)?.withoutQuery ?? raw.trimmingCharacters(in: .whitespacesAndNewlines)
    }

    /// The value to hand `--servercert`. A pin that already names its own hash
    /// form passes through untouched; a bare base64 digest gets the
    /// `pin-sha256:` prefix it means. Prefixing unconditionally (which is what
    /// the argv builder used to do) turned a perfectly good `sha256:<hex>` pin
    /// into `pin-sha256:sha256:<hex>` — refused at startup.
    static func serverCertArgument(_ pin: String) -> String {
        let p = pin.trimmingCharacters(in: .whitespacesAndNewlines)
        return p.contains(":") ? p : "pin-sha256:\(p)"
    }
}

extension VPNKind {
    /// Kinds whose openconnect protocol implements the `--external-browser`
    /// SAML/SSO flow (anyconnect, gp; pulse partially). Fortinet, Juniper,
    /// Array — and in practice F5 — have no browser sign-in path in
    /// openconnect: "SSO" there would just drop --passwd-on-stdin and fail
    /// under --non-inter. Gates the editor's SSO option and the argv builder.
    nonisolated var supportsExternalBrowserSSO: Bool {
        switch self {
        case .ciscoAnyConnect, .globalProtect, .pulse: true
        default: false
        }
    }
}

/// The command-line tools a subprocess kind can use, and where to find them.
/// `openfortivpn` USED TO BE HERE and is gone. It existed as a FortiGate-only
/// fallback for when `openconnect` was absent — and it could never run: it drives
/// `pppd`, so it needs administrator rights this app does not take, and
/// `sslTransportBlockReason` refused that combination unconditionally *before* the
/// dispatch that would have spawned it. The branch in `command(for:)` was therefore
/// unreachable, and `libopenconnect` carries the `fortinet` protocol in-process
/// anyway. A tool that cannot be reached and would not work if it were is not a
/// fallback; it is a dependency in the credits and a case in every switch.
nonisolated enum TunnelCLI: String, CaseIterable, Sendable {
    case ssh, openconnect, ocproxy, networksetup

    var absolutePathCandidates: [String] {
        switch self {
        case .ssh:           ["/usr/bin/ssh"]
        case .openconnect:   ["/opt/homebrew/bin/openconnect", "/usr/local/bin/openconnect"]
        case .ocproxy:       ["/opt/homebrew/bin/ocproxy", "/usr/local/bin/ocproxy"]
        case .networksetup:  ["/usr/sbin/networksetup"]
        }
    }
    var resolvedPath: String? {
        absolutePathCandidates.first { FileManager.default.isExecutableFile(atPath: $0) }
    }
    var isAvailable: Bool { resolvedPath != nil }

    var installHint: String {
        switch self {
        case .ssh, .networksetup: "Built into macOS."
        case .openconnect: "Install with: brew install openconnect"
        case .ocproxy: "Install with: brew install ocproxy (enables the no-root SOCKS path)"
        }
    }

    /// The bare command, for the "Copy Install Command" button. `installHint` is
    /// a sentence with the command inside it — readable, and unusable to anyone
    /// who can't select half a caption. nil for the tools macOS ships, which have
    /// nothing to install.
    var installCommand: String? {
        switch self {
        case .ssh, .networksetup: nil
        case .openconnect: "brew install openconnect"
        case .ocproxy: "brew install ocproxy"
        }
    }
}

@MainActor
@Observable
final class SubprocessTunnelStore {
    private(set) var tunnels: [SubprocessTunnelConfig] = []
    private static let key = "subprocessTunnels.v1"

    init() { load() }

    func save(_ raw: SubprocessTunnelConfig) {
        // normalized() on every save path (the OpenVPNOverrides rule).
        let t = raw.normalized()
        if let i = tunnels.firstIndex(where: { $0.id == t.id }) { tunnels[i] = t }
        else { tunnels.append(t) }
        persist()
    }
    func remove(_ id: String) {
        tunnels.removeAll { $0.id == id }
        // Delete the tunnel's keychain secrets too — password, proxy/jump passwords,
        // the OTP token seed, the client-key passphrase and the smartcard PIN — or
        // they'd linger in the keychain indefinitely after the tunnel itself is gone.
        for suffix in ["", ".proxy", ".jump", ".token", ".privateKey", ".pkcs11"] {
            KeychainCredentialStore.deleteCredentials(profile: "tunnel.\(id)\(suffix)")
        }
        persist()
    }

    private func load() {
        guard let d = UserDefaults.standard.data(forKey: Self.key),
              let list = try? JSONDecoder().decode([SubprocessTunnelConfig].self, from: d) else { return }
        let (fixed, changed) = Self.migrated(list)
        tunnels = fixed
        if changed { persist() }
    }

    /// The load-time fixups, as a PURE function so each one is testable without
    /// UserDefaults. Both exist because a field's meaning changed after configs
    /// were already saved against the old one.
    static func migrated(_ input: [SubprocessTunnelConfig]) -> (list: [SubprocessTunnelConfig], changed: Bool) {
        var list = input
        var changed = false
        for i in list.indices {
            // 1. SSO saved on a kind openconnect can't browser-sign-in (configs
            // predate the gating): fall back to password so connect doesn't
            // silently fail under --non-inter. The editor explains the switch.
            if list[i].authMode == "sso", !list[i].kind.supportsExternalBrowserSSO {
                list[i].authMode = "password"
                changed = true
            }
            // 2. CERTIFICATE AUTH, recovered. `authMode` defaults to "password"
            // and its picker was INERT until the batch that started gating the
            // `--certificate`/`--sslkey` flags on it — so nobody had ever set it,
            // and every profile that authenticated with a client certificate
            // suddenly sent `--passwd-on-stdin` with no certificate and failed.
            // A stored client certificate or key IS the answer to "which method",
            // for exactly the profiles that were signing in that way yesterday.
            if list[i].kind.isSSLVPN, list[i].authMode == "password",
               !list[i].clientCertFile.trimmingCharacters(in: .whitespaces).isEmpty
                || !list[i].clientKeyFile.trimmingCharacters(in: .whitespaces).isEmpty {
                list[i].authMode = "certificate"
                changed = true
            }
        }
        return (list, changed)
    }
    private func persist() {
        if let d = try? JSONEncoder().encode(tunnels) { UserDefaults.standard.set(d, forKey: Self.key) }
    }
}
