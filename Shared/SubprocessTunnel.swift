// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
//  SubprocessTunnel.swift
//  Config for VPN kinds carried by a managed command-line process rather than a
//  NetworkExtension: SSH (dynamic SOCKS `-D`, or `-L/-R` port forwards) and the
//  SSL-VPNs reachable through OpenConnect / openfortivpn (FortiGate, F5 BIG-IP
//  APM, and friends). The no-root path exposes a local SOCKS proxy (ssh -D, or
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

    // SSL-VPN (OpenConnect / openfortivpn). The --protocol value comes from
    // `kind.openconnectProtocol` — the kind IS the protocol, nothing stored here.
    // How the SSL-VPN authenticates: password, a client certificate, or single
    // sign-on in the browser (SAML/SSO — this is the passkey/WebAuthn path, since
    // the identity provider's page does the passkey ceremony).
    var authMode = "password"    // "password" | "certificate" | "sso"
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

    // Run the SSL-VPN through the in-process OpenConnect engine (packet-tunnel
    // extension) instead of the `openconnect` subprocess. Falls back to the
    // subprocess if the in-process path can't start. Default off.
    var preferInProcess = false

    var isDefault: Bool { self == SubprocessTunnelConfig(id: id) }
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
nonisolated enum TunnelCLI: String, CaseIterable, Sendable {
    case ssh, openconnect, openfortivpn, ocproxy, networksetup

    var absolutePathCandidates: [String] {
        switch self {
        case .ssh:           ["/usr/bin/ssh"]
        case .openconnect:   ["/opt/homebrew/bin/openconnect", "/usr/local/bin/openconnect"]
        case .openfortivpn:  ["/opt/homebrew/bin/openfortivpn", "/usr/local/bin/openfortivpn"]
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
        case .openfortivpn: "Install with: brew install openfortivpn"
        case .ocproxy: "Install with: brew install ocproxy (enables the no-root SOCKS path)"
        }
    }
}

@MainActor
@Observable
final class SubprocessTunnelStore {
    private(set) var tunnels: [SubprocessTunnelConfig] = []
    private static let key = "subprocessTunnels.v1"

    init() { load() }

    func save(_ t: SubprocessTunnelConfig) {
        if let i = tunnels.firstIndex(where: { $0.id == t.id }) { tunnels[i] = t }
        else { tunnels.append(t) }
        persist()
    }
    func remove(_ id: String) {
        tunnels.removeAll { $0.id == id }
        // Delete the tunnel's keychain secrets too — password, proxy/jump passwords,
        // the OTP token seed and the client-key passphrase — or they'd linger in
        // the keychain indefinitely after the tunnel itself is gone.
        for suffix in ["", ".proxy", ".jump", ".token", ".privateKey"] {
            KeychainCredentialStore.deleteCredentials(profile: "tunnel.\(id)\(suffix)")
        }
        persist()
    }

    private func load() {
        guard let d = UserDefaults.standard.data(forKey: Self.key),
              var list = try? JSONDecoder().decode([SubprocessTunnelConfig].self, from: d) else { return }
        // SSO saved on a kind openconnect can't browser-sign-in (configs predate
        // the gating): fall back to password so connect doesn't silently fail
        // under --non-inter. The editor shows a note explaining the switch.
        var migrated = false
        for i in list.indices where list[i].authMode == "sso" && !list[i].kind.supportsExternalBrowserSSO {
            list[i].authMode = "password"
            migrated = true
        }
        tunnels = list
        if migrated { persist() }
    }
    private func persist() {
        if let d = try? JSONEncoder().encode(tunnels) { UserDefaults.standard.set(d, forKey: Self.key) }
    }
}
