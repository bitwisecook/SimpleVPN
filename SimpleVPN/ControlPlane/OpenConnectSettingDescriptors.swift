// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
//  OpenConnectSettingDescriptors.swift
//  The OpenConnect SSL-VPN option catalog (anchors: oc.x → #oc-x in manual.html)
//  — one table shared by all seven SSL-VPN kinds (AnyConnect, FortiGate, F5 APM,
//  GlobalProtect, Juniper, Pulse, Array), because they are one editor driving one
//  tool with one set of flags.
//
//  In canonical group order (AGENTS.md "Config surfaces"). Note the MTU split
//  documented there: `oc.mtu` is the user-facing tunnel MTU and lives in Traffic
//  (it is the one someone is told to lower when transfers stall); `oc.base-mtu`
//  describes the network path UNDERNEATH the tunnel and stays in Advanced.
//
//  Moved out of `SubprocessTunnelView` so app-wide search can reach it;
//  `SubprocessTunnelView.specs` aliases this table.
//

import Foundation

@MainActor
enum OpenConnectSettings {

    static let all: [EngineSettingSpec] = [

        // MARK: Connection

        // THE VALUE THE WHOLE VPN DEPENDS ON, and it had no spec — so it was
        // invisible to settings search, unaddressable by the CLI and MDM, had no
        // manual anchor behind a help button, and (the reason it was added) could
        // not be REVEALED. The connect list's "this VPN has no server address yet"
        // banner links straight to this row; without an id there was nowhere to
        // link, and the banner would have degraded to "open the config window".
        // AGENTS.md, "Adding a new engine's options", rule 5: every user-facing
        // control gets a spec, including the ones that look like plumbing.
        .init(id: "oc.server", name: "Server Address",
              summary: "The VPN gateway to connect to — the name or address your administrator gave you.",
              group: .connection, default: ""),
        .init(id: "oc.reconnect-timeout", name: "Reconnect Timeout",
              summary: "How long (0–86400 seconds) to keep retrying a dropped tunnel before giving up.",
              group: .connection, default: Int?.none),

        // MARK: Sign-In

        // Spec'd for the same reason as `oc.server`: password sign-in cannot work
        // without it, so the connect list has to be able to say so and point here.
        .init(id: "oc.username", name: "Username",
              summary: "Who you sign in as. Used by password sign-in — a client certificate or single sign-on identifies you instead.",
              group: .signIn, default: ""),
        .init(id: "oc.password", name: "Password",
              summary: "The password for this VPN. Used by password sign-in only — a client certificate or single sign-on doesn't send it.",
              group: .signIn, default: ""),
        .init(id: "oc.client-cert", name: "Client Certificate",
              summary: "A certificate file (PEM or .p12) that identifies YOU to the gateway, instead of a password. Used by certificate sign-in only.",
              group: .signIn, default: ""),
        .init(id: "oc.client-key", name: "Client Private Key",
              summary: "The private key for the client certificate, when it isn't inside the certificate file itself.",
              group: .signIn, default: ""),
        .init(id: "oc.key-password", name: "Key / PKCS#12 Passphrase",
              summary: "The passphrase protecting your client key or .p12 file. Stored in your login keychain.",
              group: .signIn, default: ""),
        // SMARTCARD SIGN-IN HAD FIVE ROWS HERE — provider module, certificate, key,
        // PIN, remember-PIN — and a verification-code token had two. All seven are
        // gone with the features behind them. What stands in their place is not a
        // setting and therefore has no descriptor: the sign-in method picker still
        // offers "Smartcard or security key", and choosing it shows
        // `FeatureRequestNotice.smartcardSignIn` — a banner asking for the use case.
        // A banner is not addressable by the CLI or MDM and has no default to state,
        // which is exactly why it is not spec'd (AGENTS.md rule 5 is about controls
        // that SET something).
        .init(id: "oc.sso-browser", name: "Sign-In Browser",
              summary: "Which browser (and profile) opens the single sign-on page, so passkeys and saved passwords are where you keep them.",
              group: .signIn),

        // MARK: Traffic

        // The SSH surface already names these two concepts — `ssh.socks-port`
        // and `ssh.system-proxy` — and THIS editor renders both surfaces, so the
        // display names and summaries are deliberately the SAME WORDS (AGENTS.md
        // glossary: one concept, one name). Two kinds describing one concept two
        // ways is how a user who learned one editor stops trusting the other.
        .init(id: "oc.socks-port", name: "Local SOCKS Port",
              summary: "Where on this Mac the tunnel offers its proxy — point apps at 127.0.0.1 and this port. Give each tunnel its own port.",
              group: .traffic, default: 1080),
        .init(id: "oc.system-proxy", name: "Route Mac Traffic Through This Proxy",
              summary: "Points the whole Mac at the tunnel's proxy while connected (asks for your admin password) and puts things back on disconnect.",
              group: .traffic, default: false),
        // THE SAME WORDS as `wg.local-lan`, `px.local-lan` and `sshnet.local-lan`,
        // to the character (AGENTS.md glossary: one concept, one name). It is one
        // decision — "keep the printer reachable" — reaching every kind through the
        // one `LocalNetworkCarveOut` definition, and a summary reworded per kind is
        // how a user who learned one editor stops trusting the next.
        //
        // The clause this summary deliberately does NOT carry is "only while Run
        // In-Process is on". That is true, and it is a fact about the TRANSPORT
        // rather than about what the setting means, so it is said where the
        // transport is visible: as a caveat on the row when the tool will run this
        // VPN, and in the manual. Baking it into the shared summary would make four
        // identical decisions read as four different ones.
        .init(id: "oc.local-lan", name: "Allow local network access",
              summary: "Keep printers, file shares and other devices on the network you're on reachable while connected. Traffic to them leaves your Mac outside the tunnel. Default: off.",
              group: .traffic, default: false),
        .init(id: "oc.mtu", name: "MTU",
              summary: "Largest tunnel packet size, 576–1500. Leave empty to auto-detect; lower it if transfers stall.",
              group: .traffic, default: Int?.none),

        // MARK: Security

        // The ONLY control that verifies the SERVER's identity on any of the
        // seven SSL-VPN kinds — everything else here identifies YOU. A typo in it
        // is a connect that fails with an opaque certificate error, which is why
        // `SubprocessTunnelConfig.serverCertPinProblem` checks the shape and the
        // editor blocks Connect on it.
        .init(id: "oc.pinned-server-cert", name: "Pinned Server Certificate",
              summary: "Accept exactly one gateway: the one whose certificate matches this SHA-256 fingerprint. The only server-identity check these VPNs have — paste it exactly as issued.",
              group: .security, default: ""),
        .init(id: "oc.cafile", name: "CA Certificate File",
              summary: "A PEM file of extra certificate authorities to trust for the VPN server, if it uses a private CA.",
              group: .security, default: ""),
        .init(id: "oc.pfs", name: "Perfect Forward Secrecy",
              summary: "Refuse any cipher that doesn't give this session its own key, so a stolen key can't decrypt traffic recorded earlier. Turn on only if the gateway supports it — it refuses the connection otherwise.",
              group: .security, default: false),

        // MARK: Advanced

        .init(id: "oc.os", name: "Reported OS",
              summary: "The operating system OpenConnect claims to be, which some servers policy-check. Pick one only if your gateway refuses a Mac; anything else isn't a value OpenConnect accepts.",
              group: .advanced, default: ""),
        .init(id: "oc.no-dtls", name: "Disable DTLS",
              summary: "Force the slower-but-more-compatible TLS transport instead of UDP DTLS. Turn on only if DTLS is blocked or flaky.",
              group: .advanced, default: false),
        .init(id: "oc.disable-csd", name: "Skip Host Checker",
              summary: "Bypass the server's endpoint-posture/host-checker script. May be required to connect from an unmanaged Mac; some servers refuse without it.",
              group: .advanced, default: false),
        // ON BY DEFAULT, and the default is the point: the built-in engine is a full
        // system tunnel — real interface, real routes, real DNS — while the tool can
        // only give you a SOCKS port on the loopback. A VPN made before this changed
        // keeps whatever it had (see `SubprocessTunnelConfig.preferInProcess`), so the
        // declared default here describes NEW profiles, which is what a "Changed"
        // badge should measure against.
        .init(id: "oc.prefer-in-process", name: "Run In-Process",
              summary: "Carry this VPN with SimpleVPN's own built-in OpenConnect engine, as a full system tunnel with its own routes and DNS, instead of running the openconnect command-line tool (which can only offer a SOCKS proxy on a local port). On for new VPNs. Falls back to the tool for the few settings the engine can't carry.",
              group: .advanced, default: true),
        .init(id: "oc.csd-wrapper", name: "Host-Checker Wrapper",
              summary: "A script that answers the server's endpoint-posture (host checker / EPA) challenge. It runs instead of skipping the check, and takes precedence over Skip Host Checker.",
              group: .advanced, default: ""),
        .init(id: "oc.usergroup", name: "User Group / Path",
              summary: "The portal or gateway this sign-in goes to, as the path part of the address — GlobalProtect's portal-vs-gateway choice, and the URL path Juniper and Pulse expect.",
              group: .advanced, default: ""),
        .init(id: "oc.compression", name: "Compression",
              summary: "Whether the gateway may compress the traffic inside the tunnel. Leave on Default unless your administrator names a setting.",
              group: .advanced, default: ""),
        .init(id: "oc.disable-ipv6", name: "Disable IPv6 in the Tunnel",
              summary: "Ask the gateway for an IPv4-only tunnel. Use it when a broken IPv6 path inside the tunnel makes connections hang.",
              group: .advanced, default: false),
        .init(id: "oc.no-http-keepalive", name: "Disable HTTP Keepalive",
              summary: "Open a fresh connection for each request to the gateway instead of reusing one. A workaround for proxies and gateways that mishandle reused connections.",
              group: .advanced, default: false),
        .init(id: "oc.local-hostname", name: "Reported Hostname",
              summary: "The computer name this Mac reports to the gateway, instead of its real one. Some gateways policy-check or log it.",
              group: .advanced, default: ""),
        .init(id: "oc.user-agent", name: "User Agent",
              summary: "The client identity sent with every request to the gateway. Set it only where a gateway admits specific clients.",
              group: .advanced, default: ""),
        .init(id: "oc.version-string", name: "Client Version String",
              summary: "The client version reported to the gateway, e.g. 4.10.05085. Some gateways refuse a version they don't recognise.",
              group: .advanced, default: ""),
        .init(id: "oc.base-mtu", name: "Base MTU",
              summary: "The MTU of the underlying network path (576–9000, allowing jumbo frames), used to size the tunnel. Leave empty to auto-detect.",
              group: .advanced, default: Int?.none),
        .init(id: "oc.force-dpd", name: "Dead-Peer Detection (seconds)",
              summary: "Send a liveness probe this often (0–3600 seconds) and reconnect fast if the server stops answering. Empty leaves the protocol default.",
              group: .advanced, default: Int?.none),
        .init(id: "oc.extra-args", name: "Extra Arguments",
              summary: "Raw OpenConnect flags (one per row) for site-specific needs not covered above.",
              group: .advanced, default: [String]()),
    ]

    static let catalog = EngineSettingCatalog(all)

    static func specs(in group: SettingGroup) -> [EngineSettingSpec] {
        all.filter { $0.group == group }
    }
}
