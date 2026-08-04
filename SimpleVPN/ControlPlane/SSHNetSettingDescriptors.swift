// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
//  SSHNetSettingDescriptors.swift
//  The SSH Network Tunnel option catalog: one EngineSettingSpec per exposed
//  option, grouped by the canonical config-surface taxonomy (Connection →
//  Sign-In → Traffic → Security → Advanced). The ids are the CLI/MDM/manual-anchor
//  contract ("sshnet.server" → manual #sshnet-server) and NEVER change; only
//  display names and summaries may be reworded. SSHNetworkTunnelView renders its
//  sections from this table.
//
//  WHY A SEPARATE NAMESPACE FROM `ssh.*` AND NOT A REUSE OF IT. Setting ids are a
//  GLOBAL namespace bound one-to-one to a `SettingSurface` and to a manual anchor,
//  and ManualAnchorParityTests enforces both directions — so "ssh.server" cannot
//  mean two things. The wording and shape below are deliberately COPIED from the
//  `ssh.*` catalog wherever the concept is the same, because a user who has
//  learned one SSH editor should recognise the other; only the id differs.
//
//  ── WHAT IS ABSENT, AND WHY ── (each is a real decision, not an oversight)
//    • no `mode` / `socks-port` / `system-proxy` / `forwards`: this kind IS the
//      network tunnel. There is no local port for anything to be pointed at.
//    • no jump host: a ProxyJump needs either a second in-process session chained
//      through the first (not built) or ProxyCommand, and the vendored libssh has
//      `SSH_OPTIONS_PROCESS_CONFIG` off and `WITH_EXEC=OFF` as policy — nothing
//      may exec from a config file.
//    • no raw extra options: same reason. There is no ssh_config on this path.
//    • no SSH-agent or Kerberos sign-in: the packet-tunnel extension runs as root
//      in the system context, so `SSH_AUTH_SOCK` and the Kerberos ticket cache
//      simply are not there. The editor SHOWS this rather than quietly offering a
//      shorter list — see `SSHNetworkTunnelConfig.unavailableMethodReason`.
//    • no MSS clamp and no separate "base MTU": nothing is encapsulated on this
//      path (the netstack terminates the guest's TCP and re-originates a stream),
//      so there is no outer header to make room for. See the header of
//      Shared/SSHNetworkTunnelConfig.swift.
//    • no compression: it is negotiated at key exchange and would apply to every
//      flow at once, on a path whose throughput ceiling is already one session's
//      single-threaded crypto. It buys nothing here that it does not cost.
//

import Foundation

@MainActor
enum SSHNetSettings {

    static let all: [EngineSettingSpec] = [

        // MARK: Connection

        .init(id: "sshnet.server", name: "Server Address",
              summary: "The SSH server this tunnel connects to — a name like gateway.example.com, or an IP address.",
              group: .connection, default: ""),

        .init(id: "sshnet.port", name: "Port",
              summary: "The port the server's SSH service answers on. Almost every server uses 22 — leave empty for that.",
              group: .connection, default: 0),

        // MARK: Sign-In

        .init(id: "sshnet.username", name: "Username",
              summary: "The login name to use on the server.",
              group: .signIn, default: ""),

        .init(id: "sshnet.auth-method", name: "Sign-In Method",
              summary: "How to prove who you are: the account password, a private key, or a key with the certificate your organisation signed it with.",
              group: .signIn, default: SSHNetworkTunnelConfig.AuthMethod.password),

        .init(id: "sshnet.password", name: "Password",
              summary: "Used when the server asks for a password, and to unlock a protected key. Kept in your Keychain and never shown again once saved.",
              group: .signIn, default: false),

        .init(id: "sshnet.private-key", name: "Private Key",
              summary: "The private key itself, pasted in. SimpleVPN holds it for you because the tunnel runs outside your login session, where an SSH agent isn't reachable.",
              group: .signIn, default: false),

        .init(id: "sshnet.certificate", name: "Certificate",
              summary: "The OpenSSH certificate that goes with the key — the contents of your …-cert.pub file.",
              group: .signIn, default: false),

        // MARK: Traffic

        .init(id: "sshnet.send-all-traffic", name: "Send All Traffic",
              summary: "Route everything through the SSH server. Off means only the networks you list below go through the tunnel.",
              group: .traffic, default: true),

        .init(id: "sshnet.routes", name: "Networks Through the Tunnel",
              summary: "The networks to send through the SSH server when \u{201C}Send All Traffic\u{201D} is off, like 10.0.0.0/8.",
              group: .traffic, default: [String]()),

        .init(id: "sshnet.excluded-routes", name: "Networks Kept Out",
              summary: "Destinations that stay on your normal connection even when everything else goes through the tunnel. The SSH server's own address is always kept out.",
              group: .traffic, default: [String]()),

        .init(id: "sshnet.dns", name: "DNS Servers",
              summary: "Resolvers to use while connected. Lookups are carried over the SSH connection, so they don't leak onto the local network.",
              group: .traffic, default: [String]()),

        .init(id: "sshnet.far-side-dns", name: "Resolve Names at the Server",
              summary: "Look names up as the SSH server sees them — the way to reach internal names that only it can resolve.",
              group: .traffic, default: false),

        .init(id: "sshnet.far-side-resolver", name: "Server-Side Resolver",
              summary: "The resolver to use at the far end, as the server sees it — 127.0.0.1:53 for the server's own, or an internal address only it can reach.",
              group: .traffic, default: SSHNetworkTunnelConfig.defaultFarSideResolver),

        .init(id: "sshnet.mtu", name: "MTU",
              summary: "The tunnel interface's packet size. Rarely needs changing here: nothing is wrapped inside anything else on this kind of tunnel.",
              group: .traffic, default: SSHNetworkTunnelStartConfig.defaultMTU),

        // MARK: Security

        .init(id: "sshnet.host-key-policy", name: "Host Key Checking",
              summary: "How to handle the server's identity key. \u{201C}Trust on first use\u{201D} shows you a new server's key once and remembers it after you confirm — the safe default.",
              group: .security, default: SSHNetworkTunnelConfig.HostKeyPolicy.trustOnFirstUse),

        .init(id: "sshnet.pinned-host-key", name: "Pinned Host Key",
              summary: "The one server identity this tunnel will accept: the key with this SHA-256 fingerprint. Nothing else is trusted, not even known_hosts.",
              group: .security, default: ""),

        .init(id: "sshnet.key-exchange", name: "Key Exchange",
              summary: "Which key-exchange algorithms to offer (OpenSSH KexAlgorithms syntax). Empty uses the built-in preference, which already favours the post-quantum hybrids.",
              group: .security, default: ""),

        // MARK: Advanced

        .init(id: "sshnet.keepalive", name: "Keepalive (seconds)",
              summary: "How often to nudge the server so an idle tunnel isn't dropped by something in between. 0 turns it off.",
              group: .advanced, default: 30),
    ]

    static let catalog = EngineSettingCatalog(all)

    static func specs(in group: SettingGroup) -> [EngineSettingSpec] {
        all.filter { $0.group == group }
    }
}
