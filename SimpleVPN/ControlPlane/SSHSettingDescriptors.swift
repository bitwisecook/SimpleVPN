// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
//  SSHSettingDescriptors.swift
//  The SSH tunnel option catalog: one EngineSettingSpec per exposed option,
//  grouped by the canonical config-surface taxonomy (Connection → Sign-In →
//  Traffic → Security → Advanced). The ids are the CLI/MDM/manual-anchor
//  contract ("ssh.keepalive" → manual #ssh-keepalive) and NEVER change; only
//  display names and summaries may be reworded. SubprocessTunnelView renders
//  its SSH sections from this table; SSHSettingDescriptorTests pins its shape
//  and checks every anchor exists in Resources/Manual/manual.html.
//
//  Every entry maps to a real SubprocessTunnelConfig field honored by the
//  connect path (in-process libssh engine and/or /usr/bin/ssh) — nothing here
//  is aspirational. The pinned host key is the one option only the in-process
//  engine can enforce; SubprocessTunnelManager.sshPinBlockReason is the single
//  honesty gate for it.
//

import Foundation

@MainActor
enum SSHSettings {

    static let all: [EngineSettingSpec] = [

        // MARK: Connection

        .init(id: "ssh.server", name: "Server Address",
              summary: "The computer this tunnel connects to — a name like ssh.example.com, or an IP address.",
              group: .connection, default: ""),

        .init(id: "ssh.port", name: "Port",
              summary: "The port the server's SSH service answers on. Almost every server uses 22 — leave empty for that.",
              group: .connection, default: Int?.none),

        .init(id: "ssh.connect-timeout", name: "Connect Timeout",
              summary: "Give up connecting after this many seconds (1–600) if the server doesn't answer. Empty means the system default.",
              group: .connection, default: Int?.none),

        .init(id: "ssh.proxy-jump", name: "Jump Host",
              summary: "A stepping-stone computer (bastion) this connection goes through first: SSH signs in there, then hops on to the real server.",
              group: .connection, default: ""),

        .init(id: "ssh.jump-port", name: "Jump Host Port",
              summary: "The port the jump host's SSH service answers on. Leave empty for 22.",
              group: .connection, default: Int?.none),

        .init(id: "ssh.jump-username", name: "Jump Host Username",
              summary: "The account to sign in to the jump host with. The jump host's sign-in is independent of the server's.",
              group: .connection, default: ""),

        .init(id: "ssh.jump-identity-file", name: "Jump Host Identity File",
              summary: "A private key file for the jump host — it can be a different key than the server's.",
              group: .connection, default: ""),

        // MARK: Sign-In

        .init(id: "ssh.auth-method", name: "Sign-In Method",
              summary: "How to prove who you are. Automatic tries your key, then the SSH agent, then the password; choosing one method uses exactly that method.",
              group: .signIn, default: ""),

        .init(id: "ssh.username", name: "Username",
              summary: "The account name to sign in to the server with.",
              group: .signIn, default: ""),

        .init(id: "ssh.identity-file", name: "Identity File",
              summary: "A private key file that signs you in without typing anything. Leave empty to use your default keys, the SSH agent, or a password.",
              group: .signIn, default: ""),

        .init(id: "ssh.certificate-file", name: "Certificate File",
              summary: "A certificate that vouches for your key — a file ending in -cert.pub. Only needed if your organisation issues SSH certificates.",
              group: .signIn, default: ""),

        .init(id: "ssh.password", name: "Password",
              summary: "Used when the server asks for a password, and to unlock a protected key file. “Remember” keeps it in your login keychain.",
              group: .signIn, default: ""),

        // MARK: Traffic

        .init(id: "ssh.mode", name: "Mode",
              summary: "How this tunnel carries traffic: one proxy any app can use (SOCKS), specific port forwards, or a full network tunnel.",
              group: .traffic, default: SSHMode.socks),

        .init(id: "ssh.socks-port", name: "Local SOCKS Port",
              summary: "Where on this Mac the tunnel offers its proxy — point apps at 127.0.0.1 and this port. Give each tunnel its own port.",
              group: .traffic, default: 1080),

        .init(id: "ssh.system-proxy", name: "Route Mac Traffic Through This Proxy",
              summary: "Points the whole Mac at the tunnel's proxy while connected (asks for your admin password) and puts things back on disconnect.",
              group: .traffic, default: false),

        .init(id: "ssh.forwards", name: "Port Forwards",
              summary: "Specific connections to carry. “L localPort:host:port” brings a remote service to this Mac; “R” publishes a local one to the server's side.",
              group: .traffic, default: [String]()),

        // MARK: Security

        .init(id: "ssh.strict-host-key", name: "Host Key Checking",
              summary: "How to handle the server's identity key. “Trust on first use” accepts a new server once and remembers it — the safe default.",
              group: .security, default: "accept-new"),

        .init(id: "ssh.pinned-host-key", name: "Pinned Host Key",
              summary: "Accept exactly one server identity: the key with this SHA-256 fingerprint. The strictest check — nothing else is trusted, not even known_hosts.",
              group: .security, default: false),

        .init(id: "ssh.key-exchange", name: "Key Exchange",
              summary: "Which methods may be used to agree the session's encryption keys. Leave empty for the built-in choice, which already prefers post-quantum protection.",
              group: .security, default: ""),

        // MARK: Advanced

        .init(id: "ssh.keepalive", name: "Keepalive (seconds)",
              summary: "How often to send a tiny check-in so idle tunnels aren't dropped by routers and firewalls. 30 is a good default; 0 turns it off.",
              group: .advanced, default: 30),

        .init(id: "ssh.compression", name: "Compression",
              summary: "Compress the traffic inside the tunnel. Can help on very slow links; on fast ones it just adds work.",
              group: .advanced, default: false),

        .init(id: "ssh.extra-options", name: "Extra Options",
              summary: "Raw ssh_config lines (one per row, “Key Value”) for anything not covered here, e.g. Ciphers or MACs.",
              group: .advanced, default: [String]()),
    ]

    static let catalog = EngineSettingCatalog(all)

    static func specs(in group: SettingGroup) -> [EngineSettingSpec] {
        all.filter { $0.group == group }
    }
}
