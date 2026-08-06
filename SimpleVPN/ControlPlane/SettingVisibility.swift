// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
//  SettingVisibility.swift
//  Which of an editor's OWN settings are NOT on screen right now, and why.
//
//  "Take me to that setting" (SettingReveal.swift) can only scroll to, pulse and
//  focus a row that EXISTS. Five of the seven editors render a good number of their
//  rows conditionally — behind a toggle, behind the selected protocol, behind the
//  Headscale preset — and the reveal machinery had no idea: a search hit or a
//  related-settings link naming a gated row did nothing at all, while the scroll
//  host still announced "Showing X, in Y" to VoiceOver. That announcement was a
//  LIE, and a lie is worse than silence for someone who can't see the screen.
//
//  Two rules come out of that, and this file is the first:
//
//   • The gate is a fact about the CONFIG, not a disclosure state, so the reveal
//     must NOT "fix" it by flipping it. Turning on "Use an exit node" to show the
//     exit-node picker would edit the user's VPN because they asked a question
//     about it. Instead the reveal says what is true: the row isn't here, and
//     this is what would bring it back.
//   • The tables are PURE and live beside the catalogs rather than inside the
//     views, so `SettingVisibilityTests` can hold every gated id to a real spec
//     and every kind/mode to the rows it actually shows.
//
//  The second rule is in SettingReveal.swift: the announcement is made by the ROW
//  (which exists by construction), never by the host that hoped it would.
//

import Foundation

/// The gated-out settings of one editor, as of one draft.
nonisolated struct SettingVisibility: Equatable, Sendable {

    /// Setting id → why its row isn't rendered, in the user's language. An id
    /// that is absent is on screen.
    var hidden: [String: String]

    init(_ hidden: [String: String] = [:]) { self.hidden = hidden }

    /// Why this setting isn't on screen, or nil when it is (or when it belongs to
    /// another editor entirely — this table only speaks for its own surface).
    func reason(_ id: String) -> String? { hidden[id] }

    /// Nothing gated. The default an editor that renders every row unconditionally
    /// (WireGuard) publishes.
    static let everythingShown = SettingVisibility()
}

// MARK: - Tailscale / Headscale

extension SettingVisibility {

    static func tailscale(_ c: TailscaleConfig) -> SettingVisibility {
        var hidden: [String: String] = [:]
        if c.preset != .headscale {
            hidden["ts.control-url"] = "It only applies to a Headscale VPN — set Preset to Headscale to enter a control server."
        }
        if !c.useExitNode {
            // These two are clique members of `ts.exit-node`, so the help popover
            // offers a link to them EXACTLY when they are hidden. That link is the
            // reason this entry has to exist rather than be assumed away.
            let why = "It only applies while \u{201C}Use an Exit Node\u{201D} is on \u{2014} turn that on and the exit node rows appear."
            hidden["ts.exit-node-machine"] = why
            hidden["ts.exit-node-lan"] = why
        }
        return .init(hidden)
    }
}

// MARK: - IKEv2 / IPsec / L2TP (one editor, three kinds)

extension SettingVisibility {

    /// The native editor swaps most of its surface on the Protocol picker, so a
    /// reveal for the wrong kind's row is the commonest way this feature did
    /// nothing at all.
    static func native(_ c: NativeVPNConfig) -> SettingVisibility {
        var hidden: [String: String] = [:]
        func hide(_ ids: [String], _ why: String) {
            for id in ids { hidden[id] = why }
        }
        let l2tpOnlyHas = "This protocol's configuration profile carries only the server, username, password and shared secret \u{2014} set everything else in System Settings after installing it."

        switch c.kind {
        case .ipsec:
            hide(["native.auth-method", "native.password"],
                 "IPsec always signs in with a shared secret in this build, so there is no method to choose.")
            hide(["native.remote-id", "native.encryption", "native.integrity", "native.dh-group",
                  "native.pfs", "native.ike-lifetime", "native.dpd", "native.mobike"],
                 "macOS only exposes this for IKEv2 \u{2014} set Protocol to IKEv2 to reach it.")
        case .l2tp:
            hide(["native.group", "native.on-demand", "native.disconnect-sleep",
                  "native.auth-method", "native.xauth", "native.xauth-password",
                  "native.include-all", "native.exclude-local",
                  "native.remote-id", "native.encryption", "native.integrity", "native.dh-group",
                  "native.pfs", "native.ike-lifetime", "native.dpd", "native.mobike"],
                 l2tpOnlyHas)
        default:   // .ikev2
            hide(["native.group", "native.xauth", "native.xauth-password"],
                 "It only applies to IPsec (IKEv1) \u{2014} set Protocol to IPsec to reach it.")
        }

        // Within a kind, the mode toggles gate a few more.
        if c.kind == .ikev2 {
            if c.usesSharedSecret {
                hide(["native.username", "native.password"],
                     "Not used while \u{201C}Use a Shared Secret\u{201D} is on \u{2014} turn it off to sign in with a username and password.")
            } else {
                hide(["native.shared-secret"],
                     "Turn on \u{201C}Use a Shared Secret\u{201D} to enter one.")
            }
        }
        if c.kind != .l2tp, !c.includeAllNetworks {
            hidden["native.exclude-local"] =
                "It only applies while \u{201C}Send All Traffic\u{201D} is on \u{2014} without that, the local network is reachable anyway."
        }
        return .init(hidden)
    }
}

// MARK: - Proxy Tunnel

extension SettingVisibility {

    static func proxyTunnel(_ c: ProxyTunnelConfig) -> SettingVisibility {
        var hidden: [String: String] = [:]
        if !c.requiresAuth {
            let why = "Turn on \u{201C}Proxy Requires Sign-In\u{201D} to enter a username and password."
            hidden["px.username"] = why
            hidden["px.password"] = why
        }
        if c.includeDefaultRoute {
            hidden["px.included"] =
                "It only applies to a split tunnel \u{2014} turn off \u{201C}Send All Traffic\u{201D} to choose which networks go through the proxy."
        }
        return .init(hidden)
    }
}

// MARK: - SSH Network Tunnel

extension SettingVisibility {

    static func sshNetworkTunnel(_ c: SSHNetworkTunnelConfig) -> SettingVisibility {
        var hidden: [String: String] = [:]
        if !c.needsPrivateKey {
            hidden["sshnet.private-key"] =
                "Set Sign-In Method to Private Key or Certificate to paste a key."
        }
        if !c.needsCertificate {
            hidden["sshnet.certificate"] =
                "Set Sign-In Method to Certificate to paste one."
        }
        if c.includeDefaultRoute {
            hidden["sshnet.routes"] =
                "It only applies to a split tunnel \u{2014} turn off \u{201C}Send All Traffic\u{201D} to choose which networks go through the tunnel."
        }
        if !c.useFarSideResolver {
            hidden["sshnet.far-side-resolver"] =
                "Turn on \u{201C}Resolve Names at the Server\u{201D} to choose which resolver it uses."
        }
        return .init(hidden)
    }
}

// MARK: - SSH and the SSL VPNs (one editor, eight kinds)

extension SettingVisibility {

    /// This editor serves SSH on one surface and the seven OpenConnect kinds on
    /// another, so nearly every row is gated on the Kind picker before any of its
    /// own toggles get a say.
    static func subprocess(_ c: SubprocessTunnelConfig) -> SettingVisibility {
        var hidden: [String: String] = [:]
        func hide(_ ids: [String], _ why: String) {
            for id in ids { hidden[id] = why }
        }

        if c.kind == .ssh {
            hide(OpenConnectSettings.all.map(\.id),
                 "It belongs to the SSL VPN kinds (AnyConnect, FortiGate, GlobalProtect\u{2026}) \u{2014} this tunnel is SSH.")
            if !c.useJumpHost {
                hide(["ssh.proxy-jump", "ssh.jump-port", "ssh.jump-username", "ssh.jump-identity-file"],
                     "Turn on \u{201C}Connect via a jump host\u{201D} to enter one.")
            }
            if c.sshMode != .socks {
                hide(["ssh.socks-port", "ssh.system-proxy"],
                     "It only applies in SOCKS proxy mode \u{2014} choose that mode to reach it.")
            }
            if c.sshMode != .portForward {
                hidden["ssh.forwards"] =
                    "It only applies in Port forwards mode \u{2014} choose that mode to reach it."
            }
        } else {
            hide(SSHSettings.all.map(\.id),
                 "It belongs to the SSH kind \u{2014} this tunnel is \(c.kind.displayName).")
            if c.clientCertFile.trimmingCharacters(in: .whitespaces).isEmpty,
               c.clientKeyFile.trimmingCharacters(in: .whitespaces).isEmpty {
                hidden["oc.key-password"] =
                    "Set a client certificate or key above \u{2014} the passphrase row appears with it."
            }
            // THE FIVE `oc.pkcs11-*` ROWS AND THE TWO `oc.token-*` ROWS USED TO BE
            // GATED HERE, and there is nothing left to gate: the settings are gone with
            // the features. Choosing "Smartcard or security key" now reveals a banner
            // (`FeatureRequestNotice`) rather than a sub-form, and a banner is not a
            // row a search hit or a related link can land on — so it has no entry in
            // this table and needs none.
            // `oc.sso-browser` is deliberately NOT here: it is RENDERED and
            // disabled with its reason (`ssoBrowserUnused`), which is a row a
            // reveal can land on. Only a row that isn't in the hierarchy at all
            // belongs in this table.
        }
        return .init(hidden)
    }
}

// MARK: - Security keys (the `yk.` rows on the OpenVPN editor's Sign-In tab)

extension SettingVisibility {

    /// `YubiKeySignInSection` renders ONE row unconditionally — the master switch —
    /// and the rest only once it is on, with three further gates on what the key
    /// supplies. Every one of those rows is a clique member of the switch or of the
    /// mechanism (SettingRelations.swift), so the help popover offers a link to them
    /// EXACTLY when they are not on screen: the same case that made the Tailscale
    /// exit-node links look broken. Without this table the reveal would announce
    /// "Showing What the Key Supplies" with nothing there to show.
    ///
    /// Ids are written out rather than derived from `YubiKeySettings.all` to keep
    /// this table pure and readable beside the `oc.*` gates above; the
    /// visibility tests hold every id here to a real spec on the surface.
    static func securityKey(_ c: YubiKeyAuthConfig) -> SettingVisibility {
        var hidden: [String: String] = [:]
        guard c.enabled else {
            let why = "Turn on \u{201C}Use a Security Key\u{201D} to reach the security key rows."
            for id in ["yk.mechanism", "yk.delivery", "yk.serial", "yk.oath-account",
                       "yk.slot", "yk.wait-seconds", "yk.arm-automatically"] {
                hidden[id] = why
            }
            return .init(hidden)
        }
        if c.mechanism != .oathCode {
            hidden["yk.oath-account"] =
                "It only applies when the key supplies a six- or eight-digit code \u{2014} choose that under \u{201C}What the Key Supplies\u{201D}."
        }
        if c.mechanism != .challengeResponse {
            hidden["yk.slot"] =
                "It only applies when the key answers a challenge \u{2014} choose that under \u{201C}What the Key Supplies\u{201D}."
        }
        if c.mechanism == .staticPassword {
            hidden["yk.delivery"] =
                "A fixed password from the key is the whole password, so there is nothing to join it to."
        }
        return .init(hidden)
    }
}
