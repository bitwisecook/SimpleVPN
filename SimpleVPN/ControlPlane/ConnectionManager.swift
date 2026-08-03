// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
//  ConnectionManager.swift
//  The Connection Manager: the everyday controls for how a VPN behaves, framed as
//  plain-language choices — not "problems". Each is a simple on/off with a friendly
//  sentence describing what the current state means for this connection. Genuine
//  anomalies (an IPv6 or DNS leak, a stalled path, a captive portal) stay in the
//  Connection Doctor, which only appears when something is actually wrong.
//

import Foundation

/// One on/off connection behaviour, with human wording for each state.
struct ConnectionSetting: Identifiable {
    let id: String
    let title: String
    let symbol: String
    let manualAnchor: String
    /// True when turning this ON trades a little security for compatibility
    /// (shown in amber). Most settings are neutral choices.
    var riskyWhenOn = false
    let isOn: (OpenVPNOverrides) -> Bool
    let set: (inout OpenVPNOverrides, Bool) -> Void
    /// Non-technical description of the CURRENT state, personalised with the VPN's
    /// name and — when the user allowed reading it — the name of the Wi-Fi network
    /// this Mac is on, so "local devices" means something concrete.
    let explanation: (_ isOn: Bool, _ vpnName: String, _ networkName: String?) -> String
}

enum ConnectionManager {

    static let settings: [ConnectionSetting] = [
        ConnectionSetting(
            id: "local-lan", title: "Allow local devices", symbol: "printer",
            manualAnchor: "openvpn-local-lan",
            isOn: { $0.allowLocalLanAccess == true },
            set: { o, on in o.allowLocalLanAccess = on ? true : nil },
            explanation: { on, name, network in
                // The user's mental model is THE WI-FI THEY'RE ON, so name it when
                // location permission lets us read the SSID.
                let net = network.map { "\u{201C}\($0)\u{201D}" } ?? "the network you're on"
                return on
                ? "Printers, drives and other devices on \(net) stay reachable while you're connected."
                : "Devices on \(net) — printers, drives, your router's page — can't be reached while you're connected, because everything goes through \(name)."
            }),

        ConnectionSetting(
            id: "block-outside", title: "Internet only through the VPN", symbol: "lock.shield",
            manualAnchor: "openvpn-unused-families",
            isOn: { $0.allowUnusedAddrFamilies == .block },
            set: { o, on in o.allowUnusedAddrFamilies = on ? .block : nil },
            explanation: { on, name, _ in
                on
                ? "Internet traffic \(name) can't carry is blocked rather than slipping out over your normal connection \u{2014} nothing goes around the VPN."
                : "Internet traffic \(name) doesn't carry \u{2014} for example IPv6 on an IPv4-only VPN \u{2014} can still use your normal connection, which may reveal your real location."
            }),

        ConnectionSetting(
            id: "stay-connected", title: "Stay connected through interruptions", symbol: "arrow.triangle.2.circlepath",
            manualAnchor: "openvpn-tun-persist",
            isOn: { $0.tunPersist == true },
            set: { o, on in o.tunPersist = on ? true : nil },
            explanation: { on, name, _ in
                on
                ? "\(name) reconnects on its own after your Mac sleeps or switches networks, without dropping the apps that are using it."
                : "\(name) disconnects fully when your Mac sleeps or changes network, and may ask you to sign in again when it comes back."
            }),
    ]

    /// Is the whole internet routed through the tunnel? Read from the live routing
    /// table (the default route runs over the tunnel interface) — a fact we can
    /// verify, not a guess. nil ⇒ not determinable yet.
    static func isFullTunnel(_ topo: NetworkTopology) -> Bool? {
        guard let def = topo.defaultInterface,
              let iface = topo.interfaces.first(where: { $0.name == def }) else { return nil }
        return iface.kind == .tunnel
    }

    /// Friendly one-liner describing the tunnel mode for this VPN.
    /// `leakPossible` = block-outside is off, so unused address families can still
    /// travel outside the tunnel. Saying "ALL of your traffic" while the toggle right
    /// below explains that some can leak was a direct self-contradiction.
    static func tunnelModeExplanation(fullTunnel: Bool?, vpnName: String,
                                      leakPossible: Bool = false) -> String {
        switch fullTunnel {
        case .some(true):
            leakPossible
            ? "Your internet traffic is going through \(vpnName), so websites and services see its location, not yours \u{2014} except traffic \(vpnName) doesn't carry, which can still use your normal connection. Turn on \u{201C}Internet only through the VPN\u{201D} below to block that too."
            : "All of your internet traffic is going through \(vpnName). Websites and services see \(vpnName)'s location, not yours."
        case .some(false):
            "Only some traffic goes through \(vpnName) (a split tunnel); everything else uses your normal internet connection."
        case .none:
            "How much of your traffic goes through \(vpnName) will show here once it's connected."
        }
    }
}
