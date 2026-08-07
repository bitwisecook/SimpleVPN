// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
//  WireGuardEndpointSelection.swift
//  CHOOSING A WIREGUARD SERVER MOVES TWO VALUES, NOT ONE — and this file is the
//  only place that is allowed to move either.
//
//  WHY IT NEEDS A FILE. Every other kind in this app answers "which server?" with
//  an address: picking one writes `OpenVPNOverrides.server/port/proto` and the
//  certificate machinery does the rest. WireGuard has no certificate. The peer's
//  PUBLIC KEY is the authentication, and Mullvad gives every one of its 567 relays
//  its own (Docs/ServiceBundles.md §2). So a WireGuard server list is a list of
//  (address, key) PAIRS, and selecting a row has to swap BOTH, at the same
//  instant, or the tunnel dials server A while insisting on server B's identity.
//
//  WHAT GETTING IT WRONG LOOKS LIKE, and it is the reason this is a typed decision
//  rather than two assignments at a call site: the handshake FAILS CLOSED — no
//  traffic leaks, nothing reaches the wrong exit — but it fails SILENTLY. WireGuard
//  sends an initiation, the relay cannot decrypt it because the static key does not
//  belong to it, and nothing is sent back. What the user sees is a tunnel that
//  connects to nothing, forever, with no error, having changed only a menu.
//  "Confusing" is the accurate word and it is worse than an error.
//
//  THE REFUSAL IS THE OTHER HALF. A row with no key of its own, in a list where
//  other rows have one, cannot be selected — because the only thing that could be
//  done with it is keep the key that is already there, which is precisely the
//  mismatch above. A profile whose servers ALL have no key is the ordinary
//  single-peer WireGuard VPN (one relay, one key, in the `.conf` the user
//  imported), and there moving the address alone is exactly right. So the rule
//  keys off the LIST, not off the row.
//
//  PURE. No controller, no view, no network — which is what lets the invariant be
//  pinned by a test rather than asserted in a comment.
//

import Foundation

nonisolated enum WireGuardEndpointSelection {

    /// What selecting a row did, or why it did nothing.
    enum Outcome: Equatable {
        /// Apply this configuration. Address and key move together or not at all.
        case applied(WireGuardConfig)
        /// Nothing was changed, and this is the sentence to show. Never a silent
        /// no-op: a menu that appears to accept a choice and quietly keeps the old
        /// one is how somebody spends an afternoon on a tunnel that cannot connect.
        case refused(String)
    }

    /// The endpoint a WireGuard profile is currently pointed at, matched against a
    /// list — so the picker's tick and the map's highlight read the CONFIG rather
    /// than a second copy of the selection.
    ///
    /// Matched on host and port, and then required to agree on the key. A row whose
    /// address matches but whose key does not is NOT the selection: that is the
    /// mismatch state this file exists to prevent, and showing it as selected would
    /// hide it behind a tick.
    static func selected(in endpoints: [VPNEndpoint], config: WireGuardConfig) -> VPNEndpoint? {
        let host = config.endpointHost.trimmingCharacters(in: .whitespaces)
        guard !host.isEmpty else { return nil }
        let key = config.peerPublicKey.trimmingCharacters(in: .whitespaces)
        return endpoints.first { e in
            guard e.host == host else { return false }
            guard let rowKey = e.peerPublicKey else { return true }
            return rowKey == key
        }
    }

    /// Point a WireGuard configuration at one of its servers.
    ///
    /// `all` is the whole list the user was choosing from, and it is a parameter
    /// rather than derived because the DECISION depends on it: whether a keyless row
    /// is an ordinary hand-typed server or a hole in a provider's list is a fact
    /// about the list, not about the row.
    static func selecting(_ target: VPNEndpoint,
                          from all: [VPNEndpoint],
                          in config: WireGuardConfig) -> Outcome {
        let endpoint = endpointString(host: target.host,
                                      port: target.port ?? currentPort(config) ?? defaultPort)
        if let key = target.peerPublicKey.flatMap(VPNEndpoint.canonicalPeerKey) {
            var next = config
            next.endpoint = endpoint
            next.peerPublicKey = key
            return .applied(next)
        }
        // No key on this row. If anything else in the list has one, the list is a
        // set of pairs and this row is not a usable half of one.
        if all.contains(where: { $0.peerPublicKey != nil }) {
            return .refused(refusal(target))
        }
        var next = config
        next.endpoint = endpoint
        return .applied(next)
    }

    /// The one refusal sentence. It says what is missing, why it matters HERE
    /// (WireGuard has no certificate to fall back on), and what would fix it —
    /// rather than "invalid server", which tells a person nothing they can act on.
    static func refusal(_ target: VPNEndpoint) -> String {
        "\(target.displayLabel) has no public key of its own, and the other servers in "
            + "this list do. WireGuard identifies a server by its public key rather than by a "
            + "certificate, so using this address with another server\u{2019}s key would connect to "
            + "nothing at all \u{2014} quietly. Refresh the server list, or add the key on this row."
    }

    /// `host:port`, with an IPv6 literal bracketed — the grammar
    /// `WireGuardConfig.endpointProblem` and wireguard-go's own resolver both take.
    static func endpointString(host: String, port: Int) -> String {
        let h = host.trimmingCharacters(in: .whitespaces)
        return h.contains(":") && !h.hasPrefix("[") ? "[\(h)]:\(port)" : "\(h):\(port)"
    }

    /// The port the configuration is on now, so choosing a different relay from the
    /// same provider keeps the port the user's own `.conf` chose rather than
    /// silently reverting to the well-known one.
    static func currentPort(_ config: WireGuardConfig) -> Int? {
        let s = config.endpoint.trimmingCharacters(in: .whitespaces)
        guard !s.isEmpty else { return nil }
        if s.hasPrefix("["), let close = s.firstIndex(of: "]"),
           s.index(after: close) < s.endIndex, s[s.index(after: close)] == ":" {
            return Int(s[s.index(close, offsetBy: 2)...])
        }
        guard let colon = s.lastIndex(of: ":"),
              !s[s.index(after: colon)...].contains(":") else { return nil }
        return Int(s[s.index(after: colon)...])
    }

    /// WireGuard's registered port. Only reached when neither the row nor the
    /// configuration says otherwise.
    static let defaultPort = 51820
}
