// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
//  ProxyApply.swift
//  The Proxy mediator's tier-2 SOLE-WRITER wire payload + NEProxySettings realizer
//  (Docs/StateMediators.md › Proxy mediator, P3 applier). The app's `ProxyRealizer`
//  serializes the ONE arbitrated proxy decision into a `ProxyApplyRequest`, sends it
//  to the OWNER egress over the `proxy:apply:<json>` IPC, and the packet-tunnel
//  provider rebuilds `NEProxySettings` from it and sets it on the tunnel's
//  `NEPacketTunnelNetworkSettings.proxySettings` (the sole write path). Shared so the
//  request is Codable across the root(sysext) ↔ app boundary and the mapping is
//  identical on both sides (and unit-testable from the app target).
//
//  Credentials are NEVER carried here: OpenVPN's pushed proxy has no creds (only an
//  NTLM hint), and a 407 is answered from the keychain at connect. Only host/port/PAC
//  and the bypass list travel on this wire.
//

import Foundation
import NetworkExtension

/// The arbitrated system-proxy decision, reduced to what `NEProxySettings` needs.
/// `nil`/empty fields mean "that scheme isn't set". An all-empty request clears the
/// proxy (Direct). Codable for the `proxy:apply:` IPC; Equatable so the realizer can
/// skip re-applying an unchanged decision.
nonisolated struct ProxyApplyRequest: Codable, Sendable, Equatable {
    var httpHost: String?
    var httpPort: Int?
    var httpsHost: String?
    var httpsPort: Int?
    /// PAC / auto-config URL. When set, PAC wins over manual (the OS evaluates it).
    var pacURL: String?
    /// Hosts that should BYPASS the proxy → `NEProxySettings.exceptionList`.
    var bypass: [String]
    /// `NEProxySettings.excludeSimpleHostnames`.
    var excludeSimpleHostnames: Bool

    init(httpHost: String? = nil, httpPort: Int? = nil,
         httpsHost: String? = nil, httpsPort: Int? = nil,
         pacURL: String? = nil, bypass: [String] = [],
         excludeSimpleHostnames: Bool = false) {
        self.httpHost = httpHost
        self.httpPort = httpPort
        self.httpsHost = httpsHost
        self.httpsPort = httpsPort
        self.pacURL = pacURL
        self.bypass = bypass
        self.excludeSimpleHostnames = excludeSimpleHostnames
    }

    /// A manual endpoint is present when a host is set (port defaults to 0 otherwise).
    private var hasHTTP: Bool { !(httpHost ?? "").isEmpty }
    private var hasHTTPS: Bool { !(httpsHost ?? "").isEmpty }
    private var hasPAC: Bool { !(pacURL ?? "").isEmpty }

    /// Nothing to apply ⇒ Direct (clear the proxy).
    var isEmpty: Bool { !hasHTTP && !hasHTTPS && !hasPAC }

    /// Build `NEProxySettings` from the decision, or `nil` when there is nothing to
    /// set (clear the tunnel's proxy). PAC → `autoProxyConfigurationEnabled` +
    /// `proxyAutoConfigurationURL` (tier-2: let the OS evaluate the PAC; no JS
    /// evaluator — that's tier-3). Manual → `httpServer`/`httpsServer` +
    /// `httpEnabled`/`httpsEnabled`. Bypass → `exceptionList`.
    func makeNEProxySettings() -> NEProxySettings? {
        guard !isEmpty else { return nil }
        let s = NEProxySettings()
        if hasPAC, let url = pacURL, let u = URL(string: url) {
            s.autoProxyConfigurationEnabled = true
            s.proxyAutoConfigurationURL = u
        } else {
            if hasHTTP, let host = httpHost {
                s.httpServer = NEProxyServer(address: host, port: httpPort ?? 0)
                s.httpEnabled = true
            }
            if hasHTTPS, let host = httpsHost {
                s.httpsServer = NEProxyServer(address: host, port: httpsPort ?? 0)
                s.httpsEnabled = true
            }
        }
        if !bypass.isEmpty { s.exceptionList = bypass }
        s.excludeSimpleHostnames = excludeSimpleHostnames
        return s
    }
}
