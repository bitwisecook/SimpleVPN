// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
//  NetworkToolsRequest.swift
//  Hands a target to the Network Tools window when something else already knows it.
//
//  The case that matters: a connect times out, the toast offers "Network Tools…", and
//  opening a blank form there asks the user to retype the very hostname the app just
//  failed to reach. It already knows it, so it should arrive filled in and tested.
//

import Foundation
import Observation

@MainActor
@Observable
final class NetworkToolsRequest {
    static let shared = NetworkToolsRequest()

    /// Host or address to investigate, plus a bump so the window reacts even when the
    /// same host is requested twice.
    private(set) var target: String = ""
    private(set) var generation = 0
    /// Set when the request came from a failure, so the window can run the probes
    /// immediately rather than waiting to be told again.
    private(set) var autoRun = false

    /// Everything the VPN fingerprint needs beyond the host, when the caller knows it
    /// (the sidebar's Probe command does; the connect-failure toast does not). All
    /// optional, and cleared by a plain `request(_:)` so a later bare request can
    /// never inherit the previous VPN's port and be probed as the wrong protocol.
    private(set) var port: Int?
    private(set) var proto: String?
    private(set) var vpnKind: VPNKind?

    func request(_ host: String, autoRun: Bool = true) {
        submit(host, port: nil, proto: nil, vpnKind: nil, autoRun: autoRun)
    }

    /// "Probe this VPN": prefill the target and run the whole battery, including the
    /// protocol fingerprint aimed at the endpoint a connect would actually dial.
    func probe(host: String, port: Int?, proto: String?, vpnKind: VPNKind?) {
        submit(host, port: port, proto: proto, vpnKind: vpnKind, autoRun: true)
    }

    private func submit(_ host: String, port: Int?, proto: String?,
                        vpnKind: VPNKind?, autoRun: Bool) {
        let trimmed = host.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else { return }
        target = trimmed
        self.port = port
        self.proto = proto
        self.vpnKind = vpnKind
        self.autoRun = autoRun
        generation += 1
    }
}
