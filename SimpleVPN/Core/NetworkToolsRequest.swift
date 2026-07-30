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

    func request(_ host: String, autoRun: Bool = true) {
        let trimmed = host.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !trimmed.isEmpty else { return }
        target = trimmed
        self.autoRun = autoRun
        generation += 1
    }
}
