// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only

import Foundation

/// Renders a host for formats that use a colon to delimit the port.
nonisolated enum NetworkEndpoint {
    static func authority(host: String, port: Int? = nil) -> String {
        let host = host.trimmingCharacters(in: .whitespaces)
        let literal = host.contains(":") && !host.hasPrefix("[") ? "[\(host)]" : host
        return port.map { "\(literal):\($0)" } ?? literal
    }
}
