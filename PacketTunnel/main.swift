// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only

//
//  main.swift
//  PacketTunnel — system extension entry point.
//

import Foundation
import NetworkExtension
import os

// Log which build of the extension is actually loaded — so a stale/activated
// version is immediately obvious in the unified log.
let info = Bundle.main.infoDictionary
let shortVer = info?["CFBundleShortVersionString"] as? String ?? "?"
let buildVer = info?["CFBundleVersion"] as? String ?? "?"
Logger(subsystem: "com.bragi0.SimpleVPN.PacketTunnel", category: "tunnel")
    .log("PacketTunnel system extension starting — v\(shortVer, privacy: .public) (build \(buildVer, privacy: .public))")

autoreleasepool {
    NEProvider.startSystemExtensionMode()
}

dispatchMain()
