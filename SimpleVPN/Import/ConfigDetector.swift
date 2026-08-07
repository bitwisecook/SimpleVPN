// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
//  ConfigDetector.swift
//  Sniffs an imported file's contents (with the filename as a weak hint) to
//  decide which engine it belongs to, so a single "Import…" action and a single
//  drop target can accept any supported config and route it automatically.
//  Content wins over extension — a WireGuard config saved as .txt still lands in
//  WireGuard. The engine's own parser is the final gate; this only picks which.
//

import Foundation

nonisolated enum DetectedConfigKind: Sendable, Equatable {
    case openVPN
    case wireGuard
    case cisco        // AnyConnect XML or legacy .pcf — CiscoImport tells them apart
}

/// `nonisolated` because the answer is a pure function of the bytes and the name,
/// and the pure comparison layer (`ConfigurationDropMerge`) has to ask it off the
/// main actor. There is exactly one answer to "what kind of file is this?" in this
/// app, and a second one written to dodge an isolation annotation would be the
/// beginning of two.
nonisolated enum ConfigDetector {

    static func detect(text: String, filename: String) -> DetectedConfigKind {
        let lower = text.lowercased()
        let ext = (filename as NSString).pathExtension.lowercased()

        // WireGuard: INI-style [Interface]/[Peer] sections with key material.
        if lower.contains("[interface]"), lower.contains("[peer]") || lower.contains("privatekey") {
            return .wireGuard
        }

        // Cisco AnyConnect client profile (XML) or its server-list variant.
        if lower.contains("<anyconnectprofile") || lower.contains("<serverlist") {
            return .cisco
        }
        // Cisco legacy PCF (VPN Client): INI with a [main] section + a host/group.
        if lower.contains("[main]"), lower.contains("host=") || lower.contains("grouppwd") {
            return .cisco
        }
        if ext == "pcf" { return .cisco }
        if ext == "conf", lower.contains("[peer]") { return .wireGuard }

        // Everything else is treated as OpenVPN; its parser reports junk clearly.
        return .openVPN
    }
}
