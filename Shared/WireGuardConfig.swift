// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
//  WireGuardConfig.swift
//  WireGuard configuration: parse/serialize the standard wg-quick .conf INI, so
//  SimpleVPN can import, edit and export real WireGuard configs. Running the
//  tunnel in-app needs the WireGuardKit engine linked into the packet-tunnel
//  provider (dispatched by vpnType alongside OpenVPN) — until that engine build
//  lands, export hands a valid .conf to the official WireGuard app. The private
//  key is a secret: kept in the keychain, never in providerConfiguration.
//

import Foundation
import Observation

struct WireGuardConfig: Codable, Sendable, Equatable, Identifiable {
    var id = UUID().uuidString
    var name = "New WireGuard"

    // [Interface]
    var privateKey = ""
    var addresses: [String] = []     // e.g. "10.0.0.2/32"
    var dns: [String] = []
    var mtu: Int? = nil
    var listenPort: Int? = nil
    var fwMark: String = ""          // FwMark (hex/int) — mark on outgoing packets
    var table: String = ""           // Table = auto | off | <number>

    // [Peer] (single peer — the common client case; multi-peer round-trips via rawExtraPeers)
    var peerPublicKey = ""
    var presharedKey = ""
    var endpoint = ""                // host:port
    var allowedIPs: [String] = ["0.0.0.0/0", "::/0"]
    var persistentKeepalive: Int? = nil

    /// Additional [Peer] blocks preserved verbatim for lossless round-trip.
    var rawExtraPeers: [String] = []

    var isFullTunnel: Bool { allowedIPs.contains { $0 == "0.0.0.0/0" || $0 == "::/0" } }
}

extension WireGuardConfig {
    /// Parse a wg-quick .conf. Lenient: unknown keys are ignored, extra peers kept.
    static func parse(_ text: String, name: String) -> WireGuardConfig {
        var c = WireGuardConfig(name: name)
        enum Section { case none, interface, peer }
        var section: Section = .none
        var peerIndex = 0

        func values(_ s: String) -> [String] {
            s.split(separator: ",").map { $0.trimmingCharacters(in: .whitespaces) }.filter { !$0.isEmpty }
        }

        for rawLine in text.split(separator: "\n", omittingEmptySubsequences: false) {
            let line = rawLine.trimmingCharacters(in: .whitespaces)
            if line.isEmpty || line.hasPrefix("#") { continue }
            if line.hasPrefix("[") {
                let tag = line.lowercased()
                if tag.hasPrefix("[interface]") { section = .interface }
                else if tag.hasPrefix("[peer]") { section = .peer; peerIndex += 1
                    if peerIndex > 1 { c.rawExtraPeers.append("[Peer]") }
                }
                continue
            }
            guard let eq = line.firstIndex(of: "=") else { continue }
            let key = line[..<eq].trimmingCharacters(in: .whitespaces).lowercased()
            let val = line[line.index(after: eq)...].trimmingCharacters(in: .whitespaces)

            if section == .peer && peerIndex > 1 { c.rawExtraPeers.append("\(key) = \(val)"); continue }

            switch (section, key) {
            case (.interface, "privatekey"): c.privateKey = val
            case (.interface, "address"): c.addresses = values(val)
            case (.interface, "dns"): c.dns = values(val)
            case (.interface, "mtu"): c.mtu = Int(val)
            case (.interface, "listenport"): c.listenPort = Int(val)
            case (.interface, "fwmark"): c.fwMark = val
            case (.interface, "table"): c.table = val
            case (.peer, "publickey"): c.peerPublicKey = val
            case (.peer, "presharedkey"): c.presharedKey = val
            case (.peer, "endpoint"): c.endpoint = val
            case (.peer, "allowedips"): c.allowedIPs = values(val)
            case (.peer, "persistentkeepalive"): c.persistentKeepalive = Int(val)
            default: break
            }
        }
        return c
    }

    /// Serialize back to a wg-quick .conf.
    func serialize() -> String {
        var out = "[Interface]\n"
        if !privateKey.isEmpty { out += "PrivateKey = \(privateKey)\n" }
        if !addresses.isEmpty { out += "Address = \(addresses.joined(separator: ", "))\n" }
        if !dns.isEmpty { out += "DNS = \(dns.joined(separator: ", "))\n" }
        if let mtu { out += "MTU = \(mtu)\n" }
        if let listenPort { out += "ListenPort = \(listenPort)\n" }
        if !fwMark.isEmpty { out += "FwMark = \(fwMark)\n" }
        if !table.isEmpty { out += "Table = \(table)\n" }
        out += "\n[Peer]\n"
        if !peerPublicKey.isEmpty { out += "PublicKey = \(peerPublicKey)\n" }
        if !presharedKey.isEmpty { out += "PresharedKey = \(presharedKey)\n" }
        if !endpoint.isEmpty { out += "Endpoint = \(endpoint)\n" }
        if !allowedIPs.isEmpty { out += "AllowedIPs = \(allowedIPs.joined(separator: ", "))\n" }
        if let persistentKeepalive { out += "PersistentKeepalive = \(persistentKeepalive)\n" }
        if !rawExtraPeers.isEmpty { out += "\n" + rawExtraPeers.joined(separator: "\n") + "\n" }
        return out
    }

    /// What the editor shows (private key redacted; it lives in the keychain).
    func redactedConf() -> String {
        var c = self
        if !c.privateKey.isEmpty { c.privateKey = "(stored in Keychain)" }
        return c.serialize()
    }
}

@MainActor
@Observable
final class WireGuardStore {
    private(set) var configs: [WireGuardConfig] = []
    private static let key = "wireguard.v1"

    init() { load() }

    func save(_ c: WireGuardConfig) {
        if let i = configs.firstIndex(where: { $0.id == c.id }) { configs[i] = c } else { configs.append(c) }
        persist()
    }
    func remove(_ id: String) { configs.removeAll { $0.id == id }; persist() }

    private func load() {
        guard let d = UserDefaults.standard.data(forKey: Self.key),
              let list = try? JSONDecoder().decode([WireGuardConfig].self, from: d) else { return }
        configs = list
    }
    private func persist() {
        if let d = try? JSONEncoder().encode(configs) { UserDefaults.standard.set(d, forKey: Self.key) }
    }
}
