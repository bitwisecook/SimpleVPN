// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
//  CiscoImport.swift
//  Importers for the two Cisco profile formats universities and companies hand
//  out:
//   • AnyConnect / Secure Client XML (<AnyConnectProfile><ServerList><HostEntry>)
//     → one Cisco AnyConnect subprocess tunnel per HostEntry (OpenConnect
//     --protocol=anyconnect), mapping HostAddress→server, UserGroup→authgroup.
//   • Legacy Cisco VPN Client .pcf ([main] INI) → a native IPsec (IKEv1/XAuth)
//     config: Host→server, GroupName→group, Username→user, GroupPwd→shared
//     secret. The obfuscated enc_GroupPwd is carried verbatim and flagged — we
//     never reverse Cisco's (trivially reversible, but not ours to reimplement)
//     group-password scheme.
//
//  Format details verified against Cisco's admin guides and the OpenConnect/vpnc
//  docs (see the design notes in the goal history).
//

import Foundation

enum CiscoImport {

    enum Result {
        case anyConnect([SubprocessTunnelConfig])
        case pcf(config: NativeVPNConfig, cleartextSecret: String?, note: String?)
        case unrecognized
    }

    /// Detect and parse by content (extension is unreliable — .pcf/.xml/.txt).
    static func parse(_ text: String, name: String) -> Result {
        let trimmed = text.trimmingCharacters(in: .whitespacesAndNewlines)
        if trimmed.hasPrefix("<") && trimmed.contains("AnyConnectProfile") {
            let hosts = parseAnyConnectXML(text)
            return hosts.isEmpty ? .unrecognized : .anyConnect(hosts)
        }
        if trimmed.lowercased().contains("[main]") || trimmed.contains("\nHost=") || trimmed.hasPrefix("Host=") {
            return parsePCF(text, name: name)
        }
        return .unrecognized
    }

    // MARK: AnyConnect XML

    static func parseAnyConnectXML(_ xml: String) -> [SubprocessTunnelConfig] {
        let d = AnyConnectXMLDelegate()
        let parser = XMLParser(data: Data(xml.utf8))
        parser.delegate = d
        parser.parse()
        return d.hosts.compactMap { entry in
            guard !entry.address.isEmpty else { return nil }
            var c = SubprocessTunnelConfig()
            c.kind = .ciscoAnyConnect
            c.name = entry.name.isEmpty ? entry.address : entry.name
            c.server = entry.address
            c.realm = entry.userGroup            // → OpenConnect --authgroup
            return c
        }
    }

    // MARK: .pcf

    static func parsePCF(_ text: String, name: String) -> Result {
        var kv: [String: String] = [:]
        for rawLine in text.split(whereSeparator: \.isNewline) {
            let line = rawLine.trimmingCharacters(in: .whitespaces)
            if line.isEmpty || line.hasPrefix("[") || line.hasPrefix(";") || line.hasPrefix("#") { continue }
            guard let eq = line.firstIndex(of: "=") else { continue }
            let key = String(line[..<eq]).trimmingCharacters(in: .whitespaces)   // case-sensitive
            let val = String(line[line.index(after: eq)...]).trimmingCharacters(in: .whitespaces)
            kv[key] = val
        }
        guard let host = kv["Host"], !host.isEmpty else { return .unrecognized }

        var c = NativeVPNConfig()
        c.kind = .ipsec                                  // .pcf is IKEv1 IPsec + XAuth
        c.name = (kv["Description"].flatMap { $0.isEmpty ? nil : $0 }) ?? name
        c.server = host
        c.username = kv["Username"] ?? ""
        c.groupOrRealm = kv["GroupName"] ?? ""
        c.usesSharedSecret = true                        // group PSK

        let cleartext = kv["GroupPwd"].flatMap { $0.isEmpty ? nil : $0 }
        var note: String?
        if cleartext == nil, let enc = kv["enc_GroupPwd"], !enc.isEmpty {
            note = "This profile stores its group secret obfuscated (enc_GroupPwd). SimpleVPN can't reverse Cisco's scheme — paste the plain group secret, or decode it with a Cisco group-password tool. Imported: enc_GroupPwd=\(enc.prefix(12))…"
        }
        return .pcf(config: c, cleartextSecret: cleartext, note: note)
    }
}

/// Pulls HostName / HostAddress / UserGroup / PrimaryProtocol out of each
/// <HostEntry>. Handles both the namespaced and bare-xmlns profile variants.
private final class AnyConnectXMLDelegate: NSObject, XMLParserDelegate {
    struct Host { var name = "", address = "", userGroup = "", primaryProtocol = "" }
    private(set) var hosts: [Host] = []

    private var current: Host?
    private var element = ""
    private var inBackupList = false

    func parser(_ parser: XMLParser, didStartElement el: String, namespaceURI: String?,
                qualifiedName qn: String?, attributes: [String: String]) {
        element = el
        switch el {
        case "HostEntry": current = Host()
        case "BackupServerList": inBackupList = true
        default: break
        }
    }

    func parser(_ parser: XMLParser, foundCharacters string: String) {
        guard current != nil else { return }
        let text = string.trimmingCharacters(in: .whitespacesAndNewlines)
        guard !text.isEmpty else { return }
        switch element {
        case "HostName": current?.name += text
        case "HostAddress" where !inBackupList: current?.address += text
        case "UserGroup": current?.userGroup += text
        case "PrimaryProtocol": current?.primaryProtocol += text
        default: break
        }
    }

    func parser(_ parser: XMLParser, didEndElement el: String, namespaceURI: String?,
                qualifiedName qn: String?) {
        switch el {
        case "HostEntry": if let c = current { hosts.append(c) }; current = nil
        case "BackupServerList": inBackupList = false
        default: break
        }
        element = ""
    }
}
