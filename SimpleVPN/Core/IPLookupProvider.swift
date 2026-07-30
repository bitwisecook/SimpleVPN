// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
//  IPLookupProvider.swift
//  Which "what's my IP" service the public-address lookup uses. A few keyless,
//  plain-text presets (ipify, icanhazip, ifconfig.me/co, ident.me, AWS) plus a
//  user-supplied custom URL. Where a service has family-specific hosts we probe
//  IPv4 and IPv6 independently; single-endpoint services return whichever family
//  the connection used. Persisted by id in Settings ▸ Privacy.
//

import Foundation

let publicIPProviderDefaultsKey = "privacy.publicIPProvider"     // stores the id
let publicIPCustomV4DefaultsKey = "privacy.publicIPCustomV4"
let publicIPCustomV6DefaultsKey = "privacy.publicIPCustomV6"

struct IPLookupProvider: Identifiable, Sendable, Hashable {
    let id: String
    let name: String
    let v4URL: URL?
    let v6URL: URL?      // nil ⇒ single-endpoint service (family inferred from the result)

    static let presets: [IPLookupProvider] = [
        .init(id: "ipify", name: "ipify",
              v4URL: URL(string: "https://api4.ipify.org"), v6URL: URL(string: "https://api6.ipify.org")),
        .init(id: "icanhazip", name: "icanhazip",
              v4URL: URL(string: "https://ipv4.icanhazip.com"), v6URL: URL(string: "https://ipv6.icanhazip.com")),
        .init(id: "ident.me", name: "ident.me",
              v4URL: URL(string: "https://4.ident.me"), v6URL: URL(string: "https://6.ident.me")),
        .init(id: "ifconfig.me", name: "ifconfig.me",
              v4URL: URL(string: "https://ifconfig.me/ip"), v6URL: nil),
        .init(id: "ifconfig.co", name: "ifconfig.co",
              v4URL: URL(string: "https://ifconfig.co/ip"), v6URL: nil),
        .init(id: "aws", name: "Amazon (checkip)",
              v4URL: URL(string: "https://checkip.amazonaws.com"), v6URL: nil),
    ]

    static let customID = "custom"

    /// The provider the user selected (default ipify), resolving the custom URLs
    /// from defaults when "custom" is chosen.
    static var current: IPLookupProvider {
        let id = UserDefaults.standard.string(forKey: publicIPProviderDefaultsKey) ?? "ipify"
        if id == customID {
            let v4 = UserDefaults.standard.string(forKey: publicIPCustomV4DefaultsKey)
                .flatMap { URL(string: $0) }
            let v6 = UserDefaults.standard.string(forKey: publicIPCustomV6DefaultsKey)
                .flatMap { URL(string: $0) }
            return IPLookupProvider(id: customID, name: "Custom", v4URL: v4, v6URL: v6)
        }
        return presets.first { $0.id == id } ?? presets[0]
    }

    /// Presets plus a Custom entry, for the Settings picker.
    static var selectable: [IPLookupProvider] {
        presets + [IPLookupProvider(id: customID, name: "Custom…", v4URL: nil, v6URL: nil)]
    }
}
