// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only

import SwiftUI

/// The last reported DNS is visible even while its custom routing is collapsed.
/// Display-only: the saved routing draft and all edits remain owned by the host.
struct VPNDNSServerSection: View {
    let vpn: VPNController
    let profileID: String

    var body: some View {
        let dns = vpn.lastPushedIntent(for: profileID)?.dns
        Section {
            if let dns, !dns.isEmpty {
                if !dns.resolvers.isEmpty {
                    LabeledContent("DNS Servers", value: dns.resolvers.joined(separator: ", "))
                }
                if !dns.searchDomains.isEmpty {
                    LabeledContent("Search Domains", value: dns.searchDomains.joined(separator: ", "))
                }
                let domains = dns.matchDomains.filter { !$0.isEmpty }
                if !domains.isEmpty {
                    LabeledContent("Match Domains", value: domains.joined(separator: ", "))
                }
            } else {
                Text("No DNS settings have been reported by this VPN yet.")
                    .foregroundStyle(.secondary)
            }
        } header: {
            Text("DNS From This VPN")
        } footer: {
            Text("The last settings supplied by this VPN, before Custom Routing is applied.")
        }
        .textSelection(.enabled)
    }
}
