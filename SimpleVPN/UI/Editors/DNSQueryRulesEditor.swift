// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only

import SwiftUI

/// Advanced query routing. Normal DNS server/search controls remain in the host editor.
struct DNSQueryRulesEditor: View {
    let vpn: VPNController
    let profileID: String
    @Binding var dns: DNSCustomization
    @State private var testName = ""
    @Environment(\.routingEditorDraft) private var routingDraft
    private static let specs = CustomRoutingSettings.catalog

    var body: some View {
        EngineSettingRow(spec: Self.specs["cr.query-routing"], value: dns.queryRoutingEnabled) {
            Toggle(isOn: $dns.queryRoutingEnabled) {
                EngineSettingLabel(spec: Self.specs["cr.query-routing"], value: dns.queryRoutingEnabled)
            }
        }
        Text("Uses the system DNS proxy while this VPN is connected; enabling it replaces another app's DNS proxy. Changes restart the DNS proxy, not the VPN.")
            .font(.caption).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
        HStack {
            EngineSettingLabel(spec: Self.specs["cr.query-rule"], value: dns.queryRules.count)
            Spacer()
            ManualLink(setting: Self.specs["cr.query-rule"])
            Button("Add Query Rule") { dns.queryRules.append(DNSQueryRule()) }
                .accessibilityLabel("Add DNS query rule")
        }
        ForEach($dns.queryRules) { $rule in ruleRow($rule) }
        if dns.queryRules.isEmpty { Text("No query-name rules.").foregroundStyle(.secondary) }
        if !dns.queryRules.isEmpty {
            Text("First match wins. Profile precedence: default-route owner → newest connection → profile ID. Unmatched → original resolver. App-managed DoH/DoT bypasses these rules.")
                .font(.caption).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
            Text("Exact: full QNAME. Suffix: apex + descendants. Glob: *, ?, [abc], [a-z], [!abc], backslash escapes; wildcards include dots. Case-insensitive; trailing root dot ignored. ASCII or punycode.")
                .font(.caption).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
            Text("Resolvers blank → filtered VPN DNS. Explicit IPs use existing IP routes; name rules do not add routes. Resolver failure → SERVFAIL, no fallback.")
                .font(.caption).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
        }
        SettingValueField(spec: Self.specs["cr.query-test"], text: $testName, prompt: "tig-portal.grlab.co.uk", mono: true)
        if !testName.isEmpty {
            Text(testResult).font(.callout).textSelection(.enabled)
                .accessibilityLabel("DNS query preview").accessibilityValue(testResult)
        }
        if let error = vpn.dnsQueries.lastError {
            Text(error).foregroundStyle(.orange).fixedSize(horizontal: false, vertical: true)
                .accessibilityLabel("DNS query proxy configuration error")
            Button("Reapply Query Rules") { vpn.syncDNSQueryRouting(force: true) }
                .help("Re-enable the configured DNS query proxy; this replaces any other app's DNS proxy.")
        } else {
            Text(vpn.dnsQueries.updating ? "Updating DNS proxy configuration…" :
                    vpn.dnsQueries.configured ? "DNS query proxy configuration enabled." : "DNS query proxy is not configured for any connected VPN.")
                .font(.caption).foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
        }
    }
    private var testResult: String {
        var preview = dns
        preview.queryRoutingEnabled = true
        let offered: [String]?
        if routingDraft?.dnsEnabled == false || routingDraft?.serverSettingsChanged == true { offered = [] }
        else { offered = routingDraft?.resolvers ?? vpn.lastPushedIntent(for: profileID)?.dns.resolvers }
        let policy = vpn.dnsQueryPolicy(replacing: profileID, with: preview, resolversOverride: offered)
        let state = dns.queryRoutingEnabled ? "Draft" : "Disabled draft; if enabled"
        if let problem = policy.problem { return "Invalid draft: " + problem }
        guard let route = policy.route(for: testName) else { return "\(state): No query rule matches; keep the original resolver selected by macOS." }
        let target = route.rule.target == .original ? "Original resolver selected by macOS" :
            route.servers.isEmpty ? "SERVFAIL — no resolver available" : route.servers.joined(separator: ", ")
        return "\(state) — \(route.profileName): \(route.rule.match.kind.rawValue) \(route.rule.match.pattern) → \(target). Draft preview; this VPN is included even if disconnected."
    }
    private func ruleRow(_ rule: Binding<DNSQueryRule>) -> some View {
        let value = rule.wrappedValue
        let index = dns.queryRules.firstIndex { $0.id == value.id } ?? 0
        let commands = ReorderCommands(subject: "query rule \(index + 1), \(value.match.kind.rawValue) \(value.match.pattern)",
            index: index, count: dns.queryRules.count, move: { from, to in dns.queryRules = Reorder.moved(dns.queryRules, from: from, to: to) })
        return VStack(alignment: .leading, spacing: 8) {
            HStack {
                Toggle("Rule \(index + 1)", isOn: rule.enabled)
                    .accessibilityLabel("Enable DNS query rule \(index + 1)")
                Spacer()
                ReorderButtons(commands: commands).buttonStyle(.plain)
                Button { dns.queryRules.removeAll { $0.id == value.id } } label: { Image(systemName: "trash") }
                    .buttonStyle(.plain).accessibilityLabel("Delete DNS query rule \(index + 1)")
            }
            LabeledContent("Name match") {
                Picker("DNS query match type", selection: rule.match.kind) {
                    Text("Exact").tag(DNSNameMatch.Kind.exact)
                    Text("Suffix").tag(DNSNameMatch.Kind.suffix)
                    Text("Glob").tag(DNSNameMatch.Kind.glob)
                }.labelsHidden().accessibilityIdentifier("dns-query-match-kind-" + value.id.uuidString)
                TextField("", text: rule.match.pattern, prompt: Text("Hostname or glob"))
                    .textFieldStyle(.roundedBorder).scalarConfigurationValue().accessibilityLabel("DNS query pattern")
                    .accessibilityValue(value.problem.map { "\(value.match.pattern), invalid: \($0)" } ?? value.match.pattern)
            }
            Picker("Resolve using", selection: rule.target) {
                Text("Resolvers").tag(DNSQueryRule.Target.resolvers)
                Text("Original resolver").tag(DNSQueryRule.Target.original)
            }.onChange(of: value.target) { _, target in
                if target == .original { rule.wrappedValue.servers = [] }
            }
            if value.target == .resolvers {
                SettingValueField(spec: Self.specs["cr.query-resolvers"], list: rule.servers,
                    prompt: "VPN DNS, or explicit IP addresses", problem: value.servers.first(where: { !DNSResolverAddress.isValid($0) }).map { "Invalid resolver IP: " + $0 }, mono: true,
                    spokenName: "DNS query rule \(index + 1) resolvers")
            }
            if let problem = value.problem { Text(problem).font(.caption).foregroundStyle(.orange) }
        }
        .padding(.vertical, 8)
    }
}
