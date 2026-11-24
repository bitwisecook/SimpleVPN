// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
import Charts
import SwiftUI

struct RoutingFilterActivitySection: View {
    let activity: RoutingFilterActivity
    let profileID: String
    let profile: CustomRoutingProfile
    let dns: Bool
    @State private var expanded = false
    @State private var selected: RoutingFilterActivity.Rule?

    private var items: [(RoutingFilterActivity.Rule, String)] {
        if dns {
            guard !profile.dns.isIdentity else { return [] }
            return profile.dns.resolverRules.map {
                (.resolver($0.id), $0.verb.rawValue.capitalized + " " + ($0.match ?? $0.target ?? "resolver"))
            } + [(.resolver(nil), "Unmatched resolver")]
        }
        var rows: [(RoutingFilterActivity.Rule, String)] = profile.routes.rules.map {
            (.route($0.id), $0.verb.rawValue.capitalized + " " + ($0.match?.value ?? $0.target?.value ?? "route"))
        }
        if !profile.routes.isIdentity { rows.append((.route(nil), "Unmatched route")) }
        if !profile.proxy.isIdentity { rows.append((.proxy, "Proxy · " + profile.proxy.mode.rawValue.capitalized)) }
        return rows
    }
    var body: some View {
        if !items.isEmpty {
            DisclosureGroup("Configuration Rule Activity", isExpanded: $expanded) {
                if expanded {
                    Text("Matches count route, resolver or proxy configuration evaluations since SimpleVPN opened. Select a rule to see its matches per minute.")
                        .font(.caption).foregroundStyle(.secondary)
                    ForEach(items, id: \.0) { item in
                        Button {
                            selected = item.0
                        } label: {
                            LabeledContent(item.1) { Text(activity.counter(profileID, item.0).total.formatted()).monospacedDigit() }
                        }
                        .accessibilityHint("Show this rule’s activity graph")
                    }
                    if let selected, let label = items.first(where: { $0.0 == selected })?.1 {
                        let minute = Int64(Date().timeIntervalSince1970 / 60)
                        let samples = activity.counter(profileID, selected).samples.filter { $0.id > minute - 60 }
                        if samples.isEmpty {
                            Text("No matches for this rule in the last hour.").font(.caption)
                        } else {
                            Chart(samples) { sample in
                                BarMark(x: .value("Minute", Date(timeIntervalSince1970: Double(sample.id) * 60), unit: .minute),
                                        y: .value("Matches", sample.matches))
                            }.frame(height: 95).accessibilityLabel("Matches per minute for " + label)
                        }
                    }
                }
            }
            .disclosureGroupStyle(AccessibleSettingsDisclosureStyle())
        }
    }
}
