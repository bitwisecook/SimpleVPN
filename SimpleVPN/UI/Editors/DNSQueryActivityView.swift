// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only

import Charts
import SwiftUI

struct DNSQueryActivityView: View {
    let controller: DNSQueryRoutingController
    let profileID: String
    @Environment(\.dismiss) private var dismiss
    @State private var selection: Int?
    @State private var sample: DNSQueryActivity?
    @State private var unavailable = false
    @State private var reload = 0
    @State private var filter = ""
    @State private var history = DNSQueryRateHistory()

    private struct PollKey: Equatable {
        let policy: DNSQueryPolicy
        let enabled: Bool
        let updating: Bool
        let reload: Int
    }

    var body: some View {
        let policy = controller.configuration
        let key = PollKey(policy: policy, enabled: controller.configured, updating: controller.updating, reload: reload)
        NavigationStack {
            Group {
                if key.updating { ProgressView("Updating DNS query routing…") }
                else if !key.enabled {
                    ContentUnavailableView("Query Routing Is Off", systemImage: "network",
                        description: Text(controller.lastError ?? "Enable query-name routing for a connected VPN to see live counts."))
                } else if unavailable {
                    ContentUnavailableView {
                        Label("Query Activity Unavailable", systemImage: "network.slash")
                    } description: {
                        Text("macOS has enabled query routing. Its active provider has not returned counters for this configuration.")
                    } actions: { Button("Try Again") { reload += 1 } }
                } else if let sample {
                    HSplitView {
                        ruleList(policy).frame(minWidth: 190, idealWidth: 240, maxWidth: 340)
                        if let selection, sample.rows.indices.contains(selection) {
                            detail(sample.rows[selection], title: title(selection, policy: policy))
                                .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
                        } else {
                            ContentUnavailableView("Select a Rule", systemImage: "list.bullet")
                        }
                    }
                } else { ProgressView("Reading DNS query counters…") }
            }
            .navigationTitle("DNS Query Activity")
            .toolbar {
                ToolbarItem(placement: .confirmationAction) {
                    Button("Done") { dismiss() }.keyboardShortcut(.cancelAction)
                }
            }
        }
        .resizablePanel(idealWidth: 760, idealHeight: 480, minWidth: 590, minHeight: 385)
        .liveWindowTask(id: key) { await poll(key) }
        .onChange(of: selection) { history = DNSQueryRateHistory() }
    }

    private func ruleList(_ policy: DNSQueryPolicy) -> some View {
        VStack(alignment: .leading) {
            TextField("Filter rules", text: $filter).textFieldStyle(.roundedBorder)
            let indices = (0...policy.routes.count).filter { index in
                filter.isEmpty || title(index, policy: policy).localizedCaseInsensitiveContains(filter)
                    || (policy.routes.indices.contains(index) && policy.routes[index].profileName.localizedCaseInsensitiveContains(filter))
            }
            List(indices, id: \.self, selection: $selection) { index in
                VStack(alignment: .leading, spacing: 2) {
                    Text(title(index, policy: policy))
                    if policy.routes.indices.contains(index) {
                        Text(policy.routes[index].profileName).font(.caption).foregroundStyle(.secondary)
                    }
                }.accessibilityElement(children: .combine).tag(index)
            }
            .overlay { if indices.isEmpty { Text("No matching rules").foregroundStyle(.secondary) } }
            .onChange(of: indices) {
                if let selection, !indices.contains(selection) { self.selection = indices.first }
            }
        }.padding(10)
    }

    private func title(_ index: Int, policy: DNSQueryPolicy) -> String {
        guard policy.routes.indices.contains(index) else { return "Unmatched · Original resolver" }
        let rule = policy.routes[index].rule
        return "\(rule.match.kind.rawValue.capitalized) · \(rule.match.pattern)"
    }

    private func detail(_ counters: DNSQueryCounts, title: String) -> some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 10) {
                Text(title).font(.headline).textSelection(.enabled)
                LabeledContent("Matched queries", value: counters.matches.formatted())
                LabeledContent("Upstream answers", value: counters.answered.formatted())
                LabeledContent("Forwarding failures", value: counters.failed.formatted())
                LabeledContent("Query bytes", value: counters.queryBytes.formatted())
                LabeledContent("Upstream reply bytes", value: counters.replyBytes.formatted())
                Text("Each admitted query counts once. A valid upstream reply, including a DNS error, counts as an answer.")
                    .font(.caption).foregroundStyle(.secondary)
                Divider()
                Text("Queries per second").font(.headline)
                if history.points.isEmpty {
                    Text("Waiting for a second sample…").foregroundStyle(.secondary)
                } else {
                    Chart(history.points) { point in
                        LineMark(x: .value("Time", point.id), y: .value("Queries per second", point.rate))
                    }.chartYScale(domain: .automatic(includesZero: true))
                    .frame(height: 110).accessibilityLabel("Matched queries per second")
                }
            }.padding()
        }
    }

    private func poll(_ key: PollKey) async {
        unavailable = false
        history = DNSQueryRateHistory()
        guard key.enabled, !key.updating, let data = try? DNSQueryActivity.configurationData(key.policy) else {
            sample = nil
            return
        }
        let digest = DNSQueryActivity.digest(data)
        if sample?.generation != digest { sample = nil }
        while !Task.isCancelled {
            let read = await DNSQueryActivityClient.fetch(generation: digest, ruleCount: key.policy.routes.count)
            guard !Task.isCancelled else { return }
            guard let read else { sample = nil; unavailable = true; return }
            let oldSession = sample?.session
            sample = read
            if oldSession != read.session {
                history = DNSQueryRateHistory()
                selection = key.policy.routes.firstIndex { $0.profileID == profileID } ?? key.policy.routes.count
            }
            if let selection, read.rows.indices.contains(selection) {
                history.record(matches: read.rows[selection].matches, at: .now)
            }
            try? await Task.sleep(for: .seconds(2))
        }
    }
}

struct DNSQueryRateHistory {
    struct Point: Identifiable {
        let id: Date
        let rate: Double
    }
    private var previous: (UInt64, Date)?
    private(set) var points: [Point] = []

    mutating func record(matches: UInt64, at date: Date) {
        defer { previous = (matches, date) }
        guard let previous else { return }
        let interval = date.timeIntervalSince(previous.1)
        guard matches >= previous.0, interval > 0, interval < 10 else { points.removeAll(); return }
        points.append(Point(id: date, rate: Double(matches - previous.0) / interval))
        if points.count > 90 { points.removeFirst() }
    }
}
