// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only

import Charts
import SwiftUI

struct RuleActivityView: View {
    let vpn: VPNController
    let target: RuleActivityTarget
    @Environment(\.dismiss) private var dismiss
    @State private var rules: RoutingInspectionPage?
    @State private var flows: RoutingInspectionPage?
    @State private var rulePager = RuleActivityPager()
    @State private var flowPager = RuleActivityPager()
    @State private var selectedRule: UInt64?
    @State private var selectedFlow: UInt64?
    @State private var current: RoutingInspectionRule?
    @State private var history = RuleActivityHistory()
    @State private var memberFilter: String?
    @State private var ruleQuery = ""
    @State private var flowQuery = ""
    @State private var find: Find?
    @State private var notice: String?
    @State private var unavailable = false
    @State private var reload = 0
    @State private var sources: [String: String] = [:]
    @State private var detail: FlowDetail?
    @State private var columns: Columns = .endpoints
    private enum Columns: String, CaseIterable {
        case endpoints = "Endpoints", translation = "Translation", attribution = "Attribution", traffic = "Traffic"
    }
    @State private var measure: Measure = .bytes

    private enum Find: Equatable { case rules(String), flows(String) }
    private enum Measure: String, CaseIterable { case bytes = "Bytes/s", packets = "Packets/s", drops = "Drops/s" }
    private struct FlowDetail: Identifiable {
        let flow: RoutingInspectionFlow
        let source: String
        let member: String
        var id: UInt64 { flow.id }
    }
    private struct RequestKey: Equatable {
        let ruleCursor, flowCursor: UInt64
        let rule: UInt64?
        let member: String?
        let find: Find?
        let reload: Int
        let showingSnapshot: Bool
    }
    private var key: RequestKey {
        RequestKey(ruleCursor: rulePager.cursor, flowCursor: flowPager.cursor, rule: selectedRule, member: memberFilter, find: find, reload: reload, showingSnapshot: detail != nil)
    }

    var body: some View {
        NavigationStack {
            Group {
                if unavailable {
                    ContentUnavailableView {
                        Label("Rule Activity Unavailable", systemImage: "chart.xyaxis.line")
                    } description: {
                        Text("The composition must be connected through a system extension that reports rule activity.")
                    } actions: {
                        Button("Try Again") { unavailable = false; reload += 1 }
                    }
                } else if let rules {
                    HSplitView {
                        ruleList(rules).frame(minWidth: 190, idealWidth: 235, maxWidth: 350)
                        if let current {
                            VStack(alignment: .leading, spacing: 8) {
                                summary(current)
                                Divider()
                                if current.kind == "event" {
                                    ContentUnavailableView("Packet Matches", systemImage: "point.3.connected.trianglepath.dotted",
                                        description: Text("The chart counts packets that matched this handler. Select a routing rule to inspect its assigned connections."))
                                } else { flowList }
                            }.padding(12).frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
                        } else {
                            ContentUnavailableView("Select a Rule", systemImage: "list.bullet",
                                description: Text("Choose a rule to see its counters and connections."))
                        }
                    }
                } else {
                    ProgressView("Reading rules…")
                }
            }
            .navigationTitle("Rule Activity · \(target.name)")
            .toolbar { ToolbarItem(placement: .confirmationAction) {
                Button("Done") { dismiss() }.keyboardShortcut(.cancelAction)
            } }
        }
        .frame(minWidth: 720, minHeight: 530)
        .resizablePanel(idealWidth: 980, idealHeight: 660)
        .liveWindowTask(id: key) {
            guard !unavailable, detail == nil else { return }
            if let find { await findLaterPage(find) }
            else { await poll() }
        }
        .onChange(of: memberFilter) {
            resetSession()
            cancelFind()
        }
        .onChange(of: selectedRule) {
            flowPager = RuleActivityPager()
            selectedFlow = nil
            flows = nil
            history = RuleActivityHistory()
            current = rules?.rules?.first { $0.id == selectedRule }
            notice = nil
        }
        .onChange(of: ruleQuery) {
            cancelFind()
            let filtered = (rules?.rules ?? []).filter { matches($0, ruleQuery) }
            if !filtered.contains(where: { $0.id == selectedRule }) { selectedRule = filtered.first?.id }
        }
        .onChange(of: flowQuery) {
            cancelFind()
            if let row = flows?.flows?.first(where: { $0.id == selectedFlow }), !matches(row, flowQuery) {
                selectedFlow = nil
            }
        }
        .sheet(item: $detail) { entry in RuleFlowDetails(flow: entry.flow, source: entry.source, member: entry.member) }
    }

    private func ruleList(_ page: RoutingInspectionPage) -> some View {
        VStack(alignment: .leading, spacing: 8) {
            Text("Rules (\(page.total))").font(.headline)
            Picker("VPN", selection: $memberFilter) {
                Text("All VPNs").tag(nil as String?)
                ForEach(vpn.virtualMembers.keys.filter { vpn.virtualMembers[$0] == target.compositionID }
                    .sorted { memberName($0).localizedStandardCompare(memberName($1)) == .orderedAscending }, id: \.self) { id in
                    Text(memberName(id)).tag(Optional(id))
                }
            }
            searchField("Filter rules on this page", text: $ruleQuery, find: .rules(ruleQuery), next: page.nextCursor)
            let visible = (page.rules ?? []).filter { matches($0, ruleQuery) }
            List(visible, id: \.id, selection: $selectedRule) { rule in
                VStack(alignment: .leading, spacing: 2) {
                    Text(ruleName(rule))
                    Text(ruleScope(rule)).font(.caption).foregroundStyle(.secondary)
                    if !rule.active { Text("Retired").font(.caption) }
                }
                .accessibilityElement(children: .combine)
                .tag(rule.id)
            }
            .overlay {
                if visible.isEmpty {
                    Text(ruleQuery.isEmpty && page.total == 0 ? "No rules for this VPN" : ruleQuery.isEmpty ? "No rules on this page" : "No matches on this page").foregroundStyle(.secondary)
                }
            }
            pager(rulePager, next: page.nextCursor, name: "rules", previous: {
                rulePager.back(); selectedRule = nil
            }, forward: { rulePager.advance(to: $0); selectedRule = nil })
            if find != nil {
                Button("Cancel Search") { cancelFind() }
            }
            if let notice { Text(notice).font(.caption).foregroundStyle(.secondary) }
        }
        .padding(10)
    }

    private func searchField(_ label: String, text: Binding<String>, find command: Find, next: UInt64?) -> some View {
        HStack {
            TextField(label, text: text).textFieldStyle(.roundedBorder)
            if !text.wrappedValue.isEmpty {
                Button {
                    notice = nil
                    find = command
                } label: { Image(systemName: "arrow.right.to.line") }
                .disabled(next == nil || find != nil)
                .accessibilityLabel("Find on later pages")
                .help("Find the next page containing a match.")
            }
        }
    }

    private func pager(_ state: RuleActivityPager, next: UInt64?, name: String,
                       previous: @escaping () -> Void, forward: @escaping (UInt64) -> Void) -> some View {
        HStack {
            Button(action: previous) { Image(systemName: "chevron.left") }
                .disabled(state.number == 1 || find != nil).accessibilityLabel("Previous \(name) page")
            Text("Page \(state.number)").font(.caption).monospacedDigit()
            Button { if let next { forward(next) } } label: { Image(systemName: "chevron.right") }
                .disabled(next == nil || find != nil).accessibilityLabel("Next \(name) page")
        }
        .controlSize(.small)
    }

    private func summary(_ r: RoutingInspectionRule) -> some View {
        VStack(alignment: .leading, spacing: 6) {
            Text(ruleName(r)).font(.title3.bold())
            Text("\(ruleScope(r)) · Rule \(String(r.id)) · \(r.active ? "Current" : "Retired")")
                .font(.caption).foregroundStyle(.secondary).textSelection(.enabled)
            if r.port != nil && r.available == false {
                Label("VPN unavailable", systemImage: "exclamationmark.triangle").font(.caption)
            }
            if let reason = r.lastDropReason {
                Text("Last drop: \(reason)").font(.caption).textSelection(.enabled)
            }
            ViewThatFits(in: .horizontal) {
                HStack(spacing: 18) { totals(r) }
                VStack(alignment: .leading, spacing: 4) { totals(r) }
            }
            Picker("Chart", selection: $measure) {
                ForEach(Measure.allCases, id: \.self) { Text($0.rawValue).tag($0) }
            }.pickerStyle(.segmented).fixedSize().accessibilityLabel("Chart measure")
            if history.samples.isEmpty {
                Text("Waiting for a second sample…").font(.caption).foregroundStyle(.secondary)
                    .frame(maxWidth: .infinity, minHeight: 68)
            } else {
                Chart(history.samples) { sample in
                    if measure == .drops {
                        LineMark(x: .value("Time", sample.id), y: .value("Drops per second", sample.drops))
                            .foregroundStyle(.orange)
                    } else {
                        LineMark(x: .value("Time", sample.id),
                                 y: .value(measure.rawValue, measure == .bytes ? sample.bytesIn : sample.packetsIn),
                                 series: .value("Direction", "Received"))
                            .foregroundStyle(by: .value("Direction", "Received"))
                        LineMark(x: .value("Time", sample.id),
                                 y: .value(measure.rawValue, measure == .bytes ? sample.bytesOut : sample.packetsOut),
                                 series: .value("Direction", "Sent"))
                            .lineStyle(.init(lineWidth: 2, dash: [4, 3]))
                            .foregroundStyle(by: .value("Direction", "Sent"))
                    }
                }
                .chartYScale(domain: .automatic(includesZero: true))
                .accessibilityLabel("\(measure.rawValue) while viewing this rule")
                .frame(height: 100)
            }
        }
    }

    @ViewBuilder private func totals(_ rule: RoutingInspectionRule) -> some View {
        Text("Sent \(bytes(rule.bytesOut)) · \(rule.packetsOut) packets")
        Text("Received \(bytes(rule.bytesIn)) · \(rule.packetsIn) packets")
        Text("Dropped \(rule.drops)")
    }

    private var flowList: some View {
        VStack(alignment: .leading, spacing: 6) {
            HStack {
                if let flows { Text("Connections (\(flows.total))").font(.headline) }
                else { Text("Connections").font(.headline) }
                Spacer()
                Picker("Columns", selection: $columns) {
                    ForEach(Columns.allCases, id: \.self) { Text($0.rawValue).tag($0) }
                }.fixedSize()
                Button("Details…") {
                    guard let row = flows?.flows?.first(where: { $0.id == selectedFlow }) else { return }
                    detail = FlowDetail(flow: row, source: sourceName(row.source), member: memberName(row.port))
                }
                .disabled(selectedFlow == nil)
            }
            searchField("Filter connections on this page", text: $flowQuery, find: .flows(flowQuery), next: flows?.nextCursor)
            let visible = (flows?.flows ?? []).filter { matches($0, flowQuery) }
            Table(visible, selection: $selectedFlow) {
                TableColumn(columnTitles.0) { Text(firstColumn($0)) }
                TableColumn(columnTitles.1) { Text(secondColumn($0)) }
                TableColumn(columnTitles.2) { Text(thirdColumn($0)) }
                TableColumn(columnTitles.3) { Text(fourthColumn($0)) }
            }
            .overlay {
                if visible.isEmpty {
                    Text(flows == nil ? "Reading connections…" : flowQuery.isEmpty ? "No tracked connections" : "No matches on this page")
                        .foregroundStyle(.secondary)
                }
            }
            pager(flowPager, next: flows?.nextCursor, name: "connections", previous: {
                flowPager.back(); selectedFlow = nil
            }, forward: { flowPager.advance(to: $0); selectedFlow = nil })
        }
    }

    private var columnTitles: (String, String, String, String) {
        switch columns {
        case .endpoints: ("Source", "Destination", "Protocol", "State")
        case .translation: ("Original source", "Translated source", "VPN", "Generation")
        case .attribution: ("App or process rule", "Process ID", "DNS name", "TLS server name")
        case .traffic: ("Sent", "Received", "Dropped packets", "Last drop")
        }
    }

    private func firstColumn(_ row: RoutingInspectionFlow) -> String {
        switch columns {
        case .endpoints, .translation: socket(row.sourceIP, row.sourcePort, proto: row.`protocol`)
        case .attribution: sourceName(row.source)
        case .traffic: "\(bytes(row.bytesOut)) · \(row.packetsOut) packets"
        }
    }

    private func secondColumn(_ row: RoutingInspectionFlow) -> String {
        switch columns {
        case .endpoints: socket(row.destinationIP, row.destinationPort, proto: row.`protocol`)
        case .translation: row.translatedSource.isEmpty ? "Unavailable" : socket(row.translatedSource, row.sourcePort, proto: row.`protocol`)
        case .attribution: pid(row.owner)
        case .traffic: "\(bytes(row.bytesIn)) · \(row.packetsIn) packets"
        }
    }

    private func thirdColumn(_ row: RoutingInspectionFlow) -> String {
        switch columns {
        case .endpoints: protocolName(row.`protocol`)
        case .translation: memberName(row.port)
        case .attribution: row.dnsName ?? "Not observed"
        case .traffic: String(row.drops)
        }
    }

    private func fourthColumn(_ row: RoutingInspectionFlow) -> String {
        switch columns {
        case .endpoints: row.blocked ? "Blocked" : "Tracked"
        case .translation: String(row.portGeneration)
        case .attribution: row.tlsServerName ?? "Not observed"
        case .traffic: row.lastDropReason ?? "None recorded"
        }
    }

    private func ruleName(_ rule: RoutingInspectionRule) -> String {
        switch rule.kind {
        case "default": "Default route"
        case "destination": rule.prefix ?? "Destination rule"
        case "source": sourceName(rule.source)
        case "override": "\(sourceName(rule.source)) · \(rule.prefix ?? "Destination override")"
        case "event": rule.eventID ?? "Event handler"
        case "unmatched": "Unmatched traffic"
        default: rule.kind
        }
    }

    private func ruleScope(_ rule: RoutingInspectionRule) -> String {
        switch rule.kind {
        case "event", "unmatched": "Composition"
        default: memberName(rule.port)
        }
    }

    private func memberName(_ id: String?) -> String {
        guard let id, !id.isEmpty else { return "No VPN selected" }
        return vpn.profiles.first { $0.id == id }?.name ?? id
    }
    private func sourceName(_ id: String?) -> String {
        guard let id, !id.isEmpty else { return "Not attributed" }
        return sources[id] ?? id
    }
    private func matches(_ r: RoutingInspectionRule, _ query: String) -> Bool {
        query.isEmpty || [ruleName(r), memberName(r.port), r.kind, String(r.id)].contains { $0.localizedCaseInsensitiveContains(query) }
    }
    private func matches(_ f: RoutingInspectionFlow, _ query: String) -> Bool {
        guard !query.isEmpty else { return true }
        return [f.sourceIP, String(f.sourcePort), f.destinationIP, String(f.destinationPort), f.translatedSource,
                f.dnsName ?? "", f.tlsServerName ?? "", sourceName(f.source), memberName(f.port), protocolName(f.`protocol`),
                f.blocked ? "blocked" : "tracked", pid(f.owner)].contains { $0.localizedCaseInsensitiveContains(query) }
    }

    private func cacheSourceNames(_ page: RoutingInspectionPage) {
        let ids = Set((page.rules ?? []).compactMap(\.source) + (page.flows ?? []).compactMap(\.source))
        for id in ids where sources[id] == nil {
            sources[id] = vpn.routingSourceName(memberID: target.id, sourceID: id) ?? id
        }
    }

    private func request(_ table: String, cursor: UInt64, rule: UInt64? = nil) async -> RoutingInspectionPage? {
        guard vpn.virtualMembers[target.id] == target.compositionID else { return nil }
        let result = await vpn.routingInspection(memberID: target.id,
            request: RoutingInspectionRequest(table: table, cursor: cursor, limit: 40, port: memberFilter, ruleID: rule))
        return vpn.virtualMembers[target.id] == target.compositionID ? result : nil
    }

    private func cancelFind() { find = nil; notice = nil }

    private func resetSession() {
        rules = nil; flows = nil; current = nil
        rulePager = RuleActivityPager(); flowPager = RuleActivityPager()
        selectedRule = nil; selectedFlow = nil
        history = RuleActivityHistory(); sources = [:]; detail = nil
    }

    private func poll() async {
        while !Task.isCancelled {
            let page = await request("rules", cursor: rulePager.cursor)
            guard !Task.isCancelled else { return }
            guard let page else { resetSession(); unavailable = true; return }
            if let old = rules, old.sessionID != page.sessionID {
                resetSession(); reload += 1; return
            }
            if rules?.revision != page.revision { sources = [:] }
            rules = page
            cacheSourceNames(page)
            if let id = selectedRule {
                var row = page.rules?.first { $0.id == id }
                if row == nil {
                    let selected = await request("rules", cursor: 0, rule: id)
                    guard !Task.isCancelled else { return }
                    guard selected?.sessionID == page.sessionID else { resetSession(); reload += 1; return }
                    row = selected?.rules?.first { $0.id == id }
                }
                guard let row else { selectedRule = nil; return }
                if row.kind == "event" {
                    current = row
                    history.record(row, session: page.sessionID, at: .now)
                    try? await Task.sleep(for: .seconds(2))
                    continue
                }
                let states = await request("flows", cursor: flowPager.cursor, rule: id)
                guard !Task.isCancelled else { return }
                guard let states else { resetSession(); unavailable = true; return }
                guard states.sessionID == page.sessionID else { resetSession(); reload += 1; return }
                current = row; flows = states
                cacheSourceNames(states)
                if let selectedFlow, states.flows?.contains(where: { $0.id == selectedFlow }) != true { self.selectedFlow = nil }
                history.record(row, session: page.sessionID, at: .now)
            } else if let first = page.rules?.first(where: { matches($0, ruleQuery) }) {
                selectedRule = first.id
                return
            }
            try? await Task.sleep(for: .seconds(2))
        }
    }

    private func findLaterPage(_ command: Find) async {
        let table: String, query: String
        var state: RuleActivityPager, next: UInt64?, matchRule: UInt64?
        switch command {
        case .rules(let q): table = "rules"; query = q; state = rulePager; next = rules?.nextCursor
        case .flows(let q): table = "flows"; query = q; state = flowPager; next = flows?.nextCursor; matchRule = selectedRule
        }
        let session = rules?.sessionID
        // A busy router can create flows faster than a paged search can read them.
        // Search at most the number of pages present when the user started.
        let count = table == "rules" ? rules?.total : flows?.total
        var pagesRemaining = max(0, (count ?? 0) / 40 + 1 - state.number)
        while let cursor = next, cursor > state.cursor, pagesRemaining > 0, !Task.isCancelled {
            pagesRemaining -= 1
            let page = await request(table, cursor: cursor, rule: matchRule)
            guard !Task.isCancelled else { return }
            guard let page else { resetSession(); find = nil; unavailable = true; return }
            guard page.sessionID == session else { resetSession(); find = nil; return }
            cacheSourceNames(page)
            state.advance(to: cursor)
            if table == "rules", let hit = page.rules?.first(where: { matches($0, query) }) {
                rules = page; rulePager = state; selectedRule = hit.id; find = nil; return
            }
            if table == "flows", let hit = page.flows?.first(where: { matches($0, query) }) {
                flows = page; flowPager = state; selectedFlow = hit.id; find = nil; return
            }
            next = page.nextCursor
        }
        if !Task.isCancelled { notice = "No matches in the later pages searched."; find = nil }
    }
}

private func bytes(_ value: UInt64) -> String {
    ByteCountFormatter.string(fromByteCount: Int64(clamping: value), countStyle: .file)
}

private func protocolName(_ value: UInt8) -> String {
    switch value { case 6: "TCP"; case 17: "UDP"; case 1: "ICMP"; case 58: "ICMPv6"; default: "IP \(value)" }
}

private func socket(_ address: String, _ port: UInt16, proto: UInt8) -> String {
    guard proto == 6 || proto == 17 else { return address }
    return WireGuardEndpointSelection.endpointString(host: address, port: Int(port))
}

private func pid(_ owner: UInt64) -> String {
    let value = owner >> 32
    return value == 0 ? "Unavailable" : String(value)
}

private struct RuleFlowDetails: View {
    let flow: RoutingInspectionFlow
    let source, member: String
    @Environment(\.dismiss) private var dismiss

    var body: some View {
        NavigationStack {
            Form {
                Section("Recorded connection") {
                    LabeledContent("Source", value: socket(flow.sourceIP, flow.sourcePort, proto: flow.`protocol`))
                    LabeledContent("Destination", value: socket(flow.destinationIP, flow.destinationPort, proto: flow.`protocol`))
                    LabeledContent("Protocol", value: protocolName(flow.`protocol`))
                    if flow.`protocol` == 1 || flow.`protocol` == 58 {
                        LabeledContent("Echo identifier", value: String(flow.sourcePort))
                    }
                    LabeledContent("Through VPN", value: member)
                    LabeledContent("Translated source", value: flow.translatedSource.isEmpty ? "Unavailable" : flow.translatedSource)
                    LabeledContent("State", value: flow.blocked ? "Blocked" : "Tracked")
                    if let reason = flow.lastDropReason { LabeledContent("Last drop", value: reason) }
                    LabeledContent("Policy revision", value: String(flow.revision))
                    LabeledContent("VPN generation", value: String(flow.portGeneration))
                    LabeledContent("First packet", value: Date(timeIntervalSince1970: flow.firstSeen).formatted(date: .abbreviated, time: .standard))
                    LabeledContent("Last packet", value: Date(timeIntervalSince1970: flow.lastSeen).formatted(date: .abbreviated, time: .standard))
                    LabeledContent("Sent", value: "\(bytes(flow.bytesOut)) · \(flow.packetsOut) packets")
                    LabeledContent("Received", value: "\(bytes(flow.bytesIn)) · \(flow.packetsIn) packets")
                    LabeledContent("Dropped packets", value: String(flow.drops))
                }
                Section("Source and observed names") {
                    LabeledContent("App or process rule", value: source)
                    LabeledContent("Process ID", value: pid(flow.owner))
                    LabeledContent("DNS name", value: flow.dnsName ?? "Not observed")
                    LabeledContent("TLS server name", value: flow.tlsServerName ?? "Not observed")
                }
            }
            .textSelection(.enabled)
            .formStyle(.grouped)
            .navigationTitle("Connection \(String(flow.id)) · Snapshot")
            .toolbar { ToolbarItem(placement: .confirmationAction) {
                Button("Done") { dismiss() }.keyboardShortcut(.cancelAction)
            } }
        }.frame(minWidth: 380, minHeight: 420)
    }
}
