// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only

import SwiftUI

/// Language tools exist only while the source editor is on screen.
struct RoutingSourceEditor: View {
    let vpn: VPNController
    @Binding var text: String
    let adapter: String
    let accessibilityLabel: String

    var body: some View {
        RoutingSourceBuffer(vpn: vpn, text: $text, adapter: adapter, accessibilityLabel: accessibilityLabel).id(adapter)
    }
}

private struct RoutingSourceBuffer: View {
    let vpn: VPNController
    @Binding var text: String
    let accessibilityLabel: String
    @State private var document: RoutingEditorDocument
    @State private var showsBuilder = true

    init(vpn: VPNController, text: Binding<String>, adapter: String, accessibilityLabel: String) {
        self.vpn = vpn
        _text = text
        self.accessibilityLabel = accessibilityLabel
        _document = State(initialValue: RoutingEditorDocument(adapter: adapter))
    }

    var body: some View {
        @Bindable var document = document
        VStack(alignment: .leading, spacing: 7) {
            DisclosureGroup("Graphical Builder", isExpanded: $showsBuilder) {
                if showsBuilder {
                    RoutingBlockBuilder(vpn: vpn, document: document)
                        .padding(.vertical, 6)
                }
            }
            .disclosureGroupStyle(AccessibleSettingsDisclosureStyle())
            Text("Source").font(.headline).accessibilityAddTraits(.isHeader)
            ConfigurationSourceText(text: $text, format: .routingEvents, accessibilityLabel: accessibilityLabel,
                                    languageDocument: document)
                .frame(minHeight: 85)
            HStack {
                Button("Complete…") { document.inspect(.completions) }
                    .keyboardShortcut(".", modifiers: .control)
                Button("Quick Help") { document.inspect(.help) }
                Button("Event Diagram…") { document.inspect(.events) }
                Button("Syntax Tree…") { document.inspect(.tree) }
                Spacer()
            }
            .controlSize(.small)
            if let notice = document.notice {
                HStack {
                    Text(notice).font(.callout).fixedSize(horizontal: false, vertical: true)
                    if text.utf8.count <= 32768 { Button("Retry") { document.retry() } }
                }
            }
            if let first = document.issues.first {
                Button {
                    document.reveal(first.range)
                } label: {
                    Label("Line \(first.range.start.line + 1): \(first.message)", systemImage: "exclamationmark.triangle")
                        .multilineTextAlignment(.leading).fixedSize(horizontal: false, vertical: true)
                }
                .buttonStyle(.link)
                .accessibilityHint("Selects this issue in the source editor")
            }
        }
        .onAppear {
            document.showRailroad(showsBuilder)
            document.appear(source: text)
        }
        .onDisappear { document.close() }
        .onChange(of: showsBuilder) { _, show in document.showRailroad(show) }
        .onChange(of: Data(text.utf8)) { document.changed(text) }
        .sheet(item: $document.panel) { panel in
            RoutingToolsPanel(document: document, panel: panel)
        }
    }
}

private struct RoutingToolsPanel: View {
    let document: RoutingEditorDocument
    let panel: RoutingEditorDocument.Panel
    @Environment(\.dismiss) private var dismiss
    @State private var filter = ""

    private var title: String {
        switch panel {
        case .completions: "Completions"
        case .help: "Quick Help"
        case .tree: "Syntax Tree"
        case .events: "Event Diagram"
        }
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text(title).font(.headline)
            if document.loading {
                ProgressView().controlSize(.small)
            } else {
                switch panel {
                case .help:
                    Text(document.detail).textSelection(.enabled)
                        .frame(maxWidth: .infinity, alignment: .leading)
                case .completions:
                    TextField("Find a completion", text: $filter)
                    if document.suggestions.isEmpty {
                        Text("No completions at the insertion point.").foregroundStyle(.secondary)
                    } else {
                        List(document.suggestions.filter { filter.isEmpty || $0.label.localizedCaseInsensitiveContains(filter) }) { suggestion in
                            Button { document.insert(suggestion) } label: {
                                VStack(alignment: .leading) {
                                    Text(suggestion.label).font(.system(.body, design: .monospaced))
                                    Text(suggestion.detail).font(.caption).foregroundStyle(.secondary)
                                }.frame(maxWidth: .infinity, alignment: .leading).contentShape(Rectangle())
                            }.buttonStyle(.plain)
                        }
                    }
                case .events:
                    RoutingEventDiagram(document:document)
                case .tree:
                    if document.nodes.isEmpty {
                        Text("Add a handler, function or table to see its syntax tree.").foregroundStyle(.secondary)
                    } else {
                        List(document.nodes, children: \.branches) { node in
                            Button { document.reveal(node.selectionRange) } label: {
                                HStack {
                                    Label(node.title, systemImage: node.children.isEmpty ? "circle" : "point.3.connected.trianglepath.dotted")
                                    Spacer()
                                    Text("Line \(node.selectionRange.start.line + 1)").foregroundStyle(.secondary)
                                }.contentShape(Rectangle())
                            }.buttonStyle(.plain)
                                .accessibilityHint("Selects this node in the source editor")
                        }
                        if document.truncated { Text("Showing the first 1,200 syntax nodes.").font(.caption) }
                    }
                }
            }
            HStack { Spacer(); Button("Done") { dismiss() }.keyboardShortcut(.cancelAction) }
        }
        .padding(16)
        .frame(minWidth: 320, idealWidth: 480, minHeight: panel == .help ? 140 : 260, idealHeight: panel == .help ? 150 : 360)
    }
}


private struct RoutingEventDiagram: View {
    let document: RoutingEditorDocument
    @State private var selected: String?
    private let layers = ["IP packet", "Transport and control", "Protocol observation", "SSH forwarding", "Adapter events"]
    private let icons = ["IP packet":"network","Transport and control":"arrow.left.arrow.right",
                         "Protocol observation":"waveform.path.ecg","SSH forwarding":"terminal"]
    var body: some View {
        if document.events.isEmpty {
            Text("This adapter supplied no event catalog.").foregroundStyle(.secondary)
        } else {
            Text(document.events.contains { $0.layer == "SSH forwarding" }
                 ? "The SSH engine checks each channel at the event shown. Choose an event to edit its handlers."
                 : "Follow a packet from IP through the protocols it carries. Choose an event to edit its handlers.")
            ScrollView {
                VStack(alignment: .leading, spacing: 8) {
                    let visibleLayers = layers.filter { layer in document.events.contains { $0.layer == layer } }
                    ForEach(visibleLayers, id: \.self) { layer in
                        if layer != visibleLayers.first {
                            Image(systemName: "arrow.down").foregroundStyle(.secondary).accessibilityHidden(true)
                                .padding(.leading, 16)
                        }
                        let events = document.events.filter { $0.layer == layer }
                        if !events.isEmpty {
                            VStack(alignment: .leading, spacing: 5) {
                                Label(layer, systemImage: icons[layer] ?? "point.3.connected.trianglepath.dotted")
                                    .font(.headline).accessibilityAddTraits(.isHeader)
                                ForEach(events) { event in
                                    DisclosureGroup(isExpanded: Binding(get: { selected == event.id }, set: { selected = $0 ? event.id : nil })) {
                                        VStack(alignment: .leading, spacing: 6) {
                                            ForEach(event.handlers) { handler in
                                                Button("\(handler.name) · Line \(handler.range.start.line + 1)") { document.reveal(handler.range) }
                                                    .accessibilityHint("Selects the handler in the source editor")
                                            }
                                            Button("Add Handler") { document.addHandler(for: event.event) }
                                                .accessibilityLabel("Add handler for \(event.event)")
                                        }.padding(.vertical, 4)
                                    } label: {
                                        HStack {
                                            Text(event.event).font(.system(.body, design:.monospaced))
                                            Spacer()
                                            if !event.handlers.isEmpty {
                                                Text("\(event.handlers.count) linked").font(.caption).foregroundStyle(.secondary)
                                            }
                                        }
                                    }
                                }
                            }.padding(9).background(.quaternary.opacity(0.35), in: RoundedRectangle(cornerRadius: 7))
                        }
                    }
                }
            }
            if !document.detail.isEmpty { Text(document.detail).font(.callout) }
        }
    }
}
