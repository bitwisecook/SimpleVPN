// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only

import SwiftUI

struct RoutingBlockBuilder: View {
    let vpn: VPNController
    let document: RoutingEditorDocument
    @Environment(\.isEnabled) private var enabled
    @State private var declarationKey: String?
    @State private var selected: Int?
    @State private var destination: RoutingBlockSlot?
    @State private var editingBlock = false

    private var snapshot: RoutingBlockSnapshot? { document.railroad }
    private var current: Bool { snapshot?.version == document.version }
    private var canEdit: Bool {
        enabled && current && snapshot?.complete == true && snapshot?.limited == false && !document.loading
    }

    private func key(_ declaration: RoutingBlock) -> String {
        declaration.kind + ":" + (declaration.name ?? String(declaration.id))
    }

    private var root: RoutingBlock? {
        guard let declarations = snapshot?.declarations else { return nil }
        return declarations.first { key($0) == declarationKey }
            ?? declarations.first { $0.kind == "handler" }
            ?? declarations.first
    }

    private var selection: Binding<Int?> {
        Binding(get: { root?.id }, set: { id in
            declarationKey = snapshot?.declarations.first { $0.id == id }.map(key)
            clearSelection()
        })
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 8) {
            if let snapshot {
                HStack(spacing: 10) {
                    if !snapshot.declarations.isEmpty {
                        Picker("Declaration", selection: selection) {
                            ForEach(snapshot.declarations) { block in
                                Text(block.name ?? "\(block.title), line \(block.range.start.line + 1)")
                                    .tag(Optional(block.id))
                            }
                        }
                        .accessibilityLabel("Routing declaration")
                    }
                    Spacer(minLength: 0)
                    Menu("Add Handler") {
                        ForEach(snapshot.events, id: \.self) { event in
                            Button(event) {
                                document.addHandler(for: event, revealSource: false) { name in
                                    declarationKey = "handler:" + name
                                    clearSelection()
                                }
                            }
                        }
                    }
                    .disabled(!canEdit || snapshot.events.isEmpty)
                }
                if let root {
                    let model = RoutingBlockSource(root: root, source: document.railroadSource)
                    controls(model)
                    RouteGraphView(vpn: vpn, routingBlocks: diagram(model))
                        .id(key(root))
                        .frame(height: 235)
                        .clipShape(.rect(cornerRadius: 8))
                } else {
                    Text(emptyMessage(snapshot))
                        .font(.callout).foregroundStyle(.secondary)
                }
                if !current {
                    status("Updating diagram…", icon: "arrow.trianglehead.clockwise")
                } else if snapshot.limited {
                    status("Showing the first 240 blocks. Edit this configuration in Source.", icon: "text.alignleft")
                } else if !snapshot.complete {
                    status("Finish the syntax in Source to edit the diagram.", icon: "exclamationmark.triangle")
                } else if root?.kind == "handler", root?.body == nil {
                    status("This handler uses compact syntax. Select a block to find it in Source.", icon: "text.alignleft")
                }
            } else if document.notice == nil && document.railroadError == nil {
                ProgressView("Loading routing diagram…").controlSize(.small)
            }

            if let error = document.railroadError { status(error, icon: "exclamationmark.triangle") }
        }
        .controlSize(.small)
        .onChange(of: snapshot?.version) { clearSelection() }
    }

    private func emptyMessage(_ snapshot: RoutingBlockSnapshot) -> String {
        if !snapshot.complete { return "Finish the declaration in Source to see its blocks." }
        if snapshot.events.isEmpty { return "This adapter supplied no events." }
        return "Choose Add Handler to start a routing railroad."
    }

    private func diagram(_ model: RoutingBlockSource) -> RoutingBlockDiagram {
        RoutingBlockDiagram(model: model, selected: selected, destination: destination, canEdit: canEdit,
                            payload: { payload(block: $0) },
                            select: { id in selected = id },
                            selectSlot: { slot in destination = slot },
                            drop: { drag, slot in
                                guard drag.document == document.uri, drag.version == snapshot?.version else { return }
                                if let block = drag.block {
                                    apply(model.moving(block, to: slot), action: "Move Block")
                                } else if let template = drag.template {
                                    apply(model.inserting(template, at: slot), action: "Add Block")
                                }
                            })
    }

    private func controls(_ model: RoutingBlockSource) -> some View {
        let root = model.root
        let slot = destination ?? RoutingBlockSlot(scope: root.id, before: nil)
        let block = selected.flatMap(root.block)
        return VStack(alignment: .leading, spacing: 6) {
            if root.kind == "handler", root.body != nil {
                HStack(spacing: 6) {
                    ForEach(RoutingBlockTemplate.allCases, id: \.self) { template in
                        Button {
                            apply(model.inserting(template, at: slot), action: "Add Block")
                        } label: {
                            Label(template.title, systemImage: template.symbol)
                        }
                        .accessibilityLabel("Add \(template.title) block")
                        .help("Click to insert or drag onto a connector")
                        .draggable(payload(template: template)) { ReorderDragPreview(subject: template.title) }
                        .disabled(!canEdit)
                    }
                    Spacer(minLength: 0)
                }
            }
            HStack(spacing: 6) {
                Button("Show in Source") {
                    if let block { document.reveal(block.header) }
                }
                .disabled(block == nil || !current)
                if let field = block.flatMap(model.field) {
                    Button("Edit Block…") { editingBlock = true }
                        .disabled(!canEdit)
                        .popover(isPresented: $editingBlock) {
                            RoutingBlockField(field: field) { replacement in
                                apply(.init(range: field.range, replacement: replacement), action: "Edit Block")
                            }
                        }
                }
                Button("Move Here") {
                    if let block { apply(model.moving(block.id, to: slot), action: "Move Block") }
                }
                .help("Select a block and a connector to move the block to that position")
                .disabled(!canEdit || destination == nil || block.map { !model.canMove($0.id, to: slot) } != false)
                Button("Delete Block") {
                    if let block { apply(model.deleting(block.id), action: "Delete Block") }
                }
                .disabled(!canEdit || block.flatMap { model.moveRange(for: $0.id) } == nil)
                Spacer(minLength: 0)
                Button("Undo", systemImage: "arrow.uturn.backward") { document.undoRailroad() }
                    .labelStyle(.iconOnly).help("Undo").disabled(!document.canUndo)
                Button("Redo", systemImage: "arrow.uturn.forward") { document.undoRailroad(redo: true) }
                    .labelStyle(.iconOnly).help("Redo").disabled(!document.canRedo)
            }
            if root.kind == "handler", root.body != nil, canEdit {
                Text("Drag a block or its incoming connector to another connector. Select both and choose Move Here to do the same with the keyboard.")
                    .font(.caption).foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }
        }
    }

    private func status(_ message: String, icon: String) -> some View {
        Label(message, systemImage: icon).font(.callout).foregroundStyle(.secondary)
            .fixedSize(horizontal: false, vertical: true)
    }

    private func payload(block: Int? = nil, template: RoutingBlockTemplate? = nil) -> RoutingBlockDrag {
        RoutingBlockDrag(document: document.uri, version: snapshot?.version ?? -1, block: block, template: template)
    }

    private func apply(_ edit: RoutingBlockSource.Edit?, action: String) {
        guard canEdit, let edit, let revision = snapshot?.version,
              document.editRailroad(edit, version: revision, action: action) else { return }
        clearSelection()
        let announcement = switch action {
        case "Move Block": "Block moved"
        case "Add Block": "Block added"
        case "Edit Block": "Block updated"
        default: "Block deleted"
        }
        AccessibilityNotification.Announcement(announcement).post()
    }

    private func clearSelection() {
        selected = nil
        destination = nil
        editingBlock = false
    }
}

private struct RoutingBlockField: View {
    let field: RoutingBlockSource.Field
    let update: (String) -> Void
    @Environment(\.dismiss) private var dismiss
    @FocusState private var focused: Bool
    @State private var value = ""

    var body: some View {
        VStack(alignment: .leading, spacing: 10) {
            TextField(field.title, text: $value, axis: .vertical)
                .font(.system(.body, design: .monospaced))
                .focused($focused)
            HStack {
                Spacer()
                Button("Cancel") { dismiss() }.keyboardShortcut(.cancelAction)
                Button("Update Block") { update(value); dismiss() }
                    .keyboardShortcut(.defaultAction)
                    .disabled(value.utf8.elementsEqual(field.source.utf8)
                              || value.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty)
            }
        }
        .padding(12).frame(width: 330)
        .onAppear { value = field.source; focused = true }
    }
}
