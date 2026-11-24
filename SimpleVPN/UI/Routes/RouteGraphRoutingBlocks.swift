// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only

import SwiftUI
import UniformTypeIdentifiers

nonisolated struct RoutingBlockDrag: Codable, Transferable, Sendable {
    let document: String
    let version: Int
    var block: Int?
    var template: RoutingBlockTemplate?

    static var transferRepresentation: some TransferRepresentation {
        CodableRepresentation(contentType: UTType(exportedAs: "com.bragi0.simplevpn.routing-block"))
            .visibility(.ownProcess)
    }
}

struct RoutingBlockDiagram {
    let model: RoutingBlockSource
    let selected: Int?
    let destination: RoutingBlockSlot?
    let canEdit: Bool
    let payload: (Int) -> RoutingBlockDrag
    let select: (Int) -> Void
    let selectSlot: (RoutingBlockSlot) -> Void
    let drop: (RoutingBlockDrag, RoutingBlockSlot) -> Void

    var root: RoutingBlock { model.root }

    struct Track {
        let edge: GraphEdge
        let label: String?
        let slot: RoutingBlockSlot?
        let block: Int?
    }

    struct Drawing {
        let layout: RouteGraphView.Layout
        let tracks: [Track]
        let rows: [String: [RoutingBlockRow]]

        func containsControl(at point: CGPoint) -> Bool {
            layout.nodes.contains { $0.frame.contains(point) } || tracks.contains {
                $0.slot != nil && abs($0.edge.midpoint().x - point.x) < 22 && abs($0.edge.midpoint().y - point.y) < 30
            }
        }
    }

    func drawing(headerHeight: CGFloat) -> Drawing {
        let width: CGFloat = 218
        let gap: CGFloat = 86
        let spacing: CGFloat = 34
        var nodes: [GraphNode] = []
        var tracks: [Track] = []
        var lastRow = 0
        var rightmost = 0
        var rows: [String: [RoutingBlockRow]] = [:]

        func collectRows(_ block: RoutingBlock) {
            rows[String(block.id)] = model.rows(for: block)
            for child in block.children { collectRows(child) }
        }
        collectRows(root)
        let rowHeight = headerHeight + (rows.values.map(RoutingBlockTable.height).max() ?? 0)

        func node(_ station: RoutingRailroadStation, column: Int, row: Int) -> GraphNode {
            rightmost = max(rightmost, column)
            let height = headerHeight + RoutingBlockTable.height(rows[station.id] ?? [])
            let frame = CGRect(x: CGFloat(column) * (width + gap),
                               y: CGFloat(row) * (rowHeight + spacing) + (rowHeight - height) / 2,
                               width: width, height: height)
            let result = GraphNode(id: station.id, kind: .railroadStation(station), frame: frame)
            nodes.append(result)
            return result
        }

        func station(_ block: RoutingBlock, column: Int, row: Int) -> GraphNode {
            let title = block.id == root.id ? block.name ?? block.title : block.title
            let source = model.header(of: block)
            let details = block.kind == "handler" ? [block.event ?? source] : [source]
            let symbol: String = switch block.kind {
            case "handler": "bolt.circle"
            case "if", "elseIf", "else", "match", "found", "missing", "predicate": "arrow.triangle.branch"
            case "for": "repeat"
            case "table": "tablecells"
            case "expression", "action": "bolt"
            default: "chevron.left.forwardslash.chevron.right"
            }
            return node(.init(id: String(block.id), title: title, details: details, symbol: symbol),
                        column: column, row: row)
        }

        func connect(_ from: GraphNode, to: GraphNode, label: String? = nil,
                     slot: RoutingBlockSlot? = nil, block: Int? = nil) {
            let edge = GraphEdge(id: from.id + ">" + to.id,
                from: CGPoint(x: from.frame.maxX, y: from.frame.midY),
                to: CGPoint(x: to.frame.minX, y: to.frame.midY),
                active: false, rate: 0, tint: .accentColor, fromNode: from.id, toNode: to.id)
            tracks.append(Track(edge: edge, label: label, slot: slot, block: block))
        }

        func walk(_ scope: RoutingBlock, start: GraphNode, column: Int, row: Int, label: String? = nil) {
            var currentColumn = column
            var previous = start
            var previousCondition: (node: GraphNode, column: Int)?
            var nextLabel = label
            let editableScope = root.kind == "handler" && scope.acceptsBlocks
            for child in scope.children {
                if child.isAlternative, let condition = previousCondition {
                    lastRow += 1
                    let alternativeColumn = condition.column + 1
                    let alternative = station(child, column: alternativeColumn, row: lastRow)
                    connect(condition.node, to: alternative, label: "Otherwise")
                    let alternativeRow = lastRow
                    walk(child, start: alternative, column: alternativeColumn, row: alternativeRow,
                         label: child.kind == "elseIf" ? "Then" : nil)
                    previousCondition = (alternative, alternativeColumn)
                    continue
                }
                currentColumn += 1
                let next = station(child, column: currentColumn, row: row)
                let slot = editableScope ? RoutingBlockSlot(scope: scope.id, before: child.id) : nil
                let movable = canEdit && model.moveRange(for: child.id) != nil
                connect(previous, to: next, label: nextLabel, slot: slot, block: movable ? child.id : nil)
                previous = next
                previousCondition = child.kind == "if" ? (next, currentColumn) : nil
                nextLabel = nil
                if child.body != nil || !child.children.isEmpty {
                    lastRow += 1
                    let branchRow = lastRow
                    let branch = child.kind == "if" ? "Then" : child.kind == "for" ? "Repeat" : nil
                    walk(child, start: next, column: currentColumn, row: branchRow, label: branch)
                }
            }
            if scope.body != nil || scope.kind == "handler" {
                let end = node(.init(id: "end-\(scope.id)", title: scope.id == root.id ? "End" : "End of Branch",
                                     details: [], symbol: "stop.circle"),
                               column: currentColumn + 1, row: row)
                connect(previous, to: end, label: nextLabel,
                        slot: editableScope ? RoutingBlockSlot(scope: scope.id, before: nil) : nil)
            }
        }

        let start = station(root, column: 0, row: 0)
        walk(root, start: start, column: 0, row: 0)
        let size = CGSize(width: CGFloat(rightmost) * (width + gap) + width,
                          height: CGFloat(lastRow) * (rowHeight + spacing) + rowHeight)
        return Drawing(layout: .init(nodes: nodes, edges: tracks.map(\.edge), canvas: size), tracks: tracks, rows: rows)
    }
}

struct RoutingBlockTable: View {
    let rows: [RoutingBlockRow]

    private static func rowHeight(_ row: RoutingBlockRow) -> CGFloat { row.wraps ? 38 : 23 }

    static func height(_ rows: [RoutingBlockRow]) -> CGFloat {
        guard !rows.isEmpty else { return 0 }
        return 1 + rows.reduce(0) { $0 + rowHeight($1) }
    }

    var body: some View {
        VStack(spacing: 0) {
            ForEach(rows.indices, id: \.self) { index in
                let row = rows[index]
                HStack(spacing: 0) {
                    Text(row.label)
                        .font(.caption.weight(.medium)).foregroundStyle(.secondary)
                        .lineLimit(1)
                        .padding(.horizontal, 8)
                        .frame(width: 78, alignment: .leading)
                        .frame(maxHeight: .infinity)
                        .background { Rectangle().fill(Color.primary.opacity(0.045)) }
                    Divider()
                    valueCell(row)
                        .padding(.horizontal, 8)
                        .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .leading)
                }
                .frame(height: Self.rowHeight(row))
                .overlay(alignment: .top) {
                    if index > 0 {
                        Rectangle().fill(Color(nsColor: .separatorColor)).frame(height: 1)
                    }
                }
            }
        }
        .accessibilityHidden(true)
    }

    @ViewBuilder
    private func valueCell(_ row: RoutingBlockRow) -> some View {
        if let operation = row.operation {
            HStack(spacing: 5) {
                Text(operation)
                    .font(.caption.monospaced().weight(.semibold))
                    .foregroundStyle(Color.accentColor)
                    .padding(.horizontal, 4).padding(.vertical, 1)
                    .background(Color.accentColor.opacity(0.13), in: .rect(cornerRadius: 4))
                Text(row.value).font(.caption).lineLimit(1)
            }
        } else {
            Text(row.value)
                .font(.caption.monospaced())
                .lineLimit(row.wraps ? 2 : 1)
                .truncationMode(row.wraps ? .tail : .middle)
        }
    }
}

extension RouteGraphView {
    func routingTrack(_ track: RoutingBlockDiagram.Track, diagram: RoutingBlockDiagram) -> some View {
        let middle = track.edge.midpoint()
        return VStack(spacing: 1) {
            if let label = track.label {
                Text(label).font(.caption.weight(.medium)).fixedSize()
                    .padding(.horizontal, 4)
                    .background(Color(nsColor: .underPageBackgroundColor))
                    .accessibilityLabel(label + " branch")
            }
            if let slot = track.slot, diagram.canEdit {
                RoutingTrackConnector(track: track, slot: slot, diagram: diagram)
            }
        }
        .position(x: middle.x, y: middle.y)
    }
}

private struct RoutingTrackConnector: View {
    let track: RoutingBlockDiagram.Track
    let slot: RoutingBlockSlot
    let diagram: RoutingBlockDiagram
    @State private var targeted = false

    private var title: String {
        if let before = slot.before.flatMap(diagram.root.block) {
            return "Before \(before.title.lowercased()), line \(before.range.start.line + 1)"
        }
        guard let scope = diagram.root.block(slot.scope), scope.id != diagram.root.id else { return "End of handler" }
        let name = scope.kind == "if" || scope.kind == "elseIf" ? "Then branch" : scope.title
        return "End of \(name), line \(scope.range.start.line + 1)"
    }

    var body: some View {
        Group {
            if let block = track.block {
                connector.draggable(diagram.payload(block)) { ReorderDragPreview(subject: title) }
            } else {
                connector
            }
        }
        .dropDestination(for: RoutingBlockDrag.self) { payloads, _ in
            targeted = false
            if payloads.count == 1, let payload = payloads.first { diagram.drop(payload, slot) }
        }
        .onDropSessionUpdated { session in
            switch session.phase {
            case .entering, .active: targeted = true
            default: targeted = false
            }
        }
    }

    private var connector: some View {
        let selected = diagram.destination == slot
        return Button { diagram.selectSlot(slot) } label: {
            Image(systemName: selected || targeted ? "plus.circle.fill" : track.block == nil ? "plus.circle" : "arrow.right.circle")
                .font(.title3)
                .foregroundStyle(selected || targeted ? Color.accentColor : Color.secondary)
                .background(Color(nsColor: .underPageBackgroundColor), in: .circle)
                .frame(width: 38, height: 34)
                .contentShape(Rectangle())
        }
        .buttonStyle(.plain)
        .help(track.block == nil ? title : "\(title) · Drag to reconnect the next block")
        .accessibilityLabel("Connector, \(title)")
        .accessibilityValue(selected ? "Selected insertion point" : "Available insertion point")
        .accessibilityHint("Selects this position for adding or moving a block")
        .accessibilityAddTraits(selected ? .isSelected : [])
    }
}
