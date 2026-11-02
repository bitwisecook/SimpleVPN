// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only

import SwiftUI

extension RouteGraphView {
    /// Configuration stations feed the existing graph renderer and viewport.
    /// All content under its scale transform remains pure SwiftUI drawing.
    func editorLayout(_ graph: RoutingRailroadDiagram) -> Layout {
        let width: CGFloat = 248
        let gap: CGFloat = 64
        var nodes: [GraphNode] = []
        var edges: [GraphEdge] = []
        var y: CGFloat = 0
        var columns = 1
        for lane in graph.lanes {
            let heights = lane.stations.map { station -> CGFloat in
                let expandable = station.details.count > collapseThreshold
                let visible = expandable && !expandedCards.contains(station.id)
                    ? Array(station.details.prefix(collapsedRows)) : station.details
                let lines = visible.reduce(0) { $0 + max(1, Int(ceil(Double($1.count) / 28))) }
                return 70 + CGFloat(lines) * 19 + (expandable ? expanderHeight : 0)
            }
            let height = heights.max() ?? 90
            columns = max(columns, lane.stations.count)
            for (index, station) in lane.stations.enumerated() {
                let frame = CGRect(x: CGFloat(index) * (width + gap),
                                   y: y + (height - heights[index]) / 2,
                                   width: width, height: heights[index])
                nodes.append(GraphNode(id: station.id, kind: .railroadStation(station), frame: frame))
                if index > 0 {
                    let previous = nodes[nodes.count - 2]
                    edges.append(GraphEdge(id: lane.id + ":\(index)",
                        from: CGPoint(x: previous.frame.maxX, y: previous.frame.midY),
                        to: CGPoint(x: frame.minX, y: frame.midY),
                        active: lane.observedRate > 64, rate: lane.observedRate,
                        tint: .accentColor, fromNode: previous.id, toNode: station.id))
                }
            }
            y += height + 36
        }
        return Layout(nodes: nodes, edges: edges,
                      canvas: CGSize(width: CGFloat(columns) * (width + gap) - gap,
                                     height: max(100, y - 36)))
    }
}
