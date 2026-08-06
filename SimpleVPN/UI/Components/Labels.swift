// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
//  Labels.swift
//  User-defined labels applied to VPNs. A catalog of labels (name + colour) plus
//  per-profile assignments, persisted in UserDefaults. Defaults: Prod / Lab / Home.
//  Pure SwiftUI — colours round-trip through Color.Resolved (no AppKit).
//

import SwiftUI

struct LabelDef: Identifiable, Codable, Sendable, Hashable {
    var id: String
    var name: String
    var r: Double
    var g: Double
    var b: Double

    var color: Color { Color(.sRGB, red: r, green: g, blue: b, opacity: 1) }

    init(id: String = UUID().uuidString, name: String, r: Double, g: Double, b: Double) {
        self.id = id; self.name = name; self.r = r; self.g = g; self.b = b
    }
    init(id: String = UUID().uuidString, name: String, resolved: Color.Resolved) {
        self.init(id: id, name: name, r: Double(resolved.red), g: Double(resolved.green), b: Double(resolved.blue))
    }
    mutating func set(_ resolved: Color.Resolved) {
        r = Double(resolved.red); g = Double(resolved.green); b = Double(resolved.blue)
    }
}

@MainActor
@Observable
final class LabelStore {
    private(set) var labels: [LabelDef]
    private var assignments: [String: Set<String>]   // profile id → label ids

    private static let labelsKey = "labels.catalog"
    private static let assignKey = "labels.assignments"

    static let defaults: [LabelDef] = [
        LabelDef(id: "prod", name: "Prod", r: 0.96, g: 0.70, b: 0.70),  // pastel red
        LabelDef(id: "lab",  name: "Lab",  r: 0.82, g: 0.76, b: 0.93),  // lavender
        LabelDef(id: "home", name: "Home", r: 0.70, g: 0.80, b: 0.96),  // pastel blue
    ]

    init() {
        let d = UserDefaults.standard
        if let data = d.data(forKey: Self.labelsKey),
           let cat = try? JSONDecoder().decode([LabelDef].self, from: data), !cat.isEmpty {
            labels = cat
        } else {
            labels = Self.defaults
        }
        if let data = d.data(forKey: Self.assignKey),
           let a = try? JSONDecoder().decode([String: Set<String>].self, from: data) {
            assignments = a
        } else {
            assignments = [:]
        }
    }

    func labels(for profile: String) -> [LabelDef] {
        let ids = assignments[profile] ?? []
        return labels.filter { ids.contains($0.id) }   // preserve catalog order
    }

    func isAssigned(_ label: LabelDef, to profile: String) -> Bool {
        assignments[profile]?.contains(label.id) ?? false
    }

    func toggle(_ label: LabelDef, for profile: String) {
        var set = assignments[profile] ?? []
        if set.contains(label.id) { set.remove(label.id) } else { set.insert(label.id) }
        assignments[profile] = set
        persist()
    }

    /// Add a label KEEPING THE ID IT ALREADY HAS. The settings import needs this:
    /// a label's id is what a VPN's assignment points at, so re-generating one
    /// would import the catalog and quietly lose every assignment that referred to
    /// it. A label whose id is already here is left exactly as it is — renaming
    /// somebody's label out from under them is a silent destruction of the thing
    /// that organises their sidebar.
    func add(_ label: LabelDef) {
        guard !labels.contains(where: { $0.id == label.id }) else { return }
        labels.append(label)
        persist()
    }

    /// Assign an existing label to a VPN. `toggle` is the UI's verb and cannot be
    /// used by an import (a second call would take the label off again); this one
    /// is idempotent.
    func assign(_ labelID: String, to profile: String) {
        guard labels.contains(where: { $0.id == labelID }) else { return }
        var set = assignments[profile] ?? []
        guard !set.contains(labelID) else { return }
        set.insert(labelID)
        assignments[profile] = set
        persist()
    }

    func addLabel(name: String, resolved: Color.Resolved) {
        labels.append(LabelDef(name: name.isEmpty ? "New Label" : name, resolved: resolved))
        persist()
    }

    func update(_ label: LabelDef) {
        if let i = labels.firstIndex(where: { $0.id == label.id }) { labels[i] = label; persist() }
    }

    func remove(_ id: String) {
        labels.removeAll { $0.id == id }
        for (p, set) in assignments where set.contains(id) {
            var s = set; s.remove(id); assignments[p] = s
        }
        persist()
    }

    private func persist() {
        let d = UserDefaults.standard
        if let data = try? JSONEncoder().encode(labels) { d.set(data, forKey: Self.labelsKey) }
        if let data = try? JSONEncoder().encode(assignments) { d.set(data, forKey: Self.assignKey) }
    }
}

/// A pastel pill for a label.
struct LabelPill: View {
    let label: LabelDef
    @Environment(\.colorSchemeContrast) private var contrast
    var body: some View {
        Text(label.name)
            // The label colour is USER-CHOSEN: the defaults are light pastels,
            // but nothing stops a navy "Prod" — so the text picks black/white by
            // the pill's own luminance instead of assuming a light background.
            .font(.caption2).fontWeight(.medium)
            .foregroundStyle(textColor)
            .padding(.horizontal, 7).padding(.vertical, 2)
            .background(label.color, in: Capsule())
            // Increase Contrast: an explicit rim, so a pastel pill doesn't melt
            // into a light row background.
            .overlay {
                if contrast == .increased {
                    Capsule().strokeBorder(textColor.opacity(0.6), lineWidth: 1)
                }
            }
    }

    private var textColor: Color {
        // Relative luminance (sRGB, linearized) — the WCAG formula.
        func lin(_ c: Double) -> Double { c <= 0.03928 ? c / 12.92 : pow((c + 0.055) / 1.055, 2.4) }
        let l = 0.2126 * lin(label.r) + 0.7152 * lin(label.g) + 0.0722 * lin(label.b)
        return l > 0.4 ? .black.opacity(contrast == .increased ? 1 : 0.78)
                       : .white.opacity(contrast == .increased ? 1 : 0.92)
    }
}
