// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
//  RouteGraphSearch.swift
//  The route graph's search, split out of RouteGraphView.swift for size, not
//  redesigned: resolving the typed address or CIDR through RouteResolver into
//  a SearchOutcome (which cards, rows and edges light up), the answer panel
//  that says in words what the lit picture claims, and revealMatches — the
//  one-shot expand/scroll that brings a lit row into view. The routing
//  semantics live in RouteResolver and must never come back here.
//

import SwiftUI

/// Everything the search wants to SAY and to LIGHT UP, resolved once.
///
/// The routing semantics are not here and must never come back here: `RouteResolver`
/// owns "where does this go and where else could it go" for the whole app. This is
/// only the diagram's view of its answer — which cards glow, which rows, which edges.
///
/// Resolved once per body pass and threaded down, because resolving is real work: a
/// /8 query is cut into pieces by prefix subtraction, and doing that once per card
/// per pan tick would be felt.
struct SearchOutcome {   // was private — internal for the file split
    var resolution: RouteResolution
    /// Every interface any part of the query leaves by — for a CIDR that splits,
    /// that is more than one card.
    var interfaces: Set<String>
    /// "<bsd>|<raw table destination>" for every route involved, so a row only lights
    /// on the card that actually carries it.
    var litRows: Set<String>
    /// The query (or its remainder) leaves by a default route ⇒ the globe is part of
    /// the answer, and so is the edge to it.
    var hitsInternet: Bool
    /// Interfaces offering a standby DEFAULT as an alternative — their dashed edge to
    /// the globe glows, quietly: they are where this would go if the winner dropped.
    var standbyDefaults: Set<String>
}

extension RouteGraphView {

    // MARK: The answer panel
    //
    // Lives under the search field, OUTSIDE the scaled subtree — a fixed home that
    // doesn't move when the diagram is panned, and ordinary SwiftUI text because
    // nothing here is under a transform. The diagram lights up WHERE traffic goes;
    // this says exactly WHAT it does, including the parts a picture can't show: the
    // takeover order, and the pieces of a CIDR that go somewhere else.

    /// One rendered line: a lead (the query part), then where it goes.
    private struct PanelLine: Identifiable {
        let id: Int
        var lead: String
        var leadIsPrefix: Bool          // monospaced, because it's a prefix
        var interface: String?          // display name; nil ⇒ nowhere
        var route: String?              // raw table destination
        var note: String?               // "standby default", "no route"…
    }

    @ViewBuilder func answerPanel(_ outcome: SearchOutcome) -> some View {   // was private — internal for the file split
        let r = outcome.resolution
        let lines = panelLines(outcome)
        VStack(alignment: .leading, spacing: 3) {
            // The headline a picture can't give you: this one query does not have one
            // answer. Said first, and said plainly.
            if r.spansMultipleRoutes {
                Text("Splits across \(r.interfaceNames.count) interfaces")
                    .font(.caption.weight(.semibold))
            }
            ForEach(lines.prefix(panelLineLimit)) { line in
                HStack(alignment: .firstTextBaseline, spacing: 6) {
                    Text(line.lead)
                        .font(line.leadIsPrefix ? .caption.monospaced() : .caption)
                        .foregroundStyle(.secondary)
                        .frame(width: 132, alignment: .leading)
                    Text("→").font(.caption).foregroundStyle(.tertiary)
                    if let iface = line.interface {
                        // Interpolated Text, not an HStack: the three parts are one
                        // run of text that wraps and baselines together.
                        let via = Text(line.route.map { " via \($0)" } ?? "")
                            .font(.caption.monospaced()).foregroundStyle(.secondary)
                        let note = Text(line.note.map { " (\($0))" } ?? "")
                            .font(.caption).foregroundStyle(.secondary)
                        Text("\(Text(iface).font(.caption.weight(.medium)))\(via)\(note)")
                    } else {
                        Text(line.note ?? "nowhere").font(.caption).foregroundStyle(.secondary)
                    }
                }
            }
            if lines.count > panelLineLimit {
                Text("and \(lines.count - panelLineLimit) more…")
                    .font(.caption).foregroundStyle(.tertiary)
            }
            if r.segmentsTruncated {
                Text("Too finely divided to list exactly — the diverting routes are named above.")
                    .font(.caption2).foregroundStyle(.tertiary)
                    .fixedSize(horizontal: false, vertical: true)
            }
        }
        .textSelection(.enabled)
        .padding(.horizontal, 10).padding(.vertical, 8)
        .frame(maxWidth: .infinity, alignment: .leading)
        .background(.background.secondary, in: RoundedRectangle(cornerRadius: 8))
        .overlay(RoundedRectangle(cornerRadius: 8)
            .strokeBorder(Color(nsColor: .separatorColor), lineWidth: 1))
        .padding(.horizontal, 12).padding(.bottom, 8)
    }

    /// Turn the resolver's answer into lines. Two shapes: one destination (where it
    /// goes now, then where it could go instead), or a split (each diverted piece,
    /// then ONE line for everything that just falls through).
    private func panelLines(_ outcome: SearchOutcome) -> [PanelLine] {
        let r = outcome.resolution
        var lines: [PanelLine] = []
        func add(_ lead: String, prefix: Bool = false, iface: String?,
                 route: String? = nil, note: String? = nil) {
            lines.append(PanelLine(id: lines.count, lead: lead, leadIsPrefix: prefix,
                                   interface: iface, route: route, note: note))
        }

        guard r.isRoutable else {
            add("No route", iface: nil,
                note: "nothing in the routing table covers \(r.prefix.displayText)")
            return lines
        }

        if r.spansMultipleRoutes {
            // Diverted pieces are the interesting ones and get a line each. The
            // remainder is tiled into however many prefixes the subtraction needed —
            // that's arithmetic, not information, so it collapses to one line.
            for segment in r.segments where segment.source == .specific {
                add(segment.prefix.displayText, prefix: true,
                    iface: segment.interfaceName.map { displayName($0) },
                    route: segment.route?.destination)
            }
            if let remainder = r.segments.first(where: { $0.source == .covering }) {
                add("everything else", iface: remainder.interfaceName.map { displayName($0) },
                    route: remainder.route?.destination)
            }
            if r.segments.contains(where: { $0.source == .unroutable }) {
                add("the rest", iface: nil, note: "no route")
            }
            return lines
        }

        if let winner = r.winner {
            add("Goes now", iface: displayName(winner.interfaceName), route: winner.destination)
        }
        // Where it COULD go, in the order it would actually be taken over.
        for alt in r.alternatives {
            add("Could go", iface: displayName(alt.interfaceName),
                route: alt.isDefault ? nil : alt.destination,
                note: alt.isDefault ? "standby default" : nil)
        }
        if r.alternatives.isEmpty, r.winner != nil {
            add("Nothing else", iface: nil, note: "no other route could take it")
        }
        return lines
    }

    /// The BSD name is what the table says; this is what the user calls it.
    private func displayName(_ bsd: String) -> String {
        guard let iface = topo?.topology.interfaces.first(where: { $0.name == bsd })
        else { return bsd }
        let name = label(for: iface)
        return name == bsd ? bsd : "\(name) (\(bsd))"
    }

    // MARK: Search

    /// Any IPv4 or IPv6 address, or a CIDR of either family, answered by
    /// `RouteResolver` — the same code that answers it everywhere else in the app.
    /// Nothing about longest prefixes, interface scoping or which default wins is
    /// decided here; this only turns the resolver's answer into things to light up.
    var searchOutcome: SearchOutcome? {   // was private — internal for the file split
        let q = searchText.trimmingCharacters(in: .whitespaces)
        guard !q.isEmpty, let topo,
              let r = RouteResolver(topology: topo.topology).resolve(q) else { return nil }
        // Every route any piece of the query rides, keyed by interface so an identical
        // destination string on two interfaces can't light the wrong card's row.
        var rows = Set<String>()
        for route in [r.winner].compactMap({ $0 }) + r.segments.compactMap(\.route) {
            rows.insert("\(route.interfaceName)|\(route.destination)")
        }
        return SearchOutcome(
            resolution: r,
            interfaces: Set(r.interfaceNames),
            litRows: rows,
            // The remainder of a split CIDR still leaves by the default, so the globe
            // belongs to the answer whenever the covering winner is a default — but
            // only when it is THE globe's default. The globe hangs off the IPv4
            // `defaultInterface`; an IPv6 query that egresses by some other tunnel's
            // v6 default must not light it, or the picture claims an egress the
            // answer never mentioned. The panel carries that case.
            hitsInternet: r.winner?.isDefault == true
                && r.winner?.interfaceName == topo.topology.defaultInterface,
            standbyDefaults: Set(r.alternatives.filter(\.isDefault).map(\.interfaceName)))
    }

    /// Only for input that isn't an address or network at all — everything else,
    /// including "nothing routes this", is answered properly by the panel. Takes the
    /// already-resolved outcome rather than resolving again.
    func searchHint(_ outcome: SearchOutcome?) -> String? {   // was private — internal for the file split
        guard !searchText.trimmingCharacters(in: .whitespaces).isEmpty, outcome == nil
        else { return nil }
        return "Type an IP address or network, e.g. 10.1.2.3 or 2606:4700::/32"
    }

    func isHighlighted(_ row: RouteRow, in dest: GraphNode.Destination,   // was private — internal for the file split
                               _ outcome: SearchOutcome?) -> Bool {
        outcome?.litRows.contains("\(dest.interfaceName)|\(row.cidr)") == true
    }

    /// Changes exactly when the set of lit rows changes — the trigger for revealing
    /// them, and the reason revealing happens ONCE per search rather than continuously.
    func litSignature(_ outcome: SearchOutcome?) -> String {   // was private — internal for the file split
        outcome.map { $0.litRows.sorted().joined(separator: ",") } ?? ""
    }

    /// Bring a matched row into view: a highlight inside a collapsed card, or below
    /// the scroll window, is a highlight nobody can see.
    ///
    /// Fires only on a NEW answer. After that the card is the user's again — they can
    /// scroll away and it stays where they put it, and clearing the field leaves
    /// everything open exactly as it is. Nothing snaps back on its own.
    func revealMatches(_ outcome: SearchOutcome?) {   // was private — internal for the file split
        guard let outcome, let topo else { return }   // cleared search reveals nothing
        let t = topo.topology
        var opened: [String: CGFloat] = [:]
        var toExpand: Set<String> = []

        for iface in t.interfaces.filter(\.inUse) {
            for dest in destinations(for: iface, in: t) {
                guard let index = dest.routes.firstIndex(where: {
                    outcome.litRows.contains("\(dest.interfaceName)|\($0.cidr)")
                }) else { continue }
                // Short cards show every row, and a collapsed card already shows its
                // first few — neither needs disturbing.
                guard dest.routes.count > collapseThreshold else { continue }
                if !expandedCards.contains(dest.id) && index < collapsedRows { continue }

                toExpand.insert(dest.id)
                let window = min(dest.routes.count, expandedWindowRows)
                let limit = max(0, CGFloat(dest.routes.count - window) * rowHeight)
                // Roughly centred in the window, clamped to the ends of the list.
                let centred = (CGFloat(index) - CGFloat(window - 1) / 2) * rowHeight
                opened[dest.id] = min(limit, max(0, centred))
            }
        }
        guard !toExpand.isEmpty else { return }

        func apply() {
            expandedCards.formUnion(toExpand)
            for (id, offset) in opened { cardScroll[id] = offset }
        }
        // Opening a card reflows everything below it, so the motion is worth easing —
        // unless the user has asked for less of it, in which case it simply happens.
        if reduceMotion { apply() } else { withAnimation(.easeOut(duration: 0.18)) { apply() } }
    }
}
