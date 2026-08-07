// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
//  RouteGraphGuests.swift
//  VIRTUAL MACHINES AND CONTAINERS AS FIRST-CLASS NODES on the route graph, and
//  the one control that decides where their traffic goes.
//
//  WHY THEY ARE A COLUMN OF THEIR OWN, TO THE LEFT OF THIS MAC. Because that is
//  where they are. A guest on a shared network sends a packet into this Mac, which
//  then decides — exactly like every application on it — whether that packet leaves
//  by a VPN or by the physical link. Drawing guests as another "network behind an
//  interface" (which is what the routing table alone makes them look like, and what
//  the diagram showed before: a card labelled "Local network" on `bridge100`) says
//  the opposite, and it is the reason a user cannot see this today.
//
//  THE THREE ARRANGEMENTS ROUTE DIFFERENTLY AND ARE DRAWN DIFFERENTLY
//  (`ONTOLOGY.md`, "Virtual machines and containers"):
//   • a SHARED network's guests go through this Mac → the edge names the VPN
//     carrying them, and the control applies;
//   • a HOST-ONLY network has no way out at all → the edge says so, and the control
//     still applies because a tunnel can still take away this Mac's own path to it;
//   • a BRIDGED network is not this Mac's decision → the edge says that in those
//     words, and NO control is offered, because a rule there would apply perfectly
//     and change nothing;
//   • and where we cannot see which, the card says so rather than assuming.
//
//  THE TWO JOURNEYS, KEPT APART. `GuestNetworkRouting`'s header has the full
//  argument; the card obeys it by having two lines rather than one:
//    "Reaching them"  — this Mac → the guests, which the control changes.
//    "Their way out"  — the guests → the internet, which follows this Mac's own
//                       default route and which nothing here can move.
//  One line saying "your containers are outside the VPN" would be the security claim
//  we cannot honour.
//
//  DRAWING RULES, inherited and binding. Everything in this file is drawn INSIDE the
//  scaled/animated container, so: SwiftUI only — Text, shapes, `.plain` Buttons. No
//  Toggle, no Menu, no ProgressView, nothing platform-backed (that is the AppKit
//  layout deadlock). The choice is therefore ONE `.plain` Button that states the next
//  action, never a switch. The popover renders outside the transform, so the
//  inspector may use ordinary controls.
//

import SwiftUI

// MARK: - Model

/// One guest network as the graph needs it: what it is, how it is wired, how many
/// guests are on it, and where its traffic goes right now.
///
/// A VALUE, computed once per layout pass from the snapshot and the live topology,
/// so the card, the edge, the inspector, the rotor and the accessibility sentence
/// all read the same answer and cannot disagree about what is on screen.
struct GuestGraphCard: Identifiable, Equatable {
    /// `guest-<interface>` — stable across refreshes, so selection and the popover
    /// survive the 1 Hz poll.
    let id: String
    /// Which product, or an honest "a virtual machine or container".
    var title: String
    /// The host interface carrying it (`bridge100`), or the guest tap for a bridged
    /// guest (`vmenet0`).
    var interfaceName: String
    /// The guest subnet. Nil for a bridged guest — there is no network of ours.
    var subnet: String?
    /// This Mac's own address on it, when it has one.
    var hostAddress: String?
    var mode: GuestNetworkMode
    var modeEvidence: String
    /// How many guest taps are attached — how many guests are actually running.
    var guestCount: Int
    var routing: GuestNetworkRouting
    /// Where the guests' OWN traffic leaves this Mac by, in words. Nil when this Mac
    /// is not on their path or there is no way out at all.
    var wayOut: String?
    /// Live bytes on the host interface, so the guest edge's dashes march when the
    /// guests are actually doing something.
    var inRate: Double = 0
    var outRate: Double = 0

    var isActive: Bool { inRate > 512 || outRate > 512 }
}

// MARK: - Building the cards

extension RouteGraphView {

    /// Every live guest network and running-but-unattributable guest, as cards.
    ///
    /// APPEARS ONCE, BY CONSTRUCTION: keyed on the host interface name and
    /// de-duplicated on it, so a bridge reporting two addresses on one subnet — or a
    /// tap already counted as a member of a guest network — cannot produce a second
    /// node. `VirtualizationDiscovery.bridgedGuests` does the other half of that,
    /// excluding every tap a guest network has already claimed.
    var guestCards: [GuestGraphCard] {
        guard virtualization.detectionEnabled else { return [] }
        var seen = Set<String>()
        var out: [GuestGraphCard] = []

        for network in virtualization.distinctGuestNetworks {
            guard seen.insert(network.interfaceName).inserted else { continue }
            let carriers = vpn.guestNetworkCarriers(subnet: network.subnet)
            let routing = GuestNetworkRouting.decide(
                mode: network.mode, carriers: carriers,
                allowDivertOutside: ManagedPolicy.allowDivertOutside,
                forceKeepInside: ManagedPolicy.forceKeepInsideVPN)
            let iface = topo?.topology.interfaces.first { $0.name == network.interfaceName }
            out.append(GuestGraphCard(
                id: "guest-\(network.interfaceName)",
                title: network.attribution,
                interfaceName: network.interfaceName,
                subnet: network.subnet,
                hostAddress: network.hostAddress,
                mode: network.mode,
                modeEvidence: network.modeEvidence,
                guestCount: network.attachedGuestInterfaces.count,
                routing: routing,
                wayOut: wayOutSentence(mode: network.mode),
                inRate: iface?.inRate ?? 0,
                outRate: iface?.outRate ?? 0))
        }

        for guest in virtualization.bridgedGuests {
            guard seen.insert(guest.interfaceName).inserted else { continue }
            let iface = topo?.topology.interfaces.first { $0.name == guest.interfaceName }
            out.append(GuestGraphCard(
                id: "guest-\(guest.interfaceName)",
                title: guest.attribution,
                interfaceName: guest.interfaceName,
                subnet: nil,
                hostAddress: nil,
                mode: .bridged,
                modeEvidence:
                    "A guest is running on \(guest.interfaceName) and there is no network of this "
                    + "Mac\u{2019}s behind it, so this Mac is not on its path.",
                guestCount: 1,
                routing: GuestNetworkRouting.decide(
                    mode: .bridged, carriers: [],
                    allowDivertOutside: ManagedPolicy.allowDivertOutside,
                    forceKeepInside: ManagedPolicy.forceKeepInsideVPN),
                wayOut: nil,
                inRate: iface?.inRate ?? 0,
                outRate: iface?.outRate ?? 0))
        }
        return out
    }

    /// "Their way out is Wi-Fi" — the guests' OWN egress, which is this Mac's default
    /// route and is not the same question as the edge label. Deliberately phrased as
    /// an observation rather than a setting, because nothing on this screen moves it.
    private func wayOutSentence(mode: GuestNetworkMode) -> String? {
        switch mode {
        case .bridged: return nil
        case .hostOnly: return "no way out \u{2014} this Mac and its guests only"
        case .shared, .unknown:
            guard let name = topo?.topology.defaultInterface,
                  let iface = topo?.topology.interfaces.first(where: { $0.name == name })
            else { return "nothing is carrying the default route" }
            return label(for: iface)
        }
    }

    /// The tint the card, its border and its edge share. Purple = a VPN is carrying
    /// it (the same purple every tunnel card uses); gray = it is not; orange = the
    /// VPNs disagree, which is the one state worth noticing.
    func guestTint(_ card: GuestGraphCard) -> Color {
        switch card.routing.path {
        case .throughVPN: .purple
        case .aroundVPN: .gray
        case .partlyAround: .orange
        case .noVPN, .notThisMacsDecision: .secondary
        }
    }

    // MARK: - The card

    /// SwiftUI drawing only — this is inside the scaled container. Every line has a
    /// FIXED height so the card fits the frame `buildLayout` predicted for it; that
    /// is the same discipline the destination cards keep, and for the same reason
    /// (measuring the rendered card and feeding it back is the AppKit layout
    /// deadlock).
    @ViewBuilder func guestNetworkCard(_ card: GuestGraphCard) -> some View {
        let tint = guestTint(card)
        let selected = inspecting == card.id
        VStack(alignment: .leading, spacing: 0) {
            HStack(spacing: 6) {
                Image(systemName: "shippingbox").foregroundStyle(tint)
                    .accessibilityHidden(true)
                Text(card.title).font(.callout.weight(.medium)).lineLimit(1)
            }
            .padding(.horizontal, 10).frame(height: headerHeight)
            .frame(maxWidth: .infinity, alignment: .leading)
            .background(tint.opacity(0.16))
            Divider()

            VStack(alignment: .leading, spacing: 2) {
                Text(card.subnet ?? card.interfaceName)
                    .font(.caption.monospaced()).foregroundStyle(.secondary)
                    .lineLimit(1).frame(height: guestLineHeight, alignment: .leading)
                Text(card.mode.title)
                    .font(.caption2).foregroundStyle(.secondary)
                    .lineLimit(1).frame(height: guestLineHeight, alignment: .leading)
                Text(card.guestCount == 1 ? "1 guest running" : "\(card.guestCount) guests running")
                    .font(.caption2).foregroundStyle(.tertiary)
                    .lineLimit(1).frame(height: guestLineHeight, alignment: .leading)

                Divider().padding(.vertical, 2)

                // The two journeys, never merged into one claim.
                Text("Reaching them: \(card.routing.edgeLabel)")
                    .font(.caption2).foregroundStyle(.secondary)
                    .lineLimit(1).frame(height: guestLineHeight, alignment: .leading)
                Text(card.wayOut.map { "Their way out: \($0)" } ?? " ")
                    .font(.caption2).foregroundStyle(.tertiary)
                    .lineLimit(1).frame(height: guestLineHeight, alignment: .leading)

                guestChoiceControl(card)
            }
            .padding(10)
            .frame(maxWidth: .infinity, maxHeight: .infinity, alignment: .topLeading)
        }
        .background(.background.secondary, in: RoundedRectangle(cornerRadius: 10))
        .overlay(RoundedRectangle(cornerRadius: 10)
            .strokeBorder(selected ? tint : tint.opacity(0.55), lineWidth: selected ? 2 : 1))
        // A NAMED CONTAINER, not a combined one (Docs/Accessibility.md rule 4): the
        // card holds a real Button, and a card-wide `.combine` would swallow it.
        .accessibilityElement(children: .contain)
        .accessibilityLabel(guestAXLabel(card))
        .accessibilityValue(guestAXValue(card))
        .accessibilityAction(named: "Show Details") { select(card.id) }
        .accessibilityRotorEntry(id: "rotor-guest-\(card.id)", in: rotorNamespace)
        .contentShape(RoundedRectangle(cornerRadius: 10))
        .onTapGesture { select(card.id) }
        .help("Click for what is on this network and where its traffic goes")
        .popover(isPresented: Binding(
            get: { inspecting == card.id },
            set: { if !$0, inspecting == card.id { inspecting = nil } }
        ), arrowEdge: .trailing) {
            guestInspector(card)
        }
    }

    /// The whole of part three, in one control.
    ///
    /// A `.plain` Button and never a Toggle: a platform-backed control inside the
    /// scaled container deadlocks AppKit layout, and a button that names the next
    /// action is in any case the clearer thing for a choice with a consequence. Where
    /// there is no choice the same space says WHY in the user's terms rather than
    /// showing a dead switch (`Docs/Accessibility.md` rule 5: a disabled control says
    /// why, in `.help` and in the accessibility value alike).
    @ViewBuilder private func guestChoiceControl(_ card: GuestGraphCard) -> some View {
        if let next = card.routing.nextChoiceTitle, let subnet = card.subnet {
            Button {
                Task {
                    await vpn.setGuestNetworkKeptDirect(
                        card.routing.path != .aroundVPN,
                        subnet: subnet, attribution: card.title,
                        interfaceName: card.interfaceName)
                }
            } label: {
                Text(next)
                    .font(.caption2.weight(.medium))
                    .foregroundStyle(Color.accentColor)
                    .frame(maxWidth: .infinity, alignment: .leading)
                    .contentShape(Rectangle())
            }
            .buttonStyle(.plain)
            .frame(height: guestButtonHeight, alignment: .leading)
            .help(card.routing.nextChoiceConsequence(subnet: subnet))
            .accessibilityLabel(next)
            .accessibilityHint(card.routing.nextChoiceConsequence(subnet: subnet))
        } else {
            Text(card.routing.choiceBlockedReason ?? "")
                .font(.caption2).foregroundStyle(.tertiary)
                .lineLimit(2)
                .frame(height: guestButtonHeight, alignment: .topLeading)
                .accessibilityHidden(true)   // already in the card's own value sentence
        }
    }

    // MARK: - Accessibility

    /// What it is. The mode is in the label rather than the value because it does not
    /// change while you look at it — where the traffic goes does, and that is what a
    /// value is for.
    func guestAXLabel(_ card: GuestGraphCard) -> String {
        let where_ = card.subnet.map { "\($0) on \(card.interfaceName)" } ?? card.interfaceName
        return "\(card.title), \(card.mode.title.lowercased()), \(where_)"
    }

    /// What is true of it right now — the two journeys and, when there is no choice,
    /// why not.
    func guestAXValue(_ card: GuestGraphCard) -> String {
        var parts = [
            card.guestCount == 1 ? "1 guest running" : "\(card.guestCount) guests running",
            "reaching them, \(card.routing.edgeLabel)",
        ]
        if let wayOut = card.wayOut { parts.append("their way out, \(wayOut)") }
        if card.routing.nextChoiceTitle == nil, let why = card.routing.choiceBlockedReason {
            parts.append(why)
        }
        return parts.joined(separator: ", ")
    }

    /// The "Guests" rotor: jump straight to a container's network without walking the
    /// diagram, exactly as "VPNs" does for tunnels.
    func guestRotorTargets() -> [RotorTarget] {
        guestCards.map { card in
            RotorTarget(id: "rotor-guest-\(card.id)",
                        label: "\(card.title) \u{2014} \(card.routing.edgeLabel)")
        }
    }

    // MARK: - The inspector (a popover: OUTSIDE the transform, ordinary controls fine)

    @ViewBuilder func guestInspector(_ card: GuestGraphCard) -> some View {
        VStack(alignment: .leading, spacing: 10) {
            HStack(spacing: 8) {
                Image(systemName: "shippingbox")
                    .font(.title3).foregroundStyle(guestTint(card))
                VStack(alignment: .leading, spacing: 1) {
                    Text(card.title).font(.headline)
                    Text(card.interfaceName).font(.caption.monospaced()).foregroundStyle(.secondary)
                }
            }

            Divider()
            VStack(alignment: .leading, spacing: 3) {
                Text(card.mode.title).font(.callout)
                Text(card.mode.summary)
                    .font(.caption).foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
                // WHERE THE ANSWER CAME FROM. "Shared" and "shared, because Apple's own
                // record on this Mac says so" are different claims, and the second is
                // the only one worth making.
                if !card.modeEvidence.isEmpty {
                    Text(card.modeEvidence)
                        .font(.caption).foregroundStyle(.tertiary)
                        .fixedSize(horizontal: false, vertical: true)
                }
            }

            if let subnet = card.subnet {
                Divider()
                VStack(alignment: .leading, spacing: 3) {
                    Text("Guest network").font(.caption.weight(.semibold)).foregroundStyle(.secondary)
                    Text(subnet).font(.caption.monospaced()).textSelection(.enabled)
                    if let host = card.hostAddress {
                        Text("This Mac is \(host) on it")
                            .font(.caption).foregroundStyle(.secondary)
                    }
                }
            }

            Divider()
            VStack(alignment: .leading, spacing: 3) {
                Text("Reaching them: \(card.routing.edgeLabel)")
                    .font(.callout)
                    .fixedSize(horizontal: false, vertical: true)
                if let wayOut = card.wayOut {
                    Text("Their way out: \(wayOut)")
                        .font(.callout).foregroundStyle(.secondary)
                        .fixedSize(horizontal: false, vertical: true)
                    Text("Guests reach the internet through this Mac\u{2019}s own way out. Keeping "
                         + "their network direct changes what this Mac sends TO them, not what "
                         + "they send out.")
                        .font(.caption).foregroundStyle(.tertiary)
                        .fixedSize(horizontal: false, vertical: true)
                }
            }

            if let next = card.routing.nextChoiceTitle, let subnet = card.subnet {
                Divider()
                Text(card.routing.nextChoiceConsequence(subnet: subnet))
                    .font(.caption).foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
                Button(next) {
                    Task {
                        await vpn.setGuestNetworkKeptDirect(
                            card.routing.path != .aroundVPN,
                            subnet: subnet, attribution: card.title,
                            interfaceName: card.interfaceName)
                    }
                    inspecting = nil
                }
            } else if let why = card.routing.choiceBlockedReason {
                Divider()
                Text(why)
                    .font(.caption).foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }
        }
        .padding(14)
        .frame(width: 300, alignment: .leading)
    }
}
