// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
//  VPNComposition.swift
//  A saved multi-VPN "virtual config": several member VPNs plus how they relate,
//  connected together from one button. Two relationships, matching what the
//  NetworkExtension routing model can actually deliver:
//   • parallel  — members come up together; the routing table merges their routes
//     by specificity (a split tunnel's specific routes win over a full tunnel's
//     default), so full+split or split+split coexist. Two FULL tunnels conflict
//     (both claim 0.0.0.0/0) — flagged before connecting.
//   • over (chained) — retained in saved data, but refused at connect until an
//     actual transport connector exists. Start order does not select an underlay.
//   WireGuard compositions also have an explicit action that connects through
//   one virtual capture interface, using internal packet ports and flow routing.
//
//  Compositions hold no secrets — each member authenticates with its own saved
//  credentials or password-manager source, so a composition connect is
//  unattended unless a member needs a fresh OTP (then that member falls back to
//  its own connect form).
//

import Foundation
import Observation

struct VPNComposition: Codable, Sendable, Equatable, Identifiable {
    var id: String = UUID().uuidString
    var name: String = "New Composition"
    var members: [Member] = []
    /// nil uses whole-Mac destination routing. An empty array retains per-app
    /// capture mode when the last rule was temporary and its process is gone.
    var applicationRoutes: [VPNApplicationRoute]?
    var eventSource: String?
    /// Explicitly selected virtual interface. Older apps keep these groups out of their ordinary VPN list.
    var sharedInterface: Bool?
    var usesSharedRouter: Bool { sharedInterface == true || applicationRoutes != nil || eventSource != nil }

    func applicationRouteProblem(temporary: [VPNProcessRoute]) -> String? {
        guard let applicationRoutes else { return nil }
        guard (1...16).contains(members.count) else { return "Choose between one and sixteen WireGuard VPNs." }
        guard !applicationRoutes.isEmpty || !temporary.isEmpty else {
            return "Choose an app or a running process. Temporary choices must be made again after reopening SimpleVPN."
        }
        let all = applicationRoutes + temporary.map(\.route)
        let ports = Set(members.map(\.profileID))
        guard all.allSatisfy({ ports.contains($0.port) }) else { return "Choose an available VPN for each source." }
        guard Set(all.map(\.id)).count == all.count else { return "A source rule appears more than once." }
        for route in all {
            if let issue = route.processCriteriaProblem { return "\(route.name) — \(issue)" }
            if let issue = route.destinationProblem(memberIDs: ports) { return "\(route.name) — \(issue)" }
        }
        guard all.count <= SourceIdentityWire.maximumCandidates else {
            return "Choose up to \(SourceIdentityWire.maximumCandidates) app and process rules."
        }
        for (index, route) in applicationRoutes.enumerated() where applicationRoutes.prefix(index).contains(where: { route.conflicts(with: $0) }) {
            return "Rules for \(route.name) can select the same process. Give each rule a different executable name, path, or value of the same proxy variable."
        }
        if temporary.contains(where: { $0.route.processCriteria != nil }) {
            return "Choose a signed app or tool for persistent process conditions."
        }
        let capture = VPNApplicationCapture(routes: all, processRouteIDs: Set(temporary.map(\.route.id)))
        guard capture.fitsRuleBudget else {
            return "Choose up to \(VPNApplicationCapture.maximumRules) source rules and destination overrides in total."
        }
        guard capture.isValid(memberIDs: ports) else {
            return "Check each signing identity and process condition."
        }
        let tokens = Dictionary(uniqueKeysWithValues: temporary.map { ($0.route.id, $0.auditToken) })
        guard capture.accepts(processTokens: tokens) else {
            return "Choose each running process again and assign it to one VPN."
        }
        return nil
    }

    struct Member: Codable, Sendable, Equatable, Identifiable {
        var id: String { profileID }
        var profileID: String
        var role: Role = .full
        /// profileID of the member this one tunnels *over*; nil = parallel.
        var dependsOn: String? = nil
    }

    enum Role: String, Codable, Sendable, CaseIterable {
        case full, split
        var label: String { self == .full ? "Full tunnel" : "Split tunnel" }
    }

    /// Invalid graphs have no start order; callers must surface the reason rather
    /// than breaking a cycle or dropping a missing dependency into physical dialing.
    var validationProblem: String? {
        let ids = members.map(\.profileID)
        if Set(ids).count != ids.count { return "A VPN appears more than once in this composition." }
        for member in members {
            if let dependency = member.dependsOn, !ids.contains(dependency) {
                return "A VPN this composition depends on is missing."
            }
        }
        if topologicalOrder == nil { return "This composition has a circular VPN dependency." }
        return nil
    }

    private var topologicalOrder: [Member]? {
        var result: [Member] = []
        var remaining = members
        while !remaining.isEmpty {
            let ready = remaining.filter { member in
                member.dependsOn.map { dependency in result.contains { $0.profileID == dependency } } ?? true
            }
            guard !ready.isEmpty else { return nil }
            result += ready
            let readyIDs = Set(ready.map(\.profileID))
            remaining.removeAll { readyIDs.contains($0.profileID) }
        }
        return result
    }

    var startOrder: [Member] { validationProblem == nil ? topologicalOrder ?? [] : [] }

    /// More than one full-tunnel member can't coexist (both want the default route).
    var fullTunnelConflict: Bool { members.filter { $0.role == .full }.count > 1 }
}

@MainActor
@Observable
final class CompositionStore {
    private(set) var compositions: [VPNComposition] = []
    // Each newer restriction lives outside every key a client that predates
    // it can decode. Otherwise an ignored optional key would widen the route.
    private enum Bucket: String, CaseIterable {
        case destination = "compositions.v1"
        case application = "compositions.app-routing.v1"
        case event = "compositions.events.v1"
        case process = "compositions.process-context.v1"
        case shared = "compositions.shared-interface.v1"

        init(_ composition: VPNComposition) {
            if composition.sharedInterface == true { self = .shared }
            else if composition.applicationRoutes?.contains(where: { $0.processCriteria != nil }) == true { self = .process }
            else if composition.eventSource != nil { self = .event }
            else if composition.applicationRoutes != nil { self = .application }
            else { self = .destination }
        }
    }
    private let defaults: UserDefaults?

    init(defaults: UserDefaults? = .standard) {
        self.defaults = defaults
        load()
    }

    func save(_ composition: VPNComposition) {
        var previousBucket: Bucket?
        if let i = compositions.firstIndex(where: { $0.id == composition.id }) {
            previousBucket = Bucket(compositions[i])
            compositions[i] = composition
        } else {
            compositions.append(composition)
        }
        persist(removingFrom: previousBucket)
    }

    func remove(_ id: String) {
        compositions.removeAll { $0.id == id }
        persist()
    }

    /// Drop any member that references a VPN that no longer exists.
    func prune(existingProfileIDs: Set<String>) {
        var changed = false
        for i in compositions.indices {
            let before = compositions[i].members.count
            compositions[i].members.removeAll { !existingProfileIDs.contains($0.profileID) }
            // Keep missing dependencies visible: clearing one would silently
            // change a chained connection into a physical-underlay connection.
            if compositions[i].members.count != before { changed = true }
        }
        if changed { persist() }
    }

    private func load() {
        var seen = Set<String>()
        // Prefer the most restricted copy if an earlier write was interrupted.
        for bucket in Bucket.allCases.reversed() {
            guard let data = defaults?.data(forKey: bucket.rawValue),
                  let decoded = try? JSONDecoder().decode([VPNComposition].self, from: data) else { continue }
            let values = decoded.filter { seen.insert($0.id).inserted && Bucket($0) == bucket }
            compositions.insert(contentsOf: values, at: 0)
        }
    }

    private func persist(removingFrom previous: Bucket? = nil) {
        guard let defaults else { return }
        do {
            let encoded = try Bucket.allCases.map { bucket in
                (bucket, try JSONEncoder().encode(compositions.filter { Bucket($0) == bucket }))
            }
            // Remove the former representation first when changing modes. A
            // crash between writes can lose the edit, but cannot widen its scope.
            if let previous, let data = encoded.first(where: { $0.0 == previous })?.1 {
                defaults.set(data, forKey: previous.rawValue)
            }
            for (bucket, data) in encoded where bucket != previous {
                defaults.set(data, forKey: bucket.rawValue)
            }
        } catch { return }
    }
}
