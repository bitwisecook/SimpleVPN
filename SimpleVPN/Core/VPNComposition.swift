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
//   • over (chained) — a member starts only once the member it runs "over" is up,
//     so its transport rides that tunnel (its server must be routed by the lower
//     tunnel). Expressed as a per-member dependency; connect honors the order.
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

    /// Members ordered so dependencies (the tunnel you run "over") start first.
    /// Cycles are broken defensively — order is best-effort, never a hang.
    var startOrder: [Member] {
        var ordered: [Member] = []
        var remaining = members
        var guardCount = 0
        while !remaining.isEmpty && guardCount < members.count + 1 {
            let ready = remaining.filter { m in
                guard let dep = m.dependsOn else { return true }
                return ordered.contains { $0.profileID == dep } || !members.contains { $0.profileID == dep }
            }
            if ready.isEmpty { ordered += remaining; break }   // cycle: give up ordering
            ordered += ready
            let readyIDs = Set(ready.map(\.profileID))
            remaining.removeAll { readyIDs.contains($0.profileID) }
            guardCount += 1
        }
        return ordered
    }

    /// More than one full-tunnel member can't coexist (both want the default route).
    var fullTunnelConflict: Bool { members.filter { $0.role == .full }.count > 1 }
}

@MainActor
@Observable
final class CompositionStore {
    private(set) var compositions: [VPNComposition] = []
    private static let key = "compositions.v1"

    init() { load() }

    func save(_ composition: VPNComposition) {
        if let i = compositions.firstIndex(where: { $0.id == composition.id }) {
            compositions[i] = composition
        } else {
            compositions.append(composition)
        }
        persist()
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
            for j in compositions[i].members.indices {
                if let dep = compositions[i].members[j].dependsOn, !existingProfileIDs.contains(dep) {
                    compositions[i].members[j].dependsOn = nil
                }
            }
            if compositions[i].members.count != before { changed = true }
        }
        if changed { persist() }
    }

    private func load() {
        guard let data = UserDefaults.standard.data(forKey: Self.key),
              let list = try? JSONDecoder().decode([VPNComposition].self, from: data) else { return }
        compositions = list
    }
    private func persist() {
        if let data = try? JSONEncoder().encode(compositions) {
            UserDefaults.standard.set(data, forKey: Self.key)
        }
    }
}
