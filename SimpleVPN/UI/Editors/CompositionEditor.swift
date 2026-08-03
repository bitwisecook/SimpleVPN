// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
//  CompositionEditor.swift
//  Build/edit a multi-VPN composition: name it, add member VPNs, set each one's
//  role (full or split tunnel) and — for a chained member — which member it runs
//  "over". Warns about the one arrangement NetworkExtension can't deliver: two
//  full tunnels at once.
//

import SwiftUI

struct CompositionEditor: View {
    @Bindable var vpn: VPNController
    @Bindable var store: CompositionStore
    @State var draft: VPNComposition
    let onDone: () -> Void

    @Environment(\.dismiss) private var dismiss

    private var availableToAdd: [VPNController.Profile] {
        let taken = Set(draft.members.map(\.profileID))
        return vpn.profiles.filter { !taken.contains($0.id) }
    }
    private func name(_ id: String) -> String { vpn.profiles.first { $0.id == id }?.name ?? id }

    var body: some View {
        NavigationStack {
            Form {
                Section("Name") { TextField("Name", text: $draft.name) }

                Section {
                    if draft.members.isEmpty {
                        Text("Add two or more VPNs to connect together.")
                            .foregroundStyle(.secondary)
                    }
                    ForEach($draft.members) { $member in
                        memberRow($member)
                    }
                    .onDelete { draft.members.remove(atOffsets: $0) }

                    if !availableToAdd.isEmpty {
                        Menu {
                            ForEach(availableToAdd) { p in
                                Button(p.name) { draft.members.append(.init(profileID: p.id)) }
                            }
                        } label: { Label("Add VPN", systemImage: "plus") }
                    }
                } header: {
                    Text("Members")
                } footer: {
                    if draft.fullTunnelConflict {
                        Label("Two full-tunnel VPNs can't run at once — both need to carry all traffic. Make one a split tunnel.",
                              systemImage: "exclamationmark.triangle.fill")
                            .foregroundStyle(.orange)
                    } else {
                        Text("Full tunnels carry everything; split tunnels carry only their own networks and can sit beside a full tunnel. A member set to run “over” another connects after it, so its traffic rides the lower tunnel.")
                    }
                }
            }
            .formStyle(.grouped)
            .navigationTitle("Composition")
            .toolbar {
                ToolbarItem(placement: .cancellationAction) { Button("Cancel") { dismiss(); onDone() } }
                ToolbarItem(placement: .confirmationAction) {
                    Button("Save") { store.save(draft); dismiss(); onDone() }
                        .disabled(draft.members.count < 2 ||
                                  draft.name.trimmingCharacters(in: .whitespaces).isEmpty)
                }
            }
        }
        .frame(width: 480, height: 460)
    }

    @ViewBuilder private func memberRow(_ member: Binding<VPNComposition.Member>) -> some View {
        let others = draft.members.filter { $0.profileID != member.wrappedValue.profileID }
        VStack(alignment: .leading, spacing: 6) {
            Text(name(member.wrappedValue.profileID)).font(.headline)
            HStack(spacing: 12) {
                Picker("Role", selection: member.role) {
                    ForEach(VPNComposition.Role.allCases, id: \.self) { Text($0.label).tag($0) }
                }
                .fixedSize()
                Picker("Runs over", selection: Binding(
                    get: { member.wrappedValue.dependsOn ?? "" },
                    set: { member.wrappedValue.dependsOn = $0.isEmpty ? nil : $0 })) {
                    Text("Runs in parallel").tag("")
                    ForEach(others, id: \.profileID) { Text(name($0.profileID)).tag($0.profileID) }
                }
            }
            .labelsHidden()
            .controlSize(.small)
        }
        .padding(.vertical, 2)
    }
}
