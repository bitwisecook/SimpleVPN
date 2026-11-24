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
    @State private var validatedEventSource: String?
    @State private var eventProblem: String?
    @State private var eventsExpanded = false
    @State private var selectApps: Bool
    @State private var signedRoutes: [VPNApplicationRoute]
    @State private var processRoutes: [VPNProcessRoute]

    init(vpn: VPNController, store: CompositionStore, draft: VPNComposition, onDone: @escaping () -> Void) {
        self.vpn = vpn
        self.store = store
        _draft = State(initialValue: draft)
        _selectApps = State(initialValue: draft.applicationRoutes != nil)
        _signedRoutes = State(initialValue: draft.applicationRoutes ?? [])
        _processRoutes = State(initialValue: vpn.temporaryProcessRoutes[draft.id] ?? [])
        self.onDone = onDone
    }

    private var pending: VPNComposition {
        var result = draft
        result.applicationRoutes = selectApps ? signedRoutes : nil
        if selectApps { result.sharedInterface = nil }
        else if result.members.count == 1 { result.sharedInterface = true }
        if selectApps {
            result.members = draft.members.map { .init(profileID: $0.profileID, role: .split) }
        }
        return result
    }

    private var sourcePorts: [AppRoutePort] {
        draft.members.compactMap { member in
            guard let p = vpn.compositionProfiles.first(where: { $0.id == member.profileID && vpn.virtualMemberProblem(for: $0) == nil }) else { return nil }
            return AppRoutePort(id: p.id, name: p.name)
        }
    }

    @Environment(\.dismiss) private var dismiss
    @FocusState private var nameFocused: Bool

    private var availableToAdd: [VPNController.Profile] {
        let taken = Set(draft.members.map(\.profileID))
        return vpn.compositionProfiles.filter { !taken.contains($0.id) && (!selectApps || vpn.virtualMemberProblem(for: $0) == nil) }
    }
    private func name(_ id: String) -> String { vpn.compositionProfiles.first { $0.id == id }?.name ?? id }

    var body: some View {
        NavigationStack {
            Form {
                Section {
                    TextField("Name", text: $draft.name)
                        .focused($nameFocused)
                    Picker("Route traffic", selection: $selectApps) {
                        Text("By destination").tag(false)
                        Text("From selected apps").tag(true)
                    }
                    .pickerStyle(.menu)
                    .accessibilityLabel("Route traffic")
                    .accessibilityIdentifier("composition-route-traffic")
                    if !selectApps && draft.applicationRoutes != nil {
                        Text("Saving will remove this composition’s app and process rules.").font(.caption)
                    }
                }

                Section {
                    if draft.members.isEmpty {
                        Text(selectApps ? "Add a compatible VPN to carry traffic from the selected apps." : "Add a VPN to route through this connection.")
                            .foregroundStyle(.secondary)
                    }
                    ForEach($draft.members) { $member in
                        memberRow($member)
                    }
                    .onDelete { draft.members.remove(atOffsets: $0) }

                    if !availableToAdd.isEmpty {
                        Menu {
                            ForEach(availableToAdd) { p in
                                Button(p.name) { draft.members.append(.init(profileID: p.id, role: selectApps || draft.members.contains(where: { $0.role == .full }) ? .split : .full)) }
                            }
                        } label: { Label("Add VPN", systemImage: "plus") }
                    }
                } header: {
                    Text("Members")
                } footer: {
                    if selectApps {
                        Text("Selected apps can use destinations permitted by their chosen VPN or Proxy Tunnel.")
                    } else if draft.members.count == 1 {
                        Text("The virtual interface routes new outgoing connections through this VPN. Use the individual VPN for incoming connections and its own DNS configuration.")
                    } else if draft.fullTunnelConflict {
                        Label("Two full-tunnel VPNs can't run at once — both need to carry all traffic. Make one a split tunnel.",
                              systemImage: "exclamationmark.triangle.fill")
                            .foregroundStyle(.orange)
                    } else {
                        Text("Full tunnels carry everything; split tunnels carry their own networks. Chained VPN connections are unavailable in this connection mode.")
                    }
                }
                if draft.eventSource != nil || (!sourcePorts.isEmpty && sourcePorts.count == draft.members.count) {
                    DisclosureGroup("Session Event Handlers", isExpanded: $eventsExpanded) {
                        Text("Attach a named action to an outbound event. For example, clamp the TCP maximum segment size when opening a connection.")
                        ConfigSourceLabel(text: "on web tcp.syn port 443 => clamp-mss 1280", format: .routingEvents)
                        if eventsExpanded {
                            RoutingSourceEditor(vpn: vpn, text: Binding(get: { draft.eventSource ?? "" }, set: {
                                draft.eventSource = $0.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty ? nil : $0
                            }), adapter: "wireguard-shared", accessibilityLabel: "Session event handler code")
                            .frame(minHeight: 130)
                        }
                        if let eventProblem { Text(eventProblem).foregroundStyle(.red) }
                    }
                    .disclosureGroupStyle(AccessibleSettingsDisclosureStyle())
                    .task(id: draft.eventSource) {
                        eventProblem = nil
                        guard let source = draft.eventSource else { validatedEventSource = nil; return }
                        do { try await Task.sleep(for: .milliseconds(350)) } catch { return }
                        let outcome = await RoutingEventValidation.check(source)
                        guard !Task.isCancelled, draft.eventSource == source else { return }
                        switch outcome {
                        case .accepted:
                            validatedEventSource = source
                        case .rejected(let diagnostic):
                            eventProblem = diagnostic
                            validatedEventSource = nil
                        }
                    }
                }
                if selectApps {
                    AppRouteSection(ports: sourcePorts, signed: $signedRoutes, processes: $processRoutes)
                }
                if let problem = saveDisabledReason {
                    Text(problem).font(.callout).foregroundStyle(.secondary)
                }
            }
            .formStyle(.grouped)
            .navigationTitle("Composition")
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Cancel") { dismiss(); onDone() }
                        .keyboardShortcut(.cancelAction)
                }
                ToolbarItem(placement: .confirmationAction) {
                    Button("Save") {
                        vpn.temporaryProcessRoutes[draft.id] = selectApps && !processRoutes.isEmpty ? processRoutes : nil
                        store.save(pending)
                        dismiss()
                        onDone()
                    }
                        .disabled(saveDisabledReason != nil)
                        // A dead Save must say why — hover AND VoiceOver.
                        .help(saveDisabledReason ?? "Save this composition")
                        .accessibilityValue(saveDisabledReason ?? "")
                        .keyboardShortcut(.defaultAction)
                }
            }
        }
        .resizablePanel(idealWidth: 510, idealHeight: 520)
        // A new composition starts with one required field — the cursor is in it.
        .onAppear { nameFocused = true }
        // The conflict footer sits below every member row; someone who just
        // flipped a Role picker must not have to hunt for the consequence.
        .onChange(of: draft.fullTunnelConflict) { _, conflicted in
            if conflicted && !selectApps {
                AccessibilityAnnouncer.sayNow("Two full-tunnel VPNs can't run at once — make one a split tunnel")
            }
        }
    }

    private var saveDisabledReason: String? {
        if draft.name.trimmingCharacters(in: .whitespaces).isEmpty { return "Give the composition a name first." }
        if let source = draft.eventSource {
            if draft.members.count != sourcePorts.count { return "Session event handlers require shared-interface packet-provider members." }
            if validatedEventSource != source { return eventProblem ?? "Checking session event handlers…" }
        }
        if selectApps {
            if draft.members.count != sourcePorts.count { return "Choose VPNs that can share one virtual interface for app routing." }
            if let problem = pending.validationProblem { return problem }
            return pending.applicationRouteProblem(temporary: processRoutes)
        }
        if draft.members.isEmpty { return "Add a VPN first." }
        if draft.members.count == 1, let id = draft.members.first?.profileID {
            guard let profile = vpn.compositionProfiles.first(where: { $0.id == id }) else { return "Choose an available VPN." }
            if let issue = vpn.virtualMemberProblem(for: profile) { return issue }
        }
        if let problem = draft.validationProblem { return problem }
        if draft.fullTunnelConflict { return "Choose one full tunnel." }
        if draft.members.contains(where: { $0.dependsOn != nil }) { return "Use parallel connections; chained VPNs are unavailable in this connection mode." }
        return nil
    }

    @ViewBuilder private func memberRow(_ member: Binding<VPNComposition.Member>) -> some View {
        let others = draft.members.filter { $0.profileID != member.wrappedValue.profileID }
        let memberName = name(member.wrappedValue.profileID)
        VStack(alignment: .leading, spacing: 6) {
            HStack {
                Text(memberName).font(.headline)
                    .accessibilityAddTraits(.isHeader)
                Spacer()
                // .onDelete renders NO affordance in a macOS Form — without this
                // button a member could never be removed by mouse or keyboard.
                Button {
                    draft.members.removeAll { $0.profileID == member.wrappedValue.profileID }
                } label: {
                    Image(systemName: "trash").frame(width: 22, height: 22).contentShape(Rectangle())
                }
                    .buttonStyle(.plain).foregroundStyle(.secondary)
                    .accessibilityLabel("Remove \(memberName) from the composition")
            }
            if !selectApps {
                HStack(spacing: 12) {
                    // Visually the row's headline names the VPN, so the picker titles
                    // stay hidden — but VoiceOver needs "whose role" spelled out.
                    Picker("Role", selection: member.role) {
                        ForEach(VPNComposition.Role.allCases, id: \.self) { Text($0.label).tag($0) }
                    }
                    .fixedSize()
                    .accessibilityLabel("Role for \(memberName)")
                    Picker("Runs over", selection: Binding(
                        get: { member.wrappedValue.dependsOn ?? "" },
                        set: { member.wrappedValue.dependsOn = $0.isEmpty ? nil : $0 })) {
                        Text("Runs in parallel").tag("")
                        ForEach(others, id: \.profileID) { Text(name($0.profileID)).tag($0.profileID) }
                    }
                    .accessibilityLabel("Runs over, for \(memberName)")
                }
                .labelsHidden()
                .controlSize(.small)
            }
        }
        .padding(.vertical, 2)
        .accessibilityElement(children: .contain)
        .accessibilityLabel(memberName)
    }
}
