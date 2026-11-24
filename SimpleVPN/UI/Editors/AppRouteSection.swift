// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only

import AppKit
import SwiftUI
import UniformTypeIdentifiers

struct AppRoutePort: Identifiable {
    let id: String
    let name: String
}

private enum AppSourceChoice: String, Identifiable {
    case application, process
    var id: Self { self }
}

struct AppRouteSection: View {
    let ports: [AppRoutePort]
    @Binding var signed: [VPNApplicationRoute]
    @Binding var processes: [VPNProcessRoute]
    @State private var picking: AppSourceChoice?

    var body: some View {
        Section {
            ForEach($signed) { $route in
                row($route, processLabel: nil) { id in signed.removeAll { $0.id == id } }
            }
            ForEach($processes, id: \.route.id) { $process in
                let pid = SourceProcessInstance.decoded(process.auditToken).map(audit_token_to_pid)
                row($process.route, processLabel: pid.map { "Process \(String($0)) only" } ?? "This process only") { id in
                    processes.removeAll { $0.route.id == id }
                }
            }
            Menu("Add Source") {
                Button("Signed App or Tool…") { picking = .application }
                Button("Running Process…") { picking = .process }
            }
            .disabled(ports.isEmpty)
            .help(ports.isEmpty ? "Add a compatible VPN first." : "Choose what will send traffic through a VPN.")
        } header: {
            Text("App Routing")
        } footer: {
            VStack(alignment: .leading, spacing: 4) {
                Text("Connect this composition to use these rules. Changes take effect on its next connection.")
                if !signed.isEmpty || !processes.isEmpty {
                    Text("Captured traffic with no matching source is blocked. This can include helpers and other instances of a selected process.")
                }
                if !processes.isEmpty {
                    Text("A process rule takes priority over its app rule. After the process exits, other instances can still be captured and blocked until disconnect. Choose the process again after reopening SimpleVPN.")
                }
            }
        }
        .sheet(item: $picking) { choice in
            AppSourcePicker(choice: choice, ports: ports) { route, token in
                if let token {
                    guard !processes.contains(where: { $0.auditToken == token }) else { return "This running process already has a rule." }
                    processes.append(.init(route: route, auditToken: token))
                } else {
                    guard !signed.contains(where: { route.conflicts(with: $0) }) else {
                        return "An existing rule can already select this process. Give the rules distinct executable names, paths, or values of the same proxy variable."
                    }
                    signed.append(route)
                }
                return nil
            }
        }
    }

    private func row(_ route: Binding<VPNApplicationRoute>, processLabel: String?,
                     remove: @escaping (String) -> Void) -> some View {
        let value = route.wrappedValue
        return VStack(alignment: .leading, spacing: 4) {
            HStack {
                Text(value.name).font(.headline)
                Spacer()
                Button(role: .destructive) { remove(value.id) } label: { Image(systemName: "trash") }
                    .buttonStyle(.borderless)
                    .accessibilityLabel("Remove rule for \(value.name)")
            }
            Text(processLabel.map { "\($0) · \(value.signingIdentifier)" } ?? value.signingIdentifier)
                .font(.caption).foregroundStyle(.secondary).textSelection(.enabled)
            Picker("Default VPN", selection: route.port) {
                if !ports.contains(where: { $0.id == value.port }) { Text("Choose a VPN").tag(value.port) }
                ForEach(ports) { Text($0.name).tag($0.id) }
            }
            .accessibilityLabel("Default VPN for \(value.name)")
            if processLabel == nil {
                ProcessCriteriaFields(criteria: route.processCriteria, suggestedPath: nil, sourceName: value.name)
            }
            AppDestinationOverrides(route: route, ports: ports)
        }
        .accessibilityElement(children: .contain)
        .accessibilityIdentifier("app-source-\(value.id)")
    }
}

/// Editing a blank field keeps the constraint enabled; only the explicit
/// switch returns a persistent rule to all processes with this signature.
private struct ProcessCriteriaFields: View {
    @Binding var criteria: SourceProcessCriteria?
    let suggestedPath: String?
    let sourceName: String

    var body: some View {
        DisclosureGroup {
            VStack(alignment: .leading, spacing: 8) {
                Toggle("Require all entered conditions", isOn: Binding {
                    criteria != nil
                } set: { enabled in
                    if enabled {
                        var new = SourceProcessCriteria()
                        new.executablePath = suggestedPath
                        criteria = new
                    } else { criteria = nil }
                })
                .accessibilityLabel("Require process conditions for \(sourceName)")
                if let current = criteria {
                    condition("Executable name", key: \.executableName, example: "curl")
                    condition("Executable path", key: \.executablePath, example: "/usr/bin/curl")
                    condition("Ancestor executable path", key: \.ancestorPath, example: "/bin/zsh")
                    Text("Matches the signed executable and any conditions you enter each time it runs. An ancestor must be a verified process belonging to the same user.")
                        .font(.caption).foregroundStyle(.secondary)
                    condition("HTTP proxy endpoint", key: \.httpProxyEndpoint, example: "proxy.example:8080")
                    if current.httpProxyEndpoint != nil {
                        Picker("Environment variable", selection: Binding {
                            criteria?.httpProxyVariable ?? "HTTP_PROXY"
                        } set: { variable in
                            criteria?.httpProxyVariable = variable == "HTTP_PROXY" ? nil : variable
                        }) {
                            Text("HTTP_PROXY").tag("HTTP_PROXY")
                            Text("http_proxy").tag("http_proxy")
                        }
                        .accessibilityIdentifier("app-route-proxy-variable")
                        Text("Variable names are case-sensitive. curl uses lowercase http_proxy for HTTP requests.")
                            .font(.caption).foregroundStyle(.secondary)
                    }
                    if current.isEmpty || current.problem != nil {
                        Text(current.problem ?? "Enter at least one condition.")
                            .font(.caption).foregroundStyle(.secondary)
                    }
                    Text("If required process evidence is unavailable, traffic is blocked even when a broader rule could match.")
                        .font(.caption).foregroundStyle(.secondary)
                }
            }
            .textFieldStyle(.roundedBorder)
        } label: {
            if let current = criteria {
                VStack(alignment: .leading, spacing: 2) {
                    Text("Process conditions required")
                    let conditions = [
                        current.executablePath ?? current.executableName,
                        current.ancestorPath.map { "Ancestor " + $0 },
                        current.httpProxyEndpoint.map { (current.httpProxyVariable ?? "HTTP_PROXY") + "=" + $0 }
                    ].compactMap { $0 }
                    if !conditions.isEmpty {
                        Text(conditions.joined(separator: " · "))
                            .font(.caption).foregroundStyle(.secondary)
                            .lineLimit(2).help(conditions.joined(separator: " · "))
                    }
                }
            } else { Text("Process conditions") }
        }
        .disclosureGroupStyle(AccessibleSettingsDisclosureStyle())
    }

    private func condition(_ title: String, key: WritableKeyPath<SourceProcessCriteria, String?>, example: String) -> some View {
        LabeledContent(title) {
            TextField(title, text: field(key), prompt: Text(example))
                .labelsHidden()
                .accessibilityLabel("\(title) for \(sourceName)")
                .accessibilityIdentifier("app-route-condition-" + title)
        }
    }

    private func field(_ key: WritableKeyPath<SourceProcessCriteria, String?>) -> Binding<String> {
        Binding {
            criteria?[keyPath: key] ?? ""
        } set: { text in
            guard var current = criteria else { return }
            current[keyPath: key] = text.isEmpty ? nil : text
            if key == \.httpProxyEndpoint && text.isEmpty { current.httpProxyVariable = nil }
            criteria = current
        }
    }
}

/// Keep the default VPN choice visible for each source. Overrides are draft
/// data until the composition is saved and reconnected.
private struct AppDestinationOverrides: View {
    @Binding var route: VPNApplicationRoute
    let ports: [AppRoutePort]
    @FocusState private var focusedDestination: Int?

    var body: some View {
        let values = route.destinations ?? []
        DisclosureGroup {
            VStack(alignment: .leading, spacing: 8) {
                Text("The most specific matching address or network chooses the VPN. Other destinations use this source’s default VPN.")
                    .font(.caption).foregroundStyle(.secondary)
                ForEach(Array(values.enumerated()), id: \.offset) { index, value in
                    let entry = binding(at: index, fallback: value)
                    VStack(alignment: .leading, spacing: 4) {
                        HStack {
                            TextField("Address or network", text: entry.prefix, prompt: Text("10.20.0.0/16"))
                                .textFieldStyle(.roundedBorder)
                                .focused($focusedDestination, equals: index)
                                .accessibilityIdentifier("app-route-destination-\(route.id)-\(index)")
                                .accessibilityLabel("Destination \(index + 1) for \(route.name)")
                            Button(role: .destructive) {
                                var remaining = route.destinations ?? []
                                guard remaining.indices.contains(index) else { return }
                                remaining.remove(at: index)
                                route.destinations = remaining.isEmpty ? nil : remaining
                            } label: { Image(systemName: "minus.circle") }
                            .buttonStyle(.borderless)
                            .accessibilityLabel("Remove destination \(index + 1) for \(route.name)")
                        }
                        Picker("Use VPN", selection: entry.port) {
                            if !ports.contains(where: { $0.id == value.port }) { Text("Choose a VPN").tag(value.port) }
                            ForEach(ports) { Text($0.name).tag($0.id) }
                        }
                        .accessibilityLabel("VPN for destination \(index + 1) of \(route.name)")
                    }
                }
                Button("Add Destination") {
                    var next = route.destinations ?? []
                    next.append(.init(prefix: "", port: route.port))
                    route.destinations = next
                }
                .disabled(values.count >= 64 || ports.isEmpty)
            }
        } label: {
            Text(values.isEmpty ? "Destination overrides" : "Destination overrides (\(values.count))")
        }
        .disclosureGroupStyle(AccessibleSettingsDisclosureStyle())
        .onChange(of: values.count) { oldCount, newCount in
            if newCount > oldCount { focusedDestination = newCount - 1 }
        }
    }

    private func binding(at index: Int, fallback: VPNApplicationRoute.Destination) -> Binding<VPNApplicationRoute.Destination> {
        Binding {
            guard let values = route.destinations, values.indices.contains(index) else { return fallback }
            return values[index]
        } set: { newValue in
            guard var values = route.destinations, values.indices.contains(index) else { return }
            values[index] = newValue
            route.destinations = values
        }
    }
}

private struct AppSourcePicker: View {
    let choice: AppSourceChoice
    let ports: [AppRoutePort]
    let add: (VPNApplicationRoute, Data?) -> String?
    @Environment(\.dismiss) private var dismiss

    private struct Selection {
        var name: String
        var identity: SourceSigningIdentity
        var executablePath: String?
        var process: SourceProcessInstance?
    }
    private struct RunningApp: Identifiable {
        let id: Int32
        let name: String
        let application: NSRunningApplication
    }

    @State private var pidText = ""
    @State private var port = ""
    @State private var runningApps: [RunningApp] = []
    @State private var showFiles = false
    @State private var selection: Selection?
    @State private var persistentCriteria: SourceProcessCriteria?
    @State private var error: String?
    @State private var inspection: Task<Void, Never>?

    var body: some View {
        NavigationStack {
            Form {
                if choice == .application {
                    Button("Choose App or Tool…") { showFiles = true }
                    Text("A signed app or tool rule applies on future launches. Add process conditions to limit it to a name, location, ancestor, or proxy setting.")
                        .font(.caption).foregroundStyle(.secondary)
                } else {
                    Menu("Choose a Running App") {
                        ForEach(runningApps) { app in
                            Button("\(app.name) (\(String(app.id)))") {
                                pidText = String(app.id)
                                inspect {
                                    guard !app.application.isTerminated else { throw ProcessEnded() }
                                    let process = try await SourceIdentityService.runningProcess(pid: app.id)
                                    guard !app.application.isTerminated else { throw ProcessEnded() }
                                    guard Int32(pidText) == app.id else { throw CancellationError() }
                                    return pickedProcess(process, name: app.name)
                                }
                            }
                        }
                    }
                    .disabled(runningApps.isEmpty)
                    HStack {
                        TextField("Process ID", text: $pidText)
                            .accessibilityLabel("Process ID")
                            .accessibilityIdentifier("app-route-process-id")
                            .onSubmit { inspectTypedPID() }
                        Button("Check Process") { inspectTypedPID() }
                            .disabled(Int32(pidText).map { $0 > 0 } != true)
                    }
                    Text("For a command-line tool, enter its process ID from Activity Monitor.")
                        .font(.caption).foregroundStyle(.secondary)
                }
                if inspection != nil { ProgressView("Checking signing identity…").controlSize(.small) }
                if let selection {
                    LabeledContent("Source", value: selection.name)
                    if let process = selection.process {
                        LabeledContent("Process ID", value: String(process.pid))
                    }
                    LabeledContent("Signing identifier", value: selection.identity.signingIdentifier)
                    if choice == .application {
                        ProcessCriteriaFields(criteria: $persistentCriteria, suggestedPath: selection.executablePath, sourceName: selection.name)
                    }
                    if let team = selection.identity.teamIdentifier { LabeledContent("Signing team", value: team) }
                    if let process = selection.process, !process.ancestors.isEmpty {
                        DisclosureGroup("Parent processes at selection") {
                            ForEach(process.ancestors, id: \.pid) { ancestor in
                                Text("\(ancestor.name) (\(String(ancestor.pid)))")
                            }
                            Text("The rule applies only to the selected process.").font(.caption)
                        }
                    }
                }
                if let error {
                    Label(error, systemImage: "exclamationmark.triangle")
                        .foregroundStyle(.secondary).fixedSize(horizontal: false, vertical: true)
                }
                Picker("Use VPN", selection: $port) {
                    ForEach(ports) { Text($0.name).tag($0.id) }
                }
            }
            .formStyle(.grouped)
            .navigationTitle(choice == .application ? "Add Signed App or Tool" : "Add Running Process")
            .toolbar {
                ToolbarItem(placement: .cancellationAction) {
                    Button("Cancel") { dismiss() }.keyboardShortcut(.cancelAction)
                }
                ToolbarItem(placement: .confirmationAction) {
                    Button("Add Rule") {
                        guard let selection else { return }
                        let route = VPNApplicationRoute(id: UUID().uuidString, name: selection.name,
                            signingIdentifier: selection.identity.signingIdentifier,
                            designatedRequirement: selection.identity.designatedRequirement, port: port,
                            processCriteria: choice == .application ? persistentCriteria : nil)
                        if let issue = add(route, selection.process?.auditToken) { error = issue }
                        else { dismiss() }
                    }
                    .keyboardShortcut(.defaultAction)
                    .disabled(selection == nil || !ports.contains(where: { $0.id == port })
                              || persistentCriteria?.isEmpty == true || persistentCriteria?.problem != nil)
                }
            }
        }
        .frame(minWidth: 420, minHeight: 300)
        .onAppear {
            if port.isEmpty { port = ports.first?.id ?? "" }
            if choice == .process {
                runningApps = NSWorkspace.shared.runningApplications.compactMap { app in
                    guard app.activationPolicy == .regular, !app.isTerminated, let name = app.localizedName else { return nil }
                    return RunningApp(id: app.processIdentifier, name: name, application: app)
                }.sorted { $0.name.localizedStandardCompare($1.name) == .orderedAscending }
            }
        }
        .onChange(of: pidText) {
            if let pid = selection?.process?.pid, Int32(pidText) != pid { selection = nil }
        }
        .fileImporter(isPresented: $showFiles, allowedContentTypes: [.applicationBundle, .unixExecutable]) { picked in
            do {
                let url = try picked.get()
                // A new file needs a fresh explicit choice of process conditions.
                persistentCriteria = nil
                inspect {
                    let scoped = url.startAccessingSecurityScopedResource()
                    defer { if scoped { url.stopAccessingSecurityScopedResource() } }
                    let signer = try await SourceIdentityService.signedApplication(at: url)
                    let executable = Bundle(url: url)?.executableURL ?? url
                    return Selection(name: url.deletingPathExtension().lastPathComponent, identity: signer,
                                     executablePath: executable.resolvingSymlinksInPath().standardizedFileURL.path)
                }
            } catch {
                if (error as NSError).code != NSUserCancelledError { self.error = error.localizedDescription }
            }
        }
        .onDisappear { inspection?.cancel() }
    }

    private func inspectTypedPID() {
        guard let pid = Int32(pidText), pid > 0 else { return }
        inspect {
            let process = try await SourceIdentityService.runningProcess(pid: pid)
            guard Int32(pidText) == pid else { throw CancellationError() }
            return pickedProcess(process, name: process.signingIdentity.signingIdentifier)
        }
    }

    private func pickedProcess(_ process: SourceProcessInstance, name: String) -> Selection {
        Selection(name: name, identity: process.signingIdentity, process: process)
    }

    private struct ProcessEnded: LocalizedError {
        var errorDescription: String? { "The chosen process has exited. Choose another running process." }
    }

    private func inspect(_ load: @escaping @MainActor () async throws -> Selection) {
        inspection?.cancel()
        selection = nil
        error = nil
        inspection = Task {
            defer { if !Task.isCancelled { inspection = nil } }
            do {
                let picked = try await load()
                if !Task.isCancelled { selection = picked }
            } catch is CancellationError {
            } catch {
                if !Task.isCancelled { self.error = error.localizedDescription }
            }
        }
    }
}
