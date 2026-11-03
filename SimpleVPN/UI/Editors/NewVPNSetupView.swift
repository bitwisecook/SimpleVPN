// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only

import SwiftUI
import UniformTypeIdentifiers

/// Kept by Manage VPNs so switching rows never discards an unfinished setup.
@Observable
final class VPNSetupDraft: Identifiable {
    let id = UUID()
    var name = ""
    var input = ""
    var serverAddress = ""
    var kind: VPNKind?
    var usesTeleport = false
    var analysis = VPNSetupAnalysis()
    var sshHostID = ""
    var chosenType = false
    var isWorking = false
    var isCreating = false
    var candidates: [DiscoveryCandidate] = []
    var selectedCandidate: DiscoveryCandidate?
    var message = ""
}

/// An unsaved VPN, in the manager's normal detail pane. No configuration or
/// keychain item is created until the person reviews the result and chooses Add.
struct NewVPNSetupView: View {
    private enum TypeChoice: Hashable {
        case vpn(VPNKind)
        case teleport
    }

    @Bindable var draft: VPNSetupDraft
    @Binding var incomingFile: URL?
    var onCreate: (VPNSetupSubmission) async throws -> Void
    var onCancel: () -> Void

    @State private var showFilePicker = false
    @State private var isTargeted = false
    @State private var work: Task<Void, Never>?
    @State private var workRevision = 0
    @State private var failure: UserFacingError?

    private var sshHosts: [SSHConfigHost] {
        draft.analysis.format == .ssh ? SSHConfigImport.parse(draft.input) : []
    }
    private var creationProblem: String? {
        if draft.isCreating { return "Adding your VPN" }
        if draft.isWorking { return "Wait for the check to finish, or cancel it" }
        if draft.input.utf8.count > VPNSetupInput.maximumBytes { return "Choose a configuration smaller than 1 MB" }
        if draft.kind == nil { return "Add a configuration or choose a VPN type first" }
        if !draft.usesTeleport && draft.analysis.format == nil && !draft.serverAddress.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty && server == nil {
            return "Check the server address before adding this VPN"
        }
        return nil
    }
    private var canCreate: Bool { creationProblem == nil }
    private var server: VPNSetupServer? {
        draft.usesTeleport ? nil : VPNSetupServer.parse(draft.serverAddress)
    }

    private var typeChoice: Binding<TypeChoice?> {
        Binding(get: {
            draft.usesTeleport ? .teleport : draft.kind.map(TypeChoice.vpn)
        }, set: { choice in
            cancelWork()
            draft.message = ""
            draft.selectedCandidate = nil
            draft.chosenType = true
            draft.usesTeleport = choice == .teleport
            switch choice {
            case .vpn(let kind): draft.kind = kind
            case .teleport: draft.kind = .wireGuard
            case nil: draft.kind = nil
            }
        })
    }

    var body: some View {
        Form {
            introduction
            configurationSection
            detailsSection
            if !draft.message.isEmpty {
                Section {
                    Text(draft.message).foregroundStyle(.secondary)
                        .fixedSize(horizontal: false, vertical: true)
                        .accessibilityLabel(draft.message)
                }
            }
        }
        .disabled(draft.isCreating)
        .formStyle(.grouped)
        .navigationTitle("New VPN")
        .safeAreaInset(edge: .bottom, spacing: 0) { actions }
        .fileImporter(isPresented: $showFilePicker,
                      allowedContentTypes: [.data, .plainText, .xml], allowsMultipleSelection: false) { result in
            switch result {
            case .success(let urls): if let url = urls.first { readFile(url) }
            case .failure(let error): failure = UserFacingError.classify(error)
            }
        }
        .onChange(of: incomingFile, initial: true) {
            guard let url = incomingFile else { return }
            incomingFile = nil
            readFile(url)
        }
        .onChange(of: draft.input) { recogniseInput() }
        .onChange(of: draft.serverAddress) {
            if !draft.candidates.isEmpty || draft.selectedCandidate != nil || draft.message == "Checking the server…" { draft.message = "" }
            cancelWork()
            draft.candidates = []; draft.selectedCandidate = nil
        }
        .onDisappear { if !draft.isCreating { cancelWork() } }
        .sheet(item: $failure) { UserFacingErrorSheet(error: $0) }
    }

    private var introduction: some View {
        Section {
            VStack(alignment: .leading, spacing: 6) {
                Text("Let’s set up your VPN").font(.title2.bold())
                Text("Drop a configuration file, paste your setup instructions, or choose UniFi Teleport if you received an invitation.")
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }
            .padding(.vertical, 6)
        }
    }

    private var configurationSection: some View {
        Section("Configuration or Instructions") {
            VStack(spacing: 10) {
                Label("Drop a configuration file here", systemImage: "doc.badge.plus")
                    .font(.headline)
                Button("Choose Configuration…") { showFilePicker = true }
                    .accessibilityHint("Opens a file picker. You can also drop a file or paste its contents below.")
            }
            .padding(20)
            .frame(maxWidth: .infinity)
            .background(isTargeted ? Color.accentColor.opacity(0.1) : Color(nsColor: .controlBackgroundColor),
                        in: RoundedRectangle(cornerRadius: 12))
            .overlay { RoundedRectangle(cornerRadius: 12).strokeBorder(isTargeted ? AnyShapeStyle(.tint) : AnyShapeStyle(.separator), style: StrokeStyle(lineWidth: 1, dash: [6, 4])) }
            .dropDestination(for: URL.self) { urls, _ in
                guard let url = urls.first(where: \.isFileURL) else { return false }
                readFile(url)
                return true
            } isTargeted: { isTargeted = $0 }
            TextEditor(text: $draft.input)
                .frame(minHeight: 110, idealHeight: 140)
                .accessibilityLabel("Configuration or setup instructions")
                .accessibilityHint("Paste the configuration or instructions you received. They stay on this Mac.")
                .privacySensitive()
            HStack {
                PasteButton(payloadType: String.self) { values in
                    if let value = values.first { draft.input = value }
                }
                Spacer()
                if draft.isWorking {
                    ProgressView().controlSize(.small).accessibilityLabel("Identifying your VPN")
                    Button("Cancel Check") { cancelWork() }
                } else if !draft.usesTeleport && draft.analysis.format == nil && !draft.input.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
                    Button("Help Identify This", systemImage: "sparkles") { interpretInstructions() }
                        .disabled(VPNSetupIntelligence.unavailableReason != nil || draft.input.utf8.count > VPNSetupInput.maximumBytes)
                        .help(VPNSetupIntelligence.unavailableReason ?? "Uses Apple Intelligence on this Mac to read your setup instructions.")
                        .accessibilityValue(VPNSetupIntelligence.unavailableReason ?? "Uses the on-device model")
                }
            }
            if !draft.analysis.evidence.isEmpty {
                Label(draft.analysis.evidence, systemImage: draft.analysis.format == nil ? "lightbulb" : "doc.text.magnifyingglass")
                    .foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }
            if !draft.usesTeleport && draft.analysis.format == nil && !draft.input.isEmpty {
                Text(VPNSetupIntelligence.unavailableReason ?? "Apple Intelligence can help read unusual instructions. Your text stays on this Mac.")
                    .font(.callout).foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }
        }
    }

    private var detailsSection: some View {
        Section {
            TextField("Name", text: $draft.name, prompt: Text(draft.usesTeleport ? "UniFi Teleport" : "My VPN"))
                .accessibilityHint("An optional name to help you recognise this VPN.")
            if let format = draft.analysis.format {
                LabeledContent("VPN Type", value: draft.kind?.displayName ?? "Recognised configuration")
                if format == .ssh && sshHosts.count > 1 {
                    Picker("Server", selection: $draft.sshHostID) {
                        ForEach(sshHosts) { host in Text(host.alias).tag(host.id) }
                    }
                }
                Text("Your configuration will be imported when you choose Add VPN. You can enter your sign-in details next.")
                    .foregroundStyle(.secondary).font(.callout)
            } else {
                Picker("VPN Type", selection: typeChoice) {
                    Text("Choose a type…").tag(Optional<TypeChoice>.none)
                    Text("UniFi Teleport").tag(Optional(TypeChoice.teleport))
                    ForEach(VPNKind.allCases, id: \.self) { type in
                        Text(type.displayName).tag(Optional(TypeChoice.vpn(type)))
                    }
                }
                if draft.usesTeleport {
                    Text("Add this VPN, then use a fresh invitation from your UniFi console to pair it in Settings.")
                        .font(.callout).foregroundStyle(.secondary)
                        .fixedSize(horizontal: false, vertical: true)
                } else {
                    HStack {
                        TextField("Server Address", text: $draft.serverAddress, prompt: Text("vpn.example.com"))
                            .autocorrectionDisabled()
                        Button("Check Server") { checkServer() }
                            .disabled(server == nil || draft.isWorking || draft.isCreating)
                            .help(server == nil ? "Enter the server address you were given first." : "Contacts this server without signing in to help identify its VPN type.")
                            .accessibilityValue(server == nil ? "Enter a server address first" : "Contacts this server without signing in")
                    }
                    Text("A server check contacts the address above to look for the kind of VPN it uses. Some servers keep this private, so a check may find nothing.")
                        .font(.callout).foregroundStyle(.secondary)
                        .fixedSize(horizontal: false, vertical: true)
                    if !draft.candidates.isEmpty { candidateChoices }
                    Text("If you don’t know the type, paste your instructions above or check the server. You can also ask the person who gave you the VPN.")
                        .font(.callout).foregroundStyle(.secondary)
                        .fixedSize(horizontal: false, vertical: true)
                }
            }
        } header: { Text("Your VPN") }
    }

    private var candidateChoices: some View {
        VStack(alignment: .leading, spacing: 8) {
            Text("What the server suggests").font(.headline)
            ForEach(draft.candidates) { candidate in
                Button {
                    draft.kind = candidate.kind
                    draft.usesTeleport = false
                    draft.selectedCandidate = candidate
                    draft.chosenType = true
                } label: {
                    HStack {
                        Image(systemName: draft.selectedCandidate?.id == candidate.id ? "checkmark.circle.fill" : "circle")
                        VStack(alignment: .leading, spacing: 2) {
                            Text(candidate.kind?.displayName ?? candidate.title)
                            Text(candidate.detail).font(.callout).foregroundStyle(.secondary)
                        }
                    }
                }
                .buttonStyle(.borderless)
                .accessibilityLabel("Use \(candidate.kind?.displayName ?? candidate.title)")
                .accessibilityValue(draft.selectedCandidate?.id == candidate.id ? "Selected" : "Suggestion")
            }
        }
    }

    private var actions: some View {
        HStack {
            Button("Cancel", action: onCancel).keyboardShortcut(.cancelAction).disabled(draft.isCreating)
            Spacer()
            if draft.isCreating { ProgressView().controlSize(.small).accessibilityLabel("Adding VPN") }
            Button("Add VPN") { create() }
                .accessibilityIdentifier("confirm-add-vpn")
                .buttonStyle(.glassProminent)
                .keyboardShortcut(.defaultAction)
                .disabled(!canCreate)
                .help(creationProblem ?? "Add this VPN and open its settings.")
                .accessibilityValue(creationProblem ?? "Ready to add")
        }
        .padding(12)
        .background(.bar)
    }

    private func recogniseInput() {
        cancelWork()
        draft.candidates = []; draft.selectedCandidate = nil; draft.message = ""
        guard draft.input.utf8.count <= VPNSetupInput.maximumBytes else {
            draft.analysis = .init()
            if !draft.usesTeleport { draft.kind = nil }
            draft.message = "This text is too large. Choose a configuration smaller than 1 MB."
            return
        }
        draft.analysis = VPNSetupInput.analyse(draft.input)
        if draft.analysis.format != nil || !draft.chosenType {
            draft.kind = draft.analysis.kind
            draft.usesTeleport = false
        }
        if let server = draft.analysis.server { draft.serverAddress = server.address }
        draft.sshHostID = sshHosts.first?.id ?? ""
    }

    private func readFile(_ url: URL) {
        let scoped = url.startAccessingSecurityScopedResource()
        defer { if scoped { url.stopAccessingSecurityScopedResource() } }
        do {
            let size = try url.resourceValues(forKeys: [.fileSizeKey]).fileSize ?? 0
            guard size <= VPNSetupInput.maximumBytes else {
                draft.message = "This file is too large. Choose a configuration smaller than 1 MB."
                return
            }
            let text = try String(contentsOf: url, encoding: .utf8)
            if draft.name.isEmpty { draft.name = url.deletingPathExtension().lastPathComponent }
            draft.chosenType = false
            draft.input = text
            recogniseInput()
        } catch { failure = UserFacingError.classify(error) }
    }

    private func cancelWork() {
        workRevision += 1
        work?.cancel(); work = nil; draft.isWorking = false
    }

    private func interpretInstructions() {
        guard !draft.isWorking, VPNSetupIntelligence.unavailableReason == nil else { return }
        let source = draft.input
        workRevision += 1
        let revision = workRevision
        draft.isWorking = true; draft.message = ""
        work = Task {
            defer { if workRevision == revision { draft.isWorking = false } }
            do {
                let result = try await VPNSetupIntelligence.interpret(source)
                guard !Task.isCancelled, draft.input == source, workRevision == revision else { return }
                if !draft.chosenType, let type = result.kind { draft.kind = type }
                if draft.serverAddress.isEmpty, let server = result.server { draft.serverAddress = server.address }
                draft.message = result.evidence.isEmpty
                    ? "There isn’t enough information to identify a type. You can check the server or choose a type yourself."
                    : result.evidence
            } catch is CancellationError {
                // Cancellation leaves the person's text and choices untouched.
            } catch {
                guard !Task.isCancelled, draft.input == source, workRevision == revision else { return }
                draft.message = "Apple Intelligence couldn’t identify this. You can check the server or choose a type yourself."
            }
        }
    }

    private func checkServer() {
        guard !draft.isWorking, let server else { return }
        let address = draft.serverAddress
        workRevision += 1
        let revision = workRevision
        draft.isWorking = true; draft.candidates = []; draft.selectedCandidate = nil; draft.message = "Checking the server…"
        work = Task {
            let results = await EndpointDiscovery.discover(host: server.host, hintPort: server.port)
            guard !Task.isCancelled, workRevision == revision else { return }
            draft.isWorking = false
            guard draft.serverAddress == address else { draft.message = "The address changed. Check the new server when you’re ready."; return }
            draft.candidates = results.filter { $0.kind != nil }
            draft.message = draft.candidates.isEmpty
                ? "The server didn’t identify its VPN type. You can still use a configuration file or choose a type yourself."
                : "Choose a suggestion above, or use the type you were given. A server check can’t confirm your account or sign-in details."
            AccessibilityAnnouncer.sayNow(draft.message)
        }
    }

    private func create() {
        guard canCreate, let type = draft.kind else { return }
        let trimmedName = draft.name.trimmingCharacters(in: .whitespacesAndNewlines)
        let defaultName = draft.usesTeleport ? "UniFi Teleport" : "My VPN"
        let submission = VPNSetupSubmission(name: trimmedName.isEmpty ? defaultName : trimmedName,
            kind: type, text: draft.input, format: draft.analysis.format, server: server,
            sshHost: sshHosts.first { $0.id == draft.sshHostID }, discovery: draft.selectedCandidate,
            usesTeleport: draft.usesTeleport)
        draft.isCreating = true
        work = Task {
            defer { draft.isCreating = false }
            do { try await onCreate(submission) }
            catch { failure = UserFacingError.classify(error) }
        }
    }
}
