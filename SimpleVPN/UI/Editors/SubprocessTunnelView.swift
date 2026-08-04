// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
//  SubprocessTunnelView.swift
//  Editor + live control for the command-line VPN kinds (SSH SOCKS / port
//  forwards, FortiGate & F5 BIG-IP APM via OpenConnect/openfortivpn). Shows
//  which CLI backs the kind and whether it's installed, edits the fields that
//  kind needs, and runs it with a live status + rolling log. Password is stored
//  per-tunnel in the login keychain (Remember) or typed at connect.
//

import SwiftUI

struct SubprocessTunnelView: View {
    let vpn: VPNController
    @Bindable var store: SubprocessTunnelStore
    @Bindable var manager: SubprocessTunnelManager
    @State var draft: SubprocessTunnelConfig
    @State private var customRouting = CustomRoutingProfile()
    @State private var crProxyAuthUsername = ""
    @State private var crProxyAuthPassword = ""

    @State private var password = ""
    @State private var proxyPassword = ""
    @State private var jumpPassword = ""
    @State private var tokenSecret = ""
    @State private var keyPassphrase = ""
    @State private var remember = true
    @State private var loaded = false
    // Shown when a saved "sso" was migrated back to password (unsupported kind).
    @State private var authNote: String?
    // SSH import (drop well) state.
    @Environment(\.accessibilityReduceMotion) private var reduceMotion
    @State private var importTargeted = false
    @State private var importFeedback: (text: String, ok: Bool)?
    @State private var feedbackClearTask: Task<Void, Never>?
    @State private var hostPicker: HostPickerPayload?
    // Debounce for live forward edits while connected.
    @State private var applyForwardsTask: Task<Void, Never>?
    // Advanced disclosures: bound state so the whole header row is a hit
    // target and a future search-reveal can open the container.
    @State private var sshAdvancedExpanded = false
    @State private var sslAdvancedExpanded = false

    private var live: SubprocessTunnelManager.Live? { manager.live[draft.id] }
    private var active: Bool { manager.isActive(draft.id) }
    private var appBrowserSummary: String { BrowserCatalog.label(BrowserDefaults.appDefault) }

    var body: some View {
        Form {
            // Canonical group order (AGENTS.md "Config surfaces"):
            // Connection → Sign-In → Traffic → Security → Advanced.
            Section("Connection") {
                TextField("Name", text: $draft.name)
                Picker("Kind", selection: $draft.kind) {
                    ForEach([VPNKind.ssh, .fortinet, .f5apm, .ciscoAnyConnect,
                             .globalProtect, .juniper, .pulse, .arrayNetworks], id: \.self) {
                        Label($0.displayName, systemImage: $0.systemImage).tag($0)
                    }
                }
                // Switching to a kind without a browser sign-in flow can strand
                // an "sso" authMode the picker no longer offers — fix it up.
                .onChange(of: draft.kind) {
                    if draft.authMode == "sso", !draft.kind.supportsExternalBrowserSSO {
                        draft.authMode = "password"
                        authNote = "Single sign-on isn't available for \(draft.kind.displayName) — switched to password sign-in."
                    }
                }
                cliStatusRow
                if draft.kind == .ssh {
                    row("ssh.server", text: $draft.server, prompt: "ssh.example.com")
                    intRow("ssh.port", value: $draft.port, prompt: "22")
                    intRow("ssh.connect-timeout", value: $draft.connectTimeout, prompt: "system default")
                    jumpHostRows
                } else if draft.kind.isSSLVPN {
                    TextField("Server address", text: $draft.server, prompt: Text("vpn.example.com")).autocorrectionDisabled()
                    portField
                    connectionProxyRows
                    Text(gatewayFooter).font(.callout).foregroundStyle(.secondary)
                }
            }

            if draft.kind == .ssh {
                sshImportSection
                sshSignInSection
                sshTrafficSection
                sshSecuritySection
                sshAdvanced
            } else if draft.kind.isSSLVPN {
                sslSignInSection
                sslTrafficSection
                sslSecuritySection
                sslAdvanced
            }

            controlSection
            if let log = live?.log, !log.isEmpty { logSection(log) }

            CustomRoutingTabView(vpn: vpn, profileID: draft.id, profile: $customRouting,
                                proxyAuthUsername: $crProxyAuthUsername,
                                proxyAuthPassword: $crProxyAuthPassword)
        }
        .formStyle(.grouped)
        .disabled(ManagedPolicy.lockConfiguration)
        .navigationTitle(draft.name)
        .task { loadOnce() }
        .toolbar {
            ToolbarItem(placement: .confirmationAction) {
                Button("Save") { save() }
                    .disabled(draft.name.trimmingCharacters(in: .whitespaces).isEmpty || draft.server.isEmpty)
                    // A dead button must say why (the rule ConnectionView follows).
                    .help(draft.name.trimmingCharacters(in: .whitespaces).isEmpty ? "Give this tunnel a name first."
                          : draft.server.isEmpty ? "Enter the server address first."
                          : "Save changes to this tunnel")
                    .accessibilityValue(draft.name.trimmingCharacters(in: .whitespaces).isEmpty
                          ? "unavailable — give this tunnel a name first"
                          : draft.server.isEmpty ? "unavailable — enter the server address first" : "")
            }
        }
    }

    // MARK: Sections

    @ViewBuilder private var cliStatusRow: some View {
        let cli = requiredCLI
        HStack(spacing: 6) {
            Image(systemName: cli.isAvailable ? "checkmark.circle.fill" : "exclamationmark.triangle.fill")
                .foregroundStyle(cli.isAvailable ? .green : .orange)
                .accessibilityHidden(true)
            Text(cli.isAvailable ? "\(cli.rawValue) found" : cli.installHint)
                .font(.callout).foregroundStyle(.secondary)
            if draft.kind.isSSLVPN, !TunnelCLI.ocproxy.isAvailable {
                Spacer()
                // Symbol + text — orange alone said "warning" to nobody colourblind.
                Label("ocproxy not found — needs root without it", systemImage: "exclamationmark.triangle.fill")
                    .font(.caption).foregroundStyle(.orange)
            }
        }
        .accessibilityElement(children: .combine)
    }

    private var requiredCLI: TunnelCLI {
        switch draft.kind {
        case .ssh: .ssh
        case .fortinet: TunnelCLI.openconnect.isAvailable ? .openconnect : .openfortivpn
        default: .openconnect  // the other OpenConnect SSL-VPN kinds
        }
    }

    /// SSH carries traffic three ways; the mode picks which fields matter.
    @ViewBuilder private var sshTrafficSection: some View {
        Section("Traffic") {
            EngineSettingRow(spec: spec("ssh.mode"), changed: draft.sshMode != .socks) {
                Picker(selection: $draft.sshMode) {
                    ForEach(SSHMode.allCases, id: \.self) { Text($0.label).tag($0) }
                } label: { EngineSettingLabel(spec: spec("ssh.mode"), changed: draft.sshMode != .socks) }
                .pickerStyle(.segmented)
                // Segmented pickers draw no label — give VoiceOver the name back.
                .accessibilityLabel(spec("ssh.mode").name)
            }
            switch draft.sshMode {
            case .socks: socksSectionBody
            case .portForward: forwardsSectionBody
            case .netTunnel:
                Label("Point-to-point tunnel over SSH (-w). Creating the utun device requires root, so this mode is not supported in this build (it also needs “PermitTunnel” on the server).",
                      systemImage: "exclamationmark.triangle")
                    .font(.callout).foregroundStyle(.secondary)
            }
        }
    }

    /// The picker's normalized value ("" = automatic).
    private var sshMethod: String { SubprocessTunnelManager.sshAuthMethod(draft) }

    @ViewBuilder private var sshSignInSection: some View {
        Section("Sign-In") {
            EngineSettingRow(spec: spec("ssh.auth-method"), changed: !sshMethod.isEmpty) {
                Picker(selection: Binding(
                    get: { sshMethod },
                    set: { draft.sshAuthMethod = $0.isEmpty ? nil : $0 })) {
                    Text("Automatic").tag("")
                    Text("Password").tag("password")
                    Text("Key file").tag("key")
                    Text("Certificate").tag("certificate")
                    Text("SSH agent").tag("agent")
                    Text("Kerberos").tag("kerberos")
                } label: { EngineSettingLabel(spec: spec("ssh.auth-method"), changed: !sshMethod.isEmpty) }
            }
            row("ssh.username", text: $draft.username, prompt: "alex")
            // Each credential row is live only under the methods that use it —
            // a disabled row says which choice re-enables it (.help + AX value).
            row("ssh.identity-file", text: $draft.identityFile, prompt: "~/.ssh/id_ed25519",
                disabled: ["", "key", "certificate"].contains(sshMethod) ? nil
                    : "Not used when signing in with \(sshMethodLabel) — choose Automatic, “Key file” or “Certificate”.")
            row("ssh.certificate-file", text: optionalText(\.sshCertificateFile), prompt: "~/.ssh/id_ed25519-cert.pub",
                disabled: sshMethod == "certificate" ? nil
                    : "Choose “Certificate” as the sign-in method to use an SSH certificate.")
            sshPasswordRow
        }
    }

    private var sshMethodLabel: String {
        switch sshMethod {
        case "password": "a password"
        case "key": "a key file"
        case "certificate": "a certificate"
        case "agent": "the SSH agent"
        case "kerberos": "Kerberos"
        default: "this method"
        }
    }

    /// Password + Remember for SSH, presented as a descriptor row (manual link,
    /// summary) — the keychain path is unchanged. Disabled under methods that
    /// never ask for one; caveated where the stored password answers prompts.
    @ViewBuilder private var sshPasswordRow: some View {
        let passwordUnused: String? = ["agent", "kerberos"].contains(sshMethod)
            ? "Not used when signing in with \(sshMethodLabel)." : nil
        EngineSettingRow(spec: spec("ssh.password"), changed: !password.isEmpty,
                         disabledReason: passwordUnused) {
            VStack(alignment: .leading, spacing: 6) {
                LabeledContent {
                    SecureField("optional", text: $password)
                        .textContentType(.password)
                        .multilineTextAlignment(.trailing)
                } label: { EngineSettingLabel(spec: spec("ssh.password"), changed: !password.isEmpty) }
                Toggle("Remember password", isOn: $remember)
            }
        }
        if sshMethod == "password" {
            SettingCaveat("If the server asks a follow-up question — a verification code, an MFA prompt — the stored password is what gets sent. Servers that need a code per sign-in aren't suited to a remembered password.")
        }
    }

    @ViewBuilder private var sshSecuritySection: some View {
        Section("Security") {
            EngineSettingRow(spec: spec("ssh.strict-host-key"), changed: draft.strictHostKey != "accept-new") {
                Picker(selection: $draft.strictHostKey) {
                    Text("Trust on first use").tag("accept-new")
                    Text("Only known hosts").tag("yes")
                    Text("Never check (unsafe)").tag("no")
                } label: { EngineSettingLabel(spec: spec("ssh.strict-host-key"), changed: draft.strictHostKey != "accept-new") }
            }
            pinnedHostKeyRow
            row("ssh.key-exchange", text: optionalText(\.sshKexAlgorithms),
                prompt: "mlkem768x25519-sha256,…")
        }
    }

    /// Pinned host key: mono field with format validation (inline error +
    /// accessibilityValue, per Docs/Accessibility.md) and the honesty caveat
    /// when the pin can't be enforced alongside another choice.
    @ViewBuilder private var pinnedHostKeyRow: some View {
        let s = spec("ssh.pinned-host-key")
        let pinned = SubprocessTunnelManager.sshPinnedKey(draft) != nil
        EngineSettingRow(spec: s, changed: pinned) {
            VStack(alignment: .leading, spacing: 4) {
                LabeledContent {
                    TextField("SHA256:… or 64 hex characters", text: optionalText(\.sshPinnedHostKey))
                        .font(.callout.monospaced())
                        .autocorrectionDisabled()
                        .multilineTextAlignment(.trailing)
                        .accessibilityValue(pinnedKeyError.map { "Problem: \($0)" } ?? "")
                } label: { EngineSettingLabel(spec: s, changed: pinned) }
                if let error = pinnedKeyError {
                    Text(error)
                        .font(.callout).foregroundStyle(.red)
                        .accessibilityLabel("Error: \(error)")
                } else if let conflict = SubprocessTunnelManager.sshPinBlockReason(draft) {
                    Label(conflict, systemImage: "exclamationmark.triangle.fill")
                        .font(.callout).foregroundStyle(.orange)
                        .accessibilityLabel("Warning: \(conflict)")
                }
            }
        }
    }

    /// Why the typed pin isn't a usable SHA-256 fingerprint, or nil when it is
    /// (or when the field is empty).
    private var pinnedKeyError: String? {
        guard let pin = SubprocessTunnelManager.sshPinnedKey(draft) else { return nil }
        let hexCount = pin.filter(\.isHexDigit).count
        guard pin.count != 64 || hexCount != 64 else { return nil }
        return "A pinned key is the SHA-256 fingerprint: 64 hex characters (an optional “SHA256:” prefix is fine)."
    }

    /// The jump-host rows live inside Connection — a jump host is part of how
    /// the tunnel reaches its server, like the SSL kinds' connection proxy.
    /// The toggle reveals the fields; the host field carries the descriptor
    /// (summary + manual link) for the whole concept.
    @ViewBuilder private var jumpHostRows: some View {
        Toggle("Connect via a jump host (bastion)", isOn: $draft.useJumpHost)
        if draft.useJumpHost {
            row("ssh.proxy-jump", text: $draft.jumpHost, prompt: "bastion.example.com")
            intRow("ssh.jump-port", value: $draft.jumpPort, prompt: "22")
            row("ssh.jump-username", text: $draft.jumpUsername, prompt: "alex")
            row("ssh.jump-identity-file", text: $draft.jumpIdentityFile, prompt: "~/.ssh/id_bastion")
            SecureField("Jump password (optional)", text: $jumpPassword)
            Text("The jump host signs in on its own — its key and password above are independent of the server's, and the password stays in your login keychain.")
                .font(.callout).foregroundStyle(.secondary)
        }
    }

    // MARK: SSH import (drop your config / keys in)

    /// A dropped ssh_config, private key, or certificate configures the tunnel
    /// instead of retyping what ssh already knows. Config drops discover the
    /// endpoint's tunnels automatically: every LocalForward/RemoteForward/
    /// DynamicForward defined for the matching Host lands as this tunnel's
    /// forwards/SOCKS, plus jump chain, key, port and user.
    @ViewBuilder private var sshImportSection: some View {
        Section {
            VStack(spacing: 8) {
                Image(systemName: importTargeted ? "arrow.down.doc.fill" : "arrow.down.doc")
                    .font(.system(size: 26))
                    .foregroundStyle(importTargeted ? AnyShapeStyle(.tint) : AnyShapeStyle(.secondary))
                    .contentTransition(.symbolEffect(.replace))
                    .symbolEffect(.wiggle, options: .repeat(.periodic(delay: 6)),
                                  isActive: !reduceMotion && !importTargeted)
                Text("Drag your SSH config, a key, or a certificate here")
                    .font(.callout).foregroundStyle(.secondary)
                Text("Forwards, jump hosts and keys defined for this server are picked up automatically.")
                    .font(.caption).foregroundStyle(.tertiary)
                    .multilineTextAlignment(.center)
            }
            .frame(maxWidth: .infinity)
            .padding(.vertical, 14)
            .background {
                RoundedRectangle(cornerRadius: 10, style: .continuous)
                    .strokeBorder(style: StrokeStyle(lineWidth: 1.5, dash: [6, 4]))
                    .foregroundStyle(importTargeted ? AnyShapeStyle(.tint) : AnyShapeStyle(.quaternary))
            }
            .animation(.snappy(duration: 0.2), value: importTargeted)
            .dropDestination(for: URL.self) { urls, _ in
                for url in urls { handleDrop(url) }
                return true
            } isTargeted: { importTargeted = $0 }
            .accessibilityLabel("Drop zone for SSH configs, keys and certificates")

            if SSHConfigImport.userConfigExists, !draft.server.trimmingCharacters(in: .whitespaces).isEmpty {
                Button {
                    findInUserConfig()
                } label: {
                    Label("Find \(draft.server) in my SSH config", systemImage: "text.page.badge.magnifyingglass")
                }
                .help("Reads ~/.ssh/config (only when you click) and fills this tunnel from the matching Host entry.")
            }

            if let feedback = importFeedback {
                Label(feedback.text, systemImage: feedback.ok ? "checkmark.circle.fill" : "info.circle")
                    .font(.callout)
                    .foregroundStyle(feedback.ok ? AnyShapeStyle(.green) : AnyShapeStyle(.secondary))
                    .transition(.opacity)
            }
        }
        .sheet(item: $hostPicker) { payload in
            hostPickerSheet(payload)
        }
    }

    private struct HostPickerPayload: Identifiable {
        let id = UUID()
        let hosts: [SSHConfigHost]
    }

    /// Several Hosts in the dropped config and none matching the endpoint:
    /// let the user pick which one this tunnel is.
    private func hostPickerSheet(_ payload: HostPickerPayload) -> some View {
        VStack(alignment: .leading, spacing: 12) {
            Text("Which host is this tunnel for?").font(.headline)
            List(payload.hosts) { host in
                HStack {
                    VStack(alignment: .leading, spacing: 2) {
                        Text(host.alias).font(.body.weight(.medium))
                        Text(host.summary).font(.caption).foregroundStyle(.secondary)
                    }
                    Spacer()
                    Button("Use") {
                        applyHost(host)
                        hostPicker = nil
                    }
                    .buttonStyle(.glassProminent).controlSize(.small)
                    // Every row's button says "Use" — name the host it uses.
                    .accessibilityLabel("Use \(host.alias)")
                }
                .padding(.vertical, 2)
            }
            .frame(minHeight: 220)
            HStack {
                Spacer()
                Button("Cancel") { hostPicker = nil }.buttonStyle(.glass)
                    .keyboardShortcut(.cancelAction)
            }
        }
        .padding(16)
        .frame(width: 440, height: 340)
    }

    private func handleDrop(_ url: URL) {
        switch SSHConfigImport.classify(url: url) {
        case .config(let hosts):
            // Prefer the Host that matches the endpoint being configured.
            let matching = SSHConfigImport.hosts(hosts, matching: draft.server)
            if let host = matching.first ?? (hosts.count == 1 ? hosts[0] : nil) {
                applyHost(host)
            } else if hosts.isEmpty {
                showFeedback("No Host entries found in that config.", ok: false)
            } else {
                hostPicker = HostPickerPayload(hosts: hosts)
            }
        case .privateKey(let path):
            // Fill the empty slot: target key first, then the jump host's.
            if draft.identityFile.trimmingCharacters(in: .whitespaces).isEmpty || !draft.useJumpHost {
                draft.identityFile = path
                showFeedback("Using \((path as NSString).lastPathComponent) as the target's key.", ok: true)
            } else if draft.jumpIdentityFile.isEmpty {
                draft.jumpIdentityFile = path
                showFeedback("Using \((path as NSString).lastPathComponent) as the jump host's key.", ok: true)
            } else {
                draft.identityFile = path
                showFeedback("Replaced the target's key with \((path as NSString).lastPathComponent).", ok: true)
            }
        case .certificate(let path):
            // The dedicated field (not an extra option) so the in-process
            // engine presents it too — extra options force /usr/bin/ssh.
            // Dropping a certificate implies certificate sign-in.
            draft.sshCertificateFile = path
            draft.sshAuthMethod = "certificate"
            showFeedback("Using \((path as NSString).lastPathComponent) as your SSH certificate — sign-in method set to Certificate.", ok: true)
        case .publicKey:
            showFeedback("That's the public half of a key — drop the private key (the file without .pub).", ok: false)
        case .unrecognized:
            showFeedback("That didn't look like an SSH config, key or certificate.", ok: false)
        }
    }

    private func findInUserConfig() {
        guard let text = try? String(contentsOf: SSHConfigImport.userConfigURL, encoding: .utf8) else {
            showFeedback("Couldn't read ~/.ssh/config.", ok: false)
            return
        }
        let hosts = SSHConfigImport.parse(text)
        let matching = SSHConfigImport.hosts(hosts, matching: draft.server)
        if let host = matching.first {
            applyHost(host)
        } else if hosts.isEmpty {
            showFeedback("No Host entries found in ~/.ssh/config.", ok: false)
        } else {
            showFeedback("Nothing in ~/.ssh/config matches \(draft.server) — drop the file here to pick a host by hand.", ok: false)
        }
    }

    private func applyHost(_ host: SSHConfigHost) {
        let applied = SSHConfigImport.apply(host, to: &draft)
        showFeedback("Filled from Host \u{201C}\(host.alias)\u{201D}: \(applied.summary).", ok: true)
    }

    private func showFeedback(_ text: String, ok: Bool) {
        withAnimation(.snappy(duration: 0.25)) { importFeedback = (text, ok) }
        feedbackClearTask?.cancel()
        feedbackClearTask = Task {
            try? await Task.sleep(for: .seconds(ok ? 12 : 8))
            guard !Task.isCancelled else { return }
            withAnimation(.easeOut(duration: 0.4)) { importFeedback = nil }
        }
    }

    /// The local SOCKS listener binds without root, so the floor is 1024.
    private var socksPortError: String? {
        (1024...65535).contains(draft.socksPort) ? nil
            : "Use a SOCKS port between 1024 and 65535 — ports below 1024 need root."
    }

    @ViewBuilder private var socksSectionBody: some View {
        EngineSettingRow(spec: spec("ssh.socks-port"), changed: draft.socksPort != 1080) {
            VStack(alignment: .leading, spacing: 4) {
                LabeledContent {
                    TextField("1080", value: $draft.socksPort, format: .number.grouping(.never))
                        .multilineTextAlignment(.trailing).frame(maxWidth: 120)
                        // Validation rides the field's value (Docs/Accessibility.md).
                        .accessibilityValue(socksPortError.map { "Problem: \($0)" } ?? "")
                } label: { EngineSettingLabel(spec: spec("ssh.socks-port"), changed: draft.socksPort != 1080) }
                if let error = socksPortError {
                    Text(error)
                        .font(.callout).foregroundStyle(.red)
                        .accessibilityLabel("Error: \(error)")
                }
            }
        }
        EngineSettingRow(spec: spec("ssh.system-proxy"), changed: draft.setSystemProxy) {
            Toggle(isOn: $draft.setSystemProxy) {
                EngineSettingLabel(spec: spec("ssh.system-proxy"), changed: draft.setSystemProxy)
            }
            // The toggle applies live to a connected tunnel — no reconnect.
            .onChange(of: draft.setSystemProxy) {
                guard active else { return }
                store.save(draft)
                manager.setSystemProxyLive(draft, enabled: draft.setSystemProxy)
            }
        }
        if active {
            Text("Flipping it while connected applies immediately — no reconnect.")
                .font(.callout).foregroundStyle(.secondary)
        }
    }

    /// The forwards list rides inside one descriptor row (summary + manual
    /// link); every existing behaviour — live badges, debounced apply, the
    /// per-row delete buttons with real hitboxes — is unchanged.
    @ViewBuilder private var forwardsSectionBody: some View {
        EngineSettingRow(spec: spec("ssh.forwards"), changed: !draft.forwards.isEmpty) {
            VStack(alignment: .leading, spacing: 4) {
                EngineSettingLabel(spec: spec("ssh.forwards"), changed: !draft.forwards.isEmpty)
                forwardEditorRows
            }
        }
        if active {
            Text("Changes apply to the live tunnel as you finish typing — no reconnect needed.")
                .font(.callout).foregroundStyle(.secondary)
        }
    }

    @ViewBuilder private var forwardEditorRows: some View {
        ForEach(Array(draft.forwards.enumerated()), id: \.offset) { i, _ in
            VStack(alignment: .leading, spacing: 2) {
                HStack(spacing: 6) {
                    TextField("L 8080:internal.host:80", text: Binding(
                        get: { draft.forwards[i] }, set: { draft.forwards[i] = $0 }))
                        .font(.callout.monospaced())
                        .onSubmit { applyForwardsNow() }
                        .accessibilityLabel("Port forward \(i + 1)")
                        // Validation rides the field's value (Docs/Accessibility.md).
                        .accessibilityValue(forwardError(draft.forwards[i]).map { "Problem: \($0)" } ?? "")
                    // .onDelete draws NO affordance in a macOS Form — without
                    // this button a forward can't be removed by mouse or keyboard.
                    Button {
                        draft.forwards.remove(at: i); applyForwardsNow()
                    } label: {
                        Image(systemName: "trash").frame(width: 22, height: 22).contentShape(Rectangle())
                    }
                        .buttonStyle(.plain).foregroundStyle(.secondary)
                        .accessibilityLabel("Remove port forward \(i + 1)")
                }
                // Say a bad spec is bad NOW — committed, it would kill the whole
                // connect (ExitOnForwardFailure=yes on the subprocess path).
                if let error = forwardError(draft.forwards[i]) {
                    Text(error)
                        .font(.caption).foregroundStyle(.red)
                        .accessibilityLabel("Error: \(error)")
                } else if active, let phase = forwardPhase(draft.forwards[i]) {
                    forwardBadge(phase)
                }
            }
        }
        .onDelete { draft.forwards.remove(atOffsets: $0); applyForwardsNow() }
        Button("Add Forward") { draft.forwards.append("") }
            .controlSize(.small)
            // Debounced live apply: per-keystroke -O forward calls would thrash
            // half-typed specs; onSubmit above applies instantly.
            .onChange(of: draft.forwards) { scheduleApplyForwards() }
    }

    /// Why a forward line won't parse (same rules as connect), or nil when it's
    /// fine or still empty.
    private func forwardError(_ line: String) -> String? {
        let t = line.trimmingCharacters(in: .whitespaces)
        guard !t.isEmpty, SubprocessTunnelManager.parseForward(t) == nil else { return nil }
        return "Use “L localPort:host:port”, “R remotePort:host:port” or “D port”."
    }

    /// The live status of the forward a row currently describes, if any.
    private func forwardPhase(_ line: String) -> SubprocessTunnelManager.ForwardPhase? {
        let t = line.trimmingCharacters(in: .whitespaces)
        guard !t.isEmpty else { return nil }
        return live?.forwardStates[SubprocessTunnelManager.forwardKey(t)]
    }

    @ViewBuilder private func forwardBadge(_ phase: SubprocessTunnelManager.ForwardPhase) -> some View {
        switch phase {
        case .active:
            Label("Active", systemImage: "checkmark.circle.fill")
                .font(.caption).foregroundStyle(.green)
        case .pending:
            Label("Applying…", systemImage: "clock")
                .font(.caption).foregroundStyle(.secondary)
        case .failed(let why):
            Label(why, systemImage: "xmark.circle.fill")
                .font(.caption).foregroundStyle(.red).lineLimit(2)
        }
    }

    private func scheduleApplyForwards() {
        guard active else { return }
        applyForwardsTask?.cancel()
        applyForwardsTask = Task {
            try? await Task.sleep(for: .milliseconds(800))
            guard !Task.isCancelled else { return }
            applyForwardsNow()
        }
    }

    /// Persist the edited set (so the next connect reproduces it) and reconcile
    /// the live tunnel. No-op while disconnected — specs then apply at connect,
    /// exactly as before.
    private func applyForwardsNow() {
        applyForwardsTask?.cancel()
        guard active else { return }
        store.save(draft)
        manager.applyForwards(draft)
    }

    /// Web-proxy path to the SSL-VPN server, inside Connection (canonical:
    /// upstream/jump lives there): system default / direct / manual.
    @ViewBuilder private var connectionProxyRows: some View {
        Picker("Connection proxy", selection: $draft.proxyMode) {
            ForEach(ProxyMode.allCases, id: \.self) { Text($0.label).tag($0) }
        }
        if draft.proxyMode == .manual {
            TextField("Proxy URL", text: $draft.proxyURL, prompt: Text("http://proxy.example.com:8080"))
                .autocorrectionDisabled()
            TextField("Proxy username (optional)", text: $draft.proxyUsername)
                .autocorrectionDisabled()
            SecureField("Proxy password (optional)", text: $proxyPassword)
            Toggle("Include proxy password in process arguments (visible to other local processes)",
                   isOn: Binding(get: { draft.proxyPasswordInArgv ?? false },
                                 set: { draft.proxyPasswordInArgv = $0 ? true : nil }))
        }
        Text(proxyModeHelp).font(.callout).foregroundStyle(.secondary)
    }

    private var proxyModeHelp: String {
        switch draft.proxyMode {
        case .systemDefault: "Reach the VPN server through whatever web proxy your Mac is configured to use (System Settings ▸ Network ▸ Proxies)."
        case .none: "Ignore any system proxy and connect straight to the server."
        case .manual: "Send the connection through this specific HTTP/SOCKS proxy. Supports http://, https:// and socks5://. openconnect can only take a proxy password on its command line — where any local process can read it with `ps` — so it's only passed when the toggle above is on; off, an authenticating proxy will refuse the connection (use an unauthenticated proxy, or the in-process engine under Advanced)."
        }
    }

    @ViewBuilder private var sslSignInSection: some View {
        Section("Sign-In") {
            // SSO is only offered where libopenconnect has the external-browser
            // flow (AnyConnect / GlobalProtect / Pulse) — sign-in runs through
            // the bundled ocauth-helper (SubprocessTunnelManager.connectSSO).
            Picker("Sign-in method", selection: $draft.authMode) {
                Text("Password").tag("password")
                Text("Client certificate").tag("certificate")
                if draft.kind.supportsExternalBrowserSSO {
                    Text("Single sign-on (SAML / passkey)").tag("sso")
                }
            }
            if let note = authNote {
                Label(note, systemImage: "info.circle")
                    .font(.callout).foregroundStyle(.orange)
            }
            if draft.authMode == "sso" {
                Text("Signs in through your browser, so identity-provider passkeys/WebAuthn and MFA work. Pick a specific browser below to override the app default.")
                    .font(.callout).foregroundStyle(.secondary)
            } else if !draft.kind.supportsExternalBrowserSSO {
                Text("Single sign-on isn't available for \(draft.kind.displayName): openconnect has no browser sign-in flow for this protocol.")
                    .font(.caption).foregroundStyle(.secondary)
            }
            TextField("Username", text: $draft.username).textContentType(.username)
            TextField("Realm / group (optional)", text: $draft.realm)
            passwordRows

            // SAML / SSO sign-in browser + profile — live only under SSO, and
            // only for the kinds whose browser sign-in flow actually exists.
            EngineSettingRow(spec: Self.specs["oc.sso-browser"], changed: !draft.browser.isOSDefault,
                             disabledReason: ssoBrowserUnused) {
                VStack(alignment: .leading, spacing: 4) {
                    BrowserPicker(selection: $draft.browser,
                                  systemDefaultLabel: "App default (\(appBrowserSummary))")
                    Text("“App default” follows Settings; pick a specific browser here to override it for this VPN.")
                        .font(.caption).foregroundStyle(.secondary)
                }
            }

            // Software verification-code token (secret stored in the keychain).
            EngineSettingRow(spec: Self.specs["oc.token-mode"], changed: !draft.tokenMode.isEmpty,
                             disabledReason: tokenUnused) {
                Picker(selection: $draft.tokenMode) {
                    Text("None").tag("")
                    Text("TOTP").tag("totp")
                    Text("HOTP").tag("hotp")
                    Text("OIDC").tag("oidc")
                } label: {
                    EngineSettingLabel(spec: Self.specs["oc.token-mode"], changed: !draft.tokenMode.isEmpty)
                }
            }
            if !draft.tokenMode.isEmpty {
                EngineSettingRow(spec: Self.specs["oc.token-secret"], changed: !tokenSecret.isEmpty,
                                 disabledReason: tokenUnused) {
                    VStack(alignment: .leading, spacing: 4) {
                        LabeledContent {
                            SecureField("TOTP/HOTP seed", text: $tokenSecret)
                                .multilineTextAlignment(.trailing)
                        } label: {
                            EngineSettingLabel(spec: Self.specs["oc.token-secret"], changed: !tokenSecret.isEmpty)
                        }
                        Text("Required: without it the connection fails before starting.")
                            .font(.caption).foregroundStyle(.secondary)
                    }
                }
            }

            // Client-certificate sign-in — inert unless the certificate method
            // is chosen, because the argv now only carries these under it.
            row("oc.client-cert", text: $draft.clientCertFile, prompt: "~/client.pem or .p12",
                disabled: certificateUnused)
            row("oc.client-key", text: $draft.clientKeyFile, prompt: "~/client.key (optional)",
                disabled: certificateUnused)
            if !draft.clientCertFile.isEmpty || !draft.clientKeyFile.isEmpty {
                EngineSettingRow(spec: Self.specs["oc.key-password"], changed: !keyPassphrase.isEmpty,
                                 disabledReason: certificateUnused) {
                    LabeledContent {
                        SecureField("if the key or .p12 is encrypted", text: $keyPassphrase)
                            .multilineTextAlignment(.trailing)
                    } label: {
                        EngineSettingLabel(spec: Self.specs["oc.key-password"], changed: !keyPassphrase.isEmpty)
                    }
                }
            }
        }
    }

    /// The sign-in method this tunnel will actually use — the same rule the argv
    /// builder follows, so the form can never claim one thing while openconnect
    /// does another.
    private var sslMethod: String { SubprocessTunnelManager.openconnectAuthMode(draft) }

    private var sslMethodLabel: String {
        switch sslMethod {
        case "certificate": "a client certificate"
        case "sso": "single sign-on"
        default: "a password"
        }
    }

    /// Why the password rows are inert, or nil when they're in play.
    private var passwordUnused: String? {
        switch sslMethod {
        case "certificate": "Not used when signing in with a client certificate — choose “Password” as the sign-in method to send one."
        case "sso": "Not used when signing in with single sign-on — the password is typed in your browser, at your identity provider."
        default: nil
        }
    }

    /// Why the client-certificate rows are inert, or nil.
    private var certificateUnused: String? {
        sslMethod == "certificate" ? nil
            : "Not used when signing in with \(sslMethodLabel) — choose “Client certificate” as the sign-in method to present one."
    }

    /// Why the verification-code token rows are inert, or nil.
    private var tokenUnused: String? {
        sslMethod == "sso"
            ? "Not used with single sign-on — your identity provider asks for the code on its own page."
            : nil
    }

    /// Why the "skip host checker" toggle is inert, or nil: a host-checker
    /// wrapper is passed instead of the skip, whatever this toggle says.
    private var csdSkipOverridden: String? {
        let wrapper = draft.csdWrapper.trimmingCharacters(in: .whitespaces)
        guard !wrapper.isEmpty else { return nil }
        return "Overridden by the host-checker wrapper “\((wrapper as NSString).lastPathComponent)” below, which runs instead. Clear that wrapper to skip the check."
    }

    /// Why the sign-in browser picker is inert, or nil.
    private var ssoBrowserUnused: String? {
        if !draft.kind.supportsExternalBrowserSSO {
            return "\(draft.kind.displayName) has no browser sign-in flow in openconnect, so no browser is opened."
        }
        return sslMethod == "sso" ? nil
            : "Only used with single sign-on — choose “Single sign-on (SAML / passkey)” as the sign-in method."
    }

    /// Kind-specific gateway blurb — the seven SSL-VPN kinds are different
    /// products; describing them all as F5/FortiGate was misleading.
    private var gatewayFooter: String {
        switch draft.kind {
        case .fortinet: "FortiGate SSL VPN via OpenConnect (or openfortivpn). With ocproxy it needs no admin rights."
        case .f5apm: "F5 BIG-IP APM: OpenConnect performs the HTTPS sign-in then runs the PPP-over-TLS tunnel."
        case .ciscoAnyConnect: "Cisco AnyConnect / Secure Client (or an ocserv gateway) via OpenConnect. With ocproxy it needs no admin rights."
        case .globalProtect: "Palo Alto GlobalProtect via OpenConnect. “User group / path” under Advanced selects portal vs gateway sign-in."
        case .juniper: "Juniper Network Connect (oNCP) via OpenConnect. With ocproxy it needs no admin rights."
        case .pulse: "Pulse / Ivanti Connect Secure via OpenConnect. With ocproxy it needs no admin rights."
        case .arrayNetworks: "Array Networks SSL VPN via OpenConnect. With ocproxy it needs no admin rights."
        default: ""
        }
    }

    /// Every OpenConnect kind runs through `ocproxy -D <port>` here (the no-root
    /// path), so the port is editable for all of them — two tunnels on the same
    /// port would collide on bind.
    @ViewBuilder private var sslTrafficSection: some View {
        Section("Traffic") {
            intField("Local SOCKS port", value: $draft.socksPort)
                .accessibilityValue(socksPortError.map { "Problem: \($0)" } ?? "")
            if let error = socksPortError {
                Text(error)
                    .font(.callout).foregroundStyle(.red)
                    .accessibilityLabel("Error: \(error)")
            }
            Toggle("Route Mac traffic through this proxy", isOn: $draft.setSystemProxy)
                // The toggle applies live to a connected tunnel — no reconnect.
                .onChange(of: draft.setSystemProxy) {
                    guard active else { return }
                    store.save(draft)
                    manager.setSystemProxyLive(draft, enabled: draft.setSystemProxy)
                }
            Text("OpenConnect exposes this tunnel as a SOCKS proxy on 127.0.0.1:\(draft.socksPort) via ocproxy — give each tunnel its own port to run two at once. “Route Mac traffic” points the active network service's SOCKS proxy at it while connected (asks for your admin password) and restores it on disconnect.")
                .font(.callout).foregroundStyle(.secondary)
        }
    }

    // MARK: Advanced (comprehensive knobs, collapsed)

    @ViewBuilder private var sshAdvanced: some View {
        Section {
            DisclosureGroup(isExpanded: $sshAdvancedExpanded) {
                // Clearing the field means "the default (30)", never 0 —
                // 0 would silently turn keepalives off.
                intRow("ssh.keepalive", value: Binding(get: { draft.serverAliveInterval }, set: { draft.serverAliveInterval = $0 ?? 30 }), prompt: "30",
                       changed: draft.serverAliveInterval != 30)
                toggleRow("ssh.compression", isOn: $draft.compression)
                linesRow("ssh.extra-options", $draft.sshExtraOptions, prompt: "Ciphers aes256-gcm@openssh.com")
            } label: {
                advancedDisclosureLabel($sshAdvancedExpanded)
            }
        }
    }

    /// A whole-row hit target for a disclosure header — a bare string label
    /// leaves only the chevron and the word clickable (the hitbox rule).
    private func advancedDisclosureLabel(_ expanded: Binding<Bool>) -> some View {
        HStack {
            Text("Advanced")
            Spacer(minLength: 0)
        }
        .padding(.vertical, 4)
        .contentShape(Rectangle())
        .onTapGesture { withAnimation(.snappy) { expanded.wrappedValue.toggle() } }
    }

    @ViewBuilder private var sslSecuritySection: some View {
        Section("Security") {
            TextField("Pinned cert SHA-256 (optional)", text: $draft.trustedCertSHA256)
                .font(.callout.monospaced())
            row("oc.cafile", text: $draft.caFile, prompt: "~/vpn-ca.pem")
            Toggle("Require perfect forward secrecy", isOn: $draft.enablePFS)
        }
    }

    @ViewBuilder private var sslAdvanced: some View {
        Section {
            DisclosureGroup(isExpanded: $sslAdvancedExpanded) {
                row("oc.os", text: $draft.spoofOS, prompt: "mac-intel")
                toggleRow("oc.no-dtls", isOn: $draft.disableDTLS)
                // A wrapper below WINS over this toggle in the argv — say so
                // instead of letting the toggle look effective.
                toggleRow("oc.disable-csd", isOn: $draft.disableCSD, disabled: csdSkipOverridden)
                if draft.kind == .globalProtect {
                    Text("Skipping the host checker also stubs GlobalProtect's HIP report — gateways that require a HIP submission may refuse or restrict the session.")
                        .font(.caption).foregroundStyle(.secondary)
                }

                Toggle("Run in-process (no OpenConnect subprocess)", isOn: $draft.preferInProcess)
                Text("Runs this VPN through SimpleVPN's built-in OpenConnect engine as a full system tunnel, instead of the openconnect command-line tool. Falls back to the tool automatically if it can't start. New — validate against your VPN server before relying on it.")
                    .font(.caption).foregroundStyle(.secondary)

                // F5 APM / Cisco endpoint posture (host checker / EPA).
                LabeledContent("Host-checker wrapper") {
                    TextField("/path/to/csd-wrapper.sh", text: $draft.csdWrapper).autocorrectionDisabled()
                }
                Text("F5 APM and Cisco run an endpoint (posture) check at sign-in. Provide a wrapper script to satisfy it, or turn on “skip host-checker” above to bypass it where the server allows.")
                    .font(.caption).foregroundStyle(.secondary)

                // Auth group / URL path (GlobalProtect portal-vs-gateway, Juniper/Pulse realm).
                LabeledContent("User group / path") {
                    TextField("optional", text: $draft.usergroup).autocorrectionDisabled()
                }
                Picker("Compression", selection: $draft.ocCompression) {
                    Text("Default").tag("")
                    Text("Stateful").tag("stateful")
                    Text("None").tag("none")
                    Text("All").tag("all")
                }
                Toggle("Disable IPv6 in the tunnel", isOn: $draft.disableIPv6)
                Toggle("Disable HTTP keepalive", isOn: $draft.noHTTPKeepalive)
                LabeledContent("Reported hostname") {
                    TextField("optional", text: $draft.localHostname).autocorrectionDisabled()
                }
                LabeledContent("User agent") {
                    TextField("optional", text: $draft.userAgent).autocorrectionDisabled()
                }
                LabeledContent("Client version string") {
                    TextField("spoof e.g. 4.10.05085", text: $draft.versionString).autocorrectionDisabled()
                }
                intRow("oc.reconnect-timeout", value: $draft.reconnectTimeout, prompt: "300")
                intRow("oc.mtu", value: $draft.ocMTU, prompt: "auto")
                intRow("oc.base-mtu", value: $draft.baseMTU, prompt: "auto")
                intRow("oc.force-dpd", value: $draft.forceDPD, prompt: "off")
                linesRow("oc.extra-args", $draft.extraArgs, prompt: "--no-http-keepalive")
            } label: {
                advancedDisclosureLabel($sslAdvancedExpanded)
            }
        }
    }

    /// Password + Remember for the SSL-VPN kinds, as a descriptor row (summary,
    /// manual link) and inert under the methods that never send a password —
    /// the same treatment `sshPasswordRow` gives the SSH surface. Disabling
    /// alone would be theatre; the argv builder is what stopped transmitting it.
    @ViewBuilder private var passwordRows: some View {
        EngineSettingRow(spec: Self.specs["oc.password"], changed: !password.isEmpty,
                         disabledReason: passwordUnused) {
            VStack(alignment: .leading, spacing: 6) {
                LabeledContent {
                    SecureField("Password", text: $password)
                        .textContentType(.password)
                        .multilineTextAlignment(.trailing)
                } label: {
                    EngineSettingLabel(spec: Self.specs["oc.password"], changed: !password.isEmpty)
                }
                Toggle("Remember password", isOn: $remember)
            }
        }
    }

    @ViewBuilder private var controlSection: some View {
        Section {
            HStack(spacing: 12) {
                statusBadge
                Spacer()
                if active {
                    Button("Disconnect") { manager.disconnect(draft.id) }
                        .buttonStyle(.bordered).tint(.red)
                } else {
                    Button("Connect") { connect() }
                        .buttonStyle(.glassProminent)   // primary "go" — consistent with OpenVPN Connect
                        .disabled(connectBlockedReason != nil)
                }
            }
            // A dead button must say why (the rule ConnectionView follows).
            if !active, let reason = connectBlockedReason {
                Text(reason)
                    .font(.caption).foregroundStyle(.secondary)
                    .frame(maxWidth: .infinity, alignment: .trailing)
            }
        }
    }

    /// Why Connect is disabled right now, or nil when it can go.
    private var connectBlockedReason: String? {
        if draft.kind == .ssh, draft.sshMode == .netTunnel {
            return "Network tunnel (-w) requires root for the utun device — not supported in this build."
        }
        // A malformed pin, or a pin combined with an option only /usr/bin/ssh
        // carries, would fail at connect — say so here instead (dead-button rule).
        if draft.kind == .ssh, pinnedKeyError != nil {
            return "The pinned host key isn't a valid SHA-256 fingerprint — fix it under Security."
        }
        if let reason = SubprocessTunnelManager.sshPinBlockReason(draft) {
            return reason
        }
        // The chosen sign-in method missing its file(s) would fail at connect.
        if draft.kind == .ssh, let reason = SubprocessTunnelManager.sshAuthBlockReason(draft) {
            return reason
        }
        // One bad forward kills the whole session (ExitOnForwardFailure=yes).
        if draft.kind == .ssh, draft.sshMode == .portForward,
           let bad = SubprocessTunnelManager.invalidForwardLine(draft.forwards) {
            return "Fix the forward “\(bad)” under Traffic — one bad forward stops the whole tunnel."
        }
        if (draft.kind == .ssh && draft.sshMode == .socks) || draft.kind.isSSLVPN,
           let reason = socksPortError {
            return reason
        }
        if !requiredCLI.isAvailable {
            return "\(requiredCLI.rawValue) isn't installed. \(requiredCLI.installHint)"
        }
        if draft.server.isEmpty {
            return "Enter the server address."
        }
        // A password inside the server/proxy address would be stored in the
        // clear and land on the tool's command line.
        if let reason = SubprocessTunnelManager.addressCredentialReason(draft) {
            return reason
        }
        // The chosen sign-in method missing its material would fail at connect.
        if let reason = SubprocessTunnelManager.sslAuthBlockReason(draft) {
            return reason
        }
        // --token-mode without its seed would just die under --non-inter (the
        // token isn't used under SSO, so it isn't required there either).
        if draft.kind.isSSLVPN, !draft.tokenMode.isEmpty, tokenSecret.isEmpty, sslMethod != "sso" {
            return "Verification-code token (\(draft.tokenMode.uppercased())) needs its secret — add it under Sign-In."
        }
        return nil
    }

    @ViewBuilder private var statusBadge: some View {
        switch manager.status(draft.id) {
        case .disconnected: Label("Disconnected", systemImage: "circle").foregroundStyle(.secondary)
        case .connecting: HStack(spacing: 6) { ProgressView().controlSize(.small); Text("Connecting…") }
        case .connected:
            Label(live?.socksPort.map { "Connected · SOCKS 127.0.0.1:\($0)" } ?? "Connected",
                  systemImage: "checkmark.circle.fill").foregroundStyle(.green)
        case .failed(let m): Label(m, systemImage: "xmark.circle.fill").foregroundStyle(.red).lineLimit(2)
        }
    }

    private func logSection(_ log: [String]) -> some View {
        Section("Log") {
            ScrollView { Text(log.joined(separator: "\n")).font(.caption.monospaced())
                .frame(maxWidth: .infinity, alignment: .leading).textSelection(.enabled) }
                .frame(height: 140)
        }
    }

    // MARK: Bits

    // MARK: Spec catalog + row helpers

    /// Resolve a spec id: ssh.* comes from the shared SSH catalog
    /// (SSHSettingDescriptors — the CLI/MDM/manual contract); oc.* stays local.
    private func spec(_ id: String) -> EngineSettingSpec {
        id.hasPrefix("ssh.") ? SSHSettings.catalog[id] : Self.specs[id]
    }

    /// Bind an Optional config string as text: empty ↔ nil (never store "").
    private func optionalText(_ keyPath: WritableKeyPath<SubprocessTunnelConfig, String?>) -> Binding<String> {
        Binding(get: { draft[keyPath: keyPath] ?? "" },
                set: { draft[keyPath: keyPath] = $0.isEmpty ? nil : $0 })
    }

    static let specs = EngineSettingCatalog([
        .init(id: "oc.password", name: "Password",
              summary: "The password for this VPN. Used by password sign-in only — a client certificate or single sign-on doesn't send it."),
        .init(id: "oc.client-cert", name: "Client Certificate",
              summary: "A certificate file (PEM or .p12) that identifies YOU to the gateway, instead of a password. Used by certificate sign-in only."),
        .init(id: "oc.client-key", name: "Client Private Key",
              summary: "The private key for the client certificate, when it isn't inside the certificate file itself."),
        .init(id: "oc.key-password", name: "Key / PKCS#12 Passphrase",
              summary: "The passphrase protecting your client key or .p12 file. Stored in your login keychain."),
        .init(id: "oc.sso-browser", name: "Sign-In Browser",
              summary: "Which browser (and profile) opens the single sign-on page, so passkeys and saved passwords are where you keep them."),
        .init(id: "oc.token-mode", name: "Verification-Code Token",
              summary: "Have SimpleVPN generate the verification code (TOTP/HOTP/OIDC) instead of you typing it. Used alongside password or certificate sign-in."),
        .init(id: "oc.token-secret", name: "Token Secret",
              summary: "The seed your verification codes are generated from. Stored in your login keychain and handed over in a private file — never on the command line."),
        .init(id: "oc.cafile", name: "CA Certificate File",
              summary: "A PEM file of extra certificate authorities to trust for the VPN server, if it uses a private CA."),
        .init(id: "oc.os", name: "Reported OS",
              summary: "The operating system OpenConnect claims to be, which some servers policy-check. e.g. mac-intel, win, linux-64."),
        .init(id: "oc.no-dtls", name: "Disable DTLS",
              summary: "Force the slower-but-more-compatible TLS transport instead of UDP DTLS. Turn on only if DTLS is blocked or flaky."),
        .init(id: "oc.disable-csd", name: "Skip Host Checker",
              summary: "Bypass the server's endpoint-posture/host-checker script. May be required to connect from an unmanaged Mac; some servers refuse without it."),
        .init(id: "oc.reconnect-timeout", name: "Reconnect Timeout",
              summary: "How long (seconds) to keep retrying a dropped tunnel before giving up."),
        .init(id: "oc.mtu", name: "MTU",
              summary: "Largest tunnel packet size. Leave empty to auto-detect; lower it if transfers stall."),
        .init(id: "oc.base-mtu", name: "Base MTU",
              summary: "The MTU of the underlying network path, used to size the tunnel. Leave empty to auto-detect."),
        .init(id: "oc.force-dpd", name: "Dead-Peer Detection (seconds)",
              summary: "Send a liveness probe this often and reconnect fast if the server stops answering. Empty leaves the protocol default."),
        .init(id: "oc.extra-args", name: "Extra Arguments",
              summary: "Raw OpenConnect flags (one per row) for site-specific needs not covered above."),
    ])

    private func row(_ id: String, text: Binding<String>, prompt: String,
                     disabled: String? = nil) -> some View {
        EngineSettingRow(spec: spec(id), changed: !text.wrappedValue.isEmpty,
                         disabledReason: disabled) {
            LabeledContent { TextField(prompt, text: text).multilineTextAlignment(.trailing).autocorrectionDisabled() }
                label: { EngineSettingLabel(spec: spec(id), changed: !text.wrappedValue.isEmpty) }
        }
    }
    private func toggleRow(_ id: String, isOn: Binding<Bool>, disabled: String? = nil) -> some View {
        EngineSettingRow(spec: spec(id), changed: isOn.wrappedValue, disabledReason: disabled) {
            Toggle(isOn: isOn) { EngineSettingLabel(spec: spec(id), changed: isOn.wrappedValue) }
        }
    }
    /// `changed` defaults to "a value is set"; pass it explicitly for fields
    /// whose binding always has a value (e.g. keepalive's non-optional default).
    private func intRow(_ id: String, value: Binding<Int?>, prompt: String,
                        changed: Bool? = nil) -> some View {
        let isChanged = changed ?? (value.wrappedValue != nil)
        return EngineSettingRow(spec: spec(id), changed: isChanged) {
            LabeledContent { TextField(prompt, value: value, format: .number.grouping(.never)).multilineTextAlignment(.trailing).frame(maxWidth: 120) }
                label: { EngineSettingLabel(spec: spec(id), changed: isChanged) }
        }
    }
    private func linesRow(_ id: String, _ binding: Binding<[String]>, prompt: String) -> some View {
        EngineSettingRow(spec: spec(id), changed: !binding.wrappedValue.isEmpty) {
            VStack(alignment: .leading, spacing: 4) {
                EngineSettingLabel(spec: spec(id), changed: !binding.wrappedValue.isEmpty)
                ForEach(Array(binding.wrappedValue.enumerated()), id: \.offset) { i, _ in
                    HStack(spacing: 6) {
                        TextField(prompt, text: Binding(get: { binding.wrappedValue[i] }, set: { binding.wrappedValue[i] = $0 }))
                            .font(.callout.monospaced())
                            .accessibilityLabel("\(spec(id).name) line \(i + 1)")
                        // .onDelete draws NO affordance in a macOS Form — without
                        // this button a line can't be removed by mouse or keyboard.
                        Button {
                            binding.wrappedValue.remove(at: i)
                        } label: {
                            Image(systemName: "trash").frame(width: 22, height: 22).contentShape(Rectangle())
                        }
                        .buttonStyle(.plain).foregroundStyle(.secondary)
                        .accessibilityLabel("Remove \(spec(id).name) line \(i + 1)")
                    }
                }
                .onDelete { binding.wrappedValue.remove(atOffsets: $0) }
                Button("Add") { binding.wrappedValue.append("") }.controlSize(.small)
            }
        }
    }

    private var portField: some View {
        TextField("Port", value: $draft.port, format: .number.grouping(.never))
            .frame(maxWidth: 120)
    }
    private func intField(_ title: String, value: Binding<Int>) -> some View {
        TextField(title, value: value, format: .number.grouping(.never)).frame(maxWidth: 160)
    }

    private func loadOnce() {
        guard !loaded else { return }
        loaded = true
        if let c = KeychainCredentialStore.loadCredentials(profile: "tunnel." + draft.id) {
            password = c.password
        }
        proxyPassword = KeychainCredentialStore.loadCredentials(profile: "tunnel.\(draft.id).proxy")?.password ?? ""
        jumpPassword = KeychainCredentialStore.loadCredentials(profile: "tunnel.\(draft.id).jump")?.password ?? ""
        tokenSecret = KeychainCredentialStore.loadCredentials(profile: "tunnel.\(draft.id).token")?.password ?? ""
        keyPassphrase = KeychainCredentialStore.loadCredentials(profile: "tunnel.\(draft.id).privateKey")?.password ?? ""
        // A saved "sso" on a kind openconnect can't browser-sign-in (the store
        // migrates persisted configs, but this draft may predate it): fall back
        // to password and say so.
        if draft.authMode == "sso", !draft.kind.supportsExternalBrowserSSO {
            draft.authMode = "password"
            authNote = "This VPN was set to single sign-on, which openconnect can't do for \(draft.kind.displayName) — switched to password sign-in."
        }
        customRouting = vpn.customRouting(for: draft.id)
        (crProxyAuthUsername, crProxyAuthPassword) = loadCustomRoutingProxyAuthFields(profileID: draft.id)
        // Open Advanced when it already holds changes — nothing the user set
        // may hide behind a closed disclosure (the OpenVPN form's rule).
        sshAdvancedExpanded = draft.serverAliveInterval != 30 || draft.compression
            || draft.sshExtraOptions.contains { !$0.trimmingCharacters(in: .whitespaces).isEmpty }
        sslAdvancedExpanded = !draft.spoofOS.isEmpty || draft.disableDTLS || draft.disableCSD
            || draft.preferInProcess || !draft.csdWrapper.isEmpty || !draft.usergroup.isEmpty
            || !draft.ocCompression.isEmpty || draft.disableIPv6 || draft.noHTTPKeepalive
            || !draft.localHostname.isEmpty || !draft.userAgent.isEmpty || !draft.versionString.isEmpty
            || draft.reconnectTimeout != nil || draft.ocMTU != nil || draft.baseMTU != nil
            || draft.forceDPD != nil
            || draft.extraArgs.contains { !$0.trimmingCharacters(in: .whitespaces).isEmpty }
    }

    private func save() {
        store.save(draft)
        if remember, !password.isEmpty {
            try? KeychainCredentialStore.saveCredentials(profile: "tunnel." + draft.id,
                                                         .init(username: draft.username, password: password))
        } else if !remember {
            KeychainCredentialStore.deleteCredentials(profile: "tunnel." + draft.id)
        }
        // Proxy auth password (manual proxy) — its own keychain item.
        if draft.proxyMode == .manual, !proxyPassword.isEmpty {
            try? KeychainCredentialStore.saveCredentials(profile: "tunnel.\(draft.id).proxy",
                                                         .init(username: draft.proxyUsername, password: proxyPassword))
        } else {
            KeychainCredentialStore.deleteCredentials(profile: "tunnel.\(draft.id).proxy")
        }
        // Jump-host password — independent keychain item.
        if draft.useJumpHost, !jumpPassword.isEmpty {
            try? KeychainCredentialStore.saveCredentials(profile: "tunnel.\(draft.id).jump",
                                                         .init(username: draft.jumpUsername, password: jumpPassword))
        } else {
            KeychainCredentialStore.deleteCredentials(profile: "tunnel.\(draft.id).jump")
        }
        // OTP token seed (--token-secret rides a private temp file at connect).
        if !draft.tokenMode.isEmpty, !tokenSecret.isEmpty {
            try? KeychainCredentialStore.saveCredentials(profile: "tunnel.\(draft.id).token",
                                                         .init(username: draft.username, password: tokenSecret))
        } else {
            KeychainCredentialStore.deleteCredentials(profile: "tunnel.\(draft.id).token")
        }
        // Client private-key / PKCS#12 passphrase (--key-password).
        if !draft.clientCertFile.isEmpty || !draft.clientKeyFile.isEmpty, !keyPassphrase.isEmpty {
            try? KeychainCredentialStore.saveCredentials(profile: "tunnel.\(draft.id).privateKey",
                                                         .init(username: draft.username, password: keyPassphrase))
        } else {
            KeychainCredentialStore.deleteCredentials(profile: "tunnel.\(draft.id).privateKey")
        }
        // Fire-and-forget: save() is called synchronously (Save button, Connect);
        // commitCustomRouting is idempotent and CustomRoutingTabView's own
        // onDisappear covers the case where the view closes before this lands.
        let id = draft.id
        let user = crProxyAuthUsername, pass = crProxyAuthPassword
        let toCommit = customRouting
        Task { @MainActor in
            customRouting = await commitCustomRouting(vpn, profileID: id, profile: toCommit,
                                                      proxyAuthUsername: user, proxyAuthPassword: pass)
        }
    }

    private func connect() {
        save()
        manager.connect(draft, password: password.isEmpty ? nil : password)
    }
}
