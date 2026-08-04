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

    /// Which tab is showing. A binding, so a related-settings link or a search
    /// hit on the other tab can select it — no TabView in the app could be
    /// selected in code before this.
    @State private var tab: SettingsTab = .settings
    /// This editor's search catalog. It is the ONE editor serving two surfaces —
    /// SSH and the seven OpenConnect SSL-VPN kinds — so both are in the catalog,
    /// plus Custom Routing (its second tab). `kind` follows the Kind picker (set
    /// in `loadOnce` and on change) so the related links track what you switch to.
    @State private var search = SettingsSearch(surfaces: [.ssh, .openConnect, .customRouting],
                                               kind: .ssh)

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
    /// The saved-confirmation affordance every editor's primary action now has.
    @State private var savedTick = false
    // The Advanced disclosures' expansion state now lives in the shared
    // CollapsibleSettingsSection, which opens itself when the group already holds
    // changes — the two hand-kept `…Expanded` flags (and the long boolean chains
    // in loadOnce that seeded them) are gone.

    private var live: SubprocessTunnelManager.Live? { manager.live[draft.id] }
    private var active: Bool { manager.isActive(draft.id) }
    private var appBrowserSummary: String { BrowserCatalog.label(BrowserDefaults.appDefault) }

    /// The config surface: the canonical groups, in order (AGENTS.md "Config
    /// surfaces") — Connection → Sign-In → Traffic → Security → Advanced.
    private var configForm: some View {
        Form {
            SettingsSearchSection(search: search)
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
                    intRow("ssh.port", value: $draft.port, prompt: "22",
                           range: SubprocessTunnelConfig.portRange,
                           invalidMessage: "Enter a port between 1 and 65535. Leave empty for SSH's own 22.")
                    intRow("ssh.connect-timeout", value: $draft.connectTimeout, prompt: "system default",
                           range: SubprocessTunnelConfig.connectTimeoutRange,
                           invalidMessage: "Enter a timeout between 1 and 600 seconds. Leave empty to use the system's own.")
                    jumpHostRows
                } else if draft.kind.isSSLVPN {
                    TextField("Server address", text: $draft.server, prompt: Text("vpn.example.com")).autocorrectionDisabled()
                    portField
                    connectionProxyRows
                    // Connection LIFECYCLE, so it belongs here with the other
                    // timeouts rather than buried in Advanced (the taxonomy's own
                    // wording: "connection lifecycle (timeouts, stay-connected…)").
                    intRow("oc.reconnect-timeout", value: $draft.reconnectTimeout, prompt: "300",
                           range: SubprocessTunnelConfig.reconnectTimeoutRange,
                           invalidMessage: "Enter a number of seconds between 0 and 86400 — 0 gives up as soon as the tunnel drops.")
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
        }
        .formStyle(.grouped)
        .revealsSettings()
        .disabled(ManagedPolicy.lockConfiguration)
    }

    var body: some View {
        // Custom Routing is its own TAB in every editor (AGENTS.md "Config
        // surfaces") — appending it as sections put a second, differently-shaped
        // config surface inside the run of canonical groups.
        TabView(selection: $tab) {
            configForm
                .tag(SettingsTab.settings)
                .tabItem { Label("Settings", systemImage: "slider.horizontal.3") }
            Form {
                CustomRoutingTabView(vpn: vpn, profileID: draft.id, profile: $customRouting,
                                    proxyAuthUsername: $crProxyAuthUsername,
                                    proxyAuthPassword: $crProxyAuthPassword)
            }
            .formStyle(.grouped)
            .revealsSettings()
            .disabled(ManagedPolicy.lockConfiguration)
            .tag(SettingsTab.customRouting)
            .tabItem { Label("Custom Routing", systemImage: "arrow.triangle.branch") }
        }
        // Which rows this draft gates OUT — this editor serves eight kinds across
        // two surfaces, so most of its catalog is off screen at any moment. A
        // search hit or a related link naming one now says so instead of jumping
        // nowhere (SettingVisibility). Inner, so the shell's route consumption
        // can't read a stale table.
        .onAppear { search.visibility = SettingVisibility.subprocess(draft) }
        .onChange(of: SettingVisibility.subprocess(draft)) { _, new in search.visibility = new }
        .settingsEditor(search: search, tab: $tab,
                        surfaces: [.ssh, .openConnect, .customRouting], profileID: draft.id)
        // The Kind picker turns an SSH tunnel into a FortiGate one and back, so
        // which related links are reachable has to follow it.
        .onChange(of: draft.kind) { search.kind = draft.kind }
        .padding(.top, 10)
        .navigationTitle(draft.name)
        .task { loadOnce() }
        .toolbar {
            ToolbarItem(placement: .confirmationAction) {
                Button { save() } label: {
                    savedTick ? Label("Saved", systemImage: "checkmark")
                              : Label("Save", systemImage: "checkmark")
                }
                    .buttonStyle(.glassProminent)   // primary action — one idiom in every editor
                    .disabled(saveDisabledReason != nil)
                    // A dead button must say why (the rule ConnectionView follows).
                    .help(saveDisabledReason ?? "Save changes to this tunnel")
                    .accessibilityValue(saveDisabledReason.map { "unavailable — \($0)" } ?? "")
            }
        }
    }

    // MARK: Sections

    @ViewBuilder private var cliStatusRow: some View {
        let cli = requiredCLI
        VStack(alignment: .leading, spacing: 4) {
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
            // "Install with: brew install openconnect" was a string in a caption:
            // true, and unusable to anyone who doesn't live in a terminal and
            // can't select half a sentence. Two rows can be missing at once
            // (the tool itself, and ocproxy for the no-root path), so each gets
            // its own copy button.
            missingCLICommands(cli)
        }
    }

    /// A "Copy Install Command" button per tool this kind needs and doesn't have.
    @ViewBuilder private func missingCLICommands(_ cli: TunnelCLI) -> some View {
        let missing: [TunnelCLI] = {
            var out: [TunnelCLI] = []
            if !cli.isAvailable { out.append(cli) }
            if draft.kind.isSSLVPN, !TunnelCLI.ocproxy.isAvailable { out.append(.ocproxy) }
            return out
        }()
        ForEach(missing, id: \.self) { tool in
            if let command = tool.installCommand {
                CopyCommandLink(command: command,
                                title: "Copy \u{201C}\(command)\u{201D}")
            }
        }
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
            EngineSettingRow(spec: spec("ssh.mode"), value: draft.sshMode) {
                Picker(selection: $draft.sshMode) {
                    ForEach(SSHMode.allCases, id: \.self) { Text($0.label).tag($0) }
                } label: { EngineSettingLabel(spec: spec("ssh.mode"), value: draft.sshMode) }
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
            TrafficCrossLinks()
        }
    }

    /// The picker's normalized value ("" = automatic).
    private var sshMethod: String { SubprocessTunnelManager.sshAuthMethod(draft) }

    @ViewBuilder private var sshSignInSection: some View {
        Section("Sign-In") {
            EngineSettingRow(spec: spec("ssh.auth-method"), value: sshMethod) {
                Picker(selection: Binding(
                    get: { sshMethod },
                    set: { draft.sshAuthMethod = $0.isEmpty ? nil : $0 })) {
                    Text("Automatic").tag("")
                    Text("Password").tag("password")
                    Text("Key file").tag("key")
                    Text("Certificate").tag("certificate")
                    Text("SSH agent").tag("agent")
                    Text("Kerberos").tag("kerberos")
                } label: { EngineSettingLabel(spec: spec("ssh.auth-method"), value: sshMethod) }
            }
            row("ssh.username", text: $draft.username, prompt: "alex")
            // Each credential row is live only under the methods that use it —
            // a disabled row says which choice re-enables it (.help + AX value).
            row("ssh.identity-file", text: $draft.identityFile, prompt: "~/.ssh/id_ed25519",
                disabled: ["", "key", "certificate"].contains(sshMethod) ? nil
                    : "Not used when signing in with \(sshMethodLabel) — choose Automatic, “Key file” or “Certificate”.",
                warning: SubprocessTunnelConfig.missingFileWarning(draft.identityFile),
                // An sk- key file works (the built-in engine is built with FIDO2),
                // but it can't be used without touching the device — say so before
                // the connect appears to hang.
                note: SubprocessTunnelConfig.securityKeyNote(draft.identityFile))
            row("ssh.certificate-file", text: optionalText(\.sshCertificateFile), prompt: "~/.ssh/id_ed25519-cert.pub",
                disabled: sshMethod == "certificate" ? nil
                    : "Choose “Certificate” as the sign-in method to use an SSH certificate.",
                warning: SubprocessTunnelConfig.missingFileWarning(draft.sshCertificateFile ?? ""))
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
        EngineSettingRow(spec: spec("ssh.password"), value: password,
                         disabledReason: passwordUnused) {
            VStack(alignment: .leading, spacing: 6) {
                LabeledContent {
                    SecureField("optional", text: $password)
                        .textContentType(.password)
                        .multilineTextAlignment(.trailing)
                } label: { EngineSettingLabel(spec: spec("ssh.password"), value: password) }
                Toggle("Remember password", isOn: $remember)
            }
        }
        if sshMethod == "password" {
            SettingCaveat("If the server asks a follow-up question — a verification code, an MFA prompt — the stored password is what gets sent. Servers that need a code per sign-in aren't suited to a remembered password.")
        }
    }

    @ViewBuilder private var sshSecuritySection: some View {
        Section("Security") {
            EngineSettingRow(spec: spec("ssh.strict-host-key"), value: draft.strictHostKey) {
                Picker(selection: $draft.strictHostKey) {
                    Text("Trust on first use").tag("accept-new")
                    Text("Only known hosts").tag("yes")
                    Text("Never check (unsafe)").tag("no")
                } label: { EngineSettingLabel(spec: spec("ssh.strict-host-key"), value: draft.strictHostKey) }
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
        EngineSettingRow(spec: s, value: pinned) {
            VStack(alignment: .leading, spacing: 4) {
                LabeledContent {
                    TextField("SHA256:… or 64 hex characters", text: optionalText(\.sshPinnedHostKey))
                        .font(.callout.monospaced())
                        .autocorrectionDisabled()
                        .multilineTextAlignment(.trailing)
                        .accessibilityValue(pinnedKeyError.map { "Problem: \($0)" } ?? "")
                } label: { EngineSettingLabel(spec: s, value: pinned) }
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
            intRow("ssh.jump-port", value: $draft.jumpPort, prompt: "22",
                   range: SubprocessTunnelConfig.portRange,
                   invalidMessage: "Enter a port between 1 and 65535. Leave empty for SSH's own 22.")
            row("ssh.jump-username", text: $draft.jumpUsername, prompt: "alex")
            row("ssh.jump-identity-file", text: $draft.jumpIdentityFile, prompt: "~/.ssh/id_bastion",
                warning: SubprocessTunnelConfig.missingFileWarning(draft.jumpIdentityFile))
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

    /// The local SOCKS listener binds without root, so the floor is 1024. The
    /// bound is the config's own constant, so the UI range and the stored range
    /// can't drift (see `SubprocessTunnelConfig.socksPortRange`).
    private var socksPortError: String? {
        SubprocessTunnelConfig.socksPortProblem(draft.socksPort)
    }

    /// Whether the SOCKS port is a control this kind/mode actually has — the test
    /// Save applies, so an SSH port-forward tunnel isn't blocked by a port it
    /// never binds.
    private var usesSOCKSPort: Bool {
        (draft.kind == .ssh && draft.sshMode == .socks) || draft.kind.isSSLVPN
    }

    @ViewBuilder private var socksSectionBody: some View {
        socksRows(portID: "ssh.socks-port", systemProxyID: "ssh.system-proxy")
    }

    /// The SOCKS pair — the local listener's port and "route the whole Mac
    /// through it" — rendered from whichever surface's specs. ONE builder, because
    /// the SSH and SSL-VPN kinds expose the SAME TWO CONCEPTS off the same two
    /// model fields (`socksPort`, `setSystemProxy`): the SSL half used to be a
    /// bare `intField` plus a hand-written Toggle, so the two kinds described one
    /// concept in two voices and only one of them was searchable.
    @ViewBuilder private func socksRows(portID: String, systemProxyID: String) -> some View {
        EngineSettingRow(spec: spec(portID), value: draft.socksPort) {
            VStack(alignment: .leading, spacing: 4) {
                LabeledContent {
                    TextField("1080", value: $draft.socksPort, format: .number.grouping(.never))
                        .multilineTextAlignment(.trailing).frame(maxWidth: 120)
                        // Validation rides the field's value (Docs/Accessibility.md).
                        .accessibilityValue(socksPortError.map { "Problem: \($0)" } ?? "")
                } label: { EngineSettingLabel(spec: spec(portID), value: draft.socksPort) }
                if let error = socksPortError {
                    Text(error)
                        .font(.callout).foregroundStyle(.red)
                        .accessibilityLabel("Error: \(error)")
                }
            }
        }
        EngineSettingRow(spec: spec(systemProxyID), value: draft.setSystemProxy) {
            Toggle(isOn: $draft.setSystemProxy) {
                EngineSettingLabel(spec: spec(systemProxyID), value: draft.setSystemProxy)
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
        EngineSettingRow(spec: spec("ssh.forwards"), value: draft.forwards) {
            VStack(alignment: .leading, spacing: 4) {
                EngineSettingLabel(spec: spec("ssh.forwards"), value: draft.forwards)
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
                                  systemDefaultLabel: "App default (\(appBrowserSummary))",
                                  showsAppDefaultLink: true)
                    Text("“App default” follows Settings; pick a specific browser here to override it for this VPN.")
                        .font(.caption).foregroundStyle(.secondary)
                }
            }

            // Software verification-code token (secret stored in the keychain).
            EngineSettingRow(spec: Self.specs["oc.token-mode"], value: draft.tokenMode,
                             disabledReason: tokenUnused) {
                Picker(selection: $draft.tokenMode) {
                    Text("None").tag("")
                    Text("TOTP").tag("totp")
                    Text("HOTP").tag("hotp")
                    Text("OIDC").tag("oidc")
                    // openconnect takes these two as well; leaving them out
                    // meant a working configuration couldn't be expressed.
                    Text("RSA SecurID").tag("rsa")
                    Text("YubiKey (OATH)").tag("yubioath")
                    // Same as `oc.os`: a stored value from outside the set is
                    // SHOWN rather than blanked behind the user's back.
                    if SubprocessTunnelConfig.tokenModeProblem(draft.tokenMode) != nil {
                        Text(draft.tokenMode).tag(draft.tokenMode)
                    }
                } label: {
                    EngineSettingLabel(spec: Self.specs["oc.token-mode"], value: draft.tokenMode)
                }
            }
            if let caveat = SubprocessTunnelConfig.tokenModeProblem(draft.tokenMode) {
                SettingCaveat(caveat)
            }
            // YubiKey codes come off the key itself, so no seed is stored (or
            // required) for that mode.
            if SubprocessTunnelConfig.tokenModeRequiresSecret(draft.tokenMode) {
                EngineSettingRow(spec: Self.specs["oc.token-secret"], value: tokenSecret,
                                 disabledReason: tokenUnused) {
                    VStack(alignment: .leading, spacing: 4) {
                        LabeledContent {
                            SecureField("TOTP/HOTP seed", text: $tokenSecret)
                                .multilineTextAlignment(.trailing)
                        } label: {
                            EngineSettingLabel(spec: Self.specs["oc.token-secret"], value: tokenSecret)
                        }
                        Text("Required: without it the connection fails before starting.")
                            .font(.caption).foregroundStyle(.secondary)
                    }
                }
            }

            // Client-certificate sign-in — inert unless the certificate method
            // is chosen, because the argv now only carries these under it.
            row("oc.client-cert", text: $draft.clientCertFile, prompt: "~/client.pem or .p12",
                disabled: certificateUnused,
                warning: SubprocessTunnelConfig.missingFileWarning(draft.clientCertFile))
            // A certificate is set but the method says Password: openconnect is
            // handed no certificate flag at all, so the sign-in silently becomes
            // a password one. Say it beside the certificate, where it is set.
            if let caveat = certificateSetButUnusedCaveat {
                SettingCaveat(caveat)
            }
            row("oc.client-key", text: $draft.clientKeyFile, prompt: "~/client.key (optional)",
                disabled: certificateUnused,
                warning: SubprocessTunnelConfig.missingFileWarning(draft.clientKeyFile))
            if !draft.clientCertFile.isEmpty || !draft.clientKeyFile.isEmpty {
                EngineSettingRow(spec: Self.specs["oc.key-password"], value: keyPassphrase,
                                 disabledReason: certificateUnused) {
                    LabeledContent {
                        SecureField("if the key or .p12 is encrypted", text: $keyPassphrase)
                            .multilineTextAlignment(.trailing)
                    } label: {
                        EngineSettingLabel(spec: Self.specs["oc.key-password"], value: keyPassphrase)
                    }
                }
            }
        }
    }

    /// The sign-in method this tunnel will actually use — the same rule the argv
    /// builder follows, so the form can never claim one thing while openconnect
    /// does another.
    private var sslMethod: String { SubprocessTunnelManager.openconnectAuthMode(draft) }

    /// A client certificate is configured while the method is Password (or SSO),
    /// so it will NOT be presented — the exact state that turned every
    /// certificate profile into a failing password one when the flags started
    /// being gated on the picker. `SubprocessTunnelStore.migrated` repairs the
    /// profiles that predate the picker; this catches the case someone creates.
    private var certificateSetButUnusedCaveat: String? {
        guard sslMethod != "certificate" else { return nil }
        let hasCert = !draft.clientCertFile.trimmingCharacters(in: .whitespaces).isEmpty
            || !draft.clientKeyFile.trimmingCharacters(in: .whitespaces).isEmpty
        guard hasCert else { return nil }
        return "This certificate isn't sent: the sign-in method above is \(sslMethodLabel), and only \u{201C}Client certificate\u{201D} presents one. Choose Client certificate to use it."
    }

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

    /// Non-blocking: the wrapper script isn't there. openconnect fails at
    /// startup with an opaque error, so say it now — but never block a save,
    /// since the file may be created before the next connect.
    private var csdWrapperWarning: String? {
        SubprocessTunnelConfig.missingFileWarning(draft.csdWrapper)
    }

    /// Plain-language name for one of openconnect's `--os=` values.
    static func spoofOSLabel(_ value: String) -> String {
        switch value {
        case "linux": "Linux (32-bit)"
        case "linux-64": "Linux (64-bit)"
        case "win": "Windows"
        case "mac-intel": "macOS"
        case "android": "Android"
        case "apple-ios": "iOS"
        default: value
        }
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
        // The setting's name is quoted exactly as the row spells it (oc.usergroup) —
        // prose that renames a control sends the reader looking for a row that
        // isn't there, and search for a name the screen never shows.
        case .globalProtect: "Palo Alto GlobalProtect via OpenConnect. “User Group / Path” under Advanced selects portal vs gateway sign-in."
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
            // The same two rows the SSH surface shows, from the same builder and
            // the same words (oc.socks-port / oc.system-proxy mirror the ssh.*
            // pair per the AGENTS.md glossary).
            socksRows(portID: "oc.socks-port", systemProxyID: "oc.system-proxy")
            Text("OpenConnect exposes this tunnel as a SOCKS proxy on 127.0.0.1:\(draft.socksPort) via ocproxy — give each tunnel its own port to run two at once.")
                .font(.callout).foregroundStyle(.secondary)
            // …unless the built-in engine takes the connection, in which case
            // there is no ocproxy and no SOCKS listener at all. Said as a caveat
            // rather than a disabledReason because the in-process path falls back
            // to the tool whenever a setting needs it — the rows would then be
            // dead for no reason (`willRunInProcess` is the honesty gate).
            if SubprocessTunnelManager.willRunInProcess(draft) {
                SettingCaveat("With “Run In-Process” on, this VPN is carried as a full system tunnel — no SOCKS proxy is opened, so neither of the two settings above applies.")
            }
            // The user-facing MTU, on ONE shared control (UI/Components/MTUField)
            // — it sat in Advanced beside the BASE MTU, which describes the path
            // underneath and stays there (see AGENTS.md on the split).
            EngineSettingRow(spec: Self.specs["oc.mtu"], value: draft.ocMTU) {
                MTUField(spec: Self.specs["oc.mtu"], value: $draft.ocMTU,
                         range: SubprocessTunnelConfig.ocMTURange, prompt: "auto",
                         invalidMessage: "Enter an MTU between 576 and 1500. Leave empty to let OpenConnect work it out.")
            }
            TrafficCrossLinks()
        }
    }

    // MARK: Advanced (comprehensive knobs, collapsed)

    /// Through the SHARED collapsible section every editor now uses, so this
    /// surface also gets the "n changed" badge and the search-reveal hook (it was
    /// a hand-rolled `Section { DisclosureGroup }` — one of three different
    /// "Advanced" idioms that existed across five editors).
    @ViewBuilder private var sshAdvanced: some View {
        CollapsibleSettingsSection(group: .advanced, changedCount: sshAdvancedChangedCount) {
            // Clearing the field means "the default (30)", never 0 —
            // 0 would silently turn keepalives off.
            intRow("ssh.keepalive", value: Binding(get: { draft.serverAliveInterval }, set: { draft.serverAliveInterval = $0 ?? 30 }), prompt: "30",
                   range: SubprocessTunnelConfig.keepaliveRange,
                   invalidMessage: "Enter an interval between 0 and 86400 seconds — 0 turns keepalives off. Leave empty for the default 30.",
                   changed: draft.serverAliveInterval != 30)
            toggleRow("ssh.compression", isOn: $draft.compression)
            linesRow("ssh.extra-options", $draft.sshExtraOptions, prompt: "Ciphers aes256-gcm@openssh.com")
        }
    }

    private var sshAdvancedChangedCount: Int {
        [draft.serverAliveInterval != 30,
         draft.compression,
         draft.sshExtraOptions.contains { !$0.trimmingCharacters(in: .whitespaces).isEmpty }].count { $0 }
    }

    /// Every Advanced row now has a spec, so the badge counts through the
    /// specs' declared defaults — one derivation, in the catalog, rather than the
    /// nine hand-written `!draft.x.isEmpty` predicates this used to mix in beside
    /// them (AGENTS.md: "Changed is computed, never re-derived").
    private var sslAdvancedChangedCount: Int {
        [Self.specs["oc.os"].isChanged(draft.spoofOS),
         Self.specs["oc.no-dtls"].isChanged(draft.disableDTLS),
         Self.specs["oc.disable-csd"].isChanged(draft.disableCSD),
         Self.specs["oc.prefer-in-process"].isChanged(draft.preferInProcess),
         Self.specs["oc.csd-wrapper"].isChanged(draft.csdWrapper),
         Self.specs["oc.usergroup"].isChanged(draft.usergroup),
         Self.specs["oc.compression"].isChanged(draft.ocCompression),
         Self.specs["oc.disable-ipv6"].isChanged(draft.disableIPv6),
         Self.specs["oc.no-http-keepalive"].isChanged(draft.noHTTPKeepalive),
         Self.specs["oc.local-hostname"].isChanged(draft.localHostname),
         Self.specs["oc.user-agent"].isChanged(draft.userAgent),
         Self.specs["oc.version-string"].isChanged(draft.versionString),
         Self.specs["oc.base-mtu"].isChanged(draft.baseMTU),
         Self.specs["oc.force-dpd"].isChanged(draft.forceDPD),
         Self.specs["oc.extra-args"].isChanged(draft.extraArgs)].count { $0 }
    }

    @ViewBuilder private var sslSecuritySection: some View {
        Section("Security") {
            pinnedServerCertRow
            row("oc.cafile", text: $draft.caFile, prompt: "~/vpn-ca.pem",
                warning: SubprocessTunnelConfig.missingFileWarning(draft.caFile))
            toggleRow("oc.pfs", isOn: $draft.enablePFS)
        }
    }

    /// Why the pinned server certificate isn't a usable fingerprint, or nil when
    /// it is (or the field is empty). The definition lives on the config so the
    /// editor, Connect and any future importer share one answer.
    private var pinnedServerCertError: String? {
        SubprocessTunnelConfig.serverCertPinProblem(draft.trustedCertSHA256)
    }

    /// The ONLY control on these seven kinds that verifies the SERVER: a mono
    /// field with format validation (inline problem + `accessibilityValue`, per
    /// Docs/Accessibility.md), matching `pinnedHostKeyRow` on the SSH surface.
    /// It was free text with no check at all — and a typo in it is not a warning
    /// but a connect that always fails, blaming the certificate.
    @ViewBuilder private var pinnedServerCertRow: some View {
        let s = spec("oc.pinned-server-cert")
        EngineSettingRow(spec: s, value: draft.trustedCertSHA256) {
            VStack(alignment: .leading, spacing: 4) {
                LabeledContent {
                    TextField("pin-sha256:… or sha256:… (optional)", text: $draft.trustedCertSHA256)
                        .font(.callout.monospaced())
                        .autocorrectionDisabled()
                        .multilineTextAlignment(.trailing)
                        .accessibilityValue(pinnedServerCertError.map { "Problem: \($0)" }
                                            ?? draft.trustedCertSHA256)
                } label: { EngineSettingLabel(spec: s, value: draft.trustedCertSHA256) }
                if let error = pinnedServerCertError {
                    Text(error)
                        .font(.callout).foregroundStyle(.red)
                        .accessibilityLabel("Error: \(error)")
                }
            }
        }
    }

    @ViewBuilder private var sslAdvanced: some View {
        CollapsibleSettingsSection(group: .advanced, changedCount: sslAdvancedChangedCount) {
            Group {
                // openconnect accepts a CLOSED set here — free text let a typo
                // through to be refused at startup with an opaque error.
                EngineSettingRow(spec: Self.specs["oc.os"], value: draft.spoofOS) {
                    Picker(selection: $draft.spoofOS) {
                        Text("Don't say (this Mac)").tag("")
                        ForEach(SubprocessTunnelConfig.spoofOSValues, id: \.self) {
                            Text(Self.spoofOSLabel($0)).tag($0)
                        }
                        // A stored value from outside the set (an import, the CLI,
                        // MDM) gets its own row so the picker SHOWS it rather than
                        // coming up blank — `normalized()` no longer blanks it,
                        // because quietly deleting what someone stored is worse.
                        if SubprocessTunnelConfig.spoofOSProblem(draft.spoofOS) != nil {
                            Text(draft.spoofOS).tag(draft.spoofOS)
                        }
                    } label: {
                        EngineSettingLabel(spec: Self.specs["oc.os"], value: draft.spoofOS)
                    }
                }
                if let caveat = SubprocessTunnelConfig.spoofOSProblem(draft.spoofOS) {
                    SettingCaveat(caveat)
                }
                toggleRow("oc.no-dtls", isOn: $draft.disableDTLS)
                // A wrapper below WINS over this toggle in the argv — say so
                // instead of letting the toggle look effective.
                toggleRow("oc.disable-csd", isOn: $draft.disableCSD, disabled: csdSkipOverridden)
                if draft.kind == .globalProtect {
                    Text("Skipping the host checker also stubs GlobalProtect's HIP report — gateways that require a HIP submission may refuse or restrict the session.")
                        .font(.caption).foregroundStyle(.secondary)
                }

                toggleRow("oc.prefer-in-process", isOn: $draft.preferInProcess)
                Text("New — validate against your VPN server before relying on it.")
                    .font(.caption).foregroundStyle(.secondary)
                // Asking for the built-in engine is not the same as getting it:
                // any option the bridge can't express sends the connection back
                // to the tool. Say which, instead of letting the toggle look
                // effective (SubprocessTunnelManager.willRunInProcess is the gate).
                if draft.preferInProcess, !SubprocessTunnelManager.willRunInProcess(draft) {
                    SettingCaveat("This VPN uses settings the built-in engine can't carry (a port, CA file, client certificate, verification-code token, host checker, connection proxy, compression, PFS, IPv6/keepalive override, reported identity, MTU, timeout or extra arguments), so the openconnect tool runs it instead.")
                }

                // F5 APM / Cisco endpoint posture (host checker / EPA).
                row("oc.csd-wrapper", text: $draft.csdWrapper, prompt: "/path/to/csd-wrapper.sh",
                    warning: csdWrapperWarning)
                Text("F5 APM and Cisco run an endpoint (posture) check at sign-in. Provide a wrapper script to satisfy it, or turn on “Skip Host Checker” above to bypass it where the server allows.")
                    .font(.caption).foregroundStyle(.secondary)

                // Auth group / URL path (GlobalProtect portal-vs-gateway, Juniper/Pulse realm).
                row("oc.usergroup", text: $draft.usergroup, prompt: "optional")
                EngineSettingRow(spec: spec("oc.compression"), value: draft.ocCompression) {
                    Picker(selection: $draft.ocCompression) {
                        Text("Default").tag("")
                        Text("Stateful").tag("stateful")
                        Text("None").tag("none")
                        Text("All").tag("all")
                    } label: {
                        EngineSettingLabel(spec: spec("oc.compression"), value: draft.ocCompression)
                    }
                }
                toggleRow("oc.disable-ipv6", isOn: $draft.disableIPv6)
                toggleRow("oc.no-http-keepalive", isOn: $draft.noHTTPKeepalive)
                row("oc.local-hostname", text: $draft.localHostname, prompt: "optional")
                row("oc.user-agent", text: $draft.userAgent, prompt: "optional")
                row("oc.version-string", text: $draft.versionString, prompt: "4.10.05085")
                // The BASE MTU describes the path underneath the tunnel — an
                // engine internal, and a different range (jumbo frames allowed),
                // which is why it stays here while the user-facing MTU is up in
                // Traffic. Same shared control, though.
                MTUField(spec: Self.specs["oc.base-mtu"], value: $draft.baseMTU,
                         range: SubprocessTunnelConfig.baseMTURange, prompt: "auto",
                         invalidMessage: "Enter the path's MTU, between 576 and 9000 (jumbo frames). Leave empty to let OpenConnect work it out.",
                         step: 100)
                    .padding(.vertical, 2)
                intRow("oc.force-dpd", value: $draft.forceDPD, prompt: "off",
                       range: SubprocessTunnelConfig.forceDPDRange,
                       invalidMessage: "Enter an interval between 0 and 3600 seconds — 0 leaves the protocol's own rate.")
                linesRow("oc.extra-args", $draft.extraArgs, prompt: "--no-http-keepalive")
            }
        }
    }

    /// Password + Remember for the SSL-VPN kinds, as a descriptor row (summary,
    /// manual link) and inert under the methods that never send a password —
    /// the same treatment `sshPasswordRow` gives the SSH surface. Disabling
    /// alone would be theatre; the argv builder is what stopped transmitting it.
    @ViewBuilder private var passwordRows: some View {
        EngineSettingRow(spec: Self.specs["oc.password"], value: password,
                         disabledReason: passwordUnused) {
            VStack(alignment: .leading, spacing: 6) {
                LabeledContent {
                    SecureField("Password", text: $password)
                        .textContentType(.password)
                        .multilineTextAlignment(.trailing)
                } label: {
                    EngineSettingLabel(spec: Self.specs["oc.password"], value: password)
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

    /// Why Save is unavailable, in the user's language, or nil when it can go.
    ///
    /// The SOCKS port is here because `normalized()` no longer rewrites it: a
    /// stored port is something other software points at, so the choice is
    /// "block the save with the reason" or "silently move it to 1080 and break
    /// them". This is the block.
    private var saveDisabledReason: String? {
        if draft.name.trimmingCharacters(in: .whitespaces).isEmpty { return "Give this tunnel a name first." }
        if draft.server.isEmpty { return "Enter the server address first." }
        if usesSOCKSPort, let reason = socksPortError { return reason }
        return nil
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
        if usesSOCKSPort, let reason = socksPortError {
            return reason
        }
        // A mistyped certificate pin is refused by openconnect at startup with an
        // opaque certificate error — the ONE server-identity control these kinds
        // have, so it gets the dead-button treatment the SSH pin already had.
        if draft.kind.isSSLVPN, pinnedServerCertError != nil {
            return "The pinned server certificate isn't a valid SHA-256 fingerprint — fix it under Security."
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
        if draft.kind.isSSLVPN, SubprocessTunnelConfig.tokenModeRequiresSecret(draft.tokenMode),
           tokenSecret.isEmpty, sslMethod != "sso" {
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

    /// The catalog now lives in
    /// `ControlPlane/OpenConnectSettingDescriptors.swift` so app-wide search can
    /// reach it; this alias keeps the form's call sites reading
    /// `Self.specs["oc.…"]`. (The SSH half of this editor already rendered from
    /// `SSHSettings`, which was out here from the start.)
    static var specs: EngineSettingCatalog { OpenConnectSettings.catalog }

    /// `warning` is a NON-blocking caption under the field — used for "No file at
    /// that path.", which must never stop a save (the file may appear before the
    /// next connect) but is otherwise an opaque tool-startup error.
    /// `note` is INFORMATIONAL (nothing is wrong) and reads in the secondary
    /// style — a security key's "you'll be asked to touch it" is not a warning,
    /// and dressing it as one would teach users to ignore the orange triangle.
    private func row(_ id: String, text: Binding<String>, prompt: String,
                     disabled: String? = nil, warning: String? = nil,
                     note: String? = nil) -> some View {
        EngineSettingRow(spec: spec(id), value: text.wrappedValue,
                         disabledReason: disabled) {
            VStack(alignment: .leading, spacing: 4) {
                LabeledContent {
                    TextField(prompt, text: text).multilineTextAlignment(.trailing).autocorrectionDisabled()
                        // Validation rides the field's value (Docs/Accessibility.md).
                        .accessibilityValue([text.wrappedValue, warning, note]
                            .compactMap { $0 }.joined(separator: ". "))
                } label: { EngineSettingLabel(spec: spec(id), value: text.wrappedValue) }
                if let warning, disabled == nil {
                    Label(warning, systemImage: "exclamationmark.triangle.fill")
                        .font(.callout).foregroundStyle(.orange)
                        .accessibilityLabel("Warning: \(warning)")
                }
                if let note, disabled == nil {
                    Label(note, systemImage: "hand.tap")
                        .font(.callout).foregroundStyle(.secondary)
                        .fixedSize(horizontal: false, vertical: true)
                        // Already announced through the field's value above.
                        .accessibilityHidden(true)
                }
            }
        }
    }
    /// "Changed" comes from the spec's declared default — one derivation, in the
    /// catalog, rather than a hand-written predicate at each call site.
    private func toggleRow(_ id: String, isOn: Binding<Bool>, disabled: String? = nil) -> some View {
        let s = spec(id)
        return EngineSettingRow(spec: s, value: isOn.wrappedValue, disabledReason: disabled) {
            Toggle(isOn: isOn) { EngineSettingLabel(spec: s, value: isOn.wrappedValue) }
        }
    }
    /// Every numeric row goes through the shared `ValidatedNumberField`, so an
    /// out-of-range value shows an inline error and is never stored — rather
    /// than being handed to ssh/openconnect to reject at startup with an opaque
    /// message. The range always comes from `SubprocessTunnelConfig`'s own
    /// `…Range` block, so the UI bound and the stored bound can't drift.
    /// `changed` comes from the spec's declared default; pass it explicitly only
    /// for a binding whose optionality doesn't match the spec's own type (e.g.
    /// keepalive, whose model field is a non-optional Int behind an Int? binding).
    private func intRow(_ id: String, value: Binding<Int?>, prompt: String,
                        range: ClosedRange<Int>, invalidMessage: String,
                        changed: Bool? = nil) -> some View {
        let isChanged = changed ?? spec(id).isChanged(value.wrappedValue)
        return EngineSettingRow(spec: spec(id), changed: isChanged) {
            ValidatedNumberField(
                label: { EngineSettingLabel(spec: spec(id), changed: isChanged) },
                prompt: prompt, value: value, range: range, invalidMessage: invalidMessage)
        }
    }
    private func linesRow(_ id: String, _ binding: Binding<[String]>, prompt: String) -> some View {
        EngineSettingRow(spec: spec(id), value: binding.wrappedValue) {
            VStack(alignment: .leading, spacing: 4) {
                EngineSettingLabel(spec: spec(id), value: binding.wrappedValue)
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
        ValidatedNumberField(
            label: { Text("Port") },
            prompt: "443",
            value: $draft.port,
            range: SubprocessTunnelConfig.portRange,
            invalidMessage: "Enter a port between 1 and 65535. Leave empty for the standard HTTPS port.")
    }

    private func loadOnce() {
        guard !loaded else { return }
        loaded = true
        search.kind = draft.kind
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
        // Advanced opens itself when it already holds changes — the shared
        // CollapsibleSettingsSection derives that from its own changed count, so
        // there is nothing to seed here (and no chain to keep in sync).
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
        // Acknowledge the save on the button, like every other editor.
        savedTick = true
        Task { @MainActor in
            try? await Task.sleep(for: .seconds(2))
            savedTick = false
        }
    }

    private func connect() {
        save()
        manager.connect(draft, password: password.isEmpty ? nil : password)
    }
}
