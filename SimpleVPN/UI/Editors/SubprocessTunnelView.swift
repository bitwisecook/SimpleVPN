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
                    TextField("Server address", text: $draft.server, prompt: Text("ssh.example.com")).autocorrectionDisabled()
                    portField
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
            Picker("Mode", selection: $draft.sshMode) {
                ForEach(SSHMode.allCases, id: \.self) { Text($0.label).tag($0) }
            }
            .pickerStyle(.segmented)
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

    @ViewBuilder private var sshSignInSection: some View {
        Section("Sign-In") {
            TextField("Username", text: $draft.username).textContentType(.username)
            row("ssh.identity-file", text: $draft.identityFile, prompt: "~/.ssh/id_ed25519")
            passwordRows
        }
    }

    @ViewBuilder private var sshSecuritySection: some View {
        Section("Security") {
            EngineSettingRow(spec: Self.specs["ssh.strict-host-key"], changed: draft.strictHostKey != "accept-new") {
                Picker(selection: $draft.strictHostKey) {
                    Text("Trust on first use").tag("accept-new")
                    Text("Only known hosts").tag("yes")
                    Text("Never check (unsafe)").tag("no")
                } label: { EngineSettingLabel(spec: Self.specs["ssh.strict-host-key"], changed: draft.strictHostKey != "accept-new") }
            }
        }
    }

    /// The jump-host rows live inside Connection — a jump host is part of how
    /// the tunnel reaches its server, like the SSL kinds' connection proxy.
    @ViewBuilder private var jumpHostRows: some View {
        Toggle("Connect via a jump host (bastion)", isOn: $draft.useJumpHost)
        if draft.useJumpHost {
            TextField("Jump host", text: $draft.jumpHost, prompt: Text("bastion.example.com")).autocorrectionDisabled()
            TextField("Jump port", value: $draft.jumpPort, format: .number.grouping(.never)).frame(maxWidth: 120)
            TextField("Jump username", text: $draft.jumpUsername).textContentType(.username)
            TextField("Jump identity file", text: $draft.jumpIdentityFile, prompt: Text("~/.ssh/id_bastion"))
                .autocorrectionDisabled()
            SecureField("Jump password (optional)", text: $jumpPassword)
            Text("SSH first connects to the jump host, then hops to the target. The jump host uses its own key and password above — independent of the target's.")
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
            let opt = "CertificateFile \(path)"
            if !draft.sshExtraOptions.contains(opt) { draft.sshExtraOptions.append(opt) }
            showFeedback("Added the SSH certificate \((path as NSString).lastPathComponent).", ok: true)
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

    @ViewBuilder private var socksSectionBody: some View {
        intField("Local SOCKS port", value: $draft.socksPort, default: 1080)
        Toggle("Route Mac traffic through this proxy", isOn: $draft.setSystemProxy)
            // The toggle applies live to a connected tunnel — no reconnect.
            .onChange(of: draft.setSystemProxy) {
                guard active else { return }
                store.save(draft)
                manager.setSystemProxyLive(draft, enabled: draft.setSystemProxy)
            }
        Text("Points the active network service's SOCKS proxy at 127.0.0.1:\(draft.socksPort) while connected (asks for your admin password), and restores it on disconnect. Flipping it while connected applies immediately.")
            .font(.callout).foregroundStyle(.secondary)
    }

    @ViewBuilder private var forwardsSectionBody: some View {
        ForEach(Array(draft.forwards.enumerated()), id: \.offset) { i, _ in
            VStack(alignment: .leading, spacing: 2) {
                HStack(spacing: 6) {
                    TextField("L 8080:internal.host:80", text: Binding(
                        get: { draft.forwards[i] }, set: { draft.forwards[i] = $0 }))
                        .font(.callout.monospaced())
                        .onSubmit { applyForwardsNow() }
                        .accessibilityLabel("Port forward \(i + 1)")
                    // .onDelete draws NO affordance in a macOS Form — without
                    // this button a forward can't be removed by mouse or keyboard.
                    Button {
                        draft.forwards.remove(at: i); applyForwardsNow()
                    } label: { Image(systemName: "trash") }
                        .buttonStyle(.plain).foregroundStyle(.secondary)
                        .accessibilityLabel("Remove port forward \(i + 1)")
                }
                if active, let phase = forwardPhase(draft.forwards[i]) {
                    forwardBadge(phase)
                }
            }
        }
        .onDelete { draft.forwards.remove(atOffsets: $0); applyForwardsNow() }
        Button("Add Forward") { draft.forwards.append("") }
        Text(active
             ? "Changes apply to the live tunnel as you finish typing — no reconnect needed."
             : "One per line: “L localPort:host:port” (local → remote) or “R remotePort:host:port” (remote → local).")
            .font(.callout).foregroundStyle(.secondary)
            // Debounced live apply: per-keystroke -O forward calls would thrash
            // half-typed specs; onSubmit above applies instantly.
            .onChange(of: draft.forwards) { scheduleApplyForwards() }
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
            // SSO is only offered where openconnect's --external-browser flow
            // exists (AnyConnect / GlobalProtect / Pulse); elsewhere it would
            // just drop the password and fail under --non-inter.
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

            // SAML / SSO sign-in browser + profile (F5 APM, GlobalProtect, AnyConnect).
            BrowserPicker(selection: $draft.browser,
                          systemDefaultLabel: "App default (\(appBrowserSummary))")
            Text("If this VPN signs in with SAML/SSO, the browser (and profile) used for the sign-in page. “App default” follows Settings; pick a specific browser here to override it for this VPN.")
                .font(.caption).foregroundStyle(.secondary)

            // Software verification-code token (secret stored in the keychain).
            Picker("Verification-code token", selection: $draft.tokenMode) {
                Text("None").tag("")
                Text("TOTP").tag("totp")
                Text("HOTP").tag("hotp")
                Text("OIDC").tag("oidc")
            }
            if !draft.tokenMode.isEmpty {
                SecureField("Token secret (TOTP/HOTP seed)", text: $tokenSecret)
                Text("Stored in your login keychain and handed to openconnect via a private temporary file at connect — never on the command line. Required: without it the connection fails before starting.")
                    .font(.caption).foregroundStyle(.secondary)
            }

            // Client-certificate sign-in.
            LabeledContent("Client certificate") {
                TextField("~/client.pem or .p12", text: $draft.clientCertFile).autocorrectionDisabled()
            }
            LabeledContent("Client private key") {
                TextField("~/client.key (optional)", text: $draft.clientKeyFile).autocorrectionDisabled()
            }
            if !draft.clientCertFile.isEmpty || !draft.clientKeyFile.isEmpty {
                SecureField("Key / PKCS#12 passphrase (if encrypted)", text: $keyPassphrase)
                Text("Stored in your login keychain and passed to openconnect as --key-password when the key or .p12 is encrypted.")
                    .font(.caption).foregroundStyle(.secondary)
            }
        }
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
            intField("Local SOCKS port", value: $draft.socksPort, default: 1080)
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
            DisclosureGroup("Advanced") {
                toggleRow("ssh.compression", isOn: $draft.compression)
                intRow("ssh.keepalive", value: Binding(get: { draft.serverAliveInterval }, set: { draft.serverAliveInterval = $0 ?? 0 }), prompt: "30")
                intRow("ssh.connect-timeout", value: $draft.connectTimeout, prompt: "off")
                linesRow("ssh.extra-options", $draft.sshExtraOptions, prompt: "Ciphers aes256-gcm@openssh.com")
            }
        }
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
            DisclosureGroup("Advanced") {
                row("oc.os", text: $draft.spoofOS, prompt: "mac-intel")
                toggleRow("oc.no-dtls", isOn: $draft.disableDTLS)
                toggleRow("oc.disable-csd", isOn: $draft.disableCSD)
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
            }
        }
    }

    /// Password + remember rows, shared by both kinds' Sign-In sections.
    @ViewBuilder private var passwordRows: some View {
        SecureField("Password", text: $password).textContentType(.password)
        Toggle("Remember password", isOn: $remember)
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
        if !requiredCLI.isAvailable {
            return "\(requiredCLI.rawValue) isn't installed. \(requiredCLI.installHint)"
        }
        if draft.server.isEmpty {
            return "Enter the server address."
        }
        // --token-mode without its seed would just die under --non-inter.
        if draft.kind.isSSLVPN, !draft.tokenMode.isEmpty, tokenSecret.isEmpty {
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

    static let specs = EngineSettingCatalog([
        .init(id: "ssh.identity-file", name: "Identity File",
              summary: "Path to a private key to authenticate with, instead of (or before) a password. Leave empty to use your default keys or a password."),
        .init(id: "ssh.proxy-jump", name: "Jump Host",
              summary: "Connect via a bastion first — SSH hops through it to reach the real host. Format: user@bastion[:port]."),
        .init(id: "ssh.compression", name: "Compression",
              summary: "Compress the SSH stream. Can help on very slow links; usually leave off on fast ones."),
        .init(id: "ssh.keepalive", name: "Keepalive (seconds)",
              summary: "How often to send a keepalive so idle tunnels aren't dropped by NAT/firewalls. 30 is a good default."),
        .init(id: "ssh.connect-timeout", name: "Connect Timeout",
              summary: "Give up establishing the SSH connection after this many seconds. Empty means the system default."),
        .init(id: "ssh.strict-host-key", name: "Host Key Checking",
              summary: "How to handle the server's identity key. “Trust on first use” accepts a new host once and pins it — the safe default."),
        .init(id: "ssh.extra-options", name: "Extra Options",
              summary: "Raw ssh_config lines (one per row, “Key Value”) for anything not covered here, e.g. Ciphers or MACs."),
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

    private func row(_ id: String, text: Binding<String>, prompt: String) -> some View {
        EngineSettingRow(spec: Self.specs[id], changed: !text.wrappedValue.isEmpty) {
            LabeledContent { TextField(prompt, text: text).multilineTextAlignment(.trailing).autocorrectionDisabled() }
                label: { EngineSettingLabel(spec: Self.specs[id], changed: !text.wrappedValue.isEmpty) }
        }
    }
    private func toggleRow(_ id: String, isOn: Binding<Bool>) -> some View {
        EngineSettingRow(spec: Self.specs[id], changed: isOn.wrappedValue) {
            Toggle(isOn: isOn) { EngineSettingLabel(spec: Self.specs[id], changed: isOn.wrappedValue) }
        }
    }
    private func intRow(_ id: String, value: Binding<Int?>, prompt: String) -> some View {
        EngineSettingRow(spec: Self.specs[id], changed: value.wrappedValue != nil) {
            LabeledContent { TextField(prompt, value: value, format: .number.grouping(.never)).multilineTextAlignment(.trailing).frame(maxWidth: 120) }
                label: { EngineSettingLabel(spec: Self.specs[id], changed: value.wrappedValue != nil) }
        }
    }
    private func linesRow(_ id: String, _ binding: Binding<[String]>, prompt: String) -> some View {
        EngineSettingRow(spec: Self.specs[id], changed: !binding.wrappedValue.isEmpty) {
            VStack(alignment: .leading, spacing: 4) {
                EngineSettingLabel(spec: Self.specs[id], changed: !binding.wrappedValue.isEmpty)
                ForEach(Array(binding.wrappedValue.enumerated()), id: \.offset) { i, _ in
                    TextField(prompt, text: Binding(get: { binding.wrappedValue[i] }, set: { binding.wrappedValue[i] = $0 }))
                        .font(.callout.monospaced())
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
    private func intField(_ title: String, value: Binding<Int>, default def: Int) -> some View {
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
