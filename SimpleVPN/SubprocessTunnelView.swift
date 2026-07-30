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
    @Bindable var store: SubprocessTunnelStore
    @Bindable var manager: SubprocessTunnelManager
    @State var draft: SubprocessTunnelConfig

    @State private var password = ""
    @State private var proxyPassword = ""
    @State private var jumpPassword = ""
    @State private var remember = true
    @State private var loaded = false

    private var live: SubprocessTunnelManager.Live? { manager.live[draft.id] }
    private var active: Bool { manager.isActive(draft.id) }
    private var appBrowserSummary: String { BrowserCatalog.label(BrowserDefaults.appDefault) }

    var body: some View {
        Form {
            Section {
                TextField("Name", text: $draft.name)
                Picker("Kind", selection: $draft.kind) {
                    ForEach([VPNKind.ssh, .fortinet, .f5apm, .ciscoAnyConnect,
                             .globalProtect, .juniper, .pulse, .arrayNetworks], id: \.self) {
                        Label($0.displayName, systemImage: $0.systemImage).tag($0)
                    }
                }
                cliStatusRow
            }

            if draft.kind == .ssh {
                sshCommon
                sshModeSection
                sshAdvanced
            } else if draft.kind.isSSLVPN {
                sslVPNSection
                proxySection
                sslAdvanced
            }

            credentialsSection
            controlSection
            if let log = live?.log, !log.isEmpty { logSection(log) }
        }
        .formStyle(.grouped)
        .disabled(ManagedPolicy.lockConfiguration)
        .navigationTitle(draft.name)
        .task { loadOnce() }
        .toolbar {
            ToolbarItem(placement: .confirmationAction) {
                Button("Save") { save() }
                    .disabled(draft.name.trimmingCharacters(in: .whitespaces).isEmpty || draft.server.isEmpty)
            }
        }
    }

    // MARK: Sections

    @ViewBuilder private var cliStatusRow: some View {
        let cli = requiredCLI
        HStack(spacing: 6) {
            Image(systemName: cli.isAvailable ? "checkmark.circle.fill" : "exclamationmark.triangle.fill")
                .foregroundStyle(cli.isAvailable ? .green : .orange)
            Text(cli.isAvailable ? "\(cli.rawValue) found" : cli.installHint)
                .font(.callout).foregroundStyle(.secondary)
            if [.fortinet, .f5apm, .ciscoAnyConnect].contains(draft.kind), !TunnelCLI.ocproxy.isAvailable {
                Spacer()
                Text("ocproxy not found — needs root without it")
                    .font(.caption).foregroundStyle(.orange)
            }
        }
    }

    private var requiredCLI: TunnelCLI {
        switch draft.kind {
        case .ssh: .ssh
        case .fortinet: TunnelCLI.openconnect.isAvailable ? .openconnect : .openfortivpn
        default: .openconnect  // f5 / anyconnect
        }
    }

    /// SSH carries traffic three ways; the mode picks which fields matter.
    @ViewBuilder private var sshModeSection: some View {
        Section("Mode") {
            Picker("Mode", selection: $draft.sshMode) {
                ForEach(SSHMode.allCases, id: \.self) { Text($0.label).tag($0) }
            }
            .pickerStyle(.segmented)
            switch draft.sshMode {
            case .socks: socksSectionBody
            case .portForward: forwardsSectionBody
            case .netTunnel:
                Label("Point-to-point tunnel over SSH (-w). Needs admin rights and “PermitTunnel” enabled on the server — a rarely-used, advanced mode.",
                      systemImage: "exclamationmark.triangle")
                    .font(.callout).foregroundStyle(.secondary)
            }
        }
    }

    @ViewBuilder private var sshCommon: some View {
        Section("Target") {
            TextField("Host", text: $draft.server, prompt: Text("ssh.example.com")).autocorrectionDisabled()
            portField
            TextField("Username", text: $draft.username).textContentType(.username)
            row("ssh.identity-file", text: $draft.identityFile, prompt: "~/.ssh/id_ed25519")
        }
        Section {
            Toggle("Connect via a jump host (bastion)", isOn: $draft.useJumpHost)
            if draft.useJumpHost {
                TextField("Jump host", text: $draft.jumpHost, prompt: Text("bastion.example.com")).autocorrectionDisabled()
                TextField("Jump port", value: $draft.jumpPort, format: .number.grouping(.never)).frame(maxWidth: 120)
                TextField("Jump username", text: $draft.jumpUsername).textContentType(.username)
                TextField("Jump identity file", text: $draft.jumpIdentityFile, prompt: Text("~/.ssh/id_bastion"))
                    .autocorrectionDisabled()
                SecureField("Jump password (optional)", text: $jumpPassword)
            }
        } header: {
            Text("Jump Host")
        } footer: {
            if draft.useJumpHost {
                Text("SSH first connects to the jump host, then hops to the target. The jump host uses its own key and password above — independent of the target's.")
            }
        }
    }

    @ViewBuilder private var socksSectionBody: some View {
        intField("Local SOCKS port", value: $draft.socksPort, default: 1080)
        Toggle("Route Mac traffic through this proxy", isOn: $draft.setSystemProxy)
        Text("Points the active network service's SOCKS proxy at 127.0.0.1:\(draft.socksPort) while connected (asks for your admin password), and restores it on disconnect.")
            .font(.callout).foregroundStyle(.secondary)
    }

    @ViewBuilder private var forwardsSectionBody: some View {
        ForEach(Array(draft.forwards.enumerated()), id: \.offset) { i, _ in
            TextField("L 8080:internal.host:80", text: Binding(
                get: { draft.forwards[i] }, set: { draft.forwards[i] = $0 }))
                .font(.callout.monospaced())
        }
        .onDelete { draft.forwards.remove(atOffsets: $0) }
        Button("Add Forward") { draft.forwards.append("") }
        Text("One per line: “L localPort:host:port” (local → remote) or “R remotePort:host:port” (remote → local).")
            .font(.callout).foregroundStyle(.secondary)
    }

    /// Web-proxy path to the SSL-VPN gateway: system default / direct / manual.
    @ViewBuilder private var proxySection: some View {
        Section("Connection Proxy") {
            Picker("Proxy", selection: $draft.proxyMode) {
                ForEach(ProxyMode.allCases, id: \.self) { Text($0.label).tag($0) }
            }
            if draft.proxyMode == .manual {
                TextField("Proxy URL", text: $draft.proxyURL, prompt: Text("http://proxy.example.com:8080"))
                    .autocorrectionDisabled()
                TextField("Proxy username (optional)", text: $draft.proxyUsername)
                    .autocorrectionDisabled()
                SecureField("Proxy password (optional)", text: $proxyPassword)
            }
            Text(proxyModeHelp).font(.callout).foregroundStyle(.secondary)
        }
    }

    private var proxyModeHelp: String {
        switch draft.proxyMode {
        case .systemDefault: "Reach the gateway through whatever web proxy your Mac is configured to use (System Settings ▸ Network ▸ Proxies)."
        case .none: "Ignore any system proxy and connect straight to the gateway."
        case .manual: "Send the connection through this specific HTTP/SOCKS proxy. Supports http://, https:// and socks5://."
        }
    }

    @ViewBuilder private var sslVPNSection: some View {
        Section("Gateway") {
            TextField("Server URL or host", text: $draft.server, prompt: Text("vpn.example.com")).autocorrectionDisabled()
            portField
            Picker("Sign-in method", selection: $draft.authMode) {
                Text("Password").tag("password")
                Text("Client certificate").tag("certificate")
                Text("Single sign-on (SAML / passkey)").tag("sso")
            }
            if draft.authMode == "sso" {
                Text("Signs in through your browser, so identity-provider passkeys/WebAuthn and MFA work. Set a specific browser under Advanced if needed.")
                    .font(.callout).foregroundStyle(.secondary)
            }
            TextField("Username", text: $draft.username).textContentType(.username)
            TextField("Realm / group (optional)", text: $draft.realm)
            TextField("Pinned cert SHA-256 (optional)", text: $draft.trustedCertSHA256)
                .font(.callout.monospaced())
            Text(draft.kind == .f5apm
                 ? "F5 BIG-IP APM: OpenConnect performs the HTTPS logon then runs the PPP-over-TLS tunnel."
                 : "FortiGate SSL VPN via OpenConnect (or openfortivpn). With ocproxy it needs no admin rights.")
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
                EngineSettingRow(spec: Self.specs["ssh.strict-host-key"], changed: draft.strictHostKey != "accept-new") {
                    Picker(selection: $draft.strictHostKey) {
                        Text("Trust on first use").tag("accept-new")
                        Text("Only known hosts").tag("yes")
                        Text("Never check (unsafe)").tag("no")
                    } label: { EngineSettingLabel(spec: Self.specs["ssh.strict-host-key"], changed: draft.strictHostKey != "accept-new") }
                }
                linesRow("ssh.extra-options", $draft.sshExtraOptions, prompt: "Ciphers aes256-gcm@openssh.com")
            }
        }
    }

    @ViewBuilder private var sslAdvanced: some View {
        Section {
            DisclosureGroup("Advanced") {
                row("oc.cafile", text: $draft.caFile, prompt: "~/vpn-ca.pem")
                row("oc.os", text: $draft.spoofOS, prompt: "mac-intel")
                toggleRow("oc.no-dtls", isOn: $draft.disableDTLS)
                toggleRow("oc.disable-csd", isOn: $draft.disableCSD)

                Toggle("Run in-process (no OpenConnect subprocess)", isOn: $draft.preferInProcess)
                Text("Runs this VPN through SimpleVPN's built-in OpenConnect engine as a full system tunnel, instead of the openconnect command-line tool. Falls back to the tool automatically if it can't start. New — validate against your gateway before relying on it.")
                    .font(.caption).foregroundStyle(.secondary)

                // SAML / SSO sign-in browser + profile (F5 APM, GlobalProtect, AnyConnect).
                BrowserPicker(selection: $draft.browser,
                              systemDefaultLabel: "App default (\(appBrowserSummary))")
                Text("If this gateway signs in with SAML/SSO, the browser (and profile) used for the sign-in page. “App default” follows Settings; pick a specific browser here to override it for this VPN.")
                    .font(.caption).foregroundStyle(.secondary)

                // F5 APM / Cisco endpoint posture (host checker / EPA).
                LabeledContent("Host-checker wrapper") {
                    TextField("/path/to/csd-wrapper.sh", text: $draft.csdWrapper).autocorrectionDisabled()
                }
                Text("F5 APM and Cisco run an endpoint (posture) check at sign-in. Provide a wrapper script to satisfy it, or turn on “skip host-checker” above to bypass it where the gateway allows.")
                    .font(.caption).foregroundStyle(.secondary)

                // Auth group / URL path (GlobalProtect portal-vs-gateway, Juniper/Pulse realm).
                LabeledContent("User group / path") {
                    TextField("optional", text: $draft.usergroup).autocorrectionDisabled()
                }
                // Software one-time-code token (secret stored in the keychain).
                Picker("One-time-code token", selection: $draft.tokenMode) {
                    Text("None").tag("")
                    Text("TOTP").tag("totp")
                    Text("HOTP").tag("hotp")
                    Text("OIDC").tag("oidc")
                }
                // Client-certificate auth.
                LabeledContent("Client certificate") {
                    TextField("~/client.pem or .p12", text: $draft.clientCertFile).autocorrectionDisabled()
                }
                LabeledContent("Client private key") {
                    TextField("~/client.key (optional)", text: $draft.clientKeyFile).autocorrectionDisabled()
                }
                Picker("Compression", selection: $draft.ocCompression) {
                    Text("Default").tag("")
                    Text("Stateful").tag("stateful")
                    Text("None").tag("none")
                    Text("All").tag("all")
                }
                Toggle("Require perfect forward secrecy", isOn: $draft.enablePFS)
                Toggle("Disable IPv6 in the tunnel", isOn: $draft.disableIPv6)
                Toggle("Disable HTTP keep-alive", isOn: $draft.noHTTPKeepalive)
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

    @ViewBuilder private var credentialsSection: some View {
        Section("Password") {
            SecureField("Password", text: $password).textContentType(.password)
            Toggle("Remember password", isOn: $remember)
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
                        .disabled(!requiredCLI.isAvailable || draft.server.isEmpty)
                }
            }
        }
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
              summary: "A PEM file of extra certificate authorities to trust for the gateway, if it uses a private CA."),
        .init(id: "oc.os", name: "Reported OS",
              summary: "The operating system OpenConnect claims to be, which some gateways policy-check. e.g. mac-intel, win, linux-64."),
        .init(id: "oc.no-dtls", name: "Disable DTLS",
              summary: "Force the slower-but-more-compatible TLS transport instead of UDP DTLS. Turn on only if DTLS is blocked or flaky."),
        .init(id: "oc.disable-csd", name: "Skip Host Checker",
              summary: "Bypass the gateway's endpoint-posture/host-checker script. May be required to connect from an unmanaged Mac; some gateways refuse without it."),
        .init(id: "oc.reconnect-timeout", name: "Reconnect Timeout",
              summary: "How long (seconds) to keep retrying a dropped tunnel before giving up."),
        .init(id: "oc.mtu", name: "MTU",
              summary: "Largest tunnel packet size. Leave empty to auto-detect; lower it if transfers stall."),
        .init(id: "oc.base-mtu", name: "Base MTU",
              summary: "The MTU of the underlying network path, used to size the tunnel. Leave empty to auto-detect."),
        .init(id: "oc.force-dpd", name: "Dead-Peer Detection (seconds)",
              summary: "Send a liveness probe this often and reconnect fast if the gateway stops answering. Empty leaves the protocol default."),
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
    }

    private func connect() {
        save()
        manager.connect(draft, password: password.isEmpty ? nil : password)
    }
}
