// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
//  NativeVPNView.swift
//  Editor + control for the OS-native personal VPN kinds (IKEv2, IPsec). macOS
//  runs these itself via NEVPNManager — one at a time (singleton). L2TP has no
//  programmatic API, so it's offered as a downloadable configuration profile.
//

import SwiftUI
import NetworkExtension

struct NativeVPNView: View {
    let vpn: VPNController
    @Bindable var manager: NativeVPNManager
    @State var draft: NativeVPNConfig
    /// IKEv2: the password or PSK, whichever mode is active. IPsec: the XAuth
    /// password (optional — the group secret alone is sometimes enough).
    @State private var secret = ""
    /// IPsec only: the group shared secret (PSK). Kept separate from `secret`
    /// because IPsec, unlike IKEv2, can need both at once.
    @State private var sharedSecret = ""
    /// L2TP only: the PPP (user) password. A third slot for the same reason —
    /// L2TP needs the IPSec shared secret AND a user password at once, and the
    /// exported .mobileconfig carries them in different payload dictionaries.
    @State private var pppPassword = ""
    @State private var loaded = false
    @State private var customRouting = CustomRoutingProfile()
    @State private var crProxyAuthUsername = ""
    @State private var crProxyAuthPassword = ""

    private var isActive: Bool {
        manager.activeConfigID == draft.id &&
        (manager.status == .connected || manager.status == .connecting || manager.status == .reasserting)
    }

    /// nil once every field the active auth mode needs is filled in;
    /// otherwise a short caption naming what's missing, for both the Connect
    /// button's disabled state and a visible reason (never just a dead button).
    private var missingFieldCaption: String? {
        // Was `.isEmpty` only: a typo'd server reached NEVPNManager and came
        // back as an opaque IKE timeout.
        if let p = draft.serverProblem { return p }
        switch draft.kind {
        case .ipsec:
            if sharedSecret.isEmpty { return "Enter the shared secret (PSK) to connect." }
        case .ikev2:
            if draft.usesSharedSecret {
                if secret.isEmpty { return "Enter the shared secret (PSK) to connect." }
            } else {
                if draft.username.isEmpty { return "Enter a username to connect." }
                if secret.isEmpty { return "Enter a password to connect." }
            }
        default: break
        }
        return nil
    }

    /// The OTHER native config currently occupying macOS's single personal-VPN
    /// slot, if any — connecting this one replaces it, so Connect names it.
    private var activeOtherNativeName: String? {
        guard let activeID = manager.activeConfigID, activeID != draft.id,
              manager.status == .connected || manager.status == .connecting
                || manager.status == .reasserting
        else { return nil }
        let name = manager.configs.first { $0.id == activeID }?.name
            .trimmingCharacters(in: .whitespaces) ?? ""
        return name.isEmpty ? "the other native VPN" : name
    }

    private var replacesActiveVPNCaption: String? {
        activeOtherNativeName.map { "Will disconnect \($0) first." }
    }

    private var connectHelp: String {
        [replacesActiveVPNCaption, missingFieldCaption ?? "Push this configuration into macOS and connect."]
            .compactMap { $0 }.joined(separator: " ")
    }

    /// Why this server address won't work, or nil. Shown inline AND used by both
    /// gates — a bad address used to surface only as an opaque IKE timeout.
    private var serverProblem: String? {
        draft.server.isEmpty ? nil : draft.serverProblem
    }

    /// Why Save is unavailable, in the user's language, or nil.
    private var saveDisabledReason: String? {
        if draft.name.trimmingCharacters(in: .whitespaces).isEmpty { return "Give this VPN a name first." }
        if let p = draft.serverProblem { return p }
        return nil
    }

    var body: some View {
        Form {
            // Canonical group order (AGENTS.md "Config surfaces"):
            // Connection → Sign-In → Traffic → Security → Advanced.
            Section("Connection") {
                TextField("Name", text: $draft.name)
                Picker("Protocol", selection: $draft.kind) {
                    Text("IKEv2").tag(VPNKind.ikev2)
                    Text("IPsec (IKEv1)").tag(VPNKind.ipsec)
                    Text("L2TP / IPsec").tag(VPNKind.l2tp)
                }
                .onChange(of: draft.kind) {
                    // IPsec has no certificate path (no identity picker/import
                    // exists), so it's always the shared-secret mode — keep
                    // the model honest even though connect() no longer trusts
                    // this flag for IPsec either.
                    if draft.kind == .ipsec { draft.usesSharedSecret = true }
                }
                TextField("Server address", text: $draft.server, prompt: Text("vpn.example.com"))
                    .autocorrectionDisabled()
                    // Validation rides the field's value (Docs/Accessibility.md).
                    .accessibilityValue(serverProblem.map { "\(draft.server). Problem: \($0)" } ?? draft.server)
                if let p = serverProblem {
                    Label(p, systemImage: "exclamationmark.triangle.fill")
                        .font(.callout).foregroundStyle(.orange)
                        .accessibilityLabel("Problem: \(p)")
                }
                if draft.kind == .ikev2 {
                    TextField("Remote identifier (optional)", text: $draft.remoteID,
                              prompt: Text("defaults to the server address"))
                }
                if draft.kind == .ipsec {
                    TextField("Group / local identifier (optional)", text: $draft.groupOrRealm)
                }
                if draft.kind != .l2tp {
                    // The rule installed is a bare NEOnDemandRuleConnect() — no
                    // SSID, domain or interface conditions exist anywhere in this
                    // app, so say what it really does rather than let "on demand"
                    // imply a condition list the user could have set.
                    Toggle("Connect on demand", isOn: $draft.onDemand)
                        .help("Reconnects this VPN whenever any app opens a network connection. There are no per-network conditions — it applies on every network.")
                        .accessibilityValue(draft.onDemand
                            ? "on — reconnects whenever any app opens a network connection, on every network"
                            : "off")
                }
            }

            if draft.kind == .l2tp {
                l2tpSection
            } else {
                authSection
                trafficSection
                if draft.kind == .ikev2 { securitySection }
                advancedSection
                controlSection
                CustomRoutingTabView(vpn: vpn, profileID: draft.id, profile: $customRouting,
                                    proxyAuthUsername: $crProxyAuthUsername,
                                    proxyAuthPassword: $crProxyAuthPassword,
                                    kind: draft.kind)
            }
        }
        .formStyle(.grouped)
        .disabled(ManagedPolicy.lockConfiguration)
        .navigationTitle(draft.name)
        .task { loadOnce() }
        .toolbar {
            ToolbarItem(placement: .confirmationAction) {
                Button("Save") { save() }
                    .disabled(saveDisabledReason != nil)
                    // A dead Save must say why — hover AND VoiceOver.
                    .help(saveDisabledReason ?? "Save changes to this VPN")
                    .accessibilityValue(saveDisabledReason.map { "unavailable — \($0)" } ?? "")
            }
        }
    }

    @ViewBuilder private var authSection: some View {
        Section {
            if draft.kind == .ipsec {
                // No certificate/identity path exists (no picker, no import),
                // so IPsec always authenticates with a shared secret — the
                // Cisco-style group PSK, optionally paired with an XAuth
                // username/password (exactly what a .pcf import produces).
                SecureField("Shared secret (group PSK)", text: $sharedSecret)
                // There was no way to say "no XAuth": a username left behind by
                // an import kept extended authentication on with nothing to send.
                Toggle("Also sign in with a username and password (XAuth)", isOn: xauthBinding)
                    .help("Some concentrators want the group secret alone; others want a personal username and password as well. Turn this off and neither is sent.")
                let xauthOff: String? = draft.usesXAuth ? nil
                    : "Turn on \u{201C}Also sign in with a username and password (XAuth)\u{201D} to use these."
                TextField("Username (XAuth)", text: $draft.username).textContentType(.username)
                    .disabled(xauthOff != nil)
                    .help(xauthOff ?? "The personal username this concentrator expects.")
                    .accessibilityLabel("XAuth username")
                    .accessibilityValue(xauthOff.map { "unavailable — \($0)" } ?? draft.username)
                SecureField("Password (XAuth)", text: $secret)
                    .disabled(xauthOff != nil)
                    .help(xauthOff ?? "The personal password this concentrator expects.")
                    .accessibilityLabel("XAuth password")
                    .accessibilityValue(xauthOff.map { "unavailable — \($0)" } ?? "")
                if let xauthOff {
                    Text(xauthOff).font(.callout).foregroundStyle(.secondary)
                        .fixedSize(horizontal: false, vertical: true)
                }
            } else {
                Toggle("Use a shared secret (PSK)", isOn: $draft.usesSharedSecret)
                if !draft.usesSharedSecret {
                    TextField("Username", text: $draft.username).textContentType(.username)
                }
                SecureField(draft.usesSharedSecret ? "Shared secret" : "Password", text: $secret)
            }
        } header: {
            Text("Sign-In")
        } footer: {
            if draft.kind == .ipsec {
                Text("Certificate authentication isn't supported in this build — IPsec always uses a shared secret.")
            }
        }
    }

    /// The XAuth answer. `nil` in the model means "never asked", which reads as
    /// the old behaviour (on when a username exists) — writing through it records
    /// the explicit choice, so the answer stops depending on a leftover username.
    private var xauthBinding: Binding<Bool> {
        Binding(get: { draft.usesXAuth }, set: { draft.xauth = $0 })
    }

    @ViewBuilder private var trafficSection: some View {
        Section("Traffic") {
            EngineSettingRow(spec: Self.specs["native.include-all"], changed: draft.includeAllNetworks) {
                Toggle(isOn: $draft.includeAllNetworks) { EngineSettingLabel(spec: Self.specs["native.include-all"], changed: draft.includeAllNetworks) }
            }
            if draft.includeAllNetworks {
                EngineSettingRow(spec: Self.specs["native.exclude-local"], changed: !draft.excludeLocalNetworks) {
                    Toggle(isOn: $draft.excludeLocalNetworks) { EngineSettingLabel(spec: Self.specs["native.exclude-local"], changed: !draft.excludeLocalNetworks) }
                }
            }
        }
    }

    /// IKEv2 only — the crypto knobs macOS exposes.
    @ViewBuilder private var securitySection: some View {
        Section("Security") {
            enumRow("native.encryption", $draft.ikeEncryption, [
                ("", "Automatic"), ("aes256gcm", "AES-256-GCM"), ("aes128gcm", "AES-128-GCM"),
                ("aes256", "AES-256-CBC"), ("aes128", "AES-128-CBC"), ("chacha20poly1305", "ChaCha20-Poly1305")])
            enumRow("native.integrity", $draft.ikeIntegrity, [
                ("", "Automatic"), ("sha256", "SHA2-256"), ("sha384", "SHA2-384"), ("sha512", "SHA2-512")])
            enumRow("native.dh-group", $draft.ikeDHGroup, [
                ("", "Automatic"), ("14", "Group 14 (2048-bit)"), ("15", "Group 15 (3072-bit)"),
                ("16", "Group 16 (4096-bit)"), ("19", "Group 19 (P-256)"), ("20", "Group 20 (P-384)"),
                ("21", "Group 21 (P-521)"), ("31", "Group 31 (Curve25519)")])
            EngineSettingRow(spec: Self.specs["native.pfs"], changed: draft.enablePFS) {
                Toggle(isOn: $draft.enablePFS) { EngineSettingLabel(spec: Self.specs["native.pfs"], changed: draft.enablePFS) }
            }
            // Apple's API has no "enable PFS" bit: PFS is whether the data channel
            // gets its OWN Diffie-Hellman group, and it borrows the picker's. On
            // Automatic there is nothing to borrow, so the code picks Group 14 —
            // a real choice the picker doesn't show, hence a caveat.
            if draft.enablePFS && draft.ikeDHGroup.isEmpty {
                SettingCaveat("With the Diffie-Hellman Group above on Automatic, the data channel rekeys with Group 14 (2048-bit) — Automatic can't be honoured for it. Choose a group above to use that one instead.")
            }
            // The model has always applied this to BOTH security associations —
            // there was simply no control for it anywhere, so an imported value
            // (or one set by a future MDM key) could not be seen or changed.
            EngineSettingRow(spec: Self.specs["native.ike-lifetime"], changed: draft.ikeLifetimeMinutes != nil) {
                ValidatedNumberField(
                    label: { EngineSettingLabel(spec: Self.specs["native.ike-lifetime"],
                                                changed: draft.ikeLifetimeMinutes != nil) },
                    prompt: "60",
                    value: $draft.ikeLifetimeMinutes,
                    range: NativeVPNConfig.ikeLifetimeRange,
                    invalidMessage: "Enter a lifetime between 10 and 1440 minutes. Leave empty to keep macOS's own (60 minutes, or 30 for the data channel).")
            }
        }
    }

    @ViewBuilder private var advancedSection: some View {
        Section("Advanced") {
            if draft.kind == .ikev2 {
                // "Automatic", not "Default": "" now genuinely leaves the OS
                // value untouched (it used to be applied as .medium, so the
                // picker's first option named a state it didn't produce).
                enumRow("native.dpd", $draft.deadPeerDetection, [
                    ("", "Automatic"), ("none", "Off"), ("low", "Low"), ("medium", "Medium"), ("high", "High")])
                EngineSettingRow(spec: Self.specs["native.mobike"], changed: draft.disableMOBIKE) {
                    Toggle(isOn: $draft.disableMOBIKE) { EngineSettingLabel(spec: Self.specs["native.mobike"], changed: draft.disableMOBIKE) }
                }
            }
            EngineSettingRow(spec: Self.specs["native.disconnect-sleep"], changed: draft.disconnectOnSleep) {
                Toggle(isOn: $draft.disconnectOnSleep) { EngineSettingLabel(spec: Self.specs["native.disconnect-sleep"], changed: draft.disconnectOnSleep) }
            }
        }
    }

    static let specs = EngineSettingCatalog([
        .init(id: "native.encryption", name: "Encryption",
              summary: "The cipher for the IKE/child security associations. Leave Automatic unless your admin specifies one; AES-256-GCM is a strong modern default."),
        .init(id: "native.integrity", name: "Integrity / PRF",
              summary: "The hash protecting message integrity. Automatic is fine for most servers."),
        .init(id: "native.dh-group", name: "Diffie-Hellman Group",
              summary: "The key-exchange group. Higher numbers are stronger; 19–21 are elliptic-curve. Must match what the server offers."),
        .init(id: "native.dpd", name: "Dead Peer Detection",
              summary: "How aggressively to probe whether the server is still there, to notice a dropped tunnel. Higher = faster detection, more chatter. Automatic leaves macOS's own choice (every 10 minutes) untouched."),
        .init(id: "native.ike-lifetime", name: "Key Lifetime (minutes)",
              summary: "How long each key lasts before the tunnel negotiates a fresh one, 10–1440. Leave empty for macOS's own (60 minutes, or 30 for the data channel); set it only if your admin specifies a value."),
        .init(id: "native.pfs", name: "Perfect Forward Secrecy",
              summary: "Rekey the data channel with a fresh key exchange so a stolen key can't decrypt past traffic. Enable if the server requires it."),
        .init(id: "native.mobike", name: "Disable MOBIKE",
              summary: "MOBIKE lets the tunnel survive network changes (Wi-Fi ↔ Ethernet). Only disable it if a picky server misbehaves with it on."),
        .init(id: "native.include-all", name: "Send All Traffic",
              summary: "Route everything through the VPN (full tunnel). Off means only the server's routes go through it."),
        .init(id: "native.exclude-local", name: "Allow Local Network Access",
              summary: "While sending all traffic through the VPN, still let your local network (printers, file shares) stay reachable."),
        .init(id: "native.disconnect-sleep", name: "Disconnect on Sleep",
              summary: "Drop the VPN when the Mac sleeps instead of resuming it on wake. Off keeps it up across sleep."),
    ])

    private func enumRow(_ id: String, _ binding: Binding<String>, _ options: [(String, String)]) -> some View {
        EngineSettingRow(spec: Self.specs[id], changed: !binding.wrappedValue.isEmpty) {
            Picker(selection: binding) {
                ForEach(options, id: \.0) { Text($0.1).tag($0.0) }
            } label: { EngineSettingLabel(spec: Self.specs[id], changed: !binding.wrappedValue.isEmpty) }
        }
    }

    @ViewBuilder private var controlSection: some View {
        Section {
            if manager.needsEntitlement {
                Label("Native VPN needs the Personal VPN capability on this build's signing profile. Everything else works; ask to have it provisioned.",
                      systemImage: "exclamationmark.triangle.fill")
                    .font(.callout).foregroundStyle(.orange)
            }
            HStack {
                nativeStatus
                Spacer()
                if isActive {
                    Button("Disconnect") { manager.disconnect() }.buttonStyle(.bordered).tint(.red)
                } else {
                    Button("Connect") {
                        save()
                        let proxy = nativeProxySettings()
                        Task { await manager.connect(draft, secret: secret, sharedSecret: sharedSecret, proxy: proxy) }
                    }
                        .buttonStyle(.glassProminent)   // primary "go" — consistent with OpenVPN Connect
                        .disabled(missingFieldCaption != nil)
                        // macOS keeps ONE app-managed personal VPN, so connecting
                        // here tears down whichever native VPN is up. The footer
                        // said so generically; the button names the casualty.
                        .help(connectHelp)
                        .accessibilityValue([replacesActiveVPNCaption, missingFieldCaption]
                                                .compactMap { $0 }.joined(separator: " "))
                }
            }
            if !isActive, let caption = missingFieldCaption {
                Text(caption).font(.caption).foregroundStyle(.secondary)
            }
            if !isActive, let caption = replacesActiveVPNCaption {
                Text(caption).font(.caption).foregroundStyle(.secondary)
            }
            if let err = manager.lastError {
                Label(err, systemImage: "xmark.circle.fill")
                    .font(.callout).foregroundStyle(.red)
                    .accessibilityLabel("Error: \(err)")
            }
            Text("macOS runs one app-managed personal VPN at a time — connecting this one replaces any other native VPN this app started.")
                .font(.caption).foregroundStyle(.secondary)
        }
    }

    @ViewBuilder private var nativeStatus: some View {
        switch manager.status {
        case .connected where isActive: Label("Connected", systemImage: "checkmark.circle.fill").foregroundStyle(.green)
        case .connecting where isActive:
            HStack(spacing: 6) { ProgressView().controlSize(.small).accessibilityHidden(true); Text("Connecting…") }
                .accessibilityElement(children: .combine)
        default: Label("Disconnected", systemImage: "circle").foregroundStyle(.secondary)
        }
    }

    @ViewBuilder private var l2tpSection: some View {
        Section("Sign-In") {
            TextField("Username", text: $draft.username).textContentType(.username)
            // L2TP needs BOTH: a user password for PPP and the IPSec shared
            // secret. There was no password field at all, so every exported
            // profile wrote AuthName with no AuthPassword and prompted at connect.
            SecureField("Password", text: $pppPassword)
                .accessibilityLabel("L2TP password")
            Text("Your personal password for this VPN. Stored in your Keychain and written into the exported profile, so connecting doesn't ask again. Clear it to remove both.")
                .font(.callout).foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
            SecureField("Shared secret", text: $secret)
                .accessibilityLabel("L2TP shared secret")
            Text("The IPSec shared secret (sometimes called the pre-shared key or machine secret) — the same one for everyone using this VPN.")
                .font(.callout).foregroundStyle(.secondary)
                .fixedSize(horizontal: false, vertical: true)
        }
        Section {
            Button("Export Configuration Profile…") { exportMobileconfig() }
                .disabled(l2tpExportDisabledReason != nil)
                // A dead export must say why on the control, not only in the footer.
                .help(l2tpExportDisabledReason
                      ?? "Write a .mobileconfig you double-click to install this VPN in System Settings.")
                .accessibilityValue(l2tpExportDisabledReason.map { "unavailable — \($0)" } ?? "")
        } header: {
            Text("Configuration Profile")
        } footer: {
            VStack(alignment: .leading, spacing: 6) {
                Text("macOS has no programmatic L2TP API for apps. SimpleVPN writes a standard .mobileconfig you double-click to install; it then appears in System Settings ▸ VPN.")
                // Switching to L2TP doesn't just hide the crypto/DPD/MOBIKE/PFS,
                // traffic and on-demand rows — the exported profile carries none
                // of them either, so anything configured under IKEv2/IPsec is
                // silently dropped. That has to be stated where it happens.
                Label("Only the fields above are exported. Encryption, integrity, Diffie-Hellman group, key lifetime, dead peer detection, MOBIKE, Perfect Forward Secrecy, Send All Traffic, local network access, disconnect on sleep, Connect on demand and Custom Routing are NOT part of an L2TP configuration profile — anything you set for IKEv2 or IPsec is kept, but not used here. Configure those in System Settings after installing, if the profile needs them.",
                      systemImage: "exclamationmark.triangle.fill")
                    .foregroundStyle(.orange)
                    .fixedSize(horizontal: false, vertical: true)
                if let reason = l2tpExportDisabledReason {
                    Text(reason)
                }
            }
        }
    }

    /// Why the L2TP export is unavailable, in the user's language, or nil.
    private var l2tpExportDisabledReason: String? {
        if let p = draft.serverProblem { return p }
        if secret.isEmpty { return "Enter the shared secret before exporting — the profile needs it to configure IPSec." }
        return nil
    }

    private func loadOnce() {
        guard !loaded else { return }
        loaded = true
        if draft.kind == .ipsec { draft.usesSharedSecret = true }   // no cert path — always PSK
        let base = KeychainCredentialStore.loadCredentials(profile: NativeVPNSecrets.baseProfile(draft.id))
        secret = base?.password ?? ""
        if draft.kind == .l2tp {
            pppPassword = KeychainCredentialStore.loadCredentials(
                profile: NativeVPNSecrets.pppPasswordProfile(draft.id))?.password ?? ""
        }
        customRouting = vpn.customRouting(for: draft.id)
        (crProxyAuthUsername, crProxyAuthPassword) = loadCustomRoutingProxyAuthFields(profileID: draft.id)
        guard draft.kind == .ipsec else { return }
        if let group = KeychainCredentialStore.loadCredentials(profile: NativeVPNSecrets.groupPSKProfile(draft.id)) {
            sharedSecret = group.password
        } else if !secret.isEmpty {
            // Backward compat: earlier builds (and the Cisco .pcf importer,
            // ManageVPNsView.importCiscoText) stored the IPsec group PSK in
            // this same base slot, with no separate XAuth password field to
            // conflict with. Migrate it into the new shared-secret field so
            // existing saved configs keep working without re-entry.
            sharedSecret = secret
            secret = ""
        }
    }

    /// The user's Custom Routing proxy as the native VPN's `NEProxySettings` — for these
    /// kinds the app is the applier, at connect (NEVPNManager carries the proxy in the
    /// VPN configuration; the OS applies it while the tunnel is up). The sign-in comes
    /// from the keychain-backed fields (the CURRENT draft, not a possibly-racing
    /// keychain read — Connect calls save() the same instant); the stored config only
    /// ever carries the ref.
    private func nativeProxySettings() -> NEProxySettings? {
        customRouting.proxy.nativeApplyRequest(
            username: crProxyAuthUsername.isEmpty ? nil : crProxyAuthUsername,
            password: crProxyAuthPassword.isEmpty ? nil : crProxyAuthPassword)?
            .makeNEProxySettings()
    }

    private func save() {
        if draft.kind == .ipsec { draft.usesSharedSecret = true }
        manager.save(draft)
        // Emptying a secret field REMOVES the stored secret (SubprocessTunnelView's
        // rule for every one of its secrets): writing only when non-empty left the
        // previous password in the keychain, so the next Connect still signed in
        // with a password the user believed they had deleted.
        NativeVPNSecrets.apply(
            NativeVPNSecrets.plan(kind: draft.kind, secret: secret, sharedSecret: sharedSecret,
                                  pppPassword: pppPassword, xauth: draft.usesXAuth),
            id: draft.id, username: draft.username)
        // save() is synchronous (called inline from several button actions, incl.
        // Export), so the commit runs in the background — harmless since it's
        // idempotent and CustomRoutingTabView's own onDisappear covers "left before
        // this finished" too.
        let id = draft.id
        let user = crProxyAuthUsername, pass = crProxyAuthPassword
        let toCommit = customRouting
        Task { @MainActor in
            customRouting = await commitCustomRouting(vpn, profileID: id, profile: toCommit,
                                                      proxyAuthUsername: user, proxyAuthPassword: pass)
        }
    }

    private func exportMobileconfig() {
        save()
        let panel = NSSavePanel()
        panel.nameFieldStringValue = "\(draft.name).mobileconfig"
        panel.allowedContentTypes = [.init(filenameExtension: "mobileconfig") ?? .data]
        guard panel.runModal() == .OK, let url = panel.url else { return }
        try? NativeVPNProfile.l2tpMobileconfig(draft, secret: secret, pppPassword: pppPassword)
            .write(to: url, atomically: true, encoding: .utf8)
    }
}

/// Minimal, valid L2TP-over-IPsec .mobileconfig generator (PPP + IPSec payload).
enum NativeVPNProfile {
    /// Escapes the five XML-significant characters. Every interpolated string
    /// below is attacker/user-controlled (profile name, username, server) —
    /// unescaped, a name like `Foo</string><key>Bad`  would break out of its
    /// element and corrupt (or inject into) the generated plist. The base64
    /// secret needs no escaping (its alphabet is `[A-Za-z0-9+/=]`).
    private static func xmlEscaped(_ s: String) -> String {
        s.replacingOccurrences(of: "&", with: "&amp;")
         .replacingOccurrences(of: "<", with: "&lt;")
         .replacingOccurrences(of: ">", with: "&gt;")
         .replacingOccurrences(of: "\"", with: "&quot;")
         .replacingOccurrences(of: "'", with: "&apos;")
    }

    /// `pppPassword` is the L2TP user (PPP) password. It rides `PPP.AuthPassword`
    /// — the generator wrote `AuthName` with no password at all, so EVERY
    /// exported profile prompted at connect, which reads as a broken export.
    /// Emitted ONLY when set: an empty `AuthPassword` is an empty-password
    /// attempt, not "ask me".
    static func l2tpMobileconfig(_ c: NativeVPNConfig, secret: String,
                                 pppPassword: String = "") -> String {
        let uuid = UUID().uuidString
        let payloadUUID = UUID().uuidString
        let name = xmlEscaped(c.name)
        let username = xmlEscaped(c.username)
        let server = xmlEscaped(c.server)
        // User-controlled text (unlike the base64 shared secret), so it goes
        // through the same escaping as every other interpolation here.
        let authPassword = pppPassword.isEmpty ? ""
            : "\n      <key>AuthPassword</key><string>\(xmlEscaped(pppPassword))</string>"
        return """
        <?xml version="1.0" encoding="UTF-8"?>
        <!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
        <plist version="1.0"><dict>
          <key>PayloadDisplayName</key><string>\(name)</string>
          <key>PayloadIdentifier</key><string>com.bragi0.SimpleVPN.\(uuid)</string>
          <key>PayloadType</key><string>Configuration</string>
          <key>PayloadUUID</key><string>\(uuid)</string>
          <key>PayloadVersion</key><integer>1</integer>
          <key>PayloadContent</key><array><dict>
            <key>PayloadType</key><string>com.apple.vpn.managed</string>
            <key>PayloadIdentifier</key><string>com.bragi0.SimpleVPN.vpn.\(payloadUUID)</string>
            <key>PayloadUUID</key><string>\(payloadUUID)</string>
            <key>PayloadVersion</key><integer>1</integer>
            <key>UserDefinedName</key><string>\(name)</string>
            <key>VPNType</key><string>L2TP</string>
            <key>PPP</key><dict>
              <key>AuthName</key><string>\(username)</string>\(authPassword)
              <key>CommRemoteAddress</key><string>\(server)</string>
            </dict>
            <key>IPSec</key><dict>
              <key>AuthenticationMethod</key><string>SharedSecret</string>
              <key>SharedSecret</key><data>\(Data(secret.utf8).base64EncodedString())</data>
            </dict>
          </dict></array>
        </dict></plist>
        """
    }
}
