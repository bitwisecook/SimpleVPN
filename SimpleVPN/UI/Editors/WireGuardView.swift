// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
//  WireGuardView.swift
//  Import / edit / export a WireGuard configuration. A WireGuard VPN is an
//  ordinary packet-tunnel profile (the wireguard-go engine runs in-process in
//  the extension — VPNController+WireGuard.swift owns the settings blob and
//  connect flow); this editor is a structured view over the wg-quick fields.
//  The private key is kept in the keychain, never shown, and never persisted
//  through providerConfiguration.
//

import SwiftUI
import UniformTypeIdentifiers

struct WireGuardView: View {
    let vpn: VPNController
    let profileID: String
    @State private var draft = WireGuardConfig()

    @State private var loaded = false
    @State private var showImporter = false
    @State private var pasteText = ""
    @State private var showPaste = false
    @FocusState private var pasteFocused: Bool
    @State private var customRouting = CustomRoutingProfile()
    @State private var crProxyAuthUsername = ""
    @State private var crProxyAuthPassword = ""
    /// Write-only entry: a private key typed/pasted here replaces the stored
    /// one on Save, but the field itself never shows the value already in the
    /// keychain — the same "set it, never reveal it" convention as any
    /// password field.
    @State private var newPrivateKey = ""
    /// Same write-only entry for the pre-shared key. It IS key material — a
    /// symmetric secret kept in the keychain (WireGuard's post-quantum extra) —
    /// so it gets the private key's treatment exactly: the row says whether one
    /// is stored, and the value is never rendered.
    @State private var newPresharedKey = ""
    /// Set by "Remove": clears the stored pre-shared key on Save. A write-only
    /// field can only ever REPLACE a secret, and this one is optional — without
    /// this a user could never take it off again (and clearing must really
    /// clear, not leave the old key in the keychain and in use).
    @State private var removePresharedKey = false
    /// The saved-confirmation affordance every editor's primary action now has —
    /// three of six used to save with no visible acknowledgement at all.
    @State private var savedTick = false

    /// Which tab is showing. A binding, so a related-settings link or a search
    /// hit on the Custom Routing tab can select it (no TabView in the app could
    /// be selected in code before this).
    @State private var tab: SettingsTab = .settings
    /// This editor's search catalog: its own surface plus Custom Routing, which
    /// is its second tab — one field finds everything this editor shows.
    @State private var search = SettingsSearch(surfaces: [.wireGuard, .customRouting],
                                               kind: .wireGuard)

    /// The config surface: the canonical groups, in order (AGENTS.md "Config
    /// surfaces"). No Security group — WireGuard's cryptography is fixed by
    /// design, so there is nothing to choose and the group is omitted.
    private var configForm: some View {
        Form {
            SettingsSearchSection(search: search)
            Section("Connection") {
                TextField("Name", text: $draft.name)
                HStack {
                    Button("Import .conf…") { showImporter = true }
                    Button("Paste Configuration…") { pasteText = ""; showPaste = true }
                }
                EngineSettingRow(spec: Self.specs["wg.endpoint"], value: draft.endpoint) {
                    textField(Self.specs["wg.endpoint"], $draft.endpoint, prompt: "host:51820",
                              problem: endpointProblem)
                }
                problemLabel(endpointProblem)
                EngineSettingRow(spec: Self.specs["wg.listen-port"], value: draft.listenPort) {
                    ValidatedNumberField(
                        label: { EngineSettingLabel(spec: Self.specs["wg.listen-port"], value: draft.listenPort) },
                        prompt: "auto",
                        value: $draft.listenPort,
                        range: WireGuardConfig.listenPortRange,
                        invalidMessage: "Enter a port between 0 and 65535 — 0 lets the system choose one.")
                }
                if let port = draft.listenPort, WireGuardConfig.privilegedPortRange.contains(port) {
                    SettingCaveat("Ports below 1024 are reserved for system services, so \(port) can collide with something already on this Mac — and few networks forward it. WireGuard's own port is 51820; leave this empty to let the system choose.")
                }
            }

            Section("Sign-In") {
                // Descriptor-backed like every other row: the summary, the manual
                // link and the a11y contract come from the spec, so the field the
                // whole VPN depends on is finally findable and documented.
                EngineSettingRow(spec: Self.specs["wg.private-key"], value: hasPrivateKey) {
                    privateKeyRows
                }
                problemLabel(privateKeyProblem)
                EngineSettingRow(spec: Self.specs["wg.public-key"], value: draft.peerPublicKey) {
                    monoField(Self.specs["wg.public-key"], $draft.peerPublicKey, prompt: "base64 public key",
                              problem: publicKeyProblem)
                }
                problemLabel(publicKeyProblem)
                EngineSettingRow(spec: Self.specs["wg.preshared-key"], value: hasPresharedKey) {
                    presharedKeyRows
                }
                problemLabel(presharedKeyProblem)
            }

            Section("Traffic") {
                EngineSettingRow(spec: Self.specs["wg.address"], value: draft.addresses) {
                    listField(Self.specs["wg.address"], $draft.addresses, prompt: "10.0.0.2/32",
                              problem: addressProblem)
                }
                problemLabel(addressProblem)
                EngineSettingRow(spec: Self.specs["wg.allowed-ips"], value: draft.allowedIPs) {
                    listField(Self.specs["wg.allowed-ips"], $draft.allowedIPs, prompt: "0.0.0.0/0",
                              problem: allowedIPsProblem)
                }
                problemLabel(allowedIPsProblem)
                if draft.isFullTunnel {
                    // Says what the Custom Routing section further down can then
                    // actually act on: one default route, not a list of networks.
                    Label("Full tunnel — all traffic routes through this peer. The Custom Routing route rules below then apply to that single default route, not to individual networks.",
                          systemImage: "globe")
                        .font(.callout).foregroundStyle(.secondary)
                        .fixedSize(horizontal: false, vertical: true)
                }
                EngineSettingRow(spec: Self.specs["wg.dns"], value: draft.dns) {
                    listField(Self.specs["wg.dns"], $draft.dns, prompt: "1.1.1.1")
                }
                // One caveat per resolver the peer won't carry — the split-tunnel
                // footgun that shows up as "the VPN works but nothing resolves".
                ForEach(uncoveredDNS, id: \.self) { server in
                    SettingCaveat(WireGuardConfig.dnsCoverageWarning(server))
                }
                // ONE MTU control across every engine that has one (MTUField).
                EngineSettingRow(spec: Self.specs["wg.mtu"], value: draft.mtu) {
                    MTUField(spec: Self.specs["wg.mtu"], value: $draft.mtu,
                             range: WireGuardConfig.mtuRange, prompt: "1420",
                             invalidMessage: "Enter an MTU between \(WireGuardConfig.mtuRange.lowerBound) and \(WireGuardConfig.mtuRange.upperBound). Leave it empty for the engine's own 1420.")
                }
                // Below 1280 is LEGAL and sometimes the only thing that works
                // (PPPoE, double NAT) — a caveat, never a refusal.
                if let caveat = WireGuardConfig.mtuBelowIPv6MinimumCaveat(draft.mtu) {
                    SettingCaveat(caveat)
                }
                TrafficCrossLinks(gatewayNote: gatewayNote)
            }

            CollapsibleSettingsSection(group: .advanced, changedCount: advancedChangedCount) {
                EngineSettingRow(spec: Self.specs["wg.keepalive"], value: draft.persistentKeepalive) {
                    ValidatedNumberField(
                        label: { EngineSettingLabel(spec: Self.specs["wg.keepalive"], value: draft.persistentKeepalive) },
                        prompt: "off",
                        value: $draft.persistentKeepalive,
                        range: WireGuardConfig.keepaliveRange,
                        invalidMessage: "Enter a number of seconds between 0 and 65535 — 0 turns keepalives off, 25 is typical behind NAT.")
                }
                // Both are closed value sets, not free text: `Table` is
                // auto|off|<number> and `FwMark` is off|<uint32>. As TextFields
                // any typo round-tripped straight into an exported .conf that
                // wg-quick then refuses.
                EngineSettingRow(spec: Self.specs["wg.table"], value: draft.table) {
                    tableRow
                }
                // Not disabled: the value is honoured — in the EXPORTED file. What
                // it does there is turn the Allowed IPs above into documentation,
                // which is worth saying beside them.
                if draft.table.trimmingCharacters(in: .whitespaces).lowercased() == "off" {
                    SettingCaveat("In a configuration you export, \u{201C}off\u{201D} tells wg-quick to install no routes at all, so the Allowed IPs above route nothing there. SimpleVPN's own engine ignores this setting and still routes them.")
                }
                EngineSettingRow(spec: Self.specs["wg.fwmark"], value: draft.fwMark) {
                    fwMarkRow
                }
            } footer: {
                Text(Self.exportOnlyHelp)
            }

            Section {
                // The reason lived in the section footer, where a keyboard or
                // VoiceOver user reaching the button never met it. It belongs ON
                // the control (house rule: a dead control says why).
                Button("Export .conf…") { export() }
                    .disabled(exportDisabledReason != nil)
                    .help(exportDisabledReason
                          ?? "Write a standard wg-quick file for use with other WireGuard clients.")
                    .accessibilityValue(exportDisabledReason.map { "unavailable — \($0)" } ?? "")
            } footer: {
                Text(exportDisabledReason
                     ?? "Export produces a standard wg-quick file for use with other WireGuard clients.")
            }
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
                CustomRoutingTabView(vpn: vpn, profileID: profileID, profile: $customRouting,
                                    proxyAuthUsername: $crProxyAuthUsername,
                                    proxyAuthPassword: $crProxyAuthPassword)
            }
            .formStyle(.grouped)
            .revealsSettings()
            .disabled(ManagedPolicy.lockConfiguration)
            .tag(SettingsTab.customRouting)
            .tabItem { Label("Custom Routing", systemImage: "arrow.triangle.branch") }
        }
        .settingsEditor(search: search, tab: $tab,
                        surfaces: [.wireGuard, .customRouting], profileID: profileID)
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
                    // A dead Save must say why — hover AND VoiceOver (house rule).
                    .help(saveDisabledReason ?? "Save changes to this VPN")
                    .accessibilityValue(saveDisabledReason.map { "unavailable — \($0)" } ?? "")
            }
        }
        .fileImporter(isPresented: $showImporter,
                      allowedContentTypes: [UTType(filenameExtension: "conf") ?? .data, .data, .plainText]) { result in
            if case let .success(url) = result { importConf(url) }
        }
        .sheet(isPresented: $showPaste) { pasteSheet }
    }

    // MARK: Routing-table / firewall-mark rows (closed value sets, not free text)

    /// `Table` is `auto | off | <number> | <rt_tables name>`. A Picker over the two
    /// words plus a "Custom…" case, so the only reachable values are the ones
    /// wg-quick accepts — it was an unconstrained TextField.
    ///
    /// The custom case is TEXT, not a number: wg-quick hands anything that isn't
    /// `auto`/`off` to `ip route … table <value>`, which resolves NAMES out of
    /// `rt_tables`, so `Table = main` is valid and used to be blanked on save.
    @ViewBuilder private var tableRow: some View {
        let spec = Self.specs["wg.table"]
        let word = draft.table.trimmingCharacters(in: .whitespaces).lowercased()
        let isCustom = !draft.table.isEmpty && word != "auto" && word != "off"
        VStack(alignment: .leading, spacing: 6) {
            Picker(selection: Binding<String>(
                get: { isCustom ? "custom" : word },
                set: { choice in
                    switch choice {
                    case "custom": draft.table = tableNumberText.isEmpty ? "main" : tableNumberText
                    case "": draft.table = ""
                    default: draft.table = choice
                    }
                })) {
                Text("Not set — wg-quick's own default (auto)").tag("")
                Text("auto — install routes for the allowed IPs").tag("auto")
                Text("off — install no routes").tag("off")
                Text("Custom table…").tag("custom")
            } label: {
                EngineSettingLabel(spec: spec, value: draft.table)
            }
            .help(Self.exportOnlyHelp)
            if isCustom {
                LabeledContent("Table") {
                    // Assigning `tableNumberText` here is what makes the state
                    // below do its job: it was never written, so flipping to
                    // auto/off and back always came up empty.
                    TextField("main or 51820", text: Binding(
                        get: { draft.table },
                        set: { draft.table = $0; tableNumberText = $0 }))
                        .font(.callout.monospaced())
                        .multilineTextAlignment(.trailing)
                        .autocorrectionDisabled()
                        .accessibilityLabel("Routing table name or number")
                        .accessibilityValue(tableProblem.map { "\(draft.table). Problem: \($0)" } ?? draft.table)
                }
                .padding(.leading, 16)
                problemLabel(tableProblem)
            }
        }
    }

    /// The last value typed into the custom table field, so flipping to "Custom…"
    /// and back doesn't lose it.
    @State private var tableNumberText = ""

    /// Why this routing table isn't one wg-quick would take, or nil.
    private var tableProblem: String? { WireGuardConfig.tableProblem(draft.table) }

    /// `FwMark` is `off | <uint32>`, decimal or `0x…` hex — so it can't be a plain
    /// numeric field. A Picker for "off" plus a validated text case.
    @ViewBuilder private var fwMarkRow: some View {
        let spec = Self.specs["wg.fwmark"]
        let word = draft.fwMark.trimmingCharacters(in: .whitespaces).lowercased()
        let isCustom = !draft.fwMark.isEmpty && word != "off"
        VStack(alignment: .leading, spacing: 6) {
            Picker(selection: Binding<String>(
                get: { isCustom ? "custom" : word },
                set: { choice in
                    switch choice {
                    case "custom": draft.fwMark = "0x0"
                    case "": draft.fwMark = ""
                    default: draft.fwMark = choice
                    }
                })) {
                Text("Not set — wg-quick's own default (off)").tag("")
                Text("off — don't mark packets").tag("off")
                Text("Custom mark…").tag("custom")
            } label: {
                EngineSettingLabel(spec: spec, value: draft.fwMark)
            }
            .help(Self.exportOnlyHelp)
            if isCustom {
                LabeledContent("Mark") {
                    TextField("0x1234 or 4660", text: $draft.fwMark)
                        .font(.callout.monospaced())
                        .multilineTextAlignment(.trailing)
                        .autocorrectionDisabled()
                        .accessibilityLabel("Firewall mark value")
                        .accessibilityValue(fwMarkProblem.map { "\(draft.fwMark). Problem: \($0)" } ?? draft.fwMark)
                }
                .padding(.leading, 16)
                problemLabel(fwMarkProblem)
            }
        }
    }

    /// Why this firewall mark isn't one wg-quick would take, or nil.
    private var fwMarkProblem: String? {
        let s = draft.fwMark.trimmingCharacters(in: .whitespaces)
        if s.isEmpty || WireGuardConfig.isValidFwMark(s) { return nil }
        return "Enter a whole number up to 4294967295, in decimal or as 0x-prefixed hex — or choose \u{201C}off\u{201D} above."
    }

    /// Whether this VPN is carrying everything right now — the question the
    /// Traffic group answers only in theory. nil when it isn't connected.
    private var gatewayNote: String? {
        guard vpn.profiles.first(where: { $0.id == profileID })?.status == .connected else { return nil }
        return vpn.gatewayRole(for: profileID) == .full
            ? "Right now this VPN carries ALL traffic \u{2014} it owns the default route."
            : "Right now this VPN carries only the networks above \u{2014} something else owns the default route."
    }

    /// The Advanced badge count, from the specs' own declared defaults.
    private var advancedChangedCount: Int {
        [Self.specs["wg.keepalive"].isChanged(draft.persistentKeepalive),
         Self.specs["wg.table"].isChanged(draft.table),
         Self.specs["wg.fwmark"].isChanged(draft.fwMark)].count { $0 }
    }

    /// The paste sheet: focus lands in the editor so a keyboard user can ⌘V at
    /// once, ESC cancels, and Import is the default action (Return only fires
    /// it once focus leaves the editor — inside it, Return types a newline).
    private var pasteSheet: some View {
        VStack(spacing: 12) {
            Text("Paste WireGuard configuration").font(.headline)
            TextEditor(text: $pasteText).font(.callout.monospaced()).frame(width: 460, height: 260)
                .border(.quaternary)
                .focused($pasteFocused)
                .accessibilityLabel("WireGuard configuration text")
            HStack {
                Button("Cancel") { showPaste = false }
                    .keyboardShortcut(.cancelAction)
                Spacer()
                Button("Import") { applyParsed(pasteText); showPaste = false }
                    .buttonStyle(.glassProminent).disabled(pasteText.isEmpty)
                    .keyboardShortcut(.defaultAction)
            }
        }
        .padding()
        .onAppear { pasteFocused = true }
    }

    /// Status + write-only entry for the private key: the row says whether one is
    /// stored, and the value is never rendered (the "set it, never reveal it"
    /// convention every secret in this app follows).
    @ViewBuilder private var privateKeyRows: some View {
        VStack(alignment: .leading, spacing: 6) {
            LabeledContent {
                Text(hasPrivateKey ? "•••••• (in Keychain)" : "not set")
                    .foregroundStyle(.secondary)
            } label: {
                EngineSettingLabel(spec: Self.specs["wg.private-key"], value: hasPrivateKey)
            }
            LabeledContent("Set / Replace Key") {
                SecureField("paste base64 private key", text: $newPrivateKey)
                    .font(.callout.monospaced())
                    .multilineTextAlignment(.trailing)
                    .autocorrectionDisabled()
                    .accessibilityLabel("Set or replace the private key")
                    // Validation rides the field's value (Docs/Accessibility.md).
                    .accessibilityValue(privateKeyProblem.map { "Problem: \($0)" } ?? "")
            }
        }
    }

    // MARK: Pre-shared key (write-only, like the private key)

    /// Status + write-only entry for the pre-shared key. Never a plain
    /// TextField: rendering it would put a live symmetric key on screen (and in
    /// any screenshot) for a value nobody needs to read back.
    @ViewBuilder private var presharedKeyRows: some View {
        VStack(alignment: .leading, spacing: 6) {
            LabeledContent {
                HStack(spacing: 8) {
                    Text(presharedKeyStatus).foregroundStyle(.secondary)
                    if !draft.presharedKey.isEmpty, !removePresharedKey {
                        Button("Remove") { removePresharedKey = true; newPresharedKey = "" }
                            .controlSize(.small)
                            .accessibilityLabel("Remove pre-shared key")
                    }
                }
            } label: {
                EngineSettingLabel(spec: Self.specs["wg.preshared-key"], value: hasPresharedKey)
            }
            LabeledContent("Set / Replace Key") {
                SecureField("paste base64 pre-shared key", text: $newPresharedKey)
                    .font(.callout.monospaced())
                    .multilineTextAlignment(.trailing)
                    .autocorrectionDisabled()
                    .accessibilityLabel("Set or replace the pre-shared key")
                    // Validation rides the field's value (Docs/Accessibility.md).
                    .accessibilityValue(presharedKeyProblem.map { "Problem: \($0)" } ?? "")
                    // Typing a replacement cancels a pending removal — the last
                    // thing the user did is the thing that happens.
                    .onChange(of: newPresharedKey) {
                        if !newPresharedKey.isEmpty { removePresharedKey = false }
                    }
            }
        }
    }

    /// Whether a pre-shared key will be in use after Save.
    private var hasPresharedKey: Bool {
        !newPresharedKey.isEmpty || (!draft.presharedKey.isEmpty && !removePresharedKey)
    }

    private var presharedKeyStatus: String {
        if !newPresharedKey.isEmpty { return "•••••• (saved on Save)" }
        if removePresharedKey { return "removed on Save" }
        return draft.presharedKey.isEmpty ? "not set" : "•••••• (in Keychain)"
    }

    // MARK: Inline problems (the editor is where a bad value must surface)
    //
    // `Shared/WireGuardConfig.swift` carries the tested validators — the same
    // ones the connect gate and the Go engine's parseRoutes agree on. Every one
    // of them is shown against its own row, so a misconfiguration is a caption
    // under the field rather than a failed connect ten seconds later.

    private var endpointProblem: String? {
        draft.endpoint.isEmpty ? nil : WireGuardConfig.endpointProblem(draft.endpoint)
    }
    private var publicKeyProblem: String? {
        WireGuardConfig.keyProblem(draft.peerPublicKey)
    }
    /// Validates what the user TYPES. The stored key is never read back into the
    /// UI (write-only field), so there is nothing else here to check.
    private var privateKeyProblem: String? {
        WireGuardConfig.keyProblem(newPrivateKey)
    }
    private var presharedKeyProblem: String? {
        WireGuardConfig.keyProblem(newPresharedKey)
    }
    /// Interface addresses, NOT routes: `10.0.0.2/24` is a valid tunnel address,
    /// so the host-bit check that belongs on Allowed IPs must not run here.
    private var addressProblem: String? {
        draft.addresses.isEmpty ? nil : WireGuardConfig.addressesProblem(draft.addresses)
    }
    private var allowedIPsProblem: String? {
        draft.allowedIPs.isEmpty ? nil : WireGuardConfig.routesProblem(draft.allowedIPs)
    }
    /// Resolvers the peer's Allowed IPs don't cover — see
    /// `WireGuardConfig.dnsOutsideAllowedIPs` for why that breaks DNS silently.
    /// Only computed once both lists parse, so a half-typed CIDR doesn't shout.
    private var uncoveredDNS: [String] {
        guard allowedIPsProblem == nil else { return [] }
        return WireGuardConfig.dnsOutsideAllowedIPs(dns: draft.dns, allowedIPs: draft.allowedIPs)
    }

    /// Why Export is unavailable, in the user's language, or nil.
    private var exportDisabledReason: String? {
        if !hasPrivateKey { return "Set a private key above before exporting — wg-quick refuses a config without one." }
        if draft.peerPublicKey.trimmingCharacters(in: .whitespaces).isEmpty {
            return "Enter the peer public key above before exporting — wg-quick needs the server's key."
        }
        return nil
    }

    /// Why Save is unavailable, in the user's language, or nil when it can go.
    /// Was gated on an empty name alone, which let every validator above be
    /// written straight into providerConfiguration.
    private var saveDisabledReason: String? {
        if draft.name.trimmingCharacters(in: .whitespaces).isEmpty { return "Give this VPN a name first." }
        if let p = endpointProblem { return p }
        if let p = publicKeyProblem { return p }
        if let p = privateKeyProblem { return p }
        if let p = presharedKeyProblem { return p }
        if let p = addressProblem { return p }
        if let p = allowedIPsProblem { return p }
        // Both used to be absent here while `normalized()` quietly REWROTE them
        // on save (an out-of-range MTU became "engine default", an unrecognised
        // Table became "not set"). Blocking with the reason is the house rule; a
        // silent rewrite of a stored value never is.
        if let p = WireGuardConfig.mtuProblem(draft.mtu) { return p }
        if let p = tableProblem { return p }
        if let p = fwMarkProblem { return p }
        return nil
    }

    /// One amber caption for a field's problem, or nothing. Same shape as the
    /// control-URL problem in TailscaleView.
    @ViewBuilder private func problemLabel(_ problem: String?) -> some View {
        if let problem {
            Label(problem, systemImage: "exclamationmark.triangle.fill")
                .font(.callout).foregroundStyle(.orange)
                .accessibilityLabel("Problem: \(problem)")
        }
    }

    // MARK: Spec catalog + typed field helpers

    /// The catalog now lives in `ControlPlane/WireGuardSettingDescriptors.swift`
    /// (a catalog private to a View can only be searched by that View — which is
    /// why app-wide search needed every table out here). This alias keeps the
    /// form's call sites reading `Self.specs["wg.…"]`.
    static var specs: EngineSettingCatalog { WireGuardSettings.catalog }

    /// `wg.table` and `wg.fwmark` never reach our engine — `WireGuardStartConfig`
    /// has no such fields — so they only round-trip into an exported .conf. Said
    /// on the row rather than left to look effective.
    static let exportOnlyHelp =
        "Only applies to configurations you export for other WireGuard clients — SimpleVPN's own engine doesn't use it."

    private func textField(_ spec: EngineSettingSpec, _ binding: Binding<String>, prompt: String,
                           problem: String? = nil, help: String? = nil) -> some View {
        LabeledContent {
            TextField(prompt, text: binding).multilineTextAlignment(.trailing).autocorrectionDisabled()
                // The title is an EXAMPLE value — the spec name is the name.
                .accessibilityLabel(spec.name)
                // Validation rides the field's value (Docs/Accessibility.md).
                .accessibilityValue(problem.map { "\(binding.wrappedValue). Problem: \($0)" } ?? binding.wrappedValue)
                .help(help ?? spec.summary)
        } label: { EngineSettingLabel(spec: spec, value: binding.wrappedValue) }
    }
    private func monoField(_ spec: EngineSettingSpec, _ binding: Binding<String>, prompt: String,
                           problem: String? = nil) -> some View {
        LabeledContent {
            TextField(prompt, text: binding).font(.callout.monospaced()).multilineTextAlignment(.trailing).autocorrectionDisabled()
                .accessibilityLabel(spec.name)
                .accessibilityValue(problem.map { "Problem: \($0)" } ?? "")
        } label: { EngineSettingLabel(spec: spec, value: binding.wrappedValue) }
    }
    private func listField(_ spec: EngineSettingSpec, _ binding: Binding<[String]>, prompt: String,
                           problem: String? = nil) -> some View {
        LabeledContent {
            TextField(prompt, text: Binding(
                get: { binding.wrappedValue.joined(separator: ", ") },
                set: { binding.wrappedValue = $0.split(separator: ",").map { $0.trimmingCharacters(in: .whitespaces) }.filter { !$0.isEmpty } }))
                .multilineTextAlignment(.trailing).autocorrectionDisabled()
                .accessibilityLabel(spec.name)
                .accessibilityValue(problem.map { "\(binding.wrappedValue.joined(separator: ", ")). Problem: \($0)" }
                                    ?? binding.wrappedValue.joined(separator: ", "))
        } label: { EngineSettingLabel(spec: spec, value: binding.wrappedValue) }
    }

    /// Whether a private key is available for export — either already in the
    /// keychain (loaded into `draft` below) or freshly typed and not yet saved.
    private var hasPrivateKey: Bool { !draft.privateKey.isEmpty || !newPrivateKey.isEmpty }

    private func loadOnce() {
        guard !loaded else { return }
        loaded = true
        // The persisted blob is redacted; the keys come back from the keychain
        // (the "wg.<id>" item VPNController+WireGuard maintains) so the export
        // works and the private-key row can say "set".
        draft = vpn.wireGuardConfig(for: profileID).withSecretsFromKeychain()
        if draft.name.isEmpty { draft.name = vpn.displayName(for: profileID) }
        // Seed the remembered custom-table text from what is stored, so flipping
        // the picker to auto/off and back restores what was there.
        let word = draft.table.trimmingCharacters(in: .whitespaces).lowercased()
        if !draft.table.isEmpty, word != "auto", word != "off" { tableNumberText = draft.table }
        customRouting = vpn.customRouting(for: profileID)
        (crProxyAuthUsername, crProxyAuthPassword) = loadCustomRoutingProxyAuthFields(profileID: profileID)
    }

    private func importConf(_ url: URL) {
        let scoped = url.startAccessingSecurityScopedResource()
        defer { if scoped { url.stopAccessingSecurityScopedResource() } }
        guard let text = try? String(contentsOf: url, encoding: .utf8) else { return }
        applyParsed(text, name: url.deletingPathExtension().lastPathComponent)
    }

    private func applyParsed(_ text: String, name: String? = nil) {
        // An import REPLACES what the file carries and nothing else: a `.conf`
        // with no PresharedKey line is not "delete my pre-shared key". Replacing
        // the draft wholesale blanked both secrets, and save() then wrote the
        // blank pre-shared key over the stored one (see `applyingImport`).
        draft = draft.applyingImport(WireGuardConfig.parse(text, name: name ?? draft.name),
                                     name: name)
    }

    private func save() {
        // Captured BEFORE the fields are consumed: an explicit Remove is the only
        // thing that clears the stored pre-shared key.
        let removingPSK = removePresharedKey && newPresharedKey.isEmpty
        if !newPrivateKey.isEmpty {
            draft.privateKey = newPrivateKey
            newPrivateKey = ""
        }
        if !newPresharedKey.isEmpty {
            draft.presharedKey = newPresharedKey
            newPresharedKey = ""
        } else if removingPSK {
            draft.presharedKey = ""
        }
        removePresharedKey = false
        // The keys go to the keychain; only a redacted copy is persisted — the
        // same move on every save path. BOTH keys use the same nil convention
        // ("leave the stored one alone"): the pre-shared key used to be passed as
        // a plain value, so an import that carried no key destroyed it.
        vpn.setWireGuardSecrets(
            privateKey: draft.privateKey.isEmpty ? nil : draft.privateKey,
            presharedKey: WireGuardConfig.presharedKeyToSave(draft: draft.presharedKey,
                                                             removing: removingPSK),
            for: profileID)
        // Fire-and-forget: save() is called synchronously from a plain Button
        // action; both persists are idempotent, and CustomRoutingTabView's own
        // onDisappear covers the case where the view closes before this lands.
        let toSave = draft
        let user = crProxyAuthUsername, pass = crProxyAuthPassword
        let toCommit = customRouting
        Task { @MainActor in
            do { try await vpn.setWireGuardConfig(toSave, for: profileID) }
            catch { vpn.lastError = error.localizedDescription }
            customRouting = await commitCustomRouting(vpn, profileID: profileID, profile: toCommit,
                                                      proxyAuthUsername: user, proxyAuthPassword: pass)
        }
        // Acknowledge the save on the button, like every other editor.
        savedTick = true
        Task { @MainActor in
            try? await Task.sleep(for: .seconds(2))
            savedTick = false
        }
    }

    private func export() {
        let panel = NSSavePanel()
        panel.nameFieldStringValue = "\(draft.name).conf"
        panel.allowedContentTypes = [UTType(filenameExtension: "conf") ?? .data]
        guard panel.runModal() == .OK, let url = panel.url else { return }
        var toExport = draft
        if !newPrivateKey.isEmpty { toExport.privateKey = newPrivateKey }
        // Export what Save would store — including an unsaved replacement or
        // removal of the pre-shared key.
        if !newPresharedKey.isEmpty { toExport.presharedKey = newPresharedKey }
        else if removePresharedKey { toExport.presharedKey = "" }
        try? toExport.serialize().write(to: url, atomically: true, encoding: .utf8)
    }
}
