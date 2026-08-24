// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
//  OtherConnectionDetailView.swift
//  THE DETAIL PANE for the connections that are not NE profiles — the subprocess
//  tunnels (SSH and the seven OpenConnect SSL-VPNs) and the native personal VPNs.
//
//  WHY IT EXISTS. Until now these rows could not be selected in the connect list,
//  and were only LISTED while already running (see `ConnectionView`'s history) — so
//  a profile the user had just created could not be found, could not be selected,
//  and could not be connected from the window whose whole job is connecting. This
//  pane is the other half of fixing that: the row now selects, and what it selects
//  says what state the connection is in, what is stopping it, and takes you to the
//  field that fixes it.
//
//  DELIBERATELY SMALL. It is not `ConnectionDetailView` — there is no throughput
//  graph, map or inspector here, because there is no per-flow telemetry behind a
//  subprocess tunnel to draw. What it owns is exactly what the connect window is
//  for: the status, the one action, and the honest reason the action is dead.
//

import SwiftUI

// MARK: - The banner

/// WHAT IS MISSING, AND THE WAY TO IT. The banner the Q4 requirement asks for:
/// never hide a profile the user created — show it, disable the action, explain why,
/// and link to the exact place to fix it.
///
/// The sentence and the destination both come from `ConnectNeed`, which is derived
/// from the same rules the editor's own dead Connect button reads. So this cannot
/// drift into a second opinion about whether a VPN is configured — the divergence
/// that was just removed from the connect path.
///
/// COLOUR CARRIES THE DEGREE, not the whole message. Orange for "it cannot work as
/// set up" and the quieter accent for "it is set up and something has to be
/// supplied" — a missing password is an ordinary state, and dressing it as a fault
/// teaches people to ignore the orange triangle.
struct NotConfiguredBanner: View {
    let vpnName: String
    let need: ConnectNeed
    /// Take me to the field. nil when the need names no single setting (a tool that
    /// isn't installed), in which case no button is offered rather than a dead one.
    let reveal: (() -> Void)?
    /// Open this VPN's own settings — always available, because there is always
    /// somewhere to go even when no one field is at fault.
    let openSettings: () -> Void

    private var isHardProblem: Bool { need.readiness == .blocked }

    private var headline: String {
        isHardProblem ? "\(vpnName) can\u{2019}t connect as it\u{2019}s set up"
                      : "\(vpnName) needs one more thing before it can connect"
    }

    private var tint: Color { isHardProblem ? .orange : .accentColor }

    var body: some View {
        HStack(alignment: .top, spacing: 10) {
            Image(systemName: isHardProblem ? "exclamationmark.triangle.fill" : "pencil.and.list.clipboard")
                .font(.title3).foregroundStyle(tint)
                .accessibilityHidden(true)   // the combined label below says it
            VStack(alignment: .leading, spacing: 3) {
                Text(headline).font(.callout.weight(.semibold))
                Text(need.sentence)
                    .font(.callout).foregroundStyle(.secondary)
                    .fixedSize(horizontal: false, vertical: true)
            }
            Spacer(minLength: 8)
            VStack(spacing: 6) {
                if let reveal {
                    // "Take me to the empty field" — the strong version of the ask.
                    // `SettingReveal` expands the row's section, scrolls it to centre
                    // and highlights it, so this lands somewhere usable rather than
                    // merely opening a window.
                    Button("Fix This\u{2026}", action: reveal)
                        .buttonStyle(.glassProminent)
                        .help("Open the setting that\u{2019}s missing and highlight it")
                        .accessibilityLabel("Fix this")
                        .accessibilityHint("Opens this VPN\u{2019}s settings and highlights the setting that\u{2019}s missing")
                } else {
                    Button("Settings\u{2026}", action: openSettings)
                        .buttonStyle(.glassProminent)
                        .accessibilityLabel("Open \(vpnName) settings")
                }
            }
        }
        .bannerSurface(tint: tint)
        // `.contain`: the action must stay reachable (the accessibility rule the
        // other banners in this window follow).
        .accessibilityElement(children: .contain)
        .accessibilityLabel("\(headline). \(need.sentence)")
    }
}

// MARK: - The pane

struct OtherConnectionDetailView: View {
    let name: String
    let kind: VPNKind
    /// Where this connection is, in the ONE status vocabulary (`DotState`), so it
    /// cannot disagree with the sidebar dot or the menu bar.
    let dot: DotState
    let isActive: Bool
    /// What is still missing, or nil when a click connects.
    let need: ConnectNeed?
    /// Anything the engine said last time — a failure message or a caution.
    let engineNote: String?
    /// A password-capable tunnel can be completed here.  Configuration faults
    /// still use the normal precise-settings banner below.
    let inlineSignIn: AnyView?

    let connect: () -> Void
    let stop: () -> Void
    let reveal: (String) -> Void
    let openSettings: () -> Void

    private var maturity: MaturityNotice? { kind.maturityNotice }

    var body: some View {
        ScrollView {
            VStack(alignment: .leading, spacing: 16) {
                header
                // Never retain the pre-connect banner during an active session.
                // The readiness cache is based on saved credentials and can lag one
                // render behind a deliberately transient sign-in.
                if !isActive {
                    if let inlineSignIn {
                        inlineSignIn
                    } else if let need {
                        NotConfiguredBanner(
                            vpnName: name, need: need,
                            reveal: need.settingID.map { id in { reveal(id) } },
                            openSettings: openSettings)
                    }
                }
                if let engineNote {
                    Label(engineNote, systemImage: "exclamationmark.circle.fill")
                        .font(.callout).foregroundStyle(.orange)
                        .fixedSize(horizontal: false, vertical: true)
                        .accessibilityLabel("From the connection: \(engineNote)")
                }
                // A kind nobody has proven yet says so here as well as in the
                // sidebar chip: this is the screen somebody is looking at when they
                // decide whether to trust it (availability and maturity are two
                // different axes — ONTOLOGY.md).
                if let maturity {
                    MaturityBadge(notice: maturity)
                }
                Spacer(minLength: 0)
            }
            .padding(20)
            .frame(maxWidth: .infinity, alignment: .leading)
        }
        .navigationTitle(name)
    }

    @ViewBuilder private var header: some View {
        HStack(spacing: 12) {
            StatusDot(state: dot)
                .accessibilityHidden(true)   // spoken through the row below
            VStack(alignment: .leading, spacing: 2) {
                Text(name).font(.title2.weight(.semibold)).lineLimit(1)
                Text("\(kind.displayName) \u{00B7} \(dot.accessibilityDescription)")
                    .font(.callout).foregroundStyle(.secondary)
            }
            .accessibilityElement(children: .combine)
            .accessibilityLabel("\(name), \(kind.displayName), \(dot.accessibilityDescription)")
            Spacer(minLength: 12)
            action
        }
    }

    @ViewBuilder private var action: some View {
        if isActive {
            Button("Disconnect", action: stop)
                .buttonStyle(.bordered).tint(.red)
                // NAMED WITH THE CONNECTION, like the sidebar's per-row controls and
                // unlike the detail header of an NE profile. That difference is
                // load-bearing: `VPNCommands`' VPN ▸ Disconnect acts on the SELECTED
                // NE PROFILE and cannot stop a subprocess tunnel, so a bare
                // "Disconnect" here would claim the menu item's scope while meaning
                // something else (VoiceOverWalkthroughTests step 8 reads exactly that
                // distinction).
                .accessibilityLabel("Disconnect \(name)")
                .accessibilityValue(dot.accessibilityDescription)
        } else if inlineSignIn == nil {
            // DISABLED, NEVER ABSENT. An absent button is indistinguishable from a
            // broken layout — and the reason rides `.help` and the accessibility
            // value, so a dead control always says why (AGENTS.md rule 4).
            Button("Connect", action: connect)
                .buttonStyle(.glassProminent)
                .disabled(need != nil)
                .accessibilityLabel("Connect \(name)")
                .help(need?.sentence ?? "Connect \(name)")
                // The status word from the ONE vocabulary first, then the reason —
                // every Connect control in this window reports the live state in its
                // value, and `ConnectNeed.spokenValue` is the single place that
                // sentence is composed.
                .accessibilityValue(need?.spokenValue ?? dot.accessibilityDescription)
        }
    }
}

/// The small, direct sign-in surface for an OpenConnect password VPN in the main
/// window.  This is deliberately the same persistence contract as its full editor:
/// username and the *choice* to save are configuration, the base password is saved
/// only when requested, and a verification code belongs only to this attempt.
struct SubprocessTunnelInlineSignIn: View {
    let config: SubprocessTunnelConfig
    @Bindable var store: SubprocessTunnelStore
    @Bindable var manager: SubprocessTunnelManager

    @State private var username: String
    @State private var password: String
    @State private var rememberPassword: Bool
    @State private var requiresOneTimeCode: Bool
    @State private var oneTimeCode = ""
    @State private var discoveredForm: OCAuthFormSpec?
    @State private var isDiscoveringForm = false
    @State private var discoveryNote: String?

    init(config: SubprocessTunnelConfig, store: SubprocessTunnelStore,
         manager: SubprocessTunnelManager) {
        self.config = config
        self.store = store
        self.manager = manager
        let saved = KeychainCredentialStore.loadCredentials(profile: "tunnel.\(config.id)")
        _username = State(initialValue: config.username)
        _password = State(initialValue: saved?.password ?? "")
        _rememberPassword = State(initialValue: !(saved?.password ?? "").isEmpty)
        _requiresOneTimeCode = State(initialValue: config.needsOneTimeCode)
    }

    private var canConnect: Bool {
        !username.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty
            && !password.isEmpty
            && (!requiresOneTimeCode || !config.isOTPRequirementLocked
                || !oneTimeCode.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty)
    }

    private var missingExplanation: String? {
        if username.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty { return "Enter your username." }
        if password.isEmpty { return "Enter your password." }
        if requiresOneTimeCode, config.isOTPRequirementLocked,
           oneTimeCode.trimmingCharacters(in: .whitespacesAndNewlines).isEmpty {
            return "Enter the current verification code."
        }
        return nil
    }

    private var usernameLabel: String {
        discoveredForm?.fields.first(where: {
            $0.type == OCAuthFormField.Kind.text || $0.type == OCAuthFormField.Kind.ssoUser
        })?.label ?? "Username"
    }

    private var passwordLabel: String {
        discoveredForm?.fields.first(where: { $0.type == OCAuthFormField.Kind.password })?.label ?? "Password"
    }

    private var codeLabel: String {
        discoveredForm?.fields.first(where: { $0.type == OCAuthFormField.Kind.token })?.label
            ?? "Verification code"
    }

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            Label("Sign in to \(config.name)", systemImage: "person.badge.key.fill")
                .font(.headline)
            Text("Enter the details for this connection. A password is saved only when you turn on Save password.")
                .font(.callout).foregroundStyle(.secondary)
                .textSelection(.enabled)

            Grid(alignment: .leading, horizontalSpacing: 12, verticalSpacing: 10) {
                GridRow {
                    Text(usernameLabel).foregroundStyle(.secondary)
                    TextField(usernameLabel, text: $username)
                        .textContentType(.username)
                }
                GridRow {
                    Text(passwordLabel).foregroundStyle(.secondary)
                    SecureField(passwordLabel, text: $password)
                        .textContentType(.password)
                }
                if requiresOneTimeCode {
                    GridRow {
                        Text(codeLabel).foregroundStyle(.secondary)
                        TextField(codeLabel, text: $oneTimeCode)
                            .textContentType(.oneTimeCode)
                    }
                }
            }

            PasswordSavingToggle(isOn: $rememberPassword)
            if !config.isOTPRequirementLocked {
                Toggle("Verification code required", isOn: $requiresOneTimeCode)
                    .toggleStyle(.checkbox)
                Button(isDiscoveringForm ? "Checking sign-in fields…" : "Check sign-in fields") {
                    discoverSignInForm()
                }
                .disabled(isDiscoveringForm)
                .help("Ask the VPN gateway which sign-in fields it requires")
                Text("You can change this until the first successful sign-in. After that, Manage VPNs is where you change the confirmed setting.")
                    .font(.caption).foregroundStyle(.secondary)
                    .textSelection(.enabled)
            }
            if let discoveryNote {
                Text(discoveryNote).font(.caption).foregroundStyle(.secondary).textSelection(.enabled)
            }
            if requiresOneTimeCode {
                Text("The code is used once in the gateway’s separate verification-code field and is never saved.")
                    .font(.caption).foregroundStyle(.secondary)
                    .textSelection(.enabled)
            }
            HStack {
                Button("Connect", action: connect)
                    .buttonStyle(.glassProminent)
                    .disabled(!canConnect)
                    .help(missingExplanation ?? "Connect \(config.name)")
                Spacer()
            }
        }
        .bannerSurface(tint: .blue)
        .accessibilityElement(children: .contain)
        .accessibilityLabel("Sign in to \(config.name)")
        .onChange(of: manager.status(config.id)) { _, status in
            guard case .connected = status, !config.isOTPRequirementLocked else { return }
            var confirmed = config
            confirmed.username = username.trimmingCharacters(in: .whitespacesAndNewlines)
            confirmed.requiresOTP = requiresOneTimeCode ? true : nil
            confirmed.otpRequirementLocked = true
            store.save(confirmed)
        }
    }

    private func connect() {
        var revised = config
        revised.username = username.trimmingCharacters(in: .whitespacesAndNewlines)
        revised.requiresOTP = requiresOneTimeCode ? true : nil
        store.save(revised)

        if rememberPassword {
            try? KeychainCredentialStore.saveCredentials(
                profile: "tunnel.\(revised.id)",
                .init(username: revised.username, password: password))
        } else {
            KeychainCredentialStore.deleteCredentials(profile: "tunnel.\(revised.id)")
        }

        manager.connect(revised, password: password,
                        oneTimeCode: oneTimeCode.isEmpty ? nil : oneTimeCode)
        oneTimeCode = ""
    }

    private func discoverSignInForm() {
        isDiscoveringForm = true
        discoveryNote = nil
        Task {
            defer { isDiscoveringForm = false }
            do {
                let form = try await manager.discoverSignInForm(for: config)
                discoveredForm = form
                let hasCode = form.fields.contains { $0.type == OCAuthFormField.Kind.token }
                requiresOneTimeCode = hasCode
                var revised = config
                revised.requiresOTP = hasCode ? true : nil
                revised.otpRequirementLocked = nil
                store.save(revised)
                let labels = form.fields.map(\.label).joined(separator: ", ")
                discoveryNote = labels.isEmpty
                    ? "The gateway did not expose any fields before sign-in."
                    : "This gateway asks for: \(labels)."
            } catch {
                discoveryNote = "Couldn’t check the gateway’s sign-in fields: \(error.localizedDescription)"
            }
        }
    }
}
