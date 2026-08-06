// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
//  VPNController+Connect.swift
//  The connect/disconnect half of VPNController: every path that starts or stops
//  a tunnel funnels through here — the detail pane, the sidebar play button, the
//  menu bar, compositions, the CLI and intents alike — plus the credential
//  plumbing those paths draw on: transient (mid-typing) credentials, the
//  configured credential source (manual / 1Password / Apple Passwords / Touch
//  ID), the per-VPN auth shape, pause/resume with its watchdogs, and reconnect.
//  Stored state lives in VPNController.swift (extensions cannot hold it).
//

import Foundation
import AppKit
@preconcurrency import NetworkExtension
import os

extension VPNController {

    /// Re-run the connect a failure came from (the sheet's Try Again). Clearing
    /// first is also what dismisses the sheet, so the caller passes the id it
    /// captured rather than reading it back out of the failure.
    func retryConnect(id: String) async {
        clearFailure()
        do {
            try await connectUsingConfiguredSource(
                id: id, typedOTP: transientCredentials(for: id).otp)
        } catch is CancellationError {
            // The user backed out — an outcome, not a failure.
        } catch {
            Self.log.error("retry failed for \(id, privacy: .public): \(error.localizedDescription, privacy: .public)")
            report(error, profile: id)
        }
    }

    // MARK: Transient credentials (menu-bar inline entry)


    /// The dropdown's starting point for a profile: anything mid-typing, else
    /// the saved credentials, else empty.
    func transientCredentials(for id: String) -> TransientCredentials {
        if let existing = transientCreds[id] { return existing }
        var fresh = TransientCredentials()
        if let saved = savedCredentials(id: id) {
            fresh.username = saved.username
            fresh.password = saved.password
        }
        return fresh
    }


    /// Route ALL credential edits through here: updates the shared state and —
    /// when Remember is on and the profile allows saving — persists to the
    /// keychain shortly after typing stops. "Remember" means remembered, not
    /// "remembered only if you happened to connect before quitting".
    func setTransientCredentials(_ creds: TransientCredentials, for id: String) {
        transientCreds[id] = creds
        persistTask?.cancel()
        persistTask = Task { [weak self] in
            try? await Task.sleep(for: .milliseconds(600))
            guard !Task.isCancelled else { return }
            self?.persistIfRemembered(id: id)
        }
    }

    private func persistIfRemembered(id: String) {
        let c = transientCredentials(for: id)
        guard authConfig(for: id).rememberCredentials,
              allowsPasswordSave(id: id),
              !c.username.isEmpty, !c.password.isEmpty else { return }
        // Typing an OTP also lands here — don't rewrite an unchanged
        // username/password to the keychain on every pause in typing.
        if let saved = savedCredentials(id: id),
           saved.username == c.username, saved.password == c.password { return }
        do {
            try KeychainCredentialStore.saveCredentials(profile: id, .init(username: c.username, password: c.password))
        } catch {
            Self.log.error("saveCredentials failed for \(id, privacy: .public): \(error.localizedDescription, privacy: .public)")
        }
    }

    // MARK: Credential source (manual / 1Password / Apple Passwords / KeePassXC)


    func credentialSource(for id: String) -> CredentialSource {
        if let cached = credentialSources[id] { return cached }
        let proto = managers[id]?.protocolConfiguration as? NETunnelProviderProtocol
        return CredentialSource.decode(from: proto?.providerConfiguration?["credsource"] as? Data)
    }

    func setCredentialSource(_ source: CredentialSource, for id: String) async throws {
        guard !ManagedPolicy.lockConfiguration else { throw Self.configLocked }
        guard let mgr = managers[id],
              let proto = mgr.protocolConfiguration as? NETunnelProviderProtocol else { return }
        var conf = proto.providerConfiguration ?? [:]
        if let blob = source.encodedBlob() { conf["credsource"] = blob }
        else { conf.removeValue(forKey: "credsource") }
        proto.providerConfiguration = conf
        mgr.protocolConfiguration = proto
        try await mgr.saveToPreferences()
        try await mgr.loadFromPreferences()
        credentialSources[id] = source
        // Changing the source retires any "type it this time" escape: the user
        // has just answered the question that flag was standing in for.
        setTypedSignInOnce(false, for: id)
        Self.log.log("credential source for \(id, privacy: .public): \(source.kind.rawValue, privacy: .public)")
    }

    /// The provider a profile's configured source implies. Manual returns nil —
    /// the caller uses the typed/remembered credentials instead, and so does an
    /// active "type it this time".
    ///
    /// Every vendor-backed source resolves through `LocalVaultRegistry`, so a new
    /// password app is one adapter rather than another case here (that switch is
    /// exactly what had to be unpicked when Keeper turned out to have a local
    /// path after all). Apple Passwords stays inline: it is macOS's own keychain,
    /// not a vendor channel with an app to detect.
    func managerProvider(for id: String) -> CredentialProvider? {
        guard !typedSignInOnce.contains(id) else { return nil }
        let source = credentialSource(for: id)
        switch source.kind {
        case .manual:
            // Touch ID-protected saved credentials act as a manager: one
            // fingerprint releases username + password (+ the one-time code,
            // when a TOTP secret is stored).
            if authConfig(for: id).protectWithBiometrics, BiometricCredentialStore.exists(profile: id) {
                let name = profiles.first { $0.id == id }?.name ?? "the VPN"
                return BiometricCredentialProvider(reason: "unlock the sign-in for \(name)")
            }
            return nil
        case .applePasswords:
            guard !source.reference.trimmingCharacters(in: .whitespaces).isEmpty else { return nil }
            return ApplePasswordsProvider(server: source.reference, account: source.account)
        case .onePassword, .keePassXC, .keeper, .bitwarden, .dashlane,
             .keePassFile, .passwordStore, .lastPass, .protonPass, .passbolt:
            // The adapter owns the vendor's quirks (1Password's account
            // fallback, Keeper's and Bitwarden's channel choice) — this seam only asks for a
            // fetcher. A source that names nothing to fetch yields nil, which
            // routes to the typed fields rather than a doomed lookup.
            return LocalVaultRegistry.adapter(for: source.kind)?.provider(for: source)
        }
    }

    /// "Type it each time" means it. Choosing that row must actually remove what
    /// was kept for this VPN — both stores — or the promise on screen ("nothing
    /// is saved") is false the moment it is made. The transient (mid-typing)
    /// copy stays: the user may be in the middle of connecting.
    func forgetSavedSignIn(id: String) {
        KeychainCredentialStore.deleteCredentials(profile: id)
        BiometricCredentialStore.delete(profile: id)
        var auth = authConfig(for: id)
        guard auth.protectWithBiometrics else { return }
        auth.protectWithBiometrics = false
        Task { try? await setAuthConfig(auth, for: id) }
    }

    /// The source that will ACTUALLY be used, which is what every readiness
    /// decision must gate on. It differs from the stored choice in two ways, and
    /// both used to be places where a Connect button lit up for a lookup that
    /// could not happen:
    ///   • "type it this time" is on (the recovery path), or
    ///   • the chosen password app has nothing linked to fetch, so the typed
    ///     fields are what the connect will really use.
    func effectiveCredentialKind(for id: String) -> CredentialSourceKind {
        let stored = credentialSource(for: id).kind
        guard stored != .manual else { return .manual }
        return managerProvider(for: id) == nil ? .manual : stored
    }

    /// Whether the Touch ID store can satisfy this profile's whole sign-in
    /// unattended (creds present; the code too when one is required).
    func biometricCanServe(id: String) -> Bool {
        guard authConfig(for: id).protectWithBiometrics else { return false }
        let info = BiometricCredentialStore.info(profile: id)
        guard info.exists else { return false }
        return !requiresOTP(for: id) || info.hasTOTP
    }

    /// Set or replace the authenticator (TOTP) secret inside an existing
    /// protected item. Reading the current username/password back takes one
    /// Touch ID prompt — changing what the fingerprint guards should cost one.
    func updateProtectedTOTP(id: String, secret: String?) async throws {
        guard BiometricCredentialStore.exists(profile: id) else { return }
        let name = profiles.first { $0.id == id }?.name ?? "the VPN"
        let provider = BiometricCredentialProvider(reason: "update the sign-in for \(name)")
        let raw = try await provider.resolve(profile: id, fields: [.username, .password])
        try BiometricCredentialStore.save(profile: id, .init(
            username: raw.username ?? "", password: raw.password ?? "",
            totpSecret: secret?.isEmpty == true ? nil : secret))
        Self.log.log("protected TOTP secret \(secret == nil ? "cleared" : "updated", privacy: .public) for \(id, privacy: .public)")
    }

    /// Flip Touch ID protection for a profile's saved credentials, migrating the
    /// secret between the plain and protected stores. Turning protection OFF
    /// needs the secret back, which itself takes one Touch ID prompt (unless the
    /// live session state already has it).
    func setBiometricProtection(_ on: Bool, for id: String, totpSecret: String? = nil) async throws {
        var auth = authConfig(for: id)
        let name = profiles.first { $0.id == id }?.name ?? "the VPN"
        if on {
            // Source the secret from what's live (typed) or saved.
            let c = transientCredentials(for: id)
            let saved = savedCredentials(id: id)
            let username = !c.username.isEmpty ? c.username : (saved?.username ?? "")
            let password = !c.password.isEmpty ? c.password : (saved?.password ?? "")
            guard !username.isEmpty, !password.isEmpty else {
                throw err("Enter (or save) the username and password first, then turn on Touch ID protection.")
            }
            try BiometricCredentialStore.save(profile: id, .init(
                username: username, password: password, totpSecret: totpSecret))
            // The plain-keychain copy would defeat the point of the gate.
            KeychainCredentialStore.deleteCredentials(profile: id)
            auth.protectWithBiometrics = true
            try await setAuthConfig(auth, for: id)
            Self.log.log("biometric protection ON for \(id, privacy: .public)")
        } else {
            guard BiometricCredentialStore.exists(profile: id) else {
                auth.protectWithBiometrics = false
                try await setAuthConfig(auth, for: id)
                return
            }
            let provider = BiometricCredentialProvider(reason: "move the sign-in for \(name) out of Touch ID protection")
            let raw = try await provider.resolve(profile: id, fields: [.username, .password])
            if auth.rememberCredentials, allowsPasswordSave(id: id) {
                try? KeychainCredentialStore.saveCredentials(profile: id, .init(
                    username: raw.username ?? "", password: raw.password ?? ""))
            }
            var live = transientCredentials(for: id)
            live.username = raw.username ?? live.username
            live.password = raw.password ?? live.password
            transientCreds[id] = live
            BiometricCredentialStore.delete(profile: id)
            auth.protectWithBiometrics = false
            try await setAuthConfig(auth, for: id)
            Self.log.log("biometric protection OFF for \(id, privacy: .public)")
        }
    }

    // MARK: Authentication shape (per-VPN OTP requirement + password template)


    func authConfig(for id: String) -> VPNAuthConfig {
        if let cached = authConfigs[id] { return cached }
        let proto = managers[id]?.protocolConfiguration as? NETunnelProviderProtocol
        return VPNAuthConfig.decode(from: proto?.providerConfiguration?["auth"] as? Data)
    }

    func setAuthConfig(_ auth: VPNAuthConfig, for id: String) async throws {
        guard !ManagedPolicy.lockConfiguration else { throw Self.configLocked }
        guard let mgr = managers[id],
              let proto = mgr.protocolConfiguration as? NETunnelProviderProtocol else { return }
        var conf = proto.providerConfiguration ?? [:]
        if let blob = auth.encodedBlob() {
            conf["auth"] = blob
        } else {
            conf.removeValue(forKey: "auth")
        }
        proto.providerConfiguration = conf
        mgr.protocolConfiguration = proto
        try await mgr.saveToPreferences()
        try await mgr.loadFromPreferences()
        authConfigs[id] = auth
        Self.log.log("auth config saved for \(id, privacy: .public): requiresOTP=\(auth.requiresOTP)")
    }

    // MARK: Connect / disconnect

    /// Connect from a PROVIDER — the shape every existing caller uses. Resolves it into
    /// an `AuthPlan` and hands that to the real funnel below, so there is exactly one
    /// place a plan is executed.
    ///
    /// A provider always resolves to `.value`: that is what `CredentialProvider` IS,
    /// and it is why the other two deliveries could never be expressed through it. See
    /// `AuthPlan`'s header.
    func connect(id: String, using provider: CredentialProvider,
                 request: CredentialRequest, remember: Bool) async throws {
        Self.log.log("connect: \(id, privacy: .public) source=\(provider.id, privacy: .public)")
        let raw = try await provider.resolve(profile: id, fields: request.fields)
        try await connect(id: id, plan: .value(raw), request: request, remember: remember)
    }

    /// THE ONE FUNNEL. Executes a plan.
    ///
    /// Taking a plan rather than a fetcher is what removed the double resolve:
    /// `connectUsingConfiguredSource` used to resolve its provider, wrap the result in a
    /// `ManualCredentialProvider` purely to satisfy this signature, and let this method
    /// resolve THAT — a wrapper whose only job was smuggling a value through a protocol
    /// that wanted a fetcher, and which silently dropped `passkeyAssertion` because it
    /// had no field for it.
    func connect(id: String, plan: AuthPlan,
                 request: CredentialRequest, remember: Bool) async throws {
        // The control-plane guard chain (MDM, future Tcl) — every connect path
        // funnels through this method, so this one check covers the detail pane,
        // sidebar, menu bar, compositions, CLI and intents alike.
        if let why = controlDenied(.connect(profile: id)) { throw err(why) }
        guard let mgr = managers[id],
              mgr.protocolConfiguration is NETunnelProviderProtocol else {
            throw err("no such profile")
        }

        // First connect of an OpenVPN profile is the moment to ask macOS to approve the
        // system extension — not app launch. A brand-new user should meet the app, not a
        // security dialog for a capability they haven't asked for yet. Every connect path
        // funnels through here, so this covers the sidebar play button and the menu bar
        // as well as the detail pane.
        if let ensureExtensionReady, !(await ensureExtensionReady()) {
            throw err("SimpleVPN needs its network extension approved before it can connect. Open System Settings ▸ General ▸ Login Items & Extensions ▸ Network Extensions and allow SimpleVPN.")
        }
        let raw: RawCredentials
        switch plan {
        case .value(let values):
            raw = values
        // NEITHER of these reaches this method today, and that is a statement rather
        // than an omission. A `.possession` plan is executed by the engine that owns
        // the name — the SSH engine sets `SSH_OPTIONS_IDENTITY_AGENT` from its own
        // stored socket path, `openconnect` resolves a `pkcs11:` URI through p11-kit —
        // and neither goes anywhere near `startTunnel(options:)`. A `.typedByDevice`
        // plan is executed by the connect FORM, which is the only place a focused field
        // exists; by the time it gets here the code is already a typed value. The switch
        // is exhaustive so that a future producer has to come and decide, rather than
        // finding a `default` that quietly did the wrong thing.
        case .possession(let possession):
            throw err("This VPN signs in with \(possession.loggableSummary), which its "
                      + "engine handles itself \u{2014} there is nothing for SimpleVPN to send.")
        case .typedByDevice:
            throw err("Waiting for your security key. Touch it, then connect.")
        }
        let staticChallenge = hasStaticChallenge(id)
        let engine: EngineCredentials
        if staticChallenge {
            // static-challenge profiles: the OTP travels as the engine's
            // challenge response (see the options below), never concatenated
            // into the password — the template concat stays for profiles
            // without one (GR Lab depends on {password}{otp}).
            engine = EngineCredentials(username: raw.username ?? "", password: raw.password ?? "")
        } else {
            engine = request.assemble(from: raw)
        }
        // Autologin profiles authenticate with their certificate — empty
        // credentials are the correct payload, not a user mistake.
        let autologin = isAutologin(id)
        guard autologin || (!engine.username.isEmpty && !engine.password.isEmpty) else {
            throw err("missing username or password")
        }

        if remember, !engine.username.isEmpty {
            try? KeychainCredentialStore.saveCredentials(profile: id, .init(username: engine.username, password: raw.password ?? ""))
        }
        // Session secrets ride startTunnel options — in-memory through the NE
        // session. The extension runs as root in the system context and cannot
        // read the user's keychain, so options are the only reliable handoff.
        let secrets = KeychainCredentialStore.loadProfileSecrets(profile: id)
        var options: [String: NSObject] = [
            "username": engine.username as NSString,
            "password": engine.password as NSString,
        ]
        if let p = secrets?.proxyPassword { options["proxyPassword"] = p as NSString }
        if let p = secrets?.privateKeyPassword { options["privateKeyPassword"] = p as NSString }
        // The static-challenge response rides its own option so the bridge can
        // hand it to the engine as ProvideCreds.response.
        if staticChallenge, let otp = raw.otp?.trimmingCharacters(in: .whitespaces), !otp.isEmpty {
            options["challengeResponse"] = otp as NSString
        }
        // A password manager can also supply the private-key passphrase; it wins
        // over the keychain copy so the mapped 1Password field takes effect.
        if let p = raw.privateKeyPassphrase, !p.isEmpty { options["privateKeyPassword"] = p as NSString }

        // The profile's secret inline blocks — `<key>`, `<tls-crypt>`, … — which are
        // NOT in providerConfiguration (see OVPNSecretMaterial). openvpn3 takes the
        // configuration as a string, so the extension splices them back into it and
        // the material only ever exists in memory there. Same handoff as every other
        // per-profile secret, for the same reason: the extension runs as root in the
        // system context and cannot read the user's keychain.
        let inlineSecrets = ovpnSecrets(for: id)
        if !inlineSecrets.isEmpty {
            options["ovpnInlineSecrets"] = inlineSecrets as NSDictionary
            // Tag names only — the contents are the secret, the names are not.
            Self.log.log("connect: re-inserting \(inlineSecrets.keys.sorted().joined(separator: ","), privacy: .public) for \(id, privacy: .public)")
        }

        // Org policy travels with every session so the extension enforces it at
        // connect regardless of the persisted config (a profile saved before the
        // policy was pushed can't be used to leak). This is the real enforcement
        // point — the UI gates are only cosmetic.
        if ManagedPolicy.forceKeepInsideVPN { options["policyKeepInside"] = true as NSNumber }
        if ManagedPolicy.disableDivertRules { options["policyNoDiverts"] = true as NSNumber }

        // Default-gateway ownership travels with the session so the extension sets
        // its suppress gate at establish — the ≤1-owner invariant then holds from
        // the very first tun build, before (or without) the app reconciling (RC3).
        options["gatewayOwned"] = predictedGatewayOwned(id) as NSNumber

        mgr.isEnabled = true
        do {
            try await mgr.saveToPreferences()
            try await mgr.loadFromPreferences()
        } catch {
            // A silent stop here looked identical to "nothing happened" in the
            // 15:08 diagnostics — every stage failure must name itself.
            Self.log.error("connect prefs save/load failed for \(id, privacy: .public): \(error.localizedDescription, privacy: .public)")
            throw error
        }
        guard let session = mgr.connection as? NETunnelProviderSession else {
            Self.log.error("connect: no NETunnelProviderSession for \(id, privacy: .public)")
            throw err("The VPN configuration isn't ready — try removing and re-importing it.")
        }
        do {
            try session.startTunnel(options: options)
            Self.log.log("startTunnel dispatched for \(id, privacy: .public) (status now \(Self.statusText(mgr.connection.status), privacy: .public))")
        } catch {
            // Without this line a failed start is invisible in a log capture —
            // the error only reaches the UI alert.
            Self.log.error("startTunnel failed for \(id, privacy: .public): \(error.localizedDescription, privacy: .public)")
            throw error
        }
        // The notification observer is matched at fire time, but the transition to
        // .connecting can precede this line — pull current statuses now so the
        // watchdog is guaranteed to start counting.
        resyncStatuses()
        // Part of this connect attempt: is a Wi-Fi sign-in page in the way? The
        // engine would otherwise retry silently against a network that answers
        // every request with a login page. Tell the user in seconds, not after
        // the 45 s watchdog. (Probe runs only on user-initiated connects.)
        Task { [weak self] in
            guard let self else { return }
            await self.recheckCaptivePortal()
            guard self.captivePortalSuspected,
                  self.profiles.first(where: { $0.id == id })?.status != .connected else { return }
            let name = self.profiles.first { $0.id == id }?.name ?? "The VPN"
            ToastCenter.shared.post(
                "This Wi-Fi wants you to sign in before \(name) can connect.",
                symbol: "wifi.exclamationmark", tint: .indigo, seconds: 12,
                actionTitle: "Open Sign-In Page") { [weak self] in
                    guard let self else { return }
                    NSWorkspace.shared.open(self.captivePortalURL ?? ConnectionDiagnostics.captivePortalProbeURL)
                }
        }
        appliedOverrides[id] = overrides(for: id)   // what this session runs with
        appliedOVPN[id] = ovpnText(id: id) ?? ""
    }

    /// Unified connect from the shared credential state (the store every surface
    /// edits). Persists username+password iff the shared Remember preference is on
    /// and the profile allows saving; the OTP is consumed and cleared.
    func connectWithTransientCredentials(id: String) async throws {
        // Tailscale has no username/password to collect — it signs in with a
        // setup key or a browser; WireGuard signs in with its stored keys.
        // Every connect entry point funnels here or to one of the two below,
        // so the branches belong at each of them.
        if isTailscale(id) { try await connectTailscale(id: id); return }
        if isProxyTunnel(id) { try await connectProxyTunnel(id: id); return }
        if isWireGuard(id) { try await connectWireGuard(id: id); return }
        if isSSHNetworkTunnel(id) { try await connectSSHNetworkTunnel(id: id); return }
        let c = transientCredentials(for: id)
        let auth = effectiveAuthConfig(for: id)
        let provider = ManualCredentialProvider(username: c.username, password: c.password, otp: c.otp)
        try await connect(id: id, using: provider, request: auth.request,
                          remember: auth.rememberCredentials && allowsPasswordSave(id: id))
        transientCreds[id]?.otp = ""
        // A typed connect that worked retires the "type it this time" escape:
        // the next connect goes back to the source the user actually chose, and
        // finds out for itself whether it is available again.
        setTypedSignInOnce(false, for: id)
    }

    private func allowsPasswordSave(id: String) -> Bool {
        allowsPasswordSaveEvaluator?(id) ?? true
    }

    func profileEvaluation(for id: String) -> ProfileEvaluation? {
        profileEvaluationProvider?(id)
    }


    /// Autologin profiles authenticate with their certificate alone — there is
    /// no username or password to collect, gate on, or save.
    func isAutologin(_ id: String) -> Bool {
        profileEvaluation(for: id)?.autologin ?? false
    }

    /// The profile declares `static-challenge`: the server demands a challenge
    /// response (the one-time code) alongside — not inside — the password.
    func hasStaticChallenge(_ id: String) -> Bool {
        !(profileEvaluation(for: id)?.staticChallenge.isEmpty ?? true)
    }

    /// The auth shape connect flows and forms should READ: the persisted config
    /// with requiresOTP forced on when the profile itself declares a static
    /// challenge — the server will demand the code regardless of the toggle,
    /// and this is also what fixes profiles imported before the challenge was
    /// wired up. Writes still go through setAuthConfig with the raw config.
    func effectiveAuthConfig(for id: String) -> VPNAuthConfig {
        var auth = authConfig(for: id)
        if hasStaticChallenge(id) { auth.requiresOTP = true }
        return auth
    }

    func requiresOTP(for id: String) -> Bool {
        effectiveAuthConfig(for: id).requiresOTP
    }

    /// The ONE readiness decision every Connect affordance reads — the detail
    /// Connect button, the sidebar play button and the menu row — so a control
    /// is never enabled in one place and disabled in another. (Tailscale used to
    /// be connectable from the detail pane yet stuck on "Sign-in needed" in the
    /// sidebar because each view recomputed this for itself.)
    func connectReadiness(for id: String) -> ConnectReadiness {
        connectInputs(for: id).readiness
    }

    /// Gather the plain facts `ConnectReadiness` turns on. Kept separate from the
    /// (pure, testable) decision so the keychain/evaluator lookups happen once,
    /// and only for the kinds that need them.
    func connectInputs(for id: String) -> ConnectInputs {
        var inputs = ConnectInputs()
        inputs.kind = profiles.first { $0.id == id }?.kind ?? .openVPN

        // Tailscale, Proxy Tunnels and WireGuard decide on their own settings —
        // no typed credentials, so skip the evaluator/keychain work entirely.
        if inputs.kind == .tailscale { return inputs }
        if inputs.kind == .proxyTunnel {
            let config = proxyTunnelConfig(for: id)
            inputs.proxyHasProblem = config.connectProblem != nil
            inputs.proxyRequiresAuth = config.requiresAuth
            let creds = proxyTunnelCredentials(for: id)
            inputs.proxyCredentialsComplete =
                !creds.username.trimmingCharacters(in: .whitespaces).isEmpty && !creds.password.isEmpty
            return inputs
        }
        if inputs.kind == .wireGuard {
            inputs.wireGuardHasProblem = wireGuardConfig(for: id).connectProblem != nil
            inputs.wireGuardHasKey = wireGuardHasPrivateKey(id)
            return inputs
        }
        if inputs.kind == .sshNetworkTunnel {
            let config = sshNetworkTunnelConfig(for: id)
            inputs.sshNetHasProblem = config.connectProblem != nil
            let secrets = sshNetworkTunnelSecrets(for: id)
            inputs.sshNetHasCredential = config.needsPrivateKey
                ? !secrets.privateKeyPEM.isEmpty && (!config.needsCertificate || !secrets.certificatePEM.isEmpty)
                : !secrets.password.isEmpty
            return inputs
        }

        inputs.autologin = isAutologin(id)
        inputs.managerKind = effectiveCredentialKind(for: id)
        inputs.requiresOTP = effectiveAuthConfig(for: id).requiresOTP
        inputs.hasLockedUsername = !(profileEvaluation(for: id)?.userlockedUsername.isEmpty ?? true)
        let c = transientCredentials(for: id)
        inputs.typedUsername = !c.username.trimmingCharacters(in: .whitespaces).isEmpty
        inputs.typedPassword = !c.password.isEmpty
        inputs.typedOTP = !c.otp.trimmingCharacters(in: .whitespaces).isEmpty

        // Touch ID facts only matter for a manual, protected source (a manager
        // source resolves its own secret); reading them otherwise is a needless
        // keychain hit on every redraw.
        inputs.biometricProtected = authConfig(for: id).protectWithBiometrics
        if inputs.managerKind == .manual, inputs.biometricProtected {
            let info = BiometricCredentialStore.info(profile: id)
            inputs.biometricStored = info.exists
            inputs.biometricHasTOTP = info.hasTOTP
        }
        return inputs
    }

    /// Connect unattended (menu / sidebar quick-connect). Uses a configured
    /// password manager when it can run without typing, else remembered
    /// credentials. Returns false when a fresh OTP or manual entry is needed —
    /// the caller then sends the user to the credential form.
    @discardableResult
    func connectWithSavedCredentials(id: String) async -> Bool {
        if isTailscale(id) {
            do { try await connectTailscale(id: id); return true }
            catch { report(error, profile: id); return false }
        }
        if isProxyTunnel(id) {
            // A no-auth proxy connects unattended; an auth proxy connects with
            // its stored credentials (there is no OTP to type).
            do { try await connectProxyTunnel(id: id); return true }
            catch { report(error, profile: id); return false }
        }
        if isWireGuard(id) {
            // The keys are stored, so a WireGuard connect never needs typing.
            do { try await connectWireGuard(id: id); return true }
            catch { report(error, profile: id); return false }
        }
        if isSSHNetworkTunnel(id) {
            // Everything is stored (password / key / certificate, plus the pinned
            // host key), so this connects unattended — EXCEPT the first connect to
            // a server whose key nobody has looked at yet, which throws with the
            // fingerprint and sends the user to "Check and Trust". Trust on first
            // use must never happen while the user is looking elsewhere.
            do { try await connectSSHNetworkTunnel(id: id); return true }
            catch { report(error, profile: id); return false }
        }
        // Autologin: nothing to look up — the profile's certificate IS the sign-in.
        if isAutologin(id) {
            do {
                try await connect(id: id, using: ManualCredentialProvider(username: "", password: "", otp: ""),
                                  request: .usernamePassword, remember: false)
                return true
            } catch {
                report(error, profile: id)
                return false
            }
        }
        let auth = effectiveAuthConfig(for: id)

        // A password manager can auto-connect when the profile needs no OTP, or
        // when it can supply the OTP itself (1Password/KeePassXC TOTP; the
        // Touch ID store with a saved authenticator secret). Apple Passwords
        // can't provide an OTP, so an OTP profile still needs the form.
        if let provider = managerProvider(for: id) {
            // ONE answer to "can this source serve unattended?", read from the same
            // method the connect form's warning reads. It used to be re-derived here
            // from `effectiveCredentialKind(...).suppliesOTP || biometricCanServe(...)`
            // — the same question with a different set of inputs, in a different file,
            // free to disagree with the form the user was looking at.
            guard authSatisfaction(for: id).connectsUnattended else { return false }
            do {
                try await connect(id: id, using: provider, request: auth.request, remember: false)
                return true
            } catch {
                report(error, profile: id)
                return false
            }
        }

        guard !auth.requiresOTP,
              let saved = savedCredentials(id: id), !saved.password.isEmpty else { return false }
        let provider = ManualCredentialProvider(username: saved.username, password: saved.password, otp: "")
        do {
            try await connect(id: id, using: provider, request: .usernamePassword, remember: false)
            return true
        } catch {
            report(error, profile: id)
            return false
        }
    }

    /// Connect honoring the profile's configured credential source. For a
    /// manager source, resolves the item (prompting Touch ID / keychain as the
    /// manager sees fit) and overlays the typed OTP only if the manager didn't
    /// supply one. Manual sources fall back to the shared credential state.
    func connectUsingConfiguredSource(id: String, typedOTP: String) async throws {
        if isTailscale(id) { try await connectTailscale(id: id); return }
        if isProxyTunnel(id) { try await connectProxyTunnel(id: id); return }
        if isWireGuard(id) { try await connectWireGuard(id: id); return }
        if isSSHNetworkTunnel(id) { try await connectSSHNetworkTunnel(id: id); return }
        let auth = effectiveAuthConfig(for: id)
        guard managerProvider(for: id) != nil else {
            try await connectWithTransientCredentials(id: id)
            return
        }
        // ONE resolve, and the plan crosses the seam. This used to resolve here, wrap
        // the result in a `ManualCredentialProvider`, and let `connect` resolve the
        // wrapper — see `VPNController+Auth.swift`'s header.
        let plan = try await authPlan(for: id, typedOTP: typedOTP)
        try await connect(id: id, plan: plan, request: auth.request, remember: false)
    }

    // MARK: Compositions (multiple VPNs connected together)


    /// Connect every member of a composition, in dependency order: a member that
    /// runs "over" another waits for that one to reach `.connected` first (bounded).
    /// Members needing a fresh OTP are collected in `compositionNeedsAttention`.
    func connectComposition(_ composition: VPNComposition) async {
        compositionNeedsAttention = []
        for member in composition.startOrder {
            if let dep = member.dependsOn {
                await waitForConnected(id: dep, timeout: 15)
            }
            let ok = await connectWithSavedCredentials(id: member.profileID)
            if !ok {
                compositionNeedsAttention.append(member.profileID)
            }
        }
        if !compositionNeedsAttention.isEmpty {
            let names = compositionNeedsAttention
                .compactMap { id in profiles.first { $0.id == id }?.name }
                .joined(separator: ", ")
            lastError = "Connected the rest of \(composition.name). These still need a code or sign-in: \(names)."
        }
    }

    func disconnectComposition(_ composition: VPNComposition) {
        for member in composition.members { disconnect(id: member.profileID) }
    }

    /// True while any member of the composition is active.
    func isCompositionActive(_ composition: VPNComposition) -> Bool {
        composition.members.contains { m in
            profiles.first { $0.id == m.profileID }.map { UI.isActive($0.status) } ?? false
        }
    }

    private func waitForConnected(id: String, timeout: Int) async {
        for _ in 0..<(timeout * 10) {
            if profiles.first(where: { $0.id == id })?.status == .connected { return }
            try? await Task.sleep(for: .milliseconds(100))
        }
    }

    // MARK: Pause / Resume
    //
    // The engine pauses under a kept TLS session (resume needs no re-auth), so
    // NEVPNStatus stays .connected throughout — paused is app-side state.

    // ONE pause behaviour (the old "hold/block" mode is gone): the tunnel stays
    // signed in, its routes/DNS come out so traffic uses the physical interface,
    // and resume puts them back. The extension still speaks "pause:<mode>", so
    // the wire format is unchanged — the app just only ever asks for bypass.


    func pause(id: String) async {
        if let why = controlDenied(.pause(profile: id)) { lastError = why; return }
        guard let reply = await sendMessage("pause:bypass", to: id), reply == "ok" else {
            lastError = "Pause failed — the tunnel didn't acknowledge."
            return
        }
        pausedProfiles.insert(id)
        Self.log.log("paused \(id, privacy: .public)")
    }

    func resume(id: String) async {
        if let why = controlDenied(.resume(profile: id)) { lastError = why; return }
        let acknowledged = (await sendMessage("resume", to: id)) == "ok"
        pausedProfiles.remove(id)
        guard acknowledged else {
            await recoverFailedResume(id: id, why: "the tunnel didn't acknowledge resuming")
            return
        }
        Self.log.log("resumed \(id, privacy: .public)")
        // Acknowledged is NOT the same as recovered. Resuming re-applies the tunnel's
        // network settings, which makes NetworkExtension re-negotiate the session — that
        // brief pass through .reasserting is the "flash" — and if the re-apply or the
        // engine restart fails, NE tears the tunnel down a moment later. Watch for it.
        startResumeWatchdog(id: id)
    }

    /// Resume is only really done once the session is back up. Nothing else notices a
    /// teardown that arrives AFTER an "ok", which is how a failed resume used to end up
    /// looking like an ordinary Connect button with no explanation.
    private func startResumeWatchdog(id: String) {
        resumeWatchdogs[id]?.cancel()
        resumeWatchdogs[id] = Task { [weak self] in
            try? await Task.sleep(for: Self.resumeSettleWindow)
            guard !Task.isCancelled, let self else { return }
            let status = self.profiles.first { $0.id == id }?.status
            guard status == .disconnected || status == .invalid else { return }
            await self.recoverFailedResume(id: id, why: "resuming dropped the connection")
        }
    }

    /// AUTH_FAILED right after a successful session, on an OTP profile, is almost
    /// always a one-time code being REUSED: the previous connect consumed it, and
    /// LinOTP-style servers refuse a second use inside the same ~30-second window.
    /// Toggling a connection setting forces exactly that disconnect→reconnect, so
    /// without this the user reads it as "the setting broke my VPN" (it did, twice,
    /// today). Say what actually happened and what to do.
    func explainOTPReuseIfLikely(id: String) {   // was private — internal for the +File split
        guard incidents[id]?.category == .auth,
              requiresOTP(for: id),
              let lastUp = lastConnectedAt[id],
              Date().timeIntervalSince(lastUp) < 90 else { return }
        let name = profiles.first { $0.id == id }?.name ?? "The VPN"
        ToastCenter.shared.post(
            "\(name) rejected the sign-in \u{2014} the verification code was probably just used by the previous connection. Wait for your authenticator's next code, then connect again.",
            symbol: "clock.badge.exclamationmark", seconds: 12)
    }

    func cancelResumeWatchdog(id: String) {   // was private — internal for the +File split
        resumeWatchdogs[id]?.cancel()
        resumeWatchdogs[id] = nil
    }

    /// Both halves of the fix: SAY what happened, and where it's safe to, put it right.
    ///
    /// The reconnect is guarded by `canReconnectUnattended` for a specific reason — a
    /// profile needing a fresh one-time code can't be brought back without the user, and
    /// silently prompting for Touch ID or an OTP in the middle of what looked like
    /// "unpause" would be a worse surprise than saying so plainly.
    private func recoverFailedResume(id: String, why: String) async {
        let name = profiles.first { $0.id == id }?.name ?? "The VPN"
        Self.log.error("resume recovery for \(id, privacy: .public): \(why, privacy: .public)")

        // Persistent half, so the VPN's own pane still explains this later.
        TunnelIncidentStore.write(TunnelIncident(
            profile: id, category: .tunSetup, event: "RESUME_FAILED",
            info: "Resuming \(name) \(why). macOS re-applies the tunnel's settings when a "
                + "paused VPN resumes, and this time it didn't come back.",
            fatal: false))

        if canReconnectUnattended(id: id) {
            ToastCenter.shared.post(
                "\(name): \(why) — reconnecting\u{2026}",
                symbol: "arrow.triangle.2.circlepath", tint: .yellow, seconds: 6)
            await reconnect(id: id)
        } else {
            // Be explicit that this needs them, and why we didn't just do it.
            ToastCenter.shared.post(
                "\(name): \(why). It needs your sign-in again, so it wasn't reconnected for you.",
                symbol: "exclamationmark.triangle.fill", seconds: 12,
                actionTitle: "Connect") { [weak self] in
                    guard let self else { return }
                    Task { try? await self.connectUsingConfiguredSource(id: id, typedOTP: "") }
                }
        }
    }

    /// Disconnect and immediately reconnect (used to apply saved settings changes).
    /// Never called automatically — only from the user's explicit Reconnect action.
    func reconnect(id: String) async {
        // Don't tear down a working tunnel we can't bring back unattended: a
        // profile needing a fresh OTP (a one-time code can't be reused) or a
        // password that was never saved would be left silently disconnected — and
        // possibly exposed. The config change is already persisted, so it applies
        // on the next manual connect; leave the live session running until then.
        guard canReconnectUnattended(id: id) else {
            let name = profiles.first { $0.id == id }?.name ?? "this VPN"
            lastError = "Saved. It’ll take effect next time you connect \(name) — this VPN needs a code or sign-in that can’t be reused automatically, so it wasn’t reconnected for you."
            return
        }
        disconnect(id: id)
        // Wait (bounded) for the tunnel to fully stop before starting again.
        for _ in 0..<100 {   // ≤10 s
            if profiles.first(where: { $0.id == id })?.status == .disconnected { break }
            try? await Task.sleep(for: .milliseconds(100))
        }
        // Prefer the in-memory credentials that actually brought this tunnel up
        // (a typed password that Remember didn't persist) over saved ones, so an
        // apply-triggered reconnect doesn't fail a no-save profile.
        if let c = transientCreds[id], !c.password.isEmpty, !requiresOTP(for: id) {
            do { try await connectWithTransientCredentials(id: id) }
            catch { lastError = error.localizedDescription }
            return
        }
        await connectWithSavedCredentials(id: id)
    }

    /// Whether `reconnect` can bring the profile back without user interaction —
    /// used to avoid dropping a live tunnel we couldn't restore.
    func canReconnectUnattended(id: String) -> Bool {   // was private — internal for the ExtensionDoctor
        // Once a Tailscale node is registered its key is on disk, so a
        // reconnect never needs the user. A WireGuard tunnel's keys live in
        // the keychain — same answer.
        if isTailscale(id) { return true }
        if isWireGuard(id) { return true }
        if isAutologin(id) { return true }   // the certificate is the sign-in
        let auth = effectiveAuthConfig(for: id)
        if managerProvider(for: id) != nil {
            // 1Password/KeePassXC can serve an OTP itself; Apple Passwords can't.
            return !auth.requiresOTP || credentialSource(for: id).kind.suppliesOTP
        }
        if auth.requiresOTP { return false }   // a one-time code can't be reused
        if let c = transientCreds[id], !c.password.isEmpty { return true }
        if let saved = savedCredentials(id: id), !saved.password.isEmpty { return true }
        return false
    }

    /// Stop every active tunnel and wait (bounded) for teardown, so the
    /// extension isn't cut off mid-stop. The quit path calls this — a tunnel
    /// lives in the system extension and would happily outlive the app, which
    /// is how "I quit and it was still connected" happened.
    func disconnectAllAndWait() async {
        for p in profiles where p.status != .disconnected && p.status != .invalid {
            disconnect(id: p.id)
        }
        for _ in 0..<50 {   // ≤5 s
            let stillActive = profiles.contains { $0.status != .disconnected && $0.status != .invalid }
            if !stillActive { break }
            try? await Task.sleep(for: .milliseconds(100))
        }
    }

    /// Menu-bar "Disconnect and Quit". Termination then flows through the app
    /// delegate's quit handler, which finds nothing left active and proceeds.
    func disconnectAllAndQuit() async {
        await disconnectAllAndWait()
        NSApplication.shared.terminate(nil)
    }

    func disconnect(id: String) {
        if let why = controlDenied(.disconnect(profile: id)) { lastError = why; return }
        // Cancelling a connect that was already grinding away is the same evidence the
        // watchdog collects — the user just got there first. Remember the network so the
        // next attempt from here is forewarned. Short cancels (changed my mind) don't
        // count: they say nothing about reachability.
        if profiles.first(where: { $0.id == id })?.status == .connecting,
           let started = connectAttemptStarted[id],
           Date().timeIntervalSince(started) >= Self.cancelCountsAsUnreachable {
            Task {
                await NetworkMemory.shared.refresh()
                NetworkMemory.shared.rememberFailure(profile: id)
            }
        }
        managers[id]?.connection.stopVPNTunnel()
    }
}
