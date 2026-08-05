// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
//  CredentialSource.swift
//  Per-VPN choice of WHERE credentials come from: typed manually (stored in the
//  login keychain when Remember is on), fetched from the 1Password app, or
//  read from Apple Passwords / the login keychain. Stored (no secrets — only a
//  reference to the item) as a JSON blob in providerConfiguration["credsource"],
//  same lenient pattern as VPNAuthConfig / OpenVPNOverrides.
//

import Foundation

enum CredentialSourceKind: String, Codable, Sendable, CaseIterable {
    case manual
    case onePassword
    case applePasswords
    case keePassXC
    /// Keeper, reached through Keeper Commander (Keeper's own command-line tool
    /// — the Keeper app itself exposes no local API). See KeeperProvider.
    case keeper
    /// Bitwarden, reached through Bitwarden's own command-line tool — preferably
    /// through the local service that tool starts (`bw serve`), which holds the
    /// unlock so SimpleVPN never handles the key that unlocks the vault. Covers
    /// self-hosted Bitwarden and Vaultwarden identically. See BitwardenProvider.
    case bitwarden
    /// Dashlane, reached through `dcli` — Dashlane's own command-line tool, asked to
    /// PRINT the entry (`--output json`) rather than to copy it to the pasteboard,
    /// which is what it does by default. See DashlaneProvider.
    case dashlane
    /// A KeePass `.kdbx` FILE, read directly — no vendor app involved, which is why
    /// one case serves KeePassXC-as-a-file, Strongbox and KeePassium alike. See
    /// KeePassFileProvider. Distinct from `.keePassXC`, which is the running app's
    /// own socket and stays the better answer whenever it is available.
    case keePassFile
    /// A `pass` / `gopass` password store. One kind for both tools and for reading
    /// the store with `gpg` alone — the store format is what we support, not a CLI.
    case passwordStore
    /// LastPass, reached through `lpass` — LastPass's own command-line tool, and the
    /// only local read path LastPass has. Its own agent holds the vault key and hands
    /// it to no program but `lpass`, so SimpleVPN never sees a master password or a
    /// derived key. See LastPassProvider.
    case lastPass

    // nonisolated for the same reason as `suppliesOTP` below: it is a pure function
    // of the case, and nonisolated rules (the security-key mutual exclusions in
    // YubiKeyAuthConfig) name the source in their own explanations.
    nonisolated var displayName: String {
        switch self {
        case .manual: "Manual / Saved"
        case .onePassword: "1Password"
        case .applePasswords: "Apple Passwords"
        case .keePassXC: "KeePassXC"
        case .keeper: "Keeper"
        case .bitwarden: "Bitwarden"
        case .dashlane: "Dashlane"
        case .keePassFile: "KeePass database file"
        case .passwordStore: "pass / gopass"
        case .lastPass: "LastPass"
        }
    }
    var systemImage: String {
        switch self {
        case .manual: "keyboard"
        case .onePassword: "key.fill"
        case .applePasswords: "person.badge.key.fill"
        case .keePassXC: "key.horizontal.fill"
        case .keeper: "key.viewfinder"
        case .bitwarden: "shield.lefthalf.filled"
        case .dashlane: "key.radiowaves.forward"
        case .keePassFile: "doc.badge.gearshape"
        case .passwordStore: "terminal.fill"
        case .lastPass: "asterisk.circle.fill"
        }
    }

    /// Whether this manager can hand over a one-time code by itself —
    /// 1Password computes TOTP from the item, KeePassXC serves get-totp;
    /// Apple Passwords stores codes but exposes none of them to SecItem.
    /// THE one answer the readiness logic, the unattended connect and the
    /// connect form's "still needs a typed code" row all read — it used to be
    /// three scattered `== .onePassword` tests, which is exactly how a new
    /// kind would have half-worked.
    // nonisolated: read inside `ConnectInputs.readiness`, which is nonisolated
    // pure data (the app target defaults to MainActor isolation).
    /// Keeper is deliberately `false`: Keeper Commander does have a `totp`
    /// command, but nobody has proven it end-to-end against a live Keeper vault
    /// from here — and this flag is a PROMISE (true means "Connect is enabled
    /// with no code typed"). A broken promise costs an AUTH_FAILED and a
    /// consumed code; asking for a code we then don't need costs one keystroke.
    /// The fetch still USES a code when Commander hands one over.
    ///
    /// Bitwarden is `false` for exactly the same reason, and it has a second one:
    /// `bw get totp` answers "Premium status is required to use this feature." for
    /// an account without premium, so the vendor's own code route is not
    /// unconditionally available either. SimpleVPN computes the code locally from
    /// the item's TOTP seed when the item carries one — but a promise nobody has
    /// watched work against a live vault is not one to make here.
    nonisolated var suppliesOTP: Bool {
        switch self {
        // `.keePassFile` is deliberately `false`, and NOT because the format
        // cannot carry a code — it can. `keepassxc-cli show -t` prints an entry's
        // current verification code, but its own `Show.cpp` FAILS THE WHOLE RUN
        // when the entry has not got one, and there is no way to ask whether an
        // entry has one without unlocking the database (the expensive part, which
        // may also want a finger on a security key). So passing `-t` speculatively
        // would turn every ordinary entry's fetch into a failed sign-in. This flag
        // is a PROMISE — true means "Connect works with nothing typed" — so it
        // stays false and the code is typed. See KeePassFileProvider's header.
        // `.dashlane` is deliberately `false`, and again NOT because it cannot: an
        // entry's `otpSecret` / `otpUrl` arrives in the same JSON as its password, and
        // the code is computed locally from it when it is there. But this flag is a
        // PROMISE — true means "Connect works with nothing typed" — and no real
        // Dashlane vault has ever answered from this machine. There is a second reason
        // too: whether a given entry carries a seed at all is unknowable until the
        // fetch has already happened, so "Dashlane supplies codes" would be a claim
        // about the user's data rather than about Dashlane.
        // `.lastPass` is `false` for a reason that is not caution but ARITHMETIC:
        // LastPass's command-line tool has no code to give. Its `--json` output is
        // whatever `account_to_json_field` writes (`json-format.c`) — id, name,
        // fullname, username, password, timestamps, share, group, url, note — and
        // there is no code, no seed, and no `lpass totp` subcommand at all. So this
        // is not "unproven"; it is "the vendor's tool cannot", and `LastPassProvider`
        // deliberately sets nothing for `.otp` rather than mining a free-text note
        // for something that looks like a seed.
        case .manual, .applePasswords, .keeper, .bitwarden, .dashlane, .keePassFile,
             .passwordStore, .lastPass: false
        case .onePassword, .keePassXC: true
        }
    }
}

struct CredentialSource: Codable, Sendable, Equatable {
    var kind: CredentialSourceKind = .manual

    /// 1Password: item name or UUID (optionally "vault/item"). Apple Passwords
    /// and KeePassXC: the server/URL to match (e.g. "tig-vpn.grlab.co.uk" —
    /// KeePassXC matches it against each entry's URL field). Keeper: the
    /// record's UID or its folder path ("Work/VPN/GR Lab"). Unused for manual.
    var reference = ""
    /// 1Password: WHICH ACCOUNT to ask — the name shown at the top of
    /// 1Password's sidebar, or its UUID. Not cosmetic: the SDK's desktop-app
    /// integration refuses to build a client without it ("Account not found")
    /// whenever it can't pick one on its own. Apple Passwords and KeePassXC:
    /// the account (username) when a server has several saved logins.
    var account = ""
    /// 1Password only: which vault holds the item ("" = search them all).
    /// Separate from `account` — a vault names a drawer inside an account, and
    /// conflating the two is what made every 1Password fetch fail.
    var vault = ""

    /// WHICH CONFIGURED SOURCE INSTANCE this VPN reads — level 2's id, stored at
    /// level 3 (see SignInSourceInstances.swift). "" means "the one SimpleVPN set
    /// up", which after migration is the database the old single-valued settings
    /// named; it deliberately does not mean "any of them"
    /// (`SourceInstanceResolver`).
    ///
    /// An OPAQUE id, never a path: a database that moves is the same database, and
    /// a profile keyed on its path would silently point at nothing — or at whatever
    /// now sits there. Empty for every single-instance vendor, which have exactly
    /// one thing to talk to and so nothing to name.
    var instanceID = ""

    /// Which of the source item's fields feed which auth role, keyed by
    /// `CredentialField.rawValue` (username/password/otp). Empty ⇒ auto-detect
    /// from the item's field purposes/types (1Password's USERNAME/PASSWORD/OTP).
    var fieldMap: [String: String] = [:]

    var isDefault: Bool {
        kind == .manual && reference.isEmpty && account.isEmpty && vault.isEmpty
            && instanceID.isEmpty && fieldMap.isEmpty
    }

    init() {}

    /// Every key optional: blobs written by older builds are missing whichever
    /// fields hadn't been invented yet, and a strict decode would throw the
    /// whole source away (dropping the user's item choice, not just the new
    /// field). Legacy 1Password blobs carry only `account`, which the app then
    /// used AS THE VAULT — so it is migrated into `vault` while being left in
    /// `account` too: it may equally have been typed into the field labelled
    /// "Account", and the two can't be told apart after the fact. Whichever it
    /// was, it now reaches the side that understands it.
    init(from decoder: any Decoder) throws {
        let c = try decoder.container(keyedBy: CodingKeys.self)
        kind = try c.decodeIfPresent(CredentialSourceKind.self, forKey: .kind) ?? .manual
        reference = try c.decodeIfPresent(String.self, forKey: .reference) ?? ""
        account = try c.decodeIfPresent(String.self, forKey: .account) ?? ""
        // Absent in every blob written before instances existed — and absent means
        // "the one SimpleVPN set up", which is exactly what makes those profiles
        // keep reading the database they always read.
        instanceID = try c.decodeIfPresent(String.self, forKey: .instanceID) ?? ""
        fieldMap = try c.decodeIfPresent([String: String].self, forKey: .fieldMap) ?? [:]
        if let stored = try c.decodeIfPresent(String.self, forKey: .vault) {
            vault = stored
        } else {
            vault = kind == .onePassword ? account : ""
        }
    }

    func encodedBlob() -> Data? {
        guard !isDefault else { return nil }
        return try? JSONEncoder().encode(self)
    }
    static func decode(from blob: Data?) -> CredentialSource {
        guard let blob else { return CredentialSource() }
        return (try? JSONDecoder().decode(CredentialSource.self, from: blob)) ?? CredentialSource()
    }
}

// MARK: - Connect readiness (single source of truth)

/// What a VPN still needs before Connect can succeed — the ONE decision the
/// detail Connect button, the sidebar play button and the menu row all read, so
/// a control can never be enabled in one place and disabled in another.
///
/// It used to be recomputed independently in each view (`ConnectionView`'s
/// `canConnect` vs `VPNSidebarRow`'s `missingTypedInput`), and the two drifted:
/// the detail pane knew Tailscale/autologin/proxy need nothing typed, but the
/// sidebar still assumed a username+password and so showed "Sign-in needed" on a
/// Tailscale VPN and dimmed its play button — even while the detail Connect was
/// live. Both now derive from `ConnectInputs.readiness` below.
nonisolated enum ConnectReadiness: Equatable, Sendable {
    /// A click connects now — nothing is waiting on typed input.
    case ready
    /// Username + password still needed (or a proxy's stored sign-in details).
    case needsSignIn
    /// A one-time code the stored source can't supply is still needed.
    case needsCode
    /// A hard configuration problem — Connect cannot proceed as set up.
    case blocked
}

/// The plain facts the readiness decision turns on, gathered by `VPNController`
/// from the profile, its auth config, its credential source and any typed input.
/// A pure value type so the decision is testable without a live tunnel.
nonisolated struct ConnectInputs: Equatable, Sendable {
    var kind: VPNKind = .openVPN
    /// The certificate is the sign-in — no credentials to collect.
    var autologin = false

    // Proxy Tunnel (dials on its stored settings — no OTP; credentials, when the
    // proxy needs them, are entered in the editor, not the connect row).
    var proxyHasProblem = false
    var proxyRequiresAuth = false
    var proxyCredentialsComplete = false

    // WireGuard (signs in with its stored keys — nothing typed; the keys and
    // the peer settings are entered in the editor, not the connect row).
    var wireGuardHasProblem = false
    var wireGuardHasKey = false

    // Credential collection (OpenVPN and the other typed-credential kinds).
    var managerKind: CredentialSourceKind = .manual
    var requiresOTP = false
    var biometricProtected = false
    var biometricStored = false
    var biometricHasTOTP = false
    var hasLockedUsername = false
    var typedUsername = false
    var typedPassword = false
    var typedOTP = false
    /// SSH Network Tunnel: an unusable config (no server, no login name, a
    /// truncated pin) blocks; a missing credential is a SIGN-IN prompt, because
    /// that is a thing the user can supply from the connect panel.
    var sshNetHasProblem = false
    var sshNetHasCredential = false

    var readiness: ConnectReadiness {
        // Tailscale/Headscale sign themselves in — a stored setup key registers
        // the Mac silently, or the engine opens a browser sign-in on connect.
        // There is nothing to type first.
        if kind == .tailscale { return .ready }

        // A Proxy Tunnel connects on its stored configuration.
        if kind == .proxyTunnel {
            if proxyHasProblem { return .blocked }
            if !proxyRequiresAuth { return .ready }
            return proxyCredentialsComplete ? .ready : .needsSignIn
        }

        // WireGuard signs in with its keys — nothing typed. A missing private
        // key (or an unusable peer config) is an editor problem, not a
        // credential prompt, so it blocks rather than asks.
        if kind == .wireGuard {
            return (wireGuardHasProblem || !wireGuardHasKey) ? .blocked : .ready
        }

        // An SSH Network Tunnel signs in with what is stored. An unusable config
        // blocks (an editor problem, not something to type); a missing password or
        // key is a sign-in prompt.
        if kind == .sshNetworkTunnel {
            if sshNetHasProblem { return .blocked }
            return sshNetHasCredential ? .ready : .needsSignIn
        }

        // Autologin: the profile's certificate IS the sign-in.
        if autologin { return .ready }

        // A password manager supplies username/password on connect; only a code
        // it cannot provide (Apple Passwords can't; 1Password and KeePassXC
        // can) still blocks.
        if managerKind != .manual {
            let needsTypedCode = requiresOTP && !managerKind.suppliesOTP && !typedOTP
            return needsTypedCode ? .needsCode : .ready
        }

        // Touch ID-protected sign-in: the fingerprint releases everything the
        // store holds; only an uncovered one-time code can still block.
        if biometricProtected, biometricStored {
            let needsTypedCode = requiresOTP && !biometricHasTOTP && !typedOTP
            return needsTypedCode ? .needsCode : .ready
        }

        // Plain typed credentials (a userlocked username counts as present).
        if !(hasLockedUsername || typedUsername) || !typedPassword { return .needsSignIn }
        return (requiresOTP && !typedOTP) ? .needsCode : .ready
    }
}
