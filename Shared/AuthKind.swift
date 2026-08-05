// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
//  AuthKind.swift
//  AXIS 1 OF THREE: WHAT is being asked for.
//
//  The unified authentication abstraction has exactly three axes, and this is the
//  first:
//
//    • KIND       (this file) — what is wanted: a username, a password, a
//                 verification code, a certificate, a key held in an agent, a
//                 token's PIN. A CLOSED enum: it grows when a PROTOCOL grows, not
//                 when a vendor is added, and every switch over it is exhaustive so
//                 the compiler asks the question rather than a reviewer.
//    • TRANSPORT  (`AuthTransport`) — the shape of the CHANNEL. A handful of them,
//                 and the shape — not the brand — is what decides how detection,
//                 liveness and failure behave.
//    • VENDOR     (`LocalVaultVendor`, `AuthSourceID`) — grows freely, and adds
//                 nothing to the other two. That is the whole point: a thirteenth
//                 vendor is one file, not one more case in every switch.
//
//  DELIVERY IS NOT A FOURTH AXIS. Whether a (kind, source) pair hands over bytes,
//  names something the engine loads itself, or types into a focused field is an
//  ATTRIBUTE of that pair — see `AuthDelivery`.
//
//  WHY THIS TYPE REPLACED TWO. Before consolidation there were `CredentialField`
//  (four cases, in Shared, "what a source is asked to supply") and `CredentialRole`
//  (seven cases, in the app, "what slot a VPN needs filled, with its copy"). They
//  overlapped BY CONVENTION — the old header said so out loud: "Role ids reuse
//  CredentialField.rawValue where they overlap so the provider and the stored
//  mapping agree on names." A convention is not a guarantee: nothing stopped the two
//  drifting, and the stored `fieldMap` in every profile is keyed on those raw values.
//  One enum makes the agreement structural.
//
//  RAW VALUES ARE AN ON-DISK CONTRACT. `CredentialSource.fieldMap` is persisted in
//  `providerConfiguration` keyed by these strings, so the case NAMES may change but
//  the raw values may not. `.otp` keeps its raw value for exactly that reason even
//  though every user-facing string says "verification code" (the house glossary).
//
//  This file is compiled into the system extension as well as the app, so it stays
//  pure: no UI, no AppKit, no copy. The words live in
//  `SimpleVPN/Credentials/AuthKindCopy.swift`.
//

import Foundation

/// ONE kind of thing an authentication can need.
///
/// Closed on purpose. A new case here is a claim that some protocol authenticates
/// with a genuinely new sort of thing — not that a new vendor has appeared, and not
/// that an existing thing arrives over a new channel.
nonisolated enum AuthKind: String, Sendable, CaseIterable, Hashable, Codable, Identifiable {

    // MARK: The four every source speaks

    case username
    case password
    /// The one-time verification code. Case name kept short because the raw value is
    /// an on-disk contract (`fieldMap`); every user-facing string says "verification
    /// code" per the house glossary.
    case otp
    /// A WebAuthn/FIDO2 assertion. Present as a kind because the envelope is built
    /// (see the FIDO2 work) even where no shipped VPN kind consumes one yet.
    case passkey

    // MARK: The key-and-certificate kinds

    case certificate
    case privateKeyPassphrase
    case sshKey

    // MARK: The two POSSESSION kinds — never bytes, always a name
    //
    // These exist because the abstraction returns a PLAN rather than a secret. An
    // agent SIGNS without releasing the key; a PKCS#11 module is loaded by
    // `openconnect` itself. Both are real authentications with nothing to hand over,
    // and modelling them as "a private key we failed to fetch" is what forced them
    // outside the old seam.

    /// A private key held by an agent that will SIGN on our behalf. What is planned
    /// is the agent's socket path — never key material.
    case keyInAgent
    /// The PIN that unlocks a hardware token, handed to whichever engine loads the
    /// module. Distinct from `.privateKeyPassphrase`: that unlocks a FILE we could in
    /// principle read, this unlocks a DEVICE we cannot.
    case tokenPIN

    var id: String { rawValue }
}

// MARK: - Sets a request is built from

nonisolated extension AuthKind {

    /// The kinds a plain username/password sign-in needs.
    static let usernamePassword: Set<AuthKind> = [.username, .password]
    /// The same, plus a verification code.
    static let usernamePasswordOTP: Set<AuthKind> = [.username, .password, .otp]

    /// Whether this kind is a SECRET — something that must never reach argv, a log
    /// line, an error string or a diagnostic bundle.
    ///
    /// `.username` is deliberately NOT a secret (it is routinely displayed, and
    /// pretending otherwise would mean redacting the thing the connect row shows).
    /// Everything else is, including the two possession kinds: what is planned for
    /// those is a NAME, but the name is not the secret and the secret is not ours.
    var isSecret: Bool {
        switch self {
        case .username: false
        case .password, .otp, .passkey, .certificate, .privateKeyPassphrase, .sshKey,
             .keyInAgent, .tokenPIN:
            true
        }
    }

    /// Whether spending this kind COSTS something that cannot be got back — the
    /// property that decides what must never be silently retried.
    ///
    /// `.otp` is the case that names it: a one-time code is spent by the ATTEMPT, not
    /// by success, so a silent retry is guaranteed to fail and may count toward a
    /// gateway's lockout. `.tokenPIN` spends a retry counter, which is worse: three
    /// wrong PINs block a token and the fix is an admin key the user has not got.
    var isSpentByAttempt: Bool {
        switch self {
        case .otp, .tokenPIN: true
        case .username, .password, .passkey, .certificate, .privateKeyPassphrase,
             .sshKey, .keyInAgent:
            false
        }
    }
}

// MARK: - AXIS 2: the shape of the channel

/// HOW a source is reached. Deliberately separate from the vendor, because the
/// shape of the channel — not the brand — decides how detection, session liveness
/// and failure behave.
///
/// This IS the old `LocalVaultTransport`, widened to cover the mechanisms that are
/// not vaults at all. The five vault shapes keep their exact raw values, because
/// that enum was `CaseIterable` over a stable string and the diagnostic report
/// prints them.
nonisolated enum AuthTransport: String, Sendable, CaseIterable, Hashable {
    /// A vendor library doing app-to-app IPC (1Password's SDK). Detection = the
    /// library is on disk AND the app is running.
    case signedIPC
    /// A unix socket the running app listens on (KeePassXC's browser protocol).
    /// Detection = the socket exists. Nothing to spawn.
    case appSocket
    /// The vendor's own command-line tool. Detection = the tool is on disk; liveness
    /// = a session probe; failures arrive on stderr and must be scrubbed.
    case cli
    /// A loopback HTTP/REST server the vendor's tool starts (`bw serve`, Keeper's
    /// Service Mode). Cheaper per fetch than spawning.
    case localDaemon
    /// A vault FILE read directly, no vendor process at all — which is why one
    /// adapter serves KeePassXC-as-a-file, Strongbox and KeePassium.
    case file

    // MARK: The shapes that are not vaults
    //
    // Every one of these was already built and already working; none of them had a
    // name in the transport axis, which is exactly why they sat outside the seam.

    /// The macOS keychain, reached through `SecItem` — optionally behind Touch ID.
    /// Detection is free and local; there is no vendor and nothing to install.
    case osKeychain
    /// macOS's own AutoFill, which fills OUR fields when the user clicks the key.
    /// The one transport where SimpleVPN never fetches anything: it configures the
    /// field and gets out of the way.
    case osAutoFill
    /// An SSH agent over its unix socket. The key never leaves the agent — the agent
    /// signs. Detection = the socket answers a request-identities.
    case agent
    /// A physical device: a HID keyboard that types, a PKCS#11 token, a security key.
    /// Detection is enumeration, never a spawn.
    case hardware

    /// Whether establishing this channel's LIVENESS costs a subprocess.
    ///
    /// Every shape has a cheap PRESENCE probe — a stat, a bundle lookup, a socket
    /// check, an IORegistry read — and that is what the two-speed availability model
    /// rests on. What differs is the second question: "and can it answer right now?"
    /// For four of these shapes that costs a process, and a process is the thing that
    /// can put a vendor's own approval or Touch ID sheet on screen. That is why the
    /// deep pass is once per launch and skips switched-off vendors, and it is why the
    /// adapters whose answer is `false` here honestly return their cheap answer
    /// unchanged from `deepScan`.
    ///
    /// Distinct from `AuthProbeCeiling`, deliberately: this is about COST, that is
    /// about SIDE EFFECTS. Passbolt is `.cli` and so expensive to probe — but the
    /// reason it is never probed is that the probe would be a sign-in attempt against
    /// somebody else's server, which no amount of cheapness would excuse.
    var livenessNeedsSubprocess: Bool {
        switch self {
        // 1Password's SDK probe spawns `opnative-helper`; the vendor CLIs and their
        // loopback daemons are processes by definition; `ykman` starts a Python
        // interpreter to ask a security key anything at all.
        case .signedIPC, .cli, .localDaemon, .hardware: true
        // A socket either answers or it does not; a file either stats or it does not;
        // the keychain and AutoFill are the OS. Nothing to start.
        case .appSocket, .file, .osKeychain, .osAutoFill, .agent: false
        }
    }
}

// MARK: - Delivery: an attribute, not an axis

/// HOW a satisfied (kind, source) pair actually reaches the engine.
///
/// THE DECISION THIS TYPE RECORDS. An abstraction returning raw bytes cannot express
/// three of the mechanisms this app already ships: the SSH agent signs without
/// releasing a key, the PKCS#11 module is loaded by `openconnect` itself, and a
/// YubiKey *types* into a focused field. Forcing those outside reintroduces the
/// combinatorial explosion the abstraction exists to prevent — so the unified call
/// returns a PLAN (`AuthPlan`) whose case is this.
nonisolated enum AuthDelivery: String, Sendable, CaseIterable, Hashable {
    /// The bytes. `startTunnel(options:)` or a tool's stdin.
    case value
    /// A NAME — an agent socket path, a `pkcs11:` URI, a slot number — and the engine
    /// loads the thing itself. Nothing is handed over because nothing can be.
    case possession
    /// An armed capture: the device types, and the abstraction's job is to guarantee
    /// the right field has focus, with a timeout and a cancel.
    case typedByDevice
}
