// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
//  AuthPlan.swift
//  THE UNIFIED CALL RETURNS A PLAN, NOT A SECRET.
//
//  This is the decision the whole abstraction turns on, and it was forced by the code
//  rather than chosen: SimpleVPN already ships nine authentication mechanisms, and
//  THREE OF THEM NEVER HAND OVER BYTES.
//
//    • The SSH agent SIGNS. `ssh_userauth_agent` asks the agent to sign a challenge;
//      the private key never leaves it, and there is nothing for a fetch to return.
//      What can be planned is the agent's SOCKET PATH.
//    • The PKCS#11 module is loaded by `openconnect` ITSELF, through p11-kit.
//      SimpleVPN cannot `dlopen` it at all (hardened runtime plus AMFI
//      library-validation on a system-extension-embedding app), so there is no shape
//      in which we hold the key. What can be planned is the `pkcs11:` URI.
//    • A security key TYPES. It is a USB HID keyboard: it puts keystrokes into
//      whatever field has focus, and the bytes never cross an API. What can be
//      planned is an ARMED CAPTURE — the guarantee that the right field is focused,
//      with a timeout and a cancel.
//
//  A `resolve() -> RawCredentials` seam cannot express any of those. It expressed the
//  first two as "a private key we failed to fetch" and the third not at all, which is
//  precisely why all three sat OUTSIDE the credential seam, each with its own return
//  shape, its own error convention and its own waiting mechanism — the combinatorial
//  explosion the abstraction exists to prevent, arriving through the back door.
//
//  So: `.value` yields bytes, `.possession` yields a NAME, `.typedByDevice` yields an
//  armed capture. THE CONNECT PATH EXECUTES THE PLAN.
//
//  WHAT IS DELIBERATELY NOT MODELLED HERE, and why — because an abstraction that
//  quietly swallows a mechanism it cannot express is worse than one that says so:
//
//    • OpenConnect's conversational SSO (`ocauth-helper`, `OpenConnectAuthClient`,
//      `BrowserLauncher`) and Tailscale's control-URL sign-in are not plans. In both,
//      the ENGINE conducts the authentication and SimpleVPN's whole role is to open a
//      browser when the engine asks. There is no credential for us to plan, name or
//      arm — no bytes, no name we supply, no field we focus. Forcing them into
//      `.possession` would mean inventing a name nobody passes. A `.conductedByEngine`
//      case is the shape they would take, and it is not added until something needs
//      it: a case with no producer is a promise.
//    • Tailscale's setup key rides `startTunnel(options:)` already and is not fetched
//      from any source, so it has no `AuthKind` and no plan. That is why `.setupKey`
//      is absent from `AuthKind` — see its header.
//

import Foundation

// MARK: - The plan

/// What to DO to satisfy an authentication. One of exactly three shapes.
nonisolated enum AuthPlan: Sendable {

    /// THE BYTES, in the carrier the connect path already assembles from
    /// (`CredentialRequest.assemble`). Reused rather than replaced: `RawCredentials`
    /// was right for this delivery and only this delivery.
    case value(RawCredentials)

    /// A NAME. The engine loads the thing itself; nothing is handed over because
    /// nothing can be.
    case possession(AuthPossession)

    /// AN ARMED CAPTURE. The device will type; the plan says into which field, for how
    /// long, and what shape to expect.
    case typedByDevice(AuthCaptureTicket)

    /// Which delivery this is. Lets a caller decide how to execute without matching on
    /// the payload it does not need.
    var delivery: AuthDelivery {
        switch self {
        case .value: .value
        case .possession: .possession
        case .typedByDevice: .typedByDevice
        }
    }
}

// MARK: - A name, never bytes

/// The NAME of something the engine will load, unlock or ask on our behalf.
///
/// Every case here is a string or a number that is safe to hold, safe to compare and
/// — with one stated exception — safe to log. None of them is a secret, and there is
/// no case that could carry one: that is the structural guarantee, not a convention.
nonisolated enum AuthPossession: Sendable, Equatable {

    /// An SSH agent that will SIGN. The path of its unix socket.
    ///
    /// Safe to show and safe to log: it is a filesystem path, and it is exactly what
    /// the user typed into the settings field. The KEY is what is secret, and the key
    /// is the agent's, not ours — `ssh_userauth_agent` gets a signature back and never
    /// key material. Passed to libssh as `SSH_OPTIONS_IDENTITY_AGENT`, or to
    /// `/usr/bin/ssh` as `IdentityAgent=` in a generated config (never argv, because
    /// ssh has no flag for it).
    case agentSocket(path: String)

    /// A PKCS#11 object, named by an RFC 7512 URI.
    ///
    /// THE QUERY IS ALWAYS STRIPPED before it gets here (`PKCS11URI.withoutQuery`),
    /// and that is a security control rather than tidiness: `pin-value` and
    /// `pin-source` are query attributes, and this URI reaches OpenConnect's ARGV,
    /// where every process on the Mac can read it through `ps`. The PIN travels on
    /// stdin and only on stdin — which is why `.tokenPIN` is a separate `AuthKind`
    /// with a separate `.value` plan, and never part of this name.
    ///
    /// `module` is informational only. OpenConnect has no "use this module" option: it
    /// resolves the URI through p11-kit, which loads only what a `.module` file
    /// declares, so a path here is for telling the user what to register — never
    /// something we pass.
    case pkcs11Object(uri: String, module: String?)

    /// A security key's HMAC-SHA1 slot, which will answer a challenge without ever
    /// releasing the secret programmed into it. The slot number, and which key when
    /// several are attached.
    ///
    /// This is the mechanism the `.kdbx` unlock needs, and it is a possession proof in
    /// the strictest sense available here: the challenge goes in, twenty bytes come
    /// back, and the key's own secret is unobtainable by design.
    case securityKeySlot(slot: Int, serial: String?)

    /// A one-line description safe for a log or a diagnostic report. No case has a
    /// secret to leak, and this method existing is what stops a caller reaching for
    /// string interpolation on the payload and getting it wrong later.
    var loggableSummary: String {
        switch self {
        case .agentSocket: "ssh agent socket"
        case .pkcs11Object: "pkcs11 object uri"
        case .securityKeySlot(let slot, _): "security key slot \(slot)"
        }
    }
}

// MARK: - An armed capture

/// EVERYTHING THE FOCUS GUARANTEE NEEDS. A security key types into whatever field has
/// focus, so focus management *is* the feature: get it wrong and a one-time
/// credential lands in the wrong field, the wrong window, or another application.
///
/// A ticket rather than the capture object itself, deliberately. `YubiKeyCapture` is a
/// `@MainActor @Observable` class that a view owns for its whole lifetime — it holds
/// the `InteractionWait`, the `SingleUseCode` and the return-key policy. A plan is a
/// value produced per attempt, so it says what to arm and how; the view arms its own
/// capture with it. That keeps the plan `Sendable` and testable with nothing on
/// screen, and keeps the single-use code in exactly one place.
nonisolated struct AuthCaptureTicket: Sendable, Equatable {

    /// Which of the four security-key mechanisms. Decides whether anything is typed at
    /// all: `.oathCode` and `.challengeResponse` are FETCHED (`ykman` computes and we
    /// read the answer), and only `.yubicoOTP` and `.staticPassword` are keystrokes.
    var mechanism: YubiKeyCodeMechanism

    /// How the code joins the sign-in — appended to the password, its own field, or
    /// the whole of it. This is the requirement that started the security-key work:
    /// many gateways expect `{password}{otp}` in one field.
    var delivery: YubiKeyCodeDelivery

    /// WHICH FIELD MUST HAVE FOCUS. Carried as an `AuthKind` so it is the same
    /// vocabulary as everything else, and so the answer is derived from `delivery`
    /// rather than remembered at each call site.
    var focus: AuthKind

    /// How long to wait for the touch. A deadline, not a hope: without one the state
    /// never resolves and the user is left looking at a spinner.
    var wait: TimeInterval

    init(mechanism: YubiKeyCodeMechanism, delivery: YubiKeyCodeDelivery,
         wait: TimeInterval) {
        self.mechanism = mechanism
        self.delivery = delivery
        self.wait = wait
        // DERIVED, never passed in. `.appendedToPassword` composes inside the password
        // field, so that is where focus must be; everything else lands in the code
        // field. Deriving it here is what stops two call sites disagreeing about which
        // field a key is about to type into.
        self.focus = delivery == .appendedToPassword ? .password : .otp
    }

    /// Whether this ticket is executed by ARMING A FIELD (the device types) or by
    /// ASKING THE TOOL (the device computes and we read it back). Both are
    /// `.typedByDevice` plans because both end with a code in a field the user can
    /// see and cancel — but only one of them needs the focus guarantee.
    var isKeystrokeCapture: Bool { mechanism.isTypedByKey }
}

// MARK: - AXIS 3 as an identity: every source, vault or not

/// WHICH MECHANISM a plan came from.
///
/// Deliberately NOT `SignInSourceID`, and the difference is meaningful rather than
/// bureaucratic: `SignInSourceID` names a ROW IN THE CHOOSER — the things a person
/// picks when answering "where is my sign-in kept?" — and the SSH agent, a PKCS#11
/// token and a security key are none of those. They are per-VPN authentication
/// methods configured in that VPN's editor, and putting them in the chooser would
/// invite somebody to choose "SSH agent" as the place their OpenVPN password lives.
///
/// So the two enums answer two questions, and the overlap between them is exactly the
/// twelve vault vendors plus typing, the keychain and AutoFill.
nonisolated enum AuthSourceID: Hashable, Sendable {
    /// Typed by the person, every time. The floor: a Mac with nothing installed still
    /// has a keyboard.
    case typed
    /// The Apple keychain, this app's own items. `biometric` is whether the Touch ID
    /// access control is on — a genuinely different source, because a biometric item
    /// can never be synchronizable and one fingerprint releases everything at once.
    case appKeychain(biometric: Bool)
    /// macOS's own AutoFill, filling our fields. The one source that fetches nothing.
    case systemAutoFill
    /// One of the twelve password vendors.
    case vault(LocalVaultVendor)
    /// An SSH agent that signs.
    case sshAgent
    /// A PKCS#11 token whose module the engine loads.
    case pkcs11Token
    /// A security key that types or computes.
    case securityKey

    /// A stable string for accessibility identifiers, log lines and test addressing.
    var rawValue: String {
        switch self {
        case .typed: "typed"
        case .appKeychain(let biometric): biometric ? "keychain-touchid" : "keychain"
        case .systemAutoFill: "system-autofill"
        case .vault(let vendor): vendor.rawValue
        case .sshAgent: "ssh-agent"
        case .pkcs11Token: "pkcs11-token"
        case .securityKey: "security-key"
        }
    }
}

// MARK: - What a source DECLARES

/// The capability summary line, as a type.
///
/// Every one of the twelve feeds ended its report with the same pasteable line —
/// transport, supplies, proves, withholds, interactivity, lifetime, probe, states,
/// save-back, exit. Twelve prose answers agreeing on a shape is what a shape is for,
/// so this is that line, checkable by the compiler and assertable by one test instead
/// of read out of twelve documents.
///
/// THE THREE SETS ARE NOT THE SAME QUESTION, and keeping them apart is the point:
///
///   • `supplies`  — hands over the bytes. `.value`.
///   • `proves`    — will demonstrate it has the thing, without ever releasing it.
///                   `.possession`. An `SSHAgentIdentity` is public-key metadata; a
///                   PKCS#11 certificate is a name; a security-key slot answers a
///                   challenge. Nothing crosses.
///   • `withholds` — HOLDS IT AND WILL NOT GIVE IT TO US. Apple Passwords is the case
///                   that makes this a first-class set rather than an omission: it
///                   stores verification codes and exposes none of them to other
///                   apps, by design, for ever. "Absent from `supplies`" would read as
///                   an oversight; `withholds` says it is a decision somebody else
///                   made and no amount of work here changes it.
nonisolated struct AuthSourceDescriptor: Sendable, Equatable {

    var id: AuthSourceID
    /// Most-preferred first. A source with two ways in lists both (Keeper: its local
    /// daemon, then its CLI) and its own code decides.
    var transports: [AuthTransport]
    var supplies: Set<AuthKind> = []
    var proves: Set<AuthKind> = []
    var withholds: Set<AuthKind> = []
    /// How many level-2 instances this source can have. A FACT about it, never a
    /// preference — see `SourceCardinality`.
    var cardinality: SourceCardinality = .single
    /// The delivery its satisfied kinds take. A source has exactly one, which is why
    /// delivery is an attribute of a (kind, source) pair and not a fourth axis: no
    /// shipped source hands over bytes for one kind and a name for another.
    var delivery: AuthDelivery = .value
    /// The honest ceiling on what a probe can establish, or nil when a probe can prove
    /// the whole path. nil for the local sources; set for the ones whose deeper check
    /// would cost a side effect.
    var probeCeiling: AuthProbeCeiling?

    /// Whether this source can hand over anything at all. False for the two that
    /// exist to be honest about NOT being able to: system AutoFill (macOS fills our
    /// fields; we never read anything) and a pointer to an app we cannot read.
    var fetchesAnything: Bool { !supplies.isEmpty || !proves.isEmpty }
}

// MARK: - The registry: sixteen mechanisms, one table

/// EVERY authentication mechanism SimpleVPN has, declared once.
///
/// This table is the answer to "what can this app actually do, and which of it has
/// been proven?" — a question that previously needed twelve files, four unrelated
/// mechanisms and a document to answer. One test walks it and holds every claim to the
/// vendor's own adapter, so the table cannot drift from the code.
///
/// The vault rows read their transports and cardinality FROM the adapters rather than
/// repeating them, because those were already declared and a second declaration is a
/// second thing to keep right.
nonisolated enum AuthSourceCatalog {

    /// The three sources that need no vendor and no detection.
    static let typed = AuthSourceDescriptor(
        id: .typed, transports: [],
        // Everything a person can type. `.certificate` and `.sshKey` are absent
        // because nobody types a PEM into a connect row — those are file fields in an
        // editor, which is a different surface and a different story.
        supplies: [.username, .password, .otp, .privateKeyPassphrase, .tokenPIN],
        delivery: .value)

    static let keychain = AuthSourceDescriptor(
        id: .appKeychain(biometric: false), transports: [.osKeychain],
        // The TOTP secret is stored, so the code is computed locally from it — which is
        // why `.otp` is supplied here and withheld by Apple Passwords. Same OS, two
        // completely different answers, because these are OUR items in OUR access
        // group and those are Safari's in `com.apple.cfnetwork`.
        supplies: [.username, .password, .otp],
        delivery: .value)

    static let biometricKeychain = AuthSourceDescriptor(
        id: .appKeychain(biometric: true), transports: [.osKeychain],
        supplies: [.username, .password, .otp],
        delivery: .value)

    /// APPLE PASSWORDS — the row that exists to be honest.
    ///
    /// `supplies` is empty and `withholds` is not, and that is the whole finding:
    /// SimpleVPN cannot read what Safari and the Passwords app manage (those items are
    /// in the data-protection keychain under an access group this app's entitlement
    /// does not contain — unreachable by construction, not merely missing), and it
    /// cannot write there either (`SecAddSharedWebCredential` needs the VPN
    /// operator's own web server to name us, and is deprecated at macOS 26.2 with a
    /// macOS-unavailable replacement). What works is AUTOFILL: macOS fills our fields
    /// when the user clicks the key.
    ///
    /// `ApplePasswordsProvider` does still exist and does still read the FILE keychain
    /// for an `.internetPassword` matching the server, which is why `.username` and
    /// `.password` appear in `supplies` for that narrow path — but never `.otp`, which
    /// Apple exposes to nobody.
    static let applePasswords = AuthSourceDescriptor(
        id: .systemAutoFill, transports: [.osAutoFill],
        supplies: [.username, .password],
        withholds: [.otp],
        delivery: .value)

    // MARK: The four that are not vaults

    /// THE SSH AGENT. The highest value per line in the whole programme, and the
    /// clearest case for `.possession`: one option (`SSH_OPTIONS_IDENTITY_AGENT`) plus
    /// one call (`ssh_userauth_agent`) unlocks 1Password's agent, Secretive's
    /// Secure-Enclave agent, KeePassXC's agent and every hardware key — and the
    /// private key never leaves any of them.
    ///
    /// `proves: [.keyInAgent]` and `supplies: []`, exactly. There is nothing to
    /// supply, and an abstraction that insisted on bytes would have had to call this
    /// mechanism a failure.
    ///
    /// App-process only, and that is a fact about the OS rather than a limitation of
    /// the design: the system extension runs as root in the system context, where
    /// `SSH_AUTH_SOCK` does not exist.
    static let sshAgent = AuthSourceDescriptor(
        id: .sshAgent, transports: [.agent],
        proves: [.keyInAgent],
        delivery: .possession)

    /// A PKCS#11 TOKEN. Two kinds, two deliveries, and this is the one source where
    /// they differ — which is why the descriptor's single `delivery` is `.possession`
    /// and the PIN is called out here rather than modelled as a second delivery:
    ///
    ///   • `.certificate` is PROVED. The URI is a name; `openconnect` resolves it
    ///     through p11-kit and loads the module itself. SimpleVPN cannot load it.
    ///   • `.tokenPIN` is SUPPLIED — on stdin, to the tool's first password prompt,
    ///     and nowhere else. Never in the URI (`pin-value` is refused at parse time,
    ///     because the URI reaches argv) and never in a log.
    static let pkcs11Token = AuthSourceDescriptor(
        id: .pkcs11Token, transports: [.hardware],
        supplies: [.tokenPIN],
        proves: [.certificate],
        delivery: .possession)

    /// A SECURITY KEY. Four mechanisms, and they split across two deliveries — which
    /// is the one place the "one delivery per source" simplification is genuinely
    /// approximate, so it is stated rather than hidden:
    ///
    ///   • Yubico OTP and the static password are TYPED. The key is a USB HID
    ///     keyboard; the bytes never cross an API; focus management is the feature.
    ///   • An OATH code is COMPUTED and read back through `ykman` — a `.value` in
    ///     everything but the fact that a finger may be required.
    ///   • HMAC-SHA1 challenge-response PROVES possession: twenty bytes come back and
    ///     the key's own secret is unobtainable. This is what a `.kdbx` unlock needs.
    ///
    /// `delivery` is `.typedByDevice` because that is the one that constrains the
    /// CALLER — it is the only delivery that needs a focused field, a deadline and a
    /// cancel, and a caller that handles it handles the rest.
    static let securityKey = AuthSourceDescriptor(
        id: .securityKey, transports: [.hardware],
        supplies: [.otp, .password],
        proves: [.keyInAgent],
        delivery: .typedByDevice,
        // A deeper check would spend a code to find out whether codes work.
        probeCeiling: .wouldSpendSingleUseCode)

    /// One descriptor per vault vendor, built from what its adapter already declares —
    /// so a thirteenth vendor appears here by existing, and cannot appear with
    /// transports that disagree with its own code.
    /// `@MainActor` because it reads the adapter registry, which is: the registry
    /// consults the settings store for the discovery switch. The four non-vault
    /// descriptors above stay nonisolated — they declare facts about hardware and the
    /// OS, and nothing needs to be asked.
    @MainActor
    static func vault(_ vendor: LocalVaultVendor) -> AuthSourceDescriptor {
        AuthSourceDescriptor(
            id: .vault(vendor),
            transports: LocalVaultRegistry.adapter(for: vendor)?.transports ?? [],
            // Every vault serves a username and a password; that is what makes it a
            // vault. Whether it serves a CODE is a per-vendor promise, and
            // `suppliesOTP` is the one place that promise is made — read from there
            // rather than restated, because restating it is how a promise ends up true
            // in one file and false in another.
            supplies: vaultSupplies(vendor),
            withholds: vaultWithholds(vendor),
            cardinality: vendor.cardinality,
            delivery: .value)
    }

    @MainActor
    private static func vaultSupplies(_ vendor: LocalVaultVendor) -> Set<AuthKind> {
        var out: Set<AuthKind> = [.username, .password]
        // The private-key passphrase is mappable wherever a field map exists, which
        // today is 1Password alone.
        if vendor == .onePassword { out.insert(.privateKeyPassphrase) }
        if storedKind(vendor)?.suppliesOTP == true { out.insert(.otp) }
        return out
    }

    /// A vault that CANNOT hand over a code, as opposed to one that merely has not
    /// been proven able to. The distinction is `Docs/CredentialSources.md`'s: only
    /// LastPass is permanent, because its own tool's JSON has no field for a code and
    /// no `totp` subcommand — that is arithmetic, not caution. Everything else is
    /// "unproven" or "unknowable in advance", and neither of those is withholding.
    private static func vaultWithholds(_ vendor: LocalVaultVendor) -> Set<AuthKind> {
        vendor == .lastPass ? [.otp] : []
    }

    @MainActor
    private static func storedKind(_ vendor: LocalVaultVendor) -> CredentialSourceKind? {
        LocalVaultRegistry.adapter(for: vendor)?.storedKind
    }

    /// EVERYTHING, in the order the sign-in chooser offers what it offers and then the
    /// per-VPN mechanisms that are not chooser rows at all.
    @MainActor
    static var all: [AuthSourceDescriptor] {
        [typed, keychain, biometricKeychain, applePasswords]
            + LocalVaultVendor.allCases.map(vault)
            + [sshAgent, pkcs11Token, securityKey]
    }

    @MainActor
    static func descriptor(for id: AuthSourceID) -> AuthSourceDescriptor? {
        all.first { $0.id == id }
    }

    /// The descriptor a stored per-VPN source implies. `.manual` is ambiguous on
    /// purpose — it means "typed" or "the keychain" depending on whether anything is
    /// saved and whether Touch ID protects it, which only the controller knows — so
    /// this answers for the vendor-backed kinds and Apple Passwords, and the caller
    /// resolves the rest.
    @MainActor
    static func descriptor(forStored kind: CredentialSourceKind) -> AuthSourceDescriptor? {
        switch kind {
        case .manual: nil
        case .applePasswords: applePasswords
        case .onePassword, .keePassXC, .keeper, .bitwarden, .dashlane, .keePassFile,
             .passwordStore, .lastPass, .protonPass, .passbolt:
            LocalVaultRegistry.adapter(for: kind).map { vault($0.vendor) }
        }
    }
}
