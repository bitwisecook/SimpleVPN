// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
//  ConnectListing.swift
//  WHY A CONNECTION IN THE CONNECT LIST CANNOT GO YET, AND WHERE THE FIX IS —
//  for the two kinds of connection that are not NE profiles: the subprocess
//  tunnels (SSH and the seven OpenConnect SSL-VPNs) and the native personal VPNs
//  (IKEv2 / IPsec / L2TP).
//
//  THE BUG THIS EXISTS TO KILL. `ConnectionView` listed a subprocess tunnel only
//  while `tunnelManager.isActive(_:)` — so a profile could not appear before it
//  was connected, and could not be connected from the connect window because it
//  was not there. A closed loop: the user added an F5 BIG-IP APM, could see it in
//  Manage VPNs, and could not find it in the main window. The native configs had
//  the same shape of bug one line further down (only the ACTIVE one was listed).
//
//  THE RULE, and it is general: NEVER HIDE A PROFILE THE USER CREATED. List it the
//  moment it exists, disable the action, say what is missing, and link to the exact
//  place to fix it. An absent row is indistinguishable from a lost profile, and an
//  absent button from a broken layout.
//
//  WHY THIS FILE RATHER THAN A PREDICATE IN THE VIEW. "Is this configured?" was
//  already answered in `SubprocessTunnelView.connectBlockedReason` and
//  `NativeVPNView.missingFieldCaption` — inside view bodies, as `String?`, reachable
//  by nothing else. The connect list needed the same answer, and the one thing that
//  must not happen is a SECOND notion of "configured" (that divergence is exactly
//  what was just removed from the connect path — see `VPNController+Auth.swift`).
//  So the decision moves here, as a value, and both editors read it.
//
//  IT SPEAKS THE READINESS MODEL'S OWN VOCABULARY, deliberately, rather than
//  inventing one:
//
//   • `ConnectReadiness` — the verdict. The SAME enum the detail Connect button,
//     the sidebar play button and the menu row already read for an NE profile, so a
//     control cannot be live in one place and dead in another.
//   • `AuthLocus` — WHICH LEVEL owns the fix, so a caller sends somebody to the
//     right screen without knowing anything about protocols. Read it through
//     `configLevel`, which is the honest reading here: `.transport` is level 1, how
//     SimpleVPN reaches the thing that does the work (for a vault that is the
//     vendor's binary; for an SSL-VPN it is `openconnect`); `.instance` is level 2,
//     WHICH one — which server; `.entry` is level 3, `SignInConfigLevel.perVPN`,
//     anything that lives in this VPN's own settings. `.reach` is never produced
//     here for the reason it exists: nothing about a server can be established
//     without a real connection attempt.
//
//  PURE, and that is the point of `Facts`: everything the answer needs from the
//  Mac (which tools are installed, which secrets are in the keychain) arrives as a
//  value, so the whole table is testable without a tool installed, a keychain entry
//  or a window on screen.
//

import Foundation

// MARK: - Which section a connection belongs in

/// WHAT CONNECTING THIS ACTUALLY DOES TO THE MAC — the question the connect list and
/// Manage VPNs are grouped on, and the only grouping question about a connection that a
/// person can answer by watching their own machine.
///
/// WHAT IT REPLACES, AND WHY THAT HAD TO GO. Both sidebars used to be split on our
/// IMPLEMENTATION: "VPNs" meant the packet-tunnel extension, "Tunnels" meant a
/// subprocess and "Native (IKEv2 / IPsec)" meant `NEVPNManager`. So an F5 BIG-IP APM sat
/// under "Tunnels", filed away from the VPNs it behaves identically to, and the user
/// asked the obvious question — "why is APM a Tunnel and not a VPN? it sure behaves like
/// a vpn" — followed by the one that settles it: "is that a useful distinction?". It is
/// not. Which of our three transports carries a connection is invisible from outside the
/// app, and ONTOLOGY.md rule 1 forbids naming things after the implementation that
/// happens to serve them.
///
/// The line that IS useful, and is the one drawn here: **a whole-Mac VPN changes where
/// this Mac's traffic goes, and a local port does nothing at all until you aim something
/// at it.** That difference is observable (open a browser and look at your IP), it is
/// actionable (one needs a proxy configured somewhere, the other does not), and it is the
/// difference that matters for safety.
///
/// TWO RULES THIS TYPE EXISTS TO ENFORCE:
///
///  1. **The answer follows the CONFIGURATION, not the protocol.** Four of the sixteen
///     kinds can be set up either way — SSH by its mode, and the three OpenConnect kinds
///     the in-process bridge carries by "Run In-Process". A per-kind table would put an
///     `ocproxy` F5 in with the whole-Mac VPNs and be wrong about it.
///  2. **When it is uncertain, the local-port side wins.** Promising system-wide
///     protection that is not there is a security claim, not a naming quibble; the
///     opposite mistake merely undersells a connection.
nonisolated enum ConnectionScope: String, Sendable, CaseIterable {
    /// Presents a network interface and takes routes: every app follows it with nothing
    /// to configure.
    case wholeMac
    /// Opens a port on this Mac (a SOCKS proxy, or named forwards) and takes no routes.
    /// Nothing goes through it until something is pointed at the port.
    case localPort

    /// The section header, from ONTOLOGY.md's table. Never "Tunnels" (a VPN is also a
    /// tunnel) and never "Other Connections" (a list named after not being the first
    /// list).
    var sectionTitle: String {
        switch self {
        case .wholeMac: "Whole-Mac VPNs"
        case .localPort: "Local Ports"
        }
    }

    /// What puts a row in this section, in one sentence and in terms the reader can
    /// check against their own Mac. Shown on hover AND spoken (below), because
    /// Docs/Accessibility.md allows nothing to be hover-only.
    var explanation: String {
        switch self {
        case .wholeMac:
            "Connecting one of these changes where this Mac\u{2019}s traffic goes \u{2014} every app follows it, with nothing to set up."
        case .localPort:
            "Connecting one of these opens a port on this Mac. Nothing goes through it until you point an app at that port."
        }
    }

    /// What a screen reader hears on the header. A section header has to NAME ITSELF and
    /// then say what it groups — regrouping rows changes what VoiceOver announces, so the
    /// heading is the one place the new question gets asked out loud.
    var spokenHeader: String { "\(sectionTitle). \(explanation)" }
}

extension ConnectionScope {

    /// THE PARTITION BY KIND — the answer for a kind whose own settings cannot move it,
    /// and `nil` for the four that can. A caller holding a config must ask `of(_:)`
    /// instead; a caller holding only a kind (an NE profile, a native personal VPN) gets
    /// a settled answer here or there is a bug.
    ///
    /// The eight that answer `nil` are the whole test of this design:
    ///  • `.ssh` — `-D`/`-L` open a port, `-w` presents an interface. Two scopes, one
    ///    kind, decided by `sshMode`.
    ///  • ALL SEVEN OpenConnect SSL-VPN kinds — the in-process engine is a full-routes
    ///    path, and the `openconnect` subprocess runs under `ocproxy -D <port>`, which is
    ///    a local SOCKS proxy. Decided by `SubprocessTunnelManager.willRunInProcess`.
    ///
    /// It is seven and not three, and that correction is the point. An earlier version of
    /// this table settled Juniper and Array Networks as `.localPort` on the grounds that
    /// the bridge "cannot carry them by any route", and made GlobalProtect and Pulse
    /// depend on browser sign-in. All of that was downstream of a stale hand-maintained
    /// allow-list in `SubprocessTunnelManager`, not of anything the engine cannot do:
    /// `PacketTunnelProvider.startTunnel` dispatches on `VPNKind.openconnectProtocol`,
    /// which is non-nil for every one of the seven. What the bridge cannot carry is a
    /// matter of SETTINGS, and `willRunInProcess` is the single place that knows.
    /// `ConnectListingTests` asserts the correspondence rather than trusting this comment.
    static func settled(for kind: VPNKind) -> ConnectionScope? {
        switch kind {
        // Each of these presents its own interface and takes routes. Tailscale is
        // included on the same ground as the rest: it is a utun with routes whether or
        // not an exit node makes it the default one.
        case .openVPN, .wireGuard, .tailscale, .proxyTunnel, .sshNetworkTunnel:
            .wholeMac
        // macOS owns the interface for these, which is an implementation detail of whose
        // code makes the utun — not of what the user gets, which is every app.
        case .ikev2, .ipsec, .l2tp:
            .wholeMac
        case .ssh, .fortinet, .f5apm, .ciscoAnyConnect,
             .globalProtect, .juniper, .pulse, .arrayNetworks:
            nil
        }
    }

    /// Which section this subprocess tunnel belongs in, from ITS OWN SETTINGS.
    ///
    /// `@MainActor` only because `willRunInProcess` is; nothing here touches the Mac.
    @MainActor static func of(_ c: SubprocessTunnelConfig) -> ConnectionScope {
        if let settled = settled(for: c.kind) { return settled }
        if c.kind == .ssh {
            // `-w` carries a network on a point-to-point interface; `-D` and `-L`/`-R`
            // open ports. That this build then REFUSES `-w` (it needs root) is a
            // separate fact, said by `SubprocessTunnelReadiness` — and said in the
            // section the configuration actually asks for, which is the honest place for
            // it. Filing a refused network tunnel under "Local Ports" would describe a
            // connection the user never asked for.
            return c.sshMode == .netTunnel ? .wholeMac : .localPort
        }
        // An SSL-VPN is whole-Mac only when the built-in engine will REALLY take it.
        // `willRunInProcess` is the existing honesty gate: the toggle asking for
        // in-process is not the same as getting it, and any option the bridge cannot
        // express sends the connection back to the tool — and to its SOCKS port. Reading
        // the toggle instead of the gate is how this row would come to claim system-wide
        // protection that the connection does not provide.
        return SubprocessTunnelManager.willRunInProcess(c) ? .wholeMac : .localPort
    }

    /// A native personal VPN. Its store holds nothing that could move the answer, so
    /// this is `settled(for:)` with the "or there is a bug" spelled out.
    static func of(native c: NativeVPNConfig) -> ConnectionScope {
        settled(for: c.kind) ?? .wholeMac
    }

    /// An NE profile in `vpn.profiles`. Same shape, same reason.
    static func of(profileKind kind: VPNKind) -> ConnectionScope {
        settled(for: kind) ?? .wholeMac
    }
}

// MARK: - What the connect list contains

/// WHICH CONNECTIONS THE CONNECT WINDOW LISTS — as a decision, not as a view body.
///
/// It is here rather than inside `ConnectionView` for one reason: THE INVARIANT HAS
/// TO BE ASSERTABLE. "Every profile a user can create appears in the connect list"
/// was never a test, which is how a filter on `isActive` shipped and hid a whole
/// class of VPN until it was already running. A function of what EXISTS — and of
/// nothing else, most especially not of what is running — can be held to that in one
/// line (`ConnectListingTests`).
///
/// The selection TAGS live here too, because Manage VPNs' sidebar and this one must
/// spell them identically or a settings route from one window selects nothing in the
/// other. They used to be two private constants in two files that happened to agree.
@MainActor
enum ConnectListing {

    /// A subprocess tunnel's sidebar tag.
    static let tunnelTag = "tunnel:"
    /// A native personal VPN's sidebar tag.
    static let nativeTag = "native:"

    static func tag(forTunnel id: String) -> String { tunnelTag + id }
    static func tag(forNative id: String) -> String { nativeTag + id }

    /// Whether a selection names a subprocess tunnel or a native VPN rather than an
    /// NE profile.
    static func isOtherTag(_ tag: String) -> Bool {
        tag.hasPrefix(tunnelTag) || tag.hasPrefix(nativeTag)
    }

    /// The config id inside a tag (the tag itself for an NE profile).
    static func configID(from tag: String) -> String {
        if tag.hasPrefix(tunnelTag) { return String(tag.dropFirst(tunnelTag.count)) }
        if tag.hasPrefix(nativeTag) { return String(tag.dropFirst(nativeTag.count)) }
        return tag
    }

    /// An NE profile as the listing needs it: the id it is selected by, and the kind that
    /// decides which section it appears in.
    ///
    /// The kind is new here. It arrived with the sectioning, and it is not optional: a
    /// row cannot be placed without knowing what connecting it does, and the alternative
    /// — assuming every NE profile is whole-Mac — is the per-kind table this whole
    /// change exists to delete.
    nonisolated struct Profile: Equatable, Sendable, Identifiable {
        let id: String
        let kind: VPNKind
        init(id: String, kind: VPNKind) {
            self.id = id
            self.kind = kind
        }
    }

    /// THE SECTIONS, in the order they are drawn, each holding its rows in order.
    ///
    /// Empty sections are dropped rather than drawn as a bare heading — the same rule
    /// AGENTS.md applies to setting groups ("a group with nothing in it is omitted, never
    /// shown empty").
    ///
    /// Within a section the order is profiles, then subprocess tunnels, then native VPNs.
    /// That is the store order the list has always used; what changed is that it is now
    /// asked twice, once per side of the line, instead of once per store.
    static func sections(profiles: [Profile],
                         tunnels: [SubprocessTunnelConfig],
                         native: [NativeVPNConfig]) -> [(scope: ConnectionScope, tags: [String])] {
        ConnectionScope.allCases.compactMap { scope in
            var tags: [String] = []
            tags += profiles.filter { ConnectionScope.of(profileKind: $0.kind) == scope }.map(\.id)
            tags += tunnels.filter { ConnectionScope.of($0) == scope }.map { tag(forTunnel: $0.id) }
            tags += native.filter { ConnectionScope.of(native: $0) == scope }.map { tag(forNative: $0.id) }
            return tags.isEmpty ? nil : (scope, tags)
        }
    }

    /// Every row the connect list shows, in sidebar order.
    ///
    /// NO ARGUMENT DESCRIBES RUNNING STATE, and that is the design. The bug this
    /// replaces was `tunnels.filter { manager.isActive($0.id) }` — a profile the user
    /// had created was hidden until it was connected, and could not be connected
    /// because it was hidden. Nothing that could reintroduce that is reachable from
    /// this signature.
    ///
    /// IT IS THE CONCATENATION OF THE SECTIONS, deliberately, rather than a second walk
    /// over the three stores. Grouping is the thing most likely to lose a row — a row
    /// whose scope nothing claimed would simply not be drawn — so the invariant "every
    /// profile a user can create appears" is held here BY CONSTRUCTION: if a row is
    /// missing from the sections it is missing from this list too, and the tests fail.
    static func rowTags(profiles: [Profile],
                        tunnels: [SubprocessTunnelConfig],
                        native: [NativeVPNConfig]) -> [String] {
        sections(profiles: profiles, tunnels: tunnels, native: native).flatMap(\.tags)
    }

    /// Whether the empty-state page ("No VPNs Configured") is the honest thing to
    /// show. Existence again — it used to ask whether anything was RUNNING, so
    /// somebody whose only VPN was an F5 BIG-IP APM was told they had none.
    static func isEmpty(profiles: [Profile],
                        tunnels: [SubprocessTunnelConfig],
                        native: [NativeVPNConfig]) -> Bool {
        rowTags(profiles: profiles, tunnels: tunnels, native: native).isEmpty
    }

    /// WHAT A LOCAL-PORT CONNECTION ACTUALLY GIVES YOU, short enough for a 220pt sidebar
    /// caption — the port to aim at, or the forwards it will open.
    ///
    /// This is the payoff of the re-cut and the reason "Local Ports" is worth saying: the
    /// section tells you nothing goes through it until you point something at it, and the
    /// row tells you where. `nil` for a whole-Mac VPN, because "it takes your traffic" is
    /// what that section's heading already says and repeating it on every row is noise.
    @MainActor static func portSummary(_ c: SubprocessTunnelConfig) -> String? {
        guard ConnectionScope.of(c) == .localPort else { return nil }
        if c.kind == .ssh, c.sshMode == .portForward {
            let count = c.forwards.filter { !$0.trimmingCharacters(in: .whitespaces).isEmpty }.count
            switch count {
            case 0: return "No forwards yet"
            case 1: return "1 port forward"
            default: return "\(count) port forwards"
            }
        }
        // Every other local-port shape is a SOCKS listener on the loopback: SSH's `-D`,
        // and `ocproxy -D` for the OpenConnect kinds.
        return "SOCKS on 127.0.0.1:\(c.socksPort)"
    }
}

// MARK: - What is missing, attributed

/// ONE missing thing, named and placed. What `ConnectReadiness` could not carry on
/// its own: a Bool-plus-enum says a connect cannot go, and a person still has to be
/// told what to do about it.
///
/// `sentence` names the FIX, not just the fault (ONTOLOGY.md: "Failure text names
/// the fix"). `settingID` is the field to land on — the reveal machinery expands its
/// section, scrolls it to centre and highlights it, which is the difference between
/// "open the config window" and "take me to the empty field". It is nil only where
/// there is genuinely no single field to blame (a tool that is not installed).
nonisolated struct ConnectNeed: Equatable, Sendable {

    /// The verdict, in the vocabulary every other Connect affordance already uses.
    /// Never `.ready` — a `ConnectNeed` exists only when something is missing.
    var readiness: ConnectReadiness

    /// Which configuration level owns the fix.
    var locus: AuthLocus

    /// What is missing and what clears it, in the user's terms. One or two sentences.
    var sentence: String

    /// The setting to reveal, or nil when nothing on screen is at fault.
    var settingID: String?

    /// THIS STATE, IN THE ONE STATUS VOCABULARY — the words `VPNSidebarRow.statusText`
    /// already says for the packet-tunnel kinds.
    ///
    /// It is here rather than in a view because two surfaces say it (the sidebar row's
    /// caption and the detail pane's Connect value) and both are held to the
    /// vocabulary by `VoiceOverWalkthroughTests`. Inventing a specific phrase per
    /// state — "no server address", "needs setup" — is the parallel status language
    /// ONTOLOGY.md forbids; the specific wording is `sentence`, which is what the
    /// banner and every `.help` carry.
    var statusWord: String {
        switch readiness {
        case .needsSignIn: "Sign-in needed"
        case .needsCode: "Verification code needed"
        case .blocked, .ready: "Not configured"
        }
    }

    /// What a dead Connect control says in its accessibility value: the status word
    /// from the vocabulary, then the reason that makes it actionable.
    var spokenValue: String { "\(statusWord) \u{2014} \(sentence)" }

    init(_ readiness: ConnectReadiness, locus: AuthLocus, _ sentence: String,
         setting settingID: String? = nil) {
        self.readiness = readiness
        self.locus = locus
        self.sentence = sentence
        self.settingID = settingID
    }
}

// MARK: - The subprocess kinds

/// Whether a subprocess tunnel — SSH, or one of the seven OpenConnect SSL-VPNs —
/// can connect on what is stored, and what is missing when it cannot.
///
/// The rules are the ones that already existed as `SubprocessTunnelManager`'s
/// static block reasons and `SubprocessTunnelConfig`'s own validators. Nothing here
/// re-decides any of them; this is the ORDER they are asked in and the attribution
/// each one carries, in one place, so the editor's dead Connect button and the
/// connect list's dead Connect button can never disagree.
@MainActor
enum SubprocessTunnelReadiness {

    /// Everything the answer needs from this Mac. A value, so the table is testable
    /// with no tool installed and no keychain.
    struct Facts: Equatable, Sendable {
        /// The command-line tools present right now. `TunnelCLI.installed()` gathers
        /// it; a test states it.
        var installedTools: Set<TunnelCLI> = []
        /// A password saved for this tunnel (`tunnel.<id>`).
        var hasPassword = false
        /// A verification-code token secret saved (`tunnel.<id>.token`).
        var hasTokenSecret = false
        /// A smartcard / security-key PIN in hand — stored, or typed into an open
        /// editor.
        var hasSmartcardPIN = false

        init(installedTools: Set<TunnelCLI> = [], hasPassword: Bool = false,
             hasTokenSecret: Bool = false, hasSmartcardPIN: Bool = false) {
            self.installedTools = installedTools
            self.hasPassword = hasPassword
            self.hasTokenSecret = hasTokenSecret
            self.hasSmartcardPIN = hasSmartcardPIN
        }
    }

    /// The tool that would carry this kind, given what is installed. FortiGate has
    /// two (openconnect preferred, openfortivpn as the fallback), which is why this
    /// takes the installed set rather than being a property of the kind.
    static func requiredCLI(for kind: VPNKind, installed: Set<TunnelCLI>) -> TunnelCLI {
        switch kind {
        case .ssh: .ssh
        case .fortinet: installed.contains(.openconnect) ? .openconnect : .openfortivpn
        default: .openconnect   // the other six OpenConnect SSL-VPN kinds
        }
    }

    /// Which setting id names this kind's server address. The two surfaces spell it
    /// differently because they are two catalogs (`ssh.*` and `oc.*`), and the
    /// banner has to land on the right one.
    static func serverSettingID(for kind: VPNKind) -> String {
        kind == .ssh ? "ssh.server" : "oc.server"
    }

    /// Which setting id names this kind's username.
    static func usernameSettingID(for kind: VPNKind) -> String {
        kind == .ssh ? "ssh.username" : "oc.username"
    }

    /// Which setting id names this kind's password.
    static func passwordSettingID(for kind: VPNKind) -> String {
        kind == .ssh ? "ssh.password" : "oc.password"
    }

    /// What this tunnel still needs, or nil when a click connects.
    ///
    /// THE ORDER IS LOAD-BEARING, and it is the order the editor already asked in:
    /// "is the tool there?" must not come before "is there a server address?" for a
    /// brand-new profile, or somebody who has typed nothing is told to install
    /// Homebrew. Level 2 (which server) before level 1 (the tool) before level 3
    /// (the sign-in) is the sequence that produces the sentence a person can act on
    /// first.
    static func need(for c: SubprocessTunnelConfig, facts: Facts) -> ConnectNeed? {
        let serverID = serverSettingID(for: c.kind)

        // ── LEVEL 2 — WHICH SERVER. The one field nothing works without, and the
        // one a freshly-created profile is always missing. It comes first for that
        // reason: it is the answer to "I just added this, why can't I connect?".
        if c.server.trimmingCharacters(in: .whitespaces).isEmpty {
            return ConnectNeed(.blocked, locus: .instance,
                               "This \(c.kind.displayName) has no server address yet \u{2014} add the address your administrator gave you.",
                               setting: serverID)
        }
        // A password inside the address would be persisted unencrypted AND handed to
        // the tool on a command line every local process can read with `ps`.
        if let reason = SubprocessTunnelManager.addressCredentialReason(c) {
            return ConnectNeed(.blocked, locus: .instance, reason, setting: serverID)
        }

        // ── LEVEL 1 — THE ENGINE THAT WOULD CARRY IT. A missing external tool is
        // one of these states, not a reason to hide the row.
        //
        // ASK WHETHER THE TOOL WILL BE RUN AT ALL FIRST. All seven SSL-VPN kinds go
        // through the bundled in-process engine when `willRunInProcess` says so, and
        // that path never execs anything — so demanding an installed `openconnect`
        // there dead-buttons a VPN that would connect perfectly well on a Mac with
        // no Homebrew at all. That was the last real Homebrew dependency on the
        // in-process path, and it only became reachable for every SSL kind once the
        // dispatch stopped naming three of them by hand.
        if !SubprocessTunnelManager.willRunInProcess(c) {
            let cli = requiredCLI(for: c.kind, installed: facts.installedTools)
            if !facts.installedTools.contains(cli) {
                return ConnectNeed(.blocked, locus: .transport,
                                   "\(c.kind.displayName) connects using \u{201C}\(cli.rawValue)\u{201D}, which isn\u{2019}t installed on this Mac. \(cli.installHint)")
            }
            // The tool is present but cannot carry traffic without root unless
            // `ocproxy` is too — and FortiGate's own client cannot at all. Availability
            // comes from `facts` rather than the live filesystem so the answer is the
            // same in a test as on a Mac.
            if let reason = SubprocessTunnelManager.sslTransportBlockReason(
                c,
                inProcess: false,
                ocproxyAvailable: facts.installedTools.contains(.ocproxy),
                openconnectAvailable: facts.installedTools.contains(.openconnect)) {
                return ConnectNeed(.blocked, locus: .transport, reason)
            }
        }

        // ── SSH: the mode, and the host-key pin's engine constraint.
        if c.kind == .ssh {
            if c.sshMode == .netTunnel {
                return ConnectNeed(.blocked, locus: .entry,
                                   "Network tunnel mode needs root for its utun device, which this build can\u{2019}t take \u{2014} choose SOCKS proxy or port forwards instead.",
                                   setting: "ssh.mode")
            }
            if SubprocessTunnelConfig.sshPinnedHostKeyProblem(c.sshPinnedHostKey) != nil {
                return ConnectNeed(.blocked, locus: .entry,
                                   "The pinned host key isn\u{2019}t a SHA-256 fingerprint \u{2014} fix it under Security, or clear it.",
                                   setting: "ssh.pinned-host-key")
            }
            // Only the in-process libssh engine can check a pin, so a pinned config
            // combined with anything that forces /usr/bin/ssh must be refused rather
            // than silently connected unpinned.
            if let reason = SubprocessTunnelManager.sshPinBlockReason(c) {
                return ConnectNeed(.blocked, locus: .transport, reason,
                                   setting: "ssh.pinned-host-key")
            }
            if let reason = SubprocessTunnelManager.sshAuthBlockReason(c) {
                // One rule, three fields. `sshAuthBlockReason` answers for the agent
                // socket AND for the chosen method's missing file(s), so the reveal
                // target has to be picked from which of them it was about — landing
                // somebody on the identity file because their agent path is too long
                // is a link that lies.
                let target: String
                if SubprocessTunnelConfig.agentSocketProblem(c.sshAgentSocket ?? "") != nil {
                    target = "ssh.agent-socket"
                } else if SubprocessTunnelManager.sshAuthMethod(c) == "certificate",
                          !c.identityFile.trimmingCharacters(in: .whitespaces).isEmpty {
                    // The key is there; it is the certificate that is missing.
                    target = "ssh.certificate-file"
                } else {
                    target = "ssh.identity-file"
                }
                return ConnectNeed(.blocked, locus: .entry, reason, setting: target)
            }
            if c.sshMode == .portForward,
               let bad = SubprocessTunnelManager.invalidForwardLine(c.forwards) {
                return ConnectNeed(.blocked, locus: .entry,
                                   "Fix the forward \u{201C}\(bad)\u{201D} under Traffic \u{2014} one bad forward stops the whole tunnel.",
                                   setting: "ssh.forwards")
            }
        }

        // ── The local SOCKS listener, for every kind that exposes one. Out of range
        // it would fail to bind; `normalized()` deliberately does not rewrite a
        // stored port (other software points at it), so this is where it surfaces.
        if usesSOCKSPort(c), let reason = SubprocessTunnelConfig.socksPortProblem(c.socksPort) {
            return ConnectNeed(.blocked, locus: .entry, reason,
                               setting: c.kind == .ssh ? "ssh.socks-port" : "oc.socks-port")
        }

        // ── SSL-VPN: the pinned server certificate, then the chosen sign-in method.
        if c.kind.isSSLVPN {
            if SubprocessTunnelConfig.serverCertPinProblem(c.trustedCertSHA256) != nil {
                return ConnectNeed(.blocked, locus: .entry,
                                   "The pinned server certificate isn\u{2019}t a SHA-256 fingerprint \u{2014} fix it under Security, or clear it.",
                                   setting: "oc.pinned-server-cert")
            }
            if let reason = SubprocessTunnelManager.sslAuthBlockReason(c) {
                return ConnectNeed(.blocked, locus: .entry, reason,
                                   setting: sslAuthSettingID(c))
            }
        }

        // ── LEVEL 3 — THIS VPN'S OWN SIGN-IN. Everything above is "it cannot work
        // as set up"; everything below is "it is set up and something has to be
        // supplied", which is why these are `.needsSignIn` / `.needsCode` rather
        // than `.blocked`.
        return signInNeed(for: c, facts: facts)
    }

    /// The sign-in half: what this tunnel needs supplied before a click connects.
    private static func signInNeed(for c: SubprocessTunnelConfig,
                                   facts: Facts) -> ConnectNeed? {
        let mode = SubprocessTunnelManager.openconnectAuthMode(c)

        if c.kind.isSSLVPN {
            // A verification-code token with no seed dies under `--non-inter`. Not
            // under single sign-on (the identity provider asks for the code itself),
            // and not for `yubioath` (the code comes off the YubiKey — requiring a
            // seed would block a working setup).
            if mode != "sso",
               SubprocessTunnelConfig.tokenModeRequiresSecret(c.tokenMode),
               !facts.hasTokenSecret {
                return ConnectNeed(.needsCode, locus: .entry,
                                   "This VPN gets its verification code from a \(c.tokenMode.uppercased()) token, and the token\u{2019}s secret hasn\u{2019}t been saved yet.",
                                   setting: "oc.token-secret")
            }
            switch mode {
            case "token":
                if !facts.hasSmartcardPIN {
                    return ConnectNeed(.needsSignIn, locus: .entry,
                                       "This VPN signs in with a smartcard or security key, and its PIN isn\u{2019}t saved. Turn on \u{201C}Remember PIN\u{201D} to connect from here, or connect from this VPN\u{2019}s own settings and type it.",
                                       setting: "oc.pkcs11-pin")
                }
            case "password":
                if c.username.trimmingCharacters(in: .whitespaces).isEmpty {
                    return ConnectNeed(.needsSignIn, locus: .entry,
                                       "This VPN signs in with a username and password, and no username is set.",
                                       setting: usernameSettingID(for: c.kind))
                }
                if !facts.hasPassword {
                    return ConnectNeed(.needsSignIn, locus: .entry,
                                       "No password is saved for this VPN. Save one to connect from here, or connect from its own settings and type it.",
                                       setting: passwordSettingID(for: c.kind))
                }
            // A client certificate and single sign-on both need nothing typed:
            // `sslAuthBlockReason` above has already checked the certificate is
            // there, and SSO asks in the browser.
            default: break
            }
            return nil
        }

        // SSH. A password is required ONLY when the method is explicitly password:
        // the automatic chain is key file → agent → password, and an agent this
        // process inherited holds keys we cannot see from here. Demanding a stored
        // password for "automatic" would dead-button a configuration that works.
        if SubprocessTunnelManager.sshAuthMethod(c) == "password", !facts.hasPassword {
            return ConnectNeed(.needsSignIn, locus: .entry,
                               "No password is saved for this SSH tunnel. Save one to connect from here, or connect from its own settings and type it.",
                               setting: "ssh.password")
        }
        return nil
    }

    /// Which Sign-In row a blocked SSL-VPN sign-in method points at.
    private static func sslAuthSettingID(_ c: SubprocessTunnelConfig) -> String {
        switch SubprocessTunnelManager.openconnectAuthMode(c) {
        case "token":
            // The module is what a blocked token config is missing first; the
            // certificate URI only becomes the fault once a module is chosen.
            (c.pkcs11ModulePath ?? "").trimmingCharacters(in: .whitespaces).isEmpty
                ? "oc.pkcs11-module" : "oc.pkcs11-certificate"
        default: "oc.client-cert"
        }
    }

    /// Whether this config exposes a local SOCKS listener whose port has to bind.
    /// SSH does in `-D` mode; every SSL-VPN does, through `ocproxy`.
    static func usesSOCKSPort(_ c: SubprocessTunnelConfig) -> Bool {
        c.kind == .ssh ? c.sshMode == .socks : c.kind.isSSLVPN
    }
}

// MARK: - The native personal VPNs

/// Whether a native personal VPN — IKEv2 / IPsec / L2TP — can connect on what is
/// stored. Same shape and same vocabulary as the subprocess answer; the rules are
/// `NativeVPNConfig.serverProblem` and the secret each kind actually signs in with.
///
/// L2TP is the honest odd one: macOS gives an app no programmatic L2TP API at all,
/// so the row can never offer a Connect that works. It says so rather than offering
/// one that cannot, which is the same rule as everything else here.
@MainActor
enum NativeVPNReadiness {

    /// What only the keychain knows.
    struct Facts: Equatable, Sendable {
        /// The base secret: the IKEv2 password or PSK, or the IPsec XAuth password.
        var hasSecret = false
        /// IPsec's group pre-shared key.
        var hasGroupPSK = false
        /// Whether this build's signing profile carries the Personal VPN capability
        /// at all. Without it nothing native can be installed, let alone connected.
        var hasPersonalVPNCapability = true

        init(hasSecret: Bool = false, hasGroupPSK: Bool = false,
             hasPersonalVPNCapability: Bool = true) {
            self.hasSecret = hasSecret
            self.hasGroupPSK = hasGroupPSK
            self.hasPersonalVPNCapability = hasPersonalVPNCapability
        }
    }

    static func need(for c: NativeVPNConfig, facts: Facts) -> ConnectNeed? {
        // L2TP is installed by double-clicking an exported configuration profile
        // and connected in System Settings — there is no API for either. Naming
        // that is the only honest thing the row can do.
        if c.kind == .l2tp {
            return ConnectNeed(.blocked, locus: .transport,
                               "macOS gives apps no way to connect L2TP. Export this as a configuration profile from its own settings, install it, then connect it in System Settings \u{25B8} Network \u{25B8} VPN.",
                               setting: "native.shared-secret")
        }
        if !facts.hasPersonalVPNCapability {
            return ConnectNeed(.blocked, locus: .transport,
                               "This build of SimpleVPN can\u{2019}t create native VPNs \u{2014} its signing profile is missing the Personal VPN capability. Everything else works; ask to have it provisioned.")
        }
        // LEVEL 2 — which server. `serverProblem` catches the empty field AND the
        // typo, pasted URL or host:port that used to reach NEVPNManager and come
        // back minutes later as an opaque IKE timeout.
        if let problem = c.serverProblem {
            return ConnectNeed(.blocked, locus: .instance, problem, setting: "native.server")
        }
        // LEVEL 3 — this VPN's own sign-in.
        switch c.kind {
        case .ipsec:
            if !facts.hasGroupPSK {
                return ConnectNeed(.needsSignIn, locus: .entry,
                                   "This VPN signs in with a shared secret, and none is saved yet.",
                                   setting: "native.shared-secret")
            }
            if c.usesXAuth {
                if c.username.trimmingCharacters(in: .whitespaces).isEmpty {
                    return ConnectNeed(.needsSignIn, locus: .entry,
                                       "This VPN also signs in with a username and password, and no username is set.",
                                       setting: "native.username")
                }
                if !facts.hasSecret {
                    return ConnectNeed(.needsSignIn, locus: .entry,
                                       "No password is saved for this VPN.",
                                       setting: "native.xauth-password")
                }
            }
        case .ikev2:
            if c.usesSharedSecret {
                if !facts.hasSecret {
                    return ConnectNeed(.needsSignIn, locus: .entry,
                                       "This VPN signs in with a shared secret, and none is saved yet.",
                                       setting: "native.shared-secret")
                }
            } else {
                if c.username.trimmingCharacters(in: .whitespaces).isEmpty {
                    return ConnectNeed(.needsSignIn, locus: .entry,
                                       "This VPN signs in with a username and password, and no username is set.",
                                       setting: "native.username")
                }
                if !facts.hasSecret {
                    return ConnectNeed(.needsSignIn, locus: .entry,
                                       "No password is saved for this VPN.",
                                       setting: "native.password")
                }
            }
        default: break
        }
        return nil
    }
}

// MARK: - Gathering the facts

nonisolated extension TunnelCLI {
    /// Which of the command-line tools are on this Mac right now. One sweep, so a
    /// readiness answer is one `stat` per tool rather than one per question asked.
    static func installed() -> Set<TunnelCLI> {
        Set(TunnelCLI.allCases.filter(\.isAvailable))
    }
}

extension SubprocessTunnelReadiness {

    /// Gather this tunnel's facts from the Mac.
    ///
    /// IT READS ONLY THE SECRET THE CONFIGURED METHOD ACTUALLY USES — at most two
    /// keychain queries, and none at all for a certificate or single-sign-on tunnel.
    /// That is deliberate rather than tidy: a keychain query is not free, and the
    /// alternative (fill every field in) would ask for four secrets to answer a
    /// question about one. `ConnectInputs` reached the same conclusion for the Touch
    /// ID facts ("reading them otherwise is a needless keychain hit on every
    /// redraw").
    ///
    /// NOT FOR A VIEW BODY. Callers gather into state on a change and read the
    /// stored answer while drawing — see `ConnectionView.refreshOtherNeeds`.
    static func liveFacts(for c: SubprocessTunnelConfig,
                          installedTools: Set<TunnelCLI>) -> Facts {
        func saved(_ profile: String) -> Bool {
            !(KeychainCredentialStore.loadCredentials(profile: profile)?.password ?? "").isEmpty
        }
        var facts = Facts(installedTools: installedTools)
        let mode = SubprocessTunnelManager.openconnectAuthMode(c)
        if c.kind.isSSLVPN {
            if mode != "sso", SubprocessTunnelConfig.tokenModeRequiresSecret(c.tokenMode) {
                facts.hasTokenSecret = saved("tunnel.\(c.id).token")
            }
            switch mode {
            case "token": facts.hasSmartcardPIN = SubprocessTunnelManager.storedPKCS11PIN(c) != nil
            case "password": facts.hasPassword = saved("tunnel.\(c.id)")
            default: break
            }
        } else if SubprocessTunnelManager.sshAuthMethod(c) == "password" {
            facts.hasPassword = saved("tunnel.\(c.id)")
        }
        return facts
    }

    /// The whole answer for one tunnel, facts and all.
    static func need(for c: SubprocessTunnelConfig,
                     installedTools: Set<TunnelCLI>) -> ConnectNeed? {
        need(for: c, facts: liveFacts(for: c, installedTools: installedTools))
    }
}

extension NativeVPNReadiness {

    /// Gather a native VPN's facts. Same rule as the subprocess side: only the rows
    /// the kind actually owns are read (`NativeVPNSecrets` is the authority on which
    /// those are).
    static func liveFacts(for c: NativeVPNConfig, hasPersonalVPNCapability: Bool) -> Facts {
        func saved(_ profile: String) -> Bool {
            !(KeychainCredentialStore.loadCredentials(profile: profile)?.password ?? "").isEmpty
        }
        var facts = Facts(hasPersonalVPNCapability: hasPersonalVPNCapability)
        // L2TP is answered without reading anything — there is no API to connect it.
        guard c.kind != .l2tp else { return facts }
        if c.kind == .ipsec {
            facts.hasGroupPSK = saved(NativeVPNSecrets.groupPSKProfile(c.id))
            if c.usesXAuth { facts.hasSecret = saved(NativeVPNSecrets.baseProfile(c.id)) }
        } else {
            facts.hasSecret = saved(NativeVPNSecrets.baseProfile(c.id))
        }
        return facts
    }

    static func need(for c: NativeVPNConfig, hasPersonalVPNCapability: Bool) -> ConnectNeed? {
        need(for: c, facts: liveFacts(for: c, hasPersonalVPNCapability: hasPersonalVPNCapability))
    }

    /// The secrets `NativeVPNManager.connect` wants, read back from the rows
    /// `NativeVPNSecrets` defines. Read at the moment of connecting and not retained
    /// — the editor does exactly the same thing from its own fields.
    static func storedSecrets(for c: NativeVPNConfig) -> (base: String, groupPSK: String) {
        func saved(_ profile: String) -> String {
            KeychainCredentialStore.loadCredentials(profile: profile)?.password ?? ""
        }
        return (base: saved(NativeVPNSecrets.baseProfile(c.id)),
                groupPSK: c.kind == .ipsec ? saved(NativeVPNSecrets.groupPSKProfile(c.id)) : "")
    }
}
