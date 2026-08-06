// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
//  ConnectListingTests.swift
//  THE INVARIANT THAT WAS NEVER ASSERTED, and the whole reason this file exists:
//
//      EVERY PROFILE A USER CAN CREATE APPEARS IN THE CONNECT LIST — the moment it
//      exists, before it is configured and before it has ever connected — with a
//      Connect that is DISABLED AND CARRIES A REASON rather than absent.
//
//  What shipped without it: `ConnectionView` listed the subprocess-backed kinds
//  through `.filter { tunnelManager.isActive($0.id) }`. So an F5 BIG-IP APM the user
//  had just added could not appear until it was running, and could not be run from
//  the connect window because it was not in it. A closed loop, found by a screenshot
//  after three reports, invisible to 2214 tests — because nothing anywhere asked
//  "does what I created show up?".
//
//  The tests below are deliberately shaped to fail on the ORIGINAL bug and on every
//  variant of it:
//   • `everyKindAppears` iterates `VPNKind.allCases` and asserts a row for each,
//     with no running state anywhere in the call;
//   • `runningStateNeverAffectsTheList` states it as an identity;
//   • `freshProfileSaysWhatItNeeds` asserts a reason exists, is not empty, and does
//     not merely say "not configured";
//   • `everyRevealTargetExists` holds each reason's deep link to a REAL setting, so
//     "Fix This…" can never point at nothing;
//   • `configuredProfilesCanConnect` proves the gate is not simply always shut.
//

import Foundation
import Testing
@testable import SimpleVPN

@MainActor
struct ConnectListingTests {

    // MARK: - Fixtures

    /// A brand-new profile of a kind, exactly as the + button in Manage VPNs makes
    /// one: named, and otherwise empty.
    private func freshTunnel(_ kind: VPNKind) -> SubprocessTunnelConfig {
        var c = SubprocessTunnelConfig()
        c.kind = kind
        c.name = kind.displayName
        return c
    }

    private func freshNative(_ kind: VPNKind) -> NativeVPNConfig {
        var c = NativeVPNConfig()
        c.kind = kind
        c.name = kind.displayName
        return c
    }

    /// The kinds whose profiles live in the subprocess store — the ones that were
    /// hidden. Derived from `transport`, so a kind added later is covered without
    /// this list being remembered.
    private var subprocessKinds: [VPNKind] {
        VPNKind.allCases.filter { $0.transport == .subprocess }
    }

    /// The native personal-VPN kinds — hidden the same way, one line further down.
    private var nativeKinds: [VPNKind] {
        VPNKind.allCases.filter { $0.transport == .nativePersonalVPN }
    }

    /// Every tool installed. Used where the test is about something OTHER than a
    /// missing tool, so the answer isn't shadowed by this machine's Homebrew.
    private let allTools = Set(TunnelCLI.allCases)

    // MARK: - Every profile a user can create appears in the list

    /// THE HEADLINE INVARIANT. One profile of every kind, and a row for every one.
    ///
    /// Note what is NOT a parameter of `rowTags`: anything about running. The bug was
    /// only expressible because the view could reach a live manager while deciding
    /// what to draw.
    @Test func everyKindAppears() {
        let profileKinds = VPNKind.allCases.filter { $0.transport == .packetTunnel }
        // The packet-tunnel kinds are NE profiles, identified by their own ids.
        let profiles = profileKinds.map { "profile-\($0.rawValue)" }
        let tunnels = subprocessKinds.map(freshTunnel)
        let native = nativeKinds.map(freshNative)

        let rows = ConnectListing.rowTags(profiles: profiles, tunnels: tunnels, native: native)

        #expect(rows.count == VPNKind.allCases.count,
                "every kind a user can create must have exactly one row")
        for id in profiles {
            #expect(rows.contains(id))
        }
        for t in tunnels {
            #expect(rows.contains(ConnectListing.tag(forTunnel: t.id)),
                    "\(t.kind.displayName) is missing from the connect list")
        }
        for n in native {
            #expect(rows.contains(ConnectListing.tag(forNative: n.id)),
                    "\(n.kind.displayName) is missing from the connect list")
        }
    }

    /// Said as an identity, because the bug was a filter: the list is a function of
    /// what EXISTS, so nothing about state can change its contents.
    @Test func runningStateNeverAffectsTheList() {
        let tunnels = subprocessKinds.map(freshTunnel)
        let native = nativeKinds.map(freshNative)
        let rows = ConnectListing.rowTags(profiles: ["p"], tunnels: tunnels, native: native)
        // The same inputs, asked again — there is no third argument to vary, which is
        // the guarantee. A row count that tracked `isActive` could not survive this
        // signature at all.
        #expect(ConnectListing.rowTags(profiles: ["p"], tunnels: tunnels, native: native) == rows)
        #expect(rows.count == 1 + tunnels.count + native.count)
    }

    /// A configured-but-idle profile is not "no VPNs". Somebody whose only VPN was an
    /// F5 BIG-IP APM opened the app and was shown the empty-state page, with an
    /// Import button, about the VPN they had just made.
    @Test func oneIdleTunnelIsNotAnEmptyApp() {
        #expect(ConnectListing.isEmpty(profiles: [], tunnels: [], native: []))
        #expect(!ConnectListing.isEmpty(profiles: [], tunnels: [freshTunnel(.f5apm)], native: []))
        #expect(!ConnectListing.isEmpty(profiles: [], tunnels: [], native: [freshNative(.ikev2)]))
    }

    /// Tags are unique per row across all three stores — the sidebar selects by tag,
    /// and a collision would make two VPNs one row.
    @Test func tagsAreUniqueAndReversible() {
        let tunnels = subprocessKinds.map(freshTunnel)
        let native = nativeKinds.map(freshNative)
        let rows = ConnectListing.rowTags(profiles: ["plain"], tunnels: tunnels, native: native)
        #expect(Set(rows).count == rows.count)
        #expect(!ConnectListing.isOtherTag("plain"))
        for t in tunnels {
            let tag = ConnectListing.tag(forTunnel: t.id)
            #expect(ConnectListing.isOtherTag(tag))
            #expect(ConnectListing.configID(from: tag) == t.id)
        }
        for n in native {
            let tag = ConnectListing.tag(forNative: n.id)
            #expect(ConnectListing.isOtherTag(tag))
            #expect(ConnectListing.configID(from: tag) == n.id)
        }
    }

    // MARK: - Connect is disabled, and says why

    /// EVERY freshly-created subprocess profile refuses to connect AND says what is
    /// missing. The reason is what makes a disabled button legitimate; a dead control
    /// with no explanation is the failure this replaces, not an improvement on it.
    @Test func freshSubprocessProfileSaysWhatItNeeds() {
        for kind in subprocessKinds {
            let need = SubprocessTunnelReadiness.need(
                for: freshTunnel(kind),
                facts: .init(installedTools: allTools))
            guard let need else {
                Issue.record("\(kind.displayName): a brand-new profile with no server address must not be connectable")
                continue
            }
            #expect(need.readiness != .ready)
            #expect(!need.sentence.isEmpty, "\(kind.displayName): a disabled Connect must say why")
            // The first thing missing is the server address, and the banner has to
            // send the user THERE — not to a generic "configure this" page.
            #expect(need.locus == .instance,
                    "\(kind.displayName): a missing server address is a level-2 problem")
            #expect(need.settingID == SubprocessTunnelReadiness.serverSettingID(for: kind))
        }
    }

    /// The same for the native kinds.
    @Test func freshNativeProfileSaysWhatItNeeds() {
        for kind in nativeKinds {
            let need = NativeVPNReadiness.need(for: freshNative(kind), facts: .init())
            guard let need else {
                Issue.record("\(kind.displayName): a brand-new profile with no server address must not be connectable")
                continue
            }
            #expect(need.readiness != .ready)
            #expect(!need.sentence.isEmpty, "\(kind.displayName): a disabled Connect must say why")
        }
    }

    /// ONTOLOGY.md: "Failure text names the fix." A sentence that only reports the
    /// fault is half a message — and one generic sentence for every state is exactly
    /// what would send people to the wrong tab.
    @Test func reasonsAreSpecificAndInTheUsersLanguage() {
        var sentences: Set<String> = []
        for kind in subprocessKinds {
            guard let need = SubprocessTunnelReadiness.need(
                for: freshTunnel(kind), facts: .init(installedTools: allTools)) else { continue }
            sentences.insert(need.sentence)
            // "Credential" is banned from UI copy (ONTOLOGY.md), and so is the
            // vendor-speak the glossary translates away from.
            let lowered = need.sentence.lowercased()
            for banned in ["credential", "log in", "login", "endpoint", "gateway address"] {
                #expect(!lowered.contains(banned),
                        "\(kind.displayName): \u{201C}\(banned)\u{201D} is not house vocabulary")
            }
        }
        // Every kind names ITSELF, so seven SSL-VPNs do not all say the same thing.
        #expect(sentences.count == subprocessKinds.count,
                "each kind's missing-server sentence should name that kind")
    }

    /// A MISSING EXTERNAL TOOL IS ONE OF THESE STATES, NOT A REASON TO HIDE THE ROW.
    /// With the address filled in and no `openconnect` on the Mac, the row still
    /// exists, Connect is still refused, and the reason is a level-1 (transport)
    /// problem naming the install command rather than a level-3 sign-in one.
    @Test func aMissingToolIsAStateNotAHidingReason() {
        for kind in subprocessKinds where kind.isSSLVPN {
            var c = freshTunnel(kind)
            c.server = "vpn.example.com"
            c.username = "alex"
            // Nothing installed at all.
            let need = SubprocessTunnelReadiness.need(for: c, facts: .init(installedTools: []))
            guard let need else {
                Issue.record("\(kind.displayName): with no tool installed this cannot connect")
                continue
            }
            #expect(need.locus == .transport)
            #expect(need.readiness == .blocked)
            #expect(need.sentence.contains("brew install"),
                    "\(kind.displayName): say how to install it, not just that it is missing")
            // Nothing to reveal — there is no field at fault, and offering a dead
            // "Fix This…" would be worse than offering none.
            #expect(need.settingID == nil)
        }
        // The row is listed regardless — that is the point.
        #expect(!ConnectListing.isEmpty(profiles: [], tunnels: [freshTunnel(.f5apm)], native: []))
    }

    // MARK: - Every reason's deep link goes somewhere real

    /// "TAKE ME TO THE EMPTY FIELD" HAS TO LAND. Every `settingID` a reason carries
    /// must be a setting that exists, or the banner's button opens a window and
    /// highlights nothing — the exact class of failure the reveal fix just cured.
    @Test func everyRevealTargetExists() {
        for need in allReachableNeeds() {
            guard let id = need.settingID else { continue }
            #expect(AllSettings.byID[id] != nil,
                    "\u{201C}\(need.sentence)\u{201D} points at \u{201C}\(id)\u{201D}, which is not a setting")
            #expect(SettingSurface.owning(id) != nil,
                    "\u{201C}\(id)\u{201D} belongs to no surface, so a route to it resolves to no editor")
            // An app-level id would open the Settings window rather than this VPN's
            // editor — never right for a per-VPN missing field.
            #expect(!SettingsRouter.isAppLevel(settingID: id),
                    "\u{201C}\(id)\u{201D} is an app-level setting, not one of this VPN's own")
        }
    }

    /// AND THE ROW IS ACTUALLY ON SCREEN. A reveal target that `SettingVisibility`
    /// gates out for the very config that produced the need would open the editor and
    /// then say "that setting isn't shown for this VPN" — technically honest, useless
    /// as a fix. Checked against the config each need came from, which is the only way
    /// the question means anything.
    @Test func everyRevealTargetIsVisibleForItsOwnConfig() {
        for (config, need) in subprocessNeedsWithConfigs() {
            guard let id = need.settingID else { continue }
            let visibility = SettingVisibility.subprocess(config)
            #expect(visibility.reason(id) == nil, """
                \(config.kind.displayName): \u{201C}\(need.sentence)\u{201D} points at \u{201C}\(id)\u{201D}, \
                which this config hides \u{2014} \u{201C}\(visibility.reason(id) ?? "")\u{201D}
                """)
        }
    }

    /// Every subprocess state, paired with the config that produced it, so a
    /// visibility question can be asked of the right config.
    private func subprocessNeedsWithConfigs() -> [(SubprocessTunnelConfig, ConnectNeed)] {
        var out: [(SubprocessTunnelConfig, ConnectNeed)] = []
        func add(_ c: SubprocessTunnelConfig, _ facts: SubprocessTunnelReadiness.Facts) {
            if let need = SubprocessTunnelReadiness.need(for: c, facts: facts) {
                out.append((c, need))
            }
        }
        for kind in subprocessKinds {
            let tools = SubprocessTunnelReadiness.Facts(installedTools: allTools)
            add(freshTunnel(kind), tools)
            var configured = freshTunnel(kind)
            configured.server = "vpn.example.com"
            add(configured, tools)
            var named = configured
            named.username = "alex"
            add(named, tools)
            var badPort = named
            badPort.socksPort = 80
            add(badPort, tools)
            var badPin = named
            badPin.trustedCertSHA256 = "not-a-fingerprint"
            add(badPin, tools)
            if kind.isSSLVPN {
                var cert = named
                cert.authMode = "certificate"
                add(cert, tools)
                var token = named
                token.authMode = "token"
                add(token, tools)
                var totp = named
                totp.tokenMode = "totp"
                add(totp, .init(installedTools: allTools, hasPassword: true))
            } else {
                for method in ["key", "certificate", "password"] {
                    var m = named
                    m.sshAuthMethod = method
                    add(m, tools)
                }
                var certOnly = named
                certOnly.sshAuthMethod = "certificate"
                certOnly.identityFile = "/tmp/id_ed25519"
                add(certOnly, tools)
                var agent = named
                agent.sshAgentSocket = "relative/path"
                add(agent, tools)
                var pin = named
                pin.sshPinnedHostKey = "SHA256:nope"
                add(pin, tools)
                var net = named
                net.sshMode = .netTunnel
                add(net, tools)
                var fwd = named
                fwd.sshMode = .portForward
                fwd.forwards = ["nonsense"]
                add(fwd, tools)
            }
        }
        return out
    }

    /// Every state this file can produce, so `everyRevealTargetExists` is total
    /// rather than a spot check.
    private func allReachableNeeds() -> [ConnectNeed] {
        var needs: [ConnectNeed] = []
        func add(_ n: ConnectNeed?) { if let n { needs.append(n) } }

        for kind in subprocessKinds {
            // No server address.
            add(SubprocessTunnelReadiness.need(for: freshTunnel(kind),
                                               facts: .init(installedTools: allTools)))
            var configured = freshTunnel(kind)
            configured.server = "vpn.example.com"
            // No tool.
            add(SubprocessTunnelReadiness.need(for: configured, facts: .init(installedTools: [])))
            // A password in the address.
            var embedded = configured
            embedded.server = "https://alex:secret@vpn.example.com"
            add(SubprocessTunnelReadiness.need(for: embedded, facts: .init(installedTools: allTools)))
            // Password sign-in with nothing to sign in with.
            add(SubprocessTunnelReadiness.need(for: configured,
                                               facts: .init(installedTools: allTools)))
            var named = configured
            named.username = "alex"
            add(SubprocessTunnelReadiness.need(for: named, facts: .init(installedTools: allTools)))
            // A malformed pinned server certificate.
            var badPin = named
            badPin.trustedCertSHA256 = "not-a-fingerprint"
            add(SubprocessTunnelReadiness.need(for: badPin, facts: .init(installedTools: allTools)))
            // An out-of-range SOCKS port.
            var badPort = named
            badPort.socksPort = 80
            add(SubprocessTunnelReadiness.need(for: badPort, facts: .init(installedTools: allTools)))

            if kind.isSSLVPN {
                // Certificate sign-in with no certificate.
                var cert = named
                cert.authMode = "certificate"
                add(SubprocessTunnelReadiness.need(for: cert, facts: .init(installedTools: allTools)))
                // Smartcard sign-in with no module.
                var token = named
                token.authMode = "token"
                add(SubprocessTunnelReadiness.need(for: token, facts: .init(installedTools: allTools)))
                // A verification-code token with no seed.
                var totp = named
                totp.tokenMode = "totp"
                add(SubprocessTunnelReadiness.need(
                    for: totp, facts: .init(installedTools: allTools, hasPassword: true)))
            } else {
                // Explicit key sign-in with no identity file.
                var key = named
                key.sshAuthMethod = "key"
                add(SubprocessTunnelReadiness.need(for: key, facts: .init(installedTools: allTools)))
                // Explicit certificate sign-in with neither file.
                var sshCert = named
                sshCert.sshAuthMethod = "certificate"
                add(SubprocessTunnelReadiness.need(for: sshCert, facts: .init(installedTools: allTools)))
                // The key is there and the CERTIFICATE is missing — a different field
                // from the case above, and the link has to know which.
                var certOnly = sshCert
                certOnly.identityFile = "/tmp/id_ed25519"
                add(SubprocessTunnelReadiness.need(for: certOnly, facts: .init(installedTools: allTools)))
                // An agent socket path neither connect path can use — again a
                // different field, reached through the same block reason.
                var agent = named
                agent.sshAgentSocket = "relative/path"
                add(SubprocessTunnelReadiness.need(for: agent, facts: .init(installedTools: allTools)))
                // A malformed pinned host key.
                var pin = named
                pin.sshPinnedHostKey = "SHA256:nope"
                add(SubprocessTunnelReadiness.need(for: pin, facts: .init(installedTools: allTools)))
                // Network-tunnel mode, which needs root.
                var net = named
                net.sshMode = .netTunnel
                add(SubprocessTunnelReadiness.need(for: net, facts: .init(installedTools: allTools)))
                // A bad port forward.
                var fwd = named
                fwd.sshMode = .portForward
                fwd.forwards = ["nonsense"]
                add(SubprocessTunnelReadiness.need(for: fwd, facts: .init(installedTools: allTools)))
                // Explicit password sign-in with nothing saved.
                var pwd = named
                pwd.sshAuthMethod = "password"
                add(SubprocessTunnelReadiness.need(for: pwd, facts: .init(installedTools: allTools)))
            }
        }

        for kind in nativeKinds {
            add(NativeVPNReadiness.need(for: freshNative(kind), facts: .init()))
            var configured = freshNative(kind)
            configured.server = "vpn.example.com"
            add(NativeVPNReadiness.need(for: configured, facts: .init()))
            var named = configured
            named.username = "alex"
            add(NativeVPNReadiness.need(for: named, facts: .init()))
            add(NativeVPNReadiness.need(for: named, facts: .init(hasSecret: true)))
            add(NativeVPNReadiness.need(
                for: named, facts: .init(hasPersonalVPNCapability: false)))
            var psk = configured
            psk.usesSharedSecret = true
            add(NativeVPNReadiness.need(for: psk, facts: .init()))
        }
        return needs
    }

    /// And every one of them says something.
    @Test func everyReachableReasonHasASentence() {
        let needs = allReachableNeeds()
        #expect(!needs.isEmpty)
        for need in needs {
            #expect(!need.sentence.isEmpty)
            #expect(need.readiness != .ready, "a need means a connect cannot go")
        }
    }

    // MARK: - The gate opens

    /// THE OTHER HALF OF THE INVARIANT, and the one that stops it being satisfied by
    /// a function that always says no: a fully-configured profile of every kind
    /// connects with nothing left to supply.
    @Test func configuredProfilesCanConnect() {
        for kind in subprocessKinds {
            var c = freshTunnel(kind)
            c.server = "vpn.example.com"
            c.username = "alex"
            let need = SubprocessTunnelReadiness.need(
                for: c, facts: .init(installedTools: allTools, hasPassword: true))
            #expect(need == nil,
                    "\(kind.displayName): configured with a server, a username and a saved password, Connect must be live \u{2014} got \u{201C}\(need?.sentence ?? "")\u{201D}")
        }
        // IKEv2 with a username and password.
        var ike = freshNative(.ikev2)
        ike.server = "vpn.example.com"
        ike.username = "alex"
        #expect(NativeVPNReadiness.need(for: ike, facts: .init(hasSecret: true)) == nil)
        // IKEv2 with a shared secret instead.
        var psk = ike
        psk.usesSharedSecret = true
        #expect(NativeVPNReadiness.need(for: psk, facts: .init(hasSecret: true)) == nil)
        // IPsec: the group PSK is the sign-in, and XAuth can be off.
        var ipsec = freshNative(.ipsec)
        ipsec.server = "vpn.example.com"
        ipsec.xauth = false
        #expect(NativeVPNReadiness.need(for: ipsec, facts: .init(hasGroupPSK: true)) == nil)
    }

    /// A sign-in method that needs nothing typed is not asked for a password. Getting
    /// this wrong would dead-button a working certificate or single-sign-on VPN — the
    /// same failure as hiding it, wearing a different hat.
    @Test func methodsThatNeedNothingTypedAreNotBlocked() {
        var cert = freshTunnel(.ciscoAnyConnect)
        cert.server = "vpn.example.com"
        cert.authMode = "certificate"
        cert.clientCertFile = "/tmp/client.pem"
        #expect(SubprocessTunnelReadiness.need(
            for: cert, facts: .init(installedTools: allTools)) == nil)

        var sso = freshTunnel(.ciscoAnyConnect)
        sso.server = "vpn.example.com"
        sso.authMode = "sso"
        #expect(SubprocessTunnelReadiness.need(
            for: sso, facts: .init(installedTools: allTools)) == nil)

        // SSH's AUTOMATIC chain is key file → agent → password, and an agent this
        // process inherited holds keys we cannot see. Requiring a stored password for
        // "automatic" would refuse a configuration that works perfectly.
        var ssh = freshTunnel(.ssh)
        ssh.server = "ssh.example.com"
        #expect(SubprocessTunnelReadiness.need(
            for: ssh, facts: .init(installedTools: allTools)) == nil)
    }

    /// FortiGate is the one kind with two possible tools, and which one is required
    /// depends on what is installed — so the reason must name the one that is
    /// actually missing.
    @Test func fortiGateNamesWhicheverToolItWouldUse() {
        #expect(SubprocessTunnelReadiness.requiredCLI(for: .fortinet, installed: allTools)
                == .openconnect)
        #expect(SubprocessTunnelReadiness.requiredCLI(for: .fortinet, installed: [.openfortivpn])
                == .openfortivpn)
        var c = freshTunnel(.fortinet)
        c.server = "vpn.example.com"
        c.username = "alex"
        // openfortivpn present, openconnect not: nothing is missing at level 1.
        let need = SubprocessTunnelReadiness.need(
            for: c, facts: .init(installedTools: [.openfortivpn], hasPassword: true))
        #expect(need == nil, "openfortivpn alone can carry a FortiGate password sign-in")
    }

    /// L2TP cannot be connected by any app on macOS. It is still LISTED, and it says
    /// so — the honest version of "there is no Connect for this".
    @Test func l2tpIsListedAndExplainsItself() {
        let need = NativeVPNReadiness.need(for: freshNative(.l2tp), facts: .init())
        #expect(need?.readiness == .blocked)
        #expect(need?.locus == .transport)
        #expect(need?.sentence.contains("System Settings") == true)
        #expect(!ConnectListing.isEmpty(profiles: [], tunnels: [], native: [freshNative(.l2tp)]))
    }

    // MARK: - One rule, not two

    /// One block reason, three possible fields — so the link has to name the one that
    /// is actually wrong. Landing somebody on the identity file because their SSH
    /// agent path is malformed is a deep link that lies, which is worse than none.
    @Test func sshSignInProblemsPointAtTheFieldThatIsWrong() {
        var base = freshTunnel(.ssh)
        base.server = "ssh.example.com"
        base.username = "alex"

        var agent = base
        agent.sshAgentSocket = "relative/path"
        #expect(SubprocessTunnelReadiness.need(
            for: agent, facts: .init(installedTools: allTools))?.settingID == "ssh.agent-socket")

        var key = base
        key.sshAuthMethod = "key"
        #expect(SubprocessTunnelReadiness.need(
            for: key, facts: .init(installedTools: allTools))?.settingID == "ssh.identity-file")

        var cert = base
        cert.sshAuthMethod = "certificate"
        #expect(SubprocessTunnelReadiness.need(
            for: cert, facts: .init(installedTools: allTools))?.settingID == "ssh.identity-file")
        cert.identityFile = "/tmp/id_ed25519"
        #expect(SubprocessTunnelReadiness.need(
            for: cert, facts: .init(installedTools: allTools))?.settingID == "ssh.certificate-file")
    }

    /// The pinned-host-key format rule now lives in `SubprocessTunnelConfig` because
    /// the editor's inline error and this gate both ask it. Two spellings of one
    /// format rule is how they come to disagree.
    @Test func pinnedHostKeyFormatIsOneRule() {
        #expect(SubprocessTunnelConfig.sshPinnedHostKeyProblem(nil) == nil)
        #expect(SubprocessTunnelConfig.sshPinnedHostKeyProblem("") == nil)
        #expect(SubprocessTunnelConfig.sshPinnedHostKeyProblem("   ") == nil)
        #expect(SubprocessTunnelConfig.sshPinnedHostKeyProblem(String(repeating: "a", count: 64)) == nil)
        #expect(SubprocessTunnelConfig.sshPinnedHostKeyProblem("SHA256:" + String(repeating: "9", count: 64)) == nil)
        #expect(SubprocessTunnelConfig.sshPinnedHostKeyProblem("SHA256:nope") != nil)
        #expect(SubprocessTunnelConfig.sshPinnedHostKeyProblem(String(repeating: "z", count: 64)) != nil)
    }
}
