// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
//  SSHSettingDescriptorTests.swift
//  The SSH descriptor catalog is the CLI/MDM/manual-anchor contract for the
//  SSH tunnel editor — pin its shape (stable ids, canonical groups, a summary
//  and a real manual anchor per option), the config's decode tolerance for the
//  libssh-era fields, and the argv/honesty wiring behind the new options.
//

import Foundation
import Testing
@testable import SimpleVPN

@MainActor
struct SSHSettingDescriptorTests {

    // MARK: Catalog shape

    @Test func idsAreUniqueAndNamespaced() {
        let ids = SSHSettings.all.map(\.id)
        #expect(Set(ids).count == ids.count)
        #expect(ids.allSatisfy { $0.hasPrefix("ssh.") })
    }

    /// Ids are the contract — they may be added to, never renamed. This list is
    /// the shipped set; a failure here means an id changed or vanished.
    @Test func shippedIdsNeverDisappear() {
        let shipped: Set<String> = [
            "ssh.server", "ssh.port", "ssh.connect-timeout",
            "ssh.proxy-jump", "ssh.jump-port", "ssh.jump-username", "ssh.jump-identity-file",
            "ssh.auth-method", "ssh.username", "ssh.identity-file", "ssh.certificate-file", "ssh.password",
            "ssh.mode", "ssh.socks-port", "ssh.system-proxy", "ssh.forwards",
            "ssh.strict-host-key", "ssh.pinned-host-key", "ssh.key-exchange",
            "ssh.keepalive", "ssh.compression", "ssh.extra-options",
        ]
        let ids = Set(SSHSettings.all.map(\.id))
        #expect(shipped.isSubset(of: ids))
    }

    @Test func everySpecHasNameSummaryAndGroup() {
        for s in SSHSettings.all {
            #expect(!s.name.isEmpty, "\(s.id) has no display name")
            #expect(!s.summary.isEmpty, "\(s.id) has no plain-English summary")
            #expect(s.group != nil, "\(s.id) is ungrouped")
        }
    }

    /// Groups follow the canonical taxonomy order (Connection → Sign-In →
    /// Traffic → Security → Advanced), with nothing left over or empty.
    @Test func groupsAreCanonicalAndOrdered() {
        let order = SettingGroup.allCases
        let indices = SSHSettings.all.compactMap { s in s.group.flatMap(order.firstIndex(of:)) }
        #expect(indices.count == SSHSettings.all.count)
        #expect(indices == indices.sorted(), "catalog order must follow the canonical group order")
        for group in order {
            #expect(!SSHSettings.specs(in: group).isEmpty, "group \(group.title) has no SSH options")
        }
    }

    @Test func manualAnchorsExistInTheBundledManual() throws {
        let url = try #require(Bundle(for: BundleToken.self).url(forResource: "manual", withExtension: "html")
                               ?? Bundle.main.url(forResource: "manual", withExtension: "html"))
        let html = try String(contentsOf: url, encoding: .utf8)
        for s in SSHSettings.all {
            #expect(!s.manualAnchor.contains("."))
            #expect(s.manualAnchor.hasPrefix("ssh-"))
            #expect(html.contains("id=\"\(s.manualAnchor)\""), "manual.html is missing #\(s.manualAnchor)")
        }
    }

    // MARK: Config decode tolerance (fields added after configs were saved)

    @Test func configsSavedBeforeTheLibsshFieldsStillDecode() throws {
        var old = SubprocessTunnelConfig()
        old.server = "ssh.example.com"
        var json = try #require(try JSONSerialization.jsonObject(
            with: JSONEncoder().encode(old)) as? [String: Any])
        for key in ["sshAuthMethod", "sshCertificateFile", "sshPinnedHostKey", "sshKexAlgorithms"] {
            json.removeValue(forKey: key)
        }
        let decoded = try JSONDecoder().decode(SubprocessTunnelConfig.self,
                                               from: JSONSerialization.data(withJSONObject: json))
        #expect(decoded.server == "ssh.example.com")
        #expect(decoded.sshAuthMethod == nil)
        #expect(decoded.sshCertificateFile == nil)
        #expect(decoded.sshPinnedHostKey == nil)
        #expect(decoded.sshKexAlgorithms == nil)
    }

    // MARK: Legal ranges & closed value sets
    //
    // Every one of these fields was an unbounded TextField: a value the tool
    // would refuse at startup was accepted here and surfaced as an opaque
    // "openconnect exited 1" / "ssh: bad configuration option".

    @Test func rangesAreTheToolsOwn() {
        #expect(SubprocessTunnelConfig.portRange == 1...65535)
        #expect(!SubprocessTunnelConfig.portRange.contains(0))
        #expect(!SubprocessTunnelConfig.portRange.contains(65536))

        // The local SOCKS listener binds without root, so the floor is 1024.
        #expect(SubprocessTunnelConfig.socksPortRange == 1024...65535)
        #expect(!SubprocessTunnelConfig.socksPortRange.contains(1023))
        #expect(SubprocessTunnelConfig.socksPortRange.contains(1080))

        // 0 would mean "no timeout", which ssh spells by omitting the option.
        #expect(SubprocessTunnelConfig.connectTimeoutRange == 1...600)
        #expect(!SubprocessTunnelConfig.connectTimeoutRange.contains(0))
        #expect(!SubprocessTunnelConfig.connectTimeoutRange.contains(601))

        #expect(SubprocessTunnelConfig.keepaliveRange.contains(0))       // 0 = off
        #expect(SubprocessTunnelConfig.keepaliveRange.contains(30))      // the default

        // The tunnel's MTU rides an IP path; the BASE MTU describes that path,
        // which may be a jumbo-frame link — hence two different ceilings.
        #expect(SubprocessTunnelConfig.ocMTURange == 576...1500)
        #expect(SubprocessTunnelConfig.baseMTURange == 576...9000)
        #expect(!SubprocessTunnelConfig.ocMTURange.contains(9000))
        #expect(SubprocessTunnelConfig.baseMTURange.contains(9000))
        #expect(!SubprocessTunnelConfig.baseMTURange.contains(575))

        #expect(SubprocessTunnelConfig.reconnectTimeoutRange == 0...86_400)
        #expect(SubprocessTunnelConfig.forceDPDRange == 0...3600)
        #expect(!SubprocessTunnelConfig.forceDPDRange.contains(3601))
    }

    /// `--os=` and `--token-mode=` take closed sets. `rsa` and `yubioath` were
    /// missing from the picker, so a working configuration couldn't be expressed.
    @Test func closedValueSetsMatchOpenConnect() {
        #expect(SubprocessTunnelConfig.spoofOSValues
                == ["linux", "linux-64", "win", "mac-intel", "android", "apple-ios"])
        #expect(SubprocessTunnelConfig.tokenModeValues
                == ["totp", "hotp", "oidc", "rsa", "yubioath"])
        // A YubiKey holds its own secret — demanding a seed would block a
        // working setup, which is the other half of the validation rule.
        #expect(SubprocessTunnelConfig.tokenModeRequiresSecret("totp"))
        #expect(SubprocessTunnelConfig.tokenModeRequiresSecret("rsa"))
        #expect(!SubprocessTunnelConfig.tokenModeRequiresSecret("yubioath"))
        #expect(!SubprocessTunnelConfig.tokenModeRequiresSecret(""))
        // Every offered value has a human label.
        for v in SubprocessTunnelConfig.spoofOSValues {
            #expect(!SubprocessTunnelView.spoofOSLabel(v).isEmpty)
        }
    }

    @Test func normalizedTrimsAndDropsOutOfRangeNumbers() {
        var c = SubprocessTunnelConfig()
        c.name = "  Work  "
        c.server = " vpn.example.com\n"
        c.forwards = [" L 8080:internal:80 ", "", "  "]
        c.extraArgs = ["", " --no-dtls "]
        c.port = 0
        c.jumpPort = 99_999
        c.connectTimeout = 0
        c.serverAliveInterval = -5
        c.socksPort = 80
        c.ocMTU = 9000
        c.baseMTU = 100
        c.reconnectTimeout = -1
        c.forceDPD = 4000
        c.spoofOS = "windoze"
        c.tokenMode = "magic"
        let n = c.normalized()
        #expect(n.name == "Work")
        #expect(n.server == "vpn.example.com")
        #expect(n.forwards == ["L 8080:internal:80"])
        #expect(n.extraArgs == ["--no-dtls"])
        #expect(n.port == nil)
        #expect(n.jumpPort == nil)
        #expect(n.connectTimeout == nil)
        #expect(n.serverAliveInterval == 30)
        #expect(n.ocMTU == nil)
        #expect(n.baseMTU == nil)
        #expect(n.reconnectTimeout == nil)
        #expect(n.forceDPD == nil)
        // DELIBERATELY UNTOUCHED — a stored value is never silently rewritten.
        // See `aStoredSOCKSPortIsNeverRewrittenBehindTheUsersBack` below.
        #expect(n.socksPort == 80)
        #expect(n.spoofOS == "windoze")
        #expect(n.tokenMode == "magic")

        // In-range values survive untouched.
        c.port = 2222; c.jumpPort = 22; c.connectTimeout = 10
        c.serverAliveInterval = 0; c.socksPort = 1081
        c.ocMTU = 1400; c.baseMTU = 9000; c.reconnectTimeout = 0; c.forceDPD = 30
        c.spoofOS = "win"; c.tokenMode = "yubioath"
        let ok = c.normalized()
        #expect(ok.port == 2222)
        #expect(ok.jumpPort == 22)
        #expect(ok.connectTimeout == 10)
        #expect(ok.serverAliveInterval == 0)
        #expect(ok.socksPort == 1081)
        #expect(ok.ocMTU == 1400)
        #expect(ok.baseMTU == 9000)
        #expect(ok.reconnectTimeout == 0)
        #expect(ok.forceDPD == 30)
        #expect(ok.spoofOS == "win")
        #expect(ok.tokenMode == "yubioath")
    }

    /// REGRESSION (data loss). `normalized()` runs on EVERY save, and it used to
    /// move an out-of-range SOCKS port to 1080 and blank an unrecognised `--os=` /
    /// `--token-mode=`. Both are STORED values: apps, browser profiles and notes
    /// point at that port, so moving it on an unrelated save breaks them and makes
    /// the number appear to change by itself — and blanking a value someone stored
    /// loses it with no trace. The editor blocks Save on the port and caveats the
    /// other two instead.
    @Test func aStoredSOCKSPortIsNeverRewrittenBehindTheUsersBack() {
        var c = SubprocessTunnelConfig()
        c.socksPort = 80            // illegal for our unprivileged listener
        c.spoofOS = "windoze"       // openconnect would refuse it
        c.tokenMode = "magic"
        // Save something unrelated…
        c.name = " Work "
        let n = c.normalized()
        #expect(n.name == "Work")
        #expect(n.socksPort == 80, "an unrelated save moved the stored SOCKS port")
        #expect(n.spoofOS == "windoze", "an unrelated save blanked the stored reported OS")
        #expect(n.tokenMode == "magic", "an unrelated save blanked the stored token mode")
        // …and each one says what is wrong with it, in the user's language.
        #expect(SubprocessTunnelConfig.socksPortProblem(80) != nil)
        #expect(SubprocessTunnelConfig.socksPortProblem(1080) == nil)
        #expect(SubprocessTunnelConfig.spoofOSProblem("windoze") != nil)
        #expect(SubprocessTunnelConfig.spoofOSProblem("win") == nil)
        #expect(SubprocessTunnelConfig.spoofOSProblem("") == nil)
        #expect(SubprocessTunnelConfig.tokenModeProblem("magic") != nil)
        #expect(SubprocessTunnelConfig.tokenModeProblem("totp") == nil)
        #expect(SubprocessTunnelConfig.tokenModeProblem("") == nil)
    }

    /// REGRESSION (silent security/behaviour change). Gating the `--certificate` /
    /// `--sslkey` flags on `authMode` turned every existing certificate profile
    /// into a password one, because the model default is "password" and that
    /// picker was inert until the batch that started reading it — so nobody had
    /// ever set it. A stored client certificate IS the answer.
    @Test func aStoredClientCertificateMigratesToCertificateSignIn() {
        var cert = SubprocessTunnelConfig()
        cert.kind = .ciscoAnyConnect
        cert.clientCertFile = "~/client.p12"
        #expect(cert.authMode == "password")            // the default nobody set

        var keyOnly = SubprocessTunnelConfig()
        keyOnly.kind = .f5apm
        keyOnly.clientKeyFile = "~/client.key"

        // Untouched: no certificate material, so nothing to infer.
        var plain = SubprocessTunnelConfig()
        plain.kind = .fortinet

        // Untouched: SSH has no `authMode` concept and its own auth pinning.
        var ssh = SubprocessTunnelConfig()
        ssh.kind = .ssh
        ssh.clientCertFile = "~/nonsense.p12"

        // Untouched: an explicit choice is never overridden.
        var sso = SubprocessTunnelConfig()
        sso.kind = .globalProtect
        sso.authMode = "sso"
        sso.clientCertFile = "~/client.p12"

        let (out, changed) = SubprocessTunnelStore.migrated([cert, keyOnly, plain, ssh, sso])
        #expect(changed)
        #expect(out[0].authMode == "certificate")
        #expect(out[1].authMode == "certificate")
        #expect(out[2].authMode == "password")
        #expect(out[3].authMode == "password")
        #expect(out[4].authMode == "sso")
        // …and the argv follows, which is the point: the flags come back.
        #expect(SubprocessTunnelManager.openconnectArgs(for: out[0])
                .contains { $0.hasPrefix("--certificate=") })
        #expect(!SubprocessTunnelManager.openconnectArgs(for: out[0]).contains("--passwd-on-stdin"))
        // Idempotent — a second load changes nothing.
        #expect(!SubprocessTunnelStore.migrated(out).changed)
    }

    /// The pre-existing SSO fixup still works, and still only for the kinds with
    /// no browser flow.
    @Test func staleSSOStillFallsBackToPasswordOnKindsWithoutABrowserFlow() {
        var stale = SubprocessTunnelConfig()
        stale.kind = .fortinet          // no --external-browser flow
        stale.authMode = "sso"
        var fine = SubprocessTunnelConfig()
        fine.kind = .ciscoAnyConnect    // has one
        fine.authMode = "sso"
        let (out, changed) = SubprocessTunnelStore.migrated([stale, fine])
        #expect(changed)
        #expect(out[0].authMode == "password")
        #expect(out[1].authMode == "sso")
    }

    /// Non-blocking, and it must stay that way: a file may be created, mounted
    /// or synced between saving the tunnel and the next connect.
    @Test func aMissingFileIsWarnedAboutNotBlocked() {
        #expect(SubprocessTunnelConfig.missingFileWarning("") == nil)
        #expect(SubprocessTunnelConfig.missingFileWarning("   ") == nil)
        #expect(SubprocessTunnelConfig.missingFileWarning("/etc/hosts") == nil)
        // Tilde paths are expanded before the check — the tool expands them too.
        #expect(SubprocessTunnelConfig.missingFileWarning("~") == nil)
        #expect(SubprocessTunnelConfig.missingFileWarning(
            "/definitely/not/here/\(UUID().uuidString).pem") != nil)
    }

    // MARK: argv wiring (subprocess path honors the new fields)

    private func sshArgs(_ mutate: (inout SubprocessTunnelConfig) -> Void) -> [String] {
        var c = SubprocessTunnelConfig()
        c.kind = .ssh
        c.server = "ssh.example.com"
        mutate(&c)
        return SubprocessTunnelManager.command(for: c, password: nil)?.1 ?? []
    }

    /// An explicit method pins ssh to it — the chosen method is the one used,
    /// never whatever OpenSSH's default order finds first.
    @Test func passwordMethodPinsPasswordAndDisablesKeys() {
        let args = sshArgs {
            $0.sshAuthMethod = "password"
            $0.identityFile = "~/.ssh/id_ed25519"   // set but must NOT ride along
        }
        #expect(args.contains("PreferredAuthentications=password,keyboard-interactive"))
        #expect(args.contains("PubkeyAuthentication=no"))
        #expect(!args.contains("-i"))
    }

    @Test func certificateMethodPinsPublickeyWithIdentitiesOnly() {
        let args = sshArgs {
            $0.sshAuthMethod = "certificate"
            $0.identityFile = "~/.ssh/id_ed25519"
            $0.sshCertificateFile = "~/.ssh/id_ed25519-cert.pub"
        }
        #expect(args.contains("PreferredAuthentications=publickey"))
        #expect(args.contains("IdentitiesOnly=yes"))
        #expect(args.contains("-i"))
        #expect(args.contains { $0.hasPrefix("CertificateFile=") && $0.hasSuffix("/.ssh/id_ed25519-cert.pub") })
    }

    @Test func kerberosMethodEnablesGSSAPIOnly() {
        let args = sshArgs { $0.sshAuthMethod = "kerberos" }
        #expect(args.contains("GSSAPIAuthentication=yes"))
        #expect(args.contains("PreferredAuthentications=gssapi-with-mic"))
    }

    @Test func agentMethodPinsPublickeyWithoutAnIdentity() {
        let args = sshArgs {
            $0.sshAuthMethod = "agent"
            $0.identityFile = "~/.ssh/id_ed25519"
        }
        #expect(args.contains("PreferredAuthentications=publickey"))
        #expect(!args.contains("IdentitiesOnly=yes"))
        #expect(!args.contains("-i"))
    }

    @Test func kexPreferenceRidesTheArgv() {
        let args = sshArgs { $0.sshKexAlgorithms = "mlkem768x25519-sha256" }
        #expect(args.contains("KexAlgorithms=mlkem768x25519-sha256"))
    }

    @Test func defaultsAddNoneOfTheNewOptions() {
        let args = sshArgs { _ in }
        #expect(!args.contains { $0.hasPrefix("CertificateFile=") })
        #expect(!args.contains { $0.hasPrefix("GSSAPIAuthentication") })
        #expect(!args.contains { $0.hasPrefix("KexAlgorithms=") })
        #expect(!args.contains { $0.hasPrefix("PreferredAuthentications=") })
        #expect(!args.contains { $0.hasPrefix("IdentitiesOnly=") })
    }

    /// A method missing its material is refused with its fix, not attempted.
    @Test func authBlockReasonNamesTheMissingMaterial() {
        var c = SubprocessTunnelConfig()
        c.kind = .ssh
        c.server = "ssh.example.com"
        #expect(SubprocessTunnelManager.sshAuthBlockReason(c) == nil)     // automatic
        c.sshAuthMethod = "key"
        #expect(SubprocessTunnelManager.sshAuthBlockReason(c) != nil)     // no identity file
        c.identityFile = "~/.ssh/id_ed25519"
        #expect(SubprocessTunnelManager.sshAuthBlockReason(c) == nil)
        c.sshAuthMethod = "certificate"
        #expect(SubprocessTunnelManager.sshAuthBlockReason(c) != nil)     // no certificate
        c.sshCertificateFile = "~/.ssh/id_ed25519-cert.pub"
        #expect(SubprocessTunnelManager.sshAuthBlockReason(c) == nil)
    }

    // MARK: Pinned host key (in-process only — the honesty gate)

    @Test func pinnedKeyNormalizesPrefixAndCase() {
        var c = SubprocessTunnelConfig()
        c.kind = .ssh
        let hex = String(repeating: "AB12", count: 16)
        c.sshPinnedHostKey = " SHA256:\(hex) "
        #expect(SubprocessTunnelManager.sshPinnedKey(c) == hex.lowercased())
        c.sshPinnedHostKey = "   "
        #expect(SubprocessTunnelManager.sshPinnedKey(c) == nil)
    }

    @Test func pinBlocksOnlyTheConfigsTheSubprocessWouldGet() {
        var c = SubprocessTunnelConfig()
        c.kind = .ssh
        c.server = "ssh.example.com"
        c.sshPinnedHostKey = String(repeating: "ab", count: 32)

        // SOCKS + in-process-clean: the engine enforces the pin — no block.
        #expect(SubprocessTunnelManager.sshPinBlockReason(c) == nil)

        // A jump host forces /usr/bin/ssh, which can't check a pin — blocked.
        c.useJumpHost = true; c.jumpHost = "bastion.example.com"
        #expect(SubprocessTunnelManager.sshPinBlockReason(c) != nil)
        c.useJumpHost = false; c.jumpHost = ""

        // Port-forward mode runs the subprocess — blocked.
        c.sshMode = .portForward
        #expect(SubprocessTunnelManager.sshPinBlockReason(c) != nil)
        c.sshMode = .socks

        // No pin → never blocked, whatever else is set.
        c.sshPinnedHostKey = nil
        c.compression = true
        #expect(SubprocessTunnelManager.sshPinBlockReason(c) == nil)
    }

    /// A hardware security key (`sk-ssh-ed25519@openssh.com` / `sk-ecdsa…`) is a
    /// normal identity file to configure but NOT to use: the device signs, so the
    /// connect waits for a touch. The editor says so up front — a connect that
    /// silently blocks on a key nobody was told to touch reads as a hang.
    @Test func securityKeyIdentityFilesAreCalledOutFromTheirPublicHalf() throws {
        let dir = URL(fileURLWithPath: NSTemporaryDirectory())
            .appendingPathComponent("sk-note-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: dir) }

        let plain = dir.appendingPathComponent("id_ed25519")
        try Data("PRIVATE".utf8).write(to: plain)
        try Data("ssh-ed25519 AAAAC3Nz… alex@mac\n".utf8)
            .write(to: dir.appendingPathComponent("id_ed25519.pub"))
        #expect(SubprocessTunnelConfig.securityKeyNote(plain.path) == nil)

        let sk = dir.appendingPathComponent("id_ed25519_sk")
        try Data("PRIVATE".utf8).write(to: sk)
        try Data("sk-ssh-ed25519@openssh.com AAAAGnNr… alex@mac\n".utf8)
            .write(to: dir.appendingPathComponent("id_ed25519_sk.pub"))
        let note = try #require(SubprocessTunnelConfig.securityKeyNote(sk.path))
        #expect(note.lowercased().contains("touch"))
        // Passing the public half directly works too, and an unreadable/absent
        // path is informational-only: no note, never an error.
        #expect(SubprocessTunnelConfig.securityKeyNote(sk.path + ".pub") != nil)
        #expect(SubprocessTunnelConfig.securityKeyNote(dir.appendingPathComponent("nope").path) == nil)
        #expect(SubprocessTunnelConfig.securityKeyNote("") == nil)
    }

    /// The sign-in method, certificate and kex preference are carried
    /// in-process — they must NOT push a config onto the subprocess path
    /// (only jump host, compression and raw extra options do).
    @Test func newFieldsStayInProcessEligible() {
        var c = SubprocessTunnelConfig()
        c.kind = .ssh
        c.sshAuthMethod = "certificate"
        c.identityFile = "~/.ssh/id_ed25519"
        c.sshCertificateFile = "~/.ssh/id-cert.pub"
        c.sshKexAlgorithms = "sntrup761x25519-sha512"
        c.sshPinnedHostKey = String(repeating: "cd", count: 32)
        #expect(SubprocessTunnelManager.inProcessSSHSupports(c))
        // Keepalive and compression are honoured IN-PROCESS now (a keepalive timer
        // on the session queue; SSH_OPTIONS_COMPRESSION at kex), so neither pushes
        // the connection out to /usr/bin/ssh any more.
        c.compression = true
        c.serverAliveInterval = 15
        #expect(SubprocessTunnelManager.inProcessSSHSupports(c))
        // A jump host and raw ssh_config lines still do — the bridge can't express them.
        c.useJumpHost = true; c.jumpHost = "bastion.example.com"
        #expect(!SubprocessTunnelManager.inProcessSSHSupports(c))
        c.useJumpHost = false; c.jumpHost = ""
        c.sshExtraOptions = ["Ciphers aes256-gcm@openssh.com"]
        #expect(!SubprocessTunnelManager.inProcessSSHSupports(c))
    }
}

private final class BundleToken {}
