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
        c.compression = true
        #expect(!SubprocessTunnelManager.inProcessSSHSupports(c))
    }
}

private final class BundleToken {}
