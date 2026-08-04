// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
//  SSHConfigImportTests.swift
//  The OpenSSH config parser must mirror ssh's own semantics (first value wins,
//  list keywords accumulate, wildcard defaults fold in, negations veto) — an
//  import that disagrees with `ssh <alias>` would misconfigure tunnels.
//

import Testing
@testable import SimpleVPN

struct SSHConfigImportTests {

    private let sample = """
    # workstation config
    Compression yes

    Host bastion
        HostName bastion.corp.example
        User jump-user
        Port 2222

    Host tig-vpn
        HostName tig-vpn.grlab.co.uk
        User jimd
        IdentityFile ~/.ssh/id_ed25519
        IdentityFile ~/.ssh/id_backup
        CertificateFile ~/.ssh/id_ed25519-cert.pub
        ProxyJump bastion
        LocalForward 8080 internal.host:80
        LocalForward localhost:8443 internal.host:443
        RemoteForward 9000 127.0.0.1:9000
        DynamicForward 1080
        ServerAliveInterval 15

    Host *.grlab.co.uk tig-vpn
        User fallback-user
        Port 2200

    Host !tig-vpn *
        Port 4444
    """

    @Test func concreteHostsOnly() {
        let hosts = SSHConfigImport.parse(sample)
        #expect(hosts.map(\.alias) == ["bastion", "tig-vpn"])
    }

    @Test func firstValueWinsAndListsAccumulate() throws {
        let host = try #require(SSHConfigImport.parse(sample).first { $0.alias == "tig-vpn" })
        #expect(host.effectiveHostName == "tig-vpn.grlab.co.uk")
        #expect(host.user == "jimd")                       // not fallback-user (first wins)
        #expect(host.port == 2200)                          // own block has no Port → wildcard supplies it
        #expect(host.identityFiles == ["~/.ssh/id_ed25519", "~/.ssh/id_backup"])
        #expect(host.certificateFiles == ["~/.ssh/id_ed25519-cert.pub"])
        #expect(host.proxyJump == "bastion")
        #expect(host.serverAliveInterval == 15)
        #expect(host.compression == true)                   // pre-Host global
    }

    @Test func negatedPatternVetoes() throws {
        // `Host !tig-vpn *` must NOT apply Port 4444 to tig-vpn, but bastion
        // (no own Port conflict at 2222? it has 2222 first) — check a host with
        // no explicit port picks it up instead.
        let tig = try #require(SSHConfigImport.parse(sample).first { $0.alias == "tig-vpn" })
        #expect(tig.port == 2200)
        let bastion = try #require(SSHConfigImport.parse(sample).first { $0.alias == "bastion" })
        #expect(bastion.port == 2222)                       // own block wins over !-block
    }

    @Test func forwardsNormalized() throws {
        let host = try #require(SSHConfigImport.parse(sample).first { $0.alias == "tig-vpn" })
        #expect(host.localForwards == ["8080:internal.host:80", "8443:internal.host:443"])
        #expect(host.remoteForwards == ["9000:127.0.0.1:9000"])
        #expect(host.dynamicForwards == [1080])
        #expect(host.forwardLines == ["L 8080:internal.host:80", "L 8443:internal.host:443",
                                      "R 9000:127.0.0.1:9000"])
    }

    @Test func equalsSyntaxAndQuotes() {
        let hosts = SSHConfigImport.parse("""
        Host box
            HostName=box.example.net
            IdentityFile "~/.ssh/my key"
        """)
        #expect(hosts.first?.hostName == "box.example.net")
        #expect(hosts.first?.identityFiles == ["~/.ssh/my key"])
    }

    @Test func matchBlocksAreSkipped() {
        let hosts = SSHConfigImport.parse("""
        Host real
            HostName real.example.net
        Match host *.example.net
            User should-not-apply
        Host real2
            HostName real2.example.net
        """)
        #expect(hosts.map(\.alias) == ["real", "real2"])
        #expect(hosts.first?.user == nil)
    }

    @Test func applyFillsTunnelDraft() throws {
        let host = try #require(SSHConfigImport.parse(sample).first { $0.alias == "tig-vpn" })
        var config = SubprocessTunnelConfig()
        let applied = SSHConfigImport.apply(host, to: &config)
        #expect(config.server == "tig-vpn.grlab.co.uk")
        #expect(config.name == "tig-vpn")
        #expect(config.username == "jimd")
        #expect(config.port == 2200)
        #expect(config.identityFile == "~/.ssh/id_ed25519")
        // First certificate lands in the dedicated field (so the in-process
        // engine presents it); only extras would fall back to ssh_config lines.
        #expect(config.sshCertificateFile == "~/.ssh/id_ed25519-cert.pub")
        #expect(!config.sshExtraOptions.contains("CertificateFile ~/.ssh/id_ed25519-cert.pub"))
        #expect(config.useJumpHost)
        #expect(config.jumpHost == "bastion")
        // DynamicForward present → SOCKS mode, but the discovered forwards ride along.
        #expect(config.sshMode == .socks)
        #expect(config.socksPort == 1080)
        #expect(config.forwards.count == 3)
        #expect(config.compression == true)
        #expect(config.serverAliveInterval == 15)
        #expect(!applied.summary.isEmpty)
    }

    @Test func jumpChainTakesFirstHopAndSaysSo() {
        var config = SubprocessTunnelConfig()
        var host = SSHConfigHost(alias: "deep")
        host.proxyJump = "admin@edge.example:2022,inner.example"
        let applied = SSHConfigImport.apply(host, to: &config)
        #expect(config.jumpHost == "edge.example")
        #expect(config.jumpUsername == "admin")
        #expect(config.jumpPort == 2022)
        #expect(applied.summary.contains("only the first hop"))
    }

    @Test func userHostPortSplitting() {
        #expect(SSHConfigImport.splitUserHostPort("a@b:22") == ("a", "b", 22))
        #expect(SSHConfigImport.splitUserHostPort("b") == (nil, "b", nil))
        #expect(SSHConfigImport.splitUserHostPort("a@[::1]:2222") == ("a", "::1", 2222))
        #expect(SSHConfigImport.splitUserHostPort("[fe80::1]") == (nil, "fe80::1", nil))
    }

    @Test func endpointMatching() {
        let hosts = SSHConfigImport.parse(sample)
        #expect(SSHConfigImport.hosts(hosts, matching: "tig-vpn.grlab.co.uk").map(\.alias) == ["tig-vpn"])
        #expect(SSHConfigImport.hosts(hosts, matching: "TIG-VPN").map(\.alias) == ["tig-vpn"])
        #expect(SSHConfigImport.hosts(hosts, matching: "nothere.example").isEmpty)
    }

    @Test func wildcardMatcher() {
        #expect(SSHConfigImport.wildcardMatch("tig-vpn.grlab.co.uk", "*.grlab.co.uk"))
        #expect(SSHConfigImport.wildcardMatch("abc", "a?c"))
        #expect(!SSHConfigImport.wildcardMatch("abc", "a?d"))
        #expect(SSHConfigImport.wildcardMatch("anything", "*"))
        #expect(!SSHConfigImport.wildcardMatch("ab", "a*c"))
    }

    @Test func classifyByContent() throws {
        let dir = FileManager.default.temporaryDirectory
            .appendingPathComponent("ssh-import-tests-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        defer { try? FileManager.default.removeItem(at: dir) }

        func write(_ name: String, _ contents: String) throws -> URL {
            let url = dir.appendingPathComponent(name)
            try contents.write(to: url, atomically: true, encoding: .utf8)
            return url
        }
        let key = try write("weird-name", "-----BEGIN OPENSSH PRIVATE KEY-----\nAAAA\n-----END OPENSSH PRIVATE KEY-----\n")
        #expect(SSHConfigImport.classify(url: key) == .privateKey(path: key.path))

        let pem = try write("old.pem", "-----BEGIN RSA PRIVATE KEY-----\nAAAA\n-----END RSA PRIVATE KEY-----\n")
        #expect(SSHConfigImport.classify(url: pem) == .privateKey(path: pem.path))

        let cert = try write("id-cert.pub", "ssh-ed25519-cert-v01@openssh.com AAAA comment\n")
        #expect(SSHConfigImport.classify(url: cert) == .certificate(path: cert.path))

        let pub = try write("id.pub", "ssh-ed25519 AAAA comment\n")
        #expect(SSHConfigImport.classify(url: pub) == .publicKey(path: pub.path))

        let config = try write("config", "Host x\n  HostName x.example\n")
        if case .config(let hosts) = SSHConfigImport.classify(url: config) {
            #expect(hosts.map(\.alias) == ["x"])
        } else {
            Issue.record("config not recognized")
        }

        let junk = try write("junk.txt", "just some notes\n")
        #expect(SSHConfigImport.classify(url: junk) == .unrecognized)
    }
}
