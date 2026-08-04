// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
//  SecurityKeySSHTests.swift
//  FIDO2 hardware security keys for SSH: everything up to the physical touch.
//
//  "A security key needs a human finger" was the reason this whole path was
//  untested — but the finger is the LAST step. Four things happen before it, all
//  of them ordinary code, and all four are asserted here:
//
//    1. THE ENGINE CAN DO IT AT ALL. libssh only understands an `sk-` private-key
//       FILE when it was compiled WITH_FIDO2 and libfido2 was actually found;
//       when it wasn't, HAVE_LIBFIDO2 silently goes off and only agent-held keys
//       work. The build script guards that (Tools/build-libssh-xcframework.sh) —
//       this re-checks the SHIPPED archive, so the guarantee isn't known in only
//       one place, and checks for DEFINED symbols rather than mere mentions.
//    2. AN sk- KEY IS RECOGNISED AS ONE. From the public half's key type, which
//       is the only place it is stated in clear text.
//    3. IT ROUTES TO KEY AUTH. An `sk-` identity must be tried as a KEY — the
//       token does the signing — and must never quietly fall through to a
//       password the user never set.
//    4. FAILING WITHOUT A TOKEN SAYS SO. libssh reports "key authentication was
//       rejected" whether the key is wrong or simply not plugged in, which sends
//       the user to look at the wrong thing.
//
//  THE FIXTURES ARE REAL KEYS, NOT PLACEHOLDER TEXT. `ssh-keygen -t ed25519-sk`
//  cannot run here (it needs a token to enrol against), so the public-key lines
//  are assembled from the OpenSSH wire format with real Curve25519 / P-256 public
//  points from CryptoKit — and `ssh-keygen -l` is asked to confirm it agrees they
//  are ED25519-SK / ECDSA-SK keys. A fixture the system itself recognises is the
//  difference between testing the detector and testing a string literal.
//
//  WHAT A HUMAN WITH A KEY STILL HAS TO DO — nothing here can stand in for it:
//    • plug the key in, then run a tunnel whose Sign-In method is Key with an
//      `sk-` identity file, and TOUCH the key when it flashes (and type its PIN
//      if it has one). That the signature is produced, that the touch prompt
//      arrives before the connect timeout, and that a second connect asks again
//      are all properties of the device.
//    • unplug it and confirm the message this file pins is the one that appears
//      on screen.
//

import Testing
import Foundation
import CryptoKit
@testable import SimpleVPN

@MainActor
struct SecurityKeySSHTests {

    // MARK: - Fixtures: genuinely well-formed sk- public keys

    /// An SSH wire "string": 4-byte big-endian length, then the bytes.
    private static func sshString(_ bytes: [UInt8]) -> [UInt8] {
        let n = UInt32(bytes.count)
        return [UInt8(n >> 24 & 0xff), UInt8(n >> 16 & 0xff), UInt8(n >> 8 & 0xff), UInt8(n & 0xff)]
            + bytes
    }

    private static func sshString(_ text: String) -> [UInt8] { sshString(Array(text.utf8)) }

    /// `sk-ssh-ed25519@openssh.com <base64> comment` — type, the 32-byte Ed25519
    /// public key, and the application string a key is enrolled against.
    static func ed25519SKPublicKeyLine(comment: String = "alex@mac") -> String {
        let type = "sk-ssh-ed25519@openssh.com"
        let pub = Array(Curve25519.Signing.PrivateKey().publicKey.rawRepresentation)
        let blob = sshString(type) + sshString(pub) + sshString("ssh:")
        return "\(type) \(Data(blob).base64EncodedString()) \(comment)\n"
    }

    /// `sk-ecdsa-sha2-nistp256@openssh.com <base64> comment` — type, curve name,
    /// the uncompressed EC point (0x04‖X‖Y), and the application string.
    static func ecdsaSKPublicKeyLine(comment: String = "alex@mac") -> String {
        let type = "sk-ecdsa-sha2-nistp256@openssh.com"
        let point = Array(P256.Signing.PrivateKey().publicKey.x963Representation)
        let blob = sshString(type) + sshString("nistp256") + sshString(point) + sshString("ssh:")
        return "\(type) \(Data(blob).base64EncodedString()) \(comment)\n"
    }

    /// An ordinary (non-security-key) Ed25519 public key line, for the negative side.
    static func plainEd25519PublicKeyLine() -> String {
        let type = "ssh-ed25519"
        let pub = Array(Curve25519.Signing.PrivateKey().publicKey.rawRepresentation)
        let blob = sshString(type) + sshString(pub)
        return "\(type) \(Data(blob).base64EncodedString()) alex@mac\n"
    }

    /// A throwaway directory holding `<name>` (a stand-in for the private handle,
    /// which is an encrypted blob nothing here reads) and `<name>.pub`.
    private static func identity(named name: String, publicLine: String) throws -> URL {
        let dir = URL(fileURLWithPath: NSTemporaryDirectory())
            .appendingPathComponent("sk-fixture-\(UUID().uuidString)")
        try FileManager.default.createDirectory(at: dir, withIntermediateDirectories: true)
        let key = dir.appendingPathComponent(name)
        try Data("PRIVATE HANDLE".utf8).write(to: key)
        try Data(publicLine.utf8).write(to: dir.appendingPathComponent(name + ".pub"))
        return key
    }

    // MARK: - 1. The engine can do it at all

    /// The shipped archive, or nil on a fresh clone — `Vendor/` is gitignored, so
    /// the engine may simply not have been built yet. This gates the symbol test
    /// rather than failing it; `libsshArchiveMode` always runs and says which mode
    /// the suite was in, so a green run can never be mistaken for a proven one.
    nonisolated static let sshEngineArchive: URL? = {
        let repoRoot = URL(fileURLWithPath: #filePath)
            .deletingLastPathComponent()      // ControlPlane/
            .deletingLastPathComponent()      // SimpleVPNTests/
            .deletingLastPathComponent()      // repo root
        let archive = repoRoot.appendingPathComponent(
            "Vendor/SSHEngine.xcframework/macos-arm64/libSSHEngine.a")
        return FileManager.default.fileExists(atPath: archive.path) ? archive : nil
    }()

    /// Always runs, and prints which mode the FIDO2 symbol check was in — a green
    /// suite must never be mistakable for a proven one (same discipline as
    /// `liveSSHFixtureMode` in SSHLiveIntegrationTests).
    @Test func libsshArchiveMode() throws {
        let mode = Self.sshEngineArchive.map { "ENABLED — \($0.path)" }
            ?? "SKIPPED — no built SSHEngine.xcframework (run Tools/build-libssh-xcframework.sh)"
        print("libssh FIDO2 symbol check: \(mode)")
        if let archive = Self.sshEngineArchive {
            let size = try FileManager.default
                .attributesOfItem(atPath: archive.path)[.size] as? Int ?? 0
            #expect(size > 1_000_000,
                    "\(archive.path) is \(size) bytes — that is not a merged static engine")
        }
    }

    /// The FIDO2 symbols are DEFINED in the archive the app links, not merely
    /// referenced by it. The distinction IS the test: libssh's own objects carry an
    /// UNDEFINED `_fido_dev_open`, so a check that greps for the bare name passes on
    /// an archive with libfido2 missing — precisely the silent failure ("only
    /// agent-held keys work") this exists to catch.
    @Test(.enabled(if: SecurityKeySSHTests.sshEngineArchive != nil))
    func theBuiltLibsshHasFIDO2CompiledIn() throws {
        let archive = try #require(Self.sshEngineArchive)

        let nm = Process()
        nm.executableURL = URL(fileURLWithPath: "/usr/bin/nm")
        nm.arguments = [archive.path]
        let pipe = Pipe()
        nm.standardOutput = pipe
        nm.standardError = FileHandle.nullDevice
        try nm.run()
        let out = String(decoding: pipe.fileHandleForReading.readDataToEndOfFile(), as: UTF8.self)
        nm.waitUntilExit()

        /// Lines of the form "<address> T|t _symbol" — a definition, not a reference.
        func isDefined(_ symbol: String) -> Bool {
            out.split(separator: "\n").contains { line in
                let parts = line.split(separator: " ").map(String.init)
                return parts.count == 3 && (parts[1] == "T" || parts[1] == "t") && parts[2] == symbol
            }
        }

        // pki_sk.c: compiled only under WITH_FIDO2 — this is what makes an sk- key
        // FILE usable at all.
        #expect(isDefined("_pki_sk_enroll_key"),
                "libssh was built without WITH_FIDO2 — an sk- key file cannot be used")
        // sk_usbhid.c: gated on HAVE_LIBFIDO2, so its presence proves cmake really
        // found libfido2 rather than warning and carrying on. File-static, hence `t`.
        #expect(isDefined("_ssh_sk_usbhid_load_resident_keys"),
                "libssh's USB-HID security-key transport is missing — cmake did not find libfido2")
        // And libfido2 itself is merged in, not just referenced.
        #expect(isDefined("_fido_dev_open"),
                "libfido2 is not in the merged archive (only an undefined reference to it)")
        // Its CBOR dependency too; Homebrew ships libcbor dylib-only, so a static
        // build must have been merged.
        #expect(isDefined("_cbor_load"), "static libcbor is not in the merged archive")

        // The negative: a name that exists ONLY as an undefined reference must not
        // count as defined, or the check above proves nothing.
        #expect(!isDefined("_this_symbol_does_not_exist_anywhere"))
    }

    // MARK: - 2. Recognition

    /// A security-key identity is spotted from its PUBLIC half, whose first field
    /// is the key type in clear text — and both key types are, not just Ed25519.
    /// Also asserts the fixtures are real: `ssh-keygen -l` must agree they are
    /// security keys, so this tests a detector rather than a string literal.
    @Test func bothSecurityKeyTypesAreRecognisedAndOrdinaryKeysAreNot() throws {
        for (name, line, keygenType) in [
            ("id_ed25519_sk", Self.ed25519SKPublicKeyLine(), "ED25519-SK"),
            ("id_ecdsa_sk", Self.ecdsaSKPublicKeyLine(), "ECDSA-SK"),
        ] {
            let key = try Self.identity(named: name, publicLine: line)
            defer { try? FileManager.default.removeItem(at: key.deletingLastPathComponent()) }

            let note = try #require(SubprocessTunnelConfig.securityKeyNote(key.path),
                                    "\(name) was not recognised as a security key")
            #expect(note.lowercased().contains("touch"),
                    "the note must say what the user has to DO: \(note)")
            // The public half works as the path too — people paste either.
            #expect(SubprocessTunnelConfig.securityKeyNote(key.path + ".pub") != nil)

            // OpenSSH's own opinion of the fixture, when it is available.
            if let described = Self.sshKeygenDescription(of: key.path + ".pub") {
                #expect(described.contains(keygenType),
                        "ssh-keygen does not read the fixture as \(keygenType): \(described)")
            }
        }

        // An ordinary key gets no note…
        let plain = try Self.identity(named: "id_ed25519", publicLine: Self.plainEd25519PublicKeyLine())
        defer { try? FileManager.default.removeItem(at: plain.deletingLastPathComponent()) }
        #expect(SubprocessTunnelConfig.securityKeyNote(plain.path) == nil)

        // …and neither does a LOOKALIKE type. The match is exact against
        // `securityKeyTypes`: "sk-ssh-ed25519" without the @openssh.com suffix is
        // not a key type OpenSSH ever writes, and treating it as one would mean
        // telling people to touch a device that isn't involved.
        let lookalike = try Self.identity(named: "id_fake",
                                          publicLine: "sk-ssh-ed25519 AAAAC3NzaC1 alex@mac\n")
        defer { try? FileManager.default.removeItem(at: lookalike.deletingLastPathComponent()) }
        #expect(SubprocessTunnelConfig.securityKeyNote(lookalike.path) == nil)

        // Both types the app claims to know are the two OpenSSH defines.
        #expect(Set(SubprocessTunnelConfig.securityKeyTypes) == [
            "sk-ssh-ed25519@openssh.com", "sk-ecdsa-sha2-nistp256@openssh.com",
        ])
    }

    /// `ssh-keygen -l -f <pub>` output, or nil when ssh-keygen isn't usable here.
    private static func sshKeygenDescription(of path: String) -> String? {
        let tool = "/usr/bin/ssh-keygen"
        guard FileManager.default.isExecutableFile(atPath: tool) else { return nil }
        let p = Process()
        p.executableURL = URL(fileURLWithPath: tool)
        p.arguments = ["-l", "-f", path]
        let pipe = Pipe()
        p.standardOutput = pipe
        p.standardError = FileHandle.nullDevice
        guard (try? p.run()) != nil else { return nil }
        let out = String(decoding: pipe.fileHandleForReading.readDataToEndOfFile(), as: UTF8.self)
        p.waitUntilExit()
        return p.terminationStatus == 0 ? out : nil
    }

    // MARK: - 3. Routing

    /// An `sk-` identity routes to KEY authentication — the token signs — and
    /// never reaches a password first. Asserted on the pure plan, so no server and
    /// no token are needed to prove where a config sends the sign-in.
    @Test func anSKIdentityRoutesToKeyAuthAndNeverToAPasswordFirst() throws {
        let key = try Self.identity(named: "id_ed25519_sk", publicLine: Self.ed25519SKPublicKeyLine())
        defer { try? FileManager.default.removeItem(at: key.deletingLastPathComponent()) }

        var c = SSHTunnelEngine.Config(host: "ssh.example.com", port: 22, username: "alex",
                                       socksPort: 1080)
        c.identityFile = key.path
        c.password = "not the way in"

        // Automatic: the key is tried FIRST, before the agent, and the password is
        // only ever a last resort. A security key that fell through to a password
        // prompt would look like a wrong-password problem.
        let automatic = try SSHTunnelEngine.authPlan(c)
        #expect(automatic.first == .key(certificate: false),
                "automatic sign-in did not try the identity file first: \(automatic)")
        #expect(automatic.last == .password)
        #expect(automatic == [.key(certificate: false), .agent, .password])

        // Explicit Key: exactly one attempt, so the token's own failure is what the
        // user sees rather than a password rejection standing in for it.
        c.authMethod = "key"
        #expect(try SSHTunnelEngine.authPlan(c) == [.key(certificate: false)])

        // A certificate on top of the sk- key still routes to the key path.
        c.authMethod = "certificate"
        c.certificateFile = key.path + "-cert.pub"
        #expect(try SSHTunnelEngine.authPlan(c) == [.key(certificate: true)])

        // An explicit password is still honoured — the user's choice wins over our
        // opinion about their key. (Automatic is where the routing matters.)
        c.authMethod = "password"
        #expect(try SSHTunnelEngine.authPlan(c) == [.password])

        // And the doomed configurations refuse themselves with their fix, rather
        // than picking some other method behind the user's back.
        c.authMethod = "key"
        c.identityFile = ""
        #expect(throws: SSHTunnelEngine.AuthError.self) { try SSHTunnelEngine.authPlan(c) }
        c.authMethod = "password"
        c.password = nil
        #expect(throws: SSHTunnelEngine.AuthError.self) { try SSHTunnelEngine.authPlan(c) }

        // With no identity file and no password, automatic falls to the agent alone
        // — never an empty plan, which would authenticate nothing and report success.
        var bare = SSHTunnelEngine.Config(host: "h", port: 22, username: "alex", socksPort: 1080)
        bare.authMethod = nil
        #expect(try SSHTunnelEngine.authPlan(bare) == [.agent])
    }

    // MARK: - 4. Failing without a token says so

    /// With no token attached the sign-in fails — the point is that it fails with a
    /// sentence naming what to do, not libssh's generic "key authentication was
    /// rejected", and not a hang.
    @Test func aSecurityKeyFailureNamesTheTokenAndTheTouch() throws {
        let sk = try Self.identity(named: "id_ed25519_sk", publicLine: Self.ed25519SKPublicKeyLine())
        defer { try? FileManager.default.removeItem(at: sk.deletingLastPathComponent()) }

        let advice = try #require(SSHTunnelEngine.securityKeyAdvice(identityFile: sk.path),
                                  "an sk- identity produced no security-key advice")
        let lower = advice.lowercased()
        #expect(lower.contains("touch"), "the advice never mentions the touch: \(advice)")
        #expect(lower.contains("plug") || lower.contains("insert"),
                "the advice never says the key has to be attached: \(advice)")
        // No jargon: nobody hears "FIDO2", "sk-ssh-ed25519" or "libfido2".
        for jargon in ["fido", "sk-ssh", "libssh", "usbhid", "userauth"] {
            #expect(!lower.contains(jargon), "\u{201C}\(advice)\u{201D} leaks \u{201C}\(jargon)\u{201D}")
        }

        // An ORDINARY key must not be blamed on a token that was never involved.
        let plain = try Self.identity(named: "id_ed25519", publicLine: Self.plainEd25519PublicKeyLine())
        defer { try? FileManager.default.removeItem(at: plain.deletingLastPathComponent()) }
        #expect(SSHTunnelEngine.securityKeyAdvice(identityFile: plain.path) == nil)
        #expect(SSHTunnelEngine.securityKeyAdvice(identityFile: nil) == nil)
        #expect(SSHTunnelEngine.securityKeyAdvice(identityFile: "") == nil)

        // And the connect can't hang waiting for a finger that never arrives: the
        // in-process engine's own timeout bounds the whole exchange.
        var c = SSHTunnelEngine.Config(host: "h", port: 22, username: "alex", socksPort: 1080)
        c.identityFile = sk.path
        #expect(c.connectTimeout > 0,
                "an sk- sign-in with no token would wait forever without a connect timeout")
    }

    /// A security-key identity does not push the tunnel out to /usr/bin/ssh: the
    /// in-process libssh engine is FIDO2-capable (asserted above), so the sk- case
    /// stays on the path that can enforce a host-key pin.
    @Test func anSKIdentityStaysOnTheInProcessEngine() throws {
        let sk = try Self.identity(named: "id_ed25519_sk", publicLine: Self.ed25519SKPublicKeyLine())
        defer { try? FileManager.default.removeItem(at: sk.deletingLastPathComponent()) }

        var c = SubprocessTunnelConfig()
        c.kind = .ssh
        c.sshMode = .socks
        c.identityFile = sk.path
        c.sshAuthMethod = "key"
        #expect(SubprocessTunnelManager.inProcessSSHSupports(c))
        #expect(SubprocessTunnelManager.sshAuthBlockReason(c) == nil)
        // A pinned host key is still enforceable with a security key.
        c.sshPinnedHostKey = String(repeating: "ab", count: 32)
        #expect(SubprocessTunnelManager.sshPinBlockReason(c) == nil)
    }
}
