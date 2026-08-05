// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
//  PKCS11LiveIntegrationTests.swift
//  The PKCS#11 enumeration path against a REAL provider module and a REAL token.
//
//  Everything else about smartcard sign-in is contract-tested in PKCS11Tests.swift,
//  including every failure mode, using transcripts captured from the real tools. This
//  file is the only place our code actually runs them, because three claims cannot be
//  proven from a transcript:
//
//    • that `PKCS11ProcessRunner` invokes the tools with arguments they accept at all
//      (a fixture proves the parser, never the argv);
//    • that the child environment it builds is sufficient — in particular that
//      `LC_ALL=C` really does pin GnuTLS's locale-dependent `Expires:` line into the
//      one format `parseGnuTLSDate` reads;
//    • that a certificate exported through the module parses in Security.framework,
//      end to end, rather than in a PEM someone pasted into a test.
//
//  NO HARDWARE, NO NETWORK, NO PIN. The token is SoftHSM — a software token — and
//  enumeration never logs in, so nothing here can spend a PIN attempt or touch a
//  physical device. SoftHSM is a TEST dependency: SimpleVPN ships no provider module
//  for anybody's hardware and never will.
//
//  WITHOUT THE FIXTURE EVERY TEST HERE SKIPS, and `livePKCS11FixtureMode` always runs
//  and prints which mode the run was in — so a green suite can never be mistaken for
//  a proven one. To create it:
//
//      brew install softhsm gnutls opensc
//      ./Tools/pkcs11-live-test-fixture.sh
//      TEST_RUNNER_SIMPLEVPN_PKCS11_MODULE=/opt/homebrew/lib/softhsm/libsofthsm2.so \
//        xcodebuild -project SimpleVPN.xcodeproj -scheme SimpleVPN \
//        -destination 'platform=macOS' test -only-testing:SimpleVPNTests
//

import Testing
import Foundation
@testable import SimpleVPN

/// The module path the fixture script prints, or nil when the fixture isn't there.
/// Xcode prefixes injected variables with `TEST_RUNNER_`, matching the SSH live tests.
private nonisolated var liveModulePath: String? {
    let env = ProcessInfo.processInfo.environment
    guard let path = env["SIMPLEVPN_PKCS11_MODULE"] ?? env["TEST_RUNNER_SIMPLEVPN_PKCS11_MODULE"],
          !path.isEmpty, FileManager.default.isReadableFile(atPath: path) else { return nil }
    return path
}

/// The gate every live test carries. `.enabled(if:)` SKIPS rather than fails —
/// a machine with no fixture has proved nothing, which is not the same as broken.
private nonisolated var livePKCS11FixtureAvailable: Bool { liveModulePath != nil }

/// The token the fixture creates. Scoping to it keeps the tests correct on a machine
/// that has other tokens plugged in.
private nonisolated let liveTokenLabel = "SimpleVPN PKCS11 Live Test"
private nonisolated let liveTokenScope = "pkcs11:token=SimpleVPN%20PKCS11%20Live%20Test"

private nonisolated func liveEnumerator() -> PKCS11Enumerator { .live() }

// Shells out to real p11tool/pkcs11-tool against a real SoftHSM token. LocalToolRunner
// already bounds each child, but the ceiling is repeated here so a wedge anywhere in
// the suite — a token that never answers, a module that blocks on load — cannot hold a
// whole run. See the note on SSHLiveIntegrationTests.
@Suite(.timeLimit(.minutes(1)))
struct PKCS11LiveIntegrationTests {

    /// Always runs. Its whole job is to make the run's honesty visible in the log:
    /// a green suite with no fixture proved nothing about a real module.
    @Test func livePKCS11FixtureMode() {
        if let path = liveModulePath {
            print("PKCS#11 live tests: REAL — module \(path), " +
                  "p11tool \(PKCS11Tool.p11tool.resolvedPath ?? "absent"), " +
                  "pkcs11-tool \(PKCS11Tool.pkcs11Tool.resolvedPath ?? "absent")")
        } else {
            print("PKCS#11 live tests: SKIPPED — no fixture. " +
                  "Run ./Tools/pkcs11-live-test-fixture.sh and set " +
                  "SIMPLEVPN_PKCS11_MODULE to enumerate a real token.")
        }
    }

    @Test(.enabled(if: livePKCS11FixtureAvailable))
    func readsTheTokenThroughARealModule() async throws {
        let module = try #require(liveModulePath, "no PKCS#11 fixture — see this file's header")
        try #require(liveEnumerator().hasAnyTool, "needs p11tool or pkcs11-tool installed")
        let tokens = try await liveEnumerator().tokens(module: module).get()
        let token = try #require(tokens.first { $0.label == liveTokenLabel },
                                 "the fixture token isn't on this module")
        #expect(token.requiresLogin)
        #expect(token.uri.hasPrefix("pkcs11:"))
        #expect(PKCS11URI.parse(token.uri)?.tokenLabel == liveTokenLabel)
        // Nothing here logged in, so a freshly-made token has an untouched counter.
        #expect(!token.pinLocked)
        #expect(!token.isBlocked)
    }

    /// The end-to-end claim: a certificate is found, its URI is one our own validator
    /// accepts, and its expiry survives the round trip through GnuTLS's
    /// locale-dependent `Expires:` line (which only parses because the runner pins
    /// `LC_ALL=C`).
    @Test(.enabled(if: livePKCS11FixtureAvailable))
    func readsACertificateAndItsExpiryThroughARealModule() async throws {
        let module = try #require(liveModulePath, "no PKCS#11 fixture — see this file's header")
        try #require(PKCS11Tool.p11tool.resolvedPath != nil, "the expiry comes from p11tool")
        let certs = try await liveEnumerator()
            .certificates(module: module, tokenScope: liveTokenScope).get()
        let cert = try #require(certs.first, "the fixture writes one certificate")
        #expect(cert.label == "Certificate for PIV Authentication")
        #expect(PKCS11URI.problem(cert.uri) == nil,
                "a URI our own validator refuses would be unusable in the editor")
        #expect(PKCS11URI.parse(cert.uri)?.objectType == "cert")
        let expires = try #require(cert.expires, "the fixture certificate is valid for 365 days")
        #expect(expires > Date(), "a certificate made minutes ago must not read as expired")
        #expect(!cert.isExpired)
        // Security.framework read the exported certificate: this is the subject, which
        // the GnuTLS listing has no field for at all.
        #expect(cert.subject?.contains("alex.hunt") == true)
        #expect(!cert.rowSummary().isEmpty)
    }

    /// The URI enumeration produces is the URI we hand `openconnect` — pass it through
    /// the argv builder and it must survive intact (bar the query, which is dropped).
    @Test(.enabled(if: livePKCS11FixtureAvailable))
    func theEnumeratedURISurvivesTheArgvBuilder() async throws {
        let module = try #require(liveModulePath, "no PKCS#11 fixture — see this file's header")
        try #require(PKCS11Tool.p11tool.resolvedPath != nil)
        let certs = try await liveEnumerator()
            .certificates(module: module, tokenScope: liveTokenScope).get()
        let uri = try #require(certs.first?.uri)
        #expect(SubprocessTunnelConfig.pkcs11Argument(uri) == uri)
    }

    /// A module path that isn't a PKCS#11 module must come back as "unusable", not as
    /// an empty list that would read as "no token inserted".
    @Test(.enabled(if: livePKCS11FixtureAvailable))
    func aRealNonModuleIsReportedAsUnusable() async throws {
        try #require(liveModulePath != nil, "no PKCS#11 fixture — see this file's header")
        try #require(liveEnumerator().hasAnyTool)
        let result = await liveEnumerator().tokens(module: "/usr/lib/libSystem.dylib")
        #expect(result == .failure(.moduleUnusable(path: "/usr/lib/libSystem.dylib")))
    }
}
