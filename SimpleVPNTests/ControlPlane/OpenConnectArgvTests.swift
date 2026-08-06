// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
//  OpenConnectArgvTests.swift
//  The SSL-VPN (OpenConnect) surface's honesty contract: the sign-in method the
//  picker shows is the method the argv actually performs — password mode never
//  presents a certificate, certificate mode never pipes a password — plus the
//  catalog/manual contract for the rows that method gates.
//  The SSH twin of these argv tests lives in SSHSettingDescriptorTests.
//

import Foundation
import Testing
@testable import SimpleVPN

@MainActor
struct OpenConnectArgvTests {

    private func config(_ mutate: (inout SubprocessTunnelConfig) -> Void) -> SubprocessTunnelConfig {
        var c = SubprocessTunnelConfig()
        c.kind = .ciscoAnyConnect
        c.server = "vpn.example.com"
        c.username = "alex"
        mutate(&c)
        return c
    }

    private func args(_ mutate: (inout SubprocessTunnelConfig) -> Void) -> [String] {
        SubprocessTunnelManager.openconnectArgs(for: config(mutate))
    }

    // MARK: The picker decides — not whatever file paths are lying around

    /// The bug: with method = Password and stale certificate paths, openconnect
    /// got BOTH --passwd-on-stdin and --certificate, did certificate auth (the
    /// cert wins), and the piped password became an unread stdin write.
    @Test func passwordModeSendsThePasswordAndNoCertificate() {
        let a = args {
            $0.authMode = "password"
            $0.clientCertFile = "~/stale-client.pem"   // set, but must NOT be used
            $0.clientKeyFile = "~/stale-client.key"
        }
        #expect(a.contains("--passwd-on-stdin"))
        #expect(!a.contains { $0.hasPrefix("--certificate=") })
        #expect(!a.contains { $0.hasPrefix("--sslkey=") })
        #expect(!a.contains { $0.hasPrefix("--key-password=") })
    }

    @Test func certificateModePresentsTheCertificateAndNeverAsksForAPassword() {
        let a = args {
            $0.authMode = "certificate"
            $0.clientCertFile = "~/client.pem"
            $0.clientKeyFile = "~/client.key"
        }
        #expect(!a.contains("--passwd-on-stdin"))
        #expect(a.contains { $0.hasPrefix("--certificate=") && $0.hasSuffix("/client.pem") })
        #expect(a.contains { $0.hasPrefix("--sslkey=") && $0.hasSuffix("/client.key") })
    }

    /// Password mode is what the process actually receives on stdin: an unread
    /// write is what hung a certificate-mode connect.
    @Test func onlyPasswordModePipesAPasswordToTheProcess() {
        // command(for:) needs openconnect installed to return anything at all;
        // the mode rule it applies is asserted directly either way.
        #expect(SubprocessTunnelManager.openconnectAuthMode(config { $0.authMode = "password" }) == "password")
        #expect(SubprocessTunnelManager.openconnectAuthMode(config { $0.authMode = "certificate" }) == "certificate")
        if TunnelCLI.openconnect.isAvailable {
            let cert = SubprocessTunnelManager.command(for: config {
                $0.authMode = "certificate"
                $0.clientCertFile = "~/client.pem"
            }, password: "hunter2")
            #expect(cert?.2 == nil, "certificate mode must not write to a stdin nobody reads")
            let pw = SubprocessTunnelManager.command(for: config { $0.authMode = "password" },
                                                     password: "hunter2")
            #expect(pw?.2 == Data("hunter2\n".utf8))
        }
    }

    /// SSO is routed to the ocauth-helper, so it never reaches this builder; a
    /// stale "sso" on a kind with no browser flow falls back to password.
    @Test func ssoNormalizesPerKind() {
        #expect(SubprocessTunnelManager.openconnectAuthMode(config {
            $0.kind = .ciscoAnyConnect; $0.authMode = "sso"
        }) == "sso")
        #expect(SubprocessTunnelManager.openconnectAuthMode(config {
            $0.kind = .fortinet; $0.authMode = "sso"      // no browser flow
        }) == "password")
        // …and that fallback really does ask for the password on stdin.
        #expect(args { $0.kind = .fortinet; $0.authMode = "sso" }.contains("--passwd-on-stdin"))
    }

    /// A verification-code token belongs to password/certificate sign-in; under
    /// SSO the identity provider asks for the code itself.
    @Test func tokenFlagsFollowTheMethod() {
        #expect(args { $0.authMode = "password"; $0.tokenMode = "totp" }
            .contains("--token-mode=totp"))
        #expect(args { $0.authMode = "certificate"; $0.clientCertFile = "~/c.pem"; $0.tokenMode = "totp" }
            .contains("--token-mode=totp"))
        #expect(!args { $0.authMode = "sso"; $0.tokenMode = "totp" }
            .contains("--token-mode=totp"))
    }

    /// A method missing its material is refused with its fix (the SSH rule),
    /// rather than failing opaquely inside openconnect.
    @Test func certificateModeNeedsACertificateFile() {
        #expect(SubprocessTunnelManager.sslAuthBlockReason(config { $0.authMode = "certificate" }) != nil)
        #expect(SubprocessTunnelManager.sslAuthBlockReason(config {
            $0.authMode = "certificate"; $0.clientCertFile = "~/client.pem"
        }) == nil)
        #expect(SubprocessTunnelManager.sslAuthBlockReason(config { $0.authMode = "password" }) == nil)
        // SSH kinds are the other rule's business.
        #expect(SubprocessTunnelManager.sslAuthBlockReason(config {
            $0.kind = .ssh; $0.authMode = "certificate"
        }) == nil)
        // The Fortinet fallback tool can't present a certificate, so certificate
        // mode is refused rather than silently signing in with a password.
        if !TunnelCLI.openconnect.isAvailable {
            #expect(SubprocessTunnelManager.sslAuthBlockReason(config {
                $0.kind = .fortinet; $0.authMode = "certificate"; $0.clientCertFile = "~/client.pem"
            }) != nil)
        }
    }

    // MARK: Host checker — the wrapper wins, and the UI says so

    @Test func wrapperOverridesTheSkipToggle() {
        let a = args { $0.disableCSD = true; $0.csdWrapper = "/opt/csd/wrapper.sh" }
        #expect(a.contains("--csd-wrapper=/opt/csd/wrapper.sh"))
        #expect(!a.contains("--csd-wrapper=/usr/bin/true"))
        #expect(args { $0.disableCSD = true }.contains("--csd-wrapper=/usr/bin/true"))
    }

    // MARK: Credentials must not ride the address

    /// The config is persisted unencrypted and the address lands on the tool's
    /// command line, where `ps` shows it to every local process.
    @Test func aPasswordInAnAddressIsRefused() {
        #expect(SubprocessTunnelManager.passwordInAddress("https://user:secret@vpn.example.com"))
        #expect(SubprocessTunnelManager.passwordInAddress("user:secret@vpn.example.com"))
        // A bare username is not a secret — ssh targets use it routinely.
        #expect(!SubprocessTunnelManager.passwordInAddress("alex@ssh.example.com"))
        #expect(!SubprocessTunnelManager.passwordInAddress("https://vpn.example.com/path@x"))

        #expect(SubprocessTunnelManager.addressCredentialReason(config {
            $0.server = "https://user:secret@vpn.example.com"
        }) != nil)
        #expect(SubprocessTunnelManager.addressCredentialReason(config {
            $0.proxyMode = .manual; $0.proxyURL = "http://user:secret@proxy.example.com:8080"
        }) != nil)
        // Not a manual proxy ⇒ the URL isn't used, so it can't leak.
        #expect(SubprocessTunnelManager.addressCredentialReason(config {
            $0.proxyMode = .systemDefault; $0.proxyURL = "http://user:secret@proxy.example.com:8080"
        }) == nil)
        #expect(SubprocessTunnelManager.addressCredentialReason(config { _ in }) == nil)
    }

    // MARK: The pinned server certificate — the ONE server-identity control

    /// A pin is refused unless it is one of the two forms OpenConnect prints. It
    /// used to be free text, and a typo there is not a warning: it is a connect
    /// that fails every time, complaining about the server's certificate.
    @Test func onlyTheTwoRealFingerprintFormsAreAccepted() {
        func problem(_ s: String) -> String? { SubprocessTunnelConfig.serverCertPinProblem(s) }
        // Empty is fine — the pin is optional.
        #expect(problem("") == nil)
        #expect(problem("   ") == nil)
        // base64 of 32 bytes, 44 characters ending "=" — with and without the prefix.
        let b64 = Data(repeating: 0xAB, count: 32).base64EncodedString()
        #expect(b64.count == 44)
        #expect(problem(b64) == nil)
        #expect(problem("pin-sha256:\(b64)") == nil)
        // sha256: + 64 hex, either case.
        let hex = String(repeating: "ab", count: 32)
        #expect(problem("sha256:\(hex)") == nil)
        #expect(problem("SHA256:\(hex.uppercased())") == nil)
        // …and the ways a pasted pin goes wrong.
        #expect(problem("sha256:\(hex.dropLast())") != nil)      // one character short
        #expect(problem("sha256:\(hex.dropLast())z") != nil)     // not hex
        #expect(problem(hex) != nil)                             // bare hex isn't a key pin
        #expect(problem(String(b64.dropLast())) != nil)          // truncated base64
        #expect(problem("pin-sha256:\(hex)") != nil)             // right prefix, wrong body
        #expect(problem("md5:\(hex)") != nil)                    // unknown algorithm
        // SHA-1 is a form openconnect accepts and this row deliberately doesn't:
        // it is named for SHA-256, and a SHA-1 pin isn't worth pinning to.
        #expect(problem("sha1:\(String(repeating: "a", count: 40))") != nil)
    }

    /// The argv prefix follows the pin's OWN form. Prefixing unconditionally —
    /// which is what the builder used to do — turned a valid `sha256:<hex>` pin
    /// into `pin-sha256:sha256:<hex>`, refused by openconnect at startup.
    @Test func theServercertArgumentKeepsThePinsOwnForm() {
        let b64 = Data(repeating: 0x11, count: 32).base64EncodedString()
        let hex = String(repeating: "cd", count: 32)
        #expect(SubprocessTunnelConfig.serverCertArgument(b64) == "pin-sha256:\(b64)")
        #expect(SubprocessTunnelConfig.serverCertArgument("pin-sha256:\(b64)") == "pin-sha256:\(b64)")
        #expect(SubprocessTunnelConfig.serverCertArgument("sha256:\(hex)") == "sha256:\(hex)")

        #expect(args { $0.trustedCertSHA256 = "sha256:\(hex)" }.contains("--servercert=sha256:\(hex)"))
        #expect(args { $0.trustedCertSHA256 = b64 }.contains("--servercert=pin-sha256:\(b64)"))
        #expect(!args { _ in }.contains { $0.hasPrefix("--servercert=") })
    }

    // MARK: In-process is asked for, not assumed

    /// The toggle only takes effect when the built-in engine can carry every
    /// setting — otherwise the openconnect tool runs it and the editor says why.
    /// The SOCKS rows' caveat hangs off this same gate.
    @Test func inProcessIsOnlyHonouredWhenTheBridgeCanCarryTheConfig() {
        #expect(!SubprocessTunnelManager.willRunInProcess(config { _ in }))
        #expect(SubprocessTunnelManager.willRunInProcess(config { $0.preferInProcess = true }))
        // Each of these is a knob the bridge can't express, so each sends it back.
        #expect(!SubprocessTunnelManager.willRunInProcess(config {
            $0.preferInProcess = true; $0.enablePFS = true
        }))
        #expect(!SubprocessTunnelManager.willRunInProcess(config {
            $0.preferInProcess = true; $0.caFile = "~/vpn-ca.pem"
        }))
        #expect(!SubprocessTunnelManager.willRunInProcess(config {
            $0.preferInProcess = true; $0.ocMTU = 1300
        }))
        // SSH is a different engine entirely; the SSL toggle can't claim it.
        #expect(!SubprocessTunnelManager.willRunInProcess(config {
            $0.kind = .ssh; $0.preferInProcess = true
        }))
    }

    /// Every SSL-VPN kind can go in-process, because the extension dispatches on
    /// `VPNKind.openconnectProtocol` and that covers all seven. The connect path
    /// used to name only fortinet / f5apm / anyconnect while `willRunInProcess`
    /// promised all of them — the editor said "in-process", the connect quietly
    /// spawned `openconnect` and demanded ocproxy. One rule now, asserted per kind.
    @Test func everySSLVPNKindCanRunInProcess() {
        let sslKinds = VPNKind.allCases.filter(\.isSSLVPN)
        #expect(sslKinds.count == 7, "the seven SSL-VPN kinds")
        for kind in sslKinds {
            #expect(SubprocessTunnelManager.willRunInProcess(config {
                $0.kind = kind; $0.preferInProcess = true
            }), "\(kind.rawValue) should be able to run in-process")
        }
    }

    // MARK: The transport must be able to carry traffic without root

    /// `openconnect` configures a real tun, which needs root this app never takes.
    /// `--script-tun --script "ocproxy -D <port>"` is the no-root path, and it is
    /// appended only when ocproxy resolves — so ocproxy is REQUIRED on the
    /// subprocess path, and its absence used to be a silent failure.
    @Test func aSubprocessSSLVPNWithoutOcproxyIsRefusedNotLeftToFail() {
        let c = config { _ in }   // no in-process, password sign-in
        #expect(SubprocessTunnelManager.sslTransportBlockReason(
            c, ocproxyAvailable: true, openconnectAvailable: true) == nil)
        let reason = SubprocessTunnelManager.sslTransportBlockReason(
            c, ocproxyAvailable: false, openconnectAvailable: true)
        #expect(reason != nil)
        // The fix it names is the bundled engine FIRST — Homebrew is the fallback,
        // not the answer (ONTOLOGY: failure text names the fix).
        #expect(reason?.contains("Run In-Process") == true)
        #expect(reason?.contains("brew install ocproxy") == true)
    }

    /// Going in-process there is no tool and no tun of ours to make, so nothing
    /// about ocproxy can block it — that is the whole point of the migration.
    @Test func anInProcessSSLVPNNeedsNoToolAtAll() {
        for kind in VPNKind.allCases.filter(\.isSSLVPN) {
            let c = config { $0.kind = kind; $0.preferInProcess = true }
            #expect(SubprocessTunnelManager.sslTransportBlockReason(
                c, ocproxyAvailable: false, openconnectAvailable: false) == nil,
                    "\(kind.rawValue) in-process must not require any tool")
        }
    }

    /// The in-process→subprocess fallback is only a fallback if the subprocess can
    /// carry traffic. Asked with `inProcess: false` (the engine was chosen and
    /// failed to start) the answer must not say "turn on Run In-Process" — it is
    /// already on, and advice that names a box the user already ticked is how
    /// people learn to stop reading error messages.
    @Test func theFallbackIsRefusedAndNeverToldToTickABoxAlreadyTicked() {
        let c = config { $0.preferInProcess = true }
        // As the connect path sees it: in-process, so nothing to block.
        #expect(SubprocessTunnelManager.sslTransportBlockReason(
            c, ocproxyAvailable: false, openconnectAvailable: true) == nil)
        // As the fallback faces it: the subprocess needs ocproxy and hasn't got it.
        let reason = SubprocessTunnelManager.sslTransportBlockReason(
            c, inProcess: false, ocproxyAvailable: false, openconnectAvailable: true)
        #expect(reason != nil)
        #expect(reason?.contains("brew install ocproxy") == true)
        #expect(reason?.contains("Turn on Run In-Process") == false)
        // With ocproxy present the fallback is legitimate again.
        #expect(SubprocessTunnelManager.sslTransportBlockReason(
            c, inProcess: false, ocproxyAvailable: true, openconnectAvailable: true) == nil)
    }

    /// A smartcard tunnel can never run in-process (AMFI forbids `dlopen`ing the
    /// provider module in the sysext, whatever TLS backend the xcframework is
    /// built with), so ocproxy is a genuine requirement there — and the refusal
    /// must NOT offer the toggle, which would still be false with it on.
    @Test func aSmartcardTunnelIsToldTheToolIsRequiredNotOfferedTheToggle() {
        let token = config {
            $0.authMode = "token"
            $0.pkcs11ModulePath = "/opt/homebrew/lib/libykcs11.dylib"
            $0.pkcs11CertificateURI = "pkcs11:token=SimpleVPN;object=vpn"
        }
        #expect(!SubprocessTunnelManager.willRunInProcess(config {
            $0.preferInProcess = true; $0.authMode = "token"
            $0.pkcs11CertificateURI = "pkcs11:token=SimpleVPN;object=vpn"
        }))
        let reason = SubprocessTunnelManager.sslTransportBlockReason(
            token, ocproxyAvailable: false, openconnectAvailable: true)
        #expect(reason != nil)
        #expect(reason?.contains("smartcard") == true)
        #expect(reason?.contains("Run In-Process") == false,
                "offering a toggle that cannot help is a lie")
    }

    /// The Fortinet-only `openfortivpn` fallback drives `pppd` — it has no
    /// userspace mode, so there is no ocproxy equivalent and it simply needs
    /// admin rights we don't take. Refuse it rather than let pppd fail.
    @Test func theOpenfortivpnFallbackIsRefusedBecauseItNeedsRoot() {
        let f = config { $0.kind = .fortinet }
        let reason = SubprocessTunnelManager.sslTransportBlockReason(
            f, ocproxyAvailable: true, openconnectAvailable: false)
        #expect(reason?.contains("administrator rights") == true)
        #expect(reason?.contains("Run In-Process") == true)
        // With openconnect present it is the ordinary ocproxy story again.
        #expect(SubprocessTunnelManager.sslTransportBlockReason(
            f, ocproxyAvailable: true, openconnectAvailable: true) == nil)
    }

    /// A missing tool must name the tool and the fix. "The required command-line
    /// tool isn't installed" sent nobody anywhere.
    @Test func aMissingToolNamesTheToolAndTheFix() {
        let reason = SubprocessTunnelManager.missingToolReason(config { _ in })
        #expect(reason.contains("openconnect"))
        #expect(reason.contains("Run In-Process"), "the bundled engine is the fix that needs no package manager")
        // SSH is a macOS tool — Homebrew is not the answer there.
        #expect(!SubprocessTunnelManager.missingToolReason(config { $0.kind = .ssh }).contains("brew"))
    }

    // MARK: Catalog / manual contract for the SSL-VPN rows

    @Test func everyOpenConnectSpecIsNamedSummarizedAndDocumented() throws {
        let url = try #require(Bundle(for: OCBundleToken.self).url(forResource: "manual", withExtension: "html")
                               ?? Bundle.main.url(forResource: "manual", withExtension: "html"))
        let html = try String(contentsOf: url, encoding: .utf8)
        for s in SubprocessTunnelView.specs.all {
            #expect(s.id.hasPrefix("oc."), "\(s.id) is outside the oc.* namespace")
            #expect(!s.name.isEmpty, "\(s.id) has no display name")
            #expect(!s.summary.isEmpty, "\(s.id) has no plain-English summary")
            #expect(!s.manualAnchor.contains("."))
            #expect(html.contains("id=\"\(s.manualAnchor)\""), "manual.html is missing #\(s.manualAnchor)")
        }
    }
}

private final class OCBundleToken {}
