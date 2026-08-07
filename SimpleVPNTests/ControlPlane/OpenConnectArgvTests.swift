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

    /// SIMPLEVPN NO LONGER GENERATES VERIFICATION CODES, and this test is the
    /// structural half of that: `--token-mode` must never appear in an argv again,
    /// whatever a stored `tokenMode` says. The profile keeps its stored value (it is
    /// not silently rewritten) and is refused at connect with an explanation instead —
    /// asserted just below. Docs/AuthSecPKCS11.md records why the gate stays closed.
    @Test func aStoredTokenModeNeverReachesTheArgv() {
        for mode in ["totp", "hotp", "oidc", "rsa", "yubioath"] {
            for method in ["password", "certificate", "sso"] {
                let a = args { $0.authMode = method; $0.clientCertFile = "~/c.pem"; $0.tokenMode = mode }
                #expect(!a.contains { $0.hasPrefix("--token-mode") }, "\(method)/\(mode)")
                #expect(!a.contains { $0.hasPrefix("--token-secret") }, "\(method)/\(mode)")
            }
        }
    }

    /// …and it is REFUSED rather than quietly signed in some other way. Same rule for
    /// a smartcard profile: `authMode == "token"` is preserved as the marker of what
    /// the profile is, and Connect says what happened.
    @Test func aStoredTokenModeOrSmartcardIsRefusedWithAnExplanation() {
        let token = SubprocessTunnelManager.sslAuthBlockReason(config {
            $0.authMode = "password"; $0.tokenMode = "totp"
        })
        #expect(token != nil)
        #expect(token?.contains("verification code") == true)
        let smartcard = SubprocessTunnelManager.sslAuthBlockReason(config { $0.authMode = "token" })
        #expect(smartcard != nil)
        #expect(smartcard?.lowercased().contains("smartcard") == true)
        // Neither sentence tells the user to switch to a password: the profile was set
        // up by somebody who knew what the gateway wanted.
        #expect(smartcard?.contains("Sign-In settings") == true)
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
        // FortiGate used to be refused here when only `openfortivpn` was installed:
        // that tool signs in with a password on stdin and carries no certificate
        // flags, so it would have authenticated one way while the picker said another.
        // The fallback is gone (it was unreachable, and needed root), so FortiGate now
        // reaches either `openconnect` or the built-in engine, and both present a
        // certificate — there is nothing left to refuse.
        #expect(SubprocessTunnelManager.sslAuthBlockReason(config {
            $0.kind = .fortinet; $0.authMode = "certificate"; $0.clientCertFile = "~/client.pem"
        }) == nil)
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

    // MARK: In-process is the default now, and the gate is what qualifies it

    /// THE DEFAULT MOVED, and this test used to assert the opposite. A profile with
    /// nothing chosen runs in-process — a full system tunnel with its own routes and
    /// DNS — because the alternative (`ocproxy -D <port>`) is a SOCKS listener with
    /// none of that, and every routing feature in the app is switched off for it.
    ///
    /// `preferInProcess` is Optional precisely so that "nobody chose" (nil, the
    /// modern default) is a different fact from "chose the tool" (stored false), which
    /// is what lets an existing profile keep working while a new one gets the good
    /// path. Both are asserted here because the pair IS the migration.
    @Test func inProcessIsTheDefaultAndAStoredChoiceIsHonoured() {
        let fresh = config { _ in }
        #expect(fresh.preferInProcess == nil, "a new profile has chosen nothing")
        #expect(fresh.runsInProcess, "and \"nothing chosen\" now means in-process")
        #expect(SubprocessTunnelManager.willRunInProcess(fresh))

        // An existing profile carries a stored `false` — written unconditionally by
        // the encoder back when the field was a plain Bool, whether or not anyone
        // ever saw the toggle. It keeps the tool, and that is deliberate: something
        // may be pointed at its SOCKS port.
        let carriedForward = config { $0.preferInProcess = false }
        #expect(!carriedForward.runsInProcess)
        #expect(!SubprocessTunnelManager.willRunInProcess(carriedForward))
        // …and it is told there is something better, naming the cost of the change.
        let offer = SubprocessTunnelManager.inProcessOfferReason(carriedForward)
        #expect(offer?.contains("\(carriedForward.socksPort)") == true,
                "the offer must name the port that would close")

        // Nothing to offer when it is already in-process.
        #expect(SubprocessTunnelManager.inProcessOfferReason(fresh) == nil)
        // SSH is a different engine entirely; the SSL toggle can't claim it.
        #expect(!SubprocessTunnelManager.willRunInProcess(config { $0.kind = .ssh }))
    }

    /// EIGHT OF THE ELEVEN GATES ARE GONE, because they were never statements about
    /// libopenconnect — they were settings nobody had plumbed through
    /// `OCClientSettings`, and each one silently cost the user the entire routing
    /// story. Every setting below is now carried (see
    /// `InProcessOpenConnectCoverageTests`, which proves it reaches the bridge) and
    /// therefore must NOT send the connection back to the tool.
    @Test func theSettingsThatUsedToForceTheToolNoLongerDo() {
        let carried: [(String, (inout SubprocessTunnelConfig) -> Void)] = [
            ("explicit port",   { $0.port = 8443 }),
            ("CA file",         { $0.caFile = "~/vpn-ca.pem" }),
            ("usergroup",       { $0.usergroup = "gateway" }),
            ("reported OS",     { $0.spoofOS = "win" }),
            ("client cert",     { $0.authMode = "certificate"; $0.clientCertFile = "~/c.pem" }),
            ("client key",      { $0.authMode = "certificate"; $0.clientCertFile = "~/c.pem"; $0.clientKeyFile = "~/c.key" }),
            ("manual proxy",    { $0.proxyMode = .manual; $0.proxyURL = "http://proxy:8080" }),
            ("compression",     { $0.ocCompression = "stateless" }),
            ("PFS",             { $0.enablePFS = true }),
            ("IPv6 off",        { $0.disableIPv6 = true }),
            ("DTLS off",        { $0.disableDTLS = true }),
            ("local hostname",  { $0.localHostname = "mac-01" }),
            ("user agent",      { $0.userAgent = "AnyConnect/4.10" }),
            ("version string",  { $0.versionString = "4.10.05085" }),
            ("MTU",             { $0.ocMTU = 1300 }),
            ("DPD",             { $0.forceDPD = 30 }),
            ("reconnect timeout", { $0.reconnectTimeout = 60 }),
        ]
        for (name, mutate) in carried {
            #expect(SubprocessTunnelManager.willRunInProcess(config(mutate)),
                    "\(name) is carried by the bridge now — it must not force the tool")
        }
    }

    /// …and the ones that still do, each for a reason that is not "unfinished".
    /// A clause may only be deleted once the setting is genuinely CARRIED, so this
    /// is the other half of the contract: these must keep refusing.
    @Test func theSettingsThatGenuinelyCannotBeCarriedStillRefuse() {
        let refused: [(String, (inout SubprocessTunnelConfig) -> Void)] = [
            // Host checker: `openconnect_setup_csd` works by forking a child, and
            // the packet-tunnel extension is app-sandboxed AND root — running a
            // user-nominated script there is a decision with an entitlement
            // attached, not a plumbing job.
            ("host-checker wrapper", { $0.csdWrapper = "/usr/local/bin/csd.sh" }),
            ("skip host checker",    { $0.disableCSD = true }),
            // No public setter exists: OpenConnect's own CLI writes
            // `vpninfo->basemtu` / `->no_http_keepalive` directly.
            ("base MTU",             { $0.baseMTU = 9000 }),
            ("HTTP keepalive off",   { $0.noHTTPKeepalive = true }),
            // Arbitrary argv has no in-process equivalent by construction.
            ("extra arguments",      { $0.extraArgs = ["--dump-http-traffic"] }),
            // A value the library hasn't got. Guessing which of the three
            // compression modes "stateful" meant is the silent substitution this
            // whole predicate exists to prevent.
            ("unknown compression",  { $0.ocCompression = "stateful" }),
            ("unknown reported OS",  { $0.spoofOS = "solaris" }),
        ]
        for (name, mutate) in refused {
            let c = config(mutate)
            #expect(!SubprocessTunnelManager.willRunInProcess(c),
                    "\(name) cannot be carried, so it must fall back rather than be dropped")
            // And the refusal must NAME it — "some setting" sends the user hunting
            // through five tabs.
            let reason = SubprocessTunnelManager.sslTransportBlockReason(
                c, ocproxyAvailable: false)
            #expect(reason != nil, "\(name): on the tool with no ocproxy, this is blocked")
            #expect(reason?.contains("Run In-Process") == false,
                    "\(name): offering a toggle that cannot help is a lie")
        }
    }

    /// …and the two of those that look like ordinary tuning say so ON THEIR OWN
    /// ROW, while they are set. Base MTU is a number and keepalive-off is a
    /// checkbox; neither looks like "give up routes, DNS and the whole-Mac tunnel",
    /// which is what it costs. The user used to find out at connect time, if at
    /// all. A caveat on an UNSET field would be noise on every profile that never
    /// touches these, so absence is asserted just as hard as presence.
    @Test func theTwoSettingsThatLookLikeTuningWarnOnTheirOwnRow() {
        for setting in SubprocessTunnelManager.ToolOnlySetting.allCases {
            // Unset: nothing to say. Both are opt-in and most profiles never
            // carry one, so the row stays quiet.
            let untouched = config { _ in }
            #expect(!setting.isSet(untouched))
            #expect(SubprocessTunnelManager.toolOnlyCaveat(setting, untouched) == nil,
                    "\(setting.rawValue): an empty field must not be caveated")

            var c = config { _ in }
            switch setting {
            case .baseMTU: c.baseMTU = 1400
            case .noHTTPKeepalive: c.noHTTPKeepalive = true
            }
            #expect(setting.isSet(c))
            let caveat = SubprocessTunnelManager.toolOnlyCaveat(setting, c)
            #expect(caveat != nil, "\(setting.rawValue): a set value must be caveated")
            // The consequence, not the mechanism: no routes and no DNS, the port
            // that replaces them, and the sidebar section the row moves to.
            #expect(caveat?.contains("no routes") == true)
            #expect(caveat?.contains("no DNS") == true)
            #expect(caveat?.contains("\(c.socksPort)") == true,
                    "\(setting.rawValue): name the port that opens instead")
            #expect(caveat?.contains("Local Ports") == true)
            #expect(caveat?.contains("Whole-Mac VPNs") == true)
            // ONE SENTENCE, TWO PLACES. The clause naming the setting is the same
            // one the connect path uses, so the editor cannot drift away from the
            // message a user sees when the connection actually falls back.
            let noun = SubprocessTunnelManager.inProcessRefusalNoun(c)
            #expect(caveat?.contains(noun) == true,
                    "\(setting.rawValue): reuse inProcessRefusalNoun, don't restate it")
            // And it is the clause for THIS row, not whichever gate happens to be
            // first when a profile trips both.
            var both = c
            both.baseMTU = 1400
            both.noHTTPKeepalive = true
            #expect(SubprocessTunnelManager.toolOnlyCaveat(setting, both)?.contains(noun) == true,
                    "\(setting.rawValue): each row must name its own setting")
        }
        // The caveat is an SSL-VPN statement; SSH is a different engine and this
        // editor's Advanced group is never drawn for it.
        var ssh = config { $0.kind = .ssh }
        ssh.baseMTU = 1400
        #expect(SubprocessTunnelManager.toolOnlyCaveat(.baseMTU, ssh) == nil)
    }

    /// Every SSL-VPN kind can go in-process, because the extension dispatches on
    /// `VPNKind.openconnectProtocol` and that covers all seven. The connect path
    /// used to name only fortinet / f5apm / anyconnect while `willRunInProcess`
    /// promised all of them — the editor said "in-process", the connect quietly
    /// spawned `openconnect` and demanded ocproxy. One rule now, asserted per kind.
    /// SETTINGS-ONLY, NO PER-KIND ALLOW-LIST: a three-kind list here is the exact
    /// regression this asserts against.
    @Test func everySSLVPNKindCanRunInProcess() {
        let sslKinds = VPNKind.allCases.filter(\.isSSLVPN)
        #expect(sslKinds.count == 7, "the seven SSL-VPN kinds")
        for kind in sslKinds {
            #expect(SubprocessTunnelManager.willRunInProcess(config { $0.kind = kind }),
                    "\(kind.rawValue) should be able to run in-process")
        }
    }

    // MARK: The transport must be able to carry traffic without root

    /// `openconnect` configures a real tun, which needs root this app never takes.
    /// `--script-tun --script "ocproxy -D <port>"` is the no-root path, and it is
    /// appended only when ocproxy resolves — so ocproxy is REQUIRED on the
    /// subprocess path, and its absence used to be a silent failure.
    @Test func aSubprocessSSLVPNWithoutOcproxyIsRefusedNotLeftToFail() {
        // Explicitly on the tool: the default is in-process now, so a test that
        // relied on the default to mean "subprocess" would silently stop testing it.
        let c = config { $0.preferInProcess = false }
        #expect(SubprocessTunnelManager.sslTransportBlockReason(
            c, ocproxyAvailable: true) == nil)
        let reason = SubprocessTunnelManager.sslTransportBlockReason(
            c, ocproxyAvailable: false)
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
            let c = config { $0.kind = kind }
            #expect(SubprocessTunnelManager.sslTransportBlockReason(
                c, ocproxyAvailable: false) == nil,
                    "\(kind.rawValue) in-process must not require any tool")
        }
    }

    /// The in-process→subprocess fallback is only a fallback if the subprocess can
    /// carry traffic. Asked with `inProcess: false` (the engine was chosen and
    /// failed to start) the answer must not say "turn on Run In-Process" — it is
    /// already on, and advice that names a box the user already ticked is how
    /// people learn to stop reading error messages.
    @Test func theFallbackIsRefusedAndNeverToldToTickABoxAlreadyTicked() {
        let c = config { _ in }
        // As the connect path sees it: in-process, so nothing to block.
        #expect(SubprocessTunnelManager.sslTransportBlockReason(
            c, ocproxyAvailable: false) == nil)
        // As the fallback faces it: the subprocess needs ocproxy and hasn't got it.
        let reason = SubprocessTunnelManager.sslTransportBlockReason(
            c, inProcess: false, ocproxyAvailable: false)
        #expect(reason != nil)
        #expect(reason?.contains("brew install ocproxy") == true)
        #expect(reason?.contains("Turn on Run In-Process") == false)
        // With ocproxy present the fallback is legitimate again.
        #expect(SubprocessTunnelManager.sslTransportBlockReason(
            c, inProcess: false, ocproxyAvailable: true) == nil)
    }

    /// A missing tool must name the tool and the fix. "The required command-line
    /// tool isn't installed" sent nobody anywhere.
    @Test func aMissingToolNamesTheToolAndTheFix() {
        // Explicitly on the tool: the toggle is only offered when turning it ON would
        // change the answer, and for a config that is already in-process it would not.
        let reason = SubprocessTunnelManager.missingToolReason(config { $0.preferInProcess = false })
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
