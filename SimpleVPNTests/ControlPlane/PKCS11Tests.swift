// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
//  PKCS11Tests.swift
//  Smartcard / security-key sign-in (PKCS#11), all four halves:
//
//   1. the RFC 7512 URI validator, INCLUDING its refusal of `pin-value`/`pin-source`
//      (the rule that keeps the PIN off any command line);
//   2. provider-module discovery against a fake filesystem, including the
//      installed-but-not-registered-with-p11-kit state that decides whether
//      openconnect can use a module at all;
//   3. the enumeration parsers, driven by output CAPTURED FROM THE REAL TOOLS —
//      GnuTLS 3.8.13 `p11tool` and OpenSC 0.27.1 `pkcs11-tool` reading a SoftHSM
//      token holding a real certificate. Those transcripts are in `Fixtures` below,
//      verbatim, and they are what makes these parsers tested rather than asserted;
//   4. the argv/stdin contract and the connect-time failure classifier, which must
//      produce a distinct, actionable message for every failure mode.
//
//  There is no hardware token on a build machine, so nothing here touches one. What
//  is REALLY exercised (against SoftHSM, out of band) versus fixture-driven is
//  recorded in Docs/AuthSecPKCS11.md — read that before trusting either claim.
//

import Foundation
import Testing
@testable import SimpleVPN

// MARK: - Captured tool output

/// Verbatim transcripts. Whitespace is load-bearing: GnuTLS indents with tabs and
/// pads the day-of-month with a space, which is exactly what the parsers must cope
/// with, so these strings are not tidied.
private enum Fixtures {

    /// `p11tool --provider …/libsofthsm2.so --list-tokens`
    static let p11toolTokens = """
    Token 0:
    \tURL: pkcs11:model=SoftHSM%20v2;manufacturer=SoftHSM%20project;serial=e2d352046a922e7e;token=SimpleVPN%20PIV%20Test
    \tLabel: SimpleVPN PIV Test
    \tType: Generic token
    \tFlags: RNG, Requires login
    \tManufacturer: SoftHSM project
    \tModel: SoftHSM v2
    \tSerial: e2d352046a922e7e
    \tModule:\u{20}

    """

    /// The same command after two wrong PINs — the token's own retry counter showing.
    static let p11toolTokensPINLow = """
    Token 0:
    \tURL: pkcs11:model=SoftHSM%20v2;manufacturer=SoftHSM%20project;serial=e2d352046a922e7e;token=SimpleVPN%20PIV%20Test
    \tLabel: SimpleVPN PIV Test
    \tType: Generic token
    \tFlags: RNG, Requires login, uPIN low count
    \tManufacturer: SoftHSM project
    \tModel: SoftHSM v2
    \tSerial: e2d352046a922e7e
    \tModule: /opt/homebrew/lib/softhsm/libsofthsm2.so

    """

    /// A hardware PIV token on its FINAL attempt. GnuTLS's printer emits BOTH
    /// "Final uPIN attempt" and "uPIN locked" here — it tests the final-try bit
    /// twice and never prints the locked bit (checked in gnutls/src/pkcs11.c) —
    /// which is why the parser must not read this as locked.
    static let p11toolTokensFinalTry = """
    Token 7:
    \tURL: pkcs11:model=PKCS%2315%20emulated;manufacturer=piv_II;serial=108421384210c3f5;token=PIV_II%20%28PIV%20Card%20Holder%20pin%29
    \tLabel: PIV_II (PIV Card Holder pin)
    \tType: Hardware token
    \tFlags: RNG, Requires login, uPIN low count, Final uPIN attempt, uPIN locked
    \tManufacturer: piv_II
    \tModel: PKCS#15 emulated
    \tSerial: 108421384210c3f5
    """

    /// `p11tool --provider … --list-all-certs 'pkcs11:token=SimpleVPN%20PIV%20Test'`
    static let p11toolCerts = """
    Object 0:
    \tURL: pkcs11:model=SoftHSM%20v2;manufacturer=SoftHSM%20project;serial=e2d352046a922e7e;token=SimpleVPN%20PIV%20Test;id=%01;object=Certificate%20for%20PIV%20Authentication;type=cert
    \tType: X.509 Certificate (RSA-2048)
    \tExpires: Thu Aug  5 10:54:16 2027
    \tLabel: Certificate for PIV Authentication
    \tID: 01

    """

    /// `pkcs11-tool --module … --list-token-slots`. Slot 1 has no token in it.
    static let pkcs11ToolSlots = """
    Available slots:
    Slot 0 (0x6a922e7e): SoftHSM slot ID 0x6a922e7e
      token label        : SimpleVPN PIV Test
      token manufacturer : SoftHSM project
      token model        : SoftHSM v2
      token flags        : login required, rng, token initialized, user PIN count low, PIN initialized, other flags=0x20
      hardware version   : 2.7
      firmware version   : 2.7
      serial num         : e2d352046a922e7e
      pin min/max        : 4/255
      uri                : pkcs11:model=SoftHSM%20v2;manufacturer=SoftHSM%20project;serial=e2d352046a922e7e;token=SimpleVPN%20PIV%20Test
    Slot 1 (0x1): SoftHSM slot ID 0x1
      token state:   uninitialized
    """

    /// A locked token. OpenSC names the flag (its exact strings were read out of the
    /// shipped `pkcs11-tool` binary), which is why a definite "locked" reading comes
    /// from OpenSC rather than GnuTLS.
    static let pkcs11ToolSlotsLocked = """
    Available slots:
    Slot 0 (0x0): Yubico YubiKey OTP+FIDO+CCID
      token label        : YubiKey PIV #12345678
      token manufacturer : Yubico
      token model        : YubiKey YK5
      token flags        : login required, rng, token initialized, user PIN locked, PIN initialized
      serial num         : 12345678
      uri                : pkcs11:model=YubiKey%20YK5;manufacturer=Yubico;serial=12345678;token=YubiKey%20PIV
    """

    /// `pkcs11-tool --module … --list-objects --type cert` — the subject DN source.
    static let pkcs11ToolCerts = """
    Using slot 0 with a present token (0x6a922e7e)
    Certificate Object; type = X.509 cert
      label:      Certificate for PIV Authentication
      subject:    DN: OU=Engineering,O=Example Corp,CN=alex.hunt
      serial:     8CDAEF81957750B9
      ID:         1 (0x01)
      uri:        pkcs11:model=SoftHSM%20v2;manufacturer=SoftHSM%20project;serial=e2d352046a922e7e;token=SimpleVPN%20PIV%20Test;id=%01;object=Certificate%20for%20PIV%20Authentication;type=cert
    """

    static let p11toolBadModule = "pkcs11_add_provider: PKCS #11 initialization error.\n"
    static let pkcs11ToolBadModule = """
    sc_dlopen_deep failed: dlopen(/opt/homebrew/lib/nope.dylib, 0x0005): tried: '/opt/homebrew/lib/nope.dylib' (no such file)
    error: Failed to load pkcs11 module
    Aborting.
    """
    static let p11toolNoObjects = "No matching objects found\n"
}

// MARK: - Fakes

private struct FakeFiles: PKCS11FileProbing {
    var files: Set<String> = []
    var directories: [String: [String]] = [:]
    var contents: [String: String] = [:]
    func isReadableFile(_ path: String) -> Bool { files.contains(path) }
    func directoryEntries(_ path: String) -> [String] { directories[path] ?? [] }
    func text(ofFile path: String) -> String? { contents[path] }
}

/// A runner that answers by matching the argv, so a test can compose "this module
/// loads but has no token" without a module or a token existing.
private struct FakeRunner: PKCS11ToolRunning {
    /// (predicate on arguments) → (status, output). First match wins.
    var answers: [(match: @Sendable ([String]) -> Bool, reply: (Int32, String))] = []
    func run(executable: String, arguments: [String]) async -> (status: Int32, output: String) {
        for answer in answers where answer.match(arguments) {
            return (answer.reply.0, answer.reply.1)
        }
        return (0, "")
    }
}

// MARK: - 1. The URI

struct PKCS11URITests {

    @Test func acceptsTheMinimalFormOpenConnectDocuments() throws {
        let uri = try #require(PKCS11URI.parse("pkcs11:id=%01"))
        #expect(uri.value("id") == "%01")
        #expect(PKCS11URI.problem("pkcs11:id=%01") == nil)
    }

    @Test func acceptsAFullTokenScopedURI() throws {
        let raw = "pkcs11:model=PKCS%2315%20emulated;manufacturer=piv_II;serial=108421384210c3f5;token=PIV_II%20%28PIV%20Card%20Holder%20pin%29;id=%01;object=Certificate%20for%20PIV%20Authentication;type=cert"
        let uri = try #require(PKCS11URI.parse(raw))
        #expect(uri.objectType == "cert")
        #expect(uri.tokenLabel == "PIV_II (PIV Card Holder pin)")
        #expect(uri.objectLabel == "Certificate for PIV Authentication")
        // The token scope drops everything that names an OBJECT — it is what a
        // "which token is this?" query addresses.
        let scope = uri.tokenScope
        #expect(!scope.contains("id="))
        #expect(!scope.contains("object="))
        #expect(scope.contains("serial=108421384210c3f5"))
    }

    /// OpenConnect's own docs print `object-type=cert`; GnuTLS 3.8's p11tool prints
    /// `type=cert`. Both are the same attribute and both must be understood, because
    /// a user pastes whichever their tool gave them.
    @Test func understandsBothSpellingsOfTheObjectTypeAttribute() {
        #expect(PKCS11URI.parse("pkcs11:id=%01;type=cert")?.objectType == "cert")
        #expect(PKCS11URI.parse("pkcs11:id=%01;object-type=cert")?.objectType == "cert")
        #expect(PKCS11URI.problem("pkcs11:id=%01;object-type=cert") == nil)
    }

    /// THE PIN RULE. Both attributes are legal RFC 7512 and both appear in guides,
    /// and both would put the PIN (or a path to it) on a command line every local
    /// process can read.
    @Test func refusesAPINInTheURI() throws {
        let value = try #require(PKCS11URI.problem("pkcs11:id=%01?pin-value=123456"))
        #expect(value.contains("pin-value"))
        #expect(value.contains("visible"))
        let source = try #require(PKCS11URI.problem("pkcs11:id=%01?pin-source=file:///tmp/pin"))
        #expect(source.contains("pin-source"))
    }

    @Test func rejectsTheThingsAPasteGetsWrong() {
        #expect(PKCS11URI.problem("") != nil)                         // empty
        #expect(PKCS11URI.problem("id=%01") != nil)                   // no scheme
        #expect(PKCS11URI.problem("pkcs11:") != nil)                  // names nothing
        #expect(PKCS11URI.problem("pkcs11:id") != nil)                // no "="
        #expect(PKCS11URI.problem("pkcs11:nonsense=1") != nil)        // unknown attribute
        #expect(PKCS11URI.problem("pkcs11:object=My Cert") != nil)    // literal space
        #expect(PKCS11URI.problem("pkcs11:id=%0") != nil)             // truncated escape
        #expect(PKCS11URI.problem("pkcs11:id=%01;type=banana") != nil) // not an object type
    }

    /// A vendor extension is legal and must not be refused — refusing one would
    /// block a working configuration for the sake of a tidy allow-list.
    @Test func allowsVendorExtensions() {
        #expect(PKCS11URI.problem("pkcs11:id=%01;x-vendor-thing=1") == nil)
    }

    /// What goes on the command line: the query is dropped, the path is untouched.
    /// Rewriting a user's path attributes to "help" is how a working URI stops
    /// working — OpenConnect 7.01+ adds `type=` and hunts for the key itself.
    @Test func theArgumentDropsTheQueryAndKeepsEverythingElse() {
        let raw = "pkcs11:manufacturer=piv_II;id=%01;object=Certificate%20for%20PIV%20Authentication;type=cert"
        #expect(SubprocessTunnelConfig.pkcs11Argument(raw) == raw)
        #expect(SubprocessTunnelConfig.pkcs11Argument("pkcs11:id=%01?module-name=opensc")
                == "pkcs11:id=%01")
    }

    /// An unparseable string passes through rather than becoming "pkcs11:" — the
    /// argv builder is not the place a validation failure is discovered, and
    /// silently sending a DIFFERENT URI would be worse than sending the bad one.
    @Test func theArgumentDoesNotInventAURI() {
        #expect(SubprocessTunnelConfig.pkcs11Argument("  garbage  ") == "garbage")
    }
}

// MARK: - 2. Module discovery

struct PKCS11ModuleDiscoveryTests {

    @Test func findsNothingOnAMachineWithNoProvider() {
        let discovery = PKCS11ModuleDiscovery(files: FakeFiles())
        #expect(discovery.modules().isEmpty)
    }

    @Test func namesWellKnownModulesByTheirProduct() throws {
        var files = FakeFiles()
        files.files = ["/opt/homebrew/lib/opensc-pkcs11.so", "/opt/homebrew/lib/libykcs11.dylib"]
        let modules = PKCS11ModuleDiscovery(files: files).modules()
        #expect(modules.count == 2)
        let openSC = try #require(modules.first { $0.origin == .openSC })
        #expect(openSC.displayName.contains("OpenSC"))
        let yubi = try #require(modules.first { $0.origin == .yubiKey })
        #expect(yubi.displayName.contains("YubiKey"))
        // Neither is registered with p11-kit, which is the state that stops
        // openconnect using them.
        #expect(modules.allSatisfy { !$0.registeredWithP11Kit })
    }

    /// The load-bearing distinction: a module can be installed and invisible to the
    /// sign-in tool. Discovery has to tell the two apart.
    @Test func marksAModuleRegisteredWhenAP11KitFileDeclaresIt() throws {
        var files = FakeFiles()
        files.files = ["/opt/homebrew/lib/opensc-pkcs11.so"]
        files.directories = ["/opt/homebrew/etc/pkcs11/modules": ["opensc.module", "notes.txt"]]
        files.contents = [
            "/opt/homebrew/etc/pkcs11/modules/opensc.module":
                "# installed by opensc\nmodule: /opt/homebrew/lib/opensc-pkcs11.so\nx-name: OpenSC smartcards\n",
        ]
        let modules = PKCS11ModuleDiscovery(files: files).modules()
        let openSC = try #require(modules.first)
        #expect(modules.count == 1, "the same library found twice must be one entry")
        #expect(openSC.registeredWithP11Kit)
    }

    /// A bare `module:` name is resolved against p11-kit's own module directories and
    /// nowhere else. Accepting it as-is would let the dynamic loader's search order
    /// decide which code reads a private key.
    @Test func resolvesABareModuleNameOnlyInsideKnownDirectories() {
        var files = FakeFiles()
        files.files = ["/opt/homebrew/lib/pkcs11/opensc-pkcs11.so"]
        files.directories = ["/etc/pkcs11/modules": ["opensc.module"]]
        files.contents = ["/etc/pkcs11/modules/opensc.module": "module: opensc-pkcs11.so\n"]
        let resolved = PKCS11ModuleDiscovery(files: files).registeredModules()
        #expect(resolved.map(\.path) == ["/opt/homebrew/lib/pkcs11/opensc-pkcs11.so"])

        var missing = files
        missing.files = []
        #expect(PKCS11ModuleDiscovery(files: missing).registeredModules().isEmpty)
    }

    /// p11-kit's own trust module holds CA certificates, never a client certificate.
    /// Offering it as a sign-in provider could only ever waste a user's time.
    @Test func skipsTheP11KitTrustModule() {
        var files = FakeFiles()
        files.files = ["/opt/homebrew/lib/pkcs11/p11-kit-trust.dylib"]
        files.directories = ["/opt/homebrew/etc/pkcs11/modules": ["p11-kit-trust.module"]]
        files.contents = ["/opt/homebrew/etc/pkcs11/modules/p11-kit-trust.module":
                            "module: /opt/homebrew/lib/pkcs11/p11-kit-trust.dylib\n"]
        #expect(PKCS11ModuleDiscovery(files: files).modules().isEmpty)
    }

    @Test func aUserSuppliedPathIsDescribedLikeAnyOther() throws {
        var files = FakeFiles()
        files.files = ["/Users/alex/lib/vendor-pkcs11.dylib"]
        let module = try #require(PKCS11ModuleDiscovery(files: files)
            .module(atUserPath: "/Users/alex/lib/vendor-pkcs11.dylib"))
        #expect(module.origin == .userSupplied)
        #expect(!module.registeredWithP11Kit)
        // …and it carries the command that would make it usable.
        #expect(module.registrationCommand.contains("~/.config/pkcs11/modules/"))
        #expect(module.registrationCommand.contains("/Users/alex/lib/vendor-pkcs11.dylib"))
    }

    @Test func theModulePathWarningCatchesTheRealMistakes() {
        #expect(PKCS11Module.pathWarning("") == nil, "an empty field is not a mistake yet")
        // A bare name is refused BY NAME — this is the "don't trust the search order"
        // rule showing up in the UI.
        let bare = PKCS11Module.pathWarning("opensc-pkcs11.so")
        #expect(bare?.contains("full path") == true)
        #expect(PKCS11Module.pathWarning("/nonexistent/opensc-pkcs11.so") == "No file at that path.")
        #expect(PKCS11Module.pathWarning("/usr/lib")?.contains("folder") == true)
    }

    /// The registration filename is stable across runs — a fresh one each time would
    /// leave a pile of duplicate `.module` files in the user's config.
    @Test func theRegistrationFileNameIsStableAndReadable() {
        let module = PKCS11Module(path: "/opt/homebrew/lib/libykcs11.dylib", origin: .yubiKey)
        #expect(module.registrationFileName == "ykcs11.module")
        #expect(module.registrationFileName == module.registrationFileName)
    }
}

// MARK: - 3. The parsers, against captured real output

struct PKCS11ParserTests {

    @Test func readsARealTokenListing() throws {
        let tokens = PKCS11Enumerator.parseTokens(p11toolOutput: Fixtures.p11toolTokens)
        let token = try #require(tokens.first)
        #expect(tokens.count == 1)
        #expect(token.label == "SimpleVPN PIV Test")
        #expect(token.requiresLogin)
        #expect(!token.isHardware, "SoftHSM is a software token and says so")
        #expect(!token.pinCountLow && !token.pinFinalTry && !token.pinLocked)
        #expect(token.pinWarning == nil)
        // An empty `Module:` line must not become an empty string masquerading as a path.
        #expect(token.modulePath == nil)
    }

    /// The anti-bricking signal, from the real tool: two wrong PINs and the token
    /// itself reports the counter is down.
    @Test func readsThePINCountLowFlagGnuTLSPrints() throws {
        let token = try #require(PKCS11Enumerator
            .parseTokens(p11toolOutput: Fixtures.p11toolTokensPINLow).first)
        #expect(token.pinCountLow)
        #expect(!token.isBlocked, "a low count is a warning, not a refusal")
        let warning = try #require(token.pinWarning)
        #expect(warning.contains("locks"))
        #expect(token.modulePath == "/opt/homebrew/lib/softhsm/libsofthsm2.so")
    }

    /// GnuTLS prints "uPIN locked" for a FINAL TRY (it tests the final-try bit twice
    /// and never prints the locked bit). Reading that as locked would refuse a token
    /// that still works — so the parser requires "uPIN locked" WITHOUT
    /// "Final uPIN attempt".
    @Test func doesNotMistakeGnuTLSsFinalTryForALockedToken() throws {
        let token = try #require(PKCS11Enumerator
            .parseTokens(p11toolOutput: Fixtures.p11toolTokensFinalTry).first)
        #expect(token.isHardware)
        #expect(token.pinFinalTry)
        #expect(!token.pinLocked)
        #expect(!token.isBlocked)
        let warning = try #require(token.pinWarning)
        #expect(warning.contains("One PIN attempt left"))
        #expect(warning.contains("destroys"), "the consequence has to be in the words")
    }

    @Test func readsARealCertificateListing() throws {
        let certs = PKCS11Enumerator.parseCertificates(p11toolOutput: Fixtures.p11toolCerts)
        let cert = try #require(certs.first)
        #expect(certs.count == 1)
        #expect(cert.label == "Certificate for PIV Authentication")
        #expect(cert.keySummary == "RSA-2048")
        #expect(cert.objectID == "01")
        #expect(cert.uri.hasPrefix("pkcs11:"))
        // The date GnuTLS printed with strftime %c, space-padded day and all.
        let expires = try #require(cert.expires)
        let parts = Calendar.current.dateComponents([.year, .month, .day], from: expires)
        #expect(parts.year == 2027)
        #expect(parts.month == 8)
        #expect(parts.day == 5)
        #expect(!cert.isExpired)
    }

    @Test func readsOpenSCsSlotListingAndSkipsEmptyReaders() throws {
        let tokens = PKCS11Enumerator.parseTokens(pkcs11ToolOutput: Fixtures.pkcs11ToolSlots)
        #expect(tokens.count == 1, "a slot reporting \"uninitialized\" holds no token")
        let token = try #require(tokens.first)
        #expect(token.label == "SimpleVPN PIV Test")
        #expect(token.requiresLogin)
        #expect(token.pinCountLow, "OpenSC names the flag GnuTLS conflates")
        #expect(!token.pinUninitialized)
    }

    /// The one state GnuTLS cannot report. It is also the one where connecting must
    /// be refused rather than warned about.
    @Test func readsADefiniteLockFromOpenSC() throws {
        let token = try #require(PKCS11Enumerator
            .parseTokens(pkcs11ToolOutput: Fixtures.pkcs11ToolSlotsLocked).first)
        #expect(token.pinLocked)
        #expect(token.isBlocked)
        #expect(token.pinWarning?.contains("PUK") == true)
    }

    /// Flags a future OpenSC stops naming still have to warn — so the numeric
    /// "other flags=0x…" bucket is checked for the three PIN bits too.
    @Test func readsThePINBitsOutOfTheNumericFallback() throws {
        let output = """
        Available slots:
        Slot 0 (0x0): reader
          token label        : Numeric
          token flags        : login required, PIN initialized, other flags=0x30020
          uri                : pkcs11:serial=1;token=Numeric
        """
        let token = try #require(PKCS11Enumerator.parseTokens(pkcs11ToolOutput: output).first)
        #expect(token.pinCountLow, "0x10000 is CKF_USER_PIN_COUNT_LOW")
        #expect(token.pinFinalTry, "0x20000 is CKF_USER_PIN_FINAL_TRY")
        #expect(!token.pinLocked)
    }

    @Test func readsTheSubjectOpenSCPrints() throws {
        let certs = PKCS11Enumerator.parseCertificates(pkcs11ToolOutput: Fixtures.pkcs11ToolCerts)
        let cert = try #require(certs.first)
        // "DN:" is dropped and the common name leads — the part a human reads.
        #expect(cert.subject == "CN=alex.hunt, OU=Engineering, O=Example Corp")
        let subjects = PKCS11Enumerator.parseSubjects(pkcs11ToolOutput: Fixtures.pkcs11ToolCerts)
        #expect(subjects["Certificate for PIV Authentication"] == cert.subject)
    }

    /// OpenSC's reading of the PIN state wins on merge, because GnuTLS cannot tell
    /// a final try from a lock — and everything else keeps the GnuTLS values, whose
    /// URI is the one openconnect will match against.
    @Test func mergingPrefersOpenSCsPINStateAndGnuTLSsURI() throws {
        let gnutls = PKCS11Enumerator.parseTokens(p11toolOutput: Fixtures.p11toolTokens)
        var openSC = PKCS11Enumerator.parseTokens(pkcs11ToolOutput: Fixtures.pkcs11ToolSlots)
        openSC[0].pinLocked = true
        let merged = PKCS11Enumerator.merge(gnutls: gnutls, openSC: openSC)
        let token = try #require(merged.first)
        #expect(token.pinLocked)
        #expect(token.pinCountLow)
        #expect(token.uri == gnutls[0].uri)
    }

    @Test func mergingFallsBackToWhicheverToolAnswered() {
        let openSC = PKCS11Enumerator.parseTokens(pkcs11ToolOutput: Fixtures.pkcs11ToolSlots)
        #expect(PKCS11Enumerator.merge(gnutls: [], openSC: openSC).count == 1)
        #expect(PKCS11Enumerator.merge(gnutls: openSC, openSC: []).count == 1)
    }

    @Test func classifiesAModuleThatCannotBeLoaded() {
        #expect(PKCS11Enumerator.moduleFailure(in: Fixtures.p11toolBadModule, module: "/x.so")
                == .moduleUnusable(path: "/x.so"))
        #expect(PKCS11Enumerator.moduleFailure(in: Fixtures.pkcs11ToolBadModule, module: "/x.so")
                == .moduleUnusable(path: "/x.so"))
        #expect(PKCS11Enumerator.moduleFailure(in: Fixtures.p11toolTokens, module: "/x.so") == nil)
    }

    /// Security.framework reads the certificate itself, so the friendly name and the
    /// expiry don't depend on a tool's locale-dependent rendering.
    @Test func readsSubjectAndExpiryOutOfAnExportedCertificate() throws {
        let facts = try #require(PKCS11Enumerator.certificateFacts(pem: Self.samplePEM))
        #expect(facts.subject?.contains("alex.hunt") == true)
        let expires = try #require(facts.expires)
        #expect(expires > Date(timeIntervalSince1970: 1_700_000_000))
    }

    @Test func ignoresSomethingThatIsNotACertificate() {
        #expect(PKCS11Enumerator.certificateFacts(pem: "not a pem at all") == nil)
        #expect(PKCS11Enumerator.derBody(inPEM: "-----BEGIN CERTIFICATE-----\n!!\n") == nil)
    }

    /// The self-signed certificate (CN=alex.hunt, expiring 2027-08-05) that was
    /// actually loaded onto the SoftHSM token these fixtures were captured from —
    /// so the Security.framework path is parsing the same bytes `p11tool --export`
    /// produced, not a hand-made stand-in.
    static let samplePEM = """
    -----BEGIN CERTIFICATE-----
    MIIC/jCCAeYCCQCM2u+BlXdQuTANBgkqhkiG9w0BAQsFADBBMRIwEAYDVQQDDAlh
    bGV4Lmh1bnQxFTATBgNVBAoMDEV4YW1wbGUgQ29ycDEUMBIGA1UECwwLRW5naW5l
    ZXJpbmcwHhcNMjYwODA1MDk1NDE2WhcNMjcwODA1MDk1NDE2WjBBMRIwEAYDVQQD
    DAlhbGV4Lmh1bnQxFTATBgNVBAoMDEV4YW1wbGUgQ29ycDEUMBIGA1UECwwLRW5n
    aW5lZXJpbmcwggEiMA0GCSqGSIb3DQEBAQUAA4IBDwAwggEKAoIBAQDs2ax9dgor
    rkDhdIjM5l962hR9+yFptTGpfh8EBwXSpiSDCR6WMl04+kqTq/REWT5dNj0GNXNG
    MWdFvvPeLzAa5wc1AVcEu9Guk2XasR5WzK4AEAyfoAPQ3YFNEnDsr1IdBN+DsqyE
    iXoDhFDY6mwaZkBd6jDadIcLx6Hso3T4acazC126i3NWrnYXINTM3uNRA8aEAFIJ
    w1rojJqRgdaZmUNeAlYSgkCObk6O+ccjCmrCtCm4ATlgX94ouW5XcHYfAGrxlXlg
    wRVKfpZxPQJLJR0ANb8uNYctZiK+fAU2/doO6WPhjTmf3XEs4a4u5Voyhz37/r7X
    ebeUHJxj+OppAgMBAAEwDQYJKoZIhvcNAQELBQADggEBAFivooXwmJv57xU/NRlI
    c1J28oD3H9huq79ny1uZr3ZNLeCdovB19X6KKVkFEJovt38n+gnWnxsRr522dwD+
    B8oN/MUsHKK2Y48LDrlRaQtuu3ut+bqRXUcmiPxOnmcyOfL0NYoYeko+O+2kW9ww
    ctWTn1ULLOgG03zWJwRW2V51Ug7LGOMPR9WRL+VY1hyErhQ+PSDhyU21M8A23F66
    NB279YG7qxh2FAizexHlxFsxrHVSHZo+C0drOKKDmTK5Zv4yvhoWfBvnaR36/eqE
    SpT9lewSyW52Gs9y7BFjbnFmJNR8apBRgzQfZJBjYPghju2Bz8YP/yIKCbPT1P5G
    vSI=
    -----END CERTIFICATE-----
    """
}

// MARK: - 3b. The enumerator's own state machine, over the fakes

struct PKCS11EnumeratorTests {

    private func enumerator(_ answers: [(match: @Sendable ([String]) -> Bool, reply: (Int32, String))])
        -> PKCS11Enumerator {
        PKCS11Enumerator(runner: FakeRunner(answers: answers),
                         p11toolPath: "/opt/homebrew/bin/p11tool",
                         pkcs11ToolPath: nil)
    }

    @Test func noToolInstalledIsItsOwnAnswer() async {
        let bare = PKCS11Enumerator(runner: FakeRunner(), p11toolPath: nil, pkcs11ToolPath: nil)
        #expect(!bare.hasAnyTool)
        let result = await bare.tokens(module: "/opt/homebrew/lib/opensc-pkcs11.so")
        #expect(result == .failure(.noModuleInstalled))
    }

    @Test func aModuleThatWontLoadIsDistinctFromOneWithNoToken() async {
        let broken = enumerator([( { _ in true }, (1, Fixtures.p11toolBadModule) )])
        #expect(await broken.tokens(module: "/x.so") == .failure(.moduleUnusable(path: "/x.so")))

        let empty = enumerator([( { _ in true }, (0, "") )])
        #expect(await empty.tokens(module: "/opt/homebrew/lib/libykcs11.dylib")
                == .failure(.noTokenPresent(module: "libykcs11.dylib")))
    }

    @Test func listsTheTokenAndItsCertificates() async throws {
        let tool = enumerator([
            ({ $0.contains("--list-tokens") }, (0, Fixtures.p11toolTokens)),
            ({ $0.contains("--list-all-certs") }, (0, Fixtures.p11toolCerts)),
            ({ $0.contains("--export") }, (0, PKCS11ParserTests.samplePEM)),
        ])
        let tokens = try await tool.tokens(module: "/m.so").get()
        #expect(tokens.count == 1)
        let certs = try await tool.certificates(module: "/m.so", tokenScope: nil).get()
        #expect(certs.count == 1)
        // The export path filled in the subject the GnuTLS listing has no field for.
        #expect(certs[0].subject?.contains("alex.hunt") == true)
    }

    @Test func aTokenWithNoCertificateSaysSo() async {
        let tool = enumerator([
            ({ $0.contains("--list-tokens") }, (0, Fixtures.p11toolTokens)),
            ({ $0.contains("--list-all-certs") }, (0, Fixtures.p11toolNoObjects)),
        ])
        #expect(await tool.certificates(module: "/m.so", tokenScope: nil)
                == .failure(.certificateNotFound))
    }

    /// The token scope is passed to the tool, so a Mac with two readers lists the
    /// certificates on the RIGHT one.
    @Test func scopesTheListingToTheChosenToken() async {
        let scope = "pkcs11:serial=e2d352046a922e7e"
        let tool = PKCS11Enumerator(
            runner: FakeRunner(answers: [
                ({ $0.contains(scope) }, (0, Fixtures.p11toolCerts)),
                ({ _ in true }, (0, Fixtures.p11toolNoObjects)),
            ]),
            p11toolPath: "/opt/homebrew/bin/p11tool", pkcs11ToolPath: nil)
        let scoped = await tool.certificates(module: "/m.so", tokenScope: scope)
        #expect((try? scoped.get())?.count == 1)
        let unscoped = await tool.certificates(module: "/m.so", tokenScope: "pkcs11:serial=other")
        #expect(unscoped == .failure(.certificateNotFound))
    }

    /// OpenSC alone still lists certificates (with subjects, without expiry) — a
    /// machine with `opensc` and no `gnutls` must not lose the picker.
    @Test func opensCAloneStillListsCertificates() async throws {
        let tool = PKCS11Enumerator(
            runner: FakeRunner(answers: [({ _ in true }, (0, Fixtures.pkcs11ToolCerts))]),
            p11toolPath: nil, pkcs11ToolPath: "/opt/homebrew/bin/pkcs11-tool")
        let certs = try await tool.certificates(module: "/m.so", tokenScope: nil).get()
        #expect(certs.count == 1)
        #expect(certs[0].subject?.contains("alex.hunt") == true)
        #expect(certs[0].expires == nil, "pkcs11-tool doesn't print an expiry, and we don't invent one")
    }

    /// The row summary always says SOMETHING. A picker entry with a blank line under
    /// it is worse than one admitting the token reported nothing.
    @Test func everyCertificateRowSaysSomething() {
        #expect(!PKCS11Certificate().rowSummary().isEmpty)
        let now = Date(timeIntervalSince1970: 1_800_000_000)
        var expired = PKCS11Certificate(label: "Old", uri: "pkcs11:id=%01")
        expired.expires = now.addingTimeInterval(-86_400)
        #expect(expired.rowSummary(now: now).contains("expired"))
        var soon = PKCS11Certificate(label: "Soon", uri: "pkcs11:id=%02")
        soon.expires = now.addingTimeInterval(5 * 86_400)
        #expect(soon.rowSummary(now: now).contains("expires"))
        var fine = PKCS11Certificate(label: "Fine", uri: "pkcs11:id=%03")
        fine.expires = now.addingTimeInterval(400 * 86_400)
        #expect(fine.rowSummary(now: now).contains("valid until"))
    }
}

// MARK: - 4. argv, stdin, and the connect-time classifier

@MainActor
struct PKCS11ConnectTests {

    private func config(_ mutate: (inout SubprocessTunnelConfig) -> Void = { _ in })
        -> SubprocessTunnelConfig {
        var c = SubprocessTunnelConfig()
        c.kind = .ciscoAnyConnect
        c.server = "vpn.example.com"
        c.username = "alex"
        c.authMode = "token"
        c.pkcs11ModulePath = "/opt/homebrew/lib/opensc-pkcs11.so"
        c.pkcs11CertificateURI = "pkcs11:manufacturer=piv_II;id=%01"
        mutate(&c)
        return c
    }

    @Test func tokenModePassesTheURIAndNoFilePaths() {
        let a = SubprocessTunnelManager.openconnectArgs(for: config {
            $0.clientCertFile = "~/stale.pem"   // set, and must NOT be used
            $0.clientKeyFile = "~/stale.key"
        })
        #expect(a.contains("--certificate=pkcs11:manufacturer=piv_II;id=%01"))
        #expect(!a.contains { $0.hasPrefix("--certificate=") && $0.contains("stale") })
        #expect(!a.contains { $0.hasPrefix("--sslkey=") })
    }

    /// The PIN's ONE channel. Nothing on argv may look remotely like a secret — and
    /// `--key-password`, OpenConnect's documented way to pass a PKCS#11 PIN, is
    /// exactly what must not appear.
    @Test func thePINIsOnStdinAndNowhereElse() throws {
        let c = config()
        let a = SubprocessTunnelManager.openconnectArgs(for: c)
        #expect(a.contains("--passwd-on-stdin"))
        #expect(!a.contains { $0.hasPrefix("--key-password") })
        #expect(!a.contains { $0.contains("pin-value") || $0.contains("pin-source") })
        #expect(!a.contains { $0.contains("123456") })

        guard TunnelCLI.openconnect.isAvailable else {
            // command(for:) needs the resolved tool; the argv assertions above are
            // the part that does not.
            return
        }
        let built = try #require(SubprocessTunnelManager.command(for: c, password: nil, pin: "123456"))
        #expect(!built.1.contains { $0.contains("123456") }, "the PIN must not be in argv")
        #expect(built.2 == Data("123456\n".utf8), "the PIN goes down the pipe, with a newline")
    }

    /// A password-mode tunnel must not start piping PINs, and a token-mode tunnel
    /// must not pipe the gateway password: one method, one secret, one channel.
    @Test func theOtherModesKeepTheirOwnChannels() throws {
        guard TunnelCLI.openconnect.isAvailable else { return }
        var password = config()
        password.authMode = "password"
        let pw = try #require(SubprocessTunnelManager.command(for: password,
                                                              password: "hunter2", pin: "123456"))
        #expect(pw.2 == Data("hunter2\n".utf8))

        var cert = config()
        cert.authMode = "certificate"
        cert.clientCertFile = "~/client.pem"
        let file = try #require(SubprocessTunnelManager.command(for: cert,
                                                                password: "hunter2", pin: "123456"))
        #expect(file.2 == nil, "certificate mode reads no stdin at all")
    }

    @Test func anExplicitKeyURIIsPassedWhenGiven() {
        let a = SubprocessTunnelManager.openconnectArgs(for: config {
            $0.pkcs11KeyURI = "pkcs11:manufacturer=piv_II;id=%01;type=private"
        })
        #expect(a.contains("--sslkey=pkcs11:manufacturer=piv_II;id=%01;type=private"))
    }

    /// A smartcard tunnel can never run on the built-in engine: our libopenconnect is
    /// built `--with-openssl --without-gnutls`, and OpenConnect's PKCS#11 support is
    /// GnuTLS-only. Routing one in-process would sign in with no certificate at all.
    @Test func tokenModeNeverRunsInProcess() {
        var c = config()
        c.kind = .fortinet
        c.preferInProcess = true
        #expect(!SubprocessTunnelManager.willRunInProcess(c))
    }

    @Test func theEditorRefusesAnIncompleteTokenConfiguration() {
        #expect(SubprocessTunnelConfig.pkcs11Problem(config { $0.pkcs11ModulePath = nil })?
            .contains("provider module") == true)
        #expect(SubprocessTunnelConfig.pkcs11Problem(config { $0.pkcs11CertificateURI = nil })?
            .contains("Find Certificates") == true)
        #expect(SubprocessTunnelConfig.pkcs11Problem(config {
            $0.pkcs11CertificateURI = "pkcs11:id=%01?pin-value=1234"
        })?.contains("pin-value") == true)
        #expect(SubprocessTunnelConfig.pkcs11Problem(config { $0.pkcs11ModulePath = "opensc.so" })?
            .contains("full path") == true)
        // A complete one passes.
        #expect(SubprocessTunnelConfig.pkcs11Problem(config()) == nil)
        // …and none of it applies to a tunnel using another method.
        #expect(SubprocessTunnelConfig.pkcs11Problem(config {
            $0.authMode = "password"; $0.pkcs11ModulePath = nil
        }) == nil)
    }

    /// The registration gap: the module exists, p11-kit doesn't know it, so
    /// openconnect can't load it. Blocked WITH the one-line fix.
    @Test func anUnregisteredModuleBlocksConnectAndOffersTheCommand() throws {
        var files = FakeFiles()
        files.files = ["/opt/homebrew/lib/opensc-pkcs11.so"]
        let discovery = PKCS11ModuleDiscovery(files: files)
        let c = config()
        let reason = try #require(SubprocessTunnelManager
            .pkcs11RegistrationBlockReason(c, discovery: discovery))
        #expect(reason.contains("p11-kit"))
        let command = try #require(SubprocessTunnelManager
            .pkcs11RegistrationCommand(c, discovery: discovery))
        #expect(command.contains("~/.config/pkcs11/modules/opensc-pkcs11.module"))

        // Registered ⇒ no block, no command.
        var registered = files
        registered.directories = ["/opt/homebrew/etc/pkcs11/modules": ["opensc.module"]]
        registered.contents = ["/opt/homebrew/etc/pkcs11/modules/opensc.module":
                                "module: /opt/homebrew/lib/opensc-pkcs11.so\n"]
        let ok = PKCS11ModuleDiscovery(files: registered)
        #expect(SubprocessTunnelManager.pkcs11RegistrationBlockReason(c, discovery: ok) == nil)
        #expect(SubprocessTunnelManager.pkcs11RegistrationCommand(c, discovery: ok) == nil)
    }

    @Test func normalizingKeepsNotSetAsExactlyOneThing() {
        let n = config { $0.pkcs11KeyURI = "   "; $0.pkcs11ModulePath = " /m.so " }.normalized()
        #expect(n.pkcs11KeyURI == nil, "an emptied field becomes nil, never \"\"")
        #expect(n.pkcs11ModulePath == "/m.so")
    }

    @Test func rememberPINIsOffUnlessAskedFor() {
        #expect(!SubprocessTunnelConfig().pkcs11RemembersPIN)
        #expect(config { $0.pkcs11PINSource = "keychain" }.pkcs11RemembersPIN)
        #expect(!config { $0.pkcs11PINSource = "ask" }.pkcs11RemembersPIN)
    }

    /// A tunnel saved before these fields existed must still decode — the
    /// Optional-field rule the whole config follows.
    @Test func oldConfigsWithoutTheseFieldsStillDecode() throws {
        let json = """
        {"id":"abc","name":"Old","kind":"cisco","server":"vpn.example.com",
         "port":null,"username":"alex","sshMode":"socks","socksPort":1080,
         "setSystemProxy":false,"forwards":[],"identityFile":"","compression":false,
         "useJumpHost":false,"jumpHost":"","jumpUsername":"","jumpPort":null,
         "jumpIdentityFile":"","serverAliveInterval":30,"connectTimeout":null,
         "strictHostKey":"accept-new","sshExtraOptions":[],"authMode":"password",
         "realm":"","trustedCertSHA256":"","caFile":"","spoofOS":"",
         "proxyMode":"systemDefault","proxyURL":"","proxyUsername":"",
         "disableDTLS":false,"reconnectTimeout":null,"disableCSD":false,
         "csdWrapper":"","browser":{},"samlBrowser":"","ocMTU":null,"extraArgs":[],
         "usergroup":"","tokenMode":"","clientCertFile":"","clientKeyFile":"",
         "ocCompression":"","baseMTU":null,"forceDPD":null,"enablePFS":false,
         "disableIPv6":false,"noHTTPKeepalive":false,"localHostname":"",
         "userAgent":"","versionString":"","preferInProcess":false}
        """
        let decoded = try JSONDecoder().decode(SubprocessTunnelConfig.self,
                                               from: Data(json.utf8))
        #expect(decoded.pkcs11ModulePath == nil)
        #expect(decoded.pkcs11CertificateURI == nil)
        #expect(!decoded.pkcs11RemembersPIN)
    }
}

// MARK: - 4b. Every failure mode gets its own sentence

struct PKCS11WatcherTests {

    /// The real transcript shape: OpenConnect logs which PKCS#11 objects it used
    /// before it ever talks to the gateway.
    private func watch(_ lines: [String],
                       status: PKCS11TokenStatus? = nil,
                       pinSupplied: Bool = true) -> PKCS11ConnectWatcher {
        var watcher = PKCS11ConnectWatcher(tokenStatus: status, pinSupplied: pinSupplied)
        for line in lines { watcher.observe(line) }
        return watcher
    }

    @Test func aToolWithoutSmartcardSupportSaysWhatToInstall() throws {
        let w = watch(["This binary built without PKCS#11 support"])
        let message = try #require(w.failureMessage())
        #expect(message.contains("brew reinstall openconnect"))
    }

    @Test func aCertificateURIThatMatchesNothing() throws {
        let w = watch(["Error loading certificate from PKCS#11: The object was not found"])
        #expect(w.failure == .certificateNotFound)
        #expect(try #require(w.failureMessage()).contains("Find Certificates"))
    }

    @Test func aCertificateFoundWithoutItsKey() throws {
        let w = watch(["Using PKCS#11 certificate pkcs11:id=%01",
                       "Error importing PKCS#11 URL pkcs11:id=%01: No such object"])
        #expect(w.failure == .keyNotFound)
        #expect(try #require(w.failureMessage()).contains("key's own PKCS#11 URI"))
    }

    /// Even with no explicit error, "cert loaded, key never loaded" is the key
    /// failure — the shape a token that labels its key oddly actually produces.
    @Test func certificateLoadedButNoKeyIsStillAKeyFailure() throws {
        let w = watch(["Using PKCS#11 certificate pkcs11:id=%01"])
        #expect(try #require(w.failureMessage()).contains("private key"))
    }

    @Test func aWrongPINCarriesWhateverTheTokenSaidAboutRetries() throws {
        let plain = watch(["Wrong PIN"])
        #expect(try #require(plain.failureMessage()).contains("refused"))

        // With the token's own counter attached, the message escalates.
        var low = PKCS11TokenStatus(label: "YubiKey PIV")
        low.pinCountLow = true
        let warned = watch(["Wrong PIN"], status: low)
        #expect(try #require(warned.failureMessage()).contains("may destroy"))

        // And the tool's own banner is enough on its own — no pre-flight needed.
        let final = watch(["This is the final try before locking!", "Wrong PIN"])
        let message = try #require(final.failureMessage())
        #expect(message.contains("One PIN attempt left"))
        #expect(final.caution?.contains("FINAL") == true)
    }

    @Test func noPINSuppliedIsDistinctFromAWrongOne() throws {
        let w = watch(["PIN required for PIV_II (PIV Card Holder pin)",
                       "User input required in non-interactive mode"],
                      pinSupplied: false)
        #expect(w.failure == .pinRequired)
        #expect(try #require(w.failureMessage()).contains("needs its PIN"))
    }

    @Test func anExpiredCertificateNamesTheDate() throws {
        let w = watch(["Client certificate has expired at 2026-01-04 09:00:00"])
        #expect(w.failure == .certificateExpired(when: "2026-01-04 09:00:00"))
        let message = try #require(w.failureMessage())
        #expect(message.contains("2026-01-04"))
        #expect(message.contains("expired"))
    }

    /// An expiry WARNING is not a failure — it must not turn a working connection
    /// into a reported error, but it must still be said.
    @Test func anExpiringCertificateIsACautionNotAFailure() {
        let w = watch(["Using PKCS#11 certificate pkcs11:id=%01",
                       "Using PKCS#11 key pkcs11:id=%01",
                       "Client certificate expires soon at 2026-09-01 00:00:00"])
        #expect(w.failure == nil)
        #expect(w.caution?.contains("expires soon") == true)
        #expect(w.materialLoaded)
    }

    /// The most valuable rule: the hardware did its job, so the refusal came from the
    /// SERVER — a completely different conversation from anything about the token.
    @Test func materialLoadedThenNoTunnelBlamesTheServer() throws {
        let w = watch(["Using PKCS#11 certificate pkcs11:id=%01",
                       "Using PKCS#11 key pkcs11:id=%01",
                       "Got HTTP response: HTTP/1.1 401 Unauthorized"])
        #expect(w.failure == nil)
        let message = try #require(w.failureMessage())
        #expect(message.contains("VPN server refused it"))
        #expect(message.contains("enrolled"))
    }

    /// The gateway wanting a second factor after the certificate is its own case —
    /// telling that user "the server refused your certificate" would send them to
    /// the wrong administrator.
    @Test func aGatewayAskingForMoreIsItsOwnMessage() throws {
        let w = watch(["Using PKCS#11 certificate pkcs11:id=%01",
                       "Using PKCS#11 key pkcs11:id=%01",
                       "User input required in non-interactive mode"])
        #expect(try #require(w.failureMessage()).contains("asked for something else"))
    }

    /// The FIRST diagnosis is the true one; what follows is fallout.
    @Test func theFirstFailureWins() {
        let w = watch(["Wrong PIN", "Error loading certificate from PKCS#11: nope"])
        #expect(w.failure == .pinWrong(remaining: nil))
    }

    @Test func aCleanRunReportsNothing() {
        let w = watch(["Connected to HTTPS on vpn.example.com", "Configured as 10.0.0.2"])
        #expect(w.failureMessage() == nil)
        #expect(w.caution == nil)
    }

    /// Every failure mode has to have its own words. Identical messages mean the
    /// distinction was for our benefit, not the user's.
    @Test func everyFailureModeHasADistinctActionableMessage() {
        let all: [PKCS11Failure] = [
            .noModuleInstalled, .moduleUnusable(path: "/m.so"),
            .noTokenPresent(module: "libykcs11.dylib"), .certificateNotFound, .keyNotFound,
            .pinRequired, .pinWrong(remaining: nil), .pinLocked,
            .certificateExpired(when: nil), .serverRejectedCertificate,
            .toolLacksPKCS11Support,
        ]
        let messages = all.map(\.message)
        #expect(Set(messages).count == all.count, "two failure modes share a message")
        for message in messages {
            #expect(message.count > 40, "\u{201C}\(message)\u{201D} is too terse to act on")
            #expect(message.first?.isUppercase == true)
            #expect(message.hasSuffix(".") || message.hasSuffix("!"))
            // No library jargon reaches a user (Docs/Accessibility.md rule 1).
            for jargon in ["errno", "CKR_", "dlopen", "NULL", "p11_kit_uri"] {
                #expect(!message.contains(jargon), "\u{201C}\(message)\u{201D} leaks \(jargon)")
            }
        }
    }
}

// MARK: - 5. The OpenVPN side: detected, explained, refused

struct OpenVPNPKCS11Tests {

    /// openvpn3 does not merely ignore an option it doesn't know: unused options land
    /// in its "UNKNOWN/UNSUPPORTED OPTIONS" bucket and it THROWS. So a pkcs11 profile
    /// has to be caught with an explanation, not handed to the engine.
    @Test func detectsThePKCS11Family() {
        let ovpn = """
        client
        remote vpn.example.com 1194 udp
        pkcs11-providers /usr/local/lib/libykcs11.dylib
        pkcs11-id 'Yubico/PIV/…'
        pkcs11-pin-cache 300
        """
        let found = ProfileEvaluation.pkcs11Directives(in: ovpn)
        #expect(found == ["pkcs11-providers", "pkcs11-id", "pkcs11-pin-cache"])
    }

    @Test func ignoresCommentedOutAndUnrelatedLines() {
        #expect(ProfileEvaluation.pkcs11Directives(in: "# pkcs11-providers /x\n;pkcs11-id y\n").isEmpty)
        #expect(ProfileEvaluation.pkcs11Directives(in: "pkcs12 bundle.p12\ncert c.pem\n").isEmpty)
    }

    @Test func theAdviceNamesTheDirectiveAndTheWayForward() throws {
        var eval = ProfileEvaluation()
        #expect(eval.pkcs11Advice == nil)
        eval.pkcs11Directives = ["pkcs11-providers"]
        #expect(eval.usesPKCS11)
        let advice = try #require(eval.pkcs11Advice)
        #expect(advice.contains("pkcs11-providers"))
        #expect(advice.contains("SSL VPN"), "the route that DOES work has to be named")
    }
}

// MARK: - 6. Catalog / manual / relation contract for the new rows

@MainActor
struct PKCS11SettingsCatalogTests {

    private static let ids = ["oc.pkcs11-module", "oc.pkcs11-certificate", "oc.pkcs11-key",
                              "oc.pkcs11-pin", "oc.pkcs11-remember-pin"]

    /// Every user-facing control gets a spec — including the PIN field, which looks
    /// like plumbing and is a control (AGENTS.md config conventions).
    @Test func everyNewControlHasASpecInSignIn() {
        for id in Self.ids {
            let spec = OpenConnectSettings.catalog[id]
            #expect(spec.group == .signIn, "\(id) belongs to Sign-In")
            #expect(!spec.summary.isEmpty)
            #expect(spec.declaresDefault, "\(id) must declare what it rests at")
            // The summary is for a person, not an implementer.
            for jargon in ["PKCS#11 URI", "dlopen", "argv", "RFC 7512"] {
                #expect(!spec.summary.contains(jargon), "\(id)'s summary leaks \(jargon)")
            }
        }
    }

    @Test func theSmartcardRowsAreRelatedToEachOther() {
        let module = OpenConnectSettings.catalog["oc.pkcs11-module"]
        #expect(module.related.contains("oc.pkcs11-certificate"))
        #expect(module.related.contains("oc.pkcs11-pin"))
        // …and to the in-process toggle they can never be used with.
        #expect(module.related.contains("oc.prefer-in-process"))
        // Relations are symmetric by construction; check one back-edge anyway.
        #expect(OpenConnectSettings.catalog["oc.prefer-in-process"].related
            .contains("oc.pkcs11-module"))
        // The four sign-in shapes are alternatives to each other.
        #expect(OpenConnectSettings.catalog["oc.pkcs11-certificate"].related
            .contains("oc.client-cert"))
    }

    /// A search hit or a related link on a hidden row must say why it isn't there,
    /// rather than scroll nowhere while announcing that it did.
    @Test func hiddenSmartcardRowsExplainThemselves() throws {
        var c = SubprocessTunnelConfig()
        c.kind = .ciscoAnyConnect
        c.authMode = "password"
        let underPassword = SettingVisibility.subprocess(c)
        for id in Self.ids {
            #expect(try #require(underPassword.reason(id)).contains("Smartcard"))
        }

        c.authMode = "token"
        let noModule = SettingVisibility.subprocess(c)
        #expect(noModule.reason("oc.pkcs11-module") == nil, "the module row is always there")
        #expect(noModule.reason("oc.pkcs11-certificate") == nil)
        #expect(try #require(noModule.reason("oc.pkcs11-pin")).contains("provider module"))

        c.pkcs11ModulePath = "/opt/homebrew/lib/opensc-pkcs11.so"
        let ready = SettingVisibility.subprocess(c)
        for id in Self.ids { #expect(ready.reason(id) == nil) }
    }

    /// An SSH tunnel has none of these rows, and the SSH branch of the table has to
    /// keep saying so as the OpenConnect catalog grows.
    @Test func anSSHTunnelHidesThemAll() throws {
        var c = SubprocessTunnelConfig()
        c.kind = .ssh
        let visibility = SettingVisibility.subprocess(c)
        for id in Self.ids {
            #expect(try #require(visibility.reason(id)).contains("SSL VPN"))
        }
    }
}
