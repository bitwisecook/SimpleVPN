// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
//  PKCS11Discovery.swift
//  Finding the PKCS#11 provider modules installed on this Mac, and reading the
//  tokens and certificates they can see — WITHOUT loading any of them ourselves.
//
//  WHY NOT LOAD THE MODULE. See Shared/PKCS11.swift's header: a provider module is a
//  third-party dylib, and the hardened-runtime relaxation that would let us dlopen
//  one is the single relaxation AMFI forbids on a system-extension-embedding app. So
//  enumeration is delegated to the PKCS#11 tools the user already has — `p11tool`
//  (GnuTLS) first, because it is the SAME p11-kit/GnuTLS stack that Homebrew's
//  `openconnect` uses, so what it lists is exactly what will be usable; `pkcs11-tool`
//  (OpenSC) second, for the certificate SUBJECT and for a definite locked/final-try
//  reading, which GnuTLS cannot give (its own printer conflates the two — see
//  `parseTokens`).
//
//  WE NEVER GIVE A PIN TO AN ENUMERATION TOOL. Some tokens hide their objects until
//  login; for those, enumeration reports that plainly and the user types the URI.
//  Populating a picker is not worth spending an attempt from a counter whose
//  exhaustion destroys the key.
//
//  BINARY RESOLUTION AND THE CHILD ENVIRONMENT ARE `LocalToolRunner`'s, not ours.
//  That is the sign-in-source seam's hardened runner: an allow-list of documented
//  install locations instead of `PATH` (which anything able to prepend a directory
//  could otherwise use to choose what this app executes), a refusal to run from a
//  world- or non-admin-group-writable directory, an environment built from scratch
//  rather than inherited, `/dev/null` on stdin, and a hard deadline with cancellation.
//  Every one of those is a rule this work needs; re-deriving them here would have been
//  a second, weaker copy.
//
//  NOTHING SECRET CROSSES THIS BOUNDARY IN EITHER DIRECTION. No PIN goes to these
//  tools and none comes back — the only outputs are object labels, URIs and token
//  flags. That is why merging stdout with (scrubbed) stderr for classification is
//  safe here, where it would not be for a vault adapter.
//

import Foundation
import Security
import os

// MARK: - Injectable boundaries
//
// There is no hardware token on a build machine and no gateway to authenticate
// against, so every side effect this file has is behind one of these two protocols
// and the parsers below are PURE. `PKCS11DiscoveryTests` drives the whole state
// machine — including all six failure modes — with fakes.

/// Running one of the user's PKCS#11 tools.
nonisolated protocol PKCS11ToolRunning: Sendable {
    /// Returns the tool's exit status and its merged stdout+stderr. Never throws:
    /// "the tool couldn't run" is a status, not an exception, because it is one of
    /// the outcomes the caller has to explain to a user.
    func run(executable: String, arguments: [String]) async -> (status: Int32, output: String)
}

/// The filesystem facts module discovery needs.
nonisolated protocol PKCS11FileProbing: Sendable {
    func isReadableFile(_ path: String) -> Bool
    func directoryEntries(_ path: String) -> [String]
    func text(ofFile path: String) -> String?
}

nonisolated struct PKCS11FileProbe: PKCS11FileProbing {
    func isReadableFile(_ path: String) -> Bool {
        var isDir: ObjCBool = false
        let exists = FileManager.default.fileExists(atPath: path, isDirectory: &isDir)
        return exists && !isDir.boolValue && FileManager.default.isReadableFile(atPath: path)
    }
    func directoryEntries(_ path: String) -> [String] {
        (try? FileManager.default.contentsOfDirectory(atPath: path))?.sorted() ?? []
    }
    func text(ofFile path: String) -> String? {
        guard let data = FileManager.default.contents(atPath: path) else { return nil }
        return String(data: data, encoding: .utf8)
    }
}

/// The two tools that can read a token, and where they are allowed to live.
///
/// Resolution goes through `LocalToolRunner.locate`, so these two get exactly the
/// hardening the vault adapters get. They are READERS, not transports: neither is
/// needed to CONNECT with a token — that is `openconnect`'s job — so a missing one
/// costs the certificate picker and nothing else.
nonisolated enum PKCS11Tool: String, CaseIterable, Sendable {
    /// GnuTLS. Preferred, because it is the same p11-kit/GnuTLS stack Homebrew's
    /// `openconnect` uses — what it lists is what will actually be usable.
    case p11tool = "p11tool"
    /// OpenSC. Contributes the certificate subject and a definite locked reading.
    case pkcs11Tool = "pkcs11-tool"

    var resolvedPath: String? { LocalToolRunner.locate(rawValue) }
    var isAvailable: Bool { resolvedPath != nil }

    var installCommand: String {
        switch self {
        case .p11tool: "brew install gnutls"
        case .pkcs11Tool: "brew install opensc"
        }
    }
    var installHint: String {
        switch self {
        case .p11tool:
            "Install with: brew install gnutls (lets SimpleVPN list the certificates on your token)"
        case .pkcs11Tool:
            "Install with: brew install opensc (adds the smartcard provider module and reads certificate names)"
        }
    }
}

nonisolated struct PKCS11ProcessRunner: PKCS11ToolRunning {

    /// `LocalToolRunner`'s built-from-scratch environment, plus the one addition this
    /// work needs: `LC_ALL=C`. GnuTLS prints its `Expires:` line with `strftime("%c")`
    /// — locale-dependent — so without pinning the locale that date is unparseable on
    /// a machine whose `LC_TIME` isn't C. (`HOME` comes from `childEnvironment`, and
    /// is required: p11-kit reads `~/.config/pkcs11` for its module registry.)
    static func environment() -> [String: String] {
        var env = LocalToolRunner.childEnvironment()
        env["LC_ALL"] = "C"
        env["LANG"] = "C"
        env["TERM"] = "dumb"
        return env
    }

    /// A smartcard behind a slow reader is not unusual, so the deadline is longer
    /// than the vault default — but there IS one, and cancelling the survey kills
    /// the child.
    var deadline: TimeInterval = 20

    func run(executable: String, arguments: [String]) async -> (status: Int32, output: String) {
        let result = await LocalToolRunner.run(executable: executable, arguments: arguments,
                                               deadline: deadline,
                                               environment: Self.environment())
        if result.timedOut {
            return (-1, "the smartcard tool didn't answer in time")
        }
        // Both halves: the listings arrive on stdout, and every "couldn't load that
        // module" diagnosis is on stderr. Safe to merge here precisely because no
        // secret ever crosses this boundary (see the file header).
        let merged = [result.text, result.stderr].filter { !$0.isEmpty }.joined(separator: "\n")
        return (result.exitCode, merged)
    }
}

// MARK: - Module discovery

/// Which PKCS#11 provider modules are on this Mac. Pure apart from the injected
/// `PKCS11FileProbing`, so the whole table is testable against a fake filesystem.
nonisolated struct PKCS11ModuleDiscovery: Sendable {

    var files: PKCS11FileProbing = PKCS11FileProbe()

    /// The install locations that actually exist, verified rather than guessed:
    ///  • Homebrew OpenSC puts `opensc-pkcs11.so` in both `lib/` and `lib/pkcs11/`
    ///    (checked on an arm64 Homebrew install).
    ///  • The OpenSC macOS installer package puts it in `/Library/OpenSC/lib/`, with
    ///    copies in `/usr/local/lib/`.
    ///  • `yubico-piv-tool` installs `libykcs11.dylib` in its prefix's `lib/`;
    ///    Yubico's own installer uses `/usr/local/lib/`.
    ///
    /// NOTE for anyone reaching for `~/.pkcs11_modules/`: that is not a p11-kit path.
    /// p11-kit's own paths — read out of the installed `libp11-kit.0.dylib` — are
    /// `<prefix>/etc/pkcs11/modules` and `~/.config/pkcs11/modules`, which is what
    /// `registryDirectories` uses.
    static let wellKnown: [(path: String, origin: PKCS11Module.Origin)] = [
        // OpenSC
        ("/opt/homebrew/lib/pkcs11/opensc-pkcs11.so", .openSC),
        ("/opt/homebrew/lib/opensc-pkcs11.so", .openSC),
        ("/usr/local/lib/pkcs11/opensc-pkcs11.so", .openSC),
        ("/usr/local/lib/opensc-pkcs11.so", .openSC),
        ("/Library/OpenSC/lib/opensc-pkcs11.so", .openSC),
        ("/Library/OpenSC/lib/onepin-opensc-pkcs11.so", .openSC),
        // Yubico YKCS11
        ("/opt/homebrew/lib/libykcs11.dylib", .yubiKey),
        ("/usr/local/lib/libykcs11.dylib", .yubiKey),
        ("/usr/local/lib/libykcs11.so", .yubiKey),
        // SoftHSM — a software token. Listed because it is the only way to rehearse
        // this whole flow without hardware, and hiding it would not make it absent.
        ("/opt/homebrew/lib/softhsm/libsofthsm2.so", .softHSM),
        ("/usr/local/lib/softhsm/libsofthsm2.so", .softHSM),
    ]

    /// p11-kit's module registry directories, in the order p11-kit reads them.
    static let registryDirectories: [String] = {
        var dirs = ["/opt/homebrew/share/p11-kit/modules",
                    "/opt/homebrew/etc/pkcs11/modules",
                    "/usr/local/share/p11-kit/modules",
                    "/usr/local/etc/pkcs11/modules",
                    "/etc/pkcs11/modules"]
        if let home = ProcessInfo.processInfo.environment["HOME"] {
            dirs.append("\(home)/.config/pkcs11/modules")
        }
        return dirs
    }()

    /// Directories a bare `module:` name in a `.module` file may name a file in.
    /// Only absolute results are ever returned — a bare name must never let the
    /// dynamic-loader search order pick the library for us.
    static let registryModuleSearchDirectories = [
        "/opt/homebrew/lib/pkcs11", "/usr/local/lib/pkcs11", "/usr/lib/pkcs11",
    ]

    /// Every module found, well-known first (so the picker's top entries are the
    /// ones a user is likely to have meant), then p11-kit-registered ones, deduped
    /// by path.
    func modules() -> [PKCS11Module] {
        let registered = registeredModules()
        let registeredPaths = Set(registered.map(\.path))
        var out: [PKCS11Module] = []
        var seen: Set<String> = []
        for entry in Self.wellKnown where files.isReadableFile(entry.path) {
            guard seen.insert(entry.path).inserted else { continue }
            out.append(PKCS11Module(path: entry.path, origin: entry.origin, declaredName: nil,
                                    registeredWithP11Kit: registeredPaths.contains(entry.path)))
        }
        for module in registered {
            guard seen.insert(module.path).inserted else { continue }
            out.append(module)
        }
        return out
    }

    /// A module the user typed a path for, described the same way a discovered one is
    /// — including whether p11-kit knows about it, which is what decides whether
    /// openconnect can use it at all.
    func module(atUserPath raw: String) -> PKCS11Module? {
        let expanded = (raw.trimmingCharacters(in: .whitespacesAndNewlines) as NSString)
            .expandingTildeInPath
        guard !expanded.isEmpty else { return nil }
        let registered = Set(registeredModules().map(\.path))
        return PKCS11Module(path: expanded,
                            origin: Self.origin(forPath: expanded) ?? .userSupplied,
                            declaredName: nil,
                            registeredWithP11Kit: registered.contains(expanded))
    }

    /// Modules declared by p11-kit `.module` files. The trust module p11-kit ships
    /// for the system CA store is skipped: it holds no client certificate, so
    /// offering it as a sign-in provider would only ever waste a user's time.
    func registeredModules() -> [PKCS11Module] {
        var out: [PKCS11Module] = []
        for dir in Self.registryDirectories {
            for entry in files.directoryEntries(dir) where entry.hasSuffix(".module") {
                let file = "\(dir)/\(entry)"
                guard let text = files.text(ofFile: file),
                      let declared = Self.moduleDeclaration(in: text) else { continue }
                guard let resolved = resolveDeclaredModule(declared.module) else { continue }
                if (resolved as NSString).lastPathComponent.contains("p11-kit-trust") { continue }
                out.append(PKCS11Module(path: resolved,
                                        origin: Self.origin(forPath: resolved) ?? .p11KitRegistered,
                                        declaredName: declared.name,
                                        registeredWithP11Kit: true))
            }
        }
        return out
    }

    private func resolveDeclaredModule(_ declared: String) -> String? {
        if declared.hasPrefix("/") {
            return files.isReadableFile(declared) ? declared : nil
        }
        for dir in Self.registryModuleSearchDirectories {
            let candidate = "\(dir)/\(declared)"
            if files.isReadableFile(candidate) { return candidate }
        }
        return nil
    }

    /// Recognise a well-known module by its filename, so a copy in an unusual place
    /// still gets its product name in the picker.
    static func origin(forPath path: String) -> PKCS11Module.Origin? {
        let file = (path as NSString).lastPathComponent.lowercased()
        if file.contains("ykcs11") { return .yubiKey }
        if file.contains("opensc") { return .openSC }
        if file.contains("softhsm") { return .softHSM }
        return nil
    }

    /// The `module:` (and optional `x-name:`/`description:`) lines of a p11-kit
    /// `.module` file. Format is `key: value`, one per line, `#` comments.
    static func moduleDeclaration(in text: String) -> (module: String, name: String?)? {
        var module: String?
        var name: String?
        for rawLine in text.split(whereSeparator: \.isNewline) {
            let line = rawLine.trimmingCharacters(in: .whitespaces)
            if line.isEmpty || line.hasPrefix("#") { continue }
            guard let colon = line.firstIndex(of: ":") else { continue }
            let key = line[..<colon].trimmingCharacters(in: .whitespaces).lowercased()
            let value = line[line.index(after: colon)...].trimmingCharacters(in: .whitespaces)
            switch key {
            case "module": module = value
            case "x-name", "description": if name == nil { name = value }
            default: break
            }
        }
        guard let module, !module.isEmpty else { return nil }
        return (module, name)
    }
}

// MARK: - Enumeration

/// Reads tokens and certificates through the user's PKCS#11 tools.
nonisolated struct PKCS11Enumerator: Sendable {

    var runner: PKCS11ToolRunning = PKCS11ProcessRunner()
    /// Absolute paths from `LocalToolRunner.locate` — never a name the child's own
    /// search rules would resolve, and never anything found on `PATH`.
    var p11toolPath: String?
    var pkcs11ToolPath: String?

    private static let log = Logger(subsystem: "com.bragi0.SimpleVPN", category: "pkcs11")

    /// The real thing, resolved through the hardened runner.
    static func live() -> PKCS11Enumerator {
        PKCS11Enumerator(p11toolPath: PKCS11Tool.p11tool.resolvedPath,
                         pkcs11ToolPath: PKCS11Tool.pkcs11Tool.resolvedPath)
    }

    /// Whether any tool capable of reading a token is installed.
    var hasAnyTool: Bool { p11toolPath != nil || pkcs11ToolPath != nil }

    // MARK: Tokens

    /// The tokens this module can see. `.noTokenPresent` is a distinct outcome from
    /// `.moduleUnusable` on purpose — "plug the key in" and "fix the path" are
    /// different actions.
    func tokens(module: String) async -> Result<[PKCS11TokenStatus], PKCS11Failure> {
        guard !module.isEmpty else { return .failure(.noModuleInstalled) }
        var gnutlsTokens: [PKCS11TokenStatus] = []

        if let p11tool = p11toolPath {
            let result = await runner.run(executable: p11tool,
                                         arguments: ["--provider", module, "--list-tokens"])
            if let failure = Self.moduleFailure(in: result.output, module: module) {
                return .failure(failure)
            }
            gnutlsTokens = Self.parseTokens(p11toolOutput: result.output)
        }

        // OpenSC reports the locked/final-try distinction GnuTLS's printer loses, so
        // its reading is merged over the GnuTLS one where both are present.
        if let pkcs11Tool = pkcs11ToolPath {
            let result = await runner.run(executable: pkcs11Tool,
                                          arguments: ["--module", module, "--list-token-slots"])
            if gnutlsTokens.isEmpty, let failure = Self.moduleFailure(in: result.output, module: module) {
                return .failure(failure)
            }
            let openSC = Self.parseTokens(pkcs11ToolOutput: result.output)
            gnutlsTokens = Self.merge(gnutls: gnutlsTokens, openSC: openSC)
        }

        guard hasAnyTool else { return .failure(.noModuleInstalled) }
        guard !gnutlsTokens.isEmpty else {
            return .failure(.noTokenPresent(module: (module as NSString).lastPathComponent))
        }
        return .success(gnutlsTokens)
    }

    // MARK: Certificates

    /// The certificates on `tokenScope` (or on every token the module sees, when it
    /// is nil), enriched with each certificate's subject where a tool can read it.
    func certificates(module: String, tokenScope: String?) async
        -> Result<[PKCS11Certificate], PKCS11Failure> {
        guard !module.isEmpty else { return .failure(.noModuleInstalled) }
        guard let p11tool = p11toolPath else {
            // OpenSC alone can still list them, with subjects but no expiry.
            guard let pkcs11Tool = pkcs11ToolPath else { return .failure(.noModuleInstalled) }
            let result = await runner.run(executable: pkcs11Tool,
                                          arguments: ["--module", module, "--list-objects", "--type", "cert"])
            if let failure = Self.moduleFailure(in: result.output, module: module) {
                return .failure(failure)
            }
            let certs = Self.parseCertificates(pkcs11ToolOutput: result.output)
            return certs.isEmpty ? .failure(.certificateNotFound) : .success(certs)
        }

        var arguments = ["--provider", module, "--list-all-certs"]
        if let tokenScope, !tokenScope.isEmpty { arguments.append(tokenScope) }
        let result = await runner.run(executable: p11tool, arguments: arguments)
        if let failure = Self.moduleFailure(in: result.output, module: module) {
            return .failure(failure)
        }
        var certs = Self.parseCertificates(p11toolOutput: result.output)
        guard !certs.isEmpty else {
            // "No matching objects found" from a module that DOES see a token means
            // the token holds no certificate — not that the module is broken.
            return .failure(.certificateNotFound)
        }

        // Subject enrichment, best effort. Two sources, cheapest first: OpenSC
        // prints the DN directly; otherwise export the certificate and read it with
        // Security.framework (no third process, and no locale-dependent parsing).
        if let pkcs11Tool = pkcs11ToolPath {
            let objects = await runner.run(executable: pkcs11Tool,
                                           arguments: ["--module", module, "--list-objects", "--type", "cert"])
            let subjects = Self.parseSubjects(pkcs11ToolOutput: objects.output)
            for i in certs.indices where certs[i].subject == nil {
                if let subject = subjects[certs[i].label] { certs[i].subject = subject }
            }
        }
        for i in certs.indices where certs[i].subject == nil {
            let exported = await runner.run(executable: p11tool,
                                            arguments: ["--provider", module, "--export", certs[i].uri])
            if let facts = Self.certificateFacts(pem: exported.output) {
                certs[i].subject = facts.subject
                // The exported certificate's own notAfter beats a parsed `Expires:`
                // line — it is the certificate, not a rendering of it.
                if let notAfter = facts.expires { certs[i].expires = notAfter }
            }
        }
        return .success(certs)
    }

    // MARK: Failure classification (pure)

    /// Why a tool couldn't use this module at all, or nil. Both tools say so in
    /// their own words; the strings below are the shipped ones (checked against
    /// GnuTLS 3.8 and OpenSC 0.27).
    static func moduleFailure(in output: String, module: String) -> PKCS11Failure? {
        let text = output.lowercased()
        if text.contains("pkcs11_add_provider")
            || text.contains("failed to load pkcs11 module")
            || text.contains("sc_dlopen_deep failed")
            || text.contains("initialization error") {
            return .moduleUnusable(path: module)
        }
        if text.contains("no slots") || text.contains("no slot with a token")
            || text.contains("no smart card readers") {
            return .noTokenPresent(module: (module as NSString).lastPathComponent)
        }
        return nil
    }

    // MARK: p11tool parsing (pure)

    /// `p11tool --list-tokens`. One record per "Token N:" block; the fields are
    /// tab-indented `Key: value` lines.
    ///
    /// GnuTLS's own printer has a bug worth knowing about: it tests
    /// `USER_PIN_FINAL_TRY` twice, printing both "Final uPIN attempt" and "uPIN
    /// locked" for a final try, and never printing the locked flag at all. So
    /// "uPIN locked" is only believed here when "Final uPIN attempt" is absent —
    /// and a definite locked reading comes from OpenSC instead.
    static func parseTokens(p11toolOutput output: String) -> [PKCS11TokenStatus] {
        var out: [PKCS11TokenStatus] = []
        var current: PKCS11TokenStatus?
        func flush() {
            if let current, !current.uri.isEmpty || !current.label.isEmpty { out.append(current) }
            current = nil
        }
        for rawLine in output.split(whereSeparator: \.isNewline) {
            let line = rawLine.trimmingCharacters(in: .whitespaces)
            if line.hasPrefix("Token ") && line.hasSuffix(":") {
                flush()
                current = PKCS11TokenStatus()
                continue
            }
            guard current != nil, let colon = line.firstIndex(of: ":") else { continue }
            let key = String(line[..<colon])
            let value = line[line.index(after: colon)...].trimmingCharacters(in: .whitespaces)
            switch key {
            case "URL": current?.uri = value
            case "Label": current?.label = value
            case "Module": current?.modulePath = value.isEmpty ? nil : value
            case "Type": current?.isHardware = value.contains("Hardware token")
            case "Flags":
                let flags = value.split(separator: ",").map { $0.trimmingCharacters(in: .whitespaces) }
                current?.requiresLogin = flags.contains("Requires login")
                current?.pinCountLow = flags.contains("uPIN low count")
                current?.pinFinalTry = flags.contains("Final uPIN attempt")
                current?.pinLocked = flags.contains("uPIN locked") && !flags.contains("Final uPIN attempt")
                current?.pinUninitialized = flags.contains("uPIN uninitialized")
            default: break
            }
        }
        flush()
        return out
    }

    /// `p11tool --list-all-certs`. One record per "Object N:" block.
    static func parseCertificates(p11toolOutput output: String) -> [PKCS11Certificate] {
        var out: [PKCS11Certificate] = []
        var current: PKCS11Certificate?
        func flush() {
            if let current, !current.uri.isEmpty { out.append(current) }
            current = nil
        }
        for rawLine in output.split(whereSeparator: \.isNewline) {
            let line = rawLine.trimmingCharacters(in: .whitespaces)
            if line.hasPrefix("Object ") && line.hasSuffix(":") {
                flush()
                current = PKCS11Certificate()
                continue
            }
            guard current != nil, let colon = line.firstIndex(of: ":") else { continue }
            let key = String(line[..<colon])
            let value = line[line.index(after: colon)...].trimmingCharacters(in: .whitespaces)
            switch key {
            case "URL": current?.uri = value
            case "Label": current?.label = value
            case "Expires": current?.expires = parseGnuTLSDate(value)
            case "Type":
                // "X.509 Certificate (RSA-2048)" → "RSA-2048".
                if let open = value.firstIndex(of: "("), let close = value.lastIndex(of: ")"),
                   open < close {
                    current?.keySummary = String(value[value.index(after: open)..<close])
                }
            case "ID":
                // p11tool prints the raw hex ("01"); the URI carries it as "%01",
                // which is the form the picker shows so the two agree.
                current?.objectID = value.isEmpty ? "" : value
            default: break
            }
        }
        flush()
        // Only certificates: --list-all-certs is already filtered, but a URI that
        // says otherwise is a parse slip worth dropping rather than showing.
        return out.filter { PKCS11URI.parse($0.uri)?.objectType ?? "cert" == "cert" }
    }

    /// GnuTLS prints `Expires:` with `strftime("%c")` in LOCAL time, so this only
    /// parses deterministically because `PKCS11ProcessRunner` pins `LC_ALL=C`. The
    /// C locale's `%c` is `Thu Aug  5 10:54:16 2027` — note `%e`'s space padding,
    /// which is why runs of whitespace are collapsed first.
    static func parseGnuTLSDate(_ raw: String) -> Date? {
        let collapsed = raw.split(separator: " ", omittingEmptySubsequences: true).joined(separator: " ")
        let formatter = DateFormatter()
        formatter.locale = Locale(identifier: "en_US_POSIX")
        formatter.timeZone = .current
        for format in ["EEE MMM d HH:mm:ss yyyy", "EEE MMM d HH:mm:ss zzz yyyy"] {
            formatter.dateFormat = format
            if let date = formatter.date(from: collapsed) { return date }
        }
        return nil
    }

    // MARK: pkcs11-tool parsing (pure)

    /// `pkcs11-tool --list-token-slots`. Slots with no token print
    /// "token state: uninitialized" and are skipped — an empty reader is not a token.
    static func parseTokens(pkcs11ToolOutput output: String) -> [PKCS11TokenStatus] {
        var out: [PKCS11TokenStatus] = []
        var current: PKCS11TokenStatus?
        var sawTokenFields = false
        func flush() {
            if let current, sawTokenFields { out.append(current) }
            current = nil
            sawTokenFields = false
        }
        for rawLine in output.split(whereSeparator: \.isNewline) {
            let line = rawLine.trimmingCharacters(in: .whitespaces)
            if line.hasPrefix("Slot ") {
                flush()
                current = PKCS11TokenStatus()
                continue
            }
            guard current != nil, let colon = line.firstIndex(of: ":") else { continue }
            let key = line[..<colon].trimmingCharacters(in: .whitespaces)
            let value = line[line.index(after: colon)...].trimmingCharacters(in: .whitespaces)
            switch key {
            case "token label":
                current?.label = value
                sawTokenFields = true
            case "uri":
                current?.uri = value
                sawTokenFields = true
            case "token flags":
                sawTokenFields = true
                let flags = value.split(separator: ",").map { $0.trimmingCharacters(in: .whitespaces) }
                current?.requiresLogin = flags.contains("login required")
                current?.pinCountLow = flags.contains("user PIN count low")
                current?.pinFinalTry = flags.contains("final user PIN try")
                current?.pinLocked = flags.contains("user PIN locked")
                current?.pinUninitialized = !flags.contains("PIN initialized")
                // Flags OpenSC doesn't name are lumped into "other flags=0x…";
                // the three PIN bits are checked there too so a newer module that
                // stops naming them still warns.
                if let other = flags.first(where: { $0.hasPrefix("other flags=0x") }) {
                    let hex = other.dropFirst("other flags=0x".count)
                    if let bits = UInt64(hex, radix: 16) {
                        if bits & 0x0001_0000 != 0 { current?.pinCountLow = true }
                        if bits & 0x0002_0000 != 0 { current?.pinFinalTry = true }
                        if bits & 0x0004_0000 != 0 { current?.pinLocked = true }
                    }
                }
            case "token state":
                // "uninitialized" — an empty reader slot.
                if value.contains("uninitialized") { current = nil }
            default: break
            }
        }
        flush()
        return out
    }

    /// `pkcs11-tool --list-objects --type cert`. Blocks start with
    /// "Certificate Object; type = X.509 cert".
    static func parseCertificates(pkcs11ToolOutput output: String) -> [PKCS11Certificate] {
        var out: [PKCS11Certificate] = []
        var current: PKCS11Certificate?
        func flush() {
            if let current, !current.uri.isEmpty { out.append(current) }
            current = nil
        }
        for rawLine in output.split(whereSeparator: \.isNewline) {
            let line = rawLine.trimmingCharacters(in: .whitespaces)
            if line.hasPrefix("Certificate Object") {
                flush()
                current = PKCS11Certificate()
                continue
            }
            guard current != nil, let colon = line.firstIndex(of: ":") else { continue }
            let key = line[..<colon].trimmingCharacters(in: .whitespaces)
            let value = line[line.index(after: colon)...].trimmingCharacters(in: .whitespaces)
            switch key {
            case "label": current?.label = value
            case "uri": current?.uri = value
            case "subject": current?.subject = Self.tidySubject(value)
            case "ID": current?.objectID = value
            default: break
            }
        }
        flush()
        return out
    }

    /// label → subject, for merging onto a GnuTLS listing.
    static func parseSubjects(pkcs11ToolOutput output: String) -> [String: String] {
        var out: [String: String] = [:]
        for cert in parseCertificates(pkcs11ToolOutput: output) {
            guard let subject = cert.subject, !cert.label.isEmpty else { continue }
            out[cert.label] = subject
        }
        return out
    }

    /// OpenSC prints `DN: OU=Engineering,O=Example Corp,CN=alex.hunt`. Drop the
    /// "DN:" marker and lead with the common name, which is the part a human reads.
    static func tidySubject(_ raw: String) -> String {
        var text = raw.trimmingCharacters(in: .whitespaces)
        if text.hasPrefix("DN:") { text = String(text.dropFirst(3)).trimmingCharacters(in: .whitespaces) }
        let parts = text.split(separator: ",").map { $0.trimmingCharacters(in: .whitespaces) }
        guard let cn = parts.first(where: { $0.uppercased().hasPrefix("CN=") }) else { return text }
        let rest = parts.filter { $0 != cn }
        return rest.isEmpty ? cn : ([cn] + rest).joined(separator: ", ")
    }

    // MARK: Reading an exported certificate (pure, no subprocess)

    /// Subject summary + notAfter from an exported PEM, via Security.framework —
    /// so the friendly name and the expiry come from the certificate itself rather
    /// than from a tool's rendering of it.
    static func certificateFacts(pem: String) -> (subject: String?, expires: Date?)? {
        guard let der = derBody(inPEM: pem),
              let cert = SecCertificateCreateWithData(nil, der as CFData) else { return nil }
        let subject = SecCertificateCopySubjectSummary(cert) as String?
        var expires: Date?
        if let values = SecCertificateCopyValues(cert, [kSecOIDX509V1ValidityNotAfter] as CFArray, nil)
            as? [String: Any],
           let entry = values[kSecOIDX509V1ValidityNotAfter as String] as? [String: Any],
           let seconds = entry["value"] as? Double {
            // Security.framework reports the CSSM absolute time: seconds since the
            // 2001 reference date.
            expires = Date(timeIntervalSinceReferenceDate: seconds)
        }
        guard subject != nil || expires != nil else { return nil }
        return (subject, expires)
    }

    static func derBody(inPEM pem: String) -> Data? {
        let begin = "-----BEGIN CERTIFICATE-----"
        let end = "-----END CERTIFICATE-----"
        guard let start = pem.range(of: begin), let finish = pem.range(of: end),
              start.upperBound <= finish.lowerBound else { return nil }
        let base64 = pem[start.upperBound..<finish.lowerBound]
            .split(whereSeparator: \.isNewline).joined()
        return Data(base64Encoded: base64, options: [.ignoreUnknownCharacters])
    }

    // MARK: Merging two tools' readings (pure)

    /// OpenSC's PIN state wins where the two tools describe the same token, because
    /// GnuTLS cannot distinguish a final try from a lock. Everything else keeps the
    /// GnuTLS reading: its URI is the one openconnect will match against.
    static func merge(gnutls: [PKCS11TokenStatus], openSC: [PKCS11TokenStatus]) -> [PKCS11TokenStatus] {
        guard !gnutls.isEmpty else { return openSC }
        return gnutls.map { token in
            guard let match = openSC.first(where: { Self.sameToken($0, token) }) else { return token }
            var merged = token
            merged.pinCountLow = merged.pinCountLow || match.pinCountLow
            merged.pinFinalTry = merged.pinFinalTry || match.pinFinalTry
            merged.pinLocked = match.pinLocked
            merged.pinUninitialized = merged.pinUninitialized || match.pinUninitialized
            merged.triesLeft = match.triesLeft ?? merged.triesLeft
            return merged
        }
    }

    /// Two readings describe the same token when the serial matches (the one
    /// attribute both tools always print, and the one that is actually unique).
    static func sameToken(_ a: PKCS11TokenStatus, _ b: PKCS11TokenStatus) -> Bool {
        let serialA = PKCS11URI.parse(a.uri)?.value("serial")
        let serialB = PKCS11URI.parse(b.uri)?.value("serial")
        if let serialA, let serialB { return serialA == serialB }
        return !a.label.isEmpty && a.label == b.label
    }
}

// MARK: - Watching a connect attempt

/// The state machine that turns `openconnect`'s output into ONE actionable sentence.
///
/// Every string it matches is a literal from OpenConnect's own `gnutls.c` (checked
/// against master), which is the only reason this can be more specific than
/// "smartcard error": OpenConnect distinguishes "no such certificate", "no such
/// key", "wrong PIN" and "final try before locking" itself, and throws all four at
/// stderr. Pure and `mutating`, so `PKCS11WatcherTests` drives all of it — including
/// every failure mode — line by line with no process anywhere.
nonisolated struct PKCS11ConnectWatcher: Sendable, Equatable {

    /// The pre-flight token reading, when there was one. It is what turns "that PIN
    /// was refused" into "that PIN was refused, and one attempt remains".
    var tokenStatus: PKCS11TokenStatus?
    /// Whether a PIN was handed to the tool at all. Distinguishes "you didn't give
    /// me a PIN" from "the PIN you gave me was refused".
    var pinSupplied = false

    private(set) var certificateLoaded = false
    private(set) var keyLoaded = false
    private(set) var pinPromptSeen = false
    private(set) var failure: PKCS11Failure?
    /// A non-fatal caution worth showing even on a successful connect (a certificate
    /// about to expire, a PIN counter running down).
    private(set) var caution: String?
    /// Set when the tool asked for something we deliberately could not answer.
    private(set) var unansweredPrompt = false

    /// Whether the token's own material was read successfully — the fact that lets
    /// an otherwise-opaque sign-in failure be attributed to the SERVER.
    var materialLoaded: Bool { certificateLoaded && keyLoaded }

    mutating func observe(_ line: String) {
        func has(_ needle: String) -> Bool { line.contains(needle) }

        // Progress markers first: they change what a later failure MEANS.
        if has("Using PKCS#11 certificate") { certificateLoaded = true }
        if has("Using PKCS#11 key") { keyLoaded = true }
        if has("PIN required for") { pinPromptSeen = true }

        // PIN-counter cautions. These are OpenConnect's rendering of the token's own
        // CKF_USER_PIN_COUNT_LOW / CKF_USER_PIN_FINAL_TRY flags, so they are the
        // token talking, not a guess.
        if has("final try before locking") {
            caution = "The token reports this was its FINAL PIN attempt — one more wrong PIN locks it."
            var status = tokenStatus ?? PKCS11TokenStatus()
            status.pinFinalTry = true
            tokenStatus = status
        } else if has("tries left before locking") {
            caution = "The token reports only a few PIN attempts left before it locks."
            var status = tokenStatus ?? PKCS11TokenStatus()
            status.pinCountLow = true
            tokenStatus = status
        }

        // Failures, most specific first. `failure` is set once: the FIRST diagnosis
        // is the true one, and what follows is fallout.
        guard failure == nil else { return }
        if has("built without PKCS#11 support") {
            failure = .toolLacksPKCS11Support
        } else if has("Wrong PIN") {
            failure = .pinWrong(remaining: tokenStatus)
        } else if has("Client certificate has expired at") {
            failure = .certificateExpired(when: Self.trailingDate(in: line))
        } else if has("Error loading certificate from PKCS#11")
                    || has("PKCS#11 file contained no certificate")
                    || has("Setting PKCS#11 certificate failed") {
            failure = .certificateNotFound
        } else if has("Error importing PKCS#11 URL")
                    || has("Error initialising PKCS#11 key structure")
                    || has("Error importing PKCS#11 key into private key structure") {
            failure = .keyNotFound
        } else if has("User input required in non-interactive mode") {
            unansweredPrompt = true
            if pinPromptSeen && !pinSupplied {
                failure = .pinRequired
            }
        } else if has("Client certificate expires soon at") {
            caution = "The certificate on this token expires soon — ask for a replacement before it does."
        }
    }

    /// The sentence to show when the tool has exited without connecting, or nil to
    /// leave the caller's generic message in place.
    ///
    /// The last rule is the useful one: material loaded, no PIN complaint, and still
    /// no tunnel means the token did its job and the GATEWAY said no — which is a
    /// completely different conversation ("ask your administrator to enrol this
    /// certificate") from anything about the hardware.
    func failureMessage() -> String? {
        if let failure { return failure.message }
        if materialLoaded, unansweredPrompt {
            return "The token's certificate was accepted but the gateway then asked for something else (a password or a verification code). Add it under Sign-In, or ask your administrator whether this gateway allows certificate-only sign-in."
        }
        if materialLoaded {
            return PKCS11Failure.serverRejectedCertificate.message
        }
        if certificateLoaded, !keyLoaded {
            return PKCS11Failure.keyNotFound.message
        }
        return nil
    }

    /// "Client certificate has expired at 2026-01-04 09:00:00" → the date part.
    static func trailingDate(in line: String) -> String? {
        guard let marker = line.range(of: "expired at ") else { return nil }
        let tail = line[marker.upperBound...].trimmingCharacters(in: .whitespacesAndNewlines)
        return tail.isEmpty ? nil : tail
    }
}

// MARK: - Composing the two, for the UI

/// What the editor needs to know in one value: which modules exist, which tools can
/// read them, and what the chosen module currently sees.
nonisolated struct PKCS11Survey: Sendable, Equatable {
    var modules: [PKCS11Module] = []
    var toolsAvailable = false
    /// nil until a token has been looked for.
    var tokens: [PKCS11TokenStatus]?
    var certificates: [PKCS11Certificate]?
    var failure: PKCS11Failure?

    var hasModule: Bool { !modules.isEmpty }
}
