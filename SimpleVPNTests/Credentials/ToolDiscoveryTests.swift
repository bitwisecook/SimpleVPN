// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
//  ToolDiscoveryTests.swift
//  The discovery/execution split, pinned — and pinned as the LIES it must prevent,
//  because every one of them is a sentence a user could otherwise be shown:
//
//   1. "bw isn't installed" when it is sitting in ~/.bun/bin.
//   2. "keeper isn't installed" when it is on $PATH.
//   3. "keepassxc-cli isn't installed" when the app that contains it is.
//   4. …and the converse, which is the security half: a binary discovery reports
//      must NOT thereby become one execution will run. Discovery searching a
//      directory is not permission to run from it, and a world-writable directory
//      is refused even when the user names it explicitly.
//
//  Only 1Password is installed on this machine, so a live probe could never cover
//  any of this. Instead each test builds a SYNTHESISED filesystem in a temporary
//  directory — one directory per location class, a world-writable one, an app
//  bundle with a CLI inside it, and a PATH-only entry — and points a
//  `ToolDiscoveryEnvironment` at it. Everything asserted here is therefore
//  reproducible on a machine with no password manager at all.
//

import Foundation
import Testing
@testable import SimpleVPN

// MARK: - The synthesised Mac

/// A throwaway filesystem laid out like a real Mac's install locations, so
/// discovery can be exercised without any of these tools existing.
private final class FakeMac {

    let root: URL
    let home: URL
    var environment: [String: String] = [:]
    var explicitPaths: [String: String] = [:]

    init() throws {
        root = URL(fileURLWithPath: NSTemporaryDirectory())
            .appendingPathComponent("tool-discovery-\(UUID().uuidString)")
        home = root.appendingPathComponent("Users/tester")
        try FileManager.default.createDirectory(at: home, withIntermediateDirectories: true)
    }

    deinit { try? FileManager.default.removeItem(at: root) }

    /// An absolute path inside the fake root, e.g. `dir("opt/homebrew/bin")`.
    func dir(_ relative: String) -> String {
        root.appendingPathComponent(relative).path
    }

    /// Create a directory with an explicit mode. `0o777` is how a world-writable
    /// directory is synthesised — the case that must be refused.
    @discardableResult
    func makeDirectory(_ relative: String, mode: mode_t = 0o755) throws -> String {
        let path = dir(relative)
        try FileManager.default.createDirectory(
            atPath: path, withIntermediateDirectories: true,
            attributes: [.posixPermissions: NSNumber(value: mode)])
        // createDirectory applies the mode to the leaf only when it creates it, so
        // set it explicitly — an intermediate that already existed keeps its own.
        chmod(path, mode)
        return path
    }

    /// Drop an executable "binary" (a tiny script — nothing is ever run) at
    /// `<dir>/<name>`.
    @discardableResult
    func makeExecutable(_ name: String, in relativeDir: String,
                        directoryMode: mode_t = 0o755) throws -> String {
        let dirPath = try makeDirectory(relativeDir, mode: directoryMode)
        let path = (dirPath as NSString).appendingPathComponent(name)
        try Data("#!/bin/sh\nexit 0\n".utf8).write(to: URL(fileURLWithPath: path))
        chmod(path, 0o755)
        // Setting the directory mode again: writing into it doesn't change it, but
        // an intermediate created by an earlier call may have been 0o755.
        chmod(dirPath, directoryMode)
        return path
    }

    /// A file that exists but isn't executable.
    @discardableResult
    func makeNonExecutable(_ name: String, in relativeDir: String) throws -> String {
        let dirPath = try makeDirectory(relativeDir)
        let path = (dirPath as NSString).appendingPathComponent(name)
        try Data("not a program".utf8).write(to: URL(fileURLWithPath: path))
        chmod(path, 0o644)
        return path
    }

    /// A CLI shipped inside an application bundle —
    /// `<apps>/KeePassXC.app/Contents/MacOS/keepassxc-cli`.
    @discardableResult
    func makeBundledCLI(app: String, executable: String,
                        inAppsDir appsDir: String = "Applications") throws -> String {
        try makeExecutable(executable, in: "\(appsDir)/\(app)/Contents/MacOS")
    }

    /// The discovery environment for this fake Mac. `systemDirectories` is
    /// overridden so nothing on the real machine can influence the result.
    func discoveryEnvironment(systemDirectories: [String] = [],
                              applicationDirectories: [String]? = nil) -> ToolDiscoveryEnvironment {
        let explicit = explicitPaths
        return ToolDiscoveryEnvironment(
            home: home,
            environment: environment,
            systemDirectories: systemDirectories,
            applicationDirectories: applicationDirectories ?? [dir("Applications")],
            userConfiguredPath: { explicit[$0] })
    }
}

// MARK: - The candidate table (pure — no filesystem at all)

struct ToolDiscoveryCandidateTests {

    private func classes(_ candidates: [ToolDiscovery.Candidate]) -> Set<ToolLocationClass> {
        Set(candidates.map(\.locationClass))
    }

    /// Every location class the brief names is really searched. A class that exists
    /// in the enum but never appears in the table is a location we claim to cover
    /// and don't — which is exactly the kind of quiet gap this whole feature is
    /// about.
    @Test func everyPackageManagerLocationIsSearched() {
        let env = ToolDiscoveryEnvironment(
            home: URL(fileURLWithPath: "/Users/tester"),
            environment: ["HOMEBREW_PREFIX": "/opt/brew",
                          "GOBIN": "/Users/tester/gobin",
                          "PATH": "/usr/bin:/somewhere/odd"],
            systemDirectories: LocalToolRunner.systemDirectories)
        let found = classes(ToolDiscovery.candidateDirectories(env))
        for expected: ToolLocationClass in [
            .homebrewAppleSilicon, .homebrewIntel, .homebrewCustomPrefix, .macPorts,
            .systemBin, .pipx, .pipUser, .npmGlobal, .bun, .volta, .pnpm, .yarn,
            .goBin, .cargo, .miseShim, .asdfShim, .nixProfile,
        ] {
            #expect(found.contains(expected), "no candidate directory for \(expected)")
        }
    }

    /// Both Homebrew prefixes, always — an Apple-silicon-only list would fail to
    /// find a correctly installed tool on an Intel Mac, and vice versa.
    @Test func bothHomebrewPrefixesAreSearched() {
        let env = ToolDiscoveryEnvironment(home: URL(fileURLWithPath: "/Users/tester"))
        let dirs = ToolDiscovery.candidateDirectories(env).map(\.directory)
        #expect(dirs.contains("/opt/homebrew/bin"))
        #expect(dirs.contains("/usr/local/bin"))
        #expect(dirs.contains("/opt/local/bin"))
    }

    /// A relocated Homebrew is found through the variable `brew shellenv` exports.
    @Test func aRelocatedHomebrewIsFound() {
        let env = ToolDiscoveryEnvironment(
            home: URL(fileURLWithPath: "/Users/tester"),
            environment: ["HOMEBREW_PREFIX": "/opt/brew"])
        let dirs = ToolDiscovery.candidateDirectories(env).map(\.directory)
        #expect(dirs.contains("/opt/brew/bin"))
    }

    /// `$PATH` is a discovery input and never an execution one. Both halves of that
    /// sentence are asserted, because the whole design rests on them.
    @Test func pathIsADiscoveryInputOnly() {
        let env = ToolDiscoveryEnvironment(
            home: URL(fileURLWithPath: "/Users/tester"),
            environment: ["PATH": "/somewhere/odd:/another/place"])
        let pathDirs = ToolDiscovery.pathCandidates(env).map(\.directory)
        #expect(pathDirs.contains("/somewhere/odd"))
        #expect(pathDirs.contains("/another/place"))
        // …and nothing from PATH is in the execution allow-list.
        let runnable = Set(LocalToolRunner.searchDirectories(
            home: URL(fileURLWithPath: "/Users/tester")))
        #expect(!runnable.contains("/somewhere/odd"))
        #expect(!runnable.contains("/another/place"))
    }

    /// A `PATH` entry that is relative — or the bare `.` — is not a place, and must
    /// not be reported as one.
    @Test func relativePathEntriesAreDropped() {
        let env = ToolDiscoveryEnvironment(
            home: URL(fileURLWithPath: "/Users/tester"),
            environment: ["PATH": ".:relative/bin:/absolute/bin"])
        let dirs = ToolDiscovery.pathCandidates(env).map(\.directory)
        #expect(dirs == ["/absolute/bin"])
    }
}

// MARK: - Discovery over a synthesised filesystem

struct ToolDiscoveryFilesystemTests {

    private let bw = DiscoverableTool(name: "bw", title: "Bitwarden CLI", vendor: nil)

    // MARK: The four lies

    /// LIE 1: "not installed", when it is in `~/.bun/bin`.
    ///
    /// Bun's directory is not on the execution allow-list, so `locate` says nothing
    /// — and that is correct. What must NOT happen is the tool being reported absent.
    @Test func aToolInBunsDirectoryIsFoundButNotRunnable() throws {
        let mac = try FakeMac()
        let path = try mac.makeExecutable("bw", in: "Users/tester/.bun/bin")
        let found = ToolDiscovery.discover(bw, env: mac.discoveryEnvironment())

        #expect(found.isFound, "a tool in ~/.bun/bin must never be reported as absent")
        #expect(found.paths.map(\.path).contains(path))
        #expect(found.paths.first(where: { $0.path == path })?.locationClass == .bun)
        #expect(found.paths.first(where: { $0.path == path })?.usability == .outsideAllowList)
        // Nothing runnable — the honest state, and the one the new availability
        // reason exists for.
        #expect(found.isFoundButUnusable)
        // And it is CHOOSABLE: setting it explicitly is the sanctioned way out.
        #expect(found.suggestedPath == path)
    }

    /// LIE 2: "not installed", when it is only on `$PATH`.
    @Test func aToolOnlyOnPathIsFoundButNotRunnable() throws {
        let mac = try FakeMac()
        let path = try mac.makeExecutable("bw", in: "opt/odd/bin")
        mac.environment["PATH"] = "\(mac.dir("opt/odd/bin")):/usr/bin"
        let found = ToolDiscovery.discover(bw, env: mac.discoveryEnvironment())

        #expect(found.isFound)
        let hit = try #require(found.paths.first { $0.path == path })
        #expect(hit.locationClass == .pathEntry)
        #expect(hit.usability == .outsideAllowList)
        #expect(found.isFoundButUnusable)
    }

    /// LIE 3: "not installed", when the app that CONTAINS it is.
    ///
    /// `keepassxc-cli` ships inside `/Applications/KeePassXC.app/Contents/MacOS/`,
    /// so "the app is installed" already means "the CLI is available". A discovery
    /// map that misses the class of CLIs shipped inside bundles is wrong about a
    /// vendor we support.
    @Test func aCLIInsideAnAppBundleIsFound() throws {
        let mac = try FakeMac()
        let path = try mac.makeBundledCLI(app: "KeePassXC.app", executable: "keepassxc-cli")
        let tool = try #require(ToolCatalog.tool(named: "keepassxc-cli"))
        let found = ToolDiscovery.discover(tool, env: mac.discoveryEnvironment())

        #expect(found.isFound, "a CLI inside an installed app must never read as absent")
        let hit = try #require(found.paths.first { $0.path == path })
        #expect(hit.locationClass == .appBundle)
    }

    /// The catalogue really declares the bundled CLIs, not just the machinery for
    /// them — including the second one, YubiKey Manager's, which is just as easy to
    /// miss.
    @Test func theCatalogueDeclaresTheAppBundledCLIs() throws {
        let keepass = try #require(ToolCatalog.tool(named: "keepassxc-cli"))
        #expect(keepass.bundledCLIs.contains {
            $0.appBundleName == "KeePassXC.app"
                && $0.relativePath == "Contents/MacOS/keepassxc-cli"
        })
        let ykman = try #require(ToolCatalog.tool(named: "ykman"))
        #expect(ykman.bundledCLIs.contains {
            $0.appBundleName == "YubiKey Manager.app"
        })
    }

    /// LIE 4, the security one: DISCOVERY REPORTING A PATH IS NOT PERMISSION TO RUN
    /// IT. A world-writable directory means anyone using this Mac can replace the
    /// program between the check and the run, so it is refused — reported, named,
    /// explained, and refused.
    @Test func aWorldWritableDirectoryIsReportedAndRefused() throws {
        let mac = try FakeMac()
        let path = try mac.makeExecutable("bw", in: "tmp/open", directoryMode: 0o777)
        mac.environment["PATH"] = mac.dir("tmp/open")
        let found = ToolDiscovery.discover(bw, env: mac.discoveryEnvironment())

        let hit = try #require(found.paths.first { $0.path == path })
        #expect(hit.usability == .unsafeDirectory)
        #expect(!hit.usability.isRunnableIfChosen,
                "a world-writable directory must not be offered as something to choose")
        #expect(found.chosen == nil)
        // The execution side agrees, independently.
        #expect(!LocalToolRunner.isSafeExecutable(atPath: path))
    }

    /// …and it stays refused when the user names it explicitly. This is the ONE
    /// limit on the escape hatch, and it has to be a limit rather than a warning.
    @Test func anExplicitPathCannotBuyPastAWorldWritableDirectory() throws {
        let mac = try FakeMac()
        let path = try mac.makeExecutable("bw", in: "tmp/open", directoryMode: 0o777)
        mac.explicitPaths["bw"] = path
        let found = ToolDiscovery.discover(bw, env: mac.discoveryEnvironment())

        // Reported — a broken explicit path is the most useful thing to show.
        let hit = try #require(found.paths.first { $0.path == path })
        #expect(hit.locationClass == .userConfigured)
        #expect(hit.usability == .unsafeDirectory)
        #expect(found.chosen == nil, "an explicit path must not override the safety rule")
    }

    // MARK: The escape hatch, working

    /// An explicit path in a SAFE directory is runnable wherever it lives — that is
    /// the whole point of the setting.
    @Test func anExplicitPathInASafeDirectoryIsRunnable() throws {
        let mac = try FakeMac()
        let path = try mac.makeExecutable("bw", in: "Users/tester/.bun/bin")
        mac.explicitPaths["bw"] = path
        let env = mac.discoveryEnvironment()

        let usability = ToolDiscovery.classify(
            path: path, tool: "bw", env: env,
            runnerDirectories: Set(LocalToolRunner.searchDirectories(home: mac.home)))
        #expect(usability == .runnable)
    }

    // MARK: Reporting

    /// A file that exists but isn't a program is reported as such rather than as a
    /// working install.
    @Test func aNonExecutableFileIsReportedAsNotAProgram() throws {
        let mac = try FakeMac()
        let path = try mac.makeNonExecutable("bw", in: "Users/tester/.local/bin")
        let found = ToolDiscovery.discover(bw, env: mac.discoveryEnvironment())
        let hit = try #require(found.paths.first { $0.path == path })
        #expect(hit.usability == .notExecutable)
    }

    /// EVERY path is reported, not just the first — the brief asks for all of them,
    /// and a second copy in a different package manager is precisely the thing that
    /// explains a version mismatch.
    @Test func everyCopyIsReported() throws {
        let mac = try FakeMac()
        let bun = try mac.makeExecutable("bw", in: "Users/tester/.bun/bin")
        let cargo = try mac.makeExecutable("bw", in: "Users/tester/.cargo/bin")
        let go = try mac.makeExecutable("bw", in: "Users/tester/go/bin")
        let found = ToolDiscovery.discover(bw, env: mac.discoveryEnvironment())

        let paths = Set(found.paths.map(\.path))
        #expect(paths.isSuperset(of: [bun, cargo, go]))
        #expect(found.paths.count >= 3)
    }

    /// The same directory reached two ways (a class candidate and a `PATH` entry)
    /// is one hit, not two — a duplicated row reads as two installs.
    @Test func theSamePathIsNotReportedTwice() throws {
        let mac = try FakeMac()
        let path = try mac.makeExecutable("bw", in: "Users/tester/.cargo/bin")
        mac.environment["PATH"] = mac.dir("Users/tester/.cargo/bin")
        let found = ToolDiscovery.discover(bw, env: mac.discoveryEnvironment())
        #expect(found.paths.filter { $0.path == path }.count == 1)
    }

    /// A tool that genuinely isn't there says so — the honest "absent", which only
    /// means anything because the other cases are distinguished from it.
    @Test func anAbsentToolIsAbsent() throws {
        let mac = try FakeMac()
        let found = ToolDiscovery.discover(bw, env: mac.discoveryEnvironment())
        #expect(!found.isFound)
        #expect(found.chosen == nil)
        #expect(!found.isFoundButUnusable, "absent is not the same as found-and-unusable")
        #expect(found.summaryLine == "bw=absent")
    }

    // MARK: Versions

    /// A version is NEVER guessed, and never obtained by running something we
    /// wouldn't otherwise run. A tool outside the allow-list reports "unknown" WITH
    /// a reason — because running a binary found on `PATH` in order to describe it
    /// would hand that binary exactly the execution the allow-list exists to deny.
    @Test func aToolWeWontRunHasAnUnknownVersionWithAReason() throws {
        let mac = try FakeMac()
        try mac.makeExecutable("bw", in: "Users/tester/.bun/bin")
        let found = ToolDiscovery.discover(bw, env: mac.discoveryEnvironment())

        #expect(!found.version.isKnown)
        guard case .unknown(let why) = found.version else {
            Issue.record("expected an unknown version with a reason")
            return
        }
        #expect(!why.isEmpty)
        #expect(found.version.displayValue == "version unknown")
    }

    /// The version probe refuses outright for a path the allow-list declined —
    /// asserted at the probe, not only at the reporting layer, so no future caller
    /// can reach past it.
    @Test func theVersionProbeRefusesAPathOutsideTheAllowList() async throws {
        let mac = try FakeMac()
        try mac.makeExecutable("bw", in: "Users/tester/.bun/bin")
        let found = ToolDiscovery.discover(bw, env: mac.discoveryEnvironment())
        let version = await ToolDiscovery.probeVersion(bw, discovered: found)
        #expect(!version.isKnown)
    }

    /// A version is measured ONCE per path, not once per pass.
    ///
    /// `recheckIfDue` runs the deep pass every fifteen seconds while a vendor is
    /// waiting on the user, and the discovery map is re-derived every five. Without a
    /// carry-forward that meant re-spawning the whole catalogue for numbers that
    /// cannot have changed — a dozen processes a minute, one of them a Python
    /// interpreter. `versionProbed` is what settles it, and it has to survive a
    /// re-scan.
    @Test func aMeasuredVersionSurvivesARescan() throws {
        let mac = try FakeMac()
        // A path the runner accepts, by naming it explicitly.
        let path = try mac.makeExecutable("bw", in: "Users/tester/.cargo/bin")
        mac.explicitPaths["bw"] = path
        let env = mac.discoveryEnvironment()

        var entry = ToolDiscovery.discover(bw, env: env)
        #expect(!entry.versionProbed, "a fresh discovery has asked nothing")

        // Simulate what the deep pass records — INCLUDING a failure, which is a
        // settled answer too and must not be retried for ever.
        entry.version = .unknown(why: "it didn\u{2019}t answer \u{201C}--version\u{201D}")
        entry.versionProbed = true
        #expect(!entry.version.isKnown)
        #expect(entry.versionProbed,
                "a failed probe is an answer; treating it as outstanding re-spawns for ever")
    }

    /// And `LocalToolRunner` itself refuses to execute a path from a location
    /// discovery merely reported. The other side of the same guarantee.
    @Test func theRunnerRefusesWhatDiscoveryMerelyReports() async throws {
        let mac = try FakeMac()
        let path = try mac.makeExecutable("bw", in: "tmp/open", directoryMode: 0o777)
        let result = await LocalToolRunner.run(executable: path, arguments: ["--version"])
        #expect(!result.succeeded)
        #expect(result.stderr == "not an approved tool location")
    }
}

// MARK: - The catalogue itself

struct ToolCatalogTests {

    /// Tool names are unique — the map is keyed by name, so a duplicate would
    /// silently hide one entry.
    @Test func toolNamesAreUnique() {
        let names = ToolCatalog.all.map(\.name)
        #expect(Set(names).count == names.count)
    }

    /// Proton Pass's tool is `pass-cli`, and `pass` is password-store. Two
    /// different products; conflating them would read the wrong vault.
    @Test func protonPassAndPasswordStoreAreDistinctTools() {
        let names = Set(ToolCatalog.all.map(\.name))
        #expect(names.contains("pass"))
        #expect(names.contains("pass-cli"))
    }

    /// Vendors whose tool we can't yet read are still in the catalogue. "We don't
    /// support Bitwarden" and "Bitwarden's own tool is right here" are different
    /// facts, and only the second is useful in a bug report.
    @Test func vendorsWithoutAnAdapterAreStillDiscovered() {
        let names = Set(ToolCatalog.all.map(\.name))
        for tool in ["bw", "dcli", "lpass", "pass", "gopass", "vault"] {
            #expect(names.contains(tool), "\(tool) isn't in the discovery catalogue")
        }
    }

    /// Every vendor with a CLI-shaped channel has a tool that pre-fills its path
    /// field, so the Settings pane can never show a field with no possible
    /// detection behind it.
    @Test func everyToolPathFieldHasADiscoverableTool() {
        for field in SignInSourceSettings.allFields {
            guard let tool = field.kind.detectionTool else { continue }
            #expect(ToolCatalog.tool(named: tool) != nil,
                    "\(field.settingID) pre-fills from \(tool), which isn't in the catalogue")
        }
    }
}
