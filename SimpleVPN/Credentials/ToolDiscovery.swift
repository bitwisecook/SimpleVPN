// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
//  ToolDiscovery.swift
//  WHERE a vendor's command-line tool actually is on this Mac — as opposed to
//  where SimpleVPN is willing to RUN one from. Those are two different questions
//  and this file exists because conflating them produces a lie.
//
//  THE SPLIT, and it is the whole design:
//
//   • EXECUTION — `LocalToolRunner`. An allow-list of documented install
//     directories, `PATH` never consulted, world-writable directories refused.
//     That is a security control: a user-writable `PATH` entry must never decide
//     which binary this app hands a password request to. NOTHING HERE WEAKENS IT.
//     Discovery does not resolve what we execute; `LocalToolRunner.locate` still
//     does, and this file asks IT rather than re-implementing the rules.
//
//   • DISCOVERY — this file. Searches WIDELY: every install location any
//     mainstream package manager, version manager or vendor installer uses on
//     macOS, plus `PATH`, plus CLIs that ship inside application bundles — and
//     deliberately including places we would refuse to execute from.
//
//  The gap between the two is not a bug, it is the product. "Bitwarden's `bw`
//  isn't installed" is a LIE when `bw` is sitting in `~/.bun/bin`; the honest
//  sentence is "found at ~/.bun/bin/bw, but not somewhere SimpleVPN will run from
//  — set an explicit path, or install it with Homebrew." That state has a name
//  (`LocalVaultBlock.toolOutsideAllowList`) and the enablement banner can say it.
//
//  TWO HARD RULES FOR DISCOVERY ITSELF:
//
//   1. IT READS THE FILESYSTEM AND NOTHING ELSE. `stat`, and the odd `Info.plist`
//      for an app bundle. It NEVER executes a binary to learn its version —
//      executing something found on `PATH` in order to describe it would hand the
//      exact attacker-influenceable path we refuse for credentials a free run
//      instead. Versions are probed only for a binary the execution allow-list
//      already accepts (`probeVersion`), and everything else reports
//      `.unknown(why:)` rather than guessing.
//   2. IT IS LOCAL AND SILENT. No network, no prompts, no vendor dialogs, nothing
//      written anywhere. It is therefore on by default (see
//      `SignInSourceSettings.discoveryEnabled` for the master switch), because a
//      detection feature that defaults to not detecting is inert. Putting the
//      results in a SUBMITTED diagnostic report is a separate, per-submission
//      opt-in that belongs to the report flow, not to this file.
//
//  The location table is researched from each vendor's own installation guide and
//  from each package manager's own documentation — see `Docs/ToolDiscovery.md`,
//  which carries the source link for every row. Guesses are not welcome here: a
//  path we invented, presented as a documented one, sends people looking in the
//  wrong place.
//

import Foundation
import os

// MARK: - What kind of place a hit came from

/// The CLASS of install location a path belongs to. Reported per hit because
/// "found in `~/.bun/bin`" and "found in `/opt/homebrew/bin`" mean completely
/// different things to the user: one is a note, the other is a fix.
///
/// Ordering is discovery preference — earlier classes are the ones the vendors
/// document, later ones are the ones we merely recognise.
nonisolated enum ToolLocationClass: String, CaseIterable, Sendable, Hashable {
    /// A path the user typed into Settings. Always searched first, always wins.
    case userConfigured
    /// Homebrew's Apple-silicon default prefix (`/opt/homebrew`).
    case homebrewAppleSilicon
    /// Homebrew's Intel default prefix (`/usr/local`), and where most vendor
    /// `.pkg` installers land too.
    case homebrewIntel
    /// `$HOMEBREW_PREFIX` when the user has relocated Homebrew.
    case homebrewCustomPrefix
    /// MacPorts (`/opt/local/bin`).
    case macPorts
    /// macOS's own directories.
    case systemBin
    /// A CLI shipped INSIDE an application bundle. Easy to miss, and it means
    /// "the app is installed" can already mean "the CLI is available" —
    /// `keepassxc-cli` is the canonical case.
    case appBundle
    /// A location a vendor's own standalone installer documents.
    case vendorInstaller
    /// `~/.local/bin` — pipx's default `PIPX_BIN_DIR`, and also where several
    /// vendors' own `install.sh` scripts prefer to land (Proton Pass's does).
    case pipx
    /// `pip install --user` with a framework Python (`~/Library/Python/3.x/bin`).
    case pipUser
    /// npm's global prefix.
    case npmGlobal
    /// nvm's per-version bin directories.
    case nvm
    /// Bun (`~/.bun/bin`).
    case bun
    /// Volta (`~/.volta/bin`).
    case volta
    /// pnpm's global bin directory.
    case pnpm
    /// Yarn's global bin directory.
    case yarn
    /// Go (`$GOBIN`, else `$GOPATH/bin`, else `~/go/bin`).
    case goBin
    /// Cargo (`~/.cargo/bin`).
    case cargo
    /// mise's shim directory.
    case miseShim
    /// asdf's shim directory.
    case asdfShim
    /// A Nix profile.
    case nixProfile
    // NOTE: there is deliberately no PKCS#11 case. `ControlPlane/PKCS11Discovery`
    // owns that, and it answers something this file cannot — whether a module is
    // merely installed or is REGISTERED with p11-kit, which is what decides whether
    // it can be loaded at all. A shorter, dumber list here would be a second answer
    // to one question. See Docs/ToolDiscovery.md.
    /// Found ONLY by walking `$PATH`, in a directory none of the classes above
    /// describes. The most interesting class and the least trustworthy one.
    case pathEntry

    /// What a user is told this place is. Plain language, no jargon: someone who
    /// has never heard of pipx still has to understand the sentence.
    var title: String {
        switch self {
        case .userConfigured: "the path you set"
        case .homebrewAppleSilicon: "Homebrew"
        case .homebrewIntel: "Homebrew (Intel) or a vendor installer"
        case .homebrewCustomPrefix: "your relocated Homebrew"
        case .macPorts: "MacPorts"
        case .systemBin: "macOS itself"
        case .appBundle: "inside the app"
        case .vendorInstaller: "the vendor\u{2019}s own installer"
        case .pipx: "pipx, or an installer script"
        case .pipUser: "a per-user Python install"
        case .npmGlobal: "npm"
        case .nvm: "nvm"
        case .bun: "Bun"
        case .volta: "Volta"
        case .pnpm: "pnpm"
        case .yarn: "Yarn"
        case .goBin: "Go"
        case .cargo: "Cargo"
        case .miseShim: "mise"
        case .asdfShim: "asdf"
        case .nixProfile: "Nix"
        case .pathEntry: "your shell\u{2019}s search path"
        }
    }
}

// MARK: - One hit

/// Why a path we FOUND is, or is not, one SimpleVPN would run.
///
/// The distinction that matters: `.outsideAllowList` is not a fault. It is a
/// place we do not search automatically, and pointing at it explicitly is the
/// sanctioned way to use it. `.unsafeDirectory` IS a fault, and stays one even
/// when the user asks for it by name — a world-writable directory means anyone
/// on the Mac chooses what we execute, which is the whole reason the check
/// exists.
nonisolated enum ToolUsability: Sendable, Equatable {
    /// The execution allow-list already accepts this path.
    case runnable
    /// A real executable, in a safe directory, that the allow-list does not
    /// search. Setting it explicitly in Settings makes it runnable.
    case outsideAllowList
    /// Refused, and refused even if set explicitly: the directory is writable by
    /// the world (or by a group that isn't `admin`).
    case unsafeDirectory
    /// The file is there but is not a regular executable file.
    case notExecutable

    /// Would SimpleVPN run this as things stand?
    var isRunnableNow: Bool { self == .runnable }
    /// Could the user make this runnable by setting it explicitly?
    var isRunnableIfChosen: Bool { self == .runnable || self == .outsideAllowList }
}

/// One place a tool was found.
nonisolated struct DiscoveredPath: Sendable, Equatable, Identifiable {
    var path: String
    var locationClass: ToolLocationClass
    var usability: ToolUsability

    var id: String { path }

    /// One sentence: where it is, what put it there, and whether we would use it.
    var explanation: String {
        switch usability {
        case .runnable:
            "\(path) \u{2014} from \(locationClass.title). SimpleVPN will run this."
        case .outsideAllowList:
            "\(path) \u{2014} from \(locationClass.title). SimpleVPN doesn\u{2019}t look here on "
            + "its own; set this as the tool\u{2019}s path to use it."
        case .unsafeDirectory:
            "\(path) \u{2014} from \(locationClass.title). SimpleVPN won\u{2019}t run this: anyone "
            + "using this Mac can replace files in that folder."
        case .notExecutable:
            "\(path) \u{2014} from \(locationClass.title). Not a program SimpleVPN can run."
        }
    }
}

/// A tool's version, or an honest account of why we don't know it.
nonisolated enum ToolVersion: Sendable, Equatable {
    case known(String)
    /// Never a guess and never a blank: the reason is shown.
    case unknown(why: String)

    var displayValue: String {
        switch self {
        case .known(let v): v
        case .unknown: "version unknown"
        }
    }
    var isKnown: Bool { if case .known = self { true } else { false } }
}

/// The whole answer for one tool: found or not, EVERY path, which one we would
/// use, and its version when we are allowed to ask.
nonisolated struct DiscoveredTool: Sendable, Equatable, Identifiable {
    /// The binary's name (`bw`, `keeper`, `keepassxc-cli`).
    var tool: String
    /// Every hit, in discovery order, de-duplicated by resolved path.
    var paths: [DiscoveredPath] = []
    /// The path `LocalToolRunner.locate` would return — what we would actually
    /// execute. nil when nothing found is runnable.
    var chosen: String?
    var version: ToolVersion = .unknown(why: "not checked yet")
    /// Whether the version was actually MEASURED, as opposed to never asked for.
    ///
    /// Tracked separately from `version` because a failed probe also yields
    /// `.unknown(why:)` — and without this, a tool whose `--version` errors would be
    /// re-probed on every pass for ever. "We asked and it didn't answer" is a settled
    /// answer, not an outstanding question.
    var versionProbed = false

    var id: String { tool }

    var isFound: Bool { !paths.isEmpty }
    /// Found somewhere, but nowhere we would run from. THE state this file exists
    /// for: it must never be reported as "not installed".
    var isFoundButUnusable: Bool { isFound && chosen == nil }
    /// The hits the user could turn into a working setup by setting a path.
    var choosablePaths: [DiscoveredPath] { paths.filter { $0.usability.isRunnableIfChosen } }
    /// The best suggestion for the Settings field's pre-fill: what we would run,
    /// else the first hit the user could sanction.
    var suggestedPath: String? { chosen ?? choosablePaths.first?.path }

    /// One line for a diagnostic report or a log: paths and states only, never a
    /// secret (a path is not one) and never the contents of anything.
    var summaryLine: String {
        guard isFound else { return "\(tool)=absent" }
        let states = paths.map { "\($0.path)[\($0.usability)]" }.joined(separator: " ")
        return "\(tool)=\(chosen ?? "none-runnable") \(states) version=\(version.displayValue)"
    }
}

// MARK: - The environment discovery reads

/// Everything discovery derives its candidate directories from. Injectable
/// WHOLESALE so a test can synthesise a filesystem covering every location class
/// — including a world-writable directory that must be refused and a binary that
/// exists only on `PATH` — on a machine that has none of these tools installed.
nonisolated struct ToolDiscoveryEnvironment: Sendable {
    var home: URL
    /// The process environment. `PATH`, `HOMEBREW_PREFIX`, `GOBIN`, `GOPATH`,
    /// `BUN_INSTALL`, `VOLTA_HOME`, `PNPM_HOME`, `CARGO_HOME`, `NPM_CONFIG_PREFIX`
    /// and `MISE_DATA_DIR` are read from it — all of them documented by the tool
    /// that defines them.
    var environment: [String: String] = [:]
    /// The fixed system locations. Injectable so a fixture test never depends on
    /// what happens to be in `/usr/local/bin` on the machine running it.
    var systemDirectories: [String] = LocalToolRunner.systemDirectories
    /// Where application bundles are looked for, in order. Includes the Setapp
    /// subfolder and `/System/Applications` because a CLI can ship inside any of
    /// them.
    var applicationDirectories: [String] = []
    /// Where an explicitly-set path comes from. Injected as a closure rather than
    /// a `UserDefaults` so tests need no defaults domain.
    var userConfiguredPath: @Sendable (String) -> String? = { _ in nil }

    static func live(
        home: URL = FileManager.default.homeDirectoryForCurrentUser,
        environment: [String: String] = ProcessInfo.processInfo.environment,
        store: UserDefaults = .standard
    ) -> ToolDiscoveryEnvironment {
        // Snapshot the explicit paths NOW rather than capturing the defaults
        // object: `UserDefaults` isn't `Sendable`, and a discovery pass should in
        // any case see one consistent set of settings rather than values that could
        // change between the tools it looks at.
        let explicit: [String: String] = ToolCatalog.all.reduce(into: [:]) { out, tool in
            let raw = store.string(forKey: SignInSourceSettings.toolPathKey(tool.name))?
                .trimmingCharacters(in: .whitespaces) ?? ""
            if raw.hasPrefix("/") { out[tool.name] = raw }
        }
        return ToolDiscoveryEnvironment(
            home: home,
            environment: environment,
            systemDirectories: LocalToolRunner.systemDirectories,
            applicationDirectories: [
                "/Applications",
                "/Applications/Setapp",
                home.appendingPathComponent("Applications").path,
                "/System/Applications",
                "/System/Applications/Utilities",
            ],
            // The RAW setting, deliberately: `LocalToolRunner.userConfiguredPath`
            // returns nil for a path it would refuse, and a broken explicit path
            // is the single most useful thing to show someone whose working setup
            // stopped working. Classification still runs the runner's own safety
            // test, so reporting it here can never make it runnable.
            userConfiguredPath: { explicit[$0] })
    }
}

// MARK: - The catalogue of tools worth looking for

/// A CLI that ships inside an application bundle. `keepassxc-cli` is the reason
/// this type exists: it lives in `/Applications/KeePassXC.app/Contents/MacOS/`,
/// so a user who installed the app already has the CLI and telling them to
/// install one would be nonsense.
nonisolated struct BundledCLILocation: Sendable, Equatable {
    /// The bundle's name on disk, e.g. `KeePassXC.app`.
    var appBundleName: String
    /// The executable's path inside the bundle.
    var relativePath: String
}

/// A tool SimpleVPN looks for. Declarative: adding one is a row here, and it
/// immediately appears in the discovery map, the Settings pane's detection and
/// any diagnostic report — with no new branch anywhere.
nonisolated struct DiscoverableTool: Sendable, Equatable, Identifiable {
    /// The binary name searched for in every candidate directory.
    var name: String
    /// What to call it in a sentence.
    var title: String
    /// The vendor whose sign-in row it serves, when it serves one.
    var vendor: LocalVaultVendor?
    /// Absolute paths a vendor's own installer documents, beyond the generic
    /// package-manager classes. Sourced, per `Docs/ToolDiscovery.md`.
    var vendorInstallerPaths: [String] = []
    /// CLIs that ship inside an app bundle.
    var bundledCLIs: [BundledCLILocation] = []
    /// How to ask it for its version. Only ever run for a path the execution
    /// allow-list already accepts.
    var versionArguments: [String] = ["--version"]

    var id: String { name }
}

/// Every tool worth looking for, whether or not an adapter for it is built.
///
/// It covers tools we cannot yet READ from on purpose. A user's `bw` being
/// present is a true and useful fact — it is what turns "we don't support
/// Bitwarden" into "Bitwarden's tool is right here and an adapter is the only
/// missing piece", and it is what a maintainer needs in a bug report.
nonisolated enum ToolCatalog {

    static let all: [DiscoverableTool] = [
        // --- Vendors with an adapter today -------------------------------
        // Keeper Commander. Homebrew ships `keeper-commander`; Keeper's own guide
        // is `pip3 install --user` (→ ~/Library/Python/3.x/bin) or a venv. A venv
        // is by definition somewhere we cannot guess, which is exactly what the
        // explicit-path setting is for. NOTE: Keeper's standalone .pkg documents
        // its filename but not its install path, so no vendor path is asserted
        // here — a guessed path presented as documented is worse than none.
        DiscoverableTool(name: "keeper", title: "Keeper Commander", vendor: .keeper),
        // KeePassXC's CLI ships INSIDE the app, and the Homebrew cask additionally
        // symlinks it into the Homebrew bin directory. So "the app is installed"
        // already means "the CLI is available" — the class of fact that makes a
        // bare `locate` answer of "not installed" flatly wrong.
        //
        // It belongs to `.keePassFile`, NOT to `.keePassXC`. The KeePassXC row talks
        // to the RUNNING APP over its browser socket and needs no binary whatever;
        // the row that cannot work without this binary is the one that reads a
        // `.kdbx` file directly (and so also serves Strongbox and KeePassium). The
        // vendor recorded here is what decides which row gets told "found at …, but
        // not somewhere SimpleVPN will run it from", so pointing it at the socket row
        // would put that sentence on the one row it cannot help.
        DiscoverableTool(
            name: "keepassxc-cli", title: "KeePassXC command-line tool", vendor: .keePassFile,
            bundledCLIs: [
                .init(appBundleName: "KeePassXC.app", relativePath: "Contents/MacOS/keepassxc-cli"),
            ]),
        // 1Password's CLI. SimpleVPN does NOT read 1Password through it (that path
        // was retired in favour of the SDK's app IPC), but its presence and version
        // are worth reporting, and 1Password's own installers document
        // /usr/local/bin explicitly — an Intel-shaped path they give unconditionally.
        DiscoverableTool(
            name: "op", title: "1Password CLI", vendor: .onePassword,
            vendorInstallerPaths: ["/usr/local/bin/op"]),

        // Bitwarden's own tool. NO vendor installer path is asserted: npm's global
        // prefix is wherever the user's Node put it (the npm/nvm/Bun/Volta classes
        // above find those), and Bitwarden's standalone zip documents no destination
        // at all — "add the executable to your PATH", which is precisely the case
        // that produces `toolOutsideAllowList`. A guessed path presented as a
        // documented one would send people looking in the wrong place.
        DiscoverableTool(name: "bw", title: "Bitwarden CLI", vendor: .bitwarden),

        // Dashlane's own tool, and the whole of SimpleVPN's Dashlane read path — so
        // it names its vendor, which is what puts "found at …, but not somewhere
        // SimpleVPN will run it from" on the Dashlane row rather than nowhere.
        // Homebrew's tap (`brew install dashlane/tap/dashlane-cli`) lands in the
        // Homebrew bin directory; Dashlane's own manual-install instructions move the
        // standalone binary to /usr/local/bin/dcli verbatim; and its third documented
        // route is Yarn, which is precisely the case that produces
        // `toolOutsideAllowList`.
        DiscoverableTool(name: "dcli", title: "Dashlane CLI", vendor: .dashlane,
                         vendorInstallerPaths: ["/usr/local/bin/dcli"]),

        // --- Vendors on the seam, no adapter yet -------------------------
        // Reported anyway, on purpose: "we don't support LastPass" and "LastPass's
        // own tool is right here and an adapter is the only missing piece" are very
        // different facts, and the second is what a bug report needs.
        DiscoverableTool(name: "lpass", title: "LastPass CLI", vendor: nil),

        // GnuPG, and it BELONGS TO the password-store row — this is the tool that
        // actually does the decrypting, because SimpleVPN reads a `pass` store itself
        // rather than shelling to `pass`. Naming the vendor here is what puts "found
        // at …, but not somewhere SimpleVPN will run it from" on that row instead of
        // nowhere: without this entry, `toolFoundOutsideAllowList("gpg")` could never
        // fire and the store's `.toolOutsideAllowList` branch was unreachable code.
        // `gpg2` is the same program under the name some installs still use.
        DiscoverableTool(name: "gpg", title: "GnuPG", vendor: .passwordStore),
        DiscoverableTool(name: "gpg2", title: "GnuPG (gpg2)", vendor: .passwordStore),

        // `pass` and `gopass` themselves are reported but own NO vendor: the store is
        // read without them, so their absence blocks nothing and attributing a
        // "missing tool" state to them would be wrong. They are here because knowing
        // which one somebody uses is worth having in a report.
        DiscoverableTool(name: "pass", title: "pass (password-store)", vendor: nil),
        DiscoverableTool(name: "gopass", title: "gopass", vendor: nil),
        // Homebrew's formula is `go-passbolt-cli` but the BINARY it installs is
        // `passbolt`. Both names are searched: `go install` may produce the other.
        DiscoverableTool(name: "passbolt", title: "Passbolt CLI", vendor: nil),
        DiscoverableTool(name: "go-passbolt-cli", title: "Passbolt CLI (Go build)", vendor: nil),
        // Proton Pass's tool is `pass-cli`, deliberately not `pass` — the two are
        // different products and confusing them would read the wrong vault.
        DiscoverableTool(name: "pass-cli", title: "Proton Pass CLI", vendor: nil),
        DiscoverableTool(name: "vault", title: "HashiCorp Vault CLI", vendor: nil),
        // YubiKey Manager's CLI, which ALSO ships inside its app bundle at a path
        // Yubico publishes verbatim. Discovery only: what SimpleVPN does with a
        // YubiKey is not this file's business.
        DiscoverableTool(
            name: "ykman", title: "YubiKey Manager CLI", vendor: nil,
            bundledCLIs: [
                .init(appBundleName: "YubiKey Manager.app", relativePath: "Contents/MacOS/ykman"),
            ]),
    ]

    static func tool(named name: String) -> DiscoverableTool? {
        all.first { $0.name == name }
    }

    /// The tools that serve a vendor row, so the Settings pane can pre-fill a
    /// vendor's path field without knowing the catalogue's shape.
    static func tools(for vendor: LocalVaultVendor) -> [DiscoverableTool] {
        all.filter { $0.vendor == vendor }
    }
}

// MARK: - Discovery

nonisolated enum ToolDiscovery {

    private static let log = Logger(subsystem: "com.bragi0.SimpleVPN", category: "tool-discovery")

    // MARK: Candidate directories — pure, and the researched table

    /// One candidate directory and what put it there.
    nonisolated struct Candidate: Sendable, Equatable {
        var directory: String
        var locationClass: ToolLocationClass
    }

    /// Every directory discovery will look in, in order, de-duplicated. PURE:
    /// no filesystem access at all, so the table itself is unit-testable.
    ///
    /// The order is preference for REPORTING only. What we would execute is
    /// decided by `LocalToolRunner.locate`, never by this list.
    static func candidateDirectories(_ env: ToolDiscoveryEnvironment) -> [Candidate] {
        let home = env.home.path
        func h(_ suffix: String) -> String { (home as NSString).appendingPathComponent(suffix) }
        var out: [Candidate] = []
        func add(_ dir: String?, _ cls: ToolLocationClass) {
            guard let dir, !dir.isEmpty, dir.hasPrefix("/") else { return }
            let trimmed = dir.hasSuffix("/") && dir != "/" ? String(dir.dropLast()) : dir
            out.append(Candidate(directory: trimmed, locationClass: cls))
        }

        // --- Package managers, in the order their own docs describe -------
        add("/opt/homebrew/bin", .homebrewAppleSilicon)
        add("/opt/homebrew/sbin", .homebrewAppleSilicon)
        add("/usr/local/bin", .homebrewIntel)
        add("/usr/local/sbin", .homebrewIntel)
        // A relocated Homebrew. `brew shellenv` exports HOMEBREW_PREFIX, so this
        // is the documented way to find one.
        if let prefix = env.environment["HOMEBREW_PREFIX"] {
            add((prefix as NSString).appendingPathComponent("bin"), .homebrewCustomPrefix)
            add((prefix as NSString).appendingPathComponent("sbin"), .homebrewCustomPrefix)
        }
        add("/opt/local/bin", .macPorts)
        add("/opt/local/sbin", .macPorts)
        for dir in env.systemDirectories where !out.contains(where: { $0.directory == dir }) {
            add(dir, dir.hasPrefix("/opt/homebrew") ? .homebrewAppleSilicon
                   : dir.hasPrefix("/usr/local") ? .homebrewIntel
                   : dir.hasPrefix("/opt/local") ? .macPorts : .systemBin)
        }

        // --- Python -------------------------------------------------------
        // pipx puts scripts in PIPX_BIN_DIR, default ~/.local/bin.
        add(env.environment["PIPX_BIN_DIR"] ?? h(".local/bin"), .pipx)
        // `pip install --user` against a framework Python lands in
        // ~/Library/Python/3.x/bin. Enumerated, not globbed — an allow-list
        // stays an allow-list even in the discovery half.
        for minor in (9...20).reversed() {
            add(h("Library/Python/3.\(minor)/bin"), .pipUser)
        }

        // --- Node and friends ---------------------------------------------
        // npm symlinks global binaries into `$prefix/bin`; with Homebrew's node
        // that is already covered above, so what is left is a relocated prefix.
        if let prefix = env.environment["NPM_CONFIG_PREFIX"] {
            add((prefix as NSString).appendingPathComponent("bin"), .npmGlobal)
        }
        add(h(".npm-global/bin"), .npmGlobal)
        // nvm keeps one bin directory per installed Node. Those are enumerated
        // from the filesystem in `versionedNodeDirectories` — this table stays
        // pure.
        add(env.environment["BUN_INSTALL"].map { ($0 as NSString).appendingPathComponent("bin") }
            ?? h(".bun/bin"), .bun)
        add(env.environment["VOLTA_HOME"].map { ($0 as NSString).appendingPathComponent("bin") }
            ?? h(".volta/bin"), .volta)
        // pnpm's documented macOS default is ~/Library/pnpm/bin. Older releases
        // put binaries directly in PNPM_HOME, so both are searched.
        if let pnpmHome = env.environment["PNPM_HOME"] {
            add((pnpmHome as NSString).appendingPathComponent("bin"), .pnpm)
            add(pnpmHome, .pnpm)
        }
        add(h("Library/pnpm/bin"), .pnpm)
        add(h("Library/pnpm"), .pnpm)
        add(h(".yarn/bin"), .yarn)
        add(h(".config/yarn/global/node_modules/.bin"), .yarn)

        // --- Go and Rust ---------------------------------------------------
        if let gobin = env.environment["GOBIN"] {
            add(gobin, .goBin)
        }
        if let gopath = env.environment["GOPATH"] {
            add((gopath as NSString).appendingPathComponent("bin"), .goBin)
        }
        add(h("go/bin"), .goBin)
        add(env.environment["CARGO_HOME"].map { ($0 as NSString).appendingPathComponent("bin") }
            ?? h(".cargo/bin"), .cargo)

        // --- Version-manager shims -----------------------------------------
        add(env.environment["MISE_DATA_DIR"].map { ($0 as NSString).appendingPathComponent("shims") }
            ?? h(".local/share/mise/shims"), .miseShim)
        add(env.environment["ASDF_DATA_DIR"].map { ($0 as NSString).appendingPathComponent("shims") }
            ?? h(".asdf/shims"), .asdfShim)

        // --- Nix -----------------------------------------------------------
        add(h(".nix-profile/bin"), .nixProfile)
        add("/nix/var/nix/profiles/default/bin", .nixProfile)
        add("/run/current-system/sw/bin", .nixProfile)

        // De-duplicate, first class wins (the earlier class is the more specific
        // description of the same directory).
        var seen = Set<String>()
        return out.filter { seen.insert($0.directory).inserted }
    }

    /// nvm's per-version bin directories, and pnpm/volta shim variants that only
    /// exist once something is installed. Touches the filesystem (a directory
    /// listing), which is why it is separate from the pure table above.
    static func versionedNodeDirectories(_ env: ToolDiscoveryEnvironment) -> [Candidate] {
        let fm = FileManager.default
        let nvmRoot = env.environment["NVM_DIR"]
            ?? (env.home.path as NSString).appendingPathComponent(".nvm")
        let versionsDir = (nvmRoot as NSString).appendingPathComponent("versions/node")
        guard let entries = try? fm.contentsOfDirectory(atPath: versionsDir) else { return [] }
        return entries.sorted(by: >).map {
            Candidate(directory: (versionsDir as NSString)
                        .appendingPathComponent($0 + "/bin"), locationClass: .nvm)
        }
    }

    /// `$PATH`, as candidates. Deliberately last, deliberately included, and
    /// deliberately NEVER consulted by the execution side: a directory that
    /// arrived here is at best a note to the user.
    ///
    /// Relative entries and `.` are dropped — an entry that means "wherever you
    /// happen to be" is not a place.
    static func pathCandidates(_ env: ToolDiscoveryEnvironment) -> [Candidate] {
        let raw = env.environment["PATH"] ?? ""
        var seen = Set<String>()
        return raw.split(separator: ":", omittingEmptySubsequences: true)
            .map(String.init)
            .filter { $0.hasPrefix("/") }
            .filter { seen.insert($0).inserted }
            .map { Candidate(directory: $0, locationClass: .pathEntry) }
    }

    // MARK: Classifying one hit

    /// Whether the execution allow-list would run `path` for `tool`, and if not,
    /// why. Delegates every rule to `LocalToolRunner` — there is exactly one
    /// definition of "safe to execute" in this app and it is not in this file.
    static func classify(path: String, tool: String,
                         env: ToolDiscoveryEnvironment,
                         runnerDirectories: Set<String>) -> ToolUsability {
        var st = stat()
        guard stat(path, &st) == 0, (st.st_mode & S_IFMT) == S_IFREG,
              FileManager.default.isExecutableFile(atPath: path) else { return .notExecutable }
        // The directory test is the security-relevant one, and it is the runner's.
        guard LocalToolRunner.isSafeExecutable(atPath: path) else { return .unsafeDirectory }
        let parent = (path as NSString).deletingLastPathComponent
        if runnerDirectories.contains(parent) { return .runnable }
        // An explicitly-set path is runnable wherever it is (so long as the
        // directory is safe) — that is the sanctioned escape hatch.
        if env.userConfiguredPath(tool) == path { return .runnable }
        return .outsideAllowList
    }

    // MARK: The whole answer for one tool

    /// Find `tool` everywhere, classify every hit, and report which one we would
    /// run. Filesystem only.
    static func discover(_ tool: DiscoverableTool,
                         env: ToolDiscoveryEnvironment = .live()) -> DiscoveredTool {
        var out = DiscoveredTool(tool: tool.name)
        var seenPaths = Set<String>()
        let runnerDirectories = Set(LocalToolRunner.searchDirectories(home: env.home))

        func consider(_ path: String, _ cls: ToolLocationClass) {
            let standard = (path as NSString).standardizingPath
            guard seenPaths.insert(standard).inserted else { return }
            var st = stat()
            guard stat(standard, &st) == 0 else { return }
            out.paths.append(DiscoveredPath(
                path: standard, locationClass: cls,
                usability: classify(path: standard, tool: tool.name,
                                    env: env, runnerDirectories: runnerDirectories)))
        }

        // 1. A path the user set. First, always — and reported even when it is
        //    broken, because a broken explicit path is the single most useful
        //    thing to show someone whose setup stopped working.
        if let explicit = env.userConfiguredPath(tool.name) {
            consider(explicit, .userConfigured)
        }
        // 2. The researched package-manager and system locations.
        for candidate in candidateDirectories(env) {
            consider((candidate.directory as NSString).appendingPathComponent(tool.name),
                     candidate.locationClass)
        }
        // 3. The vendor's own installer paths.
        for path in tool.vendorInstallerPaths {
            consider(path, .vendorInstaller)
        }
        // 4. CLIs inside application bundles — "app installed" can already mean
        //    "CLI available", and missing this class produces a flatly wrong
        //    "not installed".
        for bundled in tool.bundledCLIs {
            for root in env.applicationDirectories {
                consider((root as NSString)
                            .appendingPathComponent(bundled.appBundleName + "/" + bundled.relativePath),
                         .appBundle)
            }
        }
        // 5. nvm's per-version directories.
        for candidate in versionedNodeDirectories(env) {
            consider((candidate.directory as NSString).appendingPathComponent(tool.name),
                     candidate.locationClass)
        }
        // 6. `$PATH`, last. This is the class the execution side will never look
        //    at, which is precisely why the user has to be told about it.
        for candidate in pathCandidates(env) {
            consider((candidate.directory as NSString).appendingPathComponent(tool.name),
                     candidate.locationClass)
        }

        // What we would ACTUALLY run comes from the runner, not from this list.
        // Asking it rather than deriving it is what keeps the two halves from
        // drifting apart the first time either changes.
        out.chosen = LocalToolRunner.locate(tool.name, home: env.home)
        out.version = out.chosen == nil
            ? .unknown(why: out.isFound
                       ? "SimpleVPN won\u{2019}t run a program from this location, so it hasn\u{2019}t been asked"
                       : "not installed")
            : .unknown(why: "not checked yet")
        return out
    }

    /// Every tool in the catalogue.
    static func discoverAll(env: ToolDiscoveryEnvironment = .live()) -> [String: DiscoveredTool] {
        var out: [String: DiscoveredTool] = [:]
        for tool in ToolCatalog.all { out[tool.name] = discover(tool, env: env) }
        return out
    }

    // MARK: Versions — allow-list only

    /// Ask a tool its version. ONLY for `discovered.chosen`, i.e. a path the
    /// execution allow-list already accepts.
    ///
    /// Running a binary from an untrusted directory in order to describe it in a
    /// diagnostic would give away exactly what the allow-list protects, so a tool
    /// we would not execute keeps `.unknown(why:)` and says why.
    static func probeVersion(_ tool: DiscoverableTool,
                             discovered: DiscoveredTool,
                             deadline: TimeInterval = 6) async -> ToolVersion {
        guard let executable = discovered.chosen else {
            return .unknown(why: discovered.isFound
                            ? "SimpleVPN won\u{2019}t run a program from this location"
                            : "not installed")
        }
        let result = await LocalToolRunner.run(executable: executable,
                                               arguments: tool.versionArguments,
                                               deadline: deadline)
        guard result.succeeded else {
            return .unknown(why: "it didn\u{2019}t answer \u{201C}\(tool.versionArguments.joined(separator: " "))\u{201D}")
        }
        // First non-empty line, trimmed and capped. A version string is not a
        // secret, but it comes from someone else's program, so it is bounded.
        let line = result.text.split(whereSeparator: \.isNewline)
            .map { $0.trimmingCharacters(in: .whitespaces) }
            .first { !$0.isEmpty } ?? ""
        guard !line.isEmpty else { return .unknown(why: "it printed nothing") }
        return .known(String(line.prefix(120)))
    }

    // MARK: Cached map

    /// The discovery map, cached briefly. The sign-in chooser polls every two
    /// seconds and several surfaces ask at once; a few dozen `stat` calls are
    /// cheap but repeating them for every observer is pointless.
    private static let cache = OSAllocatedUnfairLock<(taken: Date, map: [String: DiscoveredTool])?>(
        initialState: nil)

    static func cachedMap(ttl: TimeInterval = 5,
                          env: ToolDiscoveryEnvironment = .live()) -> [String: DiscoveredTool] {
        if let held = cache.withLock({ $0 }), Date().timeIntervalSince(held.taken) < ttl {
            return held.map
        }
        var fresh = discoverAll(env: env)
        // Carry a MEASURED version forward while the path it was measured from is
        // still the one we would run. Re-discovery is a few dozen `stat` calls and
        // happens often; a version costs a subprocess, and a program's version does
        // not change while its path doesn't. Without this the map would forget every
        // version every five seconds and the deep pass would spawn the whole
        // catalogue again — a dozen processes a minute for numbers that cannot have
        // changed, one of them starting a Python interpreter.
        let previous = cache.withLock { $0?.map } ?? [:]
        for (name, old) in previous where old.versionProbed {
            guard var entry = fresh[name], entry.chosen == old.chosen, entry.chosen != nil
            else { continue }
            entry.version = old.version
            entry.versionProbed = true
            fresh[name] = entry
        }
        let merged = fresh
        cache.withLock { $0 = (Date(), merged) }
        return merged
    }

    /// Record a version measured by `probeVersion`, so the map every surface reads is
    /// the map that carries it — rather than a second copy somewhere that can drift.
    static func recordVersion(tool: String, version: ToolVersion) {
        cache.withLock { held in
            guard var held2 = held, var entry = held2.map[tool] else { return }
            entry.version = version
            entry.versionProbed = true
            held2.map[tool] = entry
            held = held2
        }
    }

    /// Drop the cache — used when a path setting changes, so the pane's
    /// validation reflects what was just typed instead of a five-second-old
    /// answer.
    static func invalidateCache() {
        cache.withLock { $0 = nil }
    }

    /// One log line for the whole map: tool names, paths and states. No secrets
    /// pass through here (paths are not secrets), and nothing is executed.
    static func logSummary(_ map: [String: DiscoveredTool]) {
        let line = ToolCatalog.all.compactMap { map[$0.name]?.summaryLine }
            .joined(separator: " \u{00B7} ")
        log.log("tool discovery: \(line, privacy: .public)")
    }
}
