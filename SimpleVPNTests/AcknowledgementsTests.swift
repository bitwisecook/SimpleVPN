// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
//  AcknowledgementsTests.swift
//  The gate on the About window's credits. Attribution is a LICENCE OBLIGATION,
//  not a nicety: the app statically links AGPL, LGPL and BSD/MIT code and bundles
//  a framework, and every one of those requires its notice to be conveyed. A row
//  that quietly goes missing when a dependency is added is a compliance bug that
//  no compiler and no other test would notice — Sparkle and the 1Password Go SDK
//  shipped un-credited for exactly that long.
//
//  Two of these checks are about the RENDERER rather than the data:
//  `AboutView` force-unwraps `URL(string: c.url)!` per row, so a malformed URL is
//  a crash in the About window, and DB-IP's licence requires the attribution to
//  link to db-ip.com specifically — pointing it at the licence text satisfies
//  neither the link requirement nor anything else.
//

import Foundation
import Testing
@testable import SimpleVPN

struct AcknowledgementsTests {

    private var components: [AboutComponent] { Acknowledgements.components }

    /// Every row is complete. An empty licence or role renders as a blank capsule
    /// or a nameless line — visibly broken, and worse, silently non-compliant.
    @Test func everyComponentIsNamedLicensedAndDescribed() {
        for c in components {
            #expect(!c.name.trimmingCharacters(in: .whitespaces).isEmpty,
                    "a component has no name")
            #expect(!c.license.trimmingCharacters(in: .whitespaces).isEmpty,
                    "\(c.name) has no licence")
            #expect(!c.role.trimmingCharacters(in: .whitespaces).isEmpty,
                    "\(c.name) doesn't say what it does")
            #expect(!c.url.trimmingCharacters(in: .whitespaces).isEmpty,
                    "\(c.name) has no URL")
        }
    }

    /// `AboutView` builds `URL(string: c.url)!` for each row, so a URL that
    /// doesn't parse is a crash in the About window rather than a missing link.
    @Test func everyURLParsesAndIsHTTPS() {
        for c in components {
            let url = URL(string: c.url)
            #expect(url != nil, "\(c.name)'s URL doesn't parse: \(c.url)")
            #expect(url?.scheme == "https", "\(c.name)'s URL isn't https: \(c.url)")
            #expect(url?.host != nil, "\(c.name)'s URL names no host: \(c.url)")
        }
    }

    /// One row per component. A duplicate is a dependency credited twice and,
    /// usually, another one credited not at all.
    @Test func noComponentIsListedTwice() {
        let names = components.map(\.name)
        let dupes = Dictionary(grouping: names, by: { $0 }).filter { $0.value.count > 1 }.keys
        #expect(dupes.isEmpty, "listed more than once: \(dupes.sorted().joined(separator: ", "))")
    }

    /// The components that are SHIPPED in the binary and carry a notice
    /// obligation. Naming them explicitly is the point: this list is what a future
    /// dependency has to be added to, and Sparkle plus the 1Password Go SDK were
    /// both shipped and both absent before this test existed.
    @Test func everyShippedComponentWithAnObligationIsCredited() {
        let names = Set(components.map(\.name))
        for required in ["OpenVPN 3 Core", "OpenConnect (libopenconnect)", "libssh",
                         "Tailscale", "wireguard-go", "gVisor", "OpenSSL 3",
                         "Sparkle", "1Password Go SDK",
                         "Go runtime & golang.org/x libraries"] {
            #expect(names.contains(required), "\(required) ships but isn't credited")
        }
    }

    /// The tools SimpleVPN RUNS.
    /// None of these is bundled and none imposes a notice obligation, so no compiler,
    /// linker or licence scanner will ever miss one — this list is the only thing that
    /// does. The credential programme added six vendors at once, and a seventh arriving
    /// with its row forgotten would leave a feature whose provenance is invisible.
    ///
    /// Every name here is a tool the code really executes: `ToolCatalog` +
    /// `LocalToolRunner.run` call sites (`DashlaneProvider`, `LastPassProvider`,
    /// `ProtonPassProvider`, `BitwardenProvider`, `KeeperProvider`,
    /// `KeePassFileProvider`, `PassboltServer`, `GPGDecrypter`, `YubiKeyManagerTool`).
    /// Five PKCS#11 rows used to be asserted here and are gone with smartcard sign-in
    /// (Docs/AuthSecPKCS11.md): p11tool, OpenSC, p11-kit, yubico-piv-tool's libykcs11
    /// and SoftHSM. `ykman` stays — it serves the YubiKey OATH and
    /// challenge-response mechanisms, which are untouched.
    @Test func everyInvokedThirdPartyToolIsCredited() {
        let names = Set(components.map(\.name))
        for required in ["KeePassXC", "Keeper Commander", "Bitwarden CLI",
                         "Dashlane CLI (dcli)", "LastPass CLI (lpass)",
                         "Proton Pass CLI (pass-cli)", "go-passbolt-cli",
                         "GnuPG", "pass (password-store)", "gopass",
                         "yubikey-manager (ykman)",
                         // The subprocess tunnel engines (`TunnelCLI`) are run the same
                         // way and were missing for longer than the vault tools.
                         // `ssh` is not here on purpose: macOS ships it, and
                         // `openfortivpn` is not here because it is GONE — an
                         // unreachable FortiGate fallback that needed root.
                         "ocproxy"] {
            #expect(names.contains(required), "\(required) is used but isn't credited")
        }
    }

    /// The framing is the licence argument, not decoration: these rows describe
    /// somebody else's program that the USER installed, and a row that reads like a
    /// bundled dependency would claim an obligation this binary does not carry — and
    /// invite the opposite reading, that their code is in here. KeePassXC is exempt
    /// because its row says the stronger version of the same thing ("no KeePassXC code
    /// is included"), for the protocol we reimplemented.
    @Test func everyInvokedToolRowSaysItIsNotBundled() {
        for name in ["Keeper Commander", "Bitwarden CLI", "Dashlane CLI (dcli)",
                     "LastPass CLI (lpass)", "Proton Pass CLI (pass-cli)",
                     "go-passbolt-cli", "GnuPG", "pass (password-store)", "gopass",
                     "yubikey-manager (ykman)",
                     "ocproxy"] {
            let row = components.first { $0.name == name }
            #expect(row?.role.contains("not bundled") == true,
                    "\(name)'s role doesn't say it isn't bundled")
        }
        let keePassXC = components.first { $0.name == "KeePassXC" }
        #expect(keePassXC?.role.contains("no KeePassXC code is included") == true)
    }

    /// Proton Pass's `pass-cli` and the unix password store's `pass` are DIFFERENT
    /// PRODUCTS holding different vaults, and the app keeps them apart everywhere
    /// (`ToolCatalog` has three entries for exactly this reason). Two rows, two
    /// licences: collapsing them would credit the wrong project for a feature.
    @Test func protonPassAndPasswordStoreAreCreditedSeparately() throws {
        let proton = try #require(components.first { $0.name.contains("Proton Pass") })
        let store = try #require(components.first { $0.name.contains("password-store") })
        #expect(proton.license == "GPL-3.0")           // protonpass/pass-cli
        #expect(store.license == "GPL-2.0-or-later")   // password-store
        #expect(proton.url != store.url)
    }

    /// The licences that were WRONG, pinned to what each project itself states — a
    /// badge is a claim about somebody else's terms and a plausible-looking guess is
    /// the failure mode. Each source is named so a future edit argues with the project
    /// rather than with this test.
    @Test func theLicenceBadgesMatchWhatEachProjectStates() throws {
        // KeePassXC's COPYING: "either version 2 or (at your option) version 3 of the
        // License". It said GPL-3.0, which dropped the choice.
        let keePassXC = try #require(components.first { $0.name == "KeePassXC" })
        #expect(keePassXC.license.contains("GPL-2.0"))
        #expect(keePassXC.license.contains("GPL-3.0"))
        // GnuTLS's p11tool was pinned here (split BY PART — LGPL-2.1-or-later library,
        // GPL-3.0-only tools — so the bare "GPL-3.0" was wrong for a tool). Its row is
        // gone with smartcard sign-in, along with OpenSC's, p11-kit's,
        // yubico-piv-tool's and SoftHSM's: SimpleVPN runs none of them any more
        // (Docs/AuthSecPKCS11.md).
        #expect(!components.contains { $0.name == "GnuTLS p11tool" })
        // go-passbolt-cli's own LICENSE file is the MIT text (checked against the
        // repository, not against how an AGPL server tends to license its clients).
        let passbolt = try #require(components.first { $0.name == "go-passbolt-cli" })
        #expect(passbolt.license == "MIT")
        // lastpass-cli is GPLv2-or-later with an OpenSSL exception, not GPL-2.0-only.
        let lastPass = try #require(components.first { $0.name.contains("LastPass") })
        #expect(lastPass.license == "GPL-2.0-or-later")
        // Dashlane's CLI repository is Apache-2.0.
        let dashlane = try #require(components.first { $0.name.contains("Dashlane") })
        #expect(dashlane.license == "Apache-2.0")
    }

    /// DB-IP's CC BY terms require the attribution to LINK TO THEM. The row used
    /// to link to the CC licence text instead, which is the one thing the licence
    /// does not ask for.
    @Test func theDBIPRowLinksToDBIPAsItsLicenceRequires() throws {
        let row = try #require(components.first { $0.name.contains("DB-IP") })
        #expect(URL(string: row.url)?.host == "db-ip.com",
                "DB-IP's attribution must link to db-ip.com, not \(row.url)")
        // The licence still has to be named — it just lives in the text, not the link.
        #expect(row.license.contains("CC BY"))
    }

    /// gVisor's netstack powers BOTH Go engines; the role text said "inside the
    /// Tailscale engine" while the Proxy Tunnel engine is built on it directly.
    @Test func gVisorsRoleNamesBothEnginesThatUseIt() throws {
        let row = try #require(components.first { $0.name == "gVisor" })
        #expect(row.role.contains("Tailscale"))
        #expect(row.role.contains("Proxy Tunnel"))
    }

    /// The compatibility note is the only place the licences are reasoned about
    /// rather than listed, so the claims that matter are pinned here — including
    /// the two "this is ours, don't go looking for a library" statements, which a
    /// reader would otherwise have to take from a source comment they can't see.
    @Test func theCompatibilityNoteStatesWhatItMust() {
        let note = Acknowledgements.compatibilityNote
        for claim in ["AGPL-3.0", "LGPL-2.1", "CC BY 4.0", "Sparkle",
                      "1Password Go SDK", "crypto_box", "golang.org/x/crypto",
                      "RFC 8439", "KeePassXC",
                      // "PKCS#11" was pinned here, because a provider module was the one
                      // credited thing that was LOADED rather than run — by openconnect's
                      // process, not ours. No module is named any more, so the sentence
                      // that made that distinction is gone with it.
                      "openconnect"] {
            #expect(note.contains(claim), "the compatibility note never mentions \(claim)")
        }
        #expect(!Acknowledgements.sourceURL.isEmpty)
        #expect(URL(string: Acknowledgements.sourceURL) != nil)
    }
}
