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
                      "RFC 8439", "KeePassXC"] {
            #expect(note.contains(claim), "the compatibility note never mentions \(claim)")
        }
        #expect(!Acknowledgements.sourceURL.isEmpty)
        #expect(URL(string: Acknowledgements.sourceURL) != nil)
    }
}
