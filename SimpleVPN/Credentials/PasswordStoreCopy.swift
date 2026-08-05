// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
//  PasswordStoreCopy.swift
//  Everything a user reads about the `pass` / `gopass` source. Kept out of
//  SignInSources.swift for the same reason KeePassFileCopy.swift is: a vendor's block
//  of copy should never collide with another's.
//
//  TWO THINGS THIS COPY HAS TO BE HONEST ABOUT, because both will otherwise surprise
//  someone:
//
//   • THE LAYOUT IS A CONVENTION, NOT A FORMAT. `pass` guarantees only that an entry
//     is GPG-encrypted text. That the first line is the password and that `login:`
//     holds the username are habits — near-universal habits, but habits. So the copy
//     says "by convention", and the username field is configurable rather than
//     presented as a fact about the format.
//   • NEITHER `pass` NOR `gopass` IS REQUIRED. We read the store with `gpg`, so the
//     source works for someone who has a store and has never installed either. Saying
//     "install pass" when nothing needs installing would send people to do work that
//     changes nothing.
//

import Foundation

nonisolated extension LocalVaultCopyBook {

    static let passwordStore = LocalVaultCopy(
        title: "pass / gopass",
        summary: "SimpleVPN reads this VPN\u{2019}s sign-in from an entry in your password store, "
            + "using GnuPG on this Mac.",
        explanation: "The standard unix password store keeps each sign-in in its own "
            + "GPG-encrypted file under a folder — usually ~/.password-store. Point SimpleVPN at "
            + "that folder and name the entry (for example vpn/work) and it decrypts just that one "
            + "entry when you connect, with GnuPG. It reads: it never writes to your store, and "
            + "never runs git in it.\n\nBy long convention the first line of an entry is the "
            + "password and later lines are \u{201C}name: value\u{201D} — so SimpleVPN takes the "
            + "username from a `login`, `username`, `user` or `email` line, and you can tell it a "
            + "different name if you use one. That is a convention rather than a rule of the "
            + "format, so if a sign-in comes back looking wrong, that is the first thing to check."
            + "\n\nYou do not need the pass or gopass command installed: SimpleVPN speaks to GnuPG "
            + "directly. Your key\u{2019}s passphrase is handled entirely by GnuPG \u{2014} "
            + "SimpleVPN never sees it and never stores it.",
        symbol: "terminal.fill",
        storedKind: .passwordStore,
        primaryDoc: VendorDocs.passwordStore,
        // GnuPG is the thing that has to exist, not `pass`. Naming `pass` here would
        // install something the feature does not use.
        homebrewInstallCommand: "brew install gnupg",
        blocks: [
            .toolMissing: (
                headline: "GnuPG isn\u{2019}t installed",
                steps: ["Install GnuPG with `brew install gnupg`.",
                        "SimpleVPN uses **GnuPG** to decrypt your store \u{2014} the `pass` command itself is optional."]
            ),
            .toolOutsideAllowList: (
                headline: "GnuPG is installed somewhere SimpleVPN won\u{2019}t run it from",
                steps: ["Set the full path to `gpg` in **Settings \u{25B8} Sign-In Sources**.",
                        "Or install it with Homebrew, which puts it somewhere SimpleVPN already looks."]
            ),
            .noVaultFile: (
                headline: "No password store chosen yet",
                steps: ["Choose your store folder in **Settings \u{25B8} Sign-In Sources** \u{2014} usually `~/.password-store`.",
                        "Then name the entry this VPN should use, like `vpn/work`."]
            ),
            .vaultFileMissing: (
                headline: "That store folder isn\u{2019}t there any more",
                steps: ["Point SimpleVPN at where the folder is now, in **Settings \u{25B8} Sign-In Sources**."]
            ),
            .vaultNotAPasswordStore: (
                headline: "That folder isn\u{2019}t a password store",
                steps: ["A password store has a `.gpg-id` file in it. Choose the folder that does \u{2014} usually `~/.password-store`.",
                        "If you have never set one up, `pass init <your-gpg-key>` creates it."]
            ),
        ],
        guidance: [
            .toolMissing: EnablementGuidance(
                benefit: "SimpleVPN can read a sign-in straight out of your password store, with nothing to type.",
                example: [.init(text: "brew install gnupg",
                                caption: "Installs GnuPG, which is what actually decrypts your store")],
                doc: VendorDocs.passwordStore),
            .noVaultFile: EnablementGuidance(
                benefit: "Naming your store lets SimpleVPN find this VPN\u{2019}s entry in it.",
                settingLocation: "Settings \u{25B8} Sign-In Sources \u{25B8} pass / gopass \u{25B8} Store Folder",
                doc: VendorDocs.passwordStore),
            .vaultNotAPasswordStore: EnablementGuidance(
                benefit: "A store SimpleVPN can recognise is one it can read this VPN\u{2019}s sign-in from.",
                example: [.init(text: "pass init <your-gpg-key-id>",
                                caption: "Creates a store, if you have not set one up yet")],
                doc: VendorDocs.passwordStore),
        ],
        // The pinentry caveat, in the one place a user will see before it bites them.
        // Not a block, because a great many people have their passphrase cached all day
        // and the source works perfectly for them.
        uncheckedNote: "Your store is ready to read. If GnuPG has forgotten your key\u{2019}s "
            + "passphrase it will need to ask for it, and asking needs a graphical PIN entry "
            + "program \u{2014} without one, SimpleVPN can only read your store while GnuPG still "
            + "remembers the passphrase. Install one with \u{201C}brew install pinentry-mac\u{201D} "
            + "if you would rather always be asked."
    )
}
