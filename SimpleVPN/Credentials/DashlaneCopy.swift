// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
//  DashlaneCopy.swift
//  Everything a user reads about the Dashlane source. Kept out of SignInSources.swift
//  for the same reason KeePassFileCopy.swift and PasswordStoreCopy.swift are: a
//  vendor's block of copy should never collide with another's.
//
//  THREE THINGS THIS COPY HAS TO BE HONEST ABOUT, because each will otherwise
//  surprise somebody:
//
//   • THE PASTEBOARD. Dashlane's own tool copies a password to the clipboard when you
//     run it by hand — that is what `dcli p` does, and it is what every guide shows.
//     SimpleVPN never uses that mode (see DashlaneProvider's header), and saying so
//     out loud is worth more than staying quiet: a person who knows `dcli` puts
//     passwords on their clipboard deserves to be told that this doesn't.
//   • REGISTERING THIS MAC IS A ONE-TIME SETUP, and it is not instant: Dashlane
//     emails a token, or asks the code from an authenticator app. A banner that
//     showed one command without saying "it will ask you for a token" would look
//     broken the moment somebody ran it.
//   • A FETCH CAN GO TO THE NETWORK. Dashlane's tool re-synchronises the local copy
//     of the vault about once an hour, so an occasional connect is a sync as well as
//     a read. Anybody who would rather that never happened can switch it off, and
//     the recipe in Docs/AuthPwdDashlane.md says how.
//

import Foundation

nonisolated extension LocalVaultCopyBook {

    static let dashlane = LocalVaultCopy(
        title: "Dashlane",
        summary: "SimpleVPN asks Dashlane\u{2019}s own command-line tool for this VPN\u{2019}s "
            + "sign-in when you connect.",
        explanation: "SimpleVPN reads one entry from your Dashlane vault using Dashlane\u{2019}s own "
            + "command-line tool, and it asks that tool to print the entry rather than to put it on "
            + "the clipboard \u{2014} so your VPN password never sits on the pasteboard where any "
            + "program on this Mac could read it.\n\nDashlane does the unlocking, never SimpleVPN: "
            + "your Dashlane password goes to Dashlane\u{2019}s tool, which keeps the key it needs "
            + "in this Mac\u{2019}s keychain where macOS protects it. If you have turned on "
            + "Dashlane\u{2019}s fingerprint unlock, Dashlane asks for your fingerprint itself and "
            + "SimpleVPN only waits.\n\nSigning this Mac in to Dashlane is a one-time setup you do "
            + "in Terminal: Dashlane asks for your email address and a token, then for your "
            + "Dashlane password. After that, connecting needs nothing typed. If the entry carries "
            + "a verification code SimpleVPN works it out from the entry, but you may still be "
            + "asked to type one \u{2014} SimpleVPN doesn\u{2019}t promise a code it has never "
            + "watched work.",
        symbol: "key.radiowaves.forward",
        storedKind: .dashlane,
        primaryDoc: VendorDocs.dashlaneCLI,
        homebrewInstallCommand: "brew install dashlane/tap/dashlane-cli",
        blocks: [
            .toolMissing: (
                headline: "Dashlane\u{2019}s command-line tool isn\u{2019}t installed on this Mac",
                steps: ["Install it with `brew install dashlane/tap/dashlane-cli`.",
                        "Then run `dcli sync` once, in Terminal, to sign this Mac in."]
            ),
            // Deliberately NOT "isn't installed": it demonstrably is, and we can see
            // where. Saying otherwise sends someone to install a second copy.
            .toolOutsideAllowList: (
                headline: "Dashlane\u{2019}s command-line tool is installed, but not somewhere "
                    + "SimpleVPN will run it from",
                steps: ["Set the full path to `dcli` in **Settings \u{25B8} Sign-In Sources**.",
                        "Or install it with Homebrew, which puts it somewhere SimpleVPN already looks."]
            ),
            .notSignedIn: (
                headline: "This Mac isn\u{2019}t signed in to Dashlane yet",
                steps: ["Run `dcli sync` in Terminal.",
                        "Dashlane asks for your email address and a token \u{2014} by email, or from "
                            + "your authenticator app if you use one \u{2014} and then for your "
                            + "Dashlane password.",
                        "That registers this Mac once. Afterwards SimpleVPN can read your entry "
                            + "with nothing to type."]
            ),
            .vaultLocked: (
                headline: "Dashlane is signed in on this Mac, but locked",
                steps: ["Run `dcli sync` in Terminal and type your Dashlane password when it asks.",
                        "Dashlane asks you, not SimpleVPN, and keeps what it needs in this "
                            + "Mac\u{2019}s keychain.",
                        "If you have turned off `dcli configure save-master-password`, Dashlane will "
                            + "ask every time and SimpleVPN can\u{2019}t read your vault at all."]
            ),
        ],
        guidance: [
            // SimpleVPN never installs anything: the commands are shown, and the user
            // runs them. Latest release only — Dashlane's own page carries the rest.
            .toolMissing: EnablementGuidance(
                benefit: "Install Dashlane\u{2019}s own command-line tool and SimpleVPN can get "
                    + "this VPN\u{2019}s sign-in straight from Dashlane when you connect \u{2014} "
                    + "without ever putting your password on the clipboard.",
                example: [
                    .init(text: "brew install dashlane/tap/dashlane-cli",
                          caption: "Install Dashlane\u{2019}s command-line tool "
                              + "(SimpleVPN never installs it for you)"),
                    .init(text: "dcli sync",
                          caption: "Sign this Mac in to Dashlane once, in Terminal \u{2014} it asks "
                              + "for your email address, a token, then your Dashlane password"),
                ],
                doc: VendorDocs.dashlaneCLI),
            .notSignedIn: EnablementGuidance(
                benefit: "Sign this Mac in to Dashlane once and SimpleVPN can get this VPN\u{2019}s "
                    + "sign-in from Dashlane when you connect, with nothing to type.",
                example: [
                    .init(text: "dcli sync",
                          caption: "Registers this Mac and signs it in \u{2014} Dashlane asks for "
                              + "your email address, a token, then your Dashlane password"),
                    .init(text: "dcli configure user-presence --method biometrics",
                          caption: "Optional: have Dashlane ask for your fingerprint before it "
                              + "hands anything over"),
                ],
                doc: VendorDocs.dashlaneAuthentication),
            .vaultLocked: EnablementGuidance(
                benefit: "Unlock Dashlane once and SimpleVPN can get this VPN\u{2019}s sign-in from "
                    + "it with nothing to type. Dashlane asks for your Dashlane password, not "
                    + "SimpleVPN, and keeps the key it needs in this Mac\u{2019}s keychain.",
                example: [
                    .init(text: "dcli sync",
                          caption: "Type your Dashlane password when Dashlane asks for it"),
                    .init(text: "dcli status",
                          caption: "Shows whether Dashlane is unlocked on this Mac"),
                ],
                doc: VendorDocs.dashlaneAuthentication),
        ],
        // The two caveats worth knowing BEFORE they bite, in the one place somebody
        // will read first. Neither is a block: both describe a source that works.
        uncheckedNote: "SimpleVPN checks with Dashlane\u{2019}s tool when you pick this. Two things "
            + "worth knowing: SimpleVPN asks it to print your sign-in rather than copy it, so "
            + "nothing is left on your clipboard; and Dashlane refreshes its own copy of your vault "
            + "about once an hour, so a connect now and then takes a moment longer."
    )
}
