// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
//  PassboltCopy.swift
//  Everything a user reads about the Passbolt source. Kept out of
//  SignInSources.swift for the same reason KeePassFileCopy.swift and
//  PasswordStoreCopy.swift are: a vendor's block of copy should never collide
//  with another's.
//
//  FOUR THINGS THIS COPY HAS TO BE HONEST ABOUT, because each will otherwise
//  surprise somebody:
//
//   • THE PASSPHRASE IS TYPED ONCE, HERE, AND KEPT NOWHERE BY DEFAULT. Passbolt
//     signs you in with an OpenPGP key, and that key is your whole Passbolt
//     identity rather than one VPN's password — so it gets the narrowest handling
//     this app has: nothing kept unless you ask, and if you ask, the Touch ID
//     keychain and only that. The wording is the `.kdbx` row's, because it is the
//     same promise.
//   • SO THE SOURCE CAN BE SET UP AND STILL DORMANT. With nothing to unlock the
//     key, a fetch cannot happen — and the row says so with the one field that
//     fixes it, rather than appearing to hang.
//   • NOTHING ASSUMES A HOSTED PASSBOLT. Self-hosting is the normal case, so no
//     sentence here names a domain, and the address is always the user's own.
//   • THE CERTIFICATE IS ALWAYS CHECKED. Passbolt's own program has a flag to skip
//     that; SimpleVPN never passes it and offers no setting that could. For a
//     private certificate authority the copy points at the fix that works for
//     every program at once — trusting the authority on this Mac.
//
//  AND ONE THING IT DELIBERATELY DOES NOT DO. `go-passbolt-cli` can be given a
//  passphrase to keep in its own config file, or one in an environment variable,
//  and plenty of people run it that way in scripts. Neither is recommended here and
//  the second is refused outright: this is a VPN client on somebody's laptop, so
//  the copy offers the affordance a person recognises — type it once, or Touch ID —
//  and never the one an operator would provision for an unattended job. A config
//  file that already has a passphrase still works; it is honoured without being
//  advertised.
//
//  Wording: never "credential", never "log in", never a bare "OTP" (AGENTS.md
//  glossary), and no operator vocabulary at all — nothing here says "secrets
//  management", "workspace" or "provisioning". Passbolt's own words keep their
//  spelling inside `code` spans, because a command we rename is a command that
//  does not work.
//

import Foundation

nonisolated extension LocalVaultCopyBook {

    static let passbolt = LocalVaultCopy(
        title: "Passbolt",
        summary: "SimpleVPN reads this VPN\u{2019}s sign-in from your Passbolt server, using "
            + "Passbolt\u{2019}s own program on this Mac.",
        explanation: "Passbolt keeps your passwords on a server \u{2014} your organization\u{2019}s "
            + "own, or one you run yourself \u{2014} and unlocks them with an OpenPGP key. SimpleVPN "
            + "asks Passbolt\u{2019}s own command-line program for the one resource this VPN names, "
            + "and reads only that resource. It reads: it never creates, changes, shares or deletes "
            + "anything in Passbolt."
            + "\n\nYour key needs its passphrase, and SimpleVPN keeps it nowhere unless you ask. You "
            + "type it once in Settings when you set the server up, it is held until SimpleVPN quits, "
            + "and you are asked again next time you open the app. If you would rather not type it "
            + "again, macOS can remember it and release it only for a fingerprint, your Apple Watch "
            + "or this Mac\u{2019}s password. It is never written to a settings file and never appears "
            + "in a log."
            + "\n\nSimpleVPN always checks your server\u{2019}s certificate, and has no setting to "
            + "stop. If your organization runs its own certificate authority, add that authority to "
            + "this Mac\u{2019}s keychain and mark it trusted \u{2014} that is the fix for every "
            + "program at once, not just this one."
            + "\n\nYou can set up more than one server, each with its own name, address and key.",
        symbol: "lock.rectangle.stack",
        storedKind: .passbolt,
        primaryDoc: VendorDocs.passboltCLI,
        homebrewInstallCommand: "brew install passbolt/tap/go-passbolt-cli",
        blocks: [
            .toolMissing: (
                headline: "Passbolt\u{2019}s own program isn\u{2019}t installed on this Mac",
                steps: ["Install it with `brew install passbolt/tap/go-passbolt-cli`.",
                        "Then set it up for your server once with `passbolt configure`."]
            ),
            // Deliberately NOT "isn't installed": it demonstrably is, and we can
            // see where. Saying otherwise sends somebody to install a second copy.
            .toolOutsideAllowList: (
                headline: "Passbolt\u{2019}s own program is installed, but not somewhere SimpleVPN "
                    + "will run it from",
                steps: []
            ),
            .noServerConfigured: (
                headline: "No Passbolt server set up yet",
                steps: ["Add your server\u{2019}s address in **Settings \u{25B8} Sign-In Sources** "
                            + "\u{2014} it starts with https.",
                        "Then name the resource this VPN should read."]
            ),
            .notSignedIn: (
                headline: "Passbolt\u{2019}s own program isn\u{2019}t set up for this server",
                steps: []
            ),
            .vaultLocked: (
                headline: "Your Passbolt key needs its passphrase",
                steps: []
            ),
        ],
        guidance: [
            .toolMissing: EnablementGuidance(
                benefit: "Install Passbolt\u{2019}s own program and SimpleVPN can read this VPN\u{2019}s "
                    + "sign-in straight from your Passbolt server when you connect.",
                example: [
                    .init(text: "brew install passbolt/tap/go-passbolt-cli",
                          caption: "Installs Passbolt\u{2019}s own program as `passbolt` "
                              + "(SimpleVPN never installs it for you)"),
                    .init(text: "passbolt configure --serverAddress https://passbolt.example.com "
                              + "--userPrivateKeyFile ~/passbolt-key.asc",
                          caption: "Points it at your server and your key, once, in Terminal. "
                              + "Leave your passphrase out of it \u{2014} you type that in "
                              + "SimpleVPN, which keeps it nowhere unless you ask"),
                ],
                doc: VendorDocs.passboltCLI),
            .noServerConfigured: EnablementGuidance(
                benefit: "Naming your server lets SimpleVPN read this VPN\u{2019}s sign-in out of it.",
                settingLocation: "Settings \u{25B8} Sign-In Sources \u{25B8} Passbolt \u{25B8} "
                    + "Server Address",
                doc: VendorDocs.passbolt),
            .notSignedIn: EnablementGuidance(
                benefit: "Set Passbolt\u{2019}s own program up once and SimpleVPN can read this "
                    + "VPN\u{2019}s sign-in from your server when you connect \u{2014} with nothing "
                    + "to type.",
                example: [
                    .init(text: "passbolt configure --serverAddress https://passbolt.example.com "
                              + "--userPrivateKeyFile ~/passbolt-key.asc",
                          caption: "Points Passbolt\u{2019}s program at your server and your key. "
                              + "Your passphrase does not go in this command"),
                    .init(text: "passbolt verify",
                          caption: "Optional, and worth it: makes Passbolt\u{2019}s program check "
                              + "your server\u{2019}s own identity every time as well"),
                ],
                doc: VendorDocs.passboltCLI),
            .vaultLocked: EnablementGuidance(
                // The one banner that has to explain a DESIGN DECISION as well as a
                // missing thing, because "where does it go?" is the obvious question
                // about a passphrase and the answer is the reassuring part.
                benefit: "Your key needs its passphrase before anything can be read. Type it in "
                    + "SimpleVPN and it is held until SimpleVPN quits and written nowhere \u{2014} "
                    + "or let macOS remember it, and it will hand it back only for a fingerprint, "
                    + "your Apple Watch or this Mac\u{2019}s password. Your Passbolt key opens "
                    + "everything you can see in Passbolt, not just this VPN, which is why it gets "
                    + "the narrowest handling in the app.",
                settingLocation: "Settings \u{25B8} Sign-In Sources \u{25B8} Passbolt \u{25B8} "
                    + "Key Passphrase",
                doc: VendorDocs.passbolt),
        ],
        // Shown for the ONE state a filesystem check can reach and no further: the
        // program is here, the address looks right, and the program has a key and a
        // passphrase. Whether the server answers is something only a real sign-in
        // can say, and SimpleVPN does not sign in to your server just to draw a
        // green tick.
        uncheckedNote: "Your server is set up and ready to try. SimpleVPN hasn\u{2019}t contacted it "
            + "\u{2014} it doesn\u{2019}t sign in to your server just to check, because that is a "
            + "real sign-in attempt against a machine it was only asked about. Use **Test** here, or "
            + "just connect, and it will say exactly what happened."
    )
}
