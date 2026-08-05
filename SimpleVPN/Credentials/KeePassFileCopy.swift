// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
//  KeePassFileCopy.swift
//  Everything the KeePass-database-file row SAYS. Separate from the probe, the way
//  every other vendor's copy is, so the wording can be reviewed and tested with no
//  KeePassXC, no Strongbox, no KeePassium and no database anywhere near the machine.
//
//  THE WORDING PROBLEM THIS ROW HAS AND THE OTHERS DON'T. Every other row is a
//  BRAND: "1Password", "Keeper". This one is a FILE FORMAT that four products share,
//  and the person reading it may never have heard the words "KeePass format" — they
//  have heard "Strongbox" or "KeePassium". So the row is named for the file, names
//  the three apps by name, and explains why a KeePassXC tool is what opens a
//  Strongbox database. Getting that wrong would leave a Strongbox user scrolling
//  past the one row built for them.
//
//  It also has to be honest about the one thing that makes it different from every
//  other row in the chooser: SimpleVPN sees the database password. 1Password,
//  KeePassXC-the-app and Keeper all keep their master secret to themselves; a file
//  has nobody to keep it. That sentence is in the row's own explanation, not buried
//  in the manual, because it is the fact somebody needs in order to choose.
//
//  Glossary (AGENTS.md, binding): "sign in" / "sign-in", "verification code",
//  "username" / "password". Never "vault", "credential store", "provider" or a bare
//  "OTP" in anything a user reads or hears.
//

import Foundation

nonisolated extension LocalVaultCopyBook {

    /// The `.kdbx` file row.
    static let keePassFile = LocalVaultCopy(
        title: "KeePass database file",
        summary: "SimpleVPN opens a KeePass database on this Mac and reads this VPN\u{2019}s sign-in "
            + "out of it \u{2014} whichever app you keep it in.",
        explanation: "Point SimpleVPN at your .kdbx file and it reads the entry you name. This works "
            + "whatever you use to look after that file \u{2014} KeePassXC, Strongbox and KeePassium "
            + "all keep their entries in the same kind of database, and none of them has to be running. "
            + "SimpleVPN never changes your database: it only ever reads. The opening itself is done by "
            + "KeePassXC\u{2019}s own command-line tool, so no part of SimpleVPN decrypts your "
            + "database. One thing to know before you pick this: unlike the other choices here, "
            + "SimpleVPN does see your database\u{2019}s password, because a file has nobody to hold it "
            + "for you. By default nothing is kept \u{2014} you type it once each time you open "
            + "SimpleVPN \u{2014} and you can ask macOS to remember it behind Touch ID instead. If "
            + "KeePassXC is running on this Mac, the KeePassXC row above is the better choice: there "
            + "the app does the unlocking and SimpleVPN never sees anything.",
        symbol: "doc.badge.gearshape",
        storedKind: .keePassFile,
        primaryDoc: VendorDocs.keePassXCCLI,
        // The cask installs the KeePassXC app AND symlinks keepassxc-cli into
        // Homebrew's bin directory — which is why "install the app" is the whole
        // answer even for someone who will never open it.
        homebrewInstallCommand: "brew install --cask keepassxc",
        blocks: [
            .toolMissing: ("SimpleVPN needs KeePassXC\u{2019}s command-line tool to open a database "
                           + "file", []),
            .toolOutsideAllowList: (
                "KeePassXC\u{2019}s command-line tool is installed, but not somewhere SimpleVPN will "
                + "run it from", []),
            .noVaultFile: ("No KeePass database is chosen yet", []),
            .vaultFileMissing: (
                "SimpleVPN can\u{2019}t find your KeePass database any more",
                ["Check whether the file has moved, or its disk isn\u{2019}t plugged in.",
                 "Point SimpleVPN at it again in **Settings \u{25B8} Sign-In Sources**."]),
            .vaultFileNotDownloaded: (
                "Your KeePass database hasn\u{2019}t been downloaded to this Mac yet",
                ["Open its folder in the **Finder** and wait for the download to finish.",
                 "Nothing else to do \u{2014} SimpleVPN will pick it up on its own."]),
            .vaultFileNotReadable: (
                "macOS won\u{2019}t let SimpleVPN read your KeePass database",
                ["Allow **SimpleVPN** in **System Settings \u{25B8} Privacy & Security \u{25B8} Files "
                 + "and Folders**. macOS asks once per app for your Desktop, Documents, Downloads and "
                 + "iCloud Drive folders.",
                 "Or move your database somewhere macOS doesn\u{2019}t protect, and point SimpleVPN at "
                 + "it again."]),
            .vaultFileNotAKeePassDatabase: (
                "That file isn\u{2019}t a KeePass database SimpleVPN can read",
                ["Choose the file whose name ends in **.kdbx**.",
                 "An old KeePass 1 file (**.kdb**) has to be converted in KeePassXC first \u{2014} "
                 + "SimpleVPN never changes your file itself."]),
            .vaultFileTooNew: (
                "Your KeePass database is newer than the KeePassXC on this Mac can read",
                ["Update **KeePassXC** to the latest version.",
                 "Come back here \u{2014} nothing else needs changing."]),
            .vaultLocked: ("SimpleVPN needs your KeePass database\u{2019}s password", []),
            .vaultPasswordRejected: ("Your KeePass database wouldn\u{2019}t open", []),
        ],
        guidance: [
            // SimpleVPN never installs anything: the command is shown, the user runs
            // it. Latest release only, per the house rule.
            .toolMissing: EnablementGuidance(
                benefit: "Install KeePassXC and SimpleVPN can read this VPN\u{2019}s sign-in straight "
                    + "out of your KeePass database \u{2014} the same file Strongbox and KeePassium "
                    + "use. You don\u{2019}t have to open the app: what SimpleVPN needs is the "
                    + "command-line tool that comes inside it.",
                example: [
                    .init(text: "brew install --cask keepassxc",
                          caption: "Install KeePassXC (SimpleVPN never installs it for you)"),
                ],
                doc: VendorDocs.keePassXC),
            .noVaultFile: EnablementGuidance(
                benefit: "Choose your KeePass database and SimpleVPN can read this VPN\u{2019}s "
                    + "username and password out of it when you connect.",
                settingLocation: "In SimpleVPN: **Settings \u{25B8} Sign-In Sources**, then set the "
                    + "**KeePass database file**. It is the file whose name ends in **.kdbx** \u{2014} "
                    + "in Strongbox or KeePassium, look under the database\u{2019}s own settings for "
                    + "where the file is.",
                doc: VendorDocs.keePassXCCLI),
            .vaultLocked: EnablementGuidance(
                benefit: "Type your database\u{2019}s password once and SimpleVPN can open it. By "
                    + "default it is held only until SimpleVPN quits; you can ask macOS to remember it "
                    + "behind Touch ID instead, and then macOS won\u{2019}t hand it over without a "
                    + "fingerprint.",
                settingLocation: "In SimpleVPN: **Settings \u{25B8} Sign-In Sources**, then "
                    + "**KeePass database password**.",
                doc: VendorDocs.keePassXCCLI),
            .vaultPasswordRejected: EnablementGuidance(
                benefit: "Your database refused the last attempt. Type its password again \u{2014} and "
                    + "if it is right, the database may also need a key file or a security key, which "
                    + "you can set just below it.",
                settingLocation: "In SimpleVPN: **Settings \u{25B8} Sign-In Sources**, then "
                    + "**KeePass database password**.",
                doc: VendorDocs.keePassXCCLI),
        ],
        // Nothing is "unproven but reachable" here: everything checkable without
        // spending a key derivation, a fingerprint or somebody's finger is already
        // checked by the cheap pass, and the only deeper check is a real unlock.
        uncheckedNote: nil)
}
