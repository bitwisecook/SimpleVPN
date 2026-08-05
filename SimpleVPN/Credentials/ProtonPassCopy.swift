// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
//  ProtonPassCopy.swift
//  Everything a user reads about the Proton Pass source. Kept out of
//  SignInSources.swift for the same reason PasswordStoreCopy.swift is: one vendor's
//  block of copy should never collide with another's.
//
//  THREE THINGS THIS COPY HAS TO BE HONEST ABOUT, because each of them will
//  otherwise cost somebody an afternoon:
//
//   • THE PLAN. Proton Pass's command-line tool is part of the paid plans — Pass
//     Plus, Pass Family, Pass Professional, and the Proton bundles. A free-plan user
//     can install it, can see it working, and still cannot sign in to it. The tool
//     says so once, at sign-in, and then logs itself out — so the state SimpleVPN
//     finds afterwards is "not signed in", which is true and, on its own, badly
//     misleading. So BOTH sentences name the plan.
//   • THE NAME. This vendor's tool is `pass-cli`. SimpleVPN also reads the unix
//     password store, whose tool is `pass`. Different products, different vaults,
//     one letter of difference in the row heading if we are careless — so this copy
//     never says "pass" on its own, and the tool's name only ever appears inside a
//     `code` span where it is a thing to type rather than a thing to read.
//   • THE ITEM'S NAME VERSUS ITS IDENTIFIER. Proton Pass lets an item be addressed
//     by vault-and-title or by two identifiers. Titles are the ones a person can
//     type, and they are not unique: Proton's own documentation says that when
//     several items match a name, "one of them will be used". SimpleVPN will not do
//     that — it refuses and says so — and the explanation warns about it BEFORE it
//     happens, exactly as the KeePass file source's copy warns about entry paths.
//

import Foundation

nonisolated extension LocalVaultCopyBook {

    static let protonPass = LocalVaultCopy(
        title: "Proton Pass",
        summary: "SimpleVPN asks Proton Pass for this VPN\u{2019}s sign-in when you connect.",
        explanation: "SimpleVPN reads one item from Proton Pass using Proton\u{2019}s own "
            + "command-line tool. You sign that tool in once in Terminal \u{2014} Proton does the "
            + "asking, in your browser or in the terminal, and your Proton password never reaches "
            + "SimpleVPN. After that it keeps its own session on this Mac and SimpleVPN reads just "
            + "the one item you point it at, each time you connect. It only reads: it never changes "
            + "your vaults.\n\nPoint it at the vault and the item, like Work/GR Lab. You can use "
            + "Proton\u{2019}s own identifiers for both instead, and it is worth doing for a VPN you "
            + "depend on: identifiers stay the same when you rename or move things, while names do "
            + "not \u{2014} and if two items in a vault share a title, SimpleVPN will stop and ask you "
            + "which one you meant rather than reading whichever it found first.\n\nWorth knowing "
            + "before you start: Proton\u{2019}s command-line tool is part of Pass Plus, Pass Family, "
            + "Pass Professional and the Proton bundles. On a free plan it installs and runs, but "
            + "Proton will not let it sign in \u{2014} so this row can look set up and still not "
            + "work, and that is a plan rather than a fault. If a verification code is required, you "
            + "type that one yourself.",
        symbol: "lock.circle",
        storedKind: .protonPass,
        primaryDoc: VendorDocs.protonPassCLI,
        // Proton's own tap. Their installer script works too and is on their
        // installation page; Homebrew is named here because it lands somewhere
        // SimpleVPN already looks and can be upgraded without a second mechanism.
        homebrewInstallCommand: "brew install protonpass/tap/pass-cli",
        blocks: [
            .toolMissing: (
                headline: "Proton Pass\u{2019}s command-line tool isn\u{2019}t installed on this Mac",
                steps: []
            ),
            .notSignedIn: (
                // NAMES THE PLAN, on purpose. The tool logs itself out when an account
                // is not allowed to use it, so this is the state a free-plan user
                // actually lands in — and "you aren't signed in" on its own would send
                // them round the sign-in loop for ever.
                headline: "Proton Pass isn\u{2019}t signed in on this Mac",
                steps: ["Open Terminal and run `pass-cli login`, then finish in your browser.",
                        "If Proton refuses, check your plan: the command-line tool is part of "
                        + "**Pass Plus**, **Pass Family**, **Pass Professional** and the Proton bundles."]
            ),
            .vaultLocked: (
                headline: "Your Proton Pass session is locked",
                steps: ["Open Terminal and run `pass-cli session unlock`."]
            ),
            .planExcludesTool: (
                headline: "Your Proton plan doesn\u{2019}t include Proton Pass\u{2019}s command-line tool",
                steps: []
            ),
            // Deliberately NOT "isn't installed": it demonstrably is, and we can see
            // where. Saying otherwise sends someone to install a second copy.
            .toolOutsideAllowList: (
                headline: "Proton Pass\u{2019}s command-line tool is installed, but not somewhere "
                    + "SimpleVPN will run it from",
                steps: []
            ),
        ],
        guidance: [
            // SimpleVPN never installs anything: the commands are shown, and the user
            // runs them. Latest release only — Proton's own page carries the rest.
            .toolMissing: EnablementGuidance(
                benefit: "Install Proton\u{2019}s own command-line tool and SimpleVPN can get this "
                    + "VPN\u{2019}s sign-in straight from Proton Pass when you connect. Your Proton "
                    + "plan has to include it \u{2014} Pass Plus, Pass Family, Pass Professional or "
                    + "any Proton bundle.",
                example: [
                    .init(text: "brew install protonpass/tap/pass-cli",
                          caption: "Install Proton\u{2019}s command-line tool "
                              + "(SimpleVPN never installs it for you)"),
                    .init(text: "pass-cli login",
                          caption: "Sign in to Proton once, in Terminal \u{2014} it opens your browser"),
                    .init(text: "pass-cli vault list",
                          caption: "Check it worked, and see what your vaults are called"),
                ],
                doc: VendorDocs.protonPassCLI),
            .notSignedIn: EnablementGuidance(
                benefit: "Sign in once and SimpleVPN can get this VPN\u{2019}s sign-in from Proton "
                    + "Pass when you connect. Proton asks you, not SimpleVPN, and the session stays "
                    + "in Proton\u{2019}s own tool.",
                example: [
                    .init(text: "pass-cli login",
                          caption: "Sign in to Proton once, in Terminal \u{2014} it opens your browser"),
                    .init(text: "pass-cli info",
                          caption: "Check the session is live. If Proton refuses, it is your plan "
                              + "rather than this Mac"),
                ],
                doc: VendorDocs.protonPassCLILogin),
            .vaultLocked: EnablementGuidance(
                benefit: "Unlock your Proton Pass session and SimpleVPN can read this VPN\u{2019}s "
                    + "sign-in again. Proton asks for your lock code, not SimpleVPN, and SimpleVPN "
                    + "never sees it.",
                example: [
                    .init(text: "pass-cli session unlock",
                          caption: "Unlock the session in Terminal, with the code you set"),
                ],
                doc: VendorDocs.protonPassCLISession),
            // THE SUBSCRIPTION BANNER. Everything is installed and working; what is
            // missing is a plan. So there is no command to run, because running one
            // would change nothing — the fix is on Proton's own account pages, and
            // saying that plainly is the whole value of this state.
            .planExcludesTool: EnablementGuidance(
                benefit: "Proton\u{2019}s command-line tool comes with Pass Plus, Pass Family, Pass "
                    + "Professional and the Proton bundles. Everything on this Mac is set up "
                    + "correctly \u{2014} Proton is turning the tool down because of the plan on your "
                    + "account, so there is nothing here to fix and nothing to reinstall. Change the "
                    + "plan, or pick another way to sign in to this VPN.",
                settingLocation: "In your browser: your **Proton Account** subscription page.",
                doc: VendorDocs.protonPassPlans),
        ],
        uncheckedNote: "SimpleVPN checks with Proton Pass when you pick this.")
}
