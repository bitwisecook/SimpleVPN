// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
//  LastPassCopy.swift
//  Everything a user reads about the LastPass source. Kept out of
//  SignInSources.swift for the same reason PasswordStoreCopy.swift is: a vendor's
//  block of copy should never collide with another's.
//
//  THE HONESTY PROBLEM THIS COPY HAS TO SOLVE, and it is the only feed so far where
//  the answer is "set lower expectations":
//
//  `lastpass/lastpass-cli` is LastPass's OWN tool — official, GPL, and the only
//  local way in. It is also the least capable of the tools SimpleVPN reads, and
//  saying so is kinder than letting somebody discover it at connect time. So the
//  copy is best-effort ON THREE NAMED POINTS rather than vaguely disparaging:
//
//    • it can never hand over a verification code (the tool has no field for one);
//    • the sign-in happens in Terminal, and its memory of your master password
//      expires — an hour, by default;
//    • the project moves slowly, so what works today is what will work.
//
//  What the copy deliberately does NOT do:
//    • it does not print a version or a date, which would rot;
//    • it does not editorialise about LastPass the company. Whether somebody keeps
//      their passwords there is their decision, not this app's, and a VPN client is
//      not the place to relitigate it. The maturity registry entry is `.untested`
//      like every other new feed, for the same reason as every other: nobody here
//      has watched a real vault answer.
//
//  And one thing it does say plainly, because it is genuinely good news and the
//  opposite of the Bitwarden case: SimpleVPN never sees the LastPass master
//  password and never sees the key derived from it either. The tool's own agent
//  holds that key and refuses to give it to any program that is not `lpass` —
//  verified in `agent.c`, and stronger than the local service Bitwarden offers,
//  which asks nothing of whoever connects to it.
//

import Foundation

nonisolated extension LocalVaultCopyBook {

    static let lastPass = LocalVaultCopy(
        title: "LastPass",
        summary: "SimpleVPN reads this VPN\u{2019}s sign-in from LastPass using "
            + "LastPass\u{2019}s own command-line tool.",
        explanation: "SimpleVPN reads one entry from LastPass with `lpass`, LastPass\u{2019}s own "
            + "command-line tool \u{2014} the LastPass app has nothing SimpleVPN can talk to. You "
            + "sign in once in Terminal with `lpass login`, and after that the tool\u{2019}s own "
            + "background helper holds the key to your vault and answers without asking anything. "
            + "SimpleVPN never sees your LastPass master password, and never sees that key either: "
            + "the helper hands it only to `lpass` itself and refuses every other program, "
            + "SimpleVPN included.\n\nWorth setting your expectations, because this one is "
            + "best-effort. Three things it cannot do, and none of them is something SimpleVPN can "
            + "fix at this end. It never hands over a verification code \u{2014} LastPass\u{2019}s "
            + "tool has no way to give one \u{2014} so you always type that yourself. Its memory of "
            + "your master password expires after an hour unless you tell it otherwise, and when it "
            + "does you sign in again in Terminal. And an entry set to ask for your master password "
            + "every time it is read cannot be read at all, because SimpleVPN will not ask you for "
            + "that password.\n\nSimpleVPN only ever reads, and only ever the one entry this VPN "
            + "names. It reads the copy already on this Mac rather than asking LastPass\u{2019}s "
            + "servers, so connecting never waits on the network \u{2014} if you change a password "
            + "in your browser, run `lpass sync` once. Nothing is written to your vault, and "
            + "nothing is copied to the clipboard.",
        symbol: "asterisk.circle.fill",
        storedKind: .lastPass,
        primaryDoc: VendorDocs.lastPassCLI,
        homebrewInstallCommand: "brew install lastpass-cli",
        blocks: [
            .toolMissing: (
                headline: "LastPass\u{2019}s command-line tool isn\u{2019}t installed on this Mac",
                steps: ["Install it with `brew install lastpass-cli`.",
                        "The LastPass app on its own has nothing SimpleVPN can read \u{2014} `lpass` is the way in."]
            ),
            .toolOutsideAllowList: (
                headline: "LastPass\u{2019}s command-line tool is installed, but not somewhere "
                    + "SimpleVPN will run it from",
                steps: []
            ),
            .notSignedIn: (
                headline: "LastPass isn\u{2019}t signed in on this Mac",
                steps: ["In Terminal, run `lpass login you@example.com` once.",
                        "SimpleVPN never asks for your LastPass master password \u{2014} the tool does, and keeps the key to itself."]
            ),
            // Signed in, and nothing is holding the key. NOT `notSignedIn`: the
            // person did sign in, possibly this morning, and being told otherwise is
            // how they conclude SimpleVPN cannot see their vault at all.
            .vaultLocked: (
                headline: "LastPass has forgotten your master password",
                steps: ["In Terminal, run `lpass login you@example.com` again.",
                        "Its helper forgets after an hour by default. Set `LPASS_AGENT_TIMEOUT` to 0 to be asked far less often."]
            ),
            .toolDivertsSecretToClipboard: (
                headline: "LastPass would copy the password to the clipboard instead of giving it "
                    + "to SimpleVPN",
                steps: ["Remove the `-c` (or `--clip`) from the file `~/.lpass/alias.show`.",
                        "SimpleVPN won\u{2019}t read a sign-in that would be left on the clipboard for anything on this Mac to take."]
            ),
        ],
        guidance: [
            // SimpleVPN never installs anything: the commands are shown, and the
            // user runs them. Latest release only, per the house rule.
            .toolMissing: EnablementGuidance(
                benefit: "Install LastPass\u{2019}s own command-line tool and SimpleVPN can get "
                    + "this VPN\u{2019}s username and password straight from LastPass when you "
                    + "connect. You will still type the verification code yourself \u{2014} "
                    + "LastPass\u{2019}s tool has no way to give one.",
                example: [
                    .init(text: "brew install lastpass-cli",
                          caption: "Install LastPass\u{2019}s command-line tool "
                              + "(SimpleVPN never installs it for you)"),
                    .init(text: "lpass login you@example.com",
                          caption: "Sign in to LastPass once, in Terminal"),
                    .init(text: "echo 'LPASS_AGENT_TIMEOUT=0' >> ~/.lpass/env",
                          caption: "Optional: stop it forgetting your master password after an hour"),
                ],
                doc: VendorDocs.lastPassCLI),
            .notSignedIn: EnablementGuidance(
                benefit: "Sign in once in Terminal and SimpleVPN can get this VPN\u{2019}s username "
                    + "and password from LastPass when you connect. Your master password goes to "
                    + "LastPass\u{2019}s own tool and never to SimpleVPN.",
                example: [
                    .init(text: "lpass login you@example.com",
                          caption: "Sign in to LastPass once, in Terminal"),
                    .init(text: "echo 'LPASS_AGENT_TIMEOUT=0' >> ~/.lpass/env",
                          caption: "Optional: stop it forgetting your master password after an hour"),
                ],
                doc: VendorDocs.lastPassCLI),
            .vaultLocked: EnablementGuidance(
                benefit: "Sign in again and SimpleVPN can read this VPN\u{2019}s sign-in from "
                    + "LastPass with nothing to type but the verification code. LastPass asks for "
                    + "your master password, not SimpleVPN, and the key it derives stays inside "
                    + "LastPass\u{2019}s own helper.",
                example: [
                    .init(text: "lpass login you@example.com",
                          caption: "Sign in again, in Terminal"),
                    .init(text: "echo 'LPASS_AGENT_TIMEOUT=0' >> ~/.lpass/env",
                          caption: "Keep it from forgetting again in an hour"),
                ],
                doc: VendorDocs.lastPassCLI),
            .toolDivertsSecretToClipboard: EnablementGuidance(
                benefit: "Take the `-c` out of that one file and SimpleVPN can read this "
                    + "VPN\u{2019}s sign-in from LastPass again. With it there, LastPass writes the "
                    + "password to the clipboard and gives SimpleVPN nothing \u{2014} and a VPN "
                    + "password left on the clipboard can be read by anything running on this Mac.",
                example: [
                    .init(text: "cat ~/.lpass/alias.show",
                          caption: "See what is in the file (it is a line of options, nothing secret)"),
                    .init(text: "rm ~/.lpass/alias.show",
                          caption: "Or remove it entirely, if you did not mean to have one"),
                ],
                doc: VendorDocs.lastPassCLI),
        ],
        // Reachable, unproven — which for this source is the ordinary state, because
        // the only way to PROVE a read works is to do one, and a read is not
        // something an availability check may do speculatively.
        uncheckedNote: "LastPass\u{2019}s tool is here and signed in, so SimpleVPN can read this "
            + "VPN\u{2019}s sign-in from it. Two things to expect: you type the verification code "
            + "yourself, because LastPass\u{2019}s tool has no way to give one \u{2014} and it "
            + "forgets your master password after an hour unless you have told it not to, after "
            + "which you sign in again in Terminal."
    )
}
