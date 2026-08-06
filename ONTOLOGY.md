# ONTOLOGY

**One concept, one name, everywhere.** This file is the vocabulary SimpleVPN speaks: what each
thing IS, what WE call it, and what every vendor calls it.

It exists because SimpleVPN sits on top of sixteen VPN kinds and twelve sign-in sources, and
almost every one of them has its own word for the same idea. A gateway, a concentrator, a portal,
a peer, a coordination server and a tailnet are — from the user's point of view — the machine you
connect to. If the app repeats each vendor's dialect, a person who learns one editor learns
nothing about the next. So we translate once, here.

**This file is THE authority on naming.** The glossary used to live in `AGENTS.md`; it has been
moved here in full, so there is exactly one place to look and no chance of two lists drifting.
`AGENTS.md` now points here and keeps what is genuinely its own: the group taxonomy (which of the
five canonical groups a setting belongs to), the id/anchor contract, and the build rules.

**Read this before naming anything a user will read** — a label, a summary, an accessibility
string, a manual heading, an error sentence.

---

## The three rules that decide every naming argument

**1. The user's concept beats the vendor's word.** We name things after what the person is trying
to do, not after the implementation that happens to serve it. "It's an engine override" is a fact
about our code. This is why the private key's password belongs with signing in and not in a bucket
called Options.

**2. A vendor's own proper nouns keep their spelling.** The rule above stops at anything the user
must type, click or find in someone else's product. Keeper's command really is
`this-device persistent-login on`; 1Password's toggle really is "Integrate with 1Password SDKs";
`pass` really is called `pass`. Renaming those in our copy would make our instructions wrong. So:
**our words for our concepts, their words for their things** — and their words go in `code` spans
or quotation marks so the distinction is visible.

**3. Accuracy outranks consistency, but must be paid for in words, not in vocabulary.** When a
vendor's model genuinely differs, do not bend the shared term to fit — explain the difference in a
sentence. `sshNetworkTunnel` is not `ssh`; a Tailscale "server" is a coordination service rather
than a thing your traffic flows through. Say so. What is forbidden is inventing a second word for
a concept that already has one.

---

## Core concepts

### The thing you connect to

**House term: `server`** — "Server address", "Add a Server".

| Vendor / protocol | Its own word | Notes |
|---|---|---|
| OpenVPN | `remote`, server | The config directive is `remote`; quote it only when showing config |
| WireGuard | `Endpoint`, peer | `Endpoint` is a real key in `wg-quick` — quote it in a config summary, never as our label |
| IKEv2 / IPsec / L2TP | server, gateway | |
| FortiGate | gateway | Fortinet's docs say "FortiGate" |
| F5 BIG-IP APM | APM, virtual server | |
| Cisco AnyConnect / ocserv | headend, concentrator, gateway | "concentrator" is genuine Cisco vocabulary and genuinely opaque |
| Palo Alto GlobalProtect | portal, gateway | Two distinct things in GP: the *portal* hands out config, the *gateway* carries traffic. When both matter, name both explicitly |
| Juniper / Pulse | Connect Secure, VPN gateway | |
| Array Networks | AG, gateway | |
| SSH | host, jump host | `jump host` is ours for a bastion; see the glossary |
| Tailscale / Headscale | coordination server, control server, tailnet | **Not a server your traffic flows through.** Say "coordination service" when the distinction matters |
| Proxy Tunnel | upstream proxy | The proxy IS the destination here |

**Never**: endpoint, gateway, host, target, concentrator, headend, portal — as *our* label. Any of
them may appear in a sentence explaining a vendor's own terminology.

### Signing in

**House term: `sign in` (verb), `sign-in` (noun/adjective).** Never log in, login, logon, or
authenticate in UI copy. `authenticate` is fine in code and in this file.

| Concept | House term | Vendor words we translate from |
|---|---|---|
| Who you are | **username** | user, login, account name, identity, principal, email |
| The secret you know | **password** | passphrase (except where it opens a *key* — see below), secret, credential |
| The secret that opens a private key | **key passphrase** | key password, PEM password, `--key-password`, askpass |
| A short code from an app or token | **verification code** | OTP, TOTP, HOTP, one-time password/passcode, 2FA code, MFA token, Yubico OTP |
| A long-lived string that signs a machine in without a browser | **setup key** | auth key, authkey, pre-auth key, node key, enrolment token |
| Browser-based sign-in | **sign in with a browser** | SSO, SAML, OIDC, IdP flow, web auth |
| Proving identity with a file | **certificate** (+ **private key**) | client cert, identity, PKCS#12, p12, keypair |
| Hardware that proves identity | **security key** | token, smartcard, PIV card, FIDO2 authenticator, YubiKey (a brand — use it only for that brand) |
| The number that unlocks a security key | **PIN** | user PIN, token PIN |
| Where a stored sign-in lives | **password app** (user-facing) / **sign-in source** (ours) | password manager, vault, credential store, keychain (Apple's word — reserve it for Apple's keychain) |

**"Credential" is banned from UI copy** and asserted by test. It is fine in code
(`CredentialSource`, `RawCredentials`), because code has different readers.

### Inside a password app

Every vendor names its containers differently and they do not line up. Ours:

| Concept | House term | Vendor words |
|---|---|---|
| The one thing holding this VPN's sign-in | **entry** | item (1Password, Bitwarden), record (Keeper), resource (Passbolt), login, secret, bookmark |
| A container of entries | **vault** | vault, collection, folder, group, store, space, database |
| Which vault, when a person has several | **source instance** (ours) | — no vendor has a word for this because no vendor needs one |
| The identity you sign into the app with | **account** | account, tenant, organisation, workspace |
| How we reach the app | **transport** (ours) | — |

**`store`** is reserved for a `pass`/`gopass` **password store**, because that is its own name for
itself. Never use "store" generically for a vault.

### Traffic and routing

| Concept | House term | Vendor words |
|---|---|---|
| Everything goes through the VPN | **full tunnel** / "Send All Traffic" | redirect-gateway, default route, 0.0.0.0/0, `AllowedIPs = 0.0.0.0/0` |
| Only some networks go through it | **split tunnel** | split-include, split-exclude, partial tunnel |
| A network the VPN offers you | **route** | prefix, CIDR, subnet, network, allowed IP, advertised route, included route |
| A network deliberately kept out | **excluded route** / **bypass** | split-exclude, excludeLocalNetworks, negative route |
| Networks a peer shares with the tailnet | **advertised routes** | subnet routes, subnet router |
| Sending all traffic via another machine | **exit node** | Tailscale's own term; keep it |
| The largest packet that fits | **MTU** | MTU (universal — keep it) |

### What connecting actually does to your Mac

The one question about a connection a person can answer by watching their own machine, and
therefore the line the connect list and Manage VPNs are grouped on: **does this capture my
traffic, or does it hand me a port I have to aim things at?**

It is NOT the full-vs-split question above. A split-tunnel OpenVPN is still a whole-Mac
VPN — it takes the routes it offers, for every app, with nothing configured. A SOCKS proxy
takes no routes at all, for anybody, until something is pointed at it.

| Concept | House term | Means |
|---|---|---|
| Connecting changes where this Mac's traffic goes | **whole-Mac VPN** — section header "Whole-Mac VPNs" | It presents a network interface and takes routes, so every app follows it without being told to |
| Connecting opens a port on this Mac and does nothing else | **local port** — section header "Local Ports" | A SOCKS proxy or a named forward on `127.0.0.1`. No app uses it until it is aimed at it |

Words we translate away from, on the first side: packet tunnel, packet-tunnel provider,
`utun`, `NEPacketTunnelProvider`, "personal VPN", system extension, "full-routes path".
On the second: `ssh -D`, `-L`/`-R`, dynamic forward, `ocproxy`, "the no-root path",
proxy-only. All of those are facts about our code or someone's command line.

**Never** as our label:

- **"Tunnels" as the opposite of "VPNs"** — a VPN *is* a tunnel. This is the split that was
  cut in the wrong place (packet-tunnel extension on one side, subprocess and native on the
  other), which put F5 BIG-IP APM under "Tunnels" away from the VPNs it behaves identically
  to. It was asked about, and rejected, by the user.
- **"Other Connections"** for a list of configured profiles. It was honest while that
  section held only what was *running*; once it listed configured-but-idle profiles it was a
  second list of VPNs named after not being the first one.
- **"full tunnel"** for this axis. That term is taken, one table up, for Send All Traffic vs
  split tunnel — a question you ask *of* a whole-Mac VPN.

**Which side a connection is on is a fact about its CONFIGURATION, not only its protocol.**
Six of the sixteen kinds can be set up either way, so nothing may hard-code the answer per
kind:

| Kind | Side | Why |
|---|---|---|
| OpenVPN, WireGuard, Tailscale / Headscale, Proxy Tunnel, SSH Network Tunnel | whole-Mac | Each presents its own interface and takes routes |
| IKEv2, IPsec (IKEv1), L2TP / IPsec | whole-Mac | macOS owns the interface, but it is still every app. (No app can connect L2TP at all — it says so, in the section it belongs to) |
| SSH in **SOCKS proxy** or **Port forwards** mode | local port | `-D 1080`, or the `-L`/`-R` lines. No interface, no routes |
| SSH in **Network tunnel** mode | whole-Mac | `-w` is a point-to-point interface carrying a network. It is refused for an unrelated reason (it needs root), and refusing it in the section it belongs to is the honest place to do that |
| FortiGate, F5 BIG-IP APM, Cisco AnyConnect **with "Run In-Process" actually honoured** | whole-Mac | The built-in engine carries it: full routes, no proxy |
| GlobalProtect, Pulse **with "Run In-Process" AND browser sign-in** | whole-Mac | Browser sign-in ends in a cookie, and the cookie path carries any protocol whose settings the engine covers. These two have no in-process password path, so this is their only route to it |
| All five of those **without** it, plus Juniper and Array Networks always | local port | OpenConnect runs under `ocproxy -D <port>` — the no-root path this app uses — which is a SOCKS proxy on `127.0.0.1` and takes no routes |

The load-bearing rows are the OpenConnect ones. **F5 BIG-IP APM is a whole-Mac VPN when the
built-in engine carries it and a local port when the tool does** — and the tool is the
default — so its row follows the configuration, not the protocol. Filing an `ocproxy`
connection under "Whole-Mac VPNs" would promise system-wide protection that does not exist
— a security claim, not a naming quibble — so where the answer is uncertain, **the
local-port side wins**. "Asked for" is not "got", either: a setting the built-in engine
cannot express sends the connection back to the tool, so the question to ask is
`SubprocessTunnelManager.willRunInProcess` and never the toggle.

### Connection state

One vocabulary, because the status dot, the sidebar, VoiceOver and the CLI must agree.

| State | House term | Means |
|---|---|---|
| Nothing running | **off** | |
| Working on it | **connecting** | Includes signing in and negotiating |
| Traffic is flowing | **connected** | |
| The tunnel owns routes but is not fully up | **engaged** (ours, internal) | Deliberately distinct from `connected`: routing changes land before the VPN reports itself up. Not user-facing |
| Signed in, traffic outside the tunnel | **paused** | Not "disconnected" — the sign-in survives |
| Broke on its own | **dropped** | |

**Never** in UI copy: up/down, established, active/inactive, online/offline.

### Confidence and availability — two different axes

These are constantly conflated and must not be:

- **Availability** — can this work *on this Mac, right now*: installed, running, signed in,
  reachable. It changes when the user installs something. It is a live probe.
  Terms: **ready**, **needs setup**, **not installed**.
- **Maturity** — has anyone ever seen this work *at all*. It changes when a human reports a
  result. Terms: **tested**, **partly tested**, **untested**.

A source can be **ready** and **untested** simultaneously, and that is the normal state of a new
adapter. Never let one word carry both ideas.

---

## The binding one-term table (moved here from AGENTS.md)

This is the original short list, verbatim. It is the hard rule; the tables above are the
mappings that feed it.


| Concept | House term | Never |
|---|---|---|
| The remote machine a VPN connects to | **server** / "Server address" | endpoint, gateway, host, target (except quoting a protocol's own key, e.g. wg-quick `Endpoint`, in a summary) |
| A proxy on the way to the server | **connection proxy** / "Proxy Host" | egress proxy, upstream |
| SSH bastion | **jump host** | bastion alone (parenthetical "(bastion)" once is fine) |
| Authenticating | **sign in** (verb), **sign-in** (noun/adj) | log in, login, logon, authenticate (UI copy) |
| OTP / one-time code | **verification code** (Apple's word) | one-time passcode/password, OTP alone (a parenthetical "(OTP)"/"(TOTP)" gloss is fine) |
| Session keep-alive | **keepalive** (one word) | keep-alive, heartbeat |
| Routing everything through the VPN | **"Send All Traffic"** (control), **full tunnel** (gloss) | default route, send everything |
| Selective routing | **split tunnel** | policy tunnel |
| Keeping LAN reachable | **"Allow local network access"** | local LAN, exclude local networks |
| A connection every app follows without being told to | **whole-Mac VPN** (section "Whole-Mac VPNs") | packet tunnel, utun, "Tunnels" as a category, "Other Connections", full tunnel (that is the Send-All-Traffic axis) |
| A connection that only opens a port you aim apps at | **local port** (section "Local Ports") | proxy on its own — a *connection proxy* is the thing you go THROUGH to reach a server, which is a different concept one row down |
| Credentials | **username / password** | user, login, account name |
| Other products' own labels | keep their vocabulary (1Password "one-time password" field, GlobalProtect "portal/gateway", System Settings pane names) | translating another product's proper terms |

Stable descriptor/spec **ids never change** when a display name changes — ids are the
CLI/MDM/manual-anchor contract (`openvpn.server`, `wg.endpoint`, …). Manual anchors key on
ids, so renames only touch heading/link text.

---
## Writing help text

Every setting has a one-line summary and, where it earns one, a longer explanation. Consistency
here matters as much as naming, because the summaries are read in bulk.

**Shape.** Say what it does, then when you would change it. Present tense, second person, active
voice. No "this setting allows you to".

> **Port** — Use a different port. Leave empty to use the configuration file's port.

**Length.** One or two sentences in a summary. Detail belongs in the explanation or the manual.

**Defaults.** State the default when it is not obvious, in the same shape every time: "Default:
on." / "Nothing is chosen until you choose it."

**Consequences over mechanisms.** "UDP is fastest. TCP gets through restrictive networks" beats a
description of transport protocols. The user is deciding, not learning.

**Never**: jargon without a gloss, a vendor's internal term as though it were ours, "simply", "just",
"obviously", or an instruction to do something we could have done for them.

**Failure text names the fix.** A message that says what broke without saying what to do is half a
message. Every blocked state must name the one action that clears it — and if two causes are
genuinely indistinguishable, say both rather than guessing.

**Latest version only.** When documenting someone else's product, describe its current release and
link their page for the rest. No version matrices, no "on older versions this toggle is called…".

---

## Adding a new VPN kind or sign-in source

1. Find your concept in the tables above and use **our** word for it. If it genuinely is not
   there, add a row here *first* — the mapping is the design decision, and the code follows.
2. Say which side of the whole-Mac / local-port line it falls on — and whether its own
   settings can move it, as SSH's mode and OpenConnect's "Run In-Process" do. That answer is
   a value (`ConnectionScope`), never a list of kinds written out in a view, because it
   decides which section the user finds it in.
3. Put its settings in the canonical groups (`AGENTS.md`: Connection, Sign-In, Traffic, Security,
   Advanced). A group with nothing in it is omitted, never shown empty.
4. Quote the vendor's own names for commands, toggles and files verbatim, in `code` spans.
5. Write the summary in the shape above, and give it a manual anchor — the parity test will fail
   the build without one.
6. Register its maturity honestly. New means untested, and untested is not an insult.

## Why this file exists at all

Two things went wrong before it did. Settings were grouped by *implementation* (three sign-in
settings living under Options because they are engine overrides), which produced a signpost block
apologising for their location. And the same concept picked up several names across surfaces, so a
person who had learned one editor had to relearn the next. Both are naming failures before they
are UI failures, and neither is visible from inside a single screen — which is why the vocabulary
is written down in one place instead of decided per pull request.
