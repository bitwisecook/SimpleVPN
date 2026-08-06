# LastPass as a sign-in source

`SimpleVPN/Credentials/LastPassProvider.swift` + `LastPassCopy.swift` · settings in
**Settings ▸ Sign-In Sources ▸ LastPass** · manual anchors `creds-lastpass-*`

**Nobody has run this against a live LastPass vault.** Neither `lpass` nor a LastPass account exists
on the machine it was written on. Everything above "Manual test recipe" is derived from
`lastpass/lastpass-cli`'s own source and man page, with the file and function cited for every claim.
Everything below it is what a person with LastPass should do to find out, including the parts that
are *expected* to fail.

## Why this source is marked best-effort — and why that is not a slur

`lastpass/lastpass-cli` is LastPass's own tool, GPL-licensed, and the only local read path LastPass
has. It is also the least capable of the tools SimpleVPN reads. The UI copy says so, on three named
points rather than vaguely, because each is structural:

| Limit | Why it cannot be worked around here |
|---|---|
| **No verification code, ever** | `account_to_json_field` (`json-format.c`) emits `id`, `name`, `fullname`, `username`, `password`, `last_modified_gmt`, `last_touch`, `share`, `group`, `url`, `note` — and nothing else. There is no `lpass totp` subcommand. Nothing to read, nothing to compute from. |
| **Its session expires** | `agent_run` (`agent.c`) sets `alarm(3600)` unless `LPASS_AGENT_TIMEOUT` says otherwise. After that, a read wants a master password, which SimpleVPN will not ask for. |
| **"Require Password Reprompt" entries are unreadable** | `cmd_show.c` calls `agent_load_key` for any entry with `pwprotect` set, *regardless* of the agent — i.e. it prompts. SimpleVPN's stdin is `/dev/null`, so that path fails cleanly and is reported as its own state. |

Release cadence, measured 2026-08-05 so it is dated rather than editorialised: v1.4.0 (2024-04-15),
v1.5.0 (2024-05-17), v1.6.0 (2024-08-13), v1.6.1 (2024-11-14); no commit on the default branch since
2025-04-22. Quiet, not abandoned. **The shipped copy deliberately prints no version and no date** —
those rot — and says "moves slowly" plus the three limits above, which is the part a user can act on.
Nothing in the shipped copy comments on LastPass the company: whether somebody keeps their passwords
there is their decision, and a VPN client is not the place to relitigate it.

The maturity registry entry is `.untested`, exactly like every other new feed, for the same reason as
every other: nobody here has watched a real vault answer.

## The one genuinely good thing, and it is better than Bitwarden's

SimpleVPN never sees the LastPass master password **and never sees the key derived from it either**.
`agent_run` refuses any peer whose uid, gid or *executable* differs from its own
(`!process_is_same_executable(cred.pid)`), so the vault key reaches `lpass` and nothing else. Compare
`bw serve`, which authenticates nobody and will hand items to any program on the Mac. That is why
this source is **not dormant** the way Bitwarden's CLI fetch path is: one `lpass login` in Terminal
is enough, and every fetch afterwards is silent, with no secret held at this end.

## What SimpleVPN runs, exactly

Binary resolution is `LocalToolRunner.locate("lpass")` — the execution allow-list, never `PATH`.
`Settings ▸ Sign-In Sources ▸ LastPass ▸ LastPass CLI location` (`signin.tool.lpass.path`) is the one
sanctioned way to name another copy.

**Liveness (deep scan):**

```
lpass status --quiet --color=never
```

`--quiet` on purpose: without it the tool prints the signed-in email address on stdout, and an
availability probe has no business reading somebody's address. Exit 0 = the agent is holding a key;
exit 1 = it is not (`cmd_status.c`). It is **prompt-free by construction**: `cmd_status` calls
`agent_ask` (a socket read) and *not* `agent_get_decryption_key`, so it can never reach
`agent_load_key` and never asks for a master password.

**Read:**

```
lpass show --sync=no --expand-multi --json --color=never -- <entry>
```

Every flag is load-bearing:

* `--sync=no` — a connect must never wait on LastPass's servers, and must never upload. The cost is
  documented: a password changed in the browser needs one `lpass sync`.
* `--expand-multi` — **without it, two entries sharing a name make the tool print
  `Multiple matches found.` on stdout and `exit(EXIT_SUCCESS)`** (`cmd_show.c`). A caller that
  trusted the exit code and took stdout as the password would hand a VPN a line of prose. With `-x`
  we get every match and disambiguate ourselves by username, like the Bitwarden picker.
  `LastPassWire.entries` *still* checks for that marker, because "the vendor changed its mind" must
  not become "your password is now the word Multiple".
* `--json` — username and password from one read, so they cannot straddle a vault change.
* `--color=never` — colour escapes inside a password would be a corrupted password. The tool only
  colours a tty and ours is a pipe; saying so removes the assumption.
* `--` — the entry reference is the user's own text and may begin with a dash.
* **No `-c`, no `--clip`, ever.** See below.
* **Exact matching only.** `--fixed-strings` and `--basic-regexp` exist and are deliberately not
  passed: a loose match can read a different entry, and reading the wrong sign-in is worse than
  reading none. Hence the UI's `Work/VPN/GR Lab` prompt rather than `GR Lab`.

**Child environment** (`LocalToolRunner.childEnvironment`, built not inherited, plus three entries):

| Entry | Why |
|---|---|
| `LPASS_HOME=<the directory we probed>` | so the files checked and the process run can never disagree |
| `LPASS_DISABLE_PINENTRY=1` | a graphical master-password dialog must never appear from a background refresh. With it set, `password_prompt` takes the stdin path (`password.c`), stdin is `/dev/null`, and the read fails at once instead of hanging or drawing a dialog nobody asked for |
| `LPASS_CLIPBOARD_COMMAND=/usr/bin/true` | defence in depth only — see below |

`LPASS_AGENT_DISABLE` is **deliberately absent**: setting it would stop the agent being used, which
is the one thing that makes this source work without a prompt.

## The clipboard, which is the finding this feed exists to guard

**`-c` / `--clip` is not the default.** `cmd_show.c` prints to stdout unless `clip` is set, and
SimpleVPN never passes it.

**But it can be forced on, permanently, by a file the user owns.** `expand_aliases` (`lpass.c`) reads
`$LPASS_HOME/alias.show` and *prepends* its tokens to argv. The tool's own man page suggests exactly
this shape:

```
echo 'show --password -c' > ~/.config/lpass/alias.passclip
```

There is no `--no-clip`, so an alias carrying `-c` cannot be overridden by anything we append — and
`cmd_show.c` guards its print with `if (!clip)`, so the password would go to the pasteboard and
SimpleVPN would get nothing. A VPN password must not sit on the pasteboard.

So SimpleVPN **reads that file and refuses to fetch while it would divert**, with one sentence and
one fix (`LocalVaultBlock.toolDivertsSecretToClipboard`, the one new block case this feed adds). The
guard is deliberately generous about what counts, because a false positive costs one sentence and a
false negative costs a password on the pasteboard:

* `-c` alone;
* any **short cluster** containing `c` — the man page's own `show --password -c` written `-cp`, which
  `getopt_long` reads as `-c -p`;
* any **unambiguous long-option abbreviation** of `clip`. `getopt_long` accepts prefixes; `show`
  declares both `clip` and `color`, so `--c` is ambiguous and rejected by the tool itself, while
  `--cl`, `--cli` and `--clip` all mean `--clip`. All three count.

`LPASS_CLIPBOARD_COMMAND=/usr/bin/true` is set as well — `clipboard_open` runs that command through a
shell and pipes stdout into it, so a `--clip` that somehow got through would feed a program that
reads nothing rather than the pasteboard. It is **not** the guard: `$LPASS_HOME/env` is applied by
`load_saved_environment` with `setenv(…, overwrite: true)` and can override any of our entries.

## The cheap probe, and one side effect worth knowing

`LastPassHomeProbe` does five `stat` calls in `~/.lpass` and at most one small file read. No
subprocess, no prompt, no network, nothing spent. The filenames are the tool's own
(`pathname_type_lookup` in `config.c`):

| File | What its presence means |
|---|---|
| `username` + `verify` | a sign-in has been *completed* here at some point |
| `blob` | there is a cached vault (not proof of a usable key, which is why it is not the test) |
| `agent.sock` | an agent has run; whether one is *listening* is `lpass status`'s job |
| `plaintext_key` | `lpass login --plaintext-key` wrote the derived key to disk in the clear |
| `alias.show` | default options prepended to every `lpass show` |

**`lpass status` is NOT a reliable liveness probe in the `--plaintext-key` configuration.**
`agent_start` returns early when `plaintext_key` exists, so no agent is ever started, so
`agent_ask` fails, so `lpass status` says "Not logged in" — while reads work perfectly through
`agent_get_decryption_key`'s on-disk branch. `LastPassAvailabilityRules` therefore reports
`.unchecked` rather than `.blocked(.vaultLocked)` when that file is present. (The tool's own man page
calls `--plaintext-key` "discouraged except in limited situations, as it greatly decreases the
security of data"; SimpleVPN neither recommends nor forbids it, and simply does not lie about the
state it produces.)

**`lpass` creates `~/.lpass` on any invocation** — `config_path_for_type` calls
`mkdir(config, 0700)`. So `deepScan` does not run `lpass status` at all when the directory does not
exist. A probe must not leave a folder in somebody's home directory to find out they don't use
LastPass.

## Where SimpleVPN looks for `lpass`

`ToolCatalog` asserts **no vendor installer path**, on purpose. Homebrew's `lastpass-cli` formula and
MacPorts' port both land in prefixes the generic location classes already cover, and the project's
own build is `make install` to a prefix the builder chooses — which is exactly the case that produces
`toolOutsideAllowList`, and exactly what the tool-path setting is for. A guessed path presented as a
documented one sends people looking in the wrong place.

## Configuration levels

* **Level 1 (transport)** — `creds.lastpass.tool-path` (`signin.tool.lpass.path`), plus the vendor's
  own on/off switch `creds.lastpass.enabled`. That is the whole configuration surface.
* **Level 2 (instance)** — **none, and the vendor is `.single`.** `lpass` keeps one signed-in account
  per configuration directory: `agent_save` writes a single `username` value, `cmd_status` reads that
  one value back, `login` overwrites it. There is no shape in which two LastPass accounts are signed
  in at once. Which folder holds the cache *looks* instance-shaped, but a level-2 field cannot exist
  for a single-instance vendor, and putting a "which vault" question at level 1 would be exactly the
  conflation the three-level model exists to fix. So `LPASS_HOME` is pinned to the directory we
  probe. Somebody who keeps their cache elsewhere is reported as **not signed in** — a coherent state
  with a real fix, never a wrong-vault read.
* **Level 3 (per VPN)** — `{kind: .lastPass, reference: <entry name or id>, account: <username>}`.
  No instance id (there is nothing to name), no secret, ever.

MDM pins all of it through the existing keys: `SignInSourcesAllowed` / `SignInSourcesForbidden` with
the slug `lastpass`, and `SignInSourceToolPaths` with the tool name `lpass`.

## Manual test recipe

You need a real LastPass account. Nothing here is destructive: no step writes to your vault, and no
step signs you out unless it says so.

### 0. Baseline — the row before anything is installed

1. Make sure `lpass` is not installed and `~/.lpass` does not exist.
2. **Settings ▸ Sign-In Sources.** Expect: **LastPass** either absent from the sign-in chooser, or
   present as an "other password app on this Mac" *pointer* if the LastPass desktop app is installed.
   In the settings pane its state should read "not installed".
3. Confirm `~/.lpass` still does not exist. **If SimpleVPN created it, that is a bug** — the deep
   scan is supposed to skip `lpass status` entirely in this state.

### 1. Tool installed, never signed in → `notSignedIn`

```
brew install lastpass-cli
```

1. In SimpleVPN, reopen **Settings ▸ Sign-In Sources**. Expect the LastPass row to appear, blocked
   with **"LastPass isn't signed in on this Mac"**, and an enablement banner whose first command is
   `lpass login you@example.com`.
2. Check `~/.lpass`: it may now exist (the *pane's own* probe never runs the tool, but a deep scan is
   allowed to once the directory is there). Either way, **no master-password dialog should ever
   appear**, and SimpleVPN must not become unresponsive.

### 2. Installed somewhere we won't run from → `toolOutsideAllowList`

```
mkdir -p ~/bin && mv "$(brew --prefix)/bin/lpass" ~/bin/lpass
```

1. Expect the row to say **"installed, but not somewhere SimpleVPN will run it from"** and to name
   the path `~/bin/lpass` in its banner — *not* "isn't installed".
2. Paste that path into **LastPass CLI location**. Expect the validation line to read "SimpleVPN
   doesn't look in this folder on its own — it will use this one because you chose it."
3. Put it back (`mv ~/bin/lpass "$(brew --prefix)/bin/lpass"`) and clear the field.

### 3. Signed in → `ready`, and a real fetch

```
lpass login you@example.com
lpass status            # expect: Logged in as you@example.com.
```

1. In SimpleVPN, expect the LastPass row to go to **ready**. It may take one refresh cycle.
2. Create or pick a LastPass entry for a VPN you can actually connect to. Note its **full** name
   including folders, e.g. `Work/VPN/GR Lab`.
3. Edit that VPN ▸ **Sign-In** ▸ choose **LastPass** ▸ paste the full name ▸ Save.
4. **Connect.** Expect: username and password filled with nothing typed, and the verification code
   field still asking for a code. **That last part is correct, not a bug** — LastPass's tool has no
   code to give.
5. Now the negative test that matters: run `pbpaste` immediately afterwards. **Your VPN password must
   not be there.**

### 4. The name-matching trap

1. Change the VPN's entry reference to just `GR Lab` (drop the folders) and connect.
2. Expect: **"LastPass has no entry named "GR Lab". The name has to match exactly — include its
   folders, like Work/VPN/GR Lab."** If you get something vaguer, the error mapping in
   `LastPassWire.error` needs the tool's actual wording adding to it.
3. Put the full name back.

### 5. Several matches

1. Create a second entry with the *same* name in a different folder, both with passwords.
2. Reference it by the shared bare name and connect. Expect **"2 LastPass entries match — paste the
   entry's id instead of its name, or set the username so SimpleVPN knows which one you mean."**
3. Set the **Username** field to one entry's username. Expect the fetch to succeed and pick that one.
4. Get an id with `lpass ls` and paste it as the reference. Expect that to work too.
5. Delete the duplicate.

### 6. The agent forgetting → `vaultLocked`

```
pkill -f 'lpass \[agent\]'
lpass status            # expect: Not logged in.
```

1. In SimpleVPN, expect the row to become **"LastPass has forgotten your master password"** — *not*
   "isn't signed in". Being told you never signed in when you did is the specific failure this state
   exists to avoid.
2. Try to connect. Expect the recovery notice, and **no master-password dialog of any kind**.
3. `lpass login you@example.com` again; expect ready.
4. Optional, and the fix worth documenting for real users:
   `echo 'LPASS_AGENT_TIMEOUT=0' >> ~/.lpass/env`, then repeat step 1 — the agent should now survive.

### 7. The clipboard alias → `toolDivertsSecretToClipboard`

**This is the most important test in this file.**

```
echo 'show -c' > ~/.lpass/alias.show
```

1. Expect the LastPass row to become **"LastPass would copy the password to the clipboard instead of
   giving it to SimpleVPN"**, with the banner naming `~/.lpass/alias.show`.
2. Try to connect. Expect a refusal with that same sentence — and then run `pbpaste`. **Your password
   must not be on the clipboard.** If it is, SimpleVPN ran the tool when it should not have.
3. Repeat with each of these, one at a time. All four must be caught:
   `show -cp`, `show --clip`, `show --cl`, `show --cli`.
4. Repeat with `show --color=never`. This must **not** be caught — `--color` is a different option
   and blocking it would be a false positive.
5. `rm ~/.lpass/alias.show` and confirm the row returns to ready.

### 8. "Require Password Reprompt"

1. In the LastPass web vault or app, switch **Require Password Reprompt** on for the VPN's entry.
2. Connect. Expect **"That LastPass entry asks for your master password every time it is read, and
   SimpleVPN never asks for it"** — and, again, **no dialog**.
3. Switch it back off.

### 9. Staleness, which is the cost of `--sync=no`

1. Change the VPN entry's password in the LastPass web vault.
2. Connect immediately. Expect the **old** password (and probably a failed sign-in from the server).
   That is the documented trade: a connect never waits on LastPass's servers.
3. Run `lpass sync`, connect again, expect success.

### 10. Nothing leaks

1. `simplevpn` diagnostic report (or **Help ▸ Report a Problem**), submitted with tool details on.
   Grep the payload for your VPN password and your LastPass master password. **Neither may appear.**
   The LastPass section should carry only: state words, `lpass`'s paths and version, and whether the
   app is installed.
2. `log stream --predicate 'subsystem == "com.bragi0.SimpleVPN"' --level debug` during a connect.
   Expect one line, `lastpass entry resolved for <profile>`, and no secret anywhere.
3. While a connect is in flight, `ps -Ao args | grep lpass`. Expect the entry name and the flags, and
   **no password and no key** — argv is world-readable, which is why the only things on it are the
   user's own labels.

## What to report back

Whichever of §3–§9 behaved differently, with the tool's *exact* stderr line — that is what
`LastPassWire.error` matches on, and its strings were taken from the source rather than from a live
run. Anything unmatched falls through to a scrubbed, truncated "LastPass couldn't provide the
sign-in: …", which is safe but vaguer than it needs to be.
