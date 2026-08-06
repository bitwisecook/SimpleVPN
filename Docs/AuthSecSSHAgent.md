# SSH agent sign-in

SimpleVPN can sign an SSH tunnel in with the keys an **SSH agent** holds, instead of being handed a
private key file. libssh asks the agent to sign the server's challenge; the key itself never reaches
us. That makes four things possible that a key file cannot:

- **1Password** — the key stays in the vault, and 1Password asks you to approve each use.
- **Secretive** — the key is generated inside this Mac's Secure Enclave and *cannot* be exported.
- **KeePassXC** — the key is added to the agent macOS already runs, only while the database is open.
- **Hardware tokens** (YubiKey and friends) behind `ssh-agent` — the token signs, after a touch.

The user-facing documentation is the embedded manual (`#ssh-agent`, `#ssh-agent-socket`). This note is
the engineering side: where it runs, why, and what to check when it doesn't.

## Where agent sign-in can run — and where it cannot

| SSH surface | Process | Agent sign-in |
|---|---|---|
| SSH tunnel, SOCKS mode, in-process (`SSHTunnelEngine`) | **app** | yes |
| SSH tunnel via `/usr/bin/ssh` (jump host / extra options) | **app** (child process) | yes — `-o IdentityAgent` |
| SSH probe / Network Tools SSH step (`SSHProbeSession`) | **app** | *could*, deliberately not offered |
| **SSH Network Tunnel** kind (`SSHNetworkTunnelEngine`) | **packet-tunnel extension, root** | **no** |

The **probe** row is a choice, not a limitation: the staged SSH probe could call
`ssh_userauth_agent` (it holds a normal libssh session), and it deliberately does not. Agent sign-in
is a *user-visible event* — 1Password shows an approval sheet, Secretive asks for Touch ID, a token
lights up — and a diagnostic that provokes that without being asked is a diagnostic nobody trusts.
The probe ladder already holds passwords back for the analogous reason (they count against the
server's sign-in limits). If it ever offers agent sign-in it must be behind the same explicit opt-in.

The extension is the whole reason this table exists. It runs as **root in the system context**: it has
no `SSH_AUTH_SOCK`, it is not in a login session, and reaching into a user's container for an agent
socket would be exactly the boundary violation the extension is designed not to make. That is already
written into `Shared/SSHBridge.h` ("no agent and no Kerberos") and it still holds.

Could the app authenticate and hand the result over? **No** — and this is worth recording so nobody
tries. An SSH publickey signature is over the session identifier of *that* session, so the signing
has to happen inside the session being authenticated. The only ways to give the extension agent
access would be to proxy the agent protocol from the app to the extension (a new bidirectional
channel, then `ssh_set_agent_socket` on an fd we passed across a process boundary), or to move the
whole session into the app. Neither is a credential travelling over IPC, so the "no secret in
`providerConfiguration`, credentials ride `startTunnel(options:)`" invariant is untouched either way —
but both are real designs, not a wiring change. Until one is built, the SSH Network Tunnel kind uses
a key (in-memory PEM) or a password.

## Which agent gets asked

`SSH_AUTH_SOCK` in a windowed app comes from the user's **launchd session**, not from a shell:

```
$ launchctl getenv SSH_AUTH_SOCK
/var/run/com.apple.launchd.51UGqtWLcW/Listeners
```

That is macOS's own `ssh-agent`, and it is what an app launched from the Dock inherits. The
`export SSH_AUTH_SOCK=…` line a vendor tells you to add to `~/.zshrc` is read by your shell and by
nothing else — so a GUI VPN client that only honoured the environment would never see 1Password's or
Secretive's keys. Hence `ssh.agent-socket`:

- in-process it becomes libssh's `SSH_OPTIONS_IDENTITY_AGENT` (`SSHSession.useAgentSocketPath:`);
- for the `/usr/bin/ssh` path it becomes `-o IdentityAgent="…"`. The quoting is load-bearing — every
  vendor path contains a space. Verified against the OpenSSH that ships with this macOS:

  ```
  $ ssh -V
  OpenSSH_10.3p1, LibreSSL 3.3.6
  $ ssh -G -o 'IdentityAgent="/tmp/a b/agent.sock"' localhost | grep identityagent
  identityagent /tmp/a b/agent.sock
  ```

An explicit path always wins over the inherited one, and nothing is ever chosen for the user: the
vendor table in `SSHAgentProbe.vendorAgents` only powers a "use this one" button in the editor for a
socket that is present.

## The three failure modes (and why we probe at all)

`ssh_userauth_agent` returns **`SSH_AUTH_DENIED` for three different situations** — verified in
libssh 0.12.2 `src/auth.c`: `!ssh_agent_is_running(session)` returns DENIED, a NULL first identity
returns DENIED, and so does a server that refuses every identity offered. libssh's internal
`ssh_agent_get_ident_count` / `ssh_agent_is_running` are not public API, so the bridge cannot tell
them apart either. Reporting one message for all three sends users to fix the wrong thing.

So `SimpleVPN/ControlPlane/SSHAgent.swift` speaks the agent protocol itself — one read-only
`REQUEST_IDENTITIES` round trip, no mutation of anybody's vault — and the answer decides the message:

| Probe state | What the user is told to do |
|---|---|
| no socket configured or inherited | start an agent, or set **SSH Agent Socket** |
| socket path present in config/env but nothing at it (stale) | the agent has quit — start it, or update the path |
| socket there, nothing answers (dead / wedged / permission / garbled) | restart the agent; the reason is quoted |
| agent answers, **0 identities** | unlock the vault / turn the agent on for that key / `ssh-add` |
| agent answers, **N identities**, libssh said denied | the server refused these N keys (named) — fix `authorized_keys` or the username |

Two more outcomes are reported honestly rather than folded in: `SSH_AUTH_PARTIAL` (the key was
accepted and the server wants a second factor) and `SSH_AUTH_ERROR` (the exchange broke), which carry
libssh's own detail.

## Agent forwarding (`ForwardAgent`) — deliberately not implemented

Checked, not assumed. libssh has the client half of the *request* (`ssh_channel_request_auth_agent`,
which sends `auth-agent-req@openssh.com`) and a callback for the server's `auth-agent@openssh.com`
channel opens (`callbacks.h`), but **no agent proxy**: forwarding means shuttling the agent protocol
between the server's channel and the local socket yourself. Two reasons that stays unwritten:

1. `auth-agent-req` is a **session-channel** request. SimpleVPN opens `direct-tcpip` channels only
   (SOCKS, port forwards, per-flow netstack channels) and never a shell or `exec` channel — there is
   no channel to send it on, and nothing on the remote side that would use a forwarded agent.
2. It is the feature with the worst security-to-value ratio in SSH: while the connection is up,
   anyone who can reach the forwarded socket on the server — root, certainly — can ask your agent to
   sign anything. OpenSSH's own manual says as much.

If a remote-command feature ever lands, revisit this with a per-VPN, default-off switch and an honest
warning. Until then the manual says why there is no switch.

## Setting each agent up (current versions only — the vendor's page is the authority)

**1Password** — turn on *Settings ▸ Developer ▸ Use the SSH agent*, then:

```
~/Library/Group Containers/2BUA8C4S2C.com.1password/t/agent.sock
```

Docs: <https://www.1password.dev/ssh/get-started/> (`developer.1password.com/docs/ssh/` redirects
here now).

**Secretive** — install it, create a secret, then:

```
~/Library/Containers/com.maxgoedjen.Secretive.SecretAgent/Data/socket.ssh
```

Docs: <https://github.com/maxgoedjen/secretive>

**KeePassXC** — turn on *Settings ▸ SSH Agent ▸ Enable SSH Agent integration* and add the key to the
entry's *SSH Agent* tab. **Leave SSH Agent Socket empty**: on macOS KeePassXC adds keys to the
OpenSSH agent macOS already runs, so the inherited socket is the right one. KeePassXC's own guide:
"Apple has made OpenSSH an integrated part of macOS with automatic agent startup when it is first
used. No further configuration is needed."

Docs: <https://keepassxc.org/docs/>

**macOS's own agent / a hardware token** — nothing to set; `ssh-add ~/.ssh/id_ed25519` (or
`ssh-add -K` for a token-backed key) and leave the field empty.

## Manual test recipe

1. `ssh-add -l` — note what the inherited agent holds (`The agent has no identities.` is a valid
   starting state and worth testing: it is the "running but empty" case).
2. In **Manage VPNs ▸ an SSH tunnel ▸ Sign-In**, set the method to **SSH agent**. The row should
   report what step 1 said, in words.
3. Point **SSH Agent Socket** at a path that does not exist → the row reports the socket is gone;
   connecting names it and tells you to start the agent.
4. Turn on 1Password's agent, press **Use 1Password's Agent**, then **Check Again** → the row should
   name the keys 1Password is offering. Connect: 1Password prompts for approval, and the tunnel comes
   up without SimpleVPN ever holding the key.
5. Connect to a server your key is *not* on → the failure names the keys that were offered and points
   at `authorized_keys` / the username, not at the agent.

## Automated coverage

- `SimpleVPNTests/ControlPlane/SSHAgentTests.swift` — the state machine and every message, against a
  fake environment: no socket, stale path, dead socket, agent with no keys, agent with keys, a
  truncated/garbled answer, an agent that returns FAILURE, and the wire parser itself.
- `SimpleVPNTests/ControlPlane/SSHAgentLiveTests.swift` — a **real** `ssh-agent` on its own socket
  against the user-space `sshd` from `Tools/ssh-live-test-fixture.sh`: agent sign-in succeeds through
  `ssh_userauth_agent`, an agent holding only an unauthorized key is refused *by the server*, and an
  empty agent is refused with the "no keys" diagnosis. Skips (loudly) without the fixture.
