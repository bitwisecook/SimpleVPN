# Policy Events, Metadata & Commands — the Tcl vocabulary

Authoritative catalog for the PBR (tier-3) scriptable engine — see `PolicyRouting.md` for
the datapath. Goals: **comprehensive** VPN-lifecycle coverage, **cohesive predictable
names** a human can guess and pick from a list, full **read/write of any handshake portion**,
and rich **metadata + connection stats** (per VPN and per advertised route).

## Naming convention (predictable, not memorized)

1. **`SCOPE_MOMENT`** — uppercase, `_`-separated. SCOPE ∈ `POLICY` (engine), `NET` (host),
   `VPN` (one tunnel's session/status), `VPN_HS` (one tunnel's **handshake** steps), `DNS`,
   `FLOW`, `TLS`, `HTTP`.
2. **Two VPN tiers, so the timeline reads at a glance:** `VPN_*` = session & status
   (connect / up / health / down); **`VPN_HS_*` = handshake internals** (resolve → cert →
   kex → auth → config → tunnel). If it happens *during establishment*, it's `VPN_HS_`.
3. **Tense encodes timing.** A moment you can still *influence* uses **-ING / _REQUEST**
   (inputs writable); the *result* uses **past tense / _DONE** (outputs readable).
4. **Detail is a property, never a new event.** `VPN_DOWN` + `[VPN::down_reason]`, not
   `VPN_DOWN_NETWORK`. Keeps the pick-list short.
5. **One SCOPE = one subject.** Every `VPN_*`/`VPN_HS_*` event concerns one named tunnel
   (`[VPN::name]`); `POLICY_*`/`NET_*` are engine/host-wide.
6. **Read anywhere, write only in-window.** Getters valid in any event; a mutator is valid
   only while that portion is malleable (rewrite a pushed route in `VPN_HS_CONFIG`, not
   after `VPN_UP`). Every property below is tagged **RO** or **RW (event)**.

## VPN session & status events — `VPN_*`

| Event | Fires | Key properties (RO unless noted) |
|---|---|---|
| `VPN_CONNECTING` | bring-up requested, **before any I/O** | `name` `id` `kind`; **RW:** `endpoint` `transport` `port` `config_override` `creds_source`; `VPN::abort` |
| `VPN_UP` | **fully** operational | all metadata + stats baseline; actions: `ROUTE::default via`, drain-in, bring up dependents |
| `VPN_HEALTH` | periodic / on change | `rtt` `loss` `jitter` `tx_bps` `rx_bps` `dpd_state` `last_handshake` |
| `VPN_REKEY` | SA/key renegotiated | `cipher` `key_age` |
| `VPN_REASSERTING` | re-establishing under us (net change, no full down) | `trigger` |
| `VPN_DOWN` | left connected | **`down_reason`** = intentional \| network \| auth \| crashed \| unknown; `last_default` |
| `VPN_RETURNED` | reconnected after an **unexpected** drop | `prior_state` `last_default` |
| `VPN_REMOVED` | profile deconfigured | `name` `id` |

## VPN handshake events — `VPN_HS_*` (timeline order)

| Event | Fires | Readable | Writable (this event) |
|---|---|---|---|
| `VPN_HS_RESOLVING` | about to resolve the server name | `hostname` | override resolver / static IPs |
| `VPN_HS_RESOLVED` | server name resolved | `candidates` `chosen` | reorder / pin `chosen` |
| `VPN_HS_TRANSPORT` | L4 (TCP/UDP/TLS-socket) up | `local` `remote` `proto` | — |
| `VPN_HS_SERVERCERT` | server presented cert (TLS) / host key (SSH) | `chain` `subject` `issuer` `san` `sha256` `not_before/after` | `cert_accept` / `cert_reject <why>` / `cert_pin` — **default-secure** |
| `VPN_HS_KEX` | crypto negotiated | `cipher` `tls_version` `dh_group` `integrity` | `CRYPTO::require` / `reject` |
| `VPN_HS_AUTH_REQUEST` | server requests auth | `method` `realm` `prompt` `user_hint` | `VPN::auth user/pass/otp/cert` |
| `VPN_HS_AUTH_CHALLENGE` | dynamic/static challenge or SSO | `challenge` `sso_url` `is_echo` | `AUTH::respond` / drive SSO |
| `VPN_HS_AUTH_DONE` | auth resolved | `success` `server_message` | — |
| `VPN_HS_CONFIG` | server pushed config **before applied** | `PUSH::routes/dns/search/address/mtu/option` | **rewrite/add/drop** any pushed directive |
| `VPN_HS_ADDRESS` | client IP(s) assigned | `v4` `v6` `gateway` | — |
| `VPN_HS_TUNNEL` | utun plumbed, routes/DNS installed | `interface` `effective_settings` | — |

`VPN_HS_CONFIG` is the high-value hook: a server's pushed `0.0.0.0/0` is subjected to the
routing switch, and pushed DNS folds into a listener chain instead of the system resolver.

### POLICY / NET scope

`POLICY_INIT`, `POLICY_RELOAD`, `POLICY_SHUTDOWN`; `NET_CHANGE` (Wi-Fi↔Ethernet / new default
iface), `NET_CAPTIVE` (portal detected). Data-plane events (`DNS_*`, `FLOW_*`,
`TLS_CLIENTHELLO`, `HTTP_REQUEST`) are in `PolicyRouting.md`.

### Proxy / PAC events

Fire when a flow's chosen egress has a proxy policy (see `PolicyRouting.md` › Proxies & PAC).

| Event | Fires | Readable | Writable (this event) |
|---|---|---|---|
| `PAC_REQUEST` | before `FindProxyForURL` runs | `PAC::url` `PAC::host` `PAC::client_ip`, egress | `PAC::url/host/client_ip set`; short-circuit (skip PAC) |
| `PAC_RESPONSE` | after it returns | `PAC::result` (raw string), `PAC::proxies` (parsed list) | rewrite `PAC::result`/`PAC::proxies`; `PROXY::via` |

The PAC's own `dnsResolve`/`myIpAddress` are bound to the egress's resolver + fake-IP map and
are themselves interceptable.

### Mediator (intent) events — rewrite what engines push to the host

The Route/DNS/Proxy mediators (see `StateMediators.md`) fire an event at **intent capture** —
when an engine submits or updates what it wants on the host (a remote-pushed route, a netmap
update, a DHCP renewal, a pushed resolver or proxy), *before* the arbiter merges and applies it.
Handlers inspect and **rewrite the intent**: change a pushed route into a different one, redirect
it to another egress, drop it, or bind a translation/lookup table. The `*_CHANGED` variants fire
when the **monitor** detects an *external* change to the host (drift), so policy can re-assert or
adapt. (These edit config-plane intent synchronously — pure compute + table binds, no async I/O.)

| Event | Fires | Readable | Writable |
|---|---|---|---|
| `ROUTE_ADVERTISED` | engine submits/updates a route intent | `ROUTE::prefix` `egress` `metric` `is_default` `source` | rewrite prefix/metric; `ROUTE::via <egress>` (redirect); `ROUTE::drop`; `ROUTE::translate <dg>` (bind NAT/xlat table) |
| `ROUTE_WITHDRAWN` | a route intent is withdrawn | `prefix` `egress` | keep / veto |
| `ROUTE_CHANGED` | **external** route-table drift (PF_ROUTE) | what changed, `by` (if known), `expected_owner` | `ROUTE::reassert` / alert / adapt |
| `DNS_PUSHED` | engine submits DNS intent | `resolvers` `search` `matchDomains` `egress` | rewrite resolvers; reassign `DNS::domains`; `DNS::table <dg>`; drop |
| `DNS_CHANGED` | **external** DNS drift (SCDynamicStore) | changed keys | re-assert / alert |
| `PROXY_PUSHED` | engine submits proxy intent | `manual`/`pac`, `egress` | rewrite proxy; swap PAC; force direct; bind lookup table |
| `PROXY_CHANGED` | **external** proxy drift (SCDynamicStore) | changed | re-assert / alert |

`VPN_HS_CONFIG` is the *bulk* handshake-time push (edit everything at once via `PUSH::`); these
fire *per item* and also on **mid-session** changes, for fine-grained rewriting.

```tcl
when ROUTE_ADVERTISED {
    if {[ROUTE::prefix] eq "10.0.0.0/8"} {          # a remote pushes 10/8…
        ROUTE::via "Corp"                           # …keep it, but send it to Corp
        ROUTE::translate dg:corp_remap              # …and translate its addressing via a table
    }
}
when DNS_PUSHED     { DNS::domains set {*.corp *.internal} }   # this VPN's DNS owns only its domains
when ROUTE_CHANGED  { if {[ROUTE::is_default] && [ROUTE::owner] ne [ROUTE::expected_owner]} { ROUTE::reassert } }
```

**Handling changes made outside the VPNs.** The `*_CHANGED` events fire for a change from **any**
source outside our mediators — another VPN client, manual `route`/`networksetup`/`scutil`,
DHCP/RA on the physical link, macOS network reconfiguration, a captive portal. The handler gets
the full picture and **chooses** the response; it is not limited to re-asserting:

- Inspect: `ROUTE::old` / `ROUTE::new` / `ROUTE::by` (source/process if known) / `ROUTE::expected`
  (and the `DNS::`/`PROXY::` equivalents).
- Verdicts: `…::reassert` (override back to our desired), `…::accept` (adopt the external change
  as the new desired), `…::merge` / `…::transform` (adapt — e.g. keep their new LAN route but
  re-pin our default), `…::alert` (surface only). **Default with no handler = tier-2 behavior:**
  re-assert our desired, ≤1-owner enforced.

```tcl
when ROUTE_CHANGED {
    switch [ROUTE::by] {
        dhcp    { DG::set local_nets [ROUTE::new]; ROUTE::accept }   ;# adopt the new LAN, remember it
        default { if {[ROUTE::is_default]} { ROUTE::reassert } }     ;# someone else grabbed default → take it back
    }
}
when DNS_CHANGED   { if {[DNS::by] ne "us"} { DNS::reassert } }       ;# external resolver change → restore split-DNS
when PROXY_CHANGED { PROXY::alert "system proxy changed by [PROXY::by]" }
```

## Control plane — events & commands

Everything off the per-flow datapath: policy lifecycle, host/network conditions, timers &
schedules, orchestration, feeds, health, incidents. Async I/O (vetted connectors) is allowed
here — it never blocks a packet — and handlers may await. (The data plane — FLOW/DNS/handshake —
stays pure-compute + table reads.)

### Control-plane events

| Event | Fires | Typical use |
|---|---|---|
| `POLICY_INIT` / `POLICY_RELOAD` / `POLICY_SHUTDOWN` | policy (re)load / teardown | set up `VPN::require`, listeners, tables, timers |
| `POLICY_MDM_CHANGED` | managed (MDM) config changed | re-read gates/pins |
| `NET_CHANGE` | host primary network changed | re-evaluate reachability |
| `NET_PRIMARY_CHANGED` | default interface/service changed | re-pin, refresh local nets |
| `NET_LINK` | an interface went up/down | `[NET::iface]` `[NET::up]` |
| `NET_CAPTIVE` | captive portal detected / cleared | pause tunnels, allow portal |
| `NET_SLEEP` / `NET_WAKE` | system sleep / wake | tear down / re-establish, re-assert |
| `NET_REACHABILITY` | a watched target became (un)reachable | failover, health |
| `TIMER <name>` | a `TIMER::create` interval | refresh feeds, housekeeping |
| `SCHEDULE <name>` | a cron/at schedule fired | scheduled policy changes |
| `HEALTH_TICK` | periodic global tick | dashboards, aggregate stats |
| `INCIDENT` | a tunnel incident/failure was classified | react to failures, notify |
| `FAILSAFE_ENGAGED` / `FAILSAFE_RELEASED` | kill switch engaged / released | alert, adjust |
| `USER_CONNECT` / `USER_DISCONNECT` | user asked to (dis)connect a profile | augment / gate / deny with reason |

(`VPN_*` session/handshake events and the `*_CHANGED` external-drift events above are also
control-plane.)

### Control-plane commands

- **Orchestration `VPN::`** — `require <name>`, `connect`/`disconnect`/`reconnect <name>`,
  `promote`/`demote`, `list`, `state`, `next_capable`, `default_owner`.
- **Mediator control (imperative) `ROUTE:: DNS:: PROXY::`** — `ROUTE::add/withdraw/default/reassert`,
  `DNS::chain/table/reassert`, `PROXY::set/reassert` — the same namespaces the intent/`*_CHANGED`
  events use, callable from control handlers.
- **Tables & state** — `DG::` (data-groups); `TABLE::` (session key/value with per-entry
  timeouts, iRules-style: `set/get/delete/keys/lookup/incr`); `PERSIST::` (durable small state
  across reloads/restarts).
- **Time** — `TIMER::create/cancel`, `SCHEDULE::at <cron>`, `after <ms> {…}` / `after cancel`.
- **Connectors** (vetted async, control-plane only) — `HTTP:: REDIS:: CONSUL:: DNS::resolve
  FILE::`, each `?via egress?`.
- **Observability** — `LOG::info/warn/error`, `NOTIFY::user <text>` (user-facing notification),
  `METRIC::gauge/counter <name> <v>` (feeds app telemetry/UI), `INCIDENT::raise <kind> <detail>`.
- **Host/system** — `NET::` (`primary_iface`, `addresses`, `reachable <target>`, `dns`,
  `proxies`, `iface`, `up`); `SYS::` (`time`, `uptime`, `on_battery`, `locale`, `hostname`).
- **Policy/self** — `POLICY::reload`, `POLICY::enable/disable <handler>`, `POLICY::version`;
  `MDM::get <key>` (managed values — gates are MDM-owned, read-only to scripts).

Safety: mutating control-plane commands (orchestration, mediator control, `NOTIFY`) are
MDM-gateable and logged; connectors are the only I/O; no raw sockets/exec. Control handlers run
under time/resource budgets — a hung handler is killed and its partial effect rolled back to the
built-in default.

```tcl
when NET_WAKE {                                   # after wake: verify Corp, re-pin, failover if absent
    VPN::reconnect "Corp"
    after 8000 {
        if {[VPN::state "Corp"] ne "up"} {
            ROUTE::default via [VPN::next_capable]
            NOTIFY::user "Corp didn't return — using [VPN::default_owner]"
        }
    }
}
when SCHEDULE nightly { DG::load blocklist from "https://feeds.example/deny.txt" via "Corp" }
when INCIDENT { if {[INCIDENT::kind] eq "tls-fail"} { NOTIFY::user "[VPN::name]: TLS failure — check gateway cert" } }
```

## Metadata & connection stats

Same telemetry backs both the Tcl surface and the app UI (the traffic-path indicator,
per-VPN cards). In a `VPN_*`/`VPN_HS_*` event the namespaces are scoped to the current
tunnel; elsewhere address one explicitly, e.g. `STATS::vpn "Corp" rx_bps`.

**Metadata — `VPN::` (RO except where a handshake event opens a write-window)**
`name` · `id` · `kind` (openvpn/tailscale/ssh/…) · `protocol` (udp/tcp/dtls) · `endpoint` ·
`state` · `role` (default | split) · `uptime` · `client_address` · `routes` (advertised
CIDRs) · `dns` (advertised resolvers) · `search` · `mtu` · `exit_node` (tailscale).

**Link stats — `STATS::` (all RO)**
`rtt` `rtt_min` `rtt_max` `jitter` `loss` — latency/quality ·
`tx_bytes` `rx_bytes` `tx_packets` `rx_packets` — cumulative volume ·
`tx_bps` `rx_bps` `tx_pps` `rx_pps` — current throughput (windowed) ·
`since` `last_handshake` `reconnects` — lifecycle.

**Per-advertised-route stats — `STATS::route <cidr> <metric>` (RO)**
Traffic is attributed to the switch arm / advertised route it matched, so each route the VPN
advertises has its own counters: `tx_bytes` `rx_bytes` `tx_bps` `rx_bps` `flows` `last_active`.
`STATS::routes` enumerates them (`[list {cidr tx_bps rx_bps flows} …]`). **This attribution
is a PBR-datapath capability** (the L3 forwarder / netstack counts per matched route); with
PBR off only per-VPN aggregates exist. Latency availability is per-engine (see matrix).

```tcl
when VPN_HEALTH {
    if {[STATS::rtt] > 250 || [STATS::loss] > 5} { LOG::notify "[VPN::name] degraded" }
}
# busiest advertised route on Corp, for the dashboard
set busiest [lindex [lsort -index 2 -decreasing -real [STATS::routes]] 0]
```

## Command namespaces — read/write any handshake portion

Getters bare (`[VPN::cipher]`), mutators explicit (`PUSH::route drop …`). Write-window noted.

- **`VPN::`** — metadata above; mutators `endpoint`/`transport set` (`VPN_CONNECTING`),
  `abort`, `redirect_endpoint`, `promote`/`demote`, `auth`.
- **`X509::`** (`VPN_HS_SERVERCERT`) — `chain` `subject` `issuer` `san` `sha256` `sha1`
  `not_before` `not_after`; mutators `VPN::cert_accept` / `cert_reject <why>` /
  `cert_pin <sha256>`. **Default-secure:** no decision ⇒ hardened built-in verification
  stands; scripts may pin/reject *harder*; weakening needs explicit, logged, MDM-gateable
  `VPN::cert_accept -insecure`.
- **`CRYPTO::`** (`VPN_HS_KEX`) — `cipher` `tls_version` `dh_group` `integrity`; `require`/`reject`.
- **`AUTH::`** (`VPN_HS_AUTH_*`) — `method` `realm` `prompt` `challenge` `sso_url` `is_echo`;
  `VPN::auth user <u> pass <p> ?otp <o>? ?cert <ref>?`, `AUTH::respond <text>`. Secrets only
  via vetted `SECRET::get <item>` (keychain) / `TOTP::now <item>` — never inline in a script.
- **`PUSH::`** (`VPN_HS_CONFIG`) — `routes` `dns` `search` `address` `mtu` `option <name>`;
  mutators `PUSH::route {add|drop|replace} <cidr> ?via?`, `PUSH::dns {add|drop|replace}`,
  `PUSH::option {set|drop}`.
- **`STATS::` / `META::`** — read-only telemetry above.
- **`PAC::` / `PROXY::`** (events `PAC_*`) — `url` `host` `client_ip` (RW in `PAC_REQUEST`),
  `result` `proxies` (RW in `PAC_RESPONSE`); `PROXY::via <host:port>`, `PROXY::kind`,
  `PROXY::auth`.
- **`DG::`** — data-groups (below): `match` `lookup` `keys` `values`; mutators
  `add`/`remove`/`set`/`load` (MDM-gateable).
- **`LISTENER::`** — `name` (current), `create <name> {match…}`, `bind <event> <proc>`,
  `chain …` (DNS role), `vip` (its match spec).
- **`HS::raw`** — literal escape hatch: `HS::raw <stage>` reads / `set` writes the **raw
  bytes** of a handshake message where the protocol exposes it (OpenVPN control-channel
  `PUSH_REPLY`, SSH banner, TLS ClientHello). Protocol-dependent, MDM-gateable, **always
  logged**; off unless the policy opts in.
- Data-plane `IP:: TCP:: UDP:: DNS:: TLS:: HTTP:: FLOW::` — in `PolicyRouting.md`.

## Data-groups — tables, feeds & virtual lookups

Named typed tables for match + key→value lookup (GUI table editor, consistent with the Routes
UI), but the **backing is pluggable** — static, externally-fed, or entirely virtual.

- **Types:** `ip` (CIDR, longest-prefix via a radix trie), `string` (exact; `-glob`/`-regex`),
  `int`. Each entry is a key **plus an optional value payload** — a set *or* a map.
- **Backings:**
  - **static** — inline in the policy, or a watched local file.
  - **feed** — populated/refreshed from an external source by a **timer** or subscription:
    HTTP(S) JSON/CSV, **Redis** (sets/hashes/keys), **Consul** (KV/catalog), **DNS** (resolve a
    name into an IP set, TXT payloads), another data-group (derived), or an internal
    representation (`dg:routes("Corp")`, the DNS↔flow cache, GeoIP).
  - **virtual** — **no storage.** A `DG_LOOKUP` handler answers each query live and returns
    `DG::return <value>`. Pure-compute virtual tables (algorithmic membership, range math,
    hashing) resolve instantly on the datapath; a virtual table that must *fetch* per lookup is
    answered from a control-plane cache or forces the flow to `FLOW::hold` (bounded) — so prefer
    control-plane pre-population. `DG::cache <ttl>` memoizes; `-nocache` stays truly virtual.
- **Ops** (reads valid in any event; mutation MDM-gateable): `DG::match <name> <val>` → bool
  (LPM for `ip`), `DG::lookup <name> <key>` → value | "", `DG::keys`/`values`,
  `DG::add/remove/set`, `DG::load <name> from <source>`, `DG::return` (virtual).
- **Uses:** switch matchers (`ip in dg:corp_nets -> via Corp`); dynamic targets
  (`via dg:host_egress[host]`); **response rewriting** in `DNS_RESPONSE`/`HTTP_RESPONSE`/`PAC_RESPONSE`.

## Feeds, connectors & timers — fetch/process anything, off the datapath

What makes "fetch anything in Tcl" safe is **two execution planes:**

- **Control plane** (timers, feed handlers, table maintenance): async I/O via **vetted
  connectors** is allowed — it runs OFF the datapath and never blocks a packet.
- **Data plane** (FLOW/DNS/handshake events): pure-compute + table *reads*, fast and
  non-blocking. (This is the "pure-compute v1" rule — it constrains the data plane only.)

**Connectors** (control-plane only; no raw sockets/exec — this *is* the vetted surface):
`HTTP::get/post <url> ?via egress?`, `REDIS::cmd <conn> …`, `CONSUL::kv/catalog …`,
`DNS::resolve <name> ?type?`, `FILE::read <path>`. Endpoints + creds are configured
keychain-backed objects (MDM-gateable), and **every fetch goes through a chosen egress**, so an
internal Consul/Redis feed rides the corp tunnel. Connectors are async (suspend/resume the
control handler).

**Timers → events:**
- `TIMER::create <name> every <interval> ?jitter?` fires `when TIMER <name> { … }` on schedule —
  where feeds refresh and tables get monkeyed with (`DG::set/add/remove/load`).
- `after <ms> { … }` — one-shot (iRules-style).
- A failed fetch keeps the **last-good** table (staleness surfaced), never empties it; control
  handlers have their own time/resource budgets.

**Virtual-lookup event:** `DG_LOOKUP <name>` fires on a lookup into a virtual data-group; the
handler returns `DG::return <v>`. `[DG::key]` + flow context readable. Sync (compute) or
hold-and-resolve (async, bounded).

```tcl
TIMER::create refresh_nets every 30s
when TIMER refresh_nets {                                       # control plane: async fetch OK
    DG::load prod_nets from json [HTTP::get "http://consul.corp:8500/v1/kv/net/prod?raw" via "Corp"]
}
when DG_LOOKUP risky_ip { DG::return [REDIS::cmd rep GET "rep:[DG::key]"] }   # virtual, memoized

when FLOW_INIT {                                               # data plane: pure reads, fast
    if {[DG::match prod_nets [IP::daddr]]}      { FLOW::egress via "Corp" }
    if {[DG::lookup risky_ip [IP::saddr]] > 90} { FLOW::drop }
}
```

## Listeners (virtual servers)

The ingress capture & scoping layer — full model in `PolicyRouting.md` › Listeners. A listener
is a match spec (`dest`/`port`/`proto`/`source`/`app`/`on-ip`) that picks up matching traffic
and scopes a rule-set to it; `[LISTENER::name]` identifies the capturing listener in any handler.
DNS listeners are the `port 53` + `on-ip` specialization. Commands: `LISTENER::` above.

## Protocol capability matrix

The catalog is the *superset*; the editor greys out what an egress can't emit.

| Capability | OpenVPN | SSH | OpenConnect | Tailscale | Proxy-tunnel | IKEv2/IPsec | WireGuard |
|---|---|---|---|---|---|---|---|
| `VPN_CONNECTING`/`_UP`/`_DOWN` | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ | ✅ |
| `VPN_HS_RESOLVING/RESOLVED` | ✅ | ✅ | ✅ | ~ | ✅ | ❌ | ✅ |
| `VPN_HS_SERVERCERT` | ✅ TLS | ✅ host key | ✅ TLS | ❌ internal | ✅ https proxy | ❌ NE hides | ➖ none |
| `VPN_HS_KEX` | ✅ | ✅ | ~ | ❌ | ~ | ❌ | ~ fixed |
| `VPN_HS_AUTH_*` | ✅ | ✅ | ✅ +SSO | ✅ login/SSO | ✅ proxy | ➖ NE-managed | ➖ keys |
| `VPN_HS_CONFIG` | ✅ PUSH_REPLY | ➖ | ✅ CSTP | ✅ netmap | ➖ | ~ limited | ➖ static |
| `VPN_HEALTH`/`REKEY`/`REASSERTING` | ✅ | ~ | ~ | ✅ | ~ | ~ coarse | ✅ hs-age |
| `down_reason` fidelity | high | high | high (parsed) | high | medium | **low** | **none** |
| RTT / latency stat | ✅ ping | ✅ | ~ | ✅ | ✅ | ❌ | ➖ hs-age only |
| bytes / throughput | ✅ | ✅ | ✅ | ✅ | ✅ | ~ (NE counters) | ✅ |
| per-route stats | ✅ (PBR) | ✅ (PBR) | ✅ (PBR) | ✅ (PBR) | ✅ (PBR) | ~ | ✅ (PBR) |
| `HS::raw` | control text | banner/KEX | subprocess I/O | ❌ | ~ | ❌ | ❌ |

Legend: ✅ full · ~ partial · ➖ n/a to the protocol · ❌ protocol has it, API hides it.
**openvpn3 is richest** (near-1:1 event per phase); **native IKEv2/IPsec & WireGuard are
minimal** — native because `NEVPNManager` mediates everything, WireGuard because it's
connectionless (no auth exchange, no pushed config, no server disconnect → `kicked` and
`network-dead` are indistinguishable). Per-route stats need the PBR datapath; off PBR, only
per-VPN aggregates.

## Safety & execution model

- **Default-secure gates:** cert/host-key, KEX, and auth events never *weaken* built-in
  behavior implicitly; the hardened default stands absent a decision. Weakening is explicit,
  logged, MDM-gateable.
- **Bounded blocking:** gating events (auth, cert) run under a timeout; no answer ⇒ built-in
  default (keychain creds, secure verify). Synchronous vetted commands only; external async
  lookups deferred.
- **Rug-pull caveat:** reliable `down_reason` needs a graceful server teardown; a silent
  drop is indistinguishable from network loss → `unknown`.
- **Interp locality (impl):** in-extension engines (openvpn3/tailscale/proxy) reach the interp
  directly; app-side engines (SSH/openconnect/native) need the event bridged app→extension —
  a later phase.

## Example — steer a full establishment

```tcl
when VPN_CONNECTING     { if {[VPN::name] eq "Corp"} { VPN::transport set udp } }
when VPN_HS_SERVERCERT  { if {[X509::sha256] ne $::corp_pin} { VPN::cert_reject "unexpected cert" } }
when VPN_HS_AUTH_REQUEST{ VPN::auth user [SECRET::get corp.user] pass [SECRET::get corp.pass] otp [TOTP::now corp] }
when VPN_HS_CONFIG      { PUSH::route drop 0.0.0.0/0 }        ;# don't let the server own our default
when VPN_UP             { ROUTE::default via "Corp" }
when VPN_HEALTH         { if {[STATS::rtt] > 250} { ROUTE::default via [VPN::next_capable] } }
when VPN_DOWN           { if {[VPN::down_reason] ne "intentional"} { ROUTE::default via [VPN::next_capable] } }
```
