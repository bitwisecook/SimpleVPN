# Policy-Based Routing (PBR) — Tcl-scripted flow router

Design doc, 2026-08-03. Status: **agreed direction, phased build**. The near-term
destination/CIDR divert rules shipped earlier remain the fallback path when PBR is off.

## Vision

**OFF BY DEFAULT — hard invariant.** PBR is advanced functionality behind a Settings
toggle. While off (the default), nothing here exists at runtime: no PBR utun, no DNS
capture, no Tcl, and every VPN profile connects and routes exactly as it does today.
The toggle follows the same opt-in discipline as the privacy/permissions rules: flipping
it on is the user's explicit, informed act (with an explanatory sheet), and turning it
off restores stock behavior completely. Nothing in the default experience may depend on
the PBR subsystem.

A Settings toggle: **"Policy-Based Routing"**. When on, SimpleVPN stands up ONE utun that
captures everything (default route + our DNS listener IPs) and runs a user-scriptable
policy engine over all of it — DNS, TCP, UDP — in the style of **F5 iRules**: an
event-driven **Tcl 9** environment where the user writes full procs and event handlers
that inspect and rewrite traffic (addresses, ports, payload bytes) and steer each flow
into any configured egress. Multi-VPN stops being a special feature: it's a policy script
that declares which VPNs to bring up and how traffic maps onto them.

Overlapping IP spaces are handled by making routing decisions on **names, not prefixes**
(fake-IP DNS + SNI/Host sniffing): colliding 10/8s never enter a route table because the
utun only sees synthetic addresses it allocated itself.

## Decisions (2026-08-03)

1. **Declarative core, Tcl as escape hatch.** A rules IR is what the datapath executes;
   the GUI edits it directly and Tcl *emits the same IR* plus imperative event handlers.
   Multi-VPN and split-routing work with zero Tcl; a script error can never break basic
   routing. (Supersedes "multi-VPN is a Tcl script underneath.")
2. **Full capture.** When PBR is on, the utun owns the default route and every flow is
   available to the netstack/policy. Chosen for uniform inspectability; the reliability
   surface is managed via fail-open/closed, base bypasses, and the fast path (below).
3. **Two execution planes.** Data-plane handlers (FLOW/DNS/handshake) are pure-compute +
   table reads — fast, non-blocking, no I/O. A **control plane** (timers, feed handlers) may
   fetch via vetted async connectors (HTTP/Redis/Consul/DNS/file, each *through an egress*) to
   populate data-groups off the datapath. No raw sockets/exec anywhere. (See `PolicyEvents.md`
   › Feeds, connectors & timers.)
4. **DoH/DoT: detect & warn**, block is opt-in. We don't fight browser encrypted DNS by
   default; we tell the user their DNS rules won't apply to that app.
5. **Single-level egress nesting in v1.** "B's server reached via A" + each flow picks one
   egress. Arbitrary onion-stacking of a single flow through N tunnels is deferred.
6. **Fake-IP only for names with an egress rule.** Ruled names get overlap-safe synthetic
   addresses; unruled internet names get their real answer and the default egress.
7. **Unmatched literal-IP → default egress + surfaced incident** (not blocked), erring
   toward connectivity; strict setups can flip this with fail-closed later.
8. **Packet-tunnel is the PBR spine; app-identity is deferred.** `NEPacketTunnelProvider`
   owns the datapath (L3 + payload + IP/port rewrite + overlap fake-IP + iRules-on-packets).
   v1 matchers: name / CIDR / SNI / Host / listener. `app ==` routing comes later via a
   `NETransparentProxyProvider` *annotator* feeding app-id into the same switch — never by
   moving the datapath off the packet tunnel (that would forfeit the deep-packet powers).

## Datapath

```
                    ┌────────────────────────── PacketTunnel sysext ─────────────────────────┐
   apps → utun ──▶  │ L3 fast path ── per-flow verdict cache ──▶ packet egress (openvpn3,     │
                    │      │                                     tailscale, wireguard-later)  │
                    │      ├─▶ DNS listeners (N, named) ──▶ resolver chains                   │
                    │      └─▶ gVisor netstack (flow egress / rewriting / payload events)     │
                    │                └──▶ flow egress: SSH direct-tcpip, SOCKS5/CONNECT,      │
                    │                     direct, drop                                        │
                    │             Tcl 9 policy interp (events at decision points)            │
                    └─────────────────────────────────────────────────────────────────────────┘
```

- **L3 fast path**: raw packets with a cached verdict (per 5-tuple / per fake-IP) are
  forwarded without touching Tcl or the netstack. Steady-state throughput never waits on
  the interpreter.
- **gVisor netstack** (already being built for the proxy-tunnel engine) terminates flows
  that need flow-level egress, address/port rewriting, or payload inspection/mutation.
- **Egress registry**: two egress shapes, both in-process —
  - *packet egress*: engines that speak raw IP (openvpn3 bridge, tailscale engine,
    wireguard when built) — the router hands them packets;
  - *flow egress*: dialable transports (SSH `direct-tcpip`, SOCKS5, HTTP(S) CONNECT,
    direct, drop) — the netstack hands them byte streams.
- **Multi-VPN = one utun.** When PBR is on, other VPN profiles do NOT run as parallel NE
  tunnels; they attach as in-process egress engines inside the PBR tunnel. The script
  names profiles; the app (not the extension) performs connect/auth via the existing IPC
  and keychain paths. **Scripts never see credentials** — `VPN::require "GR Lab"` is a
  request by profile name, resolved app-side.

## DNS subsystem

- **N named listeners**, each a distinct IP the utun advertises (e.g. `100.100.53.1`,
  `100.100.53.2`, …). **Purpose (user-stated): programmers point different apps/tools at
  different listeners to get different DNS chains.** Each listener carries its own
  resolver chain and its own `DNS_REQUEST`/`DNS_RESPONSE` script hooks — the F5
  listener/virtual-server model.
- A **chain** is an ordered resolver policy: per-domain forwarding (suffix match →
  resolver, *via* a named egress so corp DNS rides the corp tunnel), a default resolver
  for "the internet", caching, and optional fake-IP synthesis.
- **Fake-IP**: listeners can answer with synthetic addresses (v4 pool `198.18.0.0/15`,
  v6 ULA slice), recording name↔fake-IP. Flows to fake-IPs are routed by *name* at
  connect time (real address resolved through the chosen egress, or dial-by-name for
  flow egress). This is the overlapping-IP killer and the default for domains with an
  explicit routing rule.
- **DoH/DoT bypass**: browsers doing their own DoH sidestep listeners. v1: a scriptable
  block of well-known DoH endpoints, default ON while PBR is active (open question #2).
- System resolver config: primary listener via `NEDNSSettings`; additional listeners are
  reachable by IP for explicit opt-in (`/etc/resolver/*`, `scutil`, app flags,
  containers).

## The tiers — from one VPN to full PBR

The same single-utun substrate wears three faces. A user climbs only as far as they need;
casual users never see tier 3, and the word "PBR" only appears at tier 3.

- **Tier 1 — one VPN (stock).** Exactly today's behavior. That VPN owns the default route.
  No picker, no rules surface. (Internally it can be the same single-utun with
  `default -> thatVPN`, but nothing about the UI changes.)

- **Tier 2 — multiple VPNs connected, one default-gateway picker.** The moment a *second*
  VPN connects, two NE tunnels would fight over `0.0.0.0/0` — which macOS won't arbitrate —
  so we're **necessarily** in the single-utun model: one capturing utun, each VPN attached
  as an **egress engine**. Then:
  - Each connected VPN's **advertised routes/subnets auto-populate specific switch arms**
    → that egress. Corp subnets go to corp, tailnet ranges go to the tailnet, automatically.
    No user rules.
  - **One `default` arm = one user-picked egress.** A single segmented picker / menu:
    *"Default gateway: [Corp ▾]"* — plus `Direct` and `Drop` (kill-switch) as choices.
    Changeable **live**: flipping it rewrites just the default arm and re-evaluates.
  - **No fighting is structurally impossible**, not merely prevented: only our one utun
    holds `0.0.0.0/0` at the OS level, and inside it the default is *one arm of one switch*.
    Two egresses cannot both be default because there is exactly one default arm, always
    populated (worst case `Direct`).
  - A VPN that *wants* to be full-tunnel but isn't the picked default is transparently
    **demoted to split** (only its specific subnets routed), with a surfaced note:
    *"Corp wants to route everything; it isn't the default gateway, so only its subnets go
    through it."* No silent surprise, no contention.
  - **No Tcl, no fake-IP, no packet inspection** at this tier — and if every connected
    egress is a *packet* egress (openvpn3/tailscale/wg), the datapath is a **lightweight L3
    longest-prefix-match forwarder** (dest IP → egress), *not* the gVisor netstack. The
    netstack only engages when an egress is a flow-egress (SOCKS/SSH/CONNECT) or a tier-3
    L7 rule exists. So the common multi-VPN case stays on the fast path and dodges the
    throughput risk entirely.

- **Tier 3 — full PBR (the toggle).** Unlocks custom switch arms (name/CIDR/SNI/Host/
  listener), multiple named DNS listeners, fake-IP overlap handling, the egress DAG
  (VPN-on-VPN), payload events, and the Tcl escape hatch. This is the off-by-default
  power surface everything below this heading describes.

**Off-by-default reconciliation:** tier 2 is not "turning on PBR" — it appears naturally
when you connect a second VPN and is just a gateway picker. The scary toggle is tier 3.
(Open question: does connecting a 2nd VPN auto-engage the single-utun transparently, or
prompt once? — see Open questions.)

## Listeners (virtual servers) — capturing traffic to apply rules

Borrowed from F5's **virtual server**: a **listener** is a named match spec that *picks up*
matching traffic and binds a rule-set (event handlers + profiles) to it. It's the ingress
scoping layer — handlers attached to a listener run only for that listener's traffic, so
policy stays modular instead of one monolithic global switch.

- **Match spec:** `dest <cidr|any>`, `port <range|any>`, `proto tcp|udp|icmp|any`, plus
  optional `source <cidr|any>`, `app <id>` (when available), `on-ip <listen-ip>`, `ingress <iface>`.
- **Selection:** a flow is captured by the **most-specific** matching listener (ties broken by
  explicit `priority`, like VS ordering); unmatched flows fall to the default listener (the
  global policy). `[LISTENER::name]` tells a handler which one caught the flow.
- **Bound rules & profiles:** each listener carries its own `when <EVENT> {…}` handlers plus
  optional profiles — a DNS resolver chain, an HTTP/TLS-inspect toggle, data-groups.
- **DNS listeners are the special case:** a listener with `proto {udp tcp}` `port 53`
  `on-ip <listener-ip>` + a resolver-chain profile IS the named DNS listener from the DNS
  section. "Point different apps at different listener IPs for different DNS chains" is just
  several DNS-role listeners.
- **Composition with the switch:** the routing switch is what a listener's `FLOW_INIT`
  handlers evaluate — a listener may carry its own switch arms or defer to the global one.
  Capture (listener) → its events/rules → egress (switch).

```tcl
listener web { proto tcp port 443 } {
    when TLS_CLIENTHELLO { if {[string match "*.corp" [TLS::sni]]} { FLOW::egress via "Corp" } }
}
listener db { proto tcp port 5432 dest 10.1.0.0/16 } {
    when FLOW_INIT { FLOW::egress via "Corp"; NAT::snat 10.200.0.7 }
}
# handlers outside any `listener {}` block apply to the default listener (all other traffic)
```

## Routing is a switch with a default — the IR owns 0.0.0.0/0

The whole routing model is **one ordered `switch`**: each arm is `matcher → egress`, and the
**`default` arm is `0.0.0.0/0`** — the catch-all for everything unmatched. There is no
separate "default egress" setting, no separate "default route", and no separate kill-switch
knob: they are all **the default arm of the switch**.

```
route {
    switch {
        "*.grlab.co.uk"     -> egress "GR Lab"
        10.1.0.0/16         -> egress "GR Lab"
        sni "*.github.com"  -> egress "Home Tailnet"
        listener corp       -> egress "GR Lab"
        default             -> egress direct        ;# <- this IS 0.0.0.0/0
    }
}
```

- **The IR owns the full table including 0.0.0.0/0.** "Send everything through the VPN" is
  `default -> "GR Lab"`. "Unmatched stays direct" is `default -> direct`. **Fail-closed
  kill switch is `default -> drop`.** One construct, three familiar behaviors.
- Because full capture makes the OS route table trivial (everything → our utun), *all* the
  interesting routing lives inside this switch. The OS never arbitrates; the switch does.
- **First-match-wins, ordered**, exactly like `switch`/iRules. The GUI renders the arms as
  a reorderable rule list; the `default` arm is pinned last and always present.
- **DNS is the same shape**, a parallel switch per listener: `name-matcher → resolver-chain`
  with its own `default` (the listener's "internet" resolver).
- **The Tcl escape hatch is literally a `switch`/`when`.** Declarative arm and hand-written
  arm are the same construct, so "drop this arm into Tcl" is seamless — the IR arm
  `sni "*.github.com" -> egress X` and a Tcl `when TLS_CLIENTHELLO { ... }` are two
  spellings of one switch.

Matchers and dynamic targets can also test **data-groups** — named typed tables of
IPs/networks/strings (with optional value payloads), F5-style: `ip in dg:corp_nets -> via Corp`,
`host in dg:blocklist -> drop`, or `via dg:host_egress[host]` to look up the egress. Full
data-group model (types, sources, runtime mutation, response-rewriting) is in `PolicyEvents.md`.

### Matchers depend on the capture substrate (open fork)

An arm's **egress** side is always the DAG; its **matcher** side is where the substrate
matters, because Apple splits the needed signals across two providers:

| Matcher | `NEPacketTunnelProvider` (full-capture, our engines) | `NETransparentProxyProvider` |
|---|---|---|
| name (fake-IP) / CIDR / IP | ✅ | ✅ (dest + hostname on the flow) |
| SNI / HTTP Host | ✅ (netstack sniffs first bytes) | ✅ |
| listener | ✅ | ✅ |
| **app identity** (`Slack -> personal`) | ❌ **not available** | ✅ (`sourceAppSigningIdentifier`, audit token) |
| raw L3 / ICMP / IP+port rewrite / arbitrary packet bytes | ✅ | ❌ (byte streams + chosen dest only) |

**Correction to an earlier claim:** in the packet-tunnel model we do **not** get per-flow app
identity — that lives only in the transparent-proxy provider. So `app ==` matchers and the
deep "rewrite any byte including IP/port" powers are on *different* providers. **Decided
(#8):** the **packet tunnel is the spine**; app-identity routing is deferred and arrives
later as a transparent-proxy annotator feeding `app ==` into the same switch. v1 matchers:
name / CIDR / SNI / Host / listener.

## The match context — what the switch can see (and when)

The switch is not `dst → egress`. Each arm matches over a **fact context** assembled for the
flow, and facts **arrive over time** — so evaluation is *staged*, and a target can be a
*dynamic selector* (reachability/quality-aware), not just a fixed egress.

### Fact sources

| Category | Facts | Available at | Certainty |
|---|---|---|---|
| **Flow identity** | src/dst ip:port, proto, direction, ingress iface, flow id, timestamp | `FLOW_INIT` (SYN / 1st datagram) | exact |
| **App identity** | signing id / audit token | (deferred — proxy annotator) | exact when present |
| **Name (minted)** | name, listener, intended egress | `FLOW_INIT` if the dst is a **fake-IP** we handed out | **exact** |
| **Name (correlated)** | probable name(s) via DNS↔flow join (below) | `FLOW_INIT` | probable + confidence |
| **L7** | TLS SNI, ALPN; HTTP Host/URI | `TLS_CLIENTHELLO` / `HTTP_REQUEST` (a few packets in) | exact once seen |
| **Payload** | raw stream bytes | `FLOW_COLLECT` (opt-in) | exact |
| **Egress candidates** | which VPNs are up; which **advertise a route** covering dst | any time | live |
| **Egress quality** | per-VPN & **per-route** rtt / loss / tx·rx bps / load | any time | live (windowed) |
| **Environment** | current default owner, `NET` state, time | any time | live |

### DNS ↔ flow correlation (name a flow we didn't fake-IP)

Even when we returned a real answer, we can attribute a **name** to a later flow by joining on
the target IP:

- On every `DNS_RESPONSE`, record `answer_ip → {name, listener, requesting_source, answered_at, ttl}`
  in a short-TTL reverse cache.
- At `FLOW_INIT`, look up `dst_ip`; the freshest non-expired entry yields the probable name +
  a **confidence** score. Prefer an entry whose `requesting_source`/`listener` matches the
  flow's source (raises confidence and disambiguates shared IPs).
- **Honest caveats** (confidence reflects these): many names → one IP (CDN/shared hosting) →
  the join returns *a* name, maybe not the causal one (confidence drops when the IP had
  several recent distinct names); IP reuse over time is bounded by the TTL window; apps doing
  their own DoH bypass the cache entirely (no correlation — the DoH-warn case). The fake-IP
  path stays **certain**; correlation is the fallback for normally-resolved traffic and is
  what lets `name *.github.com` match a flow to a real GitHub IP.

### Staged evaluation — provisional then committed

Facts arrive in phases, so a verdict can be **refined** as more become known, up to a commit
point (you cannot move an *established* TCP connection to another egress without resetting it):

1. `FLOW_INIT` — decide from flow identity + minted/correlated name + candidates/quality. Good
   enough for most rules. Assign a **provisional** egress.
2. A rule that needs L7 may **hold** the flow (buffer first bytes, up to a per-rule budget /
   until `TLS_CLIENTHELLO`) to match on SNI/Host — an opt-in latency cost, not the default.
3. First byte actually sent to the egress = **commit**; the egress is immutable thereafter.
   Between provisional and commit, `TLS_CLIENTHELLO`/`HTTP_REQUEST` may **re-pin** the egress.

Default is *never block*: route provisionally at `FLOW_INIT` and re-pin at the first L7 signal
if a rule asked to; only rules that explicitly `FLOW::hold` pay latency.

### Dynamic targets (the right-hand side of an arm)

An arm's target may be a fixed egress **or** a selector over live state:

- `via "Corp"` — fixed.
- `via advertises(dst)` — any up egress whose advertised routes cover the destination.
- `via first_up(Corp, Home, direct)` — reachability-ordered failover.
- `via lowest_latency(Corp, Home)` / `least_loaded(...)` — quality-aware.
- `via hash(flow)` — stable spread across a set.
- `drop` / `direct`.

```tcl
when FLOW_INIT {
    set name [FLOW::name]                       ;# minted (certain) or correlated (w/ confidence)
    if {[string match "*.corp" $name] && [FLOW::name_confidence] > 0.6} {
        FLOW::egress via advertises([IP::daddr])  ;# whichever up VPN can actually reach it
    } elseif {[FLOW::is_tls]} {
        FLOW::hold until CLIENTHELLO             ;# opt in to L7: pay a little latency
    }
}
when TLS_CLIENTHELLO {
    if {[string match "*.github.com" [TLS::sni]]} { FLOW::egress via lowest_latency(Home, Corp) }
}
```

## Addressing & DNS — the overlap engine

The core trick: **route by name, not by prefix.** Because full capture means the client's
apps only ever see addresses *we* hand them, conflicting real IP spaces stop being a
routing problem for any traffic that originated from a name.

### Flow provenance (first-class)

Every flow the netstack sees is tagged at birth:

- **resolved-by-us** — the destination is a **fake-IP** we minted answering a DNS query
  through listener L. The flow carries `(name, listener, intended-egress)` with certainty.
  No guessing.
- **literal-IP** — the app dialed a numeric address (or used its own DoH). No name, no
  fake-IP. This is the *only* genuinely ambiguous case.

### Fake-IP: the overlap solvent

- Listeners answer routable domains with synthetic addresses from a pool (v4
  `198.18.0.0/15` ≈ 128 k, v6 ULA slice). We keep `fakeIP → (name, egress, real-resolver
  context)`.
- A flow to a fake-IP is dialed **by name on its egress**: the real address is resolved
  *in that egress's DNS/routing context* and connected there. Two tunnels both hosting
  `db` at the same real `10.1.2.3` get **two different fake-IPs** → zero collision, even
  though the real addresses are identical. This is why full capture *helps*: nothing the
  client holds is a real, possibly-colliding address.
- **Lifecycle hazards to handle:** sticky allocation (same name → same fake-IP for a
  while, so app-cached IPs stay valid); pool GC that never reclaims an in-use mapping;
  respect for our own short TTLs to bound staleness; a **PTR path** so reverse lookups of
  a fake-IP return the real name (tools that print the IP stay legible).

### Literal-IP disambiguation (the residual hard case)

`ssh 10.1.2.3` when both tunnel A and tunnel B have `10.1.2.3`. No magic; the user must
express intent, but we make it ergonomic and deterministic:

1. **Per-egress CIDR claims with priority** — "`10.1.0.0/16` → A". Ordered; first match
   wins; ties are a validation error.
2. **`FLOW_INIT` on literal-IP flows** — a rule/handler fires with the numeric dest and
   the **originating app identity** (we have the audit token), so "Terminal's 10.x → A,
   everything else → B" is expressible.
3. **Default + warn** — unclaimed literal IP goes to a configured default egress and
   raises a `TunnelIncident` the UI surfaces ("10.1.2.3 matched no egress; sent direct").

### Conflicting DNS

- **Split-horizon** (`intranet.corp` = `10.x` inside, public IP outside): a per-domain
  forward rule `*.corp → resolver via A` resolves it in the right context. Standard.
- **Same name on two tunnels** (both corps have `wiki`): the name alone can't
  disambiguate — so the **listener is the key.** This is exactly the user's stated reason
  for multiple listeners: an app pointed at listener `corpA` gets A's chain, an app at
  `corpB` gets B's. App→listener binding (via `/etc/resolver`, per-app DNS, or container
  config) is the disambiguation handle when names collide.
- Each listener = its own resolver chain (ordered per-suffix forwards, each optionally
  `via` an egress so corp DNS rides the corp tunnel) + its own `DNS_REQUEST`/`DNS_RESPONSE`
  hooks + its own fake-IP policy.

## Heterogeneous VPN-on-VPN — the egress DAG

**One unifying abstraction:** an **egress** takes a flow (or packets) and delivers them,
and *its own upstream is itself an egress* (default upstream = the physical interface).
Composition falls out of that recursion.

- **packet egress** — speaks raw IP (openvpn3, tailscale, wireguard-later): the router
  hands it packets.
- **flow egress** — a dialable transport (SSH `direct-tcpip`, SOCKS5, HTTP(S) CONNECT,
  direct, drop): the netstack hands it byte streams.

Three distinct things people mean by "VPN-on-VPN", all the same DAG:

1. **Nested reachability** — B's *server* lives inside A (B's endpoint is `10.50.0.1`,
   only reachable through A). B's own uplink socket is itself a flow, routed by policy
   **via A**. `VPN::require "B" via "A"`.
2. **Stacked tunneling** — a single flow goes through B through A (onion): egress B's
   upstream is egress A rather than physical. SSH-over-Tailscale-over-OpenVPN composes
   because each layer's socket-to-its-server is just another flow we place.
3. **Heterogeneous simultaneous** — corp OpenVPN base, SOCKS for one SaaS, Tailscale for
   personal, SSH jump for a lab, all live at once; each flow picks its stack.

### What makes it correct

- **Config is an acyclic egress DAG.** Validation rejects cycles (A-via-B-via-A). Bring-up
  is **topological**: physical → A → B-over-A → …. Teardown reverses.
- **Datapath loop prevention:** an egress engine's *own* uplink packets are tagged with
  its position in the DAG; the router only ever routes them to strictly-downstream
  egresses, so an engine can never re-capture its own traffic.
- **Per-layer DNS dependency:** resolving B's *server name* may require A's resolver — so
  bring-up has a DNS edge, not just a routing edge. The DAG carries both.
- **MTU stacking:** every layer adds header overhead; nested tunnels shrink usable MTU
  fast. We compute effective path MTU down the stack, advertise it on the utun, and clamp
  TCP MSS. (Silent MTU loss is the classic VPN-on-VPN failure.)
- **Capability honesty (UDP):** a lower flow-egress can only carry UDP if it supports it —
  SOCKS5 UDP ASSOCIATE yes, HTTP CONNECT no. So WireGuard-over-CONNECT (WG is UDP) is
  **illegal** and the editor says so at config time rather than failing mysteriously;
  WG-over-SOCKS5 is legal only if the proxy grants UDP ASSOCIATE. A capability matrix per
  egress kind gates which stacks the user can even build.

## NAT — SNAT/DNAT and tunnel-egress masquerade

Two layers: automatic (required for correctness) and scriptable (power).

**Automatic egress SNAT (masquerade) — mandatory, not optional.** A packet entering an
egress must be sourced from an address the far side will route a reply back to — the
egress's **tunnel-assigned client IP** (or pool), never the utun's internal address. So
every egress applies **source NAT to its own client address by default**, with stateful
connection tracking so return traffic is reverse-translated (DNAT back) onto the
originating internal flow.

- **Netstack path** (terminated flows): implicit — the re-dial originates from the egress's
  own stack, so the tunnel client IP is the source for free; binding the dial selects a
  specific source when asked.
- **L3 fast path** (raw packet forward, tier-2 packet-egress): **explicit stateful NAPT** —
  rewrite src IP/port outbound, hold a conntrack table keyed by 5-tuple, rewrite dst on the
  return. This is precisely what makes lightweight forwarding into a tunnel work; without
  it, replies land on the tunnel client IP with no back-mapping and the flow is one-way.

**fake-IP is name-driven DNAT.** The fake-IP mechanism *is* the same NAT machinery: the
synthetic destination the client dialed is translated to the real destination at the chosen
egress. Overlap handling and DNAT are one subsystem, not two.

**Scriptable SNAT/DNAT — tier 3.** The same rewrite surface is exposed to policy, both
directions, at `FLOW_INIT` (whole-flow) and per-packet:

- `IP::saddr set <addr>` / `IP::daddr set <addr>` — source / destination NAT.
- `TCP::sport set` / `TCP::dport set` (and UDP) — port translation.
- `NAT::snat <addr|pool>` — present a **specific** source to the target (e.g. a server that
  only accepts connections from a known source subnet); `NAT::masquerade` — the default
  (egress client IP).
- All translations are **conntracked**, so the reverse path is automatic — the user
  rewrites intent one way, never both directions by hand.

```tcl
when FLOW_INIT {
    if {[IP::daddr] eq "10.50.9.9"} {
        FLOW::egress via "Corp"
        IP::daddr set 10.1.2.3        ;# DNAT: real target inside the tunnel
        NAT::snat   10.200.0.7        ;# SNAT: far side only accepts this source
    }
}
```

## Proxies & PAC — per-egress, per-flow

Proxying is **an egress attribute resolved per flow**, not a global OS setting — the same
inversion as routing, and the reason multiple VPNs each declaring their own proxy coexist
without conflict.

- **Every egress may carry a proxy policy:** `none` | `manual` (per-scheme host:port +
  exceptions + auth) | `pac` (URL or inline script). Sourced from the VPN's **pushed** config
  (`PUSH::proxy` at `VPN_HS_CONFIG` — OpenVPN `dhcp-option PROXY_*`, AnyConnect/OpenConnect
  proxy push, `NEProxySettings`) or user/MDM config.
- **Resolution order:** the routing switch first picks the flow's egress; THEN *that egress's*
  proxy policy decides, for this flow's destination, DIRECT-through-tunnel vs
  via-proxy-through-tunnel. No global conflict — each VPN's proxy applies only to flows routed
  to it; a Direct flow uses no VPN proxy.
- **The proxy is reached THROUGH its VPN** (corp proxies are internal hosts), so it nests in
  the egress DAG: flow → egress VPN → proxy on that VPN → target. Fetching a PAC URL is itself
  a flow routed to that egress.
- **PAC via JavaScriptCore (macOS's JS engine).** We run `FindProxyForURL(url, host)` ourselves
  in a `JSContext`, implementing the WPAD helpers (`dnsResolve`, `myIpAddress`, `isInNet`,
  `shExpMatch`, …) with **`dnsResolve`/`myIpAddress` bound to the egress's resolver + fake-IP
  map**, so a corp PAC resolves names the way its own tunnel would. (JavaScriptCore rather than
  CFNetwork's opaque evaluator precisely so we can inject our resolver, sandbox it, cache it,
  and let Tcl mediate.) Results cached per `(egress, host)` with TTL — per-flow JS is expensive.
- **Tcl mediates the PAC** (tier-3): `PAC_REQUEST` fires before evaluation — rewrite the inputs
  the PAC sees (`PAC::url/host/client_ip set`) or short-circuit it; `PAC_RESPONSE` fires after —
  read and rewrite the returned proxy list (`PAC::result`, `PAC::proxies`, `PROXY::via`). The
  PAC's `dnsResolve` is itself interceptable. The user fiddles with both what the PAC sees and
  what it decides. (Catalog in `PolicyEvents.md`.)
- **Scope/caveats:** PAC/HTTP-proxy is TCP-oriented (DIRECT / PROXY / SOCKS returns) — UDP does
  not traverse HTTP proxies, so UDP uses the egress directly (or a configured SOCKS). Proxy
  auth (407) draws stored creds. **Interp locality:** PAC runs in JavaScriptCore on the Swift
  side of the sysext; the Tcl policy runs on the Go side — same process, an in-process FFI hop.
- **Tier boundary:** with PBR **off**, a VPN's pushed proxy is applied to the OS as
  `NEProxySettings` on the owning tunnel (one at a time — the default owner's). Per-flow,
  per-egress, Tcl-mediated PAC is a **PBR-on (tier-3)** capability.

## Kill switch & fail-safety (full-capture reliability)

Modeled on Mullvad's firewall-first approach, adapted to our root sysext:

- **pf anchor, default-deny.** The root packet-tunnel sysext installs a pf anchor allowing
  only: the utun, the **DAG-base server IPs** (the physical-reachable endpoints everything
  tunnels through), DHCP, and — per toggle — the local LAN. Independent of tunnel liveness,
  so it holds during connect, reconnect, and a sysext **crash** (the NE-only approach leaks
  here when macOS tears the utun down).
- **NE layer:** `includeAllNetworks` + on-demand `NEOnDemandRuleConnect` /
  `disconnectOnDemand = false` so the OS re-requires the tunnel.
- **fail-open vs fail-closed** (the per-policy setting): if the policy engine/egress dies,
  fail-open tears the pf deny down and passes to physical (casual default — a crash
  shouldn't kill the internet); fail-closed leaves it up (privacy default — a crash must
  never leak). Default **fail-open**, consistent with the off-by-default, don't-surprise-
  casual-users stance.
- **Base bypasses that must always work:** captive-portal detection, DHCP, mDNS/Bonjour on
  the local link, and the DAG-base server IPs. These are the allow-list, nothing else.
- **Local-network conflict:** if the physical LAN (`192.168.0.0/24`) overlaps a tunnel's
  space, "local → direct" is just another ordered egress claim resolved by the same
  literal-IP disambiguation machinery above.

## Tcl integration

- **Runtime**: real **C Tcl 9.0**, statically linked (BSD license, no deps, arm64 build
  via `Tools/build-tcl-core.sh` following the vendored-engine script pattern). No dlopen,
  no entitlement changes — same rules as the tailscale archive.
- **Editor intelligence**: the user's **tcl-lsp** (github.com/bitwisecook/tcl-lsp, rust
  branch — lexer/parser/compiler/LSP) powers the GUI editor: highlighting, completion of
  our event/command vocabulary, diagnostics. Its **iRules simulator** example is the
  model for the event engine AND the in-app dry-run simulator.
- **Interp placement**: embedded in the Go engine (cgo). One dedicated policy thread owns
  the interp (Tcl interps are thread-bound); events dispatch over a channel and block
  only the flow being decided, never the fast path. Per-flow verdicts cached.
- **Safety**: user code runs in a **safe interp** (no file/exec/socket/open; our command
  namespaces + pure computation only), with Tcl resource limits (time + command count)
  per event. A script error yields the event's default verdict + a `TunnelIncident`;
  a limit trip logs and disables the offending handler until reload. All enable/disable
  routes through `Policy` (MDM gate) like everything else.

### Event model (iRules-flavored)

| Event | Fires | Typical commands |
|---|---|---|
| `POLICY_INIT` | script (re)load | `VPN::require`, `LISTENER::create`, table setup |
| `VPN_CONNECTING` | bring-up requested, **before dialing** | pick endpoint/transport, override config, choose creds source, `VPN::abort` |
| `VPN_HS_*` | each handshake step (resolve→cert→kex→auth→config→tunnel) | inspect/steer establishment — full catalog in **`PolicyEvents.md`** |
| `VPN_UP` | **fully** connected, tunnel usable | promote to default, drain-in, bring up dependent egresses |
| `VPN_HEALTH` | periodic / on change | `STATS::rtt/loss/tx_bps/rx_bps` — act on degradation |
| `VPN_DOWN` | egress leaves connected | disambiguated by `[VPN::down_reason]` (see below) |
| `VPN_RETURNED` | egress reconnects after an *unexpected* drop | restore prior routing, re-promote, or hold |
| `DNS_REQUEST` / `DNS_RESPONSE` | per query, per listener | `DNS::question name`, `DNS::forward to ?via?`, `DNS::answer`, `DNS::fakeip via` |
| `FLOW_INIT` | TCP SYN / first UDP datagram | `IP::daddr ?set?`, `TCP::dport ?set?`, `FLOW::egress via`, `FLOW::drop` |
| `TLS_CLIENTHELLO` | SNI parsed | `TLS::sni`, re-`FLOW::egress` |
| `HTTP_REQUEST` | plaintext Host parsed | `HTTP::host`, `HTTP::uri` |
| `FLOW_COLLECT` | opt-in payload bytes | `FLOW::collect n`, `FLOW::payload ?replace?` (both directions) |
| `FLOW_CLOSE` | teardown | accounting |

`FLOW_COLLECT`/`payload replace` is the "read/write bytes in the packet" surface — netstack-
terminated so sequence numbers stay coherent; the user edits stream bytes, not raw segments.

### Lifecycle, handshake & stats — see `PolicyEvents.md`

The full, cohesively-named event/command/metadata catalog lives in **`PolicyEvents.md`**:
the `VPN_*` session/status events, the `VPN_HS_*` handshake steps (read/write any portion of
the handshake — cert pinning, auth injection, pushed-config rewriting), the metadata +
per-VPN and **per-advertised-route** stats (`STATS::rtt/loss/tx_bps/…`, `STATS::route`), and
the per-protocol capability matrix.

The one boundary that belongs here: the built-in **tier-2** gateway picker ships ONE fixed
disconnect policy (owner drops → notify + auto-promote the next capable egress → Direct only
if none). Anything conditional — reacting to *why* a VPN dropped (`[VPN::down_reason]` =
intentional | network | auth | crashed | unknown, from `NEProviderStopReason`) or *what to do
when it returns* (`VPN_RETURNED`) — is a **tier-3 PBR script**, not the built-in policy.

### Sketch

```tcl
when POLICY_INIT {
    VPN::require "GR Lab"            ;# openvpn engine → packet egress
    VPN::require "Home Tailnet"      ;# tailscale engine
    LISTENER::create corp   100.100.53.1
    LISTENER::create home   100.100.53.2
    LISTENER::create direct 100.100.53.3
}

when DNS_REQUEST {
    switch [LISTENER::name] {
        corp    { DNS::forward to 10.1.0.53 via "GR Lab" }
        home    { DNS::forward via "Home Tailnet" }
        direct  { DNS::forward to 9.9.9.9 }
        default {
            switch -glob [DNS::question name] {
                "*.grlab.co.uk" { DNS::forward to 10.1.0.53 via "GR Lab"; DNS::fakeip via "GR Lab" }
                "*.ts.net"      { DNS::forward via "Home Tailnet"; DNS::fakeip via "Home Tailnet" }
                default         { DNS::forward to 1.1.1.1 }
            }
        }
    }
}

when FLOW_INIT {
    if {[IP::daddr] eq "10.66.0.9" && [TCP::dport] == 22} {
        IP::daddr set 100.101.32.7        ;# remap into tailnet addressing
        FLOW::egress via "Home Tailnet"
    }
}

when TLS_CLIENTHELLO {
    if {[string match "*.github.com" [TLS::sni]]} { FLOW::egress via "Home Tailnet" }
}
```

### Worked examples

**A — Overlapping IP spaces: two employers both squatting on `10.0.0.0/8`.** Route by
*name*, never by the colliding prefix. Each gets its own listener + fake-IP, so the client
only ever holds unique synthetic addresses and `10/8` never enters a routing table.

```tcl
when POLICY_INIT {
    VPN::require "AcmeCorp"                  ;# openvpn   — pushes 10.0.0.0/8
    VPN::require "GlobexCorp"                ;# openconnect — ALSO 10.0.0.0/8
    LISTENER::create acme   100.100.53.1     ;# point Acme's apps here
    LISTENER::create globex 100.100.53.2     ;# point Globex's apps here
}

when DNS_REQUEST {
    switch [LISTENER::name] {
        acme   { DNS::forward to 10.0.0.53 via "AcmeCorp";   DNS::fakeip via "AcmeCorp" }
        globex { DNS::forward to 10.0.0.53 via "GlobexCorp"; DNS::fakeip via "GlobexCorp" }
    }
}
# Acme's db (10.1.2.3) and Globex's db (also 10.1.2.3) resolve to DIFFERENT
# fake-IPs, each tagged with its egress and dialed by name there. Zero collision.
# App→listener binding (per-app /etc/resolver or container DNS) is the disambiguator.
```

**B — Peel one service off to a different VPN.** Everything defaults to Corp; GitHub goes
out the personal tailnet. Two spellings by *when* you decide:

```tcl
when POLICY_INIT { VPN::require "Corp"; VPN::require "Home Tailnet" }

when DNS_REQUEST {                            ;# decide early, at resolution
    if {[string match "*.github.com" [DNS::question name]]} {
        DNS::forward via "Home Tailnet"; DNS::fakeip via "Home Tailnet"
    }
}

when TLS_CLIENTHELLO {                        ;# or late — catches literal-IP / DoH cases,
    if {[string match "*.github.com" [TLS::sni]]} {   ;# the ClientHello still names the host
        FLOW::egress via "Home Tailnet"
    }
}
# default arm stays Corp; only github.com is diverted.
```

**C — A single literal-IP host, only for one app.** A lab box at `10.9.9.9` that only
Terminal should reach, via an SSH jump (a flow-egress):

```tcl
when FLOW_INIT {                              ;# no name — someone typed the IP
    if {[IP::daddr] eq "10.9.9.9" && [FLOW::app] eq "com.apple.Terminal"} {
        FLOW::egress via "Lab Jump"
    }
}
# (FLOW::app requires the app-identity annotator — tier-3 later; without it,
#  drop the app clause and match on the IP alone.)
```

**D — Remap an address into a tunnel.** A tool hardcodes `127.0.0.50:5432`; send it to the
real database inside Corp, rewriting the destination:

```tcl
when FLOW_INIT {
    if {[IP::daddr] eq "127.0.0.50" && [TCP::dport] == 5432} {
        IP::daddr set 10.1.2.3
        FLOW::egress via "Corp"
    }
}
```

## Dynamic reload

Scripts are config: edited in the app, **validated app-side first** (parse + dry-run
against the simulator), then shipped over the existing IPC as a blob. The extension
builds a fresh interp, runs `POLICY_INIT`, and atomically swaps at an event boundary.
Existing flows keep their verdicts; new flows see the new policy. Reload is cheap enough
to be the normal edit loop.

## GUI editor

Based on the **Window ▸ Routes** UI (the browsable/zoomable map was always the seed of
this editor). Two-way editing:

- **Visual layer**: listeners, chains, match→action rules as nodes/rows; edits regenerate
  the corresponding Tcl (marked generated regions).
- **Trapdoor**: any node can "drop into Tcl 9" — once hand-edited, the node renders as a
  *custom Tcl* block (shown, syntax-highlighted via tcl-lsp, no longer visually editable)
  rather than lossily round-tripping.
- **Simulator/trace**: feed a synthetic query/flow through the policy and see which
  events fired, what each handler decided, and the final verdict — the iRules-simulator
  model, doubling as the debugger. Live flow table gets a per-flow "explain".

### Sketches

**Tier 2 — the default-gateway picker** (main window, appears once a 2nd VPN connects; no
"PBR", no rules surface):

```
┌─ SimpleVPN ─────────────────────────────────────────────────────┐
│  Connections                                        ⚙   ◱        │
│                                                                 │
│   ●  Corp            tig-vpn.grlab.co.uk       Connected  ▊▎     │
│   ●  Home Tailnet    controlplane.tailscale…   Connected  ▊▎     │
│   ○  Lab SSH         jump.lab.example          Off               │
│                                                                 │
│  ┌───────────────────────────────────────────────────────────┐ │
│  │  Default gateway    ◉ Corp   ○ Home Tailnet   ○ Direct    │ │
│  │                     ○ Drop  (kill-switch)                 │ │
│  │  Unmatched traffic goes through Corp. Change anytime.     │ │
│  └───────────────────────────────────────────────────────────┘ │
│                                                                 │
│   Corp also routes         10.0.0.0/8 · 172.16.0.0/12           │
│   Home Tailnet also routes 100.64.0.0/10                        │
│   ⚠ Corp wants to route everything; it isn't the default, so    │
│     only its subnets go through it.                             │
└─────────────────────────────────────────────────────────────────┘
```

**Tier 3 — the routing switch editor** (Window ▸ Routes ▸ Policy). Arms are the switch,
first-match-wins, `default` pinned last; any arm can drop into Tcl:

```
┌─ Routes ▸ Policy ───────────────────────────────────────────────────────┐
│  Match  (first match wins)                →  Egress          Simulate ▸  │
│  ┌────────────────────────────────────────────────────────────────────┐ │
│  │ ≡  name   *.grlab.co.uk                →  Corp           ✎   ✕     │ │
│  │ ≡  cidr   10.1.0.0/16                   →  Corp           ✎   ✕     │ │
│  │ ≡  sni    *.github.com                  →  Home Tailnet   ✎   ✕     │ │
│  │ ≡  app    Slack            ⚠ needs proxy →  Home Tailnet  ✎   ✕     │ │
│  │ ≡ {tcl}   when FLOW_INIT { NAT::snat … } →  «script»      ✎   ✕     │ │
│  │ ┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄┄ │ │
│  │    default  (0.0.0.0/0)                 →  [ Direct    ▾ ]          │ │
│  └────────────────────────────────────────────────────────────────────┘ │
│  [ + Rule ▾ ]   [ ⇄ Drop into Tcl ]        Kill-switch: default→Drop     │
└──────────────────────────────────────────────────────────────────────────┘
```

**DNS listeners** (Window ▸ Routes ▸ DNS) — the "different apps, different chains" model:

```
┌─ Routes ▸ DNS Listeners ────────────────────────────────────────────────┐
│  Listener   Address          Chain                                       │
│  ┌────────────────────────────────────────────────────────────────────┐ │
│  │ corp    100.100.53.1   *.corp → 10.1.0.53 via Corp ; * → 1.1.1.1    │ │
│  │ home    100.100.53.2   *      → via Home Tailnet                     │ │
│  │ direct  100.100.53.3   *      → 9.9.9.9                              │ │
│  └────────────────────────────────────────────────────────────────────┘ │
│  Point an app at a listener IP to give it that DNS chain.  [ + Listener ] │
└──────────────────────────────────────────────────────────────────────────┘
```

**Live flows + explain** (the debugger surface):

```
┌─ Routes ▸ Live Flows ───────────────────────────────────────────────────┐
│  App       Destination              Egress        Matched                │
│  ┌────────────────────────────────────────────────────────────────────┐ │
│  │ Safari   wiki.grlab.co.uk:443    Corp          name *.grlab.co.uk   │ │
│  │ ssh      10.1.2.3:22             Corp          cidr 10.1.0.0/16     │ │
│  │ curl     198.18.4.7→db.corp:5432 Corp          fake-IP db.corp      │ │
│  │ Music    17.253.…:443            Direct        default              │ │
│  └────────────────────────────────────────────────────────────────────┘ │
│  ▸ Explain  “curl → db.corp”:  DNS_REQUEST(corp) → fakeip via Corp →     │
│    FLOW_INIT → DNAT 198.18.4.7⇒10.1.2.3 → SNAT⇒10.200.0.7 → egress Corp  │
└──────────────────────────────────────────────────────────────────────────┘
```

## Security invariants (inherit repo hardening rules)

Scripts never see credentials or keychain material; `VPN::require` resolves app-side.
Safe interp, resource limits, incident logging on error. Policy/MDM can disable PBR,
pin the script, or forbid `FLOW_COLLECT`. Nothing in the Tcl namespace can write files,
spawn processes, or open sockets directly — network side effects happen only through
vetted commands.

## Phases

- **P0 (done/underway)**: netstack + SOCKS/CONNECT dialers (proxy-tunnel engine) — the substrate.
- **P1 — Tier 2, the mainstream win**: single capturing utun + egress registry + **L3
  fast-path forwarder with mandatory egress SNAT/masquerade + conntrack**. Auto-populate
  specific arms from each connected VPN's routes; expose the **default-gateway picker**
  (live-changeable, structurally one default arm → no fighting). No Tcl, no fake-IP, no
  netstack unless a flow-egress is present. **This is the throughput-critical phase — the
  fast path must be benchmarked here.**
- **P2 — Tier 3 static rules**: single DNS listener + custom static switch arms
  (CIDR/domain → egress), fake-IP overlap handling, scriptable-less DNAT via fake-IP.
  Reuses the divert-rules UI. Proves the full switch model before Tcl.
- **P3 — embed Tcl 9**: `POLICY_INIT`, `DNS_*`, `FLOW_INIT`, named listeners, hot reload,
  SNAT/DNAT commands, safe-interp + limits.
- **P4**: `TLS_CLIENTHELLO`, `HTTP_REQUEST`, `FLOW_COLLECT`/payload rewrite; egress DAG
  (single-level VPN-on-VPN).
- **P5**: GUI editor on the Routes window, tcl-lsp integration, simulator/trace.
- **P6**: app-identity via the transparent-proxy annotator (`app ==` matchers); multi-VPN
  orchestration polish — `VPN::require` health/failover events, "combine my VPNs" one-click.

## Risks to validate early

- **Throughput.** A gVisor userspace TCP/IP stack terminating *all* flows (full capture)
  has a real performance ceiling vs kernel forwarding. P1 must benchmark line-rate TCP/UDP
  through the netstack on Apple Silicon before we commit the architecture; the L3 fast path
  (cached-verdict packets bypassing the netstack) is the primary mitigation and must be
  measured, not assumed.
- **Two full-tunnel providers don't coexist.** macOS won't cleanly arbitrate two NE
  packet-tunnel providers both claiming the default route — which means **full capture is
  effectively required for real simultaneous multi-VPN**, not merely a power-user nicety.
  This validates the full-capture choice but also means "multi-VPN" and "PBR on" are the
  same switch at the OS level.
- **App-identity substrate split** (see the matcher table) — resolve before promising
  app-based routing in any UI copy.

## Open questions

1. **OpenVPN-as-egress**: when PBR is on, an OpenVPN profile attaches in-process instead
   of running as its own NE tunnel. Acceptable UX? (Proposed: yes — profile card shows
   "routed by policy".)
2. **DoH/DoT default**: block known DoH endpoints while PBR is on (scriptable override)?
3. **v6 story for fake-IP** pool sizing and ULA choice.
4. **UDP payload events** in v1 or defer (TCP-only `FLOW_COLLECT` first)?
