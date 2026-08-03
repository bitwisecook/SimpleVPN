# System-State Mediators — Routes, DNS, Proxies

A single architectural principle applied to the three things a VPN mutates on the host:
**capture each engine's *intent*, arbitrate it centrally, be the sole writer, monitor the real
OS state for external drift, and publish effective state live.** This is what lets us make
guarantees (never two default gateways, coherent DNS, one proxy decision), stay in sync, and
react the instant something else changes the system. It is backing-agnostic: the same mediator
API is realized by today's multi-tunnel model and, later, by the PBR utun (`PolicyRouting.md`).

## The problem it fixes

Today each engine mutates the host on its own — openvpn3's `TunBuilder` route/DNS callbacks,
Tailscale's `CallbackRouter`, OpenConnect's vpnc-script, native `NEVPNManager`, each building
its own `NEPacketTunnelNetworkSettings`. Nobody owns the merged result, so states fight and
desync (the OpenVPN full/split bug: two notions of "who holds the default", neither sourced
from reality). Three mediators replace that with one authority per resource.

## The common shape (all three mediators)

```
   engines ──▶ [1] Intent capture ──▶ [2] Arbiter ──▶ [3] Applier (SOLE writer) ──▶ OS
                                          ▲                                          │
   policy (owner pick, PBR switch) ───────┘                                         │
                                          ▲            [4] Monitor (OS drift) ◀──────┘
   UI ◀── [5] Publisher (effective state) ┘◀───────────────┘
```

1. **Intent capture.** An engine never writes the host directly; it submits structured
   *intent* — `RouteIntent` / `DNSIntent` / `ProxyIntent` — describing what it *wants*
   (advertised prefixes, whether it wants the default, its resolvers/search domains, its
   proxy/PAC). For our in-house engines this is captured at the bridge seam that already
   translates engine state into `NENetworkSettings`; the bridge now *submits* rather than
   *applies*. Intent is inspectable and per-engine. **This is the scriptable seam:** in tier-3,
   `ROUTE_ADVERTISED`/`DNS_PUSHED`/`PROXY_PUSHED` events fire here so a Tcl handler can rewrite
   intent before arbitration (redirect a pushed route, bind a translation table, restrict a
   VPN's DNS domains); `*_CHANGED` events fire from stage 4 on external drift (`PolicyEvents.md`).
   The tier-2 mediators must route intent through a single hookable point so these attach later
   without restructuring.
2. **Arbiter.** Merges all intents into one coherent desired state under policy + invariants
   (below). This is where "≤1 default owner", split-DNS precedence, and single-proxy-decision
   are *computed*, not hoped for.
3. **Applier — the sole writer.** Realizes the desired state to the OS through exactly one
   path per resource. Nothing else in the app writes routes/DNS/proxy. Backing-agnostic:
   `MultiTunnelRealizer` now (per-tunnel `includedRoutes`/DNS/proxy + native manager + pf),
   `PBRRealizer` later (the capturing utun + the switch).
4. **Monitor — external drift.** Watches the *actual* OS state and fires the instant anything
   external changes it (another VPN app, a `route` command, a network change, macOS
   reconfiguring). On divergence: re-assert desired state (self-heal) and/or surface it.
5. **Publisher.** Emits effective (real, observed) state to the UI live — generalizing the
   `effectiveDefaultOwned` read-back channel added for the gateway fix to all three resources.
   The UI reflects reality, never just the stored preference.

## Route mediator

- **Intent:** `RouteIntent { egress, advertisedPrefixes, wantsDefault, metric }` per engine.
- **Arbiter/invariant:** exactly **≤1 default owner**; non-owners keep their specific prefixes
  (demoted to split). Owner chosen by policy (tier-2 gateway pick; tier-3 the switch's default
  arm). Atomic switch = strip-old → add-new (never two defaults). This is the just-fixed
  gateway logic, promoted to the arbiter; `GatewayPolicy` stays the pure role/invariant math.
- **Applier:** per-tunnel `NEPacketTunnelNetworkSettings.includedRoutes` + default suppression
  (`_suppressDefault` / `gateway:full|split` IPC), native-manager `includeAllNetworks`, and —
  the enforcement teeth — a **pf anchor** (root sysext) that only permits egress where policy
  says, so "no two default gateways" holds at the firewall even if the kernel route table is
  perturbed.
- **Monitor:** a **`PF_ROUTE` socket** (route add/delete/change messages) — immediate external
  drift detection; fallback periodic `NET_RT_DUMP` diff. External default-route changes are
  caught and re-asserted (or surfaced) at once.
- **macOS honesty:** we are not the kernel and cannot *forbid* another process writing the
  route table — but we are the sole writer for *our* tunnels, we detect foreign changes
  instantly, we re-assert, and pf enforces the actual egress. That combination is the
  guarantee.

## DNS mediator

- **Intent:** `DNSIntent { egress, resolvers, searchDomains, matchDomains, dnsFakeIP? }`.
- **Arbiter:** merge into a coherent **split-DNS** config — which resolver serves which domain
  — instead of letting the last VPN's push clobber the rest. (This is the tier-2 precursor of
  the PBR named-DNS-listeners: several VPNs' pushed resolvers become per-domain routes to the
  right egress.) Precedence + conflict resolution live here.
- **Applier (REAL, sole writer):** per-tunnel `NEDNSSettings` + `matchDomains`, pushed
  live over the `dns:apply:`/`dns:clear` IPC (`Shared/DNSApply.swift`). Because DNS
  arbitrates per-domain, the applier is PER PARTICIPANT: the catch-all owner gets the
  default resolvers scoped to `[""]`; each split participant gets its resolvers scoped
  to only the domains it won. The in-process bridges (openvpn3, OpenConnect) store the
  override and re-apply their captured tun settings live (no reconnect) — the DNS
  parallel of the proxy applier. RECONNECT is now only the FALLBACK for engines with no
  live DNS applier (proxy-tunnel / Tailscale re-establish DNS from their config; native
  kinds are OS-owned). (Tier-3: our DNS listeners + resolver chains.)
- **Monitor:** **`SCDynamicStore`** notifications on `State:/Network/Global/DNS` and
  per-service DNS keys — detect external resolver changes and re-assert.
- **Publisher:** effective resolver map to the UI (which domain resolves where).

## Proxy mediator

- **Intent:** `ProxyIntent { egress, manual(per-scheme+exceptions) | pac(url|script) | none }`
  — captured from each VPN's pushed proxy config (`PUSH::proxy`, `NEProxySettings`).
- **Arbiter:** per the Proxies model (`PolicyRouting.md`) — proxy is a **per-egress attribute
  resolved per flow**, so multiple VPNs' proxies coexist. Tier-2 realization: apply the
  *owner's* proxy as system `NEProxySettings`; tier-3: per-flow per-egress PAC (JavaScriptCore)
  with Tcl mediation.
- **Monitor:** `SCDynamicStore` on the proxies key — detect and re-assert external proxy
  changes.
- **Publisher:** effective proxy decision to the UI.

### Pushed-proxy sources by VPN kind (intent capture is per-kind)

Each protocol conveys proxy config through a different channel, so the `ProxyIntent` capture
must be per-kind. The three shapes a proxy arrives in: a **PAC URL**, a **manual
host:port(+auth)** per scheme, or **none**.

| Kind | Manual HTTP/HTTPS host:port | Proxy auth | PAC URL | Channel / where we capture it |
|---|---|---|---|---|
| **OpenVPN** | ✅ `dhcp-option PROXY_HTTP`/`PROXY_HTTPS` | ~ (`PROXY_NTLM` flag; push carries no creds — client supplies) | ✅ `PROXY_AUTO_CONFIG_URL` | openvpn3 TunBuilder `tun_builder_set_proxy_http/https/auto_config_url` — **already captured** (`OpenVPN3Bridge.mm:121-128`); also `PROXY_BYPASS` → exceptions |
| **OpenConnect** (AnyConnect / GlobalProtect) | ~ vendor-specific gateway/profile push | ~ | ~ (AnyConnect & GP can push a PAC) | subprocess output / connect config — parse from openconnect (needs verification per real gateway; distinct from `--proxy`, which is the *outbound* proxy we dial THROUGH) |
| **IKEv2 / IPsec** (native) | ✅ via `NEProxySettings` | ✅ (`NEProxyServer` user/pass) | ✅ (`proxyAutoConfigurationURL` / auto) | OS-applied from the profile; we **observe** it via `SCDynamicStore` (NEVPNManager owns the write) |
| **Tailscale** | ⛔ none | — | ⛔ | — (no proxy push) |
| **WireGuard** | ⛔ none | — | ⛔ | — (config has no proxy directive) |
| **SSH** | ⛔ | — | ⛔ | it *provides* a SOCKS proxy (`-D`), it doesn't *push* one to the client |
| **Proxy-tunnel** | ⛔ | — | ⛔ | it dials *through* an upstream proxy; not a pushed-proxy source |

Notes: OpenVPN's pushed proxy carries no credentials (only an NTLM hint) — proxy auth (a 407)
is answered from stored creds / the keychain, never from the push. `NEProxySettings` (native)
*does* carry `NEProxyServer.username/password`. A PAC (any kind) only names proxies; auth is
still resolved at connect. So `ProxyIntent` needs: `scheme → (host, port)`, an optional
`pacURL`/`pacScript`, an `authSource` (keychain ref), and a bypass/`matchDomains` list.

## VPN-kind participation (handle every kind cleanly)

Kinds touch these resources very differently; each mediator must **classify** every connected
profile and handle it in exactly one clean bucket — participate, participate-with-limits,
proxy-only, or excluded-with-reason — never silently mis-handle or assume all kinds are NE
route-participants.

| Kind | Route | DNS | Proxy | How |
|---|---|---|---|---|
| OpenVPN (openvpn3) | ✅ full | ✅ | ✅ | bridge; `_suppressDefault`; pushed DNS/proxy |
| Proxy-tunnel | ✅ full | ✅ | ➖ (it *is* an egress) | `suppressDefaultRoute` |
| Tailscale | ✅ default **only with exit node** | ✅ (netmap/MagicDNS) | ➖ | exit-node prefs |
| OpenConnect (in-process NE) | ✅ full | ✅ (CSTP push) | ✅ | bridge; `_suppressDefault` (`setDefaultRouteOwned:` / `setInitialDefaultRouteOwned:`) — demotes live like openvpn3 (keeps split-include subnets, drops the default + DNS catch-all when non-owner), so it enters ≤1-owner arbitration with no reconnect |
| OpenConnect (subprocess/ocproxy) | ➖ no default route | ~ | ✅ **proxy** (system SOCKS) | Proxy-mediator participant |
| SSH | ➖ no default route | ➖ | ✅ **proxy** (SOCKS `-D`) | Proxy-mediator participant |
| Native IKEv2/IPsec/L2TP | ~ coarse (full/split via `includeAllNetworks`; no live demote) | ~ (`NEDNSSettings`) | ~ (`NEProxySettings`) | OS-run via NEVPNManager; entitlement-gated |
| WireGuard | ✅ full | ✅ (`DNS=` servers → catch-all) | ➖ (no proxy directive) | `WireGuardNetworkSettings` `suppressDefaultRoute` — demotes live like the proxy tunnel |

**Route-mediator classification rule:** only kinds with a real default-route capability get a
gateway role and enter ≤1-owner arbitration. Kinds with no default route (SSH, subprocess
OpenConnect) are **excluded** from the gateway picker with a reason and never
assigned a role. Native kinds participate coarsely (`includeAllNetworks`) or are marked limited.
The Proxy mediator owns the SOCKS-proxy kinds (SSH, ocproxy OpenConnect). Never crash, never
silently no-op a kind — every kind resolves to one bucket, surfaced in the UI.

## Guarantees this buys

- **One default gateway, always** — computed invariant + pf enforcement + drift re-assert.
- **In sync** — single writer per resource; effective state is observed, not assumed.
- **Live UI** — the Publisher pushes real state; the picture can't say split while routing full.
- **Foreign-change resilience** — the Monitors catch anything external and self-heal.
- **One surface for both eras** — tier-2 and tier-3 differ only in the Realizer; policy, API,
  invariants, monitoring, and UI are shared.

## API surface (backing-agnostic, per mediator)

- `submit(intent, from: engine)` / `withdraw(engine)` — capture.
- `setPolicy(...)` — owner pick / PBR switch / precedence.
- `effective()` — observed OS truth (drives the UI).
- `reconcile()` — drive OS toward desired; `onDrift(observed)` — monitor callback → re-assert.
- `plan()` — computed desired state (testable in isolation, like `GatewayPolicy`).

## Build phasing

- **P1 — Route mediator (formalize + monitor).** Extract the just-fixed gateway logic into a
  `RouteMediator` (arbiter + `MultiTunnelRealizer`), add the `PF_ROUTE` monitor + live publish.
  Behavior-preserving; adds drift detection and the clean seam. Highest value (it's the
  resource with a live invariant).
- **P2 — DNS mediator.** Capture per-engine DNS intent, arbitrate split-DNS, `SCDynamicStore`
  monitor. Precursor to PBR DNS listeners.
- **P3 — Proxy mediator.** Capture proxy intent, owner-proxy applier, `SCDynamicStore` monitor.
- **P4 — PBR realizers.** Add `PBRRealizer` for each; policy flips the backing, API unchanged.

## Boundaries & notes

- Native `NEVPNManager` tunnels participate through the same intents (the manager is their
  applier); they're part of the ≤1-owner plan.
- pf programming lives in the **root sysext** (already root — no separate daemon), shared with
  the kill switch (`PolicyRouting.md`).
- The mediators are the *implementation* substrate; `PolicyRouting.md`/`PolicyEvents.md`
  describe the tier-3 policy that sits on top. Same plan objects flow through both.
