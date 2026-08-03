# PBR — Policy-Based Routing engine home (design done, engine not built)

Tier-3 of the routing architecture: the Tcl-9 iRules-style policy engine — full-capture
single utun, gVisor netstack, routing-as-a-switch, egress DAG, NAT/SNAT/DNAT, fake-IP
overlap handling, named DNS listeners, per-egress proxies + PAC via JavaScriptCore.

The **design is the contract** — read it before writing code here:

- `Docs/PolicyRouting.md` — the engine design, GUI sketches, example Tcl scripts
- `Docs/PolicyEvents.md`  — the `VPN_*` / `VPN_HS_*` event & command taxonomy
- `Docs/StateMediators.md` — how the engine slots in as the mediators' realizer (P4)

Integration points that already exist and MUST be reused, not duplicated:

- `Mediators/StateMediator.swift` — `MediatorIntentHook` / `MediatorDriftHook` are the
  Tcl attach points (`ROUTE_ADVERTISED`, `DNS_PUSHED`, `*_CHANGED`); the engine becomes
  a `MediatorRealizer` behind the same protocols the multi-tunnel realizer implements.
- `Mediators/CustomRouting.swift` — tier-2 per-VPN filters; PBR supersedes them only
  when the user opts in (off by default, always).
- `Vendor/proxy-engine` — the gVisor netstack the full-capture utun builds on.
