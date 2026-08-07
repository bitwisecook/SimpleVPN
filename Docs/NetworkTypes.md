# Network value types — one type per network concept, and the conventions they share

**Status: `MACAddress` ✅ built. Everything else 📐 to do, on no schedule.** This is a **todo list
with the reasoning attached**, not work in progress. Nothing below is half-done; each type is either
built or has not been started, and each one is written so it can be picked up on its own without
re-deriving the conventions or rediscovering the traps.

- ✅ **BUILT** — in `main`, tested.
- 📐 **TO DO** — designed here, not started. No schedule, no order forced beyond §6.

Read `ONTOLOGY.md` for the words (**hardware address**, **route**, **host interface**) and
`Docs/Networking.md` for where in the packet path each of these values lives.

---

## 0. Why this exists, in one paragraph

**Several of these rules are currently correct in several places by discipline, and — checked while
writing this — they do not all carry the same ones.** `RoutingRule.routeDest` refuses a `/0` because
a default-route divert is a full VPN bypass. `LocalNetworkCarveOut` refuses one too, and goes
further with floors of `/8` and `/16`, for a related but different reason. `RoutePrefixMath` refuses
neither, because it only ever answers "do these overlap?" and a `/0` overlaps everything, which is
true. `RouteTableSource.maskLength` is the only place that meets a real netmask and it deliberately
does **not** refuse a non-contiguous one — it falls back to a population count, because dropping the
route would make a destination silently unroutable. **Four places, four different subsets of the
same rulebook, each defensible on its own.** Nothing makes them agree; nothing tells the fifth
author which subset applies to them.

That is the *quiet* version of the problem.

**The loud version was the hardware address, and it was the same shape one step worse: every
spelling was handled correctly somewhere, and nowhere in one place, so they silently never
matched.** `netstat` prints
`42:0:5c:85:fa:1a`; UTM records `EA:85:74:8B:18:97`; VirtualBox writes `0800271A2B3C`. Each parser
was right about its own file. Compared as strings across files they were never equal, so guest names
never attached to the route diagram — and the symptom was **nothing at all**: no error, no empty
state, no log line, just a diagram that looked finished and was missing the thing it was built to
show. That is the failure mode this whole document is about. A wrong answer announces itself; a
never-matching comparison does not.

A normaliser fixes it for as long as everybody remembers to call it. A type fixes it by
construction.

---

## 1. The conventions — proven once by `MACAddress`, binding on the rest

**1. Store the parsed value, never a string.** Six bytes for a hardware address, a `UInt16` for a
port, 4 or 16 bytes for an IP address, address-plus-length for a prefix. Then `==` and `hashValue`
are structural and no spelling participates in them. `MACAddress` stores the six octets packed into
a `UInt64`; `IPPrefix` already stores masked bytes plus a length. Neither can hold a spelling.

**2. Parsing is strict and total.** `init?` yields a value or nothing. Never a partial parse, never
a repaired value, and **never a zero value standing in for failure** — `00:00:00:00:00:00` and
`0.0.0.0` are legal values, so if either can also mean "it didn't parse" the two become
indistinguishable at exactly the moment somebody writes `?? .zero`. `MACAddressTests` pins this
explicitly.

**3. Accept what real sources write; refuse the rest, with the refusal tested.** Every spelling
`MACAddress` accepts is in a table in its header naming who writes it. Cisco's dotted-quad
(`ea85.748b.1897`) is **refused**, with a test saying so, because nothing this app reads emits it —
supporting a format on speculation is how a parser widens until it accepts a corrupted field.

**4. Separate canonical from display, and never compare through either.** `MACAddress` has
`canonicalText` (padded lower-case, one form per address) and `bsdText` (what `ether_ntoa(3)`,
`netstat` and `arp` print). They are different strings for the same value. Comparison uses the
octets.

**5. Rendering is by requested form, and each rendering is named for what it is for.** Not
`description`, not `toString()` — a named property whose doc comment says which caller needs that
exact spelling and why. Add a rendering when a caller needs one; a rendering with no caller is a
liability, because it will acquire one carelessly.

**6. `Sendable`, `Hashable`, `Comparable` where order is real, `Codable` only where something
persists one.** `MACAddress` is `Comparable` because a guest's recorded addresses are `sorted()`
(and a *string* sort put `a:…` after `10:…`). It is `Codable` because `NetworkFingerprint` is —
lenient decode, canonical encode, the same asymmetry `ProviderPeerKey` uses for base64.

**7. Where persistence already exists, the persisted spelling is pinned and says so.**
`NetworkFingerprint.key` renders `bsdText` and not `canonicalText`, with a comment explaining that
every key already in `UserDefaults` was written in that spelling and canonicalising would silently
orphan a third of them. **Changing a persisted rendering needs a migration, not an edit.**

**8. A type that names a device or a person is not loggable, and the type enforces that.**
`MACAddress` has **no `CustomStringConvertible`**, so making one visible takes naming a rendering,
and `grep canonicalText` therefore finds every place one becomes visible. It *does* conform to
`CustomDebugStringConvertible` returning `MACAddress(hidden)` — without that, an accidental
`"\(mac)"` falls through to Swift's mirror and prints the packed storage, which is the address in
decimal. Its `Codable` failure message quotes nothing, because an error string is a place a value
gets copied into a report.

**9. The discipline is enforced by scanning the source, not by review.**
`HardwareAddressTypeDisciplineTests` (in `SimpleVPNTests/Monitoring/MACAddressTests.swift`) walks
every production source and fails if:

| Scan | Catches |
|---|---|
| `noHardwareAddressIsHeldAsAString` | any `mac`/`gatewayMAC`/`neighbours`/… declared or passed as `String`, `[String]`, `Set<String>`, `[String: Set<String>]` |
| `thereIsExactlyOneParserForAHardwareAddress` | a hand-rolled `normalisedMAC`, or a call to `ether_ntoa`/`ether_aton` |
| `everyPlaceThatRendersAnAddressIsAccountedFor` | a `.canonicalText`/`.bsdText` in a file not on a three-entry allow-list, each entry carrying its reason |
| `nothingInDiagnosticsHandlesAHardwareAddress` | anything MAC-shaped under `SimpleVPN/Diagnostics/` |
| `theNetworkKeyIsNeverLoggedInTheClear` | `NetworkFingerprint.key` logged `privacy: .public` |

This is the same idiom as `SettingAlignmentTests` and for the same reason: what is being checked is
a property of how the code is **written**. Copy the shape for each new type. **The scan is worth
more than the type** — the type is correct today either way; the scan is what makes it still correct
after somebody adds a fifth vendor's config parser.

**10. Where a house term is user-facing, `ONTOLOGY.md` gets it first.** "Hardware address" (never
"MAC address") is now a row in the traffic-and-routing table, together with the rule that it never
leaves this Mac. The Swift type is still `MACAddress`, because that is what an engineer greps for;
the two do not have to agree, and only the user-facing word is fixed.

---

## 2. What already exists, and what becomes of it

Four things in the tree are members of this family in spirit. **None of them should be duplicated.**

| Existing | Where | Verdict |
|---|---|---|
| **`MACAddress`** ✅ | `Shared/MACAddress.swift` | The template. Done. |
| **`IPPrefix` + `IPFamily`** | `SimpleVPN/Monitoring/RouteResolver.swift` | **This is already the prefix type, and it is good.** Masked bytes, prefix length, containment, `overlaps`, `subtracting`, `halves`, numeric ordering, `inet_ntop` canonical text, three parse entry points with different strictnesses (`parseDestination`, `parseQuery`, `parseAddress`) and zone handled as a scoping qualifier *outside* the value. The prefix work is **moving it to `Shared/` and adopting it**, not writing it. Do not start a new one. |
| **`ProviderHostname`** | `SimpleVPN/Providers/ProviderServerList.swift` | **Becomes the FQDN type, or is expressed in terms of it.** Do not end up with two. Its extra rule — must end with the provider's shipped suffix — is a *policy* on top of a name, so the shape is likely `ProviderHostname { let name: FQDN }` rather than a subclass of rules. Note it deliberately has no IDN handling and no case folding, which the general type cannot copy. |
| **`ProviderPeerKey`** | same file | **Leave alone.** A WireGuard key is not a network address; it is here only as the precedent for lenient-in/canonical-out and for "a type, not a validated String". |
| **`RoutePrefixMath`** | `Shared/RoutePrefixMath.swift` | **Absorb into the prefix type.** It is `overlaps(_:_:)` over CIDR *strings*, with its own parser, its own contiguity rules and its own `/0` handling — i.e. a second implementation of `IPPrefix.overlaps`. Two consumers: `RuleStatus` and `ProxyTunnelConfig.routeOverlapWarning` (which is why it is in `Shared/` at all). |
| **`RoutingRule.routeDest`** | `Shared/RoutingRule.swift` | **Absorb.** A third parser (`parsed`), plus the `/0`-refusal rule, plus `RouteDest` — which is address+prefix+family, i.e. an `IPPrefix` with a different name and a `Codable` wire format that is part of the app↔extension contract. **The wire format must not change**; the in-memory type behind it can. |
| **`LocalNetworkCarveOut`** | `Shared/LocalNetworkCarveOut.swift` | **Defers to the prefix type; keeps its policy.** Its `/0` refusal and its `ipv4PrefixFloor = 8` / `ipv6PrefixFloor = 16` are *safety policy about carve-outs*, not facts about prefixes, and belong here — but the masking and parsing under them should be the shared type's. |
| **`DNSSearchDomains`** | `SimpleVPN/Mediators/` | **Express in terms of FQDN.** It already normalises case, strips the trailing dot and rejects spaces, URLs, slashes and `@` — which is most of the FQDN comparison rule, arrived at separately. |
| **`NetworkFingerprint`** | `SimpleVPN/Monitoring/NetworkMemory.swift` | Now holds a `MACAddress`; still holds `gatewayIP` and `localNetwork` as `String`. Two future call sites. |

---

## 3. The types, one checklist each

Each entry: **stores / accepts / renders / traps / absorbs / call sites.**

### 3.1 `MACAddress` ✅ BUILT

Stores six octets. Accepts colon (padded or unpadded, any case), hyphen, bare-12; refuses Cisco
dotted-quad, mixed separators, wrong length, non-hex, non-ASCII digits, empty. Renders
`canonicalText` and `bsdText`. See `Shared/MACAddress.swift` — it is the worked example for
everything below.

### 3.2 `Port` 📐

- **Stores** `UInt16`. Nothing else; there is no such thing as port 70000, and today several places
  hold an `Int` that could be one.
- **Decide explicitly what `0` means**, and it is the first thing to decide because the answer is
  not obvious. Three live meanings in this tree: *unspecified* (let the engine pick), *invalid*
  (a parse produced nothing), and *the config's own* (the app already treats a `nil` port as "leave
  whatever the `.ovpn` says"). Suggestion, to be overturned with a reason: **`Port` cannot be 0 —
  `Port(0)` returns nil — and "unspecified" is spelled `Port?` = `nil`**, which is the convention
  the app already uses and which makes the third meaning the same as the first.
- **Renders** the decimal digits, and that is likely the only rendering. Resist a "with the
  protocol" form; that is an endpoint's job (§3.6).
- **Traps.** A port parsed out of a `host:port` string is not a port until the host has been
  disambiguated from an IPv6 address (§3.5). Well-known-port *names* (`https`) are not accepted —
  nothing here reads `/etc/services` and starting now would be a new dependency.
- **Call sites**: ~71 `port: Int` and 6 `port: String` across the app, extension and CLI. Large but
  shallow — mostly config structs and their editors.
- **Why it is a good second type**: many call sites, all trivial, no persistence format at risk
  beyond `Int`↔`UInt16` in JSON, and it proves the conventions on something that is *not* an
  address.

### 3.3 `IPv4Address`, `IPv6Address`, `IPAddress` 📐

- **Stores** 4 or 16 bytes. `IPAddress` is the two-case enum over them, or a family tag plus bytes —
  `IPFamily` already exists and should be reused, not re-declared.
- **Accepts** what `inet_pton` accepts, and deliberately **not** what `inet_aton` accepts:
  `10.11` and `0177.0.0.1` are legal to `inet_aton` and are how a shortened or octal address gets
  read as somewhere else entirely. `IPPrefix.parse` already draws this line and draws it three ways
  on purpose (§2) — copy the three-entry-points idea rather than picking one strictness.
- **Renders**, and this is where v6 earns its own attention:
  - **compressed** (`fd7a:115c:a1e0::`) — the canonical form, RFC 5952. `inet_ntop` gives it.
  - **expanded** (`fd7a:115c:a1e0:0000:…`) — for anything that aligns columns.
  - **with a zone** (`fe80::1%en0`). **The zone is not part of the value** — `IPPrefix` already
    decided this and carries it alongside, because `fe80::1%en0` and `fe80::1%en1` are the same
    address in two scopes and must not compare unequal. Keep that decision.
  - **mixed / embedded v4** (`::ffff:10.0.0.1`).
  - **bracketed for a host:port** — see §3.6, and make it the type's, not the call site's.
- **Traps.**
  - **IPv4-mapped v6 needs a stated policy.** `::ffff:10.0.0.1` and `10.0.0.1` are the same host and
    different values. State whether the type folds them, refuses to compare them, or keeps them
    distinct — and say it in the header, because whichever is chosen will surprise someone.
  - Uppercase hex in v6 is legal on the way in and never produced on the way out.
  - `0.0.0.0` and `::` are meaningful values, not failures (convention 2).
- **Call sites**: everywhere. This is why it is last (§6).

### 3.4 `IPPrefix` (subnet) 📐 — mostly a move, not a build

- **Stores** family + masked bytes + prefix length. **Already built** in
  `SimpleVPN/Monitoring/RouteResolver.swift` and good; masking on construction is what makes
  `10.0.0.5/24 == 10.0.0.0/24`, which is the whole point.
- **The work is**: move it to `Shared/` (the extension needs it — `ProxyTunnelConfig` already reaches
  for `RoutePrefixMath` for exactly this), then delete the other three implementations by pointing
  them at it.
- **The hard-won rules it must carry, each already true somewhere and each with a reason:**

  | Rule | Today lives in | Why |
  |---|---|---|
  | `/0` refused as a *carve-out or divert* | `RoutingRule.routeDest`, `LocalNetworkCarveOut` | a `/0` bypass is a full VPN escape, and an MDM `ForceKeepInsideVPN` escape |
  | `/0` *permitted* as a route destination | `IPPrefix.defaultRoute`, `RouteResolver` | "default" is a real, common table row |
  | `/0` *permitted* in an overlap question | `RoutePrefixMath.overlaps` | "does `/0` overlap this?" has the answer yes, and refusing to answer would be wrong |
  | non-contiguous netmask **summarised by population count, not refused** | `RouteTableSource.maskLength` | the kernel accepts one; dropping the route would make a destination silently unroutable, so the record keeps its real destination bytes and the length is the closest single number. **This is the opposite of what the other rules do and it is deliberate** — do not "fix" it while consolidating. |
  | v4 floored at `/8`, v6 at `/16` **for carve-outs only** | `LocalNetworkCarveOut` | a `/3` is not a local network, it is an eighth of the internet |
  | prefixes nest or are disjoint, never partially overlap | `IPPrefix.overlaps` | the assumption every route-set operation rests on |

  **The first three rows contradict each other and all three are right.** `/0` is a legal prefix, a
  legal route, a legal answer to an overlap question, and an illegal *carve-out*. So the refusal is
  **policy at the call site, not validation in the type** — this is the single most likely thing to
  get wrong while consolidating, because two of the current call sites want the guard and it is
  tempting to move it somewhere it would apply to all of them.
- **Absorbs**: `RoutePrefixMath` entirely; `RoutingRule.parsed`; `RouteDest`'s in-memory shape
  (**not** its JSON, which is an app↔extension wire contract).
- **Renders**: `addressText`, `description` (`a/len`), `displayText` (a host prefix is just the
  address) — all three already exist and are already used.

### 3.5 `FQDN` 📐 — the genuinely hard one

- **Stores** the labels, or the normalised name plus enough to render it back. Not the raw text.
- **Comparison is case-insensitive ASCII**, per label, and that is a *rule about the value*, so it
  belongs in `==` and in `hashValue` — not in a `lowercased()` somebody remembers.
- **The trailing dot** is a real distinction (`corp.example.` is absolute) and is almost never what
  a user means. `DNSSearchDomains` already strips it. Decide whether the type keeps it as a flag or
  drops it, and say so.
- **Limits**: 253 total, 63 per label, no empty label, no label starting or ending with `-`.
  `ProviderHostname` already enforces all four.
- **IDN / punycode is where this gets genuinely hard, and it must not be waved through.** `ProviderHostname` deliberately does no IDN handling at all, with a comment saying a provider that starts publishing Unicode should be handled *deliberately rather than silently normalised into something that no longer matches what the user was shown*. That reasoning is the type's inheritance. The decision to make, explicitly:
  - refuse non-ASCII outright (safest, and what happens today);
  - or accept and convert to A-labels on the way in — which then needs a homograph policy, because `аpple.com` with a Cyrillic а is a different domain that renders identically, and a VPN client showing the user a hostname they think they recognise is precisely the wrong place to be relaxed about that.
  - **No third option where it depends on the caller.**
- **Absorbs**: `ProviderHostname` (or is absorbed by it — see §2), `DNSSearchDomains`' normalisation.
- **Call sites**: ~111 `host:`/`hostname:`/`server: String`. The largest surface here.

### 3.6 `Endpoint` (host + port) 📐 — the bracket bug, owned

- **Stores** a host (an `FQDN` or an `IPAddress`) and a `Port`.
- **THE reason to build it**: `[::1]:443`. An IPv6 literal in a `host:port` string **must** be
  bracketed, and today **five** places do that by hand, each with its own idea of when to bracket
  and how to unbracket:
  - `SimpleVPN/Geo/WireGuardEndpointSelection.swift:110` — `h.contains(":") && !h.hasPrefix("[")`
  - `SimpleVPN/Geo/EndpointDiscovery.swift:85`, `:94` — the parse side, guarded by *counting* colons
  - `SimpleVPN/Import/SSHConfigImport.swift:259` — the parse side, `hasPrefix("[")` then find `]`
  - `Shared/SSHNetworkTunnelConfig.swift:182` — the first one's rule, written out again
  - `SimpleVPN/Credentials/BitwardenProvider.swift:145` — `host.contains(":")` → bracket, **with no
    already-bracketed guard**, so an already-bracketed host would become `[[::1]]`. Latent only
    because `isLoopback` gates it and rejects the bracketed spellings — i.e. prevented by an
    unrelated function, which is the accident this whole document is about.

  This entry said "three places" until the fourth and fifth were found while writing
  `Docs/Drift.md` §5; **the count is now guarded** by `DriftRegisterTests`, which fails on a sixth.
  Make it **one rendering the type owns** (`wireText`, or whatever it is called) and delete the
  string interpolation at every call site.
- **Parsing is the same trap in reverse**: splitting on the last `:` is right for `host:443` and
  wrong for `::1`, and `EndpointDiscovery` already guards it by counting colons.
- **Traps.** A port is optional and its absence means "the scheme's default" or "the config's own",
  never 0 (§3.2). A trailing dot on the host survives into the SNI.

### 3.7 `InterfaceName` 📐 — small, and worth it for one reason

- **Stores** the BSD name (`en0`, `utun4`, `bridge100`), and *optionally* the kernel index, which is
  what `if_indextoname`/`if_nametoindex` convert between and what `RouteTableSource` already carries
  on every record.
- **Traps.**
  - **A zone suffix is not part of the name**: `utun4%utun4` appears in real route text, and
    `NetworkIdentity.isVirtualInterface` already splits on `%` for exactly this reason.
  - **A guest tap has no address**, and `44076b1` proved that this matters: `readInterfaces` kept
    only interfaces *with* an address, so `vmenet0` was never in the list, so
    `attachedGuestInterfaces` was always empty and "N guests running" could only ever read zero on a
    live machine. **An interface is not defined by having an address.** Any type here must not
    re-import that assumption.
  - The index is only valid for this boot and must never be persisted as identity.
- **Value**: small (~20 files), and the tunnel-prefix rules (`utun`/`tun`/`tap`/`gif`/`stf`/`ipsec`/
  `ppp`/`feth`) currently live as a `[String]` on `NetworkIdentity` that several places consult.

---

## 4. What must NOT happen

- **Do not put call-site policy in an initialiser.** The `/0` case (§3.4) is the worked example: the
  same prefix is legal as a route and illegal as a carve-out.
- **Do not add a rendering with no caller.** Convention 5.
- **Do not change a persisted rendering without a migration.** Convention 7, and
  `NetworkFingerprint.key` is the live example.
- **Do not give a device-identifying type a `description`.** Convention 8.
- **Do not leave two types for one concept.** `ProviderHostname` and a new `FQDN` coexisting is the
  specific failure to avoid; that is how `RoutePrefixMath` and `IPPrefix` came to both exist.

---

## 5. Doing it all at once — what would go wrong

Someone will be tempted, because the types are small and obviously related. Concretely:

1. **`IPAddress` and `FQDN` together touch nearly every file in the tree** (~111 host sites, plus
   every config struct, every editor, every settings builder in `Shared/`, both sides of the
   app↔extension boundary). A change that large cannot be reviewed against the *behaviour* question
   that matters here, which is "did any comparison silently change meaning?" — and that question has
   to be asked value by value.
2. **Three of these have persisted or wire formats** — `RouteDest`'s JSON is an app↔extension
   contract, `NetworkFingerprint.key` is in `UserDefaults`, and `providerConfiguration` carries CIDR
   strings. Each needs its own "pinned, or migrated" decision, and batching them is how one gets
   made by accident.
3. **The conventions are not proven yet.** They have one worked example. §1's advice about renderings
   and about `Codable` is a hypothesis until a second and third type either confirm it or force a
   change — and it is much cheaper to change a convention after two types than after seven.
4. **The `/0` contradiction (§3.4) is exactly the kind of thing found while consolidating one type**
   and missed while consolidating five.
5. **A landing this size cannot be green in one increment on a flaky machine**, which is a practical
   reason and not a lesser one.

---

## 6. A suggested order, and what makes each stage safe alone

Fewest call sites and clearest traps first; the ones that touch everything last, after the
conventions have been proven twice.

| # | Type | Why here | Safe alone because |
|---|---|---|---|
| 1 | `MACAddress` ✅ | done | — |
| 2 | **`Port`** | many sites, all shallow, no addresses involved | `UInt16` in, `Int` out at the JSON boundary; nothing compares ports across spellings today, so nothing can silently change meaning. Proves the conventions on a non-address. |
| 3 | **`InterfaceName`** | ~20 files, two sharp traps already documented | Names are already compared as exact strings and already agree; this makes the `%zone` rule and the "no address ≠ not an interface" rule structural rather than remembered. |
| 4 | **`IPPrefix` → `Shared/`** | a move plus three deletions, not a build | The type is already tested through `RouteResolver`. Land the move first with no call-site changes, then delete `RoutePrefixMath`, then `RoutingRule.parsed`, then point `LocalNetworkCarveOut` at it — four increments, each independently green. Keep `RouteDest`'s JSON byte-identical. |
| 5 | **`IPv4Address` / `IPv6Address` / `IPAddress`** | large, but `IPPrefix` has already settled family, bytes, zone and canonical text | By stage 4 the parsing and rendering rules exist and are tested; this is mostly adoption. Do v4 before v6 if it splits usefully. |
| 6 | **`Endpoint`** | needs `IPAddress` and `Port` to exist | Its whole value is the bracket rendering, which is three call sites; it is small once 2 and 5 are done. |
| 7 | **`FQDN`** | largest surface, and the one genuine design decision (IDN) | Last on purpose. Settle IDN in writing before any code — and settle `ProviderHostname`'s fate in the same breath, so two never exist at once. |

**Every stage carries its own source scan**, copied from
`HardwareAddressTypeDisciplineTests` and narrowed to that type's names. A stage that lands the type
without the scan has done the smaller half of the work.
