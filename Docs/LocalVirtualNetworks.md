# Local virtual networks — virtual machines and containers under a VPN

`SimpleVPN/Monitoring/VirtualizationDiscovery.swift` · settings in `VirtualizationSettingDescriptors.swift`
(**Settings ▸ General ▸ Privacy**) · manual anchors `vm-what-is-it`, `vm-detect`, `vm-warn-on-connect`

**Two products were installed on the machine this was written on: Apple `container` 1.0.0 and UTM
4.7.5. Everything else in the table below is reasoned from the vendor's own documentation and has not
been run here** — Parallels Desktop, VMware Fusion, VirtualBox, Docker Desktop, OrbStack, Colima,
Lima, Multipass and Podman were not installed and are not tested. `verifiedLocally` in the catalog is
the machine-readable form of that sentence, and it is true for exactly two rows.

**And the headline finding is that the failure everyone expects did not happen.** With Tailscale
active, Apple Containers networking **did not break**: from inside a guest, ICMP, DNS, a TLS
handshake, a 5 MB download and a 3 MB upload all succeeded — and all still succeeded with the guest
forced to MTU 1500, the configuration that should have been worst. Three measured reasons, none of
them luck:

* the guest's default MTU is **1280**, comfortably under any tunnel's;
* the guest's only resolver is the **vmnet DNS proxy on the bridge** (`192.168.64.1`), so it inherits
  the host resolver — including whatever the tunnel installed — instead of holding a stale server;
* Tailscale sets neither `includeAllNetworks` nor a route that outranks the interface-scoped route to
  the guest subnet, so the subnet is never captured in the first place.

**One thing did reproduce: DNS search-domain loss.** The host had search domains; the guest's
`/etc/resolv.conf` was `nameserver 192.168.64.1` and nothing else. A fully-qualified tailnet name
resolved from the guest; the short name returned NXDOMAIN. **No routing toggle fixes that**, and this
feature does not claim to — it is a property of what vmnet's proxy passes down.

So be clear about what the routing exclusion in this feature is *for*: it guards against **SimpleVPN's
own full-tunnel modes** (an OpenVPN/OpenConnect/WireGuard profile with a default route, or a
`includeAllNetworks` tunnel), **not against Tailscale**, which was measured not to need it.

## Where the warning actually happens

`VirtualizationBypass` decides *what could be offered*; `SimpleVPN/ControlPlane/VPNController+GuestNetworks.swift`
is the only thing that calls it, and `GuestNetworkCaptureBanner` (`UI/Connection/ConnectionBanners.swift`)
is the only thing that shows it. Three decisions worth knowing:

* **The hook is `handleStatusChange` at `.connecting`, not a connect method.** There is no single
  connect method to hang it on — Tailscale, WireGuard, the Proxy Tunnel and the SSH Network Tunnel each
  have their own, dispatched before `connect(id:plan:…)`. All four are `NETunnelProviderManager`
  underneath, so all four reach `.connecting`, and that is also the only honest moment: a guest's
  subnet exists **only while the guest is running**, so the interface list is read then
  (`TopologyMonitor.liveInterfaces()`, not the monitor's cached list — it polls only while something is
  displaying the railroad).
* **The tunnel's shape gates the warning.** A full tunnel captures everything; a split tunnel only
  warns where one of its carried prefixes overlaps the guest subnet (`RoutePrefixMath.overlaps`, the
  same arithmetic the routing-rule editor uses). Warning about a VPN that carries `10.0.0.0/8` and
  nothing else would teach people to ignore the banner.
* **The scan is off the main thread and on a deadline, and it had to be.** Detection was described as
  "local and silent — no prompts"; that was wrong. `utmGuests` enumerates
  `~/Library/Containers/com.utmapp.UTM/Data/Documents`, which is **another application's sandbox
  container**, and macOS gates it behind a consent check. With the check unanswered `open` does not
  fail — it **blocks**, indefinitely. Wiring the feature for the first time froze the entire app on
  that call, caught by the Report a Problem accessibility audit (whose "wait for the app to idle"
  never returned). So `snapshotOffMain` runs the filesystem half off the main actor with a 2 s budget,
  and computes the guest networks — `getifaddrs` only, which is the half the warning actually needs —
  *before* any filesystem call, so the warning still works when the rest times out.
* **Accepting goes through `setRoutingRules`** — the ordinary guarded path, which re-materialises every
  profile's include-set and reconnects what is live. No new mechanism, and the extension still
  re-applies `policyKeepInside` when it builds the `DivertPlan`, so a rule stored before an MDM policy
  arrived cannot leak. A dismissal is **session-scoped and not persisted**: the next connect is a new
  decision, and a permanently silenced warning about traffic being cut off is a warning that does not
  work.

## The two classes — the distinction the whole feature turns on

| | `.routedSubnet` | `.userspace` |
|---|---|---|
| How the guest reaches the network | a real host interface with a guest subnet behind it | a host process translates the guest's traffic and re-sends it as its own |
| Visible on this Mac as | `bridge100+`, `vmnet1`/`vmnet8`, `vnic0`, `vboxnet0` with an IPv4 address | **nothing** — no interface, no subnet |
| Breaks under a full tunnel because | the tunnel captures or blackholes the guest subnet | it does not, usually — it inherits the host's path, MTU and resolver |
| What fixes it | **keep the subnet out of the tunnel** (the profile's excluded routes) | **the guest's MTU** (at or below the tunnel's) and **the guest's DNS** |
| Does a routing exclusion help? | yes | **no — there is no subnet to exclude** |

`.perGuest` is the honest third answer, not a fudge: UTM and plain QEMU support both and the choice is
per virtual machine, so "UTM is installed" cannot decide it. `VirtualizationDiscovery.utmGuests` reads
each `config.plist` to get the real answer (`Shared`/`Bridged`/`Host` → routed, `Emulated` → QEMU
slirp → userspace).

A feature that skipped this distinction would look like it worked, fix nothing at all for Docker
users, and leave us confidently wrong. Hence: detection **classifies**, and the UI must never offer a
routing fix for a `.userspace` product.

## The three ARRANGEMENTS — a second axis, and not a refinement of the first

`GuestNetworkClass` above answers *is there a host interface at all*. It does not answer *who decides
where the guests' traffic goes*, and those come apart: a `.routedSubnet` product can put its guests
behind this Mac, beside it on the LAN, or in a cul-de-sac with it, and the three route differently
enough that one UI sentence for all of them is wrong for two of them. `GuestNetworkMode` is that
second axis; `ONTOLOGY.md` binds the words.

| | **shared** | **bridged** | **host-only** |
|---|---|---|---|
| Where the guests are | behind this Mac | on the same network as this Mac | with this Mac and nothing else |
| Is this Mac's routing table on their path? | **yes** | **no** | yes, for the only path there is |
| Can a VPN here change where their traffic goes? | yes | **no** | there is nowhere for it to go |
| What a tunnel capturing the subnet costs | their way out, maybe | nothing — it never sees them | this Mac's own path to them |
| Is the through/around choice offered? | yes | **no** | yes |
| Vendor words | `nat`, Shared, `vmnet8` | Bridged, `vmnet0` | Host, host-only, private, `vmnet1`, `vboxnet0` |

**And a fourth answer, which is the one that took the most care.** Telling *shared* from *host-only*
means knowing whether this Mac is translating the guests' traffic, and that lives in `pf` —
`Docs/Networking.md` §6.1 measured `pfctl -sr` as `Permission denied` for an unprivileged process, and
this app does not elevate. So the mode is read from **the vendors' own on-disk records** where they
keep one, and is `.unknown` otherwise, with a sentence in the UI saying so. Never assumed.

| Source | What it gives | Where |
|---|---|---|
| Apple `container`'s network record | the mode verbatim (`"mode":"nat"` — **measured 2026-08-07**) | `~/Library/Application Support/com.apple.container/networks/<name>/entity.json` |
| UTM's per-VM config | `Shared` / `Bridged` / `Host` / `Emulated` | each `.utm` bundle's `config.plist` |
| VMware, Parallels, VirtualBox | the vendor's own fixed adapter convention (`vmnet1` host-only, `vmnet8` NAT, `vnic0` shared, `vnic1` host-only, `vboxnet*` host-only by construction) | the interface name — no filesystem, so the never-blocking half of the scan gets it too |
| everything else | nothing | `.unknown`, said out loud |

**Only a UNANIMOUS record is used.** Nothing on disk maps `default` to `bridge100`, so with two
different arrangements recorded on one Mac we do not know which bridge is which, and the answer is
`.unknown` rather than the first match. Saying "shared" on a coin toss is a security claim.

**`net/if_bridge.h` is not in the macOS SDK** (checked, Xcode 26.5), so bridge membership — which
would separate bridged from the rest directly — would mean re-declaring the kernel's `ioctl` structs
by hand. Not done: a hand-copied struct that drifts is worse than an honest `.unknown`.

## Naming the guests — where the names come from, and what may be attached to what

A name on a routing diagram is a claim somebody acts on, so it is held to the diagram's standard:
**attach only on evidence, list as unattached otherwise, and say which.** `GuestInventory` is the
implementation; `ONTOLOGY.md` binds the words (*guest name*, *unattached*, *evidence*, and the three
presence states).

| Product | Name from | Attachment evidence | Verified here |
|---|---|---|---|
| Apple `container` | `containers/<id>/config.json` → `id` (+ `image.reference`) | `networks[].network` — the product's own network NAME | **yes, real record read 2026-08-07** |
| UTM | each `.utm` bundle's `config.plist` → `Information.Name` | `Network[].MacAddress` matched against the live neighbour cache | **yes, real record read 2026-08-07** |
| Parallels Desktop | `~/Parallels/*.pvm/config.pvs` → `<VmName>` | `<MAC>` in the same file | no — written from vendor docs |
| VMware Fusion | `*.vmwarevm/*.vmx` → `displayName` | `ethernet0.address` / `.generatedAddress` | no — written from vendor docs |
| VirtualBox | `~/VirtualBox VMs/<n>/<n>.vbox` → `<Machine name=…>` | `<Adapter MACAddress=…>` | no — written from vendor docs |
| **Docker Desktop, Podman** | **nothing** — container names live behind a daemon socket | — | **out of scope by rule** |

**Docker and Podman are out by rule, not by omission.** Their names are not in a file; getting them
means asking a daemon. `LocalToolRunner` never consults `PATH`, this app does not run a vendor's CLI
to discover things, and a daemon query is a different privacy and latency proposition from reading a
settings file the user's own tools wrote. The UI says so rather than showing an empty list that reads
as "you have none".

**Two verbatim records, so a future reader need not re-derive them.** Apple `container`:

```json
{"id":"6a20af99-…","image":{"reference":"docker.io/library/alpine:latest"},
 "networks":[{"options":{"mtu":1280,"hostname":"6a20af99-…"},"network":"default"}]}
```

UTM (`BIGIP-21.1.0.1.utm`): `Information.Name` = `BIGIP-21.1.0.1`, `Network[0]` =
`{Mode: Bridged, BridgeInterface: en0, MacAddress: EA:85:74:8B:18:97}`.

**THE SPELLING TRAP, and it would have failed silently.** `netstat` prints a hardware address with no
leading zeros in lower case (`42:0:5c:85:fa:1a` — measured); UTM records `EA:85:74:8B:18:97`.
Compared raw they never match, and the symptom is "names are never attached" rather than a crash.
`NetworkTopology.normalisedMAC` is the one place both are reduced to the same string; VirtualBox and
Parallels write it with no separators at all, which gets its own converter rather than loosening that
comparison.

**The two surfaces do not support the same set of vendors, and the reason is the interface shape.**
A *per-guest* line on the traffic graph needs one tap per guest, and only Apple's vmnet stack creates
them (`vmenet0`, `vmenet1`, …). VMware's `vmnet1`/`vmnet8`, Parallels' `vnic0` and VirtualBox's
`vboxnet0` are the *host* interfaces for a whole network — real counters, but the whole network's.

| | Route diagram: named card | Traffic graph: per-network line | Traffic graph: per-guest line |
|---|---|---|---|
| Apple `container`, UTM (Apple backend) | yes | yes | **yes** — one `vmenet` tap per guest |
| Parallels, VMware Fusion, VirtualBox | yes | yes | no — one host interface for the network |
| Docker Desktop, Podman (containers) | no name at all | n/a — no host interface | no |

**Two elimination rules, both stated so neither is mistaken for a heuristic:**

* **network name → interface.** Nothing on disk maps `default` to `bridge100`. With exactly one live
  guest network *and* exactly one recorded network, the mapping is forced. Two of either and the
  guest is unattached.
* **tap → guest** (the traffic graph's). Nothing records which `vmenet` a guest was given. With
  exactly one tap on the network and exactly one named guest on it, no other assignment is possible.
  Otherwise the line keeps the tap's own name.

**A BUG THIS WORK FOUND: the taps were never in the interface list.** `TopologyMonitor.readInterfaces`
kept only interfaces with an address (or a tunnel), and a `vmenet` tap has no address by design — so
`GuestNetwork.attachedGuestInterfaces` was always empty and "N guests running" could only ever read
zero on a real machine. Fixed by admitting `.virtualMachine` interfaces; `inUse` is unchanged, so
every existing `filter(\.inUse)` behaves exactly as before. It is also what makes a per-guest
throughput series possible at all.

## Per product (current versions only — the vendor's page is the authority)

| Product | Class | Host interface | Documented subnet | Run here? |
|---|---|---|---|---|
| Apple Containers (`container`) | routed | `vmenet*` tap + `bridge1xx` | `192.168.64.0/24` | **yes — 1.0.0** |
| UTM | per guest | `vmenet*` (Apple backend) | assigned by vmnet | **yes — 4.7.5** |
| Docker Desktop | **userspace** | none (`docker0` is inside the Linux VM) | none | no |
| OrbStack | routed | its own | `198.19.248.0/21` | no |
| Colima | per guest | `socket_vmnet` when asked for one | `192.168.105.0/24` | no |
| Lima | per guest | `socket_vmnet` when asked for one | `192.168.105.0/24` | no |
| Multipass | routed | a `bridge*` | vendor-assigned | no |
| VMware Fusion | routed | `vmnet1` (host-only), `vmnet8` (NAT) | in VMware's own `networking` file | no |
| Parallels Desktop | routed | `vnic0`, `vnic1` | `10.211.55.0/24`, `10.37.129.0/24` | no |
| VirtualBox | routed | `vboxnet0` | `192.168.56.0/24` | no |
| QEMU (outside UTM) | per guest | none with the default `-netdev user` | none | no |
| Podman | **userspace** | none | none | no |
| Rancher Desktop | per guest | depends on the VM backend | none asserted | no |

Two spellings that are not the same thing and have bitten people: Apple's tap is **`vmenet`**,
VMware's adapter is **`vmnet`**. `attribute(interfaceName:)` checks VMware's before any generic prefix
walk for exactly that reason.

A documented subnet is only ever used to *recognise* a network we could not otherwise attribute. It is
never a substitute for reading the live interface — what the vendor documents is not what a given Mac
is using.

## Two measured implementation traps

1. **The subnet lives on the bridge, not on the tap.** Apple's vmnet creates `vmenet0` for the guest —
   which has **no IPv4 address at all** — and `bridge100`, which holds `192.168.64.1/24`. Reading the
   guest network off `vmenet0` finds nothing and concludes there is no VM network, which is the
   plausible-and-wrong implementation. The taps are still worth reading: their *names* are how you
   know a guest is actually attached.
2. **`bridge0` must be excluded.** It is the ordinary user-configurable Thunderbolt/Ethernet bridge
   that exists on stock macOS. macOS allocates vmnet bridges from `bridge100` upwards, so the number
   is the discriminator. Treating `bridge0` as a guest network would invite someone to route **their
   real LAN** around their VPN — a split-tunnel hole offered in a dialog that claimed to be fixing a
   container.

## Manual test recipe

Needs: Apple's `container` (or UTM with a *Shared* VM), and a SimpleVPN profile that carries a default
route.

1. **Nothing running.** With no guest booted, open **Settings ▸ General ▸ Privacy**.
   **Expect:** the products you have installed are listed, and **no guest networks** — because a
   subnet is assigned when a guest boots. It must not invent `192.168.64.0/24` from the on-disk
   network record; that record says `"mode":"nat"` and carries no subnet.
2. **Boot a guest**, then look again (`ifconfig` to confirm independently).
   **Expect:** one guest network naming the **`bridge1xx`** and its `/24`, with the `vmenet*` taps
   listed as attached guests. The host address is the bridge's, not the tap's.
3. **`bridge0`.** In System Settings, create a Thunderbolt/Ethernet bridge so `bridge0` has an IPv4
   address.
   **Expect:** it is **not** offered as a guest network anywhere, ever.
4. **Connect a full-tunnel VPN** with the guest running and **Warn Before a VPN Captures Them** on.
   **Expect:** a warning naming the subnet, and an offer to keep it out. Decline it →
   **routing is unchanged** (`netstat -rn` before and after are identical).
5. **Accept the offer.**
   **Expect:** the subnet appears in that profile's excluded routes, visibly and removably, and in no
   other profile. Guest connectivity returns.
6. **Docker Desktop, if you have it.** With it installed and a container running, connect the same
   VPN.
   **Expect:** no routing offer at all — instead the MTU/DNS sentence. An exclusion offered here would
   be a lie, and its absence is the test.
7. **Turn detection off.**
   **Expect:** no products, no networks, no warning, and the snapshot reports `detectionEnabled ==
   false` rather than an empty list that reads as "you have none".
8. **The Tailscale case, for the record.** With Tailscale connected and a guest running: from inside
   the guest, `ping`, a DNS lookup, `curl https://…`, a 5 MB download and a 3 MB upload should all
   succeed, at the default MTU **and** at 1500. A **short** tailnet name is expected to fail while its
   FQDN succeeds — the search-domain finding above, not a regression.
9. **Nothing was executed.** Across all of the above:
   `sudo fs_usage -w -f exec | grep -iE 'docker|container|VBoxManage|prlctl|qemu|ifconfig'`.
   **Expect:** nothing. Detection is `stat`, plist reads and `getifaddrs` — no daemon woken, no
   `--version`, no network, nothing written.

## Automated coverage

* `SimpleVPNTests/ControlPlane/ManualAnchorParityTests.swift` — registers `vm.` as a catalog, so both
  settings must have manual sections with a stated default, and `vm-what-is-it` is declared prose.
  A `vm.*` setting added without documentation fails here.
* `SimpleVPNTests/Monitoring/VirtualizationBypassTests.swift` — the refusals, and (in
  `GuestNetworkCaptureTests`) the connect-time gate: a full tunnel captures everything, a split tunnel
  carrying `10.0.0.0/8` says **nothing** about `192.168.64.0/24`, and one that overlaps the guest
  subnet still warns. `GuestNetworkWiringTests` pins the seams themselves, because a path with no
  caller is exactly the defect this feature shipped with once.
* `SimpleVPNTests/Monitoring/VirtualizationDiscoveryTests.swift`.
  `VirtualizationEnvironment` injects the filesystem, Launch Services, directory listing and plist
  reads wholesale so a synthesised machine — including one with every product installed — can be
  tested without depending on the machine running the test. The cases it covers: `bridge100` recognised
  and `bridge0` refused; the address read off the bridge while `vmenet0` (no IPv4) is reported only as
  an attached tap; VMware's `vmnet1` attributed to VMware and not mistaken for Apple's `vmenet`; a
  vmnet bridge with two vmnet products installed naming both candidates rather than guessing one;
  each UTM mode mapping to its class from a real `config.plist` shape; `excludableSubnets` empty for a
  userspace-only machine; and `detectionEnabled == false` yielding a snapshot that says so.
