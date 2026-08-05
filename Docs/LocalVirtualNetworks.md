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
* **Owed, and not yet written:** `SimpleVPNTests/Monitoring/VirtualizationDiscoveryTests.swift`.
  `VirtualizationEnvironment` injects the filesystem, Launch Services, directory listing and plist
  reads wholesale so a synthesised machine — including one with every product installed — can be
  tested without depending on the machine running the test. The cases it owes: `bridge100` recognised
  and `bridge0` refused; the address read off the bridge while `vmenet0` (no IPv4) is reported only as
  an attached tap; VMware's `vmnet1` attributed to VMware and not mistaken for Apple's `vmenet`; a
  vmnet bridge with two vmnet products installed naming both candidates rather than guessing one;
  each UTM mode mapping to its class from a real `config.plist` shape; `excludableSubnets` empty for a
  userspace-only machine; and `detectionEnabled == false` yielding a snapshot that says so.
