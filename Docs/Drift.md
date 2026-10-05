# Drift — the register of things this codebase implements more than once

**One concept, several implementations, differing by accident rather than intent.** That is
drift, and it produced most of one day's bug reports: five copies of an editor row so a
one-line fix landed in one of them; two hardware-address normalisers so guest names never
attached; three row builders under one heading so one section showed two icon styles, two
heights, two dot positions and a chip squeezed to "Untest…".

This file is the **register**: every duplication known to us, where the copies are, whether
they currently agree, and the verdict.

**A register that said "merge everything" would be ignored, so this one does not.** Section
6 is the model: four places implement prefix rules, with four different subsets of one
rulebook, and each subset is right for its own question. Forcing them into agreement would
break three of them. The verdict there is *keep separate, bounded* — and the guard that
goes with it does not demand agreement, it demands that there is never a **fifth**.

## The verdicts

| | Meaning |
|---|---|
| **COLLAPSE** | One implementation. Done, or the next thing to do. |
| **KEEP SEPARATE** | Genuinely different subjects. The entry states the reason and the guard bounds the count. |
| **NOT YET DECIDED** | A real inconsistency whose resolution is a design decision nobody has made. Written down so it is not rediscovered as a bug. |

## The guards

Prose does not stop drift; a failing test does. Two suites carry these:

* **`SimpleVPNTests/ControlPlane/DriftRegisterTests.swift`** — one table, one row per
  guarded concept below, naming the files allowed to contain it. **A new file containing a
  guarded implementation fails the build.** Collapsing is one fix; adding the file to the
  table with a reason, here and there, is the other — and that is a deliberate act visible
  in a diff, which is the whole point.
* **`SimpleVPNTests/UI/SidebarRowDisciplineTests.swift`** — the sidebar rows specifically:
  one row layout, one set of metrics, one caption rule, one spoken sentence, one dot
  position.

Plus the ones that already existed and are not repeated here:
`SettingAlignmentTests` (§9), `HardwareAddressTypeDisciplineTests` (§4),
`RuleListReachabilityTests`, `ConnectListingTests`, `ManualAnchorParityTests`.

---

## 1. Setting rows — five per-editor helpers ✅ COLLAPSED

**The concept:** a labelled row in a config surface, with its value on the right.

**Was:** five near-identical private row helpers, one per editor. The reported bug — "values
not right-aligned", reported **twice** — was one line in a shared row that only misbehaved
for `Picker`s; thirty call sites looked wrong because one shared thing was wrong, and five
copies is why the first fix reached only one of them.

**Now:** `SettingRowLayout`, `SettingValueField`, `SettingPicker`. `EngineSettingRow` and
`OpenVPNOptionsForm.SettingRow` are the two row TYPES that cannot merge (they differ in
where "changed" and availability come from) and neither writes the layout out.

**Verdict: COLLAPSE — done (`fb0a00d`).** Guarded by `SettingAlignmentTests`.

## 2. `SubprocessTunnelView` — excluded from §1, and three defects later ⛔ OUT OF SCOPE HERE

**The concept:** the same setting rows as §1, in the SSL-VPN / SSH editor.

`fb0a00d` could not touch this file — another agent held it — and it is now the source of
three separate defects (settings silently not persisting, an unbounded pane that blew a
sidebar to 4627pt, an unexplained banner). It is **owned by another agent right now** and
this change stays out of it.

**This entry is the point of this file.** The exclusion was recorded honestly in a commit
message, and a commit message is not a place anybody looks. The rule that came out of it is
in `AGENTS.md` — *"A change that cannot cover part of its own scope"*.

**Verdict: COLLAPSE — blocked on ownership.** Not on a list somewhere: the exclusion is
`SidebarRowDisciplineTests.subprocessTunnelViewIsStillOutsideTheSharedRows`, which passes
today and **fails the moment that file stops being excluded without this entry being
updated**. It cannot be forgotten because it is in the test run.

## 3. Sidebar rows — five builders under one heading ✅ COLLAPSED (this change)

**The concept:** a row in a list of connections.

**Was five.** `VPNSidebarRow` and `ConnectionView.otherConnectionRow` in the main window;
`profileRow`, `tunnelRow` and `nativeRow` in Manage VPNs; plus `VPNRow` in `ContentView`,
which only Manage VPNs' profile rows used. `7df48eb` merged the main window's two SECTIONS
and said so plainly — the three Manage VPNs builders were "lifted … verbatim, no layout
restructure" — so the headings stopped dividing rows by transport and the rows kept doing
it themselves. In one section the user saw:

* two icon styles — a `LogoBadge` on a profile row, a bare `Image(systemName:)` on the
  tunnel beside it. That is our transport split showing through the icons after it had
  been taken out of the words (ONTOLOGY.md rule 1: never name — or draw — a thing after
  the implementation that happens to serve it);
* two heights — 52pt with padding, versus whatever the text came to;
* a dot in two positions — inside the badge for a profile, a separate leading `StatusDot`
  for everything else;
* an inconsistent subtitle — none on a profile row, the kind on a native row, which for a
  VPN the `+` menu named after its kind rendered "IKEv2" under "IKEv2";
* **"Untest…"** — the maturity chip's `Text` compressed to a five-character stub. That
  chip's entire job is to invite a report on a VPN kind nobody has tried, so unreadable
  means it cannot do it.

**Now:** `SimpleVPN/UI/Components/ConnectionRow.swift` —

| Piece | What it owns |
|---|---|
| `ConnectionRowMetrics` | the numbers: badge 26pt @1.15, 6pt gutter, 6pt vertical padding, 52pt minimum |
| `ConnectionRowCaption` | the line under the name, **including when there is none** |
| `ConnectionRowSentence` | the row as one sentence, from `DotState` rather than a typed word |
| `ConnectionRowLayout` | the assembled non-interactive row |

Used by Manage VPNs' three row builders (which now pass in only what differs: which store
answers, the caption's extra fact, the context menu) and by the main window's
`otherConnectionRow`. `VPNRow` is deleted.

**`VPNSidebarRow` keeps its own layout, with a stated reason** — its middle column is
INTERACTIVE (a destination picker replaces the caption for a multi-endpoint VPN, and an
interactive control cannot live inside the `.combine` element a one-sentence row is made
of) and its trailing column is the live transport control. It reads `ConnectionRowMetrics`
and `ConnectionRowSentence`, which is what had actually drifted.

**The composition row keeps its own layout too**, for a different reason: a composition is
a GROUP of VPNs, so it has no kind, no maturity, no logo and no dot — everything the shared
row is made of. It takes the metrics.

**Verdict: COLLAPSE — done.** Guarded by `SidebarRowDisciplineTests`.

## 4. Hardware addresses — two hand-rolled normalisers ✅ COLLAPSED

**The concept:** a MAC address.

`NetworkTopology` handled the colon spellings, `GuestInventory` the unseparated one, and
they disagreed about which spellings were legal. Compared as strings across files they were
never equal, and **the symptom was nothing at all** — no error, no empty state, just guest
names that never attached to the route diagram.

**Now:** `Shared/MACAddress.swift`, one parser, six packed octets, structural `==`.

**Verdict: COLLAPSE — done (`842c325`).** Guarded by `HardwareAddressTypeDisciplineTests`,
in two halves: no hardware address is declared as a `String`, and nobody normalises one by
hand. `Docs/NetworkTypes.md` §1 is the conventions this proved.

## 5. `[::1]:443` — the IPv6 bracket, hand-rolled in **five** places ⚠️ COLLAPSE, not started

**The concept:** rendering (and re-parsing) `host:port` when the host may be an IPv6
literal.

`Docs/NetworkTypes.md` §3.6 records three sites. **There are five**, and the two it does not
list are the interesting ones:

| Site | Rule it applies |
|---|---|
| `SimpleVPN/Geo/WireGuardEndpointSelection.swift:110` | `contains(":") && !hasPrefix("[")` → bracket |
| `SimpleVPN/Geo/EndpointDiscovery.swift:85`, `:94` | parse side — guards by COUNTING colons |
| `SimpleVPN/Import/SSHConfigImport.swift:259` | parse side — `hasPrefix("[")` + find `]` |
| **`Shared/SSHNetworkTunnelConfig.swift:182`** | same rule as the first, written out again |
| **`SimpleVPN/Credentials/BitwardenProvider.swift:145`** | `contains(":")` → bracket, **with no already-bracketed guard** |

The last one is the drift doing what drift does: four sites carry the `!hasPrefix("[")`
check and the fifth does not, so a host that arrives already bracketed becomes `[[::1]]`.
It is latent rather than live today only because `isLoopback` gates it and rejects the
bracketed spellings — i.e. it is prevented by an unrelated function, which is exactly the
kind of accident that stops being true.

**Verdict: COLLAPSE — designed, not started.** The design is `Endpoint` in
`Docs/NetworkTypes.md` §3.6, which needs `IPAddress` and `Port` first. Until then the
guard bounds it: **`DriftRegisterTests` fails on a sixth site**, and `Docs/NetworkTypes.md`
§3.6 has been corrected to name all five.

## 6. Prefix rules — four places, four subsets ✅ KEEP SEPARATE (this is the model entry)

**The concept:** what a CIDR prefix is allowed to be.

| Place | Its rule | Why it is right |
|---|---|---|
| `RoutingRule.routeDest` | refuses `/0` | a default-route divert is a full VPN bypass |
| `LocalNetworkCarveOut` | refuses `/0`, floors v4 at `/8` and v6 at `/16` | a `/3` is not a local network, it is an eighth of the internet |
| `RoutePrefixMath.overlaps` | permits `/0` | "does `/0` overlap this?" has the answer **yes**, and refusing to answer would be wrong |
| `RouteTableSource.maskLength` | **accepts** a non-contiguous netmask, summarising it by population count | the kernel accepts one, and dropping the route would make a destination silently unroutable |

The last is the opposite of what the other three do **and it is deliberate**. Four subsets
of one rulebook, each defensible on its own; nothing makes them agree, and nothing should.

**What is wrong is not the disagreement — it is that nothing tells the fifth author which
subset applies to them.** So:

**Verdict: KEEP SEPARATE, BOUNDED.** The parsing and masking *underneath* the policies
should become one `IPPrefix` (`Docs/NetworkTypes.md` §3.3) — the policies stay where they
are. `DriftRegisterTests` allows exactly these four files to declare a prefix policy and
fails on a fifth, whose author then has to come here and say which subset they are.

## 7. "Change…" — two affordances, one screen ✅ COLLAPSED (this change)

**The concept:** the button that reopens the sign-in chooser.

`SignInSourceSummary` had one and `SignInSourceRecoveryNotice` had the other, and the
recovery banner sits **directly above** the summary line — so both are on screen at once.
They had already drifted: two button styles and two accessibility shapes (one carried a
hint, one did not). The second one's own comment stated the rule it could not enforce —
*"two identical actions on one screen must not have two appearances."*

**Now:** `ChangeSignInSourceButton`, one view, both call sites.

**Verdict: COLLAPSE — done.** Guarded by `DriftRegisterTests`: `"Change\u{2026}"` may be
spelled in exactly one place.

## 8. Socketpair framing — 4-byte AF header vs raw IP ✅ KEEP SEPARATE

**The concept:** how a packet is framed on an engine's tun file descriptor.

`openvpn3` sets `tun_prefix = true` and frames every packet with `htonl(AF_INET/AF_INET6)`;
`libopenconnect`'s `os_tun` path carries raw IP and infers the family from the version
nibble. **This is not our choice** — each engine's own source decides it, and making them
agree would mean patching a vendored engine.

**Verdict: KEEP SEPARATE — the difference is upstream's.** It is documented at both call
sites and in `Docs/Networking.md` §3.2, which calls it "the single most surprising thing in
the packet path". `DriftRegisterTests` bounds it: only the two bridges may frame a tun fd,
so a third fd-shaped engine has to declare its framing here rather than inherit whichever
neighbour it was copied from.

## 9. Status words — three vocabularies ✅ KEEP SEPARATE (layered, not duplicated)

**The concept:** what the app calls a connection's state.

* `DotState.accessibilityDescription` — the six dot states, in words. **The base
  vocabulary**, and the only route by which a hidden dot reaches VoiceOver.
* `VPNController.statusText(_:)` — `NEVPNStatus` in the user's words, for a visible caption.
* `ConnectNeed.statusWord` — "Sign-in needed" / "Verification code needed" / "Not
  configured", for a connection that cannot go yet. `NEVPNStatus` has no case for any of
  them.

These are **layers over one vocabulary**, not three copies: each names states the others
cannot. What *was* duplicated is now gone — `active ? "connected" : "disconnected"` was
written out for the composition row in `ManageVPNsView` **and** in `MenuBarView`, two
literals nothing kept in step with the enum.

**Verdict: KEEP SEPARATE, BOUNDED.** `DriftRegisterTests` fails on a `"connected"` /
`"disconnected"` literal in an accessibility string outside these three definitions.

## 10. Sidebar selection tags — two private constants ✅ COLLAPSED

`ManageVPNsView` and `ConnectionView` each held `"tunnel:"` / `"native:"` and happened to
agree; a settings route travelling between the windows resolves by tag, so disagreeing
would have selected nothing. They are `ConnectListing.tunnelTag` / `.nativeTag` now.

**Verdict: COLLAPSE — done.** Guarded by `DriftRegisterTests`.

## 11. Connect-list caption — the state, or the kind? ❓ NOT YET DECIDED

In the main window's "Whole-Mac VPNs" section, side by side:

* an NE profile row's caption is its **state** ("Connected", "Sign-in needed");
* every other row's caption is its **kind and port** ("F5 BIG-IP APM · SOCKS on
  127.0.0.1:1080").

Both are defensible — the profile rows have a live `NEVPNStatus` to say and the others do
not; the others have a port to say and the profiles do not — and the result is still two
rows in one section answering two different questions.

**Verdict: NOT YET DECIDED.** It is not a bug and it is not consistent. Recorded so the
next person to look at that section knows it was seen rather than missed. Deciding it means
deciding what a connect list's caption is *for*, which is a design question and not a
tidy-up. (Manage VPNs is settled: it is a configuration list, so its caption is the kind.)

## 12. `LogoBadge`'s fallback glyph ✅ COLLAPSED (this change)

A globe for an NE profile ("a logo is expected and simply absent") and the kind's symbol for
everything else — **in the same sidebar section**. The reason had stopped being true: only
the OpenVPN editor has a logo well, so WireGuard, Tailscale, Proxy Tunnel and SSH Network
Tunnel profiles could never get a logo either and still drew a globe that said nothing about
them. All five call sites pass `fallbackSymbol: kind.systemImage` now; a logo, when there is
one, still wins.

**Verdict: COLLAPSE — done, and the guard is the compiler.** `fallbackSymbol` has **no
default value**, so a new call site cannot silently inherit a policy — it has to state one,
visibly, in the diff. A compile error is the strongest structural guard available and is
always preferable to a source scan when the shape allows it.

## 13. Compact notices and user labels ✅ COLLAPSED

**The concepts:** an in-context notice that must survive a split view's minimum-size pass,
and a run of user-defined labels that must not consume its row.

**Was:** every banner repeated its own padding, rounded background and multiline layout.
The F5 maturity notice was measured at effectively zero width and expanded to 4,627 points;
the split view centred that height, leaving both panes apparently empty and unable to scroll
back. User labels also had no width or count policy: a long label, or enough ordinary labels,
could crowd out the connection name, state and action in a sidebar or the menu bar.

**Now:** `BannerSurface` is the common chrome and, crucially, owns the 320-point readable
minimum width seen by the split-view measurement. `EditorPaneMetrics` provides the matching
520-point floor at Manage VPNs' one detail host, so an editor cannot bypass the banner's
contract through its own `TabView` or form. It is used by informational, warning, recovery and
editor notices; richer diagnostic and setup cards remain cards because their interaction structure
is intentionally different. `LabelPill` owns one shortened visual label while retaining its full
accessibility name; `LabelPills` owns a row's bounded two-label prefix and its explicit `+N`
remainder. The three compact connection surfaces use it.

**Verdict: COLLAPSE — done.** `BannerAndLabelLayoutTests` measures zero-width banner layout,
long labels and many-label runs; `EditorPaneHeightTests` measures the actual F5 editor as well as
the banner. A future visual copy cannot quietly bring this failure class back.

---

## 14. Engine dependency pins — coordinated versions ✅ KEEP SEPARATE

The native engine scripts each statically bundle OpenSSL, so their `OPENSSL_PIN`
values must agree. The proxy module is folded into the Tailscale archive, so its
gVisor requirement and `build-proxy-engine.sh` must match the version selected by
the Tailscale module. Sparkle's package version in `project.yml` and the release
workflow's appcast tools must agree too; both now use 2.10.0.

**Compatibility boundary (2026-09-30):** Tailscale 1.102.5 requires wireguard-go
`v0.0.0-20260715223240-2e01ba5b00f0`. The newer Tailscale-branch revision
`45a234e5a70d` changes `tun.Device.Read` and `tun.GSOSplit`, and Tailscale's own
`net/tstun` no longer compiles against it. Keep the release's WireGuard pin until
a stable Tailscale release adopts that API; update them together. The comment
beside the requirement in `Vendor/tailscale-engine/src/go.mod` points here, and
the existing real WireGuard handshake tests run before its archive is built.

gVisor updates must resolve **`@go`**, not `@latest`: upstream's default branch
requires Bazel and lacks the source layout needed by standard Go tooling. The
2026-09-30 Go-branch revision is pinned in both modules and the proxy build script.

**Verdict: KEEP SEPARATE — each engine builds independently, with coordinated
pins.** Verify all engine archives whenever a shared dependency changes.

**Dependency build verification:** the official Metal component is installed and
the signed app/extension build and full Swift suite include the actual shaders.
Go engine builds, race suites and encrypted peer fixtures pass with these pins.
Use macOS 26-compatible native libraries as described in `README.md` to avoid
newer-host Homebrew deployment-target warnings. Platform checks remain in §18.

## 15. Secret persistence across engines — KEEP SEPARATE AT THE PROCESS BOUNDARY

App-owned credentials, PEMs, WireGuard keys/PSKs and Tailscale node identity belong in
user Keychain accounts. The extension receives transient start options. Tailscale's
`keychain_state.go` emits bounded, revisioned snapshots through private session IPC;
`VPNController+TailscaleState` saves and reads back the user-Keychain record before
acknowledging it. Legacy state is deleted only after that acknowledgement. Shutdown
releases blocked writes. The app must stay running for subsequent state changes.

An editing policy lock no longer skips verified OpenVPN secret migration. A failed
Keychain write or OS configuration save retains the only copy and surfaces a migration
notice. Native proxy passwords have no OS persistent-reference property: new native
proxy authentication is refused before saving; legacy passwords are moved to verified
user-Keychain accounts before redacting the OS protocol. An OS refusal remains visible.

`ConfigSecretTransfer.accounts` deliberately remains a closed role vocabulary alongside
engine account construction. Import cannot choose an arbitrary account. Secret and
placeholder exports include Tailscale identity and migrated native proxy credentials;
external vault contents, agent keys and provider-wide unlocks remain external.

## 16. SSH signing in the app and system extension — KEEP SEPARATE WITH SHARED SIGNING

App SSH supports user `.ssh` files, selected agents (including 1Password) and imported
Keychain PEMs. Reverse/jump subprocess modes retain their file/agent boundary and refuse
Keychain PEM rather than writing a temporary key. Apple Passwords supplies passwords;
it does not expose arbitrary PEM storage through its picker.

SSH Network Tunnel authenticates its own root-owned SSH session through
`SSHAgentSigningBroker`: a provider-local socketpair and private NE session messages
carry only key-list and signing frames. The user app opens the selected user agent;
no root filesystem relay, agent mutation, private-key extraction or signature reuse
between SSH sessions occurs. Host-key verification precedes authentication. Cancellation
closes the broker, bounded frames use exact request IDs, and the app must stay running
for reconnect signing. A real ssh-agent/sshd test authenticates through this broker and
checks that libssh releases its borrowed agent descriptor. Interactive 1Password approval
and installed-extension signing still need platform verification.

## 17. Mediator apply loops and live editor saves — COLLAPSED

Route/DNS/proxy use `MediatorApplyLoop` to serialize and coalesce the latest plan.
Completed partial writes update applied caches; failures cannot masquerade as success.
Forced drift writes bypass idempotency. Slow/failing host tests exercise suspensions,
failed demotion, supersession and restoration after partial proxy failure.

Proxy, Tailscale and SSH Network editors use `LatestSettingsSave` with captured drafts;
a blur or close during an earlier save queues the latest valid state. The shared list
field keeps its editing text separately from normalized stored values. Tests cover held
saves and external updates; actual focus/blur list entry remains a UI verification item.

Native personal-VPN mutations use a FIFO `AsyncOperationGate`, deliberately separate
from coalesced plan application: remove must wait for pending credential/settings writes.
A lifecycle revision cancels stale connects, including disconnect during an OS save.
Successful saves record installed identity before any cancellation can skip starting.
Native removal refuses an unverified legacy or externally changed OS identity rather
than deleting another configuration or its credentials.

WireGuard and virtual-composition starts reserve their profile IDs before any OS
write suspends. Cancelling a member invalidates the whole pending composition, but
retains the reservation until its write drains. A shared FIFO gate makes removal wait
for these writes. Independent starts cannot compete for an active or reserved member.

## 18. Routing preview and execution plus virtual interface ownership — COLLAPSED WITH EXPLICIT COMPATIBILITY

The filtered `RoutePlan` now drives inspection and execution, including edited prefixes.
One `NetworkSettingsWriter` owns all OS writes, including the OpenVPN/OpenConnect bridge
paths. Confirmation precedes published ownership; timeout poisons the writer and ends
the provider. OpenVPN's adapter retains its four-byte family framing.
Telemetry begun before an acknowledged mutation is discarded; older confirmed settings
revisions cannot overwrite new ownership. CLI pause/resume/gateway replies report a
failed acknowledgement as failure.

The explicit **Connect Through One Virtual Interface** composition action currently
supports two to sixteen single-peer WireGuard members. `VirtualRoutingEngine` owns one
capture pump; Go instance handles and generations isolate ports and late callbacks.
The whole virtual route plan is one OS transaction followed by one versioned Go commit.
Stopped ports retain capture of private prefixes. Loss of default egress retains default
capture and drops traffic; explicit Direct releases it. Physical UDP sockets are bound
to a real underlay before bind and blackhole when no physical path exists.

**KEEP SEPARATE:** other engines retain independent provider sessions. They use scoped
Go APIs where applicable, but are not virtual routing ports yet. Distinct scoped DNS,
custom proxies/local exclusions, chained transports, per-app/fake-IP/L7/Tcl routing and
native VPN packet ports are refused or unavailable in virtual mode. The capability gate
and `NetworkArchitectureBoundaryTests` must be changed together when these boundaries
end. Do not infer provider-crash kill-switch guarantees from core packet tests: signed,
notarized capture, sleep/wake/crash and macOS 26/27 verification remain required.
Restarting a stopped virtual member requires reconnecting the composition; the ordinary
WireGuard start is guarded so it cannot create a competing independent interface.

## Adding to this file

Two occasions, and both are cheap:

1. **You found a duplication.** Add a section: the concept, the sites, whether they agree,
   the verdict. "NOT YET DECIDED" is a real verdict and always beats silence.
2. **A guard failed and collapsing is not the answer.** Add the new site to the guard's
   table AND to this file, with the reason it must differ. The table and this file are read
   together on purpose: neither is allowed to be the only record.

**Never** silence a guard by loosening its needle. Widening a pattern until it stops
matching is how the register becomes decorative.
