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

The shared row now places the maturity badge below the name/caption, in the same
text column. A fixed badge beside the name consumed the entire text width in a
persisted 144pt sidebar, hiding the name and overflowing the column. Manage VPNs
also enforces a 240pt minimum on both its list content and split-view column.
The live UI regression imports a long public-only profile name and checks the
row's bounds against the sidebar before removing only that fixture.

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

## 5. IPv6 brackets in endpoint strings

`NetworkEndpoint.authority` renders IPv6 hosts with brackets for the shared VPN
drivers, the SSH carrier and forwarding paths, WireGuard endpoint selection, and
the Bitwarden loopback client. It preserves brackets that are already present.
Endpoint Discovery parses optional ports and SSH import also parses usernames.
`DriftRegisterTests` guards the renderer and those format-specific parsers.

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

## 8. Socketpair framing at the Darwin tunnel boundary

**The concept:** how a packet is framed on an engine's tun file descriptor.

OpenVPN 3 sets `tun_prefix = true`. OpenConnect enables `TUN_HAS_AF_PREFIX` for
Darwin's native tun FD. Both use a four-byte address family in network byte order.
`VirtualDatagramPort` owns that socketpair for shared OpenVPN and for both OpenConnect
attachments. Standalone OpenVPN uses its own pump, which also observes its pause and
resume state. `DriftRegisterTests` guards both socketpair implementations.

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
workflow's appcast tools must agree too; both now use 2.10.1.

**Compatibility boundary (2026-10-28):** Tailscale 1.104.4 and its selected
WireGuard revision `417aef361226` use slab-based `tun.Device.Read` and
`conn.ReceiveFunc` APIs. The callback TUN and loopback handshake fixture reserve
`tun.ReadPacketSpacing` before and after the packet; bounds tests verify both.
Update Tailscale, WireGuard, and these adapters together.

gVisor updates resolve **`@go`**, not `@latest`: upstream's default branch
requires Bazel and lacks the source layout needed by standard Go tooling. The
2026-11-23 Go-branch revision (`83df8eae069e`) is pinned in both modules and the
proxy build script.

OpenSSL 4.1.0 is built once from its SHA-256-verified upstream source with a macOS
26 deployment target (`Tools/build-openssl.sh`). All three engines consume this
repository-local installation. The CI installer uses the same script, avoiding
Homebrew formula snapshots and host-only deployment targets. The native engine
cache keys include this script. Other native inputs remain at their current
upstream releases (OpenConnect 9.21, libssh 0.12.2, libfido2 1.17.0, libcbor 0.15.0,
Asio 1.38.2, fmt 12.2.1, xxHash 0.8.4, LZ4 1.11.1).

**Dependency refresh (2026-11-02):** all three native engines now share OpenSSL
4.1.0 (official source SHA-256 verified). OpenVPN core 3.12 advances to
`0abc8313b8fe5f63dbebc10d53094952957845d9`. Both Go netstacks share gVisor's
Go-compatible revision `v0.0.0-20261102110059-1cea747efe8d`; the standalone proxy
build guard agrees. Reachable Go dependencies and test dependencies were
updated with `go get -u -t ./...` and tidied in each module: CBOR 2.10.0,
AWS config/credentials/signin/SSM/SSO/SSOOIDC patch releases, and glob 1.1.0.
Tailscale's stable WireGuard fork remains `417aef361226`, matching its slab API.
Sparkle 2.10.1, Tailscale 1.104.4, 1Password SDK 0.4.1, Teleport's adapted source,
OpenConnect 9.21, libssh 0.12.2, the remaining native inputs, Go 1.27.3 and the
SHA-pinned GitHub Actions already match their current upstream releases.

**Verification (2026-11-02):** rebuilt OpenSSL, all three native xcframeworks,
the 1Password archive and the combined Tailscale/proxy archive. Native symbol
checks, Go vet/tests, proxy C-boundary tests and Tailscale/proxy race suites pass.
Sparkle resolves at 2.10.1. The signed Debug app, extension and test targets build.
The unit run reports **2,881 passes and one failure**:
`SSHSettingDescriptorTests.groupsAreCanonicalAndOrdered()` still requires every
`SettingGroup` to contain SSH options, but the pre-existing workspace DNS-tab
changes add `.dns`, for which SSH has no options. This test and the DNS taxonomy
were not changed by the dependency refresh. The live SSH integration suite passes
with the local sshd fixture and OpenSSL 4.1.0. Full results are retained in
`build/dependencies-20261102-tests.xcresult`; build and engine logs use the same
`build/dependencies-20261102-` prefix. Installed-provider/live-VPN acceptance
remains covered by the existing §18 register entry.

**Dependency refresh (2026-11-18):** Tailscale 1.104.7 uses its WireGuard fork
at `9e0ab45c16ca`. The Go toolchain moves to 1.27.4 and both netstacks pin
gVisor `v0.0.0-20261118061622-13a33f77533a`. All three Go module graphs
were upgraded and tidied, including their test dependencies. OpenVPN core
3.12 advances to `0c1ce172fe918b05463d71e682a0c2f2d8fe7899`, with fmt
12.2.1 and LZ4 1.11.1. OpenConnect shares the LZ4 pin. The libssh build
uses SHA-256-verified libcbor 0.15.0. The release workflow uses setup-go
7.1.0 and both packaging paths use dmgbuild 2.0.0. OpenSSL 4.1.0,
Sparkle 2.10.1 and 1Password SDK 0.4.1 were already current. The Teleport
pairing helper builds from the Tailscale module and uses its WireGuard pin.
The three Go modules passed their tests and the native engine build scripts
rebuilt their archives. The unsigned Debug app and packet tunnel built against
those archives. A disk image created with dmgbuild 2.0.0 and the repository's
Finder layout passed `hdiutil verify`.

**Dependency refresh (2026-11-23):** Both Go netstacks use gVisor's Go branch
at `83df8eae069e` and share the refreshed `x/exp` revision. The Tailscale
module also refreshes reachable indirect dependencies while retaining the
stable Tailscale/WireGuard pairing. OpenVPN core 3.12 uses
`cd2487bcde7c43130582344d9c512cb7842226f6`. OpenSSH portable 10.6p2
uses a verified source archive and retains the local listener's supervisor
identity check. SwiftNIO uses 2.105.1, and the SwiftNIO Extras 1.35.3
SOCKS message sources and notices match the previous vendored release.
Release CI uses Rust 1.100.0. RoutingLSP's offline vendor directory
matches its updated lockfile. OpenVPN, OpenSSH, the Go engines, and the
signed Debug app rebuilt successfully. Go and Rust tests passed, as did
the OpenSSH reverse-forwarding test against a loopback SSH server. The
signed macOS unit run passed 3,060 tests and skipped 23. Its one failure
was the existing password authentication picker in `NativeVPNView.swift`,
which `SettingAlignmentTests.everySettingRowsPickerIsRightAligned()` flags.

**Verdict: KEEP SEPARATE — each engine builds independently, with coordinated
pins.** Verify all engine archives whenever a shared dependency changes.

**Dependency build verification (2026-10-28):** signed Debug and clean Release
builds pass with the actual shaders and rebuilt native/Go archives. The Xcode MCP
unit run reports 3,096 passes, zero failures and 22 explicit skips. Go engine,
proxy C-boundary and race suites pass with these dependency pins. Release nested
code signatures verify with `codesign --verify --deep --strict`.

**UI verification (2026-10-28):** focused unlocked-session audits pass for main,
Manage VPNs, Routes, all three Settings panes, Network Tools, Report a Problem,
About, Help and Find a Setting. Full non-UI results and the per-workflow limits
are recorded in [UIWorkflowReview.md](UIWorkflowReview.md). The earlier locked
session is no longer the only evidence. Live provider/capture acceptance remains
tracked in §18.

**Unresolved runtime warnings:** instrumentation attributed negative width to
AppKit's `NSTabViewSegmentedControl` initialization (`-22 × 24`) through
`SwiftUI.AppKitTabView.updateNSView`. Width clamps and public tab styles did not
prevent it. Security main-thread and QoS notices still need caller attribution;
background probe code alone does not establish their origin. No production
swizzling or warning suppression was retained. Keep these open until a verified
fix or an upstream resolution removes the diagnostics.

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
saves and external updates. A disposable imported profile now exercises actual
comma-list typing and focus changes in the running app.

Manage VPNs uses separate native `ToolbarItem`s for reorder commands, with the same
button renderer as inline `ReorderButtons`. A custom HStack and Image-only controls
produced unnamed AppKit overflow items at narrow widths. Real button titles and
independent native items preserve remove/reorder/search names in that menu. The
actions now belong to the whole window's primary toolbar, rather than inheriting
sidebar placement. Native regular remove/reorder/search controls size their own
symbol and padding. Add has a circular 36pt target with its indicator hidden;
a hosted menu prevents AppKit's toolbar extraction from rebuilding its label
as an oval. It remains a native menu, using the same Add actions as before.
The UI list-entry regression checks actual control widths and handles overflow
without activating an unverified menu item.

The shared setting row's accessibility availability value now belongs to its
containing row. Applying an empty value to the control replaced the actual text
field value, hiding entered settings from VoiceOver and UI assertions. Child
fields retain their own value/validation without switching view identity while
typing. Testing notices start concise; expanded details remain an explicit,
remembered choice under the versioned presentation preference.

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

The offline destination-language prototype and the live virtual router share
`packetrouter.DestinationTable`. Source rule order is validated before lowering.
The editor asks the compiler for both token spans and test decisions. Live capture
and forwarding use the same ordered member claims after a port stops. See the
[routing language and staged acceptance tests](RoutingLanguage.md).

Per-app compositions have a separate OS routing method and a versioned provider
configuration. The GUI and the packet provider validate the same source bindings.
The shared Go router checks the process generation and selected WireGuard peer.
Per-app sessions do not elect a whole-Mac gateway, resolver or proxy. See
[identity and installed-system acceptance](RoutingEvidence.md#app-and-running-process-routing-in-simplevpn).

The filtered `RoutePlan` now drives inspection and execution, including edited prefixes.
One `NetworkSettingsWriter` owns all OS writes, including the OpenVPN/OpenConnect bridge
paths. Confirmation precedes published ownership; timeout poisons the writer and ends
the provider. OpenVPN's adapter retains its four-byte family framing.
Telemetry begun before an acknowledged mutation is discarded; older confirmed settings
revisions cannot overwrite new ownership. CLI pause/resume/gateway replies report a
failed acknowledgement as failure.

**Set Up a Routed Connection…** supports one to sixteen compatible packet members. Whole-Mac capture can combine WireGuard, paired Teleport, numeric SOCKS5 or HTTP(S) proxies, OpenVPN, Cisco AnyConnect, HTTPS GlobalProtect, TLS/PPP Fortinet and F5, HTTPS Juniper Network Connect, Pulse and Array, supported Tailscale/Headscale profiles, SSH Network Tunnel, SSH point-to-point and built-in IPsec. OpenVPN accepts built-in certificate and password sign-in, including verification codes available to the app. The shared SSL adapter uses a fresh authenticated session, including browser sign-in for protocols with built-in SSO support. App-scoped capture uses the same ports after verifying common resolver settings and the packet’s source identity. The signed provider validates both the saved member profile and its start options. Each independently authenticated child has a private slot and generation. Revoking one member stops its egress and rejects its stale replies.

The shared router applies the capture policy, chooses a member and translates the source address. The member policy runs on its own outgoing and returning packets. The reverse path requires the recorded member, generation and tuple before the shared inbound rules and reverse translation deliver the reply. In whole-Mac destination routing, a stopped private prefix stays captured. Explicit Direct releases default capture. Chained carriers and incompatible resolver policies require independent connections.

Private peers exercise the packet and channel boundaries. Installed system-extension behavior during sleep, network roaming and a provider crash still needs a separate acceptance run.
Restarting a stopped virtual member requires reconnecting the composition; the ordinary
WireGuard start is guarded so it cannot create a competing independent interface.

The provider keeps an unavailable member’s carrier exclusions until the session ends.
Its route claims stay active until an acknowledged plan withdraws them. A replacement
must still cover those claims. Gateway demotion treats a pair of IPv4 or IPv6 half-defaults
as a default. The settings writer publishes changes after macOS acknowledges each request.

Whole-Mac routed connections apply saved destination and native DNS filters to authenticated
member claims before packet capture. Shared DNS changes install resolver settings and the
corresponding host routes as one acknowledged plan. Private resolver scopes remain captured
when their member drops. A single shared interface can publish one resolver configuration,
so DNS assignments to different members require independent interfaces. macOS treats DNS
on its default tunnel as catch-all, so scoped-only DNS requires split capture.
Selected-app connections use source rules with member destination overrides and common DNS.
Per-profile system proxy rewrites and legacy destination diverts require independent connections.
OS-managed personal VPNs, external OpenConnect SOCKS sessions, and SSH listener/forwarding
modes have no packet member port. Point-to-point SSH uses the saved tunnel routes. Live
endpoint verification requires the actual configured VPN peers.

Installed-extension acceptance has a separate launch contract:
`Tools/test-installed-app.sh` explicitly sets Xcode's `UITargetAppPath`, and the UI
tests use the configured target. They compare the visible app build and the exact
enabled OS registration. Live provider IPC, packet capture, sleep, roaming, and
crash handling require separate checks on that same installed build.

Editor railroads also use `RouteGraphView`'s existing viewport, renderer and topology
watcher. `RoutingRailroadProjection` adapts public engine facts to the same filters
and arbiters; it does not implement another route resolver. Draft, confirmed and
observed lanes remain distinct. `RoutingRailroadTests` checks transformations,
read-only preview behavior, invalid/unknown state and layout bounds.

## 19. Teleport and plain WireGuard — ONE DEVICE IMPLEMENTATION

Teleport is a managed WireGuard configuration (`WireGuardConfig.usesTeleport`),
not a separate VPNKind or engine. `teleport/client.go` exchanges invites and
negotiates ICE/CONNECT plus authenticated STUN. Both ordinary sessions and virtual
ports call the same `createWGState` constructor, callback TUN and packet router.
Negotiated addresses replace the member’s static addresses before router NAT is
built; DNS comes from the session, with explicit routes through its owner.
The virtual router’s physical sockets and interface-change send gate stay in use.

The upstream protocol files are pinned and attributed in `teleport/README.md` and
its MIT LICENSE. Its WireGuard device, netstack and SOCKS proxy are deliberately
excluded: those would duplicate existing implementations. Its automatic echo-based
endpoint recovery is also excluded; the shipped manual states that endpoint loss
requires disconnect/reconnect. Future recovery must renegotiate through the shared
constructor and router transaction, never add another device implementation.

Pairing runs in the bundled `teleport-pair` helper using the same Go API code and
private stdin/stdout pipes. The reusable identity is verified in the user’s
`teleport.<profile>` Keychain account before success. It is supplied only through
private start options, redacted from engine logs, deleted with the profile and
included only in explicitly secret-bearing configuration exports.

**Verdict: KEEP SEPARATE control plane, SHARE the WireGuard engine.** Protocol
fixtures and Teleport configuration tests cover invite exchange, socket handoff,
secret exclusion and routing configuration. A user confirmed UniFi Teleport
working on a live setup on 2026-11-03.

## 20. Required names and editor save failures — SHARED PRESENTATION, ENGINE PERSISTENCE

All seven editor families render `ConfigurationNameField` from
`SettingValueRow.swift` and use its whitespace policy for the editor save gate.
The missing-name reason is visible and spoken beside the explicitly named input.
`AccessibleSettingsDisclosureStyle` is shared by the Advanced/certificate headers:
a real header Button owns activation while expanded fields keep their own roles.
The shared settings-row containers also have explicit names. Keep this shared
when adding an editor; a private name row would recreate inconsistent validation.

Custom Routing has one throwing persistence operation (`persistCustomRouting`)
and one reporting adapter (`commitCustomRouting`) for live-save call sites.
OpenVPN's Done action uses the throwing operation so a failed save cannot dismiss
the sheet. Proxy credential references are published only after Keychain accepts
the secret. The failure-injection cases live in `ConfigurationWorkflowReviewTests`.

**KEEP SEPARATE:** protocol configuration writes still belong to each engine's
manager/controller; they do not share a transaction. Each must propagate secret
write errors to its editor. Native/external-client local error text and the shared
controller failure presentation are separate because those stores have different
owners. Live-save failures do not provide rollback of earlier successful fields.

The 2026-10-28 review's remaining runtime warnings, unaudited sheets, installed-app
and live-server checks are explicit in [UIWorkflowReview.md](UIWorkflowReview.md).
Do not interpret a green window audit as coverage of every state of that window.

## 21. Help navigation and window fitting — KEEP SEPARATE WITH SHARED GEOMETRY

The bundled HTML owns its responsive contents navigation: sidebar above 900 CSS
pixels and a floating top panel below that. The floating panel always starts
collapsed to a grab handle, including at medium widths; it must not obscure the
article with an expanded contents list when Help opens.
Pointer proximity reveals the compact panel; a real button, Escape, focus retention
and a skip link provide keyboard/VoiceOver access. Following a topic or native
manual deep link closes floating contents before scrolling. Tables scroll locally
and long text wraps instead of widening the document.

The native window preserves a useful saved size but fits on opening/refocus and
display changes, outside SwiftUI's layout pass. It reuses
`MainWindowSizingPolicy.fittedFrame`; auxiliary window containment does not inherit
the main window's automatic size suggestions or its permanent manual-size opt-out.
These lifecycle policies intentionally remain separate. `ManualResponsiveLayoutTests`
loads the shipped HTML in WebKit at wide, narrow and short sizes and exercises
compact reveal/dismissal; shared geometry tests cover offset and smaller screens.

## 22. Initial installation and Sparkle updates — KEEP SEPARATE WITH SHARED INSTALLER CODE

Opening a downloaded copy and checking for an update inside the installed app are
different entry points. Sparkle retains in-app updates. Initial installation uses
`SimpleVPNLauncher` and the separate signed `SimpleVPNInstaller` app.
`InstallationModel`, `InstallationWorker` and `InstallationRunningApps` compile
into both targets; version/discovery/copy policies have one implementation.
`Tools/generate-installer-icon.py` derives the badged icon from the app's source;
`Tools/test-installer.sh` guards that relationship and the replacement decisions.

**Runtime acceptance remains a release gate:** signed/notarized DMG launch,
live Dock handoff, VPN quit cancellation, ejection and Trash behavior require
the acceptance matrix in [Installation.md](Installation.md). Builds and unit
tests alone do not establish these checks. Recovery bundles are kept if rollback
or Trash fails, rather than swept up with temporary helper sessions.

## DNS query matching and OS suffix scopes — KEEP SEPARATE WITH SHARED PRECEDENCE

`Shared/DNSQueryRouting.swift` is the sole exact/suffix/glob query matcher used by
`DNSQueryProxyProvider`, the advanced hostname tester and routing diagram. Query
rules inspect actual QNAMEs. Native `NEDNSSettings.matchDomains` remains a suffix
scope, never represented as exact or arbitrary glob enforcement. Both use
`DNSArbiter.ranked` for cross-profile precedence; native scopes are canonicalised
before collision arbitration. IP literal validation delegates to
`DNSResolverAddress`, rather than duplicating the resolver parser.

The optional DNS proxy owns per-query forwarding only; `NetworkSettingsWriter`
continues to own tunnel DNS settings. Normal configuration does not activate the
proxy. Configuration acknowledgement is distinct from live provider verification.
`DNSQueryRoutingTests`, `DNSWireMessageTests` and loopback UDP/TCP transport tests
cover these boundaries. No Tcl/PBR/fake-IP or packet egress router is introduced.

## Protocol events in the playground and on a connected VPN

The offline playground and the virtual packet router share the compiler and evaluator in `Vendor/proxy-engine/src/routelang`. Each adapter supplies its field and action permissions. The offline host stages changes to decoded event fixtures. The shared WireGuard router stages supported header edits on outbound inner packets. Other engines have different ownership boundaries. The catalog's adapter inventory records those boundaries and supplies the atlas reference. Keep the hosts separate so fixture-only actions cannot be enabled by loading the same source into a live composition. The live adapter rejection and rollback tests in `packetrouter/event_rich_test.go` guard this distinction.

The atlas also models TLS termination, FTP and FTPS expectations and independent proxy legs. Proxy Tunnel's shipped ClientHello backend selector forwards the original TLS stream after choosing a target. A live terminating endpoint and authenticated application helpers require their own implementations.

## Adding to this file

Two occasions, and both are cheap:

1. **You found a duplication.** Add a section: the concept, the sites, whether they agree,
   the verdict. "NOT YET DECIDED" is a real verdict and always beats silence.
2. **A guard failed and collapsing is not the answer.** Add the new site to the guard's
   table AND to this file, with the reason it must differ. The table and this file are read
   together on purpose: neither is allowed to be the only record.

**Never** silence a guard by loosening its needle. Widening a pattern until it stops
matching is how the register becomes decorative.

## Native packet rules and the offline routing reference

**Keep separate.** The signed checker and provider execute live events with `Vendor/routing-core`. The Go portable evaluator in `Vendor/proxy-engine/src/routelang` provides browser traces and the differential oracle. The compact reference parser and matcher serve portable tooling and parity tests. Both implementations share the packet host, rule ordering, limits, counters and permission schema. Production selects the runtime during policy activation. A runtime fault drops the event.

When adding an opcode, field type or standard-library function, run the native differential suites with the shipping build tag as well as the portable suites. The Swift composition editor requires a receipt from a native build. The packet tests cover compact candidate masks, staged edits, missing evidence, consumed budgets and terminal counters. The routing atlas identifies fixture-only events separately from provider capabilities.

The Rust editor tree preserves source ranges for partially written programs. The Go frontend accepts completed programs and supplies authoritative adapter/type diagnostics through the bundled checker. The syntax tree can stay available while a declaration is incomplete. Any new syntax requires an editor range case and a compiler acceptance case. Signed LLVM kernels, activation-time register or threaded programs, and the portable evaluator share the same observable decisions, precise failure sites and budgets. The release’s differential tests compare these paths.

## Proxy protocol ownership

The local dynamic SSH listener decodes SOCKS5 with Apple NIOSOCKS from swift-nio-extras 1.35.3 and NIOCore 2.105.1. The packet-tunnel Go service uses SagerNet sing 0.9.6 for its upstream SOCKS5 messages and datagram addresses. The service uses the Go HTTP library for CONNECT and crypto/tls with system trust for HTTPS proxies. Each library executes in its existing process and language runtime. The upstream UDP association binds the expected address and port to the guest flow. Web proxy modes carry TCP and can forward DNS over TCP.


### SSH tunnel-device ownership

OpenSSH portable 10.6p2 opens a local tunnel device before requesting the remote
`tun@openssh.com` channel. On Darwin its portable backend opens `/dev/tunN`.
OpenSSH closes inherited descriptors above stderr at startup, and its documented
multiplexing protocol supports stream and port forwarding. NetworkExtension
supplies packet batches through `NEPacketTunnelFlow`. The remote OpenSSH server
also checks `PermitTunnel`, key restrictions and availability of its own device.
See upstream `ssh.c`, `clientloop.c`, `openbsd-compat/port-net.c`, `serverloop.c`
and `PROTOCOL.mux`.

The saved legacy SSH tunnel-device mode remains readable. The manager and
readiness check refuse connection consistently. The separate SSH Network Tunnel
kind carries routed TCP via authenticated `direct-tcpip` channels.
`SSHSettingDescriptorTests` checks that the legacy mode cannot produce a command.
