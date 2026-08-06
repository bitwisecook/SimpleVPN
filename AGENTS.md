# SimpleVPN — Agent & Contributor Guide

Native **macOS 26** SwiftUI app (Swift 6, strict concurrency) that opens VPN tunnels — a Tunnelblick
replacement. It started as OpenVPN-only and now covers the 16 kinds in `Shared/VPNKind.swift` across
six engines (OpenVPN 3, OpenConnect SSL-VPNs, WireGuard, Tailscale/Headscale, SSH, native
IKEv2/IPsec/L2TP, plus the Proxy Tunnel and SSH Network Tunnel netstack kinds). First target config:
GR Lab (`tig-vpn.grlab.co.uk:1197 udp4`, TLS client + username/password + OTP, inline CA/tls-auth,
AES-128-GCM).

## Build system: XcodeGen — do NOT hand-edit the Xcode project

- **`project.yml` is the source of truth.** Regenerate the project with:
  ```sh
  xcodegen generate
  ```
- **Never hand-edit `SimpleVPN.xcodeproj/project.pbxproj`** — it is generated and will be overwritten.
- Build / verify:
  ```sh
  xcodebuild -project SimpleVPN.xcodeproj -scheme SimpleVPN -configuration Debug \
    -destination 'generic/platform=macOS' build
  ```
  (or the Xcode MCP `BuildProject`).

## Targets

| Target | Type | Notes |
|---|---|---|
| `SimpleVPN` | app | SwiftUI, `MainActor` default isolation. macOS only. |
| `PacketTunnel` | **system extension** | `NEPacketTunnelProvider` — ONE provider driving every in-process engine. `SWIFT_DEFAULT_ACTOR_ISOLATION: nonisolated` (no UI/main actor). Product name **must equal the bundle id** so the bundle is `com.bragi0.SimpleVPN.PacketTunnel.systemextension`. |
| `OPNativeHelper` | tool | `opnative-helper`, the 1Password Go SDK. The **only** binary carrying the library-validation relaxation (AMFI forbids it on a sysext-embedding app) — that is why it is a separate process at all. Rides in `Contents/MacOS`. |
| `OCAuthHelper` | tool | `ocauth-helper`, OpenConnect conversational SSO over stdin/stdout. **HARD POLICY: no entitlements, ever** — libopenconnect is statically linked and dlopens nothing. Rides in `Contents/MacOS`. |
| `SimpleVPNCLI` | tool | `simplevpn`. Ships in **`Contents/Helpers`, never `Contents/MacOS`** — "simplevpn" and "SimpleVPN" differ only by case, so a `MacOS/` copy silently overwrites the app binary. `PRODUCT_MODULE_NAME` must differ from the app's by more than case too. |
| `SimpleVPNTests` | unit tests | Swift Testing + XCTest, `@testable import SimpleVPN`. |
| `SimpleVPNUITests` | UI tests | `performAccessibilityAudit()` per window (see Accessibility below). |

Team `QVUFB5676H`, bundles `com.bragi0.SimpleVPN[.PacketTunnel]`, App Group `group.com.bragi0.SimpleVPN`,
keychain group `$(AppIdentifierPrefix)com.bragi0.SimpleVPN.shared`.

## Zero warnings is ENFORCED, not aspirational

`SWIFT_TREAT_WARNINGS_AS_ERRORS: YES` + `GCC_TREAT_WARNINGS_AS_ERRORS: YES` are set on **all seven of
our targets** in `project.yml` — per-target, deliberately not project-wide, so the Sparkle SPM
dependency is never compiled under `-Werror`. A new warning is a build failure; treat it as one.

- **Third-party headers we don't control** (openvpn3/asio/openssl via `client/ovpncli.hpp`,
  `openconnect.h`) are silenced **at the `#include`** with a narrow
  `#pragma clang diagnostic push` / `ignored "-Weverything"` / `pop` and a comment — see
  `PacketTunnel/Bridges/OpenVPN3Bridge.mm`, `OpenConnectBridge.mm`,
  `SimpleVPN/Import/OVPNProfileEvaluator.mm`, `OCAuthHelper/OCAuthShim.h`. That is the ONLY sanctioned
  suppression shape. Never relax a target's `-Werror`, and never add a project-wide `-Wno-`.
- **Deprecations kept on purpose** (a deprecated NE API we still need, deliberately-kept AES-128) get a
  narrow, commented suppression at the use site stating WHY and what would replace it.
- **One benign toolchain notice remains and cannot be silenced:** building `PacketTunnel` prints
  `appintentsmetadataprocessor … warning: Metadata extraction skipped. No AppIntents.framework
  dependency found.` Xcode adds `ExtractAppIntentsMetadata` to every bundle target with Swift sources,
  the phase cannot be turned off, and the xcspec's `LM_FILTER_WARNINGS` (`--quiet-warnings`) does *not*
  suppress this particular line (verified). It is correct — a packet-tunnel system extension has no App
  Intents surface; App Intents live in the app (`SimpleVPN/Intents/`). Do not chase it, and do not
  filter it out of a build log in a way that would also hide real warnings.
- When grepping a build log for warnings, **do not** filter `Vendor/` wholesale: `Vendor/*/src/*.go`
  and the build scripts' output are OUR sources.

## Signing — the load-bearing gotcha

The packet tunnel is a **System Extension** (for Developer ID / notarized-DMG sideload). That REQUIRES the
`packet-tunnel-provider-systemextension` entitlement, which **only Developer ID (`MAC_APP_DIRECT`)
provisioning profiles grant** — development profiles give plain `packet-tunnel-provider` and will fail with
*"provisioning profile doesn't match the entitlements file's value for … networkextension"*.

- **Manual signing**, identity `Developer ID Application`, profiles `SimpleVPN App DirectDist` /
  `SimpleVPN Tunnel DirectDist` (one per App ID), hardened runtime on.
- The `.entitlements` files must list **only** `packet-tunnel-provider-systemextension`. Do **not** let
  Xcode's *Signing & Capabilities → Network Extensions → Packet Tunnel* checkbox re-add the non-suffixed
  `packet-tunnel-provider` — it breaks the Developer ID profile match.
- Creating a **Developer ID Application certificate** must be done by the **account holder** in
  Xcode ▸ Settings ▸ Accounts ▸ Manage Certificates (the ASC API returns 403 for it). Provisioning
  profiles and bundle-id capabilities *can* be scripted via the ASC API.

## Running the system extension locally (live-test runbook)

`systemextensionsctl developer on` requires **SIP disabled** on this macOS — we don't do that. Instead
run the **notarized** build (SIP stays on, no developer mode):

```sh
./Tools/build-notarize-install.sh    # Release + Developer ID + --timestamp → notarize → staple → /Applications
```
Notes learned the hard way: the build needs `OTHER_CODE_SIGN_FLAGS=--timestamp` (notary rejects signatures
without a secure timestamp) and `CODE_SIGN_INJECT_BASE_ENTITLEMENTS=NO` (no `get-task-allow`); notarytool
is invoked with `--key/--key-id/--issuer` directly (keychain-profile lookup fails in background shells).

Then launch **/Applications/SimpleVPN.app** and:
1. **Activate Extension** → approve in **System Settings ▸ General ▸ Login Items & Extensions**.
2. **Import .ovpn…** (the GR Lab config) → **Install Profile** → approve the "add VPN configurations" prompt.
3. Enter username + password + OTP → **Connect**. GR Lab expects the password field as `{password}{otp}`
   (the UI concatenates them).

Logs: `log stream --predicate 'subsystem == "com.bragi0.SimpleVPN.PacketTunnel"' --level debug`
(or Console.app). The provider logs every openvpn3 event/log line and errors.

## Notarization

`notarytool` keychain profile **`SimpleVPN-Notary`** (backed by the ASC API key). Notarize the signed
`.app` (or the DMG) with `xcrun notarytool submit … --keychain-profile SimpleVPN-Notary` and staple.

## OpenVPN engine (`OpenVPNEngine.xcframework`)

macOS ships no OpenVPN engine (native VPN = IKEv2/IPsec/L2TP only), so we vendor the **OpenVPN 3 client
core** (pinned, currently core 3.12) with **OpenSSL 3** + lz4 statically linked, `USE_TUN_BUILDER` on,
external-PKI dropped (no client-cert/smartcard use). **arm64 only** for now (Apple Silicon; add x86_64
slices at distribution time if needed).

- Rebuild: `./Tools/build-openvpn3-xcframework.sh` (needs Homebrew: asio fmt lz4 xxhash openssl@3).
- Outputs (gitignored): `Vendor/OpenVPNEngine.xcframework` (link) + `Vendor/openvpn3-include/` (bridge
  headers: openvpn3 + asio + openssl). **Run the script after a fresh clone before building in Xcode.**
- The `PacketTunnel` target links the xcframework and sets `CLANG_CXX_LANGUAGE_STANDARD=c++20`,
  `HEADER_SEARCH_PATHS=Vendor/openvpn3-include`, and the openvpn3 defines. A thin **Objective-C++ bridge**
  (`OpenVPN3Bridge.mm`: subclass `ClientAPI::OpenVPNClient`, map `TunBuilderBase` →
  `NEPacketTunnelNetworkSettings`) drives it.

### Packet pump — the 4-byte PF header (load-bearing!)

openvpn3 on macOS sets `tun_prefix = true` (`cliopt.hpp`), so every packet it reads/writes on the
`tun_builder_establish()` fd is prefixed with a **4-byte protocol-family header** (`htonl(AF_INET/AF_INET6)`,
per `openvpn/tun/tunio.hpp`). `NEPacketTunnelFlow` deals in *raw* IP packets (protocol passed separately),
so the socketpair pump in `OpenVPN3Bridge.mm` **must prepend that header** when writing app→engine and
**strip it** when reading engine→app. Without it the tunnel connects but silently carries zero traffic.

## Tailscale / Headscale engine (`Vendor/tailscale-engine`)

The **open-source tailscale.com client stack** (BSD-3-Clause, pinned in `src/go.mod`) compiled as a Go
**c-archive** and linked straight into `PacketTunnel` — the second Go-as-c-archive in the tree after the
1Password SDK, and the same shape (pinned `go.mod`/`go.sum`, hand-written stable header, build script
with a symbol cross-check).

- Rebuild: `./Tools/build-tailscale-engine.sh` (needs the Go toolchain; runs `gofmt -l`, `go vet`,
  `go test` before producing the archive). Outputs the gitignored `Vendor/tailscale-engine/libtsengine.a`;
  `src/` + `include/` are tracked. **Run it after a fresh clone before building in Xcode.**
- **Not tsnet.** tsnet is a dial-only netstack; a real TUN VPN needs the packet path, so
  `src/main.go` composes what tailscaled composes (`tsd.System` + `wgengine.NewUserspaceEngine` +
  `ipnlocal.LocalBackend`) with two substitutions: a custom `tun.Device` whose Read/Write cross the C
  boundary, and `router.CallbackRouter` (Tailscale's own shim for "Mac, iOS, Android") standing in for
  both the OS router and the DNS configurator, so the extension never mutates the host network stack
  behind NetworkExtension's back.
- **One `VPNKind`.** Headscale is `.tailscale` with a custom `controlURL` — never a second kind.
- **No PF header on this boundary** (contrast the openvpn3 pump above): the Go TUN deals in raw IP
  packets both ways. `TailscaleEngine.deliver` picks the protocol number from the packet's own IP
  version nibble; nothing is prepended or stripped.
- **Codesigning:** the archive is statically linked, dlopens nothing, and therefore needs **no**
  hardened-runtime relaxation — unlike the 1Password SDK, which is why that one lives in the separate
  `opnative-helper` binary. No entitlement changed for this engine, and none may be added to the app.
- **Node state** lives at `/Library/Application Support/SimpleVPN/tailscale/<profile>` (root, 0700) so
  the node key survives relaunches. The app cannot delete it (root-owned); `remove(id:)` asks the
  extension to shred it via the `tsforget` IPC message, which only works while a session exists.
- Auth keys ride `startTunnel(options:)` in memory like every other credential; they are never in
  `providerConfiguration`, never logged (`TailscaleStartConfig.redactedJSONString()` is the only
  loggable form), and never echoed back in `TSStatus`.

### Creds path (M3)

`auth-user-pass` creds are provided programmatically via `ProvideCreds`; GR Lab's OTP is the password field
as `{password}{otp}` (no `static-challenge`). No client cert → `ENABLE_EXTERNAL_PKI` is deliberately off.

## Architecture direction
- Raw `.ovpn` is the source of truth (handed to the engine so all directives are honored); the SwiftUI form
  is a structured view over it. Credentials + OTP (`{password}{otp}`) injected at connect time, never stored
  in the profile.
- **Distribution:** system extension now (DMG sideload). A thin **app-extension** variant is added later for
  TestFlight/Mac App Store (which can't ship system extensions), sharing logic via a `TunnelCore` framework.

## Settings/overrides architecture (M7 rework)

- **`Shared/OpenVPNOverrides.swift`** — per-VPN engine overrides. Invariant: every field Optional,
  `nil` = "engine default, never touched", never serialized; lenient decoding tolerates app↔extension
  version skew. Persisted as one JSON blob at `providerConfiguration["overrides"]` (omitted when empty);
  `providerConfiguration["vpnType"]` carries `VPNKind` (absent ⇒ openvpn). Secrets (proxy/private-key
  passwords) go through `KeychainCredentialStore` (per-profile `secrets` service → read-once session
  payload), NEVER providerConfiguration. Bridge side: `OVPNClientSettings` (apply-only-non-nil onto
  `ClientAPI::Config` in `OpenVPN3Bridge.mm`).
- **App-target layout** (one module, concern-per-directory — reorganized from the old `Core/` junk
  drawer; a file's directory states its concern, and everything outside `App/`, `UI/`, and
  `Diagnostics/` stays UI-free — no SwiftUI/AppKit imports):
  - `SimpleVPN/App/` — entry point, lifecycle, system-extension activation.
  - `SimpleVPN/UI/` — every view, grouped: `Connection/ Editors/ Routes/ Tools/ Map/ Credentials/
    MenuBar/ Settings/ Components/`.
  - `SimpleVPN/ControlPlane/` — `VPNController`, engine managers (native/subprocess/SSH), compositions,
    the descriptor registry (`OpenVPNSettingDescriptors` — stable ids like `openvpn.compression` drive
    the Options form, manual anchors, a11y labels, and CLI/MDM addressing), `EngineSettings` — plus the
    **control surface**: `ControlSurface.swift` (commands/queries/events as pure data; the wire format
    is a public contract pinned by ControlSurfaceTests), `ControlPlaneDispatcher` (THE single mutation
    entry: guard chain [MDM now, Tcl `CTL_*` later] → readiness → execute → one event stream) and
    `ControlServer` (unix-socket JSON-lines host for the CLI). CONSISTENCY IS STRUCTURAL: the
    dispatcher installs its guard chain into `VPNController.controlGuard`, and the lifecycle entries
    (connect/disconnect/pause/resume/setDefaultGateway) consult it — UI buttons, the `simplevpn` CLI,
    App Intents and future interfaces are gated identically, with no bypass to forget.
  - `SimpleVPN/Credentials/` — provider seam (manual/1Password/Apple Passwords), TOTP, auth config,
    SSO browser launching.
  - `SimpleVPN/Mediators/` — the route/DNS/proxy system-state mediators (`Docs/StateMediators.md`) +
    tier-2 Custom Routing.
  - `SimpleVPN/Monitoring/` — reachability/link/public-IP monitors, route-table readers, network
    memory/topology, traffic history; `Probes/` holds the whole probe stack (ladder, TLS/IKE/SSH/WG,
    MTU).
  - `SimpleVPN/Diagnostics/` — logging/highlighting, doctor, diagnostic bundles + capture UI, crash
    handling, `UserFacingError`.
  - `SimpleVPN/Geo/` — GeoIP, regions, endpoints/discovery/ranking, world-map model.
  - `SimpleVPN/Import/` — config importers (ovpn/cisco/ssh/cert) + detector, i.e. ONE VPN's
    file at a time.
  - `SimpleVPN/Portability/` — the WHOLE configuration as one file: every VPN and every app
    setting, exported and imported as JSON or YAML (`Docs/SecretsAndSync.md` §5 step 1). One
    model (`ConfigValue`) with two encoders, keys that are stable setting ids, secret-free by
    default and test-proven so, and an import that validates and shows a diff before applying.
    Distinct from `Import/` on purpose: that is a document action on one VPN, this is a
    settings operation on the Mac.
  - `SimpleVPN/MDM/` — `ManagedPolicy` (forced defaults) + `Policy` (the seam every enable/disable
    routes through).
  - `SimpleVPN/Intents/` — App Intents / Shortcuts (`VPNIntents.swift`), thin adapters over the
    dispatcher. **Built.**
  - top-level `CLI/` — the `simplevpn` tool (target `SimpleVPNCLI`), a thin control-socket client.
    **Built**; it compiles `ControlSurface.swift` directly rather than importing a framework.
  - `SimpleVPN/PBR/` — the tier-3 policy-routing engine. Still a **charter README only** (design done,
    engine not built). Read the README before adding code there. The `TunnelCore`-style framework
    boundary is likewise still unextracted.
- **Naming rule:** protocol-specific code carries the protocol's name (`OpenVPN*`/`OVPN*`); shared
  infrastructure stays protocol-neutral. New VPN kinds (WireGuard, IPsec, …) switch on `VPNKind` at
  four seams: NE protocol object, editor form, importer, connect flow.
- **Manual:** `SimpleVPN/Resources/Manual/manual.html`, WKWebView window id "manual", anchors generated
  from descriptor ids — keep them in sync. **ALL documentation is EMBEDDED in the app** (binding):
  every engine/feature manual ships inside the bundle and setting rows deep-link to bundled anchors —
  never a web URL. A VPN app's documentation must work exactly when the network doesn't.
- **GeoIP:** country-level DB-IP mmdb under `Vendor/geoip/` (gitignored); `Tools/fetch-geoip.sh`
  refreshes it when >1 week old (hooked into `build-notarize-install.sh`, soft-fails offline).
  Map land geometry: `Tools/convert-naturalearth.py` → `SimpleVPN/Resources/Map/land-110m.bin`.
- **Failure UX:** extension classifies openvpn3 events into `TunnelIncident`s (App Group); the app runs
  failure-time diagnostics (DNS/reach/TLS/captive-portal, baseline comparison) — active probes ONLY on
  failure; live link health is judged passively from byte counters.

## Config surfaces — group taxonomy (binding; naming lives in ONTOLOGY.md)

ONE canonical group taxonomy across every config surface, so a user who learns one editor
knows them all. Groups, in this order, in every editor (a kind that has nothing for a group
OMITS it — never an empty section):

1. **Connection** — name, kind/preset, server address, port, protocol, how you reach the
   server (jump host, upstream/connection proxy), connection lifecycle (timeouts,
   stay-connected, on-demand).
2. **Sign-In** — credentials, keys/certificates used to identify YOU, credential managers,
   verification-code (OTP) config, sign-in browser, remember-password.
3. **Traffic** — full vs split tunnel ("Send All Traffic"), routes/allowed IPs, exit node,
   forwards, SOCKS, DNS, local-network access, user-facing MTU.
4. **Security** — verifying the SERVER and the channel: host-key/certificate checking,
   pinned certs, CA files, TLS versions, ciphers, key exchange, PFS, strictness.
5. **Advanced** — keep-alives, engine internals, spoofing, escape hatches, rarely-touched.

**Custom Routing stays its own tab everywhere it exists** — enforced, not aspirational.
It was a tab in EditVPNView and appended `Section`s in the others, which is the same
surface wearing two shapes. **All seven** hosts now put the canonical groups in one
`TabView` tab ("Settings") and `CustomRoutingTabView` in a second ("Custom Routing") —
EditVPNView, WireGuardView, NativeVPNView, SubprocessTunnelView, TailscaleView,
ProxyTunnelView, SSHNetworkTunnelView. The count is load-bearing: adding an editor means
adding it to the MDM-lock test that asserts every host disables under lock. The host still
owns the draft and commits from Save (see `CustomRoutingTabView.swift`'s header — tab
switches fire its `onDisappear` commit, which is idempotent). Live STATUS blocks
("This Network", "Right Now") are not config groups: they go AFTER the canonical groups,
never between them.

The mechanism per surface: the OpenVPN Options form derives its sections from
`SettingGroup` in `OpenVPNSettingDescriptors.swift` (regroup by editing a descriptor's
`group` — the form, SettingsSearch and manual all follow); the other editors use
`Section("<Group>")` headers in canonical order. EditVPNView's tabs follow the same order
(General · Servers=Connection · Sign-In · Options · Certificates · Configuration · Custom
Routing). The app-wide Settings window groups by user goal: General · Menu Bar & Icons ·
Updates · Privacy · Advanced. The manual's nav group headings
(`Resources/Manual/manual.html`) mirror the five group names — keep them in sync when
regrouping.

**One "Advanced" idiom:** `UI/Components/CollapsibleSettingsSection.swift`, group-generic
and shared. Every editor gets the whole-row hit target, the "n changed" badge and the
search-reveal hook from it. Never hand-roll a `Section { DisclosureGroup }` again.

**The MTU split (decided; do not re-litigate).** A user-facing MTU is **Traffic** — it is
the number someone is told to lower when transfers stall (`wg.mtu`, `px.mtu`, `oc.mtu`).
An MTU that describes the network path *underneath* the tunnel is **Advanced**
(`oc.base-mtu`): different subject, different range (jumbo frames allowed), and nobody
reaches for it to fix a stalling download. All of them render through the ONE shared
control, `UI/Components/MTUField.swift` (type it *and* nudge it).

**"Changed" is computed, never re-derived.** `EngineSettingSpec` carries the value the
setting rests at (`default:`), and `isChanged(_:)` / `EngineSettingRow(spec:value:)` /
`EngineSettingLabel(spec:value:)` answer from it. Hand-writing `changed: !draft.x` at the
call site is how one setting ends up bold when it is at its default and plain when it
isn't — several rows had it inverted. New specs declare a default;
`ManualAnchorParityTests` holds every catalog to it.

**One text-row idiom:** `LabeledContent { TextField … } label: { EngineSettingLabel … }`.
Not a full-width `.roundedBorder` field whose placeholder doubles as its name.

**A Toggle's label is its spec's name** — `EngineSettingLabel(spec:)`, never a second
hand-written string. A row that renders the spec name while its Toggle says something else
gives one setting two names: search finds one, the screen shows the other.

### Naming glossary — MOVED to ONTOLOGY.md

The one-term-per-concept table, the vendor mappings it translates from, and the rules for
writing help text now live in **`ONTOLOGY.md`** at the repo root. It is the same authority,
in one place, and it covers what this table could not: what every VPN concentrator and
password app calls the same thing, so a new kind or source is named by looking it up rather
than by guessing.

**Read `ONTOLOGY.md` before naming anything a user will read** — a label, a summary, an AX
string, a manual heading, an error sentence.


### Adding a new engine's options (e.g. the libssh SSH engine)

1. Declare an `EngineSettingCatalog` (`EngineSettings.swift`) — one spec per option with a
   stable id in a per-engine namespace bound 1:1 to a `SettingSurface` (the shipped ones are
   `ssh.keepalive`, `sshnet.mtu`, `oc.*`, `wg.*`, `px.*`, `native.*`, `openvpn.*`). Namespaces are
   GLOBAL and cannot be reused across engines; register the new one in `SettingSurface` and in
   `ManualAnchorParityTests.catalogs` or that test fails. Give it a display name from the glossary
   below and a one-sentence plain-English summary. Render every row through
   `EngineSettingRow`/`EngineSettingLabel` (bold-when-changed, summary, manual link, a11y
   built in; wrap bare TextFields in `LabeledContent` so the example prompt never becomes
   the VoiceOver name).
2. Lay the form out as `Section`s in the canonical order above; omit empty groups; Custom
   Routing stays a tab.
3. Add one manual section per spec id in `Resources/Manual/manual.html` (anchor = id with
   dots→dashes) under a nav heading named for the engine, and a `Default:` line per
   setting. **`SimpleVPNTests/ControlPlane/ManualAnchorParityTests.swift` enforces this in
   BOTH directions**: a spec with no anchor is a broken help button, an anchor with no spec
   is dead documentation. Register the new catalog in that test's `catalogs` table (and any
   prose-only chapter in `proseAnchors`) — that registration is what makes the reverse
   check total.
4. Disabled Save/Connect buttons must say why (`.help` + `.accessibilityValue`);
   validation errors ride the field's `accessibilityValue` (see Docs/Accessibility.md).
5. **Every user-facing control gets a spec** — including the ones that look like plumbing:
   secrets (`wg.private-key`, `native.password`), master toggles that gate other rows
   (`openvpn.proxy-enabled`), and the value the whole VPN depends on. An unspec'd control
   is invisible to SettingsSearch, unaddressable by the CLI and MDM, and has no manual
   anchor behind its help button. Keychain-backed and UI-state controls use
   `SettingDescriptor`'s closure initializer rather than a keypath.
6. **Primary action, one idiom:** `.buttonStyle(.glassProminent)` plus the `savedTick`
   Save→Saved affordance. A Save that changes nothing on screen reads as one that
   didn't happen.

## Accessibility — a first-class requirement, not a pass

The bar is WORLD CLASS: someone using VoiceOver (or switch control, or keyboard
only) must be able to use the app normally — connect, configure, and UNDERSTAND
ITS STATE — as quickly as a sighted mouse user. Rules, all binding:

- **Every control**: `accessibilityLabel` (what it is), `accessibilityValue`
  (its current state, live), `accessibilityHint` only when the outcome isn't
  obvious from the label. Never leak internal jargon ("sysext", "IPC") into any
  of them — same plain language as the visible UI.
- **State changes are ANNOUNCED, not discovered**: connection status flips
  (connected / disconnected / needs sign-in / doctor findings) post VoiceOver
  announcements (`AccessibilityNotification.Announcement`) — a blind user must
  hear the connect succeed without touching anything. Debounce so reconnect
  churn doesn't spam.
- **Custom-drawn surfaces are navigable structures, not labeled pictures**:
  Canvas/graph views expose `accessibilityChildren`/rotors with one element per
  meaningful node/edge, each with label+value+custom actions matching what a
  click can do. Swift Charts get `AXChartDescriptor` (audio graphs).
- **Grouping and order**: `.accessibilityElement(children: .combine)` on rows
  so a row reads as one sentence, not five fragments; focus order follows the
  visual reading order; sheets/popovers return focus to their opener.
- **Full keyboard operability**: everything clickable is reachable and
  activatable by keyboard (`focusable`, key equivalents, ESC dismisses).
- **Visual accommodations**: Reduce Motion everywhere (house rule already);
  Differentiate Without Color — the status-dot language ALWAYS pairs color
  with a shape/symbol difference; respect Increase Contrast; no fixed tiny
  fonts on informational text.
- **Regression gate, in two halves**: SimpleVPNUITests runs
  `performAccessibilityAudit()` per window ("is anything unnamed or
  unreachable?"), and `VoiceOverWalkthroughTests` asserts, step by step, that
  what VoiceOver would SAY matches what `Docs/Accessibility.md` promises — it
  never turns VoiceOver on, it reads the same accessibility tree. New failures
  in either are build-breaking, same as warnings. What is left for a human is
  the short checklist at the end of that doc: speech and announcement timing,
  audio graphs, the rotor, and anything needing a live connection.
