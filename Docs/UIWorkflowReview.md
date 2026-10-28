# UI and configuration review — 2026-10-28

This review covers entry, navigation, validation, saving, failure recovery,
cancellation, accessibility semantics and window sizing across the macOS app.
Source review, hosted layout measurements and live accessibility tests provide
different evidence; none substitutes for signing in to each supported VPN.
The review used Xcode 27.1 on macOS 27.2, with the updated engine dependencies.

## Changes made

- The shared Xcode scheme now runs and profiles `SimpleVPN.app`. XcodeGen had
  selected the packet-tunnel system extension as the executable.
- All seven editor families use `ConfigurationNameField`. A blank name has a
  visible explanation and an accessibility value, with one whitespace policy.
  Its input has an explicit label; Form's adjacent visible label was not exposed
  as the field's label in XCTest. OpenVPN's optional-control switches also have
  explicit labels and live values.
- OpenVPN's Done action stays open after rename, configuration, credential,
  protected verification-code or Custom Routing persistence failures. Its
  credential writes respect the managed configuration lock.
- Custom Routing publishes a proxy credential reference only after Keychain
  accepts the secret. The shared throwing persistence operation also lets Done
  report failure instead of closing as though it saved.
- Tailscale, Proxy Tunnel, SSH Network Tunnel and native VPN secret writes
  propagate errors. The external-client editor shows secret errors locally and
  does not start a connection after a failed save. Cisco import explains a
  partially imported profile whose secret could not be stored.
- Remembered OpenVPN credentials no longer discard Keychain write errors. This
  also prevents removal of the protected copy when moving out of Touch ID if
  writing the ordinary Keychain copy fails.
- Discovery rejects overlapping scans, cancels its task on dismissal and ignores
  late results. This prevents a dismissed sheet from announcing stale results;
  it does not establish immediate cancellation of every underlying socket.
- Export completion is visible and announced. Export, import and recovery
  containers have names. Import cannot be dismissed while applying; Escape
  closes the preview/result when idle. A late apply cannot recreate a dismissed
  import sheet.
- Manual Help has loading, timeout, reload and local-browser fallback states.
  VPN Sign-In validates incoming web addresses, exposes loading and failure,
  supports retry and closes with Escape. Its model has regression tests for
  invalid links, retry and cancellation.
- Disclosure, credential, import-feedback and settings-reveal animations respect
  Reduce Motion, including the shared expansion path. `AccessibleSettingsDisclosureStyle`
  gives certificate/Advanced headers a real Button and keeps expanded controls
  independent. The shared settings-row containers and Servers table are named.
- Manage VPNs retries its initial selection when a newer profile load publishes.
  An empty or superseded load does not permanently consume initial selection;
  existing user selections and explicit settings destinations take precedence.

## Configuration coverage

| Surface | Paths reviewed | Evidence and remaining limits |
|---|---|---|
| OpenVPN: General | Name, logo, labels, optional controls, live save and Done | Shared name validation; whole editor minimum sizing; Manage accessibility. No real profile was edited for validation tests. |
| OpenVPN: Servers | Server list, import/add, discovery, selection and connection availability | Source review of server ownership, disabled reasons and discovery cancellation. No manual production scan or real VPN connection. Ordinary configured background probes may run. |
| OpenVPN: Sign-In | Manual/vault credentials, verification codes, security keys, Touch ID, field mapping | Save errors and motion fixed; existing credential/readiness regression suites. Live vault approval, biometric prompts and sign-in remain manual checks. |
| OpenVPN: Options | Five canonical groups, optional overrides, search, reset confirmation and reveal | Shared descriptors/reveal tests; Reduce Motion expansion fixed. No real options were reset. |
| OpenVPN: Certificates | CA, certificate, private key and TLS key import, wrong-slot correction, PKCS#12 password, details | Import cancellation/error source review; disclosure activation and motion fixed. Page audit passes with certificate details expanded; PKCS#12/import sheet audit still needed. |
| OpenVPN: Configuration | Raw configuration, validation, import/export and secret handling | Source and existing parser/secret-transfer tests. No real configuration was replaced or exported. |
| WireGuard | Settings, peers, addresses, keys, import/paste/export, Custom Routing | Hosted sizing and shared validation. Teleport changes are concurrent work by another agent; real pairing/interoperability is outside this review's verification. |
| Tailscale / Headscale | Registration key, control server, routes, DNS, exit-machine choices, live preferences, Custom Routing | Error propagation fixed; hosted sizing and existing model tests. No real registration or preference push. |
| Proxy Tunnel | Proxy scheme/address, authentication, traffic/DNS, validation, Custom Routing | Credential errors fixed; hosted sizing and existing model tests. Real proxy authentication untested. |
| SSH Network Tunnel | Server, sign-in mode, keys/certificates, host-key trust, algorithms, traffic/DNS, Custom Routing | Credential errors fixed; hosted sizing and existing model tests. Real host trust/signing requires live SSH fixtures. |
| Native IKEv2 / IPsec / L2TP | Protocol-specific sign-in and security, traffic, singleton OS configuration, L2TP profile export, Custom Routing | All three measured at minimum size; secret errors fixed. OS prompts, connection and installation of exported profiles remain live acceptance. |
| External clients: SSH and seven SSL VPN kinds | Executable/discovery, connection, sign-in/browser, proxy/jump host, traffic/security/advanced, import and Custom Routing | Every kind measured through the actual editor; save-before-connect error gate fixed. No external client was used to connect. |
| Custom Routing in every editor | Rules, DNS, proxy, authentication, availability, related-setting navigation, commit on leaving | Shared secret-write failure/success tests; named tab reachability. Editing route rules and live OS application require disposable profiles. |

## App workflows and configuration pages

| Workflow/page | Review and validation |
|---|---|
| Launch and main window | Scheme executable corrected; development-copy/installed-app boundary retained. Main accessibility audit passes. This development copy cannot validate the installed extension's connection UI. |
| Manage VPNs | Add/import, initial selection, sidebar grouping/reorder, editor presentation, export consent, removal confirmation, settings routing and empty state reviewed. Read-only window audit passes; final row/editor walkthrough recorded below. |
| Settings: General | App visibility, updater, engine approval/removal, public-address lookup, probing, virtualization privacy, export/import and recovery reviewed. The automated audit visits General, Sign-In Sources and Labels individually. |
| Settings: Sign-In Sources | Discovery consent, vendor enablement, detected versus configured paths, vault instances, add/rename/remove and unavailable-source recovery reviewed. No vault was unlocked or external approval requested. |
| Settings: Labels | Named label controls and catalog editing reviewed; audit visits this pane. No real label was renamed or removed. |
| Find a Setting and related links | Scope, empty results, route/tab/reveal, repeated destination, unavailable setting and Back paths reviewed. Accessibility audit and Escape check pass. |
| Import/export | File cancellation, preview/diff, apply, busy state, completion, recovery copy and secret consent reviewed. No real settings import/export performed. |
| Provider onboarding/server lists | Provider instructions, file chooser/drop alternative, explicit download consent, cancellation and validation reviewed in source. Fresh-install runtime path needs an isolated empty installation. |
| Help and About | Both window audits pass. Manual recovery fixed; About's information/copy/report entry points reviewed. No report sent. |
| VPN Sign-In | Invalid link, load failure, timeout, retry and close reviewed; model tests pass. Full identity-provider redirect completion remains live acceptance. Closing the web window does not prove cancellation of the originating external authentication process. |
| Routes | Window audit, named search, keyboard zoom and accessible diagram structure pass. Rotor behavior and audio presentation still need human VoiceOver use. |
| Network Tools | Window audit and disabled-control explanations pass. No manual diagnostic probe was launched against production servers; ordinary configured background probes may run. |
| Diagnostics and reports | Report a Problem window audit passes. Crash notice was inspected and dismissed locally after a test-fixture crash. Issue/UI report sheets and sending remain untested; nothing was submitted. |
| Menu bar and connected inspector | Credential disclosure motion fixed; status/readiness and shared actions reviewed in source. Live reconnect/pause/traffic log, speech timing and audio graphs require a connected disposable VPN. |
| Other sheets | Composition, field mapping, server-file/provider import, SSH host picker, PKCS#12, paste configuration, region picker, issue/UI reports and traffic log received source-level dismissal/error/keyboard review. They do not yet have individual runtime accessibility audits. |

## Verification and open findings

The final full non-UI suite passed **3,112 cases, zero failures, 22 explicit
live-SSH skips** after the initial-selection and accessibility fixes. The expanded layout suite passed
all six tests, including every editor family, all native protocols and every
external-client kind at the minimum width/height proposal. The new workflow
tests cover blank names, proxy secret failure/success, scheme executable selection
and VPN Sign-In state transitions.

The first expanded layout fixture omitted `ProfileEvaluator` from OpenVPN's
environment and crashed the test host. The fixture now provides the service; its
focused and full reruns passed. The local crash notice was dismissed without
submitting a report. UI results gathered while that notice obscured other windows
were rerun where applicable, not treated as successful coverage.

Read-only window accessibility audits passed for main, Manage VPNs, Routes,
Settings (all three panes), Network Tools, Report a Problem, About, Help and
Find a Setting. Mechanical VoiceOver checks passed for Routes search/zoom,
diagram structure, Settings labels, Network Tools, Custom Routing tab reachability
and Escape dismissal. Profile-dependent main-window checks skipped behind the development
copy's activation boundary. All seven OpenVPN page audits also pass. Their tests
assert that the requested tab is selected; Sign-In expands its verification-code
options and verifies that the template is still a named editable field, while
Certificates expands and audits its details. Neither these checks nor the automated contrast
exclusions establish WCAG compliance, speech timing or human usability.

**Still open:**

1. AppKit emits negative-width messages during native tab initialization.
   Instrumentation captured `NSTabViewSegmentedControl` at `(-22, 24)` from
   `NSTabView._layoutSegmentedControl → _addedTab → setTabViewItems →
   SwiftUI.AppKitTabView.updateNSView`. Outer width clamps and public tab styles
   did not prevent it. No production swizzling or warning suppression was kept.
2. UI runs also capture Security's main-thread runtime notice and QoS notices.
   The Security emission site was identified, but an application caller has not
   been established. Background probe call sites alone do not prove the origin.
3. PacketTunnel's App Intents metadata-extraction notice is the documented
   toolchain limitation in `AGENTS.md`; it is not filtered from logs.
4. A fresh Release dependency fetch encountered this Mac's global HTTPS-to-SSH
   GitHub rewrite and an SSH-agent refusal. Release built using the existing,
   resolved Sparkle cache. Global Git/SSH settings were not changed.
The monotonic-build-number script messages are intentional build notes: the
script must run to assign a consistent app/extension build number. They are not
compiler warnings.

Transient audit screenshot-creation errors occurred on Sign-In. After the
disclosure correction, both its collapsed and expanded focused audits passed.
The screen-capture error itself was not diagnosed as an app defect.

These warnings and live-acceptance gaps prevent a claim that every product
workflow and every warning has been resolved. Installed-extension, real VPN/SSO,
vault and accommodation testing remain required before release.

## Final validation receipt

- Xcode MCP Debug build-for-testing: passed (2026-10-28 11:30).
- Full non-UI suite: 3,112 passed, 0 failed, 22 live-SSH skips;
  `test-console-log-2026-10-28T11-33-29Z.txt`.
- OpenVPN Sign-In (expanded), Certificates (expanded), Options: 3 passed, 0
  failed, 0 skipped; `test-console-log-2026-10-28T11-30-24Z.txt`.
- OpenVPN General, Servers, Configuration, Custom Routing: 4 passed, 0 failed,
  0 skipped; `test-console-log-2026-10-28T11-31-47Z.txt`.
- Manage VPN rows/editor walkthrough: passed;
  `test-console-log-2026-10-28T11-15-36Z.txt`. Custom Routing tab reachability and
  Escape dismissal also passed in focused reruns.
- Signed Release build: passed; `build/ui-review-release-final.log`.
- Nested Release signatures: `codesign --verify --deep --strict` passed.
- Final generated project retains warnings-as-errors. No warning suppression or
  diagnostic runtime hooks were added to the product.

Full test-console logs/result bundles were returned by Xcode MCP. A local receipt
is retained under the gitignored `build/ui-review/` directory. Window and sheet
coverage limits above remain open even when all listed focused cases pass.


## Help width and window follow-up — 2026-10-28

Help now uses a sidebar above 900 CSS pixels and a floating contents panel below
that. Every floating width starts collapsed to a small grab handle. Cursor approach
or entering the panel reveals it; leaving retreats after 400 ms, while keyboard
focus or an explicit open keeps it usable. Escape, outside clicks and selecting a
topic close it. A skip link and an accessible disclosure button avoid a hover-only
interaction. Long text wraps and reference tables scroll locally when needed.

The Help window fits its restored frame inside the current screen's visible area
on opening/refocus and display changes, reusing the existing frame-fitting policy.
It permits small windows and preserves their size when it is already usable.

The focused WebKit reflow/interaction, anchor-parity and deep-link suites passed
26 cases with no failures (`test-console-log-2026-10-28T11-53-21Z.txt`). The Help
window accessibility audit also passed (`test-console-log-2026-10-28T11-53-55Z.txt`).
The live 720-point Help window was visually inspected with the collapsed handle
and article visible. Geometry tests cover small and offset display rectangles;
physical display removal/reconnection was not performed.
