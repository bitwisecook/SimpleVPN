# Accessibility — Conventions, Coverage, Release Checklist

The bar (AGENTS.md, binding): someone using VoiceOver, Switch Control, or the keyboard alone
must be able to use the app normally — connect, configure, and **understand its state** — as
quickly as a sighted mouse user. This document is the working expansion of that requirement:
the patterns waves 1–3 established, a coverage table of what each surface exposes, the
keyboard-driving contract, and the human walkthrough script release QA runs with VoiceOver
actually on.

## The rules (all binding)

1. **Every control** carries `accessibilityLabel` (what it is) and `accessibilityValue`
   (its current state, kept live). `accessibilityHint` only where the outcome isn't obvious
   from the label. No internal jargon ("sysext", "IPC", "IP_BOUND_IF") anywhere a user can
   hear it — the same plain language as the visible UI.
2. **State changes are announced, not discovered.** All VoiceOver speech goes through
   `AccessibilityAnnouncer` (Diagnostics/AccessibilityAnnouncer.swift) — never post
   `AccessibilityNotification.Announcement` from a view. Two paths:
   - *Event-driven*: the announcer subscribes to `ControlPlaneDispatcher.subscribe()` — the
     same event stream the CLI and App Intents consume — and speaks status/gateway
     transitions in plain sentences ("Tig Lab connected", "Tig Lab needs a verification
     code"), debounced per profile over a 3 s quiet window, newest state wins.
   - *User-initiated*: `AccessibilityAnnouncer.sayNow(_:)` for a reveal or completion the
     user just asked for. Immediate — the click is the debounce. Wave-3 users: options-form
     search reveal ("Showing Compression, in Security"), endpoint scan completion, import
     success, embedded-editor "Saved", composition full-tunnel conflict, "Log copied".
3. **The status vocabulary is `DotState`** (App/ContentView.swift). Six states — off / busy /
   connected / paused / degraded / captive-portal — each with a color, an SF-symbol *shape*
   (`symbolName`, drawn when Differentiate Without Color is on), and
   `accessibilityDescription` in words ("connection problem", "sign-in page in the way").
   Every dot is `accessibilityHidden`; its state rides in the words of the row/pill that
   contains it. New surfaces reuse `DotState` — never invent a parallel status language.
4. **Rows read as sentences.** `.accessibilityElement(children: .combine)` on plain rows so
   VoiceOver reads "Tig Lab, OpenVPN, connected, Prod" — one element, not five fragments.
   Rows that CONTAIN interactive children (a disclosure, a delete button, an inline menu)
   use `.accessibilityElement(children: .contain)` + an explicit container
   `accessibilityLabel` sentence instead — a row-wide `.combine` silently swallows the
   buttons (the wave-3 bug class found in ProbeStepRow, CertificateCard,
   PendingSettingsNotice). Custom-Routing rule rows are the reference: the container
   sentence is "Add 10.0.0.0/8, overlaps a pushed route" while the verb picker, fields and
   delete button stay reachable inside.
5. **Validation errors are associated, not ambient.** The error is part of the field's own
   `accessibilityValue` ("…Problem: not a valid setup key") or the combined row sentence,
   *and* the visible error `Label` announces its role ("Problem: …" / "Error: …") — never
   only red/orange text somewhere else. **A disabled button says why**: the same reason
   string goes to `.help` (hover) and `.accessibilityValue` (VoiceOver) — see the Save
   buttons in every editor.
6. **Custom-drawn surfaces are navigable structures, not labeled pictures.** Canvas/graph
   views expose children and rotors (Routes window: "VPNs" and "Problems" rotors, one
   element per card/edge/drift line, custom actions matching clicks). Swift Charts get
   `AXChartDescriptor` audio graphs: connection throughput, interface traffic, and the
   Network Tools latency chart (lost pings are a discrete "Lost" series, not zero-latency
   lies).
7. **Full keyboard operability.** See "Keyboard driving" below. No onTapGesture-only,
   onHover-only, or drag-only affordances; macOS `Form`s render no affordance for
   `.onDelete`, so every deletable row also has a visible trash/remove button.
8. **Visual accommodations.**
   - *Reduce Motion*: house rule everywhere (dot rhythms become static opacities, eases
     become instant).
   - *Differentiate Without Color*: color is never the only carrier. The dots swap to
     per-state SF-symbol shapes; route-diagram edges get per-status dash rhythms
     (`EdgeStatus.accessibleDash`: paused = long strokes, down = dots, captive portal =
     knock-knock) on top of the always-on solid-vs-dashed distinction; log severity bands
     gain underlines (thick = error/fault, single = warning) via
     `LogHighlighter.nsAttributed(differentiateWithoutColor:)`; the traffic log's idle dot
     is hollow vs the active filled one (always, not just under the setting); the latency
     chart draws losses as ✕ marks.
   - *Increase Contrast* (`\.colorSchemeContrast == .increased`): secondary text on tinted
     glass promotes to primary (ProblemPill, the connecting pill); `LabelPill` picks
     black/white text by the user-chosen color's WCAG luminance and gains a rim. macOS has
     no Button Shapes setting (that env is iOS-only) — Increase Contrast is the
     accommodation we honor.
9. **The regression gate is real, and it is two gates.** SimpleVPNUITests runs
   `performAccessibilityAudit()` over the **main, Routes, Settings, and Manage VPNs**
   windows with one shared exclusion list (SimpleVPNUITests.swift documents each
   exclusion and why it is a framework artifact) — the audit answers "is anything
   unnamed or unreachable?". `VoiceOverWalkthroughTests` answers the different question
   "does what VoiceOver would SAY match what this document promises?", step by step
   (see "The walkthrough, automated" below). New failures in either are build-breaking,
   same as warnings.

## Vocabulary

What VoiceOver says IS the UI, so the naming glossary (AGENTS.md "Config surfaces — group
taxonomy & naming glossary") binds AX labels, values, hints, and announcements too. The
load-bearing terms:

- **verification code** — never "OTP"/"one-time passcode" in spoken strings (a
  parenthetical "(OTP)" gloss in visible copy is fine); Apple's own word, and what the
  connect form's nudges and announcements already use.
- **sign in / sign-in** — never "log in"/"login"/"authenticate" (System Settings pane
  names like "Login Items & Extensions" and the "login keychain" keep Apple's naming).
- **server / server address** — never "endpoint"/"gateway"/"host" for the machine a VPN
  connects to.
- **keepalive** (one word), **Send All Traffic** / **full tunnel**, **Allow local network
  access** — one phrasing per concept across every editor and the manual.
- Config-surface group names are exactly **Connection · Sign-In · Traffic · Security ·
  Advanced** — search-reveal announcements ("Showing Compression, in Security") speak the
  group title from `SettingGroup`, so renaming a group is a spoken-UI change.

## Keyboard driving

The contract, per surface kind:

- **Tab order** follows the visual columns: `.focusSection()` on the sidebar of the main
  window and Manage VPNs makes Tab move sidebar → detail instead of walking rows. Within
  the credential form the AppKit-backed `AutoFillField`s sit in the hosting view's natural
  key loop in source order (Username → Password → OTP → toggles → buttons).
- **Enter**: in any credential field, Enter submits (`AutoFillField.onSubmit` →
  `attemptConnect`, which routes through `connectTask` so an Enter-initiated connect is
  cancellable like a clicked one). Outside a field, the visibly prominent button owns
  Return via `.keyboardShortcut(.defaultAction)` — Connect in the detail header, Scan /
  Run / Open / Import / Save in their sheets. One default action per window, always the
  `.glassProminent` button.
- **ESC**: every sheet and popover closes on ESC — a `.cancelAction` shortcut on its
  Cancel/Done button (or `.onExitCommand` where Done already owns Return). ESC also
  cancels an in-flight connect (the ✕ beside the "Connecting…" pill carries
  `.cancelAction`).
- **Space** activates the focused control (native).
- **Initial focus** lands on the control the user most likely came for:
  - Main window: the first credential field that needs typing (`firstMissingField`), also
    re-focused by every "nudge" (dimmed play button, doctor findings).
  - Manage VPNs: the sidebar list (arrow keys pick a VPN at once).
  - Routes: the search field; the diagram is one Tab away.
  - Network Tools: the target-host field.
  - Sheets: the single required field (PKCS#12 password, composition name, discover
    address, WireGuard paste editor, 1Password browse search).
- **Pan/zoom surfaces** (route diagram, world map): the surface is `.focusable()`; arrows
  pan (`onMoveCommand`), unmodified `+`/`-` zoom, `0` fits (diagram). The Routes toolbar
  buttons also carry ⌘−/⌘=/⌘0. Nothing on these surfaces is reachable *only* by
  pinch/drag/scroll.
- **Context menus are never the only path.** Whatever a row's context menu offers also
  exists as a Tab-reachable control: Manage VPNs' − toolbar button removes the selected
  VPN/tunnel/native config, Export lives in the toolbar, compositions carry an inline
  ellipsis menu. (VoiceOver users additionally have VO-Shift-M on any row.)
- Interactive cards inside the scaled route diagram expose their click as a **named
  accessibility action** ("Trace what feeds this") — custom actions are how Switch Control
  and VoiceOver activate what a mouse click does on drawn surfaces.

## Coverage table

| Surface | What it exposes |
|---|---|
| Sidebar / menu bar rows (`VPNRow`, MenuBarView) | One sentence per VPN: name, kind, DotState words, labels. Hidden dot/logo. Announcer speaks transitions. |
| Connect control (ConnectionDetailView+ConnectControl) | Connect: label + live status value + missing-input hint; default action. Working pill: one element. Cancel ✕: ESC. |
| Credential form | AutoFill-capable fields with real names, `firstMissingField` focus, shake nudge paired with focus + "Required" AX value. |
| Sign-in chooser (`SignInSourceChooser`, first-connect card + the "Change…" popover) | One element per way of signing in: label = its name, value = its state in words ("Ready to use", "1Password isn't running", "SimpleVPN can't read this app"), hint = the SAME sentence the hover shows (`option.explanation` feeds both). Rows that SimpleVPN can fetch from are buttons carrying `.isSelected`; rows for password apps we cannot read are `.contain` containers whose own sentence says so — the two classes differ in wording, never only in styling. Choosing one is announced (`SignInSourceCatalog.announcement`). A vendor row that also carries a "Configure…" button becomes a `.contain` container with its own sentence rather than a `.combine` one — a row-wide `.combine` swallows the button (rule 4). The AutoFill footnote NAMES the System Settings pane and a button opens it: both, because a button whose destination is invisible is hover-only in another costume. Keyboard: Tab walks the rows, initial focus lands on the choice already made, ESC closes the popover. |
| Maturity banner + badge (`MaturityBanner`, `MaturityBadge`) | "Nobody has proven this yet", and it is CONTENT. The banner is a `.contain` container whose own label is the whole notice (`MaturityNotice.spokenSummary`) — never a colour, never a hover: the report button and the collapse button stay reachable inside, each naming what it does and what stays behind ("The “Untested” label stays either way"). Collapsing is announced, and the collapsed form still SPEAKS the state, because it still shows the badge. In list rows (main sidebar, Manage VPNs, menu bar) the chip is `accessibilityHidden` and its words ride the row's own sentence instead — the same rule as the status dots — appended last, after name, kind, state and labels, because it is the least urgent and most permanent thing about a row. On a sign-in row the chip sits beside the title and the maturity is a SECOND clause in the row's `accessibilityValue` after its live state ("Ready to use. Untested — nobody has confirmed KeePassXC working yet"): availability and maturity are different facts and are never merged into one phrase. Every word comes from the registry (`FeatureMaturity.swift`), so what VoiceOver says about a kind changes on the same one line the visible banner does. |
| Enablement banner (`EnablementBanner`, inside a chooser row that needs switching on) | One container whose label is `EnablementGuidance.spokenSummary` — the benefit, the current-version setting location, every command with its caption, and the vendor page's name. The commands and the link are CONTENT, never hover-only; each Copy button names the command it copies and reports "Copied" in its value; the copy is announced. |
| Connection telemetry / interface traffic | `AXChartDescriptor` audio graphs, combined stat rows. |
| Routes window | Named container "Route diagram"; one element per card with label+value+actions; "VPNs"/"Problems" rotors; drift lines are rotor entries; edges: dash + symbol + words, DWC dash rhythms; keyboard pan/zoom. |
| Gateway bar | Value = owner in words; announcer speaks gateway changes. |
| Manage VPNs | Combined rows for every store (NE, tunnels, native, compositions) incl. status words; toolbar +/−/Export; composition row menu; sidebar initial focus. |
| Editors (OpenVPN options, Tailscale, WireGuard, Proxy, SSH Network Tunnel, Subprocess, Native, Certificates, Custom Routing, Composition) | Labels from the descriptor/spec registries (`SettingDescriptor.name`, `EngineSettingSpec.name`); bold "changed" state spoken ("changed from default"); errors in field values + "Problem:" labels; disabled Save/Connect explain themselves; rule rows read as sentences. Live status a row discovers for itself rides that row's own value — the SSH agent row speaks what the agent holds ("Your SSH agent has 3 keys: …" / "No SSH agent is running") in the field's `accessibilityValue`, with the on-screen label `accessibilityHidden` so it isn't said twice, and pairs its colour with a per-state SF Symbol. |
| Import / discovery | Import success announced; candidate rows as sentences; "Create <what>" buttons; scan completion announced. |
| Network Tools | Mediator cards read as sentences with named Re-assert buttons; probe/DNS/traceroute/path rows as sentences ("no reply", "the answer macOS used"); latency audio graph; named pickers and port fields. |
| Traffic log | Rows as sentences (columns inlined, glyphs translated); filled/hollow activity dot; per-row actions menu named; ESC closes. |
| Logs (LogText) | Named "Log" text view; severity = tint + underline under DWC; Copy All announces. |
| Settings | Labels tab: every color well/name field/delete button names its label; permission states are sentences. |
| Settings ▸ Sign-In Sources (`SignInSourcesSettings`) | Every row is an `EngineSettingRow` over a `creds.*` spec, so the label, summary, manual link and reveal come from the registry rather than from the view. **The value/suggestion distinction is carried in WORDS**: a path field's title argument is always empty (the name is the spec's), a detected path is a `prompt:` placeholder plus its own "SimpleVPN found" row, and the field's `accessibilityValue` says which of the two you are looking at ("Not set. SimpleVPN uses the one it found: …" versus the path followed by its validation) — grey-versus-black reaches nobody using VoiceOver. Validation state is part of that spoken value AND a visible `Label` that announces its role ("Problem: …"). "Use What SimpleVPN Found" / "Clear" each carry their reason when disabled. The "where it was found" disclosure lists every path with, in words, whether SimpleVPN will run it from there. A row locked by MDM says whose decision it is. |
| About | Identity block combined; component rows one sentence each (link preserved). |
| Diagnostics sheets (crash, issue, error) | ESC + default action; remedy steps read without markup. |

## The walkthrough, automated: `VoiceOverWalkthroughTests`

The fifteen-step walkthrough below used to be entirely manual. Most of each step was
never a judgement at all — it was a FACT about the accessibility tree ("this element
exists, it is reachable, and what VoiceOver would read is what this doc promises"), and
what VoiceOver reads IS that tree. `SimpleVPNUITests/VoiceOverWalkthroughTests.swift`
asserts those facts, one test per step, in this section's order, so the human checklist
below is only the part a person must do.

**VoiceOver is never switched on by the tests** — that would make the machine start
speaking. They read the same `label` / `value` / structure VoiceOver reads. They are
also **read-only about the tester's own VPNs** on purpose: a gate that edits your
profiles to check a label is worse than no gate.

Four things are structurally out of reach for any UI test, and every step below that
depends on one says so:

- **Speech and announcement timing.** `AccessibilityNotification.Announcement` leaves no
  trace in the tree, so no test can hear "Tig Lab connected" or judge the 3 s debounce.
- **Audio graphs.** `AXChartDescriptor` isn't exposed to XCUITest.
- **The rotor.** VO-U is a VoiceOver affordance, not an AX attribute. The tests assert
  the *structure* a rotor is built from (named children carrying values).
- **Anything needing a live connection** (a real connect, the throughput chart, the
  traffic log) or a system accessibility preference.

The tests SKIP with a reason, never flake, when the environment can't present UI, when
the machine has no VPNs configured, or when the selected VPN has no credential fields
(its credentials come from a manager). A skipped step is a step the human still owns for
that run.

## Human VoiceOver walkthrough (release QA)

Run with a real build (notarized install per AGENTS.md), VoiceOver on (⌘F5). **~5
minutes now**, not 15: each step lists what the gate already proved and what is left for
your ears. Any failure — yours or the gate's — is release-blocking, same as a failed audit.

| # | Step | Proven automatically | You still judge |
|---|---|---|---|
| 1 | **Launch** and arrow the VPN list (VO-⇧-↓) | Each VPN row is ONE static text, naming the VPN, its kind and its state in words; ≥3 comma-separated parts; the row exposes no image at all (dots and logos are hidden, so the dot's state can only reach you as words) | That arrowing the list *reads* like a list, and the sentence is pleasant rather than merely complete |
| 2 | **Pick a VPN that needs credentials** — focus should be in the first empty field, named ("Username") | Every credential field on screen is named, and named from the glossary (Username / Password / verification code) — never by its example prompt | That INITIAL focus lands in the first empty field |
| 2b | **Import a VPN and DON'T connect** — the sign-in chooser appears | Every row is named and carries its state in its value; every row for a password app we can't read SAYS so in its own words (not just in a different style). Skips when no VPN is at its first connect | That Tab walks the rows, that focus starts on the choice already made, that choosing one is spoken — and that a VPN which has already connected is never asked again |
| 3 | **Return with the password empty**, then fill in and submit | — | The nudge: which field focus moves to, "Required" in its value, Tab order Username → Password → verification code, and hearing "<name> connected" without touching anything |
| 4 | **Hear the state** — VO-focus the Connect area | Every Connect/Disconnect control carries a non-empty value drawn from the ONE connection vocabulary | That the value is spoken the moment focus lands, and the "Connecting…" pill reads as one element while it churns |
| 5 | **Open Routes** (⇧⌘R), search, zoom | ⇧⌘R really opens the window; the search field is named for what it takes, not by its prompt; ⌘= and ⌘0 really change the zoom | That focus LANDS in the search field, that the answer panel is spoken, and that arrow-key panning feels like panning |
| 6 | **Use the rotor** (VO-U → "VPNs", then "Problems") | The diagram is a named container ("Route diagram") with children; every button inside is named; at least one card carries both a name and a value | The rotors themselves: that "VPNs" and "Problems" are offered, and that a healthy connection lists no problems |
| 7 | **Read the throughput chart** (inspector) | The live-details toggle is named and reports whether the pane is showing | The audio graph — needs a live connection, and tones are heard, not read. Confirm the summary sentence names the current rates |
| 8 | **Pause or disconnect** | Every status phrase on screen comes from one vocabulary; VPN ▸ Disconnect is enabled exactly when the Connect controls report something active | The announcement: its wording, that it arrives without moving focus, and that reconnect churn doesn't spam |
| 9 | **Open Manage VPNs** (⇧⌘M) | ⇧⌘M opens it; every sidebar row reads as one sentence including a `DotState` status word; every "Help for X" button names a setting that is on screen under that name; a disabled Save carries its reason in its value | That focus starts in the sidebar list, and that Tab reaches the editor |
| 10 | **Break a setting** (invalid control URL in a Tailscale/Headscale editor) | — | All of it: type the bad value and hear the field's own value speak the problem, and Save explain itself. Automating this would mean editing one of your real VPNs |
| 11 | **Custom Routing** | It is its own named tab beside "Settings", and both tabs are reachable; any rule row already present reads as a sentence | Adding a rule that overlaps a pushed route, and hearing the overlap explained ("…overlaps a pushed route") |
| 12 | **Settings** (⌘,) | The window opens from the menu or ⌘,; all five group headings (General · Menu Bar & Icons · Updates · Privacy · Advanced) are on screen under those names; the Labels tab is reachable and its per-label controls name which label they edit | Actually toggling a checkbox and renaming a label, and hearing the change confirmed |
| 13 | **Network Tools** (⇧⌘T) | ⇧⌘T opens it; the host field is named "Host or IP to test" (it used to be nameless — VoiceOver read its example, "example.com", as its name); the three Re-assert buttons name their subject; EVERY disabled control in the window carries its reason in its value; the DNS card names the resolvers macOS is actually using | Hearing the scan FINISH (the completion announcement) and the latency audio graph |
| 14 | **Traffic log** (connected VPN's inspector) | The ESC contract, on the one sheet reachable while disconnected: ⌘⇧F presents "Find a Setting…" and ESC closes it | The traffic log itself — rows as sentences with columns inlined and glyphs translated, and focus returning to the row that opened it |
| 15 | **Accommodations** (System Settings ▸ Accessibility ▸ Display) | The half that holds whatever the settings are: no VPN row exposes an image, and the route diagram's links state their condition in words | The visual pass — Differentiate Without Color (dots become shapes, edge dash rhythms, log underlines), Increase Contrast (pill text darkens, label pills gain rims), Reduce Motion (nothing pulses) |

Two notes on the gate's own limits, both measured rather than assumed:

- XCUITest cannot make the Routes search field the first responder in a test session
  ("Neither element nor any descendant has keyboard focus"), which is why step 5's
  focus/typing half is human.
- SwiftUI's Settings scene does not reliably answer the bare ⌘, in a test session, so
  step 12 opens the window by menu and falls back to the shortcut.
