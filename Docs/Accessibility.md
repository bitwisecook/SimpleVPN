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
9. **The regression gate is real.** SimpleVPNUITests runs `performAccessibilityAudit()`
   over the **main, Routes, Settings, and Manage VPNs** windows with one shared exclusion
   list (SimpleVPNUITests.swift documents each exclusion and why it is a framework
   artifact). New audit failures are build-breaking, same as warnings.

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
| Connection telemetry / interface traffic | `AXChartDescriptor` audio graphs, combined stat rows. |
| Routes window | Named container "Route diagram"; one element per card with label+value+actions; "VPNs"/"Problems" rotors; drift lines are rotor entries; edges: dash + symbol + words, DWC dash rhythms; keyboard pan/zoom. |
| Gateway bar | Value = owner in words; announcer speaks gateway changes. |
| Manage VPNs | Combined rows for every store (NE, tunnels, native, compositions) incl. status words; toolbar +/−/Export; composition row menu; sidebar initial focus. |
| Editors (OpenVPN options, Tailscale, WireGuard, Proxy, Subprocess, Native, Certificates, Custom Routing, Composition) | Labels from the descriptor/spec registries (`SettingDescriptor.name`, `EngineSettingSpec.name`); bold "changed" state spoken ("changed from default"); errors in field values + "Problem:" labels; disabled Save/Connect explain themselves; rule rows read as sentences. |
| Import / discovery | Import success announced; candidate rows as sentences; "Create <what>" buttons; scan completion announced. |
| Network Tools | Mediator cards read as sentences with named Re-assert buttons; probe/DNS/traceroute/path rows as sentences ("no reply", "the answer macOS used"); latency audio graph; named pickers and port fields. |
| Traffic log | Rows as sentences (columns inlined, glyphs translated); filled/hollow activity dot; per-row actions menu named; ESC closes. |
| Logs (LogText) | Named "Log" text view; severity = tint + underline under DWC; Copy All announces. |
| Settings | Labels tab: every color well/name field/delete button names its label; permission states are sentences. |
| About | Identity block combined; component rows one sentence each (link preserved). |
| Diagnostics sheets (crash, issue, error) | ESC + default action; remedy steps read without markup. |

## Human VoiceOver walkthrough (release QA)

Run with a real build (notarized install per AGENTS.md), VoiceOver on (⌘F5). Every step
must pass by ear — no peeking. ~15 minutes.

1. **Launch** SimpleVPN. VO announces the window; interact with the sidebar (VO-⇧-↓) and
   arrow through the VPN list. Each row must read as one sentence: name, kind, state
   ("disconnected"), labels. No "image", no unlabeled buttons.
2. **Pick a VPN** that needs credentials. Focus should already be in the first empty
   field (VO says its name — "Username"). Press Return with the password still empty and
   hear the field VO lands on (the nudge) plus "Required" in its value.
3. **Fill in credentials** (Tab moves Username → Password → OTP in order) and press
   Return in the last field. Without touching anything, you must hear
   "<name> connected" within a few seconds.
4. **Hear the state**: VO-focus the Connect area — the Disconnect/stop control reports
   the live status in its value. The sidebar row now says "connected".
5. **Open Routes** (⇧⌘R or VPN ▸ Routes…). Focus lands in the search field — type an
   address you route (e.g. 10.0.0.1) and hear the answer panel. Clear it, then Tab to
   the diagram and pan with arrows, zoom with `+`/`-`, `0` to fit.
6. **Use the rotor**: VO-U, choose "VPNs", jump to your VPN's card; then rotor
   "Problems" — with a healthy connection it should be empty (say so out loud: "no
   problems listed").
7. **Read the throughput chart** (main window inspector): VO onto the chart and play the
   audio graph. Confirm the summary sentence gives current rates.
8. **Pause or disconnect** and hear the announcement ("<name> disconnected") without
   moving focus.
9. **Open Manage VPNs** (⇧⌘M). Focus is in the sidebar list; arrow to a tunnel/native
   row and confirm the row sentence includes its status. Tab into the editor; find a
   Save button and hear why it's disabled (or that it saves).
10. **Break a setting**: in a Tailscale/Headscale editor type an invalid control URL —
    the field's value must speak the problem, and Save must explain itself.
11. **Custom Routing**: add a rule that overlaps a pushed route; the row must read as a
    sentence ending "…overlaps a pushed route", and the overlap button must say what it
    overlaps.
12. **Settings** (⌘,): toggle a checkbox in General, then in Labels rename a label — every
    control names WHICH label it edits.
13. **Network Tools** (⇧⌘T): focus is in the host field; type an address, Return. Hear
    the scan finish. Walk the DNS rows — the one macOS used must say so.
14. **Traffic log** (from a connected VPN's inspector): rows read as sentences; ESC
    closes the sheet and focus returns to the opener.
15. **Accommodations spot-check** (System Settings ▸ Accessibility ▸ Display): turn on
    Differentiate Without Color — dots become shapes, route edges change dash rhythm per
    state, log errors gain underlines. Turn on Increase Contrast — pill text darkens,
    label pills gain rims. Turn on Reduce Motion — nothing pulses.

Any step that fails is release-blocking, same as a failed audit.
