# CLI — the `simplevpn` command-line tool

Target `SimpleVPNCLI` (product `simplevpn`; the target name is deliberately NOT
`simplevpn` — differing from the app target only by case collides the two
`*.build` intermediate directories on a case-insensitive filesystem and corrupts
the build graph).

A **thin client**: every command is one JSON line to the running app's control
socket (`~/Library/Application Support/SimpleVPN/control.sock`, mode 0600,
same-user only), so the CLI exercises exactly the paths the UI does — the same
`ControlPlaneDispatcher`, the same MDM guard chain, the same readiness rules,
the same live event stream. It compiles `ControlPlane/ControlSurface.swift`
directly, so app and CLI can never disagree about the protocol.

```
simplevpn list [--json]            every VPN: status, readiness, gateway
simplevpn status <vpn> [--json]
simplevpn connect <vpn>            stored credentials only; "needs sign-in" → open the app
simplevpn disconnect <vpn>
simplevpn pause <vpn> · resume <vpn>
simplevpn gateway [set <vpn> | direct]
simplevpn watch [--json]           stream live events (status flips, gateway moves, denials)
simplevpn version
```

Exit codes: 0 ok · 1 failed · 2 not ready · 3 denied by policy · 4 app not
running · 64 usage.

Ground rules (still binding):

- It must NOT embed a second control plane — new capabilities are added to the
  control surface first, then rendered here.
- Credential material never crosses the socket; the wire vocabulary has no
  command that carries a secret.
- `MDM/ManagedPolicy` binds here exactly as in the UI: locked is locked.
- Wire format is a public contract — add fields leniently, never rename
  (`ControlSurface.swift` documents it; ControlSurfaceTests pins it).
