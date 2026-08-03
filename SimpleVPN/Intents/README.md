# Intents — App Intents / Shortcuts surface

`VPNIntents.swift`: `ConnectVPNIntent`, `DisconnectVPNIntent`, `VPNStatusIntent`,
`VPNProfileEntity` (+ query), and `SimpleVPNShortcuts`. The dispatcher reaches the
intents via `AppDependencyManager` (`VPNIntentSupport.register`, called at app init).

Ground rules (binding):

- Intents are **thin adapters** over the control plane — they submit the same
  `ControlCommand`/`ControlQuery` the UI and the `simplevpn` CLI use, through the
  same `ControlPlaneDispatcher`. Never a parallel path.
- Anything MDM locks (`MDM/ManagedPolicy`) is locked here too — the guard chain is
  installed into `VPNController` itself, so there is no side door to forget.
- Credential-requiring connects surface `needsSignIn` as a *result*, not a prompt
  loop: Shortcuts can't type an OTP; the intent tells the user to open the app.
