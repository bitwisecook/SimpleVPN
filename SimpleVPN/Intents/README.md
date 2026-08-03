# Intents — App Intents / Shortcuts home (nothing here yet)

Future Siri/Shortcuts/Spotlight surface: `ConnectVPNIntent`, `DisconnectVPNIntent`,
`VPNStatusIntent`, an `AppShortcutsProvider`, and entity types (`VPNProfileEntity`)
resolving against `VPNController.profiles`.

Ground rules when this lands:

- Intents are a **thin adapter** over the control plane — they call the same
  `VPNController` methods the UI does (`connect(id:)`, `disconnect(id:)`,
  `connectReadiness(for:)`), never a parallel path.
- Anything MDM locks (`MDM/ManagedPolicy`) is locked here too — an intent must not
  become the side door around a managed restriction.
- Credential-requiring connects surface `needsSignIn` as a *result*, not a prompt
  loop: Shortcuts can't type an OTP; the intent should open the app to the profile.
