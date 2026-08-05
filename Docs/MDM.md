# Managing SimpleVPN with MDM

SimpleVPN reads organization policy from **managed preferences** — values pushed by
an MDM (Jamf, Intune, Kandji, etc.) into SimpleVPN's preference domain
`com.bragi0.SimpleVPN`. Managed values arrive as *forced* (read-only) keys: the app
both **greys out** the matching controls ("Managed by your organization") and
**enforces** them at connect, so a managed connection can't be weakened locally.

All keys are optional. An absent key means the user is free.

### Connection behaviour (Boolean)

| Key | Effect when `true` |
|---|---|
| `ForceKeepInsideVPN` | "Internet only through the VPN" is forced on and locked; traffic the VPN doesn't carry is blocked, and **no "send outside the VPN" divert rules** are allowed. |
| `DisableDivertRules` | **No divert rules at all** — neither "send outside" nor "route over another VPN". |
| `LockProxySettings` | Proxy configuration is read-only. |
| `LockConfiguration` | A connection's configuration and options (the .ovpn, engine overrides, certificates, proxy) can't be edited in the app. Also makes **Settings ▸ Sign-In Sources** read-only. |

### Sign-in sources — which password apps may be used

| Key | Type | Effect |
|---|---|---|
| `SignInSourcesAllowed` | array of strings | Present ⇒ **only** these password apps may be used. Values are the vendor slugs `onepassword`, `keepassxc`, `keeper`. An empty array means none. |
| `SignInSourcesForbidden` | array of strings | These are always denied, whatever `SignInSourcesAllowed` says. Same slugs. |
| `SignInSourceToolPaths` | dictionary of string → string | Pins a tool's absolute path, keyed by the tool's binary name (currently `keeper`). Relative paths are ignored — a bare name would be resolved by rules the app does not control. |
| `DisableCredentialToolDiscovery` | Boolean | SimpleVPN never looks for password apps on this Mac: no vendor rows, no inventory. Typing a sign-in, the Apple keychain and Apple Passwords still work. |

Notes on the sign-in keys:

- A denied or pinned row is **visibly locked and says why** ("Your organization decides whether
  Keeper can be used"). It never silently reverts — a control that snaps back with no explanation
  reads as a bug in the app rather than as policy.
- A pinned path is shown **as the field's value**, marked as the organization's. Showing the
  user's stale value while running the pinned one is the silent-revert failure this avoids.
- A pinned path still has to pass the app's own safety rule: a program in a world-writable
  directory is refused even by policy, because anyone on that Mac could replace it between the
  check and the run.
- Forbidding a vendor means it is **neither offered nor mentioned** — it does not reappear in the
  chooser's "other password apps on this Mac" list.
- The slugs are a stable contract, like every setting id. Each vendor's controls are also
  addressable individually as `creds.<slug>.enabled` and `creds.<slug>.<field>` — see
  `Docs/ToolDiscovery.md` and the app's own manual (Sign-In Sources).

## Sample configuration profile payload

Deploy a `.mobileconfig` with a `com.apple.ManagedClient.preferences` payload
targeting `com.bragi0.SimpleVPN`:

```xml
<key>PayloadType</key>
<string>com.apple.ManagedClient.preferences</string>
<key>PayloadContent</key>
<dict>
  <key>com.bragi0.SimpleVPN</key>
  <dict>
    <key>Forced</key>
    <array>
      <dict>
        <key>mcx_preference_settings</key>
        <dict>
          <key>ForceKeepInsideVPN</key><true/>
          <key>DisableDivertRules</key><true/>
          <key>LockProxySettings</key><true/>
          <key>LockConfiguration</key><true/>
          <!-- Sign-in sources: 1Password only, Keeper explicitly denied, and
               its tool path pinned for the machines that do use it. -->
          <key>SignInSourcesAllowed</key>
          <array>
            <string>onepassword</string>
          </array>
          <key>SignInSourcesForbidden</key>
          <array>
            <string>keeper</string>
          </array>
          <key>SignInSourceToolPaths</key>
          <dict>
            <key>keeper</key><string>/opt/corp/bin/keeper</string>
          </dict>
        </dict>
      </dict>
    </array>
  </dict>
</dict>
```

Because the values are delivered as *forced*, the app detects them via
`objectIsForced(forKey:)` and shows the **Settings ▸ Managed by Your Organization**
summary only when policy is genuinely in effect (not when a user happens to have a
same-named local default).

## Notes / limits

- Enforcement is app-side: the app refuses to persist changes that violate policy
  and forces "keep inside the VPN" into the effective overrides at connect.
- `LockConfiguration` covers the OpenVPN proxy too (proxy is an engine override).
  `LockProxySettings` is the finer control for engines whose proxy is separate.
- Locking the *set* of connections a user may have (deploying the profiles
  themselves) is a separate concern from these behavioural locks and is a future
  addition (managed profile provisioning).
