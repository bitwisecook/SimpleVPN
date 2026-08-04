# Managing SimpleVPN with MDM

SimpleVPN reads organization policy from **managed preferences** — values pushed by
an MDM (Jamf, Intune, Kandji, etc.) into SimpleVPN's preference domain
`com.bragi0.SimpleVPN`. Managed values arrive as *forced* (read-only) keys: the app
both **greys out** the matching controls ("Managed by your organization") and
**enforces** them at connect, so a managed connection can't be weakened locally.

All keys are Boolean and optional. An absent key means the user is free.

| Key | Effect when `true` |
|---|---|
| `ForceKeepInsideVPN` | "Internet only through the VPN" is forced on and locked; traffic the VPN doesn't carry is blocked, and **no "send outside the VPN" divert rules** are allowed. |
| `DisableDivertRules` | **No divert rules at all** — neither "send outside" nor "route over another VPN". |
| `LockProxySettings` | Proxy configuration is read-only. |
| `LockConfiguration` | A connection's configuration and options (the .ovpn, engine overrides, certificates, proxy) can't be edited in the app. |

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
