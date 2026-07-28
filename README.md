# SimpleVPN

A native macOS OpenVPN client — SwiftUI, Swift 6 (strict concurrency), macOS 26+, built as a
Tunnelblick replacement. The tunnel runs in a Network Extension **system extension** driving the
[OpenVPN 3](https://github.com/OpenVPN/openvpn3) client core, so it installs like a normal app
(notarized, Developer ID) and shows up in System Settings ▸ VPN like a first-class citizen.

## Features

- Multiple VPN targets, imported from / exported to standard `.ovpn` files
- Username + password stored in the Keychain, per-connect one-time passcode (OTP) with a
  configurable credential template (default `{password}{otp}`)
- Live throughput graph (Swift Charts), uptime, reconnect count, and a connection-path
  diagram including pushed DNS and proxy/PAC
- Per-VPN logos and user-defined pastel labels
- Menu-bar quick connect/disconnect
- Liquid Glass UI following the Apple HIG

## Building

Requires Xcode 26+, [XcodeGen](https://github.com/yonaskolb/XcodeGen), and Homebrew
(`cmake`, `openssl@3`, `lz4`) for the engine build.

```sh
./Tools/build-openvpn3-xcframework.sh   # one-time: builds Vendor/OpenVPNEngine.xcframework
xcodegen generate                       # project.yml is the source of truth
open SimpleVPN.xcodeproj
```

`Tools/build-notarize-install.sh` produces a notarized Release build and installs it to
`/Applications` (Developer ID signing; see `AGENTS.md` for signing conventions).

## License

GPLv3 — see [LICENSE](LICENSE). The OpenVPN 3 core (built into the vendored xcframework,
not committed) is AGPLv3.
