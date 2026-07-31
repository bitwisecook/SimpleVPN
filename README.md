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

Requires Xcode 26+, [XcodeGen](https://github.com/yonaskolb/XcodeGen), Homebrew
(`cmake`, `openssl@3`, `lz4`) for the C engine builds, and a Go toolchain for the two
Go static archives (1Password SDK, Tailscale/Headscale engine).

```sh
./Tools/build-openvpn3-xcframework.sh   # one-time: builds Vendor/OpenVPNEngine.xcframework
./Tools/build-openconnect-xcframework.sh
./Tools/build-libssh2-xcframework.sh
./Tools/build-onepassword-sdk.sh        # Go: Vendor/onepassword-native/libopnative.a
./Tools/build-tailscale-engine.sh       # Go: Vendor/tailscale-engine/libtsengine.a
xcodegen generate                       # project.yml is the source of truth
open SimpleVPN.xcodeproj
```

`Tools/build-notarize-install.sh` produces a notarized Release build and installs it to
`/Applications` (Developer ID signing; see `AGENTS.md` for signing conventions).

## License

GPLv3 — see [LICENSE](LICENSE). The OpenVPN 3 core (built into the vendored xcframework,
not committed) is AGPLv3.
