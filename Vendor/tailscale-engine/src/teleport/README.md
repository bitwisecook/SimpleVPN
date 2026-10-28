# Teleport control plane

Adapted from sinnet3000/teleport-client at commit
`04a76bc3c2f5997362fb12563c37c3a43c3bfffa` (MIT; see LICENSE).

Retained API exchange, scrypt token derivation, ICE candidates, authenticated STUN,
nomination, secret redaction, and their upstream tests. `client.go` adds the narrow
SimpleVPN interface: Pair returns an in-memory identity; Prepare returns ephemeral
WireGuard configuration and a transport preserving the nominated UDP sockets.

Changes: package extraction, bounded HTTP response reads, HTTPS-only invite URLs,
Tailscale's already-pinned wireguard-go **conn interfaces**, offset-aware sends,
and optional delegation to the virtual router's physical transport. The upstream
WireGuard device, gVisor netstack, SOCKS proxy, file session store, CLI lifecycle,
MTU probing and echo/recovery loop are not included. WireGuard devices and raw IP
packets are owned by the existing SimpleVPN engine and virtual router.

Reconnect explicitly performs a new ICE/CONNECT exchange with the Keychain session.
Endpoint loss requires disconnect/reconnect; automatic Teleport renegotiation is
not implemented. This is visible in Docs/Drift.md and the in-app manual.
