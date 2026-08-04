# SSH Network Tunnel — implementation plan (research 2026-08-04, read-only pass)

Destination: `Docs/SSHNetworkTunnel.md` (move in when no writer is active).

## Verified ground truth
| Thing | Where |
|---|---|
| netstack + forwarders | `Vendor/proxy-engine/src/engine.go buildEngine()` — `channel.New(512,mtu,"")`, NIC promiscuous+spoofing, `tcp.NewForwarder(s,0,2048,st.handleTCP)`, `udp.NewForwarder(s,st.handleUDP)` |
| **THE flow-dial line** | `forward.go handleTCP()`: `st.up.dialThrough(ctx, st.dialer, targetHost, targetPort)` — dialed BEFORE `r.CreateEndpoint`, so failure ⇒ `r.Complete(true)` ⇒ RST. Fail-fast already correct. |
| other dial sites | `dns.go dnsOverTCP()`, `forward.go dialTargetThroughProxy()` (DEAD — delete) |
| UDP policy | `udp.go serveUDP()` — non-SOCKS upstream ALREADY sends port 53 as DNS-over-TCP and refuses other UDP with a per-flow `setLastError`. Only needs a `st.up != nil` guard. |
| C header style | `Vendor/proxy-engine/include/pxengine.h`; BOTH `Tools/build-proxy-engine.sh` and `build-tailscale-engine.sh` assert `nm -gU` vs header — a new export means editing both loops |
| Swift engine model | `PacketTunnel/Engines/ProxyTunnelEngine.swift` (`@unchecked Sendable`, static `current` behind a lock because C fn-ptrs can't capture) |
| libssh bridge | `SimpleVPN/ControlPlane/SSHBridge.{h,m}` — APP TARGET ONLY; `openDirectTCPIPToHost:port:error:`, `checkHostKeyWithKnownHosts:pin:` (read-only), `enterDataMode` |
| secrets model | `VPNController+WireGuard.swift connectWireGuard` — keychain `wg.<id>`, read at connect, `startTunnel(options:)`, never providerConfiguration |

## Decisions
- **D1 New `VPNKind.sshNetworkTunnel = "sshnet"`**, not a Proxy Tunnel preset (px rejects `@` in the URL, has no auth/host-key fields, and `ProxyArbiter` classifies px as `.egressItself` which is wrong here) and not `.ssh` (that kind is `.subprocess`/`.proxyOnly`). Transport `.packetTunnel`, participation `.full`. Do NOT use the `tun@openssh.com` channel (needs server root + `PermitTunnel`); `direct-tcpip` needs nothing.
- **D2 Flow dial returns a socketpair FD**, not a byte-pump callback family. Precedent: `OpenVPN3Bridge.mm:659`, `OpenConnectBridge.mm:327`. Go keeps a real `net.Conn` so `pipe()`/`copyCounted()`/`CloseWrite()`/counters work unchanged, and backpressure is the kernel's. A pump family would need the 3ms/20ms polling of `SSHTunnelEngine.pump` on every flow — unacceptable here.
- **D3 The extension is PIN-ONLY, always.** `KNOWNHOSTS`/`GLOBAL_KNOWNHOSTS` already `/dev/null` (`SSHBridge.m:154`); root+sandbox can't read/write the user's known_hosts. App resolves trust, passes the expected fingerprint, extension refuses anything else. No prompt, no TOFU, ever.
- **D4 Key material crosses as an in-memory PEM blob.** `ssh_pki_import_privkey_file` can't read the user's key; agent needs `SSH_AUTH_SOCK`; GSSAPI needs the user's ticket cache. So auth-method offers password/key/certificate ONLY — agent and Kerberos must be shown-with-reason, not silently missing.
- **D5 NO MSS clamp, NO MTU reduction.** The netstack TERMINATES guest TCP and re-originates a byte stream: guest segments never travel inside another IP packet, so clamping prevents no fragmentation. Classic TCP-over-TCP meltdown also doesn't apply. Real costs are window mismatch / HOL / double congestion control (R2–R4).

## Go work (`Vendor/proxy-engine/src/`)
- New `flowdial.go`: `PXSetFlowDialCallback`, `extensionDialer` implementing a new `flowDialer` interface. Refusal codes −1 generic, −2 no upstream, −3 session down, −4 server refused, −5 timeout. Adoption: `os.NewFile(fd)` → `net.FileConn` (which DUPs) → close the `os.File` immediately.
- Refactor: `upstream` gains `dial(ctx,host,port)`; `engineState.up` → a `flowDialer` (keep concrete `st.up` too, nil for ssh, for the SOCKS-UDP path); `handleTCP`/`dnsOverTCP` use the interface; `serveUDP`'s `st.up.kind == proxySOCKS5` gains a nil guard; delete `dialTargetThroughProxy`; `parseUpstream` accepts `ssh://` with userinfo (username isn't a secret), default port 22.
- DNS sentinel: `startConfig.DNSSentinel` + `DNSUpstream`; one substitution at the head of `serveDNSoverTCP` so the guest's "resolver" becomes a `direct-tcpip` to e.g. `127.0.0.1:53` AT THE SERVER — the thing SSH is uniquely good at and SOCKS can't express.
- Status: add `udpRefused` counter (today a black-holed UDP flow only sets `lastError`, which the next flow overwrites).
- Header + BOTH build scripts' symbol loops.

## Extension work
- `git mv SSHBridge.{h,m} Shared/` (Shared is a whole-dir source on both targets — no per-target list to drift; do NOT leave a copy in ControlPlane or the app compiles it twice → duplicate ObjC symbols).
- `project.yml` PacketTunnel: `+Vendor/libssh-include`, `+$(SRCROOT)/Shared` header paths, link `SSHEngine.xcframework`, `+libgssapi_krb5.tbd`; bridging header `#import "SSHBridge.h"`.
- Isolation: target is `nonisolated` by default (good — the dial callback runs on a Go goroutine and must not hop). Needs `extension SSHChannel: @unchecked Sendable {}` AND `extension SSHSession: @unchecked Sendable {}` in the new engine file — NOT in Shared (retroactive-conformance clash if both targets ever merge).
- Entitlements: NO change (`network.client` covers it). But three sandbox facts are load-bearing: no key file, no known_hosts, no agent/Kerberos.
- New `PacketTunnel/Engines/SSHNetworkTunnelEngine.swift`: two queues (serial `ssh` for every libssh call, concurrent `pumps`); static `@convention(c)` dial callback; `dialFlow` = socketpair (256 KiB bufs, `SO_NOSIGPIPE`) → channel open on `ssh` with a **15 s budget** (under Go's 30 s so the RST is ours) → start pump → return the far fd. **Late-completion rule: a timed-out dial that later succeeds MUST close its channel and both fds** (else a leaked server-side socket per timeout).
- **Pump must not poll.** Add bridge `waitForActivityWithTimeoutMs:` (wraps `ssh_event_add_session`/`ssh_event_dopoll`) + `sendKeepalive`. One reader loop per session driven by readiness; per-flow blocking `read(2)` on the socketpair for real backpressure. `ssh_event_dopoll` with many channels is the biggest unproven piece — PROTOTYPE FIRST.
- Reconnect: 1,2,4,8,15,30 s cap, ±20% jitter, indefinite; close all channels+socketpairs so in-flight flows get EOF (reset, not hang). **Do NOT drop the tunnel settings on session loss** — keep the utun so traffic is refused rather than leaking to the physical path (kill-switch-shaped, must be commented).
- Flows fail fast (−3 while reconnecting), never queue.

## Auth + host keys
- `startTunnel(options:)`: `sshUsername`, `sshPassword` (also the key passphrase — the bridge conflates them), `sshPrivateKeyPEM`, `sshCertificatePEM`, `sshExpectedHostKeySHA256` (**REQUIRED non-empty**), `gatewayOwned`. Keychain namespace `sshnet.<id>`.
- New bridge method `authKeyForUser:privateKeyPEM:certificatePEM:passphrase:error:` (`ssh_pki_import_privkey_base64`).
- Extension: host key checked BEFORE auth (else credentials go to whoever answered); `.notFound`/`.unavailable` treated as refusals too.
- App-side ladder (must match `ssh.pinned-host-key`/`ssh.strict-host-key` + `sshPinBlockReason`): pin → known_hosts match → strict=yes refuse → accept-new/no show a TRUST SHEET then append (logged at `.notice`; TOFU never silent). First connect never TOFUs inside the extension.
- Pure `Shared/SSHHostKeyDecision.swift` for testability. Truncated pin must never match (bridge uses exact `hexTail` equality).

## DNS
Three shapes, each honest: explicit servers → DNS-over-TCP through SSH; **sentinel + far-side upstream (recommended)**; empty DNS → warn (full tunnel: only works if the server can reach your resolvers; split: it's a leak). Failure does NOT fall back to the physical path (that's the leak the tunnel exists to prevent) — count it and surface `lastError`. Non-DNS UDP refused per flow + `udpRefused` counter + an editor caveat naming QUIC.

## Config/UI/mediators
- New `sshnet.*` descriptor catalog — ids are a GLOBAL namespace bound 1:1 to a `SettingSurface` and enforced by `ManualAnchorParityTests`, so `ssh.*` ids CANNOT be reused; copy wording/shape instead. Absent-with-reason: mode/socks-port/system-proxy/forwards, jump hosts (no ProxyCommand in-process; `SSH_OPTIONS_PROCESS_CONFIG` disabled by policy), extra-options, agent/kerberos auth. No `mss-clamp` (D5).
- Registrations (exhaustive): `VPNKind` (+displayName/systemImage/transport), `SearchableSetting.SettingSurface`, `RouteMediator.participation` → `.full`, `DNSArbiter` → like px, **`ProxyArbiter` → `.none`** (not `.egressItself`), `profileWantsFullTunnel`/`gatewaySubnets`, `PacketTunnelProvider` (kind ladder, `sshnetstatus` verb, incident writer, 1 Hz stats, gateway re-apply), `ManualAnchorParityTests.catalogs`, manual sections.
- Tunnel addresses: reuse px's RFC 2544 `198.18.0.1` — NOT the user's suggested `192.168.9.0/24` (real RFC 1918 space they may actually route). Sentinel resolver `198.18.0.53`, validated against the user's included routes.
- **§7e MANDATORY: exclude the resolved SSH server address (`/32`,`/128`) from tunnel routes.** `proxy.go` COMMENT CLAIMS the extension already does this for the proxy — IT DOES NOT (no such code, no `IP_BOUND_IF` anywhere). Today's px tunnel works only because NE implicitly excludes the provider's own sockets. For SSH a loop hangs the carrier itself. Add the route AND fix the stale comment.
- `routingIncludes` is consumed ONLY by the OpenVPN bridge → Custom Routing's "route X over VPN Y" is a NO-OP today when Y is a Proxy Tunnel. Wire it for this kind; file the px equivalent separately rather than silently diverging.

## Risks
- **R1 (build-blocking, unverifiable without linking): three static archives each bundling OpenSSL.** All three scripts pin `OPENSSL_PIN=3.6.3` identically for this reason; two co-link today (app links OpenVPN+SSH), three untested. FIRST ACTION: `nm -gU` the three `.a`s for `_OPENSSL_init_ssl`/`_EVP_CIPHER_CTX_new` and check for multiple `T`.
- **R2 window mismatch** — netstack default receive buffer vs libssh's ~64 KiB channel window; set explicit `TCPReceiveBufferSizeRangeOption`/send equivalent when the extension dialer is in use. Needs measurement. Do NOT touch `LinkEPCapabilities`/`SupportedGSOKind` (kernel-panic comment in `buildEngine`).
- **R3** one session, one serial queue, single-threaded crypto ⇒ few hundred Mbit/s aggregate ≈ single-stream. Don't overpromise. v2: N sessions hashed by destination.
- **R4** `ssh_event_dopoll` with many channels unproven; fallback a blocking thread with `ssh_channel_select`. The 20 ms poll is NOT acceptable on this path.
- **R5** every dial waits on the shared serial queue — bounded budget + mandatory late-completion cleanup.

## Tests
Go: `TestParseUpstreamSSH`, `TestExtensionDialerAdoptsSocketpair` (incl. fd-leak check), `TestFlowDialRefusalCodes`, `TestServeUDPRefusesNonDNSWithoutSOCKS`, `TestDNSSentinelRewrite`, extend `TestStartConfigKeys`/`TestStatusOmitsSecrets`.
Swift: start-payload key parity with the Go struct, `connectProblem` gates, network-settings (server `/32` excluded, resolver `/32`s split-only, sentinel), `SSHHostKeyDecision` all four branches + truncated-pin, descriptor/anchor parity, mediator classification.

## Corrections to my briefing (agent was right)
1. `proxy.go`'s proxy-address-exclusion comment is FALSE.
2. MSS clamp / MTU reduction inapplicable (no encapsulation).
3. TCP-over-TCP meltdown inapplicable for the same reason.
4. Byte-pump callbacks work but fd handoff is better and has precedent.
5. `ssh.*` ids cannot be reused (global namespace + parity test).
6. Agent/Kerberos/key-FILE auth impossible in the extension.
7. `SSHSettingDescriptors` header claims every entry is honored by the in-process engine — `ssh.keepalive` and `ssh.compression` are subprocess-only (pre-existing honesty gap; fix separately).
8. `routingIncludes` no-op for proxy-tunnel kinds (pre-existing).
