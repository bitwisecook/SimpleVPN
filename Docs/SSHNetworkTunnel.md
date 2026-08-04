# SSH Network Tunnel — design and implementation notes

**Status: SHIPPED** (commit `b6fc52c`). This was written as a pre-implementation plan and has been
past-tensed against the landed code; the design rationale is kept because it is the record of *why*
the shape is what it is. Where the implementation diverged from the plan, the divergence is called
out inline. The one genuinely open item is **R2** (receive-window tuning, deliberately unmeasured).

## Ground truth (as built)
| Thing | Where |
|---|---|
| netstack + forwarders | `Vendor/proxy-engine/src/engine.go buildEngine()` — `channel.New(512,mtu,"")`, NIC promiscuous+spoofing, `tcp.NewForwarder(s,0,2048,st.handleTCP)`, `udp.NewForwarder(s,st.handleUDP)` |
| **THE flow-dial line** | `forward.go handleTCP()`: `st.up.dialThrough(ctx, st.dialer, targetHost, targetPort)` — dialed BEFORE `r.CreateEndpoint`, so failure ⇒ `r.Complete(true)` ⇒ RST. Fail-fast already correct. |
| other dial sites | `dns.go dnsOverTCP()`. (`forward.go dialTargetThroughProxy()` was dead and has been deleted.) |
| UDP policy | `udp.go serveUDP()` — non-SOCKS upstream ALREADY sends port 53 as DNS-over-TCP and refuses other UDP with a per-flow `setLastError`. Only needs a `st.up != nil` guard. |
| C header style | `Vendor/proxy-engine/include/pxengine.h`; BOTH `Tools/build-proxy-engine.sh` and `build-tailscale-engine.sh` assert `nm -gU` vs header — a new export means editing both loops |
| Swift engine model | `PacketTunnel/Engines/ProxyTunnelEngine.swift` (`@unchecked Sendable`, static `current` behind a lock because C fn-ptrs can't capture) |
| libssh bridge | `Shared/SSHBridge.{h,m}` — compiled into **BOTH** targets (`Shared` is a whole-directory source for `SimpleVPN` and `PacketTunnel`; `PacketTunnel`'s `HEADER_SEARCH_PATHS` includes `$(SRCROOT)/Shared` for exactly this). `openDirectTCPIPToHost:port:error:`, `checkHostKeyWithKnownHosts:pin:` (read-only), `enterDataMode`, `waitForActivityWithTimeoutMs:` |
| secrets model | `VPNController+WireGuard.swift connectWireGuard` — keychain `wg.<id>`, read at connect, `startTunnel(options:)`, never providerConfiguration |

## Decisions
- **D1 New `VPNKind.sshNetworkTunnel = "sshnet"`**, not a Proxy Tunnel preset (px rejects `@` in the URL, has no auth/host-key fields, and `ProxyArbiter` classifies px as `.egressItself` which is wrong here) and not `.ssh` (that kind is `.subprocess`/`.proxyOnly`). Transport `.packetTunnel`, participation `.full`. Do NOT use the `tun@openssh.com` channel (needs server root + `PermitTunnel`); `direct-tcpip` needs nothing.
- **D2 Flow dial returns a socketpair FD**, not a byte-pump callback family. Precedent: `OpenVPN3Bridge.mm:659`, `OpenConnectBridge.mm:327`. Go keeps a real `net.Conn` so `pipe()`/`copyCounted()`/`CloseWrite()`/counters work unchanged, and backpressure is the kernel's. A pump family would need the 3ms/20ms polling of `SSHTunnelEngine.pump` on every flow — unacceptable here.
- **D3 The extension is PIN-ONLY, always.** `KNOWNHOSTS`/`GLOBAL_KNOWNHOSTS` already `/dev/null` (`SSHBridge.m:154`); root+sandbox can't read/write the user's known_hosts. App resolves trust, passes the expected fingerprint, extension refuses anything else. No prompt, no TOFU, ever.
- **D4 Key material crosses as an in-memory PEM blob.** `ssh_pki_import_privkey_file` can't read the user's key; agent needs `SSH_AUTH_SOCK`; GSSAPI needs the user's ticket cache. So auth-method offers password/key/certificate ONLY — agent and Kerberos must be shown-with-reason, not silently missing.
- **D5 NO MSS clamp, NO MTU reduction.** The netstack TERMINATES guest TCP and re-originates a byte stream: guest segments never travel inside another IP packet, so clamping prevents no fragmentation. Classic TCP-over-TCP meltdown also doesn't apply. Real costs are window mismatch / HOL / double congestion control (R2–R4).

## Go work (`Vendor/proxy-engine/src/`) — DONE
All of the below landed; `flowdial.go` + `flowdial_test.go` + `sshflow_test.go` are the new files.
- `flowdial.go`: `PXSetFlowDialCallback`, `extensionDialer` implementing a new `flowDialer` interface. Refusal codes −1 generic, −2 no upstream, −3 session down, −4 server refused, −5 timeout. Adoption: `os.NewFile(fd)` → `net.FileConn` (which DUPs) → close the `os.File` immediately.
- Refactor: `upstream` gains `dial(ctx,host,port)`; `engineState.up` → a `flowDialer` (keep concrete `st.up` too, nil for ssh, for the SOCKS-UDP path); `handleTCP`/`dnsOverTCP` use the interface; `serveUDP`'s `st.up.kind == proxySOCKS5` gains a nil guard; delete `dialTargetThroughProxy`; `parseUpstream` accepts `ssh://` with userinfo (username isn't a secret), default port 22.
- DNS sentinel: `startConfig.DNSSentinel` + `DNSUpstream`; one substitution at the head of `serveDNSoverTCP` so the guest's "resolver" becomes a `direct-tcpip` to e.g. `127.0.0.1:53` AT THE SERVER — the thing SSH is uniquely good at and SOCKS can't express.
- Status: add `udpRefused` counter (today a black-holed UDP flow only sets `lastError`, which the next flow overwrites).
- Header + BOTH build scripts' symbol loops.

## Extension work — DONE
Landed as `PacketTunnel/Engines/SSHNetworkTunnelEngine.swift` plus `Shared/SSHNetworkTunnelConfig.swift`
and `Shared/SSHNetworkTunnelNetworkSettings.swift`.
- `git mv SSHBridge.{h,m} Shared/` — done (Shared is a whole-dir source on both targets — no per-target list to drift; do NOT leave a copy in ControlPlane or the app compiles it twice → duplicate ObjC symbols).
- `project.yml` PacketTunnel: `+Vendor/libssh-include`, `+$(SRCROOT)/Shared` header paths, link `SSHEngine.xcframework`, `+libgssapi_krb5.tbd`; bridging header `#import "SSHBridge.h"`.
- Isolation: target is `nonisolated` by default (good — the dial callback runs on a Go goroutine and must not hop). Needs `extension SSHChannel: @unchecked Sendable {}` AND `extension SSHSession: @unchecked Sendable {}` in the new engine file — NOT in Shared (retroactive-conformance clash if both targets ever merge).
- Entitlements: NO change (`network.client` covers it). But three sandbox facts are load-bearing: no key file, no known_hosts, no agent/Kerberos.
- New `PacketTunnel/Engines/SSHNetworkTunnelEngine.swift`: two queues (serial `ssh` for every libssh call, concurrent `pumps`); static `@convention(c)` dial callback; `dialFlow` = socketpair (256 KiB bufs, `SO_NOSIGPIPE`) → channel open on `ssh` with a **15 s budget** (under Go's 30 s so the RST is ours) → start pump → return the far fd. **Late-completion rule: a timed-out dial that later succeeds MUST close its channel and both fds** (else a leaked server-side socket per timeout).
- **Pump must not poll** — done, but only after a live server proved the first two attempts wrong (see R4): `waitForActivityWithTimeoutMs:` waits in a plain `poll()` on the session socket (`POLLIN`, plus `POLLOUT` only while libssh really has output queued) **and the self-pipe** (`SSHBridge.m` `_wakePipe`, poked by `wakeActivityWait`), and uses `ssh_event_dopoll(event, 0)` purely to turn readiness into parsed packets. `sendKeepalive` as planned; one reader loop per session driven by readiness, per-flow blocking `read(2)` on the socketpair for real backpressure.
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

## Config/UI/mediators — DONE
`SimpleVPN/ControlPlane/SSHNetSettingDescriptors.swift` (18 `sshnet.*` ids),
`SimpleVPN/UI/Editors/SSHNetworkTunnelView.swift` (the seventh Custom-Routing-tab host),
`SimpleVPN/ControlPlane/VPNController+SSHNetworkTunnel.swift`.
- `sshnet.*` descriptor catalog — ids are a GLOBAL namespace bound 1:1 to a `SettingSurface` and enforced by `ManualAnchorParityTests`, so `ssh.*` ids CANNOT be reused; copy wording/shape instead. Absent-with-reason: mode/socks-port/system-proxy/forwards, jump hosts (no ProxyCommand in-process; `SSH_OPTIONS_PROCESS_CONFIG` disabled by policy), extra-options, agent/kerberos auth. No `mss-clamp` (D5).
- Registrations (exhaustive): `VPNKind` (+displayName/systemImage/transport), `SearchableSetting.SettingSurface`, `RouteMediator.participation` → `.full`, `DNSArbiter` → like px, **`ProxyArbiter` → `.none`** (not `.egressItself`), `profileWantsFullTunnel`/`gatewaySubnets`, `PacketTunnelProvider` (kind ladder, `sshnetstatus` verb, incident writer, 1 Hz stats, gateway re-apply), `ManualAnchorParityTests.catalogs`, manual sections.
- Tunnel addresses: reuse px's RFC 2544 `198.18.0.1` — NOT the user's suggested `192.168.9.0/24` (real RFC 1918 space they may actually route). Sentinel resolver `198.18.0.53`, validated against the user's included routes.
- **§7e exclude the resolved SSH server address (`/32`,`/128`) from tunnel routes — DONE.** `Shared/ProxyTunnelNetworkSettings.swift` `proxyExclusions(host:)` is the shared implementation, called once at connect from `PacketTunnelProvider` and reused by `Shared/SSHNetworkTunnelNetworkSettings.swift`. NE's implicit exclusion of the provider's own sockets is the mechanism the px tunnel already relied on; this is belt-and-braces so the host routing table itself never points the carrier's address at the utun (for SSH a loop hangs the carrier). `proxy.go`'s comment, which used to claim only the second mechanism existed, now describes both accurately.
- `routingIncludes` — wired for this kind: `Shared/RoutingRule.swift` returns true for `.sshNetworkTunnel` from both `canAcceptRoutedInTraffic` (routed-in destinations are re-dialled as fresh `direct-tcpip` channels) and `canDivertOutside`, with the TCP-only caveat surfaced by `SSHNetworkTunnelConfig.udpCaveat`. The px equivalent is still outstanding and is deliberately filed separately rather than silently diverging.

## Risks
- **R1 three static archives each bundling OpenSSL — RESOLVED before landing.** All three scripts pin `OPENSSL_PIN=3.6.3` identically, so the object files are byte-identical and ld64's lazy archive loading pulls exactly one copy; verified by linking all three together. `project.yml`'s `SSHEngine.xcframework` dependency on `PacketTunnel` records the finding and names this as the place a future pin divergence would surface as duplicate symbols.
- **R2 window mismatch** — netstack default receive buffer vs libssh's ~64 KiB channel window; set explicit `TCPReceiveBufferSizeRangeOption`/send equivalent when the extension dialer is in use. Needs measurement. Do NOT touch `LinkEPCapabilities`/`SupportedGSOKind` (kernel-panic comment in `buildEngine`).
- **R3** one session, one serial queue, single-threaded crypto ⇒ few hundred Mbit/s aggregate ≈ single-stream. Don't overpromise. v2: N sessions hashed by destination.
- **R4 `ssh_event_dopoll` with many channels — RESOLVED, and the first two answers were both wrong.** Not a scaling problem, and not the `ssh_channel_select` fallback either. The reasoned-about answer was "dopoll starves writers, add a self-pipe wake to its poll set". The first run against a real sshd (`SSHLiveIntegrationTests`) showed that was inert: **`ssh_event_dopoll` never blocks at all on a connected session**, because libssh re-arms `POLLOUT` on the session socket after every write (`ssh_socket_unbuffered_write`) and a connected socket is always writable. A 300 ms "event wait" returned in <3 ms every time — a 100% CPU spin that owned the session's serial queue, so writes waited **p50 202 ms / max 204 ms** (24 channels, n=960) *with* the wake pipe in place. libssh's own `ssh_channel_select` has the same problem and papers over it by looping dopoll to a deadline. Shipped fix: wait in a plain `poll()` (session socket + self-pipe) and use `dopoll(…, 0)` only for packet processing → **p50 1.0 ms / p99 1.8 ms / max 2.0 ms**, with the wake suppressed as a control at **p50 148 ms / max 151 ms** (so the self-pipe is genuinely load-bearing, it just had nothing to interrupt before).
- **R5** every dial waits on the shared serial queue — bounded budget + mandatory late-completion cleanup.

## Tests — DONE
Contracts: `Vendor/proxy-engine/src/{flowdial_test.go,sshflow_test.go}` and
`SimpleVPNTests/ControlPlane/SSHNetworkTunnelTests.swift`.

Against a REAL SSH server: `SimpleVPNTests/ControlPlane/SSHLiveIntegrationTests.swift`
— host-key pin (match, wrong, truncated, at every strictness), key-file *and*
in-memory-PEM sign-in, direct-tcpip round trip + half-close, 24 concurrent channels
with write-latency percentiles (and the wake-suppressed control), keepalive,
compression, session-loss detection and reconnect, plus the app engine's SOCKS path
end to end. Each test starts its own `/usr/sbin/sshd` on a free loopback port from the
fixture `./Tools/ssh-live-test-fixture.sh` lays down, and **skips cleanly when the
fixture is absent** — `liveSSHFixtureMode` always runs and prints which mode it was.

The flow-dial C boundary itself: `Vendor/proxy-engine/src/flowdial_live_test.go` with
a real `PXFlowDialCallback` (cgo is not allowed in `_test.go`, so the callback lives in
`flowdial_cgotest.go` behind the `pxcgotest` tag; `Tools/build-proxy-engine.sh` runs
that pass).

Go: `TestParseUpstreamSSH`, `TestExtensionDialerAdoptsSocketpair` (incl. fd-leak check), `TestFlowDialRefusalCodes`, `TestServeUDPRefusesNonDNSWithoutSOCKS`, `TestDNSSentinelRewrite`, extend `TestStartConfigKeys`/`TestStatusOmitsSecrets`.
Swift: start-payload key parity with the Go struct, `connectProblem` gates, network-settings (server `/32` excluded, resolver `/32`s split-only, sentinel), `SSHHostKeyDecision` all four branches + truncated-pin, descriptor/anchor parity, mediator classification.

## Corrections to the original briefing (all since acted on)
1. `proxy.go`'s proxy-address-exclusion comment was FALSE — comment corrected and the exclusion route now genuinely added.
2. MSS clamp / MTU reduction inapplicable (no encapsulation).
3. TCP-over-TCP meltdown inapplicable for the same reason.
4. Byte-pump callbacks work but fd handoff is better and has precedent.
5. `ssh.*` ids cannot be reused (global namespace + parity test).
6. Agent/Kerberos/key-FILE auth impossible in the extension.
7. `SSHSettingDescriptors`' header claimed every entry was honoured by the in-process engine while `ssh.keepalive` and `ssh.compression` were subprocess-only. FIXED both ways: the engine now implements them (a keepalive timer on the session queue sending `keepalive@openssh.com`, and `SSH_OPTIONS_COMPRESSION` at key exchange) and the header says so.
8. `routingIncludes` was a no-op for proxy-tunnel kinds. Wired for `.sshNetworkTunnel`; still open for `.proxyTunnel`.
