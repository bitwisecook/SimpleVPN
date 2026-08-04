// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
//  pxengine.h
//  Stable C interface to the proxy-tunnel engine — a tun2socks-style userspace
//  TCP/IP stack (gVisor netstack) that terminates every flow on the utun and
//  re-dials it through an upstream SOCKS5 or HTTP(S) CONNECT proxy, in-process,
//  inside SimpleVPN's packet-tunnel system extension. This header is
//  hand-written so Swift never sees the cgo-generated header's Go typedef cruft;
//  Tools/build-proxy-engine.sh verifies the exported symbols match. All returned
//  strings are malloc'd UTF-8 JSON — release them with PXFree. Full
//  request/response contract is documented in Vendor/proxy-engine/src/engine.go.
//
//  LINKING NOTE: two Go c-archives cannot be linked into one binary (duplicate
//  Go-runtime symbols). PacketTunnel already links the Tailscale Go archive, so
//  the proxy engine's exports are folded into THAT archive (the Tailscale shim
//  blank-imports the pxengine package); libpxengine.a is a standalone build for
//  isolated verification only. See Tools/build-proxy-engine.sh and AGENTS.md.

#ifndef PXENGINE_H
#define PXENGINE_H

#ifdef __cplusplus
extern "C" {
#endif

/// Engine → Swift packet delivery. `bytes` is borrowed for the duration of the
/// call ONLY (it is Go-owned memory) — copy before returning. Always a raw IP
/// packet: NO 4-byte protocol-family header (unlike the openvpn3 tun pump).
typedef void (*PXPacketCallback)(const unsigned char *bytes, int len);

/// Engine → Swift text delivery (JSON for stateChanged, prose for logLine).
/// The string is valid for the duration of the call only.
typedef void (*PXStringCallback)(const char *text);

/// Register the callbacks. Call once before PXStart; any may be NULL.
/// Callbacks fire on arbitrary Go goroutines: the Swift implementations must be
/// thread-safe and must not block (packetOut is on the data path).
///  - packetOut(bytes,len)   engine → NEPacketTunnelFlow
///  - stateChanged(json)     {"state","message"} — "running" / "stopped"
///  - logLine(text)          diagnostics for os_log (never contains credentials)
void PXSetCallbacks(PXPacketCallback packetOut,
                    PXStringCallback stateChanged,
                    PXStringCallback logLine);

/// Engine → Swift per-flow dial, for the SSH Network Tunnel kind: the transport
/// is an SSH session Swift owns, so Swift opens each flow and hands back a
/// SOCKET FILE DESCRIPTOR the engine adopts (and closes when the flow ends).
/// `host` is borrowed for the duration of the call only.
///
/// A NEGATIVE return is a refusal and the code says why — the guest gets an
/// immediate RST rather than a black hole:
///   -1 generic · -2 no session · -3 session down (reconnecting) ·
///   -4 the server refused the forward · -5 timed out
/// Flows are never queued: while the session is down every dial refuses with -3.
typedef int (*PXFlowDialCallback)(const char *host, int port);

/// Register the flow dialler. REQUIRED before PXStart when the upstream URL is
/// `ssh://…` (PXStart refuses that scheme without one, rather than leaving every
/// flow to fail with -2). Fires on arbitrary Go goroutines, one per flow: the
/// Swift implementation must be thread-safe and must return promptly — its own
/// budget has to be under the engine's 30 s dial timeout so the RST is ours.
/// NULL clears it.
void PXSetFlowDialCallback(PXFlowDialCallback dial);

/// Bring the userspace stack up and point it at the upstream. Synchronous:
/// there is no control-plane handshake, so it returns once the stack is composed
/// (the routes/DNS the app advertises are then immediately live). `configJSON`
/// carries the upstream URL, credentials (in memory only), MTU and — for the SSH
/// kind — the far-side DNS sentinel pair ("dnsSentinel"/"dnsUpstream": every DNS
/// query addressed to the sentinel is re-aimed at the resolver it stands for,
/// resolved AT THE SERVER over the same session).
/// The upstream scheme decides who dials each flow: socks5/http/https are dialled
/// in-process (proxy.go); `ssh://` is dialled by PXSetFlowDialCallback.
/// response: {"ok":true} or {"error":{"kind","message"}}
/// kinds: badRequest | alreadyRunning | engine | other
char *PXStart(const char *configJSON);

/// Tear the stack down. Idempotent; always {"ok":true}.
char *PXStop(void);

/// Current state + flow/byte counters and the last per-flow error (for the
/// connection panel). Returns {"state":"stopped"} when nothing is running.
/// Never carries the upstream address or any credential.
char *PXStatus(void);

/// Swift → engine packet submission. Raw IP packet, no PF header. Returns 1 when
/// injected, 0 when dropped (not running / bad length / unknown IP version).
int PXPacketIn(const void *bytes, int length);

/// Free any string returned by PXStart/PXStop/PXStatus.
void PXFree(char *p);

#ifdef __cplusplus
}
#endif

#endif /* PXENGINE_H */
