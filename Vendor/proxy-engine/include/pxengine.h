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

/// Bring the userspace stack up and point it at the upstream proxy. Synchronous:
/// there is no control-plane handshake, so it returns once the stack is composed
/// (the routes/DNS the app advertises are then immediately live). `configJSON`
/// carries the upstream URL, credentials (in memory only) and MTU.
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
