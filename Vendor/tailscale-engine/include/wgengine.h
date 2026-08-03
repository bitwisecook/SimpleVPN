// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
//  wgengine.h
//  Stable C interface to the plain-WireGuard engine — wireguard-go's device
//  package driven directly with a static one-peer config (the classic wg-quick
//  client shape), no control plane, in-process inside SimpleVPN's packet-tunnel
//  system extension. This header is hand-written so Swift never sees the
//  cgo-generated header's Go typedef cruft; Tools/build-tailscale-engine.sh
//  verifies the exported symbols match. All returned strings are malloc'd
//  UTF-8 JSON — release them with WGFree. Full request/response contract is
//  documented in Vendor/tailscale-engine/src/wireguard.go.
//
//  LINKING NOTE: these symbols are compiled into libtsengine.a alongside the
//  Tailscale node's TS* exports and the proxy tunnel's folded-in PX* exports —
//  two Go c-archives cannot be linked into one binary, and that same archive's
//  module already pins wireguard-go. This engine and the Tailscale node are
//  never run at once in one provider process (one tunnel per session).

#ifndef WGENGINE_H
#define WGENGINE_H

#ifdef __cplusplus
extern "C" {
#endif

/// Engine → Swift packet delivery. `bytes` is borrowed for the duration of the
/// call ONLY (it is Go-owned memory) — copy before returning. Always a raw IP
/// packet: NO 4-byte protocol-family header (unlike the openvpn3 tun pump).
typedef void (*WGPacketCallback)(const unsigned char *bytes, int len);

/// Engine → Swift text delivery (log lines; never contains key material).
/// The string is valid for the duration of the call only.
typedef void (*WGStringCallback)(const char *text);

/// Register the callbacks. Call once before WGStart; either may be NULL.
/// Callbacks fire on arbitrary Go goroutines: the Swift implementations must
/// be thread-safe and must not block (packetOut is on the data path).
///  - packetOut(bytes,len)   engine → NEPacketTunnelFlow
///  - logLine(text)          diagnostics for os_log (never contains keys)
void WGSetCallbacks(WGPacketCallback packetOut,
                    WGStringCallback logLine);

/// Bring the WireGuard device up. Synchronous: the device is running when this
/// returns {"ok":true,...} (the Noise handshake itself is lazy — first packet
/// or keepalive — and visible via WGStatus). `configJSON` carries the base64
/// keys (in memory only — they arrived via startTunnel options), the
/// host:port endpoint, allowed IPs, keepalive, listen port and MTU.
/// response: {"ok":true,"endpoint":"<resolved ip:port>"} or
///           {"error":{"kind","message"}}
/// kinds: badRequest | alreadyRunning | endpoint | engine | other
/// The resolved endpoint should become NE's tunnelRemoteAddress so the
/// encrypted UDP to the server is routed around the tunnel it carries.
char *WGStart(const char *configJSON);

/// Tear the device down. Idempotent; always {"ok":true}.
char *WGStop(void);

/// Current state + byte counters, last-handshake time (unix seconds; 0 =
/// never), the peer's current endpoint and the local listen port. Returns
/// {"state":"stopped"} when nothing is running. NEVER carries key material —
/// the shim whitelists what it reads out of the device.
char *WGStatus(void);

/// Swift → engine packet submission. Raw IP packet, no PF header. Returns 1
/// when queued, 0 when dropped (queue full / not running / bad length).
/// Never blocks — a VPN must drop rather than stall the flow reader.
int WGPacketIn(const void *bytes, int length);

/// Free any string returned by WGStart/WGStop/WGStatus.
void WGFree(char *p);

#ifdef __cplusplus
}
#endif

#endif /* WGENGINE_H */
