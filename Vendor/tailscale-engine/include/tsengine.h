// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
//  tsengine.h
//  Stable C interface to libtsengine.a — the open-source Tailscale client
//  stack (tailscale.com, BSD-3-Clause) compiled as a c-archive with a small
//  JSON-contract shim (Vendor/tailscale-engine/src/main.go), driving
//  SimpleVPN's Tailscale / Headscale VPN kind from inside the packet-tunnel
//  system extension. This header is hand-written so Swift never sees the
//  cgo-generated header's Go typedef cruft; Tools/build-tailscale-engine.sh
//  verifies the exported symbols match. All returned strings are malloc'd
//  UTF-8 JSON — release them with TSFree. Full request/response contract is
//  documented in main.go.
//
//  Headscale is NOT a separate engine: it is this engine pointed at a
//  different controlURL.

#ifndef TSENGINE_H
#define TSENGINE_H

#ifdef __cplusplus
extern "C" {
#endif

/// Engine → Swift packet delivery. `bytes` is borrowed for the duration of the
/// call ONLY (it is Go-owned memory) — copy before returning. Always a raw IP
/// packet: NO 4-byte protocol-family header (unlike the openvpn3 tun pump).
typedef void (*TSPacketCallback)(const unsigned char *bytes, int len);

/// Engine → Swift text delivery (JSON, or a bare URL for browseToURL).
/// The string is valid for the duration of the call only.
typedef void (*TSStringCallback)(const char *text);

/// Register the callbacks. Call once before TSStart; any may be NULL.
/// Callbacks fire on arbitrary Go goroutines: the Swift implementations must
/// be thread-safe and must not block (packetOut is on the data path).
///  - packetOut(bytes,len)   engine → NEPacketTunnelFlow
///  - stateChanged(json)     {"state","authURL","message"} — ipn.State names
///  - browseToURL(url)       interactive sign-in needed; open this URL
///  - netmapChanged(json)    routes/addresses/DNS to re-apply as
///                           NEPacketTunnelNetworkSettings
///  - logLine(text)          diagnostics for os_log (never contains keys)
void TSSetCallbacks(TSPacketCallback packetOut,
                    TSStringCallback stateChanged,
                    TSStringCallback browseToURL,
                    TSStringCallback netmapChanged,
                    TSStringCallback logLine);

/// Bring the node up. Non-blocking: it returns once the stack is composed and
/// the control-plane conversation has started; progress arrives via the
/// callbacks. `configJSON` carries controlURL / hostname / authKey / stateDir
/// and the routing + DNS toggles.
/// response: {"ok":true} or {"error":{"kind","message"}}
/// kinds: badRequest | alreadyRunning | stateDir | engine | backend | other
char *TSStart(const char *configJSON);

/// Tear the node down. Idempotent; always {"ok":true}.
char *TSStop(void);

/// Current state + netmap summary (self IPs, MagicDNS suffix, peer counts,
/// exit-node options, byte counters, the last applied tunnel config).
/// Returns {"state":"NoState",…} when nothing is running.
char *TSStatus(void);

/// Apply a subset of prefs live (exit node, accept-routes, accept-DNS,
/// advertised routes) without a reconnect. Absent JSON fields are untouched.
char *TSUpdatePrefs(const char *prefsJSON);

/// Swift → engine packet submission. Raw IP packet, no PF header. Returns 1
/// when queued, 0 when dropped (queue full / not running / bad length).
/// Never blocks — a VPN must drop rather than stall the flow reader.
int TSPacketIn(const void *bytes, int length);

/// Free any string returned by TSStart/TSStop/TSStatus/TSUpdatePrefs.
void TSFree(char *p);

#ifdef __cplusplus
}
#endif

#endif /* TSENGINE_H */
