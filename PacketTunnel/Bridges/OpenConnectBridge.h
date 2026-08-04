// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
//  OpenConnectBridge.h
//  Objective-C surface over libopenconnect (C), for the Swift
//  NEPacketTunnelProvider. Runs the OpenConnect auth + mainloop on a background
//  thread, maps the negotiated IP config onto NEPacketTunnelNetworkSettings, and
//  pumps IP packets between openconnect and the provider's NEPacketTunnelFlow via
//  a socketpair — the same shape as OpenVPN3Bridge, so the provider treats the two
//  engines uniformly. Covers the OpenConnect protocols: Fortinet, F5, GlobalProtect,
//  AnyConnect. In-process: no `openconnect` subprocess.
//

#import <Foundation/Foundation.h>
#import <NetworkExtension/NetworkExtension.h>

NS_ASSUME_NONNULL_BEGIN

typedef NS_ENUM(NSInteger, OCStatus) {
    OCStatusDisconnected = 0,
    OCStatusConnecting,
    OCStatusConnected,
    OCStatusReconnecting,
    OCStatusDisconnecting,
};

/// Per-connection settings for an OpenConnect session. Secrets are read-once from
/// the session payload and never persisted here.
@interface OCClientSettings : NSObject
@property (copy) NSString *server;          // host or https URL
@property (copy) NSString *protocol;        // "fortinet" | "f5" | "gp" | "anyconnect"
@property (copy) NSString *username;
@property (nullable, copy) NSString *password;
/// A session cookie obtained OUT of process (the app's ocauth-helper SSO
/// sign-in). When set, the bridge skips openconnect_obtain_cookie entirely —
/// no forms, no credentials — and connects with this cookie. In-memory only
/// (startTunnel options); never persisted, never logged.
@property (nullable, copy) NSString *cookie;
@property (nullable, copy) NSString *realm;             // authgroup
@property (nullable, copy) NSString *serverCertSHA256;  // pin (accept only this)
@property (nullable, copy) NSString *caFile;            // extra CA bundle path
@property (nullable, copy) NSString *externalBrowser;   // SAML/SSO browser path ("" = default)
@property (nullable, copy) NSString *userAgent;
@end

@class OpenConnectBridge;

@protocol OpenConnectBridgeDelegate <NSObject>
- (void)ocBridge:(OpenConnectBridge *)bridge didChangeStatus:(OCStatus)status event:(NSString *)name info:(NSString *)info;
- (void)ocBridge:(OpenConnectBridge *)bridge didFailWithError:(NSError *)error;
- (void)ocBridge:(OpenConnectBridge *)bridge didLog:(NSString *)line;
@end

// NS_SWIFT_SENDABLE: this bridge is designed for cross-thread use and
// already is used that way — it owns its own engine thread, delivers
// delegate callbacks on that thread, and answers stats/pause calls from
// the provider's work queue. The annotation states that existing
// contract to Swift 6 rather than introducing it.
NS_SWIFT_SENDABLE
@interface OpenConnectBridge : NSObject

- (instancetype)initWithProvider:(NEPacketTunnelProvider *)provider
                        delegate:(id<OpenConnectBridgeDelegate>)delegate;

/// Authenticate and bring the tunnel up. Returns NO + `error` if setup fails to
/// start; connection progress arrives via the delegate.
- (BOOL)connectWithSettings:(OCClientSettings *)settings
                      error:(NSError * _Nullable * _Nullable)error;

/// Tear the connection down (returns quickly; final status via delegate).
- (void)disconnect;

/// Default-gateway ownership (PolicyRouting.md Tier 2 · Docs/StateMediators.md),
/// mirroring OpenVPN3Bridge. owned=YES ⇒ this tunnel advertises the default route
/// (0.0.0.0/0 · ::/0) — the full-tunnel owner. owned=NO ⇒ the default route is
/// suppressed while every specific pushed subnet (the gateway's split-include
/// routes) is STILL advertised: the tunnel is transparently demoted to split.
/// Live — it re-applies the captured tun settings with no reconnect (the CSTP
/// session and the packet pump are untouched); returns NO on apply failure.
- (BOOL)setDefaultRouteOwned:(BOOL)owned;

/// Establish-time seed of the same ownership gate, set from the desired role the
/// app passes in `startTunnel` options BEFORE the tun is built. Unlike
/// `setDefaultRouteOwned:` this does NOT re-apply settings (there is no live tun
/// yet) — it just records the flag so the very first `setup_tun` honours it,
/// keeping the ≤1-owner invariant robust to the app not reconciling live.
- (void)setInitialDefaultRouteOwned:(BOOL)owned;

/// Apply (or clear) the arbitrated system proxy on this tunnel's network settings
/// (Proxy mediator applier — Docs/StateMediators.md), mirroring OpenVPN3Bridge. The
/// mediator computes ONE proxy decision and the provider sends it here for the OWNER
/// egress only; `proxy == nil` clears it. Stored and merged into the captured tun
/// settings, then re-applied live (no reconnect). Returns NO on apply failure.
- (BOOL)applyProxySettings:(nullable NEProxySettings *)proxy NS_SWIFT_NAME(applyProxySettings(_:));

/// Apply (or clear) the arbitrated per-tunnel DNS on this tunnel's network settings
/// (DNS mediator applier — Docs/StateMediators.md), mirroring OpenVPN3Bridge. The
/// provider sends THIS engine's split-DNS slice here; `dns == nil` clears the override
/// and restores the captured/pushed DNS. Re-applied live (no reconnect). Returns NO on
/// apply failure.
- (BOOL)applyDNSSettings:(nullable NEDNSSettings *)dns NS_SWIFT_NAME(applyDNSSettings(_:));

/// Cumulative transport counters, for throughput sampling.
- (void)transportBytesIn:(int64_t *)bytesIn bytesOut:(int64_t *)bytesOut;

/// Connection topology for display (same keys as OpenVPN3Bridge.connectionInfo).
- (NSDictionary<NSString *, id> *)connectionInfo;

@end

NS_ASSUME_NONNULL_END
