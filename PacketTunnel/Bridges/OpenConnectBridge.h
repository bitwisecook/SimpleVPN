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

/// Everything below was a REFUSAL rather than a setting until now: each one is a
/// single `openconnect_set_*` call, and because none of them was plumbed, a profile
/// that set any of them was sent back to the `openconnect` subprocess under
/// `ocproxy -D <port>` — a SOCKS listener with no interface, no routes and no DNS.
/// The gate that used to name them is `SubprocessTunnelManager.inProcessOpenConnectSupports`,
/// and it is now down to what libopenconnect genuinely cannot express here.
///
/// `nil` / `0` means "not set" throughout — the engine's own default stands. Nothing
/// here is a secret except `privateKeyPassword` and `proxyPassword`, which arrive in
/// `startTunnel(options:)` and never touch `providerConfiguration`.

/// `--usergroup`: the URL PATH openconnect appends. GlobalProtect's
/// portal-vs-gateway choice, and the path Juniper and Pulse expect.
@property (nullable, copy) NSString *urlPath;
/// `--os`: one of linux, linux-64, win, mac-intel, android, apple-ios.
@property (nullable, copy) NSString *reportedOS;
/// `--version-string`: the client version reported to the gateway.
@property (nullable, copy) NSString *versionString;
/// `--local-hostname`: the computer name reported instead of this Mac's own.
@property (nullable, copy) NSString *localName;
/// `--certificate` / `--sslkey`: client certificate sign-in from files on disk.
/// A PKCS#11 URI is NOT accepted here — this libopenconnect is built
/// `--with-openssl --without-gnutls` and has no PKCS#11 backend.
@property (nullable, copy) NSString *clientCertFile;
@property (nullable, copy) NSString *clientKeyFile;
/// `--key-password`: the passphrase for an encrypted key / PKCS#12. SECRET.
@property (nullable, copy) NSString *privateKeyPassword;
/// `--proxy`: the web proxy the GATEWAY is reached through, resolved in the app
/// (the root extension sees a different SystemConfiguration view). Credentials are
/// separate rather than embedded, which the subprocess has no way to do.
@property (nullable, copy) NSString *proxy;
@property (nullable, copy) NSString *proxyUsername;
@property (nullable, copy) NSString *proxyPassword;   // SECRET
/// `--compression`: "none" | "stateless" | "all". Anything else is ignored here and
/// refused by the gate, because guessing which of the three was meant is exactly the
/// silent substitution the gate exists to prevent.
@property (nullable, copy) NSString *compression;
@property (assign) BOOL pfs;            // --pfs
@property (assign) BOOL disableIPv6;    // --disable-ipv6
@property (assign) BOOL disableDTLS;    // --no-dtls
@property (assign) int mtu;             // --mtu (the TUNNEL's MTU; 0 = pushed)
@property (assign) int dpd;             // --force-dpd, seconds (0 = protocol default)
/// `--reconnect-timeout`, seconds. Not a setter at all: it is the second argument
/// to `openconnect_mainloop`, which is why it is the one entry on the old refusal
/// list that could not have been fixed by adding a call during setup.
///
/// An NSNumber and not an `int` because **0 is a legal value here** — the config's
/// own range is `0...86400` and 0 means "give up immediately". Using 0 as the
/// "unset" sentinel (which is right for `mtu`, whose floor is 576) would silently
/// turn "give up at once" into "retry for five minutes". nil = the engine's 300s.
@property (nullable, strong) NSNumber *reconnectTimeout;
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

/// Divert rules (`Shared/RoutingRule.swift` · `DivertPlan`), mirroring
/// OpenVPN3Bridge: destinations to route AROUND this VPN become excluded routes.
/// Each entry is `@{ "address": NSString, "prefix": NSNumber, "ipv6": NSNumber }`
/// — `RouteDest.dictionary`. Set BEFORE `connectWithSettings:` so the first
/// `setup_tun` carries them; a later call takes effect on the next settings
/// re-apply (gateway flip / proxy or DNS apply).
- (void)setDivertedDestinations:(NSArray<NSDictionary<NSString *, id> *> *)dests;

/// The other half: destinations another VPN routes INTO this one (the `.overVPN`
/// target side) become included routes, so the OS hands them to this tunnel.
- (void)setIncludedDestinations:(NSArray<NSDictionary<NSString *, id> *> *)dests;

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
