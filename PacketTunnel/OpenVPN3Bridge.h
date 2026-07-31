// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only

//
//  OpenVPN3Bridge.h
//  Objective-C surface over the OpenVPN 3 ClientAPI (C++), for use from the
//  Swift NEPacketTunnelProvider. The bridge owns a background thread running
//  the openvpn3 event loop, maps TunBuilder callbacks onto
//  NEPacketTunnelNetworkSettings, and pumps IP packets between openvpn3 and
//  the provider's NEPacketTunnelFlow via a SOCK_DGRAM socketpair.
//

#import <Foundation/Foundation.h>
#import <NetworkExtension/NetworkExtension.h>

NS_ASSUME_NONNULL_BEGIN

/// NSError userInfo keys on bridge failures: the openvpn3 event name (e.g.
/// AUTH_FAILED) and its info line — the app classifies failures from these.
extern NSErrorUserInfoKey const OVPNErrorEventNameKey;
extern NSErrorUserInfoKey const OVPNErrorEventInfoKey;

typedef NS_ENUM(NSInteger, OVPNStatus) {
    OVPNStatusDisconnected = 0,
    OVPNStatusConnecting,
    OVPNStatusConnected,
    OVPNStatusReconnecting,
    OVPNStatusDisconnecting,
};

@class OpenVPN3Bridge;

/// Client-side engine options (ClientAPI::Config overrides). Every property is
/// nullable; nil means "leave the engine's compiled-in default untouched" — the
/// bridge assigns only non-nil values onto ClientAPI::Config. Built from the
/// Swift OpenVPNOverrides model (raw enum tokens / NSNumber-wrapped bools+ints);
/// the two passwords are keychain-sourced at connect time and never persisted.
@interface OVPNClientSettings : NSObject

// Connection
@property (nullable, copy) NSString *serverOverride;
@property (nullable, copy) NSString *portOverride;          // digits, 1...65535
@property (nullable, copy) NSString *protoOverride;         // "udp" | "tcp" | "adaptive"
@property (nullable, strong) NSNumber *protoVersionOverride;        // int: 4 | 6
@property (nullable, strong) NSNumber *connTimeout;                 // int seconds; 0 = retry forever

// Reliability
@property (nullable, strong) NSNumber *tunPersist;                  // bool
@property (nullable, strong) NSNumber *retryOnAuthFailed;           // bool
@property (nullable, strong) NSNumber *autologinSessions;           // bool (engine default: true)

// Network & privacy
@property (nullable, strong) NSNumber *allowLocalLanAccess;         // bool
@property (nullable, copy) NSString *allowUnusedAddrFamilies; // "yes" | "no"
@property (nullable, strong) NSNumber *googleDnsFallback;           // bool

// Security
@property (nullable, copy) NSString *tlsVersionMinOverride;   // "disabled" | "tls_1_2" | "tls_1_3"
@property (nullable, copy) NSString *tlsCertProfileOverride;  // "legacy" | "preferred" | "suiteb" | "legacy-default" | "preferred-default"
@property (nullable, copy) NSString *compressionMode;         // "no" | "asym" | "yes"
@property (nullable, strong) NSNumber *enableLegacyAlgorithms;        // bool
@property (nullable, strong) NSNumber *enableNonPreferredDCAlgorithms; // bool
@property (nullable, copy) NSString *tlsCipherList;
@property (nullable, copy) NSString *tlsCiphersuitesList;
@property (nullable, strong) NSNumber *disableClientCert;           // bool
@property (nullable, strong) NSNumber *defaultKeyDirection;         // int: -1 | 0 | 1

// Proxy
@property (nullable, copy) NSString *proxyHost;
@property (nullable, copy) NSString *proxyPort;             // digits, 1...65535
@property (nullable, copy) NSString *proxyUsername;
@property (nullable, strong) NSNumber *proxyAllowCleartextAuth;     // bool

// Troubleshooting
@property (nullable, strong) NSNumber *sslDebugLevel;               // int 0...9
@property (nullable, strong) NSNumber *synchronousDnsLookup;        // bool

// Keychain-sourced secrets (session payload, read-once; never in providerConfiguration)
@property (nullable, copy) NSString *proxyPassword;
@property (nullable, copy) NSString *privateKeyPassword;

@end

@protocol OpenVPN3BridgeDelegate <NSObject>
/// Lifecycle events from the engine (name is the openvpn3 event, e.g. CONNECTED, AUTH_FAILED).
- (void)bridge:(OpenVPN3Bridge *)bridge didChangeStatus:(OVPNStatus)status event:(NSString *)name info:(NSString *)info;
/// A fatal error occurred; the tunnel will not come up / has gone down.
- (void)bridge:(OpenVPN3Bridge *)bridge didFailWithError:(NSError *)error;
/// Verbose engine log line.
- (void)bridge:(OpenVPN3Bridge *)bridge didLog:(NSString *)line;
@end

// NS_SWIFT_SENDABLE: this bridge is designed for cross-thread use and
// already is used that way — it owns its own engine thread, delivers
// delegate callbacks on that thread, and answers stats/pause calls from
// the provider's work queue. The annotation states that existing
// contract to Swift 6 rather than introducing it.
NS_SWIFT_SENDABLE
@interface OpenVPN3Bridge : NSObject

- (instancetype)initWithProvider:(NEPacketTunnelProvider *)provider
                        delegate:(id<OpenVPN3BridgeDelegate>)delegate;

/// Start a connection. `ovpnConfig` is the full .ovpn text. username/password are
/// supplied to the server (password should already include any appended OTP).
/// `settings` carries per-VPN engine overrides; nil (or nil properties) leaves the
/// engine defaults untouched. Returns NO and populates `error` if the profile
/// fails to evaluate.
- (BOOL)connectWithProfile:(NSString *)ovpnConfig
                  username:(NSString *)username
                  password:(NSString *)password
                  settings:(nullable OVPNClientSettings *)settings
                     error:(NSError * _Nullable * _Nullable)error;

/// Stop the connection (returns quickly; completion arrives via delegate status).
- (void)disconnect;

/// Pause the engine (transport closed, TLS session kept — resume needs no re-auth).
/// The tun settings stay as-is; combine with reapplyTunSettingsIncludingRoutes:
/// to control what happens to traffic while paused.
- (void)pauseWithReason:(NSString *)reason;

/// Resume a paused engine (reconnects the transport under the kept session).
- (void)resume;

/// Re-apply the captured tunnel network settings. includeRoutes=YES restores the
/// normal captured routes/DNS; NO strips routes and DNS so traffic bypasses the
/// tunnel over the physical interface (deliberate leak — the "bypass" pause mode).
/// Returns NO if the settings could not be applied.
- (BOOL)reapplyTunSettingsIncludingRoutes:(BOOL)includeRoutes;

/// Cumulative transport counters, for throughput sampling.
- (void)transportBytesIn:(int64_t *)bytesIn bytesOut:(int64_t *)bytesOut;

/// Connection topology for display, merged from the engine's ConnectionInfo
/// (when connected) and the captured tun setup:
///   "server"        → NSString  (VPN server endpoint address)
///   "serverIP"      → NSString  (resolved transport address, or "")
///   "serverPort"    → NSString  (transport port, or "")
///   "serverProto"   → NSString  (transport protocol, or "")
///   "tunnelIP"      → NSString  (assigned in-tunnel IPv4 address, or "")
///   "tunnelIPv6"    → NSString  (assigned in-tunnel IPv6 address, or "")
///   "gateway4"      → NSString  (in-tunnel IPv4 gateway, or "")
///   "gateway6"      → NSString  (in-tunnel IPv6 gateway, or "")
///   "mtu"           → NSNumber  (tunnel MTU)
///   "dns"           → NSArray<NSString *>  (pushed DNS servers)
///   "searchDomains" → NSArray<NSString *>  (pushed DNS search domains)
///   "proxies"       → NSArray<NSString *>  (pushed HTTP/HTTPS proxies or PAC URL)
- (NSDictionary<NSString *, id> *)connectionInfo;

/// Observed traffic flows since the tunnel came up, for the app's per-VPN traffic
/// log. Each entry keys off the remote endpoint and carries byte/packet counts and
/// recency. Only IP/L4 headers are inspected — no payload.
- (NSArray<NSDictionary<NSString *, id> *> *)flowStats;

/// Destinations to route *around* this VPN (the "send outside the VPN" divert
/// rule), merged into the tunnel's excluded routes. Set before connect. Each
/// entry: @{ "address": NSString, "prefix": NSNumber, "ipv6": NSNumber(bool) }.
- (void)setDivertedDestinations:(NSArray<NSDictionary<NSString *, id> *> *)dests;

/// Destinations another VPN routes *into* this one (the "over another VPN" target
/// side), merged into this tunnel's included routes. Same entry shape as above.
- (void)setIncludedDestinations:(NSArray<NSDictionary<NSString *, id> *> *)dests;

@end

NS_ASSUME_NONNULL_END
