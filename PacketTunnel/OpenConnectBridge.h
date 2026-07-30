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

@interface OpenConnectBridge : NSObject

- (instancetype)initWithProvider:(NEPacketTunnelProvider *)provider
                        delegate:(id<OpenConnectBridgeDelegate>)delegate;

/// Authenticate and bring the tunnel up. Returns NO + `error` if setup fails to
/// start; connection progress arrives via the delegate.
- (BOOL)connectWithSettings:(OCClientSettings *)settings
                      error:(NSError * _Nullable * _Nullable)error;

/// Tear the connection down (returns quickly; final status via delegate).
- (void)disconnect;

/// Cumulative transport counters, for throughput sampling.
- (void)transportBytesIn:(int64_t *)bytesIn bytesOut:(int64_t *)bytesOut;

/// Connection topology for display (same keys as OpenVPN3Bridge.connectionInfo).
- (NSDictionary<NSString *, id> *)connectionInfo;

@end

NS_ASSUME_NONNULL_END
