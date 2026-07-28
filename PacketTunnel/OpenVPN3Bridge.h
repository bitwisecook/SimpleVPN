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

typedef NS_ENUM(NSInteger, OVPNStatus) {
    OVPNStatusDisconnected = 0,
    OVPNStatusConnecting,
    OVPNStatusConnected,
    OVPNStatusReconnecting,
    OVPNStatusDisconnecting,
};

@class OpenVPN3Bridge;

@protocol OpenVPN3BridgeDelegate <NSObject>
/// Lifecycle events from the engine (name is the openvpn3 event, e.g. CONNECTED, AUTH_FAILED).
- (void)bridge:(OpenVPN3Bridge *)bridge didChangeStatus:(OVPNStatus)status event:(NSString *)name info:(NSString *)info;
/// A fatal error occurred; the tunnel will not come up / has gone down.
- (void)bridge:(OpenVPN3Bridge *)bridge didFailWithError:(NSError *)error;
/// Verbose engine log line.
- (void)bridge:(OpenVPN3Bridge *)bridge didLog:(NSString *)line;
@end

@interface OpenVPN3Bridge : NSObject

- (instancetype)initWithProvider:(NEPacketTunnelProvider *)provider
                        delegate:(id<OpenVPN3BridgeDelegate>)delegate;

/// Start a connection. `ovpnConfig` is the full .ovpn text. username/password are
/// supplied to the server (password should already include any appended OTP).
/// Returns NO and populates `error` if the profile fails to evaluate.
- (BOOL)connectWithProfile:(NSString *)ovpnConfig
                  username:(NSString *)username
                  password:(NSString *)password
                     error:(NSError * _Nullable * _Nullable)error;

/// Stop the connection (returns quickly; completion arrives via delegate status).
- (void)disconnect;

/// Cumulative transport counters, for throughput sampling.
- (void)transportBytesIn:(int64_t *)bytesIn bytesOut:(int64_t *)bytesOut;

/// Connection topology captured from the tunnel setup, for display:
///   "server"   → NSString  (VPN server endpoint address)
///   "tunnelIP" → NSString  (assigned in-tunnel IPv4 address, or "")
///   "dns"      → NSArray<NSString *>  (pushed DNS servers)
///   "proxies"  → NSArray<NSString *>  (pushed HTTP/HTTPS proxies or PAC URL)
- (NSDictionary<NSString *, id> *)connectionInfo;

@end

NS_ASSUME_NONNULL_END
