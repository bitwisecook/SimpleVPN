// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
//  SSHBridge.h
//  Thin Objective-C surface over libssh2 for the in-process SSH engine. One
//  SSHSession owns a connected socket + libssh2 session; it opens channels for
//  the two transports we support in-process:
//    • direct-tcpip  — SOCKS (-D) and port-forwards (-L)
//    • tun@openssh.com — the net-tunnel (-w) mode (OpenSSH has no library, so we
//      speak its channel protocol directly on libssh2)
//  libssh2 sessions are single-threaded: the caller MUST serialise every call on
//  one queue. Blocking mode is used; timeouts bound the blocking calls.
//

#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

@interface SSHChannel : NSObject
/// Read up to len bytes; returns count, 0 on would-block (EAGAIN), negative on a
/// hard error, and 0 with isEOF set at clean end. Non-blocking once in data mode.
- (NSInteger)read:(void *)buffer maxLength:(NSInteger)len;
/// Write; returns bytes accepted (may be < len, or 0 on EAGAIN), negative on error.
- (NSInteger)write:(const void *)buffer length:(NSInteger)len;
- (BOOL)isEOF;
- (BOOL)isClosed;
/// MUST be called on the session's serial queue (frees libssh2 channel state).
- (void)close;
@end

@interface SSHSession : NSObject

/// Connect a TCP socket to host:port and run the libssh2 handshake.
- (BOOL)connectToHost:(NSString *)host port:(int)port
              timeout:(int)seconds error:(NSError * _Nullable * _Nullable)error;

/// The server host key fingerprint (SHA-256, hex) for known-hosts verification.
@property (nullable, readonly) NSString *hostKeyFingerprintSHA256;

/// Verify the server host key BEFORE authenticating (libssh2 does none of this
/// itself — skipping it is a MITM hole). Precedence: an explicit pinned SHA-256
/// wins; otherwise the OpenSSH known_hosts file at `knownHostsPath` is consulted.
/// `strict` is "yes" (fail on unknown/mismatch), "accept-new" (pin unknown hosts,
/// still fail on mismatch), or "no" (accept-new + tolerate, but mismatch still
/// fails — a changed key is always refused). Returns YES if the host is trusted.
- (BOOL)verifyHostKeyWithKnownHosts:(nullable NSString *)knownHostsPath
                                pin:(nullable NSString *)pinSHA256
                             strict:(NSString *)strict
                              error:(NSError * _Nullable * _Nullable)error;

/// Switch the session to non-blocking after auth, so channel reads/writes never
/// block the shared serial queue (kills head-of-line blocking between channels).
- (void)enterDataMode;

// Auth (try in order the caller prefers). Each returns YES on success.
- (BOOL)authPasswordForUser:(NSString *)user password:(NSString *)password
                      error:(NSError * _Nullable * _Nullable)error;
- (BOOL)authKeyForUser:(NSString *)user privateKeyPath:(NSString *)keyPath
            passphrase:(nullable NSString *)passphrase
                 error:(NSError * _Nullable * _Nullable)error;
- (BOOL)authAgentForUser:(NSString *)user error:(NSError * _Nullable * _Nullable)error;

/// Open a direct-tcpip channel to host:port through the server (SOCKS / -L).
- (nullable SSHChannel *)openDirectTCPIPToHost:(NSString *)host port:(int)port
                                         error:(NSError * _Nullable * _Nullable)error;

/// Open a tun@openssh.com channel for point-to-point net-tunnel (-w). `mode` is
/// 1 (point-to-point) or 2 (ethernet); `remoteUnit` is the server tun unit or -1.
- (nullable SSHChannel *)openTunChannelMode:(int)mode remoteUnit:(int)remoteUnit
                                       error:(NSError * _Nullable * _Nullable)error;

- (void)disconnect;

@end

NS_ASSUME_NONNULL_END
