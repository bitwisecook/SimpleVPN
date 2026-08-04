// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
//  SSHBridge.h
//  Thin Objective-C surface over libssh for the in-process SSH engine. One
//  SSHSession owns a connected libssh session; it opens channels for the two
//  transports we support in-process:
//    • direct-tcpip  — SOCKS (-D) and port-forwards (-L)
//    • tun@openssh.com — the net-tunnel (-w) mode (libssh has no public API for
//      that channel type, so the build script compiles a tiny wrapper into the
//      vendored library — see Tools/build-libssh-xcframework.sh)
//  libssh sessions are not thread-safe: the caller MUST serialise every call on
//  one queue. Blocking mode is used; SSH_OPTIONS_TIMEOUT bounds the blocking
//  calls.
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
/// MUST be called on the session's serial queue (frees libssh channel state).
- (void)close;
@end

/// What consulting known_hosts (or a pin) says about the key a server just
/// presented. Kept separate from `verifyHostKeyWithKnownHosts:` because the
/// staged probe must be able to ASK without the accept-new side effect of
/// writing a new entry — a diagnostic that silently trusts a new key would
/// destroy the very evidence the next real connection needs.
typedef NS_ENUM(NSInteger, SSHHostKeyStatus) {
    SSHHostKeyStatusMatch = 0,        ///< known, and this is the same key
    SSHHostKeyStatusMismatch = 1,     ///< known, and the key has CHANGED
    SSHHostKeyStatusNotFound = 2,     ///< no record of this host
    SSHHostKeyStatusUnavailable = 3,  ///< couldn't ask (no session / no key)
};

@interface SSHSession : NSObject

/// Connect a TCP socket to host:port and run the SSH handshake. libssh's own
/// ssh_config/ProxyCommand processing is disabled — the app's importer is the
/// only thing that reads OpenSSH config, and nothing may exec from a config.
- (BOOL)connectToHost:(NSString *)host port:(int)port
              timeout:(int)seconds error:(NSError * _Nullable * _Nullable)error;

/// The server host key fingerprint (SHA-256, hex) for known-hosts verification.
@property (nullable, readonly) NSString *hostKeyFingerprintSHA256;

/// The host key's algorithm ("ssh-ed25519", "ecdsa-sha2-nistp256", …) and its
/// wire-blob length in bytes — reported by the probe so a fingerprint has context.
@property (nullable, readonly) NSString *hostKeyType;
@property (readonly) NSInteger hostKeyLength;

/// What the handshake actually agreed on: keys "kex", "hostkey", "cipher",
/// "mac" (absent for AEAD ciphers, where the cipher authenticates itself).
/// Empty when the session isn't up.
@property (readonly) NSDictionary<NSString *, NSString *> *negotiatedMethods;

/// READ-ONLY known_hosts/pin check — never writes, never trusts on first use.
/// A non-empty `pinSHA256` decides on its own; otherwise known_hosts is read.
- (SSHHostKeyStatus)checkHostKeyWithKnownHosts:(nullable NSString *)knownHostsPath
                                           pin:(nullable NSString *)pinSHA256;

/// The authentication methods the server offers for `user` ("publickey",
/// "password", "keyboard-interactive", "gssapi-with-mic"…). This sends the
/// standard "none" request every SSH client sends before choosing a method; it
/// submits no credential. Returns an EMPTY array when the server let the user
/// straight in without any authentication at all.
- (nullable NSArray<NSString *> *)authMethodsForUser:(NSString *)user
                                               error:(NSError * _Nullable * _Nullable)error;

/// Verify the server host key BEFORE authenticating (skipping it is a MITM
/// hole). Precedence: an explicit pinned SHA-256 wins; otherwise the OpenSSH
/// known_hosts file at `knownHostsPath` is consulted.
/// `strict` is "yes" (fail on unknown/mismatch), "accept-new" (pin unknown hosts,
/// still fail on mismatch), or "no" (accept-new + tolerate, but mismatch still
/// fails — a changed key is always refused). Returns YES if the host is trusted.
- (BOOL)verifyHostKeyWithKnownHosts:(nullable NSString *)knownHostsPath
                                pin:(nullable NSString *)pinSHA256
                             strict:(NSString *)strict
                              error:(NSError * _Nullable * _Nullable)error;

/// YES when the last `verifyHostKeyWithKnownHosts:` trusted a previously-unknown
/// host on first use (accept-new / no) and appended it to known_hosts. Pair with
/// `hostKeyFingerprintSHA256` / `hostKeyType` to log exactly what was trusted —
/// TOFU must never be silent.
@property (readonly) BOOL acceptedNewHostKey;

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
/// Kerberos single sign-on (gssapi-with-mic) using the user's existing ticket —
/// a libssh capability libssh2 never had. Needs a ticket (kinit / AD login);
/// fails cleanly without one.
- (BOOL)authGSSAPIForUser:(NSString *)user error:(NSError * _Nullable * _Nullable)error;

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
