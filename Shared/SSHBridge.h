// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
//  SSHBridge.h
//  Thin Objective-C surface over libssh for the in-process SSH engine. One
//  SSHSession owns a connected libssh session. `direct-tcpip` is the transport both
//  in-process callers actually use; the tun@openssh.com channel is built but unused
//  (see the channel-type list below).
//
//  WHY THIS LIVES IN Shared/ AND NOT IN THE APP: two targets drive libssh now —
//  the app (SSHTunnelEngine: SOCKS, port forwards, the staged probe) and the
//  packet-tunnel system extension (SSHNetworkTunnelEngine: one direct-tcpip
//  channel per netstack flow). Shared/ is a whole-directory source on BOTH
//  targets, so there is no per-target file list to drift. Do NOT leave a copy
//  behind in the app: the same .m compiled twice is duplicate Objective-C
//  symbols at link time.
//
//  THREE SANDBOX FACTS ARE LOAD-BEARING IN THE EXTENSION and none of them is
//  true in the app, so the two callers use different halves of this API:
//    • no key FILE — the extension runs as root in the system context and
//      cannot read the user's ~/.ssh, so it uses the PEM-blob auth below;
//    • no known_hosts — for the same reason, plus it must never WRITE one, so
//      it is pin-only (the app resolves trust and passes the fingerprint);
//    • no agent and no Kerberos — SSH_AUTH_SOCK and the ticket cache belong to
//      the user's session, which the extension is not in.
//
//  The channel types:
//    • direct-tcpip  — SOCKS (-D) and port-forwards (-L)
//    • tun@openssh.com — the net-tunnel (-w) mode. Built and available (libssh has no
//      public API for that channel type, so the build script compiles a tiny wrapper
//      into the vendored library — see Tools/build-libssh-xcframework.sh) but with NO
//      CALLER yet: `-w` still runs through /usr/bin/ssh, and the SSH Network Tunnel
//      kind uses per-flow direct-tcpip instead (no server-side root / PermitTunnel)
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
/// Send channel EOF — "I have nothing more to send" — WITHOUT closing the channel,
/// so the other direction stays readable. This is the half-close every
/// request/response protocol that ends its request with a FIN depends on: close the
/// channel outright instead and the answer already on its way is discarded.
/// (`isEOF` is the mirror image: the SERVER's half-close arriving here.)
///
/// MUST be called on the session's serial queue. NO when the request couldn't be
/// written — including a would-block, which is not fatal: call it again.
- (BOOL)sendEOF;
/// MUST be called on the session's serial queue (frees libssh channel state).
- (void)close;
@end

/// The `code` on an NSError from this bridge (domain "SSHBridge"). Everything
/// that isn't agent sign-in reports `SSHBridgeErrorGeneric` — the message is the
/// payload there. AGENT sign-in is the exception: its three real-world failures
/// need three different pieces of advice, and libssh cannot tell them apart on
/// its own (see `authAgentForUser:error:`), so the code says exactly what libssh
/// reported and the caller refines it with what it knows about the agent.
typedef NS_ENUM(NSInteger, SSHBridgeErrorCode) {
    SSHBridgeErrorGeneric = 1,
    /// SSH_AUTH_DENIED from `ssh_userauth_agent`. AMBIGUOUS BY LIBSSH'S DESIGN:
    /// it is returned for "no agent answered", "the agent offered no identity"
    /// AND "the server refused every identity the agent offered" alike
    /// (libssh 0.12.2 src/auth.c). The caller must consult the agent itself to
    /// choose between them.
    SSHBridgeErrorAgentDenied = 20,
    /// SSH_AUTH_PARTIAL: an agent key WAS accepted, and the server wants a
    /// further step as well.
    SSHBridgeErrorAgentPartial = 21,
    /// SSH_AUTH_ERROR: the exchange itself broke (transport or agent protocol).
    SSHBridgeErrorAgentTransport = 22,
};

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

/// Same, with an explicit key-exchange preference (OpenSSH KexAlgorithms
/// syntax, comma-separated; nil/empty keeps libssh's default list — which
/// already prefers the post-quantum hybrids this build ships). A list libssh
/// can't parse or fulfil fails the connect with a clear error rather than
/// silently negotiating something else.
- (BOOL)connectToHost:(NSString *)host port:(int)port
              timeout:(int)seconds
        kexAlgorithms:(nullable NSString *)kexAlgorithms
                error:(NSError * _Nullable * _Nullable)error;

/// Same again, plus transport compression (`ssh -C` / `Compression yes`). It is
/// negotiated during key exchange, so it can only be asked for BEFORE connecting;
/// a server that doesn't offer zlib simply runs uncompressed, like ssh(1).
- (BOOL)connectToHost:(NSString *)host port:(int)port
              timeout:(int)seconds
        kexAlgorithms:(nullable NSString *)kexAlgorithms
          compression:(BOOL)compression
                error:(NSError * _Nullable * _Nullable)error;

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
/// Key auth presenting an OpenSSH certificate (…-cert.pub) alongside the
/// private key — the CA-signed sign-in flow libssh2 never had. A nil/empty
/// certificatePath is plain key auth.
- (BOOL)authKeyForUser:(NSString *)user privateKeyPath:(NSString *)keyPath
       certificatePath:(nullable NSString *)certificatePath
            passphrase:(nullable NSString *)passphrase
                 error:(NSError * _Nullable * _Nullable)error;
/// Key auth from an IN-MEMORY PEM blob rather than a file — the only key auth
/// the packet-tunnel extension can do. It runs as root in the system context and
/// cannot read the user's ~/.ssh, so the app reads the key, keeps it in memory,
/// and hands it over in `startTunnel(options:)`. `certificatePEM` is an optional
/// OpenSSH certificate (the …-cert.pub text) grafted onto the key, same as the
/// file-based call. `passphrase` unlocks an encrypted key.
///
/// The blob is zeroed before this returns: it is the one credential that would
/// otherwise sit in a released NSString's freed pages.
- (BOOL)authKeyForUser:(NSString *)user
         privateKeyPEM:(NSString *)privateKeyPEM
        certificatePEM:(nullable NSString *)certificatePEM
            passphrase:(nullable NSString *)passphrase
                 error:(NSError * _Nullable * _Nullable)error;

/// Point this session's agent lookups at ONE specific listening socket instead
/// of whatever `SSH_AUTH_SOCK` says (libssh's `SSH_OPTIONS_IDENTITY_AGENT`, the
/// same knob as OpenSSH's `IdentityAgent`). Tilde paths are expanded by libssh.
///
/// WHY THIS EXISTS: the agents worth having on a Mac do not live at the socket a
/// GUI app inherits. `SSH_AUTH_SOCK` in a windowed app comes from the user's
/// launchd session (macOS's own ssh-agent); 1Password, Secretive and any other
/// vendor agent listen in their own container, and users point at them with a
/// line in a shell profile that an app launched from the Dock never reads. This
/// is how a VPN gets to those keys.
///
/// Call it BEFORE `authAgentForUser:` (the option is read when the agent is
/// first contacted). An empty path is rejected rather than quietly meaning
/// "default" — libssh treats "" as an error, and so should the caller's config.
- (BOOL)useAgentSocketPath:(NSString *)path error:(NSError * _Nullable * _Nullable)error;

/// Sign in with the keys an SSH agent holds — 1Password, Secretive (Secure
/// Enclave), KeePassXC, a hardware token behind ssh-agent — so the private key
/// never leaves the vault. libssh asks the agent to sign; we never see the key.
///
/// ON FAILURE the NSError's `code` is one of `SSHBridgeErrorCode`'s agent cases.
/// `SSHBridgeErrorAgentDenied` deliberately does NOT distinguish "no agent" from
/// "agent with no keys" from "server said no" — libssh returns SSH_AUTH_DENIED
/// for all three — so the message here is the neutral one and the caller (which
/// can ask the agent how many identities it holds) is what turns it into advice.
/// See SimpleVPN/ControlPlane/SSHAgent.swift.
///
/// NOT USABLE FROM THE PACKET-TUNNEL EXTENSION: it runs as root in the system
/// context, has no `SSH_AUTH_SOCK`, and must not reach into a user's session.
- (BOOL)authAgentForUser:(NSString *)user error:(NSError * _Nullable * _Nullable)error;
/// Kerberos single sign-on (gssapi-with-mic) using the user's existing ticket —
/// a libssh capability libssh2 never had. Needs a ticket (kinit / AD login);
/// fails cleanly without one.
- (BOOL)authGSSAPIForUser:(NSString *)user error:(NSError * _Nullable * _Nullable)error;

/// Block until the session's socket has something to say, then let libssh
/// process it — the ONE call that lets a multi-channel reader loop be event
/// driven instead of polled.
///
/// This exists because the alternative is a timer. A session carrying N netstack
/// flows has to notice incoming data on any of them, and `ssh_channel_read_nonblocking`
/// only reports what libssh has ALREADY parsed off the socket; something must
/// pump the transport. The subprocess-era engine did that with a 3ms/20ms
/// dispatch timer, which on this path would mean waking the session queue fifty
/// times a second forever and adding up to 20 ms of latency to every packet.
/// This waits on the real fd instead: idle costs nothing, and a packet is
/// processed the moment it lands.
///
/// It is NOT `ssh_event_dopoll(event, ms)`, which was the obvious implementation
/// and does not work: libssh re-arms POLLOUT on the session socket after every
/// write, so dopoll on a connected (therefore always-writable) socket returns
/// immediately, forever — a 100% CPU spin that also starves everything else
/// queued behind it. Measured, not theorised; see the long comment on the
/// implementation. dopoll is used with a ZERO timeout for its packet processing,
/// and the waiting is a plain `poll()`.
///
/// Returns:  1  the poll processed something (or the timeout expired cleanly —
///              the caller must sweep its channels either way);
///           0  the timeout expired with nothing to do;
///          -1  the session is gone or libssh reported a hard error — the
///              caller must treat it as session loss and reconnect.
///
/// MUST be called on the session's serial queue like every other call here, and
/// it BLOCKS that queue for up to `ms`. That would starve every other caller on
/// that queue — a flow with bytes to send, a channel waiting to open — which is
/// what `wakeActivityWait` is for: call it from any thread first and the wait in
/// progress returns at once, releasing the queue.
- (int)waitForActivityWithTimeoutMs:(int)ms;

/// Interrupt a `waitForActivityWithTimeoutMs:` in progress so the session queue
/// becomes free. Thread-safe and callable from ANY thread (it is a one-byte write
/// to a pipe the poll set watches) — unlike every other method here. Cheap enough
/// to call before each queued libssh call; harmless when nothing is waiting.
- (void)wakeActivityWait;

/// Send a session keepalive ("keepalive@openssh.com", reply requested) — the
/// in-process equivalent of `ssh -o ServerAliveInterval`. MUST be called on the
/// session's serial queue like every other call here. NO when there is no
/// session or the request couldn't be written.
- (BOOL)sendKeepalive;

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
