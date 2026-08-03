// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
//  SSHBridge.m
//  libssh2 wrapper (blocking mode). Single-threaded per session — the Swift
//  engine drives all calls on one serial queue. See SSHBridge.h.
//

#import "SSHBridge.h"
#import <libssh2.h>
#import <os/log.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <netdb.h>
#include <unistd.h>
#include <fcntl.h>
#include <arpa/inet.h>

static NSErrorDomain const kSSHErrorDomain = @"SSHBridge";
static os_log_t gSSHLog(void) {
    static os_log_t log;
    static dispatch_once_t once;
    dispatch_once(&once, ^{ log = os_log_create("com.bragi0.SimpleVPN", "libssh2"); });
    return log;
}

/// libssh2's own account of the handshake, key exchange and auth negotiation.
///
/// Without this, an SSH tunnel that fails to come up leaves NOTHING in a diagnostics
/// bundle from the library that actually failed — the app can only report "the SSH
/// handshake failed", which is a symptom, not a cause. Requires the xcframework to be
/// built with -DENABLE_DEBUG_LOGGING (see Tools/build-libssh2-xcframework.sh); without
/// that define libssh2_trace* are compiled out and this never runs.
///
/// Logged at DEFAULT level, not debug: os_log discards debug messages rather than
/// persisting them, which would make the trace unavailable after the fact — the exact
/// trap that had been hiding the OpenVPN handshake.
static void ssh_trace(LIBSSH2_SESSION *session, void *context,
                      const char *data, size_t length) {
    (void)session; (void)context;
    if (!data || length == 0) return;
    NSString *line = [[NSString alloc] initWithBytes:data length:length
                                           encoding:NSUTF8StringEncoding];
    if (!line) return;
    line = [line stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceAndNewlineCharacterSet]];
    if (line.length == 0) return;
    os_log(gSSHLog(), "%{public}s", line.UTF8String);
}

static NSError *sshErr(NSString *m) {
    return [NSError errorWithDomain:kSSHErrorDomain code:1 userInfo:@{ NSLocalizedDescriptionKey: m }];
}

// Compare only the hex tail after any "sha256:"/"pin-sha256:" prefix, lowercased,
// as exact equality (a suffix compare would let a truncated pin match).
static NSString *hexTail(NSString *s) {
    NSRange c = [s rangeOfString:@":" options:NSBackwardsSearch];
    return [(c.location == NSNotFound ? s : [s substringFromIndex:c.location + 1]) lowercaseString];
}

@interface SSHChannel ()
@property (assign) LIBSSH2_CHANNEL *chan;
@end

@implementation SSHChannel
- (instancetype)initWithChannel:(LIBSSH2_CHANNEL *)c { if ((self = [super init])) _chan = c; return self; }
- (NSInteger)read:(void *)buffer maxLength:(NSInteger)len {
    if (!_chan) return -1;
    ssize_t n = libssh2_channel_read(_chan, (char *)buffer, (size_t)len);
    return n == LIBSSH2_ERROR_EAGAIN ? 0 : n;
}
- (NSInteger)write:(const void *)buffer length:(NSInteger)len {
    if (!_chan) return -1;
    ssize_t n = libssh2_channel_write(_chan, (const char *)buffer, (size_t)len);
    return n == LIBSSH2_ERROR_EAGAIN ? 0 : n;
}
- (BOOL)isEOF { return _chan ? (libssh2_channel_eof(_chan) != 0) : YES; }
- (BOOL)isClosed { return _chan == NULL; }
- (void)close {
    if (_chan) { libssh2_channel_close(_chan); libssh2_channel_free(_chan); _chan = NULL; }
}
- (void)dealloc {
    // Do NOT touch libssh2 here: dealloc runs on whatever thread releases the last
    // reference (typically an NWConnection callback thread), and libssh2 session
    // state is single-threaded. The engine closes every channel explicitly on the
    // session queue; any channel still open at dealloc is reclaimed by
    // libssh2_session_free at teardown. Freeing here would be a cross-thread UAF.
    if (_chan) { /* leaked to session teardown on purpose — safety over the leak */ }
}
@end

@implementation SSHSession {
    int _sock;
    LIBSSH2_SESSION *_session;
    NSString *_fp;
    NSString *_host;
    int _port;
    BOOL _acceptedNewHostKey;
}

+ (void)initialize { if (self == [SSHSession class]) libssh2_init(0); }

- (instancetype)init { if ((self = [super init])) { _sock = -1; } return self; }

- (BOOL)connectToHost:(NSString *)host port:(int)port timeout:(int)seconds error:(NSError **)error {
    struct addrinfo hints = {0}, *res = NULL;
    hints.ai_family = AF_UNSPEC; hints.ai_socktype = SOCK_STREAM;
    char portstr[8]; snprintf(portstr, sizeof(portstr), "%d", port);
    if (getaddrinfo(host.UTF8String, portstr, &hints, &res) != 0 || !res) {
        if (error) *error = sshErr(@"Couldn't resolve the SSH server address."); return NO;
    }
    int s = -1;
    for (struct addrinfo *ai = res; ai; ai = ai->ai_next) {
        s = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);
        if (s < 0) continue;
        struct timeval tv = { .tv_sec = seconds, .tv_usec = 0 };
        setsockopt(s, SOL_SOCKET, SO_RCVTIMEO, &tv, sizeof(tv));
        setsockopt(s, SOL_SOCKET, SO_SNDTIMEO, &tv, sizeof(tv));
        if (connect(s, ai->ai_addr, ai->ai_addrlen) == 0) break;
        close(s); s = -1;
    }
    freeaddrinfo(res);
    if (s < 0) { if (error) *error = sshErr(@"Couldn't connect to the SSH server."); return NO; }
    _sock = s;
    _host = [host copy];
    _port = port;

    _session = libssh2_session_init();
    if (!_session) { if (error) *error = sshErr(@"Couldn't initialise the SSH session."); return NO; }

    // Trace BEFORE the handshake, so key exchange and auth negotiation are captured —
    // that's where SSH tunnels actually fail.
    //
    // The mask is chosen deliberately. TRANS/SOCKET are omitted: they emit per-packet
    // byte-level detail, which is both enormous and the channel most likely to carry
    // fragments of authentication material into a log the user may share. ERROR/KEX/AUTH/
    // CONN give the negotiation story — cipher and MAC chosen, which auth methods the
    // server offered and which were tried, channel open/close — with no payload.
    libssh2_trace_sethandler(_session, NULL, ssh_trace);
    libssh2_trace(_session, LIBSSH2_TRACE_ERROR | LIBSSH2_TRACE_KEX |
                            LIBSSH2_TRACE_AUTH  | LIBSSH2_TRACE_CONN);

    libssh2_session_set_blocking(_session, 1);
    if (libssh2_session_handshake(_session, _sock) != 0) {
        if (error) *error = sshErr(@"The SSH handshake failed."); return NO;
    }
    const char *h = libssh2_hostkey_hash(_session, LIBSSH2_HOSTKEY_HASH_SHA256);
    if (h) {
        NSMutableString *fp = [NSMutableString string];
        for (int i = 0; i < 32; i++) [fp appendFormat:@"%02x", (unsigned char)h[i]];
        _fp = fp;
    }
    return YES;
}

- (NSString *)hostKeyFingerprintSHA256 { return _fp; }

static NSString *hostKeyTypeName(int ktype) {
    switch (ktype) {
        case LIBSSH2_HOSTKEY_TYPE_RSA:       return @"ssh-rsa";
        case LIBSSH2_HOSTKEY_TYPE_DSS:       return @"ssh-dss";
        case LIBSSH2_HOSTKEY_TYPE_ECDSA_256: return @"ecdsa-sha2-nistp256";
        case LIBSSH2_HOSTKEY_TYPE_ECDSA_384: return @"ecdsa-sha2-nistp384";
        case LIBSSH2_HOSTKEY_TYPE_ECDSA_521: return @"ecdsa-sha2-nistp521";
        case LIBSSH2_HOSTKEY_TYPE_ED25519:   return @"ssh-ed25519";
        default: return nil;
    }
}

- (NSString *)hostKeyType {
    if (!_session) return nil;
    size_t klen = 0; int ktype = 0;
    if (!libssh2_session_hostkey(_session, &klen, &ktype)) return nil;
    return hostKeyTypeName(ktype) ?: [NSString stringWithFormat:@"key type %d", ktype];
}

- (NSInteger)hostKeyLength {
    if (!_session) return 0;
    size_t klen = 0; int ktype = 0;
    if (!libssh2_session_hostkey(_session, &klen, &ktype)) return 0;
    return (NSInteger)klen;
}

- (NSDictionary<NSString *, NSString *> *)negotiatedMethods {
    if (!_session) return @{};
    NSMutableDictionary *out = [NSMutableDictionary dictionary];
    struct { NSString *name; int method; } wanted[] = {
        { @"kex",         LIBSSH2_METHOD_KEX },
        { @"hostkey",     LIBSSH2_METHOD_HOSTKEY },
        { @"cipher",      LIBSSH2_METHOD_CRYPT_CS },
        { @"mac",         LIBSSH2_METHOD_MAC_CS },
        { @"compression", LIBSSH2_METHOD_COMP_CS },
    };
    for (size_t i = 0; i < sizeof(wanted) / sizeof(wanted[0]); i++) {
        const char *value = libssh2_session_methods(_session, wanted[i].method);
        if (value) out[wanted[i].name] = @(value);
    }
    return out;
}

- (SSHHostKeyStatus)checkHostKeyWithKnownHosts:(NSString *)knownHostsPath
                                           pin:(NSString *)pinSHA256 {
    if (!_session) return SSHHostKeyStatusUnavailable;

    if (pinSHA256.length) {
        if (!_fp.length) return SSHHostKeyStatusUnavailable;
        return [hexTail(_fp) isEqualToString:hexTail(pinSHA256)]
            ? SSHHostKeyStatusMatch : SSHHostKeyStatusMismatch;
    }

    size_t klen = 0; int ktype = 0;
    const char *hostkey = libssh2_session_hostkey(_session, &klen, &ktype);
    if (!hostkey) return SSHHostKeyStatusUnavailable;

    LIBSSH2_KNOWNHOSTS *kh = libssh2_knownhost_init(_session);
    if (!kh) return SSHHostKeyStatusUnavailable;
    if (knownHostsPath.length) {
        libssh2_knownhost_readfile(kh, knownHostsPath.UTF8String, LIBSSH2_KNOWNHOST_FILE_OPENSSH);
    }
    int typemask = LIBSSH2_KNOWNHOST_TYPE_PLAIN | LIBSSH2_KNOWNHOST_KEYENC_RAW;
    struct libssh2_knownhost *known = NULL;
    int check = libssh2_knownhost_checkp(kh, _host.UTF8String, _port, hostkey, klen,
                                         typemask, &known);
    // Deliberately no libssh2_knownhost_addc/writefile here: see SSHHostKeyStatus.
    libssh2_knownhost_free(kh);

    switch (check) {
        case LIBSSH2_KNOWNHOST_CHECK_MATCH:    return SSHHostKeyStatusMatch;
        case LIBSSH2_KNOWNHOST_CHECK_MISMATCH: return SSHHostKeyStatusMismatch;
        case LIBSSH2_KNOWNHOST_CHECK_NOTFOUND: return SSHHostKeyStatusNotFound;
        default:                               return SSHHostKeyStatusUnavailable;
    }
}

- (NSArray<NSString *> *)authMethodsForUser:(NSString *)user error:(NSError **)error {
    if (!_session) {
        if (error) *error = sshErr(@"No SSH session to ask.");
        return nil;
    }
    const char *list = libssh2_userauth_list(_session, user.UTF8String,
                                             (unsigned int)strlen(user.UTF8String));
    if (!list) {
        // A NULL list with the session marked authenticated means the server
        // accepted "none" — an open server, which is worth reporting as such.
        if (libssh2_userauth_authenticated(_session)) return @[];
        if (error) *error = sshErr(@"The server didn't say how it wants you to sign in.");
        return nil;
    }
    NSArray<NSString *> *methods = [@(list) componentsSeparatedByString:@","];
    NSMutableArray<NSString *> *out = [NSMutableArray array];
    for (NSString *m in methods) {
        NSString *t = [m stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceCharacterSet]];
        if (t.length) [out addObject:t];
    }
    return out;
}

- (BOOL)verifyHostKeyWithKnownHosts:(NSString *)knownHostsPath
                                pin:(NSString *)pinSHA256
                             strict:(NSString *)strict
                              error:(NSError **)error {
    if (!_session) { if (error) *error = sshErr(@"No SSH session to verify."); return NO; }
    _acceptedNewHostKey = NO;

    // Pin takes precedence: exact SHA-256 match or nothing.
    if (pinSHA256.length) {
        if (_fp.length && [hexTail(_fp) isEqualToString:hexTail(pinSHA256)]) return YES;
        if (error) *error = sshErr(@"The SSH server's host key doesn't match the pinned fingerprint.");
        return NO;
    }

    // Otherwise consult OpenSSH known_hosts.
    size_t klen = 0; int ktype = 0;
    const char *hostkey = libssh2_session_hostkey(_session, &klen, &ktype);
    if (!hostkey) { if (error) *error = sshErr(@"The SSH server didn't present a host key."); return NO; }

    LIBSSH2_KNOWNHOSTS *kh = libssh2_knownhost_init(_session);
    if (!kh) { if (error) *error = sshErr(@"Couldn't initialise host-key checking."); return NO; }
    if (knownHostsPath.length)
        libssh2_knownhost_readfile(kh, knownHostsPath.UTF8String, LIBSSH2_KNOWNHOST_FILE_OPENSSH);

    int typemask = LIBSSH2_KNOWNHOST_TYPE_PLAIN | LIBSSH2_KNOWNHOST_KEYENC_RAW;
    struct libssh2_knownhost *known = NULL;
    int check = libssh2_knownhost_checkp(kh, _host.UTF8String, _port, hostkey, klen,
                                         typemask, &known);

    BOOL trusted = NO;
    NSString *why = nil;
    switch (check) {
        case LIBSSH2_KNOWNHOST_CHECK_MATCH:
            trusted = YES;
            break;
        case LIBSSH2_KNOWNHOST_CHECK_MISMATCH:
            // A CHANGED key is always refused, regardless of strictness — this is
            // the exact signature of a MITM.
            why = @"The SSH server's host key has CHANGED since last time — refusing to connect (possible interception).";
            break;
        case LIBSSH2_KNOWNHOST_CHECK_NOTFOUND:
        default:
            if ([strict isEqualToString:@"yes"]) {
                why = [NSString stringWithFormat:
                       @"The SSH server's host key is not in known_hosts (StrictHostKeyChecking=yes). It offered %@ SHA256:%@.",
                       [self hostKeyType] ?: @"a key", _fp ?: @"(unavailable)"];
            } else {
                // accept-new / no: trust on first use and record it. The caller
                // reads `acceptedNewHostKey` + the fingerprint to surface what
                // was just trusted — TOFU must never be silent.
                int keyenc = LIBSSH2_KNOWNHOST_TYPE_PLAIN | LIBSSH2_KNOWNHOST_KEYENC_RAW;
                switch (ktype) {
                    case LIBSSH2_HOSTKEY_TYPE_RSA:        keyenc |= LIBSSH2_KNOWNHOST_KEY_SSHRSA; break;
                    case LIBSSH2_HOSTKEY_TYPE_DSS:        keyenc |= LIBSSH2_KNOWNHOST_KEY_SSHDSS; break;
                    case LIBSSH2_HOSTKEY_TYPE_ECDSA_256:  keyenc |= LIBSSH2_KNOWNHOST_KEY_ECDSA_256; break;
                    case LIBSSH2_HOSTKEY_TYPE_ECDSA_384:  keyenc |= LIBSSH2_KNOWNHOST_KEY_ECDSA_384; break;
                    case LIBSSH2_HOSTKEY_TYPE_ECDSA_521:  keyenc |= LIBSSH2_KNOWNHOST_KEY_ECDSA_521; break;
                    case LIBSSH2_HOSTKEY_TYPE_ED25519:    keyenc |= LIBSSH2_KNOWNHOST_KEY_ED25519; break;
                    default: break;
                }
                // Non-standard ports are recorded the way OpenSSH does: "[host]:port".
                NSString *entryHost = (_port == 22) ? _host
                    : [NSString stringWithFormat:@"[%@]:%d", _host, _port];
                struct libssh2_knownhost *added = NULL;
                if (libssh2_knownhost_addc(kh, entryHost.UTF8String, NULL, (char *)hostkey, klen,
                                           NULL, 0, keyenc, &added) == 0 && added && knownHostsPath.length) {
                    // APPEND only the one new line. libssh2_knownhost_writefile
                    // would rewrite the whole file from the parsed entries,
                    // destroying comments, @cert-authority/@revoked markers and
                    // any line it couldn't parse.
                    char line[1024]; size_t outlen = 0;
                    if (libssh2_knownhost_writeline(kh, added, line, sizeof(line), &outlen,
                                                    LIBSSH2_KNOWNHOST_FILE_OPENSSH) == 0 && outlen > 0) {
                        int fd = open(knownHostsPath.UTF8String,
                                      O_WRONLY | O_APPEND | O_CREAT, 0600);
                        if (fd >= 0) {
                            // If the existing file doesn't end in a newline, add
                            // one first so we don't glue onto its last entry.
                            struct stat st; char last = 0;
                            if (fstat(fd, &st) == 0 && st.st_size > 0 &&
                                pread(fd, &last, 1, st.st_size - 1) == 1 && last != '\n') {
                                write(fd, "\n", 1);
                            }
                            write(fd, line, outlen);
                            if (line[outlen - 1] != '\n') write(fd, "\n", 1);
                            close(fd);
                        }
                    }
                }
                _acceptedNewHostKey = YES;
                trusted = YES;
            }
            break;
    }
    libssh2_knownhost_free(kh);
    if (!trusted && error) *error = sshErr(why ?: @"The SSH server's host key couldn't be verified.");
    return trusted;
}

- (void)enterDataMode {
    if (_session) libssh2_session_set_blocking(_session, 0);
}

- (BOOL)authPasswordForUser:(NSString *)user password:(NSString *)password error:(NSError **)error {
    if (libssh2_userauth_password(_session, user.UTF8String, password.UTF8String) != 0) {
        if (error) *error = sshErr(@"SSH password authentication was rejected."); return NO;
    }
    return YES;
}

- (BOOL)authKeyForUser:(NSString *)user privateKeyPath:(NSString *)keyPath
            passphrase:(NSString *)passphrase error:(NSError **)error {
    NSString *path = keyPath.stringByExpandingTildeInPath;
    NSString *pub = [path stringByAppendingPathExtension:@"pub"];
    const char *pubPath = [NSFileManager.defaultManager fileExistsAtPath:pub] ? pub.UTF8String : NULL;
    if (libssh2_userauth_publickey_fromfile(_session, user.UTF8String, pubPath,
                                            path.UTF8String, passphrase.UTF8String ?: "") != 0) {
        if (error) *error = sshErr(@"SSH key authentication was rejected."); return NO;
    }
    return YES;
}

- (BOOL)authAgentForUser:(NSString *)user error:(NSError **)error {
    LIBSSH2_AGENT *agent = libssh2_agent_init(_session);
    if (!agent) { if (error) *error = sshErr(@"No SSH agent available."); return NO; }
    BOOL ok = NO;
    if (libssh2_agent_connect(agent) == 0 && libssh2_agent_list_identities(agent) == 0) {
        struct libssh2_agent_publickey *ident = NULL, *prev = NULL;
        while (libssh2_agent_get_identity(agent, &ident, prev) == 0 && ident) {
            if (libssh2_agent_userauth(agent, user.UTF8String, ident) == 0) { ok = YES; break; }
            prev = ident;
        }
    }
    libssh2_agent_disconnect(agent);
    libssh2_agent_free(agent);
    if (!ok && error) *error = sshErr(@"The SSH agent had no key the server accepted.");
    return ok;
}

- (SSHChannel *)openDirectTCPIPToHost:(NSString *)host port:(int)port error:(NSError **)error {
    // Channel-open is a short multi-step exchange; do it blocking so we don't have
    // to spin on EAGAIN, then the session returns to its (non-blocking) data mode.
    int wasNonBlocking = _session ? (libssh2_session_get_blocking(_session) == 0) : 0;
    if (wasNonBlocking) libssh2_session_set_blocking(_session, 1);
    LIBSSH2_CHANNEL *c = libssh2_channel_direct_tcpip_ex(_session, host.UTF8String, port,
                                                         "127.0.0.1", 0);
    if (wasNonBlocking) libssh2_session_set_blocking(_session, 0);
    if (!c) { if (error) *error = sshErr(@"Couldn't open the SSH forwarding channel."); return nil; }
    return [[SSHChannel alloc] initWithChannel:c];
}

- (SSHChannel *)openTunChannelMode:(int)mode remoteUnit:(int)remoteUnit error:(NSError **)error {
    // tun@openssh.com channel-open payload: tunnel-mode(uint32) + remote-unit(uint32,
    // 0x7fffffff = "any"). Packets on the channel are IP frames with a 4-byte AF header.
    uint8_t msg[8];
    uint32_t m = htonl((uint32_t)mode);
    uint32_t u = htonl(remoteUnit < 0 ? 0x7fffffff : (uint32_t)remoteUnit);
    memcpy(msg, &m, 4); memcpy(msg + 4, &u, 4);
    int wasNonBlocking = _session ? (libssh2_session_get_blocking(_session) == 0) : 0;
    if (wasNonBlocking) libssh2_session_set_blocking(_session, 1);
    LIBSSH2_CHANNEL *c = libssh2_channel_open_ex(_session, "tun@openssh.com",
        (unsigned int)strlen("tun@openssh.com"),
        LIBSSH2_CHANNEL_WINDOW_DEFAULT, LIBSSH2_CHANNEL_PACKET_DEFAULT,
        (const char *)msg, sizeof(msg));
    if (wasNonBlocking) libssh2_session_set_blocking(_session, 0);
    if (!c) { if (error) *error = sshErr(@"The server refused a network tunnel (PermitTunnel?)."); return nil; }
    return [[SSHChannel alloc] initWithChannel:c];
}

- (void)disconnect {
    if (_session) {
        libssh2_session_disconnect(_session, "bye");
        libssh2_session_free(_session);
        _session = NULL;
    }
    if (_sock >= 0) { close(_sock); _sock = -1; }
}

- (void)dealloc { [self disconnect]; }

@end
