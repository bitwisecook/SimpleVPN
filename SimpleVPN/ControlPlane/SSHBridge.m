// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
//  SSHBridge.m
//  libssh wrapper (blocking mode). Single-threaded per session — the Swift
//  engine drives all calls on one serial queue. See SSHBridge.h.
//

#import "SSHBridge.h"
#import <libssh/libssh.h>
#import <libssh/callbacks.h>
#import <os/log.h>
#include <fcntl.h>
#include <unistd.h>

// tun@openssh.com channel open — compiled into the vendored library by
// Tools/build-libssh-xcframework.sh (libssh's own channel_open is static, so
// the wrapper lives inside channels.c where it can reach it).
extern int libsshx_channel_open_tun(ssh_channel channel,
                                    uint32_t tun_mode,
                                    uint32_t remote_unit);

static NSErrorDomain const kSSHErrorDomain = @"SSHBridge";
static os_log_t gSSHLog(void) {
    static os_log_t log;
    static dispatch_once_t once;
    dispatch_once(&once, ^{ log = os_log_create("com.bragi0.SimpleVPN", "libssh"); });
    return log;
}

/// libssh's own account of the handshake, key exchange and auth negotiation.
///
/// Without this, an SSH tunnel that fails to come up leaves NOTHING in a diagnostics
/// bundle from the library that actually failed — the app can only report "the SSH
/// handshake failed", which is a symptom, not a cause. Unlike libssh2 (which compiled
/// tracing out unless the build defined ENABLE_DEBUG_LOGGING), libssh always ships its
/// logging; the level below decides what it says.
///
/// The level is chosen deliberately: SSH_LOG_PROTOCOL gives the negotiation story —
/// kex and cipher chosen, which auth methods were offered and tried, channel
/// open/close — with no payload. SSH_LOG_PACKET and up emit per-packet byte-level
/// detail, which is both enormous and the channel most likely to carry fragments of
/// authentication material into a log the user may share.
///
/// Logged at DEFAULT level, not debug: os_log discards debug messages rather than
/// persisting them, which would make the trace unavailable after the fact — the exact
/// trap that had been hiding the OpenVPN handshake.
static void ssh_trace(int priority, const char *function,
                      const char *buffer, void *userdata) {
    (void)priority; (void)function; (void)userdata;
    if (!buffer || buffer[0] == '\0') return;
    os_log(gSSHLog(), "%{public}s", buffer);
}

static NSError *sshErr(NSString *m) {
    return [NSError errorWithDomain:kSSHErrorDomain code:1 userInfo:@{ NSLocalizedDescriptionKey: m }];
}

/// Fixed user-facing sentence + libssh's own reason in parentheses. The
/// library's strings are terse and occasionally quote the server, so they only
/// ever reach a step's evidence, where the redactor sees them first.
static NSError *sshErrDetail(NSString *m, ssh_session session) {
    const char *detail = session ? ssh_get_error(session) : NULL;
    if (detail && detail[0] != '\0') {
        return sshErr([NSString stringWithFormat:@"%@ (%s)", m, detail]);
    }
    return sshErr(m);
}

// Compare only the hex tail after any "sha256:"/"pin-sha256:" prefix, lowercased,
// as exact equality (a suffix compare would let a truncated pin match).
static NSString *hexTail(NSString *s) {
    NSRange c = [s rangeOfString:@":" options:NSBackwardsSearch];
    return [(c.location == NSNotFound ? s : [s substringFromIndex:c.location + 1]) lowercaseString];
}

@interface SSHChannel ()
@property (assign) ssh_channel chan;
@end

@implementation SSHChannel
- (instancetype)initWithChannel:(ssh_channel)c { if ((self = [super init])) _chan = c; return self; }
- (NSInteger)read:(void *)buffer maxLength:(NSInteger)len {
    if (!_chan) return -1;
    // Contract: >0 data, 0 when nothing is buffered yet (would-block), 0 at EOF
    // (isEOF turns true), negative on hard error. SSH_EOF maps to the EOF case.
    int n = ssh_channel_read_nonblocking(_chan, buffer, (uint32_t)len, 0);
    if (n == SSH_EOF) return 0;
    if (n == SSH_AGAIN) return 0;
    return n;   // >0 data, 0 nothing yet, SSH_ERROR(-1) hard error
}
- (NSInteger)write:(const void *)buffer length:(NSInteger)len {
    if (!_chan) return -1;
    int n = ssh_channel_write(_chan, buffer, (uint32_t)len);
    return n == SSH_AGAIN ? 0 : n;
}
- (BOOL)isEOF { return _chan ? (ssh_channel_is_eof(_chan) != 0) : YES; }
- (BOOL)isClosed { return _chan == NULL; }
- (void)close {
    if (_chan) { ssh_channel_close(_chan); ssh_channel_free(_chan); _chan = NULL; }
}
- (void)dealloc {
    // Do NOT touch libssh here: dealloc runs on whatever thread releases the last
    // reference (typically an NWConnection callback thread), and libssh session
    // state is single-threaded. The engine closes every channel explicitly on the
    // session queue; any channel still open at dealloc is reclaimed by
    // ssh_free at teardown. Freeing here would be a cross-thread UAF.
    if (_chan) { /* leaked to session teardown on purpose — safety over the leak */ }
}
@end

@implementation SSHSession {
    ssh_session _session;
    ssh_key _hostKey;       // the server's public key, held for type/length/TOFU
    NSString *_fp;
    NSString *_host;
    int _port;
    BOOL _acceptedNewHostKey;
}

+ (void)initialize {
    if (self == [SSHSession class]) {
        ssh_init();
        // Trace is global in libssh (per-session callbacks exist but the level
        // is process-wide); install it before any session so key exchange and
        // auth negotiation are captured — that's where SSH tunnels actually fail.
        ssh_set_log_callback(ssh_trace);
        ssh_set_log_level(SSH_LOG_PROTOCOL);
    }
}

- (BOOL)connectToHost:(NSString *)host port:(int)port timeout:(int)seconds error:(NSError **)error {
    return [self connectToHost:host port:port timeout:seconds kexAlgorithms:nil error:error];
}

- (BOOL)connectToHost:(NSString *)host port:(int)port timeout:(int)seconds
        kexAlgorithms:(NSString *)kexAlgorithms error:(NSError **)error {
    _session = ssh_new();
    if (!_session) { if (error) *error = sshErr(@"Couldn't initialise the SSH session."); return NO; }
    _host = [host copy];
    _port = port;

    unsigned int p = (unsigned int)port;
    long tmo = (long)seconds;
    // No implicit configuration: libssh would otherwise read ~/.ssh/ssh_config
    // and /etc/ssh/ssh_config at connect (ProxyJump and friends). The app's
    // importer is the only thing that reads OpenSSH config; the engine connects
    // to exactly what it was told. (The vendored build also compiles the
    // ProxyCommand exec paths out entirely — WITH_EXEC=OFF.)
    bool no = false;
    ssh_options_set(_session, SSH_OPTIONS_PROCESS_CONFIG, &no);
    // Neutralise the default known-hosts files too; the check/verify calls set
    // the caller's path explicitly (nil means "consult nothing").
    ssh_options_set(_session, SSH_OPTIONS_KNOWNHOSTS, "/dev/null");
    ssh_options_set(_session, SSH_OPTIONS_GLOBAL_KNOWNHOSTS, "/dev/null");
    ssh_options_set(_session, SSH_OPTIONS_HOST, host.UTF8String);
    ssh_options_set(_session, SSH_OPTIONS_PORT, &p);
    ssh_options_set(_session, SSH_OPTIONS_TIMEOUT, &tmo);   // connect + blocking calls
    // Key-exchange preference (OpenSSH KexAlgorithms syntax). A list libssh
    // rejects fails HERE, loudly — never a silent fall-through to defaults.
    if (kexAlgorithms.length) {
        if (ssh_options_set(_session, SSH_OPTIONS_KEY_EXCHANGE,
                            kexAlgorithms.UTF8String) != SSH_OK) {
            if (error) *error = sshErrDetail(@"The key-exchange list wasn't accepted.", _session);
            return NO;
        }
    }

    ssh_set_blocking(_session, 1);
    if (ssh_connect(_session) != SSH_OK) {
        if (error) *error = sshErrDetail(@"The SSH handshake failed.", _session);
        return NO;
    }

    ssh_key key = NULL;
    if (ssh_get_server_publickey(_session, &key) == SSH_OK && key) {
        _hostKey = key;
        unsigned char *hash = NULL; size_t hlen = 0;
        if (ssh_get_publickey_hash(key, SSH_PUBLICKEY_HASH_SHA256, &hash, &hlen) == 0 && hash) {
            NSMutableString *fp = [NSMutableString string];
            for (size_t i = 0; i < hlen; i++) [fp appendFormat:@"%02x", hash[i]];
            _fp = fp;
            ssh_clean_pubkey_hash(&hash);
        }
    }
    return YES;
}

- (NSString *)hostKeyFingerprintSHA256 { return _fp; }

- (NSString *)hostKeyType {
    if (!_hostKey) return nil;
    const char *name = ssh_key_type_to_char(ssh_key_type(_hostKey));
    return name ? @(name) : nil;
}

- (NSInteger)hostKeyLength {
    // The wire-blob length in bytes (what libssh2 reported as klen), recovered
    // from the base64 export — libssh has no public blob-length getter.
    if (!_hostKey) return 0;
    char *b64 = NULL;
    if (ssh_pki_export_pubkey_base64(_hostKey, &b64) != SSH_OK || !b64) return 0;
    NSData *blob = [[NSData alloc] initWithBase64EncodedString:@(b64) options:0];
    ssh_string_free_char(b64);
    return (NSInteger)blob.length;
}

- (NSDictionary<NSString *, NSString *> *)negotiatedMethods {
    if (!_session) return @{};
    NSMutableDictionary *out = [NSMutableDictionary dictionary];
    const char *kex = ssh_get_kex_algo(_session);
    if (kex) out[@"kex"] = @(kex);
    NSString *hostkey = [self hostKeyType];
    if (hostkey) out[@"hostkey"] = hostkey;
    const char *cipher = ssh_get_cipher_out(_session);     // client→server, like _CS
    if (cipher) out[@"cipher"] = @(cipher);
    const char *mac = ssh_get_hmac_out(_session);          // NULL for AEAD ciphers
    if (mac) out[@"mac"] = @(mac);
    return out;
}

/// Point the session at the caller's known_hosts (nil = consult nothing).
/// libssh reads the file lazily at check time, so this can differ per call.
- (void)useKnownHosts:(NSString *)knownHostsPath {
    const char *path = knownHostsPath.length ? knownHostsPath.UTF8String : "/dev/null";
    ssh_options_set(_session, SSH_OPTIONS_KNOWNHOSTS, path);
}

- (SSHHostKeyStatus)checkHostKeyWithKnownHosts:(NSString *)knownHostsPath
                                           pin:(NSString *)pinSHA256 {
    if (!_session) return SSHHostKeyStatusUnavailable;

    if (pinSHA256.length) {
        if (!_fp.length) return SSHHostKeyStatusUnavailable;
        return [hexTail(_fp) isEqualToString:hexTail(pinSHA256)]
            ? SSHHostKeyStatusMatch : SSHHostKeyStatusMismatch;
    }

    if (!_hostKey) return SSHHostKeyStatusUnavailable;
    [self useKnownHosts:knownHostsPath];
    // ssh_session_is_known_server only READS — the write is a separate call
    // (ssh_session_update_known_hosts) that this method never makes: see
    // SSHHostKeyStatus for why the probe must be able to ask without pinning.
    switch (ssh_session_is_known_server(_session)) {
        case SSH_KNOWN_HOSTS_OK:        return SSHHostKeyStatusMatch;
        case SSH_KNOWN_HOSTS_CHANGED:   return SSHHostKeyStatusMismatch;
        // OTHER = the host is on record but with a different key TYPE. The
        // recorded key can't vouch for this one, so it reports as a mismatch —
        // same hard stop OpenSSH makes.
        case SSH_KNOWN_HOSTS_OTHER:     return SSHHostKeyStatusMismatch;
        case SSH_KNOWN_HOSTS_NOT_FOUND: return SSHHostKeyStatusNotFound;   // no file
        case SSH_KNOWN_HOSTS_UNKNOWN:   return SSHHostKeyStatusNotFound;   // not in file
        case SSH_KNOWN_HOSTS_ERROR:
        default:                        return SSHHostKeyStatusUnavailable;
    }
}

- (NSArray<NSString *> *)authMethodsForUser:(NSString *)user error:(NSError **)error {
    if (!_session) {
        if (error) *error = sshErr(@"No SSH session to ask.");
        return nil;
    }
    // The standard "none" request every SSH client sends before choosing a
    // method; it submits no credential.
    int rc = ssh_userauth_none(_session, user.UTF8String);
    if (rc == SSH_AUTH_SUCCESS) return @[];   // open server — worth reporting as such
    if (rc == SSH_AUTH_ERROR) {
        if (error) *error = sshErrDetail(@"The server didn't say how it wants you to sign in.", _session);
        return nil;
    }
    int list = ssh_userauth_list(_session, user.UTF8String);
    NSMutableArray<NSString *> *out = [NSMutableArray array];
    struct { unsigned int bit; NSString *name; } methods[] = {
        { SSH_AUTH_METHOD_PUBLICKEY,    @"publickey" },
        { SSH_AUTH_METHOD_GSSAPI_MIC,   @"gssapi-with-mic" },
        { SSH_AUTH_METHOD_GSSAPI_KEYEX, @"gssapi-keyex" },
        { SSH_AUTH_METHOD_PASSWORD,     @"password" },
        { SSH_AUTH_METHOD_INTERACTIVE,  @"keyboard-interactive" },
        { SSH_AUTH_METHOD_HOSTBASED,    @"hostbased" },
    };
    for (size_t i = 0; i < sizeof(methods) / sizeof(methods[0]); i++) {
        if ((unsigned int)list & methods[i].bit) [out addObject:methods[i].name];
    }
    if (out.count == 0) {
        if (error) *error = sshErr(@"The server didn't say how it wants you to sign in.");
        return nil;
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
    if (!_hostKey) { if (error) *error = sshErr(@"The SSH server didn't present a host key."); return NO; }
    [self useKnownHosts:knownHostsPath];

    BOOL trusted = NO;
    NSString *why = nil;
    switch (ssh_session_is_known_server(_session)) {
        case SSH_KNOWN_HOSTS_OK:
            trusted = YES;
            break;
        case SSH_KNOWN_HOSTS_CHANGED:
        case SSH_KNOWN_HOSTS_OTHER:
            // A CHANGED key is always refused, regardless of strictness — this is
            // the exact signature of a MITM. (OTHER — same host, different key
            // type — gets the same treatment; the recorded key can't vouch here.)
            why = @"The SSH server's host key has CHANGED since last time — refusing to connect (possible interception).";
            break;
        case SSH_KNOWN_HOSTS_NOT_FOUND:   // no known_hosts file at all
        case SSH_KNOWN_HOSTS_UNKNOWN:     // file exists, host not in it
            if ([strict isEqualToString:@"yes"]) {
                why = [NSString stringWithFormat:
                       @"The SSH server's host key is not in known_hosts (StrictHostKeyChecking=yes). It offered %@ SHA256:%@.",
                       [self hostKeyType] ?: @"a key", _fp ?: @"(unavailable)"];
            } else {
                // accept-new / no: trust on first use and record it. The caller
                // reads `acceptedNewHostKey` + the fingerprint to surface what
                // was just trusted — TOFU must never be silent.
                if (knownHostsPath.length) {
                    // Pre-create the file 0600 so libssh's append (mode "a",
                    // umask-default 0644) never widens a fresh known_hosts.
                    int fd = open(knownHostsPath.UTF8String,
                                  O_WRONLY | O_APPEND | O_CREAT, 0600);
                    if (fd >= 0) close(fd);
                    // APPENDS one OpenSSH-format line (non-standard ports as
                    // "[host]:port", same as OpenSSH) — never rewrites the file,
                    // so comments and @cert-authority/@revoked markers survive.
                    ssh_session_update_known_hosts(_session);
                }
                _acceptedNewHostKey = YES;
                trusted = YES;
            }
            break;
        case SSH_KNOWN_HOSTS_ERROR:
        default:
            why = @"The SSH server's host key couldn't be verified.";
            break;
    }
    if (!trusted && error) *error = sshErr(why ?: @"The SSH server's host key couldn't be verified.");
    return trusted;
}

- (void)enterDataMode {
    if (_session) ssh_set_blocking(_session, 0);
}

- (BOOL)authPasswordForUser:(NSString *)user password:(NSString *)password error:(NSError **)error {
    if (ssh_userauth_password(_session, user.UTF8String, password.UTF8String) != SSH_AUTH_SUCCESS) {
        if (error) *error = sshErr(@"SSH password authentication was rejected."); return NO;
    }
    return YES;
}

- (BOOL)authKeyForUser:(NSString *)user privateKeyPath:(NSString *)keyPath
            passphrase:(NSString *)passphrase error:(NSError **)error {
    return [self authKeyForUser:user privateKeyPath:keyPath certificatePath:nil
                     passphrase:passphrase error:error];
}

- (BOOL)authKeyForUser:(NSString *)user privateKeyPath:(NSString *)keyPath
       certificatePath:(NSString *)certificatePath
            passphrase:(NSString *)passphrase error:(NSError **)error {
    NSString *path = keyPath.stringByExpandingTildeInPath;
    ssh_key key = NULL;
    // libssh derives the public half from the private key — no .pub file needed.
    if (ssh_pki_import_privkey_file(path.UTF8String,
                                    passphrase.length ? passphrase.UTF8String : NULL,
                                    NULL, NULL, &key) != SSH_OK || !key) {
        if (error) *error = sshErr(@"Couldn't read the SSH private key (wrong passphrase, or an unsupported format).");
        return NO;
    }
    // OpenSSH certificate sign-in: graft the …-cert.pub onto the private key so
    // the userauth request presents the CA-signed certificate, not the bare key.
    if (certificatePath.length) {
        ssh_key cert = NULL;
        if (ssh_pki_import_cert_file(certificatePath.stringByExpandingTildeInPath.UTF8String,
                                     &cert) != SSH_OK || !cert) {
            ssh_key_free(key);
            if (error) *error = sshErr(@"Couldn't read the SSH certificate file (expected an OpenSSH …-cert.pub).");
            return NO;
        }
        int copied = ssh_pki_copy_cert_to_privkey(cert, key);
        ssh_key_free(cert);
        if (copied != SSH_OK) {
            ssh_key_free(key);
            if (error) *error = sshErr(@"The SSH certificate doesn't go with that private key.");
            return NO;
        }
    }
    int rc = ssh_userauth_publickey(_session, user.UTF8String, key);
    ssh_key_free(key);
    if (rc != SSH_AUTH_SUCCESS) {
        if (error) *error = sshErr(certificatePath.length
            ? @"SSH certificate authentication was rejected."
            : @"SSH key authentication was rejected.");
        return NO;
    }
    return YES;
}

- (BOOL)authAgentForUser:(NSString *)user error:(NSError **)error {
    // libssh speaks to the agent at SSH_AUTH_SOCK itself, trying each identity.
    if (ssh_userauth_agent(_session, user.UTF8String) != SSH_AUTH_SUCCESS) {
        if (error) *error = sshErr(@"The SSH agent had no key the server accepted.");
        return NO;
    }
    return YES;
}

- (BOOL)authGSSAPIForUser:(NSString *)user error:(NSError **)error {
    // gssapi-with-mic uses the user's existing Kerberos ticket; the username
    // rides the session (set at connect for the auth exchange).
    ssh_options_set(_session, SSH_OPTIONS_USER, user.UTF8String);
    if (ssh_userauth_gssapi(_session) != SSH_AUTH_SUCCESS) {
        if (error) *error = sshErr(@"Kerberos sign-in was rejected (is there a valid ticket?).");
        return NO;
    }
    return YES;
}

/// Channel-open is a short multi-step exchange; do it blocking so we don't have
/// to spin on SSH_AGAIN, then the session returns to its (non-blocking) data mode.
- (SSHChannel *)openChannelBlocking:(int (^)(ssh_channel))open
                            failure:(NSString *)failureMessage
                              error:(NSError **)error {
    if (!_session) { if (error) *error = sshErr(failureMessage); return nil; }
    int wasNonBlocking = (ssh_is_blocking(_session) == 0);
    if (wasNonBlocking) ssh_set_blocking(_session, 1);
    ssh_channel c = ssh_channel_new(_session);
    int rc = c ? open(c) : SSH_ERROR;
    if (wasNonBlocking) ssh_set_blocking(_session, 0);
    if (rc != SSH_OK) {
        if (c) ssh_channel_free(c);
        if (error) *error = sshErrDetail(failureMessage, _session);
        return nil;
    }
    return [[SSHChannel alloc] initWithChannel:c];
}

- (SSHChannel *)openDirectTCPIPToHost:(NSString *)host port:(int)port error:(NSError **)error {
    return [self openChannelBlocking:^int(ssh_channel c) {
        return ssh_channel_open_forward(c, host.UTF8String, port, "127.0.0.1", 0);
    } failure:@"Couldn't open the SSH forwarding channel." error:error];
}

- (SSHChannel *)openTunChannelMode:(int)mode remoteUnit:(int)remoteUnit error:(NSError **)error {
    // tun@openssh.com channel-open payload: tunnel-mode(uint32) + remote-unit(uint32,
    // 0x7fffffff = "any"). Packets on the channel are IP frames with a 4-byte AF header.
    uint32_t unit = remoteUnit < 0 ? 0x7fffffff : (uint32_t)remoteUnit;
    return [self openChannelBlocking:^int(ssh_channel c) {
        return libsshx_channel_open_tun(c, (uint32_t)mode, unit);
    } failure:@"The server refused a network tunnel (PermitTunnel?)." error:error];
}

- (void)disconnect {
    if (_hostKey) { ssh_key_free(_hostKey); _hostKey = NULL; }
    if (_session) {
        ssh_disconnect(_session);
        ssh_free(_session);
        _session = NULL;
    }
    _fp = nil;
}

- (void)dealloc { [self disconnect]; }

@end
