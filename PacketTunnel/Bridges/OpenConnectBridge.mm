// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
//  OpenConnectBridge.mm
//  ObjC surface over libopenconnect. Auth + mainloop run on a background thread;
//  the negotiated IP config becomes NEPacketTunnelNetworkSettings; IP packets are
//  pumped between openconnect and NEPacketTunnelFlow over a socketpair (same shape
//  as OpenVPN3Bridge). In-process — no `openconnect` subprocess.
//
//  Runtime note: SSO is signed in OUT of process now (ocauth-helper) and arrives here
//  as a cookie, so `openconnect_obtain_cookie` below is only the non-SSO fallback. The
//  structure is otherwise the standard libopenconnect embedding (obtain_cookie →
//  make_cstp_connection → setup_tun → mainloop). Tools/OpenConnect exercises native
//  Darwin framing and mandatory peer pinning against a private CSTP endpoint.
//

#import "OpenConnectBridge.h"
#import "VirtualDatagramPort.h"
#include <fcntl.h>
#import <os/log.h>
#include <string>
#include <mutex>
#include <atomic>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Weverything"
#include <openconnect.h>
#pragma clang diagnostic pop

static NSErrorDomain const kOCErrorDomain = @"OpenConnectBridge";
static os_log_t gOCLog = os_log_create("com.bragi0.SimpleVPN.PacketTunnel", "openconnect");
#define OCLOG(fmt, ...) os_log(gOCLog, fmt, ##__VA_ARGS__)

@implementation OCClientSettings
@end

// C trampolines → the bridge instance carried as privdata.
static BOOL parseOCPrefix(const char *s, int max, int *result) {
    if (!s || !*s) return NO;
    int prefix = 0;
    for (; *s; s++) {
        if (*s < '0' || *s > '9') return NO;
        prefix = prefix * 10 + (*s - '0');
        if (prefix > max) return NO;
    }
    *result = prefix;
    return YES;
}
static BOOL validOCNetmask(const char *s) {
    struct in_addr address;
    if (!s || inet_pton(AF_INET, s, &address) != 1) return NO;
    uint32_t inverse = ~ntohl(address.s_addr);
    return (inverse & (inverse + 1)) == 0;
}
static int oc_validate_cert(void *priv, const char *reason);
static int oc_process_form(void *priv, struct oc_auth_form *form);
static void oc_progress(void *priv, int level, const char *fmt, ...) __attribute__((format(printf, 3, 4)));
static void oc_setup_tun(void *priv);
static void oc_stats(void *priv, const struct oc_stats *stats);
static int oc_member_socket(void *priv, int fd, int family);
static int oc_required_pin(void *priv);
static void oc_member_reconnected(void *priv);
static int oc_member_resolve(void *priv, const char *node, const char *service, const struct addrinfo *hints, struct addrinfo **result);

@interface OpenConnectBridge () {
    __weak NEPacketTunnelProvider<SVPTunnelSettingsApplying> *_provider;
    __weak id<OpenConnectBridgeDelegate> _delegate;
    SVPPacketPolicy *_packetPolicy;
    VirtualDatagramPort *_member;
    uint32_t _interfaceIndex;
    BOOL _haveMemberTun;
    std::mutex _cancelMutex;
    struct openconnect_info *_vpninfo;
    OCClientSettings *_cfg;
    dispatch_queue_t _runQueue;      // owns the openconnect mainloop
    VirtualDatagramPort *_hostPort;
    int _commandFD;                  // borrowed until vpninfo_free; protected by _cancelMutex
    std::atomic<uint32_t> _pumpGeneration;
    std::atomic<bool> _running;
    std::mutex _statsMutex;
    int64_t _bytesIn, _bytesOut;
    bool _statsPending;
    NSMutableDictionary<NSString *, id> *_info;

    // Default-gateway ownership + a snapshot of the negotiated IP config, so the
    // tun settings can be rebuilt and re-applied live when the gateway role flips
    // (setDefaultRouteOwned:) without re-calling into libopenconnect off the run
    // thread. All guarded by _cfgMutex. Mirrors OpenVPN3Bridge's captured tun state.
    std::mutex _cfgMutex;
    BOOL _suppressDefault;            // demoted to split: drop the default route
    BOOL _haveConfig;                 // a setup_tun has captured a config to rebuild from
    NSString *_capRemote;
    NSArray<NSString *> *_capV4Addrs, *_capV4Masks;   // parallel address/netmask
    BOOL _capHaveV4Default;
    NSString *_capV6Addr; NSInteger _capV6Prefix; BOOL _capHaveV6;
    BOOL _capHaveV6Default;
    NSArray<NEIPv4Route *> *_capV4Split;              // gateway split-include routes
    NSArray<NEIPv6Route *> *_capV6Split;
    NSArray<NSString *> *_capDNS;
    NSArray<NSString *> *_capSearchDomains;
    int _capMTU;
    // App-arbitrated overrides (Docs/StateMediators.md), guarded by _cfgMutex like the
    // captured config. When set they OVERRIDE what the push captured; nil restores it.
    // Mirrors OpenVPN3Bridge's _proxySettings/_dnsOverride.
    NEProxySettings *_proxySettings;   // Proxy mediator applier (owner egress only)
    NEDNSSettings *_dnsOverride;       // DNS mediator applier (this engine's slice)
    // Divert rules (Shared/RoutingRule.swift · DivertPlan), guarded by _cfgMutex
    // like the captured config: destinations to route AROUND this VPN and
    // destinations other VPNs route INTO it. Same shape and same meaning as
    // OpenVPN3Bridge's _extra* arrays — this bridge builds its own tun settings,
    // so both halves of a divert apply here too.
    NSArray<NEIPv4Route *> *_extraV4Excluded;
    NSArray<NEIPv6Route *> *_extraV6Excluded;
    NSArray<NEIPv4Route *> *_extraV4Included;
    NSArray<NEIPv6Route *> *_extraV6Included;
}
@end

@implementation OpenConnectBridge

- (instancetype)initWithProvider:(NEPacketTunnelProvider<SVPTunnelSettingsApplying> *)provider
                        delegate:(id<OpenConnectBridgeDelegate>)delegate
                    packetPolicy:(SVPPacketPolicy *)packetPolicy {
    if ((self = [self initWithEngineDelegate:delegate])) {
        _provider = provider;
        _packetPolicy = packetPolicy;
    }
    return self;
}

- (instancetype)initWithInterfaceIndex:(uint32_t)index delegate:(id<OpenConnectBridgeDelegate>)delegate
                               received:(void (^)(NSData *))received {
    if ((self = [self initWithEngineDelegate:delegate])) {
        _interfaceIndex = index;
        _member = [[VirtualDatagramPort alloc] initWithFamilyHeader:YES received:received];
    }
    return self;
}

- (instancetype)initWithEngineDelegate:(id<OpenConnectBridgeDelegate>)delegate {
    if ((self = [super init])) {
        _delegate = delegate;
        _pumpGeneration = 0;
        _running = false;
        _info = [NSMutableDictionary dictionary];
        _commandFD = -1;
        _runQueue = dispatch_queue_create("com.bragi0.SimpleVPN.openconnect.run", DISPATCH_QUEUE_SERIAL);

    }
    return self;
}

- (BOOL)connectWithSettings:(OCClientSettings *)settings error:(NSError **)error {
    _cfg = settings;
    _running = true;
    dispatch_async(_runQueue, ^{ [self runSession]; });
    return YES;
}

- (void)runSession {
    [self connectAndPump];
    [self teardownTun];
    {
        std::lock_guard<std::mutex> lock(_cancelMutex);
        _commandFD = -1;
    }
    if (_vpninfo) { openconnect_vpninfo_free(_vpninfo); _vpninfo = NULL; }
    _running = false;
    [self emitStatus:OCStatusDisconnected event:@"DISCONNECTED" info:@""];
}

- (void)connectAndPump {
    [self emitStatus:OCStatusConnecting event:@"CONNECTING" info:_cfg.server];

    const char *ua = _cfg.userAgent.length ? _cfg.userAgent.UTF8String : "SimpleVPN";
    _vpninfo = openconnect_vpninfo_new(ua, oc_validate_cert, NULL, oc_process_form,
                                       oc_progress, (__bridge void *)self);
    if (!_vpninfo) { [self fail:@"Couldn't initialise the OpenConnect engine."]; return; }

    openconnect_set_loglevel(_vpninfo, PRG_INFO);
    openconnect_set_setup_tun_handler(_vpninfo, oc_setup_tun);
    openconnect_set_stats_handler(_vpninfo, oc_stats);
    if (_member) openconnect_set_reconnected_handler(_vpninfo, oc_member_reconnected);
    openconnect_set_member_guards(_vpninfo, _member ? oc_member_socket : NULL,
                                  _cfg.serverCertSHA256.length ? oc_required_pin : NULL);
    if (_member || _cfg.resolveIP.length || _cfg.resolveHost.length) openconnect_override_getaddrinfo(_vpninfo, oc_member_resolve);

    // Certificate trust: validate against the OS trust store (and any extra CA
    // bundle) by default. oc_validate_cert is only invoked when that verification
    // *fails*, and it rejects unless the user pinned this exact certificate — so a
    // gateway with an untrusted/self-signed cert and no pin cannot be MITM'd.
    openconnect_set_system_trust(_vpninfo, 1);
    if (_cfg.caFile.length) openconnect_set_cafile(_vpninfo, _cfg.caFile.UTF8String);

    // Cancel fd: disconnect() writes here so openconnect_mainloop returns promptly
    // instead of us calling mainloop concurrently from another thread.
    bool cancelReady;
    {
        std::lock_guard<std::mutex> lock(_cancelMutex);
        if (!_running.load()) return;
        _commandFD = openconnect_setup_cmd_pipe(_vpninfo);
        cancelReady = _commandFD >= 0;
    }
    if (!cancelReady) { [self fail:@"The connection could not create a cancellation channel."]; return; }

    if (_cfg.protocol.length && openconnect_set_protocol(_vpninfo, _cfg.protocol.UTF8String) != 0) {
        [self fail:@"This OpenConnect protocol is unavailable."]; return;
    }

    // WEB PROXY TO THE GATEWAY, before parse_url — the proxy is part of how the
    // server is reached, and openconnect resolves nothing until it connects. The
    // app resolved "use the system proxy" for us: it is unsandboxed and in the
    // user's context, while this process is root in the system context and sees a
    // different SystemConfiguration view.
    //
    // `openconnect_set_http_proxy` takes credentials only as URL userinfo — there is
    // no separate setter (`openconnect_set_proxy_auth` chooses the auth *methods*,
    // not the identity). Compose them only when starting the engine. The
    // saved-password opt-in for the external tool is independent of this path.
    if (_cfg.proxy.length) {
        NSString *url = _cfg.proxy;
        if (_cfg.proxyUsername.length) {
            NSCharacterSet *allowed = [NSCharacterSet characterSetWithCharactersInString:
                @"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-._~"];
            NSString *user = [_cfg.proxyUsername stringByAddingPercentEncodingWithAllowedCharacters:allowed];
            NSString *password = [_cfg.proxyPassword stringByAddingPercentEncodingWithAllowedCharacters:allowed];
            NSString *cred = password.length ? [NSString stringWithFormat:@"%@:%@", user, password] : user;
            NSRange scheme = [url rangeOfString:@"://"];
            url = scheme.location == NSNotFound
                ? [NSString stringWithFormat:@"http://%@@%@", cred, url]
                : [url stringByReplacingCharactersInRange:NSMakeRange(NSMaxRange(scheme), 0)
                                               withString:[cred stringByAppendingString:@"@"]];
        }
        if (openconnect_set_http_proxy(_vpninfo, url.UTF8String) != 0) {
            [self fail:@"That proxy address couldn't be used to reach the gateway."]; return;
        }
    }

    if (openconnect_parse_url(_vpninfo, _cfg.server.UTF8String) != 0) {
        [self fail:@"That server address couldn't be parsed."]; return;
    }

    // `--usergroup`. Set AFTER parse_url, which writes urlpath itself from the
    // address: setting it first would be silently overwritten, which is the whole
    // class of bug this batch is about.
    if (!_cfg.cookie.length && _cfg.urlPath.length) openconnect_set_urlpath(_vpninfo, _cfg.urlPath.UTF8String);

    // WHAT THIS CLIENT CLAIMS TO BE. Each is a plain setter and each was a refusal
    // until now. `set_reported_os` also selects the matching CSD trojan binary, so
    // it is not purely cosmetic.
    if (_cfg.reportedOS.length && openconnect_set_reported_os(_vpninfo, _cfg.reportedOS.UTF8String) != 0) {
        [self fail:@"That reported operating system isn't one OpenConnect knows."]; return;
    }
    if (_cfg.versionString.length) openconnect_set_version_string(_vpninfo, _cfg.versionString.UTF8String);
    if (_cfg.localName.length) openconnect_set_localname(_vpninfo, _cfg.localName.UTF8String);

    // CLIENT CERTIFICATE SIGN-IN from files. Refused before this change, which is
    // the most expensive of the old gates: a certificate profile could not have a
    // system tunnel at all. FILES ONLY: a `pkcs11:` URI would fail here with a
    // confusing "no certificate found", because this build has no PKCS#11 backend.
    // Nothing can produce one now — SimpleVPN does not sign in with a certificate on a
    // smartcard at all (Docs/AuthSecPKCS11.md).
    if (_cfg.clientCertFile.length) {
        if (openconnect_set_client_cert(_vpninfo, _cfg.clientCertFile.UTF8String,
                                        _cfg.clientKeyFile.length ? _cfg.clientKeyFile.UTF8String : NULL) != 0) {
            [self fail:@"That client certificate couldn't be loaded."]; return;
        }
        if (_cfg.privateKeyPassword.length) {
            openconnect_set_key_password(_vpninfo, _cfg.privateKeyPassword.UTF8String);
        }
    }

    // TRANSPORT SHAPE. `compression` is mapped rather than parsed: the three modes
    // in `oc_compression_mode_t` are all there are, and an unrecognised value is
    // left alone here AND refused by the app's gate, so nothing is substituted.
    if ([_cfg.compression isEqualToString:@"none"]) {
        openconnect_set_compression_mode(_vpninfo, OC_COMPRESSION_MODE_NONE);
    } else if ([_cfg.compression isEqualToString:@"stateless"]) {
        openconnect_set_compression_mode(_vpninfo, OC_COMPRESSION_MODE_STATELESS);
    } else if ([_cfg.compression isEqualToString:@"all"]) {
        openconnect_set_compression_mode(_vpninfo, OC_COMPRESSION_MODE_ALL);
    }
    if (_cfg.pfs) openconnect_set_pfs(_vpninfo, 1);
    if (_cfg.disableIPv6) openconnect_disable_ipv6(_vpninfo);
    if (_cfg.disableDTLS) openconnect_disable_dtls(_vpninfo);
    if (_cfg.mtu > 0) openconnect_set_reqmtu(_vpninfo, _cfg.mtu);
    if (_cfg.dpd > 0) openconnect_set_dpd(_vpninfo, _cfg.dpd);

    // Cookie auth: the app already signed in (ocauth-helper SSO) and handed us
    // the session cookie — skip obtain_cookie (no forms, no credentials here).
    if (_cfg.cookie.length) {
        if (openconnect_set_cookie(_vpninfo, _cfg.cookie.UTF8String) != 0) {
            [self fail:@"The sign-in session couldn't be applied."]; return;
        }
    } else if (openconnect_obtain_cookie(_vpninfo) != 0) {
        [self fail:@"Sign-in failed (check your username, password or one-time code)."]; return;
    }
    int result = openconnect_make_cstp_connection(_vpninfo);
    if (result != 0) {
        if (result == -ENOTSUP && [_cfg.protocol isEqualToString:@"fortinet"]) {
            [self fail:@"The Fortinet gateway requires split DNS rules this VPN cannot apply."];
        } else if (result == -ENOTSUP && [_cfg.protocol isEqualToString:@"f5"]) {
            [self fail:@"The F5 gateway requires split DNS rules this VPN cannot apply."];
        } else {
            [self fail:@"Couldn't establish the secure connection to the gateway."];
        }
        return;
    }

    if (!_cfg.disableDTLS && openconnect_setup_dtls(_vpninfo, 60) != 0) {
        openconnect_disable_dtls(_vpninfo);   // The gateway can offer TLS alone.
    }

    // Pump the tunnel until asked to stop. mainloop returns 0 to be called again,
    // < 0 on a fatal error.
    //
    // `--reconnect-timeout` is HERE and nowhere else: it is mainloop's second
    // argument, not a setter, which is why it was the one entry on the old refusal
    // list that could not have been fixed by adding a call in setup. Absent keeps
    // OpenConnect's own 300 seconds; a stored 0 means "give up at once" and must
    // reach the library AS 0 — see the NSNumber note on the property.
    const int reconnectTimeout = _cfg.reconnectTimeout ? _cfg.reconnectTimeout.intValue : 300;
    while (_running.load()) {
        int r = openconnect_mainloop(_vpninfo, reconnectTimeout, 10);
        if (r < 0) { if (_running.load()) [self fail:@"The VPN connection dropped."]; break; }
    }
}

- (void)disconnect {
    std::lock_guard<std::mutex> lock(_cancelMutex);
    if (!_running.exchange(false)) return;
    // Wake the mainloop via its cancel fd — do NOT call openconnect_mainloop here;
    // it is already running on _runQueue and is not safe to invoke concurrently on
    // the same _vpninfo (and _vpninfo may be freed by runSession as we return).
    if (_commandFD >= 0) { const char cancel = OC_CMD_CANCEL; (void)write(_commandFD, &cancel, 1); }
}

- (BOOL)sendMemberPacket:(NSData *)packet { return _running.load() && [_member sendPacket:packet]; }
- (NEPacketTunnelNetworkSettings *)memberNetworkSettings { return [self buildCapturedSettings]; }
- (void)stopMemberWithCompletion:(void (^)(void))completion {
    [self disconnect];
    // Leave the native descriptor alive for the authenticated PPP termination
    // and gateway logout. runSession closes the lane before this callback.
    dispatch_async(_runQueue, completion);
}
- (int)bindSocket:(int)fd family:(int)family {
    if (!_interfaceIndex || (family != AF_INET && family != AF_INET6)) return -1;
    return setsockopt(fd, family == AF_INET ? IPPROTO_IP : IPPROTO_IPV6,
        family == AF_INET ? IP_BOUND_IF : IPV6_BOUND_IF, &_interfaceIndex, sizeof(_interfaceIndex));
}
- (int)resolveHost:(const char *)node service:(const char *)service hints:(const struct addrinfo *)hints result:(struct addrinfo **)result {
    if (!node || !hints) return EAI_NONAME;
    if (_cfg.resolveHost.length) {
        if (strcasecmp(node, _cfg.resolveHost.UTF8String) != 0) return EAI_NONAME;
        node = _cfg.resolveIP.UTF8String;
    }
    struct addrinfo numeric = *hints;
    numeric.ai_flags |= AI_NUMERICHOST;
    return node ? getaddrinfo(node, service, &numeric, result) : EAI_NONAME;
}

// MARK: - Auth / cert callbacks

// Invoked by libopenconnect ONLY when the server certificate fails verification
// against the system trust store. Returning 0 accepts anyway; non-zero aborts.
// A CA-valid gateway never reaches here. We accept a failing cert only if the
// user pinned this exact certificate (trust-on-configuration for private/self-
// signed gateways); otherwise we reject, so there is no blanket accept-all.
- (int)validateCert:(const char *)reason {
    if (!_cfg.serverCertSHA256.length) {
        OCLOG("cert REJECTED — untrusted and no pin configured (%{public}s)", reason ?: "");
        return -1;
    }
    return openconnect_check_full_sha256_pin(_vpninfo, _cfg.serverCertSHA256.UTF8String);
}

- (int)processForm:(struct oc_auth_form *)form {
    const char *authID = form->auth_id ?: "";
    for (struct oc_form_opt *opt = form->opts; opt; opt = opt->next) {
        if (opt->flags & OC_FORM_OPT_IGNORE || opt->type == OC_FORM_OPT_HIDDEN || opt->type == OC_FORM_OPT_SSO_TOKEN)
            continue;
        NSString *answer = nil;
        if (form->authgroup_opt && opt == &form->authgroup_opt->form && _cfg.realm.length) {
            answer = _cfg.realm;
        } else if (opt->type == OC_FORM_OPT_SELECT) {
            struct oc_form_opt_select *select = (struct oc_form_opt_select *)opt;
            if (select->nr_choices == 1 && select->choices && select->choices[0] && select->choices[0]->name)
                answer = @(select->choices[0]->name);
        } else if (opt->type == OC_FORM_OPT_TOKEN) {
            answer = _cfg.oneTimeCode;
            _cfg.oneTimeCode = nil;
        } else {
            NSString *kind = opt->type == OC_FORM_OPT_TEXT ? @"text"
                : opt->type == OC_FORM_OPT_PASSWORD ? @"password"
                : opt->type == OC_FORM_OPT_SSO_USER ? @"sso-user" : nil;
            if (kind && opt->name && _cfg.authFieldAnswer)
                answer = _cfg.authFieldAnswer(@(authID), @(opt->name), @(opt->label ?: opt->name), kind);
        }
        if (!answer.length || openconnect_set_option_value(opt, answer.UTF8String) != 0)
            return OC_FORM_RESULT_CANCELLED;
    }
    return OC_FORM_RESULT_OK;
}

- (void)progress:(int)level line:(NSString *)line {
    [_delegate ocBridge:self didLog:line];
}

- (void)stats:(const struct oc_stats *)s {
    std::lock_guard<std::mutex> lk(_statsMutex);
    _statsPending = false;
    _bytesIn = (int64_t)s->rx_bytes;
    _bytesOut = (int64_t)s->tx_bytes;
}

- (void)transportBytesIn:(int64_t *)bytesIn bytesOut:(int64_t *)bytesOut {
    // libopenconnect publishes stats only on OC_CMD_STATS. Ask on demand;
    // its mainloop answers asynchronously without pausing the packet path.
    std::lock_guard<std::mutex> lk(_statsMutex);
    if (!_statsPending) {
        std::lock_guard<std::mutex> hold(_cancelMutex);
        if (_running.load() && _commandFD >= 0) {
            const char request = OC_CMD_STATS;
            _statsPending = write(_commandFD, &request, 1) == 1;
        }
    }
    if (bytesIn) *bytesIn = _bytesIn;
    if (bytesOut) *bytesOut = _bytesOut;
}

- (NSDictionary<NSString *, id> *)connectionInfo {
    NSMutableDictionary<NSString *, id> *out;
    @synchronized (self) { out = [_info mutableCopy]; }
    // Ground-truth default-route ownership (same channel as OpenVPN3Bridge): a
    // default was advertised AND it is not suppressed. The app seeds its
    // applied-role cache and traffic-path UI from this, never a config grep.
    std::lock_guard<std::mutex> hold(_cfgMutex);
    BOOL effectiveOwned = (_capHaveV4Default || _capHaveV6Default) && !_suppressDefault;
    out[@"defaultV4"] = @(_capHaveV4Default);
    out[@"defaultV6"] = @(_capHaveV6Default);
    out[@"searchDomains"] = _capSearchDomains ?: @[];
    out[@"suppressDefault"] = @(_suppressDefault);
    out[@"effectiveDefaultOwned"] = @(effectiveOwned);
    return out;
}

// MARK: - Tun bring-up

- (void)setupTun {
    const struct oc_ip_info *ip = NULL;
    if (openconnect_get_ip_info(_vpninfo, &ip, NULL, NULL) != 0 || !ip) {
        [self fail:@"The gateway didn't provide an IP configuration."]; return;
    }
    NEPacketTunnelProvider<SVPTunnelSettingsApplying> *provider = _provider;
    if (!provider && !_member) return;

    // Snapshot the negotiated config into ivars so the tun settings can be rebuilt
    // and re-applied live when the gateway role flips, without re-entering
    // libopenconnect off the run thread (the OpenVPN3Bridge captured-state pattern).
    NSMutableArray<NSString *> *dns = [NSMutableArray array];
    for (int i = 0; i < 3; i++) if (ip->dns[i]) [dns addObject:@(ip->dns[i])];

    NSMutableArray<NEIPv4Route *> *v4Split = [NSMutableArray array];
    NSMutableArray<NEIPv6Route *> *v6Split = [NSMutableArray array];
    for (struct oc_split_include *si = ip->split_includes; si; si = si->next) {
        if (!si->route || ![self appendSplitRoute:@(si->route) v4:v4Split v6:v6Split]) {
            [self fail:@"The gateway supplied an invalid split route."]; return;
        }
    }
    // F5 explicitly represents UseDefaultGateway with a /0 mask. For
    // split-tunnel policies, an empty per-family list grants no routes in
    // that family. Some protocols omit split lists altogether for full VPNs.
    BOOL implicitDefault = ip->split_includes == NULL && ![_cfg.protocol isEqualToString:@"f5"];
    BOOL v4Default = implicitDefault || (ip->netmask && strcmp(ip->netmask, "0.0.0.0") == 0);
    BOOL v6Default = implicitDefault;
    for (NEIPv4Route *route in [v4Split copy]) {
        if ([route.destinationSubnetMask isEqualToString:@"0.0.0.0"]) { v4Default = YES; [v4Split removeObject:route]; }
    }
    for (NEIPv6Route *route in [v6Split copy]) {
        if (route.destinationNetworkPrefixLength.intValue == 0) { v6Default = YES; [v6Split removeObject:route]; }
    }

    int v6prefix = 128;
    NSString *assigned6 = ip->addr6 ? @(ip->addr6) : nil;
    struct in6_addr v6;
    if (ip->netmask6) {
        // The public oc_ip_info ABI allows the address to appear exclusively
        // inside netmask6. Pulse and AnyConnect commonly send address/prefix.
        NSArray<NSString *> *parts = [@(ip->netmask6) componentsSeparatedByString:@"/"];
        if (parts.count != 2 || inet_pton(AF_INET6, parts.firstObject.UTF8String, &v6) != 1 ||
            !parseOCPrefix(parts.lastObject.UTF8String, 128, &v6prefix)) {
            [self fail:@"The gateway supplied an invalid IPv6 prefix."]; return;
        }
        if (!assigned6) assigned6 = parts.firstObject;
        if (v6prefix == 0) { v6Default = YES; v6prefix = 128; }
    }
    struct in_addr v4;
    if ((ip->addr && (inet_pton(AF_INET, ip->addr, &v4) != 1 || v4.s_addr == INADDR_ANY ||
                     IN_MULTICAST(ntohl(v4.s_addr)))) ||
        (ip->netmask && !validOCNetmask(ip->netmask)) ||
        (assigned6 && (inet_pton(AF_INET6, assigned6.UTF8String, &v6) != 1 ||
                       IN6_IS_ADDR_UNSPECIFIED(&v6) || IN6_IS_ADDR_MULTICAST(&v6))) || (!ip->addr && !assigned6)) {
        [self fail:@"The gateway supplied an invalid tunnel address or subnet mask."]; return;
    }

    {
        std::lock_guard<std::mutex> hold(_cfgMutex);
        _capRemote = ip->gateway_addr ? @(ip->gateway_addr) : @"127.0.0.1";
        if (ip->addr) {
            _capV4Addrs = @[@(ip->addr)];
            _capV4Masks = @[ip->netmask && strcmp(ip->netmask, "0.0.0.0") ? @(ip->netmask) : @"255.255.255.255"];
            _capHaveV4Default = v4Default;
        } else {
            _capV4Addrs = nil; _capV4Masks = nil; _capHaveV4Default = NO;
        }
        _capV6Addr = assigned6;
        _capV6Prefix = v6prefix;
        _capHaveV6 = assigned6 != nil;
        _capHaveV6Default = assigned6 != nil && v6Default;
        _capV4Split = [v4Split copy];
        _capV6Split = [v6Split copy];
        _capDNS = [dns copy];
        NSArray<NSString *> *domains = ip->domain ? [@(ip->domain) componentsSeparatedByCharactersInSet:
            NSCharacterSet.whitespaceAndNewlineCharacterSet] : @[];
        _capSearchDomains = [domains filteredArrayUsingPredicate:[NSPredicate predicateWithFormat:@"length > 0"]];
        _capMTU = ip->mtu;
        _haveConfig = YES;
    }

    // libopenconnect records the actual host chosen after its authentication
    // flow (including DNS/load-balancer selection). `gateway_addr` below is an
    // IN-TUNNEL next hop, not the Internet endpoint: exposing it as the server
    // made the live globe follow a private 10/8 address instead of the gateway
    // this session is actually connected to.
    const char *connectedHost = openconnect_get_hostname(_vpninfo);
    NSString *serverIP = connectedHost ? @(connectedHost) : @"";
    if ([serverIP hasPrefix:@"["] && [serverIP hasSuffix:@"]"] && serverIP.length > 2) {
        serverIP = [serverIP substringWithRange:NSMakeRange(1, serverIP.length - 2)];
    }
    int serverPort = openconnect_get_port(_vpninfo);

    @synchronized (self) {
        if (ip->addr) _info[@"tunnelIP"] = @(ip->addr);
        if (assigned6) _info[@"tunnelIPv6"] = assigned6;
        if (ip->gateway_addr) _info[@"gateway4"] = @(ip->gateway_addr);
        if (serverIP.length) {
            _info[@"server"] = serverIP;
            _info[@"serverIP"] = serverIP;
        }
        if (serverPort > 0) _info[@"serverPort"] = [NSString stringWithFormat:@"%d", serverPort];
        if (ip->mtu > 0) _info[@"mtu"] = @(ip->mtu);
        _info[@"dns"] = [dns copy];
    }

    if (_member) {
        if (ip->split_excludes || ip->split_dns || _haveMemberTun) {
            [self fail:@"This OpenConnect member changed its network or requested unsupported split DNS or excluded routes."];
            return;
        }
        int descriptor = [_member openEngineDescriptor];
        if (descriptor < 0 || openconnect_setup_tun_fd(_vpninfo, descriptor) != 0) {
            [self fail:@"The OpenConnect member packet channel could not start."]; return;
        }
        _haveMemberTun = YES;
        [self emitStatus:OCStatusConnected event:@"CONNECTED" info:_cfg.server];
        return;
    }
    if (![self applySettings:[self buildCapturedSettings]]) {
        [self fail:@"macOS refused the tunnel network settings."]; return;
    }

    [self teardownTun];
    uint32_t generation = _pumpGeneration.load();
    __weak OpenConnectBridge *weakSelf = self;
    NEPacketTunnelFlow *flow = provider.packetFlow;
    // libopenconnect's Darwin TUN uses a four-byte address family in both
    // directions, including when the descriptor belongs to our socketpair.
    _hostPort = [[VirtualDatagramPort alloc] initWithFamilyHeader:YES received:^(NSData *packet) {
        OpenConnectBridge *bridge = weakSelf;
        if (!bridge || bridge->_pumpGeneration.load() != generation) return;
        NSData *accepted = packet;
        if (bridge->_packetPolicy.inspectInbound) {
            NSMutableData *edit = [packet mutableCopy];
            if (![bridge->_packetPolicy apply:edit.mutableBytes length:edit.length inbound:YES]) return;
            accepted = edit;
        } else if (![bridge->_packetPolicy observePacket:packet.bytes length:packet.length inbound:YES]) return;
        uint32_t af = (((const uint8_t *)accepted.bytes)[0] >> 4) == 6 ? AF_INET6 : AF_INET;
        [flow writePackets:@[accepted] withProtocols:@[@(af)]];
    }];
    int descriptor = [_hostPort openEngineDescriptor];
    if (descriptor < 0 || openconnect_setup_tun_fd(_vpninfo, descriptor) != 0) {
        [self fail:@"The OpenConnect packet channel could not start."];
        return;
    }
    [self readFromFlow:flow port:_hostPort generation:generation];
    [self emitStatus:OCStatusConnected event:@"CONNECTED" info:_cfg.server];
}

- (void)readFromFlow:(NEPacketTunnelFlow *)flow port:(VirtualDatagramPort *)port generation:(uint32_t)generation {
    __weak VirtualDatagramPort *weakPort = port;
    __weak OpenConnectBridge *weakBridge = self;
    __weak NEPacketTunnelFlow *weakFlow = flow;
    [flow readPacketsWithCompletionHandler:^(NSArray<NSData *> *packets, NSArray<NSNumber *> *protocols) {
        OpenConnectBridge *bridge = weakBridge;
        NEPacketTunnelFlow *flow = weakFlow;
        VirtualDatagramPort *port = weakPort;
        if (!bridge || !flow || !port || bridge->_pumpGeneration.load() != generation) return;
        if (bridge->_packetPolicy.inspectOutbound) {
            for (NSData *packet in packets) {
                NSMutableData *copy = [packet mutableCopy];
                if ([bridge->_packetPolicy apply:copy.mutableBytes length:copy.length inbound:NO])
                    [port sendPacket:copy];
            }
        } else {
            if (![bridge->_packetPolicy observeOutboundBatch:packets]) return;
            for (NSData *packet in packets) [port sendPacket:packet];
        }
        if (bridge->_pumpGeneration.load() == generation) [bridge readFromFlow:flow port:port generation:generation];
    }];
}

- (void)teardownTun {
    _pumpGeneration.fetch_add(1);
    [_member close];
    [_hostPort close];
    _hostPort = nil;
}

// MARK: - Route / DNS building (gated on default-route ownership)

// Parse one libopenconnect split-include "route" string into an NE route and
// append it to the matching family bucket. The field is "addr/mask" where the
// mask is either a prefix length or (for v4) a dotted-quad netmask.
- (BOOL)appendSplitRoute:(NSString *)route
                       v4:(NSMutableArray<NEIPv4Route *> *)v4
                       v6:(NSMutableArray<NEIPv6Route *> *)v6 {
    NSArray<NSString *> *parts = [route componentsSeparatedByString:@"/"];
    if (parts.count > 2) return NO;
    NSString *address = parts.firstObject;
    NSString *suffix = parts.count == 2 ? parts.lastObject : nil;
    struct in6_addr addr6;
    if (inet_pton(AF_INET6, address.UTF8String, &addr6) == 1) {
        int prefix = 128;
        if (suffix && !parseOCPrefix(suffix.UTF8String, 128, &prefix)) return NO;
        [v6 addObject:[[NEIPv6Route alloc] initWithDestinationAddress:address networkPrefixLength:@(prefix)]];
        return YES;
    }
    struct in_addr addr4;
    if (inet_pton(AF_INET, address.UTF8String, &addr4) != 1) return NO;
    NSString *mask = suffix;
    if ([suffix containsString:@"."]) {
        if (!validOCNetmask(suffix.UTF8String)) return NO;
    } else {
        int prefix = 32;
        if (suffix && !parseOCPrefix(suffix.UTF8String, 32, &prefix)) return NO;
        struct in_addr subnet = { .s_addr = prefix == 0 ? 0 : htonl(UINT32_MAX << (32 - prefix)) };
        char text[INET_ADDRSTRLEN];
        if (!inet_ntop(AF_INET, &subnet, text, sizeof(text))) return NO;
        mask = @(text);
    }
    [v4 addObject:[[NEIPv4Route alloc] initWithDestinationAddress:address subnetMask:mask]];
    return YES;
}

// Turn the app's destination dictionaries (@{ "address": NSString, "prefix":
// NSNumber, "ipv6": NSNumber(bool) } — RouteDest.dictionary) into NE routes.
// Same decode as OpenVPN3Bridge's, so one wire shape serves both bridges.
static void oc_splitDests(NSArray<NSDictionary<NSString *, id> *> *dests,
                          NSMutableArray<NEIPv4Route *> *v4,
                          NSMutableArray<NEIPv6Route *> *v6) {
    for (NSDictionary *d in dests) {
        NSString *address = d[@"address"];
        int prefix = [d[@"prefix"] intValue];
        BOOL ipv6 = [d[@"ipv6"] boolValue];
        if (address.length == 0 || prefix < 0 || prefix > (ipv6 ? 128 : 32)) continue;
        if (ipv6) {
            [v6 addObject:[[NEIPv6Route alloc] initWithDestinationAddress:address networkPrefixLength:@(prefix)]];
        } else {
            uint32_t mask = prefix == 0 ? 0 : htonl(0xFFFFFFFFu << (32 - prefix));
            struct in_addr a; a.s_addr = mask; char buf[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, &a, buf, sizeof(buf));
            [v4 addObject:[[NEIPv4Route alloc] initWithDestinationAddress:address subnetMask:@(buf)]];
        }
    }
}

// Divert rules from the app: destinations to route *around* this VPN.
- (void)setDivertedDestinations:(NSArray<NSDictionary<NSString *, id> *> *)dests {
    NSMutableArray<NEIPv4Route *> *v4 = [NSMutableArray new];
    NSMutableArray<NEIPv6Route *> *v6 = [NSMutableArray new];
    oc_splitDests(dests, v4, v6);
    std::lock_guard<std::mutex> hold(_cfgMutex);
    _extraV4Excluded = v4; _extraV6Excluded = v6;
    OCLOG("divert: %lu v4 + %lu v6 destinations",
          (unsigned long)v4.count, (unsigned long)v6.count);
}

// Destinations other VPNs route *into* this one (the `.overVPN` target side):
// added to this tunnel's included routes so the OS sends them here.
- (void)setIncludedDestinations:(NSArray<NSDictionary<NSString *, id> *> *)dests {
    NSMutableArray<NEIPv4Route *> *v4 = [NSMutableArray new];
    NSMutableArray<NEIPv6Route *> *v6 = [NSMutableArray new];
    oc_splitDests(dests, v4, v6);
    std::lock_guard<std::mutex> hold(_cfgMutex);
    _extraV4Included = v4; _extraV6Included = v6;
    OCLOG("route-in: %lu v4 + %lu v6 destinations",
          (unsigned long)v4.count, (unsigned long)v6.count);
}

// Build the tun settings from the captured config, honouring the ownership gate:
// an owner (!_suppressDefault) advertises the default route; a demoted non-owner
// drops the default but keeps every specific split-include subnet, and drops the
// DNS catch-all so it can't hijack every lookup (mirrors OpenVPN3Bridge).
- (NEPacketTunnelNetworkSettings *)buildCapturedSettings {
    std::lock_guard<std::mutex> hold(_cfgMutex);
    NEPacketTunnelNetworkSettings *settings =
        [[NEPacketTunnelNetworkSettings alloc] initWithTunnelRemoteAddress:(_capRemote ?: @"127.0.0.1")];

    if (_capV4Addrs.count) {
        NEIPv4Settings *v4 = [[NEIPv4Settings alloc] initWithAddresses:_capV4Addrs subnetMasks:_capV4Masks];
        NSMutableArray<NEIPv4Route *> *inc = [(_capV4Split ?: @[]) mutableCopy];
        if (_capHaveV4Default && !_suppressDefault) [inc addObject:[NEIPv4Route defaultRoute]];
        // Destinations other VPNs route into this one, and this VPN's own diverts.
        if (_extraV4Included.count) [inc addObjectsFromArray:_extraV4Included];
        v4.includedRoutes = inc;
        if (_extraV4Excluded.count) v4.excludedRoutes = _extraV4Excluded;
        settings.IPv4Settings = v4;
    }
    if (_capHaveV6 && _capV6Addr) {
        NEIPv6Settings *v6 = [[NEIPv6Settings alloc] initWithAddresses:@[_capV6Addr]
                                                 networkPrefixLengths:@[@(_capV6Prefix)]];
        NSMutableArray<NEIPv6Route *> *inc = [(_capV6Split ?: @[]) mutableCopy];
        if (_capHaveV6Default && !_suppressDefault) [inc addObject:[NEIPv6Route defaultRoute]];
        if (_extraV6Included.count) [inc addObjectsFromArray:_extraV6Included];
        v6.includedRoutes = inc;
        if (_extraV6Excluded.count) v6.excludedRoutes = _extraV6Excluded;
        settings.IPv6Settings = v6;
    }
    // DNS: the app-arbitrated override (DNS mediator applier) is the sole writer when
    // set, winning over the captured push; nil falls back to the captured DNS.
    if (_dnsOverride) {
        settings.DNSSettings = _dnsOverride;
    } else if (_capDNS.count) {
        NEDNSSettings *d = [[NEDNSSettings alloc] initWithServers:_capDNS];
        if (_capSearchDomains.count) d.searchDomains = _capSearchDomains;
        BOOL ownsDefault = (_capHaveV4Default || _capHaveV6Default) && !_suppressDefault;
        if (ownsDefault) {
            d.matchDomains = @[@""];              // owner: route ALL DNS through the tunnel
            settings.DNSSettings = d;
        } else if (_capSearchDomains.count) {
            // Demoted / split: scope the tunnel's resolvers to its own search
            // domains only. With none there is nothing safe to scope to, so the
            // tunnel DNS is left off entirely.
            d.matchDomains = _capSearchDomains;
            settings.DNSSettings = d;
        }
    }
    // System proxy: apply the app-arbitrated decision (owner egress only) whenever a
    // config is in play (mirrors OpenVPN3Bridge).
    if (_proxySettings) settings.proxySettings = _proxySettings;
    if (_capMTU > 0) settings.MTU = @(_capMTU);
    return settings;
}

// Apply settings synchronously (callers are off the main thread). Returns YES on
// success. Must NOT be called while holding _cfgMutex (it blocks on completion).
- (BOOL)applySettings:(NEPacketTunnelNetworkSettings *)settings {
    NEPacketTunnelProvider<SVPTunnelSettingsApplying> *provider = _provider;
    if (!provider) return NO;
    dispatch_semaphore_t done = dispatch_semaphore_create(0);
    __block BOOL ok = NO;
    [provider applyNetworkSettings:settings completionHandler:^(NSError *e) {
        ok = (e == nil);
        if (e) OCLOG("setTunnelNetworkSettings failed: %{public}s", e.localizedDescription.UTF8String);
        dispatch_semaphore_signal(done);
    }];
    dispatch_semaphore_wait(done, DISPATCH_TIME_FOREVER);
    return ok;
}

// MARK: - Default-gateway ownership (StateMediators.md · Route mediator)

- (void)setInitialDefaultRouteOwned:(BOOL)owned {
    // Establish-time seed, BEFORE setup_tun builds the tun. No reapply: no tun yet.
    std::lock_guard<std::mutex> hold(_cfgMutex);
    _suppressDefault = !owned;
    OCLOG("setInitialDefaultRouteOwned: %d (suppressDefault=%d)", owned, !owned);
}

- (BOOL)setDefaultRouteOwned:(BOOL)owned {
    BOOL haveConfig;
    {
        std::lock_guard<std::mutex> hold(_cfgMutex);
        _suppressDefault = !owned;
        haveConfig = _haveConfig;
    }
    OCLOG("setDefaultRouteOwned: %d (suppressDefault=%d)", owned, !owned);
    // Live: rebuild + re-apply the captured settings with the default-route gate
    // flipped. No reconnect — the CSTP session and the packet pump are untouched.
    // Before the first setup_tun there is nothing to rebuild; the flag we just
    // stored will be honoured when the tun is first built.
    if (!haveConfig) return YES;
    return [self applySettings:[self buildCapturedSettings]];
}

// MARK: - Proxy / DNS mediator appliers (Docs/StateMediators.md)

// Store the arbitrated system proxy and re-apply the captured settings live (no
// reconnect); nil clears it. Mirrors OpenVPN3Bridge.applyProxySettings:.
- (BOOL)applyProxySettings:(NEProxySettings *)proxy {
    BOOL haveConfig;
    {
        std::lock_guard<std::mutex> hold(_cfgMutex);
        _proxySettings = proxy;
        haveConfig = _haveConfig;
    }
    OCLOG("applyProxySettings: %{public}s", proxy ? "set" : "cleared");
    if (!haveConfig) return YES;   // no tun yet; honoured at first setup_tun
    return [self applySettings:[self buildCapturedSettings]];
}

// Store the arbitrated per-tunnel DNS and re-apply the captured settings live (no
// reconnect); nil restores the captured/pushed DNS. Mirrors OpenVPN3Bridge.
- (BOOL)applyDNSSettings:(NEDNSSettings *)dns {
    BOOL haveConfig;
    {
        std::lock_guard<std::mutex> hold(_cfgMutex);
        _dnsOverride = dns;
        haveConfig = _haveConfig;
    }
    OCLOG("applyDNSSettings: %{public}s", dns ? "set" : "cleared");
    if (!haveConfig) return YES;
    return [self applySettings:[self buildCapturedSettings]];
}

// MARK: - Delegate plumbing

- (void)emitStatus:(OCStatus)status event:(NSString *)name info:(NSString *)info {
    [_delegate ocBridge:self didChangeStatus:status event:name info:info];
}

- (void)fail:(NSString *)message {
    _running = false;
    NSError *e = [NSError errorWithDomain:kOCErrorDomain code:1
                                 userInfo:@{ NSLocalizedDescriptionKey: message }];
    [_delegate ocBridge:self didFailWithError:e];
}

@end

// MARK: - C trampolines

static int oc_validate_cert(void *priv, const char *reason) {
    return [(__bridge OpenConnectBridge *)priv validateCert:reason];
}
static int oc_process_form(void *priv, struct oc_auth_form *form) {
    return [(__bridge OpenConnectBridge *)priv processForm:form];
}
static void oc_progress(void *priv, int level, const char *fmt, ...) {
    char line[1024];
    va_list ap; va_start(ap, fmt); vsnprintf(line, sizeof(line), fmt, ap); va_end(ap);
    [(__bridge OpenConnectBridge *)priv progress:level line:[NSString stringWithUTF8String:line] ?: @""];
}
static void oc_setup_tun(void *priv) {
    [(__bridge OpenConnectBridge *)priv setupTun];
}
static void oc_stats(void *priv, const struct oc_stats *stats) {
    [(__bridge OpenConnectBridge *)priv stats:stats];
}

static int oc_member_socket(void *priv, int fd, int family) {
    return [(__bridge OpenConnectBridge *)priv bindSocket:fd family:family];
}
static void oc_member_reconnected(void *priv) {
    OpenConnectBridge *bridge = (__bridge OpenConnectBridge *)priv;
    [bridge disconnect];
    [bridge fail:@"The OpenConnect member must negotiate new settings after reconnect."];
}
static int oc_required_pin(void *priv) {
    return [(__bridge OpenConnectBridge *)priv validateCert:"required peer identity"];
}
static int oc_member_resolve(void *priv, const char *node, const char *service, const struct addrinfo *hints, struct addrinfo **result) {
    return [(__bridge OpenConnectBridge *)priv resolveHost:node service:service hints:hints result:result];
}
