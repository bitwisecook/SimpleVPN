// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
//  OpenConnectBridge.mm
//  ObjC surface over libopenconnect. Auth + mainloop run on a background thread;
//  the negotiated IP config becomes NEPacketTunnelNetworkSettings; IP packets are
//  pumped between openconnect and NEPacketTunnelFlow over a socketpair (same shape
//  as OpenVPN3Bridge). In-process — no `openconnect` subprocess.
//
//  Runtime note: the exact tun framing over a provided fd and the finer points of
//  SAML/SSO auth need validation against a live gateway; the structure below is the
//  standard libopenconnect embedding (obtain_cookie → make_cstp_connection →
//  setup_tun → mainloop).
//

#import "OpenConnectBridge.h"
#import <os/log.h>
#include <string>
#include <mutex>
#include <atomic>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Weverything"
#include <openconnect.h>
#pragma clang diagnostic pop

static NSErrorDomain const kOCErrorDomain = @"OpenConnectBridge";
static os_log_t gOCLog = os_log_create("com.bragi0.SimpleVPN.PacketTunnel", "openconnect");
#define OCLOG(fmt, ...) os_log(gOCLog, fmt, ##__VA_ARGS__)
static const int kOCSockBuf = 1 << 20;

@implementation OCClientSettings
@end

// C trampolines → the bridge instance carried as privdata.
static int oc_validate_cert(void *priv, const char *reason);
static int oc_process_form(void *priv, struct oc_auth_form *form);
static void oc_progress(void *priv, int level, const char *fmt, ...) __attribute__((format(printf, 3, 4)));
static void oc_setup_tun(void *priv);
static void oc_stats(void *priv, const struct oc_stats *stats);

@interface OpenConnectBridge () {
    __weak NEPacketTunnelProvider *_provider;
    __weak id<OpenConnectBridgeDelegate> _delegate;
    struct openconnect_info *_vpninfo;
    OCClientSettings *_cfg;
    dispatch_queue_t _runQueue;      // owns the openconnect mainloop
    dispatch_queue_t _pumpQueue;     // services the inbound read source (never blocked by the mainloop)
    dispatch_source_t _readSource;
    int _ourFD, _ocFD;
    int _cancelPipe[2];              // write end nudges openconnect_mainloop to return on disconnect
    std::atomic<uint32_t> _pumpGeneration;
    std::atomic<bool> _running;
    std::mutex _statsMutex;
    int64_t _bytesIn, _bytesOut;
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
}
@end

@implementation OpenConnectBridge

- (instancetype)initWithProvider:(NEPacketTunnelProvider *)provider
                        delegate:(id<OpenConnectBridgeDelegate>)delegate {
    if ((self = [super init])) {
        _provider = provider;
        _delegate = delegate;
        _ourFD = _ocFD = -1;
        _pumpGeneration = 0;
        _running = false;
        _info = [NSMutableDictionary dictionary];
        _cancelPipe[0] = _cancelPipe[1] = -1;
        _runQueue = dispatch_queue_create("com.bragi0.SimpleVPN.openconnect.run", DISPATCH_QUEUE_SERIAL);
        // Inbound packets are pumped on their own queue — the run queue is
        // monopolised by the mainloop for the whole session, so a read source
        // targeted there would never fire.
        _pumpQueue = dispatch_queue_create("com.bragi0.SimpleVPN.openconnect.pump", DISPATCH_QUEUE_SERIAL);
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
    [self emitStatus:OCStatusConnecting event:@"CONNECTING" info:_cfg.server];

    const char *ua = _cfg.userAgent.length ? _cfg.userAgent.UTF8String : "SimpleVPN";
    _vpninfo = openconnect_vpninfo_new(ua, oc_validate_cert, NULL, oc_process_form,
                                       oc_progress, (__bridge void *)self);
    if (!_vpninfo) { [self fail:@"Couldn't initialise the OpenConnect engine."]; return; }

    openconnect_set_loglevel(_vpninfo, PRG_INFO);
    openconnect_set_setup_tun_handler(_vpninfo, oc_setup_tun);
    openconnect_set_stats_handler(_vpninfo, oc_stats);

    // Certificate trust: validate against the OS trust store (and any extra CA
    // bundle) by default. oc_validate_cert is only invoked when that verification
    // *fails*, and it rejects unless the user pinned this exact certificate — so a
    // gateway with an untrusted/self-signed cert and no pin cannot be MITM'd.
    openconnect_set_system_trust(_vpninfo, 1);
    if (_cfg.caFile.length) openconnect_set_cafile(_vpninfo, _cfg.caFile.UTF8String);

    // Cancel fd: disconnect() writes here so openconnect_mainloop returns promptly
    // instead of us calling mainloop concurrently from another thread.
    if (pipe(_cancelPipe) == 0) openconnect_set_cancel_fd(_vpninfo, _cancelPipe[0]);

    if (_cfg.protocol.length) openconnect_set_protocol(_vpninfo, _cfg.protocol.UTF8String);
    if (openconnect_parse_url(_vpninfo, _cfg.server.UTF8String) != 0) {
        [self fail:@"That server address couldn't be parsed."]; return;
    }

    if (openconnect_obtain_cookie(_vpninfo) != 0) {
        [self fail:@"Sign-in failed (check your username, password or one-time code)."]; return;
    }
    if (openconnect_make_cstp_connection(_vpninfo) != 0) {
        [self fail:@"Couldn't establish the secure connection to the gateway."]; return;
    }

    [self emitStatus:OCStatusConnected event:@"CONNECTED" info:_cfg.server];

    // Pump the tunnel until asked to stop. mainloop returns 0 to be called again,
    // < 0 on a fatal error.
    while (_running.load()) {
        int r = openconnect_mainloop(_vpninfo, 300, 10);
        if (r < 0) { if (_running.load()) [self fail:@"The VPN connection dropped."]; break; }
    }
    [self teardownTun];
    if (_vpninfo) { openconnect_vpninfo_free(_vpninfo); _vpninfo = NULL; }
    if (_cancelPipe[0] >= 0) { close(_cancelPipe[0]); _cancelPipe[0] = -1; }
    if (_cancelPipe[1] >= 0) { close(_cancelPipe[1]); _cancelPipe[1] = -1; }
    [self emitStatus:OCStatusDisconnected event:@"DISCONNECTED" info:@""];
}

- (void)disconnect {
    _running = false;
    // Wake the mainloop via its cancel fd — do NOT call openconnect_mainloop here;
    // it is already running on _runQueue and is not safe to invoke concurrently on
    // the same _vpninfo (and _vpninfo may be freed by runSession as we return).
    if (_cancelPipe[1] >= 0) { char b = 'x'; (void)write(_cancelPipe[1], &b, 1); }
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
    const char *h = openconnect_get_peer_cert_hash(_vpninfo);
    NSString *hash = h ? [NSString stringWithUTF8String:h] : @"";
    // openconnect hashes may carry a prefix ("pin-sha256:" / "sha256:"); the pin
    // may too. Compare only the hex tail after the last ':' , case-insensitively,
    // as an exact equality (not hasSuffix:, which a truncated pin could satisfy).
    NSString *(^tail)(NSString *) = ^NSString *(NSString *s) {
        NSRange c = [s rangeOfString:@":" options:NSBackwardsSearch];
        return (c.location == NSNotFound ? s : [s substringFromIndex:c.location + 1]).lowercaseString;
    };
    BOOL match = [tail(hash) isEqualToString:tail(_cfg.serverCertSHA256)];
    OCLOG("pinned cert %{public}s (%{public}s)", match ? "matched" : "MISMATCH", reason ?: "");
    return match ? 0 : -1;
}

- (int)processForm:(struct oc_auth_form *)form {
    // Pick the auth group (realm) if the form offers one.
    if (form->authgroup_opt && _cfg.realm.length) {
        openconnect_set_option_value(&form->authgroup_opt->form, _cfg.realm.UTF8String);
    }
    for (struct oc_form_opt *opt = form->opts; opt; opt = opt->next) {
        if (opt->flags & OC_FORM_OPT_IGNORE) continue;
        switch (opt->type) {
            case OC_FORM_OPT_TEXT:
            case OC_FORM_OPT_SSO_USER:
                if (_cfg.username.length) openconnect_set_option_value(opt, _cfg.username.UTF8String);
                break;
            case OC_FORM_OPT_PASSWORD:
            case OC_FORM_OPT_TOKEN:
                if (_cfg.password.length) openconnect_set_option_value(opt, _cfg.password.UTF8String);
                break;
            default: break;
        }
    }
    return OC_FORM_RESULT_OK;
}

- (void)progress:(int)level line:(NSString *)line {
    [_delegate ocBridge:self didLog:line];
}

- (void)stats:(const struct oc_stats *)s {
    std::lock_guard<std::mutex> lk(_statsMutex);
    _bytesIn = (int64_t)s->rx_bytes;
    _bytesOut = (int64_t)s->tx_bytes;
}

- (void)transportBytesIn:(int64_t *)bytesIn bytesOut:(int64_t *)bytesOut {
    std::lock_guard<std::mutex> lk(_statsMutex);
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
    NEPacketTunnelProvider *provider = _provider;
    if (!provider) return;

    // Snapshot the negotiated config into ivars so the tun settings can be rebuilt
    // and re-applied live when the gateway role flips, without re-entering
    // libopenconnect off the run thread (the OpenVPN3Bridge captured-state pattern).
    NSMutableArray<NSString *> *dns = [NSMutableArray array];
    for (int i = 0; i < 3; i++) if (ip->dns[i]) [dns addObject:@(ip->dns[i])];

    NSMutableArray<NEIPv4Route *> *v4Split = [NSMutableArray array];
    NSMutableArray<NEIPv6Route *> *v6Split = [NSMutableArray array];
    for (struct oc_split_include *si = ip->split_includes; si; si = si->next) {
        if (!si->route) continue;
        [self appendSplitRoute:@(si->route) v4:v4Split v6:v6Split];
    }

    NSInteger v6prefix = 128;
    if (ip->addr6 && ip->netmask6) {
        NSString *nm = @(ip->netmask6);   // "addr/prefix"
        NSRange slash = [nm rangeOfString:@"/"];
        if (slash.location != NSNotFound) v6prefix = [[nm substringFromIndex:slash.location + 1] integerValue];
    }

    {
        std::lock_guard<std::mutex> hold(_cfgMutex);
        _capRemote = ip->gateway_addr ? @(ip->gateway_addr) : @"127.0.0.1";
        if (ip->addr && ip->netmask) {
            _capV4Addrs = @[@(ip->addr)]; _capV4Masks = @[@(ip->netmask)];
            _capHaveV4Default = YES;   // OpenConnect brings up a full tunnel by default
        } else {
            _capV4Addrs = nil; _capV4Masks = nil; _capHaveV4Default = NO;
        }
        _capV6Addr = ip->addr6 ? @(ip->addr6) : nil;
        _capV6Prefix = v6prefix;
        _capHaveV6 = (ip->addr6 != NULL);
        _capHaveV6Default = (ip->addr6 != NULL);
        _capV4Split = [v4Split copy];
        _capV6Split = [v6Split copy];
        _capDNS = [dns copy];
        _capSearchDomains = ip->domain ? @[@(ip->domain)] : @[];
        _capMTU = ip->mtu;
        _haveConfig = YES;
    }

    @synchronized (self) {
        if (ip->addr) _info[@"tunnelIP"] = @(ip->addr);
        if (ip->addr6) _info[@"tunnelIPv6"] = @(ip->addr6);
        if (ip->gateway_addr) _info[@"server"] = @(ip->gateway_addr);
        if (ip->mtu > 0) _info[@"mtu"] = @(ip->mtu);
        if (dns.count) _info[@"dns"] = [dns copy];
    }

    if (![self applySettings:[self buildCapturedSettings]]) {
        [self fail:@"macOS refused the tunnel network settings."]; return;
    }

    // openconnect calls this handler again on every CSTP reconnect. Cancel the
    // previous read source and close our previous socketpair end first, or each
    // reconnect leaks a source + two fds until the extension exhausts descriptors.
    [self teardownTun];

    // Hand openconnect a socketpair end; pump the other into the packet flow.
    int fds[2];
    if (socketpair(AF_UNIX, SOCK_DGRAM, 0, fds) != 0) { [self fail:@"socketpair failed"]; return; }
    setsockopt(fds[0], SOL_SOCKET, SO_SNDBUF, &kOCSockBuf, sizeof(kOCSockBuf));
    setsockopt(fds[1], SOL_SOCKET, SO_RCVBUF, &kOCSockBuf, sizeof(kOCSockBuf));
    _ocFD = fds[0];
    _ourFD = fds[1];
    _pumpGeneration.fetch_add(1);
    openconnect_setup_tun_fd(_vpninfo, _ocFD);
    [self startPumpInto:provider.packetFlow];
}

// openconnect ↔ packetFlow. Framing note: unlike openvpn3 (which frames a utun
// with a 4-byte AF header), libopenconnect's os_tun fd path carries RAW IP with no
// address-family prefix in either direction. So outbound we write pkt.bytes verbatim
// and inbound we infer the family from the IP version nibble (buf[0] >> 4). If a
// future openconnect build switches to a 4-byte AF header on the fd, both the write
// (skip 4) and the read (family from the header, payload at +4) must change together.
- (void)startPumpInto:(NEPacketTunnelFlow *)flow {
    int fd = _ourFD;
    uint32_t gen = _pumpGeneration.load();

    // packetFlow → openconnect
    [flow readPacketsWithCompletionHandler:^(NSArray<NSData *> *packets, NSArray<NSNumber *> *protocols) {
        if (self->_pumpGeneration.load() != gen) return;
        for (NSData *pkt in packets) (void)write(fd, pkt.bytes, pkt.length);
        [self startPumpInto:flow];
    }];

    // openconnect → packetFlow. Target the pump queue, NOT _runQueue: the run
    // queue is serial and monopolised by the mainloop for the whole session, so a
    // source targeted there would never deliver a single inbound packet.
    _readSource = dispatch_source_create(DISPATCH_SOURCE_TYPE_READ, (uintptr_t)fd, 0, _pumpQueue);
    dispatch_source_set_event_handler(_readSource, ^{
        uint8_t buf[65536];
        ssize_t n = read(fd, buf, sizeof(buf));
        if (n <= 0) return;
        uint32_t af = ((buf[0] >> 4) == 6) ? AF_INET6 : AF_INET;
        [flow writePackets:@[[NSData dataWithBytes:buf length:(NSUInteger)n]] withProtocols:@[@(af)]];
    });
    dispatch_resume(_readSource);
}

- (void)teardownTun {
    _pumpGeneration.fetch_add(1);
    int fd = _ourFD; _ourFD = -1;
    if (_readSource) {
        dispatch_source_t src = _readSource; _readSource = nil;
        dispatch_source_set_cancel_handler(src, ^{ if (fd >= 0) close(fd); });
        dispatch_source_cancel(src);
    } else if (fd >= 0) {
        close(fd);
    }
    _ocFD = -1;   // openconnect owns/closes its end
}

// MARK: - Route / DNS building (gated on default-route ownership)

// Parse one libopenconnect split-include "route" string into an NE route and
// append it to the matching family bucket. The field is "addr/mask" where the
// mask is either a prefix length or (for v4) a dotted-quad netmask.
- (void)appendSplitRoute:(NSString *)route
                      v4:(NSMutableArray<NEIPv4Route *> *)v4
                      v6:(NSMutableArray<NEIPv6Route *> *)v6 {
    NSRange slash = [route rangeOfString:@"/" options:NSBackwardsSearch];
    NSString *addr = slash.location == NSNotFound ? route : [route substringToIndex:slash.location];
    NSString *maskPart = slash.location == NSNotFound ? @"" : [route substringFromIndex:slash.location + 1];
    addr = [addr stringByTrimmingCharactersInSet:[NSCharacterSet whitespaceCharacterSet]];
    if (!addr.length) return;

    if ([addr containsString:@":"]) {                    // IPv6
        NSInteger prefix = maskPart.length ? [maskPart integerValue] : 128;
        if (prefix < 0 || prefix > 128) prefix = 128;
        [v6 addObject:[[NEIPv6Route alloc] initWithDestinationAddress:addr networkPrefixLength:@(prefix)]];
        return;
    }
    // IPv4: mask may be a prefix length or a dotted-quad netmask.
    NSString *mask;
    if ([maskPart containsString:@"."]) {
        mask = maskPart;
    } else {
        NSInteger prefix = maskPart.length ? [maskPart integerValue] : 32;
        if (prefix < 0 || prefix > 32) prefix = 32;
        uint32_t m = prefix == 0 ? 0 : htonl(0xFFFFFFFFu << (32 - prefix));
        struct in_addr a; a.s_addr = m; char buf[INET_ADDRSTRLEN];
        inet_ntop(AF_INET, &a, buf, sizeof(buf));
        mask = @(buf);
    }
    [v4 addObject:[[NEIPv4Route alloc] initWithDestinationAddress:addr subnetMask:mask]];
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
        v4.includedRoutes = inc;
        settings.IPv4Settings = v4;
    }
    if (_capHaveV6 && _capV6Addr) {
        NEIPv6Settings *v6 = [[NEIPv6Settings alloc] initWithAddresses:@[_capV6Addr]
                                                 networkPrefixLengths:@[@(_capV6Prefix)]];
        NSMutableArray<NEIPv6Route *> *inc = [(_capV6Split ?: @[]) mutableCopy];
        if (_capHaveV6Default && !_suppressDefault) [inc addObject:[NEIPv6Route defaultRoute]];
        v6.includedRoutes = inc;
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
    NEPacketTunnelProvider *provider = _provider;
    if (!provider) return NO;
    dispatch_semaphore_t done = dispatch_semaphore_create(0);
    __block BOOL ok = NO;
    [provider setTunnelNetworkSettings:settings completionHandler:^(NSError *e) {
        ok = (e == nil);
        if (e) OCLOG("setTunnelNetworkSettings failed: %{public}s", e.localizedDescription.UTF8String);
        dispatch_semaphore_signal(done);
    }];
    dispatch_semaphore_wait(done, dispatch_time(DISPATCH_TIME_NOW, 15 * NSEC_PER_SEC));
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
