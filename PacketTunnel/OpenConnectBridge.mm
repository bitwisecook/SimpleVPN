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
    @synchronized (self) { return [_info copy]; }
}

// MARK: - Tun bring-up

- (void)setupTun {
    const struct oc_ip_info *ip = NULL;
    if (openconnect_get_ip_info(_vpninfo, &ip, NULL, NULL) != 0 || !ip) {
        [self fail:@"The gateway didn't provide an IP configuration."]; return;
    }
    NEPacketTunnelProvider *provider = _provider;
    if (!provider) return;

    NEPacketTunnelNetworkSettings *settings =
        [[NEPacketTunnelNetworkSettings alloc] initWithTunnelRemoteAddress:
            (ip->gateway_addr ? @(ip->gateway_addr) : @"127.0.0.1")];

    if (ip->addr && ip->netmask) {
        NEIPv4Settings *v4 = [[NEIPv4Settings alloc] initWithAddresses:@[@(ip->addr)]
                                                          subnetMasks:@[@(ip->netmask)]];
        v4.includedRoutes = @[[NEIPv4Route defaultRoute]];   // split routing is a refinement
        settings.IPv4Settings = v4;
    }
    if (ip->addr6) {
        // netmask6 is "addr/prefix"; addr6 is the bare address.
        NSInteger prefix = 128;
        if (ip->netmask6) {
            NSString *nm = @(ip->netmask6);
            NSRange slash = [nm rangeOfString:@"/"];
            if (slash.location != NSNotFound) prefix = [[nm substringFromIndex:slash.location + 1] integerValue];
        }
        NEIPv6Settings *v6 = [[NEIPv6Settings alloc] initWithAddresses:@[@(ip->addr6)]
                                                 networkPrefixLengths:@[@(prefix)]];
        v6.includedRoutes = @[[NEIPv6Route defaultRoute]];
        settings.IPv6Settings = v6;
    }
    NSMutableArray<NSString *> *dns = [NSMutableArray array];
    for (int i = 0; i < 3; i++) if (ip->dns[i]) [dns addObject:@(ip->dns[i])];
    if (dns.count) {
        NEDNSSettings *d = [[NEDNSSettings alloc] initWithServers:dns];
        if (ip->domain) d.searchDomains = @[@(ip->domain)];
        d.matchDomains = @[@""];
        settings.DNSSettings = d;
    }
    if (ip->mtu > 0) settings.MTU = @(ip->mtu);

    @synchronized (self) {
        if (ip->addr) _info[@"tunnelIP"] = @(ip->addr);
        if (ip->addr6) _info[@"tunnelIPv6"] = @(ip->addr6);
        if (ip->gateway_addr) _info[@"server"] = @(ip->gateway_addr);
        if (ip->mtu > 0) _info[@"mtu"] = @(ip->mtu);
        if (dns.count) _info[@"dns"] = [dns copy];
    }

    dispatch_semaphore_t done = dispatch_semaphore_create(0);
    __block BOOL ok = NO;
    [provider setTunnelNetworkSettings:settings completionHandler:^(NSError *e) {
        ok = (e == nil);
        if (e) OCLOG("setTunnelNetworkSettings failed: %{public}s", e.localizedDescription.UTF8String);
        dispatch_semaphore_signal(done);
    }];
    dispatch_semaphore_wait(done, dispatch_time(DISPATCH_TIME_NOW, 15 * NSEC_PER_SEC));
    if (!ok) { [self fail:@"macOS refused the tunnel network settings."]; return; }

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
