// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only

//
//  OpenVPN3Bridge.mm
//  ObjC++ bridge between the OpenVPN 3 ClientAPI and NEPacketTunnelProvider.
//

#import "OpenVPN3Bridge.h"
#import <os/log.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <memory>
#include <string>

// The openvpn3 ClientAPI. Implementation lives in OpenVPNEngine.xcframework;
// this pulls in only the public interface. Warnings from the C++ headers are noise here.
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Weverything"
#include <client/ovpncli.hpp>
#pragma clang diagnostic pop

using namespace openvpn;                 // DnsOptions, DnsAddress, ...
using namespace openvpn::ClientAPI;      // Config, EvalConfig, ProvideCreds, Event, ...

static NSErrorDomain const kOVPNErrorDomain = @"OpenVPN3Bridge";
static const int kOVPNSockBuf = 1 << 20; // 1 MiB socketpair buffers
static os_log_t gBridgeLog = os_log_create("com.bragi0.SimpleVPN.PacketTunnel", "bridge");
#define BLOG(fmt, ...) os_log(gBridgeLog, fmt, ##__VA_ARGS__)

// MARK: - Private ObjC surface the C++ client calls into.
@interface OpenVPN3Bridge ()
- (void)tunReset;
- (void)tunSetRemote:(NSString *)address;
- (void)tunAddIPv4Address:(NSString *)address prefix:(int)prefix;
- (void)tunAddIPv6Address:(NSString *)address prefix:(int)prefix;
- (void)tunRerouteGWv4;
- (void)tunRerouteGWv6;
- (void)tunAddRoute:(NSString *)address prefix:(int)prefix ipv6:(BOOL)ipv6;
- (void)tunExcludeRoute:(NSString *)address prefix:(int)prefix ipv6:(BOOL)ipv6;
- (void)tunAddDNS:(NSString *)address;
- (void)tunAddSearchDomain:(NSString *)domain;
- (void)tunAddProxy:(NSString *)proxy;
- (void)tunSetMTU:(int)mtu;
- (int)tunEstablish;
- (void)tunTeardown;
- (void)emitStatus:(OVPNStatus)status event:(NSString *)name info:(NSString *)info;
- (void)emitError:(NSString *)message;
- (void)emitLog:(NSString *)line;
@end

// MARK: - C++ OpenVPN 3 client.
namespace {
using namespace openvpn::ClientAPI;

class Client : public OpenVPNClient {
public:
    explicit Client(OpenVPN3Bridge *bridge) : bridge_((__bridge void *)bridge) {}

    OpenVPN3Bridge *bridge() const { return (__bridge OpenVPN3Bridge *)bridge_; }

    // ---- TunBuilderBase ----
    bool tun_builder_new() override { [bridge() tunReset]; return true; }
    bool tun_builder_set_layer(int layer) override { return layer == 3; } // TUN only
    bool tun_builder_set_remote_address(const std::string &address, bool) override {
        [bridge() tunSetRemote:@(address.c_str())]; return true;
    }
    bool tun_builder_add_address(const std::string &address, int prefix, const std::string &,
                                 bool ipv6, bool) override {
        if (ipv6) [bridge() tunAddIPv6Address:@(address.c_str()) prefix:prefix];
        else      [bridge() tunAddIPv4Address:@(address.c_str()) prefix:prefix];
        return true;
    }
    bool tun_builder_reroute_gw(bool ipv4, bool ipv6, unsigned int) override {
        if (ipv4) [bridge() tunRerouteGWv4];
        if (ipv6) [bridge() tunRerouteGWv6];
        return true;
    }
    bool tun_builder_add_route(const std::string &address, int prefix, int, bool ipv6) override {
        [bridge() tunAddRoute:@(address.c_str()) prefix:prefix ipv6:ipv6]; return true;
    }
    bool tun_builder_exclude_route(const std::string &address, int prefix, int, bool ipv6) override {
        [bridge() tunExcludeRoute:@(address.c_str()) prefix:prefix ipv6:ipv6]; return true;
    }
    bool tun_builder_set_dns_options(const DnsOptions &dns) override {
        for (const auto &kv : dns.servers)
            for (const auto &addr : kv.second.addresses)
                [bridge() tunAddDNS:@(addr.address.c_str())];
        for (const auto &d : dns.search_domains)
            [bridge() tunAddSearchDomain:@(d.to_string().c_str())];
        return true;
    }
    bool tun_builder_set_mtu(int mtu) override { [bridge() tunSetMTU:mtu]; return true; }
    bool tun_builder_set_proxy_http(const std::string &host, int port) override {
        [bridge() tunAddProxy:[NSString stringWithFormat:@"HTTP %s:%d", host.c_str(), port]]; return true;
    }
    bool tun_builder_set_proxy_https(const std::string &host, int port) override {
        [bridge() tunAddProxy:[NSString stringWithFormat:@"HTTPS %s:%d", host.c_str(), port]]; return true;
    }
    bool tun_builder_set_proxy_auto_config_url(const std::string &url) override {
        [bridge() tunAddProxy:[NSString stringWithFormat:@"PAC %s", url.c_str()]]; return true;
    }
    bool tun_builder_set_session_name(const std::string &) override { return true; }
    bool tun_builder_persist() override { return false; }      // force fd-based establish()
    int  tun_builder_establish() override { return [bridge() tunEstablish]; }
    void tun_builder_teardown(bool) override { [bridge() tunTeardown]; }

    // ---- OpenVPNClient ----
    bool socket_protect(openvpn_io::detail::socket_type, std::string, bool) override {
        return true; // NE sockets already bypass the tunnel
    }
    bool pause_on_connection_timeout() override { return false; }
    void external_pki_cert_request(ExternalPKICertRequest &req) override { req.error = true; req.errorText = "external PKI not supported"; }
    void external_pki_sign_request(ExternalPKISignRequest &req) override { req.error = true; req.errorText = "external PKI not supported"; }
    void acc_event(const AppCustomControlMessageEvent &) override {}

    void log(const LogInfo &li) override { [bridge() emitLog:@(li.text.c_str())]; }

    void event(const Event &ev) override {
        NSString *name = @(ev.name.c_str());
        NSString *info = @(ev.info.c_str());
        if (ev.fatal || ev.error) { [bridge() emitError:[NSString stringWithFormat:@"%@: %@", name, info]]; return; }
        OVPNStatus s = OVPNStatusConnecting;
        if (ev.name == "CONNECTED")            s = OVPNStatusConnected;
        else if (ev.name == "DISCONNECTED")    s = OVPNStatusDisconnected;
        else if (ev.name == "RECONNECTING")    s = OVPNStatusReconnecting;
        [bridge() emitStatus:s event:name info:info];
    }

private:
    void *bridge_;
};
} // namespace

// MARK: - Bridge implementation.
@implementation OpenVPN3Bridge {
    __weak NEPacketTunnelProvider *_provider;
    __weak id<OpenVPN3BridgeDelegate> _delegate;
    std::unique_ptr<Client> _client;
    dispatch_queue_t _runQueue;   // runs the blocking connect()
    dispatch_queue_t _cbQueue;    // serializes delegate callbacks

    // captured tun settings
    NSMutableArray<NSString *> *_v4Addrs, *_v4Masks, *_v6Addrs;
    NSMutableArray<NSNumber *> *_v6Prefixes;
    NSMutableArray<NEIPv4Route *> *_v4Included, *_v4Excluded;
    NSMutableArray<NEIPv6Route *> *_v6Included, *_v6Excluded;
    NSMutableArray<NSString *> *_dns, *_searchDomains, *_proxies;
    NSString *_remote;
    BOOL _defaultV4, _defaultV6;
    int _mtu;

    // packet pump
    int _ovpnFD;                  // openvpn3-owned end
    int _ourFD;                   // our end
    dispatch_source_t _readSource;
}

- (instancetype)initWithProvider:(NEPacketTunnelProvider *)provider delegate:(id<OpenVPN3BridgeDelegate>)delegate {
    if ((self = [super init])) {
        _provider = provider;
        _delegate = delegate;
        _runQueue = dispatch_queue_create("com.bragi0.SimpleVPN.ovpn.run", DISPATCH_QUEUE_SERIAL);
        _cbQueue = dispatch_queue_create("com.bragi0.SimpleVPN.ovpn.cb", DISPATCH_QUEUE_SERIAL);
        _ovpnFD = _ourFD = -1;
        _mtu = 1500;
    }
    return self;
}

- (BOOL)connectWithProfile:(NSString *)ovpnConfig username:(NSString *)username
                  password:(NSString *)password error:(NSError **)error {
    _client = std::make_unique<Client>(self);

    BLOG("connectWithProfile: %{public}lu bytes, user=%{public}s", (unsigned long)ovpnConfig.length, username.UTF8String);
    ClientAPI::Config config;
    config.content = ovpnConfig.UTF8String;
    ClientAPI::EvalConfig ev = _client->eval_config(config);
    BLOG("eval_config: error=%d msg=%{public}s", ev.error, ev.message.c_str());
    if (ev.error) {
        if (error) *error = [NSError errorWithDomain:kOVPNErrorDomain code:1
            userInfo:@{NSLocalizedDescriptionKey: @(ev.message.c_str())}];
        _client.reset();
        return NO;
    }

    ClientAPI::ProvideCreds creds;
    creds.username = username.UTF8String;
    creds.password = password.UTF8String;
    ClientAPI::Status cs = _client->provide_creds(creds);
    if (cs.error) {
        if (error) *error = [NSError errorWithDomain:kOVPNErrorDomain code:2
            userInfo:@{NSLocalizedDescriptionKey: @(cs.message.c_str())}];
        _client.reset();
        return NO;
    }

    [self emitStatus:OVPNStatusConnecting event:@"CONNECTING" info:@""];
    dispatch_async(_runQueue, ^{
        ClientAPI::Status st = self->_client->connect(); // blocks until disconnect
        if (st.error) [self emitError:@(st.message.c_str())];
        [self emitStatus:OVPNStatusDisconnected event:@"DISCONNECTED" info:@""];
    });
    return YES;
}

- (void)disconnect {
    [self emitStatus:OVPNStatusDisconnecting event:@"DISCONNECTING" info:@""];
    if (_client) _client->stop();
}

- (void)transportBytesIn:(int64_t *)bytesIn bytesOut:(int64_t *)bytesOut {
    if (!_client) { if (bytesIn) *bytesIn = 0; if (bytesOut) *bytesOut = 0; return; }
    ClientAPI::TransportStats ts = _client->transport_stats();
    if (bytesIn) *bytesIn = ts.bytesIn;
    if (bytesOut) *bytesOut = ts.bytesOut;
}

- (NSDictionary<NSString *, id> *)connectionInfo {
    return @{
        @"server":   _remote ?: @"",
        @"tunnelIP": _v4Addrs.firstObject ?: @"",
        @"dns":      _dns ? [_dns copy] : @[],
        @"proxies":  _proxies ? [_proxies copy] : @[],
    };
}

// MARK: TunBuilder capture
- (void)tunReset {
    _v4Addrs = [NSMutableArray new]; _v4Masks = [NSMutableArray new];
    _v6Addrs = [NSMutableArray new]; _v6Prefixes = [NSMutableArray new];
    _v4Included = [NSMutableArray new]; _v4Excluded = [NSMutableArray new];
    _v6Included = [NSMutableArray new]; _v6Excluded = [NSMutableArray new];
    _dns = [NSMutableArray new]; _searchDomains = [NSMutableArray new];
    _proxies = [NSMutableArray new];
    _defaultV4 = _defaultV6 = NO; _remote = nil; _mtu = 1500;
}
- (void)tunSetRemote:(NSString *)address { _remote = address; }
- (void)tunAddIPv4Address:(NSString *)address prefix:(int)prefix {
    [_v4Addrs addObject:address];
    uint32_t mask = prefix == 0 ? 0 : htonl(0xFFFFFFFFu << (32 - prefix));
    struct in_addr a; a.s_addr = mask; char buf[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &a, buf, sizeof(buf));
    [_v4Masks addObject:@(buf)];
}
- (void)tunAddIPv6Address:(NSString *)address prefix:(int)prefix {
    [_v6Addrs addObject:address]; [_v6Prefixes addObject:@(prefix)];
}
- (void)tunRerouteGWv4 { _defaultV4 = YES; }
- (void)tunRerouteGWv6 { _defaultV6 = YES; }
- (void)tunAddRoute:(NSString *)address prefix:(int)prefix ipv6:(BOOL)ipv6 {
    if (ipv6) [_v6Included addObject:[[NEIPv6Route alloc] initWithDestinationAddress:address networkPrefixLength:@(prefix)]];
    else {
        uint32_t mask = prefix == 0 ? 0 : htonl(0xFFFFFFFFu << (32 - prefix));
        struct in_addr a; a.s_addr = mask; char buf[INET_ADDRSTRLEN]; inet_ntop(AF_INET, &a, buf, sizeof(buf));
        [_v4Included addObject:[[NEIPv4Route alloc] initWithDestinationAddress:address subnetMask:@(buf)]];
    }
}
- (void)tunExcludeRoute:(NSString *)address prefix:(int)prefix ipv6:(BOOL)ipv6 {
    if (ipv6) [_v6Excluded addObject:[[NEIPv6Route alloc] initWithDestinationAddress:address networkPrefixLength:@(prefix)]];
    else {
        uint32_t mask = prefix == 0 ? 0 : htonl(0xFFFFFFFFu << (32 - prefix));
        struct in_addr a; a.s_addr = mask; char buf[INET_ADDRSTRLEN]; inet_ntop(AF_INET, &a, buf, sizeof(buf));
        [_v4Excluded addObject:[[NEIPv4Route alloc] initWithDestinationAddress:address subnetMask:@(buf)]];
    }
}
- (void)tunAddDNS:(NSString *)address { [_dns addObject:address]; }
- (void)tunAddSearchDomain:(NSString *)domain { [_searchDomains addObject:domain]; }
- (void)tunAddProxy:(NSString *)proxy { [_proxies addObject:proxy]; }
- (void)tunSetMTU:(int)mtu { _mtu = mtu; }

- (int)tunEstablish {
    NEPacketTunnelProvider *provider = _provider;
    if (!provider) { BLOG("tunEstablish: provider gone"); return -1; }
    BLOG("tunEstablish: remote=%{public}s v4addrs=%lu defaultV4=%d dns=%lu mtu=%d",
         _remote.UTF8String, (unsigned long)_v4Addrs.count, _defaultV4, (unsigned long)_dns.count, _mtu);

    NEPacketTunnelNetworkSettings *settings =
        [[NEPacketTunnelNetworkSettings alloc] initWithTunnelRemoteAddress:(_remote ?: @"127.0.0.1")];

    if (_v4Addrs.count) {
        NEIPv4Settings *ipv4 = [[NEIPv4Settings alloc] initWithAddresses:_v4Addrs subnetMasks:_v4Masks];
        NSMutableArray *inc = [_v4Included mutableCopy];
        if (_defaultV4) [inc addObject:[NEIPv4Route defaultRoute]];
        ipv4.includedRoutes = inc;
        ipv4.excludedRoutes = _v4Excluded;
        settings.IPv4Settings = ipv4;
    }
    if (_v6Addrs.count) {
        NEIPv6Settings *ipv6 = [[NEIPv6Settings alloc] initWithAddresses:_v6Addrs networkPrefixLengths:_v6Prefixes];
        NSMutableArray *inc = [_v6Included mutableCopy];
        if (_defaultV6) [inc addObject:[NEIPv6Route defaultRoute]];
        ipv6.includedRoutes = inc;
        ipv6.excludedRoutes = _v6Excluded;
        settings.IPv6Settings = ipv6;
    }
    if (_dns.count) {
        NEDNSSettings *dns = [[NEDNSSettings alloc] initWithServers:_dns];
        if (_searchDomains.count) dns.searchDomains = _searchDomains;
        if (_defaultV4 || _defaultV6) dns.matchDomains = @[@""]; // route all DNS through the tunnel
        settings.DNSSettings = dns;
    }
    settings.MTU = @(_mtu);

    // Apply network settings synchronously (establish() is called off the main thread).
    dispatch_semaphore_t sem = dispatch_semaphore_create(0);
    __block NSError *applyError = nil;
    [provider setTunnelNetworkSettings:settings completionHandler:^(NSError *e) {
        applyError = e; dispatch_semaphore_signal(sem);
    }];
    dispatch_semaphore_wait(sem, DISPATCH_TIME_FOREVER);
    if (applyError) { BLOG("setTunnelNetworkSettings failed: %{public}s", applyError.localizedDescription.UTF8String); [self emitError:applyError.localizedDescription]; return -1; }
    BLOG("tunEstablish: network settings applied");

    // Bridge openvpn3's tun fd to the packet flow via a datagram socketpair.
    int fds[2];
    if (socketpair(AF_UNIX, SOCK_DGRAM, 0, fds) != 0) { BLOG("socketpair failed"); [self emitError:@"socketpair failed"]; return -1; }
    setsockopt(fds[0], SOL_SOCKET, SO_SNDBUF, &kOVPNSockBuf, sizeof(kOVPNSockBuf));
    setsockopt(fds[0], SOL_SOCKET, SO_RCVBUF, &kOVPNSockBuf, sizeof(kOVPNSockBuf));
    setsockopt(fds[1], SOL_SOCKET, SO_SNDBUF, &kOVPNSockBuf, sizeof(kOVPNSockBuf));
    setsockopt(fds[1], SOL_SOCKET, SO_RCVBUF, &kOVPNSockBuf, sizeof(kOVPNSockBuf));
    _ovpnFD = fds[0];
    _ourFD = fds[1];

    [self startReadingPacketsInto:provider.packetFlow];
    [self startReadingFDIntoFlow:provider.packetFlow];
    BLOG("tunEstablish: packet pump started, handing fd %d to openvpn3", _ovpnFD);
    return _ovpnFD;
}

// apps -> openvpn3: read from packetFlow, prepend the 4-byte PF header openvpn3 expects
// (tun_prefix=true on macOS), write as one datagram to our fd.
- (void)startReadingPacketsInto:(NEPacketTunnelFlow *)flow {
    int fd = _ourFD;
    [flow readPacketsWithCompletionHandler:^(NSArray<NSData *> *packets, NSArray<NSNumber *> *protocols) {
        for (NSUInteger i = 0; i < packets.count; i++) {
            NSData *pkt = packets[i];
            uint32_t af = (uint32_t)protocols[i].unsignedIntValue;   // AF_INET / AF_INET6
            uint32_t hdr = htonl(af);
            NSMutableData *framed = [NSMutableData dataWithCapacity:4 + pkt.length];
            [framed appendBytes:&hdr length:4];
            [framed appendData:pkt];
            (void)write(fd, framed.bytes, framed.length);
        }
        if (self->_ourFD >= 0) [self startReadingPacketsInto:flow];
    }];
}

// openvpn3 -> apps: read a datagram (4-byte PF header + IP), strip the header, inject the IP.
- (void)startReadingFDIntoFlow:(NEPacketTunnelFlow *)flow {
    _readSource = dispatch_source_create(DISPATCH_SOURCE_TYPE_READ, (uintptr_t)_ourFD, 0, _cbQueue);
    dispatch_source_set_event_handler(_readSource, ^{
        uint8_t buf[65536];
        ssize_t n = read(self->_ourFD, buf, sizeof(buf));
        if (n <= 4) return;                          // need header + at least 1 byte of IP
        uint32_t af = ntohl(*(const uint32_t *)buf); // PF_INET / PF_INET6
        if (af != AF_INET && af != AF_INET6)
            af = ((buf[4] >> 4) == 6) ? AF_INET6 : AF_INET;  // fall back to IP version
        NSData *ip = [NSData dataWithBytes:buf + 4 length:(NSUInteger)(n - 4)];
        [flow writePackets:@[ip] withProtocols:@[@(af)]];
    });
    dispatch_resume(_readSource);
}

- (void)tunTeardown {
    if (_readSource) { dispatch_source_cancel(_readSource); _readSource = nil; }
    if (_ourFD >= 0) { close(_ourFD); _ourFD = -1; }
    // _ovpnFD is owned by openvpn3 after establish(); it closes it.
    _ovpnFD = -1;
}

// MARK: callbacks
- (void)emitStatus:(OVPNStatus)status event:(NSString *)name info:(NSString *)info {
    id<OpenVPN3BridgeDelegate> d = _delegate;
    dispatch_async(_cbQueue, ^{ [d bridge:self didChangeStatus:status event:name info:info]; });
}
- (void)emitError:(NSString *)message {
    id<OpenVPN3BridgeDelegate> d = _delegate;
    NSError *err = [NSError errorWithDomain:kOVPNErrorDomain code:100 userInfo:@{NSLocalizedDescriptionKey: message ?: @"error"}];
    dispatch_async(_cbQueue, ^{ [d bridge:self didFailWithError:err]; });
}
- (void)emitLog:(NSString *)line {
    id<OpenVPN3BridgeDelegate> d = _delegate;
    dispatch_async(_cbQueue, ^{ [d bridge:self didLog:line]; });
}

@end
