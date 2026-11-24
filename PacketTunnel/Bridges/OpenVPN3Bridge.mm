// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only

//
//  OpenVPN3Bridge.mm
//  ObjC++ bridge between the OpenVPN 3 ClientAPI and NEPacketTunnelProvider.
//

#import "OpenVPN3Bridge.h"
#import "VirtualDatagramPort.h"
#include <fcntl.h>
#import <os/log.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <memory>
#include <string>
#include <mutex>
#include <atomic>
#include <arpa/inet.h>
#include <netinet/in.h>

// The openvpn3 ClientAPI. Implementation lives in OpenVPNEngine.xcframework;
// this pulls in only the public interface. Warnings from the C++ headers are noise here.
#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Weverything"
#include <client/ovpncli.hpp>
#pragma clang diagnostic pop

using namespace openvpn;                 // DnsOptions, DnsAddress, ...
using namespace openvpn::ClientAPI;      // Config, EvalConfig, ProvideCreds, Event, ...

static NSErrorDomain const kOVPNErrorDomain = @"OpenVPN3Bridge";
NSErrorUserInfoKey const OVPNErrorEventNameKey = @"OVPNEventName";
NSErrorUserInfoKey const OVPNErrorEventInfoKey = @"OVPNEventInfo";

@implementation OVPNClientSettings
@end
static const int kOVPNSockBuf = 1 << 20; // 1 MiB socketpair buffers

static os_log_t gBridgeLog = os_log_create("com.bragi0.SimpleVPN.PacketTunnel", "bridge");
#define BLOG(fmt, ...) os_log(gBridgeLog, fmt, ##__VA_ARGS__)

// MARK: - Private ObjC surface the C++ client calls into.
@interface OpenVPN3Bridge ()
- (BOOL)protectSocket:(int)fd ipv6:(BOOL)ipv6;
- (void)tunReset;
- (void)emitErrorEvent:(NSString *)name info:(NSString *)info;
- (void)tunSetRemote:(NSString *)address;
- (void)tunAddIPv4Address:(NSString *)address prefix:(int)prefix;
- (void)tunAddIPv6Address:(NSString *)address prefix:(int)prefix;
- (void)tunRerouteGWv4;
- (void)tunRerouteGWv6;
- (void)tunAddRoute:(NSString *)address prefix:(int)prefix ipv6:(BOOL)ipv6;
- (void)tunExcludeRoute:(NSString *)address prefix:(int)prefix ipv6:(BOOL)ipv6;
- (void)tunAddDNS:(NSString *)address;
- (void)tunAddSearchDomain:(NSString *)domain;
- (void)tunSetProxyHTTP:(NSString *)host port:(int)port;
- (void)tunSetProxyHTTPS:(NSString *)host port:(int)port;
- (void)tunSetProxyPAC:(NSString *)url;
- (void)tunAddProxyBypass:(NSString *)host;
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
    // "Allow local network access" (Config::allowLocalLanAccess). openvpn3 asks the
    // BUILDER which networks are local and turns each answer into a `net_gateway`
    // route itself (TunProp::configure_builder → tunprop.hpp). The base class returns
    // an empty vector, and this override was missing — so the whole setting was a
    // silent no-op. The list is decided in the app and handed over in the session
    // (already policy-gated); the engine still decides whether to ASK, so an
    // allowLocalLanAccess=false profile carves nothing out even with a list here.
    std::vector<std::string> tun_builder_get_local_networks(bool ipv6) override {
        std::vector<std::string> out;
        for (NSString *cidr in [bridge() localNetworks]) {
            if (cidr.length == 0) continue;
            // The engine wants the two families separately; ours are mixed. A colon
            // is the only thing that distinguishes them in a CIDR.
            const bool entryIsIPv6 = [cidr rangeOfString:@":"].location != NSNotFound;
            if (entryIsIPv6 != ipv6) continue;
            out.emplace_back(cidr.UTF8String);
        }
        return out;
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
    // Pushed-proxy capture (dhcp-option PROXY_HTTP/PROXY_HTTPS/PROXY_AUTO_CONFIG_URL/
    // PROXY_BYPASS): structured per-scheme host:port, PAC url, and bypass list — the
    // Proxy mediator's per-kind intent for OpenVPN (Docs/StateMediators.md › Proxy).
    bool tun_builder_set_proxy_http(const std::string &host, int port) override {
        [bridge() tunSetProxyHTTP:@(host.c_str()) port:port]; return true;
    }
    bool tun_builder_set_proxy_https(const std::string &host, int port) override {
        [bridge() tunSetProxyHTTPS:@(host.c_str()) port:port]; return true;
    }
    bool tun_builder_set_proxy_auto_config_url(const std::string &url) override {
        [bridge() tunSetProxyPAC:@(url.c_str())]; return true;
    }
    bool tun_builder_add_proxy_bypass(const std::string &bypass_host) override {
        [bridge() tunAddProxyBypass:@(bypass_host.c_str())]; return true;
    }
    bool tun_builder_set_session_name(const std::string &) override { return true; }
    bool tun_builder_persist() override { return false; }      // force fd-based establish()
    int  tun_builder_establish() override { return [bridge() tunEstablish]; }
    void tun_builder_teardown(bool) override { [bridge() tunTeardown]; }

    // ---- OpenVPNClient ----
    bool socket_protect(openvpn_io::detail::socket_type fd, std::string, bool ipv6) override {
        return [bridge() protectSocket:fd ipv6:ipv6];
    }
    bool pause_on_connection_timeout() override { return false; }
    void external_pki_cert_request(ExternalPKICertRequest &req) override { req.error = true; req.errorText = "external PKI not supported"; }
    void external_pki_sign_request(ExternalPKISignRequest &req) override { req.error = true; req.errorText = "external PKI not supported"; }
    void acc_event(const AppCustomControlMessageEvent &) override {}

    void log(const LogInfo &li) override { [bridge() emitLog:@(li.text.c_str())]; }

    void event(const Event &ev) override {
        NSString *name = @(ev.name.c_str());
        NSString *info = @(ev.info.c_str());
        if (ev.fatal || ev.error) { [bridge() emitErrorEvent:name info:info]; return; }
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
    __weak NEPacketTunnelProvider<SVPTunnelSettingsApplying> *_provider;
    __weak id<OpenVPN3BridgeDelegate> _delegate;
    SVPPacketPolicy *_packetPolicy;
    VirtualDatagramPort *_member;
    uint32_t _interfaceIndex;
    std::unique_ptr<Client> _client;
    dispatch_queue_t _runQueue;   // runs the blocking connect()
    dispatch_queue_t _cbQueue;    // serializes delegate callbacks

    // captured tun settings
    NSMutableArray<NSString *> *_v4Addrs, *_v4Masks, *_v6Addrs;
    NSMutableArray<NSNumber *> *_v6Prefixes;
    NSMutableArray<NEIPv4Route *> *_v4Included, *_v4Excluded;
    NSMutableArray<NEIPv6Route *> *_v6Included, *_v6Excluded;
    NSMutableArray<NSString *> *_dns, *_searchDomains, *_proxies;
    // Structured pushed-proxy capture (was loose "SCHEME host:port" strings in
    // _proxies — kept, derived, for existing connectionInfo consumers).
    NSString *_proxyHTTPHost, *_proxyHTTPSHost, *_proxyPACURL;
    int _proxyHTTPPort, _proxyHTTPSPort;
    NSMutableArray<NSString *> *_proxyBypass;
    // The arbitrated system proxy the app asked us to apply (Proxy mediator P3).
    // Owner-egress only; nil = none. Guarded by _stateMutex like the rest.
    NEProxySettings *_proxySettings;
    // The arbitrated per-tunnel DNS the app asked us to apply (DNS mediator applier —
    // Docs/StateMediators.md). When set it OVERRIDES the DNS captured from the push;
    // nil restores the captured/pushed DNS. Guarded by _stateMutex like the rest.
    NEDNSSettings *_dnsOverride;
    NSString *_remote;
    BOOL _defaultV4, _defaultV6;
    // Default-gateway ownership: when YES the pushed default route is suppressed
    // (this tunnel is demoted to split — specific subnets only). Guarded by
    // _stateMutex like the rest of the captured tun state. Defaults NO (owner).
    BOOL _suppressDefault;
    int _mtu;

    // Guards ALL captured tun state below: the openvpn3 event thread rebuilds
    // it on every (re)connect while the provider's queues read it (stats IPC,
    // pause/resume settings rebuilds). ObjC strong-ivar stores are not atomic —
    // unguarded concurrent access is a use-after-free waiting for a reconnect.
    std::mutex _stateMutex;

    // packet pump
    int _ovpnFD;                  // openvpn3-owned end
    int _ourFD;                   // our end
    dispatch_source_t _readSource;
    NSFileHandle *_pumpWriter; // kept alive by each active NE write, including during teardown
    // Bumped on every establish/teardown; stale pump loops check it and exit
    // instead of re-arming against a new session's fd.
    std::atomic<uint32_t> _pumpGeneration;

    // User divert rules: destinations to exclude from this tunnel (route around
    // the VPN). Set by the provider before connect from providerConfiguration;
    // merged into the captured excluded routes. Guarded by _stateMutex.
    NSMutableArray<NEIPv4Route *> *_extraV4Excluded;
    NSMutableArray<NEIPv6Route *> *_extraV6Excluded;
    // Destinations other VPNs divert *into* this one — added to included routes.
    NSMutableArray<NEIPv4Route *> *_extraV4Included;
    NSMutableArray<NEIPv6Route *> *_extraV6Included;
}

- (instancetype)initWithProvider:(NEPacketTunnelProvider<SVPTunnelSettingsApplying> *)provider delegate:(id<OpenVPN3BridgeDelegate>)delegate
                    packetPolicy:(SVPPacketPolicy *)packetPolicy {
    if ((self = [self initWithEngineDelegate:delegate])) {
        _provider = provider;
        _packetPolicy = packetPolicy;
    }
    return self;
}

- (instancetype)initWithInterfaceIndex:(uint32_t)index delegate:(id<OpenVPN3BridgeDelegate>)delegate
                               received:(void (^)(NSData *))received {
    if ((self = [self initWithEngineDelegate:delegate])) {
        _member = [[VirtualDatagramPort alloc] initWithFamilyHeader:YES received:received];
        _interfaceIndex = index;
    }
    return self;
}

- (BOOL)protectSocket:(int)fd ipv6:(BOOL)ipv6 {
    if (!_member) return YES;
    return _interfaceIndex != 0 && setsockopt(fd, ipv6 ? IPPROTO_IPV6 : IPPROTO_IP,
        ipv6 ? IPV6_BOUND_IF : IP_BOUND_IF, &_interfaceIndex, sizeof(_interfaceIndex)) == 0;
}

- (BOOL)sendMemberPacket:(NSData *)packet { return [_member sendPacket:packet]; }
- (NEPacketTunnelNetworkSettings *)memberNetworkSettings { return [self buildTunSettingsIncludingRoutes:YES]; }
- (void)stopMemberWithCompletion:(void (^)(void))completion {
    [_member close];
    [self disconnect];
    dispatch_async(_runQueue, completion);
}

- (instancetype)initWithEngineDelegate:(id<OpenVPN3BridgeDelegate>)delegate {
    if ((self = [super init])) {
        _delegate = delegate;
        _runQueue = dispatch_queue_create("com.bragi0.SimpleVPN.ovpn.run", DISPATCH_QUEUE_SERIAL);
        _cbQueue = dispatch_queue_create("com.bragi0.SimpleVPN.ovpn.cb", DISPATCH_QUEUE_SERIAL);
        _ovpnFD = _ourFD = -1;
        _mtu = 1500;
    }
    return self;
}

- (BOOL)connectWithProfile:(NSString *)ovpnConfig username:(NSString *)username
                  password:(NSString *)password
                  settings:(OVPNClientSettings *)s error:(NSError **)error {
    _client = std::make_unique<Client>(self);

    // Username is a credential — keep it out of the public system log.
    BLOG("connectWithProfile: %{public}lu bytes, user=%{private}s", (unsigned long)ovpnConfig.length, username.UTF8String);
    ClientAPI::Config config;
    config.content = ovpnConfig.UTF8String;

    // Per-VPN overrides: assign only non-nil values — nil leaves the engine's
    // compiled-in default untouched (the round-trip contract with the app).
    if (s) {
        if (s.serverOverride)          config.serverOverride = s.serverOverride.UTF8String;
        if (s.portOverride)            config.portOverride = s.portOverride.UTF8String;
        if (s.protoOverride)           config.protoOverride = s.protoOverride.UTF8String;
        if (s.protoVersionOverride != nil)    config.protoVersionOverride = s.protoVersionOverride.intValue;
        if (s.connTimeout != nil)             config.connTimeout = s.connTimeout.intValue;
        if (s.tunPersist != nil)              config.tunPersist = s.tunPersist.boolValue;
        if (s.retryOnAuthFailed != nil)       config.retryOnAuthFailed = s.retryOnAuthFailed.boolValue;
        if (s.autologinSessions != nil)       config.autologinSessions = s.autologinSessions.boolValue;
        if (s.allowLocalLanAccess != nil)     config.allowLocalLanAccess = s.allowLocalLanAccess.boolValue;
        if (s.allowUnusedAddrFamilies) config.allowUnusedAddrFamilies = s.allowUnusedAddrFamilies.UTF8String;
        if (s.googleDnsFallback != nil)       config.googleDnsFallback = s.googleDnsFallback.boolValue;
        if (s.tlsVersionMinOverride)   config.tlsVersionMinOverride = s.tlsVersionMinOverride.UTF8String;
        if (s.tlsCertProfileOverride)  config.tlsCertProfileOverride = s.tlsCertProfileOverride.UTF8String;
        if (s.compressionMode)         config.compressionMode = s.compressionMode.UTF8String;
        if (s.enableLegacyAlgorithms != nil)  config.enableLegacyAlgorithms = s.enableLegacyAlgorithms.boolValue;
        if (s.enableNonPreferredDCAlgorithms != nil) config.enableNonPreferredDCAlgorithms = s.enableNonPreferredDCAlgorithms.boolValue;
        if (s.tlsCipherList)           config.tlsCipherList = s.tlsCipherList.UTF8String;
        if (s.tlsCiphersuitesList)     config.tlsCiphersuitesList = s.tlsCiphersuitesList.UTF8String;
        if (s.disableClientCert != nil)       config.disableClientCert = s.disableClientCert.boolValue;
        if (s.defaultKeyDirection != nil)     config.defaultKeyDirection = s.defaultKeyDirection.intValue;
        if (s.proxyHost)               config.proxyHost = s.proxyHost.UTF8String;
        if (s.proxyPort)               config.proxyPort = s.proxyPort.UTF8String;
        if (s.proxyUsername)           config.proxyUsername = s.proxyUsername.UTF8String;
        if (s.proxyPassword)           config.proxyPassword = s.proxyPassword.UTF8String;
        if (s.proxyAllowCleartextAuth != nil) config.proxyAllowCleartextAuth = s.proxyAllowCleartextAuth.boolValue;
        if (s.sslDebugLevel != nil)           config.sslDebugLevel = s.sslDebugLevel.intValue;
        if (s.synchronousDnsLookup != nil)    config.synchronousDnsLookup = s.synchronousDnsLookup.boolValue;
        if (s.privateKeyPassword)      config.privateKeyPassword = s.privateKeyPassword.UTF8String;
    }

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
    // static-challenge one-time code — the engine formats the wire response
    // itself (base64 SCRV1 or appended, per the profile's directive).
    if (s && s.challengeResponse) creds.response = s.challengeResponse.UTF8String;
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

- (void)pauseWithReason:(NSString *)reason {
    if (!_client) return;
    BLOG("pause: %{public}s", reason.UTF8String);
    _client->pause(reason.UTF8String ?: "user-pause");
}

- (void)resume {
    if (!_client) return;
    BLOG("resume");
    _client->resume();
}

- (BOOL)reapplyTunSettingsIncludingRoutes:(BOOL)includeRoutes {
    // Called from the provider's message queue, never the main thread
    // (applyTunSettings blocks on the settings completion).
    NSError *err = [self applyTunSettings:[self buildTunSettingsIncludingRoutes:includeRoutes]];
    if (err) {
        BLOG("reapplyTunSettings(routes=%d) failed: %{public}s", includeRoutes, err.localizedDescription.UTF8String);
        return NO;
    }
    BLOG("reapplyTunSettings: applied (routes=%d)", includeRoutes);
    return YES;
}

- (void)setInitialDefaultRouteOwned:(BOOL)owned {
    // Establish-time seed of the ownership gate, BEFORE connect() builds the tun.
    // The app passes the desired role via startTunnel options so the ≤1-owner
    // invariant holds at the very first establish — even before (or without) the
    // app reconciling live (RC3). No reapply here: there is no tun to rebuild yet.
    std::lock_guard<std::mutex> hold(_stateMutex);
    _suppressDefault = !owned;
    BLOG("setInitialDefaultRouteOwned: %d (suppressDefault=%d)", owned, !owned);
}

- (BOOL)setDefaultRouteOwned:(BOOL)owned {
    { std::lock_guard<std::mutex> hold(_stateMutex); _suppressDefault = !owned; }
    BLOG("setDefaultRouteOwned: %d (suppressDefault=%d)", owned, !owned);
    // Live: rebuild and re-apply the captured settings with the default route
    // gate flipped. No reconnect — the TLS session and fd pump are untouched.
    return [self reapplyTunSettingsIncludingRoutes:YES];
}

- (void)transportBytesIn:(int64_t *)bytesIn bytesOut:(int64_t *)bytesOut {
    if (!_client) { if (bytesIn) *bytesIn = 0; if (bytesOut) *bytesOut = 0; return; }
    ClientAPI::TransportStats ts = _client->transport_stats();
    if (bytesIn) *bytesIn = ts.bytesIn;
    if (bytesOut) *bytesOut = ts.bytesOut;
}

- (NSDictionary<NSString *, id> *)connectionInfo {
    // The engine's ConnectionInfo carries transport + per-family detail the tun
    // capture doesn't (resolved server IP/port/proto, in-tunnel gateways);
    // fall back to captured tun state where it isn't defined.
    NSString *serverIP = @"", *serverPort = @"", *serverProto = @"";
    NSString *vpnIp4 = @"", *vpnIp6 = @"", *gw4 = @"", *gw6 = @"";
    if (_client) {
        ClientAPI::ConnectionInfo ci = _client->connection_info();
        if (ci.defined) {
            serverIP = @(ci.serverIp.c_str());
            serverPort = @(ci.serverPort.c_str());
            serverProto = @(ci.serverProto.c_str());
            vpnIp4 = @(ci.vpnIp4.c_str());
            vpnIp6 = @(ci.vpnIp6.c_str());
            gw4 = @(ci.gw4.c_str());
            gw6 = @(ci.gw6.c_str());
        }
    }
    std::lock_guard<std::mutex> hold(_stateMutex);
    // Effective default-route ownership = the engine's GROUND TRUTH: a default
    // route was pushed (redirect-gateway / server push) AND it is not suppressed.
    // The app seeds its applied-role cache from this, never the client-.ovpn grep,
    // so it can never wrongly skip a needed gateway:split/full (RC1).
    BOOL effectiveOwned = (_defaultV4 || _defaultV6) && !_suppressDefault;
    return @{
        @"server":        _remote ?: @"",
        @"serverIP":      serverIP,
        @"serverPort":    serverPort,
        @"serverProto":   serverProto,
        @"tunnelIP":      vpnIp4.length ? vpnIp4 : (_v4Addrs.firstObject ?: @""),
        @"tunnelIPv6":    vpnIp6.length ? vpnIp6 : (_v6Addrs.firstObject ?: @""),
        @"gateway4":      gw4,
        @"gateway6":      gw6,
        @"mtu":           @(_mtu),
        @"dns":           _dns ? [_dns copy] : @[],
        @"searchDomains": _searchDomains ? [_searchDomains copy] : @[],
        @"proxies":       _proxies ? [_proxies copy] : @[],
        @"proxyHTTPHost":  _proxyHTTPHost ?: @"",
        @"proxyHTTPPort":  @(_proxyHTTPPort),
        @"proxyHTTPSHost": _proxyHTTPSHost ?: @"",
        @"proxyHTTPSPort": @(_proxyHTTPSPort),
        @"proxyPAC":       _proxyPACURL ?: @"",
        @"proxyBypass":    _proxyBypass ? [_proxyBypass copy] : @[],
        @"defaultV4":            @(_defaultV4),
        @"defaultV6":            @(_defaultV6),
        @"suppressDefault":      @(_suppressDefault),
        @"effectiveDefaultOwned": @(effectiveOwned),
    };
}

// MARK: TunBuilder capture (every access under _stateMutex — see ivar comment)
- (void)tunReset {
    std::lock_guard<std::mutex> hold(_stateMutex);
    _v4Addrs = [NSMutableArray new]; _v4Masks = [NSMutableArray new];
    _v6Addrs = [NSMutableArray new]; _v6Prefixes = [NSMutableArray new];
    _v4Included = [NSMutableArray new]; _v4Excluded = [NSMutableArray new];
    _v6Included = [NSMutableArray new]; _v6Excluded = [NSMutableArray new];
    _dns = [NSMutableArray new]; _searchDomains = [NSMutableArray new];
    _proxies = [NSMutableArray new]; _proxyBypass = [NSMutableArray new];
    _proxyHTTPHost = _proxyHTTPSHost = _proxyPACURL = nil;
    _proxyHTTPPort = _proxyHTTPSPort = 0;
    // NOTE: _proxySettings is deliberately NOT reset here — like _suppressDefault, the
    // app-arbitrated proxy decision must survive an engine-driven reconnect that
    // rebuilds the captured tun state.
    // NOTE: _dnsOverride is deliberately NOT reset here either, for the same reason —
    // the app-arbitrated DNS decision must survive an engine-driven reconnect.
    _defaultV4 = _defaultV6 = NO; _remote = nil; _mtu = 1500;
    // NOTE: _suppressDefault is deliberately NOT reset here. A (re)connect rebuilds
    // the captured routes, but the coordinator's chosen gateway ownership must
    // survive an engine-driven reconnect (RECONNECTING rebuilds the tun) — the app
    // re-asserts it too, but honouring the last-set flag avoids a full-tunnel flash
    // mid-reconnect for a VPN that was demoted to split.
}
- (void)tunSetRemote:(NSString *)address {
    std::lock_guard<std::mutex> hold(_stateMutex);
    _remote = address;
}
- (void)tunAddIPv4Address:(NSString *)address prefix:(int)prefix {
    std::lock_guard<std::mutex> hold(_stateMutex);
    [_v4Addrs addObject:address];
    uint32_t mask = prefix == 0 ? 0 : htonl(0xFFFFFFFFu << (32 - prefix));
    struct in_addr a; a.s_addr = mask; char buf[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &a, buf, sizeof(buf));
    [_v4Masks addObject:@(buf)];
}
- (void)tunAddIPv6Address:(NSString *)address prefix:(int)prefix {
    std::lock_guard<std::mutex> hold(_stateMutex);
    [_v6Addrs addObject:address]; [_v6Prefixes addObject:@(prefix)];
}
- (void)tunRerouteGWv4 { std::lock_guard<std::mutex> hold(_stateMutex); _defaultV4 = YES; }
- (void)tunRerouteGWv6 { std::lock_guard<std::mutex> hold(_stateMutex); _defaultV6 = YES; }
- (void)tunAddRoute:(NSString *)address prefix:(int)prefix ipv6:(BOOL)ipv6 {
    std::lock_guard<std::mutex> hold(_stateMutex);
    if (ipv6) [_v6Included addObject:[[NEIPv6Route alloc] initWithDestinationAddress:address networkPrefixLength:@(prefix)]];
    else {
        uint32_t mask = prefix == 0 ? 0 : htonl(0xFFFFFFFFu << (32 - prefix));
        struct in_addr a; a.s_addr = mask; char buf[INET_ADDRSTRLEN]; inet_ntop(AF_INET, &a, buf, sizeof(buf));
        [_v4Included addObject:[[NEIPv4Route alloc] initWithDestinationAddress:address subnetMask:@(buf)]];
    }
}
- (void)tunExcludeRoute:(NSString *)address prefix:(int)prefix ipv6:(BOOL)ipv6 {
    std::lock_guard<std::mutex> hold(_stateMutex);
    if (ipv6) [_v6Excluded addObject:[[NEIPv6Route alloc] initWithDestinationAddress:address networkPrefixLength:@(prefix)]];
    else {
        uint32_t mask = prefix == 0 ? 0 : htonl(0xFFFFFFFFu << (32 - prefix));
        struct in_addr a; a.s_addr = mask; char buf[INET_ADDRSTRLEN]; inet_ntop(AF_INET, &a, buf, sizeof(buf));
        [_v4Excluded addObject:[[NEIPv4Route alloc] initWithDestinationAddress:address subnetMask:@(buf)]];
    }
}
// Divert rules from the app: destinations to route *around* this VPN. Each entry
// is @{ "address": NSString, "prefix": NSNumber, "ipv6": NSNumber(bool) }.
- (void)setDivertedDestinations:(NSArray<NSDictionary<NSString *, id> *> *)dests {
    std::lock_guard<std::mutex> hold(_stateMutex);
    _extraV4Excluded = [NSMutableArray new];
    _extraV6Excluded = [NSMutableArray new];
    for (NSDictionary *d in dests) {
        NSString *address = d[@"address"];
        int prefix = [d[@"prefix"] intValue];
        BOOL ipv6 = [d[@"ipv6"] boolValue];
        if (address.length == 0) continue;
        if (ipv6) {
            [_extraV6Excluded addObject:[[NEIPv6Route alloc] initWithDestinationAddress:address networkPrefixLength:@(prefix)]];
        } else {
            uint32_t mask = prefix == 0 ? 0 : htonl(0xFFFFFFFFu << (32 - prefix));
            struct in_addr a; a.s_addr = mask; char buf[INET_ADDRSTRLEN]; inet_ntop(AF_INET, &a, buf, sizeof(buf));
            [_extraV4Excluded addObject:[[NEIPv4Route alloc] initWithDestinationAddress:address subnetMask:@(buf)]];
        }
    }
    BLOG("divert: %lu v4 + %lu v6 destinations", (unsigned long)_extraV4Excluded.count, (unsigned long)_extraV6Excluded.count);
}

// Destinations other VPNs route *into* this one (the "over another VPN" target
// side): added to this tunnel's included routes so the OS sends them here.
- (void)setIncludedDestinations:(NSArray<NSDictionary<NSString *, id> *> *)dests {
    std::lock_guard<std::mutex> hold(_stateMutex);
    _extraV4Included = [NSMutableArray new];
    _extraV6Included = [NSMutableArray new];
    for (NSDictionary *d in dests) {
        NSString *address = d[@"address"];
        int prefix = [d[@"prefix"] intValue];
        BOOL ipv6 = [d[@"ipv6"] boolValue];
        if (address.length == 0) continue;
        if (ipv6) {
            [_extraV6Included addObject:[[NEIPv6Route alloc] initWithDestinationAddress:address networkPrefixLength:@(prefix)]];
        } else {
            uint32_t mask = prefix == 0 ? 0 : htonl(0xFFFFFFFFu << (32 - prefix));
            struct in_addr a; a.s_addr = mask; char buf[INET_ADDRSTRLEN]; inet_ntop(AF_INET, &a, buf, sizeof(buf));
            [_extraV4Included addObject:[[NEIPv4Route alloc] initWithDestinationAddress:address subnetMask:@(buf)]];
        }
    }
    BLOG("route-in: %lu v4 + %lu v6 destinations", (unsigned long)_extraV4Included.count, (unsigned long)_extraV6Included.count);
}

- (void)tunAddDNS:(NSString *)address { std::lock_guard<std::mutex> hold(_stateMutex); [_dns addObject:address]; }
- (void)tunAddSearchDomain:(NSString *)domain { std::lock_guard<std::mutex> hold(_stateMutex); [_searchDomains addObject:domain]; }
- (void)tunSetProxyHTTP:(NSString *)host port:(int)port {
    std::lock_guard<std::mutex> hold(_stateMutex);
    _proxyHTTPHost = host; _proxyHTTPPort = port;
    [_proxies addObject:[NSString stringWithFormat:@"HTTP %@:%d", host, port]];
}
- (void)tunSetProxyHTTPS:(NSString *)host port:(int)port {
    std::lock_guard<std::mutex> hold(_stateMutex);
    _proxyHTTPSHost = host; _proxyHTTPSPort = port;
    [_proxies addObject:[NSString stringWithFormat:@"HTTPS %@:%d", host, port]];
}
- (void)tunSetProxyPAC:(NSString *)url {
    std::lock_guard<std::mutex> hold(_stateMutex);
    _proxyPACURL = url;
    [_proxies addObject:[NSString stringWithFormat:@"PAC %@", url]];
}
- (void)tunAddProxyBypass:(NSString *)host {
    std::lock_guard<std::mutex> hold(_stateMutex);
    if (host.length) [_proxyBypass addObject:host];
}
- (void)tunSetMTU:(int)mtu { std::lock_guard<std::mutex> hold(_stateMutex); _mtu = mtu; }

// Proxy mediator P3 applier (Docs/StateMediators.md): store the arbitrated system
// proxy and re-apply the captured settings so it takes effect live (no reconnect).
- (BOOL)applyProxySettings:(NEProxySettings *)proxy {
    { std::lock_guard<std::mutex> hold(_stateMutex); _proxySettings = proxy; }
    BLOG("applyProxySettings: %{public}s", proxy ? "set" : "cleared");
    return [self reapplyTunSettingsIncludingRoutes:YES];
}

// DNS mediator applier (Docs/StateMediators.md): store the arbitrated per-tunnel DNS
// and re-apply the captured settings so it takes effect live (no reconnect). When set
// it overrides the DNS captured from the push; nil restores the captured/pushed DNS.
- (BOOL)applyDNSSettings:(NEDNSSettings *)dns {
    { std::lock_guard<std::mutex> hold(_stateMutex); _dnsOverride = dns; }
    BLOG("applyDNSSettings: %{public}s", dns ? "set" : "cleared");
    return [self reapplyTunSettingsIncludingRoutes:YES];
}

/// Build NEPacketTunnelNetworkSettings from the captured tun state.
/// includeRoutes=NO keeps only the interface addresses/MTU — no routes, no DNS —
/// so traffic flows over the physical interface (the "bypass" pause mode).
- (NEPacketTunnelNetworkSettings *)buildTunSettingsIncludingRoutes:(BOOL)includeRoutes {
    std::lock_guard<std::mutex> hold(_stateMutex);
    NEPacketTunnelNetworkSettings *settings =
        [[NEPacketTunnelNetworkSettings alloc] initWithTunnelRemoteAddress:(_remote ?: @"127.0.0.1")];

    if (_v4Addrs.count) {
        NEIPv4Settings *ipv4 = [[NEIPv4Settings alloc] initWithAddresses:_v4Addrs subnetMasks:_v4Masks];
        if (includeRoutes) {
            NSMutableArray *inc = [_v4Included mutableCopy];
            // Gate the pushed default route on ownership: a VPN demoted to split
            // (_suppressDefault) keeps every specific subnet in _v4Included but
            // drops 0.0.0.0/0 so it stops owning the gateway.
            if (_defaultV4 && !_suppressDefault) [inc addObject:[NEIPv4Route defaultRoute]];
            if (_extraV4Included) [inc addObjectsFromArray:_extraV4Included];
            ipv4.includedRoutes = inc;
            ipv4.excludedRoutes = [_v4Excluded arrayByAddingObjectsFromArray:(_extraV4Excluded ?: @[])];
        } else {
            ipv4.includedRoutes = @[];
        }
        settings.IPv4Settings = ipv4;
    }
    if (_v6Addrs.count) {
        NEIPv6Settings *ipv6 = [[NEIPv6Settings alloc] initWithAddresses:_v6Addrs networkPrefixLengths:_v6Prefixes];
        if (includeRoutes) {
            NSMutableArray *inc = [_v6Included mutableCopy];
            if (_defaultV6 && !_suppressDefault) [inc addObject:[NEIPv6Route defaultRoute]];
            if (_extraV6Included) [inc addObjectsFromArray:_extraV6Included];
            ipv6.includedRoutes = inc;
            ipv6.excludedRoutes = [_v6Excluded arrayByAddingObjectsFromArray:(_extraV6Excluded ?: @[])];
        } else {
            ipv6.includedRoutes = @[];
        }
        settings.IPv6Settings = ipv6;
    }
    // DNS: the app-arbitrated override (DNS mediator applier — Docs/StateMediators.md)
    // is the sole writer when set, winning over the pushed DNS; nil falls back to the
    // captured push. Only asserted when routes are in play (bypass mode leaves DNS off).
    if (includeRoutes && _dnsOverride) {
        settings.DNSSettings = _dnsOverride;
    } else if (includeRoutes && _dns.count) {
        NEDNSSettings *dns = [[NEDNSSettings alloc] initWithServers:_dns];
        if (_searchDomains.count) dns.searchDomains = _searchDomains;
        BOOL ownsDefault = (_defaultV4 || _defaultV6) && !_suppressDefault;
        if (ownsDefault) {
            dns.matchDomains = @[@""];            // owner: route ALL DNS through the tunnel
            settings.DNSSettings = dns;
        } else if (_searchDomains.count) {
            // Split (demoted, or a genuinely split-tunnel profile): scope the
            // tunnel's resolvers to its own search domains only, so a non-owner
            // can't hijack every lookup on the Mac. With no search domains there
            // is nothing safe to scope to, so the tunnel DNS is left off entirely.
            dns.matchDomains = _searchDomains;
            settings.DNSSettings = dns;
        }
    }
    // System proxy: apply the app-arbitrated decision (owner egress only) whenever
    // routes are in play. In bypass mode (includeRoutes=NO) no proxy is asserted.
    if (includeRoutes && _proxySettings) settings.proxySettings = _proxySettings;
    settings.MTU = @(_mtu);
    return settings;
}

/// Apply settings synchronously (callers are off the main thread). Returns nil error on success.
- (NSError *)applyTunSettings:(NEPacketTunnelNetworkSettings *)settings {
    NEPacketTunnelProvider<SVPTunnelSettingsApplying> *provider = _provider;
    if (!provider) return [NSError errorWithDomain:kOVPNErrorDomain code:102
        userInfo:@{NSLocalizedDescriptionKey: @"provider gone"}];
    dispatch_semaphore_t sem = dispatch_semaphore_create(0);
    __block NSError *applyError = nil;
    [provider applyNetworkSettings:settings completionHandler:^(NSError *e) {
        applyError = e; dispatch_semaphore_signal(sem);
    }];
    dispatch_semaphore_wait(sem, DISPATCH_TIME_FOREVER);
    return applyError;
}

- (int)tunEstablish {
    if (_member) return [_member openEngineDescriptor];
    NEPacketTunnelProvider<SVPTunnelSettingsApplying> *provider = _provider;
    if (!provider) { BLOG("tunEstablish: provider gone"); return -1; }
    BLOG("tunEstablish: remote=%{public}s v4addrs=%lu defaultV4=%d dns=%lu mtu=%d",
         _remote.UTF8String, (unsigned long)_v4Addrs.count, _defaultV4, (unsigned long)_dns.count, _mtu);

    NSError *applyError = [self applyTunSettings:[self buildTunSettingsIncludingRoutes:YES]];
    if (applyError) { BLOG("setTunnelNetworkSettings failed: %{public}s", applyError.localizedDescription.UTF8String); [self emitError:applyError.localizedDescription]; return -1; }
    BLOG("tunEstablish: network settings applied");

    // Bridge openvpn3's tun fd to the packet flow via a datagram socketpair.
    int fds[2];
    if (socketpair(AF_UNIX, SOCK_DGRAM, 0, fds) != 0) { BLOG("socketpair failed"); [self emitError:@"socketpair failed"]; return -1; }
    setsockopt(fds[0], SOL_SOCKET, SO_SNDBUF, &kOVPNSockBuf, sizeof(kOVPNSockBuf));
    setsockopt(fds[0], SOL_SOCKET, SO_RCVBUF, &kOVPNSockBuf, sizeof(kOVPNSockBuf));
    setsockopt(fds[1], SOL_SOCKET, SO_SNDBUF, &kOVPNSockBuf, sizeof(kOVPNSockBuf));
    setsockopt(fds[1], SOL_SOCKET, SO_RCVBUF, &kOVPNSockBuf, sizeof(kOVPNSockBuf));
    int writerFD = fcntl(fds[1], F_DUPFD_CLOEXEC, 0);
    if (writerFD < 0) {
        close(fds[0]); close(fds[1]);
        [self emitError:@"Could not open the tunnel packet writer."]; return -1;
    }
    _pumpWriter = [[NSFileHandle alloc] initWithFileDescriptor:writerFD closeOnDealloc:YES];
    _ovpnFD = fds[0];
    _ourFD = fds[1];
    _pumpGeneration.fetch_add(1);   // new session: new pump generation

    [self startReadingPacketsInto:provider.packetFlow writer:_pumpWriter generation:_pumpGeneration.load()];
    [self startReadingFDIntoFlow:provider.packetFlow];
    BLOG("tunEstablish: packet pump started, handing fd %d to openvpn3", _ovpnFD);
    return _ovpnFD;
}

// apps -> openvpn3: read from packetFlow, prepend the 4-byte PF header openvpn3 expects
// (tun_prefix=true on macOS), write as one datagram to our fd.
- (void)startReadingPacketsInto:(NEPacketTunnelFlow *)flow writer:(NSFileHandle *)writer generation:(uint32_t)generation {
    __weak NSFileHandle *weakWriter = writer;
    __weak OpenVPN3Bridge *weakBridge = self;
    __weak NEPacketTunnelFlow *weakFlow = flow;
    [flow readPacketsWithCompletionHandler:^(NSArray<NSData *> *packets, NSArray<NSNumber *> *protocols) {
        // A teardown (reconnect, stop) bumps the generation: this loop belongs
        // to a dead session — exit without touching the (closed/reused) fd and
        // without re-arming a duplicate reader against the new session.
        OpenVPN3Bridge *bridge = weakBridge;
        NEPacketTunnelFlow *flow = weakFlow;
        __attribute__((objc_precise_lifetime)) NSFileHandle *lease = weakWriter;
        if (!bridge || !flow || !lease || bridge->_pumpGeneration.load() != generation) return;
        int fd = lease.fileDescriptor;
        BOOL inspect = bridge->_packetPolicy.inspectOutbound;
        if (!inspect && ![bridge->_packetPolicy observeOutboundBatch:packets]) return;
        for (NSUInteger i = 0; i < packets.count; i++) {
            NSData *pkt = packets[i];
            uint32_t af = (uint32_t)protocols[i].unsignedIntValue;   // AF_INET / AF_INET6
            uint32_t hdr = htonl(af);
            NSMutableData *framed = [NSMutableData dataWithCapacity:4 + pkt.length];
            [framed appendBytes:&hdr length:4];
            [framed appendData:pkt];
            if (inspect && ![bridge->_packetPolicy apply:(uint8_t *)framed.mutableBytes + sizeof(hdr)
                                               length:pkt.length inbound:NO]) continue;
            (void)send(fd, framed.bytes, framed.length, MSG_DONTWAIT);
        }
        if (bridge->_pumpGeneration.load() == generation) [bridge startReadingPacketsInto:flow writer:lease generation:generation];
    }];
}

// openvpn3 -> apps: read a datagram (4-byte PF header + IP), strip the header, inject the IP.
- (void)startReadingFDIntoFlow:(NEPacketTunnelFlow *)flow {
    int fd = _ourFD;   // captured: the handler must never chase the mutable ivar
    uint32_t generation = _pumpGeneration.load();
    _readSource = dispatch_source_create(DISPATCH_SOURCE_TYPE_READ, (uintptr_t)fd, 0, _cbQueue);
    dispatch_source_set_event_handler(_readSource, ^{
        if (self->_pumpGeneration.load() != generation) return;
        uint8_t buf[65536];
        ssize_t n = read(fd, buf, sizeof(buf));
        if (n <= 4) return;                          // need header + at least 1 byte of IP
        uint32_t af = ntohl(*(const uint32_t *)buf); // PF_INET / PF_INET6
        if (af != AF_INET && af != AF_INET6)
            af = ((buf[4] >> 4) == 6) ? AF_INET6 : AF_INET;  // fall back to IP version
        NSUInteger length = (NSUInteger)(n - 4);
        BOOL permitted = self->_packetPolicy.inspectInbound
            ? [self->_packetPolicy apply:buf + 4 length:length inbound:YES]
            : [self->_packetPolicy observePacket:buf + 4 length:length inbound:YES];
        if (!permitted) return;
        NSData *ip = [NSData dataWithBytes:buf + 4 length:length];
        [flow writePackets:@[ip] withProtocols:@[@(af)]];
    });
    dispatch_resume(_readSource);
}

- (void)tunTeardown {
    [_member close];
    _pumpGeneration.fetch_add(1);   // stale pump loops see this and exit
    _pumpWriter = nil;
    int fd = _ourFD;
    _ourFD = -1;
    if (_readSource) {
        dispatch_source_t src = _readSource;
        _readSource = nil;
        // The fd closes only after the source is fully cancelled — closing it
        // out from under a running event handler hands the handler a recycled
        // descriptor belonging to someone else.
        dispatch_source_set_cancel_handler(src, ^{ if (fd >= 0) close(fd); });
        dispatch_source_cancel(src);
    } else if (fd >= 0) {
        close(fd);
    }
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

/// Engine error events keep their structured name/info so the provider can
/// classify the failure for the user (see TunnelIncidents).
- (void)emitErrorEvent:(NSString *)name info:(NSString *)info {
    id<OpenVPN3BridgeDelegate> d = _delegate;
    NSString *eventName = name ?: @"ERROR";
    NSString *message = info.length ? [NSString stringWithFormat:@"%@: %@", eventName, info] : eventName;
    NSError *err = [NSError errorWithDomain:kOVPNErrorDomain code:101 userInfo:@{
        NSLocalizedDescriptionKey: message,
        OVPNErrorEventNameKey: name ?: @"",
        OVPNErrorEventInfoKey: info ?: @"",
    }];
    dispatch_async(_cbQueue, ^{ [d bridge:self didFailWithError:err]; });
}
- (void)emitLog:(NSString *)line {
    id<OpenVPN3BridgeDelegate> d = _delegate;
    dispatch_async(_cbQueue, ^{ [d bridge:self didLog:line]; });
}

@end
