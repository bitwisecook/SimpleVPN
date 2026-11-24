// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
#import "OpenConnectBridge.h"
#include <net/if.h>
#include <arpa/inet.h>
#include <algorithm>
#include <fcntl.h>
#include <unistd.h>
#include <openconnect.h>

@interface Peer : NSObject <OpenConnectBridgeDelegate>
@property(nonatomic, strong) dispatch_semaphore_t ready;
@property(nonatomic, strong) dispatch_semaphore_t received;
@property(atomic, copy) NSString *address;
@property(atomic, copy) NSData *packet;
@property(atomic) BOOL failed;
@property(nonatomic) BOOL expectsIPv6;
@end
@implementation Peer
- (void)ocBridge:(OpenConnectBridge *)bridge didChangeStatus:(OCStatus)status event:(NSString *)event info:(NSString *)info {
    if (status == OCStatusConnected) {
        NEPacketTunnelNetworkSettings *network = bridge.memberNetworkSettings;
        if (!self.expectsIPv6 || ([network.IPv6Settings.addresses.firstObject isEqualToString:@"2001:db8::22"] &&
            (network.IPv6Settings.networkPrefixLengths.firstObject.intValue == 64 ||
             network.IPv6Settings.networkPrefixLengths.firstObject.intValue == 128)))
            self.address = network.IPv4Settings.addresses.firstObject;
        dispatch_semaphore_signal(self.ready);
    }
}
- (void)ocBridge:(OpenConnectBridge *)bridge didFailWithError:(NSError *)error {
    self.failed = YES;
    dispatch_semaphore_signal(self.ready);
}
- (void)ocBridge:(OpenConnectBridge *)bridge didLog:(NSString *)line {}
@end

int main(int argc, char **argv) {
    @autoreleasepool {
        if (argc == 2 && strcmp(argv[1], "--fd-ownership") == 0) {
            int channel[2];
            if (pipe(channel) < 0) return 1;
            int stdinState = fcntl(STDIN_FILENO, F_GETFD);
            auto *ctx = openconnect_vpninfo_new("fixture", nullptr, nullptr, nullptr, nullptr, nullptr);
            if (!ctx) return 1;
            openconnect_set_cancel_fd(ctx, channel[0]);
            openconnect_vpninfo_free(ctx);
            bool valid = fcntl(channel[0], F_GETFD) >= 0 && fcntl(STDIN_FILENO, F_GETFD) == stdinState;
            close(channel[0]); close(channel[1]);
            return valid ? 0 : 1;
        }
        if (argc != 6) return 2;
        NSString *mode = @(argv[4]);
        Peer *peer = [Peer new];
        peer.expectsIPv6 = [@[@"gp", @"anyconnect"] containsObject:@(argv[5])] || [mode isEqual:@"allow-dual"];
        peer.ready = dispatch_semaphore_create(0);
        peer.received = dispatch_semaphore_create(0);
        uint32_t index = [mode isEqualToString:@"bad-interface"] ? UINT32_MAX : if_nametoindex("lo0");
        OpenConnectBridge *bridge = [[OpenConnectBridge alloc] initWithInterfaceIndex:index delegate:peer received:^(NSData *packet) {
            peer.packet = packet;
            dispatch_semaphore_signal(peer.received);
        }];
        OCClientSettings *settings = [OCClientSettings new];
        settings.protocol = @(argv[5]);
        settings.server = [NSString stringWithFormat:@"https://gateway.fixture.invalid:%s/", argv[1]];
        settings.resolveIP = @"127.0.0.1";
        settings.resolveHost = [mode isEqualToString:@"bad-host"] ? @"other.fixture.invalid" : @"gateway.fixture.invalid";
        settings.caFile = @(argv[2]);
        settings.serverCertSHA256 = @(argv[3]);
        settings.cookie = @{@"anyconnect": @"webvpn=disposable-fixture", @"gp": @"user=fixture&portal=lab&authcookie=disposable-fixture",
            @"f5": @"MRHSession=disposable-fixture", @"fortinet": @"SVPNCOOKIE=disposable-fixture",
            @"nc": @"DSID=disposable-fixture", @"pulse": @"disposable-fixture", @"array": @"ANsession=disposable-fixture"}[settings.protocol];
        if (!settings.cookie) return 2;
        settings.disableDTLS = YES;
        settings.reconnectTimeout = @0;

        NSError *error = nil;
        if (![bridge connectWithSettings:settings error:&error] ||
            dispatch_semaphore_wait(peer.ready, dispatch_time(DISPATCH_TIME_NOW, 10 * NSEC_PER_SEC))) return 3;
        if ([mode hasPrefix:@"allow"]) {
            if (peer.failed || ![peer.address isEqualToString:@"198.18.30.2"]) return 4;
            uint8_t request[] = {0x45,0,0,32,0,0,0,0,64,17,0xb2,0x9d,198,18,30,2,198,18,30,9,
                                 0xb0,1,0x23,0x28,0,12,0,0,'c','s','t','p'};
            NSData *out = [NSData dataWithBytes:request length:sizeof(request)];
            if (![bridge sendMemberPacket:out] ||
                dispatch_semaphore_wait(peer.received, dispatch_time(DISPATCH_TIME_NOW, 4 * NSEC_PER_SEC))) return 5;
            std::swap_ranges(request + 12, request + 16, request + 16);
            std::swap_ranges(request + 20, request + 22, request + 22);
            NSData *expected = [NSData dataWithBytes:request length:sizeof(request)];
            if (![peer.packet isEqualToData:expected]) return 6;
            int64_t expectedBytes = sizeof(request);
            if ([mode isEqual:@"allow-dual"]) {
                uint8_t v6[52] = {0x60,0,0,0, 0,12,17,64};
                inet_pton(AF_INET6, "2001:db8::22", v6 + 8);
                inet_pton(AF_INET6, "2001:db8::29", v6 + 24);
                const uint8_t udp[] = {0xb0,1,0x23,0x28,0,12,0xf1,0x48,'i','p','v','6'};
                memcpy(v6 + 40, udp, sizeof(udp));
                if (![bridge sendMemberPacket:[NSData dataWithBytes:v6 length:sizeof(v6)]] ||
                    dispatch_semaphore_wait(peer.received, dispatch_time(DISPATCH_TIME_NOW, 4 * NSEC_PER_SEC))) return 5;
                std::swap_ranges(v6 + 8, v6 + 24, v6 + 24);
                std::swap_ranges(v6 + 40, v6 + 42, v6 + 42);
                if (![peer.packet isEqualToData:[NSData dataWithBytes:v6 length:sizeof(v6)]]) return 6;
                expectedBytes += sizeof(v6);
            }
            int64_t bytesIn = 0, bytesOut = 0;
            for (int i = 0; i < 40 && (bytesIn != expectedBytes || bytesOut != expectedBytes); i++) {
                [bridge transportBytesIn:&bytesIn bytesOut:&bytesOut];
                if (bytesIn != expectedBytes || bytesOut != expectedBytes) usleep(25000);
            }
            if (bytesIn != expectedBytes || bytesOut != expectedBytes) return 9;
        } else if (!peer.failed || peer.address) return 7;
        dispatch_semaphore_t done = dispatch_semaphore_create(0);
        [bridge stopMemberWithCompletion:^{ dispatch_semaphore_signal(done); }];
        if (dispatch_semaphore_wait(done, dispatch_time(DISPATCH_TIME_NOW, 5 * NSEC_PER_SEC))) return 8;
    }
    return 0;
}
