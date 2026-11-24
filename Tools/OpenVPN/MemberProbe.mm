// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
// Two real scoped clients share an AF_UNIX-only upstream server. No host tunnel interface.
#import "OpenVPN3Bridge.h"
#include <arpa/inet.h>
#include <net/if.h>

@interface Peer : NSObject <OpenVPN3BridgeDelegate>
@property(nonatomic, strong) OpenVPN3Bridge *bridge;
@property(atomic, copy) NSString *address;
@property(atomic, copy) NSData *packet;
@property(nonatomic, strong) dispatch_semaphore_t connected;
@property(nonatomic, strong) dispatch_semaphore_t received;
@end
@implementation Peer
- (instancetype)init {
    if ((self = [super init])) {
        _connected = dispatch_semaphore_create(0);
        _received = dispatch_semaphore_create(0);
        __weak Peer *weakPeer = self;
        _bridge = [[OpenVPN3Bridge alloc] initWithInterfaceIndex:if_nametoindex("lo0") delegate:self received:^(NSData *packet) {
            Peer *peer = weakPeer;
            if (peer && packet.length == 32) { peer.packet = packet; dispatch_semaphore_signal(peer.received); }
        }];
    }
    return self;
}
- (void)bridge:(OpenVPN3Bridge *)bridge didChangeStatus:(OVPNStatus)status event:(NSString *)name info:(NSString *)info {
    if (status == OVPNStatusConnected) {
        self.address = bridge.memberNetworkSettings.IPv4Settings.addresses.firstObject;
        dispatch_semaphore_signal(self.connected);
    }
}
- (void)bridge:(OpenVPN3Bridge *)bridge didFailWithError:(NSError *)error {
    fprintf(stderr, "Member failed: %s\n", error.localizedDescription.UTF8String);
    dispatch_semaphore_signal(self.connected);
}
- (void)bridge:(OpenVPN3Bridge *)bridge didLog:(NSString *)line {}
@end

static bool transfer(Peer *a, Peer *b, uint8_t marker) {
    uint8_t p[32] = {0x45, 0, 0, 32, 0, 1, 0, 0, 64, 17, 0, 0};
    if (inet_pton(AF_INET, a.address.UTF8String, p + 12) != 1 || inet_pton(AF_INET, b.address.UTF8String, p + 16) != 1) return false;
    uint32_t sum = 0;
    for (size_t i = 0; i < 20; i += 2) sum += (p[i] << 8) + p[i + 1];
    while (sum >> 16) sum = (sum & 65535) + (sum >> 16);
    p[10] = (uint8_t)(~sum >> 8); p[11] = (uint8_t)~sum;
    p[20] = 0xc1; p[21] = 1; p[22] = 0xc1; p[23] = 2; p[25] = 12;
    p[28] = 'O'; p[29] = 'V'; p[30] = 'P'; p[31] = marker;
    NSData *expected = [NSData dataWithBytes:p length:sizeof(p)];
    for (int i = 0; i < 5; i++) {
        if (![a.bridge sendMemberPacket:expected]) return false;
        if (dispatch_semaphore_wait(b.received, dispatch_time(DISPATCH_TIME_NOW, NSEC_PER_SEC)) == 0 &&
            [expected isEqualToData:b.packet]) return true;
    }
    return false;
}
int main(int argc, char **argv) {
    @autoreleasepool {
        if (argc != 3) return 2;
        NSArray<Peer *> *peers = @[[Peer new], [Peer new]];
        for (int i = 0; i < 2; i++) {
            NSError *error = nil;
            NSString *source = [NSString stringWithContentsOfFile:@(argv[i + 1]) encoding:NSUTF8StringEncoding error:&error];
            if (!source || ![peers[i].bridge connectWithProfile:source username:@"" password:@"" settings:nil error:&error]) return 3;
            if (dispatch_semaphore_wait(peers[i].connected, dispatch_time(DISPATCH_TIME_NOW, 15 * NSEC_PER_SEC)) || !peers[i].address) return 4;
        }
        if ([peers[0].address isEqual:peers[1].address] || !transfer(peers[0], peers[1], 'A') || !transfer(peers[1], peers[0], 'B')) {
            fprintf(stderr, "Member datagram failure: %s / %s, received lengths %lu / %lu\n",
                peers[0].address.UTF8String, peers[1].address.UTF8String,
                (unsigned long)peers[0].packet.length, (unsigned long)peers[1].packet.length);
            return 5;
        }
        dispatch_group_t stopped = dispatch_group_create();
        for (Peer *peer in peers) { dispatch_group_enter(stopped); [peer.bridge stopMemberWithCompletion:^{ dispatch_group_leave(stopped); }]; }
        if (dispatch_group_wait(stopped, dispatch_time(DISPATCH_TIME_NOW, 5 * NSEC_PER_SEC))) return 6;
        puts("OpenVPN members authenticated, used distinct addresses, and exchanged intact datagrams in both directions.");
    }
    return 0;
}
