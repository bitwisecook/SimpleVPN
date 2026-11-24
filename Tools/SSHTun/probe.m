// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
#import "SSHBridge.h"
#import <net/if.h>

int main(int argc, char **argv) {
    @autoreleasepool {
        if (argc != 4) return 1;
        NSString *mode = @(argv[3]);
        SSHSession *session = [SSHSession new];
        session.physicalInterfaceIndex = if_nametoindex("lo0");
        if (!session.physicalInterfaceIndex) return 1;
        NSError *error = nil;
        if (![session connectToHost:@"127.0.0.1" port:atoi(argv[1]) timeout:3 error:&error]) return 2;
        BOOL matches = [session checkHostKeyWithKnownHosts:nil pin:@(argv[2])] == SSHHostKeyStatusMatch;
        if ([mode isEqual:@"wrongpin"]) { [session disconnect]; return matches ? 3 : 0; }
        if (!matches || ![session authPasswordForUser:@"fixture" password:@"fixture-secret" error:&error]) return 4;
        NSMutableArray *packets = [NSMutableArray array];
        SSHChannel *tun = [session openPointToPointUnit:7 mtu:1400 received:^(NSData *p) {
            [packets addObject:p];
        } error:&error];
        if ([mode isEqual:@"denied"]) { [session disconnect]; return tun ? 5 : 0; }
        if (!tun) return 6;
        [session enterDataMode];
        NSMutableArray *sent = [NSMutableArray array];
        for (int i = 0; i < 4; i++) {
            BOOL ipv6 = i % 2;
            NSMutableData *data = [NSMutableData dataWithLength:ipv6 ? 48 : 28];
            uint8_t *p = data.mutableBytes;
            if (ipv6) { p[0] = 0x60; p[5] = 8; p[6] = 17; p[7] = 64; }
            else { p[0] = 0x45; p[3] = 28; p[8] = 64; p[9] = 17; }
            p[data.length - 1] = i + 1;
            if ([tun writeTunPacket:data] != 1) return 7;
            [sent addObject:data];
        }
        for (int i = 0; packets.count < 4 && i < 25; i++) {
            if ([session waitForActivityWithTimeoutMs:100] < 0) break;
        }
        BOOL ok = [packets isEqualToArray:sent];
        [tun close];
        [session disconnect];
        return ok ? 0 : 8;
    }
}
