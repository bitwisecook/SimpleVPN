// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
// Runs the provider's actual ARC wrapper against the two shipping static archives.
#import "SVPPacketPolicy.h"
#import "packetpolicy.h"
#include <cassert>
#include <initializer_list>

static NSDictionary *snapshot(SVPPacketPolicy *policy) {
    return [NSJSONSerialization JSONObjectWithData:[policy snapshot] options:0 error:nil];
}
static NSArray *flows(SVPPacketPolicy *policy) {
    return [NSJSONSerialization JSONObjectWithData:[policy trafficLogSnapshot] options:0 error:nil];
}
int main() {
    @autoreleasepool {
        for (const char *adapter : {"wireguard", "wireguard-teleport", "tailscale-node",
                 "openvpn3", "openconnect-packet", "proxy-socks5", "proxy-http", "proxy-https", "sshnet",
                 "ssh-tun", "ikev2-strongswan", "ipsec-strongswan", "l2tp-strongswan"}) {
            char *error = nullptr;
            auto handle = PPCreateWithContext(adapter, "fixture", "", "", &error);
            assert(handle && !error);
            SVPPacketPolicy *policy = [[SVPPacketPolicy alloc] initWithHandle:handle];
            assert(!policy.inspectInbound && !policy.inspectOutbound);
            uint8_t outgoing[] = {0x45,0,0,28,0,0,0,0,64,17,0,0,192,0,2,1,192,0,2,2,25,77,0,53,0,8,0,0};
            uint8_t incoming[] = {0x45,0,0,28,0,0,0,0,64,17,0,0,192,0,2,2,192,0,2,1,0,53,25,77,0,8,0,0};
            NSData *packet = [NSData dataWithBytes:outgoing length:sizeof(outgoing)];
            assert(([policy observeOutboundBatch:@[packet, packet]]));
            assert([policy observePacket:incoming length:sizeof(incoming) inbound:YES]);
            NSDictionary *counts = snapshot(policy);
            assert([counts[@"outbound"][@"forwardedBytes"] intValue] == 56);
            assert([counts[@"outbound"][@"evaluatedPackets"] intValue] == 0);
            assert([counts[@"inbound"][@"receivedPackets"] intValue] == 1);
            assert([snapshot(policy)[@"outbound"][@"forwardedPackets"] intValue] == 2);
            NSArray *activity = flows(policy);
            assert(activity.count == 1);
            NSDictionary *remote = activity.firstObject;
            assert([remote[@"address"] isEqual:@"192.0.2.2"]);
            assert([remote[@"port"] intValue] == 53 && [remote[@"proto"] intValue] == 17);
            assert([remote[@"bytesOut"] intValue] == 56 && [remote[@"bytesIn"] intValue] == 28);
            assert([remote[@"packetsOut"] intValue] == 2 && [remote[@"packetsIn"] intValue] == 1);
            [policy close]; [policy close];
            assert(![policy observePacket:outgoing length:sizeof(outgoing) inbound:NO] && ![policy snapshot]);
            assert(![policy trafficLogSnapshot]);
        }
        char *error = nullptr;
        auto handle = PPCreateWithContext("openvpn3", "fixture", "openvpn",
            "on cut: inbound.ip.packet { drop(); }", &error);
        assert(handle && !error);
        SVPPacketPolicy *policy = [[SVPPacketPolicy alloc] initWithHandle:handle];
        assert(policy.inspectInbound && !policy.inspectOutbound);
        uint8_t udp[] = {0x45,0,0,28,0,0,0,0,64,17,0xf6,0xcd,192,0,2,1,192,0,2,2,0,53,25,77,0,8,0,0};
        assert(![policy apply:udp length:sizeof(udp) inbound:YES]);
        assert([snapshot(policy)[@"inbound"][@"droppedPackets"] intValue] == 1);
        assert(flows(policy).count == 0);
        [policy close];
        assert(![policy apply:udp length:sizeof(udp) inbound:YES]);

        handle = PPCreateWithContext("tailscale-node", "fixture", "tailscale",
            "on passed: inbound.ip.packet { count(); }", &error);
        assert(handle && !error);
        policy = [[SVPPacketPolicy alloc] initWithHandle:handle];
        assert(policy.inspectInbound);
        assert([policy apply:udp length:sizeof(udp) inbound:YES]);
        assert(flows(policy).count == 1);
    }
}
