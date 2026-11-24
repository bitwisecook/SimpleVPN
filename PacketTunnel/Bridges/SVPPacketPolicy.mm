// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
#import "SVPPacketPolicy.h"
#import "packetpolicy.h"
#import "../../Vendor/routing-core/include/routing_flow_log.h"
#include <arpa/inet.h>
#import <os/lock.h>
#include <atomic>
#include <mutex>
#include <vector>

@implementation SVPPacketPolicy {
    std::atomic<uint64_t> _handle;
    os_unfair_lock _lock;
    std::mutex _snapshotLock;
    uint64_t _packets[2], _bytes[2];
    RCFlowLog *_flows;
}
- (instancetype)initWithHandle:(uint64_t)handle {
    if ((self = [super init])) {
        _lock = OS_UNFAIR_LOCK_INIT;
        _handle.store(handle);
        _flows = rc_flow_log_new();
        // An invalid handle must take the fail-closed evaluation path.
        _inspectOutbound = PPDirectionNeedsPackets(handle, 0) != 0;
        _inspectInbound = PPDirectionNeedsPackets(handle, 1) != 0;
    }
    return self;
}
- (BOOL)observeOutboundBatch:(NSArray<NSData *> *)packets {
    os_unfair_lock_lock(&_lock);
    BOOL open = _handle.load() != 0;
    if (open) {
        _packets[0] += packets.count;
        for (NSData *packet in packets) {
            _bytes[0] += packet.length;
            rc_flow_log_record(_flows, (const uint8_t *)packet.bytes, packet.length, false);
        }
    }
    os_unfair_lock_unlock(&_lock);
    return open;
}
- (BOOL)observePacket:(const void *)bytes length:(NSUInteger)length inbound:(BOOL)inbound {
    os_unfair_lock_lock(&_lock);
    BOOL open = _handle.load() != 0;
    if (open) {
        _packets[inbound ? 1 : 0] += 1;
        _bytes[inbound ? 1 : 0] += length;
        rc_flow_log_record(_flows, (const uint8_t *)bytes, length, inbound);
    }
    os_unfair_lock_unlock(&_lock);
    return open;
}
- (BOOL)apply:(void *)bytes length:(NSUInteger)length inbound:(BOOL)inbound {
    if (length > INT_MAX || PPApply(_handle.load(), inbound ? 1 : 0, bytes, (int)length) != 1) return NO;
    os_unfair_lock_lock(&_lock);
    BOOL open = _handle.load() != 0;
    if (open) rc_flow_log_record(_flows, (const uint8_t *)bytes, length, inbound);
    os_unfair_lock_unlock(&_lock);
    return open;
}
- (NSData *)trafficLogSnapshot {
    os_unfair_lock_lock(&_lock);
    RCFlowLog *log = _flows;
    if (!log) {
        os_unfair_lock_unlock(&_lock);
        return nil;
    }
    std::vector<RCFlowLogRow> rows(rc_flow_log_snapshot(log, nullptr, 0));
    if (!rows.empty()) rc_flow_log_snapshot(log, rows.data(), rows.size());
    os_unfair_lock_unlock(&_lock);

    NSMutableArray *result = [NSMutableArray arrayWithCapacity:rows.size()];
    for (const RCFlowLogRow &row : rows) {
        char address[INET6_ADDRSTRLEN];
        if (!inet_ntop(row.family == 6 ? AF_INET6 : AF_INET, row.address, address, sizeof(address))) continue;
        [result addObject:@{
            @"family": @(row.family), @"address": @(address), @"port": @(row.port), @"proto": @(row.protocol),
            @"bytesOut": @(row.bytes[0]), @"bytesIn": @(row.bytes[1]),
            @"packetsOut": @(row.packets[0]), @"packetsIn": @(row.packets[1]),
            @"ageFirst": @(row.age_first), @"ageLast": @(row.age_last),
        }];
    }
    return [NSJSONSerialization dataWithJSONObject:result options:0 error:NULL];
}
- (NSData *)snapshot {
    // Serialize inspectors, but release the traffic lock before Go encodes rules.
    std::lock_guard<std::mutex> snapshotGuard(_snapshotLock);
    uint64_t packets[2], bytes[2];
    os_unfair_lock_lock(&_lock);
    uint64_t handle = _handle.load();
    for (int d = 0; d < 2; ++d) {
        packets[d] = _packets[d]; bytes[d] = _bytes[d];
        _packets[d] = _bytes[d] = 0;
    }
    os_unfair_lock_unlock(&_lock);
    if (!handle) return nil;
    for (int d = 0; d < 2; ++d) {
        if (packets[d]) PPObserve(handle, d, packets[d], bytes[d]);
    }
    char *json = PPStatus(handle);
    if (!json) return nil;
    NSData *result = [NSData dataWithBytes:json length:strlen(json)];
    PPFree(json);
    return result;
}
- (void)close {
    os_unfair_lock_lock(&_lock);
    uint64_t old = _handle.exchange(0);
    RCFlowLog *flows = _flows;
    _flows = nullptr;
    os_unfair_lock_unlock(&_lock);
    if (old) PPDestroy(old);
    rc_flow_log_free(flows);
}
- (void)dealloc { [self close]; }
@end
