// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
#pragma once
#import <Foundation/Foundation.h>
NS_ASSUME_NONNULL_BEGIN
NS_SWIFT_SENDABLE
@interface SVPPacketPolicy : NSObject
- (instancetype)init NS_UNAVAILABLE;
- (instancetype)initWithHandle:(uint64_t)handle;
@property(nonatomic, readonly) BOOL inspectOutbound;
@property(nonatomic, readonly) BOOL inspectInbound;
- (BOOL)observeOutboundBatch:(NSArray<NSData *> *)packets;
- (BOOL)observePacket:(const void *)bytes length:(NSUInteger)length inbound:(BOOL)inbound;
- (BOOL)apply:(void *)bytes length:(NSUInteger)length inbound:(BOOL)inbound;
- (nullable NSData *)snapshot;
- (nullable NSData *)trafficLogSnapshot;
- (void)close;
@end
NS_ASSUME_NONNULL_END
