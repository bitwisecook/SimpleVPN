// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN
/// Private packet lane for an authenticated L3 VPN. A generation's socketpair
/// can only communicate with that engine; neither end references an NE flow.
@interface VirtualDatagramPort : NSObject
- (instancetype)initWithFamilyHeader:(BOOL)familyHeader received:(void (^)(NSData *))received;
/// Ownership of the returned descriptor passes to the native VPN library.
- (int)openEngineDescriptor;
- (BOOL)sendPacket:(NSData *)packet;
- (void)close;
@end
NS_ASSUME_NONNULL_END
