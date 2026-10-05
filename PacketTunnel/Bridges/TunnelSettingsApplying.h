// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
#pragma once
#import <NetworkExtension/NetworkExtension.h>
NS_ASSUME_NONNULL_BEGIN
/// Engines request settings through the provider-owned serialized writer.
@protocol SVPTunnelSettingsApplying <NSObject>
- (void)applyNetworkSettings:(nullable NETunnelNetworkSettings *)settings
          completionHandler:(void (^)(NSError * _Nullable))completionHandler
    NS_SWIFT_NAME(applyNetworkSettings(_:completionHandler:));
@end
NS_ASSUME_NONNULL_END
