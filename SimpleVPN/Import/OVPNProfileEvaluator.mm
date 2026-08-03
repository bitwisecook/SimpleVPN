// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
//  OVPNProfileEvaluator.mm
//  Thin ObjC++ wrapper over OpenVPNClientHelper::eval_config. This is the only
//  place the app target touches the OpenVPN 3 C++ headers; it links the same
//  OpenVPNEngine.xcframework as the packet tunnel.
//

#import "OVPNProfileEvaluator.h"

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Weverything"
#include <client/ovpncli.hpp>
#pragma clang diagnostic pop

#include <string>

using namespace openvpn::ClientAPI;

@implementation OVPNEvalResult

- (instancetype)init {
    if ((self = [super init])) {
        _message = @""; _profileName = @""; _friendlyName = @"";
        _userlockedUsername = @""; _staticChallenge = @"";
        _remoteHost = @""; _remotePort = @""; _remoteProto = @"";
        _serverList = @[]; _serverFriendlyNames = @[];
        _allowPasswordSave = YES;
    }
    return self;
}

@end

@implementation OVPNProfileEvaluator

+ (OVPNEvalResult *)evaluate:(NSString *)ovpnText {
    OVPNEvalResult *r = [OVPNEvalResult new];
    @autoreleasepool {
        try {
            OpenVPNClientHelper helper;
            Config config;
            config.content = ovpnText.UTF8String ?: "";
            EvalConfig ev = helper.eval_config(config);

            r.error = ev.error;
            r.message = @(ev.message.c_str());
            r.profileName = @(ev.profileName.c_str());
            r.friendlyName = @(ev.friendlyName.c_str());
            r.autologin = ev.autologin;
            r.externalPki = ev.externalPki;
            r.privateKeyPasswordRequired = ev.privateKeyPasswordRequired;
            r.allowPasswordSave = ev.allowPasswordSave;
            r.userlockedUsername = @(ev.userlockedUsername.c_str());
            r.staticChallenge = @(ev.staticChallenge.c_str());
            r.staticChallengeEcho = ev.staticChallengeEcho;
            r.remoteHost = @(ev.remoteHost.c_str());
            r.remotePort = @(ev.remotePort.c_str());
            r.remoteProto = @(ev.remoteProto.c_str());

            NSMutableArray<NSString *> *servers = [NSMutableArray new];
            NSMutableArray<NSString *> *names = [NSMutableArray new];
            for (const auto &entry : ev.serverList) {
                [servers addObject:@(entry.server.c_str())];
                [names addObject:@(entry.friendlyName.c_str())];
            }
            r.serverList = servers;
            r.serverFriendlyNames = names;
        } catch (const std::exception &e) {
            r.error = YES;
            r.message = @(e.what());
        } catch (...) {
            r.error = YES;
            r.message = @"profile evaluation failed";
        }
    }
    return r;
}

@end
