// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
//  OVPNProfileEvaluator.h
//  App-side static profile evaluation using the real OpenVPN 3 parser
//  (OpenVPNClientHelper::eval_config — a pure parse, no tunnel or session).
//  Drives profile-adaptive UI: placeholders, conditional rows, server pickers,
//  and import validation. The result mirrors ClientAPI::EvalConfig.
//

#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

@interface OVPNEvalResult : NSObject

// Parse outcome
@property BOOL error;
@property (copy) NSString *message;

// Identity
@property (copy) NSString *profileName;
@property (copy) NSString *friendlyName;

// Authentication shape
@property BOOL autologin;
@property BOOL externalPki;
@property BOOL privateKeyPasswordRequired;
@property BOOL allowPasswordSave;
@property (copy) NSString *userlockedUsername;
@property (copy) NSString *staticChallenge;
@property BOOL staticChallengeEcho;

// First `remote`
@property (copy) NSString *remoteHost;
@property (copy) NSString *remotePort;
@property (copy) NSString *remoteProto;

// Optional user-selectable server list (parallel arrays)
@property (copy) NSArray<NSString *> *serverList;
@property (copy) NSArray<NSString *> *serverFriendlyNames;

@end

@interface OVPNProfileEvaluator : NSObject

/// Statically evaluate an .ovpn profile. Never throws — parse problems come back
/// with `error = YES` and a human-readable `message`.
+ (OVPNEvalResult *)evaluate:(NSString *)ovpnText;

@end

NS_ASSUME_NONNULL_END
