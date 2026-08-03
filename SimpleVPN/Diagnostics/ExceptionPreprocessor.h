// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
//  ExceptionPreprocessor.h
//  See the .m — intercepts Objective-C exceptions at THROW time.
//

#import <Foundation/Foundation.h>

NS_ASSUME_NONNULL_BEGIN

typedef void (^SVPNExceptionObserver)(NSException *exception);

/// Install a throw-time observer. Idempotent; chains to any existing preprocessor.
void SVPNInstallExceptionPreprocessor(SVPNExceptionObserver observer);

NS_ASSUME_NONNULL_END
