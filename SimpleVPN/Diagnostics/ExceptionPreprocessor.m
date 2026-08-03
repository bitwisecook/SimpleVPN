// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
//  ExceptionPreprocessor.m
//  Catch Objective-C exceptions where they are THROWN, not where they go uncaught.
//
//  Third attempt at this, and the first two failed for reasons worth recording so nobody
//  repeats them:
//
//   1. NSSetUncaughtExceptionHandler — never fires. An exception raised in AppKit's
//      display cycle ends at +[NSApplication _crashOnException:], which kills the
//      process; the CoreFoundation "uncaught" path is never reached.
//   2. Swizzling -[NSApplication reportException:] — never fires either. The real
//      backtrace goes _NSViewLayout → (AppKit internals) → _crashOnException: directly,
//      with no trip through reportException:.
//
//  objc_setExceptionPreprocessor sits at objc_exception_throw itself, which is upstream
//  of EVERY path — including the one that was losing three crashes in a row. That's also
//  where CoreFoundation's own __exceptionPreprocess lives (visible at frame 0 of the
//  crash's backtrace), so we chain to it rather than replacing it.
//
//  Deliberately LOG-ONLY at this level: the preprocessor sees every exception, including
//  the ones frameworks throw and catch as ordinary control flow. Writing a crash report
//  here would invent crashes that never happened.
//

#import "ExceptionPreprocessor.h"
#import <objc/objc-exception.h>

static SVPNExceptionObserver gObserver = nil;
static objc_exception_preprocessor gPrevious = NULL;

static id svpn_preprocess(id exception) {
    if (gObserver != nil && [exception isKindOfClass:[NSException class]]) {
        gObserver((NSException *)exception);
    }
    // Chain, or the framework behaviour that depends on the previous preprocessor breaks.
    return gPrevious != NULL ? gPrevious(exception) : exception;
}

void SVPNInstallExceptionPreprocessor(SVPNExceptionObserver observer) {
    static BOOL installed = NO;
    if (installed) { return; }
    installed = YES;
    gObserver = [observer copy];
    gPrevious = objc_setExceptionPreprocessor(&svpn_preprocess);
}
