// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
//  SimpleVPN-Bridging-Header.h
//  App-target bridging header. The app links the OpenVPN 3 engine only for
//  static profile evaluation (see OVPNProfileEvaluator).
//

#import "OVPNProfileEvaluator.h"
#import "SSHBridge.h"
#import "ExceptionPreprocessor.h"

// libproc socket enumeration (AppConnectionInspector): which processes hold
// established TCP connections over a tunnel. Real kernel APIs — never lsof/
// netstat text parsing.
#include <libproc.h>
#include <sys/proc_info.h>
