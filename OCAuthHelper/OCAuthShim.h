// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
// ocauth-helper C shim. libopenconnect's progress callback is VARIADIC
// (printf-style), which Swift cannot implement — this one-function shim wraps
// openconnect_vpninfo_new with a trampoline that vsnprintf-formats each line
// and forwards it through a plain (non-variadic) function pointer.

#ifndef OCAUTH_SHIM_H
#define OCAUTH_SHIM_H

#pragma clang diagnostic push
#pragma clang diagnostic ignored "-Weverything"
#include <openconnect.h>
#pragma clang diagnostic pop

typedef void (*ocauth_progress_fn)(void *privdata, int level, const char *line);

/* Same contract as openconnect_vpninfo_new (write_new_config unused → NULL),
   with the variadic progress callback replaced by a formattable one. One
   session per helper process, so the trampoline state is a simple global. */
struct openconnect_info *ocauth_vpninfo_new(const char *useragent,
                                            openconnect_validate_peer_cert_vfn validate,
                                            openconnect_process_auth_form_vfn form,
                                            ocauth_progress_fn progress,
                                            void *privdata);

#endif /* OCAUTH_SHIM_H */
