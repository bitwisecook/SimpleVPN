// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
// See OCAuthShim.h — variadic-progress trampoline for the Swift helper.

#include "OCAuthShim.h"

#include <stdarg.h>
#include <stdio.h>
#include <string.h>

static ocauth_progress_fn g_progress;

__attribute__((format(printf, 3, 4)))
static void trampoline(void *privdata, int level, const char *fmt, ...)
{
    char line[1024];
    va_list ap;

    if (!g_progress)
        return;
    va_start(ap, fmt);
    vsnprintf(line, sizeof(line), fmt, ap);
    va_end(ap);
    /* openconnect terminates its lines; the JSON event carries the text only. */
    size_t len = strlen(line);
    while (len > 0 && (line[len - 1] == '\n' || line[len - 1] == '\r'))
        line[--len] = '\0';
    g_progress(privdata, level, line);
}

struct openconnect_info *ocauth_vpninfo_new(const char *useragent,
                                            openconnect_validate_peer_cert_vfn validate,
                                            openconnect_process_auth_form_vfn form,
                                            ocauth_progress_fn progress,
                                            void *privdata)
{
    g_progress = progress;
    return openconnect_vpninfo_new(useragent, validate, NULL, form, trampoline, privdata);
}
