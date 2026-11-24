// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
#ifndef SIMPLEVPN_ROUTING_FLOW_LOG_H
#define SIMPLEVPN_ROUTING_FLOW_LOG_H
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#ifdef __cplusplus
extern "C" {
#endif

typedef struct RCFlowLog RCFlowLog;
typedef struct {
    uint8_t address[16];
    uint16_t port;
    uint8_t protocol, family;
    uint64_t bytes[2], packets[2]; // outbound, inbound
    double age_first, age_last;
} RCFlowLogRow;

// Serialize access to this per-session, in-memory log in the packet provider.
RCFlowLog *rc_flow_log_new(void);
void rc_flow_log_free(RCFlowLog *);
void rc_flow_log_record(RCFlowLog *, const uint8_t *, size_t length, bool inbound);
size_t rc_flow_log_snapshot(const RCFlowLog *, RCFlowLogRow *, size_t capacity);

#ifdef __cplusplus
}
#endif
#endif
