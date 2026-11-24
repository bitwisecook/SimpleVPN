// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
#ifndef SIMPLEVPN_ROUTING_MEDIATION_H
#define SIMPLEVPN_ROUTING_MEDIATION_H
#include <stdint.h>
#ifdef __cplusplus
extern "C" {
#endif
// Zero-initialize one row per direction and serialize access in the session owner.
typedef struct {
 uint64_t received_packets,received_bytes,forwarded_packets,forwarded_bytes,
          dropped_packets,dropped_bytes,evaluated_packets,edited_packets,rule_hits;
} RCTrafficCounters;
enum RCTrafficStage { RC_RECEIVE, RC_FORWARD, RC_DROP_PACKET, RC_PASSTHROUGH, RC_EVALUATE };
void rc_traffic_record(RCTrafficCounters*,uint32_t stage,uint64_t packets,uint64_t bytes,uint64_t hits,uint64_t edited);
typedef struct RCUdpHistory RCUdpHistory;
typedef struct { uint8_t family,src[16],dst[16]; uint16_t src_port,dst_port; } RCUdpTuple;
// One owner per session/direction. Times are milliseconds from a monotonic origin.
RCUdpHistory *rc_udp_history_new(void);
void rc_udp_history_free(RCUdpHistory*);
int32_t rc_udp_seen(RCUdpHistory*,const RCUdpTuple*,uint64_t now_ms);
void rc_udp_accept(RCUdpHistory*,const RCUdpTuple*,uint64_t now_ms);
#ifdef __cplusplus
}
#endif
#endif
