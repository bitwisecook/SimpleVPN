// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
#ifndef SIMPLEVPN_ROUTING_DNS_H
#define SIMPLEVPN_ROUTING_DNS_H
#include <stdint.h>
#include <stdbool.h>
typedef struct RCDnsPlan RCDnsPlan;
typedef enum { RC_DNS_UNMATCHED, RC_DNS_MATCHED, RC_DNS_INVALID } RCDnsStatus;
typedef struct { uint32_t status; uint16_t index; } RCDnsResult;
RCDnsPlan *rc_dns_plan_new(void);
bool rc_dns_plan_add(RCDnsPlan *, uint16_t index, uint8_t kind, const uint8_t *, uint32_t);
RCDnsResult rc_dns_match(const RCDnsPlan *, const uint8_t *canonical_name, uint32_t);
void rc_dns_plan_free(RCDnsPlan *);
#endif
