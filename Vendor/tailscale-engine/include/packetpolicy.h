// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
#ifndef SIMPLEVPN_PACKET_POLICY_H
#define SIMPLEVPN_PACKET_POLICY_H
#include <stdint.h>
#ifdef __cplusplus
extern "C" {
#endif
// A valid empty policy tracks pass-through traffic. Strings are UTF-8,
// NUL-terminated, with no embedded NUL. source <= 32768, metadata <= 256 bytes.
uint64_t PPCreate(const char *adapter, const char *source, char **error);
uint64_t PPCreateWithContext(const char *adapter,const char *profile,const char *kind,const char *source,char **error);
// 0 outbound (OS to VPN), 1 inbound (VPN to OS). NeedsPackets returns -1
// for a stale handle, 0 when counters can be batched, or 1 for active policy.
int PPDirectionNeedsPackets(uint64_t handle,int direction);
void PPObserve(uint64_t handle,int direction,uint64_t packets,uint64_t bytes);
int PPApply(uint64_t handle,int direction,void *bytes,int length);
char *PPStatus(uint64_t handle);
void PPDestroy(uint64_t handle);
void PPFree(char *text);
#ifdef __cplusplus
}
#endif
#endif
