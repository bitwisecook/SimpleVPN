// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
#ifndef SIMPLEVPN_VIRTUAL_ROUTER_H
#define SIMPLEVPN_VIRTUAL_ROUTER_H
#include <stdint.h>
#ifdef __cplusplus
extern "C" {
#endif
typedef void (*VRPacketCallback)(uint64_t context, const unsigned char *bytes, int length);
char *VRCreateInstance(const char *configuration, uint64_t context, VRPacketCallback packetOut);
int VRSetUnderlayInterface(uint64_t handle, uint32_t index);
int VRPacketIn(uint64_t handle, const void *bytes, int length);
char *VRApplyPolicy(uint64_t handle, const char *policy);
char *VRCheckPolicy(uint64_t handle, const char *policy);
char *VRStatus(uint64_t handle);
char *VRStopPort(uint64_t handle, const char *id);
char *VRStopInstance(uint64_t handle);
void VRFree(char *text);
#ifdef __cplusplus
}
#endif
#endif
