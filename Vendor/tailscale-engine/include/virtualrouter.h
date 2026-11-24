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
/* Starts with the negotiated settings of each authenticated driver. Slot is the
 * zero-based member index. Send must enqueue or copy its borrowed bytes before
 * returning, and must not synchronously stop or reconfigure the session. */
typedef int (*VRPortSendCallback)(uint64_t context, uint32_t slot, uint64_t generation, const unsigned char *bytes, int length);
char *VRCreateInstanceWithPorts(const char *configuration, uint64_t context, VRPacketCallback packetOut, VRPortSendCallback portSend);
int VRPortReturn(uint64_t handle, uint32_t slot, uint64_t generation, const void *bytes, int length);
int VRRevokePort(uint64_t handle, uint32_t slot, uint64_t generation);
int VRReplacePort(uint64_t handle, uint32_t slot, uint64_t oldGeneration, const char *member);
int VRSetUnderlayInterface(uint64_t handle, uint32_t index);
int VRPacketIn(uint64_t handle, const void *bytes, int length);
/* Alias is resolved by the capture provider from this packet's OS metadata.
 * Owner is the packed process incarnation (PID + PID version), zero if unknown. */
int VRPacketInWithSource(uint64_t handle, const void *bytes, int length, const char *source, uint64_t owner);
char *VRApplyPolicy(uint64_t handle, const char *policy);
char *VRCheckPolicy(uint64_t handle, const char *policy);
char *VRValidateEvents(const char *source);
char *VRInspect(uint64_t handle, const char *request);
char *VRStatus(uint64_t handle);
char *VRPacketStats(uint64_t handle);
char *VRPortPacketStats(uint64_t handle, uint32_t slot);
char *VRStopPort(uint64_t handle, const char *id);
char *VRStopInstance(uint64_t handle);
void VRFree(char *text);
#ifdef __cplusplus
}
#endif
#endif
