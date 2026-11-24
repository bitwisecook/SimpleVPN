// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
#pragma once
#include "SVIPsec.h"
// Dedicated process, exact physical underlay and private point-to-point channels.
// The host validates the suspended image before sending any credentials.
// As with SVIKEStart, callback strings and packet bytes are borrowed. Call stop
// from the owner queue, after returning from a callback.
uint64_t SVWorkerStart(const char *executable, const SVIKEConfig *config, const char *ppp_user,
                       const uint8_t *ppp_password, size_t length, uint32_t ifindex,
                       SVIKECallbacks callbacks, void *context);
bool SVWorkerSend(uint64_t member, const uint8_t *packet, size_t length);
uint16_t SVWorkerMTU(uint64_t member);
void SVWorkerStop(uint64_t member);
int SVWorkerMain(void);
