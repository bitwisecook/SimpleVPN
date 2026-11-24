// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
#pragma once
#include "../SVIPsec.h"
typedef struct SVPPP SVPPP;
typedef bool (*SVPPPOutput)(const uint8_t *, size_t);
SVPPP *sv_ppp_new(const char *user, const uint8_t *password, size_t length, SVIKECallbacks callbacks,
                  void *context, SVPPPOutput carrier_output);
bool sv_ppp_carrier_up(SVPPP *, const uint8_t local[4], const uint8_t remote[4]);
void sv_ppp_carrier_down(SVPPP *);
bool sv_ppp_input(SVPPP *, const uint8_t *bytes, size_t length);
bool sv_ppp_send(SVPPP *, const uint8_t *bytes, size_t length);
void sv_ppp_quiesce(SVPPP *);
void sv_ppp_free(SVPPP *);
uint16_t sv_ppp_mtu(SVPPP *);
