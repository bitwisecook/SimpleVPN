// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
#pragma once
struct pbuf;
struct netif;
int sv_l2tp_inner_input(struct pbuf *, struct netif *);
#define LWIP_HOOK_IP4_INPUT(p, n) sv_l2tp_inner_input(p, n)
