// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
#pragma once
#define NO_SYS 1
#define SYS_LIGHTWEIGHT_PROT 0
#define LWIP_SOCKET 0
#define LWIP_NETCONN 0
#define LWIP_IPV4 1
#define LWIP_IPV6 0
#define LWIP_TCP 0
#define LWIP_ARP 0
#define LWIP_ETHERNET 0
#define LWIP_RAW 0
#define LWIP_ICMP 0
#define IP_FRAG 0
#define IP_REASSEMBLY 0
#define LWIP_DNS 1
#define LWIP_NETIF_LOOPBACK 0
#define LWIP_HAVE_LOOPIF 0
#define PPP_SUPPORT 1
#define PPPOL2TP_SUPPORT 1
#define MSCHAP_SUPPORT 1
#define PPPOS_SUPPORT 0
#define VJ_SUPPORT 0
#define LWIP_STATS 0
#define MEM_ALIGNMENT 8
#define MEM_SIZE 65536
#define PPPOL2TP_DEFMRU 1360
#define LWIP_HOOK_FILENAME "ppp-hook.h"
#ifdef SIMPLEVPN_PPP_FIXTURE
#define PPP_SERVER 1
#endif
