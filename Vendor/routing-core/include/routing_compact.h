// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
#ifndef SIMPLEVPN_ROUTING_COMPACT_H
#define SIMPLEVPN_ROUTING_COMPACT_H
#include <stdint.h>
#include <stddef.h>

// All buffers belong to the caller. The core retains no addresses.
typedef struct {
    uint8_t address[16], family, prefix, kind, action;
    uint16_t port, value;
    uint8_t id_len, source_len, name_len;
    uint8_t id[80], source[80], name[253];
} svp_compact_row;

typedef struct {
    uint64_t hits[2];
    uint16_t mss;
    uint8_t has_mss, dscp, has_dscp, recursion, has_recursion, dropped;
} svp_compact_result;

// Returns the number of rows or -1 with a NUL-terminated UTF-8 diagnostic.
int32_t svp_compact_compile(const uint8_t *text, size_t length,
    svp_compact_row *rows, size_t capacity, char *error, size_t error_size);

// The two candidate bit sets are compiled by event and destination port. A
// nonzero return signals an invalid ABI argument; the caller must drop.
int32_t svp_compact_match(const svp_compact_row *rows, size_t count,
    uint64_t low, uint64_t high, const uint8_t *address, uint8_t family,
    const char *source, size_t source_len, const char *name, size_t name_len,
    svp_compact_result *result);
#endif
