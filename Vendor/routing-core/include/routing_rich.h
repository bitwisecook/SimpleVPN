// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
#ifndef SIMPLEVPN_ROUTING_RICH_H
#define SIMPLEVPN_ROUTING_RICH_H
#include "routing_core.h"
#include <stdbool.h>
#ifdef __cplusplus
extern "C" {
#endif
typedef struct RCRichPlan RCRichPlan;
typedef struct {
    uint32_t status, pc, instructions, remaining_bytes;
    uint8_t *message;
    uint32_t message_len;
} RCRichResult;

// RCR1 is a bounded, little-endian typed compiler interchange, copied at load.
// Header: "RCR1", u32 field count, pairs (u8 kind, u8 edit), u32 table count.
// Table: u8 key/element kinds, u32 count, repeated tagged key/value pairs.
// Code: u32 instruction count, then op:u8, arg/target/aux:u32, kind:u8,
// name:string, and a tagged value for literals. Opcode numbering matches the
// Go compiler's literal..deny. Read/write use arg=field; lookup uses aux=table.
// Strings and byte strings are u32 length then bytes. Value tags: 1 bool (u8),
// 2 signed int64, 3 string, 4 DNS, 5 address (4/6 u8 family + octets),
// 6 prefix (address payload + u8 width), 7 bytes, 128|element array (u32
// count + tagged items). Arrays contain only scalar elements.
typedef struct { uint32_t status, length; uint8_t *bytes; } RCCompilerOutput;
RCCompilerOutput rc_compile_llvm(const uint8_t *image, uint32_t n);
void rc_compiler_output_free(RCCompilerOutput output);
bool rc_rich_is_precompiled(const uint8_t *image, uint32_t n);
RCRichPlan *rc_rich_new(const uint8_t *plan, uint32_t n);
void rc_rich_free(RCRichPlan *plan);
// Snapshot: one tagged value per declared field. Tag 0 denotes unavailable.
// Returns only staged scalar packet edits on success. On status 7, message
// contains the VM diagnostic without line decoration. All budgets are shared
// across the handlers of one event. A plan may run concurrently on distinct
// frames. The caller must keep it alive until all active evaluations finish.
RCRichResult rc_rich_eval(const RCRichPlan *plan,const uint8_t *snapshot,uint32_t n,
    RCFrame *edits,uint32_t remaining_instructions,uint32_t remaining_bytes);
void rc_rich_message_free(uint8_t *message,uint32_t len);
#ifdef __cplusplus
}
#endif
#endif
