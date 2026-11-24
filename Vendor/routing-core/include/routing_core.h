// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
#ifndef SIMPLEVPN_ROUTING_CORE_H
#define SIMPLEVPN_ROUTING_CORE_H
#include <stdint.h>
#ifdef __cplusplus
extern "C" {
#endif

typedef struct RCPlan RCPlan;
enum { RC_MAX_FIELDS = 32, RC_MAX_INSTRUCTIONS = 8192 };
enum RCType { RC_INT = 1, RC_BOOL };
enum RCWrite { RC_READ_ONLY = 0, RC_DSCP, RC_MSS, RC_DNS_RD };
enum RCOp {
    RC_CONST_INT = 1, RC_CONST_BOOL, RC_READ, RC_WRITE, RC_LOAD, RC_STORE,
    RC_EQ, RC_NE, RC_LT, RC_LE, RC_GT, RC_GE,
    RC_ADD, RC_SUB, RC_MUL, RC_DIV, RC_MOD, RC_NEG, RC_NOT,
    RC_JUMP, RC_BRANCH_FALSE, RC_AND_THEN, RC_OR_ELSE, RC_DROP, RC_COUNT, RC_DISCARD
};
enum RCStatus {
    RC_OK = 0, RC_DROPPED, RC_MISSING_FIELD, RC_INVALID_WRITE,
    RC_ARITHMETIC_BOUNDS, RC_BUDGET, RC_INVALID_ABI
};
typedef struct { uint32_t op, arg; int64_t imm; } RCInstruction;
typedef struct { uint32_t type, write; } RCField;
typedef struct { int64_t values[RC_MAX_FIELDS]; uint32_t present, written; } RCFrame;
typedef struct { uint32_t status, pc, instructions; } RCResult;

// Copies one handler and its field descriptors. Arrays may be NULL only at
// length zero. Returns NULL for unsupported or malformed plans. An immutable
// plan can be evaluated concurrently using separate initialized frames.
RCPlan *rc_plan_new(const RCInstruction *code, uint32_t n,
                    const RCField *fields, uint32_t field_count);
// Caller owns the plan and must finish all concurrent evaluations before free.
void rc_plan_free(RCPlan *plan);
// Supply the remaining shared Go VM instruction budget. The faulting or
// over-budget instruction counts as attempted. pc identifies its source.
// Field reads observe earlier edits; commit staged frame values only on RC_OK.
// A frame belongs to this evaluation exclusively and contains no pointers.
RCResult rc_eval(const RCPlan *plan, RCFrame *frame, uint32_t remaining_instructions);
#ifdef __cplusplus
}
#endif
#endif
