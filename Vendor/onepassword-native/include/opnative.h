// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
//  opnative.h
//  Stable C interface to libopnative.a — the 1Password Go SDK
//  (github.com/1Password/onepassword-sdk-go) compiled as a c-archive with a
//  small JSON-contract shim (Vendor/onepassword-native/src/main.go). This
//  header is hand-written so Swift never sees the cgo-generated header's Go
//  typedef cruft; Tools/build-onepassword-sdk.sh verifies the exported symbols
//  match. All returned strings are malloc'd UTF-8 JSON — release them with
//  OPNativeFree. Full request/response contract documented in main.go.

#ifndef OPNATIVE_H
#define OPNATIVE_H

#ifdef __cplusplus
extern "C" {
#endif

/// Resolve op:// secret references via the 1Password desktop app (local IPC +
/// user authorization prompt). Blocking — call off the main thread.
/// request:  {"integrationName","integrationVersion","account","secretRefs":[…],"timeoutSeconds"}
/// response: {"values":{ref:secret,…}} or {"error":{"kind","message"}}
char *OPNativeResolve(const char *requestJSON);

/// Fetch one item's full field list by title or UUID (vault optional — empty
/// searches every vault). Blocking — call off the main thread.
/// request:  {"integrationName","integrationVersion","account","vault","itemRef","timeoutSeconds"}
/// response: {"item":{"title","vaultID","itemID","fields":[{"id","label","purpose","type","value","otp"},…]}}
///           or {"error":{"kind","message"}} (kind "ambiguous" ⇒ several items
///           share that title; candidates are listed in the message)
char *OPNativeGetItem(const char *requestJSON);

/// List vault or item OVERVIEWS for the pickers — never field values. An empty
/// "vault" lists the account's vaults; a vault id/title lists that vault's
/// items (the SDK's item list is per-vault). Blocking — call off the main
/// thread; the first call may raise 1Password's authorization prompt.
/// request:  {"integrationName","integrationVersion","account","vault","timeoutSeconds"}
/// response: {"vaults":[{"id","title"},…]} or {"items":[{"id","title","category"},…]}
///           or {"error":{"kind","message"}}
char *OPNativeList(const char *requestJSON);

/// Item LOOKUP: which items look like `query`, with the vault each lives in —
/// the coordinates an op:// secret reference needs and an item title alone
/// can't supply. The SDK has no search of its own (its item list is per-vault
/// and unfiltered), so this fans out over the account's vaults and ranks
/// titles with the app's own ladder (0 exact · 1 prefix · 2 substring ·
/// 3 letters in order). An empty query lists everything. OVERVIEWS ONLY — a
/// match never carries a field, a value or an OTP code. Blocking — call off
/// the main thread.
/// request:  {"integrationName","integrationVersion","account","vault","query","limit","timeoutSeconds"}
/// response: {"matches":[{"itemID","title","category","vaultID","vaultTitle","score"},…]}
///           or {"error":{"kind","message"}}
char *OPNativeLookup(const char *requestJSON);

/// Prompt-free check that a 1Password app with SDK support is installed.
/// Returns {"available":bool,"reason":"…"}.
char *OPNativeProbe(void);

/// Free any string returned by OPNativeResolve/OPNativeGetItem/OPNativeList/
/// OPNativeLookup/OPNativeProbe.
void OPNativeFree(char *p);

#ifdef __cplusplus
}
#endif

#endif /* OPNATIVE_H */
