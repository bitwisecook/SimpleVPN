// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//
// main.go — cgo shim exporting the official 1Password Go SDK
// (github.com/1password/onepassword-sdk-go) to Swift as a C static archive
// (-buildmode=c-archive). Desktop-app authentication only: the SDK dlopens
// libop_sdk_ipc_client.dylib from the installed 1Password.app and the desktop
// app shows a Touch ID / authorization prompt naming this executable. No
// service-account tokens, no secrets at rest here.
//
// C contract (all strings are UTF-8, malloc'd by Go, freed via OPNativeFree):
//
//	OPNativeResolve(requestJSON) -> responseJSON
//	  request:  {"integrationName": "...", "integrationVersion": "...",
//	             "account": "<1Password account name or UUID, may be \"\">",
//	             "secretRefs": ["op://vault/item/field", ...],
//	             "timeoutSeconds": 180}          // optional, default 180
//	  response: {"values": {"op://…": "secret", ...}}
//	         or {"error": {"kind": "...", "message": "..."}}
//	  kinds: appNotInstalled | appNotRunning | integrationDisabled |
//	         userCancelled | sessionExpired | itemNotFound | accountNotFound |
//	         rateLimited | badRequest | other
//
//	  "account" is NOT optional in practice: the SDK's desktop-app integration
//	  answers an account it can't match — the empty string included — with
//	  "Account not found", surfaced as kind accountNotFound so the app can ask
//	  for the account name instead of blaming the item.
//
//	OPNativeGetItem(requestJSON) -> responseJSON
//	  request:  {"integrationName": "...", "integrationVersion": "...",
//	             "account": "...", "vault": "<title or UUID, may be \"\">",
//	             "itemRef": "<item title, UUID, or op://… / onepassword://… link>",
//	             "timeoutSeconds": 180}
//	  response: {"item": {"title": ..., "vaultID": ..., "itemID": ...,
//	             "fields": [{"id","label","purpose","type","value","otp"}, ...]}}
//	         or {"error": {"kind": "...", "message": "..."}}
//	  kinds: as OPNativeResolve, plus "ambiguous" when the title matches more
//	  than one item (candidate titles ride in the message). Field "purpose" is
//	  USERNAME/PASSWORD/"" (reconstructed from the built-in login field IDs —
//	  the SDK has no purpose attribute), "type" uses the CLI's names
//	  (STRING/CONCEALED/OTP/…) and "otp" carries the computed TOTP code.
//
//	OPNativeList(requestJSON) -> responseJSON
//	  request:  {"integrationName": "...", "integrationVersion": "...",
//	             "account": "...",
//	             "vault": "<empty = list vaults; id or title = list its items>",
//	             "timeoutSeconds": 180}
//	  response: {"vaults": [{"id","title"}, ...]}      (vault empty)
//	         or {"items":  [{"id","title","category"}, ...]}
//	         or {"error": {"kind": "...", "message": "..."}}
//	  kinds: as OPNativeResolve.
//
//	  OVERVIEWS ONLY — a list response never carries a field, a value or an
//	  OTP code. The SDK's ItemsList is per-vault (List(ctx, vaultID, …)), so
//	  listing items without naming a vault is a badRequest rather than a
//	  sweep of every vault the account can see.
//
//	OPNativeProbe() -> {"available": bool, "reason": "..."}
//	  Prompt-free: only checks that the 1Password app's SDK IPC dylib exists
//	  on disk (same paths the SDK itself probes). It does NOT confirm the app
//	  is running/unlocked or that "Integrate with other apps" is enabled.
//
//	OPNativeFree(p) — free any string returned by the calls above.
//
// Client lifetime: one SDK client is cached per (account, integration) tuple.
// Desktop-app sessions last ~10 minutes; on DesktopSessionExpiredError the
// shim drops the cached client, builds a fresh one (which re-prompts) and
// retries the resolve exactly once. A mutex serialises everything — credential
// fetches are rare and the desktop app shows one prompt at a time anyway.
//
// Go runtime note: as a c-archive the runtime starts lazily on first call, does
// not take over the host signal handling the way a Go executable does (it
// installs SA_ONSTACK handlers for its own panics but preserves/chains the
// existing ones), and never calls exit(). Safe to embed in a GUI app.
package main

/*
#include <stdlib.h>
*/
import "C"

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"sync"
	"time"
	"unsafe"

	onepassword "github.com/1password/onepassword-sdk-go"
)

// ---- Wire types ------------------------------------------------------------

type resolveRequest struct {
	IntegrationName    string   `json:"integrationName"`
	IntegrationVersion string   `json:"integrationVersion"`
	Account            string   `json:"account"`
	SecretRefs         []string `json:"secretRefs"`
	TimeoutSeconds     int      `json:"timeoutSeconds"`
}

type shimError struct {
	Kind    string `json:"kind"`
	Message string `json:"message"`
}

type resolveResponse struct {
	Values map[string]string `json:"values,omitempty"`
	Error  *shimError        `json:"error,omitempty"`
}

type itemRequest struct {
	IntegrationName    string `json:"integrationName"`
	IntegrationVersion string `json:"integrationVersion"`
	Account            string `json:"account"`
	Vault              string `json:"vault"`
	ItemRef            string `json:"itemRef"`
	TimeoutSeconds     int    `json:"timeoutSeconds"`
}

// itemField mirrors the `op item get --format json` field vocabulary the Swift
// side already speaks (purpose USERNAME/PASSWORD, type OTP/CONCEALED/STRING) so
// the field-mapping sheet needed no re-teaching when the CLI went away.
type itemField struct {
	ID      string `json:"id"`
	Label   string `json:"label"`
	Purpose string `json:"purpose"`
	Type    string `json:"type"`
	Value   string `json:"value"`
	OTP     string `json:"otp,omitempty"`
}

type itemPayload struct {
	Title   string      `json:"title"`
	VaultID string      `json:"vaultID"`
	ItemID  string      `json:"itemID"`
	Fields  []itemField `json:"fields"`
}

type itemResponse struct {
	Item  *itemPayload `json:"item,omitempty"`
	Error *shimError   `json:"error,omitempty"`
}

type listRequest struct {
	IntegrationName    string `json:"integrationName"`
	IntegrationVersion string `json:"integrationVersion"`
	Account            string `json:"account"`
	Vault              string `json:"vault"`
	TimeoutSeconds     int    `json:"timeoutSeconds"`
}

type vaultOverview struct {
	ID    string `json:"id"`
	Title string `json:"title"`
}

// itemOverview is deliberately the SDK's ItemOverview minus everything that
// could describe the item's contents: a picker needs a name and an id, and a
// list response that carried values would be a secret leak with a nice label.
type itemOverview struct {
	ID       string `json:"id"`
	Title    string `json:"title"`
	Category string `json:"category"`
}

// Pointer slices so an EMPTY list still says which kind of list it is —
// `{"vaults":[]}` (account has no vaults) must not decode the same as an item
// list, and `omitempty` on a plain slice would flatten both to `{}`.
type listResponse struct {
	Vaults *[]vaultOverview `json:"vaults,omitempty"`
	Items  *[]itemOverview  `json:"items,omitempty"`
	Error  *shimError       `json:"error,omitempty"`
}

// Error kinds — keep in sync with OnePasswordNativeError in
// SimpleVPN/Core/OnePasswordNative.swift.
const (
	kindAppNotInstalled     = "appNotInstalled"
	kindAppNotRunning       = "appNotRunning"
	kindIntegrationDisabled = "integrationDisabled"
	kindUserCancelled       = "userCancelled"
	kindSessionExpired      = "sessionExpired"
	kindItemNotFound        = "itemNotFound"
	kindAccountNotFound     = "accountNotFound"
	kindRateLimited         = "rateLimited"
	kindBadRequest          = "badRequest"
	kindAmbiguous           = "ambiguous"
	kindOther               = "other"
)

// ---- Client cache ----------------------------------------------------------

var (
	mu        sync.Mutex // serialises client creation AND resolves
	client    *onepassword.Client
	clientKey string // account + "\x00" + name + "\x00" + version
)

func cachedClient(ctx context.Context, account, name, version string) (*onepassword.Client, error) {
	key := account + "\x00" + name + "\x00" + version
	if client != nil && clientKey == key {
		return client, nil
	}
	c, err := onepassword.NewClient(ctx,
		onepassword.WithDesktopAppIntegration(account),
		onepassword.WithIntegrationInfo(name, version),
	)
	if err != nil {
		return nil, err
	}
	client, clientKey = c, key
	return c, nil
}

func dropClient() { client, clientKey = nil, "" }

// ---- Error classification --------------------------------------------------

// classify maps SDK errors onto the shim's error kinds. The SDK only types two
// errors (DesktopSessionExpiredError, RateLimitExceededError); everything else
// arrives as a plain message from the desktop app's IPC dylib, so the rest is
// substring heuristics — kept deliberately loose and ordered most- to
// least-specific.
func classify(err error) shimError {
	var dse *onepassword.DesktopSessionExpiredError
	if errors.As(err, &dse) {
		return shimError{Kind: kindSessionExpired, Message: err.Error()}
	}
	var rle *onepassword.RateLimitExceededError
	if errors.As(err, &rle) {
		return shimError{Kind: kindRateLimited, Message: err.Error()}
	}
	msg := err.Error()
	s := strings.ToLower(msg)
	switch {
	case strings.Contains(s, "desktop application not found"),
		strings.Contains(s, "app is not installed"):
		return shimError{Kind: kindAppNotInstalled, Message: msg}
	case strings.Contains(s, "not running"),
		strings.Contains(s, "connection refused"),
		strings.Contains(s, "cannot connect"),
		strings.Contains(s, "failed to connect"),
		strings.Contains(s, "locked"):
		return shimError{Kind: kindAppNotRunning, Message: msg}
	case strings.Contains(s, "integration") &&
		(strings.Contains(s, "disabled") || strings.Contains(s, "not enabled") ||
			strings.Contains(s, "not allowed") || strings.Contains(s, "turned off")):
		return shimError{Kind: kindIntegrationDisabled, Message: msg}
	case strings.Contains(s, "cancel"), // "canceled"/"cancelled"
		strings.Contains(s, "denied"),
		strings.Contains(s, "rejected"),
		strings.Contains(s, "not authorized"),
		strings.Contains(s, "authorization"):
		return shimError{Kind: kindUserCancelled, Message: msg}
	case strings.Contains(s, "session") && strings.Contains(s, "expired"):
		return shimError{Kind: kindSessionExpired, Message: msg}
	// Before the generic "not found": WithDesktopAppIntegration refuses an
	// account it can't match — including the empty string — with "Account not
	// found", which reads as a missing ITEM but is answered by naming the
	// account (1Password's top-left sidebar name), not by re-picking the item.
	case strings.Contains(s, "account not found"),
		strings.Contains(s, "no account") && strings.Contains(s, "found"):
		return shimError{Kind: kindAccountNotFound, Message: msg}
	case strings.Contains(s, "not found"):
		return shimError{Kind: kindItemNotFound, Message: msg}
	default:
		return shimError{Kind: kindOther, Message: msg}
	}
}

// classifyRefError maps a per-reference ResolveAll failure.
func classifyRefError(ref string, e onepassword.ResolveReferenceError) shimError {
	switch e.Type {
	case onepassword.ResolveReferenceErrorTypeVariantItemNotFound,
		onepassword.ResolveReferenceErrorTypeVariantVaultNotFound,
		onepassword.ResolveReferenceErrorTypeVariantFieldNotFound,
		onepassword.ResolveReferenceErrorTypeVariantNoMatchingSections:
		return shimError{Kind: kindItemNotFound,
			Message: fmt.Sprintf("%s: %s", ref, e.Type)}
	case onepassword.ResolveReferenceErrorTypeVariantParsing:
		return shimError{Kind: kindBadRequest,
			Message: fmt.Sprintf("%s: %s", ref, e.Parsing())}
	case onepassword.ResolveReferenceErrorTypeVariantUnableToGenerateTOTPCode:
		return shimError{Kind: kindOther,
			Message: fmt.Sprintf("%s: %s", ref, e.UnableToGenerateTOTPCode())}
	default:
		return shimError{Kind: kindOther,
			Message: fmt.Sprintf("%s: %s", ref, e.Type)}
	}
}

// ---- Core ------------------------------------------------------------------

func handleResolve(reqJSON string) resolveResponse {
	var req resolveRequest
	if err := json.Unmarshal([]byte(reqJSON), &req); err != nil {
		return resolveResponse{Error: &shimError{Kind: kindBadRequest,
			Message: "bad request JSON: " + err.Error()}}
	}
	if len(req.SecretRefs) == 0 {
		return resolveResponse{Error: &shimError{Kind: kindBadRequest,
			Message: "secretRefs is empty"}}
	}
	if req.IntegrationName == "" {
		req.IntegrationName = "SimpleVPN"
	}
	if req.IntegrationVersion == "" {
		req.IntegrationVersion = "dev"
	}
	timeout := 180 * time.Second
	if req.TimeoutSeconds > 0 {
		timeout = time.Duration(req.TimeoutSeconds) * time.Second
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	mu.Lock()
	defer mu.Unlock()

	values, shimErr := resolveOnce(ctx, req)
	// A cached client outliving the desktop app's ~10-minute session surfaces
	// as DesktopSessionExpired — rebuild the client (which re-prompts) and
	// retry exactly once.
	if shimErr != nil && shimErr.Kind == kindSessionExpired {
		dropClient()
		values, shimErr = resolveOnce(ctx, req)
	}
	if shimErr != nil {
		return resolveResponse{Error: shimErr}
	}
	return resolveResponse{Values: values}
}

func resolveOnce(ctx context.Context, req resolveRequest) (map[string]string, *shimError) {
	c, err := cachedClient(ctx, req.Account, req.IntegrationName, req.IntegrationVersion)
	if err != nil {
		e := classify(err)
		return nil, &e
	}
	resp, err := c.Secrets().ResolveAll(ctx, req.SecretRefs)
	if err != nil {
		e := classify(err)
		if e.Kind != kindSessionExpired {
			// Whole-call failures (app quit, integration toggled off, …) can
			// leave the cached client wedged; a fresh one costs little.
			dropClient()
		}
		return nil, &e
	}
	values := make(map[string]string, len(req.SecretRefs))
	for _, ref := range req.SecretRefs {
		r, ok := resp.IndividualResponses[ref]
		if !ok {
			return nil, &shimError{Kind: kindOther,
				Message: "no response for reference " + ref}
		}
		if r.Error != nil {
			e := classifyRefError(ref, *r.Error)
			return nil, &e
		}
		if r.Content == nil {
			return nil, &shimError{Kind: kindOther,
				Message: "empty response for reference " + ref}
		}
		values[ref] = r.Content.Secret
	}
	return values, nil
}

// ---- Full-item read ---------------------------------------------------------

func handleGetItem(reqJSON string) itemResponse {
	var req itemRequest
	if err := json.Unmarshal([]byte(reqJSON), &req); err != nil {
		return itemResponse{Error: &shimError{Kind: kindBadRequest,
			Message: "bad request JSON: " + err.Error()}}
	}
	if strings.TrimSpace(req.ItemRef) == "" {
		return itemResponse{Error: &shimError{Kind: kindBadRequest,
			Message: "itemRef is empty"}}
	}
	// A link-style reference carries its own coordinates: op://vault/item[/…]
	// ("Copy Secret Reference") or onepassword://…?i=item&v=vault (deep link).
	// Peel either to (vault, item) — the same shapes the app's
	// parseOnePasswordDrop accepts — so a pasted link resolves too.
	if item, vault, ok := parseItemLink(strings.TrimSpace(req.ItemRef)); ok {
		req.ItemRef = item
		if vault != "" {
			req.Vault = vault
		}
	}
	if req.IntegrationName == "" {
		req.IntegrationName = "SimpleVPN"
	}
	if req.IntegrationVersion == "" {
		req.IntegrationVersion = "dev"
	}
	timeout := 180 * time.Second
	if req.TimeoutSeconds > 0 {
		timeout = time.Duration(req.TimeoutSeconds) * time.Second
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	mu.Lock()
	defer mu.Unlock()

	item, shimErr := getItemOnce(ctx, req)
	// Same session-expiry policy as resolve: rebuild the client (re-prompts)
	// and retry exactly once.
	if shimErr != nil && shimErr.Kind == kindSessionExpired {
		dropClient()
		item, shimErr = getItemOnce(ctx, req)
	}
	if shimErr != nil {
		return itemResponse{Error: shimErr}
	}
	return itemResponse{Item: item}
}

// parseItemLink extracts (item, vault) from the two link shapes 1Password
// hands out — `op://vault/item[/section/field]` secret references and
// `onepassword://…?i=item&v=vault` deep links. ok is false for anything that
// isn't a link (bare titles/UUIDs pass through untouched).
func parseItemLink(s string) (item, vault string, ok bool) {
	if rest, found := strings.CutPrefix(s, "op://"); found {
		parts := strings.Split(rest, "/")
		for i, p := range parts {
			if u, err := url.PathUnescape(p); err == nil {
				parts[i] = u
			}
		}
		if len(parts) >= 2 && parts[0] != "" && parts[1] != "" {
			return parts[1], parts[0], true
		}
		if len(parts) == 1 && parts[0] != "" {
			return parts[0], "", true
		}
		return "", "", false
	}
	if strings.HasPrefix(s, "onepassword://") {
		u, err := url.Parse(s)
		if err != nil {
			return "", "", false
		}
		q := u.Query()
		item := q.Get("i")
		if item == "" {
			item = q.Get("item")
		}
		vault := q.Get("v")
		if vault == "" {
			vault = q.Get("vault")
		}
		if item != "" {
			return item, vault, true
		}
	}
	return "", "", false
}

// matchVaults narrows a vault list to the one the user named — by UUID, then
// exact title, then case-folded title. An empty `want` means "all of them"
// (the item search sweeps every vault). Shared by the item read and the item
// list so a vault name that works in one works in the other.
func matchVaults(vaults []onepassword.VaultOverview, want string) ([]onepassword.VaultOverview, *shimError) {
	if want == "" {
		return vaults, nil
	}
	var byID, byTitle, byFold []onepassword.VaultOverview
	for _, v := range vaults {
		switch {
		case v.ID == want:
			byID = append(byID, v)
		case v.Title == want:
			byTitle = append(byTitle, v)
		case strings.EqualFold(v.Title, want):
			byFold = append(byFold, v)
		}
	}
	switch {
	case len(byID) > 0:
		return byID, nil
	case len(byTitle) > 0:
		return byTitle, nil
	case len(byFold) > 0:
		return byFold, nil
	default:
		return nil, &shimError{Kind: kindItemNotFound,
			Message: fmt.Sprintf("no vault named %q", want)}
	}
}

func getItemOnce(ctx context.Context, req itemRequest) (*itemPayload, *shimError) {
	c, err := cachedClient(ctx, req.Account, req.IntegrationName, req.IntegrationVersion)
	if err != nil {
		e := classify(err)
		return nil, &e
	}
	fail := func(err error) *shimError {
		e := classify(err)
		if e.Kind != kindSessionExpired {
			// Same wedged-client hygiene as resolveOnce.
			dropClient()
		}
		return &e
	}

	vaults, err := c.Vaults().List(ctx)
	if err != nil {
		return nil, fail(err)
	}
	// Vault may name a vault by UUID or title, or be empty (search everywhere).
	wantVault := strings.TrimSpace(req.Vault)
	candidates, shimErr := matchVaults(vaults, wantVault)
	if shimErr != nil {
		return nil, shimErr
	}

	// The item reference may be a UUID or a title; a UUID hit is unique by
	// construction, an exact title beats a case-folded one, and a title that
	// still matches several items is a genuine ambiguity the user must break
	// (with a vault or the UUID) — silently picking one would connect a VPN
	// with the wrong credentials.
	ref := strings.TrimSpace(req.ItemRef)
	type match struct {
		vaultID, vaultTitle, itemID, title string
	}
	var byID, byTitle, byFold []match
	for _, v := range candidates {
		items, err := c.Items().List(ctx, v.ID)
		if err != nil {
			// When sweeping all vaults, one unlistable vault mustn't sink the
			// search; a vault the user named explicitly must report its error.
			if wantVault != "" {
				return nil, fail(err)
			}
			continue
		}
		for _, o := range items {
			m := match{vaultID: v.ID, vaultTitle: v.Title, itemID: o.ID, title: o.Title}
			switch {
			case o.ID == ref:
				byID = append(byID, m)
			case o.Title == ref:
				byTitle = append(byTitle, m)
			case strings.EqualFold(o.Title, ref):
				byFold = append(byFold, m)
			}
		}
	}
	var matches []match
	switch {
	case len(byID) > 0:
		matches = byID[:1]
	case len(byTitle) > 0:
		matches = byTitle
	default:
		matches = byFold
	}
	if len(matches) == 0 {
		return nil, &shimError{Kind: kindItemNotFound,
			Message: fmt.Sprintf("no item matching %q", ref)}
	}
	if len(matches) > 1 {
		names := make([]string, 0, len(matches))
		for _, m := range matches {
			names = append(names, fmt.Sprintf("%q in vault %q", m.title, m.vaultTitle))
		}
		return nil, &shimError{Kind: kindAmbiguous,
			Message: fmt.Sprintf("%d items match %q: %s", len(matches), ref,
				strings.Join(names, ", "))}
	}

	chosen := matches[0]
	full, err := c.Items().Get(ctx, chosen.vaultID, chosen.itemID)
	if err != nil {
		return nil, fail(err)
	}

	payload := &itemPayload{
		Title:   full.Title,
		VaultID: full.VaultID,
		ItemID:  full.ID,
		Fields:  make([]itemField, 0, len(full.Fields)),
	}
	for _, f := range full.Fields {
		out := itemField{ID: f.ID, Label: f.Title, Value: f.Value}
		// The SDK dropped the CLI's field "purpose"; the built-in Login
		// username/password fields keep their well-known IDs (and live outside
		// any section), which is the same signal the purposes encoded.
		if f.SectionID == nil {
			switch f.ID {
			case "username":
				out.Purpose = "USERNAME"
			case "password":
				out.Purpose = "PASSWORD"
			}
		}
		switch f.FieldType {
		case onepassword.ItemFieldTypeTOTP:
			out.Type = "OTP"
			// Only the computed current code ever leaves the shim — the raw
			// Value is the otpauth:// seed, and handing that out as a
			// username/password/otp would exfiltrate the TOTP secret.
			out.Value = ""
			if f.Details != nil {
				if otp := f.Details.OTP(); otp != nil && otp.Code != nil {
					out.OTP = *otp.Code
				}
			}
		case onepassword.ItemFieldTypeConcealed:
			out.Type = "CONCEALED"
		case onepassword.ItemFieldTypeText:
			out.Type = "STRING"
		default:
			out.Type = strings.ToUpper(string(f.FieldType))
		}
		payload.Fields = append(payload.Fields, out)
	}
	return payload, nil
}

// ---- Vault / item listing ---------------------------------------------------

func handleList(reqJSON string) listResponse {
	var req listRequest
	if err := json.Unmarshal([]byte(reqJSON), &req); err != nil {
		return listResponse{Error: &shimError{Kind: kindBadRequest,
			Message: "bad request JSON: " + err.Error()}}
	}
	if req.IntegrationName == "" {
		req.IntegrationName = "SimpleVPN"
	}
	if req.IntegrationVersion == "" {
		req.IntegrationVersion = "dev"
	}
	timeout := 180 * time.Second
	if req.TimeoutSeconds > 0 {
		timeout = time.Duration(req.TimeoutSeconds) * time.Second
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	mu.Lock()
	defer mu.Unlock()

	resp, shimErr := listOnce(ctx, req)
	// Same session-expiry policy as resolve/getItem: rebuild the client (which
	// re-prompts) and retry exactly once.
	if shimErr != nil && shimErr.Kind == kindSessionExpired {
		dropClient()
		resp, shimErr = listOnce(ctx, req)
	}
	if shimErr != nil {
		return listResponse{Error: shimErr}
	}
	return resp
}

func listOnce(ctx context.Context, req listRequest) (listResponse, *shimError) {
	c, err := cachedClient(ctx, req.Account, req.IntegrationName, req.IntegrationVersion)
	if err != nil {
		e := classify(err)
		return listResponse{}, &e
	}
	fail := func(err error) *shimError {
		e := classify(err)
		if e.Kind != kindSessionExpired {
			// Same wedged-client hygiene as resolveOnce.
			dropClient()
		}
		return &e
	}

	vaults, err := c.Vaults().List(ctx)
	if err != nil {
		return listResponse{}, fail(err)
	}

	wantVault := strings.TrimSpace(req.Vault)
	if wantVault == "" {
		out := make([]vaultOverview, 0, len(vaults))
		for _, v := range vaults {
			out = append(out, vaultOverview{ID: v.ID, Title: v.Title})
		}
		sort.Slice(out, func(i, j int) bool {
			return strings.ToLower(out[i].Title) < strings.ToLower(out[j].Title)
		})
		return listResponse{Vaults: &out}, nil
	}

	candidates, shimErr := matchVaults(vaults, wantVault)
	if shimErr != nil {
		return listResponse{}, shimErr
	}
	out := make([]itemOverview, 0, 64)
	seen := make(map[string]bool)
	for _, v := range candidates {
		// The SDK lists items per vault, so a title that matches several vaults
		// contributes all of them — the picker would otherwise silently show
		// one drawer's contents under another drawer's name.
		items, err := c.Items().List(ctx, v.ID)
		if err != nil {
			return listResponse{}, fail(err)
		}
		for _, o := range items {
			// Archived/deleted items can't sign anyone in; offering them in a
			// picker only invites a connect that fails later.
			if o.State != "" && o.State != onepassword.ItemStateActive {
				continue
			}
			if seen[o.ID] {
				continue
			}
			seen[o.ID] = true
			out = append(out, itemOverview{ID: o.ID, Title: o.Title,
				Category: string(o.Category)})
		}
	}
	sort.Slice(out, func(i, j int) bool {
		return strings.ToLower(out[i].Title) < strings.ToLower(out[j].Title)
	})
	return listResponse{Items: &out}, nil
}

// probe reports whether the 1Password app's SDK IPC dylib is installed — the
// same locations internal/shared_lib_core.go checks. File-existence only, so
// it can never raise a prompt.
func probe() (bool, string) {
	home, _ := os.UserHomeDir()
	paths := []string{
		"/Applications/1Password.app/Contents/Frameworks/libop_sdk_ipc_client.dylib",
	}
	if home != "" {
		paths = append(paths,
			filepath.Join(home, "Applications/1Password.app/Contents/Frameworks/libop_sdk_ipc_client.dylib"))
	}
	for _, p := range paths {
		if _, err := os.Stat(p); err == nil {
			return true, p
		}
	}
	return false, "1Password app (8+) with SDK support not found in /Applications or ~/Applications"
}

// ---- C exports -------------------------------------------------------------

func jsonCString(v any) *C.char {
	b, err := json.Marshal(v)
	if err != nil {
		// Marshal of our own structs can't realistically fail; belt-and-braces.
		return C.CString(`{"error":{"kind":"other","message":"internal marshal failure"}}`)
	}
	return C.CString(string(b))
}

//export OPNativeResolve
func OPNativeResolve(requestJSON *C.char) *C.char {
	if requestJSON == nil {
		return jsonCString(resolveResponse{Error: &shimError{
			Kind: kindBadRequest, Message: "nil request"}})
	}
	return jsonCString(handleResolve(C.GoString(requestJSON)))
}

//export OPNativeGetItem
func OPNativeGetItem(requestJSON *C.char) *C.char {
	if requestJSON == nil {
		return jsonCString(itemResponse{Error: &shimError{
			Kind: kindBadRequest, Message: "nil request"}})
	}
	return jsonCString(handleGetItem(C.GoString(requestJSON)))
}

//export OPNativeList
func OPNativeList(requestJSON *C.char) *C.char {
	if requestJSON == nil {
		return jsonCString(listResponse{Error: &shimError{
			Kind: kindBadRequest, Message: "nil request"}})
	}
	return jsonCString(handleList(C.GoString(requestJSON)))
}

//export OPNativeProbe
func OPNativeProbe() *C.char {
	ok, reason := probe()
	return jsonCString(struct {
		Available bool   `json:"available"`
		Reason    string `json:"reason,omitempty"`
	}{ok, reason})
}

//export OPNativeFree
func OPNativeFree(p *C.char) {
	C.free(unsafe.Pointer(p))
}

func main() {} // required for c-archive; never runs
