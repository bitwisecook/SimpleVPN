//go:build js && wasm

// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
package main

import (
	"encoding/json"
	"pxengine/routelang"
	"pxengine/routelang/catalog"
	"syscall/js"
)

func main() {
	schema := catalog.Schema()
	packet := catalog.Packet()
	liveSchemas := map[string]routelang.Schema{}
	adapters := catalog.Adapters()
	for _, a := range adapters {
		if s, ok := catalog.LiveForAdapter(a.ID); ok {
			liveSchemas[a.ID] = s
		}
	}
	output := map[string]map[string]any{}
	for name, event := range schema {
		fields := map[string]any{}
		live, supportsPacket := packet[name]
		for key, f := range event.Fields {
			_, onPacket := live.Fields[key]
			var owners []string
			for _, a := range adapters {
				if _, present := liveSchemas[a.ID][name].Fields[key]; present {
					owners = append(owners, a.ID)
				}
			}
			fields[key] = map[string]any{"type": f.Type, "writable": f.Writable, "onPacket": onPacket, "liveAdapters": owners}
		}
		output[name] = map[string]any{"fields": fields, "actions": event.Actions, "packet": supportsPacket}
	}
	meta, _ := json.Marshal(catalog.Inventory())
	var rows []map[string]any
	_ = json.Unmarshal(meta, &rows)
	for _, row := range rows {
		key, _ := row["event"].(string)
		if dest := output[key]; dest != nil {
			for _, field := range []string{"boundary", "live", "protocol", "description"} {
				dest[field] = row[field]
			}
		}
	}
	catalogJSON, _ := json.Marshal(output)
	functionsJSON, _ := json.Marshal(routelang.BuiltinNames())
	adaptersJSON, _ := json.Marshal(catalog.Adapters())
	js.Global().Set("simpleVPNRulesCatalog", string(catalogJSON))
	js.Global().Set("simpleVPNRulesFunctions", string(functionsJSON))
	js.Global().Set("simpleVPNRoutingAdapters", string(adaptersJSON))
	js.Global().Set("simpleVPNRulesRun", js.FuncOf(func(this js.Value, args []js.Value) any {
		if len(args) != 1 || args[0].Type() != js.TypeString {
			return `{"ok":false,"error":"missing program"}`
		}
		return encodedEvaluate(args[0].String())
	}))
	js.Global().Call("simpleVPNRulesBooted")
	select {}
}
