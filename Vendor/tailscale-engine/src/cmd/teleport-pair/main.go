// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
// One-shot pairing over private pipes. No credentials in argv, disk or logs.
package main

import (
	"context"
	"encoding/json"
	"io"
	"os"
	"time"
	"tsengine/teleport"
)

func main() {
	var request struct {
		Invite string `json:"invite"`
		Name   string `json:"name"`
	}
	if err := json.NewDecoder(io.LimitReader(os.Stdin, 16*1024)).Decode(&request); err != nil {
		os.Exit(1)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Second)
	defer cancel()
	session, err := teleport.Pair(ctx, request.Invite, request.Name)
	if err != nil {
		// API errors may carry new service fields. Keep helper failures generic.
		_ = json.NewEncoder(os.Stdout).Encode(map[string]string{"error": "Teleport could not pair. Check the invite is fresh and the console is online, then try again."})
		os.Exit(1)
	}
	_ = json.NewEncoder(os.Stdout).Encode(session)
}
