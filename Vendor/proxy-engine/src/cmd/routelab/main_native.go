//go:build !js

// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
package main

import (
	"fmt"
	"io"
	"os"
)

func main() {
	raw, e := io.ReadAll(io.LimitReader(os.Stdin, 768<<10+1))
	if e != nil {
		fmt.Fprintln(os.Stderr, e)
		os.Exit(1)
	}
	fmt.Print(encodedEvaluate(string(raw)))
}
