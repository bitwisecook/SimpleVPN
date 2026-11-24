// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only

//go:build !routing_rust

package routelang

import "errors"

const nativePacketsRequired = false

func compilePacketPlans(_ *Program) (map[string]packetNativeEvent, int, error) { return nil, 0, nil }

func (*Program) ExportReadOnlyEvents([]string) ([]NativeHandlerImage, error) {
	return nil, errors.New("native routing compiler required")
}

func LLVM(_ []byte) ([]byte, error) {
	return nil, errors.New("use the native routing compiler to emit LLVM IR")
}
