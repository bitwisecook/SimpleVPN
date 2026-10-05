// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//go:build !darwin

package main

import (
	"errors"
	"github.com/tailscale/wireguard-go/conn"
)

// Production capture is macOS-only. Portable core tests inject their own bind.
type physicalBind struct{ conn.Bind }

func newPhysicalBind(uint32) *physicalBind { return &physicalBind{conn.NewDefaultBind()} }
func (b *physicalBind) SetInterface(uint32) error {
	return errors.New("physical scoping requires macOS")
}
