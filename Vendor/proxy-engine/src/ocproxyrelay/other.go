// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
//go:build !darwin || !cgo

package ocproxyrelay

import "errors"

func Run(args []string) error { return errors.New("managed OpenConnect proxy requires macOS") }
