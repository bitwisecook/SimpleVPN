// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only

package catalog

import (
	_ "embed"
	"encoding/json"
	"slices"
	"sync"
)

// Adapter describes a specific operating mode. VPNKinds uses the raw saved
// profile IDs; an extension independent of profiles has an empty list.
type Adapter struct {
	ID           string   `json:"id"`
	Name         string   `json:"name"`
	VPNKinds     []string `json:"vpnKinds"`
	ProfileModes []string `json:"profileModes,omitempty"`
	Profiles     []string `json:"profiles"`
	Boundary     string   `json:"boundary"`
	Availability string   `json:"availability"`
	RichPolicy   bool     `json:"richPolicy"`
	Description  string   `json:"description"`
}

//go:embed adapters.json
var adapterJSON []byte

// Only a capability query or the offline reference needs to parse the catalog.
// The live packet path does no work to maintain this inventory.
var readAdapters = sync.OnceValue(func() []Adapter {
	var rows []Adapter
	if err := json.Unmarshal(adapterJSON, &rows); err != nil {
		panic("invalid embedded routing adapter inventory: " + err.Error())
	}
	return rows
})

func (a Adapter) clone() Adapter {
	a.VPNKinds = slices.Clone(a.VPNKinds)
	a.ProfileModes = slices.Clone(a.ProfileModes)
	a.Profiles = slices.Clone(a.Profiles)
	return a
}

func Adapters() []Adapter {
	rows := readAdapters()
	clones := make([]Adapter, len(rows))
	for i, row := range rows {
		clones[i] = row.clone()
	}
	return clones
}

// AdapterByID looks up an exact operating mode. A VPN kind alone can have
// several substantially different capture and policy boundaries.
func AdapterByID(id string) (Adapter, bool) {
	for _, row := range readAdapters() {
		if row.ID == id {
			return row.clone(), true
		}
	}
	return Adapter{}, false
}

// PacketPolicy reports whether this mode exposes a bidirectional inner-IP attachment.
func (a Adapter) PacketPolicy() bool { return a.RichPolicy && len(SSHEvents(a.ID)) == 0 }

// SSHEvents enumerates the channel boundaries owned by this adapter.
func SSHEvents(adapter string) []string {
	switch adapter {
	case "ssh-libssh":
		return []string{"ssh.forward_open"}
	case "ssh-openssh-reverse":
		return []string{"ssh.reverse_delivery"}
	case "ssh-openssh":
		return []string{"ssh.forward_open", "ssh.reverse_delivery"}
	default:
		return nil
	}
}
