// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"os"
	"sync"
	"time"

	"tailscale.com/ipn"
)

const maxNodeState = 1024 * 1024

// The root extension owns only transient state. Once bootstrap finishes, a
// write does not succeed until the app acknowledges saving that revision in
// the user's Keychain. It never creates or rewrites a plaintext identity file.
type keychainState struct {
	mu                     sync.Mutex
	writes                 sync.Mutex
	data                   map[ipn.StateKey][]byte
	revision, acknowledged uint64
	changed                chan struct{}
	closed                 bool
	armed                  bool
	legacyFile             string
	fail                   func()
	timeout                time.Duration
}
type nodeStateSnapshot struct {
	Revision uint64 `json:"revision"`
	Data     string `json:"data"`
}

func newKeychainState(seed, legacyFile string, fail func()) (*keychainState, error) {
	s := &keychainState{data: make(map[ipn.StateKey][]byte), changed: make(chan struct{}), legacyFile: legacyFile,
		fail: fail, timeout: 10 * time.Second}
	if len(seed) > maxNodeState {
		return nil, errors.New("node state exceeds storage limit")
	}
	if seed == "" {
		file, err := os.Open(legacyFile)
		var legacy []byte
		if err == nil {
			legacy, err = io.ReadAll(io.LimitReader(file, maxNodeState+1))
			_ = file.Close()
		}
		if err != nil && !os.IsNotExist(err) {
			return nil, errors.New("cannot read previous node identity")
		}
		if len(legacy) > maxNodeState {
			return nil, errors.New("previous node state exceeds storage limit")
		}
		seed = string(legacy)
		if len(legacy) != 0 {
			s.revision = 1
		}
	}
	if seed != "" {
		if err := json.Unmarshal([]byte(seed), &s.data); err != nil || s.data == nil {
			return nil, errors.New("invalid saved node identity")
		}
	}
	return s, nil
}

func (s *keychainState) ReadState(key ipn.StateKey) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nil, errors.New("node state store stopped")
	}
	value, ok := s.data[key]
	if !ok {
		return nil, ipn.ErrStateNotExist
	}
	return bytes.Clone(value), nil
}

func (s *keychainState) wait() error {
	timer := time.NewTimer(s.timeout)
	defer timer.Stop()
	for {
		s.mu.Lock()
		closed, synced, changed := s.closed, s.acknowledged == s.revision, s.changed
		s.mu.Unlock()
		if closed {
			return errors.New("node state store stopped")
		}
		if synced {
			return nil
		}
		select {
		case <-changed:
		case <-timer.C:
			if s.fail != nil {
				s.fail()
			}
			return errors.New("user Keychain did not acknowledge node state")
		}
	}
}

func (s *keychainState) WriteState(key ipn.StateKey, value []byte) error {
	s.writes.Lock()
	defer s.writes.Unlock()
	s.mu.Lock()
	armed := s.armed
	s.mu.Unlock()
	if armed {
		if err := s.wait(); err != nil {
			return err
		}
	}
	s.mu.Lock()
	if s.closed {
		s.mu.Unlock()
		return errors.New("node state store stopped")
	}
	if old, exists := s.data[key]; (value == nil && !exists) || (value != nil && exists && bytes.Equal(old, value)) {
		s.mu.Unlock()
		return nil
	}
	next := make(map[ipn.StateKey][]byte, len(s.data)+1)
	for key, value := range s.data {
		next[key] = value
	}
	if value == nil {
		delete(next, key)
	} else {
		next[key] = bytes.Clone(value)
	}
	encoded, err := json.Marshal(next)
	if err != nil || len(encoded) > maxNodeState {
		s.mu.Unlock()
		return errors.New("node state exceeds storage limit")
	}
	s.data = next
	s.revision++
	s.mu.Unlock()
	if armed {
		return s.wait()
	}
	return nil
}

func (s *keychainState) arm() {
	s.mu.Lock()
	s.armed = true
	s.mu.Unlock()
	go func() { _ = s.wait() }()
}

func (s *keychainState) snapshot() (nodeStateSnapshot, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed {
		return nodeStateSnapshot{}, errors.New("node state store stopped")
	}
	data, err := json.Marshal(s.data)
	return nodeStateSnapshot{Revision: s.revision, Data: string(data)}, err
}

func (s *keychainState) ack(revision uint64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if s.closed || revision != s.revision {
		return errors.New("stale node state acknowledgement")
	}
	// Only after the user-Keychain write succeeds may the old root file go.
	if s.legacyFile != "" {
		if err := os.Remove(s.legacyFile); err != nil && !os.IsNotExist(err) {
			return errors.New("cannot remove previous plaintext node identity")
		}
		s.legacyFile = ""
	}
	s.acknowledged = revision
	close(s.changed)
	s.changed = make(chan struct{})
	return nil
}

func (s *keychainState) close() {
	s.mu.Lock()
	defer s.mu.Unlock()
	if !s.closed {
		s.closed = true
		clear(s.data)
		close(s.changed)
	}
}
