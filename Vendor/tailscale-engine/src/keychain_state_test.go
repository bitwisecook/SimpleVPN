// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only
package main

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestNodeStateMigratesOnlyAfterKeychainAckAndNeverWritesPlaintext(t *testing.T) {
	path := filepath.Join(t.TempDir(), "tailscaled.state")
	legacy := []byte(`{"node":"cHJpdmF0ZSBpZGVudGl0eQ=="}`)
	if err := os.WriteFile(path, legacy, 0600); err != nil {
		t.Fatal(err)
	}
	s, err := newKeychainState("", path, nil)
	if err != nil {
		t.Fatal(err)
	}
	defer s.close()
	s.arm()
	snapshot, _ := s.snapshot()
	if snapshot.Revision == 0 {
		t.Fatal("legacy identity was treated as already in Keychain")
	}
	if err := s.ack(snapshot.Revision + 1); err == nil {
		t.Fatal("future acknowledgement accepted")
	}
	if actual, _ := os.ReadFile(path); !bytes.Equal(actual, legacy) {
		t.Fatal("legacy file modified before acknowledgement")
	}
	if err := s.ack(snapshot.Revision); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatal("acknowledged plaintext identity retained")
	}
	done := make(chan error, 1)
	go func() { done <- s.WriteState("node", []byte("rotated identity")) }()
	var update nodeStateSnapshot
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		update, _ = s.snapshot()
		if update.Revision > snapshot.Revision {
			break
		}
		time.Sleep(time.Millisecond)
	}
	select {
	case <-done:
		t.Fatal("write succeeded without user-Keychain ack")
	default:
	}
	if err := s.ack(snapshot.Revision); err == nil {
		t.Fatal("stale acknowledgement accepted")
	}
	if err := s.ack(update.Revision); err != nil {
		t.Fatal(err)
	}
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatal("new node key written to plaintext file")
	}
	read, _ := s.ReadState("node")
	read[0] = 'X'
	actual, _ := s.ReadState("node")
	if string(actual) != "rotated identity" {
		t.Fatal("read exposed mutable backing storage")
	}
}

func TestNodeStateFailsClosedWhenTheKeychainBrokerDoesNotAnswer(t *testing.T) {
	failed := make(chan struct{}, 4)
	s, err := newKeychainState("", filepath.Join(t.TempDir(), "missing.state"), func() { failed <- struct{}{} })
	if err != nil {
		t.Fatal(err)
	}
	s.timeout = 10 * time.Millisecond
	s.arm()
	if err := s.WriteState("node", []byte("secret")); err == nil {
		t.Fatal("unacknowledged write succeeded")
	}
	select {
	case <-failed:
	case <-time.After(time.Second):
		t.Fatal("no persistence-failure signal")
	}
	s.close()
	if _, err := s.snapshot(); err == nil {
		t.Fatal("stopped store returned credentials")
	}
	if _, err := s.ReadState("node"); err == nil {
		t.Fatal("stopped store retained readable identity")
	}
}

func TestNodeStateDistinguishesEmptyValueFromRemoval(t *testing.T) {
	s, err := newKeychainState("", t.TempDir()+"/missing", nil)
	if err != nil {
		t.Fatal(err)
	}
	defer s.close()
	if err = s.WriteState("empty", []byte{}); err != nil {
		t.Fatal(err)
	}
	if _, err = s.ReadState("empty"); err != nil {
		t.Fatal("empty value lost", err)
	}
	if err = s.WriteState("empty", nil); err != nil {
		t.Fatal(err)
	}
	if _, err = s.ReadState("empty"); err == nil {
		t.Fatal("deleted empty value retained")
	}
}
