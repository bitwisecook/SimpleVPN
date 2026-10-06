// Copyright 2026 James Deucker (bitwisecook)
// SPDX-License-Identifier: GPL-3.0-only

// Package instance owns monotonic opaque engine handles. A removed handle never
// resolves to a new session; callers retain a Go reference during each operation.
package instance

import "sync"

type Registry[T any] struct {
	mu     sync.RWMutex
	next   uint64
	values map[uint64]T
}

func (r *Registry[T]) Add(value T) uint64 {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.next++
	if r.next == 0 {
		panic("engine handle space exhausted")
	}
	if r.values == nil {
		r.values = make(map[uint64]T)
	}
	r.values[r.next] = value
	return r.next
}

func (r *Registry[T]) Get(handle uint64) (T, bool) {
	r.mu.RLock()
	defer r.mu.RUnlock()
	value, ok := r.values[handle]
	return value, ok
}

func (r *Registry[T]) Remove(handle uint64) (T, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	value, ok := r.values[handle]
	delete(r.values, handle)
	return value, ok
}
