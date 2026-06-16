// Copyright (c) 2026, the go-volumes/s3 authors
// SPDX-License-Identifier: BSD-3-Clause

package s3_test

import (
	"bytes"
	"context"
	"testing"

	"github.com/go-volumes/pool"
	s3 "github.com/go-volumes/s3"
)

// Compile-time proof that *Store satisfies the real pool.Backing interface.
// This is the only place the module depends on go-volumes/pool, and it is a
// test-only dependency: production code keeps no pool import.
var _ pool.Backing = (*s3.Store)(nil)

// TestPoolRoundTrip is the real-consumer test: build a copy-on-write pool on an
// S3-backed Store (httptest-backed), create a volume, write to it, read it
// back, and verify the bytes survive a Sync/Close/reopen cycle.
func TestPoolRoundTrip(t *testing.T) {
	srv := newHTTPTestStore(t)
	defer srv.Close()

	store := srv.openStore(t, "pool", 64*1024) // small chunks to force cross-chunk

	// CreateWith reserves the data region on our Store and lays down the pool
	// header + metadata. Capacity 8 MiB, 4 KiB pool blocks.
	p, err := pool.CreateWith(store, 8<<20, 4096)
	if err != nil {
		t.Fatalf("pool.CreateWith: %v", err)
	}

	vol, err := p.CreateVolume("data", 1<<20) // 1 MiB volume
	if err != nil {
		t.Fatalf("CreateVolume: %v", err)
	}

	// Write a recognisable pattern spanning several pool blocks and several
	// store chunks.
	payload := make([]byte, 200*1024)
	for i := range payload {
		payload[i] = byte(i*7 + 3)
	}
	if n, err := vol.WriteAt(payload, 100*1024); err != nil || n != len(payload) {
		t.Fatalf("vol.WriteAt: n=%d err=%v", n, err)
	}

	got := make([]byte, len(payload))
	if n, err := vol.ReadAt(got, 100*1024); err != nil || n != len(got) {
		t.Fatalf("vol.ReadAt: n=%d err=%v", n, err)
	}
	if !bytes.Equal(got, payload) {
		t.Fatal("volume round-trip mismatch before reopen")
	}

	// A hole (never-written region) reads as zeros.
	hole := make([]byte, 4096)
	if _, err := vol.ReadAt(hole, 0); err != nil {
		t.Fatalf("read hole: %v", err)
	}
	for _, b := range hole {
		if b != 0 {
			t.Fatal("expected zero hole")
		}
	}

	// Close the pool (which Syncs and Closes the Store), then reopen from S3 and
	// confirm the data persisted durably.
	if err := p.Close(); err != nil {
		t.Fatalf("pool.Close: %v", err)
	}

	store2 := srv.openStore(t, "pool", 0) // adopt persisted chunk size
	p2, err := pool.OpenWith(store2)
	if err != nil {
		t.Fatalf("pool.OpenWith: %v", err)
	}
	defer p2.Close()
	vol2, err := p2.OpenVolume("data")
	if err != nil {
		t.Fatalf("OpenVolume: %v", err)
	}
	got2 := make([]byte, len(payload))
	if _, err := vol2.ReadAt(got2, 100*1024); err != nil {
		t.Fatalf("reopened ReadAt: %v", err)
	}
	if !bytes.Equal(got2, payload) {
		t.Fatal("volume data did not survive reopen from S3")
	}
}

var _ = context.Background
