package main

import (
	"bytes"
	"path/filepath"
	"testing"
	"time"

	"github.com/steerlabs/portablefs/vcs/internal/pft2"
	"github.com/steerlabs/portablefs/vcs/spikes/direct-store-seglog/seglog"
)

func TestPebbleIndexGivesFastRecoveryTheSameState(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "store")
	opts := seglog.Options{
		Dir: dir, SegmentBytes: 256 << 10, GroupInterval: time.Hour, GroupBytes: 32 << 10,
		PersistIndex: true, IndexOpener: openPebbleIndex,
	}
	store, err := seglog.Open(opts)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	const keys = 2048
	for i := 0; i < keys; i++ {
		if err := store.Put(cellKey(2, uint64(i)*pft2.CellBytes), dataCell(i, uint64(i))); err != nil {
			t.Fatalf("put %d: %v", i, err)
		}
	}
	if err := store.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	full, err := seglog.Open(opts)
	if err != nil {
		t.Fatalf("full open: %v", err)
	}
	fullKeys := full.IndexKeys()
	if got := full.Recovery().Mode; got != "full-scan" {
		t.Fatalf("recovery mode = %q", got)
	}
	if err := full.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	fastOpts := opts
	fastOpts.FastRecovery = true
	fast, err := seglog.Open(fastOpts)
	if err != nil {
		t.Fatalf("fast open: %v", err)
	}
	defer fast.Close()
	if got := fast.Recovery().Mode; got != "index+tail" {
		t.Fatalf("recovery mode = %q", got)
	}
	if fast.IndexKeys() != fullKeys || fullKeys != keys {
		t.Fatalf("keys: fast=%d full=%d expected=%d", fast.IndexKeys(), fullKeys, keys)
	}
	for i := 0; i < keys; i += 97 {
		got, found, err := fast.Get(cellKey(2, uint64(i)*pft2.CellBytes))
		if err != nil || !found {
			t.Fatalf("key %d missing (found=%v err=%v)", i, found, err)
		}
		if !bytes.Equal(got, dataCell(i, uint64(i))) {
			t.Fatalf("key %d holds the wrong value", i)
		}
	}
}

func TestMutationsAgreeAcrossEngines(t *testing.T) {
	base := t.TempDir()
	const files = 64
	states := map[string]map[string][]byte{}
	for _, name := range []string{"seglog", "pebble"} {
		dir := filepath.Join(base, name)
		if err := buildTemplate(name, dir, files); err != nil {
			t.Fatalf("%s template: %v", name, err)
		}
		store, err := openEngine(name, dir, engineOptions{})
		if err != nil {
			t.Fatalf("%s open: %v", name, err)
		}
		state := newMutationState(files, 12345)
		for op := 0; op < 200; op++ {
			if _, err := applyMutation(store, state, operationKind("mixed", op), op); err != nil {
				t.Fatalf("%s op %d: %v", name, op, err)
			}
			if err := store.Barrier(); err != nil {
				t.Fatalf("%s barrier: %v", name, err)
			}
		}
		snapshot := map[string][]byte{}
		for i := 0; i < files+40; i++ {
			key := inodeKey(uint64(i + 1))
			if value, found, err := store.Get(key); err != nil {
				t.Fatalf("%s get: %v", name, err)
			} else if found {
				snapshot[key] = value
			}
		}
		states[name] = snapshot
		if err := store.Close(); err != nil {
			t.Fatalf("%s close: %v", name, err)
		}
	}
	if len(states["seglog"]) != len(states["pebble"]) {
		t.Fatalf("engines disagree on inode count: %d vs %d", len(states["seglog"]), len(states["pebble"]))
	}
	for key, value := range states["seglog"] {
		if !bytes.Equal(value, states["pebble"][key]) {
			t.Fatalf("engines disagree on %q", key)
		}
	}
}

func TestFastRecoveryRefusesAnIndexOlderThanTheCleaner(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "store")
	opts := seglog.Options{
		Dir: dir, SegmentBytes: 128 << 10, GroupInterval: time.Millisecond, GroupBytes: 16 << 10,
		PersistIndex: true, IndexOpener: openPebbleIndex, CleanUtilization: 0.7,
	}
	store, err := seglog.Open(opts)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	const keys = 256
	for round := 0; round < 40; round++ {
		for i := 0; i < keys; i++ {
			if err := store.Put(cellKey(2, uint64(i)*pft2.CellBytes), dataCell(round*keys+i, uint64(i))); err != nil {
				t.Fatalf("put: %v", err)
			}
		}
	}
	if err := store.Barrier(); err != nil {
		t.Fatalf("barrier: %v", err)
	}
	if store.Stats().SegmentsReclaimed == 0 {
		t.Fatalf("expected the cleaner to reclaim segments")
	}
	if err := store.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}

	fastOpts := opts
	fastOpts.FastRecovery = true
	fast, err := seglog.Open(fastOpts)
	if err != nil {
		t.Fatalf("fast open: %v", err)
	}
	defer fast.Close()
	if fast.IndexKeys() != keys {
		t.Fatalf("recovered %d keys, expected %d (mode %q)", fast.IndexKeys(), keys, fast.Recovery().Mode)
	}
	for i := 0; i < keys; i++ {
		got, found, err := fast.Get(cellKey(2, uint64(i)*pft2.CellBytes))
		if err != nil || !found {
			t.Fatalf("key %d missing after recovery (found=%v err=%v mode=%q)", i, found, err, fast.Recovery().Mode)
		}
		if !bytes.Equal(got, dataCell(39*keys+i, uint64(i))) {
			t.Fatalf("key %d recovered a stale value in mode %q", i, fast.Recovery().Mode)
		}
	}
}
