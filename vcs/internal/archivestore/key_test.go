package archivestore

import (
	"errors"
	"strings"
	"testing"
)

const (
	testVolumeID = "3f2b1c4d-5e6f-4a8b-9c0d-1e2f3a4b5c6d"
	testAttempt  = "a1b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5d"
)

func TestKeyFor(t *testing.T) {
	key, err := KeyFor("cells/cell-a", testVolumeID, 7, testAttempt, "manifest")
	if err != nil {
		t.Fatalf("KeyFor: %v", err)
	}
	want := "cells/cell-a/" + testVolumeID + "/7-" + testAttempt + "/manifest"
	if key != want {
		t.Fatalf("key = %q, want %q", key, want)
	}
	bare, err := KeyFor("", testVolumeID, 1, testAttempt, "pack-000001")
	if err != nil {
		t.Fatalf("KeyFor with an empty prefix: %v", err)
	}
	if bare != testVolumeID+"/1-"+testAttempt+"/pack-000001" {
		t.Fatalf("key = %q", bare)
	}
	if err := validateKey(key); err != nil {
		t.Fatalf("a derived key must satisfy validateKey: %v", err)
	}
	if err := validateKey(bare); err != nil {
		t.Fatalf("a derived key must satisfy validateKey: %v", err)
	}
}

func TestKeyForDistinguishesEveryIdentityComponent(t *testing.T) {
	otherVolume := "3f2b1c4d-5e6f-4a8b-9c0d-1e2f3a4b5c6e"
	otherAttempt := "a1b2c3d4-e5f6-4a7b-8c9d-0e1f2a3b4c5e"
	seen := map[string]struct{}{}
	tuples := []struct {
		volume  string
		epoch   uint64
		attempt string
		object  string
	}{
		{testVolumeID, 7, testAttempt, "manifest"},
		{testVolumeID, 7, testAttempt, "pack-000001"},
		{testVolumeID, 8, testAttempt, "manifest"},
		{testVolumeID, 7, otherAttempt, "manifest"},
		{otherVolume, 7, testAttempt, "manifest"},
	}
	for _, tuple := range tuples {
		key, err := KeyFor("p", tuple.volume, tuple.epoch, tuple.attempt, tuple.object)
		if err != nil {
			t.Fatalf("KeyFor(%+v): %v", tuple, err)
		}
		if _, duplicate := seen[key]; duplicate {
			t.Fatalf("two distinct identity tuples collided on key %q", key)
		}
		seen[key] = struct{}{}
	}
}

func TestKeyForRejections(t *testing.T) {
	cases := map[string]func() (string, error){
		"uppercase volume UUID": func() (string, error) {
			return KeyFor("p", strings.ToUpper(testVolumeID), 1, testAttempt, "manifest")
		},
		"non-UUID volume": func() (string, error) { return KeyFor("p", "volume-1", 1, testAttempt, "manifest") },
		"zero epoch":      func() (string, error) { return KeyFor("p", testVolumeID, 0, testAttempt, "manifest") },
		"non-UUID attempt": func() (string, error) {
			return KeyFor("p", testVolumeID, 1, "attempt", "manifest")
		},
		"empty object": func() (string, error) { return KeyFor("p", testVolumeID, 1, testAttempt, "") },
		"object with a slash": func() (string, error) {
			return KeyFor("p", testVolumeID, 1, testAttempt, "packs/000001")
		},
		"object with a dot": func() (string, error) {
			return KeyFor("p", testVolumeID, 1, testAttempt, "pack.000001")
		},
		"uppercase object": func() (string, error) { return KeyFor("p", testVolumeID, 1, testAttempt, "Manifest") },
		"traversal object": func() (string, error) { return KeyFor("p", testVolumeID, 1, testAttempt, "..") },
		"overlong object": func() (string, error) {
			return KeyFor("p", testVolumeID, 1, testAttempt, strings.Repeat("a", 65))
		},
		"absolute prefix": func() (string, error) { return KeyFor("/p", testVolumeID, 1, testAttempt, "manifest") },
		"traversal prefix": func() (string, error) {
			return KeyFor("a/../b", testVolumeID, 1, testAttempt, "manifest")
		},
		"overlong prefix": func() (string, error) {
			return KeyFor(strings.Repeat("a", maxKeyPrefixBytes+1), testVolumeID, 1, testAttempt, "manifest")
		},
	}
	for name, run := range cases {
		t.Run(name, func(t *testing.T) {
			if _, err := run(); !errors.Is(err, ErrInvalid) {
				t.Fatalf("expected ErrInvalid, got %v", err)
			}
		})
	}
}

func TestKeyForBoundsTotalLength(t *testing.T) {
	// The grammar's own limits must keep every derivable key inside
	// MaxKeyBytes, so the total bound is a guard that can never fire rather
	// than a limit a legitimate deployment could trip over. Build the longest
	// possible key and check the headroom.
	prefix := strings.Repeat("a", maxKeyPrefixBytes)
	longest, err := KeyFor(prefix, testVolumeID, ^uint64(0), testAttempt, strings.Repeat("b", 64))
	if err != nil {
		t.Fatalf("the longest legal key was rejected: %v", err)
	}
	if len(longest) > MaxKeyBytes {
		t.Fatalf("longest derivable key is %d bytes, over the %d-byte bound", len(longest), MaxKeyBytes)
	}
	if err := validateKey(strings.Repeat("a", MaxKeyBytes+1)); !errors.Is(err, ErrInvalid) {
		t.Fatalf("validateKey did not enforce the total bound: %v", err)
	}
}

func TestClientKeyForUsesThePinnedPrefix(t *testing.T) {
	client, err := New(Config{
		Endpoint:           "http://127.0.0.1:9000",
		Region:             "us-west-2",
		Bucket:             "portablefs-archive",
		KeyPrefix:          "pinned/prefix",
		AccessKeyID:        "AKIA",
		SecretAccessKey:    "secret",
		ChecksumCapability: ChecksumNone,
		PathStyle:          true,
	})
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	key, err := client.KeyFor(testVolumeID, 3, testAttempt, "manifest")
	if err != nil {
		t.Fatalf("KeyFor: %v", err)
	}
	if !strings.HasPrefix(key, "pinned/prefix/") {
		t.Fatalf("key %q does not sit under the pinned prefix", key)
	}
}

func TestValidateKeyRejections(t *testing.T) {
	cases := []string{
		"",
		"/leading",
		"trailing/",
		"a//b",
		"a/./b",
		"a/../b",
		"a b",
		"a\x00b",
		"a?b",
		strings.Repeat("a", MaxKeyBytes+1),
	}
	for _, key := range cases {
		if err := validateKey(key); !errors.Is(err, ErrInvalid) {
			t.Fatalf("validateKey(%q) accepted a bad key", key)
		}
	}
}

// TestPinnedObjectNames pins the exact byte forms. These names are wire-frozen
// object-store layout: the archiver writes them, the hydrator and the
// Manager's verifier re-derive them, and existing sealed archives name them in
// durable records — a change here orphans every archived volume.
func TestPinnedObjectNames(t *testing.T) {
	if ManifestObjectName != "manifest" {
		t.Fatalf("ManifestObjectName = %q", ManifestObjectName)
	}
	for index, want := range map[int]string{0: "pack-000000", 1: "pack-000001", 1023: "pack-001023"} {
		if got := PackObjectName(index); got != want {
			t.Fatalf("PackObjectName(%d) = %q, want %q", index, got, want)
		}
	}
}
