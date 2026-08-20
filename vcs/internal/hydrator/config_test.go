package hydrator

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

const (
	testVolumeID = "11111111-2222-4333-8444-555555555555"
	testCellID   = "99999999-8888-4777-8666-555555555555"
	testAttempt  = "abcdef01-2345-4678-8abc-def012345678"
)

func testConfig() LaunchConfig {
	return LaunchConfig{
		Version:           LaunchConfigVersion,
		VolumeID:          testVolumeID,
		CellID:            testCellID,
		SealedEpoch:       7,
		Attempt:           testAttempt,
		Mode:              ModeServe,
		ManifestSHA256:    strings.Repeat("a", 64),
		ManifestSizeBytes: 4096,
		ManifestCRC64NVME: strings.Repeat("b", 16),
		ChunkSizeBytes:    8 << 20,
	}
}

func TestLoadLaunchConfigIsStrict(t *testing.T) {
	path := filepath.Join(t.TempDir(), LaunchConfigName)
	valid, err := json.Marshal(testConfig())
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	refused := map[string][]byte{
		"an unknown field":     []byte(strings.TrimSuffix(string(valid), "}") + `,"surprise":1}`),
		"a second document":    append(append([]byte(nil), valid...), valid...),
		"a truncated document": valid[:len(valid)/2],
		"an unknown mode": []byte(strings.Replace(string(valid),
			fmt.Sprintf(`"mode":%q`, ModeServe), `"mode":"drain"`, 1)),
		"an unknown version": []byte(strings.Replace(string(valid), `"version":1`, `"version":2`, 1)),
		"a zero epoch":       []byte(strings.Replace(string(valid), `"sealed_epoch":7`, `"sealed_epoch":0`, 1)),
		"a chunk larger than the wire frame": []byte(strings.Replace(string(valid),
			fmt.Sprintf(`"chunk_size_bytes":%d`, 8<<20), `"chunk_size_bytes":33554432`, 1)),
		"a manifest digest that is not hex": []byte(strings.Replace(string(valid),
			strings.Repeat("a", 64), strings.Repeat("A", 64), 1)),
		"a manifest of no bytes": []byte(strings.Replace(string(valid),
			`"manifest_size_bytes":4096`, `"manifest_size_bytes":0`, 1)),
	}
	for name, payload := range refused {
		if err := os.WriteFile(path, payload, 0o600); err != nil {
			t.Fatalf("write %s: %v", name, err)
		}
		if _, err := LoadLaunchConfig(path); err == nil {
			t.Fatalf("%s was accepted", name)
		}
	}
	if err := os.WriteFile(path, valid, 0o600); err != nil {
		t.Fatalf("write the valid configuration: %v", err)
	}
	config, err := LoadLaunchConfig(path)
	if err != nil {
		t.Fatalf("the valid configuration was refused: %v", err)
	}
	if config != testConfig() {
		t.Fatal("the parsed configuration does not round-trip")
	}
}

func TestReadyMarkerIsStrictAndBindsToItsAttempt(t *testing.T) {
	path := filepath.Join(t.TempDir(), ReadyName)
	if _, err := ReadReady(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("a missing marker reported %v, not os.ErrNotExist", err)
	}
	ready := Ready{
		Version:     ReadyVersion,
		VolumeID:    testVolumeID,
		SealedEpoch: 7,
		Attempt:     testAttempt,
		Entries:     42,
		WrittenUnix: 1_700_000_000,
	}
	payload, err := marshalReady(ready)
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	if err := writeAtomic(path, payload); err != nil {
		t.Fatalf("write: %v", err)
	}
	loaded, err := ReadReady(path)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if loaded != ready {
		t.Fatal("the marker does not round-trip")
	}
	if err := loaded.Describes(testConfig()); err != nil {
		t.Fatalf("the marker does not describe its own attempt: %v", err)
	}
	other := testConfig()
	other.Attempt = "00000000-0000-4000-8000-000000000000"
	if err := loaded.Describes(other); err == nil {
		t.Fatal("a marker from another attempt was accepted")
	}
	other = testConfig()
	other.SealedEpoch = 8
	if err := loaded.Describes(other); err == nil {
		t.Fatal("a marker from another epoch was accepted")
	}
}

func TestWriteAtomicLeavesNoTemporaryBehind(t *testing.T) {
	directory := t.TempDir()
	path := filepath.Join(directory, "state")
	if err := writeAtomic(path, []byte("content")); err != nil {
		t.Fatalf("write: %v", err)
	}
	entries, err := os.ReadDir(directory)
	if err != nil {
		t.Fatalf("read: %v", err)
	}
	if len(entries) != 1 || entries[0].Name() != "state" {
		t.Fatalf("the directory holds %d entries after an atomic write", len(entries))
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("stat: %v", err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("the state file is mode %v, not 0600", info.Mode().Perm())
	}
}
