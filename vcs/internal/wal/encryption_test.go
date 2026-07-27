package wal

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"github.com/steerlabs/portablefs/vcs/internal/secure"
)

const (
	testKeyA = "00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff"
	testKeyB = "ffeeddccbbaa99887766554433221100ffeeddccbbaa99887766554433221100"
)

func encA(t *testing.T) *secure.AtRest {
	t.Helper()
	a, err := secure.NewAtRestFromKey(testKeyA)
	if err != nil || a == nil {
		t.Fatalf("build cipher: %v", err)
	}
	return a
}

// TestEncryptedWALRoundTrip: records written through an encrypted WAL replay back
// identically, and the plaintext payload never appears on disk.
func TestEncryptedWALRoundTrip(t *testing.T) {
	path := filepath.Join(t.TempDir(), "wal.log")
	w, err := OpenEncrypted(path, encA(t))
	if err != nil {
		t.Fatal(err)
	}
	secret := []byte("TOP-SECRET-PAYLOAD-bytes")
	if err := w.Append(Record{Op: OpWrite, Path: "secret.txt", Data: secret}); err != nil {
		t.Fatal(err)
	}
	if err := w.Append(Record{Op: OpCreate, Path: "another.txt", Mode: 0o644}); err != nil {
		t.Fatal(err)
	}

	recs, err := w.Replay()
	if err != nil {
		t.Fatalf("replay: %v", err)
	}
	if len(recs) != 2 || recs[0].Path != "secret.txt" || !bytes.Equal(recs[0].Data, secret) {
		t.Fatalf("replayed = %+v, want the two records with intact payload", recs)
	}

	// The plaintext must not be present in the on-disk file.
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(raw, secret) {
		t.Fatal("plaintext payload found on disk — WAL is not encrypted at rest")
	}
	if bytes.Contains(raw, []byte("secret.txt")) {
		t.Fatal("plaintext path found on disk — WAL is not encrypted at rest")
	}
}

// TestEncryptedWALWrongKeyFails: reading an encrypted WAL with the wrong key fails
// loudly (never silently drops acknowledged records).
func TestEncryptedWALWrongKeyFails(t *testing.T) {
	path := filepath.Join(t.TempDir(), "wal.log")
	w, err := OpenEncrypted(path, encA(t))
	if err != nil {
		t.Fatal(err)
	}
	if err := w.Append(Record{Op: OpCreate, Path: "f", Mode: 0o644}); err != nil {
		t.Fatal(err)
	}
	_ = w.Close()

	wrong, _ := secure.NewAtRestFromKey(testKeyB)
	w2, err := OpenEncrypted(path, wrong)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := w2.Replay(); err == nil {
		t.Fatal("replay with the wrong key should fail, not silently return empty")
	}
}

// TestEncryptedWALInteriorCorruptionDetected: corruption of a non-tail record in an
// encrypted WAL is caught (never silently drops records that follow it). The crc
// over the sealed payload catches the flipped byte before the still-good record
// after it; only a genuine torn TAIL is discarded.
func TestEncryptedWALInteriorCorruptionDetected(t *testing.T) {
	path := filepath.Join(t.TempDir(), "wal.log")
	w, err := OpenEncrypted(path, encA(t))
	if err != nil {
		t.Fatal(err)
	}
	if err := w.Append(Record{Op: OpWrite, Path: "first", Data: []byte("hello")}); err != nil {
		t.Fatal(err)
	}
	if err := w.Append(Record{Op: OpCreate, Path: "second", Mode: 0o644}); err != nil {
		t.Fatal(err)
	}
	_ = w.Close()

	raw, _ := os.ReadFile(path)
	raw[8] ^= 0xff // flip a byte in the FIRST record's sealed payload (after its 8-byte header)
	if err := os.WriteFile(path, raw, 0o644); err != nil {
		t.Fatal(err)
	}
	w2, _ := OpenEncrypted(path, encA(t))
	if _, err := w2.Replay(); err == nil {
		t.Fatal("interior corruption must error, not silently drop the records after it")
	}
}

// TestEncryptedWALTornTailDiscarded: a torn final write on an encrypted WAL is
// still discarded (the intact prefix survives) — encryption does not break crash
// recovery.
func TestEncryptedWALTornTailDiscarded(t *testing.T) {
	path := filepath.Join(t.TempDir(), "wal.log")
	w, err := OpenEncrypted(path, encA(t))
	if err != nil {
		t.Fatal(err)
	}
	if err := w.Append(Record{Op: OpCreate, Path: "kept", Mode: 0o644}); err != nil {
		t.Fatal(err)
	}
	_ = w.Close()
	// Simulate a torn trailing write: append a partial frame (fewer bytes than a header).
	f, _ := os.OpenFile(path, os.O_WRONLY|os.O_APPEND, 0o644)
	_, _ = f.Write([]byte{0, 0, 1})
	_ = f.Close()

	w2, _ := OpenEncrypted(path, encA(t))
	recs, err := w2.Replay()
	if err != nil {
		t.Fatalf("torn tail should be discarded without error: %v", err)
	}
	if len(recs) != 1 || recs[0].Path != "kept" {
		t.Fatalf("replayed = %+v, want the intact record [kept]", recs)
	}
}

// TestEncryptedStandbyMirrorsPlaintextRecords: replication carries plaintext records
// (sealed in transit by TLS); each node seals its own WAL with its own key. A
// standby with a DIFFERENT key still mirrors the primary's records faithfully.
func TestEncryptedStandbyMirrorsPlaintextRecords(t *testing.T) {
	dir := t.TempDir()
	primary, err := OpenEncrypted(filepath.Join(dir, "p.wal"), encA(t))
	if err != nil {
		t.Fatal(err)
	}
	standbyKey, _ := secure.NewAtRestFromKey(testKeyB)
	standby, err := OpenEncrypted(filepath.Join(dir, "s.wal"), standbyKey)
	if err != nil {
		t.Fatal(err)
	}
	for _, p := range []string{"a", "b"} {
		if err := primary.Append(Record{Op: OpCreate, Path: p, Mode: 0o644}); err != nil {
			t.Fatal(err)
		}
	}
	if err := primary.AttachReplica(&localReplica{w: standby}); err != nil {
		t.Fatalf("attach: %v", err)
	}
	recs, err := standby.Replay()
	if err != nil {
		t.Fatalf("standby replay (own key): %v", err)
	}
	if len(recs) != 2 || recs[0].Path != "a" || recs[1].Path != "b" {
		t.Fatalf("standby mirror = %+v, want [a b]", recs)
	}
}
