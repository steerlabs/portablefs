package fsproto

import (
	"crypto/sha256"
	"encoding/binary"
	"testing"

	"github.com/steerlabs/portablefs/vcs/internal/wal"
)

// serveManagedAuthority starts a managed (journal-native) authority over a real
// TCP listener and returns its address. Mirrors newManagedServer but served on
// a socket so a real *Client (which requires the v8 baseline) can dial it.
func serveManagedAuthority(t *testing.T) string {
	t.Helper()
	addr, _ := serveManagedAuthorityFS(t)
	return addr
}

// wbTestDigest chains the mutation-stream digest the way the engine and the
// authority both compute it: over the canonical PFR1 bytes with the stream
// sequence zeroed.
func wbTestDigest(t *testing.T, prev [32]byte, records []wal.Record) [32]byte {
	t.Helper()
	d := prev
	for _, rec := range records {
		seq := rec.Seq
		rec.Seq = 0
		rec.Env = nil
		payload, err := wal.EncodePFR1(&rec)
		if err != nil {
			t.Fatalf("pfr1: %v", err)
		}
		inner := sha256.Sum256(payload)
		h := sha256.New()
		h.Write([]byte("PortableFS/PFW5/stream/v1\x00"))
		h.Write(d[:])
		var b [8]byte
		binary.BigEndian.PutUint64(b[:], seq)
		h.Write(b[:])
		h.Write(inner[:])
		copy(d[:], h.Sum(nil))
	}
	return d
}

func wbZeroDigest() [32]byte {
	return sha256.Sum256([]byte("PortableFS/PFW5/empty/v1\x00"))
}

// TestWriteBackManagedCoordination exercises the adaptive write-back wire
// surface end to end: DelegationAcquire grants the scope with a durable
// epoch, FlushWriteback applies the acknowledged create+write under the
// stream's digest discipline, the acked bytes are durable on the authority,
// and CheckinManaged releases the scope after the drain.
func TestWriteBackManagedCoordination(t *testing.T) {
	addr := serveManagedAuthority(t)
	cli, err := Dial(addr, 2)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = cli.Close() })
	cli.SetOwner("M")
	if _, err := cli.EnsureExactSession(); err != nil {
		t.Fatalf("establish exact session: %v", err)
	}

	// Only an existing directory is delegable (a file delegates its parent;
	// an absent scope declines to write-through).
	if _, st, err := cli.Mkdir("w", 0o755); err != nil || st != OK {
		t.Fatalf("mkdir: st=%d err=%v", st, err)
	}
	if grant, err := cli.DelegationAcquire("absent-dir", "wb-stream-1"); err != nil || grant.Granted {
		t.Fatalf("absent scope must decline: %+v err=%v", grant, err)
	}
	grant, err := cli.DelegationAcquire("w", "wb-stream-1")
	if err != nil || !grant.Granted || grant.Epoch == "" {
		t.Fatalf("delegation acquire: %+v err=%v", grant, err)
	}

	// The stream flush applies the acknowledged records under the digest
	// chain; a lost-reply retry of identical bytes converges.
	records := []wal.Record{
		{Seq: 1, Op: wal.OpCreate, Path: "w/f.txt", Mode: 0o644},
		{Seq: 2, Op: wal.OpWrite, Path: "w/f.txt", Offset: 0, Data: []byte("hello-writeback")},
	}
	prev := wbZeroDigest()
	end := wbTestDigest(t, prev, records)
	scopes := []WBScope{{Path: "w", Epoch: grant.Epoch, Through: records[len(records)-1].Seq}}
	through, st, err := cli.FlushWriteback(FlushBatch{WritebackID: "wb-stream-1", Scopes: scopes, PrevDigest: prev, EndDigest: end, Records: records})
	if err != nil || st != OK || through != 2 {
		t.Fatalf("managed write-back flush: through=%d st=%d err=%v", through, st, err)
	}
	through2, st2, err := cli.FlushWriteback(FlushBatch{WritebackID: "wb-stream-1", Scopes: scopes, PrevDigest: prev, EndDigest: end, Records: records})
	if err != nil || st2 != OK || through2 != 2 {
		t.Fatalf("retry flush: through=%d st=%d err=%v", through2, st2, err)
	}

	// The durable stream state is queryable for recovery.
	view, err := cli.WritebackState("wb-stream-1")
	if err != nil || !view.Exists || view.Through != 2 || view.Digest != end {
		t.Fatalf("writeback state: %+v err=%v", view, err)
	}

	// The acked write is durable on the authority.
	data, _, _, rst, err := cli.ReadV("w/f.txt", 0, 128)
	if err != nil || rst != OK || string(data) != "hello-writeback" {
		t.Fatalf("readback after managed flush: st=%d data=%q err=%v", rst, string(data), err)
	}

	if err := cli.CheckinManaged("w", grant.Epoch); err != nil {
		t.Fatalf("managed checkin: %v", err)
	}
}
