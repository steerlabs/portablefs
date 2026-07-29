package wal

import (
	"bytes"
	"encoding/gob"
	"encoding/hex"
	"testing"
)

func TestJournalDigestGoldenVector(t *testing.T) {
	// Pinned in packages/metadata-db/src/journal.test.ts: the shared
	// cross-language chain formula sha256(prev[32] || be64(len) || payload).
	first := []byte("portablefs golden payload")
	second := []byte("second record")
	h1 := ChainDigestBytes([32]byte{}, first)
	if hex.EncodeToString(h1[:]) != "fe09d60c3e04d2da7ca7df524d4fff1de0c0d05621757e5883ddc595bbb05cf3" {
		t.Fatalf("record hash diverged from the TS golden vector: %x", h1)
	}
	h2 := ChainDigestBytes(h1, second)
	if hex.EncodeToString(h2[:]) != "d94275bb13beb719863c6c7daf252cf17487d5a8a8b531ff4610946b39698baa" {
		t.Fatalf("chain digest diverged from the TS golden vector: %x", h2)
	}
}

// TestChainDigestMatchesRecordDigest proves recordDigest (the file WAL's
// internal record chain) is exactly ChainDigestBytes over the record's gob
// payload, so a reader holding only the stored bytes reproduces the chain.
func TestChainDigestMatchesRecordDigest(t *testing.T) {
	records := []Record{
		{Seq: 7, Op: OpWrite, Path: "/f", Data: []byte("alpha")},
		{Seq: 8, Op: OpWrite, Path: "/f", Data: []byte("beta")},
	}
	prev := [32]byte{1, 2, 3}
	for _, r := range records {
		var payload bytes.Buffer
		if err := gob.NewEncoder(&payload).Encode(&r); err != nil {
			t.Fatalf("gob encode: %v", err)
		}
		direct, err := recordDigest(prev, r)
		if err != nil {
			t.Fatalf("recordDigest: %v", err)
		}
		if ChainDigestBytes(prev, payload.Bytes()) != direct {
			t.Fatalf("payload chain digest does not match recordDigest for %+v", r)
		}
		prev = direct
	}
}
