package treehash

import (
	"fmt"
	"sort"
	"testing"
)

func fixtureEntries(n int) []Entry {
	entries := make([]Entry, 0, n)
	for i := 0; i < n; i++ {
		e := Entry{
			Path: fmt.Sprintf("dir%03d/file-%06d.bin", i%37, i),
			Kind: "file", Mode: 0o644, Size: int64(i * 13),
			Blob: &Blob{Digest: fmt.Sprintf("sha256:%064d", i), Size: int64(i * 13), Compression: "none"},
		}
		if i%11 == 0 {
			e.UID, e.GID = 7, 8
		}
		entries = append(entries, e)
	}
	return entries
}

func TestStreamingMatchesBatch(t *testing.T) {
	entries := fixtureEntries(5000)
	want := Compute(entries)

	sorted := append([]Entry(nil), entries...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].Path < sorted[j].Path })
	s := NewStreaming()
	for _, e := range sorted {
		if err := s.Add(e); err != nil {
			t.Fatal(err)
		}
	}
	if got := s.Root(); got != want {
		t.Fatalf("streaming root %s, batch %s", got, want)
	}
}

func TestStreamingHandlesAstralPaths(t *testing.T) {
	// U+10000 (surrogate pair, UTF-16 units 0xD800 0xDC00) sorts BEFORE
	// U+E000 in UTF-16 code-unit order but AFTER it in byte order — the one
	// divergence the overflow path must absorb.
	entries := []Entry{
		{Path: "a", Kind: "file", Mode: 0o644},
		{Path: "z-\uE000", Kind: "file", Mode: 0o644},
		{Path: "z-\U00010000", Kind: "file", Mode: 0o644},
	}
	want := Compute(entries)

	byteSorted := append([]Entry(nil), entries...)
	sort.Slice(byteSorted, func(i, j int) bool { return byteSorted[i].Path < byteSorted[j].Path })
	s := NewStreaming()
	for _, e := range byteSorted {
		if err := s.Add(e); err != nil {
			t.Fatal(err)
		}
	}
	if got := s.Root(); got != want {
		t.Fatalf("astral streaming root %s, batch %s", got, want)
	}
}

func TestStreamingRejectsDisorder(t *testing.T) {
	s := NewStreaming()
	// Two ASCII paths in the same shard, delivered backwards.
	a, b := "x", "y"
	if ShardID(a) != ShardID(b) {
		// Find a same-shard pair deterministically.
		for i := 0; ; i++ {
			b = fmt.Sprintf("x%08d", i)
			if ShardID(a) == ShardID(b) && a < b {
				break
			}
		}
	}
	if err := s.Add(Entry{Path: b, Kind: "file"}); err != nil {
		t.Fatal(err)
	}
	if err := s.Add(Entry{Path: a, Kind: "file"}); err == nil {
		t.Fatal("out-of-order add must fail")
	}
}
