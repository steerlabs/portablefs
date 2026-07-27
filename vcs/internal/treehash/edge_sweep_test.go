package treehash

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"math/rand"
	"strings"
	"sync"
	"testing"
)

// hashPrefix is a quick sanity check that a hash has the expected shape.
const hashPrefix = "sha256:"

func okHash(t *testing.T, h string) {
	t.Helper()
	if !strings.HasPrefix(h, hashPrefix) {
		t.Fatalf("hash %q missing %q prefix", h, hashPrefix)
	}
	hexPart := strings.TrimPrefix(h, hashPrefix)
	if len(hexPart) != 64 {
		t.Fatalf("hash hex length = %d, want 64 (%q)", len(hexPart), h)
	}
	if _, err := hex.DecodeString(hexPart); err != nil {
		t.Fatalf("hash hex not decodable: %v (%q)", err, h)
	}
}

// ----- Empty / degenerate trees -----

// TestEmptyTreeDeterministic: an empty entry set produces a fixed root hash equal
// to SHA-256 over rootVersion + "\n" + shardCount (no shards). This is the canonical
// "empty volume" hash and must be stable and well-formed.
func TestEmptyTreeDeterministic(t *testing.T) {
	got := Compute(nil)
	okHash(t, got)

	// Recompute the documented pre-image independently.
	h := sha256.New()
	h.Write([]byte(rootVersion))
	h.Write([]byte("\n"))
	h.Write([]byte("1024"))
	var sum [32]byte
	copy(sum[:], h.Sum(nil))
	want := hashPrefix + hex.EncodeToString(sum[:])
	if got != want {
		t.Fatalf("empty tree hash = %s, want %s", got, want)
	}
	// Empty slice and nil slice agree.
	if got2 := Compute([]Entry{}); got2 != got {
		t.Fatalf("Compute([]) = %s, Compute(nil) = %s, must match", got2, got)
	}
}

// TestSingleEntry: a one-entry tree is well-formed and differs from empty.
func TestSingleEntry(t *testing.T) {
	e := Entry{Path: "only.txt", Kind: "file", Mode: 420, Size: 1, Executable: false,
		Blob: &Blob{Digest: sha("0"), Size: 1, Compression: "none", Packed: false}}
	got := Compute([]Entry{e})
	okHash(t, got)
	if got == Compute(nil) {
		t.Fatal("a one-entry tree must not equal the empty tree")
	}
}

// ----- Determinism / stability across runs -----

func TestComputeStableAcrossRepeatedCalls(t *testing.T) {
	entries := mixedEntries()
	first := Compute(entries)
	for i := 0; i < 50; i++ {
		if got := Compute(entries); got != first {
			t.Fatalf("Compute not stable on call %d: %s != %s", i, got, first)
		}
	}
}

// TestComputeOrderIndependent: shuffling the input entries must not change the
// hash. The hash sorts paths within a shard and shards by id, so input order is
// irrelevant — this is a core required property.
func TestComputeOrderIndependent(t *testing.T) {
	entries := mixedEntries()
	want := Compute(entries)

	rng := rand.New(rand.NewSource(1))
	for trial := 0; trial < 20; trial++ {
		shuffled := make([]Entry, len(entries))
		copy(shuffled, entries)
		rng.Shuffle(len(shuffled), func(i, j int) { shuffled[i], shuffled[j] = shuffled[j], shuffled[i] })
		if got := Compute(shuffled); got != want {
			t.Fatalf("trial %d: shuffled hash %s != canonical %s", trial, got, want)
		}
	}
}

// TestReverseOrderIdentical is an explicit worst-case of order independence.
func TestReverseOrderIdentical(t *testing.T) {
	entries := mixedEntries()
	rev := make([]Entry, len(entries))
	for i := range entries {
		rev[len(entries)-1-i] = entries[i]
	}
	if Compute(entries) != Compute(rev) {
		t.Fatal("reversed entry order must hash identically")
	}
}

// ----- Field sensitivity (every hashed field changes the hash) -----

func TestEveryHashedFieldChangesHash(t *testing.T) {
	base := Entry{Path: "f.txt", Kind: "file", Mode: 420, Size: 10, Executable: false,
		UID: 1000, GID: 2000,
		Blob: &Blob{Digest: sha("a"), Size: 10, Compression: "none", Packed: false}}
	baseHash := Compute([]Entry{base})

	mutate := func(name string, f func(*Entry)) {
		e := base
		// deep-copy the blob so mutations don't alias base.Blob
		if base.Blob != nil {
			b := *base.Blob
			e.Blob = &b
		}
		f(&e)
		if got := Compute([]Entry{e}); got == baseHash {
			t.Fatalf("changing %s did not change the hash", name)
		}
	}

	mutate("path", func(e *Entry) { e.Path = "g.txt" })
	mutate("kind", func(e *Entry) { e.Kind = "directory" })
	mutate("mode", func(e *Entry) { e.Mode = 493 })
	mutate("size", func(e *Entry) { e.Size = 11 })
	mutate("executable", func(e *Entry) { e.Executable = true })
	mutate("uid", func(e *Entry) { e.UID = 1001 })
	mutate("gid", func(e *Entry) { e.GID = 2001 })
	mutate("blob.digest", func(e *Entry) { e.Blob.Digest = sha("b") })
	mutate("blob.size", func(e *Entry) { e.Blob.Size = 99 })
	mutate("blob.compression", func(e *Entry) { e.Blob.Compression = "zstd" })
	mutate("blob.packed", func(e *Entry) { e.Blob.Packed = true })
}

// TestUIDGIDZeroOmittedFromHash: uid/gid of 0 are omitted (back-compat), so an
// entry with explicit 0 ownership hashes identically to one with no ownership.
// A non-zero value must differ.
func TestUIDGIDZeroOmittedFromHash(t *testing.T) {
	noOwner := Entry{Path: "x", Kind: "file", Mode: 420, Size: 1,
		Blob: &Blob{Digest: sha("0"), Size: 1, Compression: "none", Packed: false}}
	zeroOwner := noOwner
	zeroOwner.UID = 0
	zeroOwner.GID = 0
	if Compute([]Entry{noOwner}) != Compute([]Entry{zeroOwner}) {
		t.Fatal("uid=0/gid=0 must be omitted and hash like no ownership")
	}

	// The omission is reflected in the comparable key (no uid/gid keys present).
	key := ComparableKey(zeroOwner)
	if strings.Contains(key, `"uid"`) || strings.Contains(key, `"gid"`) {
		t.Fatalf("zero uid/gid must be omitted from the comparable key: %s", key)
	}

	withOwner := noOwner
	withOwner.UID = 1
	if Compute([]Entry{noOwner}) == Compute([]Entry{withOwner}) {
		t.Fatal("non-zero uid must change the hash")
	}
}

// ----- Symlink entries -----

// TestSymlinkTargetInHash: a symlink's LinkTarget participates in the hash, and an
// empty LinkTarget is omitted from the comparable key.
func TestSymlinkTargetInHash(t *testing.T) {
	link := Entry{Path: "l", Kind: "symlink", Mode: 511, Size: 5, LinkTarget: "a.txt"}
	other := link
	other.LinkTarget = "b.txt"
	if Compute([]Entry{link}) == Compute([]Entry{other}) {
		t.Fatal("symlink target must affect the hash")
	}
	key := ComparableKey(link)
	if !strings.Contains(key, `"linkTarget":"a.txt"`) {
		t.Fatalf("linkTarget missing from comparable key: %s", key)
	}

	// Empty link target -> linkTarget key omitted.
	empty := Entry{Path: "l", Kind: "symlink", Mode: 511, Size: 0}
	if strings.Contains(ComparableKey(empty), "linkTarget") {
		t.Fatalf("empty linkTarget must be omitted: %s", ComparableKey(empty))
	}
}

// TestSymlinkComparableKeyExact pins the exact comparable key of a simple symlink
// (no blob, no chunks). The string is the SHA pre-image, so this is the Go<->TS
// contract for the symlink shape and key ordering.
func TestSymlinkComparableKeyExact(t *testing.T) {
	link := Entry{Path: "link", Kind: "symlink", Mode: 511, Size: 5, LinkTarget: "a.txt"}
	want := `{"executable":false,"kind":"symlink","linkTarget":"a.txt","mode":511,"path":"link","size":5}`
	if got := ComparableKey(link); got != want {
		t.Fatalf("symlink comparable key mismatch:\n got %s\nwant %s", got, want)
	}
}

// ----- Chunked file entries -----

// TestChunkedFileOrderMatters: chunks are emitted in slice order (NOT sorted), so
// reordering chunks changes the hash. This locks in that chunk order is part of
// the content identity.
func TestChunkedFileOrderMatters(t *testing.T) {
	c1 := Chunk{Digest: sha("a"), Size: 3, Offset: 0}
	c2 := Chunk{Digest: sha("b"), Size: 3, Offset: 3}
	inOrder := Entry{Path: "big", Kind: "file", Mode: 420, Size: 6,
		Blob:   &Blob{Digest: sha("1"), Size: 6, Compression: "none", Packed: false},
		Chunks: []Chunk{c1, c2}}
	swapped := inOrder
	swapped.Chunks = []Chunk{c2, c1}
	if Compute([]Entry{inOrder}) == Compute([]Entry{swapped}) {
		t.Fatal("chunk order must affect the hash (chunks are not sorted)")
	}
}

func TestChunkFieldsInHash(t *testing.T) {
	base := Entry{Path: "big", Kind: "file", Mode: 420, Size: 6,
		Blob:   &Blob{Digest: sha("1"), Size: 6, Compression: "none", Packed: false},
		Chunks: []Chunk{{Digest: sha("a"), Size: 3, Offset: 0}}}
	baseHash := Compute([]Entry{base})

	mut := func(name string, f func(*Entry)) {
		e := base
		e.Chunks = append([]Chunk(nil), base.Chunks...)
		f(&e)
		if Compute([]Entry{e}) == baseHash {
			t.Fatalf("changing chunk %s did not change the hash", name)
		}
	}
	mut("digest", func(e *Entry) { e.Chunks[0].Digest = sha("c") })
	mut("size", func(e *Entry) { e.Chunks[0].Size = 4 })
	mut("offset", func(e *Entry) { e.Chunks[0].Offset = 1 })
	mut("count", func(e *Entry) { e.Chunks = append(e.Chunks, Chunk{Digest: sha("d"), Size: 1, Offset: 3}) })
}

// TestChunkedComparableKeyExact pins the exact key shape for a chunked entry:
// chunks render as an array of {digest,offset,size} objects (keys alphabetical)
// in slice order, and the "chunks" key sorts before "executable".
func TestChunkedComparableKeyExact(t *testing.T) {
	e := Entry{Path: "big", Kind: "file", Mode: 493, Size: 6, Executable: true,
		Blob:   &Blob{Digest: sha("1"), Size: 6, Compression: "none", Packed: false},
		Chunks: []Chunk{{Digest: sha("a"), Size: 3, Offset: 0}, {Digest: sha("b"), Size: 3, Offset: 3}}}
	want := `{"blob":{"compression":"none","digest":"` + sha("1") + `","packed":false,"size":6},` +
		`"chunks":[{"digest":"` + sha("a") + `","offset":0,"size":3},{"digest":"` + sha("b") + `","offset":3,"size":3}],` +
		`"executable":true,"kind":"file","mode":493,"path":"big","size":6}`
	if got := ComparableKey(e); got != want {
		t.Fatalf("chunked comparable key mismatch:\n got %s\nwant %s", got, want)
	}
}

// TestEmptyChunksOmitted: a zero-length Chunks slice is omitted from the key
// (the `if len(e.Chunks) > 0` guard), so it hashes like an entry with no chunks.
func TestEmptyChunksOmitted(t *testing.T) {
	withNil := Entry{Path: "f", Kind: "file", Mode: 420, Size: 1,
		Blob: &Blob{Digest: sha("0"), Size: 1, Compression: "none", Packed: false}}
	withEmpty := withNil
	withEmpty.Chunks = []Chunk{}
	if Compute([]Entry{withNil}) != Compute([]Entry{withEmpty}) {
		t.Fatal("empty chunks slice must be omitted (hash like no chunks)")
	}
	if strings.Contains(ComparableKey(withEmpty), "chunks") {
		t.Fatalf("empty chunks must be omitted from key: %s", ComparableKey(withEmpty))
	}
}

// ----- Duplicate paths (last write wins) -----

// TestDuplicatePathLastWins: when two entries share a path, Compute keeps the last
// one (map assignment in input order). This documents the de-dup behavior.
func TestDuplicatePathLastWins(t *testing.T) {
	a := Entry{Path: "dup", Kind: "file", Mode: 420, Size: 1,
		Blob: &Blob{Digest: sha("a"), Size: 1, Compression: "none", Packed: false}}
	b := Entry{Path: "dup", Kind: "file", Mode: 420, Size: 2,
		Blob: &Blob{Digest: sha("b"), Size: 2, Compression: "none", Packed: false}}

	// [a, b] keeps b; should equal a tree of just b.
	if Compute([]Entry{a, b}) != Compute([]Entry{b}) {
		t.Fatal("with duplicate paths, the last entry must win")
	}
	// [b, a] keeps a; should equal a tree of just a, and differ from [a, b].
	if Compute([]Entry{b, a}) != Compute([]Entry{a}) {
		t.Fatal("duplicate-path resolution must honor input order (last wins)")
	}
	if Compute([]Entry{a, b}) == Compute([]Entry{b, a}) {
		t.Fatal("[a,b] and [b,a] differ when a,b share a path (different survivor)")
	}
}

// ----- Path / shard edges -----

// TestEmptyPathEntry: an entry with an empty path is still hashable; shardID("")
// is well-defined (FNV seed mod 1024) and the key carries `"path":""`.
func TestEmptyPathEntry(t *testing.T) {
	e := Entry{Path: "", Kind: "file", Mode: 420, Size: 0,
		Blob: &Blob{Digest: sha("0"), Size: 0, Compression: "none", Packed: false}}
	got := Compute([]Entry{e})
	okHash(t, got)
	if !strings.Contains(ComparableKey(e), `"path":""`) {
		t.Fatalf("empty path must render as \"path\":\"\": %s", ComparableKey(e))
	}
	// shardID("") is the FNV-1a seed mod 1024.
	if ShardID("") != 2166136261%shardCount {
		t.Fatalf("ShardID(\"\") = %d, want %d", ShardID(""), 2166136261%shardCount)
	}
}

// TestShardIDDeterministicAndBounded: shard ids are stable and always < shardCount.
func TestShardIDDeterministicAndBounded(t *testing.T) {
	paths := []string{"", "a", "a.txt", "dir/sub/file.bin", "目標/café-🚀-naïve/ .txt", strings.Repeat("z/", 500) + "deep"}
	for _, p := range paths {
		id1 := ShardID(p)
		id2 := ShardID(p)
		if id1 != id2 {
			t.Fatalf("ShardID(%q) not deterministic: %d vs %d", p, id1, id2)
		}
		if id1 >= shardCount {
			t.Fatalf("ShardID(%q) = %d, must be < %d", p, id1, shardCount)
		}
	}
}

// TestManyEntriesAcrossShards builds a large tree (more entries than shards, so
// many shards hold multiple paths and intra-shard UTF-16 sorting is exercised)
// and checks determinism + order independence + well-formedness.
func TestManyEntriesAcrossShards(t *testing.T) {
	const n = 5000
	entries := make([]Entry, 0, n)
	for i := 0; i < n; i++ {
		p := "f/" + itoaPadded(i) + ".dat"
		entries = append(entries, Entry{Path: p, Kind: "file", Mode: 420, Size: int64(i),
			Blob: &Blob{Digest: sha(string(rune('0' + i%10))), Size: int64(i), Compression: "none", Packed: i%2 == 0}})
	}
	want := Compute(entries)
	okHash(t, want)

	// Reverse order -> identical.
	rev := make([]Entry, n)
	for i := range entries {
		rev[n-1-i] = entries[i]
	}
	if Compute(rev) != want {
		t.Fatal("large tree must be order-independent")
	}
	// Repeat -> identical.
	if Compute(entries) != want {
		t.Fatal("large tree must be deterministic")
	}
}

// TestUTF16SortOrderIndependent: a tree containing a surrogate-pair path hashes
// deterministically and order-independently (the package sorts paths by UTF-16
// code unit, which differs from UTF-8 byte order).
func TestUTF16SortOrderIndependent(t *testing.T) {
	rocket := Entry{Path: "🚀.txt", Kind: "file", Mode: 420, Size: 1,
		Blob: &Blob{Digest: sha("a"), Size: 1, Compression: "none", Packed: false}}
	ee := Entry{Path: ".txt", Kind: "file", Mode: 420, Size: 1,
		Blob: &Blob{Digest: sha("b"), Size: 1, Compression: "none", Packed: false}}
	h1 := Compute([]Entry{rocket, ee})
	h2 := Compute([]Entry{ee, rocket})
	if h1 != h2 {
		t.Fatalf("surrogate-pair tree not order independent: %s != %s", h1, h2)
	}
	okHash(t, h1)
}

// ----- jsString escaping edges (via the public ComparableKey) -----

// TestComparableKeyEscaping checks JSON.stringify-equivalent escaping of control
// characters and special chars in the path string, which feeds the hash pre-image.
// Expected fragments for sub-0x20 control chars are built with Sprintf so no raw
// control bytes appear in this source file.
func TestComparableKeyEscaping(t *testing.T) {
	// uesc returns the \uXXXX escape jsString emits for a control rune (lowercase
	// hex, 4 digits — matching the production fmt.Sprintf("\\u%04x", r)).
	uesc := func(r rune) string { return fmt.Sprintf(`\u%04x`, r) }

	cases := []struct {
		path string
		want string // the "path":<...> fragment expected in the key
	}{
		{"a\"b", `"path":"a\"b"`},
		{`a\b`, `"path":"a\\b"`},
		{"a\nb", `"path":"a\nb"`},
		{"a\tb", `"path":"a\tb"`},
		{"a\rb", `"path":"a\rb"`},
		{"a\bb", `"path":"a\bb"`},
		{"a\fb", `"path":"a\fb"`},
		{"a\x00b", `"path":"a` + uesc(0x00) + `b"`},
		{"a\x1fb", `"path":"a` + uesc(0x1f) + `b"`},
		{"a/b", `"path":"a/b"`},       // forward slash NOT escaped (matches JSON.stringify)
		{"emoji🚀", `"path":"emoji🚀"`}, // raw UTF-8, no \u escaping above U+001F
	}
	for _, c := range cases {
		e := Entry{Path: c.path, Kind: "file", Mode: 420, Size: 1,
			Blob: &Blob{Digest: sha("0"), Size: 1, Compression: "none", Packed: false}}
		key := ComparableKey(e)
		if !strings.Contains(key, c.want) {
			t.Fatalf("path %q: key %s missing fragment %s", c.path, key, c.want)
		}
	}
}

// ----- Concurrency (-race) -----

// TestConcurrentComputeSameInput: many goroutines computing the same tree must all
// agree and the run must be race-free. Compute builds local maps, so this also
// guards against accidental shared mutable state.
func TestConcurrentComputeSameInput(t *testing.T) {
	entries := mixedEntries()
	want := Compute(entries)

	const goroutines = 64
	var wg sync.WaitGroup
	errs := make(chan string, goroutines)
	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			// Pass a private copy so no goroutine shares the input slice's backing array.
			in := make([]Entry, len(entries))
			copy(in, entries)
			if got := Compute(in); got != want {
				errs <- got
			}
		}()
	}
	wg.Wait()
	close(errs)
	for got := range errs {
		t.Fatalf("concurrent Compute disagreed: %s != %s", got, want)
	}
}

// TestConcurrentComputeDistinctInputs runs Compute on different trees in parallel
// to surface any data race in shared package state (there should be none).
func TestConcurrentComputeDistinctInputs(t *testing.T) {
	const goroutines = 32
	var wg sync.WaitGroup
	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			e := Entry{Path: "g/" + itoaPadded(i), Kind: "file", Mode: 420, Size: int64(i),
				Blob: &Blob{Digest: sha("0"), Size: int64(i), Compression: "none", Packed: false}}
			h1 := Compute([]Entry{e})
			h2 := Compute([]Entry{e})
			if h1 != h2 {
				t.Errorf("goroutine %d: non-deterministic %s != %s", i, h1, h2)
			}
		}(i)
	}
	wg.Wait()
}

// ----- helpers -----

// mixedEntries returns a representative manifest: a plain file, an executable file
// with chunks, a symlink, a directory, an owned file, and unicode paths.
func mixedEntries() []Entry {
	return []Entry{
		{Path: "a.txt", Kind: "file", Mode: 420, Size: 3, Executable: false,
			Blob: &Blob{Digest: sha("0"), Size: 3, Compression: "none", Packed: false}},
		{Path: "dir/b.bin", Kind: "file", Mode: 493, Size: 6, Executable: true,
			Blob:   &Blob{Digest: sha("1"), Size: 6, Compression: "zstd", Packed: true},
			Chunks: []Chunk{{Digest: sha("a"), Size: 3, Offset: 0}, {Digest: sha("b"), Size: 3, Offset: 3}}},
		{Path: "link", Kind: "symlink", Mode: 511, Size: 5, Executable: false, LinkTarget: "a.txt"},
		{Path: "dir", Kind: "directory", Mode: 493, Size: 0, Executable: false},
		{Path: "owned.txt", Kind: "file", Mode: 420, Size: 3, UID: 1000, GID: 2000,
			Blob: &Blob{Digest: sha("c"), Size: 3, Compression: "none", Packed: false}},
		{Path: "目標/café-🚀-naïve.txt", Kind: "file", Mode: 420, Size: 2,
			Blob: &Blob{Digest: sha("d"), Size: 2, Compression: "none", Packed: false}},
	}
}

func itoaPadded(i int) string {
	const width = 8
	s := []byte("00000000")
	n := i
	for p := width - 1; p >= 0 && n > 0; p-- {
		s[p] = byte('0' + n%10)
		n /= 10
	}
	return string(s)
}
