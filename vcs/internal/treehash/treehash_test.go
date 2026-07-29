package treehash

import (
	"strings"
	"testing"
)

func sha(c string) string { return "sha256:" + strings.Repeat(c, 64) }

// TestGoldenMatchesTS pins the hash of a fixed entry set to the value computed by
// the TS implementation (packages/core/src/tree.ts computeTreeHash). The broader
// 200+-entry cross-check (unicode/emoji/special-chars) lives in
// .volume-cache/treehash-crosscheck.mjs.
func TestGoldenMatchesTS(t *testing.T) {
	entries := []Entry{
		{Path: "a.txt", Kind: "file", Mode: 420, Size: 3, Executable: false,
			Blob: &Blob{Digest: sha("0"), Size: 3, Compression: "none", Packed: false}},
		{Path: "dir/b.bin", Kind: "file", Mode: 493, Size: 6, Executable: true,
			Blob:   &Blob{Digest: sha("1"), Size: 6, Compression: "none", Packed: false},
			Chunks: []Chunk{{Digest: sha("a"), Size: 3, Offset: 0}, {Digest: sha("b"), Size: 3, Offset: 3}}},
		{Path: "link", Kind: "symlink", Mode: 511, Size: 5, Executable: false, LinkTarget: "a.txt"},
		{Path: "dir", Kind: "directory", Mode: 493, Size: 0, Executable: false},
	}
	const golden = "sha256:079aec8d22fd3ab1b93ce9236ed88a7c73487c4340cfe683155ac7dba3463d06"
	if got := Compute(entries); got != golden {
		t.Fatalf("Compute = %s, want TS-verified golden %s", got, golden)
	}
}

// TestGoldenOwnershipMatchesTS pins the hash of a manifest with ownership to the
// TS value, locking in the uid/gid encoding (and that a root entry without
// ownership hashes the same as before — back-compatible).
func TestGoldenOwnershipMatchesTS(t *testing.T) {
	entries := []Entry{
		{Path: "owned.txt", Kind: "file", Mode: 420, Size: 3, UID: 1000, GID: 2000,
			Blob: &Blob{Digest: sha("a"), Size: 3, Compression: "none", Packed: false}},
		{Path: "rootfile.txt", Kind: "file", Mode: 420, Size: 2,
			Blob: &Blob{Digest: sha("b"), Size: 2, Compression: "none", Packed: false}},
	}
	const golden = "sha256:443a25a464c05f258d0b779687796bf95cf3772d52838ef81a746956a76f6e21"
	if got := Compute(entries); got != golden {
		t.Fatalf("Compute = %s, want TS-verified golden %s", got, golden)
	}
}

// TestGoldenBoundaryMatchesTS pins the hash of a manifest that exercises the
// newly-tightened domain boundaries to the value computed by the TS
// implementation (packages/core computeTreeHash):
//
//   - mode/uid/gid at the uint32 maximum (0xffffffff = 4294967295). The Go VCS
//     decodes these as uint32 and the comparable key emits them as base-10
//     integers; TS emits the same JS number via JSON.stringify. This locks in
//     that the largest in-domain ownership/mode values hash byte-identically.
//   - a symlink whose LinkTarget carries multibyte UTF-8: a non-BMP emoji
//     "🚀" (a UTF-16 surrogate pair), accented Latin ("café", "naïve"), CJK
//     ("目標"), and a literal space. jsString must emit these as raw UTF-8 the
//     same way JSON.stringify does (no \uXXXX escaping above U+001F), or the
//     symlink entry would hash differently across the two implementations.
//   - a non-BMP emoji + accents IN the path, so the FNV-1a shard id (computed
//     over UTF-16 code units) and the UTF-16-code-unit path sort are exercised
//     for a surrogate-pair path under the boundary mode/uid/gid.
//
// The golden is produced by the committed TS implementation. To regenerate /
// re-verify it from a clean checkout (depends only on packages/core, no scratch
// files), run from the repo root:
//
//	node --input-type=module -e 'import { computeTreeHash } from "./packages/core/dist/tree.js";
//	  const M = 0xffffffff;
//	  console.log(computeTreeHash([
//	    { path: "boundary/maxmode.txt", kind: "file", mode: M, size: 3, mtimeMs: 0, executable: true, uid: M, gid: M, blob: { digest: "sha256:"+"a".repeat(64), size: 3, compression: "none", packed: false } },
//	    { path: "boundary/link", kind: "symlink", mode: M, size: 1, mtimeMs: 0, executable: false, uid: M, gid: M, linkTarget: "目標/café-🚀-naïve/ .txt" },
//	    { path: "emoji-🚀-café/x.txt", kind: "file", mode: M, size: 2, mtimeMs: 0, executable: false, uid: M, gid: M, blob: { digest: "sha256:"+"b".repeat(64), size: 2, compression: "none", packed: false } },
//	  ]));'
//
// It was additionally cross-checked byte-identically against a Go bridge on
// both the per-entry comparable keys and the final root hash when the port
// was written. (A local generator also lives at
// .volume-cache/treehash-boundary-probe.mjs, mirroring treehash-crosscheck.mjs.)
func TestGoldenBoundaryMatchesTS(t *testing.T) {
	const maxU32 = 0xffffffff // 4294967295
	entries := []Entry{
		{Path: "boundary/maxmode.txt", Kind: "file", Mode: maxU32, Size: 3, Executable: true,
			UID: maxU32, GID: maxU32,
			Blob: &Blob{Digest: sha("a"), Size: 3, Compression: "none", Packed: false}},
		{Path: "boundary/link", Kind: "symlink", Mode: maxU32, Size: 1, Executable: false,
			UID: maxU32, GID: maxU32, LinkTarget: "目標/café-🚀-naïve/ .txt"},
		{Path: "emoji-🚀-café/x.txt", Kind: "file", Mode: maxU32, Size: 2, Executable: false,
			UID: maxU32, GID: maxU32,
			Blob: &Blob{Digest: sha("b"), Size: 2, Compression: "none", Packed: false}},
	}
	const golden = "sha256:b97ffc3fc25cbf3aa58066af629ecc73b20aea7a654e99f135a1dd0f4e7c09da"
	if got := Compute(entries); got != golden {
		t.Fatalf("Compute = %s, want TS-verified golden %s", got, golden)
	}
}

// TestBoundaryComparableKeysAreStable pins the exact per-entry comparable keys of
// the boundary manifest. These strings are the pre-image fed (with the path and a
// NUL separator) into the shard SHA-256, so they ARE the Go↔TS contract: the same
// strings are emitted by the TS comparableEntry/stableJson path (confirmed via a
// debug bridge when the port was written). Pinning them makes any drift in integer or string
// encoding fail here with a readable diff rather than only as an opaque hash change.
func TestBoundaryComparableKeysAreStable(t *testing.T) {
	const maxU32 = 0xffffffff
	cases := []struct {
		entry Entry
		want  string
	}{
		{
			entry: Entry{Path: "boundary/maxmode.txt", Kind: "file", Mode: maxU32, Size: 3, Executable: true,
				UID: maxU32, GID: maxU32,
				Blob: &Blob{Digest: sha("a"), Size: 3, Compression: "none", Packed: false}},
			want: `{"blob":{"compression":"none","digest":"` + sha("a") + `","packed":false,"size":3},"executable":true,"gid":4294967295,"kind":"file","mode":4294967295,"path":"boundary/maxmode.txt","size":3,"uid":4294967295}`,
		},
		{
			entry: Entry{Path: "boundary/link", Kind: "symlink", Mode: maxU32, Size: 1, Executable: false,
				UID: maxU32, GID: maxU32, LinkTarget: "目標/café-🚀-naïve/ .txt"},
			want: `{"executable":false,"gid":4294967295,"kind":"symlink","linkTarget":"目標/café-🚀-naïve/ .txt","mode":4294967295,"path":"boundary/link","size":1,"uid":4294967295}`,
		},
	}
	for _, c := range cases {
		if got := ComparableKey(c.entry); got != c.want {
			t.Fatalf("ComparableKey(%q) mismatch:\n got %s\nwant %s", c.entry.Path, got, c.want)
		}
	}
}

func TestShardIDKnownValue(t *testing.T) {
	if got := ShardID("a.txt"); got != 506 {
		t.Fatalf("ShardID(a.txt) = %d, want 506", got)
	}
}

func TestLessUTF16SurrogateOrdering(t *testing.T) {
	// 🚀 (U+1F680) is a UTF-16 surrogate pair starting 0xD83D, which is < 0xE000,
	// so it sorts BEFORE "" in UTF-16 code-unit order (matching JS `<`) —
	// the opposite of UTF-8 byte order. The tree hash must use UTF-16 order.
	rocket, ec := "🚀", ""
	if !lessUTF16(rocket, ec) {
		t.Fatal(`lessUTF16(🚀, ) should be true (UTF-16 code-unit order)`)
	}
	if !(ec < rocket) {
		t.Fatal(`sanity: Go byte order should disagree ( < 🚀)`)
	}
}

func TestComparableKeyShape(t *testing.T) {
	e := Entry{Path: "a&b.txt", Kind: "file", Mode: 420, Size: 1, Executable: false,
		Blob: &Blob{Digest: "sha256:00", Size: 1, Compression: "none", Packed: false}}
	want := `{"blob":{"compression":"none","digest":"sha256:00","packed":false,"size":1},"executable":false,"kind":"file","mode":420,"path":"a&b.txt","size":1}`
	if got := ComparableKey(e); got != want {
		t.Fatalf("ComparableKey mismatch:\n got %s\nwant %s", got, want)
	}
}
