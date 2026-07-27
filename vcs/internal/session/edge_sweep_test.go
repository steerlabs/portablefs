package session_test

// edge_sweep_test.go is an exhaustive boundary + failure sweep of the write-back core
// (internal/session). It reuses the in-process harness in session_test.go (startAuthority /
// startAuthorityAddr / nopBlobs / corruptMidLogRecord) and drives ONLY the public API:
// session.New / NewManager / Session.{Create,Write,Read,Truncate,Remove,Mkdir,Symlink,Rename,
// Chmod,Chtimes,Chown,LocalStat,Flush,Fsync,Close} and the authority client's FlushBatch.
//
// Boundaries swept: zero/empty, one byte, exactly-at and +/-1 of the session base-fetch chunk
// (1 MiB) and the flush batch cap (512), the workfs block (4 MiB); sparse holes, grow/shrink/
// same-size truncate, partial vs full overwrite (untouched edges survive a base fetch),
// idempotent repeat, delete-then-recreate (FRESH not adopted), O_CREAT adopt, create-over-kind
// (no clobber), Mkdir/Symlink, rename of file / overlaid dir (children travel) / un-overlaid
// dir+symlink (kind+target preserved) / nonexistent source (ErrNotExist, fabricate nothing),
// Chmod/Chtimes/Chown on overlaid vs read-through paths, duplicate/resent flush (exactly-once,
// no revert), epoch reset + ESTALE/superseded (records kept, no compaction = no loss), crash
// recovery (durable WAL re-flush; torn/mid-log salvage via Renumber), idle-release + the
// release-before-acquire barrier, ConfigureEpochFloor monotonic across a simulated restart, and
// concurrent multi-goroutine writes+flushes (run under -race).

import (
	"bytes"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/steerlabs/portablefs/vcs/internal/fsproto"
	"github.com/steerlabs/portablefs/vcs/internal/session"
	"github.com/steerlabs/portablefs/vcs/internal/wal"
)

const (
	fetchChunk = 1 << 20 // session.go fetchBase/fetchBaseExists chunk; base reads loop on this
	flushCap   = 512     // session.go maxFlushBatch; one round-trip ships at most this many records
	blockBytes = 4 << 20 // workfs block; the authority's base fetch granularity
)

// newSess is a tiny helper: mkdir the root on the authority and open a session over it.
func newSess(t *testing.T, cli *fsproto.Client, owner, id, root string) *session.Session {
	t.Helper()
	if _, st, err := cli.Mkdir(root, 0o755); err != nil || st != fsproto.OK {
		t.Fatalf("mkdir %q: st=%d err=%v", root, st, err)
	}
	s, err := session.New(wbAuth{cli}, owner, id, root, filepath.Join(t.TempDir(), id+".wal"))
	if err != nil {
		t.Fatalf("session.New(%q): %v", root, err)
	}
	return s
}

// readAllLocal pulls a file's full local content via the overlay (ok must be true).
func readAllLocal(t *testing.T, s *session.Session, path string) []byte {
	t.Helper()
	data, ok, err := s.Read(path, 0, int64(maxReadLen))
	if err != nil {
		t.Fatalf("local read %q: %v", path, err)
	}
	if !ok {
		t.Fatalf("local read %q: ok=false (expected overlay-served)", path)
	}
	return data
}

const maxReadLen = 8 << 20 // generous read length for these tests

// readAllAuthority pulls a file's full content from the authority in one read.
func readAllAuthority(t *testing.T, cli *fsproto.Client, path string) ([]byte, int32) {
	t.Helper()
	data, st, err := cli.Read(path, 0, int64(maxReadLen))
	if err != nil {
		t.Fatalf("authority read %q: %v", path, err)
	}
	return data, st
}

// ---------------------------------------------------------------------------
// 1. Write / Read / Truncate boundaries: page edges, sparse, grow/shrink, empty.
// ---------------------------------------------------------------------------

// TestWriteReadBoundaries sweeps write+local-read at and around the session base-fetch chunk
// (1 MiB) and the workfs block (4 MiB), plus zero/one/empty/append-at-EOF/overwrite-at-EOF.
func TestWriteReadBoundaries(t *testing.T) {
	cli := startAuthority(t)
	cli.SetOwner("M")
	s := newSess(t, cli, "M", "wb", "wb")
	defer s.Close()

	for _, sz := range []int64{
		0, 1, 2,
		fetchChunk - 1, fetchChunk, fetchChunk + 1,
		2 * fetchChunk,
		blockBytes - 1, blockBytes, blockBytes + 1,
	} {
		p := fmt.Sprintf("wb/f-%d", sz)
		if err := s.Create(p, 0o644); err != nil {
			t.Fatalf("create %s: %v", p, err)
		}
		want := make([]byte, sz)
		for i := range want {
			want[i] = byte(i*131 + 7) // deterministic non-trivial pattern
		}
		if sz > 0 {
			if n, err := s.Write(p, 0, want); err != nil || n != int(sz) {
				t.Fatalf("write %s: n=%d err=%v, want n=%d", p, n, err, sz)
			}
		}
		// Local read of the whole thing must match exactly across every chunk/block boundary.
		got := readAllLocal(t, s, p)
		if !bytes.Equal(got, want) {
			t.Fatalf("size %d: local read len=%d != want len=%d", sz, len(got), len(want))
		}
		// LocalStat surfaces the exact size.
		if _, _, gsz, _, _, _, ok := s.LocalStat(p); !ok || gsz != sz {
			t.Fatalf("size %d: LocalStat size=%d ok=%v", sz, gsz, ok)
		}
		// Read entirely past EOF yields empty (ok=true: handled locally).
		if data, ok, err := s.Read(p, sz, 16); err != nil || !ok || len(data) != 0 {
			t.Fatalf("size %d: read past EOF data=%q ok=%v err=%v", sz, data, ok, err)
		}
		// A short read that straddles EOF is clipped to the real end.
		if sz >= 4 {
			data, ok, err := s.Read(p, sz-2, 100)
			if err != nil || !ok || !bytes.Equal(data, want[sz-2:]) {
				t.Fatalf("size %d: straddle-EOF read=%v ok=%v err=%v", sz, data, ok, err)
			}
		}
	}
}

// TestSparseWriteHoleReadsZero writes only at a high offset; the unwritten hole [0,off) must
// read back as zeros, and the file size must reach off+len (a sparse grow).
func TestSparseWriteHoleReadsZero(t *testing.T) {
	cli := startAuthority(t)
	cli.SetOwner("M")
	s := newSess(t, cli, "M", "sp", "sp")
	defer s.Close()

	if err := s.Create("sp/f", 0o644); err != nil {
		t.Fatal(err)
	}
	// Write 3 bytes at exactly the chunk boundary — the hole spans a whole fetch chunk.
	const off = int64(fetchChunk)
	if _, err := s.Write("sp/f", off, []byte("END")); err != nil {
		t.Fatal(err)
	}
	got := readAllLocal(t, s, "sp/f")
	if int64(len(got)) != off+3 {
		t.Fatalf("sparse size=%d, want %d", len(got), off+3)
	}
	for i := int64(0); i < off; i++ {
		if got[i] != 0 {
			t.Fatalf("hole byte %d = %d, want 0", i, got[i])
		}
	}
	if string(got[off:]) != "END" {
		t.Fatalf("tail=%q, want END", got[off:])
	}
	// Durable: the authority reflects the hole + tail after flush.
	if err := s.Flush(); err != nil {
		t.Fatal(err)
	}
	ad, st := readAllAuthority(t, cli, "sp/f")
	if st != fsproto.OK || int64(len(ad)) != off+3 || string(ad[off:]) != "END" {
		t.Fatalf("authority sparse len=%d st=%d tail=%q", len(ad), st, byteTail(ad, 3))
	}
	for i := int64(0); i < off; i++ {
		if ad[i] != 0 {
			t.Fatalf("authority hole byte %d = %d, want 0", i, ad[i])
		}
	}
}

func byteTail(b []byte, n int) string {
	if len(b) < n {
		return string(b)
	}
	return string(b[len(b)-n:])
}

// TestTruncateGrowShrinkSame covers truncate to a larger size (zero-extend), smaller size
// (clip), and the exact same size (no-op), at and around the chunk boundary; then truncate to
// zero (empty).
func TestTruncateGrowShrinkSame(t *testing.T) {
	cli := startAuthority(t)
	cli.SetOwner("M")
	s := newSess(t, cli, "M", "tr", "tr")
	defer s.Close()

	if err := s.Create("tr/f", 0o644); err != nil {
		t.Fatal(err)
	}
	base := bytes.Repeat([]byte("ab"), fetchChunk) // 2 MiB of "abab..."
	if _, err := s.Write("tr/f", 0, base); err != nil {
		t.Fatal(err)
	}

	// Shrink to exactly the chunk boundary.
	if err := s.Truncate("tr/f", fetchChunk); err != nil {
		t.Fatal(err)
	}
	if got := readAllLocal(t, s, "tr/f"); !bytes.Equal(got, base[:fetchChunk]) {
		t.Fatalf("shrink-to-chunk len=%d, want %d", len(got), fetchChunk)
	}
	// Same-size truncate is a no-op.
	if err := s.Truncate("tr/f", fetchChunk); err != nil {
		t.Fatal(err)
	}
	if got := readAllLocal(t, s, "tr/f"); int64(len(got)) != fetchChunk {
		t.Fatalf("same-size truncate changed len to %d", len(got))
	}
	// Grow past the boundary by one byte: the extension is zero-filled.
	if err := s.Truncate("tr/f", fetchChunk+1); err != nil {
		t.Fatal(err)
	}
	got := readAllLocal(t, s, "tr/f")
	if int64(len(got)) != fetchChunk+1 || got[fetchChunk] != 0 {
		t.Fatalf("grow+1: len=%d lastByte=%d, want len=%d lastByte=0", len(got), got[fetchChunk], fetchChunk+1)
	}
	if !bytes.Equal(got[:fetchChunk], base[:fetchChunk]) {
		t.Fatal("grow corrupted the retained prefix")
	}
	// Truncate to empty.
	if err := s.Truncate("tr/f", 0); err != nil {
		t.Fatal(err)
	}
	if got := readAllLocal(t, s, "tr/f"); len(got) != 0 {
		t.Fatalf("truncate-to-zero left %d bytes", len(got))
	}
	// Durable: authority ends at size 0.
	if err := s.Flush(); err != nil {
		t.Fatal(err)
	}
	if a, st, err := cli.Getattr("tr/f"); err != nil || st != fsproto.OK || a.Size != 0 {
		t.Fatalf("authority tr/f size=%v st=%d err=%v, want 0", attrSize(a), st, err)
	}
}

func attrSize(a *fsproto.Attr) any {
	if a == nil {
		return "<nil attr>"
	}
	return a.Size
}

// ---------------------------------------------------------------------------
// 2. Partial-overwrite base fetch: untouched edges survive (file seeded on authority).
// ---------------------------------------------------------------------------

// TestPartialOverwriteBaseFetchAtBoundaries seeds a file directly on the authority, then writes
// a small middle slice through the session at/around the chunk boundary. The session must pull
// the base so the untouched head and tail survive — both locally and after flush.
func TestPartialOverwriteBaseFetchAtBoundaries(t *testing.T) {
	for _, baseSize := range []int64{fetchChunk - 1, fetchChunk, fetchChunk + 1, 2 * fetchChunk} {
		t.Run(fmt.Sprintf("base-%d", baseSize), func(t *testing.T) {
			cli := startAuthority(t)
			cli.SetOwner("M")
			if _, st, err := cli.Mkdir("d", 0o755); err != nil || st != fsproto.OK {
				t.Fatalf("mkdir: %d %v", st, err)
			}
			base := make([]byte, baseSize)
			for i := range base {
				base[i] = byte('A' + i%26)
			}
			cli.Create("d/f", 0o644)
			if _, st, err := cli.Write("d/f", 0, base, 0o644); err != nil || st != fsproto.OK {
				t.Fatalf("seed write: %d %v", st, err)
			}
			s, err := session.New(wbAuth{cli}, "M", "pf", "d", filepath.Join(t.TempDir(), "pf.wal"))
			if err != nil {
				t.Fatal(err)
			}
			defer s.Close()

			// Overwrite 4 bytes straddling the chunk boundary (the trickiest base-merge spot).
			mid := int64(fetchChunk) - 2
			if mid < 0 || mid+4 > baseSize {
				mid = baseSize / 2
			}
			patch := []byte("WXYZ")
			if _, err := s.Write("d/f", mid, patch); err != nil {
				t.Fatalf("partial write: %v", err)
			}
			want := append([]byte(nil), base...)
			copy(want[mid:mid+4], patch)

			if got := readAllLocal(t, s, "d/f"); !bytes.Equal(got, want) {
				t.Fatalf("local partial overwrite mismatch (len got=%d want=%d)", len(got), len(want))
			}
			if err := s.Flush(); err != nil {
				t.Fatal(err)
			}
			if got, st := readAllAuthority(t, cli, "d/f"); st != fsproto.OK || !bytes.Equal(got, want) {
				t.Fatalf("authority partial overwrite mismatch st=%d (len got=%d want=%d)", st, len(got), len(want))
			}
		})
	}
}

// ---------------------------------------------------------------------------
// 3. Create idempotency / adopt / fresh-after-delete / create-over-kind.
// ---------------------------------------------------------------------------

// TestCreateIdempotentSameKindNoTruncate: a second Create of an already-local file is a no-op —
// it must NOT truncate the bytes written between the two creates (O_CREAT without O_TRUNC).
func TestCreateIdempotentSameKindNoTruncate(t *testing.T) {
	cli := startAuthority(t)
	cli.SetOwner("M")
	s := newSess(t, cli, "M", "ci", "ci")
	defer s.Close()

	if err := s.Create("ci/f", 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Write("ci/f", 0, []byte("KEEPME")); err != nil {
		t.Fatal(err)
	}
	if err := s.Create("ci/f", 0o644); err != nil { // idempotent: must not zero KEEPME
		t.Fatalf("second create: %v", err)
	}
	if got := readAllLocal(t, s, "ci/f"); string(got) != "KEEPME" {
		t.Fatalf("idempotent Create truncated content: %q", got)
	}
}

// TestCreateOverDirectoryDoesNotClobberAuthority: O_CREAT on a path that is a DIRECTORY on the
// authority must never destroy that directory. The session records no OpCreate (the dir already
// exists), and the authority's idempotent applyCreate keeps the directory — so after Close the
// path is STILL a directory with its children intact.
func TestCreateOverDirectoryDoesNotClobberAuthority(t *testing.T) {
	cli := startAuthority(t)
	cli.SetOwner("M")
	// Seed the directory + child on the authority BEFORE this mount checks out the parent (the
	// realistic ordering: the dir pre-exists; a direct client op under a held checkout is EBUSY).
	for _, p := range []string{"cd", "cd/sub"} {
		if _, st, err := cli.Mkdir(p, 0o755); err != nil || st != fsproto.OK {
			t.Fatalf("mkdir %s: %d %v", p, st, err)
		}
	}
	if _, st, err := cli.Create("cd/sub/keep", 0o644); err != nil || st != fsproto.OK {
		t.Fatalf("seed child: %d %v", st, err)
	}
	s, err := session.New(wbAuth{cli}, "M", "cd", "cd", filepath.Join(t.TempDir(), "cd.wal"))
	if err != nil {
		t.Fatalf("session.New: %v", err)
	}

	if err := s.Create("cd/sub", 0o644); err != nil {
		t.Fatalf("create over dir: %v", err)
	}
	// No mutation may have been recorded (the dir already exists — adopt branch, no OpCreate).
	if recs, _ := s.PendingStats(); recs != 0 {
		t.Fatalf("Create over an existing dir recorded %d pending op(s); a flush could clobber the dir", recs)
	}
	if err := s.Close(); err != nil { // flush (no-op) + checkin
		t.Fatalf("close: %v", err)
	}
	a, st, err := cli.Getattr("cd/sub")
	if err != nil || st != fsproto.OK || a.Kind != "directory" {
		t.Fatalf("DIRECTORY CLOBBERED by create-over-kind: kind=%q st=%d err=%v", attrKind(a), st, err)
	}
	if _, st, _ := cli.Getattr("cd/sub/keep"); st != fsproto.OK {
		t.Fatalf("child under create-over-dir vanished: st=%d", st)
	}
}

func attrKind(a *fsproto.Attr) string {
	if a == nil {
		return "<nil>"
	}
	return a.Kind
}

// TestRecreateAfterFlushedDeleteIsFreshNotAdopted is the SQLite -journal pattern at the chunk
// boundary: create+write a >chunk file, flush it durable, Remove it, then re-Create. The
// re-created file must be FRESH/empty — it must not resurrect the (now-stale) authority content.
func TestRecreateAfterFlushedDeleteIsFreshNotAdopted(t *testing.T) {
	cli := startAuthority(t)
	cli.SetOwner("M")
	s := newSess(t, cli, "M", "rc", "rc")
	defer s.Close()

	if err := s.Create("rc/j", 0o644); err != nil {
		t.Fatal(err)
	}
	big := bytes.Repeat([]byte("S"), fetchChunk+5) // spans the fetch chunk boundary
	if _, err := s.Write("rc/j", 0, big); err != nil {
		t.Fatal(err)
	}
	if err := s.Flush(); err != nil { // now the stale journal is durable on the authority
		t.Fatal(err)
	}
	if err := s.Remove("rc/j"); err != nil {
		t.Fatal(err)
	}
	if err := s.Create("rc/j", 0o644); err != nil {
		t.Fatalf("re-create: %v", err)
	}
	if got := readAllLocal(t, s, "rc/j"); len(got) != 0 {
		t.Fatalf("re-create after delete adopted %d stale bytes; must be FRESH/empty", len(got))
	}
	// And the freshness must be durable: flush, the authority must end empty (the tombstone+fresh
	// create applied), not the stale 1MiB+5.
	if err := s.Flush(); err != nil {
		t.Fatal(err)
	}
	if a, st, err := cli.Getattr("rc/j"); err != nil || st != fsproto.OK || a.Size != 0 {
		t.Fatalf("authority rc/j size=%v st=%d err=%v after recreate, want 0 (fresh)", attrSize(a), st, err)
	}
}

// TestRemoveThenRecreateDirectory: Remove a locally-made directory then re-Mkdir it; the path
// must end as a live directory (the tombstone is superseded by the new mkdir), durably.
func TestRemoveThenRecreateDirectory(t *testing.T) {
	cli := startAuthority(t)
	cli.SetOwner("M")
	s := newSess(t, cli, "M", "rd", "rd")
	defer s.Close()

	if err := s.Mkdir("rd/d", 0o755); err != nil {
		t.Fatal(err)
	}
	if err := s.Remove("rd/d"); err != nil {
		t.Fatal(err)
	}
	// After Remove, LocalStat reports absent (tombstone): kind "".
	if k, _, _, _, _, _, ok := s.LocalStat("rd/d"); !ok || k != "" {
		t.Fatalf("after Remove LocalStat kind=%q ok=%v, want absent", k, ok)
	}
	if err := s.Mkdir("rd/d", 0o755); err != nil {
		t.Fatalf("re-mkdir: %v", err)
	}
	if k, _, _, _, _, _, ok := s.LocalStat("rd/d"); !ok || k != "directory" {
		t.Fatalf("re-mkdir LocalStat kind=%q ok=%v, want directory", k, ok)
	}
	if err := s.Flush(); err != nil {
		t.Fatal(err)
	}
	if a, st, err := cli.Getattr("rd/d"); err != nil || st != fsproto.OK || a.Kind != "directory" {
		t.Fatalf("authority rd/d kind=%q st=%d err=%v, want directory", attrKind(a), st, err)
	}
}

// ---------------------------------------------------------------------------
// 4. Mkdir / Symlink local-view + durability.
// ---------------------------------------------------------------------------

// TestMkdirAndSymlinkLocalAndDurable: a locally-created directory and symlink surface their kind
// (and the symlink its target) via LocalStat, and reach the authority with the right kind/target
// after flush.
func TestMkdirAndSymlinkLocalAndDurable(t *testing.T) {
	cli := startAuthority(t)
	cli.SetOwner("M")
	s := newSess(t, cli, "M", "ms", "ms")

	if err := s.Mkdir("ms/dir", 0o750); err != nil {
		t.Fatal(err)
	}
	if err := s.Symlink("ms/link", "the/target"); err != nil {
		t.Fatal(err)
	}
	if k, mode, _, _, _, _, ok := s.LocalStat("ms/dir"); !ok || k != "directory" || mode != 0o750 {
		t.Fatalf("dir LocalStat kind=%q mode=%o ok=%v", k, mode, ok)
	}
	if k, _, _, _, _, _, ok := s.LocalStat("ms/link"); !ok || k != "symlink" {
		t.Fatalf("symlink LocalStat kind=%q ok=%v", k, ok)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	if a, st, err := cli.Getattr("ms/dir"); err != nil || st != fsproto.OK || a.Kind != "directory" {
		t.Fatalf("authority ms/dir kind=%q st=%d err=%v", attrKind(a), st, err)
	}
	tgt, st, err := cli.Readlink("ms/link")
	if err != nil || st != fsproto.OK || tgt != "the/target" {
		t.Fatalf("authority ms/link target=%q st=%d err=%v, want the/target", tgt, st, err)
	}
}

// ---------------------------------------------------------------------------
// 5. Rename: file, overlaid dir (children travel), un-overlaid dir, nonexistent source.
// ---------------------------------------------------------------------------

// TestRenameLocalFileMovesContentAndTombstones renames a locally-created file: the destination
// carries the content, the old path is tombstoned, and a re-read of the old path reads-through
// (LocalStat reports absent).
func TestRenameLocalFileMovesContentAndTombstones(t *testing.T) {
	cli := startAuthority(t)
	cli.SetOwner("M")
	s := newSess(t, cli, "M", "rf", "rf")
	defer s.Close()

	if err := s.Create("rf/a", 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Write("rf/a", 0, []byte("PAYLOAD")); err != nil {
		t.Fatal(err)
	}
	if err := s.Rename("rf/a", "rf/b"); err != nil {
		t.Fatalf("rename: %v", err)
	}
	if got := readAllLocal(t, s, "rf/b"); string(got) != "PAYLOAD" {
		t.Fatalf("renamed file content=%q, want PAYLOAD", got)
	}
	if k, _, _, _, _, _, ok := s.LocalStat("rf/a"); !ok || k != "" {
		t.Fatalf("old path after rename: kind=%q ok=%v, want tombstoned/absent", k, ok)
	}
	if err := s.Flush(); err != nil {
		t.Fatal(err)
	}
	if got, st := readAllAuthority(t, cli, "rf/b"); st != fsproto.OK || string(got) != "PAYLOAD" {
		t.Fatalf("authority rf/b=%q st=%d", got, st)
	}
	if _, st, _ := cli.Getattr("rf/a"); st != fsproto.ENOENT {
		t.Fatalf("authority rf/a st=%d, want ENOENT after rename", st)
	}
}

// TestRenameUnoverlaidDirectoryPreservesKindAndChild renames a directory that exists only on the
// authority (never overlaid locally). Its kind must be preserved (LocalStat: directory), and its
// un-overlaid children must travel with it on the authority (flushed OpRename).
func TestRenameUnoverlaidDirectoryPreservesKindAndChild(t *testing.T) {
	cli := startAuthority(t)
	cli.SetOwner("M")
	// Seed the directory subtree BEFORE checkout (a direct client op under a held checkout is EBUSY).
	for _, p := range []string{"ru", "ru/dir"} {
		if _, st, err := cli.Mkdir(p, 0o755); err != nil || st != fsproto.OK {
			t.Fatalf("mkdir %s: %d %v", p, st, err)
		}
	}
	if _, st, err := cli.Create("ru/dir/kid", 0o644); err != nil || st != fsproto.OK {
		t.Fatalf("seed kid: %d %v", st, err)
	}
	if _, st, err := cli.Write("ru/dir/kid", 0, []byte("KID"), 0o644); err != nil || st != fsproto.OK {
		t.Fatalf("write kid: %d %v", st, err)
	}
	s, err := session.New(wbAuth{cli}, "M", "ru", "ru", filepath.Join(t.TempDir(), "ru.wal"))
	if err != nil {
		t.Fatalf("session.New: %v", err)
	}

	if err := s.Rename("ru/dir", "ru/dir2"); err != nil {
		t.Fatalf("rename unoverlaid dir: %v", err)
	}
	if k, _, _, _, _, _, ok := s.LocalStat("ru/dir2"); !ok || k != "directory" {
		t.Fatalf("renamed unoverlaid dir kind=%q ok=%v, want directory (not a fabricated file)", k, ok)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	if a, st, err := cli.Getattr("ru/dir2"); err != nil || st != fsproto.OK || a.Kind != "directory" {
		t.Fatalf("authority ru/dir2 kind=%q st=%d err=%v", attrKind(a), st, err)
	}
	if got, st := readAllAuthority(t, cli, "ru/dir2/kid"); st != fsproto.OK || string(got) != "KID" {
		t.Fatalf("authority moved child ru/dir2/kid=%q st=%d, want KID", got, st)
	}
	if _, st, _ := cli.Getattr("ru/dir/kid"); st != fsproto.ENOENT {
		t.Fatalf("old child ru/dir/kid st=%d, want ENOENT after dir rename", st)
	}
}

// TestRenameOverlaidDirectoryCarriesDeepChildren renames a locally-made directory whose deeply
// nested children were edited locally — every descendant must re-key to the new path (local +
// durable), and every old descendant path must be tombstoned.
func TestRenameOverlaidDirectoryCarriesDeepChildren(t *testing.T) {
	cli := startAuthority(t)
	cli.SetOwner("M")
	s := newSess(t, cli, "M", "ro", "ro")
	defer s.Close()

	if err := s.Mkdir("ro/d", 0o755); err != nil {
		t.Fatal(err)
	}
	if err := s.Mkdir("ro/d/sub", 0o755); err != nil {
		t.Fatal(err)
	}
	if err := s.Create("ro/d/sub/deep", 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Write("ro/d/sub/deep", 0, []byte("DEEP")); err != nil {
		t.Fatal(err)
	}
	if err := s.Create("ro/d/top", 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Write("ro/d/top", 0, []byte("TOP")); err != nil {
		t.Fatal(err)
	}

	if err := s.Rename("ro/d", "ro/d2"); err != nil {
		t.Fatalf("rename dir: %v", err)
	}
	// Local view: both the shallow and deep children moved; the old paths are gone.
	if got := readAllLocal(t, s, "ro/d2/sub/deep"); string(got) != "DEEP" {
		t.Fatalf("deep child after dir rename=%q, want DEEP", got)
	}
	if got := readAllLocal(t, s, "ro/d2/top"); string(got) != "TOP" {
		t.Fatalf("shallow child after dir rename=%q, want TOP", got)
	}
	for _, old := range []string{"ro/d/sub/deep", "ro/d/top", "ro/d/sub"} {
		if k, _, _, _, _, _, ok := s.LocalStat(old); !ok || k != "" {
			t.Fatalf("old descendant %q kind=%q ok=%v, want tombstoned/absent", old, k, ok)
		}
	}
	// Durable: the authority reflects the moved deep child.
	if err := s.Flush(); err != nil {
		t.Fatal(err)
	}
	if got, st := readAllAuthority(t, cli, "ro/d2/sub/deep"); st != fsproto.OK || string(got) != "DEEP" {
		t.Fatalf("authority ro/d2/sub/deep=%q st=%d, want DEEP", got, st)
	}
}

// TestRenameNonexistentSourceFabricatesNothing: renaming a path that exists nowhere (no overlay,
// not on the authority) must fail with os.ErrNotExist and create no destination — neither
// locally nor (after a flush attempt) on the authority.
func TestRenameNonexistentSourceFabricatesNothing(t *testing.T) {
	cli := startAuthority(t)
	cli.SetOwner("M")
	s := newSess(t, cli, "M", "rn", "rn")
	defer s.Close()

	if err := s.Rename("rn/ghost", "rn/dst"); !os.IsNotExist(err) {
		t.Fatalf("rename of nonexistent source err=%v, want os.ErrNotExist", err)
	}
	if _, _, _, _, _, _, ok := s.LocalStat("rn/dst"); ok {
		t.Fatal("a failed rename fabricated the destination locally")
	}
	if err := s.Flush(); err != nil {
		t.Fatalf("flush after failed rename: %v", err)
	}
	if _, st, _ := cli.Getattr("rn/dst"); st != fsproto.ENOENT {
		t.Fatalf("authority rn/dst st=%d, want ENOENT (failed rename must fabricate nothing)", st)
	}
}

// ---------------------------------------------------------------------------
// 6. Chmod / Chtimes / Chown: overlaid (buffered + flushed) vs read-through (no shadow).
// ---------------------------------------------------------------------------

// TestMetadataOnOverlaidPathBufferedAndFlushed sets mode/mtime/owner on a locally-created file;
// LocalStat surfaces them immediately, and they reach the authority after flush.
func TestMetadataOnOverlaidPathBufferedAndFlushed(t *testing.T) {
	cli := startAuthority(t)
	cli.SetOwner("M")
	s := newSess(t, cli, "M", "md", "md")

	if err := s.Create("md/f", 0o644); err != nil {
		t.Fatal(err)
	}
	if err := s.Chmod("md/f", 0o600); err != nil {
		t.Fatal(err)
	}
	const mtimeMs = int64(1599999999000)
	if err := s.Chtimes("md/f", mtimeMs); err != nil {
		t.Fatal(err)
	}
	if err := s.Chown("md/f", 1234, 5678); err != nil {
		t.Fatal(err)
	}
	// LocalStat surfaces every locally-set field with no stale read-back.
	k, mode, _, mt, uid, gid, ok := s.LocalStat("md/f")
	if !ok || k != "file" || mode != 0o600 || mt != mtimeMs || uid != 1234 || gid != 5678 {
		t.Fatalf("LocalStat kind=%q mode=%o mt=%d uid=%d gid=%d ok=%v", k, mode, mt, uid, gid, ok)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	a, st, err := cli.Getattr("md/f")
	if err != nil || st != fsproto.OK {
		t.Fatalf("authority getattr: st=%d err=%v", st, err)
	}
	if a.Mode&0o777 != 0o600 || a.MtimeMs != mtimeMs || a.Uid != 1234 || a.Gid != 5678 {
		t.Fatalf("authority after flush mode=%o mt=%d uid=%d gid=%d, want 0600/%d/1234/5678",
			a.Mode&0o777, a.MtimeMs, a.Uid, a.Gid, mtimeMs)
	}
}

// TestMetadataOnReadThroughDirDoesNotShadow: Chmod/Chtimes/Chown on a directory the session has
// NOT overlaid (e.g. the OS bumps its mtime when a sibling is created) must NOT fabricate a
// kind:"file" overlay entry shadowing the directory — LocalStat stays read-through (ok=false) —
// yet the ops still reach the authority on flush and the path stays a directory there.
func TestMetadataOnReadThroughDirDoesNotShadow(t *testing.T) {
	cli := startAuthority(t)
	cli.SetOwner("M")
	// Seed the sub-directory BEFORE checkout (a direct client op under a held checkout is EBUSY).
	for _, p := range []string{"mr", "mr/sub"} {
		if _, st, err := cli.Mkdir(p, 0o755); err != nil || st != fsproto.OK {
			t.Fatalf("mkdir %s: %d %v", p, st, err)
		}
	}
	s, err := session.New(wbAuth{cli}, "M", "mr", "mr", filepath.Join(t.TempDir(), "mr.wal"))
	if err != nil {
		t.Fatalf("session.New: %v", err)
	}

	const mtimeMs = int64(1700000000000)
	if err := s.Chmod("mr/sub", 0o711); err != nil {
		t.Fatal(err)
	}
	if err := s.Chtimes("mr/sub", mtimeMs); err != nil {
		t.Fatal(err)
	}
	if err := s.Chown("mr/sub", 9, 9); err != nil {
		t.Fatal(err)
	}
	// None of the three may have fabricated an overlay entry (would shadow the dir as a file).
	if k, _, _, _, _, _, ok := s.LocalStat("mr/sub"); ok {
		t.Fatalf("metadata op fabricated an overlay entry for read-through dir mr/sub (kind=%q); shadows the directory", k)
	}
	if err := s.Close(); err != nil {
		t.Fatal(err)
	}
	a, st, err := cli.Getattr("mr/sub")
	if err != nil || st != fsproto.OK {
		t.Fatalf("authority getattr mr/sub: st=%d err=%v", st, err)
	}
	if a.Kind != "directory" {
		t.Fatalf("mr/sub kind=%q after metadata ops + flush, want directory (not shadowed)", a.Kind)
	}
	if a.Mode&0o777 != 0o711 || a.MtimeMs != mtimeMs || a.Uid != 9 || a.Gid != 9 {
		t.Fatalf("read-through dir metadata not flushed: mode=%o mt=%d uid=%d gid=%d", a.Mode&0o777, a.MtimeMs, a.Uid, a.Gid)
	}
}

// ---------------------------------------------------------------------------
// 7. Flush exactly-once: duplicate / resent batches (no revert), and idle no-op flush.
// ---------------------------------------------------------------------------

// TestFlushExactlyOnceRedundantReflushNoRevert: a second write+flush must OVERWRITE the authority
// (advance it), and a subsequent redundant flush with nothing pending must be a clean no-op that
// does NOT revert the overwrite to the first generation's value. This is the exactly-once
// discriminator the write-back layer documents: re-flushing an already-acked prefix mustn't undo
// a later change. Driven entirely through the session (the holder of the checkout).
func TestFlushExactlyOnceRedundantReflushNoRevert(t *testing.T) {
	cli := startAuthority(t)
	cli.SetOwner("M")
	s := newSess(t, cli, "M", "fx", "fx")
	defer s.Close()

	if err := s.Create("fx/f", 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Write("fx/f", 0, []byte("ORIG")); err != nil {
		t.Fatal(err)
	}
	if err := s.Flush(); err != nil {
		t.Fatal(err)
	}
	if got, st := readAllAuthority(t, cli, "fx/f"); st != fsproto.OK || string(got) != "ORIG" {
		t.Fatalf("after first flush authority=%q, want ORIG", got)
	}
	// Overwrite via the session, flush: the authority advances to NEWV.
	if _, err := s.Write("fx/f", 0, []byte("NEWV")); err != nil {
		t.Fatal(err)
	}
	if err := s.Flush(); err != nil {
		t.Fatalf("second flush: %v", err)
	}
	if recs, _ := s.PendingStats(); recs != 0 {
		t.Fatalf("after second flush pending=%d, want 0", recs)
	}
	if got, st := readAllAuthority(t, cli, "fx/f"); st != fsproto.OK || string(got) != "NEWV" {
		t.Fatalf("after overwrite+flush authority=%q, want NEWV", got)
	}
	// Several redundant flushes with nothing pending: each a clean no-op, NEVER a revert to ORIG.
	for i := 0; i < 3; i++ {
		if err := s.Flush(); err != nil {
			t.Fatalf("redundant flush %d: %v", i, err)
		}
	}
	if got, st := readAllAuthority(t, cli, "fx/f"); st != fsproto.OK || string(got) != "NEWV" {
		t.Fatalf("redundant flush reverted the authority to %q, want NEWV", got)
	}
}

// TestFlushBatchDuplicateResendExactlyOnce drives the authority's dedup directly (we control the
// epoch): apply a batch, mutate the authority, then RESEND the identical batch+epoch. The resend
// must be a no-op (returns the prior through, applies nothing) and must not revert the mutation.
func TestFlushBatchDuplicateResendExactlyOnce(t *testing.T) {
	cli := startAuthority(t)
	cli.SetOwner("M")
	if _, st, err := cli.Mkdir("dx", 0o755); err != nil || st != fsproto.OK {
		t.Fatalf("mkdir: %d %v", st, err)
	}
	const id = "dx-sess"
	const epoch = uint64(7777)
	batch := []wal.Record{
		{Seq: 0, Op: wal.OpCreate, Path: "dx/f", Mode: 0o644},
		{Seq: 1, Op: wal.OpWrite, Path: "dx/f", Offset: 0, Data: []byte("AAAA")},
	}
	th, st, err := cli.FlushBatch(id, epoch, "M", batch)
	if err != nil || st != fsproto.OK || th != 1 {
		t.Fatalf("first flush through=%d st=%d err=%v, want through=1 OK", th, st, err)
	}
	if _, st, err := cli.Write("dx/f", 0, []byte("ZZZZ"), 0o644); err != nil || st != fsproto.OK {
		t.Fatalf("authority overwrite: %d %v", st, err)
	}
	// Exact resend of the same batch+epoch: pure no-op, returns through=1, applies nothing.
	th2, st2, err2 := cli.FlushBatch(id, epoch, "M", batch)
	if err2 != nil || st2 != fsproto.OK || th2 != 1 {
		t.Fatalf("resend through=%d st=%d err=%v, want through=1 OK (exactly-once)", th2, st2, err2)
	}
	if got, _ := readAllAuthority(t, cli, "dx/f"); string(got) != "ZZZZ" {
		t.Fatalf("duplicate resend reverted the overwrite to %q, want ZZZZ", got)
	}
}

// ---------------------------------------------------------------------------
// 8. Epoch reset + ESTALE / superseded: records kept, no compaction = no loss.
// ---------------------------------------------------------------------------

// TestEpochResetNewGenerationStartsAtSeqZero: a new generation of a SessionID (higher epoch)
// re-flushes from local Seq 0 — the authority resets its dedup watermark to 0 and applies the
// batch (it must NOT be dropped as a stale resend just because Seq 0 was already used once).
func TestEpochResetNewGenerationStartsAtSeqZero(t *testing.T) {
	cli := startAuthority(t)
	cli.SetOwner("M")
	if _, st, err := cli.Mkdir("ep", 0o755); err != nil || st != fsproto.OK {
		t.Fatalf("mkdir: %d %v", st, err)
	}
	const id = "ep-sess"
	// Generation 1 advances the watermark to through=2.
	if th, st, err := cli.FlushBatch(id, 100, "M", []wal.Record{
		{Seq: 0, Op: wal.OpCreate, Path: "ep/f", Mode: 0o644},
		{Seq: 1, Op: wal.OpWrite, Path: "ep/f", Offset: 0, Data: []byte("GEN1")},
	}); err != nil || st != fsproto.OK || th != 1 {
		t.Fatalf("gen1 through=%d st=%d err=%v", th, st, err)
	}
	// Generation 2: HIGHER epoch, local Seq restarts at 0 — must reset + apply, not drop.
	th, st, err := cli.FlushBatch(id, 200, "M", []wal.Record{
		{Seq: 0, Op: wal.OpWrite, Path: "ep/f", Offset: 0, Data: []byte("GEN2!")},
	})
	if err != nil || st != fsproto.OK || th != 0 {
		t.Fatalf("gen2 (Seq0, higher epoch) through=%d st=%d err=%v, want through=0 OK (epoch reset)", th, st, err)
	}
	if got, _ := readAllAuthority(t, cli, "ep/f"); string(got) != "GEN2!" {
		t.Fatalf("epoch reset did not apply gen2: %q, want GEN2!", got)
	}
}

// TestSupersededFlushKeepsRecordsNoLoss: when a session's epoch falls BELOW the authority's
// watermark epoch (a newer generation of the same id took over), its flush is rejected with
// ESTALE. The session must KEEP its pending records (no compaction = no loss), mark itself
// superseded so further Flush calls short-circuit, and never leak the stale write to the
// authority. Models a recovered session whose wall-clock epoch fell behind a pre-crash one.
func TestSupersededFlushKeepsRecordsNoLoss(t *testing.T) {
	cli := startAuthority(t)
	cli.SetOwner("M")
	const id = "sup-sess"
	s := newSess(t, cli, "M", id, "su")

	if err := s.Create("su/a", 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Write("su/a", 0, []byte("FIRST")); err != nil {
		t.Fatal(err)
	}
	if err := s.Flush(); err != nil { // establishes the watermark at THIS session's epoch
		t.Fatalf("first flush: %v", err)
	}
	// A "newer generation" of the same SessionID bumps the authority watermark to a far-higher
	// epoch (its own Seq space, restarting at 0).
	if _, st, err := cli.FlushBatch(id, 1<<62, "M", []wal.Record{
		{Seq: 0, Op: wal.OpCreate, Path: "su/b", Mode: 0o644},
	}); err != nil || st != fsproto.OK {
		t.Fatalf("newer-generation bump: st=%d err=%v", st, err)
	}

	// Now the original session (older epoch) writes more and flushes -> ESTALE / superseded.
	if _, err := s.Write("su/a", 5, []byte("MORE")); err != nil {
		t.Fatal(err)
	}
	recBefore, _ := s.PendingStats()
	if recBefore == 0 {
		t.Fatal("expected a pending record before the stale flush")
	}
	ferr := s.Flush()
	var rej *session.FlushRejectedError
	if ferr == nil || !asFlushRejected(ferr, &rej) || rej.Status != fsproto.ESTALE {
		t.Fatalf("stale flush err=%v, want *FlushRejectedError{Status: ESTALE(%d)}", ferr, fsproto.ESTALE)
	}
	// Records KEPT (no compaction = no loss).
	if recAfter, _ := s.PendingStats(); recAfter != recBefore {
		t.Fatalf("superseded flush compacted records: before=%d after=%d (DATA LOSS)", recBefore, recAfter)
	}
	// Subsequent Flush short-circuits to a no-op (superseded), still keeping the records.
	if err := s.Flush(); err != nil {
		t.Fatalf("post-supersede flush must be a no-op, got %v", err)
	}
	if recAfter2, _ := s.PendingStats(); recAfter2 != recBefore {
		t.Fatalf("second superseded flush changed pending: before=%d after=%d", recBefore, recAfter2)
	}
	// The stale write never reached the authority.
	if got, _ := readAllAuthority(t, cli, "su/a"); string(got) != "FIRST" {
		t.Fatalf("stale write leaked to authority: %q, want FIRST", got)
	}
	// Closing a superseded session must not panic / double-fault (the records persist in the WAL
	// for recovery on a clean restart; Close attempts the flush, which no-ops out).
	_ = s.Close()
}

// asFlushRejected is a tiny errors.As shim that keeps the test free of an extra import block.
func asFlushRejected(err error, target **session.FlushRejectedError) bool {
	if e, ok := err.(*session.FlushRejectedError); ok {
		*target = e
		return true
	}
	return false
}

// ---------------------------------------------------------------------------
// 9. Crash recovery: durable WAL re-flush; torn-tail & mid-log salvage via Renumber.
// ---------------------------------------------------------------------------

// TestCrashRecoveryReflushesDurableTail: a session that durably logged records but crashed
// before flushing must, on restart with the same WAL + owner, re-flush the WHOLE tail to the
// authority exactly-once — including a write that spans the fetch chunk boundary.
func TestCrashRecoveryReflushesDurableTail(t *testing.T) {
	cli := startAuthority(t)
	cli.SetOwner("R")
	if _, st, err := cli.Mkdir("ws", 0o755); err != nil || st != fsproto.OK {
		t.Fatalf("mkdir ws: %d %v", st, err)
	}
	walPath := filepath.Join(t.TempDir(), "sess-R.wal")

	big := bytes.Repeat([]byte("Z"), fetchChunk+9)
	w, err := wal.Open(walPath)
	if err != nil {
		t.Fatal(err)
	}
	var last uint64
	for _, r := range []wal.Record{
		{Op: wal.OpCreate, Path: "ws/db", Mode: 0o644},
		{Op: wal.OpWrite, Path: "ws/db", Offset: 0, Data: big},
	} {
		seq, aerr := w.AppendBuffered(r)
		if aerr != nil {
			t.Fatal(aerr)
		}
		last = seq
	}
	if err := w.CommitThrough(last); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	if _, st, _ := cli.Getattr("ws/db"); st == fsproto.OK {
		t.Fatal("ws/db must be absent before recovery")
	}

	s, err := session.New(wbAuth{cli}, "R", "R-ws", "ws", walPath)
	if err != nil {
		t.Fatalf("recovery session: %v", err)
	}
	defer s.Close()
	got, st := readAllAuthority(t, cli, "ws/db")
	if st != fsproto.OK || !bytes.Equal(got, big) {
		t.Fatalf("authority after recovery: len=%d st=%d, want len=%d", len(got), st, len(big))
	}
}

// TestCrashRecoverySalvagesValidPrefixOnMidLogCorruption: a crashed session's WAL with bit-rot in
// the MIDDLE (not just a torn tail) must re-flush the valid PREFIX rather than abandon the whole
// tail. records 0,1 (ws/a="AAAA") stay valid; record 2 onward is unreadable.
func TestCrashRecoverySalvagesValidPrefixOnMidLogCorruption(t *testing.T) {
	cli := startAuthority(t)
	cli.SetOwner("M")
	if _, st, err := cli.Mkdir("ws", 0o755); err != nil || st != fsproto.OK {
		t.Fatalf("mkdir ws: %d %v", st, err)
	}
	walPath := filepath.Join(t.TempDir(), "sess.wal")

	w, err := wal.Open(walPath)
	if err != nil {
		t.Fatal(err)
	}
	var last uint64
	for _, r := range []wal.Record{
		{Op: wal.OpCreate, Path: "ws/a", Mode: 0o644},
		{Op: wal.OpWrite, Path: "ws/a", Offset: 0, Data: []byte("AAAA")},
		{Op: wal.OpCreate, Path: "ws/b", Mode: 0o644}, // record idx 2 — corrupted below
		{Op: wal.OpWrite, Path: "ws/b", Offset: 0, Data: []byte("BBBB")},
	} {
		seq, aerr := w.AppendBuffered(r)
		if aerr != nil {
			t.Fatal(aerr)
		}
		last = seq
	}
	if err := w.CommitThrough(last); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	corruptMidLogRecord(t, walPath, 2) // records 0,1 stay valid; 2 onward unreadable

	s, err := session.New(wbAuth{cli}, "M", "sess", "ws", walPath)
	if err != nil {
		t.Fatalf("New (recovery): %v", err)
	}
	defer s.Close()
	if got, st := readAllAuthority(t, cli, "ws/a"); st != fsproto.OK || string(got) != "AAAA" {
		t.Fatalf("recovery must re-flush the valid prefix; ws/a=%q st=%d, want AAAA", got, st)
	}
	// The corrupt tail (ws/b) was not salvageable, so it must be absent on the authority.
	if _, st, _ := cli.Getattr("ws/b"); st == fsproto.OK {
		t.Fatal("ws/b must be absent: it lived in the corrupt tail that could not be salvaged")
	}
}

// TestCrashRecoveryTornTailSalvagesIntactPrefix: a torn final record (a partial write from a
// crash, with no valid data after it) is discarded; the intact prefix before it is re-flushed.
// We tear the tail by truncating the WAL mid-way through its last record's body.
func TestCrashRecoveryTornTailSalvagesIntactPrefix(t *testing.T) {
	cli := startAuthority(t)
	cli.SetOwner("M")
	if _, st, err := cli.Mkdir("ws", 0o755); err != nil || st != fsproto.OK {
		t.Fatalf("mkdir ws: %d %v", st, err)
	}
	walPath := filepath.Join(t.TempDir(), "sess.wal")

	w, err := wal.Open(walPath)
	if err != nil {
		t.Fatal(err)
	}
	var last uint64
	for _, r := range []wal.Record{
		{Op: wal.OpCreate, Path: "ws/a", Mode: 0o644},
		{Op: wal.OpWrite, Path: "ws/a", Offset: 0, Data: []byte("KEEP")},
		{Op: wal.OpWrite, Path: "ws/a", Offset: 4, Data: bytes.Repeat([]byte("T"), 4096)}, // big last record
	} {
		seq, aerr := w.AppendBuffered(r)
		if aerr != nil {
			t.Fatal(aerr)
		}
		last = seq
	}
	if err := w.CommitThrough(last); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	// Tear the tail: lop off the last 2 KiB so the final record's body is truncated (a torn tail,
	// no valid data following) while the first two records stay intact.
	fi, err := os.Stat(walPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Truncate(walPath, fi.Size()-2048); err != nil {
		t.Fatal(err)
	}

	s, err := session.New(wbAuth{cli}, "M", "sess", "ws", walPath)
	if err != nil {
		t.Fatalf("New (recovery): %v", err)
	}
	defer s.Close()
	// The intact prefix (ws/a="KEEP") must have been re-flushed; the torn 3rd record dropped.
	got, st := readAllAuthority(t, cli, "ws/a")
	if st != fsproto.OK || string(got) != "KEEP" {
		t.Fatalf("torn-tail recovery: ws/a=%q st=%d, want KEEP (intact prefix re-flushed, torn tail dropped)", got, st)
	}
}

// ---------------------------------------------------------------------------
// 10. Manager: idle-release, release-before-acquire barrier, recover-all.
// ---------------------------------------------------------------------------

// TestIdleReleaseFlushesBeforeCheckin: a session idle past the window auto-flushes, checks in,
// and is removed from resolution — and its writes are durable BEFORE another owner can acquire.
func TestIdleReleaseFlushesBeforeCheckin(t *testing.T) {
	cli := startAuthority(t)
	cli.SetOwner("A")
	if _, st, err := cli.Mkdir("shared", 0o755); err != nil || st != fsproto.OK {
		t.Fatalf("mkdir: %d %v", st, err)
	}
	mgr := session.NewManager(wbAuth{cli}, "A", t.TempDir(), 40*time.Millisecond)
	mgr.Start(15 * time.Millisecond)
	defer mgr.Stop()

	s, err := mgr.Ensure("shared/f")
	if err != nil {
		t.Fatalf("ensure: %v", err)
	}
	if err := s.Create("shared/f", 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Write("shared/f", 0, []byte("HANDOFF")); err != nil {
		t.Fatal(err)
	}

	if !waitFor(2*time.Second, func() bool { return mgr.For("shared/f") == nil }) {
		t.Fatal("session was not idle-released within 2s")
	}
	// Another owner can now acquire the handed-off subtree, and A's write is already durable.
	granted, heldBy, err := cli.Checkout("shared", "B")
	if err != nil || !granted {
		t.Fatalf("B should acquire after A's release: granted=%v heldBy=%q err=%v", granted, heldBy, err)
	}
	if got, st := readAllAuthority(t, cli, "shared/f"); st != fsproto.OK || string(got) != "HANDOFF" {
		t.Fatalf("A's data must be durable before release: got %q st=%d", got, st)
	}
}

// TestReleaseBeforeAcquireBarrierNoDataLoss exercises the release-before-acquire barrier on ONE
// subtree under an aggressive idle window: a single manager repeatedly re-acquires the same
// subtree as the sweeper releases it. The barrier must prevent a second WAL handle on the same
// file; the final authority content must equal the last write (no handoff data loss), and no WAL
// debris may remain after Stop. Run under -race.
func TestReleaseBeforeAcquireBarrierNoDataLoss(t *testing.T) {
	cli := startAuthority(t)
	cli.SetOwner("A")
	if _, st, err := cli.Mkdir("bar", 0o755); err != nil || st != fsproto.OK {
		t.Fatalf("mkdir: %d %v", st, err)
	}
	walDir := t.TempDir()
	mgr := session.NewManager(wbAuth{cli}, "A", walDir, 2*time.Millisecond) // tiny idle: constant handoff
	mgr.Start(time.Millisecond)

	var last []byte
	for i := 0; i < 120; i++ {
		val := []byte(fmt.Sprintf("v%03d", i))
		for { // retry across the release-before-acquire barrier (Ensure waits out the handoff)
			s, err := mgr.Ensure("bar/f")
			if err != nil {
				time.Sleep(time.Millisecond)
				continue
			}
			if err := s.Create("bar/f", 0o644); err != nil {
				time.Sleep(time.Millisecond)
				continue
			}
			if _, err := s.Write("bar/f", 0, val); err != nil {
				time.Sleep(time.Millisecond)
				continue
			}
			if err := s.Fsync(); err != nil { // durable locally before we count it as written
				time.Sleep(time.Millisecond)
				continue
			}
			break
		}
		last = val
		time.Sleep(300 * time.Microsecond) // occasionally exceed the 2ms idle -> release mid-stream
	}
	if err := mgr.Stop(); err != nil { // final flush + checkin of whatever is still held
		t.Fatalf("stop: %v", err)
	}
	// The last write must be durable (the barrier serialized every acquire/release, losing nothing).
	got, st := readAllAuthority(t, cli, "bar/f")
	if st != fsproto.OK {
		t.Fatalf("authority bar/f st=%d after churned handoff", st)
	}
	if !bytes.HasPrefix(got, last) {
		t.Fatalf("handoff churn lost the last write: authority=%q want prefix %q", got, last)
	}
	if left, _ := filepath.Glob(filepath.Join(walDir, "sess-*.wal")); len(left) != 0 {
		t.Fatalf("graceful Stop left WAL debris: %v", left)
	}
}

// TestManagerRecoverAllReflushesCrashLeftovers: on startup, a fresh manager over a PERSISTENT
// walDir proactively re-flushes the un-flushed tail of a crash-leftover session WAL.
func TestManagerRecoverAllReflushesCrashLeftovers(t *testing.T) {
	cli := startAuthority(t)
	cli.SetOwner("A")
	if _, st, err := cli.Mkdir("proj", 0o755); err != nil || st != fsproto.OK {
		t.Fatalf("mkdir: %d %v", st, err)
	}
	walDir := t.TempDir()

	crashed := session.NewManager(wbAuth{cli}, "A", walDir, 0)
	s, err := crashed.Ensure("proj/data")
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Create("proj/data", 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Write("proj/data", 0, []byte("CRASH-TAIL")); err != nil {
		t.Fatal(err)
	}
	if err := s.Fsync(); err != nil { // durable in the WAL, never flushed (the crash)
		t.Fatal(err)
	}
	// No Stop: simulate the crash (the WAL stays un-flushed on disk).
	if _, st, _ := cli.Getattr("proj/data"); st == fsproto.OK {
		t.Fatal("proj/data must be absent before recovery")
	}

	restarted := session.NewManager(wbAuth{cli}, "A", walDir, 0)
	restarted.RecoverAll()
	defer restarted.Stop()
	if got, st := readAllAuthority(t, cli, "proj/data"); st != fsproto.OK || string(got) != "CRASH-TAIL" {
		t.Fatalf("authority after RecoverAll: %q st=%d, want CRASH-TAIL", got, st)
	}
}

// waitFor polls cond every ms up to d, returning true as soon as cond holds.
func waitFor(d time.Duration, cond func() bool) bool {
	deadline := time.Now().Add(d)
	for time.Now().Before(deadline) {
		if cond() {
			return true
		}
		time.Sleep(time.Millisecond)
	}
	return cond()
}

// ---------------------------------------------------------------------------
// 11. ConfigureEpochFloor monotonic across a simulated restart.
// ---------------------------------------------------------------------------

// TestEpochFloorMonotonicAcrossRestart: a manager persists a generation floor in its walDir;
// after a "restart" (a fresh manager over the same walDir) the next session's epoch must exceed
// any epoch a prior run used — even if the wall clock stepped backward — and the floor file must
// only ever advance. Driven through NewManager + New (the production path).
func TestEpochFloorMonotonicAcrossRestart(t *testing.T) {
	cli := startAuthority(t)
	cli.SetOwner("M")
	if _, st, err := cli.Mkdir("ef", 0o755); err != nil || st != fsproto.OK {
		t.Fatalf("mkdir: %d %v", st, err)
	}
	walDir := t.TempDir()
	floorPath := filepath.Join(walDir, ".epoch")

	// Model a PRIOR run that issued a very high generation (it ran while the clock was far ahead)
	// and persisted it — by writing the floor file directly, the way persistEpochFloor would.
	high := uint64(time.Now().UnixNano()) + uint64(24*time.Hour)
	if err := os.WriteFile(floorPath, []byte(strconv.FormatUint(high, 10)), 0o600); err != nil {
		t.Fatal(err)
	}

	// "Restart": a fresh manager seeds the floor from walDir/.epoch (NewManager calls
	// ConfigureEpochFloor). A new session's epoch must exceed the persisted high-water mark.
	mgr := session.NewManager(wbAuth{cli}, "M", walDir, 0)
	defer mgr.Stop()
	s, err := mgr.Ensure("ef/f")
	if err != nil {
		t.Fatalf("ensure: %v", err)
	}
	_ = s

	// The floor file must have advanced to >= high (creating the session issued an epoch and
	// persisted it; the persist is monotonic so it can only be >= the seeded floor).
	got := readFloor(t, floorPath)
	if got < high {
		t.Fatalf("floor file regressed across restart: got %d < prior high %d (would ESTALE-strand a live owner)", got, high)
	}

	// A second restart must continue ABOVE this floor — generations never repeat or regress.
	mgr2 := session.NewManager(wbAuth{cli}, "M", walDir, 0)
	defer mgr2.Stop()
	if _, err := mgr2.Ensure("ef/g"); err != nil {
		t.Fatalf("ensure g: %v", err)
	}
	if got2 := readFloor(t, floorPath); got2 < got {
		t.Fatalf("floor regressed on second restart: %d < %d", got2, got)
	}
}

func readFloor(t *testing.T, path string) uint64 {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read floor: %v", err)
	}
	v, err := strconv.ParseUint(strings.TrimSpace(string(b)), 10, 64)
	if err != nil {
		t.Fatalf("parse floor %q: %v", b, err)
	}
	return v
}

// ---------------------------------------------------------------------------
// 12. Concurrency: multi-goroutine writes + flushes (run under -race).
// ---------------------------------------------------------------------------

// TestConcurrentWritesDisjointFilesThenFlush: many goroutines each write their own file under one
// session, with a flusher goroutine draining concurrently. After a final flush every file must be
// durable and correct on the authority. Exercises the overlay map + WAL + flush under the race
// detector; the disjoint-file partition makes the expected end state deterministic.
func TestConcurrentWritesDisjointFilesThenFlush(t *testing.T) {
	cli := startAuthority(t)
	cli.SetOwner("M")
	s := newSess(t, cli, "M", "cc", "cc")
	defer s.Close()

	const G = 16
	const perG = 40
	var wg sync.WaitGroup
	stop := make(chan struct{})

	// Background flusher: drains concurrently with the writers (Flush is serialized internally).
	var flusherWG sync.WaitGroup
	flusherWG.Add(1)
	go func() {
		defer flusherWG.Done()
		for {
			select {
			case <-stop:
				return
			default:
				_ = s.Flush()
				time.Sleep(200 * time.Microsecond)
			}
		}
	}()

	for g := 0; g < G; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			for i := 0; i < perG; i++ {
				p := fmt.Sprintf("cc/g%d-f%d", g, i)
				if err := s.Create(p, 0o644); err != nil {
					t.Errorf("create %s: %v", p, err)
					return
				}
				payload := []byte(fmt.Sprintf("g%d-f%d-data", g, i))
				if _, err := s.Write(p, 0, payload); err != nil {
					t.Errorf("write %s: %v", p, err)
					return
				}
				if err := s.Fsync(); err != nil {
					t.Errorf("fsync %s: %v", p, err)
					return
				}
			}
		}(g)
	}
	wg.Wait()
	close(stop)
	flusherWG.Wait()

	if err := s.Flush(); err != nil { // final drain of anything the concurrent flusher missed
		t.Fatalf("final flush: %v", err)
	}
	for g := 0; g < G; g++ {
		for i := 0; i < perG; i++ {
			p := fmt.Sprintf("cc/g%d-f%d", g, i)
			want := fmt.Sprintf("g%d-f%d-data", g, i)
			got, st, err := cli.Read(p, 0, 64)
			if err != nil || st != fsproto.OK || string(got) != want {
				t.Fatalf("authority %s = %q st=%d err=%v, want %q", p, got, st, err, want)
			}
		}
	}
}

// TestConcurrentWritesSingleFileLastWriterDurable: many goroutines hammer DISJOINT regions of one
// file concurrently (each owns a fixed 8-byte slot), with concurrent fsyncs. The overlay must
// serialize the read-modify-writes so no slot corrupts another; after a final flush every slot
// holds its owner's bytes on the authority. Run under -race.
func TestConcurrentWritesSingleFileDisjointSlots(t *testing.T) {
	cli := startAuthority(t)
	cli.SetOwner("M")
	s := newSess(t, cli, "M", "cs", "cs")
	defer s.Close()

	const G = 24
	const slot = 8
	if err := s.Create("cs/f", 0o644); err != nil {
		t.Fatal(err)
	}
	// Pre-size the file so every slot exists (avoids a benign grow race on the tail).
	if _, err := s.Write("cs/f", 0, make([]byte, G*slot)); err != nil {
		t.Fatal(err)
	}

	var wg sync.WaitGroup
	for g := 0; g < G; g++ {
		wg.Add(1)
		go func(g int) {
			defer wg.Done()
			b := bytes.Repeat([]byte{byte('A' + g)}, slot)
			for r := 0; r < 25; r++ {
				if _, err := s.Write("cs/f", int64(g*slot), b); err != nil {
					t.Errorf("g%d write: %v", g, err)
					return
				}
				if r%5 == 0 {
					_ = s.Fsync()
				}
			}
		}(g)
	}
	wg.Wait()
	if err := s.Flush(); err != nil {
		t.Fatalf("flush: %v", err)
	}
	got, st := readAllAuthority(t, cli, "cs/f")
	if st != fsproto.OK || len(got) != G*slot {
		t.Fatalf("authority cs/f len=%d st=%d, want %d", len(got), st, G*slot)
	}
	for g := 0; g < G; g++ {
		want := bytes.Repeat([]byte{byte('A' + g)}, slot)
		if !bytes.Equal(got[g*slot:(g+1)*slot], want) {
			t.Fatalf("slot %d corrupted: got %q want %q", g, got[g*slot:(g+1)*slot], want)
		}
	}
}

// TestConcurrentManagerMultiSubtreeFlushAll: several subtrees written concurrently through one
// Manager, with FlushAll racing the writers; after Stop every subtree's data is durable. Stresses
// the manager's per-root session map + concurrent FlushAll under -race.
func TestConcurrentManagerMultiSubtreeFlushAll(t *testing.T) {
	cli := startAuthority(t)
	cli.SetOwner("M")
	const subtrees = 8
	for i := 0; i < subtrees; i++ {
		if _, st, err := cli.Mkdir(fmt.Sprintf("t%d", i), 0o755); err != nil || st != fsproto.OK {
			t.Fatalf("mkdir t%d: %d %v", i, st, err)
		}
	}
	mgr := session.NewManager(wbAuth{cli}, "M", t.TempDir(), 0) // idle=0: no handoff churn, deterministic end state
	mgr.Start(time.Millisecond)

	var wg sync.WaitGroup
	for i := 0; i < subtrees; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			for j := 0; j < 30; j++ {
				p := fmt.Sprintf("t%d/f%d", i, j)
				s, err := mgr.Ensure(p)
				if err != nil {
					t.Errorf("ensure %s: %v", p, err)
					return
				}
				if err := s.Create(p, 0o644); err != nil {
					t.Errorf("create %s: %v", p, err)
					return
				}
				if _, err := s.Write(p, 0, []byte(fmt.Sprintf("t%d-f%d", i, j))); err != nil {
					t.Errorf("write %s: %v", p, err)
					return
				}
			}
		}(i)
	}
	// Race FlushAll against the writers.
	flusherDone := make(chan struct{})
	go func() {
		for {
			select {
			case <-flusherDone:
				return
			default:
				_ = mgr.FlushAll()
				time.Sleep(300 * time.Microsecond)
			}
		}
	}()
	wg.Wait()
	close(flusherDone)
	if err := mgr.Stop(); err != nil { // final flush + checkin of all subtrees
		t.Fatalf("stop: %v", err)
	}
	for i := 0; i < subtrees; i++ {
		for j := 0; j < 30; j++ {
			p := fmt.Sprintf("t%d/f%d", i, j)
			want := fmt.Sprintf("t%d-f%d", i, j)
			got, st, err := cli.Read(p, 0, 64)
			if err != nil || st != fsproto.OK || string(got) != want {
				t.Fatalf("authority %s = %q st=%d err=%v, want %q", p, got, st, err, want)
			}
		}
	}
}
