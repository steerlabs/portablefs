package session_test

import (
	"fmt"
	"path/filepath"
	"testing"

	"github.com/trendup-ai/portablefs/vcs/internal/fsproto"
	"github.com/trendup-ai/portablefs/vcs/internal/session"
)

// TestSessionChunkedFlush: a backlog larger than maxFlushBatch (512) flushes correctly as
// several bounded batches — every record lands on the authority across chunk boundaries.
func TestSessionChunkedFlush(t *testing.T) {
	cli := startAuthority(t)
	cli.SetOwner("M")
	if _, st, err := cli.Mkdir("big", 0o755); err != nil || st != fsproto.OK {
		t.Fatalf("mkdir big: %d %v", st, err)
	}
	sess, err := session.New(wbAuth{cli}, "M", "big", "big", filepath.Join(t.TempDir(), "big.wal"))
	if err != nil {
		t.Fatal(err)
	}
	defer sess.Close()

	const num = 600 // 600 files × (create+write) = 1200 records > 512 → 3 chunks
	for i := 0; i < num; i++ {
		p := fmt.Sprintf("big/f%d", i)
		if err := sess.Create(p, 0o644); err != nil {
			t.Fatalf("create %s: %v", p, err)
		}
		if _, err := sess.Write(p, 0, []byte(fmt.Sprintf("v%d", i))); err != nil {
			t.Fatalf("write %s: %v", p, err)
		}
	}
	if err := sess.Flush(); err != nil {
		t.Fatalf("chunked flush: %v", err)
	}
	// Spot-check across chunk boundaries (chunks are 512,512,176 records ≈ 256,256,88 files).
	for _, i := range []int{0, 255, 256, 511, 512, 599} {
		p := fmt.Sprintf("big/f%d", i)
		got, st, _ := cli.Read(p, 0, 64)
		want := fmt.Sprintf("v%d", i)
		if st != fsproto.OK || string(got) != want {
			t.Fatalf("authority %s = %q st=%d, want %q (chunked flush dropped a record?)", p, got, st, want)
		}
	}
}
