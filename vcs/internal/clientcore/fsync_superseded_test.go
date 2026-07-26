package clientcore

import (
	"context"
	"testing"

	"github.com/trendup-ai/portablefs/vcs/internal/fsproto"
	"github.com/trendup-ai/portablefs/vcs/internal/wal"
)

// TestFsyncAuthorityErrorsOnSupersededSession pins m1: with fsync=authority, a fsync on a
// superseded/fenced session must return an error (EIO to the frontend), never success. A superseded
// session's Flush short-circuits to a no-op returning nil, so its records never reached the authority;
// reporting durable success would be a false guarantee (the force-revoke residual).
func TestFsyncAuthorityErrorsOnSupersededSession(t *testing.T) {
	addr := serveCore(t)
	ctx := context.Background()
	v := dialCore(t, addr, Options{
		Owner:       "M",
		WriteBack:   true,
		WALDir:      t.TempDir(),
		FsyncPolicy: FsyncAuthority,
	})

	a, st := v.Create(ctx, "f", 0o644)
	if st != fsproto.OK {
		t.Fatalf("create: %d", st)
	}
	n := NewNodeState(a.Ino, a.Ino != 0)
	if _, st := v.Write(ctx, "f", n, 0, []byte("FIRST")); st != fsproto.OK {
		t.Fatalf("write: %d", st)
	}
	if err := v.FlushToAuthority(ctx); err != nil { // establish the watermark at this session's epoch
		t.Fatalf("initial flush: %v", err)
	}

	sess := v.Sessions().For("f")
	if sess == nil {
		t.Fatal("no session covers f")
	}
	// A newer generation of the SAME SessionID bumps the authority watermark to a far-higher epoch,
	// so this session's next flush is rejected (ESTALE) and the session marks itself superseded.
	if _, bst, err := v.Client().FlushBatch(sess.ID(), 1<<62, "M", []wal.Record{
		{Seq: 0, Op: wal.OpCreate, Path: "g", Mode: 0o644},
	}); err != nil || bst != fsproto.OK {
		t.Fatalf("watermark bump: st=%d err=%v", bst, err)
	}

	// Write more, then drive the transition: this flush is rejected and sets superseded=true.
	if _, st := v.Write(ctx, "f", n, 5, []byte("MORE")); st != fsproto.OK {
		t.Fatalf("second write: %d", st)
	}
	_ = v.FsyncPath("f") // transition flush (rejected); may already report EIO
	if !sess.IsSuperseded() {
		t.Fatal("session should be superseded after a stale flush")
	}

	// The KEY assertion: a fsync on the now-superseded session (whose Flush is a silent no-op) must
	// still return EIO, not success.
	if st := v.FsyncPath("f"); st != fsproto.EIO {
		t.Fatalf("fsync=authority on a superseded session must EIO, got %d", st)
	}
}
