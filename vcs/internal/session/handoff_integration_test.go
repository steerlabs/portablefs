package session_test

import (
	"bytes"
	"context"
	"net"
	"path/filepath"
	"testing"
	"time"

	"github.com/steerlabs/portablefs/vcs/internal/delegation"
	"github.com/steerlabs/portablefs/vcs/internal/fsproto"
	"github.com/steerlabs/portablefs/vcs/internal/session"
	"github.com/steerlabs/portablefs/vcs/internal/wal"
	"github.com/steerlabs/portablefs/vcs/internal/workfs"
)

// startAuthorityAddr starts ONE in-process authority and returns its address so SEVERAL clients
// (separate mounts) can connect to the same volume — needed to model a real cross-mount handoff.
func startAuthorityAddr(t *testing.T) string {
	t.Helper()
	w, err := wal.Open(filepath.Join(t.TempDir(), "auth.wal"))
	if err != nil {
		t.Fatal(err)
	}
	fs, err := workfs.New(nil, nopBlobs{}, w)
	if err != nil {
		t.Fatal(err)
	}
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	go func() { _ = fsproto.NewServer(fs, fs, delegation.New()).Serve(ctx, ln) }()
	return ln.Addr().String()
}

// TestSQLiteHandoffPatternNoLoss models the failing e2e: mount A writes a "DB" via the SQLite
// DELETE-journal pattern (per txn: create/write/remove the -journal, overwrite a DB page) then
// idle-releases; mount B acquires (adopts), does the same, idle-releases; the durable authority
// state must then EXACTLY equal a flat-array application of every DB write — no rows lost to the
// background-flush / idle-release / adopt machinery. Deterministic, no Docker.
func TestSQLiteHandoffPatternNoLoss(t *testing.T) {
	addr := startAuthorityAddr(t)
	mkCli := func() *fsproto.Client {
		c, err := fsproto.Dial(addr, 4)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = c.Close() })
		return c
	}
	admin := mkCli()
	admin.SetOwner("admin")
	if _, st, err := admin.Mkdir("ws", 0o755); err != nil || st != fsproto.OK {
		t.Fatalf("mkdir ws: st=%d err=%v", st, err)
	}

	const idle = 50 * time.Millisecond
	const flush = 12 * time.Millisecond
	mgrA := session.NewManager(wbAuth{mkCli()}, "A", t.TempDir(), idle)
	mgrB := session.NewManager(wbAuth{mkCli()}, "B", t.TempDir(), idle)
	mgrA.Start(flush)
	mgrB.Start(flush)
	defer mgrA.Stop()
	defer mgrB.Stop()

	const page = 4096
	const npages = 4
	ref := make([]byte, 0)
	applyRef := func(off int64, data []byte) {
		end := off + int64(len(data))
		if int64(len(ref)) < end {
			ref = append(ref, make([]byte, end-int64(len(ref)))...)
		}
		copy(ref[off:end], data)
	}
	// One SQLite-like transaction: journal create/write, a DB page overwrite, journal remove.
	txn := func(mgr *session.Manager, i int) error {
		s, err := mgr.Ensure("ws/app.db")
		if err != nil {
			return err
		}
		_ = s.Create("ws/app.db", 0o644) // SQLite opens the DB with O_CREAT every txn (idempotent / adopt)
		_ = s.Create("ws/app.db-journal", 0o644)
		if _, err := s.Write("ws/app.db-journal", 0, bytes.Repeat([]byte{0x5a}, 512)); err != nil {
			return err
		}
		off := int64((i % npages) * page)
		data := bytes.Repeat([]byte{byte(i + 1)}, page)
		if _, err := s.Write("ws/app.db", off, data); err != nil {
			return err
		}
		_ = s.Remove("ws/app.db-journal")
		applyRef(off, data)
		return nil
	}
	runTxns := func(mgr *session.Manager, start, n int) {
		for i := start; i < start+n; i++ {
			for { // retry while contending for the checkout (handoff in progress)
				if err := txn(mgr, i); err == nil {
					break
				}
				time.Sleep(2 * time.Millisecond)
			}
			// Real agents run each txn as a SEPARATE process with variable gaps. When a gap exceeds
			// the idle window the session releases mid-stream and the next txn re-acquires + adopts.
			if i%9 == 0 {
				time.Sleep(3 * idle) // gap > idle: idle-release, then the next txn re-acquires
			} else {
				time.Sleep(time.Millisecond)
			}
		}
	}

	runTxns(mgrA, 0, 100)
	time.Sleep(4 * idle) // A goes idle → flush + release
	runTxns(mgrB, 100, 100)
	time.Sleep(4 * idle) // B goes idle → flush + release

	got, st, err := admin.Read("ws/app.db", 0, 1<<20)
	if err != nil || st != fsproto.OK {
		t.Fatalf("read app.db: st=%d err=%v", st, err)
	}
	if !bytes.Equal(got, ref) {
		first := -1
		for i := 0; i < len(ref) && i < len(got); i++ {
			if got[i] != ref[i] {
				first = i
				break
			}
		}
		t.Fatalf("HANDOFF LOST DATA: durable len=%d want=%d; first diff at byte %d (page %d): got=%d want=%d",
			len(got), len(ref), first, first/page, byteAt(got, first), byteAt(ref, first))
	}
}

func byteAt(b []byte, i int) int {
	if i < 0 || i >= len(b) {
		return -1
	}
	return int(b[i])
}
