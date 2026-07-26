package session

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/trendup-ai/portablefs/vcs/internal/wal"
)

type noApplyRecoveryAuthority struct {
	flushes  int
	checkins int
}

func (a *noApplyRecoveryAuthority) Checkout(path, owner string) (bool, string, CheckoutGrant, error) {
	return true, "", CheckoutGrant{}, nil
}

func (a *noApplyRecoveryAuthority) Checkin(path, owner string, _ CheckoutGrant) error {
	a.checkins++
	return nil
}

func (a *noApplyRecoveryAuthority) Read(path string, off, length int64) ([]byte, int32, error) {
	return nil, 2, nil
}

func (a *noApplyRecoveryAuthority) Stat(path string) (string, uint32, int32, error) {
	return "", 0, 2, nil
}

func (a *noApplyRecoveryAuthority) Readlink(path string) (string, int32, error) {
	return "", 2, nil
}

func (a *noApplyRecoveryAuthority) FlushBatch(sessionID string, epoch uint64, owner string, _ CheckoutGrant, records []wal.Record) (uint64, int32, error) {
	a.flushes++
	if len(records) == 0 {
		return 0, statusOK, nil
	}
	return records[len(records)-1].Seq, statusOK, nil
}

func TestCrashRecoveryPreservesWALWhenFlushOKDoesNotMaterializeRecords(t *testing.T) {
	walPath := filepath.Join(t.TempDir(), "sess-R-root.wal")
	w, err := wal.Open(walPath)
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range []wal.Record{
		{Op: wal.OpCreate, Path: "lost.txt", Mode: 0o644},
		{Op: wal.OpWrite, Path: "lost.txt", Offset: 0, Data: []byte("must-stay")},
	} {
		if _, err := w.AppendBuffered(r); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.CommitThrough(1); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}

	auth := &noApplyRecoveryAuthority{}
	s, err := New(auth, "R", "R-root", "", walPath)
	if err == nil {
		_ = s.Close()
		t.Fatal("recovery succeeded even though the authority OK did not materialize recovered records")
	}
	if !strings.Contains(err.Error(), "verify recovered") {
		t.Fatalf("recovery error=%v, want verification failure", err)
	}
	if auth.flushes != 2 {
		t.Fatalf("flushes=%d, want 2 (initial recovery attempt plus fresh-epoch retry)", auth.flushes)
	}
	if auth.checkins != 1 {
		t.Fatalf("checkins=%d, want 1", auth.checkins)
	}
	info, err := os.Stat(walPath)
	if err != nil {
		t.Fatal(err)
	}
	if info.Size() == 0 {
		t.Fatal("recovery compacted the WAL to 0 bytes after an unverified OK")
	}
	reopen, err := wal.Open(walPath)
	if err != nil {
		t.Fatal(err)
	}
	defer reopen.Close()
	recs, err := reopen.Replay()
	if err != nil {
		t.Fatal(err)
	}
	if len(recs) != 2 || recs[0].Op != wal.OpCreate || recs[1].Op != wal.OpWrite || string(recs[1].Data) != "must-stay" {
		t.Fatalf("preserved WAL records = %+v, want create+write tail", recs)
	}
}
