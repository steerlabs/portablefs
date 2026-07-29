package pfj3

import (
	"path/filepath"
	"testing"
	"time"

	"github.com/steerlabs/portablefs/vcs/internal/pfc2"
	"github.com/steerlabs/portablefs/vcs/internal/wal"
)

func openFileLog(t *testing.T, path string) *FileEntryLog {
	t.Helper()
	w, err := wal.Open(path)
	if err != nil {
		t.Fatalf("open wal: %v", err)
	}
	t.Cleanup(func() { _ = w.Close() })
	f, err := NewFileEntryLog(w)
	if err != nil {
		t.Fatalf("open file entry log: %v", err)
	}
	return f
}

func sessionOpenEntry(t *testing.T, f *FileEntryLog, id string, gen uint64) (JournalEntry, int64) {
	t.Helper()
	ref := pfc2.SessionRef{SessionID: id, Generation: gen}
	issued, err := f.IssueAdmissionFact(pfc2.FactScope{
		Session: ref, Purpose: pfc2.FactPurposeSessionOpen, PriorDbTimeFloorMs: f.floor,
	})
	if err != nil {
		t.Fatalf("issue fact: %v", err)
	}
	var token [pfc2.TokenHashBytes]byte
	token[0] = 1
	open, err := pfc2.NewSessionOpenRecord(ref, "owner-"+id, token, 8, issued.Fact, 90*time.Second)
	if err != nil {
		t.Fatalf("build session open: %v", err)
	}
	return JournalEntry{Controls: []pfc2.Record{*open}}, issued.Fact.DbMs
}

// TestFileEntryLogCrashReplayRecoversEntriesAndFloor pins the harness-backend
// contract: committed entries (controls and tree arms) replay identically
// from the file after a reopen, the LSN space continues where it left off,
// and the durable fact floor is recovered from the replayed manifests.
func TestFileEntryLogCrashReplayRecoversEntriesAndFloor(t *testing.T) {
	path := filepath.Join(t.TempDir(), "authority.wal")
	f := openFileLog(t, path)

	open, factDbMs := sessionOpenEntry(t, f, "pfs-file-1", 1)
	tree := JournalEntry{Tree: &wal.Record{Op: wal.OpCreate, Path: "a.txt", Mode: 0o644}}
	first, end, err := f.AppendEntriesBuffered([]JournalEntry{open, tree})
	if err != nil {
		t.Fatalf("append: %v", err)
	}
	if first != 0 || end != 2 {
		t.Fatalf("reserved [%d,%d), want [0,2)", first, end)
	}
	if err := f.CommitThrough(end - 1); err != nil {
		t.Fatalf("commit: %v", err)
	}

	// Reopen the SAME file (the crash path: nothing was closed cleanly).
	re := openFileLog(t, path)
	if re.floor != factDbMs {
		t.Fatalf("recovered floor = %d, want the consumed fact's DbMs %d", re.floor, factDbMs)
	}
	var got []JournalEntry
	if err := re.ReplayEntriesInto(func(e JournalEntry) error {
		got = append(got, e)
		return nil
	}); err != nil {
		t.Fatalf("replay: %v", err)
	}
	if len(got) != 2 || got[0].LSN != 0 || got[1].LSN != 1 {
		t.Fatalf("replayed %d entries (%+v), want 2 contiguous", len(got), got)
	}
	if len(got[0].Controls) != 1 || got[0].Controls[0].Kind != pfc2.KindSessionOpen {
		t.Fatalf("entry 0 lost its control arm: %+v", got[0])
	}
	if got[1].Tree == nil || got[1].Tree.Path != "a.txt" || got[1].Tree.Seq != 1 {
		t.Fatalf("entry 1 lost its tree arm: %+v", got[1])
	}

	// The LSN space continues from the replayed tail.
	next, _, err := re.AppendEntriesBuffered([]JournalEntry{
		{Tree: &wal.Record{Op: wal.OpMkdir, Path: "d", Mode: 0o755}},
	})
	if err != nil {
		t.Fatalf("append after reopen: %v", err)
	}
	if next != 2 {
		t.Fatalf("append after reopen reserved LSN %d, want 2", next)
	}
}

// TestFileEntryLogFactContractFailsClosed pins the issue/consume rules: a
// stale issuer floor refuses issuance, and a consumed fact never validates a
// second entry.
func TestFileEntryLogFactContractFailsClosed(t *testing.T) {
	path := filepath.Join(t.TempDir(), "authority.wal")
	f := openFileLog(t, path)

	ref := pfc2.SessionRef{SessionID: "pfs-file-2", Generation: 1}
	if _, err := f.IssueAdmissionFact(pfc2.FactScope{
		Session: ref, Purpose: pfc2.FactPurposeSessionOpen, PriorDbTimeFloorMs: f.floor + 5,
	}); err == nil {
		t.Fatal("a stale issuer floor must refuse issuance")
	}

	open, _ := sessionOpenEntry(t, f, "pfs-file-2", 1)
	if _, _, err := f.AppendEntriesBuffered([]JournalEntry{open}); err != nil {
		t.Fatalf("first consume: %v", err)
	}
	// The same control (same frozen fact) must never journal twice.
	if _, _, err := f.AppendEntriesBuffered([]JournalEntry{open}); err == nil {
		t.Fatal("a consumed admission fact must not validate a second entry")
	}
}
