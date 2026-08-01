package portablefsd

import (
	"context"
	"errors"
	"testing"

	"github.com/steerlabs/portablefs/vcs/internal/fsproto"
	"github.com/steerlabs/portablefs/vcs/internal/pfslocal"
)

// A write reply has two halves and they do not fail together.
//
// `Written` is the POSIX outcome of the write: once the bytes are committed it
// is decided, and nothing that happens afterwards may change it. `Attr` is a
// cache fill for the frontend, refreshed after the fact by operations that can
// fail on their own terms — an attribute round trip, a registry lookup, the
// binding journal.
//
// Collapsing the two is not a cosmetic bug. The daemon replies with either a
// body or an errno, so a post-commit failure that returns an errno tells the
// application "this write did nothing" about bytes that are already in the WAL.
// A libc that retries — which is exactly what an application does with a
// failed write — reissues them. On an O_APPEND descriptor the retry cannot
// overwrite the first copy, because the offset is resolved at EOF each time, so
// the file ends up with the data TWICE. Silent duplication in an append-only
// log is the worst outcome the write path can produce, and it is reachable from
// a transient disk error that has nothing to do with the write.
//
// These tests pin the split: committed progress survives every post-commit
// failure, and no new item identity is published across one.

// failingBindingJournal is a binding journal on a device that cannot write.
// The binding journal is the post-commit step with real teeth: its own contract
// (see bindingJournal.append) makes a failed append a correctness failure that
// fails the frontend gate closed, so it is the strongest case for "the reply
// must still be truthful about the bytes".
func failingBindingJournal(t *testing.T, a *attach) {
	t.Helper()
	j := newBindingJournal(t.TempDir())
	j.testWrite = func([]byte) (int, error) {
		return 0, errors.New("binding journal device failure")
	}
	a.journal = j
	// A binding delta buffered by an earlier operation. flushBindingDelta is
	// called by whichever operation comes next, so this write is the one that
	// carries it — and the one whose reply the failure would destroy.
	a.pendingBindings = append(a.pendingBindings, bindingJournalEntry{
		Op: "bind", Path: delegatedPath, ID: 101, Gen: 1,
	})
}

func TestCommittedWriteSurvivesAPostCommitFailure(t *testing.T) {
	f := newWriteCreditFixture(t)
	f.releaseLane()
	ctx := context.Background()

	payload := []byte("committed-bytes")
	failingBindingJournal(t, f.a)

	rep, eno := f.a.write(ctx, &pfslocal.WriteRequest{
		Handle: delegatedHandle,
		Data:   payload,
	})
	if eno != 0 {
		t.Fatalf("write reported errno %d for %d bytes it had already committed; "+
			"an application retries this and duplicates them", eno, len(payload))
	}
	if rep == nil {
		t.Fatal("write returned no reply for a committed write")
	}
	if int(rep.Written) != len(payload) {
		t.Fatalf("Written=%d, want the %d committed bytes", rep.Written, len(payload))
	}
}

// TestCommittedAppendIsNeverDuplicatedByAPostCommitFailure is the same defect
// in the lane where it corrupts data rather than merely misreporting it. The
// append commits, the reply is destroyed, the application retries, and O_APPEND
// resolves EOF a second time — so the bytes land twice and no layer can tell
// they were meant to be one write.
func TestCommittedAppendIsNeverDuplicatedByAPostCommitFailure(t *testing.T) {
	f := newWriteCreditFixture(t)
	f.releaseLane()
	ctx := context.Background()

	payload := []byte("append-once")
	failingBindingJournal(t, f.a)

	rep, eno := f.a.write(ctx, &pfslocal.WriteRequest{
		Handle: delegatedHandle,
		Data:   payload,
		Append: true,
	})
	if eno != 0 || rep == nil || int(rep.Written) != len(payload) {
		t.Fatalf("append reply rep=%v eno=%d, want %d bytes written; "+
			"a retry of this append duplicates the record", rep, eno, len(payload))
	}

	// The bytes are in the file exactly once — the reply told the truth, so no
	// retry was invited.
	h := f.a.handles[delegatedHandle]
	got, st := f.vol.ReadOpenHandle(ctx, delegatedPath, h.state, 0, 4096)
	if st != fsproto.OK {
		t.Fatalf("read back: %d", st)
	}
	if len(got) != len(payload) {
		t.Fatalf("file holds %d bytes (%q), want exactly the %d appended once",
			len(got), got, len(payload))
	}
}
