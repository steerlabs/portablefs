package writeback

// ROUND 21b: A CAPACITY REFUSAL FENCED THE ENTIRE MOUNT.
//
// docs/self-hosting.md promises, of the VCS_DIRTY_RSS_MAX_MB bound:
//
//	"Writes past the bound refuse with ENOSPC; reads, truncates, and metadata
//	 operations always keep working."
//
// What a live mount delivered at the bound was `ls` EIO, `stat` EIO, `read`
// EIO, `mkdir` EIO — every path of the volume, until remount. The chain:
//
//	workfs.ErrDirtyRSSCapacity -> fsproto status 28 -> the flusher's capacity
//	arm -> f.park -> Engine.markStreamDead -> Engine.failClosed, which latches
//	ErrFailedClosed for the mount's LIFETIME.
//
// ErrFailedClosed is not a write gate. clientcore's beginExactOperation asks
// for it in front of the exact-handle READ, GETATTR and GETXATTR paths, and
// Engine.Truncate asks for it too — so the fence took the reads, the metadata
// AND the operator's documented remedy (truncate to hand the authority's dirty
// blocks back) with it. The design comment directly above the capacity arm said
// the point was "letting the application see ENOSPC"; the delivered behaviour
// was the opposite of every clause of the promise.
//
// These tests state the promise as an executable contract, and they state the
// other half too: the conditions that SHOULD fence still fence.

import (
	"context"
	"errors"
	"testing"
	"time"
)

// TestCapacityRefusalDoesNotFenceReadsMetadataOrTruncate is the round-21b
// contract. Every assertion here failed on aad03e9.
func TestCapacityRefusalDoesNotFenceReadsMetadataOrTruncate(t *testing.T) {
	e, _ := newStatusFixture(t, 28) // ENOSPC from the authority's bounded store
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()

	// Drive the engine to the refusal.
	if err := e.DrainAll(ctx); !errors.Is(err, ErrNoSpace) {
		t.Fatalf("drain under a capacity refusal = %v, want ErrNoSpace", err)
	}

	// ── THE MOUNT IS NOT FENCED ──────────────────────────────────────────────
	//
	// This single assertion is the whole defect. MutationError is what
	// clientcore's beginExactOperation consults, so a non-nil value here IS
	// `stat` EIO and `read` EIO on every path of the volume.
	if err := e.MutationError(); err != nil {
		t.Fatalf("REPRO: a capacity refusal fail-closed the engine: %v\n"+
			"ErrFailedClosed gates clientcore's exact-handle read/getattr/getxattr "+
			"paths and Truncate, so this is `ls`/`stat`/`read` EIO on the whole "+
			"mount for a condition POSIX calls ENOSPC", err)
	}

	// ── READS KEEP WORKING ───────────────────────────────────────────────────
	permit, err := e.BeginRead(ctx, "d/f")
	if err != nil {
		t.Fatalf("REPRO: read admission refused under a capacity refusal: %v", err)
	}
	ent, result := permit.Lookup("d/f")
	permit.Close()
	if result != LookupHit {
		t.Fatalf("read view lost the file under a capacity refusal: result=%v", result)
	}
	if ent.Size == 0 {
		t.Fatalf("read view reports an empty file; the acknowledged bytes are gone")
	}

	// ── THE RELEASING OPERATION KEEPS WORKING ────────────────────────────────
	//
	// Truncate is the remedy the product documents for exactly this condition:
	// it is what hands the authority's resident dirty blocks back. A remedy
	// refused by the condition it remedies is not a remedy.
	//
	// (rm is deliberately NOT the remedy: on a managed authority an unlinked
	// inode parks until reap, so it releases nothing. It is admitted below
	// because it is a metadata operation, not because it frees anything.)
	if _, handled, err := e.Truncate(ctx, "d/f", 0); err != nil {
		t.Fatalf("REPRO: truncate refused under a capacity refusal (handled=%v): %v\n"+
			"this is the operator's documented escape from the dirty-RSS bound", handled, err)
	}

	// ── METADATA KEEPS WORKING ───────────────────────────────────────────────
	if _, handled, err := e.Mkdir(ctx, "d/sub", 0o755); err != nil {
		t.Fatalf("REPRO: mkdir refused under a capacity refusal (handled=%v): %v", handled, err)
	}
	if _, handled, err := e.Setattr(ctx, "d/f", SetattrRequest{SetMode: true, Mode: 0o600}); err != nil {
		t.Fatalf("REPRO: chmod refused under a capacity refusal (handled=%v): %v", handled, err)
	}

	// ── WRITES GET A DEFINITE ENOSPC ─────────────────────────────────────────
	//
	// handled=true matters as much as the errno: an unhandled refusal falls
	// through to the authority lane and the application learns nothing.
	_, handled, werr := e.WriteAt(ctx, "d/f", 0, []byte("more"))
	if !handled {
		t.Fatalf("a refused write fell through to the authority lane; the "+
			"application never sees the refusal (err=%v)", werr)
	}
	if !errors.Is(werr, ErrNoSpace) {
		t.Fatalf("write under a capacity refusal = %v, want ErrNoSpace (ENOSPC)", werr)
	}
	if _, _, werr := e.WriteAppend(ctx, "d/f", []byte("more")); !errors.Is(werr, ErrNoSpace) {
		t.Fatalf("append under a capacity refusal = %v, want ErrNoSpace (ENOSPC)", werr)
	}

	// ── AND IT IS REPORTED AS CAPACITY, NOT AS A DEAD UPLINK ─────────────────
	//
	// Stalled means "the far end stopped answering", and every admission gate
	// relays it as the EIO-class answer. The far end here is answering promptly
	// with a verdict this client already holds.
	if v := e.StallVerdict(); v.Stalled {
		t.Fatalf("a capacity refusal was reported as a stalled uplink; that " +
			"replaces the definite ENOSPC with EIO one layer up")
	}
	if st := e.Status(); !st.CapacityRefused {
		t.Fatalf("Status does not report the capacity refusal: %+v", st)
	}
}

// TestCapacityRefusalIsRelievedByTheAuthority states the other half of "not
// terminal": the refusal is a statement about the AUTHORITY's occupancy, and
// when the authority applies a batch it has disproved it. Round 19 gave the
// authority exactly that release path (history-cut adoption folds the dirty
// pool), so a mount must un-refuse itself rather than requiring a remount.
func TestCapacityRefusalIsRelievedByTheAuthority(t *testing.T) {
	auth := newFakeAuthority()
	auth.mu.Lock()
	auth.dirs["d"] = true
	auth.mu.Unlock()
	remote := &statusRemote{fakeAuthority: auth, status: 28}
	e, err := Open(context.Background(), Config{
		StateDir: t.TempDir(), VolumeID: "vol", Branch: "main", Remote: remote,
		BudgetBytes: 1 << 30,
	})
	if err != nil {
		t.Fatalf("open engine: %v", err)
	}
	t.Cleanup(func() { _, _ = e.ForceClose("test teardown") })
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()

	if _, handled, err := e.Create(ctx, "d/f", 0o644, false, false); err != nil || !handled {
		t.Fatalf("create: handled=%v err=%v", handled, err)
	}
	if _, handled, err := e.WriteAt(ctx, "d/f", 0, []byte("payload")); err != nil || !handled {
		t.Fatalf("write: handled=%v err=%v", handled, err)
	}
	if err := e.DrainAll(ctx); !errors.Is(err, ErrNoSpace) {
		t.Fatalf("drain under a capacity refusal = %v, want ErrNoSpace", err)
	}
	if e.CapacityRefusal() == nil {
		t.Fatalf("the capacity refusal did not latch")
	}

	// The authority folds its dirty pool and starts applying again.
	remote.setStatus(0)
	if err := e.DrainAll(ctx); err != nil {
		t.Fatalf("REPRO: the stream never drained after the authority released: %v\n"+
			"a capacity refusal that no authority recovery can clear makes remount "+
			"the only exit from a relievable condition", err)
	}
	if cerr := e.CapacityRefusal(); cerr != nil {
		t.Fatalf("the capacity refusal survived the authority applying a batch: %v", cerr)
	}
	if _, handled, err := e.WriteAt(ctx, "d/f", 0, []byte("again")); err != nil || !handled {
		t.Fatalf("writes were not re-admitted after relief: handled=%v err=%v", handled, err)
	}
}

// TestGenuineFailClosedStillFencesTheMount is the guard on the other side. The
// capacity split must not weaken the conditions that SHOULD fence: a fence
// (ESTALE) and a proven contradiction about the batch's own content (EINVAL
// typed corruption, EPERM out-of-subtree) are statements that the stream can
// never be drained by anyone, and sealing the mount is the honest answer.
func TestGenuineFailClosedStillFencesTheMount(t *testing.T) {
	for _, tc := range []struct {
		name   string
		status int32
	}{
		{"ESTALE: the authority fenced the stream", 116},
		{"EINVAL: typed writeback corruption", 22},
		{"EPERM: records outside the granted subtree", 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e, _ := newStatusFixture(t, tc.status)
			ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancel()
			if err := e.DrainAll(ctx); err == nil {
				t.Fatalf("status %d drained successfully; the fixture never applies", tc.status)
			}
			if err := e.MutationError(); !errors.Is(err, ErrFailedClosed) {
				t.Fatalf("status %d left MutationError = %v; a proven contradiction "+
					"about the stream must still fail the engine closed", tc.status, err)
			}
			if cerr := e.CapacityRefusal(); cerr != nil {
				t.Fatalf("status %d was misreported as a capacity refusal: %v", tc.status, cerr)
			}
		})
	}
}
