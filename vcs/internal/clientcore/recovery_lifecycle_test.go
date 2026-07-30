package clientcore

import (
	"context"
	"errors"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/steerlabs/portablefs/vcs/internal/fsproto"
)

func TestAttachCancellationTerminatesLostRebindBeforeStoreUnlock(t *testing.T) {
	addr, server := serveCoreServer(t)
	var dropRebind atomic.Bool
	var rebindRequests atomic.Int32
	rebindSeen := make(chan struct{}, 1)
	// Install one immutable hook before the first client. Tests switch its
	// behavior through atomics so server connection goroutines never race a
	// hook replacement.
	server.SetDropReply(func(req *fsproto.Request, _ *fsproto.Response) bool {
		if req.Op != fsproto.OpWritebackRebind || !dropRebind.Load() {
			return false
		}
		rebindRequests.Add(1)
		select {
		case rebindSeen <- struct{}{}:
		default:
		}
		return true
	})

	walDir := t.TempDir()
	opts := Options{
		Addr: addr, Pool: 4, Owner: "recovery-cancel",
		VolumeID: "recovery-cancel", Branch: "main", WALDir: walDir,
	}
	v1, err := Dial(context.Background(), opts)
	if err != nil {
		t.Fatalf("first attach: %v", err)
	}
	if _, st := v1.Mkdir(context.Background(), "d", 0o755); st != fsproto.OK {
		t.Fatalf("mkdir: %d", st)
	}
	if _, st := v1.Create(context.Background(), "d/file", 0o644); st != fsproto.OK {
		t.Fatalf("create: %d", st)
	}
	if !v1.wb.Covers("d/file") {
		t.Fatal("precondition: create did not install a delegation")
	}
	if jobID, err := v1.CloseJournalDurable(); err != nil || jobID == "" {
		t.Fatalf("park first stream: job=%q err=%v", jobID, err)
	}

	dropRebind.Store(true)
	attachCtx, cancelAttach := context.WithCancel(context.Background())
	attachOut := make(chan error, 1)
	go func() {
		v, err := Dial(attachCtx, opts)
		if v != nil {
			_, _ = v.CloseJournalDurable()
			attachOut <- errors.New("cancelled attach returned a live Volume")
			return
		}
		attachOut <- err
	}()
	select {
	case <-rebindSeen:
	case <-time.After(5 * time.Second):
		cancelAttach()
		t.Fatal("recovery Rebind did not reach the lost-reply seam")
	}

	// The unresolved exact transition still owns the store lock. A racing
	// opener must be rejected before it can inspect or mutate recovery state.
	if raced, err := Dial(context.Background(), opts); err == nil {
		_, _ = raced.CloseJournalDurable()
		cancelAttach()
		t.Fatal("racing attach acquired the recovery store before Rebind terminated")
	} else if !strings.Contains(err.Error(), "owned by another engine") {
		cancelAttach()
		t.Fatalf("racing attach failed for the wrong reason: %v", err)
	}

	cancelAttach()
	select {
	case err := <-attachOut:
		if !errors.Is(err, context.Canceled) {
			t.Fatalf("cancelled attach error = %v, want context.Canceled", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("attach cancellation did not Abort and join the unresolved Rebind")
	}
	afterReturn := rebindRequests.Load()
	time.Sleep(100 * time.Millisecond)
	if got := rebindRequests.Load(); got != afterReturn {
		t.Fatalf("Rebind kept running after attach returned: requests %d -> %d", afterReturn, got)
	}

	// The first Rebind committed before every reply was lost. A fresh opener
	// must take the released lock, fence/rebind that holder, and recover without
	// manufacturing HOLDER_CHANGED or DIGEST_MISMATCH.
	dropRebind.Store(false)
	v3, err := Dial(context.Background(), opts)
	if err != nil {
		t.Fatalf("fresh attach after cancelled lost Rebind: %v", err)
	}
	defer func() { _ = v3.Close() }()
	if jobs := v3.RecoveryJobs(); len(jobs) != 0 {
		t.Fatalf("fresh attach false-conflicted after cancelled Rebind: %+v", jobs)
	}
}
