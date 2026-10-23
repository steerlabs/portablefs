//go:build linux

package fusev3

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/hanwen/go-fuse/v2/fuse"
	"github.com/steerlabs/portablefs/vcs/internal/workspaceadmission"
	"github.com/steerlabs/portablefs/vcs/internal/writeback"
)

type clockAdmissionFlusher struct{}

func (clockAdmissionFlusher) FlushBatchSize() (int, int) { return 1, 4096 }
func (clockAdmissionFlusher) FlushBatch(context.Context, writeback.Identity, []writeback.Entry) ([]uint64, error) {
	return nil, errors.New("test keeps capacity owned")
}

func TestWorkspaceClockDeniesEntryBeforeRootObservation(t *testing.T) {
	f := newStockFixture(t)
	f.lookup(t, 1, "cached")
	bindWorkspaceTestGate(t, f.mount)
	clock := &workspaceTestClockOwner{}
	f.mount.workspaceLifecycle = &workspaceLifecycle{clock: clock}
	clock.unavailable.Store(true)
	if _, err := f.mount.workspace.Check(); err != nil {
		t.Fatal("test root already closed", err)
	}
	calls := f.rpcCalls()
	unique := f.unique.Add(2)
	status := closedWorkspaceCall(t, f.mount, func() fuse.Status {
		return testEntryFileSystem(f.raw).Lookup(nil, &fuse.InHeader{Unique: unique, NodeId: 1}, "cached", &fuse.EntryOut{})
	})
	if status != fuse.EIO || f.rpcCalls() != calls || f.raw.ReplyWriteTracked(unique) || f.mount.workspaceServing() {
		t.Fatal("unavailable shared clock admitted an answer before root observation", status)
	}
}

func TestWorkspaceClockDeniesCapacityWaitBeforeRootObservation(t *testing.T) {
	for _, kind := range []string{"write", "truncate", "metadata"} {
		t.Run(kind, func(t *testing.T) {
			f := newStockFixture(t)
			bindWorkspaceTestGate(t, f.mount)
			clock := &workspaceTestClockOwner{}
			f.mount.workspaceLifecycle = &workspaceLifecycle{clock: clock}
			unique := f.unique.Add(2)
			entry, status := f.mount.workspaceFS().beginWorkspaceEntry(unique)
			if status != fuse.OK {
				t.Fatal(status)
			}
			defer func() {
				f.mount.workspaceFS().finishWorkspaceEntry(unique, entry)
				f.raw.ReplyWritten(unique, fuse.EIO)
			}()
			ctx := context.WithValue(t.Context(), mutationCallbackKey{}, &mutationCallback{publication: *entry})
			ctx = workspaceAdmissionContext(ctx)
			buffer, err := writeback.New(clockAdmissionFlusher{}, writeback.Options{MaxEntries: 1})
			if err != nil {
				t.Fatal(err)
			}
			first, next := writeback.Identity{1}, writeback.Identity{2}
			if _, err = buffer.Write(t.Context(), first, 0, []byte("owned capacity")); err != nil {
				t.Fatal(err)
			}
			done := make(chan error, 1)
			go func() {
				var err error
				switch kind {
				case "write":
					_, err = buffer.Write(ctx, next, 0, []byte("must not accept"))
				case "truncate":
					_, err = buffer.Truncate(ctx, next, 10)
				default:
					_, err = buffer.SetAttr(ctx, next, writeback.Attributes{HasMode: true, Mode: 0600})
				}
				done <- err
			}()
			deadline := time.Now().Add(time.Second)
			for buffer.Stats().WaitingAdmissions != 1 {
				if time.Now().After(deadline) {
					t.Fatal("capacity waiter not owned")
				}
				time.Sleep(time.Millisecond)
			}
			clock.unavailable.Store(true)
			buffer.Drop(first, "release only the old capacity owner")
			if err = <-done; !errors.Is(err, workspaceadmission.ErrClosed) {
				t.Fatal("clock-invalid waiter became accepted", err)
			}
			if stats := buffer.Stats(); stats.Entries != 0 || stats.WaitingAdmissions != 0 {
				t.Fatal("clock-invalid wait left accepted work", stats)
			}
			if _, err = f.mount.workspace.Check(); err != nil {
				t.Fatal("test root already observed closure", err)
			}
		})
	}
}
