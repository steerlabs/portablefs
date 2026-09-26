//go:build linux

package fusev3

import (
	"context"
	"errors"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/steerlabs/portablefs/vcs/internal/authoritypb"
	"github.com/steerlabs/portablefs/vcs/internal/authorityrpc"
	"github.com/steerlabs/portablefs/vcs/internal/writeback"
)

type orderedFlushFake struct {
	delegationFakeRPC
	permits      chan struct{}
	entered      chan uint64
	release      <-chan struct{}
	active, peak atomic.Int32
	muOrder      sync.Mutex
	assigned     []uint64
	fail         map[uint64]error
	errno        map[uint64]syscall.Errno
}

func (*orderedFlushFake) SupportsOrderedFlush() bool { return true }
func (f *orderedFlushFake) CallMutation(ctx context.Context, r *authoritypb.Request) (*authoritypb.Response, error) {
	if r.GetBarrier() != nil {
		return nil, errors.New("durability held for pipeline test")
	}
	return f.delegationFakeRPC.CallMutation(ctx, r)
}
func (f *orderedFlushFake) CallMutationSegments(ctx context.Context, r *authoritypb.Request, pieces [][]byte, assigned authorityrpc.MutationAssigned) (*authoritypb.Response, error) {
	select {
	case f.permits <- struct{}{}:
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	defer func() { <-f.permits }()
	n := f.active.Add(1)
	defer f.active.Add(-1)
	for old := f.peak.Load(); n > old; old = f.peak.Load() {
		if f.peak.CompareAndSwap(old, n) {
			break
		}
	}
	w := r.GetWrite()
	ordinal := w.GetFlushSequence()
	f.muOrder.Lock()
	f.assigned = append(f.assigned, ordinal)
	f.muOrder.Unlock()
	if err := assigned(authorityrpc.MutationIdentity{Sequence: ordinal}); err != nil {
		return nil, err
	}
	f.entered <- ordinal
	select {
	case <-f.release:
	case <-ctx.Done():
		return nil, ctx.Err()
	}
	if err := f.fail[ordinal]; err != nil {
		return nil, err
	}
	if errno := f.errno[ordinal]; errno != 0 {
		return &authoritypb.Response{Errno: int32(errno)}, nil
	}
	size := 0
	for _, piece := range pieces {
		size += len(piece)
	}
	if size != int(w.Size) || len(w.Data) != 0 {
		return nil, errors.New("scatter size/carrier mismatch")
	}
	return &authoritypb.Response{AppliedSequence: ordinal, VolumeVersion: ordinal + 100, Body: &authoritypb.Response_Write{Write: &authoritypb.WriteReply{CommittedSize: uint64(size), AssignedOffset: w.Position, PostAttr: &authoritypb.Attr{Kind: authoritypb.Attr_REGULAR, Size: int64(w.Position) + int64(size)}}}}, nil
}
func pipelineFake(release <-chan struct{}) *orderedFlushFake {
	return &orderedFlushFake{delegationFakeRPC: delegationFakeRPC{maxWrite: 8}, permits: make(chan struct{}, 4), entered: make(chan uint64, 32), release: release}
}
func TestDelegationPipelineAdmitsFourChunksBeforeJoining(t *testing.T) {
	release := make(chan struct{})
	f := pipelineFake(release)
	m := newDelegationTestManager(t, f)
	id := installDelegationForTest(t, m, 101, authoritypb.DelegationMode_DELEGATION_MODE_FULL)
	if _, err := m.Write(t.Context(), id, 0, []byte("abcdefghijklmnopqrstuvwxyz0123456789ABCD"), false); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	ctx, cancel := context.WithTimeout(t.Context(), time.Second)
	defer cancel()
	go func() { _, err := m.FlushIdentity(ctx, id); done <- err }()
	for range 4 {
		select {
		case <-f.entered:
		case <-ctx.Done():
			close(release)
			t.Fatal("four chunks never entered together")
		}
	}
	select {
	case seq := <-f.entered:
		close(release)
		t.Fatalf("fifth chunk %d entered before first wave completed", seq)
	default:
	}
	if f.peak.Load() != 4 {
		close(release)
		t.Fatalf("peak=%d", f.peak.Load())
	}
	close(release)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	f.muOrder.Lock()
	defer f.muOrder.Unlock()
	if len(f.assigned) != 5 {
		t.Fatalf("chunks=%v", f.assigned)
	}
	for i, seq := range f.assigned {
		if seq != uint64(i+1) {
			t.Fatalf("predecessor admission was reordered: %v", f.assigned)
		}
	}
}
func TestDelegationPipelineReducesFailuresOnceAfterJoining(t *testing.T) {
	for _, uncertain := range []bool{false, true} {
		t.Run(map[bool]string{false: "capacity", true: "uncertainty dominates capacity"}[uncertain], func(t *testing.T) {
			release := make(chan struct{})
			close(release)
			f := pipelineFake(release)
			f.errno = map[uint64]syscall.Errno{1: syscall.ENOSPC, 3: syscall.EDQUOT}
			if uncertain {
				f.fail = map[uint64]error{4: authorityrpc.ErrTransportUncertain}
			}
			m := newDelegationTestManager(t, f)
			id := installDelegationForTest(t, m, 102, authoritypb.DelegationMode_DELEGATION_MODE_FULL)
			if _, err := m.Write(t.Context(), id, 0, []byte("abcdefghijklmnopqrstuvwxyz012345"), false); err != nil {
				t.Fatal(err)
			}
			_, err := m.FlushIdentity(t.Context(), id)
			if uncertain && !errors.Is(err, writeback.ErrLost) || !uncertain && !errors.Is(err, syscall.ENOSPC) {
				t.Fatalf("wave error=%v", err)
			}
			parsed, _ := delegationIdentity(id)
			if m.LossSequence() != 1 || m.buf.Stats().Entries != 0 || f.active.Load() != 0 {
				t.Fatalf("wave did not join/drop exactly once: loss=%d stats=%+v active=%d", m.LossSequence(), m.buf.Stats(), f.active.Load())
			}
			if delegationStateOwned(m.state(parsed)) == uncertain {
				t.Fatal("wave failure chose wrong grant disposition")
			}
			if !uncertain {
				if _, err := m.Write(t.Context(), id, 0, []byte("next"), false); err != nil {
					t.Fatal(err)
				}
				if _, err := m.FlushIdentity(t.Context(), id); err != nil {
					t.Fatal(err)
				}
				f.muOrder.Lock()
				defer f.muOrder.Unlock()
				if f.assigned[len(f.assigned)-1] != 5 {
					t.Fatal("preserved grant reset dense ordinal after capacity refusal")
				}
			}
		})
	}
}
