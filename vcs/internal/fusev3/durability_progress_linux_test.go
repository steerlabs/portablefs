//go:build linux

package fusev3

import (
	"context"
	"testing"
	"time"

	"github.com/steerlabs/portablefs/vcs/internal/authoritypb"
	"github.com/steerlabs/portablefs/vcs/internal/authorityrpc"
)

type progressBarrierRPC struct {
	delegationFakeRPC
	cuts   chan uint64
	resume chan struct{}
}

func (f *progressBarrierRPC) CallMutationSegments(ctx context.Context, req *authoritypb.Request, spans [][]byte, assigned authorityrpc.MutationAssigned) (*authoritypb.Response, error) {
	return waveWrite(ctx, &f.waveOrder, f.CallMutation, req, spans, assigned)
}
func (f *progressBarrierRPC) CallMutation(ctx context.Context, req *authoritypb.Request) (*authoritypb.Response, error) {
	if barrier := req.GetBarrier(); barrier != nil {
		f.cuts <- barrier.GetCutSequence()
		select {
		case <-f.resume:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	return f.delegationFakeRPC.CallMutation(ctx, req)
}

func TestDurabilityProgressCoalescesApplicationsWhileOwnerIsBusy(t *testing.T) {
	fake := &progressBarrierRPC{cuts: make(chan uint64, 2), resume: make(chan struct{}, 2)}
	m := newDelegationTestManager(t, fake)
	id := installDelegationForTest(t, m, 113, authoritypb.DelegationMode_DELEGATION_MODE_FULL)
	apply := func(offset int64) {
		if _, err := m.Write(t.Context(), id, offset, []byte("x"), false); err != nil {
			t.Fatal(err)
		}
		if _, err := m.FlushIdentity(t.Context(), id); err != nil {
			t.Fatal(err)
		}
	}
	apply(0)
	select {
	case cut := <-fake.cuts:
		if cut != 1 {
			t.Fatalf("first cut=%d", cut)
		}
	case <-time.After(time.Second):
		t.Fatal("application did not wake durability")
	}
	for i := 1; i <= 1000; i++ {
		apply(int64(i))
	}
	if len(fake.cuts) != 0 {
		t.Fatal("concurrent barrier owners")
	}
	fake.resume <- struct{}{}
	select {
	case cut := <-fake.cuts:
		if cut != 1001 {
			t.Fatalf("coalesced cut=%d want 1001", cut)
		}
	case <-time.After(time.Second):
		t.Fatal("busy owner stranded later applications")
	}
	fake.resume <- struct{}{}
	waitFor(t, "all accepted records retire", func() bool { return m.buf.Stats().Entries == 0 })
	fake.mu.Lock()
	defer fake.mu.Unlock()
	if fake.barriers != 2 {
		t.Fatalf("barriers=%d want 2 bounded coalesced cuts", fake.barriers)
	}
}
