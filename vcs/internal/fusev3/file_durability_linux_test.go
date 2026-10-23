//go:build linux

package fusev3

import (
	"context"
	"errors"
	"fmt"
	"github.com/steerlabs/portablefs/vcs/internal/authoritypb"
	"github.com/steerlabs/portablefs/vcs/internal/authorityrpc"
	"testing"
	"time"
)

type fileDurabilityRPC struct{ delegationFakeRPC }

func (f *fileDurabilityRPC) CallMutationSegments(ctx context.Context, request *authoritypb.Request, segments [][]byte, assigned authorityrpc.MutationAssigned) (*authoritypb.Response, error) {
	return waveWrite(ctx, &f.waveOrder, f.CallMutation, request, segments, assigned)
}

func (f *fileDurabilityRPC) CallMutation(ctx context.Context, r *authoritypb.Request) (*authoritypb.Response, error) {
	if r.GetBarrier() != nil {
		return nil, errors.New("unrelated identity prevents volume durability")
	}
	return f.delegationFakeRPC.CallMutation(ctx, r)
}
func (f *fileDurabilityRPC) CallIdempotent(ctx context.Context, r *authoritypb.Request) (*authoritypb.Response, error) {
	if r.GetFsync() != nil {
		return &authoritypb.Response{Body: &authoritypb.Response_Fsync{Fsync: &authoritypb.FsyncReply{DurableSequence: 0}}}, nil
	}
	return f.delegationFakeRPC.CallIdempotent(ctx, r)
}
func TestFileFsyncDoesNotWaitForUnrelatedDurablePrefix(t *testing.T) {
	for _, operation := range []string{"fsync", "fdatasync", "synchronous write"} {
		t.Run(operation, func(t *testing.T) {
			f := &fileDurabilityRPC{}
			m := newDelegationTestManager(t, f)
			other := installDelegationForTest(t, m, 110, authoritypb.DelegationMode_DELEGATION_MODE_FULL)
			id := installDelegationForTest(t, m, 111, authoritypb.DelegationMode_DELEGATION_MODE_FULL)
			if _, err := m.Write(t.Context(), other, 0, []byte("other"), false); err != nil {
				t.Fatal(err)
			}
			if _, err := m.FlushIdentity(t.Context(), other); err != nil {
				t.Fatal(err)
			}
			ctx, cancel := context.WithTimeout(t.Context(), 100*time.Millisecond)
			defer cancel()
			if _, err := m.Write(ctx, id, 0, []byte("file"), operation == "synchronous write"); err != nil {
				t.Fatal(err)
			}
			if operation != "synchronous write" {
				if err := m.Fsync(ctx, id, operation == "fdatasync"); err != nil {
					t.Fatal(err)
				}
			}
			if stats := m.buf.Stats(); stats.Entries != 1 || stats.Bytes != 5 || stats.LossSequence != 0 {
				t.Fatalf("file fsync crossed identity boundary: %+v", stats)
			}
			m.durabilityMu.Lock()
			durable := m.durableHigh
			m.durabilityMu.Unlock()
			if durable != 0 {
				t.Fatal("file fsync invented a common durable prefix")
			}
		})
	}
}

type fsyncRecallRPC struct {
	delegationFakeRPC
	manager  *delegationManager
	identity []byte
	grant    *authoritypb.Delegation
}

func (f *fsyncRecallRPC) CallIdempotent(ctx context.Context, request *authoritypb.Request) (*authoritypb.Response, error) {
	if request.GetFsync() == nil {
		return f.delegationFakeRPC.CallIdempotent(ctx, request)
	}
	done := f.manager.HandleControlEvent(ctx, &authoritypb.ControlEvent{Incarnation: 7, Sequence: 1,
		Event: &authoritypb.ControlEvent_DelegationBreak{DelegationBreak: &authoritypb.DelegationBreak{
			Identity: f.identity, Delegation: &authoritypb.DelegationRef{Id: f.grant.Id, Generation: f.grant.Generation}, BudgetNanos: uint64(time.Second),
		}},
	})
	select {
	case <-done:
		if fakeControlCount(&f.delegationFakeRPC, func(r *authoritypb.Request) bool { return r.GetDelegationBreakAck() != nil }) != 1 {
			return nil, errors.New("FSYNC blocked its required delegation callback")
		}
		return &authoritypb.Response{Body: &authoritypb.Response_Fsync{Fsync: &authoritypb.FsyncReply{}}}, nil
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}

func TestFileFsyncAllowsRequiredDelegationCallback(t *testing.T) {
	for _, synchronousWrite := range []bool{false, true} {
		t.Run(fmt.Sprint(synchronousWrite), func(t *testing.T) {
			fake := &fsyncRecallRPC{}
			m := newDelegationTestManager(t, fake)
			fake.manager = m
			fake.identity = installDelegationForTest(t, m, 111, authoritypb.DelegationMode_DELEGATION_MODE_FULL)
			fake.grant = delegationTestGrant(143, authoritypb.DelegationMode_DELEGATION_MODE_FULL)
			ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
			defer cancel()
			if _, err := m.Write(ctx, fake.identity, 0, []byte("accepted"), synchronousWrite); err != nil {
				t.Fatal(err)
			}
			if !synchronousWrite {
				if err := m.Fsync(ctx, fake.identity, false); err != nil {
					t.Fatal(err)
				}
			}
		})
	}
}
