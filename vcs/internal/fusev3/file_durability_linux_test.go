//go:build linux

package fusev3

import (
	"context"
	"errors"
	"github.com/steerlabs/portablefs/vcs/internal/authoritypb"
	"testing"
	"time"
)

type fileDurabilityRPC struct{ delegationFakeRPC }

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
