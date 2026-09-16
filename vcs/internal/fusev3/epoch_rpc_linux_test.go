//go:build linux

package fusev3

import (
	"context"
	"sync/atomic"
	"testing"

	"github.com/steerlabs/portablefs/vcs/internal/authoritypb"
)

type epochFacadeTestRPC struct {
	RPC
	root   *authoritypb.Item
	closed atomic.Bool
}

func (r *epochFacadeTestRPC) Root() *authoritypb.Item        { return r.root }
func (r *epochFacadeTestRPC) IOLimits() (uint32, uint32)     { return 1 << 20, 1 << 20 }
func (r *epochFacadeTestRPC) FinishLocalSessionEnforcement() {}
func (r *epochFacadeTestRPC) Close() error {
	r.closed.Store(true)
	return nil
}

type recoveringEpochTestRPC struct {
	*epochFacadeTestRPC
	next RPC
}

func (r *recoveringEpochTestRPC) RecoverEpoch(context.Context) (RPC, error) {
	return r.next, nil
}

func TestEpochRPCPublishesOneCompleteReplacement(t *testing.T) {
	root := func(marker byte) *authoritypb.Item {
		identity := make([]byte, 16)
		identity[0] = marker
		return &authoritypb.Item{
			Token: []byte{marker}, StableIdentity: identity,
			Attr: &authoritypb.Attr{Inode: uint64(marker), Kind: authoritypb.Attr_DIRECTORY},
		}
	}
	old := &epochFacadeTestRPC{root: root(1)}
	next := &epochFacadeTestRPC{root: root(2)}
	facade := newEpochRPC(&recoveringEpochTestRPC{epochFacadeTestRPC: old, next: next})
	if got := facade.Root().GetStableIdentity()[0]; got != 1 {
		t.Fatalf("initial root identity marker = %d", got)
	}
	if err := facade.recover(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := facade.Root().GetStableIdentity()[0]; got != 2 {
		t.Fatalf("recovered root identity marker = %d", got)
	}
	if !old.closed.Load() {
		t.Fatal("old epoch transport remained open after replacement publication")
	}
}
