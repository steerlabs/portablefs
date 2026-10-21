//go:build linux

package fusev3

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/steerlabs/portablefs/vcs/internal/authoritypb"
	"github.com/steerlabs/portablefs/vcs/internal/writeback"
)

type metadataResetRPC struct {
	delegationFakeRPC
	entered, resume chan struct{}
}

func (f *metadataResetRPC) CallMutation(ctx context.Context, r *authoritypb.Request) (*authoritypb.Response, error) {
	if r.GetSetAttr() == nil {
		return f.delegationFakeRPC.CallMutation(ctx, r)
	}
	close(f.entered)
	// Model an exact session-owned result already recorded before cache reset.
	<-f.resume
	return &authoritypb.Response{AppliedSequence: 91, VisibleSequence: 91, VolumeVersion: 91, PostState: &authoritypb.PostState{Objects: []*authoritypb.ObjectPostState{{StableIdentity: delegationTestIdentity(48), ObjectVersion: 91, Attr: &authoritypb.Attr{Kind: authoritypb.Attr_REGULAR, Mode: 0600}}}}}, nil
}

func TestMetadataFlushReceiptCannotAdvanceColdSuccessor(t *testing.T) {
	f := &metadataResetRPC{entered: make(chan struct{}), resume: make(chan struct{})}
	var once sync.Once
	release := func() { once.Do(func() { close(f.resume) }) }
	defer release()
	m := newDelegationTestManager(t, f)
	id := installDelegationForTest(t, m, 48, authoritypb.DelegationMode_DELEGATION_MODE_FULL)
	parsed, _ := delegationIdentity(id)
	state := m.retainState(parsed, false)
	defer m.releaseState(state)
	if _, err := m.SetAttr(t.Context(), id, writeback.Attributes{HasMode: true, Mode: 0600}); err != nil {
		t.Fatal(err)
	}
	old := m.buf
	m.StartWriteback()
	select {
	case <-f.entered:
	case <-time.After(time.Second):
		t.Fatal("metadata flush never entered")
	}
	reset := make(chan struct{})
	go func() { m.FenceSubscription("metadata reply retained across cold reset"); close(reset) }()
	waitUntil(t, time.Second, "old metadata grant retired", func() bool { state.admission.RLock(); defer state.admission.RUnlock(); return state.ref == nil })
	select {
	case <-reset:
		t.Fatal("reset released metadata receipt before joining resolver")
	default:
	}
	release()
	select {
	case <-reset:
	case <-time.After(time.Second):
		t.Fatal("reset did not join metadata resolver")
	}
	m.SetIncarnation(8)
	if m.buf == old || m.LossSequence() != 1 {
		t.Fatal("metadata reset lost buffer or exact loss accounting")
	}
	m.durabilityMu.Lock()
	applied, durable := m.appliedHigh, m.durableHigh
	m.durabilityMu.Unlock()
	if applied != 0 || durable != 0 || m.buf.Stats().Entries != 0 {
		t.Fatalf("metadata receipt entered successor: applied=%d durable=%d stats=%+v", applied, durable, m.buf.Stats())
	}
	if _, ok := m.BaseAttr(id); ok {
		t.Fatal("old metadata base entered successor")
	}
	m.tokenMu.Lock()
	receipts := len(m.tokens)
	m.tokenMu.Unlock()
	if receipts != 0 {
		t.Fatal("old metadata token entered successor")
	}
}
