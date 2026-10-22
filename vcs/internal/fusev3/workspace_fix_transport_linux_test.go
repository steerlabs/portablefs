//go:build linux

package fusev3

import (
	"bufio"
	"bytes"
	"context"
	"errors"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/steerlabs/portablefs/vcs/internal/authoritypb"
	"github.com/steerlabs/portablefs/vcs/internal/authorityrpc"
	"github.com/steerlabs/portablefs/vcs/internal/volumeserver"
	"google.golang.org/protobuf/proto"
)

// A protocol-conforming frozen two-page snapshot over the real TLS client.
// Only the first attempt is delayed; all subsequent empty-cursor Subscribes
// use the production authority's fresh snapshot and authorization checks.
type workspaceDelayedSubscribe struct {
	authorityrpc.Handler
	mu            sync.Mutex
	session       []byte
	mode          string
	starts, pages int
	attaches      atomic.Uint64
	first         *authoritypb.Response
}

func (h *workspaceDelayedSubscribe) Handle(ctx context.Context, q *authoritypb.Request) *authoritypb.Response {
	if q.GetAttach() != nil {
		h.attaches.Add(1)
	}
	if q.GetSubscribe() == nil {
		return h.Handler.Handle(ctx, q)
	}
	h.mu.Lock()
	if !bytes.Equal(q.GetSession().GetId(), h.session) {
		h.mu.Unlock()
		return h.Handler.Handle(ctx, q)
	}
	first := len(q.GetSubscribe().GetSnapshotId()) == 0
	if first {
		h.starts++
	} else {
		h.pages++
	}
	bad := h.starts == 1
	mode := h.mode
	var cached *authoritypb.Response
	if !first && bad && h.first != nil {
		cached = proto.Clone(h.first).(*authoritypb.Response)
	}
	h.mu.Unlock()
	if cached != nil {
		cached.RequestId = q.RequestId
		page := cached.GetSubscribe()
		page.DelegatedIdentities = [][]byte{bytes.Repeat([]byte{0x22}, 16)}
		page.NextAfterIdentity = nil
		delay := 9200 * time.Millisecond
		if mode == "pagination-expired" {
			delay = 10100 * time.Millisecond
		}
		time.Sleep(delay)
		return cached
	}
	response := h.Handler.Handle(ctx, q)
	if !bad || response.GetSubscribe() == nil {
		return response
	}
	if mode == "first-expired" {
		time.Sleep(10100 * time.Millisecond)
		return response
	}
	page := response.GetSubscribe()
	page.DelegatedIdentities = [][]byte{bytes.Repeat([]byte{0x11}, 16)}
	page.NextAfterIdentity = bytes.Repeat([]byte{0x11}, 16)
	h.mu.Lock()
	h.first = proto.Clone(response).(*authoritypb.Response)
	h.mu.Unlock()
	return response
}

func workspaceDelayedSubscribeChild(t *testing.T, phase, mode string) {
	reader, proof, mounted := reviewAdopt(t)
	defer reader.Retire()
	life := &workspaceLifecycle{lane: make(chan struct{}, 1), clock: &workspaceTestClockOwner{}, standalone: true, persist: func(WorkspaceObservation) error { return nil }}
	var h *workspaceDelayedSubscribe
	f := newIntegrationFixture(t, integrationConfig{Mounts: 2, SessionLease: 2 * time.Minute, RequestTimeout: 20 * time.Second, workspace: reader, workspaceRecovery: proof, workspaceFirstOnly: true, workspaceLifecycle: life, workspaceDispatch: true, beforeServe: func(f *integrationFixture) {
		h = &workspaceDelayedSubscribe{Handler: f.counter.inner, mode: mode}
		f.counter.inner = h
	}})
	var off atomic.Int64
	c := &reviewChild{t: t, in: bufio.NewReader(os.Stdin), f: f, m: f.mounts[0], off: &off}
	mounted.Store(c.m)
	if r := c.req("open"); r != "<nil>" {
		t.Fatal(r)
	}
	serial := c.suspend()
	h.mu.Lock()
	h.session = append([]byte(nil), c.m.rpc.SessionID()...)
	h.mu.Unlock()
	attachBefore := h.attaches.Load()
	if attachBefore != 2 {
		t.Fatal("fixture did not count both real Attach requests", attachBefore)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 30*time.Second)
	var o WorkspaceObservation
	var err error
	if phase == "Prepare" {
		o, err = c.m.PrepareWorkspace(ctx, 1, serial)
	} else {
		o, err = c.m.RecoverWorkspace(ctx, 1, serial)
	}
	cancel()
	h.mu.Lock()
	starts, pages := h.starts, h.pages
	h.mu.Unlock()
	if err != nil || !o.Prepared || o.Result.Disposition != authorityrpc.LifecycleCompleted || starts != 2 || mode != "first-expired" && pages != 1 || h.attaches.Load() != attachBefore || c.m.isRevoked() {
		t.Fatal("unusable attempt ended logical job or consumed another Attach", o, err, starts, pages)
	}
	c.req("dispose")
	select {
	case <-c.m.kernelConnectionDone:
	case <-time.After(30 * time.Second):
		t.Fatal("owner EOF stranded mount")
	}
}
func TestWorkspaceRealClientRetriesUnusableSubscribe(t *testing.T) {
	for _, phase := range []string{"Prepare", "Recover"} {
		for _, mode := range []string{"first-expired", "pagination-expired", "pagination-lead"} {
			t.Run(phase+"/"+mode, func(t *testing.T) {
				runReviewKernelParent(t, func(t *testing.T) { workspaceDelayedSubscribeChild(t, phase, mode) })
			})
		}
	}
}

// The real frontend's background durability owner retains a visibility cut
// through cold retirement, a lost DATA connection, and a park beyond one
// reconnect attempt budget. A later receipt cannot act on the successor buffer.
func workspaceVisibilityOwnerChild(t *testing.T) {
	reader, proof, mounted := reviewAdopt(t)
	defer reader.Retire()
	life := &workspaceLifecycle{lane: make(chan struct{}, 1), clock: &workspaceTestClockOwner{}, standalone: true, persist: func(WorkspaceObservation) error { return nil }}
	var listener *controlFaultListener
	f := newIntegrationFixture(t, integrationConfig{Mounts: 2, SessionLease: 2 * time.Minute, workspace: reader, workspaceRecovery: proof, workspaceFirstOnly: true, workspaceLifecycle: life, workspaceDispatch: true, wrapListener: func(l net.Listener) net.Listener { listener = &controlFaultListener{Listener: l}; return listener }})
	var off atomic.Int64
	c := &reviewChild{t: t, in: bufio.NewReader(os.Stdin), f: f, m: f.mounts[0], off: &off}
	mounted.Store(c.m)
	if r := c.req("open"); r != "<nil>" {
		t.Fatal(r)
	}
	manager := c.m.delegations
	c.m.raw.mu.RLock()
	rootToken := append([]byte(nil), c.m.raw.nodesByID[1].node.item.GetToken()...)
	c.m.raw.mu.RUnlock()
	applyCut := func(mode uint32) uint64 {
		response, err := f.clients[0].CallMutation(t.Context(), &authoritypb.Request{Body: &authoritypb.Request_SetAttr{SetAttr: &authoritypb.SetAttrRequest{Item: rootToken, Mode: &mode}}})
		if err != nil || response.GetErrno() != 0 || response.GetAppliedSequence() == 0 {
			t.Fatal("authority supplied no application cut", response, err)
		}
		return response.GetAppliedSequence()
	}
	// Feed forward a real authority receipt without first letting the frontend
	// settle it. No counter is rewound and only the real durability worker runs.
	cut := applyCut(0750)
	entered, release := make(chan struct{}), make(chan struct{})
	var releaseOnce sync.Once
	defer releaseOnce.Do(func() { close(release) })
	var held, successorSeen atomic.Bool
	var successorCut atomic.Uint64
	successorBarrier := make(chan uint64, 1)
	f.counter.setBeforeHandle(func(q *authoritypb.Request) {
		if !bytes.Equal(q.GetSession().GetId(), c.m.rpc.SessionID()) {
			return
		}
		if q.GetWaitVisibility().GetCutSequence() == cut && held.CompareAndSwap(false, true) {
			close(entered)
			<-release
		}
		if next := successorCut.Load(); next != 0 && q.GetBarrier().GetCutSequence() == next && successorSeen.CompareAndSwap(false, true) {
			manager.durabilityMu.Lock()
			high := manager.durableHigh
			manager.durabilityMu.Unlock()
			successorBarrier <- high
		}
	})
	manager.durabilityMu.Lock()
	if manager.appliedHigh != 0 || manager.durableHigh != 0 {
		manager.durabilityMu.Unlock()
		t.Fatal("fixture already settled a frontend cut")
	}
	old := manager.durableBuffer
	manager.appliedHigh = cut
	manager.durabilityMu.Unlock()
	manager.kickDurability()
	select {
	case <-entered:
	case <-time.After(5 * time.Second):
		t.Fatal("real background visibility owner did not dispatch")
	}
	serial := c.suspend()
	snapshot := f.clients[0].DispatchSnapshot()
	var retained []byte
	for _, o := range snapshot.Owners {
		var q authoritypb.Request
		_ = proto.Unmarshal(o.Body, &q)
		if q.GetWaitVisibility() != nil {
			retained = append([]byte(nil), o.Body...)
		}
	}
	if len(retained) == 0 {
		t.Fatal("background visibility owner missing at cold cut")
	}
	listener.partitionTransport(t, 0, 0)
	time.Sleep(volumeserver.SubscriptionTTL + time.Second)
	if c.m.isRevoked() || c.m.rpc.SessionEndCause() != nil {
		t.Fatal("park timeout terminalized old visibility owner")
	}
	found := false
	for _, o := range f.clients[0].DispatchSnapshot().Owners {
		found = found || bytes.Equal(retained, o.Body)
	}
	if !found {
		t.Fatal("immutable visibility request lost")
	}
	releaseOnce.Do(func() { close(release) })
	listener.heal()
	c.recover(serial)
	successor := applyCut(0755)
	successorCut.Store(successor)
	manager.durabilityMu.Lock()
	same := manager.durableBuffer == old
	manager.appliedHigh = successor
	manager.durabilityMu.Unlock()
	if same {
		t.Fatal("cold cut did not replace the old buffer")
	}
	manager.kickDurability()
	// This request can only come from the same serial worker after the old
	// visibility owner's complete frontend disposition. Its predecessor must
	// not have advanced the successor buffer's durable prefix.
	select {
	case high := <-successorBarrier:
		if high != 0 {
			t.Fatal("old visibility completion advanced successor buffer", high)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("old background owner did not settle and advance after wake")
	}
	for _, owner := range f.clients[0].DispatchSnapshot().Owners {
		if bytes.Equal(owner.Body, retained) {
			t.Fatal("old visibility owner survived its frontend disposition")
		}
	}
	if c.m.isRevoked() || c.m.rpc.SessionEndCause() != nil || manager.LossSequence() != 0 {
		t.Fatal("old completion revoked the recovered mount")
	}
	c.req("dispose")
	select {
	case <-c.m.kernelConnectionDone:
	case <-time.After(30 * time.Second):
		t.Fatal("owner EOF stranded mount")
	}
}
func TestWorkspaceRealVisibilityOwnerOutlivesPark(t *testing.T) {
	runReviewKernelParent(t, workspaceVisibilityOwnerChild)
}

func TestKernelOrdinaryExpiredSessionIsTerminal(t *testing.T) {
	f := newIntegrationFixture(t, integrationConfig{Mounts: 2, SessionLease: 20 * time.Second})
	f.advanceClock(time.Minute)
	f.sweepSessions()
	ctx, cancel := context.WithTimeout(t.Context(), 10*time.Second)
	defer cancel()
	_, err := f.clients[0].CallRead(ctx, &authoritypb.Request{Body: &authoritypb.Request_KeepAlive{KeepAlive: &authoritypb.KeepAliveRequest{}}})
	if !errors.Is(err, authorityrpc.ErrSessionEnded) || !errors.Is(f.clients[0].SessionEndCause(), authorityrpc.ErrSessionEnded) {
		t.Fatal("ordinary expiry remained a transient transport failure", err, f.clients[0].SessionEndCause())
	}
}
