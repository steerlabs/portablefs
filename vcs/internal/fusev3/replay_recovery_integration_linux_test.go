//go:build linux

package fusev3

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/steerlabs/portablefs/vcs/internal/authoritymetrics"
	"github.com/steerlabs/portablefs/vcs/internal/authoritypb"
	"github.com/steerlabs/portablefs/vcs/internal/authorityrpc"
	"github.com/steerlabs/portablefs/vcs/internal/continuous"
	"github.com/steerlabs/portablefs/vcs/internal/volumeserver"
	"google.golang.org/protobuf/proto"
)

type replaySubscriptionClock struct{ offset *atomic.Int64 }

func replaySubscriptionClockFor(offset *atomic.Int64) subscriptionClock {
	if offset == nil {
		return nil
	}
	return replaySubscriptionClock{offset}
}
func (c replaySubscriptionClock) Now() time.Time {
	return continuous.Time().Add(time.Duration(c.offset.Load()))
}
func (c replaySubscriptionClock) NewTimer(d time.Duration) subscriptionTimer {
	return wallSubscriptionTimer{timer: time.NewTimer(d)}
}

type replayAuthorityClock struct{ fixture *integrationFixture }

func (c replayAuthorityClock) Now() time.Time { return c.fixture.now() }
func (c replayAuthorityClock) NewTimer(d time.Duration) volumeserver.CoherenceTimer {
	return replayAuthorityTimer{time.NewTimer(d)}
}

type replayAuthorityTimer struct{ *time.Timer }

func (t replayAuthorityTimer) C() <-chan time.Time { return t.Timer.C }

type replayCutListener struct {
	net.Listener
	mu          sync.Mutex
	connections []net.Conn
}

func (l *replayCutListener) Accept() (net.Conn, error) {
	c, err := l.Listener.Accept()
	if err != nil {
		return nil, err
	}
	l.mu.Lock()
	l.connections = append(l.connections, c)
	l.mu.Unlock()
	return c, nil
}
func (l *replayCutListener) cut(t *testing.T, role string) {
	t.Helper()
	index := 0
	if role == "control" {
		index = 1
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if len(l.connections) < 2 {
		t.Fatal("initial role pair missing")
	}
	if err := l.connections[index].Close(); err != nil {
		t.Fatal(err)
	}
}

// Hold a recorded descriptor outcome, rather than delaying a timer and hoping
// that a response happened to be in flight when cache permission expired.
// The original response and any replay stay immutable behind these gates.
type replayRecoveryHandler struct {
	authorityrpc.Handler
	kind      string
	armed     atomic.Bool
	entered   chan struct{}
	release   chan struct{}
	cold      chan struct{}
	replayed  chan *authoritypb.Response
	coldFirst bool
	settled   chan struct{}
	mu        sync.Mutex
	original  *authoritypb.Request
	outcome   *authoritypb.Response
	coldOnce  sync.Once
	latestInc atomic.Uint64
}

func (h *replayRecoveryHandler) Handle(ctx context.Context, r *authoritypb.Request) *authoritypb.Response {
	h.mu.Lock()
	original := h.original
	h.mu.Unlock()
	if original != nil && r.GetSubscribe() != nil && !h.coldFirst {
		select {
		case <-h.settled:
		case <-ctx.Done():
		}
	}
	matches := r.GetCloseBatch() != nil
	if h.kind == "open" {
		matches = r.GetOpen() != nil
	}
	if h.kind == "write" {
		matches = r.GetWrite() != nil
	}
	replay := original != nil && matches && proto.Equal(r.GetMutation(), original.GetMutation())
	if replay && h.coldFirst {
		select {
		case <-h.cold:
		case <-ctx.Done():
		}
	}
	result := h.Handler.Handle(ctx, r)
	if r.GetSubscribe() != nil && result.GetErrno() == 0 {
		h.latestInc.Store(result.GetSubscribe().GetIncarnation())
	}
	if matches && h.armed.CompareAndSwap(true, false) {
		h.mu.Lock()
		h.original = proto.Clone(r).(*authoritypb.Request)
		h.outcome = proto.Clone(result).(*authoritypb.Response)
		h.mu.Unlock()
		close(h.entered)
		<-h.release
	} else if replay {
		h.replayed <- proto.Clone(result).(*authoritypb.Response)
	}
	if original != nil && r.GetSubscribe() != nil && result.GetErrno() == 0 {
		h.coldOnce.Do(func() { close(h.cold) })
	}
	return result
}

func TestKernelMutationReplayAcrossColdRecovery(t *testing.T) {
	for _, clockMode := range []string{"both_clocks", "authority_only"} {
		for _, coldFirst := range []bool{false, true} {
			for _, role := range []string{"data", "control"} {
				t.Run(fmt.Sprintf("%s/cold_first_%t/%s", clockMode, coldFirst, role), func(t *testing.T) {
					var offset atomic.Int64
					var localOffset *atomic.Int64
					if clockMode == "both_clocks" {
						localOffset = &offset
					}
					var listener *replayCutListener
					f := newIntegrationFixture(t, integrationConfig{Mounts: 1, skipMounts: true, SessionLease: 2 * time.Minute, clockOffset: localOffset, wrapListener: func(l net.Listener) net.Listener { listener = &replayCutListener{Listener: l}; return listener }})
					inner := f.counter.inner.(*authorityrpc.VolumeHandler)
					// The runtime's lease and the coordinator's subscription both age under
					// the explicit authority jump. Client time remains independent in the
					// authority_only schedule, as with a parked client process.
					inner.Coherence = volumeserver.NewCoherenceCoordinator(volumeserver.CoherenceConfig{Clock: replayAuthorityClock{f}})
					f.coherence = inner.Coherence
					gate := &replayRecoveryHandler{Handler: f.server.Handler, entered: make(chan struct{}), release: make(chan struct{}), cold: make(chan struct{}), replayed: make(chan *authoritypb.Response, 4), settled: make(chan struct{}), coldFirst: coldFirst}
					f.server.Handler = gate
					var releaseOnce, settleOnce sync.Once
					release := func() { releaseOnce.Do(func() { close(gate.release) }) }
					settled := func() { settleOnce.Do(func() { close(gate.settled) }) }
					t.Cleanup(func() { release(); settled() })
					f.mountAll()
					m := f.mounts[0]
					kernel := m.kernelMount
					root := mustOpenFile(t, f.mountPath(0), os.O_RDONLY, 0)
					defer root.Close()
					mustWrite(t, f.join(0, "tail"), []byte("initial"), 0600)
					mustWrite(t, f.join(0, "cached"), []byte("oldpage"), 0600)
					mustWrite(t, f.join(0, "gone"), []byte("present"), 0600)
					mustWrite(t, f.join(0, "close-target"), []byte("close"), 0600)
					if err := root.Sync(); err != nil {
						t.Fatal(err)
					}
					f.waitForDelegationReleases(t)
					held := mustOpenFile(t, f.join(0, "tail"), os.O_RDWR, 0)
					defer held.Close()
					otherAffected := mustOpenFile(t, f.join(0, "tail"), os.O_RDWR, 0)
					defer otherAffected.Close()
					// The close-target keeps its write grant, so RELEASE uses deferred CLOSE_BATCH.
					doomed := mustOpenFile(t, f.join(0, "close-target"), os.O_RDWR, 0)
					cached := mustOpenFile(t, f.join(0, "cached"), os.O_RDONLY, 0)
					defer cached.Close()
					if got := readExactlyAt(t, cached, 0, 7, "prime kernel pages"); string(got) != "oldpage" {
						t.Fatal(string(got))
					}
					if _, err := os.Stat(f.join(0, "gone")); err != nil {
						t.Fatal(err)
					}
					if _, err := os.Stat(f.join(0, "new")); !errors.Is(err, os.ErrNotExist) {
						t.Fatalf("prime negative=%v", err)
					}
					if err := root.Sync(); err != nil {
						t.Fatal(err)
					}
					waitUntil(t, 5*time.Second, "setup descriptor cleanup", func() bool {
						m.delegations.closeMu.Lock()
						defer m.delegations.closeMu.Unlock()
						return m.delegations.closePending == 0
					})
					m.raw.mu.RLock()
					primed := len(m.raw.cachedStableNames) > 0 && len(m.raw.cachedNegatives) > 0 && len(m.raw.cachedAttrs) > 0 && len(m.raw.cachedData) > 0
					m.raw.mu.RUnlock()
					if !primed {
						t.Fatal("cache withdrawal fixture did not prime names, negatives, attributes and pages")
					}
					// Retain an accepted volatile tail without assigning it a DATA replay
					// identity. Reset may discard these bytes, but must still settle the
					// independently assigned CLOSE_BATCH outcome below.
					parked := make(chan struct{})
					var parkOnce sync.Once
					f.transports[0].hookMu.Lock()
					f.transports[0].beforeDelegatedMutation = func(ctx context.Context, r *authoritypb.Request) error {
						if r.GetWrite() != nil {
							parkOnce.Do(func() { close(parked) })
							<-ctx.Done()
							return ctx.Err()
						}
						return nil
					}
					f.transports[0].hookMu.Unlock()
					lossBefore := m.delegations.LossSequence()
					if _, err := held.WriteAt([]byte("volatile"), 0); err != nil {
						t.Fatal(err)
					}
					select {
					case <-parked:
					case <-time.After(5 * time.Second):
						t.Fatal("volatile tail did not park before assignment")
					}
					gate.armed.Store(true)
					if err := doomed.Close(); err != nil {
						t.Fatal(err)
					}
					select {
					case <-gate.entered:
					case <-time.After(5 * time.Second):
						t.Fatal("CLOSE_BATCH not recorded")
					}
					oldInc := m.delegations.incarnation()
					var session volumeserver.SessionID
					copy(session[:], f.transports[0].session)
					if !coldFirst {
						m.epochMu.Lock()
					}
					locked := !coldFirst
					defer func() {
						if locked {
							m.epochMu.Unlock()
						}
					}()
					f.advanceClock(15 * time.Second)
					if localOffset != nil {
						offset.Add(int64(15 * time.Second))
					}
					if err := f.coherence.CheckSession(volumeserver.SubscriptionToken{Session: session, Incarnation: oldInc}); err == nil {
						t.Fatal("authority subscription did not expire at explicit clock jump")
					}
					// Model remote changes after exclusion expired. The cold withdrawal must
					// remove all old cache coordinates before any fresh lookup/read can serve.
					if err := os.Remove(filepath.Join(f.volumeRoot, "gone")); err != nil {
						t.Fatal(err)
					}
					if err := os.WriteFile(filepath.Join(f.volumeRoot, "new"), []byte("new"), 0600); err != nil {
						t.Fatal(err)
					}
					if err := os.WriteFile(filepath.Join(f.volumeRoot, "cached"), []byte("newpage"), 0600); err != nil {
						t.Fatal(err)
					}
					m.subscription.deactivate()
					if m.subscription.stamp() != (subscriptionStamp{}) {
						t.Fatal("expired cache admission remained open")
					}
					listener.cut(t, role)
					if role == "data" || !coldFirst {
						release()
					}
					if !coldFirst {
						waitUntil(t, 5*time.Second, "old close resolved before reset", func() bool {
							m.delegations.closeMu.Lock()
							defer m.delegations.closeMu.Unlock()
							return m.delegations.closePending == 0
						})
						settled()
						m.epochMu.Unlock()
						locked = false
					}
					waitUntil(t, 10*time.Second, "replacement subscription", func() bool {
						stamp := m.subscription.stamp()
						return stamp.incarnation != 0 && stamp.incarnation != oldInc
					})
					if coldFirst && role == "control" {
						release()
					}
					waitUntil(t, 5*time.Second, "retained descriptor debt discharged", func() bool {
						m.delegations.closeMu.Lock()
						defer m.delegations.closeMu.Unlock()
						return m.delegations.closePending == 0
					})
					if role == "data" {
						select {
						case replay := <-gate.replayed:
							gate.mu.Lock()
							want := proto.Clone(gate.outcome).(*authoritypb.Response)
							gate.mu.Unlock()
							want.RequestId = replay.RequestId
							if !proto.Equal(want, replay) || replay.GetMutation() == nil {
								t.Fatalf("changed retained replay: %v", replay)
							}
						case <-time.After(5 * time.Second):
							t.Fatal("DATA loss did not replay exact CLOSE_BATCH")
						}
					}
					f.transports[0].hookMu.Lock()
					f.transports[0].beforeDelegatedMutation = nil
					f.transports[0].hookMu.Unlock()
					if got := m.delegations.LossSequence(); got != lossBefore+1 {
						t.Fatalf("accepted-tail loss=%d, want %d", got, lossBefore+1)
					}
					if err := held.Sync(); !errors.Is(err, syscall.EIO) {
						t.Fatalf("affected handle fsync=%v, want EIO", err)
					}
					if err := root.Sync(); !errors.Is(err, syscall.EIO) {
						t.Fatalf("pre-loss root barrier=%v, want EIO", err)
					}
					if err := otherAffected.Sync(); !errors.Is(err, syscall.EIO) {
						t.Fatalf("second affected handle fsync=%v", err)
					}
					for range 3 {
						if err := held.Sync(); err != nil {
							t.Fatalf("repeated affected handle fsync=%v", err)
						}
						if err := otherAffected.Sync(); err != nil {
							t.Fatalf("repeated second handle fsync=%v", err)
						}
						if err := cached.Sync(); err != nil {
							t.Fatalf("unaffected handle fsync=%v", err)
						}
						if err := root.Sync(); !errors.Is(err, syscall.EIO) {
							t.Fatalf("pre-loss root forgot retained loss: %v", err)
						}
						if got := m.delegations.LossSequence(); got != lossBefore+1 {
							t.Fatalf("observation changed loss counter: %d", got)
						}
					}
					if _, err := os.Stat(f.join(0, "gone")); !errors.Is(err, os.ErrNotExist) {
						t.Fatalf("stale positive survived withdrawal: %v", err)
					}
					requireContent(t, f.join(0, "new"), []byte("new"), "negative cache withdrawal")
					if got := readExactlyAt(t, cached, 0, 7, "post-withdrawal kernel refault"); string(got) != "newpage" {
						t.Fatalf("stale pages survived: %q", got)
					}
					requireContent(t, f.join(0, "tail"), []byte("initial"), "old volatile tail not reapplied")
					fresh := mustOpenFile(t, f.join(0, "fresh"), os.O_CREATE|os.O_RDWR, 0600)
					if _, err := fresh.Write([]byte("serving")); err != nil {
						t.Fatal(err)
					}
					if err := fresh.Sync(); err != nil {
						t.Fatal(err)
					}
					if err := fresh.Close(); err != nil {
						t.Fatal(err)
					}
					newRoot := mustOpenFile(t, f.mountPath(0), os.O_RDONLY, 0)
					if err := newRoot.Sync(); err != nil {
						t.Fatal(err)
					}
					newRoot.Close()
					installed, err := observeKernelMount(f.mountPath(0))
					if err != nil {
						t.Fatal(err)
					}
					if installed.id != kernel.id || installed.device != kernel.device || installed.source != kernel.source || m.isRevoked() || f.clients[0].SessionEndCause() != nil {
						t.Fatalf("original FUSE connection ended: mount=%v session=%v", m.fatalError(), f.clients[0].SessionEndCause())
					}
					select {
					case <-m.kernelConnectionDone:
						t.Fatal("kernel connection ended during cold recovery")
					default:
					}
				})
			}
		}
	}
}

// This is the original recorded-OPEN reproduction, with fixed assertions. A
// pending raw callback must resolve its exact descriptor before cold Subscribe;
// requesting reset first must still drain that publication boundary.
func TestKernelOpenReplayBeforeColdSubscribe(t *testing.T) {
	var offset atomic.Int64
	var listener *replayCutListener
	f := newIntegrationFixture(t, integrationConfig{Mounts: 1, skipMounts: true, SessionLease: 2 * time.Minute, clockOffset: &offset, wrapListener: func(l net.Listener) net.Listener { listener = &replayCutListener{Listener: l}; return listener }})
	inner := f.counter.inner.(*authorityrpc.VolumeHandler)
	inner.Coherence = volumeserver.NewCoherenceCoordinator(volumeserver.CoherenceConfig{Clock: replayAuthorityClock{f}})
	f.coherence = inner.Coherence
	gate := &replayRecoveryHandler{Handler: f.server.Handler, kind: "open", entered: make(chan struct{}), release: make(chan struct{}), cold: make(chan struct{}), replayed: make(chan *authoritypb.Response, 4), settled: make(chan struct{})}
	f.server.Handler = gate
	var releaseOnce, settleOnce sync.Once
	release := func() { releaseOnce.Do(func() { close(gate.release) }) }
	settle := func() { settleOnce.Do(func() { close(gate.settled) }) }
	t.Cleanup(func() { release(); settle() })
	f.mountAll()
	m := f.mounts[0]
	kernel := m.kernelMount
	mustWrite(t, f.join(0, "data"), []byte("original"), 0600)
	root := mustOpenFile(t, f.mountPath(0), os.O_RDONLY, 0)
	if err := root.Sync(); err != nil {
		t.Fatal(err)
	}
	root.Close()
	gate.armed.Store(true)
	opened := make(chan *os.File, 1)
	openErrors := make(chan error, 1)
	go func() { file, err := os.OpenFile(f.join(0, "data"), os.O_RDWR, 0); opened <- file; openErrors <- err }()
	select {
	case <-gate.entered:
	case <-time.After(5 * time.Second):
		t.Fatal("OPEN did not reach recorded boundary")
	}
	oldInc := m.delegations.incarnation()
	f.advanceClock(15 * time.Second)
	offset.Add(int64(15 * time.Second))
	var session volumeserver.SessionID
	copy(session[:], f.transports[0].session)
	if err := f.coherence.CheckSession(volumeserver.SubscriptionToken{Session: session, Incarnation: oldInc}); err == nil {
		t.Fatal("authority horizon did not expire")
	}
	m.subscription.deactivate()
	listener.cut(t, "data")
	release()
	var file *os.File
	select {
	case file = <-opened:
	case <-time.After(5 * time.Second):
		t.Fatal("OPEN replay failed to resolve")
	}
	if err := <-openErrors; err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	settle()
	waitUntil(t, 10*time.Second, "cold subscription after OPEN", func() bool { inc := m.subscription.stamp().incarnation; return inc != 0 && inc != oldInc })
	select {
	case replay := <-gate.replayed:
		gate.mu.Lock()
		want := proto.Clone(gate.outcome).(*authoritypb.Response)
		gate.mu.Unlock()
		want.RequestId = replay.RequestId
		if !proto.Equal(want, replay) || replay.GetMutation() == nil {
			t.Fatalf("OPEN exact outcome changed: %v", replay)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("lost OPEN was not replayed")
	}
	if got := readExactlyAt(t, file, 0, 8, "retained OPEN descriptor"); string(got) != "original" {
		t.Fatal(string(got))
	}
	fresh := mustOpenFile(t, f.join(0, "fresh"), os.O_CREATE|os.O_RDWR, 0600)
	if _, err := fresh.Write([]byte("usable")); err != nil {
		t.Fatal(err)
	}
	if err := fresh.Sync(); err != nil {
		t.Fatal(err)
	}
	fresh.Close()
	installed, err := observeKernelMount(f.mountPath(0))
	if err != nil {
		t.Fatal(err)
	}
	if installed.id != kernel.id || installed.device != kernel.device || m.isRevoked() || f.clients[0].SessionEndCause() != nil {
		t.Fatal("OPEN replay terminated original FUSE connection")
	}
}

// A cache buffer can be stopped while its assigned ordered WRITE still owns
// immutable spans and a replay slot. Reset joins that resolver, then discards
// the old local cut without treating its late application receipt as durability.
func TestKernelAssignedFlushReplaySurvivesColdReset(t *testing.T) {
	var offset atomic.Int64
	var listener *replayCutListener
	f := newIntegrationFixture(t, integrationConfig{Mounts: 1, skipMounts: true, SessionLease: 2 * time.Minute, clockOffset: &offset, wrapListener: func(l net.Listener) net.Listener { listener = &replayCutListener{Listener: l}; return listener }})
	inner := f.counter.inner.(*authorityrpc.VolumeHandler)
	inner.Coherence = volumeserver.NewCoherenceCoordinator(volumeserver.CoherenceConfig{Clock: replayAuthorityClock{f}})
	f.coherence = inner.Coherence
	gate := &replayRecoveryHandler{Handler: f.server.Handler, kind: "write", entered: make(chan struct{}), release: make(chan struct{}), cold: make(chan struct{}), replayed: make(chan *authoritypb.Response, 4), settled: make(chan struct{})}
	f.server.Handler = gate
	var releaseOnce, settleOnce sync.Once
	release := func() { releaseOnce.Do(func() { close(gate.release) }) }
	settle := func() { settleOnce.Do(func() { close(gate.settled) }) }
	t.Cleanup(func() { release(); settle() })
	var writes atomic.Int32
	inner.OnMutation = func(o authorityrpc.MutationObservation) {
		if o.Operation == authoritymetrics.OperationWrite && o.Disposition == "executed" {
			writes.Add(1)
		}
	}
	f.mountAll()
	m := f.mounts[0]
	kernel := m.kernelMount
	root := mustOpenFile(t, f.mountPath(0), os.O_RDONLY, 0)
	defer root.Close()
	mustWrite(t, f.join(0, "data"), []byte("initial!"), 0600)
	held := mustOpenFile(t, f.join(0, "data"), os.O_RDWR, 0)
	defer held.Close()
	if err := root.Sync(); err != nil {
		t.Fatal(err)
	}
	baselineWrites := writes.Load()
	gate.armed.Store(true)
	if _, err := held.WriteAt([]byte("applied!"), 0); err != nil {
		t.Fatal(err)
	}
	select {
	case <-gate.entered:
	case <-time.After(5 * time.Second):
		t.Fatal("ordered WRITE did not record before loss")
	}
	oldInc := m.delegations.incarnation()
	f.advanceClock(15 * time.Second)
	offset.Add(int64(15 * time.Second))
	var session volumeserver.SessionID
	copy(session[:], f.transports[0].session)
	if err := f.coherence.CheckSession(volumeserver.SubscriptionToken{Session: session, Incarnation: oldInc}); err == nil {
		t.Fatal("authority subscription stayed live")
	}
	m.subscription.deactivate()
	listener.cut(t, "data")
	release()
	select {
	case replay := <-gate.replayed:
		gate.mu.Lock()
		want := proto.Clone(gate.outcome).(*authoritypb.Response)
		gate.mu.Unlock()
		want.RequestId = replay.RequestId
		if !proto.Equal(want, replay) || replay.GetMutation() == nil {
			t.Fatalf("ordered WRITE replay changed: %v", replay)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("cache reset abandoned assigned WRITE resolver")
	}
	settle()
	waitUntil(t, 10*time.Second, "cold reset joins assigned WRITE", func() bool { inc := m.subscription.stamp().incarnation; return inc != 0 && inc != oldInc })
	if writes.Load() != baselineWrites+1 {
		t.Fatalf("ordered storage WRITE executions=%d", writes.Load())
	}
	if m.delegations.LossSequence() == 0 {
		t.Fatal("late application receipt erased unproven tail loss")
	}
	if err := held.Sync(); !errors.Is(err, syscall.EIO) {
		t.Fatalf("affected handle fsync=%v", err)
	}
	if err := root.Sync(); !errors.Is(err, syscall.EIO) {
		t.Fatalf("old root barrier=%v", err)
	}
	requireContent(t, f.join(0, "data"), []byte("applied!"), "single original storage application")
	fresh := mustOpenFile(t, f.join(0, "fresh"), os.O_CREATE|os.O_RDWR, 0600)
	if _, err := fresh.Write([]byte("alive")); err != nil {
		t.Fatal(err)
	}
	if err := fresh.Sync(); err != nil {
		t.Fatal(err)
	}
	fresh.Close()
	newRoot := mustOpenFile(t, f.mountPath(0), os.O_RDONLY, 0)
	if err := newRoot.Sync(); err != nil {
		t.Fatal(err)
	}
	newRoot.Close()
	installed, err := observeKernelMount(f.mountPath(0))
	if err != nil {
		t.Fatal(err)
	}
	if installed.id != kernel.id || installed.device != kernel.device || m.isRevoked() || f.clients[0].SessionEndCause() != nil {
		t.Fatal("assigned WRITE reset ended original connection")
	}
}
