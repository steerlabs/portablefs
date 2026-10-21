//go:build linux

package fusev3

import (
	"context"
	"fmt"
	"net"
	"os"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"github.com/hanwen/go-fuse/v2/fuse"
	"github.com/steerlabs/portablefs/vcs/internal/authoritypb"
	"github.com/steerlabs/portablefs/vcs/internal/authorityrpc"
	"github.com/steerlabs/portablefs/vcs/internal/volumeserver"
	"github.com/steerlabs/portablefs/vcs/internal/writeback"
)

// Use the real XFS authority and TLS client with a manually driven RawFS. This
// exposes callback return separately from physical settlement and cold activation;
// no kernel scheduler or subscription-runner timing chooses these boundaries.
func newCleanupFrontend(t *testing.T, f *integrationFixture) (*Mount, *rawFileSystem, *integrationTransport) {
	t.Helper()
	client, transport := f.dialClient()
	cfg := testConfig(integrationMaxInFlight)
	cfg.RequestTimeout = integrationRequestTimeout
	cfg.MaxInFlight = integrationMaxInFlight
	cfg.PresentedUID, cfg.PresentedGID = uint32(os.Geteuid()), uint32(os.Getegid())
	cfg.subscriptionClock = replaySubscriptionClockFor(f.cfg.clockOffset)
	m := newMount(context.Background(), transport, cfg)
	root := &node{mount: m, item: cloneItem(transport.Root()), requestTimeout: cfg.RequestTimeout, maxRead: 64 << 10, maxWrite: 64 << 10}
	raw := newRawFileSystem(m, root)
	m.setNotifier(&fakeNotifier{})
	t.Cleanup(func() {
		m.cancel()
		m.delegations.Stop()
		_ = client.DetachAfterUnmount(context.Background(), &authoritypb.MountAbsenceProof{ObservedUnixNanos: time.Now().UnixNano(), Observation: []byte("manually driven raw frontend installed no kernel mount"), Component: "fusev3-cleanup-test"})
		_ = client.Close()
	})
	if err := m.subscription.subscribe(t.Context()); err != nil {
		t.Fatal(err)
	}
	return m, raw, transport
}

func cleanupClockFixture(t *testing.T, offset *atomic.Int64, listener **replayCutListener, wrap func(authorityrpc.Handler) authorityrpc.Handler) *integrationFixture {
	t.Helper()
	f := newIntegrationFixture(t, integrationConfig{Mounts: 1, skipMounts: true, SessionLease: 2 * time.Minute, clockOffset: offset, wrapListener: func(l net.Listener) net.Listener {
		cut := &replayCutListener{Listener: l}
		*listener = cut
		return cut
	}, beforeServe: func(f *integrationFixture) {
		inner := f.counter.inner.(*authorityrpc.VolumeHandler)
		inner.Coherence = volumeserver.NewCoherenceCoordinator(volumeserver.CoherenceConfig{Clock: replayAuthorityClock{f}})
		f.coherence = inner.Coherence
		f.counter.trackOpens = true
		f.counter.openHandles = make(map[integrationOpenKey]struct{})
		if wrap != nil {
			f.server.Handler = wrap(f.server.Handler)
		}
	}})
	return f
}

func expireCleanupSubscription(t *testing.T, f *integrationFixture, m *Mount, transport *integrationTransport, offset *atomic.Int64) {
	t.Helper()
	inc := m.delegations.incarnation()
	f.advanceClock(15 * time.Second)
	offset.Add(int64(15 * time.Second))
	var session volumeserver.SessionID
	copy(session[:], transport.session)
	if err := f.coherence.CheckSession(volumeserver.SubscriptionToken{Session: session, Incarnation: inc}); err == nil {
		t.Fatal("authority subscription did not expire")
	}
}

func awaitCleanup(t *testing.T, ch <-chan struct{}, description string) {
	t.Helper()
	select {
	case <-ch:
	case <-time.After(5 * time.Second):
		t.Fatal(description)
	}
}

func TestStaleCreateCallbackHistoryPrecedesColdReset(t *testing.T) {
	for _, mode := range []string{"physical_reply", "full_queue", "full_queue_shutdown"} {
		t.Run(mode, func(t *testing.T) {
			var offset atomic.Int64
			var listener *replayCutListener
			f := cleanupClockFixture(t, &offset, &listener, nil)
			mount, raw, transport := newCleanupFrontend(t, f)
			mount.delegations.Stop()
			m, err := newDelegationManagerWithCloseCapacity(transport, integrationRequestTimeout, mount.subscription.stamp().incarnation, writeback.Options{}, 1)
			if err != nil {
				t.Fatal(err)
			}
			mount.delegations, mount.subscription.control, m.subscription = m, m, mount.subscription
			m.SetCleanupFailureReporter(func(err error) { mount.cleanupFailed("callback cleanup", err, nil) })
			active, waiting := make(chan struct{}), make(chan struct{})
			var waitingOnce sync.Once
			m.SetCleanupRetryWaiter(func(ctx context.Context) error {
				waitingOnce.Do(func() { close(waiting) })
				select {
				case <-active:
					return nil
				case <-ctx.Done():
					return ctx.Err()
				}
			})
			root := raw.nodesByID[1]
			var scratch []*dirHandle
			if mode != "physical_reply" {
				for range 3 {
					scratchUnique := nextTestRequestUnique()
					ctx, finish, status := raw.mutationContext(scratchUnique)
					if !status.Ok() {
						t.Fatal(status)
					}
					h, _, errno := root.node.OpendirHandle(ctx, syscall.O_RDONLY)
					finish()
					completeTestReply(t, raw, scratchUnique, fuse.OK)
					if errno != 0 {
						t.Fatal(errno)
					}
					scratch = append(scratch, h)
				}
			}
			accepted, deliver := make(chan struct{}), make(chan struct{})
			var deliverOnce sync.Once
			releaseResponse := func() { deliverOnce.Do(func() { close(deliver) }) }
			defer releaseResponse()
			transport.setAfterMutation(func(req *authoritypb.Request, response *authoritypb.Response, err error) {
				if req.GetCreate() != nil {
					if err != nil || response.GetCreate() == nil || response.GetPostState() == nil {
						t.Error("CREATE did not carry accepted post-state")
					}
					close(accepted)
					<-deliver
				}
			})
			unique := nextTestRequestUnique()
			ready, finishGate, returned := make(chan context.Context, 1), make(chan struct{}), make(chan struct{})
			atHistory, historyGate := make(chan struct{}), make(chan struct{})
			var historyOnce sync.Once
			releaseHistory := func() { historyOnce.Do(func() { close(historyGate) }) }
			defer releaseHistory()
			var finishOnce sync.Once
			releaseFinish := func() { finishOnce.Do(func() { close(finishGate) }) }
			defer releaseFinish()
			var created *fileHandle
			go func() {
				defer close(returned)
				ctx, finish, status := raw.mutationContext(unique)
				if !status.Ok() {
					t.Error(status)
					return
				}
				defer finish()
				callback := ctx.Value(mutationCallbackKey{}).(*mutationCallback)
				callback.beforeHistoryEnd = func() { close(atHistory); <-historyGate }
				item, handle, _, errno := root.node.Create(ctx, "stale-created", syscall.O_RDONLY|syscall.O_CREAT|syscall.O_EXCL, 0600)
				if errno != 0 {
					t.Error(errno)
					return
				}
				created = handle
				record, errno := raw.intern(ctx, item)
				if errno != 0 {
					t.Error(errno)
					return
				}
				raw.bindPath(record, root, "stale-created")
				if err := raw.publishEntry(ctx, &fuse.EntryOut{}, root, "stale-created", record, item.Attr); err != nil {
					t.Error(err)
					return
				}
				if err := completeSourcePublication(ctx); err != nil {
					t.Error(err)
					return
				}
				if len(scratch) != 0 {
					if outcome := scratch[2].closeForCleanup(ctx); outcome.failed() {
						t.Error(outcome.cause)
					}
				}
				ready <- ctx
				<-finishGate
			}()
			awaitCleanup(t, accepted, "CREATE was not recorded")
			expireCleanupSubscription(t, f, mount, transport, &offset)
			if len(scratch) != 0 {
				if outcome := scratch[0].closeForCleanup(t.Context()); outcome.failed() {
					t.Fatal(outcome.cause)
				}
				awaitCleanup(t, waiting, "cleanup did not retain the refused descriptor")
				if outcome := scratch[1].closeForCleanup(t.Context()); outcome.failed() {
					t.Fatal(outcome.cause)
				}
				if len(m.closeQueue) != cap(m.closeQueue) {
					t.Fatal("close queue is not full")
				}
			}
			m.InterruptSubscription()
			releaseResponse()
			var callbackCtx context.Context
			select {
			case callbackCtx = <-ready:
			case <-time.After(5 * time.Second):
				t.Fatal("stale CREATE failed to pin metadata")
			}
			raw.mu.Lock()
			pin := raw.replyPublications[unique].holderAdmission
			raw.mu.Unlock()
			if pin == nil || pin.admission.TryLock() {
				t.Fatal("CREATE has no physical metadata pin")
			}
			if len(scratch) != 0 && pendingCloses(m) != 3 {
				t.Fatal("callback did not reserve its producer")
			}

			// Hold the index exactly where endGrantRequest must finish. Queue a
			// cold writer before letting the callback exit, then prove that writer
			// cannot cross the reader/history boundary while the index is held.
			releaseFinish()
			awaitCleanup(t, atHistory, "callback did not reach history cleanup")
			m.mu.Lock()
			indexHeld := true
			defer func() {
				if indexHeld {
					m.mu.Unlock()
				}
			}()
			crossed, resetGate, recovered := make(chan struct{}), make(chan struct{}), make(chan struct{})
			var resetOnce sync.Once
			releaseReset := func() { resetOnce.Do(func() { close(resetGate) }) }
			defer releaseReset()
			go func() {
				mount.epochMu.Lock()
				close(crossed)
				<-resetGate
				m.FenceSubscription("callback exit with a physical metadata pin")
				mount.epochMu.Unlock()
				close(recovered)
			}()
			waitUntil(t, time.Second, "cold writer queued behind callback", func() bool {
				if mount.epochMu.TryRLock() {
					mount.epochMu.RUnlock()
					return false
				}
				return true
			})
			releaseHistory()
			awaitCleanup(t, callbackCtx.Done(), "callback did not finish its work context")
			select {
			case <-crossed:
				t.Error("cold writer crossed unfinished grant-history cleanup")
			case <-time.After(50 * time.Millisecond):
			}
			m.mu.Unlock()
			indexHeld = false
			awaitCleanup(t, returned, "callback did not return")
			awaitCleanup(t, crossed, "cold writer did not acquire epoch")
			releaseReset()
			waitUntil(t, time.Second, "reset joined physical metadata pin", func() bool {
				if m.epoch.TryRLock() {
					m.epoch.RUnlock()
					return false
				}
				return true
			})
			select {
			case <-recovered:
				t.Fatal("reset discarded a physical metadata pin")
			default:
			}
			stopped := make(chan struct{})
			if mode == "full_queue_shutdown" {
				go func() { m.Stop(); close(stopped) }()
			}
			completeTestReply(t, raw, unique, fuse.OK)
			awaitCleanup(t, recovered, "physical reply and cold reset deadlocked")
			if mode == "full_queue_shutdown" {
				awaitCleanup(t, stopped, "shutdown failed to join the reserved producer")
				if pendingCloses(m) != 0 {
					t.Fatal("shutdown stranded cleanup ownership")
				}
			} else {
				transport.setAfterMutation(nil)
				if err := mount.subscription.subscribe(t.Context()); err != nil {
					t.Fatal(err)
				}
				close(active)
				waitUntil(t, 5*time.Second, "cleanup after cold activation", func() bool { return pendingCloses(m) == 0 })
				if err := created.closeForCleanup(t.Context(), 0, false); err.failed() {
					t.Fatal(err.cause)
				}
				waitUntil(t, 5*time.Second, "CREATE descriptor retired", func() bool { return pendingCloses(m) == 0 })
			}
			if mount.isRevoked() || transport.SessionEndCause() != nil {
				t.Fatalf("unexpected terminal cleanup: %v / %v", mount.fatalError(), transport.SessionEndCause())
			}
		})
	}
}

func TestWriteAndSetattrReacquisitionRetainTemporaryDescriptors(t *testing.T) {
	for _, operation := range []string{"WRITE", "SETATTR"} {
		for _, expiry := range []string{"before_install", "after_install"} {
			t.Run(fmt.Sprintf("%s/%s", operation, expiry), func(t *testing.T) {
				var offset atomic.Int64
				var listener *replayCutListener
				gate := &replayRecoveryHandler{kind: "open", entered: make(chan struct{}), release: make(chan struct{}), cold: make(chan struct{}), replayed: make(chan *authoritypb.Response, 4), settled: make(chan struct{})}
				var closeAttempts, retired atomic.Int32
				scratchHandle := func() []byte {
					gate.mu.Lock()
					defer gate.mu.Unlock()
					return cloneBytes(gate.outcome.GetOpen().GetHandle())
				}
				// Count actual retirement at the authority, including exact replay.
				observer := &cleanupOutcomeHandler{Handler: gate, observe: func(req *authoritypb.Request, result *authoritypb.Response) {
					if batch := req.GetCloseBatch(); batch != nil && result.GetErrno() == 0 {
						for i, c := range batch.Closes {
							if string(c.Handle) == string(scratchHandle()) && result.GetCloseBatch().GetResults()[i].GetRetired() {
								retired.Add(1)
							}
						}
					} else if req.GetCloseBatch() != nil && result.GetFailure() == authoritypb.FailureClass_FAILURE_CLASS_COHERENCE {
						if result.GetMutation() != nil || result.GetSessionTerminal() {
							t.Error("refusal was recorded or terminal")
						}
					}
				}}
				f := cleanupClockFixture(t, &offset, &listener, func(handler authorityrpc.Handler) authorityrpc.Handler {
					gate.Handler = handler
					return observer
				})
				var releaseOnce sync.Once
				release := func() { releaseOnce.Do(func() { close(gate.release) }) }
				defer release()
				defer func() { gate.coldOnce.Do(func() { close(gate.cold) }) }()
				mount, raw, transport := newCleanupFrontend(t, f)
				m := mount.delegations
				unique := nextTestRequestUnique()
				out := &fuse.CreateOut{}
				status := raw.Create(nil, &fuse.CreateIn{InHeader: fuse.InHeader{Unique: unique, NodeId: 1}, Flags: syscall.O_CREAT | syscall.O_RDWR, Mode: 0600}, "reacquire", out)
				completeTestReply(t, raw, unique, fuse.OK)
				if !status.Ok() {
					t.Fatal(status)
				}
				held := raw.handles[out.Fh].file
				identity := held.node.item.GetStableIdentity()
				if err := m.ReleaseBatch(t.Context(), [][]byte{identity}); err != nil {
					t.Fatal(err)
				}
				f.counter.mu.Lock()
				baseline := len(f.counter.openHandles)
				f.counter.mu.Unlock()
				active, waiting := make(chan struct{}), make(chan struct{})
				var waitingOnce sync.Once
				m.SetCleanupRetryWaiter(func(ctx context.Context) error {
					waitingOnce.Do(func() { close(waiting) })
					select {
					case <-active:
						return nil
					case <-ctx.Done():
						return ctx.Err()
					}
				})
				var scratch []byte
				// The first cleanup batch must reach the authority while expired,
				// yielding a real unrecorded refusal, not an injected client error.
				transport.hookMu.Lock()
				transport.beforeDelegatedMutation = func(ctx context.Context, req *authoritypb.Request) error {
					if batch := req.GetCloseBatch(); batch != nil {
						if len(batch.Closes) != 1 || string(batch.Closes[0].Handle) != string(scratchHandle()) {
							t.Error("cleanup changed its temporary handle")
						}
						if closeAttempts.Add(1) == 1 && expiry == "after_install" {
							// Complete the accepted operation's durability before expiry;
							// this schedule isolates descriptor cleanup from volatile loss.
							m.advanceDurability()
							if operation == "WRITE" && !m.Owns(identity) {
								t.Error("scratch cleanup preceded successful grant installation")
							}
							expireCleanupSubscription(t, f, mount, transport, &offset)
						}
					}
					return nil
				}
				transport.hookMu.Unlock()

				gate.armed.Store(true)
				done := make(chan fuse.Status, 1)
				go func() {
					unique := nextTestRequestUnique()
					var status fuse.Status
					if operation == "WRITE" {
						_, status = raw.writeStock(&fuse.WriteIn{InHeader: fuse.InHeader{Unique: unique, NodeId: out.NodeId}, Fh: out.Fh, Size: 1, Flags: syscall.O_RDWR | syscall.O_APPEND | syscall.O_SYNC}, []byte("x"))
					} else {
						in := &fuse.SetAttrIn{}
						in.Unique, in.NodeId, in.Valid, in.Size = unique, out.NodeId, fuse.FATTR_SIZE, 0
						status = raw.SetAttr(nil, in, &fuse.AttrOut{})
					}
					completeTestReply(t, raw, unique, fuse.OK)
					done <- status
				}()
				awaitCleanup(t, gate.entered, "write-intent OPEN was not recorded")
				gate.mu.Lock()
				scratch = cloneBytes(gate.outcome.GetOpen().GetHandle())
				if !gate.original.GetOpen().GetWriteIntent() || gate.outcome.GetMutation() == nil || len(scratch) != 16 {
					t.Fatal("reacquisition was not a recorded write-intent OPEN")
				}
				gate.mu.Unlock()
				if expiry == "before_install" {
					expireCleanupSubscription(t, f, mount, transport, &offset)
					listener.cut(t, "data")
				}
				release()
				select {
				case status := <-done:
					if expiry == "before_install" && status != fuse.EIO {
						t.Fatalf("expired reacquisition: %v", status)
					}
					if expiry == "after_install" && !status.Ok() {
						t.Fatalf("installed reacquisition: %v", status)
					}
				case <-time.After(5 * time.Second):
					t.Fatal("WRITE/SETATTR callback failed to return")
				}
				if expiry == "before_install" {
					select {
					case replay := <-gate.replayed:
						if string(replay.GetOpen().GetHandle()) != string(scratch) {
							t.Fatal("replay changed scratch handle")
						}
					case <-time.After(5 * time.Second):
						t.Fatal("lost OPEN was not replayed")
					}
				}
				awaitCleanup(t, waiting, "unrecorded refusal abandoned its cleanup owner")
				if pendingCloses(m) != 1 || retired.Load() != 0 || closeAttempts.Load() != 1 {
					t.Fatalf("pending=%d retired=%d attempts=%d", pendingCloses(m), retired.Load(), closeAttempts.Load())
				}
				f.counter.mu.Lock()
				live := len(f.counter.openHandles)
				f.counter.mu.Unlock()
				if live != baseline+1 {
					t.Fatalf("authority open table: %d, want baseline %d + scratch", live, baseline)
				}
				close(gate.settled)
				if err := mount.subscription.subscribe(t.Context()); err != nil {
					t.Fatal(err)
				}
				close(active)
				waitUntil(t, 5*time.Second, "scratch retirement after cold activation", func() bool { return pendingCloses(m) == 0 })
				if retired.Load() != 1 || closeAttempts.Load() != 2 {
					t.Fatalf("retired=%d attempts=%d", retired.Load(), closeAttempts.Load())
				}
				f.counter.mu.Lock()
				live = len(f.counter.openHandles)
				f.counter.mu.Unlock()
				if live != baseline {
					t.Fatalf("authority open table: %d, baseline %d", live, baseline)
				}
				if m.LossSequence() != 0 {
					t.Fatal("descriptor recovery lost accepted data")
				}
				transport.hookMu.Lock()
				transport.beforeDelegatedMutation = nil
				transport.hookMu.Unlock()
				// The original descriptor remains usable independently of the
				// retired scratch handle and can obtain the next live write grant.
				unique = nextTestRequestUnique()
				_, status = raw.writeStock(&fuse.WriteIn{InHeader: fuse.InHeader{Unique: unique, NodeId: out.NodeId}, Fh: out.Fh, Size: 1, Flags: syscall.O_RDWR | syscall.O_APPEND | syscall.O_SYNC}, []byte("y"))
				completeTestReply(t, raw, unique, fuse.OK)
				if !status.Ok() || mount.isRevoked() || transport.SessionEndCause() != nil {
					t.Fatalf("original descriptor/session unusable: %v / %v / %v", status, mount.fatalError(), transport.SessionEndCause())
				}
			})
		}
	}
}

type cleanupOutcomeHandler struct {
	authorityrpc.Handler
	observe func(*authoritypb.Request, *authoritypb.Response)
}

func (h *cleanupOutcomeHandler) Handle(ctx context.Context, req *authoritypb.Request) *authoritypb.Response {
	result := h.Handler.Handle(ctx, req)
	h.observe(req, result)
	return result
}
