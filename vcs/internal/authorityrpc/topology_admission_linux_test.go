//go:build linux

package authorityrpc

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"syscall"
	"testing"
	"time"

	"github.com/steerlabs/portablefs/vcs/internal/authoritypb"
	"github.com/steerlabs/portablefs/vcs/internal/localroutes"
	"github.com/steerlabs/portablefs/vcs/internal/restorefixture"
	"github.com/steerlabs/portablefs/vcs/internal/volumeserver"
	"github.com/steerlabs/portablefs/vcs/internal/xfsstore"
	"google.golang.org/protobuf/proto"
)

// No timer can expire a recall or subscription in these schedules. Watchdogs
// only fail a test; flush and exact CONTROL acknowledgments provide progress.
type topologyFrozenClock struct{ now time.Time }

func (c topologyFrozenClock) Now() time.Time { return c.now }
func (topologyFrozenClock) NewTimer(time.Duration) volumeserver.CoherenceTimer {
	return topologyFrozenTimer{make(chan time.Time)}
}

type topologyFrozenTimer struct{ ch chan time.Time }

func (c topologyFrozenTimer) C() <-chan time.Time { return c.ch }
func (topologyFrozenTimer) Stop() bool            { return true }

type topologyMembership struct {
	*volumeserver.FileMountMembership
	mu             sync.Mutex
	active         map[volumeserver.SessionID]volumeserver.MountMembershipProfile
	beforeActivate func(volumeserver.SessionID)
}

func (m *topologyMembership) Activate(id volumeserver.SessionID) error {
	return m.ActivateProfile(id, volumeserver.MembershipFSKitExclusive)
}
func (m *topologyMembership) ActivateProfile(id volumeserver.SessionID, p volumeserver.MountMembershipProfile) error {
	if m.beforeActivate != nil {
		m.beforeActivate(id)
	}
	if err := m.FileMountMembership.ActivateProfile(id, p); err != nil {
		return err
	}
	m.mu.Lock()
	m.active[id] = p
	m.mu.Unlock()
	return nil
}
func (m *topologyMembership) Deactivate(id volumeserver.SessionID) error {
	if err := m.FileMountMembership.Deactivate(id); err != nil {
		return err
	}
	m.mu.Lock()
	delete(m.active, id)
	m.mu.Unlock()
	return nil
}
func (m *topologyMembership) has(id volumeserver.SessionID, p volumeserver.MountMembershipProfile) bool {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.active[id] == p
}

type topologyAuthorizer struct{ deadline time.Time }

func (a topologyAuthorizer) Authorize(_ context.Context, _ string, token []byte) (volumeserver.Authorization, error) {
	access := volumeserver.AccessRead | volumeserver.AccessWrite | volumeserver.AccessAdmin
	if bytes.Equal(token, []byte("cacheless")) {
		access = volumeserver.AccessRead
	}
	return volumeserver.Authorization{Access: access, Deadline: a.deadline}, nil
}

type topologyHandlerFixture struct {
	h          *VolumeHandler
	ctx        context.Context
	root       string
	epoch      []byte
	membership *topologyMembership
}

func newTopologyHandlerFixture(t *testing.T) *topologyHandlerFixture {
	t.Helper()
	root := restorefixture.Root(t)
	store := openTakeoverTestStore(t, root)
	now := time.Now()
	runtime, err := volumeserver.New("handler-fskit", volumeserver.Config{SessionLease: time.Minute, MaxReplaySlots: 16, MaxSessions: 8, MaxLockRecords: 64, Now: func() time.Time { return now }, ContinuousNow: func() (time.Duration, error) { return time.Second, nil }})
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "mount.membership")
	if err := os.Chmod(filepath.Dir(path), 0700); err != nil {
		t.Fatal(err)
	}
	durable, _, err := volumeserver.OpenFileMountMembership(path, "handler-fskit", true)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = durable.Close() })
	membership := &topologyMembership{FileMountMembership: durable, active: make(map[volumeserver.SessionID]volumeserver.MountMembershipProfile)}
	c, err := NewCoordination(CoordinationConfig{Store: store, Fencer: runtime, Locks: runtime.Locks(), Membership: membership, Prior: volumeserver.PriorEpochStrictMountsFenced, Now: func() time.Time { return now }, ContinuousNow: func() (time.Duration, error) { return time.Second, nil }})
	if err != nil {
		t.Fatal(err)
	}
	c.Coherence = volumeserver.NewCoherenceCoordinator(volumeserver.CoherenceConfig{Clock: topologyFrozenClock{now}})
	h := testVolumeHandler()
	c.Bind(h)
	h.Store, h.Runtime, h.Authorizer = store, runtime, topologyAuthorizer{deadline: now.Add(time.Hour)}
	ctx := context.WithValue(t.Context(), peerIdentityKey{}, [32]byte{0xA5})
	return &topologyHandlerFixture{h: h, ctx: ctx, root: root, membership: membership}
}
func (f *topologyHandlerFixture) attach(t *testing.T, id uint64, profile authoritypb.FrontendProfile, active bool) (*authoritypb.Response, *authoritypb.Request) {
	t.Helper()
	request := fskitAttachRequest(id)
	request.GetAttach().FrontendProfile = profile
	request.GetAttach().ReplaySlots = 9
	if profile == authoritypb.FrontendProfile_FRONTEND_PROFILE_CACHELESS_READER {
		request.GetAttach().AccessToken = []byte("cacheless")
	}
	if profile == authoritypb.FrontendProfile_FRONTEND_PROFILE_UNSPECIFIED {
		request.GetAttach().Purpose = authoritypb.SessionPurpose_SESSION_PURPOSE_ROUTE_ADMIN
		request.GetAttach().RoutesRevision = nil
	}
	attached := f.h.Handle(f.ctx, request)
	if attached.GetErrno() != 0 {
		t.Fatalf("attach=%v", attached)
	}
	f.epoch = attached.GetEpoch()
	proof := proofFromAttach(attached)
	var session volumeserver.SessionID
	copy(session[:], proof.GetId())
	t.Cleanup(func() {
		// A failed frozen-clock schedule must not strand teardown behind a
		// recall. Retire every holder before waiting on an activation token.
		f.membership.mu.Lock()
		ids := make([]volumeserver.SessionID, 0, len(f.membership.active))
		for id := range f.membership.active {
			ids = append(ids, id)
		}
		f.membership.mu.Unlock()
		for _, id := range ids {
			f.h.Coherence.ExpireSession(id)
		}
		f.h.Runtime.FenceSession(session)
	})
	activation := &authoritypb.Request{RequestId: id + 1, Epoch: f.epoch, Session: proof, Body: &authoritypb.Request_Activate{Activate: &authoritypb.ActivateRequest{AttachAttemptId: testAttachAttempt(id), DataBindingGeneration: 1, ControlBindingGeneration: 1}}}
	if active {
		return f.require(t, f.ctx, activation), activation
	}
	return attached, activation
}
func (f *topologyHandlerFixture) handle(t *testing.T, ctx context.Context, req *authoritypb.Request) *authoritypb.Response {
	t.Helper()
	done := make(chan *authoritypb.Response, 1)
	go func() { done <- f.h.Handle(ctx, req) }()
	return admissionReceive(t, done)
}

func (f *topologyHandlerFixture) require(t *testing.T, ctx context.Context, req *authoritypb.Request) *authoritypb.Response {
	t.Helper()
	r := f.handle(t, ctx, req)
	if r.GetErrno() != 0 {
		t.Fatalf("%T=%v", req.Body, r)
	}
	return r
}
func topologySession(proof *authoritypb.SessionProof) volumeserver.SessionID {
	var id volumeserver.SessionID
	copy(id[:], proof.GetId())
	return id
}
func (f *topologyHandlerFixture) routesRequest(proof *authoritypb.SessionProof, rules string, expected [32]byte) *authoritypb.Request {
	return &authoritypb.Request{RequestId: 90, Epoch: f.epoch, Session: proof, Body: &authoritypb.Request_ApplyRoutes{ApplyRoutes: &authoritypb.ApplyRoutesRequest{Rules: []byte(rules), ExpectedRevision: expected[:]}}}
}
func (f *topologyHandlerFixture) subscribedFile(t *testing.T) (*authoritypb.SessionProof, *authoritypb.SubscribeReply, *authoritypb.CreateReply) {
	t.Helper()
	linux, activation := f.attach(t, 10, authoritypb.FrontendProfile_FRONTEND_PROFILE_LINUX, true)
	proof := activation.Session
	sub := f.require(t, f.ctx, &authoritypb.Request{RequestId: 12, Epoch: f.epoch, Session: proof, Body: &authoritypb.Request_Subscribe{Subscribe: &authoritypb.SubscribeRequest{}}}).GetSubscribe()
	create := f.require(t, f.ctx, &authoritypb.Request{RequestId: 13, Epoch: f.epoch, Session: proof, Mutation: &authoritypb.Mutation{Sequence: 1}, Body: &authoritypb.Request_Create{Create: &authoritypb.CreateRequest{Parent: linux.GetActivate().GetRoot().GetToken(), Name: []byte("dirty"), Mode: 0600, Flags: &authoritypb.OpenFlags{Read: true, Write: true}, Exclusive: true, WriteIntent: true}}}).GetCreate()
	if create.GetDelegation() == nil {
		t.Fatal("CREATE did not grant delegation")
	}
	return proof, sub, create
}
func (f *topologyHandlerFixture) poll(t *testing.T, proof *authoritypb.SessionProof, incarnation uint64, want func(*authoritypb.ControlEvent) bool) *authoritypb.ControlEvent {
	t.Helper()
	var after uint64
	for {
		done := make(chan *authoritypb.Response, 1)
		go func(cursor uint64) {
			done <- f.h.Handle(f.ctx, &authoritypb.Request{RequestId: 70, Epoch: f.epoch, Session: proof, Body: &authoritypb.Request_NextControlEvent{NextControlEvent: &authoritypb.NextControlEventRequest{Incarnation: incarnation, AfterSequence: cursor}}})
		}(after)
		r := admissionReceive(t, done)
		if r.GetErrno() != 0 {
			t.Fatal(r)
		}
		event := r.GetControlEvent()
		if want(event) {
			return event
		}
		after = event.GetSequence()
	}
}
func (f *topologyHandlerFixture) flush(t *testing.T, proof *authoritypb.SessionProof, file *authoritypb.CreateReply) *authoritypb.Response {
	t.Helper()
	req := stockWriteTestRequest(80, 1, 1, xfsstore.Capability{}, []byte("committed dirty bytes"), 0, 0)
	req.Epoch, req.Session, req.GetWrite().Handle = f.epoch, proof, file.GetHandle()
	req.GetWrite().Delegation = &authoritypb.DelegationRef{Id: file.GetDelegation().GetId(), Generation: file.GetDelegation().GetGeneration()}
	return f.require(t, f.ctx, req)
}
func (f *topologyHandlerFixture) ack(t *testing.T, proof *authoritypb.SessionProof, sub *authoritypb.SubscribeReply, event *authoritypb.ControlEvent, applied uint64) {
	t.Helper()
	req := &authoritypb.Request{RequestId: 81, Epoch: f.epoch, Session: proof}
	if recall := event.GetDelegationRecall(); recall != nil {
		req.Body = &authoritypb.Request_DelegationRecallAck{DelegationRecallAck: &authoritypb.DelegationRecallAck{Incarnation: sub.GetIncarnation(), EventSequence: event.GetSequence(), Delegation: recall.GetDelegation(), AppliedSequence: applied}}
	} else {
		req.Body = &authoritypb.Request_DelegationBreakAck{DelegationBreakAck: &authoritypb.DelegationBreakAck{Incarnation: sub.GetIncarnation(), EventSequence: event.GetSequence(), Delegation: event.GetDelegationBreak().GetDelegation(), AppliedSequence: applied}}
	}
	f.require(t, f.ctx, req)
}

func TestTopologyActivationRecallAndPendingRoutesOnXFS(t *testing.T) {
	for _, ordinary := range []string{"none", "mutation", "write-open"} {
		for _, outcome := range []string{"real-change", "no-op", "stale-CAS", "tracked"} {
			t.Run(ordinary+"/"+outcome, func(t *testing.T) {
				f := newTopologyHandlerFixture(t)
				linux, sub, file := f.subscribedFile(t)
				_, admin := f.attach(t, 30, authoritypb.FrontendProfile_FRONTEND_PROFILE_UNSPECIFIED, true)
				_, activation := f.attach(t, 40, authoritypb.FrontendProfile_FRONTEND_PROFILE_FSKIT_EXCLUSIVE, false)
				activated := make(chan *authoritypb.Response, 1)
				go func() { activated <- f.h.Handle(f.ctx, activation) }()
				event := f.poll(t, linux, sub.GetIncarnation(), func(e *authoritypb.ControlEvent) bool { return e.GetDelegationRecall() != nil })
				f.h.coherenceProfileAdmission.mu.Lock()
				exclusive := f.h.coherenceProfileAdmission.writer
				f.h.coherenceProfileAdmission.mu.Unlock()
				if !exclusive {
					t.Fatal("recall did not hold exclusive profile admission")
				}
				var ordinaryDone chan *authoritypb.Response
				if ordinary != "none" {
					req := stockWriteTestRequest(50, 2, 1, xfsstore.Capability{}, []byte("must not apply"), 0, 0)
					req.Epoch, req.Session, req.GetWrite().Handle = f.epoch, linux, file.GetHandle()
					if ordinary == "write-open" {
						req.Body = &authoritypb.Request_Open{Open: &authoritypb.OpenRequest{Item: file.GetItem().GetToken(), Flags: &authoritypb.OpenFlags{Write: true}, WriteIntent: true}}
					}
					wait := newAdmissionWaitContext(f.ctx)
					ordinaryDone = make(chan *authoritypb.Response, 1)
					go func() { ordinaryDone <- f.h.Handle(wait, req) }()
					// Topology admission precedes this profile wait in the real handler.
					admissionReceive(t, wait.waiting)
				}
				rules, expected, want := "/local/\n", routesRevisionOf(""), int32(syscall.EBUSY)
				switch outcome {
				case "no-op":
					rules = ""
					want = 0
				case "stale-CAS":
					expected = routesRevisionOf("/stale/\n")
					rules = "/vendor/\n"
					want = int32(syscall.EPERM)
				case "tracked":
					rules = "/vendor/\n"
					want = int32(syscall.EINVAL)
				}
				if outcome == "tracked" || outcome == "stale-CAS" {
					if err := os.Mkdir(filepath.Join(f.root, ".git"), 0755); err != nil {
						t.Fatal(err)
					}
					if err := os.WriteFile(filepath.Join(f.root, ".git/index"), testGitIndex("vendor/tracked"), 0644); err != nil {
						t.Fatal(err)
					}
				}
				routeReq := f.routesRequest(admin.Session, rules, expected)
				wait := newAdmissionWaitContext(f.ctx)
				routeDone := make(chan *authoritypb.Response, 1)
				go func() { routeDone <- f.h.Handle(wait, routeReq) }()
				admissionReceive(t, wait.waiting)
				f.h.Routes.lockWaitAdmission.mu.Lock()
				adminHeld := f.h.Routes.lockWaitAdmission.writer
				f.h.Routes.lockWaitAdmission.mu.Unlock()
				if !adminHeld {
					t.Fatal("ApplyRoutes did not reach the topology wait")
				}
				// A wire reference is insufficient: a stale generation must still fail
				// BeginFlush before any storage effect even during exclusive admission.
				beforeStale := f.h.coherenceVersionNow()
				stale := stockWriteTestRequest(79, 3, 1, xfsstore.Capability{}, []byte("stale"), 0, 0)
				stale.Epoch, stale.Session, stale.GetWrite().Handle = f.epoch, linux, file.GetHandle()
				stale.GetWrite().Delegation = &authoritypb.DelegationRef{Id: file.GetDelegation().GetId(), Generation: file.GetDelegation().GetGeneration()}
				stale.GetWrite().Delegation.Generation++
				if r := f.handle(t, f.ctx, stale); r.GetErrno() == 0 {
					t.Fatalf("stale flush=%v", r)
				}
				if data, err := os.ReadFile(filepath.Join(f.root, "dirty")); err != nil || len(data) != 0 || f.h.coherenceVersionNow() != beforeStale {
					t.Fatalf("stale generation applied: %q/%v", data, err)
				}
				var identity [16]byte
				copy(identity[:], file.GetItem().GetStableIdentity())
				token, err := f.h.coherenceToken(topologySession(linux))
				if err != nil {
					t.Fatal(err)
				}
				delegationID, err := parseCoherenceDelegationID(file.GetDelegation().GetId())
				if err != nil {
					t.Fatal(err)
				}
				pin, err := f.h.Coherence.BeginFlush(token, identity, delegationID, file.GetDelegation().GetGeneration())
				if err != nil {
					t.Fatal(err)
				}
				defer pin.End(0)
				flushed := f.flush(t, linux, file)
				ack := &authoritypb.Request{RequestId: 81, Epoch: f.epoch, Session: linux, Body: &authoritypb.Request_DelegationRecallAck{DelegationRecallAck: &authoritypb.DelegationRecallAck{Incarnation: sub.GetIncarnation(), EventSequence: event.GetSequence(), Delegation: &authoritypb.DelegationRef{Id: file.GetDelegation().GetId(), Generation: file.GetDelegation().GetGeneration()}, AppliedSequence: flushed.GetAppliedSequence()}}}
				if r := f.handle(t, f.ctx, ack); r.GetErrno() != int32(syscall.EINVAL) {
					t.Fatalf("recall ignored generation apply pin: %v", r)
				}
				state := f.h.initCoherenceControlState()
				state.mu.Lock()
				coordinatorRequest := state.sessions[topologySession(linux)].obligations[event.GetSequence()].coordinatorRequest
				state.mu.Unlock()
				if err := f.h.Coherence.AckDelegation(token, identity, delegationID, file.GetDelegation().GetGeneration(), coordinatorRequest, flushed.GetAppliedSequence()); !errors.Is(err, volumeserver.ErrDelegationBusy) {
					t.Fatalf("pinned recall reason = %v", err)
				}
				pin.End(flushed.GetAppliedSequence())
				f.ack(t, linux, sub, event, flushed.GetAppliedSequence())
				response := admissionReceive(t, activated)
				if response.GetErrno() != 0 {
					t.Fatal(response)
				}
				if ordinaryDone != nil {
					r := admissionReceive(t, ordinaryDone)
					if r.GetErrno() != int32(syscall.EBUSY) || r.GetPostState() != nil || r.GetMutation() != nil {
						t.Fatalf("ordinary operation=%v", r)
					}
				}
				routeResult := admissionReceive(t, routeDone)
				if routeResult.GetErrno() != want {
					t.Fatalf("ApplyRoutes=%v want errno %d", routeResult, want)
				}
				if outcome == "stale-CAS" && (routeResult.GetFailure() != authoritypb.FailureClass_FAILURE_CLASS_ROUTES || !bytes.Equal(routeResult.GetRoutesMismatch().GetActiveRevision(), emptyRoutesRevision()) || !bytes.Equal(routeResult.GetRoutesMismatch().GetPresentedRevision(), expected[:])) {
					t.Fatalf("CAS lost exact routing refusal: %v", routeResult)
				}
				if outcome == "no-op" && !bytes.Equal(routeResult.GetApplyRoutes().GetRevision(), emptyRoutesRevision()) {
					t.Fatal(routeResult)
				}
				if active, _ := f.h.Routes.Revision(); active != routesRevisionOf("") {
					t.Fatal("refused route changed topology")
				}
				data, err := os.ReadFile(filepath.Join(f.root, "dirty"))
				if err != nil || string(data) != "committed dirty bytes" {
					t.Fatalf("data=%q err=%v", data, err)
				}
				if _, live := f.h.Coherence.LookupDelegation(identity); live {
					t.Fatal("recall retained generation after ack and pin drain")
				}
				macID := topologySession(activation.Session)
				if !f.membership.has(macID, volumeserver.MembershipFSKitExclusive) {
					t.Fatal("Mac membership not durable")
				}
				if err := f.h.Writers.CheckOwner(macID); err != nil {
					t.Fatal(err)
				}
				cred, err := f.h.credential(f.ctx, activation)
				if err != nil {
					t.Fatal(err)
				}
				use, err := f.h.Runtime.Begin(cred)
				if err != nil {
					t.Fatal(err)
				}
				use.End()
				// Replay must return its retained body before any new topology/profile wait.
				writerEntered, writerRelease := make(chan struct{}), make(chan struct{})
				writerDone := make(chan error, 1)
				go func() {
					_, err := f.h.Lifecycle.ExecuteTopologyExclusive(f.ctx, func() (int, error) { close(writerEntered); <-writerRelease; return 0, nil })
					writerDone <- err
				}()
				admissionReceive(t, writerEntered)
				f.h.coherenceProfileAdmission.Lock()
				replayDone := make(chan *authoritypb.Response, 1)
				go func() { replayDone <- f.h.Handle(f.ctx, activation) }()
				replay := admissionReceive(t, replayDone)
				f.h.coherenceProfileAdmission.Unlock()
				close(writerRelease)
				if err := admissionReceive(t, writerDone); err != nil {
					t.Fatal(err)
				}
				if !proto.Equal(response.GetActivate(), replay.GetActivate()) {
					t.Fatalf("activation replay changed: %v", replay)
				}
			})
		}
	}
}

func TestTopologyCachelessBreakAndPendingRoutesOnXFS(t *testing.T) {
	f := newTopologyHandlerFixture(t)
	linux, sub, file := f.subscribedFile(t)
	reader, readActivation := f.attach(t, 20, authoritypb.FrontendProfile_FRONTEND_PROFILE_CACHELESS_READER, true)
	_, admin := f.attach(t, 30, authoritypb.FrontendProfile_FRONTEND_PROFILE_UNSPECIFIED, true)
	readDone := make(chan *authoritypb.Response, 1)
	go func() {
		readDone <- f.h.Handle(f.ctx, &authoritypb.Request{RequestId: 22, Epoch: f.epoch, Session: readActivation.Session, Mutation: &authoritypb.Mutation{Sequence: 1}, Body: &authoritypb.Request_Lookup{Lookup: &authoritypb.LookupRequest{Parent: reader.GetActivate().GetRoot().GetToken(), Name: []byte("dirty")}}})
	}()
	event := f.poll(t, linux, sub.GetIncarnation(), func(e *authoritypb.ControlEvent) bool { return e.GetDelegationBreak() != nil })
	wait := newAdmissionWaitContext(f.ctx)
	routesDone := make(chan *authoritypb.Response, 1)
	go func() {
		routesDone <- f.h.Handle(wait, f.routesRequest(admin.Session, "/local/\n", routesRevisionOf("")))
	}()
	admissionReceive(t, wait.waiting)
	flush := f.flush(t, linux, file)
	f.ack(t, linux, sub, event, flush.GetAppliedSequence())
	if r := admissionReceive(t, readDone); r.GetErrno() != 0 || r.GetLookup().GetItem().GetAttr().GetSize() != int64(len("committed dirty bytes")) {
		t.Fatalf("cacheless read=%v", r)
	}
	if r := admissionReceive(t, routesDone); r.GetErrno() != int32(syscall.EBUSY) {
		t.Fatalf("routes=%v", r)
	}
}

func TestTopologyActivationAndRoutePublicationOnXFS(t *testing.T) {
	t.Run("activation wins", func(t *testing.T) {
		f := newTopologyHandlerFixture(t)
		_, admin := f.attach(t, 10, authoritypb.FrontendProfile_FRONTEND_PROFILE_UNSPECIFIED, true)
		_, activation := f.attach(t, 20, authoritypb.FrontendProfile_FRONTEND_PROFILE_FSKIT_EXCLUSIVE, false)
		entered, release := make(chan struct{}), make(chan struct{})
		unblock := sync.OnceFunc(func() { close(release) })
		defer unblock()
		f.membership.beforeActivate = func(volumeserver.SessionID) { close(entered); <-release }
		activated := make(chan *authoritypb.Response, 1)
		go func() { activated <- f.h.Handle(f.ctx, activation) }()
		admissionReceive(t, entered)
		wait := newAdmissionWaitContext(f.ctx)
		routeDone := make(chan *authoritypb.Response, 1)
		go func() {
			routeDone <- f.h.Handle(wait, f.routesRequest(admin.Session, "/local/\n", routesRevisionOf("")))
		}()
		admissionReceive(t, wait.waiting)
		if _, err := os.Lstat(filepath.Join(f.root, localroutes.ConfigPath)); !os.IsNotExist(err) {
			t.Fatalf("route published during activation: %v", err)
		}
		unblock()
		if r := admissionReceive(t, activated); r.GetErrno() != 0 {
			t.Fatal(r)
		}
		if r := admissionReceive(t, routeDone); r.GetErrno() != int32(syscall.EBUSY) {
			t.Fatal(r)
		}
	})
	t.Run("route wins", func(t *testing.T) {
		f := newTopologyHandlerFixture(t)
		_, admin := f.attach(t, 10, authoritypb.FrontendProfile_FRONTEND_PROFILE_UNSPECIFIED, true)
		_, activation := f.attach(t, 20, authoritypb.FrontendProfile_FRONTEND_PROFILE_FSKIT_EXCLUSIVE, false)
		entered, release := make(chan struct{}), make(chan struct{})
		unblock := sync.OnceFunc(func() { close(release) })
		defer unblock()
		f.h.Routes.syncDirectory = func(dir xfsstore.Capability) error {
			close(entered)
			<-release
			return f.h.Routes.Store.SyncObject(dir)
		}
		routesDone := make(chan *authoritypb.Response, 1)
		go func() {
			routesDone <- f.h.Handle(f.ctx, f.routesRequest(admin.Session, "/local/\n", routesRevisionOf("")))
		}()
		admissionReceive(t, entered)
		// A revision refusal must precede exclusive profile admission too.
		f.h.coherenceProfileAdmission.RLock()
		defer f.h.coherenceProfileAdmission.RUnlock()
		wait := newAdmissionWaitContext(f.ctx)
		activated := make(chan *authoritypb.Response, 1)
		go func() { activated <- f.h.Handle(wait, activation) }()
		admissionReceive(t, wait.waiting)
		unblock()
		if r := admissionReceive(t, routesDone); r.GetErrno() != 0 {
			t.Fatal(r)
		}
		r := admissionReceive(t, activated)
		if r.GetErrno() != int32(syscall.EPERM) || r.GetUncertain() || r.GetFailure() != authoritypb.FailureClass_FAILURE_CLASS_ROUTES {
			t.Fatalf("old activation=%v", r)
		}
		mac := topologySession(activation.Session)
		if f.membership.has(mac, volumeserver.MembershipFSKitExclusive) {
			t.Fatal("stale activation recorded membership")
		}
		if err := f.h.Writers.CheckOwner(mac); err == nil {
			t.Fatal("stale activation published writer")
		}
		cred, err := f.h.credential(f.ctx, activation)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := f.h.Runtime.Begin(cred); !errors.Is(err, volumeserver.ErrSessionProvisional) {
			t.Fatalf("stale activation runtime=%v", err)
		}
		if stats := f.h.Coherence.Stats(); stats.RecallCompleted != 0 {
			t.Fatalf("stale activation recalled: %+v", stats)
		}
	})
}

func TestTopologyApplyCancellationLeavesLocksAndRoutesOnXFS(t *testing.T) {
	f := newTopologyHandlerFixture(t)
	_, admin := f.attach(t, 10, authoritypb.FrontendProfile_FRONTEND_PROFILE_UNSPECIFIED, true)
	locks := f.h.Runtime.Locks()
	owner, waitingID := volumeserver.SessionID{1}, volumeserver.SessionID{2}
	for _, id := range []volumeserver.SessionID{owner, waitingID} {
		locks.RegisterSession(id, time.Now().Add(time.Hour))
	}
	held := volumeserver.Lock{Object: volumeserver.ObjectKey{1}, Owner: volumeserver.LockOwner{Session: owner}, Type: volumeserver.LockWrite, Range: volumeserver.ToEOF(0)}
	if err := locks.Set(held); err != nil {
		t.Fatal(err)
	}
	queued := held
	queued.Owner.Session = waitingID
	pending, err := locks.BeginWait(queued)
	if err != nil {
		t.Fatal(err)
	}
	reader, err := f.h.Routes.AcquireTopologyRead(f.ctx)
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Release()
	ctx1, cancel1 := context.WithCancel(f.ctx)
	defer cancel1()
	firstWait := newAdmissionWaitContext(ctx1)
	first := make(chan *authoritypb.Response, 1)
	req := f.routesRequest(admin.Session, "/local/\n", routesRevisionOf(""))
	go func() { first <- f.h.Handle(firstWait, req) }()
	admissionReceive(t, firstWait.waiting)
	ctx2, cancel2 := context.WithCancel(f.ctx)
	defer cancel2()
	secondWait := newAdmissionWaitContext(ctx2)
	second := make(chan *authoritypb.Response, 1)
	go func() { second <- f.h.Handle(secondWait, req) }()
	admissionReceive(t, secondWait.waiting)
	cancel2()
	if r := admissionReceive(t, second); r.GetErrno() != int32(syscall.EINTR) || r.GetUncertain() {
		t.Fatalf("admin-queued cancel=%v", r)
	}
	cancel1()
	if r := admissionReceive(t, first); r.GetErrno() != int32(syscall.EINTR) || r.GetUncertain() {
		t.Fatalf("topology-queued cancel=%v", r)
	}
	reader.Release()
	if _, err := os.Lstat(filepath.Join(f.root, localroutes.ConfigPath)); !os.IsNotExist(err) {
		t.Fatalf("canceled routes wrote: %v", err)
	}
	if err := locks.Unlock(held.Object, held.Owner, held.Range); err != nil {
		t.Fatal(err)
	}
	if err := pending.Await(f.ctx); err != nil {
		t.Fatalf("canceled admin interrupted old lock queue: %v", err)
	}
	if r := f.require(t, f.ctx, f.routesRequest(admin.Session, "", routesRevisionOf(""))); r.GetApplyRoutes() == nil {
		t.Fatal(r)
	}
}

func TestTopologyCanceledLockRegistration(t *testing.T) {
	r := &RoutesController{Locks: volumeserver.NewLockTable(16, 16, time.Now)}
	r.lockWaitAdmission.Lock()
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	wait := newAdmissionWaitContext(ctx)
	done := make(chan error, 1)
	go func() {
		_, err := r.beginLockWait(wait, func() error { t.Error("canceled lock registration ran admission"); return nil }, volumeserver.Lock{})
		done <- err
	}()
	admissionReceive(t, wait.waiting)
	cancel()
	if err := admissionReceive(t, done); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	r.lockWaitAdmission.Unlock()
}

func TestTopologyRouteValidationAndNoOpPrecedenceOnXFS(t *testing.T) {
	for _, state := range []string{"clean", "live", "prior-unproven"} {
		t.Run(state, func(t *testing.T) {
			f := newTopologyHandlerFixture(t)
			rules := "/local/\n"
			rev := routesRevisionOf(rules)
			if _, err := f.h.Routes.Apply(f.ctx, []byte(rules), routesRevisionOf("")); err != nil {
				t.Fatal(err)
			}
			if state == "live" {
				if err := f.h.Lifecycle.Activate(volumeserver.SessionID{7}, func() error { return nil }); err != nil {
					t.Fatal(err)
				}
			}
			if state == "prior-unproven" {
				l, err := volumeserver.NewMountLifecycle(volumeserver.MountLifecycleConfig{Membership: noopMembership{}, Prior: volumeserver.PriorEpochUnproven})
				if err != nil {
					t.Fatal(err)
				}
				f.h.Routes.Mounts = l
			}
			f.h.Routes.syncDirectory = func(xfsstore.Capability) error { t.Error("no-op/refusal reached route commit"); return nil }
			if r, err := f.h.Routes.Apply(f.ctx, []byte(rules), rev); err != nil || !bytes.Equal(r.GetCanonical(), []byte(rules)) {
				t.Fatalf("valid no-op=%v/%v", r, err)
			}
			if state != "clean" {
				if _, err := f.h.Routes.Apply(f.ctx, []byte("/other/\n"), rev); !errors.Is(err, volumeserver.ErrRoutesLive) {
					t.Fatalf("real change=%v", err)
				}
			}
			if err := os.Mkdir(filepath.Join(f.root, ".git"), 0755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(f.root, ".git/index"), testGitIndex("local/tracked"), 0644); err != nil {
				t.Fatal(err)
			}
			stale := routesRevisionOf("/stale/\n")
			_, err := f.h.Routes.Apply(f.ctx, []byte(rules), stale)
			var mismatch *RoutesMismatchError
			if !errors.As(err, &mismatch) || mismatch.Active != rev || mismatch.Presented != stale {
				t.Fatalf("CAS before Git/no-op/live=%v", err)
			}
			if _, err := f.h.Routes.Apply(f.ctx, []byte(rules), rev); !errors.Is(err, errRoutesTrackedByGit) {
				t.Fatalf("Git before no-op/live=%v", err)
			}
			ctx, cancel := context.WithCancel(f.ctx)
			cancel()
			if _, err := f.h.Routes.Apply(ctx, bytes.Repeat([]byte{'x'}, maxRoutesBytes+1), rev); !errors.Is(err, syscall.EFBIG) {
				t.Fatalf("size before cancellation=%v", err)
			}
			if _, err := f.h.Routes.Apply(ctx, []byte("!invalid/\n"), rev); !errors.Is(err, errRoutesInvalid) {
				t.Fatalf("parse before cancellation=%v", err)
			}
			if _, err := f.h.Routes.Apply(ctx, []byte(rules), rev); !errors.Is(err, context.Canceled) {
				t.Fatalf("cancellation before authoritative checks=%v", err)
			}
		})
	}
}

func TestTopologyRouteCancellationAfterPublicationSettlesOnXFS(t *testing.T) {
	for _, syncErr := range []error{nil, syscall.ENOSPC} {
		name := "success"
		if syncErr != nil {
			name = "uncertain"
		}
		t.Run(name, func(t *testing.T) {
			f := newTopologyHandlerFixture(t)
			ctx, cancel := context.WithCancel(f.ctx)
			defer cancel()
			f.h.Routes.syncDirectory = func(dir xfsstore.Capability) error {
				cancel()
				if syncErr != nil {
					return syncErr
				}
				return f.h.Routes.Store.SyncObject(dir)
			}
			_, err := f.h.Routes.Apply(ctx, []byte("/local/\n"), routesRevisionOf(""))
			if syncErr == nil && err != nil || syncErr != nil && !errors.Is(err, xfsstore.ErrOutcomeUncertain) {
				t.Fatalf("post-publication result=%v", err)
			}
			if rev, _ := f.h.Routes.Revision(); rev != routesRevisionOf("/local/\n") {
				t.Fatal("published revision replaced by canceled outcome")
			}
		})
	}
}

func TestTopologyActivationDeferredFenceUsesProductionCleanupOnXFS(t *testing.T) {
	f := newTopologyHandlerFixture(t)
	_, activation := f.attach(t, 20, authoritypb.FrontendProfile_FRONTEND_PROFILE_FSKIT_EXCLUSIVE, false)
	mac := topologySession(activation.Session)
	hook := make(chan struct{})
	// Handle has already installed closeSessionResources, including its synchronous
	// SweepExclusions. This later hook proves the production hook returned.
	f.h.Runtime.OnSessionEnd(func(id volumeserver.SessionID) {
		if id == mac {
			close(hook)
		}
	})
	f.membership.beforeActivate = func(id volumeserver.SessionID) {
		bad := proto.Clone(activation).(*authoritypb.Request)
		bad.Session.ResumeSecret[0] ^= 1
		bad.Body = &authoritypb.Request_KeepAlive{KeepAlive: &authoritypb.KeepAliveRequest{}}
		if r := f.h.Handle(f.ctx, bad); r.GetErrno() == 0 {
			t.Error("bad runtime credential did not request deferred fence")
		}
	}
	done := make(chan *authoritypb.Response, 1)
	go func() { done <- f.h.Handle(f.ctx, activation) }()
	if r := admissionReceive(t, done); r.GetErrno() != 0 {
		t.Fatal(r)
	}
	admissionReceive(t, hook)
	if !f.membership.has(mac, volumeserver.MembershipFSKitExclusive) {
		t.Fatal("fence erased durable membership")
	}
	if _, err := f.h.sessionResources(mac); !errors.Is(err, volumeserver.ErrSessionExpired) {
		t.Fatalf("production resources not cleaned: %v", err)
	}
	if r := f.h.Handle(f.ctx, &authoritypb.Request{RequestId: 50, Epoch: f.epoch, Session: activation.Session, Body: &authoritypb.Request_KeepAlive{KeepAlive: &authoritypb.KeepAliveRequest{}}}); r.GetErrno() == 0 {
		t.Fatal("terminal activation admitted new work")
	}
	if err := f.h.Lifecycle.RequireCleanRouteAbsence(); !errors.Is(err, volumeserver.ErrRoutesLive) {
		t.Fatalf("fence manufactured clean absence: %v", err)
	}
}
