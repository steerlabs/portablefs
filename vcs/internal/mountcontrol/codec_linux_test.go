//go:build linux

package mountcontrol

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	control "github.com/steerlabs/portablefs/vcs/internal/workspacecontrol"
	pb "github.com/steerlabs/portablefs/vcs/internal/workspacepb"
	"golang.org/x/sys/unix"
)

func request(op string, n, operation uint64) Request {
	return Request{Operation: op, MountInstanceID: "mnt_0000000000000000000001", Workspace: &Workspace{Version: 8, RequestID: strconv.FormatUint(n, 10), OperationID: strconv.FormatUint(operation, 10), BootID: strings.Repeat("01", 16), HostServiceID: strings.Repeat("02", 16), GuestServiceID: strings.Repeat("03", 16), Generation: "1", GateSerial: "0", BudgetNanos: "45000000000"}}
}
func witness() Witness {
	return Witness{Process: "123/456", Source: "portablefs-instance", Target: "/workspaces/example", Kernel: "exact-kernel"}
}
func phase() *Phase {
	return &Phase{ActionID: "1", Options: []string{"nodev", "nosuid"}, Witness: witness()}
}
func suspension(t *testing.T) *pb.Suspension {
	t.Helper()
	s := &pb.Suspension{BootId: bytes.Repeat([]byte{1}, 16), HostServiceId: bytes.Repeat([]byte{2}, 16), GuestServiceId: bytes.Repeat([]byte{3}, 16), Generation: 1, Nonce: bytes.Repeat([]byte{4}, 16)}
	for i := 0; i < control.MaxMounts; i++ {
		s.Roster = append(s.Roster, &pb.MountID{AuthorityId: bytes.Repeat([]byte{5}, 32), VolumeId: fmt.Sprintf("%03d%s", i, strings.Repeat("v", 125)), Incarnation: bytes.Repeat([]byte{6}, 16)})
	}
	return s
}
func transaction(t *testing.T, r *Request) {
	t.Helper()
	var err error
	r.Workspace.HostRequestID = "7"
	if r.Operation == "workspace-suspend" {
		r.Workspace.Transaction, err = EncodeTransaction(suspension(t))
	} else {
		r.Workspace.Transaction, err = EncodeTransaction(&pb.ResumeToken{Suspension: suspension(t), WakeNonce: bytes.Repeat([]byte{7}, 16)})
	}
	if err != nil {
		t.Fatal(err)
	}
}
func response(r Request, state string) Response {
	return Response{OK: true, MountInstanceID: r.MountInstanceID, Workspace: &WorkspaceResponse{Binding: *r.Workspace, State: state, AuthorizationDeadlineUnixNanos: "0", Outcome: Outcome{Durability: "unresolved", Observation: "unobserved", Release: "unresolved", CleanupDebt: "0"}}}
}
func TestEveryWorkspaceRequestAndMaximumRoster(t *testing.T) {
	for _, op := range []string{"workspace-prepare", "workspace-observe", "workspace-install-kernel", "workspace-recover", "workspace-suspend", "workspace-cleanup", "workspace-unmount-complete"} {
		t.Run(op, func(t *testing.T) {
			r := request(op, 1, 1)
			switch op {
			case "workspace-observe":
				r.Workspace.RequestID = "2"
			case "workspace-install-kernel":
				r.Workspace.RequestID = "2"
				r.Workspace.Phase = phase()
			case "workspace-unmount-complete":
				r.Workspace.RequestID = "2"
				r.Workspace.Phase = phase()
				r.Workspace.Phase.Options = nil
				r.Workspace.Phase.Mode = "terminal"
				r.Workspace.Phase.Removal = &Removal{KernelAbsent: true, AbortCompleted: true}
			case "workspace-cleanup":
				r.Workspace.Phase = &Phase{Mode: "voluntary", Witness: witness()}
			case "workspace-suspend", "workspace-recover":
				transaction(t, &r)
			}
			raw, _ := json.Marshal(r)
			if len(raw) > MaxWorkspaceRequest {
				t.Fatal("maximum roster does not fit")
			}
			if _, err := DecodeRequest(raw); err != nil {
				t.Fatal(err)
			}
			r.Workspace.Version = 7
			bad, _ := json.Marshal(r)
			if _, err := DecodeRequest(bad); err == nil {
				t.Fatal("unequal version")
			}
		})
	}
}
func TestLocalCodecStrictGrammarAndBounds(t *testing.T) {
	r := request("workspace-prepare", 1, 1)
	raw, _ := json.Marshal(r)
	for name, bad := range map[string][]byte{
		"duplicate":    bytes.Replace(raw, []byte(`"version":8`), []byte(`"version":8,"version":8`), 1),
		"case":         bytes.Replace(raw, []byte(`"version":8`), []byte(`"Version":8`), 1),
		"unknown":      bytes.Replace(raw, []byte(`"version":8`), []byte(`"version":8,"extra":1`), 1),
		"trailing":     append(append([]byte{}, raw...), []byte(` {}`)...),
		"null":         bytes.Replace(raw, []byte(`"capability":""`), []byte(`"capability":null`), 1),
		"number":       bytes.Replace(raw, []byte(`"requestId":"1"`), []byte(`"requestId":1`), 1),
		"leading-zero": bytes.Replace(raw, []byte(`"requestId":"1"`), []byte(`"requestId":"01"`), 1),
		"zero-id":      bytes.Replace(raw, []byte(`"requestId":"1"`), []byte(`"requestId":"0"`), 1),
		"budget":       bytes.Replace(raw, []byte(`"45000000000"`), []byte(`"45000000001"`), 1),
		"oversized":    append(raw, bytes.Repeat([]byte(" "), MaxWorkspaceRequest)...),
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := DecodeRequest(bad); err == nil {
				t.Fatal("accepted malformed request")
			}
		})
	}
	ordinary := Request{Capability: strings.Repeat("g", 32<<10), ClientCertificatePEM: strings.Repeat("c", MaxIdentityBytes), Sequence: 1}
	raw, _ = json.Marshal(ordinary)
	if len(raw) <= 4096 {
		t.Fatal("small fixture")
	}
	if _, err := DecodeRequest(raw); err != nil {
		t.Fatal("ordinary maximum shrank", err)
	}
	if _, err := DecodeRequest(append(raw, bytes.Repeat([]byte(" "), MaxOrdinaryRequest)...)); err == nil {
		t.Fatal("ordinary overrun")
	}
	if _, err := DecodeResponse([]byte(`{"ok":true}`), false); err != nil {
		t.Fatal(err)
	}
	if _, err := DecodeResponse(append([]byte(`{"ok":true}`), bytes.Repeat([]byte(" "), MaxOrdinaryResponse)...), false); err == nil {
		t.Fatal("response overrun")
	}
}
func TestEveryWorkspaceResponseIsImmutableTypedEvidence(t *testing.T) {
	for _, state := range []string{"accepted", "preparing", "kernel-required", "pending-recovery", "pending-suspend", "prepared", "cold", "unmount-required", "install-complete", "unmount-recorded", "cleanup-finalized", "failed"} {
		t.Run(state, func(t *testing.T) {
			r := response(request("workspace-observe", 2, 1), state)
			w := r.Workspace
			switch state {
			case "install-complete", "unmount-recorded", "cleanup-finalized":
				w.Witness = witness()
			case "kernel-required":
				w.Action = phase()
			case "unmount-required":
				w.Action = phase()
				w.Action.Options = nil
				w.Action.Mode = "terminal"
				w.Action.Reason = "revoked"
			case "prepared":
				w.AuthorizationDeadlineUnixNanos = "2000000000000000000"
				w.Witness.Session = "session"
				w.Readiness = &Prepared{SessionValidated: true, AuthorizationValidated: true, Renewal: Renewal{State: "installed", InstalledSequence: "1"}, SubscriptionIncarnation: "1"}
			case "cold":
				w.ColdComplete = true
			case "failed":
				w.Reason = "unrecoverable"
			}
			raw, err := EncodeResponse(r)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := DecodeResponse(raw, true); err != nil {
				t.Fatal(err)
			}
			if state == "prepared" {
				w.Readiness.Renewal.InstalledSequence = "0"
				if _, err := EncodeResponse(r); err == nil {
					t.Fatal("sequence zero ready")
				}
			}
			w.Outcome.Durability = "durable"
			if _, err := EncodeResponse(r); err == nil {
				t.Fatal("unobserved durability certified")
			}
		})
	}
}

type handlerFunc func(context.Context, Request, *Rights) (Response, error)

func (f handlerFunc) Handle(c context.Context, r Request, d *Rights) (Response, error) {
	return f(c, r, d)
}
func descriptors(t *testing.T) (*Rights, []int) {
	t.Helper()
	var fds []int
	for i := 0; i < 2; i++ {
		f, err := os.CreateTemp(t.TempDir(), "owned")
		if err != nil {
			t.Fatal(err)
		}
		fd, err := unix.FcntlInt(f.Fd(), unix.F_DUPFD_CLOEXEC, 0)
		f.Close()
		if err != nil {
			t.Fatal(err)
		}
		fds = append(fds, fd)
	}
	return &Rights{FDs: fds}, append([]int{}, fds...)
}
func assertClosed(t *testing.T, fds []int) {
	t.Helper()
	for _, fd := range fds {
		if _, err := unix.FcntlInt(uintptr(fd), unix.F_GETFD, 0); !errors.Is(err, unix.EBADF) {
			t.Fatalf("descriptor %d leaked: %v", fd, err)
		}
	}
}
func TestWorkspaceReplayRetainsOnlyStartPhaseAndLatestObservation(t *testing.T) {
	var replay Replay
	calls := 0
	state := "kernel-required"
	h := handlerFunc(func(_ context.Context, r Request, d *Rights) (Response, error) {
		calls++
		result := "accepted"
		if r.Operation == "workspace-observe" {
			result = state
		}
		if r.Operation == "workspace-install-kernel" {
			result = "install-complete"
		}
		out := response(r, result)
		if result == "install-complete" {
			out.Workspace.Witness = witness()
		}
		if result == "kernel-required" {
			out.Workspace.Action = phase()
		}
		return out, nil
	})
	start := request("workspace-prepare", 1, 1)
	if _, err := replay.Do(context.Background(), start, &Rights{}, h); err != nil {
		t.Fatal(err)
	}
	obs := request("workspace-observe", 2, 1)
	a, err := replay.Do(context.Background(), obs, &Rights{}, h)
	if err != nil {
		t.Fatal(err)
	}
	state = "preparing"
	again, err := replay.Do(context.Background(), obs, &Rights{}, h)
	if err != nil || again.Workspace.State != a.Workspace.State || calls != 2 {
		t.Fatal("observation mutated")
	}
	install := request("workspace-install-kernel", 3, 1)
	install.Workspace.Phase = phase()
	d, fds := descriptors(t)
	duplicates := &Rights{}
	for _, fd := range fds {
		x, err := unix.Dup(fd)
		if err != nil {
			t.Fatal(err)
		}
		duplicates.FDs = append(duplicates.FDs, x)
	}
	if _, err := replay.Do(context.Background(), install, d, h); err != nil {
		t.Fatal(err)
	}
	assertClosed(t, fds)
	dupeFDs := append([]int{}, duplicates.FDs...)
	if _, err := replay.Do(context.Background(), install, duplicates, h); err != nil {
		t.Fatal(err)
	}
	assertClosed(t, dupeFDs)
	for n := uint64(4); n < 1004; n++ {
		if _, err := replay.Do(context.Background(), request("workspace-observe", n, 1), &Rights{}, h); err != nil {
			t.Fatal(err)
		}
	}
	if replay.start.id != 1 || replay.phase.id != 3 || replay.observation.id != 1003 || replay.high != 1003 {
		t.Fatal("unbounded or wrong replay ownership")
	}
	if _, err := replay.Do(context.Background(), obs, &Rights{}, h); err == nil {
		t.Fatal("retired observation executed")
	}
	if _, err := replay.Do(context.Background(), install, &Rights{}, h); err == nil {
		t.Fatal("missing descriptors on duplicate")
	}
}
func TestWorkspaceChangedIDClosesAndRetryCannotExtendSuspend(t *testing.T) {
	now := time.Now()
	var deadlines []time.Time
	closed := 0
	replay := Replay{Now: func() time.Time { return now }, CloseAdmission: func() { closed++ }}
	h := handlerFunc(func(c context.Context, r Request, _ *Rights) (Response, error) {
		d, _ := c.Deadline()
		deadlines = append(deadlines, d)
		state := "accepted"
		if r.Operation == "workspace-observe" {
			state = "pending-suspend"
		}
		return response(r, state), nil
	})
	r := request("workspace-suspend", 1, 1)
	transaction(t, &r)
	if _, err := replay.Do(context.Background(), r, &Rights{}, h); err != nil {
		t.Fatal(err)
	}
	now = now.Add(20 * time.Second)
	r.Workspace.BudgetNanos = "25000000000"
	if _, err := replay.Do(context.Background(), r, &Rights{}, h); err != nil {
		t.Fatal(err)
	}
	if len(deadlines) != 1 {
		t.Fatal("retry dispatched")
	}
	if _, err := replay.Do(context.Background(), request("workspace-observe", 2, 1), &Rights{}, h); err != nil {
		t.Fatal(err)
	}
	if !deadlines[0].Equal(deadlines[1]) {
		t.Fatal("drain deadline extended")
	}
	r.Workspace.GateSerial = "1"
	if _, err := replay.Do(context.Background(), r, &Rights{}, h); err == nil || closed != 1 {
		t.Fatal("changed retry did not close")
	}
}
func TestWorkspaceUnavailableAndDescriptorRejectionOwnEveryRight(t *testing.T) {
	for _, op := range []string{"workspace-prepare", "workspace-install-kernel"} {
		for _, count := range []int{0, 1, 2, 3} {
			t.Run(fmt.Sprintf("%s/%d", op, count), func(t *testing.T) {
				r := request(op, 1, 1)
				if op == "workspace-install-kernel" {
					r.Workspace.RequestID = "2"
					r.Workspace.Phase = phase()
				}
				d, all := descriptors(t)
				for len(d.FDs) < count {
					x, err := unix.Dup(d.FDs[0])
					if err != nil {
						t.Fatal(err)
					}
					d.FDs = append(d.FDs, x)
					all = append(all, x)
				}
				for len(d.FDs) > count {
					unix.Close(d.FDs[len(d.FDs)-1])
					d.FDs = d.FDs[:len(d.FDs)-1]
				}
				if _, err := (&Replay{}).Do(context.Background(), r, d, nil); err == nil {
					t.Fatal("unavailable lifecycle succeeded")
				}
				assertClosed(t, all)
			})
		}
	}
	d, fds := descriptors(t)
	unix.Close(d.FDs[1])
	x, _ := unix.Dup(d.FDs[0])
	d.FDs[1] = x
	fds = append(fds, x)
	if d.Validate("workspace-install-kernel") == nil {
		t.Fatal("same open description accepted twice")
	}
	d.Close()
	assertClosed(t, fds)
}
func TestWorkspaceTransactionUsesFixedRosterBodyAndCanonicalScanner(t *testing.T) {
	r := request("workspace-suspend", 1, 1)
	transaction(t, &r)
	if r.ValidateWorkspace() != nil {
		t.Fatal("local fixed roster refused")
	}
	r.Workspace.Transaction += "="
	if r.ValidateWorkspace() == nil {
		t.Fatal("padded token")
	}
	transaction(t, &r)
	r.Workspace.Generation = "2"
	if r.ValidateWorkspace() == nil {
		t.Fatal("transaction rebound")
	}
}
func TestPeerClassificationRequiresExactRootProcess(t *testing.T) {
	root := Peer{UID: 0, PID: 20, Start: 30}
	for _, tc := range []struct {
		peer Peer
		want PeerClass
	}{{root, WorkspacePeer}, {Peer{0, 20, 31}, Refused}, {Peer{0, 21, 30}, Refused}, {Peer{1000, 20, 30}, Ordinary}, {Peer{1001, 20, 30}, Refused}} {
		if got := Classify(tc.peer, 1000, &root); got != tc.want {
			t.Fatalf("%+v = %v", tc.peer, got)
		}
	}
	if Classify(Peer{}, 1000, &Peer{}) != Refused {
		t.Fatal("unseeded root")
	}
}

func TestWorkspaceLostInstallResponseReconcilesActionAndOwnership(t *testing.T) {
	replay := &Replay{}
	var accepted []int
	installs := 0
	h := handlerFunc(func(_ context.Context, r Request, d *Rights) (Response, error) {
		switch r.Operation {
		case "workspace-prepare":
			return response(r, "accepted"), nil
		case "workspace-observe":
			out := response(r, "kernel-required")
			out.Workspace.Action = phase()
			return out, nil
		case "workspace-install-kernel":
			installs++
			accepted = d.Take()
			out := response(r, "install-complete")
			out.Workspace.Witness = witness()
			return out, nil
		}
		return Response{}, ErrGrammar
	})
	if _, err := replay.Do(context.Background(), request("workspace-prepare", 1, 1), &Rights{}, h); err != nil {
		t.Fatal(err)
	}
	if _, err := replay.Do(context.Background(), request("workspace-observe", 2, 1), &Rights{}, h); err != nil {
		t.Fatal(err)
	}
	r := request("workspace-install-kernel", 3, 1)
	r.Workspace.Phase = phase()
	d, _ := descriptors(t)
	duplicates := &Rights{}
	for _, fd := range d.FDs {
		x, err := unix.Dup(fd)
		if err != nil {
			t.Fatal(err)
		}
		duplicates.FDs = append(duplicates.FDs, x)
	}
	client, server := sockets(t)
	client.Close()
	receipt, err := replay.Do(context.Background(), r, d, h)
	if err != nil {
		t.Fatal(err)
	}
	defer func() {
		for _, fd := range accepted {
			unix.Close(fd)
		}
	}()
	if WriteResponse(server, receipt) == nil {
		t.Fatal("lost socket unexpectedly wrote")
	}
	retried, err := replay.Do(context.Background(), r, duplicates, h)
	if err != nil || retried.Workspace.State != "install-complete" || installs != 1 || len(accepted) != 2 {
		t.Fatal("lost receipt changed owner", err, installs)
	}
	for _, fd := range accepted {
		if _, err := unix.FcntlInt(uintptr(fd), unix.F_GETFD, 0); err != nil {
			t.Fatal("accepted owner lost descriptor", err)
		}
	}
}
func TestWorkspaceActionsAndResumeAuthorizationCannotBeRebound(t *testing.T) {
	r := &Replay{}
	calls := 0
	h := handlerFunc(func(_ context.Context, q Request, _ *Rights) (Response, error) {
		calls++
		state := "accepted"
		if q.Operation == "workspace-observe" {
			state = "failed"
		}
		out := response(q, state)
		if state == "failed" {
			out.Workspace.Reason = "terminal"
		}
		return out, nil
	})
	recover := request("workspace-recover", 1, 1)
	transaction(t, &recover)
	if _, err := r.Do(context.Background(), recover, &Rights{}, h); err != nil {
		t.Fatal(err)
	}
	if _, err := r.Do(context.Background(), request("workspace-observe", 2, 1), &Rights{}, h); err != nil {
		t.Fatal(err)
	}
	recover.Workspace.RequestID = "3"
	recover.Workspace.OperationID = "3"
	if _, err := r.Do(context.Background(), recover, &Rights{}, h); err == nil || calls != 2 {
		t.Fatal("Resume authorization consumed twice")
	}
	install := request("workspace-install-kernel", 4, 1)
	install.Workspace.Phase = phase()
	d, _ := descriptors(t)
	if _, err := r.Do(context.Background(), install, d, h); err == nil || calls != 2 {
		t.Fatal("unsolicited bootstrap action")
	}
}
func TestWorkspaceErrorReceiptCannotExecuteAgainAfterWaiterLoss(t *testing.T) {
	calls := 0
	r := &Replay{}
	h := handlerFunc(func(context.Context, Request, *Rights) (Response, error) {
		calls++
		return Response{}, context.Canceled
	})
	q := request("workspace-prepare", 1, 1)
	for i := 0; i < 2; i++ {
		if _, err := r.Do(context.Background(), q, &Rights{}, h); !errors.Is(err, context.Canceled) {
			t.Fatal(err)
		}
	}
	if calls != 1 {
		t.Fatal("lost waiter restarted assigned phase")
	}
}

func TestWorkspaceSuspendChargesReplayLaneDelay(t *testing.T) {
	base := time.Now()
	received := make(chan struct{})
	var elapsed atomic.Int64
	var first sync.Once
	r := &Replay{Now: func() time.Time {
		now := base.Add(time.Duration(elapsed.Load()))
		first.Do(func() { close(received) })
		return now
	}}
	r.mu.Lock()
	q := request("workspace-suspend", 1, 1)
	transaction(t, &q)
	done := make(chan error, 1)
	go func() {
		_, err := r.Do(context.Background(), q, &Rights{}, handlerFunc(func(ctx context.Context, q Request, _ *Rights) (Response, error) {
			deadline, _ := ctx.Deadline()
			if !deadline.Equal(base.Add(45 * time.Second)) {
				t.Error("queue delay extended drain deadline", deadline)
			}
			return response(q, "accepted"), nil
		}))
		done <- err
	}()
	<-received
	elapsed.Store(int64(20 * time.Second))
	r.mu.Unlock()
	if err := <-done; err != nil {
		t.Fatal(err)
	}
}
