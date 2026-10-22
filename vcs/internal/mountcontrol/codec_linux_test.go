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
	"testing"

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
		r.Workspace.DrainBudgetNanos = "15000000000"
		r.Workspace.Transaction, err = EncodeTransaction(suspension(t))
	} else {
		r.Workspace.Transaction, err = EncodeTransaction(&pb.ResumeToken{Suspension: suspension(t), WakeNonce: bytes.Repeat([]byte{7}, 16)})
	}
	if err != nil {
		t.Fatal(err)
	}
}
func response(r Request, state string) Response {
	return Response{OK: true, MountInstanceID: r.MountInstanceID, Workspace: &WorkspaceResponse{Binding: r.Workspace.ResponseBinding(), State: state, AuthorizationDeadlineUnixNanos: "0", Outcome: Outcome{Durability: "unresolved", Observation: "unobserved", Release: "unresolved", CleanupDebt: "0"}}}
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
func TestEveryWorkspaceResponseIsTypedEvidence(t *testing.T) {
	for _, state := range []string{"accepted", "preparing", "kernel-required", "pending-recovery", "pending-suspend", "prepared", "cold", "unmount-required", "unmount-recorded", "cleanup-finalized", "failed"} {
		t.Run(state, func(t *testing.T) {
			r := response(request("workspace-observe", 2, 1), state)
			w := r.Workspace
			if state != "accepted" && state != "unmount-recorded" {
				w.Phases = absentPhases()
			}
			switch state {
			case "unmount-recorded", "cleanup-finalized":
				w.Witness = witness()
			case "kernel-required":
				w.Witness = witness()
				w.Phases.Install = ActionStatus{Progress: "offered", Action: kernelAction(*phase())}
			case "unmount-required":
				w.Witness = witness()
				w.Phases.Install = ActionStatus{Progress: "offered", Action: kernelAction(*phase())}
				p := phase()
				p.Options = nil
				p.Mode = "terminal"
				p.Reason = "revoked"
				w.Phases.Install = ActionStatus{Progress: "absent"}
				w.Phases.TerminalRemoval = ActionStatus{Progress: "offered", Action: kernelAction(*p)}
			case "prepared":
				w.Witness = witness()
				w.Phases.Install = ActionStatus{Progress: "complete", Action: kernelAction(*phase())}
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
				if _, err := (&Owner{}).Do(context.Background(), r, d); err == nil {
					t.Fatal("unavailable lifecycle succeeded")
				}
				assertClosed(t, all)
			})
		}
	}
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

func TestDrainAllowanceIsCanonicalAndOnlyOnSuspend(t *testing.T) {
	for _, allowance := range []string{"", "0", "01", "+1", "15000000001", "18446744073709551616"} {
		q := request("workspace-suspend", 1, 1)
		transaction(t, &q)
		q.Workspace.DrainBudgetNanos = allowance
		if q.ValidateWorkspace() == nil {
			t.Fatal("invalid drain allowance", allowance)
		}
	}
	for _, op := range []string{"workspace-prepare", "workspace-recover", "workspace-observe"} {
		q := request(op, 1, 1)
		if op == "workspace-recover" {
			transaction(t, &q)
		}
		if op == "workspace-observe" {
			q.Workspace.RequestID = "2"
		}
		q.Workspace.DrainBudgetNanos = "1"
		if q.ValidateWorkspace() == nil {
			t.Fatal("unexpected drain allowance", op)
		}
	}
}

func TestFinitePhaseAndRefusalGrammar(t *testing.T) {
	q := request("workspace-observe", 2, 1)
	for _, err := range []error{ErrUnavailable, ErrOccupied, ErrRetired, ErrGrammar, ErrActionConsumed, ErrNotAccepted, ErrIncarnationTerminal, ErrPeerRefused, context.Canceled, context.DeadlineExceeded, errors.New("private")} {
		if _, err := EncodeResponse(WorkspaceRefusal(q, err)); err != nil {
			t.Fatal(err)
		}
	}
	for _, progress := range []string{"", "queued", "consumed", "success"} {
		out := response(q, "preparing")
		out.Workspace.Phases = absentPhases()
		out.Workspace.Phases.Install.Progress = progress
		if _, err := EncodeResponse(out); err == nil {
			t.Fatal("unknown phase progress", progress)
		}
	}
	out := response(q, "preparing")
	out.Workspace.Witness = witness()
	out.Workspace.Phases = absentPhases()
	out.Workspace.Phases.Install = ActionStatus{Progress: "failed", Action: kernelAction(*phase()), Failure: "private diagnostic"}
	if _, err := EncodeResponse(out); err == nil {
		t.Fatal("unbounded failure grammar")
	}
	out = WorkspaceRefusal(q, ErrActionConsumed)
	out.Workspace.Refusal = "private diagnostic"
	if _, err := EncodeResponse(out); err == nil {
		t.Fatal("unbounded refusal")
	}
}
