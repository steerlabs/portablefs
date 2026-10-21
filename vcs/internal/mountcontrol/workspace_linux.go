//go:build linux

package mountcontrol

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/steerlabs/portablefs/vcs/internal/mountid"
	control "github.com/steerlabs/portablefs/vcs/internal/workspacecontrol"
	pb "github.com/steerlabs/portablefs/vcs/internal/workspacepb"
	"golang.org/x/sys/unix"
	"google.golang.org/protobuf/proto"
)

type Workspace struct {
	Version        uint32 `json:"version"`
	RequestID      string `json:"requestId"`
	OperationID    string `json:"operationId"`
	BootID         string `json:"bootId"`
	HostServiceID  string `json:"hostServiceId"`
	GuestServiceID string `json:"guestServiceId"`
	Generation     string `json:"generation"`
	GateSerial     string `json:"gateSerial"`
	BudgetNanos    string `json:"budgetNanos"`
	HostRequestID  string `json:"hostRequestId,omitempty"`
	Transaction    string `json:"transaction,omitempty"`
	Phase          *Phase `json:"phase,omitempty"`
}

// Witness is partial until bootstrap supplies kernel/session evidence. Existing
// fields are immutable for the operation; absence never proves resource absence.
type Witness struct {
	Process        string `json:"process,omitempty"`
	Source         string `json:"source,omitempty"`
	Target         string `json:"target,omitempty"`
	Kernel         string `json:"kernel,omitempty"`
	Session        string `json:"session,omitempty"`
	Enrollment     string `json:"enrollment,omitempty"`
	RoutesRevision string `json:"routesRevision,omitempty"`
}
type Phase struct {
	ActionID string   `json:"actionId,omitempty"`
	Mode     string   `json:"mode,omitempty"`
	Reason   string   `json:"reason,omitempty"`
	Options  []string `json:"options,omitempty"`
	Witness  Witness  `json:"witness"`
	Removal  *Removal `json:"removal,omitempty"`
}
type Removal struct {
	KernelAbsent   bool `json:"kernelAbsent"`
	AbortCompleted bool `json:"abortCompleted"`
}
type Renewal struct {
	State             string `json:"state"`
	InstalledSequence string `json:"installedSequence"`
}
type Outcome struct {
	Durability  string `json:"durability"`
	Observation string `json:"observation"`
	Release     string `json:"release"`
	CleanupDebt string `json:"cleanupDebt"`
}
type Loss struct {
	Sequence        string `json:"sequence"`
	AcceptedEntries string `json:"acceptedEntries"`
	AcceptedBytes   string `json:"acceptedBytes"`
	Reason          string `json:"reason"`
	Aggregated      bool   `json:"aggregated,omitempty"`
}
type Prepared struct {
	SessionValidated        bool    `json:"sessionValidated"`
	AuthorizationValidated  bool    `json:"authorizationValidated"`
	Standalone              bool    `json:"standalone"`
	Renewal                 Renewal `json:"renewal"`
	SubscriptionIncarnation string  `json:"subscriptionIncarnation"`
}
type WorkspaceResponse struct {
	Binding                        Workspace `json:"binding"`
	State                          string    `json:"state"`
	Witness                        Witness   `json:"witness"`
	AuthorizationDeadlineUnixNanos string    `json:"authorizationDeadlineUnixNanos"`
	Outcome                        Outcome   `json:"outcome"`
	Loss                           []Loss    `json:"loss,omitempty"`
	ColdComplete                   bool      `json:"coldComplete,omitempty"`
	Readiness                      *Prepared `json:"readiness,omitempty"`
	Action                         *Phase    `json:"action,omitempty"`
	Reason                         string    `json:"reason,omitempty"`
}

func decimal(s string, positive bool) (uint64, error) {
	n, err := strconv.ParseUint(s, 10, 64)
	if err != nil || strconv.FormatUint(n, 10) != s || positive && n == 0 {
		return 0, ErrGrammar
	}
	return n, nil
}
func identifier(s string) bool {
	raw, err := hex.DecodeString(s)
	return err == nil && hex.EncodeToString(raw) == s && control.ID(raw)
}
func IsWorkspace(op string) bool { return strings.HasPrefix(op, "workspace-") }
func (w *Workspace) validate() error {
	if w == nil || w.Version != 8 || !identifier(w.BootID) || !identifier(w.HostServiceID) || !identifier(w.GuestServiceID) {
		return ErrGrammar
	}
	for _, s := range []string{w.RequestID, w.OperationID} {
		if _, err := decimal(s, true); err != nil {
			return err
		}
	}
	for _, s := range []string{w.Generation, w.GateSerial} {
		if _, err := decimal(s, false); err != nil {
			return err
		}
	}
	n, err := decimal(w.BudgetNanos, true)
	if err != nil || n > uint64(45*time.Second) {
		return ErrGrammar
	}
	return nil
}
func (r Request) ValidateWorkspace() error {
	w := r.Workspace
	if !mountid.ValidMountInstance(r.MountInstanceID) || r.Capability != "" || r.ClientCertificatePEM != "" || r.Sequence != 0 {
		return ErrGrammar
	}
	if err := w.validate(); err != nil {
		return err
	}
	start := false
	transaction := false
	switch r.Operation {
	case "workspace-prepare":
		start = true
		if w.Phase != nil {
			return ErrGrammar
		}
	case "workspace-observe":
		if w.Phase != nil {
			return ErrGrammar
		}
	case "workspace-recover", "workspace-suspend":
		start = true
		transaction = true
		if w.Phase != nil {
			return ErrGrammar
		}
		if _, err := decimal(w.HostRequestID, true); err != nil {
			return err
		}
		raw, err := base64.RawURLEncoding.DecodeString(w.Transaction)
		if err != nil || base64.RawURLEncoding.EncodeToString(raw) != w.Transaction {
			return ErrGrammar
		}
		var s *pb.Suspension
		if r.Operation == "workspace-suspend" {
			var x pb.Suspension
			if err := control.DecodeBody(raw, &x); err != nil {
				return err
			}
			if err := control.Suspension(&x); err != nil {
				return err
			}
			s = &x
		} else {
			var t pb.ResumeToken
			if err := control.DecodeBody(raw, &t); err != nil {
				return err
			}
			if err := control.Token(&t); err != nil {
				return err
			}
			s = t.Suspension
		}
		if hex.EncodeToString(s.BootId) != w.BootID || hex.EncodeToString(s.HostServiceId) != w.HostServiceID || hex.EncodeToString(s.GuestServiceId) != w.GuestServiceID || strconv.FormatUint(s.Generation, 10) != w.Generation {
			return ErrGrammar
		}
	case "workspace-cleanup":
		start = true
		if w.Phase == nil || w.Phase.ActionID != "" || w.Phase.Removal != nil || len(w.Phase.Options) != 0 || !mode(w.Phase.Mode) || !boundWitness(w.Phase.Witness) {
			return ErrGrammar
		}
	case "workspace-install-kernel":
		if w.Phase == nil || !action(w.Phase) || w.Phase.Mode != "" || w.Phase.Reason != "" || w.Phase.Removal != nil || len(w.Phase.Options) == 0 || len(w.Phase.Options) > 32 {
			return ErrGrammar
		}
	case "workspace-unmount-complete":
		if w.Phase == nil || !action(w.Phase) || !mode(w.Phase.Mode) || len(w.Phase.Options) != 0 || w.Phase.Removal == nil || !w.Phase.Removal.KernelAbsent {
			return ErrGrammar
		}
	default:
		return ErrGrammar
	}
	if start != (w.RequestID == w.OperationID) {
		return ErrGrammar
	}
	if !transaction && (w.HostRequestID != "" || w.Transaction != "") {
		return ErrGrammar
	}
	return nil
}
func mode(s string) bool { return s == "voluntary" || s == "terminal" }
func boundWitness(w Witness) bool {
	return w.Process != "" && w.Source != "" && strings.HasPrefix(w.Target, "/")
}
func action(p *Phase) bool {
	_, err := decimal(p.ActionID, true)
	return err == nil && boundWitness(p.Witness)
}
func (r Response) ValidateWorkspace() error {
	w := r.Workspace
	if w == nil || w.Binding.validate() != nil || !mountid.ValidMountInstance(r.MountInstanceID) || r.Sequence != 0 || r.LossSequence != "" || r.AuthorizationDeadlineUnixMs != 0 || r.Error != "" || !r.OK {
		return ErrGrammar
	}
	debt, err := decimal(w.Outcome.CleanupDebt, false)
	if err != nil {
		return err
	}
	if control.Outcome(&pb.MountOutcome{Durability: w.Outcome.Durability, Observation: w.Outcome.Observation, Release: w.Outcome.Release, CleanupDebt: debt}) != nil {
		return ErrGrammar
	}
	if _, err := decimal(w.AuthorizationDeadlineUnixNanos, false); err != nil {
		return err
	}
	if len(w.Reason) > control.MaxReason || len(w.Loss) > control.MaxLosses {
		return ErrGrammar
	}
	var seq uint64
	for i, l := range w.Loss {
		n, err := decimal(l.Sequence, true)
		if err != nil || n <= seq || l.Reason == "" || len(l.Reason) > control.MaxReason {
			return ErrGrammar
		}
		seq = n
		if l.Aggregated && (i != control.MaxLosses-1 || i != len(w.Loss)-1 || l.Reason != control.AggregateReason) {
			return ErrGrammar
		}
		for _, v := range []string{l.AcceptedEntries, l.AcceptedBytes} {
			if _, err := decimal(v, false); err != nil {
				return err
			}
		}
	}
	switch w.State {
	case "accepted", "preparing", "pending-recovery", "pending-suspend":
	case "install-complete":
		if !boundWitness(w.Witness) || w.Witness.Kernel == "" {
			return ErrGrammar
		}
	case "unmount-recorded", "cleanup-finalized":
		if !boundWitness(w.Witness) {
			return ErrGrammar
		}
	case "prepared":
		p := w.Readiness
		if p == nil || !p.SessionValidated || !p.AuthorizationValidated || !identifier(p.SubscriptionIncarnation) || w.Witness.Session == "" || w.AuthorizationDeadlineUnixNanos == "0" {
			return ErrGrammar
		}
		n, err := decimal(p.Renewal.InstalledSequence, false)
		if err != nil || control.Renewal(&pb.RenewalReadiness{State: p.Renewal.State, InstalledSequence: n}) != nil || p.Renewal.State == "pending" || (p.Renewal.State == "not-required") != p.Standalone {
			return ErrGrammar
		}
	case "cold":
		if !w.ColdComplete {
			return ErrGrammar
		}
	case "kernel-required":
		if w.Action == nil || !action(w.Action) || len(w.Action.Options) == 0 || w.Action.Mode != "" || w.Action.Removal != nil {
			return ErrGrammar
		}
	case "unmount-required":
		if w.Action == nil || !action(w.Action) || !mode(w.Action.Mode) || w.Action.Reason == "" || len(w.Action.Options) != 0 || w.Action.Removal != nil {
			return ErrGrammar
		}
	case "failed":
		if w.Reason == "" {
			return ErrGrammar
		}
	default:
		return ErrGrammar
	}
	if (w.Readiness != nil) != (w.State == "prepared") || w.ColdComplete != (w.State == "cold") || (w.Action != nil) != (w.State == "kernel-required" || w.State == "unmount-required") {
		return ErrGrammar
	}
	if w.State != "failed" && w.Reason != "" {
		return ErrGrammar
	}
	return nil
}

// Rights owns every received descriptor until a handler explicitly takes it.
// Rejections, duplicate phases and lost pre-acceptance sockets close this owner.
type Rights struct{ FDs []int }

func (r *Rights) Close() {
	for _, fd := range r.FDs {
		_ = unix.Close(fd)
	}
	r.FDs = nil
}
func (r *Rights) Take() []int { fds := r.FDs; r.FDs = nil; return fds }

type fileIdentity struct {
	Dev, Ino, Rdev uint64
	Mode           uint32
}

func (r *Rights) identities() ([]fileIdentity, error) {
	var out []fileIdentity
	for _, fd := range r.FDs {
		var s unix.Stat_t
		if err := unix.Fstat(fd, &s); err != nil {
			return nil, err
		}
		out = append(out, fileIdentity{uint64(s.Dev), s.Ino, uint64(s.Rdev), s.Mode})
	}
	if len(out) == 2 && out[0] == out[1] {
		return nil, ErrGrammar
	}
	return out, nil
}
func (r *Rights) Validate(op string) error {
	want := 0
	if op == "workspace-install-kernel" {
		want = 2
	}
	if len(r.FDs) != want {
		return ErrGrammar
	}
	_, err := r.identities()
	return err
}

// Handler owns jobs independently of request waiters. It must return bounded
// phase receipts/snapshots, never wait for the lifetime of Prepare or Recover.
type Handler interface {
	Handle(context.Context, Request, *Rights) (Response, error)
}
type receipt struct {
	id       uint64
	body     []byte
	files    []fileIdentity
	response []byte
	err      error
}
type Replay struct {
	mu                        sync.Mutex
	high                      uint64
	operation                 string
	instance                  string
	active                    bool
	prepareStarted            bool
	lastResume                [32]byte
	recoveredGeneration       uint64
	nextAction                *Phase
	actionKind                string
	binding                   *Workspace
	deadline                  time.Time
	start, phase, observation *receipt
	Now                       func() time.Time
	CloseAdmission            func()
}

func (r *Replay) now() time.Time {
	if r.Now != nil {
		return r.Now()
	}
	return time.Now()
}
func immutable(req Request) []byte {
	copy := *req.Workspace
	copy.BudgetNanos = ""
	req.Workspace = &copy
	raw, _ := json.Marshal(req)
	return raw
}
func (r *Replay) Do(ctx context.Context, req Request, rights *Rights, h Handler) (result Response, resultErr error) {
	defer rights.Close()
	if err := req.ValidateWorkspace(); err != nil {
		if r.CloseAdmission != nil {
			r.CloseAdmission()
		}
		return Response{}, err
	}
	if err := rights.Validate(req.Operation); err != nil {
		if r.CloseAdmission != nil {
			r.CloseAdmission()
		}
		return Response{}, err
	}
	files, err := rights.identities()
	if err != nil {
		return Response{}, err
	}
	body := immutable(req)
	id, _ := decimal(req.Workspace.RequestID, true)
	r.mu.Lock()
	defer r.mu.Unlock()
	for _, old := range []*receipt{r.start, r.phase, r.observation} {
		if old != nil && old.id == id {
			if !bytes.Equal(body, old.body) || !reflectFiles(files, old.files) {
				if r.CloseAdmission != nil {
					r.CloseAdmission()
				}
				return Response{}, ErrGrammar
			}
			if old.err != nil {
				return Response{}, old.err
			}
			return DecodeResponse(old.response, true)
		}
	}
	if id <= r.high {
		return Response{}, ErrGrammar
	}
	r.high = id
	start := req.Workspace.RequestID == req.Workspace.OperationID
	if !start && (r.binding == nil || req.MountInstanceID != r.instance || req.Workspace.OperationID != r.operation || !sameBinding(*r.binding, *req.Workspace)) {
		return Response{}, ErrGrammar
	}
	generation, _ := decimal(req.Workspace.Generation, false)
	if start && r.binding != nil {
		oldGeneration, _ := decimal(r.binding.Generation, false)
		serial, _ := decimal(req.Workspace.GateSerial, false)
		oldSerial, _ := decimal(r.binding.GateSerial, false)
		if req.MountInstanceID != r.instance || req.Workspace.BootID != r.binding.BootID || req.Workspace.HostServiceID != r.binding.HostServiceID || req.Workspace.GuestServiceID != r.binding.GuestServiceID || generation < oldGeneration || serial < oldSerial {
			return Response{}, ErrGrammar
		}
	}
	if req.Operation == "workspace-recover" && generation <= r.recoveredGeneration {
		return Response{}, ErrGrammar
	}
	if req.Operation == "workspace-prepare" && r.prepareStarted {
		return Response{}, ErrGrammar
	}
	if req.Operation == "workspace-recover" && r.lastResume == sha256.Sum256([]byte(req.Workspace.Transaction)) {
		return Response{}, ErrGrammar
	}
	if req.Operation == "workspace-install-kernel" || req.Operation == "workspace-unmount-complete" {
		expected := "kernel-required"
		if req.Operation == "workspace-unmount-complete" {
			expected = "unmount-required"
		}
		p := *req.Workspace.Phase
		p.Removal = nil
		if r.nextAction == nil || r.actionKind != expected || !reflect.DeepEqual(p, *r.nextAction) {
			return Response{}, ErrGrammar
		}
	}
	if start && r.active && req.Operation != "workspace-suspend" && req.Operation != "workspace-cleanup" {
		return Response{}, ErrGrammar
	}
	if h == nil {
		return Response{}, ErrUnavailable
	}
	if start {
		if r.active && r.CloseAdmission != nil {
			r.CloseAdmission()
		}
		r.active = true
		r.nextAction = nil
		r.actionKind = ""
		if req.Operation == "workspace-prepare" {
			r.prepareStarted = true
		}
		if req.Operation == "workspace-recover" {
			r.lastResume = sha256.Sum256([]byte(req.Workspace.Transaction))
			r.recoveredGeneration = generation
		}
		r.instance = req.MountInstanceID
		r.operation = req.Workspace.OperationID
		copy := *req.Workspace
		r.binding = &copy
		r.start = nil
		r.phase = nil
		r.observation = nil
		r.deadline = time.Time{}
		if req.Operation == "workspace-suspend" {
			n, _ := decimal(req.Workspace.BudgetNanos, true)
			r.deadline = r.now().Add(time.Duration(n))
		}
	}
	n, _ := decimal(req.Workspace.BudgetNanos, true)
	deadline := r.now().Add(time.Duration(n))
	if !r.deadline.IsZero() && r.deadline.Before(deadline) {
		deadline = r.deadline
	}
	attempt, cancel := context.WithDeadline(ctx, deadline)
	defer cancel()
	// Once dispatched, even an error receipt is immutable. Losing a waiter or
	// rejecting a handler result cannot permit a second execution of its phase.
	retained := &receipt{id: id, body: body, files: files}
	defer func() {
		if resultErr != nil {
			retained.err = resultErr
		}
		if start {
			r.start = retained
		} else if req.Operation == "workspace-observe" {
			r.observation = retained
		} else {
			r.phase = retained
		}
	}()
	response, err := h.Handle(attempt, req, rights)
	if err != nil {
		return Response{}, err
	}

	state := response.Workspace
	if state == nil {
		return Response{}, ErrGrammar
	}
	switch req.Operation {
	case "workspace-prepare", "workspace-recover", "workspace-suspend", "workspace-cleanup":
		if state.State != "accepted" && state.State != "failed" {
			return Response{}, ErrGrammar
		}
	case "workspace-install-kernel":
		if state.State != "install-complete" && state.State != "failed" {
			return Response{}, ErrGrammar
		}
	case "workspace-unmount-complete":
		if state.State != "unmount-recorded" && state.State != "failed" {
			return Response{}, ErrGrammar
		}
	case "workspace-observe":
		if state.State == "accepted" || state.State == "install-complete" || state.State == "unmount-recorded" {
			return Response{}, ErrGrammar
		}
	}
	raw, err := EncodeResponse(response)
	if err != nil {
		return Response{}, err
	}
	bound := req
	bound.Workspace = &response.Workspace.Binding
	if response.MountInstanceID != req.MountInstanceID || !bytes.Equal(immutable(bound), body) {
		return Response{}, ErrGrammar
	}
	if state.Action != nil {
		raw, _ := json.Marshal(state.Action)
		var copy Phase
		_ = json.Unmarshal(raw, &copy)
		r.nextAction = &copy
		r.actionKind = state.State
	}
	if req.Operation == "workspace-install-kernel" || req.Operation == "workspace-unmount-complete" {
		r.nextAction = nil
		r.actionKind = ""
	}
	if state.State == "prepared" || state.State == "cold" || state.State == "cleanup-finalized" || state.State == "failed" {
		r.active = false
	}
	retained.response = raw
	return DecodeResponse(raw, true)
}
func sameBinding(a, b Workspace) bool {
	return a.Version == b.Version && a.BootID == b.BootID && a.HostServiceID == b.HostServiceID && a.GuestServiceID == b.GuestServiceID && a.Generation == b.Generation && a.GateSerial == b.GateSerial && a.OperationID == b.OperationID
}
func reflectFiles(a, b []fileIdentity) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// EncodeTransaction retains the strict body grammar, independently of the host
// Envelope rule that forbids a host-supplied Suspend roster.
func EncodeTransaction(m proto.Message) (string, error) {
	raw, err := proto.MarshalOptions{Deterministic: true}.Marshal(m)
	if err != nil {
		return "", err
	}
	if err := control.DecodeBody(raw, m); err != nil {
		return "", err
	}
	return base64.RawURLEncoding.EncodeToString(raw), nil
}
