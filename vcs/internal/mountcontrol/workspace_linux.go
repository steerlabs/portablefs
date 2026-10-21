//go:build linux

package mountcontrol

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
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
	Refusal                        string    `json:"refusal,omitempty"`
}

func decimal(s string, positive bool) (uint64, error) {
	n, err := strconv.ParseUint(s, 10, 64)
	if err != nil || strconv.FormatUint(n, 10) != s || positive && n == 0 {
		return 0, ErrGrammar
	}
	return n, nil
}
func positiveDecimal(s string) bool { _, err := decimal(s, true); return err == nil }
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
	if !boundedPhase(w.Phase) {
		return ErrGrammar
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
func boundedWitness(w Witness) bool {
	return len(w.Process)+len(w.Source)+len(w.Target)+len(w.Kernel)+len(w.Session)+len(w.Enrollment)+len(w.RoutesRevision) <= 512
}
func boundedPhase(p *Phase) bool {
	if p == nil {
		return true
	}
	size := 0
	for _, option := range p.Options {
		size += len(option)
	}
	return boundedWitness(p.Witness) && size <= 256 && len(p.Options) <= 32 && len(p.Reason) <= control.MaxReason
}
func boundWitness(w Witness) bool {
	return boundedWitness(w) && w.Process != "" && w.Source != "" && strings.HasPrefix(w.Target, "/")
}
func action(p *Phase) bool {
	_, err := decimal(p.ActionID, true)
	return err == nil && boundWitness(p.Witness)
}
func (r Response) ValidateWorkspace() error {
	w := r.Workspace
	if w == nil || w.Binding.validate() != nil || !mountid.ValidMountInstance(r.MountInstanceID) || r.Sequence != 0 || r.LossSequence != "" || r.AuthorizationDeadlineUnixMs != 0 || r.Error != "" {
		return ErrGrammar
	}
	if w.Binding != w.Binding.ResponseBinding() {
		return ErrGrammar
	}
	if w.State == "refused" {
		switch w.Refusal {
		case "unavailable", "occupied", "retired", "invalid", "handler-failed", "deadline", "stopped", "peer-refused":
		default:
			return ErrGrammar
		}
		if r.OK || w.Readiness != nil || w.Action != nil || w.ColdComplete || len(w.Loss) != 0 || w.Reason != "" || w.Witness != (Witness{}) || w.AuthorizationDeadlineUnixNanos != "0" || w.Outcome != (Outcome{"unresolved", "unobserved", "unresolved", "0"}) {
			return ErrGrammar
		}
		return nil
	}
	if !r.OK || w.Refusal != "" {
		return ErrGrammar
	}
	if !boundedWitness(w.Witness) || !boundedPhase(w.Action) {
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
		if p == nil || !p.SessionValidated || !p.AuthorizationValidated || !positiveDecimal(p.SubscriptionIncarnation) || w.Witness.Session == "" || w.AuthorizationDeadlineUnixNanos == "0" {
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

// sameDescription compares kernel struct file owners, including /dev/fuse
// connections. kcmp compares within this process; no other process is inspected.
func sameDescription(a, b int) (bool, error) {
	result, _, errno := unix.Syscall6(unix.SYS_KCMP, uintptr(os.Getpid()), uintptr(os.Getpid()), 0, uintptr(a), uintptr(b), 0)
	if errno != 0 {
		return false, fmt.Errorf("compare descriptor owners: %w", errno)
	}
	return result == 0, nil
}

func (r *Rights) retain() (*Rights, error) {
	out := &Rights{}
	for _, fd := range r.FDs {
		copy, err := unix.FcntlInt(uintptr(fd), unix.F_DUPFD_CLOEXEC, 0)
		if err != nil {
			out.Close()
			return nil, err
		}
		out.FDs = append(out.FDs, copy)
	}
	return out, nil
}
func (r *Rights) same(other *Rights) bool {
	if len(r.FDs) != len(other.FDs) {
		return false
	}
	for i, fd := range r.FDs {
		same, err := sameDescription(fd, other.FDs[i])
		if err != nil || !same {
			return false
		}
	}
	return true
}
func (r *Rights) Validate(op string) error {
	want := 0
	if op == "workspace-install-kernel" {
		want = 2
	}
	if len(r.FDs) != want {
		return ErrGrammar
	}
	if want == 2 {
		same, err := sameDescription(r.FDs[0], r.FDs[1])
		if err != nil {
			return err
		}
		if same {
			return ErrGrammar
		}
	}
	return nil
}

// Handler owns jobs independently of request waiters. It must return bounded
// phase receipts/snapshots, never wait for the lifetime of Prepare or Recover.
type Handler interface {
	Handle(context.Context, Request, *Rights) (Response, error)
}
type receipt struct {
	id       uint64
	body     []byte
	files    *Rights
	response []byte
	done     chan struct{}
	cancel   context.CancelFunc
}
type Replay struct {
	mu                        sync.Mutex
	high                      [3]uint64 // start, phase and observation lanes advance independently
	operation                 string
	instance                  string
	active                    bool
	prepareStarted            bool
	lastResume                [32]byte
	recoveredGeneration       uint64
	nextAction                *Phase
	actionKind                string
	binding                   *Workspace
	start, phase, observation *receipt
	closed                    bool
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
func (r *Replay) closeAdmission() {
	if r.CloseAdmission != nil {
		r.CloseAdmission()
	}
}
func (r *Replay) Close() {
	r.mu.Lock()
	r.closed = true
	retained := []*receipt{r.start, r.phase, r.observation}
	for _, old := range retained {
		if old != nil {
			old.cancel()
		}
	}
	r.mu.Unlock()
	for _, old := range retained {
		if old != nil {
			<-old.done
			old.files.Close()
		}
	}
}
func inFlight(old *receipt) bool {
	if old == nil {
		return false
	}
	select {
	case <-old.done:
		return false
	default:
		return true
	}
}
func waitReceipt(ctx context.Context, old *receipt) (Response, error) {
	select {
	case <-ctx.Done():
		return Response{}, ctx.Err()
	case <-old.done:
		return DecodeResponse(old.response, true)
	}
}
func (r *Replay) Do(ctx context.Context, req Request, rights *Rights, h Handler) (Response, error) {
	defer rights.Close()
	if err := req.ValidateWorkspace(); err != nil {
		r.closeAdmission()
		return Response{}, err
	}
	if err := rights.Validate(req.Operation); err != nil {
		r.closeAdmission()
		return Response{}, err
	}
	// Close permission before even waiting for replay bookkeeping or a lane.
	if req.Operation == "workspace-suspend" || req.Operation == "workspace-cleanup" {
		r.closeAdmission()
	}
	receivedAt := r.now()
	budget, _ := decimal(req.Workspace.BudgetNanos, true)
	deadline := receivedAt.Add(time.Duration(budget))
	if d, ok := ctx.Deadline(); ok && d.Before(deadline) {
		deadline = d
	}
	body := immutable(req)
	id, _ := decimal(req.Workspace.RequestID, true)
	r.mu.Lock()
	if r.closed {
		r.mu.Unlock()
		return Response{}, ErrUnavailable
	}
	for _, old := range []*receipt{r.start, r.phase, r.observation} {
		if old != nil && old.id == id {
			same := bytes.Equal(body, old.body) && rights.same(old.files)
			r.mu.Unlock()
			if !same {
				r.closeAdmission()
				return Response{}, ErrGrammar
			}
			return waitReceipt(ctx, old)
		}
	}
	refuse := func(err error) (Response, error) { r.mu.Unlock(); return Response{}, err }
	if err := ctx.Err(); err != nil {
		return refuse(err)
	}
	start := req.Workspace.RequestID == req.Workspace.OperationID
	lane := 1
	if start {
		lane = 0
	} else if req.Operation == "workspace-observe" {
		lane = 2
	}
	if id <= r.high[lane] {
		return refuse(ErrRetired)
	}
	if !start && (r.binding == nil || req.MountInstanceID != r.instance || req.Workspace.OperationID != r.operation || !sameBinding(*r.binding, *req.Workspace)) {
		return refuse(ErrGrammar)
	}
	generation, _ := decimal(req.Workspace.Generation, false)
	if start && r.binding != nil {
		oldGeneration, _ := decimal(r.binding.Generation, false)
		serial, _ := decimal(req.Workspace.GateSerial, false)
		oldSerial, _ := decimal(r.binding.GateSerial, false)
		if req.MountInstanceID != r.instance || req.Workspace.BootID != r.binding.BootID || req.Workspace.HostServiceID != r.binding.HostServiceID || req.Workspace.GuestServiceID != r.binding.GuestServiceID || generation < oldGeneration || serial < oldSerial {
			return refuse(ErrGrammar)
		}
	}
	if req.Operation == "workspace-recover" && (generation <= r.recoveredGeneration || r.lastResume == sha256.Sum256([]byte(req.Workspace.Transaction))) {
		return refuse(ErrGrammar)
	}
	if req.Operation == "workspace-prepare" && r.prepareStarted {
		return refuse(ErrGrammar)
	}
	if req.Operation == "workspace-install-kernel" || req.Operation == "workspace-unmount-complete" {
		expected := "kernel-required"
		if req.Operation == "workspace-unmount-complete" {
			expected = "unmount-required"
		}
		p := *req.Workspace.Phase
		p.Removal = nil
		if !r.active || r.nextAction == nil || r.actionKind != expected || !reflect.DeepEqual(p, *r.nextAction) {
			return refuse(ErrGrammar)
		}
	}
	if start && r.active && req.Operation != "workspace-suspend" && req.Operation != "workspace-cleanup" {
		return refuse(ErrOccupied)
	}
	if lane == 2 && inFlight(r.observation) || lane != 2 && (inFlight(r.start) || inFlight(r.phase)) {
		return refuse(ErrOccupied)
	}
	if h == nil {
		return refuse(ErrUnavailable)
	}
	files, err := rights.retain()
	if err != nil {
		return refuse(err)
	}
	// Neither socket hangup nor its cancellation becomes job cancellation. The
	// first receipt deadline bounds this dispatch, including Suspend retries.
	job, cancel := context.WithDeadline(context.WithoutCancel(ctx), deadline)
	retained := &receipt{id: id, body: body, files: files, done: make(chan struct{}), cancel: cancel}
	retire := func(old *receipt) {
		if old != nil {
			old.files.Close()
		}
	}
	if start {
		r.active = true
		r.nextAction, r.actionKind = nil, ""
		if req.Operation == "workspace-prepare" {
			r.prepareStarted = true
		}
		if req.Operation == "workspace-recover" {
			r.lastResume = sha256.Sum256([]byte(req.Workspace.Transaction))
			r.recoveredGeneration = generation
		}
		r.instance, r.operation = req.MountInstanceID, req.Workspace.OperationID
		copy := req.Workspace.ResponseBinding()
		r.binding = &copy
		retire(r.start)
		retire(r.phase)
		r.start, r.phase = retained, nil
		// An observation of the overtaken operation may still finish. It owns no
		// descriptors, and its result cannot update the new operation's actions.
	} else if lane == 2 {
		retire(r.observation)
		r.observation = retained
	} else {
		retire(r.phase)
		r.phase = retained
	}
	r.high[lane] = id
	owned := &Rights{FDs: rights.Take()}
	r.mu.Unlock()
	go r.dispatch(job, req, owned, h, retained)
	return waitReceipt(ctx, retained)
}
func (r *Replay) dispatch(ctx context.Context, req Request, rights *Rights, h Handler, retained *receipt) {
	defer retained.cancel()
	response, err := h.Handle(ctx, req, rights)
	// Received duplicates are disposed before the receipt becomes observable.
	rights.Close()
	if err == nil {
		if response.Workspace == nil {
			err = ErrGrammar
		} else {
			state := response.Workspace.State
			switch req.Operation {
			case "workspace-prepare", "workspace-recover", "workspace-suspend", "workspace-cleanup":
				if state != "accepted" && state != "failed" {
					err = ErrGrammar
				}
			case "workspace-install-kernel":
				if state != "install-complete" && state != "failed" {
					err = ErrGrammar
				}
			case "workspace-unmount-complete":
				if state != "unmount-recorded" && state != "failed" {
					err = ErrGrammar
				}
			case "workspace-observe":
				if state == "accepted" || state == "install-complete" || state == "unmount-recorded" {
					err = ErrGrammar
				}
			}
			if response.MountInstanceID != req.MountInstanceID || !reflect.DeepEqual(response.Workspace.Binding, req.Workspace.ResponseBinding()) {
				err = ErrGrammar
			}
		}
	}
	var raw []byte
	if err == nil {
		raw, err = EncodeResponse(response)
	}
	if err != nil {
		response = WorkspaceRefusal(req, err)
		raw, _ = EncodeResponse(response)
	}
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.binding != nil && sameBinding(*r.binding, *req.Workspace) {
		state := response.Workspace
		// An older observation may finish after a phase completed this job.
		// Its immutable snapshot cannot restore permission to perform an action.
		if state.Action != nil && r.active {
			rawAction, _ := json.Marshal(state.Action)
			var copy Phase
			_ = json.Unmarshal(rawAction, &copy)
			r.nextAction, r.actionKind = &copy, state.State
		}
		if req.Operation == "workspace-install-kernel" || req.Operation == "workspace-unmount-complete" {
			r.nextAction, r.actionKind = nil, ""
		}
		if state.State == "prepared" || state.State == "cold" || state.State == "cleanup-finalized" || state.State == "failed" || !response.OK {
			r.active = false
			r.nextAction, r.actionKind = nil, ""
		}
	}
	retained.response = raw
	close(retained.done)
}
func sameBinding(a, b Workspace) bool {
	return a.Version == b.Version && a.BootID == b.BootID && a.HostServiceID == b.HostServiceID && a.GuestServiceID == b.GuestServiceID && a.Generation == b.Generation && a.GateSerial == b.GateSerial && a.OperationID == b.OperationID
}

// ResponseBinding contains only bounded correlation fields. Transaction bodies
// and phase payloads are retained in the receipt, never echoed on the wire.
func (w Workspace) ResponseBinding() Workspace {
	w.Transaction, w.HostRequestID, w.Phase = "", "", nil
	return w
}
func WorkspaceRefusal(req Request, err error) Response {
	code := "handler-failed"
	switch {
	case errors.Is(err, ErrPeerRefused):
		code = "peer-refused"
	case errors.Is(err, ErrUnavailable):
		code = "unavailable"
	case errors.Is(err, ErrOccupied):
		code = "occupied"
	case errors.Is(err, ErrRetired):
		code = "retired"
	case errors.Is(err, ErrGrammar):
		code = "invalid"
	case errors.Is(err, context.DeadlineExceeded):
		code = "deadline"
	case errors.Is(err, context.Canceled):
		code = "stopped"
	}
	return Response{MountInstanceID: req.MountInstanceID, Workspace: &WorkspaceResponse{Binding: req.Workspace.ResponseBinding(), State: "refused", Refusal: code, AuthorizationDeadlineUnixNanos: "0", Outcome: Outcome{Durability: "unresolved", Observation: "unobserved", Release: "unresolved", CleanupDebt: "0"}}}
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
