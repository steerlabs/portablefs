//go:build linux

package mountcontrol

import (
	"context"
	"encoding/base64"
	"encoding/hex"
	"errors"
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
	Version          uint32 `json:"version"`
	RequestID        string `json:"requestId"`
	OperationID      string `json:"operationId"`
	BootID           string `json:"bootId"`
	HostServiceID    string `json:"hostServiceId"`
	GuestServiceID   string `json:"guestServiceId"`
	Generation       string `json:"generation"`
	GateSerial       string `json:"gateSerial"`
	BudgetNanos      string `json:"budgetNanos"`
	DrainBudgetNanos string `json:"drainBudgetNanos,omitempty"`
	HostRequestID    string `json:"hostRequestId,omitempty"`
	Transaction      string `json:"transaction,omitempty"`
	Phase            *Phase `json:"phase,omitempty"`
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

// ActionStatus is a fixed lifecycle slot, never a response receipt.
// Absent slots are explicit; a failed slot remains consumed.
// KernelAction binds to the response mount witness; repeating that witness in
// every fixed slot would exceed the maximum loss-ledger frame.
type KernelAction struct {
	ActionID string   `json:"actionId"`
	Mode     string   `json:"mode,omitempty"`
	Reason   string   `json:"reason,omitempty"`
	Options  []string `json:"options,omitempty"`
	Removal  *Removal `json:"removal,omitempty"`
}

func (a KernelAction) WithWitness(w Witness) *Phase {
	return &Phase{ActionID: a.ActionID, Mode: a.Mode, Reason: a.Reason, Options: append([]string(nil), a.Options...), Removal: a.Removal, Witness: w}
}
func kernelAction(p Phase) *KernelAction {
	return &KernelAction{ActionID: p.ActionID, Mode: p.Mode, Reason: p.Reason, Options: append([]string(nil), p.Options...), Removal: p.Removal}
}

type ActionStatus struct {
	Progress string        `json:"progress"`
	Action   *KernelAction `json:"action,omitempty"`
	Failure  string        `json:"failure,omitempty"`
}
type PhaseFacts struct {
	Install          ActionStatus `json:"install"`
	VoluntaryRemoval ActionStatus `json:"voluntaryRemoval"`
	TerminalRemoval  ActionStatus `json:"terminalRemoval"`
}

type WorkspaceResponse struct {
	Binding                        Workspace   `json:"binding"`
	State                          string      `json:"state"`
	Witness                        Witness     `json:"witness"`
	AuthorizationDeadlineUnixNanos string      `json:"authorizationDeadlineUnixNanos"`
	Outcome                        Outcome     `json:"outcome"`
	Loss                           []Loss      `json:"loss,omitempty"`
	ColdComplete                   bool        `json:"coldComplete,omitempty"`
	Readiness                      *Prepared   `json:"readiness,omitempty"`
	Phases                         *PhaseFacts `json:"phases,omitempty"`
	Reason                         string      `json:"reason,omitempty"`
	Refusal                        string      `json:"refusal,omitempty"`
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
	if r.Operation == "workspace-suspend" {
		n, err := decimal(w.DrainBudgetNanos, false)
		if err != nil || n > uint64(15*time.Second) {
			return ErrGrammar
		}
	} else if w.DrainBudgetNanos != "" {
		return ErrGrammar
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
			if x.AwakeRecovery != (w.DrainBudgetNanos == "0") {
				return ErrGrammar
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

// AwakeRecoveryCut is carried by the exact transaction, never inferred from
// an absent deadline or a socket retry budget.
func (w *Workspace) AwakeRecoveryCut() bool {
	if w == nil {
		return false
	}
	raw, err := base64.RawURLEncoding.DecodeString(w.Transaction)
	var x pb.Suspension
	return err == nil && control.DecodeBody(raw, &x) == nil && x.AwakeRecovery
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
	if r.Metadata != nil {
		return ErrGrammar
	}
	w := r.Workspace
	if w == nil || w.Binding.validate() != nil || !mountid.ValidMountInstance(r.MountInstanceID) || r.Sequence != 0 || r.LossSequence != "" || r.AuthorizationDeadlineUnixMs != 0 || r.Error != "" {
		return ErrGrammar
	}
	if w.Binding != w.Binding.ResponseBinding() {
		return ErrGrammar
	}
	if w.State == "refused" {
		switch w.Refusal {
		case "unavailable", "occupied", "retired", "invalid", "handler-failed", "deadline", "stopped", "peer-refused", "action-consumed", "not-accepted", "incarnation-terminal":
		default:
			return ErrGrammar
		}
		if r.OK || w.Readiness != nil || w.Phases != nil || w.ColdComplete || len(w.Loss) != 0 || w.Reason != "" || w.Witness != (Witness{}) || w.AuthorizationDeadlineUnixNanos != "0" || w.Outcome != (Outcome{"unresolved", "unobserved", "unresolved", "0"}) {
			return ErrGrammar
		}
		return nil
	}
	if !r.OK || w.Refusal != "" {
		return ErrGrammar
	}
	if !boundedWitness(w.Witness) || !validPhases(w.Phases, w.Witness) {
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
	if len(w.Reason) > control.MaxReason || validLoss(w.Loss) != nil {
		return ErrGrammar
	}

	switch w.State {
	case "accepted", "preparing", "pending-recovery", "pending-suspend", "recovery-required":
	case "unmount-recorded", "cleanup-finalized":
		if !boundWitness(w.Witness) {
			return ErrGrammar
		}
	case "prepared":
		p := w.Readiness
		if w.Phases == nil || w.Phases.Install.Progress != "complete" || !boundWitness(w.Witness) || w.Witness.Kernel == "" || p == nil || !p.SessionValidated || !p.AuthorizationValidated || !positiveDecimal(p.SubscriptionIncarnation) || w.Witness.Session == "" || w.AuthorizationDeadlineUnixNanos == "0" {
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
		if w.Phases == nil || w.Phases.Install.Progress != "offered" {
			return ErrGrammar
		}
	case "unmount-required":
		if w.Phases == nil || w.Phases.VoluntaryRemoval.Progress != "offered" && w.Phases.TerminalRemoval.Progress != "offered" {
			return ErrGrammar
		}
	case "failed":
		if w.Reason == "" {
			return ErrGrammar
		}
	default:
		return ErrGrammar
	}
	if (w.Readiness != nil) != (w.State == "prepared") || w.ColdComplete != (w.State == "cold") {
		return ErrGrammar
	}
	if (w.Phases == nil) != (w.State == "accepted" || w.State == "unmount-recorded") {
		return ErrGrammar
	}
	if w.State != "failed" && w.Reason != "" {
		return ErrGrammar
	}
	return nil
}

func validLoss(loss []Loss) error {
	if len(loss) > control.MaxLosses {
		return ErrGrammar
	}
	var seq uint64
	for i, l := range loss {
		n, err := decimal(l.Sequence, true)
		if err != nil || n <= seq || l.Reason == "" || len(l.Reason) > control.MaxReason {
			return ErrGrammar
		}
		seq = n
		if l.Aggregated && (i != control.MaxLosses-1 || i != len(loss)-1 || l.Reason != control.AggregateReason) {
			return ErrGrammar
		}
		for _, v := range []string{l.AcceptedEntries, l.AcceptedBytes} {
			if _, err := decimal(v, false); err != nil {
				return err
			}
		}
	}
	return nil
}

func validPhases(f *PhaseFacts, witness Witness) bool {
	if f == nil {
		return true
	}
	var ids [3]string
	for i, s := range []ActionStatus{f.Install, f.VoluntaryRemoval, f.TerminalRemoval} {
		if s.Progress == "absent" {
			if s.Action != nil || s.Failure != "" {
				return false
			}
			continue
		}
		if s.Progress != "offered" && s.Progress != "running" && s.Progress != "complete" && s.Progress != "failed" {
			return false
		}
		if s.Action == nil || !boundedPhase(s.Action.WithWitness(witness)) || !action(s.Action.WithWitness(witness)) || (i > 0 && ids[0] == s.Action.ActionID || i > 1 && ids[1] == s.Action.ActionID) || !phaseFailure(s.Failure) || (s.Progress == "failed") != (s.Failure != "") {
			return false
		}
		ids[i] = s.Action.ActionID
		p := s.Action
		if i == 0 {
			if p.Mode != "" || p.Reason != "" || len(p.Options) == 0 || p.Removal != nil {
				return false
			}
		} else {
			expected := "voluntary"
			if i == 2 {
				expected = "terminal"
			}
			if p.Mode != expected || p.Reason == "" || len(p.Options) != 0 || (p.Removal != nil) != (s.Progress == "complete") {
				return false
			}
			if p.Removal != nil && (!p.Removal.KernelAbsent || i == 2 && !p.Removal.AbortCompleted) {
				return false
			}
		}
	}
	return true
}

func phaseFailure(s string) bool {
	return s == "" || s == "handler-failed" || s == "stopped" || s == "deadline"
}

// Rights owns received descriptors. Acceptance moves the inventory into the
// job under its state lock; rejected attempts dispose only their own inventory.
type Rights struct {
	FDs []int
	mu  sync.Mutex
}

func (r *Rights) Close() {
	r.mu.Lock()
	fds := r.FDs
	r.FDs = nil
	r.mu.Unlock()
	for _, fd := range fds {
		_ = unix.Close(fd)
	}
}
func (r *Rights) Validate(op string) error {
	want := 0
	if op == "workspace-install-kernel" {
		want = 2
	}
	if len(r.FDs) != want {
		return ErrGrammar
	}
	// The real bootstrap validator checks ordered FUSE/abort roles before
	// acceptance. Descriptor replay identity is deliberately irrelevant.
	return nil
}

func sameBinding(a, b Workspace) bool {
	return a.Version == b.Version && a.BootID == b.BootID && a.HostServiceID == b.HostServiceID && a.GuestServiceID == b.GuestServiceID && a.Generation == b.Generation && a.GateSerial == b.GateSerial && a.OperationID == b.OperationID
}

// ResponseBinding omits transaction, phase and drain allowance. Socket attempt
// correlation never authorizes a lifecycle transition.
func (w Workspace) ResponseBinding() Workspace {
	w.Transaction, w.HostRequestID, w.Phase, w.DrainBudgetNanos = "", "", nil, ""
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
	case errors.Is(err, ErrActionConsumed):
		code = "action-consumed"
	case errors.Is(err, ErrNotAccepted):
		code = "not-accepted"
	case errors.Is(err, ErrIncarnationTerminal):
		code = "incarnation-terminal"
	case errors.Is(err, ErrGrammar):
		code = "invalid"
	case errors.Is(err, context.DeadlineExceeded):
		code = "deadline"
	case errors.Is(err, context.Canceled):
		code = "stopped"
	}
	return Response{MountInstanceID: req.MountInstanceID, Workspace: &WorkspaceResponse{Binding: req.Workspace.ResponseBinding(), State: "refused", Refusal: code, AuthorizationDeadlineUnixNanos: "0", Outcome: unknownOutcome()}}
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
