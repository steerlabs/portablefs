package mountenrollment

import (
	"context"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"strings"
	"sync"
	"time"
	"unicode/utf8"

	"github.com/steerlabs/portablefs/vcs/internal/controlplane"
)

// ErrObsoleteInstallation reports a known remote success whose permission was
// closed before local publication. The sequence advances, readiness does not.
var ErrObsoleteInstallation = errors.New("renewal installation belongs to an obsolete permit")

type GrantSource interface {
	Refresh(context.Context, string, uint64) (controlplane.MountAuthorization, error)
}

type GrantInstaller func(context.Context, string, uint64, []byte) (time.Time, error)

// Permit identifies one permission interval, including repeated closes within a
// generation. CheckPermit must be nonblocking; installers recheck it themselves.
type Permit struct {
	Generation uint64 `json:"generation,string"`
	GateSerial uint64 `json:"gateSerial,string"`
}
type permitKey struct{}

func WithPermit(ctx context.Context, p Permit) context.Context {
	return context.WithValue(ctx, permitKey{}, p)
}
func PermitFromContext(ctx context.Context) (Permit, bool) {
	p, ok := ctx.Value(permitKey{}).(Permit)
	return p, ok
}

type RenewalReadiness struct {
	State                 string    `json:"state"`
	InstalledSequence     uint64    `json:"installedSequence,string"`
	Permit                Permit    `json:"permit"`
	SessionID             string    `json:"sessionId,omitempty"`
	AuthorizationDeadline time.Time `json:"authorizationDeadline"`
}

// Standalone readiness has no renewal sequence, permit, session or deadline.
// Pending proofs carry only their permit, never a zero-time installed claim.
func (r RenewalReadiness) MarshalJSON() ([]byte, error) {
	type proof struct {
		State                 string     `json:"state"`
		InstalledSequence     uint64     `json:"installedSequence,string,omitempty"`
		Permit                *Permit    `json:"permit,omitempty"`
		SessionID             string     `json:"sessionId,omitempty"`
		AuthorizationDeadline *time.Time `json:"authorizationDeadline,omitempty"`
	}
	out := proof{State: r.State}
	if r.State != "not-required" && r.Permit != (Permit{}) {
		out.Permit = &r.Permit
	}
	if r.State == "installed" {
		out.InstalledSequence, out.SessionID = r.InstalledSequence, r.SessionID
		out.AuthorizationDeadline = &r.AuthorizationDeadline
	}
	return json.Marshal(out)
}

func (r RenewalReadiness) Ready(standalone bool, p Permit, session string, deadline time.Time) bool {
	if r.Permit != p {
		return false
	}
	if r.State == "not-required" {
		return standalone && r.InstalledSequence == 0
	}
	return !standalone && r.State == "installed" && r.InstalledSequence > 0 && r.SessionID == session && session != "" && r.AuthorizationDeadline.Equal(deadline) && !deadline.IsZero()
}

type RenewalStatus struct {
	Readiness RenewalReadiness

	AuthorizationDeadline time.Time
	LastSuccess           time.Time
	NextAttempt           time.Time
	Sequence              uint64
	ConsecutiveFailures   uint64
	LastError             string
}

type RenewalEventKind string

const (
	RenewalScheduled RenewalEventKind = "scheduled"
	RenewalSucceeded RenewalEventKind = "succeeded"
	RenewalRetrying  RenewalEventKind = "retrying"
	RenewalDenied    RenewalEventKind = "denied"
	RenewalCutoff    RenewalEventKind = "cutoff"
	RenewalStopped   RenewalEventKind = "stopped"
)

// RenewalEvent is one fact emitted by the single renewal owner. Status is a
// complete snapshot after that fact, never a sparse collection of fields that
// each platform has to interpret differently.
type RenewalEvent struct {
	Kind       RenewalEventKind
	ObservedAt time.Time
	Status     RenewalStatus
}

type Renewer struct {
	// Managed requires an explicit Resume permit before dispatch. No implicit
	// ordinary permit is available on this branch.
	Managed                      bool
	CheckPermit                  func(Permit) bool
	mu                           sync.Mutex
	running, initialized, parked bool
	serving                      bool // readiness published in this permission interval
	permit                       Permit
	wake                         chan struct{}
	attemptCancel                context.CancelFunc
	attemptDone                  chan struct{}
	session                      string
	deadline, authorizedAt       time.Time
	sequence                     uint64
	pending                      *controlplane.MountAuthorization
	readiness, installed         RenewalReadiness
	status                       RenewalStatus
	force                        bool
	terminal                     error
	waitHook                     func(context.Context, time.Time, <-chan struct{}) error
	scheduleHook                 func(Permit, time.Time) // acknowledges a specific scheduling decision in tests

	Source  GrantSource
	Now     func() time.Time
	Observe func(RenewalEvent)
	Timeout time.Duration
	// MinimumSafetyMargin reserves enough time for a platform owner to make
	// cached kernel state unservable after renewal fails. FSKit sets this to its
	// full repair budget; Linux uses the default five-second floor.
	MinimumSafetyMargin time.Duration
}

// Park revokes local dispatch immediately and joins the current source/installer.
// An uncooperative installer retains its owner until it actually returns.
func (r *Renewer) Park(ctx context.Context) error {
	r.mu.Lock()
	r.parked = true
	r.serving = false
	r.readiness = RenewalReadiness{State: "pending", Permit: r.permit}
	if r.attemptCancel != nil {
		r.attemptCancel()
	}
	done := r.attemptDone
	r.signalLocked()
	r.mu.Unlock()
	if done != nil {
		select {
		case <-done:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	return nil
}
func (r *Renewer) Resume(p Permit) error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.terminal != nil {
		return r.terminal
	}
	if r.Managed && (r.CheckPermit == nil || !r.CheckPermit(p)) {
		return errors.New("renewal resume requires a current permit")
	}
	if r.parked && r.attemptDone != nil {
		return errors.New("renewal resume waits for the parked installation owner")
	}
	r.permit = p
	r.parked = false
	r.force = r.pending != nil || !r.installationSafeLocked()
	r.readiness = RenewalReadiness{State: "pending", Permit: p}
	// Park is the only live transition back to closed recovery. Repeating
	// Resume cannot remove the cutoff from an already serving owner.
	if r.installationSafeLocked() && r.pending == nil {
		r.readiness = r.installed
		r.readiness.Permit = p
		r.serving = true
	}
	r.signalLocked()
	return nil
}

// RefreshNow wakes the owner for an immediate scheduling decision. Ordinary
// owners may refresh early. Managed owners preserve the normal Manager refresh
// time for a recorded install; only an unknown pending grant retries immediately.
func (r *Renewer) RefreshNow() { r.mu.Lock(); r.force = true; r.signalLocked(); r.mu.Unlock() }
func (r *Renewer) Readiness() RenewalReadiness {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.terminal != nil || !r.running || !r.allowedLocked() || !r.installationSafeLocked() {
		return RenewalReadiness{State: "pending", Permit: r.permit}
	}
	return r.readiness
}

// A proof is publishable only outside the serving withdrawal margin.
func (r *Renewer) installationSafeLocked() bool {
	return r.installed.InstalledSequence > 0 && r.now().Before(safeCutoff(r.authorizedAt, r.installed.AuthorizationDeadline, r.MinimumSafetyMargin))
}
func (r *Renewer) signalLocked() {
	if r.wake == nil {
		r.wake = make(chan struct{}, 1)
	}
	select {
	case r.wake <- struct{}{}:
	default:
	}
}
func (r *Renewer) allowedLocked() bool {
	return !r.parked && (!r.Managed || (r.CheckPermit != nil && r.CheckPermit(r.permit)))
}
func (r *Renewer) wait(ctx context.Context, target time.Time) error {
	r.mu.Lock()
	if r.wake == nil {
		r.wake = make(chan struct{}, 1)
	}
	wake := r.wake
	r.mu.Unlock()
	if r.waitHook != nil {
		return r.waitHook(ctx, target, wake)
	}
	var tick <-chan time.Time
	if !target.IsZero() {
		timer := time.NewTimer(max(time.Duration(0), target.Sub(r.now())))
		defer timer.Stop()
		tick = timer.C
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-wake:
		return nil
	case <-tick:
		return nil
	}
}

// Run is the sole dispatcher. Reentry continues the same session, sequence and
// exact pending grant; a second concurrent runner or a new session is refused.
func (r *Renewer) Run(ctx context.Context, sessionID string, initialDeadline time.Time, install GrantInstaller) error {
	if r == nil || r.Source == nil || sessionID == "" || install == nil {
		return errors.New("complete automatic mount renewal configuration is required")
	}
	r.mu.Lock()
	if r.terminal != nil {
		err := r.terminal
		r.mu.Unlock()
		return err
	}
	if r.running || (r.initialized && r.session != sessionID) {
		r.mu.Unlock()
		return errors.New("renewal owner already bound")
	}
	if !r.initialized {
		if !initialDeadline.After(r.now()) {
			r.mu.Unlock()
			return errors.New("live initial authorization required")
		}
		r.initialized = true
		r.session = sessionID
		r.sequence = 1
		r.deadline = initialDeadline
		r.authorizedAt = r.now()
		r.readiness = RenewalReadiness{State: "pending", Permit: r.permit}
		r.status = RenewalStatus{AuthorizationDeadline: initialDeadline, Sequence: 1}
	}
	r.running = true
	r.serving = false
	r.readiness = RenewalReadiness{State: "pending", Permit: r.permit}
	if r.Managed && r.allowedLocked() && r.pending == nil && r.installationSafeLocked() {
		r.readiness = r.installed
		r.readiness.Permit = r.permit
		r.serving = true
	} else {
		r.force = true
	}
	r.mu.Unlock()
	defer func() {
		r.mu.Lock()
		r.running = false
		r.readiness = RenewalReadiness{State: "pending", Permit: r.permit}
		r.mu.Unlock()
	}()
	timeout := r.Timeout
	if timeout <= 0 {
		timeout = 20 * time.Second
	}
	backoff := 500 * time.Millisecond
	for {
		if ctx.Err() != nil {
			r.emit(RenewalStopped, time.Time{}, "", 0)
			return nil
		}
		r.mu.Lock()
		if !r.allowedLocked() {
			r.mu.Unlock()
			if r.wait(ctx, time.Time{}) != nil {
				continue
			}
			continue
		}
		cutoff := safeCutoff(r.authorizedAt, r.deadline, r.MinimumSafetyMargin)
		next := r.status.NextAttempt
		if r.force {
			next = time.Time{}
			r.force = false
		}
		// A managed wakeup preserves the normal mid-window refresh schedule,
		// safely beyond Manager's minimum interval. Pending exact retries need
		// no Manager refresh and must remain immediately reconcilable.
		if r.Managed && r.pending == nil && r.installed.InstalledSequence > 0 {
			earliest := refreshTime(r.authorizedAt, r.deadline, r.session, r.sequence)
			if next.Before(earliest) {
				next = earliest
			}
		}
		bounded := !r.Managed || r.serving
		if bounded && !r.now().Before(cutoff) {
			err := errors.New("automatic mount reauthorization reached its safe cutoff")
			r.terminal = err
			r.readiness = RenewalReadiness{State: "pending", Permit: r.permit}
			r.mu.Unlock()
			r.emit(RenewalCutoff, time.Time{}, boundedError(err), r.statusFailures())
			return err
		}
		if bounded && next.After(cutoff) {
			next = cutoff
		}
		if hook := r.scheduleHook; hook != nil {
			permit := r.permit
			r.mu.Unlock()
			hook(permit, next)
			r.mu.Lock()
			if !r.allowedLocked() || r.permit != permit {
				r.mu.Unlock()
				continue
			}
		}
		if next.After(r.now()) {
			r.mu.Unlock()
			_ = r.wait(ctx, next)
			continue
		}
		p, seq, session := r.permit, r.sequence, r.session
		deadline := r.now().Add(timeout)
		// Managed preparation runs behind closed admission. Its attempts remain
		// bounded, but the previous serving window cannot retire a live pending
		// grant or end transient recovery. The generation owns cancellation.
		if bounded {
			deadline = minTime(deadline, cutoff)
		}
		attemptCtx, cancel := context.WithDeadline(WithPermit(ctx, p), deadline)
		r.attemptCancel = cancel
		done := make(chan struct{})
		r.attemptDone = done
		pending := r.pending
		r.mu.Unlock()
		var err error
		if pending == nil {
			var grant controlplane.MountAuthorization
			grant, err = r.Source.Refresh(attemptCtx, session, seq)
			if err == nil {
				if grant.Sequence != seq || (grant.SessionID != "" && grant.SessionID != session) || grant.Capability == "" || grant.ExpiresUnix <= 0 {
					err = fmt.Errorf("invalid Manager renewal grant: %w", ErrDefinitiveDenial)
				} else {
					r.mu.Lock()
					r.pending = &grant
					pending = r.pending
					r.mu.Unlock()
				}
			}
		}
		r.mu.Lock()
		allowed := r.allowedLocked() && r.permit == p && attemptCtx.Err() == nil
		r.mu.Unlock()
		installed := time.Time{}
		if err == nil && allowed {
			installed, err = install(attemptCtx, pending.Capability, seq, []byte(pending.ClientCertificatePEM))
		}
		r.mu.Lock()
		// A successful installer is a known remote installation even if Park/Close
		// raced it. Keep that sequence before considering readiness publication.
		obsolete := errors.Is(err, ErrObsoleteInstallation)
		known := (err == nil || obsolete) && allowed
		if known {
			if obsolete {
				err = nil
			}
			r.pending = nil
			if seq == math.MaxUint64 {
				err = fmt.Errorf("renewal sequence exhausted: %w", ErrDefinitiveDenial)
			} else {
				r.sequence++
			}
			if !installed.Equal(time.Unix(pending.ExpiresUnix, 0)) || !installed.After(r.now()) {
				err = fmt.Errorf("authority installed a deadline different from the Manager grant: %w", ErrDefinitiveDenial)
			} else {
				r.deadline = installed
				r.authorizedAt = r.now()
				r.installed = RenewalReadiness{State: "installed", InstalledSequence: seq, Permit: p, SessionID: session, AuthorizationDeadline: installed}
				if r.allowedLocked() && r.permit == p && ctx.Err() == nil && !obsolete && r.installationSafeLocked() {
					r.readiness = r.installed
					r.serving = true
				}
			}
		}
		if errors.Is(err, ErrDefinitiveDenial) {
			r.terminal = err
			r.readiness = RenewalReadiness{State: "pending", Permit: r.permit}
		}
		r.attemptCancel = nil
		r.attemptDone = nil
		cancel()
		close(done)
		current := r.allowedLocked() && r.permit == p
		r.mu.Unlock()
		if errors.Is(err, ErrDefinitiveDenial) {
			r.emit(RenewalDenied, time.Time{}, boundedError(err), r.statusFailures()+1)
			return err
		}
		if !current {
			continue
		}
		if ctx.Err() != nil {
			continue
		}
		if err == nil && !known {
			continue
		}
		if err == nil {
			backoff = 500 * time.Millisecond
			r.emit(RenewalSucceeded, time.Time{}, "", 0)
			r.mu.Lock()
			next = refreshTime(r.now(), r.deadline, session, r.sequence)
			r.mu.Unlock()
			if ctx.Err() == nil {
				r.emit(RenewalScheduled, next, "", 0)
			}
			continue
		}
		failures := r.statusFailures() + 1
		next = r.now().Add(backoff)
		if bounded && !next.Before(cutoff) {
			resultErr := fmt.Errorf("automatic mount reauthorization could not complete before the safe cutoff: %w", err)
			r.mu.Lock()
			r.terminal = resultErr
			r.readiness = RenewalReadiness{State: "pending", Permit: r.permit}
			r.mu.Unlock()
			r.emit(RenewalCutoff, time.Time{}, boundedError(resultErr), failures)
			return resultErr
		}
		r.emit(RenewalRetrying, next, boundedError(err), failures)
		backoff = min(30*time.Second, backoff*2)
	}
}
func minTime(a, b time.Time) time.Time {
	if a.Before(b) {
		return a
	}
	return b
}
func (r *Renewer) statusFailures() uint64 {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.status.ConsecutiveFailures
}
func (r *Renewer) emit(kind RenewalEventKind, next time.Time, message string, failures uint64) {
	r.mu.Lock()
	r.status.AuthorizationDeadline = r.deadline
	r.status.Sequence = r.sequence
	if kind == RenewalSucceeded {
		r.status.Sequence--
		r.status.LastSuccess = r.authorizedAt
	}
	r.status.NextAttempt = next
	r.status.LastError = message
	r.status.ConsecutiveFailures = failures
	r.status.Readiness = r.readiness
	if !r.allowedLocked() || kind == RenewalStopped || kind == RenewalCutoff || kind == RenewalDenied {
		r.readiness = RenewalReadiness{State: "pending", Permit: r.permit}
		r.status.Readiness = r.readiness
	}
	status := r.status
	r.mu.Unlock()
	r.observe(kind, status)
}

func boundedError(err error) string {
	if err == nil {
		return ""
	}
	value := strings.TrimSpace(strings.ReplaceAll(strings.ToValidUTF8(err.Error(), "?"), "\x00", "?"))
	if value == "" {
		value = "automatic renewal failed"
	}
	for len(value) > 1024 {
		_, size := utf8.DecodeLastRuneInString(value)
		if size == 0 {
			return "renewal error exceeded its presentation bound"
		}
		value = value[:len(value)-size]
	}
	return value
}

func (renewer *Renewer) now() time.Time {
	if renewer.Now != nil {
		return renewer.Now()
	}
	return time.Now()
}

func (renewer *Renewer) observe(kind RenewalEventKind, status RenewalStatus) {
	if renewer.Observe != nil {
		renewer.Observe(RenewalEvent{Kind: kind, ObservedAt: renewer.now(), Status: status})
	}
}

func refreshTime(now, deadline time.Time, sessionID string, sequence uint64) time.Time {
	remaining := deadline.Sub(now)
	if remaining <= 0 {
		return now
	}
	// A stable per-session offset spreads many mounts over the middle 20% of
	// their windows without a global random source or timer polling.
	seed := sha256.Sum256([]byte("schedule\x00" + sessionID + "\x00" + fmt.Sprint(sequence)))
	percent := 40 + int(seed[len(seed)-1])%21
	return now.Add(time.Duration(int64(remaining) * int64(percent) / 100))
}

func safeCutoff(authorizedAt, deadline time.Time, minimum time.Duration) time.Time {
	window := deadline.Sub(authorizedAt)
	margin := window / 10
	if minimum < 5*time.Second {
		minimum = 5 * time.Second
	}
	if margin < minimum {
		margin = minimum
	}
	if margin > time.Minute && minimum <= time.Minute {
		margin = time.Minute
	}
	return deadline.Add(-margin)
}
