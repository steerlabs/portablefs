package authorityrpc

import (
	"context"
	"errors"
	"sync"
	"time"

	"github.com/steerlabs/portablefs/vcs/internal/authoritypb"
	"google.golang.org/protobuf/proto"
)

// DispatchFence belongs to one client/session. Passive response readers remain
// alive while parked. Assigned cleanup retains its exact body and replay slot;
// an applying operation must settle before Park can certify quiescence.
// Ordinary clients have no fence and keep their existing dispatch path.
type DispatchFence struct {
	waitingApplying  int
	mu               sync.Mutex
	parked, draining bool
	check            func() error
	io               int
	changed          chan struct{}
	owners           map[*authoritypb.Request]DispatchOwner
}

type DispatchOwner struct {
	Identity MutationIdentity
	Body     []byte
	Applying bool
}

type DispatchSnapshot struct {
	WaitingApplying int
	Parked          bool
	InFlightIO      int
	Owners          []DispatchOwner
}

type dispatchTimeoutKey struct{}
type dispatchReplayKey struct{}

// ErrDispatchExpired ends an unsubmitted foreground attempt whose captured
// drain permission cannot become valid again. Cleanup owners without a
// foreground budget remain parked for the next lifecycle permission.
var ErrDispatchExpired = errors.New("authorityrpc: captured dispatch permission expired")

// WithDispatchTimeout bounds submitted I/O without spending its budget behind
// a local readiness fence. The parent still owns cancellation of the job.
func WithDispatchTimeout(ctx context.Context, timeout time.Duration) context.Context {
	return context.WithValue(ctx, dispatchTimeoutKey{}, timeout)
}

func NewDispatchFence() *DispatchFence {
	return &DispatchFence{parked: true, owners: make(map[*authoritypb.Request]DispatchOwner), changed: make(chan struct{})}
}
func (f *DispatchFence) signal() { close(f.changed); f.changed = make(chan struct{}) }
func (f *DispatchFence) Resume(check func() error) error {
	if check == nil {
		return errors.New("authorityrpc: dispatch requires current clock and lifecycle permission")
	}
	if err := check(); err != nil {
		return err
	}
	return f.installPermission(check)
}

// Drain retains the old cut's bounded permission after serving admission has
// closed. It cannot revive an unjoined Park, renew the grant, or admit a new
// TLS connection: those connections still await the configured clock owner.
func (f *DispatchFence) Drain(check func() error) error {
	if check == nil {
		return errors.New("authorityrpc: drain requires the captured cut permission")
	}
	return f.installPermission(check)
}

func (f *DispatchFence) installPermission(check func() error) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.draining && (!f.parked || f.io != 0) {
		return errors.New("authorityrpc: resume requires the parked dispatch join")
	}
	f.check = check
	f.parked, f.draining = false, false
	f.signal()
	return nil
}
func (f *DispatchFence) Park(ctx context.Context) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.draining = true
	for {
		applying := false
		for _, o := range f.owners {
			applying = applying || o.Applying
		}
		if !applying {
			f.parked = true
			f.signal()
			if f.io == 0 {
				return nil
			}
		}
		changed := f.changed
		f.mu.Unlock()
		select {
		case <-changed:
		case <-ctx.Done():
			f.mu.Lock()
			return ctx.Err()
		}
		f.mu.Lock()
	}
}
func (f *DispatchFence) Snapshot() DispatchSnapshot {
	f.mu.Lock()
	defer f.mu.Unlock()
	s := DispatchSnapshot{Parked: f.parked, InFlightIO: f.io, WaitingApplying: f.waitingApplying}
	for _, o := range f.owners {
		o.Body = append([]byte(nil), o.Body...)
		s.Owners = append(s.Owners, o)
	}
	return s
}

// A readiness refusal is a local admission barrier, never a transport or
// session verdict. No request or I/O is registered until it passes. The check
// owner has no notification API; bounded resampling also observes cancellation.
func (f *DispatchFence) waitReadyLocked(ctx context.Context, assigning bool) error {
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		if f.parked || assigning && f.draining || f.check == nil {
			changed := f.changed
			f.mu.Unlock()
			select {
			case <-changed:
			case <-ctx.Done():
			}
			f.mu.Lock()
			continue
		}
		err := f.check()
		if err == nil {
			return nil
		}
		if errors.Is(err, ErrDispatchExpired) && !assigning {
			request, _ := ctx.Value(dispatchReplayKey{}).(*authoritypb.Request)
			if owner, ok := f.owners[request]; ok && owner.Identity.Sequence != 0 {
				// Only the retained exact replay can cross an expired cache cut.
				// The authority either returns its recorded outcome or refuses the
				// old subscription; this cannot authorize a new application.
				return nil
			}
		}
		if timeout, _ := ctx.Value(dispatchTimeoutKey{}).(time.Duration); timeout > 0 && errors.Is(err, ErrDispatchExpired) {
			return err
		}
		changed := f.changed
		f.mu.Unlock()
		timer := time.NewTimer(10 * time.Millisecond)
		select {
		case <-changed:
		case <-timer.C:
		case <-ctx.Done():
		}
		timer.Stop()
		f.mu.Lock()
	}
}

func (f *DispatchFence) begin(ctx context.Context, assigning bool) (func(), error) {
	if f == nil {
		return func() {}, nil
	}
	f.mu.Lock()
	if err := f.waitReadyLocked(ctx, assigning); err != nil {
		f.mu.Unlock()
		return nil, err
	}
	f.io++
	f.mu.Unlock()
	return func() { f.mu.Lock(); f.io--; f.signal(); f.mu.Unlock() }, nil
}
func (f *DispatchFence) own(ctx context.Context, r *authoritypb.Request) (func(), error) {
	if f == nil {
		return func() {}, nil
	}
	applying := r.GetMutation() != nil && r.GetBarrier() == nil && r.GetCloseBatch() == nil && r.GetClose() == nil && r.GetReclaim() == nil && r.GetFsync() == nil
	body, err := proto.MarshalOptions{Deterministic: true}.Marshal(r)
	if err != nil {
		return nil, err
	}
	f.mu.Lock()
	if applying {
		f.waitingApplying++
	}
	err = f.waitReadyLocked(ctx, applying)
	if applying {
		f.waitingApplying--
	}
	if err != nil {
		f.mu.Unlock()
		return nil, err
	}
	f.owners[r] = DispatchOwner{Identity: MutationIdentity{r.GetMutation().GetSlot(), r.GetMutation().GetSequence()}, Body: body, Applying: applying}
	f.mu.Unlock()
	return func() { f.mu.Lock(); delete(f.owners, r); f.signal(); f.mu.Unlock() }, nil
}

func (c *Client) ParkDispatch(ctx context.Context) error {
	if c.cfg.DispatchFence == nil {
		return errors.New("authorityrpc: client has no lifecycle dispatch owner")
	}
	return c.cfg.DispatchFence.Park(ctx)
}
func (c *Client) ResumeDispatch(check func() error) error {
	if c.cfg.DispatchFence == nil {
		return errors.New("authorityrpc: client has no lifecycle dispatch owner")
	}
	return c.cfg.DispatchFence.Resume(check)
}
func (c *Client) DrainDispatch(check func() error) error {
	if c.cfg.DispatchFence == nil {
		return errors.New("authorityrpc: client has no lifecycle dispatch owner")
	}
	return c.cfg.DispatchFence.Drain(check)
}
func (c *Client) DispatchSnapshot() DispatchSnapshot {
	if c.cfg.DispatchFence == nil {
		return DispatchSnapshot{}
	}
	return c.cfg.DispatchFence.Snapshot()
}
