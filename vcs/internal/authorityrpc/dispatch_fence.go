package authorityrpc

import (
	"context"
	"errors"
	"sync"

	"github.com/steerlabs/portablefs/vcs/internal/authoritypb"
	"google.golang.org/protobuf/proto"
)

// DispatchFence belongs to one client/session. Passive response readers remain
// alive while parked. Assigned cleanup retains its exact body and replay slot;
// an applying operation must settle before Park can certify quiescence.
// Ordinary clients have no fence and keep their existing dispatch path.
type DispatchFence struct {
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
	Parked     bool
	InFlightIO int
	Owners     []DispatchOwner
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
	s := DispatchSnapshot{Parked: f.parked, InFlightIO: f.io}
	for _, o := range f.owners {
		o.Body = append([]byte(nil), o.Body...)
		s.Owners = append(s.Owners, o)
	}
	return s
}
func (f *DispatchFence) begin(ctx context.Context, assigning bool) (func(), error) {
	if f == nil {
		return func() {}, nil
	}
	f.mu.Lock()
	for f.parked || assigning && f.draining {
		changed := f.changed
		f.mu.Unlock()
		select {
		case <-changed:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
		f.mu.Lock()
	}
	if err := ctx.Err(); err != nil {
		f.mu.Unlock()
		return nil, err
	}
	if f.check == nil {
		f.mu.Unlock()
		return nil, errors.New("authorityrpc: dispatch has no readiness owner")
	}
	if err := f.check(); err != nil {
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
	for f.parked || applying && f.draining {
		changed := f.changed
		f.mu.Unlock()
		select {
		case <-changed:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
		f.mu.Lock()
	}
	if err := ctx.Err(); err != nil {
		f.mu.Unlock()
		return nil, err
	}
	if err := f.check(); err != nil {
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
func (c *Client) DispatchSnapshot() DispatchSnapshot {
	if c.cfg.DispatchFence == nil {
		return DispatchSnapshot{}
	}
	return c.cfg.DispatchFence.Snapshot()
}
