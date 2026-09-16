//go:build linux

package fusev3

import (
	"context"
	"errors"
	"sync"
	"syscall"
	"time"

	"github.com/steerlabs/portablefs/vcs/internal/authoritypb"
	"github.com/steerlabs/portablefs/vcs/internal/authorityrpc"
)

// epochRecoverableRPC is implemented by the production mount transport. A
// replacement is a distinct value because authority capabilities, replay
// slots, subscription incarnations, and handles never cross an epoch.
type epochRecoverableRPC interface {
	RecoverEpoch(context.Context) (RPC, error)
}

// epochRPC is the stable mount-side facade shared by request callbacks,
// subscription control, and delegation flushing. Calls snapshot one complete
// epoch transport before dispatch. Recovery publishes its replacement with one
// pointer swap, so no consumer can observe a mixture of old and new methods.
type epochRPC struct {
	mu        sync.RWMutex
	recoverMu sync.Mutex
	rpc       RPC
}

func newEpochRPC(rpc RPC) *epochRPC { return &epochRPC{rpc: rpc} }

func (e *epochRPC) current() RPC {
	e.mu.RLock()
	rpc := e.rpc
	e.mu.RUnlock()
	return rpc
}

// recover replaces an ended epoch only after the caller has permanently
// staled its open handles and accounted for buffered loss. The new session is
// published before the old transport is closed, allowing the subscription
// owner to start a cold Subscribe immediately through this same facade.
func (e *epochRPC) recover(ctx context.Context) error {
	if e == nil || ctx == nil {
		return syscall.EINVAL
	}
	e.recoverMu.Lock()
	defer e.recoverMu.Unlock()
	old := e.current()
	provider, ok := old.(epochRecoverableRPC)
	if !ok {
		return errors.New("fusev3: authority transport does not support epoch recovery")
	}
	replacement, err := provider.RecoverEpoch(ctx)
	if err != nil {
		return err
	}
	if replacement == nil {
		return errors.New("fusev3: epoch recovery returned no authority transport")
	}
	if !validItem(replacement.Root()) {
		_ = replacement.Close()
		return errors.New("fusev3: replacement epoch omitted a valid root capability")
	}
	oldRead, oldWrite := old.IOLimits()
	newRead, newWrite := replacement.IOLimits()
	if newRead < oldRead || newWrite < oldWrite {
		_ = replacement.Close()
		return errors.New("fusev3: replacement epoch reduced the mounted kernel I/O bounds")
	}
	// The caller has already staled every old handle, dropped the old buffer,
	// drained subscription workers, and invalidated the old cache. Complete the
	// ended client's local-enforcement edge while old is still addressable;
	// forwarding through the facade after publication would finish the new
	// session instead.
	old.FinishLocalSessionEnforcement()
	e.mu.Lock()
	e.rpc = replacement
	e.mu.Unlock()
	_ = old.Close()
	return nil
}

func (e *epochRPC) Root() *authoritypb.Item            { return e.current().Root() }
func (e *epochRPC) IOLimits() (uint32, uint32)         { return e.current().IOLimits() }
func (e *epochRPC) SessionLease() time.Duration        { return e.current().SessionLease() }
func (e *epochRPC) SessionDone() <-chan struct{}       { return e.current().SessionDone() }
func (e *epochRPC) SessionError() error                { return e.current().SessionError() }
func (e *epochRPC) SessionEndPending() <-chan struct{} { return e.current().SessionEndPending() }
func (e *epochRPC) SessionEndCause() error             { return e.current().SessionEndCause() }
func (e *epochRPC) FinishLocalSessionEnforcement()     { e.current().FinishLocalSessionEnforcement() }
func (e *epochRPC) SessionID() []byte                  { return e.current().SessionID() }

func (e *epochRPC) CallRead(ctx context.Context, request *authoritypb.Request) (*authoritypb.Response, error) {
	return e.current().CallRead(ctx, request)
}

func (e *epochRPC) CallReadRetained(ctx context.Context, request *authoritypb.Request, force func(error)) (*authoritypb.Response, authorityrpc.ResponseConsumption, error) {
	return e.current().CallReadRetained(ctx, request, force)
}

func (e *epochRPC) CallIdempotent(ctx context.Context, request *authoritypb.Request) (*authoritypb.Response, error) {
	return e.current().CallIdempotent(ctx, request)
}

func (e *epochRPC) CallIdempotentRetained(ctx context.Context, request *authoritypb.Request, force func(error)) (*authoritypb.Response, authorityrpc.ResponseConsumption, error) {
	return e.current().CallIdempotentRetained(ctx, request, force)
}

func (e *epochRPC) CallMutation(ctx context.Context, request *authoritypb.Request) (*authoritypb.Response, error) {
	return e.current().CallMutation(ctx, request)
}

func (e *epochRPC) CallMutationWithIdentity(ctx context.Context, request *authoritypb.Request, assigned authorityrpc.MutationAssigned) (*authoritypb.Response, error) {
	return e.current().CallMutationWithIdentity(ctx, request, assigned)
}

func (e *epochRPC) CallMutationWithIdentityRetained(ctx context.Context, request *authoritypb.Request, assigned authorityrpc.MutationAssigned, force func(error)) (*authoritypb.Response, authorityrpc.ResponseConsumption, error) {
	return e.current().CallMutationWithIdentityRetained(ctx, request, assigned, force)
}

func (e *epochRPC) Subscribe(ctx context.Context, snapshotID, afterIdentity []byte) (*authoritypb.SubscribeReply, time.Time, error) {
	return e.current().Subscribe(ctx, snapshotID, afterIdentity)
}

func (e *epochRPC) RenewSubscription(ctx context.Context, incarnation uint64) (time.Time, error) {
	return e.current().RenewSubscription(ctx, incarnation)
}

func (e *epochRPC) NextControlEvent(ctx context.Context, incarnation, afterSequence, completedThrough uint64) (*authoritypb.ControlEvent, error) {
	return e.current().NextControlEvent(ctx, incarnation, afterSequence, completedThrough)
}

func (e *epochRPC) AcknowledgeChanges(ctx context.Context, incarnation, position uint64) error {
	return e.current().AcknowledgeChanges(ctx, incarnation, position)
}

func (e *epochRPC) AcknowledgeDelegationRecall(ctx context.Context, incarnation, eventSequence uint64, delegation *authoritypb.DelegationRef, appliedSequence uint64) error {
	return e.current().AcknowledgeDelegationRecall(ctx, incarnation, eventSequence, delegation, appliedSequence)
}

func (e *epochRPC) AcknowledgeDelegationBreak(ctx context.Context, incarnation, eventSequence uint64, delegation *authoritypb.DelegationRef, appliedSequence uint64) error {
	return e.current().AcknowledgeDelegationBreak(ctx, incarnation, eventSequence, delegation, appliedSequence)
}

func (e *epochRPC) AcknowledgeDelegationModeChange(ctx context.Context, incarnation, eventSequence uint64, delegation *authoritypb.DelegationRef, appliedSequence uint64) error {
	return e.current().AcknowledgeDelegationModeChange(ctx, incarnation, eventSequence, delegation, appliedSequence)
}

func (e *epochRPC) ReleaseDelegations(ctx context.Context, incarnation uint64, releases []*authoritypb.DelegationRelease) error {
	return e.current().ReleaseDelegations(ctx, incarnation, releases)
}

func (e *epochRPC) Barrier(ctx context.Context, cutSequence uint64) (*authoritypb.BarrierReply, error) {
	return e.current().Barrier(ctx, cutSequence)
}

func (e *epochRPC) DetachAfterUnmount(ctx context.Context, proof MountAbsenceProof) error {
	return e.current().DetachAfterUnmount(ctx, proof)
}

func (e *epochRPC) Close() error { return e.current().Close() }

var _ RPC = (*epochRPC)(nil)
