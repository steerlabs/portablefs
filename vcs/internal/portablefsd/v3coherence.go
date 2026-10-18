package portablefsd

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log"
	"sync"
	"syscall"

	"github.com/steerlabs/portablefs/vcs/internal/pfslocal"
)

var (
	errV3EventSubscriber = errors.New("portablefsd: event stream already has a frontend subscriber")
	errV3EventTerminal   = errors.New("portablefsd: event stream is terminal")
)

type v3SessionClient interface {
	Epoch() []byte
	SessionID() []byte
	SessionDone() <-chan struct{}
	SessionError() error
	Close() error
}

// v3CoherenceBridge owns source publication and the one terminal event binding.
// Losing its event owner is terminal; a successor cannot prove kernel state.
type v3CoherenceBridge struct {
	client              v3SessionClient
	mu                  sync.Mutex
	sourcePublication   *v3SourcePublicationCoordinator
	frontendOrigin      uint64
	subscribed          bool
	detaching           bool
	detachHadSubscriber bool
	detachStreamEnding  bool
	terminal            error
	terminalDone        chan struct{}
	failOnce            sync.Once
	onFailure           func(error)
}

func newV3CoherenceBridge(client v3SessionClient, onFailure func(error)) (*v3CoherenceBridge, error) {
	if client == nil || len(client.Epoch()) != 16 || len(client.SessionID()) != 16 {
		return nil, errors.New("portablefsd: authority omitted epoch or session identity")
	}
	b := &v3CoherenceBridge{client: client, sourcePublication: newV3SourcePublicationCoordinator(), terminalDone: make(chan struct{}), onFailure: onFailure}
	go b.watchSession()
	return b, nil
}

func (b *v3CoherenceBridge) reserveFrontendPublication(localOperationID v3CallbackID) {
	b.sourcePublication.reserve(localOperationID)
}

func (b *v3CoherenceBridge) releaseFrontendPublication(localOperationID v3CallbackID) {
	b.sourcePublication.retire(localOperationID)
}

func (b *v3CoherenceBridge) finishFrontendPublication(localOperationID v3CallbackID) error {
	consumptions, err := b.sourcePublication.finishFrontendPublication(localOperationID)
	if err != nil {
		err = b.fail(err)
		// fail marks the source coordinator terminal. That terminal state is the
		// proof that local serving was revoked, so the second finish is allowed
		// to transfer any response which the malformed lifecycle stranded.
		consumptions, _ = b.sourcePublication.finishFrontendPublication(localOperationID)
	}
	for _, consumption := range consumptions {
		if consumption != nil {
			consumption.Consume()
		}
	}
	return err
}

func (b *v3CoherenceBridge) acknowledgePublication(
	localOperationID v3CallbackID,
	semanticCommit pfslocal.PublicationSemanticCommit,
) (bool, error) {
	known, err := b.sourcePublication.acknowledge(localOperationID, semanticCommit)
	if err != nil {
		if errors.Is(err, errV3SourcePublicationNotPublished) {
			return known, b.stopServing(err)
		}
		return known, b.fail(err)
	}
	return known, nil
}

func (b *v3CoherenceBridge) readyForOperations() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.terminal != nil {
		return errors.Join(errV3EventTerminal, b.terminal)
	}
	if !b.subscribed {
		return syscall.EAGAIN
	}
	return nil
}

func (b *v3CoherenceBridge) beginDetach() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.detaching {
		return syscall.EBUSY
	}
	b.detaching = true
	b.detachHadSubscriber = b.subscribed
	b.detachStreamEnding = false
	return nil
}

func (b *v3CoherenceBridge) acceptPlannedDetachCancellation(cause error) bool {
	if cause == nil {
		return false
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	if !b.detaching || b.terminal != nil {
		return false
	}
	b.detachStreamEnding = true
	return true
}

func (b *v3CoherenceBridge) abortDetach(cause error) {
	b.mu.Lock()
	streamLost := b.detachStreamEnding || b.detachHadSubscriber && !b.subscribed
	b.detaching = false
	b.detachHadSubscriber = false
	b.detachStreamEnding = false
	b.mu.Unlock()
	select {
	case <-b.client.SessionDone():
		streamLost = true
	default:
	}
	if streamLost {
		_ = b.fail(fmt.Errorf("planned kernel detach aborted after the FSKit frontend disconnected: %w", cause))
	}
}

func (b *v3CoherenceBridge) bind() error {
	b.mu.Lock()
	defer b.mu.Unlock()
	if b.terminal != nil {
		return errors.Join(errV3EventTerminal, b.terminal)
	}
	if b.detaching {
		return syscall.EBUSY
	}
	if b.subscribed {
		return errV3EventSubscriber
	}
	b.subscribed = true
	return nil
}

func (b *v3CoherenceBridge) unbind() {
	b.mu.Lock()
	b.subscribed = false
	b.frontendOrigin = 0
	b.mu.Unlock()
}

func (b *v3CoherenceBridge) watchSession() {
	<-b.client.SessionDone()
	b.mu.Lock()
	detaching := b.detaching
	b.mu.Unlock()
	if detaching {
		return
	}
	_ = b.fail(sessionFailure(b.client))
}

func (b *v3CoherenceBridge) abandonBeforeMount() {
	b.mu.Lock()
	b.detaching = true
	b.mu.Unlock()
}

func (b *v3CoherenceBridge) fail(cause error) error {
	cause = b.stopServing(cause)
	// A transport/protocol failure cannot deliver trustworthy later evidence.
	// This close also retires a locally terminal bridge after exact unmount.
	_ = b.client.Close()
	return cause
}

func (b *v3CoherenceBridge) stopServing(cause error) error {
	if cause == nil {
		cause = errV3EventTerminal
	}
	b.failOnce.Do(func() {
		// The cause is logged here, at the one point that always holds it.
		// Callers propagate the terminal sentinel, and a log line built from
		// what a caller happens to see reports the wrapper instead of the
		// reason the stream died — which is the only thing an operator needs.
		log.Printf("portablefsd: v3 coherence stream failed terminally: %v", cause)
		if b.onFailure != nil {
			b.onFailure(cause)
		}
		b.sourcePublication.fail(cause)
		b.mu.Lock()
		b.terminal = cause
		close(b.terminalDone)
		b.mu.Unlock()
	})
	return cause
}

func sessionFailure(client v3SessionClient) error {
	if err := client.SessionError(); err != nil {
		return err
	}
	return io.ErrClosedPipe
}

// run keeps terminal delivery on the original bound connection, independent of DATA.
func (b *v3CoherenceBridge) run(ctx context.Context, deliver func(*pfslocal.Event) error) error {
	if deliver == nil {
		return syscall.EINVAL
	}
	if err := b.bind(); err != nil {
		return err
	}
	return b.runBound(ctx, deliver)
}
func (b *v3CoherenceBridge) runBound(ctx context.Context, deliver func(*pfslocal.Event) error) error {
	defer b.unbind()
	select {
	case <-ctx.Done():
		if b.acceptPlannedDetachCancellation(ctx.Err()) {
			return ctx.Err()
		}
		return b.stopServing(ctx.Err())
	case <-b.client.SessionDone():
		b.mu.Lock()
		detaching := b.detaching
		b.mu.Unlock()
		if detaching {
			return nil
		}
		_ = b.fail(sessionFailure(b.client))
	case <-b.terminalDone:
	}
	if err := deliver(&pfslocal.Event{Kind: &pfslocal.AttachState{State: pfslocal.AttachStateDegraded}}); err != nil {
		return err
	}
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.terminal
}

// frontendClosing records event-owner loss synchronously with connection
// teardown. An aborted kernel detach can never resume a stream already lost.
func (b *v3CoherenceBridge) frontendClosing(origin uint64) {
	b.mu.Lock()
	if origin == 0 || b.frontendOrigin != origin || b.terminal != nil {
		b.mu.Unlock()
		return
	}
	if b.detaching {
		b.detachStreamEnding = true
		b.mu.Unlock()
		return
	}
	b.mu.Unlock()
	_ = b.stopServing(errors.New("FSKit event owner disconnected"))
}
