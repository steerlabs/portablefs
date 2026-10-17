package portablefsd

import (
	"errors"
	"sync"
)

// v3ReclaimTokenWireBytes is one item capability inside ReclaimRequest.items:
// a one-byte tag, a one-byte length, and the 16-byte token.
const v3ReclaimTokenWireBytes = 18

// v3Reclaimer retires authority item capabilities through exact batched
// Reclaim mutations. Every capability retirement on one data plane goes
// through it: FSKit reclaim, a duplicate capability returned for an item the
// daemon already holds, and abandoned provisional items.
//
// At most one batch is in flight. Tokens submitted while it runs form the next
// batch, so a burst costs one round trip per batch and an idle reclaimer sends
// at once; there is no timer. There is also no unawaited queue: every
// submitter waits for the batch that carries its tokens, which is the
// backpressure that bounds the forming batch.
//
// A token reaches the reclaimer exactly once, after its last local owner let
// go, so no batch repeats a token. Any batch failure is terminal: the
// authority rejects a whole batch for one stale or duplicate token and can
// partially apply a batch on a storage error, so no failed batch can be
// recovered item by item.
type v3Reclaimer struct {
	send     func([][]byte) error
	maxBatch int

	mu      sync.Mutex
	changed *sync.Cond
	forming *v3ReclaimBatch
	running bool
	// drained means a clean detach is about to end the session, which releases
	// every capability the authority still holds for it. Later tokens are
	// therefore already retired by that detach and are never sent.
	drained bool
	// failure is sticky: no batch is sent after one failed.
	failure error
}

type v3ReclaimBatch struct {
	tokens [][]byte
	done   chan struct{}
	err    error
}

func newV3Reclaimer(maxBatch int, send func([][]byte) error) *v3Reclaimer {
	if maxBatch < 1 {
		maxBatch = 1
	}
	r := &v3Reclaimer{send: send, maxBatch: maxBatch}
	r.changed = sync.NewCond(&r.mu)
	return r
}

// retire submits tokens and returns once every batch carrying them settled.
func (r *v3Reclaimer) retire(tokens ...[]byte) error {
	var batches []*v3ReclaimBatch
	r.mu.Lock()
	for _, token := range tokens {
		for r.failure == nil && !r.drained && r.forming != nil && len(r.forming.tokens) >= r.maxBatch {
			r.changed.Wait()
		}
		if r.failure != nil || r.drained {
			break
		}
		if r.forming == nil {
			r.forming = &v3ReclaimBatch{done: make(chan struct{})}
		}
		r.forming.tokens = append(r.forming.tokens, token)
		if len(batches) == 0 || batches[len(batches)-1] != r.forming {
			batches = append(batches, r.forming)
		}
		if !r.running {
			r.running = true
			go r.run()
		}
	}
	err := r.failure
	r.mu.Unlock()
	for _, batch := range batches {
		<-batch.done
		err = errors.Join(err, batch.err)
	}
	return err
}

func (r *v3Reclaimer) run() {
	r.mu.Lock()
	for r.forming != nil {
		batch := r.forming
		r.forming = nil
		failure := r.failure
		r.changed.Broadcast()
		r.mu.Unlock()
		batch.err = failure
		if failure == nil {
			batch.err = r.send(batch.tokens)
		}
		close(batch.done)
		r.mu.Lock()
		if batch.err != nil && r.failure == nil {
			r.failure = batch.err
		}
	}
	r.running = false
	r.changed.Broadcast()
	r.mu.Unlock()
}

// drain settles every submitted batch before a clean detach ends the session.
// Tokens submitted afterwards are released by that detach and return at once.
func (r *v3Reclaimer) drain() {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.drained = true
	r.changed.Broadcast()
	for r.running {
		r.changed.Wait()
	}
}
