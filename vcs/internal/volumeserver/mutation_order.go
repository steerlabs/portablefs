package volumeserver

import (
	"container/list"
	"context"
	"sync"
)

// mutationOrder is the cancellable FIFO ownership queue for cache-visible
// mutations. A plain channel does not promise which source wins when a release,
// a participant-state change, and several senders become runnable together.
// That ambiguity is especially costly for callback-serialized frontends: the
// current source can repeatedly reacquire order while a peer is forced to
// release its FSKit callback lane definite-preapply.
//
// Eligibility is deliberately not part of this type. Every queued Execute keeps
// watching its frontend's exact repair state and may remove its own waiter from
// any position. The queue supplies only the property shared by all profiles:
// surviving waiters are granted in effective arrival order, cancellation cannot
// leak ownership, and a grant cannot be stolen between wakeup and use.
//
// An ordinal may be reserved without adding a list element. That is the
// nonblocking fairness debt used after a macOS 26 repair forced a callback to
// leave: an absent retry never stalls the queue, while one bounded qualifying
// fresh enqueue may use the reserved effective-arrival cut ahead of later
// ordinary traffic. Eligibility, operation-ID exclusion, and claim consumption
// remain higher-layer policy.
type mutationOrder struct {
	mu          sync.Mutex
	held        bool
	nextOrdinal uint64
	waiters     list.List
}

type mutationOrderWaiter struct {
	order   *mutationOrder
	ready   chan struct{}
	element *list.Element
	ordinal uint64
	granted bool
	settled bool
}

func newMutationOrder() *mutationOrder { return &mutationOrder{} }

func (o *mutationOrder) nextOrdinalLocked() uint64 {
	o.nextOrdinal++
	if o.nextOrdinal == 0 {
		panic("volumeserver: mutation-order ordinal exhausted")
	}
	return o.nextOrdinal
}

func (o *mutationOrder) reserveOrdinal() uint64 {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.nextOrdinalLocked()
}

func (o *mutationOrder) enqueue() *mutationOrderWaiter {
	return o.enqueueFor(0)
}

func (o *mutationOrder) enqueueFor(reserved uint64) *mutationOrderWaiter {
	w := &mutationOrderWaiter{order: o, ready: make(chan struct{})}
	o.mu.Lock()
	if reserved == 0 {
		w.ordinal = o.nextOrdinalLocked()
	} else {
		w.ordinal = reserved
	}
	if !o.held && o.waiters.Len() == 0 {
		o.grantLocked(w)
	} else {
		o.insertLocked(w)
	}
	o.mu.Unlock()
	return w
}

func (o *mutationOrder) insertLocked(w *mutationOrderWaiter) {
	if back := o.waiters.Back(); back == nil || back.Value.(*mutationOrderWaiter).ordinal <= w.ordinal {
		w.element = o.waiters.PushBack(w)
		return
	}
	for element := o.waiters.Front(); element != nil; element = element.Next() {
		if element.Value.(*mutationOrderWaiter).ordinal > w.ordinal {
			w.element = o.waiters.InsertBefore(w, element)
			return
		}
	}
	w.element = o.waiters.PushBack(w)
}

func (o *mutationOrder) acquire(ctx context.Context) (*mutationOrderWaiter, error) {
	w := o.enqueue()
	select {
	case <-w.ready:
		return w, nil
	case <-ctx.Done():
		w.abandon()
		return nil, ctx.Err()
	}
}

func (o *mutationOrder) grantLocked(w *mutationOrderWaiter) {
	o.held = true
	w.granted = true
	w.element = nil
	close(w.ready)
}

func (o *mutationOrder) grantNextLocked() {
	if o.held {
		return
	}
	front := o.waiters.Front()
	if front == nil {
		return
	}
	w := front.Value.(*mutationOrderWaiter)
	o.waiters.Remove(front)
	o.grantLocked(w)
}

// abandon removes a waiter that can no longer proceed. It is safe on every
// cancel-vs-grant race: if the grant already won, abandon releases that exact
// ownership before returning.
func (w *mutationOrderWaiter) abandon() {
	o := w.order
	o.mu.Lock()
	if w.settled {
		o.mu.Unlock()
		return
	}
	w.settled = true
	if w.granted {
		o.held = false
	} else if w.element != nil {
		o.waiters.Remove(w.element)
		w.element = nil
	}
	o.grantNextLocked()
	o.mu.Unlock()
}

func (w *mutationOrderWaiter) release() {
	o := w.order
	o.mu.Lock()
	if w.settled || !w.granted || !o.held {
		o.mu.Unlock()
		panic("volumeserver: invalid mutation-order release")
	}
	w.settled = true
	o.held = false
	o.grantNextLocked()
	o.mu.Unlock()
}

// queued is package-private observability for deterministic tests. Production
// decisions never depend on queue length.
func (o *mutationOrder) queued() int {
	o.mu.Lock()
	defer o.mu.Unlock()
	return o.waiters.Len()
}
