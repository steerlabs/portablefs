package volumeserver

import (
	"context"
	"errors"
	"sync"
	"time"
)

var (
	ErrDelegationStale = errors.New("volumeserver: stale delegation generation")
	ErrDelegationBusy  = errors.New("volumeserver: delegation has an active operation")
	ErrDelegationAck   = errors.New("volumeserver: invalid delegation acknowledgment")
)

type DelegationMode uint8

const (
	DelegationFull DelegationMode = iota + 1
	DelegationWritethrough
)

type DelegationState uint8

const (
	DelegationReserved DelegationState = iota + 1
	DelegationActive
	DelegationRecalling
)

type Delegation struct {
	ID         uint64
	Identity   [16]byte
	Holder     SessionID
	Generation uint64
	Mode       DelegationMode
	State      DelegationState
}

type delegationRecord struct {
	grant          Delegation
	owner          *changeSubscriber
	position       uint64
	pending        *delegationCut
	active         uint64
	applied        uint64
	retired        bool
	readers        uint64
	closingReaders bool
	ephemeral      bool
}
type delegationCut struct {
	request  uint64
	recall   bool
	mode     DelegationMode
	deadline time.Time
	done     bool
	applied  uint64
	floor    uint64
}
type cacheHandleCounts struct {
	total    uint64
	sessions map[SessionID]uint64
}

// OpenCacheCapable atomically accounts an open and decides its kernel mode.
// false means the caller MUST use direct-IO, even for the holder itself. Call
// before publishing the open reply; roll back with CloseCacheCapable on failure.
func (c *CoherenceCoordinator) OpenCacheCapable(token SubscriptionToken, identity [16]byte) (bool, error) {
	if identity == ([16]byte{}) {
		return false, ErrCoherenceIdentity
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	s, err := c.subscriberLocked(token)
	if err != nil {
		return false, err
	}
	if c.delegations[identity] != nil {
		return false, nil
	}
	counts := c.cacheHandles[identity]
	if counts == nil {
		counts = &cacheHandleCounts{sessions: make(map[SessionID]uint64)}
		c.cacheHandles[identity] = counts
	}
	counts.total++
	counts.sessions[token.Session]++
	s.handles[identity]++
	return true, nil
}
func (c *CoherenceCoordinator) CloseCacheCapable(token SubscriptionToken, identity [16]byte) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	s, err := c.subscriberLocked(token)
	if err != nil {
		return err
	}
	if s.handles[identity] == 0 {
		return ErrCoherenceIdentity
	}
	c.closeHandlesLocked(s, identity, 1)
	return nil
}
func (c *CoherenceCoordinator) closeHandlesLocked(s *changeSubscriber, identity [16]byte, n uint64) {
	counts := c.cacheHandles[identity]
	counts.total -= n
	counts.sessions[s.token.Session] -= n
	s.handles[identity] -= n
	if counts.sessions[s.token.Session] == 0 {
		delete(counts.sessions, s.token.Session)
	}
	if s.handles[identity] == 0 {
		delete(s.handles, identity)
	}
	if counts.total == 0 {
		delete(c.cacheHandles, identity)
	}
	if r := c.delegations[identity]; r != nil && !r.retired {
		c.issueModeChangeLocked(r)
	}
}

// issueModeChangeLocked starts an acknowledged transition only when no other
// cut owns the identity. The live grant retains its old mode until the holder
// proves it installed the target; recalls and breaks serialize through pending.
func (c *CoherenceCoordinator) issueModeChangeLocked(r *delegationRecord) {
	if r == nil || r.retired || r.ephemeral || r.grant.State != DelegationActive || r.pending != nil {
		return
	}
	target := c.modeLocked(r.grant.Identity, r.grant.Holder)
	if target == r.grant.Mode {
		return
	}
	c.nextRequest++
	if c.nextRequest == 0 {
		panic("volumeserver: delegation request exhausted")
	}
	p := &delegationCut{
		request: c.nextRequest, mode: target,
		deadline: c.clock.Now().Add(DelegationRecallBudget), floor: r.applied,
	}
	r.pending = p
	eventGrant := r.grant
	eventGrant.Mode = target
	c.appendLocked(StreamEvent{
		Kind: StreamDelegationMode, Target: r.grant.Holder, Delegation: eventGrant,
		Request: p.request, Deadline: p.deadline, AppliedSequence: p.floor,
	})
}

// expireDelegationCutsLocked covers asynchronous mode changes, which have no
// waiting request goroutine to observe their deadline. Recall and break waiters
// perform the same transition in cut; repeating it here is idempotent.
func (c *CoherenceCoordinator) expireDelegationCutsLocked() {
	now := c.clock.Now()
	for _, r := range c.delegations {
		if r.pending != nil && !now.Before(r.pending.deadline) {
			c.dropDelegationLocked(r, true)
		}
	}
}
func (c *CoherenceCoordinator) modeLocked(identity [16]byte, holder SessionID) DelegationMode {
	if counts := c.cacheHandles[identity]; counts != nil && counts.total > counts.sessions[holder] {
		return DelegationWritethrough
	}
	return DelegationFull
}

// DelegationReservation closes caching before CREATE exposes a new identity.
// Grant or Abort is mandatory. A reservation is single-owner, not concurrent.
// Its request turn is NOT a storage commit lock: flushes never acquire it.
type DelegationReservation struct {
	coordinator *CoherenceCoordinator
	record      *delegationRecord
	turn        *mutationSequencerWaiter
	existing    bool
	finished    bool
}

func delegationDependencies(identity [16]byte) MutationDependencies {
	return newMutationDependencies(inodeKey(identity))
}

// ReserveNew is nonblocking and may run inside CREATE's storage turn, after
// obtaining the new identity but before releasing the binding's publication
// exclusion. It is only for an identity that cannot already be named by peers.
// Existing-name CREATE and OPEN use Reserve, outside all storage locks.
func (c *CoherenceCoordinator) ReserveNew(token SubscriptionToken, identity [16]byte) (*DelegationReservation, error) {
	if identity == ([16]byte{}) {
		return nil, ErrCoherenceIdentity
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	s, err := c.subscriberLocked(token)
	if err != nil {
		return nil, err
	}
	if c.delegations[identity] != nil {
		return nil, ErrDelegationBusy
	}
	return c.reserveLocked(s, identity, nil), nil
}
func (c *CoherenceCoordinator) reserveLocked(s *changeSubscriber, identity [16]byte, turn *mutationSequencerWaiter) *DelegationReservation {
	c.nextDelegation++
	if c.nextDelegation == 0 {
		panic("volumeserver: delegation generation exhausted")
	}
	// A volume-global generation avoids retaining one counter per deleted file.
	r := &delegationRecord{owner: s, grant: Delegation{ID: c.nextDelegation, Identity: identity, Holder: s.token.Session, Generation: c.nextDelegation, Mode: c.modeLocked(identity, s.token.Session), State: DelegationReserved}}
	c.delegations[identity] = r
	s.held[identity] = r
	r.position = c.appendLocked(StreamEvent{Kind: StreamChange, Change: ChangeEntry{Kind: DelegationGranted, Identity: identity, VolumeVersion: c.watermark}})
	return &DelegationReservation{coordinator: c, record: r, turn: turn}
}

// Reserve queues FIFO on this identity alone, recalling an old holder first.
// Never call with storage dependencies held. CONTROL and BeginFlush bypass
// this queue, so A requesting B's identity and B requesting A's identity do
// not form a cycle. Disjoint identities own independent sequencer keys.
func (c *CoherenceCoordinator) Reserve(ctx context.Context, token SubscriptionToken, identity [16]byte) (*DelegationReservation, error) {
	if identity == ([16]byte{}) {
		return nil, ErrCoherenceIdentity
	}
	turn, err := c.requests.acquire(ctx, delegationDependencies(identity))
	if err != nil {
		return nil, err
	}
	success := false
	defer func() {
		if !success {
			turn.release()
		}
	}()
	for {
		c.mu.Lock()
		s, err := c.subscriberLocked(token)
		if err != nil {
			c.mu.Unlock()
			return nil, err
		}
		r := c.delegations[identity]
		if r == nil {
			reservation := c.reserveLocked(s, identity, turn)
			c.mu.Unlock()
			success = true
			return reservation, nil
		}
		if !r.retired && r.owner == s && r.grant.State == DelegationActive && r.pending == nil {
			c.mu.Unlock()
			success = true
			return &DelegationReservation{coordinator: c, record: r, turn: turn, existing: true}, nil
		}
		if r.retired || r.grant.State == DelegationReserved {
			changed := c.notificationLocked()
			deadline := s.horizon
			if !r.retired {
				deadline = minTime(deadline, r.owner.horizon)
			}
			c.mu.Unlock()
			if err := c.wait(ctx, changed, deadline); err != nil {
				return nil, err
			}
			continue
		}
		c.mu.Unlock()
		if _, err := c.cut(ctx, r, true); err != nil {
			return nil, err
		}
	}
}
func (r *DelegationReservation) Grant(ctx context.Context) (Delegation, error) {
	grant, _, err := r.grant(ctx, false, false)
	return grant, err
}

// grant can install the storage pin before releasing the identity's request
// turn. That ordering is needed by server-owned synchronous mutations: a peer
// must observe either the reservation or the active pin, never an unpinned
// grant that it could recall between Grant and BeginFlush.
func (r *DelegationReservation) grant(ctx context.Context, pin, ephemeral bool) (Delegation, *DelegationFlush, error) {
	if r == nil || r.finished {
		return Delegation{}, nil, ErrDelegationStale
	}
	c := r.coordinator
	if ephemeral && r.existing {
		return Delegation{}, nil, ErrDelegationBusy
	}
	if ephemeral {
		c.mu.Lock()
		if r.record.retired || c.delegations[r.record.grant.Identity] != r.record || r.record.grant.State != DelegationReserved {
			c.mu.Unlock()
			r.Abort()
			return Delegation{}, nil, ErrDelegationStale
		}
		r.record.ephemeral = true
		c.mu.Unlock()
	}
	if !r.existing {
		if err := c.WaitWithdrawn(ctx, r.record.position, r.record.grant.Holder); err != nil {
			r.Abort()
			return Delegation{}, nil, err
		}
	}
	var grant Delegation
	var flush *DelegationFlush
	for {
		c.mu.Lock()
		_, err := c.subscriberLocked(r.record.owner.token)
		if err == nil && (r.record.retired || c.delegations[r.record.grant.Identity] != r.record) {
			err = ErrDelegationStale
		}
		if err != nil {
			c.mu.Unlock()
			r.Abort()
			return Delegation{}, nil, err
		}
		// Once withdrawals are complete no new read may join this generation's
		// drain. Already pinned replies can finish without any request-turn lock.
		if !r.record.closingReaders {
			r.record.closingReaders = true
			c.signalLocked()
		}
		if r.record.readers == 0 {
			r.record.grant.State = DelegationActive
			r.record.grant.Mode = c.modeLocked(r.record.grant.Identity, r.record.grant.Holder)
			grant = r.record.grant
			if pin {
				r.record.active++
				flush = &DelegationFlush{coordinator: c, record: r.record}
			}
			c.signalLocked()
			c.mu.Unlock()
			break
		}
		changed := c.notificationLocked()
		deadline := r.record.owner.horizon
		c.mu.Unlock()
		if err := c.wait(ctx, changed, deadline); err != nil {
			r.Abort()
			return Delegation{}, nil, err
		}
	}

	r.finish()
	return grant, flush, nil
}
func (r *DelegationReservation) finish() {
	r.finished = true
	if r.turn != nil {
		r.turn.release()
	}
}
func (r *DelegationReservation) Abort() {
	if r == nil || r.finished {
		return
	}
	c := r.coordinator
	c.mu.Lock()
	if !r.existing && !r.record.retired {
		c.dropDelegationLocked(r.record, false)
	}
	c.mu.Unlock()
	r.finish()
}

// DataMutated is the first-WRITE/SETATTR/FALLOCATE guard for an unowned identity.
// The resulting id+generation must still be pinned with BeginFlush at apply.
func (c *CoherenceCoordinator) DataMutated(ctx context.Context, token SubscriptionToken, identity [16]byte) (Delegation, error) {
	r, err := c.Reserve(ctx, token, identity)
	if err != nil {
		return Delegation{}, err
	}
	return r.Grant(ctx)
}

// BeginSynchronousMutation admits an authority-applied mutation which has no
// client delegation reference. A newly created delegation is private to this
// operation and is released by End; an existing grant owned by the same
// session is merely pinned and remains live. Peers wait for a private mutation
// to finish instead of receiving a recall for a generation the client never
// learned.
func (c *CoherenceCoordinator) BeginSynchronousMutation(ctx context.Context, token SubscriptionToken, identity [16]byte) (*DelegationFlush, error) {
	r, err := c.Reserve(ctx, token, identity)
	if err != nil {
		return nil, err
	}
	_, flush, err := r.grant(ctx, true, !r.existing)
	return flush, err
}

// DataGuard excludes delegation reassignment through a peer's storage read.
// Release immediately after sampling storage and its version, before waiting
// on cache publication. It never owns the coordinator mutex.
type DataGuard struct {
	turn            *mutationSequencerWaiter
	once            sync.Once
	coordinator     *CoherenceCoordinator
	record          *delegationRecord
	AppliedSequence uint64
}

func (g *DataGuard) Release() {
	if g == nil {
		return
	}
	g.once.Do(func() {
		if g.record != nil {
			c := g.coordinator
			c.mu.Lock()
			g.record.readers--
			c.finishRetiredLocked(g.record)
			c.signalLocked()
			c.mu.Unlock()
		}
		if g.turn != nil {
			g.turn.release()
		}
	})
}

// DataConsumed covers READ, GETATTR, attribute-bearing LOOKUP/READDIR, FSYNC,
// and COPY_FILE_RANGE source. Call separately for listing children; never hold
// one guard while acquiring another (multi-identity storage ordering is the
// handler's atomic MutationDependencies footprint). A holder's backing reads
// bypass its own break and request queue: flushing can require these reads.
func (c *CoherenceCoordinator) DataConsumed(ctx context.Context, token SubscriptionToken, identity [16]byte) (*DataGuard, error) {
	if err := c.CheckSession(token); err != nil {
		return nil, err
	}
	c.mu.Lock()
	r := c.delegations[identity]
	own := r != nil && !r.retired && r.owner.token == token
	c.mu.Unlock()
	if own {
		return &DataGuard{}, nil
	}
	guard, err := c.consume(ctx, identity)
	if err != nil {
		return nil, err
	}
	if err := c.CheckSession(token); err != nil {
		guard.Release()
		return nil, err
	}
	return guard, nil
}

// BreakForRead is the trusted non-subscribing gateway form. The handler must
// still authorize the request. Use DataConsumed to retain a read admission.
func (c *CoherenceCoordinator) BreakForRead(ctx context.Context, identity [16]byte) error {
	guard, err := c.consume(ctx, identity)
	if err != nil {
		return err
	}
	guard.Release()
	return nil
}
func (c *CoherenceCoordinator) consume(ctx context.Context, identity [16]byte) (*DataGuard, error) {
	if identity == ([16]byte{}) {
		return nil, ErrCoherenceIdentity
	}
	var turn *mutationSequencerWaiter
	owned := false
	defer func() {
		if turn != nil && !owned {
			turn.abandon()
		}
	}()
	for {
		c.mu.Lock()
		c.expireLocked()
		r := c.delegations[identity]
		// A pending cache-installing read may hold the folio needed by withdrawal.
		// Let it sample storage while reserved, then pin it until the reply sample
		// finishes. The client publication drain, not this request queue, decides
		// whether that sample can be installed. Observe reservation and enqueue under
		// the same mutex; otherwise installation between precheck and enqueue closes
		// Grant -> cumulative ack -> pending read -> Grant.
		if r != nil && !r.retired && r.grant.State == DelegationReserved && !r.closingReaders {
			r.readers++
			c.mu.Unlock()
			return &DataGuard{coordinator: c, record: r}, nil
		}
		if turn == nil {
			turn = c.requests.enqueue(delegationDependencies(identity))
		}
		ready := false
		select {
		case <-turn.ready:
			ready = true
		default:
		}
		if ready && r == nil {
			c.mu.Unlock()
			owned = true
			return &DataGuard{turn: turn}, nil
		}
		if ready && !r.retired && r.grant.State != DelegationReserved {
			c.mu.Unlock()
			seq, err := c.cut(ctx, r, false)
			if err != nil {
				return nil, err
			}
			c.mu.Lock()
			busy := r.retired && (r.active != 0 || r.readers != 0)
			c.mu.Unlock()
			if busy {
				continue
			}
			owned = true
			return &DataGuard{turn: turn, AppliedSequence: seq}, nil
		}
		changed := c.notificationLocked()
		deadline := c.clock.Now().Add(SubscriptionTTL)
		if r != nil {
			if r.retired {
				deadline = time.Time{}
			} else {
				deadline = r.owner.horizon
			}
		}
		c.mu.Unlock()
		if ready {
			if err := c.wait(ctx, changed, deadline); err != nil {
				return nil, err
			}
		} else if deadline.IsZero() {
			select {
			case <-turn.ready:
			case <-changed:
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		} else {
			timer := c.clock.NewTimer(max(time.Duration(0), deadline.Sub(c.clock.Now())))
			select {
			case <-turn.ready:
			case <-changed:
			case <-timer.C():
			case <-ctx.Done():
				timer.Stop()
				return nil, ctx.Err()
			}
			timer.Stop()
		}
	}
}

// Recall is a trusted control-plane withdrawal. It shares only this identity's
// FIFO request lane; it never blocks delivery/ack or holder flush application.
func (c *CoherenceCoordinator) Recall(ctx context.Context, identity [16]byte) error {
	if identity == ([16]byte{}) {
		return ErrCoherenceIdentity
	}
	turn, err := c.requests.acquire(ctx, delegationDependencies(identity))
	if err != nil {
		return err
	}
	defer turn.release()
	for {
		c.mu.Lock()
		c.expireLocked()
		r := c.delegations[identity]
		if r == nil {
			c.mu.Unlock()
			return nil
		}
		if r.retired || r.grant.State == DelegationReserved {
			changed := c.notificationLocked()
			deadline := r.owner.horizon
			if r.retired {
				deadline = time.Time{}
			}
			c.mu.Unlock()
			if err := c.wait(ctx, changed, deadline); err != nil {
				return err
			}
			continue
		}
		c.mu.Unlock()
		_, err := c.cut(ctx, r, true)
		if err != nil {
			return err
		}
	}
}
func (c *CoherenceCoordinator) cut(ctx context.Context, r *delegationRecord, recall bool) (uint64, error) {
	if err := ctx.Err(); err != nil {
		return 0, err
	}
	c.mu.Lock()
	c.expireLocked()
	if r.retired {
		seq := r.applied
		c.mu.Unlock()
		return seq, ctx.Err()
	}
	if r.ephemeral {
		c.mu.Unlock()
		for {
			c.mu.Lock()
			c.expireLocked()
			if r.retired {
				seq := r.applied
				c.mu.Unlock()
				return seq, ctx.Err()
			}
			if !r.ephemeral {
				c.mu.Unlock()
				return c.cut(ctx, r, recall)
			}
			changed := c.notificationLocked()
			deadline := r.owner.horizon
			c.mu.Unlock()
			if err := c.wait(ctx, changed, deadline); err != nil {
				return 0, err
			}
		}
	}
	p := r.pending
	if p == nil {
		c.nextRequest++
		if c.nextRequest == 0 {
			panic("volumeserver: delegation request exhausted")
		}
		p = &delegationCut{request: c.nextRequest, recall: recall, deadline: c.clock.Now().Add(DelegationRecallBudget), floor: r.applied}
		r.pending = p
		kind := StreamBreakForRead
		if recall {
			kind = StreamRecall
			r.grant.State = DelegationRecalling
		}
		c.appendLocked(StreamEvent{Kind: kind, Target: r.grant.Holder, Delegation: r.grant, Request: p.request, Deadline: p.deadline, AppliedSequence: p.floor})
	}
	c.mu.Unlock()
	for {
		c.mu.Lock()
		c.expireLocked()
		if p.done || r.retired {
			seq := max(p.applied, r.applied)
			c.mu.Unlock()
			return seq, ctx.Err()
		}
		if !c.clock.Now().Before(p.deadline) {
			c.dropDelegationLocked(r, true)
			seq := r.applied
			c.mu.Unlock()
			return seq, ctx.Err()
		}
		changed := c.notificationLocked()
		deadline := minTime(p.deadline, r.owner.horizon)
		c.mu.Unlock()
		// A sent cut is a terminal obligation, even if its triggering read or
		// mutation is canceled. Give the healthy holder its entire drain budget;
		// cancellation alone must not discard acknowledged buffered writes.
		_ = c.wait(context.WithoutCancel(ctx), changed, deadline)
	}
}

// AckDelegation is independent of Ack: it proves a holder drained and applied
// its accepted cut, not that preceding stream withdrawals finished. Handler
// CONTROL must service it even while the cumulative ack is parked. The client
// must not wait for flush *visibility* before this ack, only storage apply.
// A break acknowledges a cut, not an idle writer: later flushes may already be
// applying/applied. Its sequence must lie between the event's applied floor and
// the known applied high-water. Recall additionally requires every pin drained.
func (c *CoherenceCoordinator) AckDelegation(token SubscriptionToken, identity [16]byte, id, generation, request, applied uint64) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	s, err := c.subscriberLocked(token)
	if err != nil {
		return err
	}
	r := c.delegations[identity]
	if r == nil || r.retired || r.owner != s || r.grant.ID != id || r.grant.Generation != generation {
		return ErrDelegationStale
	}
	p := r.pending
	if p == nil || p.request != request {
		return ErrDelegationAck
	}
	if !c.clock.Now().Before(p.deadline) {
		c.dropDelegationLocked(r, true)
		return ErrDelegationStale
	}
	if p.recall && r.active != 0 {
		return ErrDelegationBusy
	}
	if applied < p.floor || applied > r.applied {
		return ErrDelegationAck
	}
	p.applied = applied
	p.done = true
	if p.recall {
		c.dropDelegationLocked(r, false)
	} else {
		r.pending = nil
		if p.mode != 0 {
			r.grant.Mode = p.mode
		}
		c.issueModeChangeLocked(r)
	}
	c.signalLocked()
	return nil
}

// DelegationFlush pins exact authority across storage I/O. A recall/expiry can
// reject later flushes immediately, but cannot grant a peer until this pin ends.
// This is why the 5 s peer budget does not promise to interrupt stuck local I/O.
type DelegationFlush struct {
	coordinator *CoherenceCoordinator
	record      *delegationRecord
	mu          sync.Mutex
	ended       bool
	once        sync.Once
}

// RetainDelegation promotes a private synchronous-mutation generation into a
// client-visible grant. It must run after successful storage application and
// before End, so a failed operation never leaks a grant absent from its reply.
// Calling it for an already-visible same-holder generation is an idempotent
// query for that exact grant.
func (f *DelegationFlush) RetainDelegation() (Delegation, error) {
	if f == nil {
		return Delegation{}, ErrDelegationStale
	}
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.ended {
		return Delegation{}, ErrDelegationStale
	}
	c := f.coordinator
	c.mu.Lock()
	defer c.mu.Unlock()
	r := f.record
	if r.retired || c.delegations[r.grant.Identity] != r || r.grant.State == DelegationReserved {
		return Delegation{}, ErrDelegationStale
	}
	r.grant.Mode = c.modeLocked(r.grant.Identity, r.grant.Holder)
	r.ephemeral = false
	c.signalLocked()
	return r.grant, nil
}

func (c *CoherenceCoordinator) BeginFlush(token SubscriptionToken, identity [16]byte, id, generation uint64) (*DelegationFlush, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	s, err := c.subscriberLocked(token)
	if err != nil {
		return nil, err
	}
	r := c.delegations[identity]
	if r == nil || r.retired || r.owner != s || r.grant.ID != id || r.grant.Generation != generation || r.grant.State == DelegationReserved {
		c.lossLocked(s, Delegation{ID: id, Identity: identity, Holder: token.Session, Generation: generation})
		return nil, ErrDelegationStale
	}
	if r.pending != nil && !c.clock.Now().Before(r.pending.deadline) {
		c.dropDelegationLocked(r, true)
		return nil, ErrDelegationStale
	}
	r.active++
	return &DelegationFlush{coordinator: c, record: r}, nil
}

// End records an applied storage sequence, or zero on definite no-apply error.
// Call after OnCommit and after releasing storage locks, before waiting for
// visibility. Flushed bytes may not be reported applied until this call.
func (f *DelegationFlush) End(applied uint64) {
	if f == nil {
		return
	}
	f.once.Do(func() {
		f.mu.Lock()
		defer f.mu.Unlock()
		f.ended = true
		c := f.coordinator
		c.mu.Lock()
		defer c.mu.Unlock()
		r := f.record
		r.applied = max(r.applied, applied)
		r.active--
		if r.ephemeral && r.active == 0 {
			c.dropDelegationLocked(r, false)
		}
		c.finishRetiredLocked(r)
		c.signalLocked()
	})
}
func (c *CoherenceCoordinator) lossLocked(s *changeSubscriber, grant Delegation) {
	s.loss++
	if s.loss == 0 {
		panic("volumeserver: loss sequence exhausted")
	}
	c.appendLocked(StreamEvent{Kind: StreamLoss, Target: s.token.Session, Delegation: grant, LossSequence: s.loss})
}
func (c *CoherenceCoordinator) dropDelegationLocked(r *delegationRecord, lost bool) {
	if r.retired {
		return
	}
	r.retired = true
	delete(r.owner.held, r.grant.Identity)
	if lost && r.grant.State != DelegationReserved {
		c.lossLocked(r.owner, r.grant)
	}
	c.finishRetiredLocked(r)
	c.signalLocked()
}
func (c *CoherenceCoordinator) finishRetiredLocked(r *delegationRecord) {
	if !r.retired || r.active != 0 || r.readers != 0 || c.delegations[r.grant.Identity] != r {
		return
	}
	// Release follows the final pinned flush's OnCommit, so clients cannot start
	// caching while an admitted old-generation write is still applying.
	delete(c.delegations, r.grant.Identity)
	c.appendLocked(StreamEvent{Kind: StreamChange, Change: ChangeEntry{Kind: DelegationReleased, Identity: r.grant.Identity, VolumeVersion: c.watermark}})
}

// ReleaseBatch validates the entire batch before changing any record. The
// caller attests last-handle close and completed flush; active pins or cuts
// refuse release. Duplicate identities and stale generations reject the batch.
func (c *CoherenceCoordinator) ReleaseBatch(token SubscriptionToken, grants []Delegation) (uint64, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	s, err := c.subscriberLocked(token)
	if err != nil {
		return 0, err
	}
	seen := make(map[[16]byte]struct{}, len(grants))
	for _, g := range grants {
		r := c.delegations[g.Identity]
		if _, ok := seen[g.Identity]; ok {
			return 0, ErrDelegationStale
		}
		seen[g.Identity] = struct{}{}
		if r == nil || r.retired || r.owner != s || r.grant.ID != g.ID || r.grant.Generation != g.Generation {
			return 0, ErrDelegationStale
		}
		if r.active != 0 || r.pending != nil || r.grant.State != DelegationActive {
			return 0, ErrDelegationBusy
		}
	}
	for _, g := range grants {
		c.dropDelegationLocked(c.delegations[g.Identity], false)
	}
	return c.position, nil
}
func (c *CoherenceCoordinator) LookupDelegation(identity [16]byte) (Delegation, bool) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.expireLocked()
	r := c.delegations[identity]
	if r == nil || r.retired {
		return Delegation{}, false
	}
	return r.grant, true
}
