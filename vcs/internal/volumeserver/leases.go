package volumeserver

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"sort"
	"sync"
	"time"
)

var (
	ErrLeaseCoordinate = errors.New("volumeserver: invalid lease coordinate")
	ErrLeaseRight      = errors.New("volumeserver: invalid lease right")
	ErrLeaseConflict   = errors.New("volumeserver: lease conflicts with an outstanding grant")
	ErrLeaseEpoch      = errors.New("volumeserver: lease epoch mismatch")
	ErrLeaseCursor     = errors.New("volumeserver: lease event cursor mismatch")
	ErrLeaseDischarge  = errors.New("volumeserver: invalid lease discharge")
	ErrLeaseHolder     = errors.New("volumeserver: lease holder is not active")
	ErrLeaseBlocked    = errors.New("volumeserver: lease coordinate is under recall")
	ErrLeaseCapacity   = errors.New("volumeserver: lease grant capacity exhausted")
	ErrLeaseStartup    = errors.New("volumeserver: prior cache leases may still be live")
	ErrLeaseRoutesLive = errors.New("volumeserver: route change requires clean mount absence")
)

// Protocol6MaxLeaseTTL is the frozen authority safety horizon. It is shared
// by restart recovery and client token validation so no grant can outlive the
// interval during which an uncleanly restarted authority refuses mutation.
const Protocol6MaxLeaseTTL = 20 * time.Second

// Protocol6LeaseWithdrawalBudget is reserved at the tail of every client
// token for local cache purge. Frontends stop using cached state this long
// before the authority horizon and abort if purge has not finished by it.
const Protocol6LeaseWithdrawalBudget = 5 * time.Second

// LeaseFamily identifies one independently revocable cache class. A data
// coordinate covers the whole file in protocol 6; byte ranges describe what a
// mutation changed, never a smaller grant.
type LeaseFamily uint8

const (
	LeaseFamilyName LeaseFamily = iota + 1
	LeaseFamilyAttributes
	LeaseFamilyData
	LeaseFamilyEnumeration
)

// LeaseRight is intentionally closed. N-X and A-X are representable for a
// future grant policy, but protocol 6's first policy grants neither. E has no
// exclusive right.
type LeaseRight uint8

const (
	LeaseRightNameRead LeaseRight = iota + 1
	LeaseRightNameExclusive
	LeaseRightAttributesRead
	LeaseRightAttributesExclusive
	LeaseRightDataRead
	LeaseRightDataExclusive
	LeaseRightEnumerationRead
)

func (r LeaseRight) family() LeaseFamily {
	switch r {
	case LeaseRightNameRead, LeaseRightNameExclusive:
		return LeaseFamilyName
	case LeaseRightAttributesRead, LeaseRightAttributesExclusive:
		return LeaseFamilyAttributes
	case LeaseRightDataRead, LeaseRightDataExclusive:
		return LeaseFamilyData
	case LeaseRightEnumerationRead:
		return LeaseFamilyEnumeration
	default:
		return 0
	}
}

func (r LeaseRight) exclusive() bool {
	return r == LeaseRightNameExclusive || r == LeaseRightAttributesExclusive || r == LeaseRightDataExclusive
}

// LeaseCoordinate is stable across authority epochs but grants are not. Name
// coordinates use ParentIdentity+Name; every other family uses Identity.
type LeaseCoordinate struct {
	Family         LeaseFamily
	Identity       [16]byte
	ParentIdentity [16]byte
	Name           []byte
}

func (c LeaseCoordinate) validate() error {
	switch c.Family {
	case LeaseFamilyName:
		if c.ParentIdentity == ([16]byte{}) || len(c.Name) == 0 || len(c.Name) > 255 || c.Identity != ([16]byte{}) {
			return ErrLeaseCoordinate
		}
		if bytes.IndexByte(c.Name, 0) >= 0 || bytes.IndexByte(c.Name, '/') >= 0 || bytes.Equal(c.Name, []byte(".")) || bytes.Equal(c.Name, []byte("..")) {
			return ErrLeaseCoordinate
		}
	case LeaseFamilyAttributes, LeaseFamilyData, LeaseFamilyEnumeration:
		if c.Identity == ([16]byte{}) || c.ParentIdentity != ([16]byte{}) || len(c.Name) != 0 {
			return ErrLeaseCoordinate
		}
	default:
		return ErrLeaseCoordinate
	}
	return nil
}

func (c LeaseCoordinate) key() string {
	if c.Family == LeaseFamilyName {
		key := make([]byte, 1+len(c.ParentIdentity)+len(c.Name))
		key[0] = byte(c.Family)
		copy(key[1:], c.ParentIdentity[:])
		copy(key[1+len(c.ParentIdentity):], c.Name)
		return string(key)
	}
	key := make([]byte, 1+len(c.Identity))
	key[0] = byte(c.Family)
	copy(key[1:], c.Identity[:])
	return string(key)
}

func cloneLeaseCoordinate(c LeaseCoordinate) LeaseCoordinate {
	c.Name = bytes.Clone(c.Name)
	return c
}

// LeaseGrant is the complete cache authority held by one mount. ExpiresAt is
// internal to the authority; the wire carries only a conservatively sampled
// remaining duration that the frontend anchors to its request-start clock.
type LeaseGrant struct {
	Coordinate LeaseCoordinate
	Right      LeaseRight
	Epoch      uint64
	ExpiresAt  time.Time
	IssuedAt   uint64
}

type LeaseRenewal struct {
	Coordinate LeaseCoordinate
	Epoch      uint64
}

type LeaseGrantRequest struct {
	Coordinate LeaseCoordinate
	Right      LeaseRight
}

type LeaseEventPhase uint8

const (
	LeaseEventRevoke LeaseEventPhase = iota + 1
	LeaseEventComplete
)

type LeaseEventCursor struct {
	Sequence uint64
	Phase    LeaseEventPhase
}

// LeaseRecall names both epochs around the GRANTED -> REVOKING transition.
// Matching RevokeEpoch, rather than the previous grant epoch, prevents a late
// discharge from completing a later recall of the same coordinate.
type LeaseRecall struct {
	Coordinate  LeaseCoordinate
	Right       LeaseRight
	GrantEpoch  uint64
	RevokeEpoch uint64
}

// LeaseEvent carries no post-state in REVOKE. COMPLETE carries the exact
// authority mutation record the holder installs while it discharges.
type LeaseEvent struct {
	Cursor           LeaseEventCursor
	Initiator        SessionID
	Recalls          []LeaseRecall
	PostState        []VisibilityObjectPostState
	SnapshotSequence uint64
}

type LeaseDischargeMode uint8

const (
	LeaseDischargeToNone LeaseDischargeMode = iota + 1
	LeaseDischargeContinuity
)

type LeaseDischarge struct {
	Coordinate  LeaseCoordinate
	RevokeEpoch uint64
	Mode        LeaseDischargeMode
	// SuccessorRight is reserved for a representable downgrade. Protocol 6 v1
	// has whole-file D coordinates, so partial-data continuity is rejected.
	SuccessorRight LeaseRight
}

type leaseState uint8

const (
	leaseGranted leaseState = iota + 1
	leaseRevoking
)

type leaseRecord struct {
	grant       LeaseGrant
	state       leaseState
	revokeEpoch uint64
	transaction uint64
}

type leaseDelivery struct {
	event    LeaseEvent
	done     chan error
	deadline time.Time
	once     sync.Once
}

func (d *leaseDelivery) finish(err error) {
	d.once.Do(func() {
		d.done <- err
		close(d.done)
	})
}

type leaseHolder struct {
	id       SessionID
	terminal <-chan struct{}
	leases   map[string]*leaseRecord
	// nextEpoch is holder-global. Coordinate churn therefore consumes only a
	// scalar counter instead of leaving an immortal counter entry per name.
	// Exact live coordinate epochs are still reused so reordered read replies
	// cannot invalidate an otherwise renewable token.
	nextEpoch uint64
	pending   *leaseDelivery
	// barrier reserves this holder's one CONTROL lane across REVOKE and
	// COMPLETE. Clearing pending after the REVOKE Ack must not let a disjoint
	// transaction insert an event between those two phases.
	barrier uint64
	fenced  bool
	// sourceAck is only an idempotence high-water. An exact live obligation is
	// always checked first because disjoint source mutations may discharge out
	// of sequence order.
	sourceAck uint64
	acked     LeaseEventCursor
	changed   chan struct{}
}

func (h *leaseHolder) signalLocked() {
	close(h.changed)
	h.changed = make(chan struct{})
}

type LeaseConfig struct {
	TTL          time.Duration
	RecallBudget time.Duration
	MaxPerHolder uint32
	MaxTotal     uint64
	// StartupGrace is the frozen maximum protocol lease TTL retained across an
	// unclean authority restart. PriorGrantsFenced is reserved for tests or a
	// supervisor that has separately proven the previous epoch's mounts absent.
	StartupGrace      time.Duration
	PriorGrantsFenced bool
	Now               func() time.Time
	Fencer            SessionFencer
	OnRecall          func(time.Duration, int)
}

// LeaseCoordinator owns the exact in-epoch cache-authority table. Storage
// mutation ordering remains in mutationSequencer; this coordinator only closes
// cache-grant admission and runs the recall barrier for those coordinates.
type LeaseCoordinator struct {
	cfg LeaseConfig

	mu      sync.Mutex
	holders map[SessionID]*leaseHolder
	blocked map[string]uint64
	// blockedSource names the holder whose outstanding discharge receipt is the
	// only thing still holding each key closed, so that receipt does not close
	// the coordinate against the holder that owes it.
	blockedSource map[string]SessionID
	readers       map[string]uint64
	source        map[sourceLeaseKey]*sourceLeaseObligation
	next          uint64
	committed     uint64
	totalLeases   uint64
	startupUntil  time.Time
	changed       chan struct{}
}

func NewLeaseCoordinator(cfg LeaseConfig) (*LeaseCoordinator, error) {
	if cfg.TTL <= 0 || cfg.TTL > Protocol6MaxLeaseTTL || cfg.RecallBudget <= 0 || cfg.MaxPerHolder == 0 || cfg.MaxTotal == 0 ||
		uint64(cfg.MaxPerHolder) > cfg.MaxTotal || cfg.Fencer == nil || cfg.StartupGrace < 0 ||
		(!cfg.PriorGrantsFenced && cfg.StartupGrace < cfg.TTL) {
		return nil, errors.New("volumeserver: leases need explicit TTL, recall budget, and fencer")
	}
	if cfg.Now == nil {
		cfg.Now = time.Now
	}
	startupUntil := cfg.Now()
	if !cfg.PriorGrantsFenced {
		startupUntil = startupUntil.Add(cfg.StartupGrace)
	}
	return &LeaseCoordinator{
		cfg: cfg, holders: make(map[SessionID]*leaseHolder), blocked: make(map[string]uint64),
		blockedSource: make(map[string]SessionID),
		readers:       make(map[string]uint64), source: make(map[sourceLeaseKey]*sourceLeaseObligation),
		next: 1, committed: 1, startupUntil: startupUntil, changed: make(chan struct{}),
	}, nil
}

func (c *LeaseCoordinator) signalLocked() {
	close(c.changed)
	c.changed = make(chan struct{})
}

func (c *LeaseCoordinator) ActivateHolder(id SessionID, terminal <-chan struct{}) error {
	if id == (SessionID{}) || terminal == nil {
		return ErrLeaseHolder
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	if _, exists := c.holders[id]; exists {
		return ErrLeaseHolder
	}
	c.holders[id] = &leaseHolder{
		id: id, terminal: terminal, leases: make(map[string]*leaseRecord), changed: make(chan struct{}),
	}
	c.signalLocked()
	return nil
}

// RemoveHolder drops only authority state. A caller may invoke it immediately
// after a proven clean unmount; an unproven loss must leave grants present until
// their authority expiry, which is handled by FenceHolder.
func (c *LeaseCoordinator) RemoveHolder(id SessionID) error {
	c.mu.Lock()
	defer c.mu.Unlock()
	h := c.holders[id]
	if h == nil {
		return ErrLeaseHolder
	}
	c.removeHolderLocked(h, nil)
	return nil
}

func (c *LeaseCoordinator) removeHolderLocked(h *leaseHolder, cause error) {
	if c.holders[h.id] != h {
		return
	}
	for key, obligation := range c.source {
		if key.holder == h.id {
			c.finishSourceDischargeLocked(key, h, obligation)
		}
	}
	if uint64(len(h.leases)) > c.totalLeases {
		panic("volumeserver: lease capacity accounting underflow")
	}
	c.totalLeases -= uint64(len(h.leases))
	delete(c.holders, h.id)
	if h.pending != nil {
		h.pending.finish(cause)
		h.pending = nil
	}
	h.signalLocked()
	c.signalLocked()
}

// FenceHolder ends the session but deliberately retains unexpired grants. A
// peer mutation may proceed only when the exact grant expiry has elapsed;
// deletion at fence time would confuse liveness with cache death.
func (c *LeaseCoordinator) FenceHolder(id SessionID) {
	newlyFenced := false
	c.mu.Lock()
	if holder := c.holders[id]; holder != nil && !holder.fenced {
		holder.fenced = true
		newlyFenced = true
		holder.signalLocked()
		c.signalLocked()
	}
	c.mu.Unlock()
	if newlyFenced {
		c.cfg.Fencer.FenceSession(id)
	}
}

func (c *LeaseCoordinator) grantAllowed(right LeaseRight) bool {
	switch right {
	case LeaseRightNameRead, LeaseRightAttributesRead, LeaseRightDataRead, LeaseRightDataExclusive, LeaseRightEnumerationRead:
		return true
	default:
		return false
	}
}

func nextLeaseEpochLocked(holder *leaseHolder) uint64 {
	holder.nextEpoch++
	if holder.nextEpoch == 0 {
		panic("volumeserver: lease epoch exhausted")
	}
	return holder.nextEpoch
}

// LeaseReadAdmission couples a storage read to every grant derived from it.
// Mutations close the coordinates and wait for admitted readers to either
// install their grants or leave before they select the recall audience.
type LeaseReadAdmission struct {
	coordinator *LeaseCoordinator
	holder      SessionID
	keys        map[string]struct{}
	mu          sync.Mutex
	closed      bool
	granted     map[string]struct{}
	snapshot    uint64
	generation  uint64
}

func (c *LeaseCoordinator) BeginRead(ctx context.Context, id SessionID, coordinates ...LeaseCoordinate) (*LeaseReadAdmission, error) {
	return c.beginRead(ctx, id, true, coordinates...)
}

// TryBeginRead is the callback-safe form. A FUSE request may hold a kernel
// folio or parent lock needed by recall invalidation, so it must never park
// behind a blocked coordinate; the frontend receives an immediate retry result
// with zero cache validity instead.
func (c *LeaseCoordinator) TryBeginRead(id SessionID, coordinates ...LeaseCoordinate) (*LeaseReadAdmission, error) {
	return c.beginRead(context.Background(), id, false, coordinates...)
}

func (c *LeaseCoordinator) beginRead(ctx context.Context, id SessionID, wait bool, coordinates ...LeaseCoordinate) (*LeaseReadAdmission, error) {
	if len(coordinates) == 0 {
		return nil, ErrLeaseCoordinate
	}
	keys := make(map[string]struct{}, len(coordinates))
	for _, coordinate := range coordinates {
		if err := coordinate.validate(); err != nil {
			return nil, err
		}
		keys[coordinate.key()] = struct{}{}
	}
	for {
		c.mu.Lock()
		c.expireLocked(c.cfg.Now())
		if c.holders[id] == nil || c.holders[id].fenced {
			c.mu.Unlock()
			return nil, ErrLeaseHolder
		}
		blocked := false
		for key := range keys {
			// A coordinate held closed only by this holder's own outstanding
			// discharge receipt does not close it against that holder. The purge the
			// receipt attests to already happened, before the reply that let this
			// request be issued at all; the receipt itself only has to keep every
			// other holder out until it lands. Refusing the source here would make an
			// ordinary write-then-read on one mount return EAGAIN. Every earlier
			// phase of the transaction still blocks the source too: until peers have
			// discharged, the barrier is not complete for anyone.
			if c.blocked[key] != 0 && c.blockedSource[key] != id {
				blocked = true
				break
			}
		}
		if !blocked {
			for key := range keys {
				c.readers[key]++
			}
			snapshot := c.committed
			generation := c.next
			c.mu.Unlock()
			return &LeaseReadAdmission{
				coordinator: c, holder: id, keys: keys, granted: make(map[string]struct{}),
				snapshot: snapshot, generation: generation,
			}, nil
		}
		if !wait {
			c.mu.Unlock()
			return nil, ErrLeaseBlocked
		}
		changed := c.changed
		c.mu.Unlock()
		select {
		case <-changed:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
}

// SnapshotSequence is the global lease-mutation cut at which this read was
// admitted. Coordinate blocking keeps every covered storage read stable until
// Release, and later mutations receive a strictly greater sequence.
func (a *LeaseReadAdmission) SnapshotSequence() uint64 {
	if a == nil {
		return 0
	}
	return a.snapshot
}

func (a *LeaseReadAdmission) Release() {
	if a == nil || a.coordinator == nil {
		return
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.closed {
		return
	}
	a.closed = true
	c := a.coordinator
	c.mu.Lock()
	for key := range a.keys {
		if c.readers[key] == 0 {
			c.mu.Unlock()
			panic("volumeserver: lease read admission underflow")
		}
		c.readers[key]--
		if c.readers[key] == 0 {
			delete(c.readers, key)
		}
	}
	c.signalLocked()
	c.mu.Unlock()
}

// GrantRead installs one new epoch while the storage read that produced the
// response is still admitted. It remains legal after a mutation closes the
// coordinate: that mutation waits for this admission and then recalls the
// newly installed epoch before apply.
func (a *LeaseReadAdmission) Grant(coordinate LeaseCoordinate, right LeaseRight) (LeaseGrant, error) {
	grants, err := a.GrantBatch([]LeaseGrantRequest{{Coordinate: coordinate, Right: right}})
	if err != nil {
		return LeaseGrant{}, err
	}
	return grants[0], nil
}

// GrantBatch installs a reply's related cache authorities atomically. A
// positive LOOKUP, for example, is either cacheable under both N and A or under
// neither; capacity pressure can never strand a partial token.
func (a *LeaseReadAdmission) GrantBatch(requests []LeaseGrantRequest) ([]LeaseGrant, error) {
	if a == nil || a.coordinator == nil {
		return nil, ErrLeaseCoordinate
	}
	if len(requests) == 0 {
		return nil, ErrLeaseCoordinate
	}
	keys := make(map[string]struct{}, len(requests))
	for _, request := range requests {
		if err := request.Coordinate.validate(); err != nil {
			return nil, err
		}
		if request.Right.family() != request.Coordinate.Family || !a.coordinator.grantAllowed(request.Right) {
			return nil, ErrLeaseRight
		}
		key := request.Coordinate.key()
		if _, admitted := a.keys[key]; !admitted {
			return nil, ErrLeaseCoordinate
		}
		if _, duplicate := keys[key]; duplicate {
			return nil, ErrLeaseEpoch
		}
		keys[key] = struct{}{}
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.closed {
		return nil, ErrLeaseEpoch
	}
	for key := range keys {
		if _, duplicate := a.granted[key]; duplicate {
			return nil, ErrLeaseEpoch
		}
	}
	c := a.coordinator
	c.mu.Lock()
	defer c.mu.Unlock()
	now := c.cfg.Now()
	holder := c.holders[a.holder]
	if holder == nil || holder.fenced {
		return nil, ErrLeaseHolder
	}
	newRecords := uint64(0)
	for _, request := range requests {
		key := request.Coordinate.key()
		for otherID, other := range c.holders {
			record := other.leases[key]
			if record != nil && record.state == leaseGranted && record.grant.ExpiresAt.After(now) &&
				otherID != a.holder && (request.Right.exclusive() || record.grant.Right.exclusive()) {
				return nil, ErrLeaseConflict
			}
		}
		if holder.leases[key] == nil {
			newRecords++
		}
	}
	if uint64(len(holder.leases))+newRecords > uint64(c.cfg.MaxPerHolder) || c.totalLeases+newRecords > c.cfg.MaxTotal {
		return nil, ErrLeaseCapacity
	}
	grants := make([]LeaseGrant, 0, len(requests))
	for _, request := range requests {
		grant, err := c.grantLocked(a.holder, request.Coordinate, request.Right, now, a.generation, false)
		if err != nil {
			panic("volumeserver: prevalidated lease grant batch failed: " + err.Error())
		}
		a.granted[request.Coordinate.key()] = struct{}{}
		grants = append(grants, grant)
	}
	return grants, nil
}

// Grant installs a grant for state that requires no preceding storage read
// (for example an OPEN mode decision). Cacheable read replies use BeginRead and
// LeaseReadAdmission.Grant so a mutation cannot fit between read and grant.
func (c *LeaseCoordinator) Grant(ctx context.Context, id SessionID, coordinate LeaseCoordinate, right LeaseRight) (LeaseGrant, error) {
	if err := coordinate.validate(); err != nil {
		return LeaseGrant{}, err
	}
	if right.family() != coordinate.Family || !c.grantAllowed(right) {
		return LeaseGrant{}, ErrLeaseRight
	}
	admission, err := c.BeginRead(ctx, id, coordinate)
	if err != nil {
		return LeaseGrant{}, err
	}
	defer admission.Release()
	return admission.Grant(coordinate, right)
}

// successor is set only for a post-state grant. It suppresses the in-place
// epoch refresh below: a successor covers state the same transaction just
// applied, so it must not inherit the epoch of the payload that transaction's
// source discharge is simultaneously obliged to retire.
func (c *LeaseCoordinator) grantLocked(id SessionID, coordinate LeaseCoordinate, right LeaseRight, now time.Time, issuedAt uint64, successor bool) (LeaseGrant, error) {
	if right.family() != coordinate.Family || !c.grantAllowed(right) {
		return LeaseGrant{}, ErrLeaseRight
	}
	key := coordinate.key()
	h := c.holders[id]
	if h == nil || h.fenced {
		return LeaseGrant{}, ErrLeaseHolder
	}
	for otherID, other := range c.holders {
		record := other.leases[key]
		if record == nil || record.state != leaseGranted || !record.grant.ExpiresAt.After(now) {
			continue
		}
		if otherID != id && (right.exclusive() || record.grant.Right.exclusive()) {
			return LeaseGrant{}, ErrLeaseConflict
		}
	}
	if record := h.leases[key]; !successor && record != nil && record.state == leaseGranted &&
		record.grant.Right == right && record.grant.ExpiresAt.After(now) {
		// A second read of the same coordinate refreshes the existing authority
		// token. Rotating its epoch would make an earlier, still-valid DATA reply
		// impossible to renew merely because replies were reordered.
		record.grant.ExpiresAt = now.Add(c.cfg.TTL)
		record.grant.IssuedAt = issuedAt
		return cloneLeaseGrant(record.grant), nil
	}
	newRecord := h.leases[key] == nil
	if newRecord && (uint64(len(h.leases)) >= uint64(c.cfg.MaxPerHolder) || c.totalLeases >= c.cfg.MaxTotal) {
		return LeaseGrant{}, ErrLeaseCapacity
	}
	grant := LeaseGrant{
		Coordinate: cloneLeaseCoordinate(coordinate), Right: right, Epoch: nextLeaseEpochLocked(h), ExpiresAt: now.Add(c.cfg.TTL), IssuedAt: issuedAt,
	}
	h.leases[key] = &leaseRecord{grant: grant, state: leaseGranted}
	if newRecord {
		c.totalLeases++
	}
	return cloneLeaseGrant(grant), nil
}

func cloneLeaseGrant(grant LeaseGrant) LeaseGrant {
	grant.Coordinate = cloneLeaseCoordinate(grant.Coordinate)
	return grant
}

// Remaining returns the authority-clock duration safe to put on the wire. A
// frontend anchors it at request start, so response latency is conservative.
func (c *LeaseCoordinator) Remaining(grant LeaseGrant) time.Duration {
	remaining := grant.ExpiresAt.Sub(c.cfg.Now())
	if remaining < 0 {
		return 0
	}
	return remaining
}

// Renew refreshes exact live epochs and explicitly withdraws well-formed tokens
// which expired or lost a race with recall. A recall is ordinary coherence, not
// a session-integrity failure; only malformed/duplicate input or an inactive
// holder rejects the request.
func (c *LeaseCoordinator) Renew(id SessionID, renewals []LeaseRenewal) ([]LeaseGrant, []LeaseRenewal, error) {
	c.mu.Lock()
	defer c.mu.Unlock()
	now := c.cfg.Now()
	c.expireLocked(now)
	h := c.holders[id]
	if h == nil || h.fenced {
		return nil, nil, ErrLeaseHolder
	}
	seen := make(map[string]struct{}, len(renewals))
	records := make([]*leaseRecord, 0, len(renewals))
	withdrawn := make([]LeaseRenewal, 0)
	for _, renewal := range renewals {
		if err := renewal.Coordinate.validate(); err != nil {
			return nil, nil, err
		}
		key := renewal.Coordinate.key()
		if _, duplicate := seen[key]; duplicate {
			return nil, nil, ErrLeaseEpoch
		}
		seen[key] = struct{}{}
		record := h.leases[key]
		if record == nil || record.state != leaseGranted || record.grant.Epoch != renewal.Epoch {
			withdrawn = append(withdrawn, LeaseRenewal{Coordinate: cloneLeaseCoordinate(renewal.Coordinate), Epoch: renewal.Epoch})
			continue
		}
		records = append(records, record)
	}
	expires := now.Add(c.cfg.TTL)
	grants := make([]LeaseGrant, len(records))
	for index, record := range records {
		if c.blocked[record.grant.Coordinate.key()] == 0 {
			record.grant.ExpiresAt = expires
			record.grant.IssuedAt = c.next
		}
		grants[index] = cloneLeaseGrant(record.grant)
	}
	return grants, withdrawn, nil
}

// RenewHeld is the piggyback form used on an authenticated authority round
// trip. It does not revive expired or revoking grants.
func (c *LeaseCoordinator) RenewHeld(id SessionID) []LeaseGrant {
	c.mu.Lock()
	defer c.mu.Unlock()
	now := c.cfg.Now()
	c.expireLocked(now)
	h := c.holders[id]
	if h == nil || h.fenced {
		return nil
	}
	expires := now.Add(c.cfg.TTL)
	grants := make([]LeaseGrant, 0, len(h.leases))
	for _, record := range h.leases {
		if record.state != leaseGranted {
			continue
		}
		if c.blocked[record.grant.Coordinate.key()] == 0 {
			record.grant.ExpiresAt = expires
			record.grant.IssuedAt = c.next
		}
		grants = append(grants, cloneLeaseGrant(record.grant))
	}
	sort.Slice(grants, func(i, j int) bool { return grants[i].Coordinate.key() < grants[j].Coordinate.key() })
	return grants
}

type LeaseRecallTarget struct {
	Coordinate LeaseCoordinate
}

type LeaseRecallTransaction struct {
	coordinator    *LeaseCoordinator
	sequence       uint64
	initiator      SessionID
	keys           []string
	deliveries     map[SessionID]*leaseDelivery
	sourceKeys     []string
	started        time.Time
	once           sync.Once
	commitOnce     sync.Once
	commitSequence uint64
}

type LeaseSourceDischarge struct {
	Sequence uint64
	Recalls  []LeaseRecall
}

type sourceLeaseKey struct {
	holder   SessionID
	sequence uint64
}

type sourceLeaseObligation struct {
	discharge LeaseSourceDischarge
	keys      []string
	done      chan struct{}
	deadline  time.Time
	expires   time.Time
	once      sync.Once
}

func (t *LeaseRecallTransaction) Sequence() uint64 {
	if t == nil {
		return 0
	}
	return t.sequence
}

// AssignCommitSequence allocates the globally committed storage cut after the
// filesystem operation has returned. It is separate from Sequence, which is a
// pre-apply admission generation and may complete out of order for disjoint
// coordinates.
func (t *LeaseRecallTransaction) AssignCommitSequence() uint64 {
	if t == nil || t.coordinator == nil {
		return 0
	}
	t.commitOnce.Do(func() {
		c := t.coordinator
		c.mu.Lock()
		c.committed++
		if c.committed == 0 {
			c.mu.Unlock()
			panic("volumeserver: lease commit sequence exhausted")
		}
		t.commitSequence = c.committed
		c.mu.Unlock()
	})
	return t.commitSequence
}

// CommittedSequence returns the latest completed storage cut without
// allocating a new one. Definite no-change operations publish this existing
// cut so successful no-ops do not invent object versions.
func (c *LeaseCoordinator) CommittedSequence() uint64 {
	if c == nil {
		return 0
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.committed
}

// PrepareRecall closes new grant admission, excludes the mutating holder from
// remote kernel obligations, dispatches REVOKE, and waits until every peer has
// acknowledged that its installing lane is closed.
func (c *LeaseCoordinator) PrepareRecall(ctx context.Context, source SessionID, targets []LeaseRecallTarget) (*LeaseRecallTransaction, error) {
	return c.prepareRecall(ctx, source, nil, true, targets)
}

// PrepareRecallFromExternalSource recalls Linux lease holders for a mutation
// initiated by an active frontend that does not participate in the lease
// protocol. The caller must pass that authenticated session's terminal channel;
// closing it aborts admission before apply. External sources never own lease
// records and therefore never receive a source-discharge obligation.
func (c *LeaseCoordinator) PrepareRecallFromExternalSource(ctx context.Context, source SessionID, terminal <-chan struct{}, targets []LeaseRecallTarget) (*LeaseRecallTransaction, error) {
	if source == (SessionID{}) || terminal == nil {
		return nil, ErrLeaseHolder
	}
	return c.prepareRecall(ctx, source, terminal, false, targets)
}

func externalLeaseSourceActive(terminal <-chan struct{}) bool {
	select {
	case <-terminal:
		return false
	default:
		return true
	}
}

func (c *LeaseCoordinator) prepareRecall(ctx context.Context, source SessionID, externalTerminal <-chan struct{}, requireHolder bool, targets []LeaseRecallTarget) (*LeaseRecallTransaction, error) {
	coordinates := make(map[string]LeaseCoordinate, len(targets))
	for _, target := range targets {
		if err := target.Coordinate.validate(); err != nil {
			return nil, err
		}
		coordinates[target.Coordinate.key()] = cloneLeaseCoordinate(target.Coordinate)
	}
	if len(coordinates) == 0 {
		return nil, ErrLeaseCoordinate
	}
	keys := make([]string, 0, len(coordinates))
	for key := range coordinates {
		keys = append(keys, key)
	}
	sort.Strings(keys)

	// First reserve the coordinates. BeginRead observes this block before it can
	// enter, so the admitted-reader count can only decrease from this point.
	var sequence uint64
	for {
		c.mu.Lock()
		now := c.cfg.Now()
		c.expireLocked(now)
		if now.Before(c.startupUntil) {
			c.mu.Unlock()
			return nil, ErrLeaseStartup
		}
		if requireHolder && (c.holders[source] == nil || c.holders[source].fenced) ||
			!requireHolder && !externalLeaseSourceActive(externalTerminal) {
			c.mu.Unlock()
			return nil, ErrLeaseHolder
		}
		busy := false
		for _, key := range keys {
			if c.blocked[key] != 0 {
				busy = true
				break
			}
		}
		if busy {
			changed := c.changed
			c.mu.Unlock()
			if requireHolder {
				select {
				case <-changed:
					continue
				case <-ctx.Done():
					return nil, ctx.Err()
				}
			}
			select {
			case <-changed:
				continue
			case <-externalTerminal:
				return nil, ErrLeaseHolder
			case <-ctx.Done():
				return nil, ctx.Err()
			}
		}

		c.next++
		if c.next == 0 {
			c.mu.Unlock()
			panic("volumeserver: lease recall sequence exhausted")
		}
		sequence = c.next
		for _, key := range keys {
			c.blocked[key] = sequence
		}
		c.mu.Unlock()
		break
	}

	// A read admitted before the block may have already observed storage. It is
	// allowed to install the grant derived from that observation, then leaves.
	// Only after all such readers drain do we select the exact recall audience.
	// This makes read+grant atomic with respect to the mutation barrier without
	// holding a coordinator mutex across storage I/O.
	for {
		c.mu.Lock()
		now := c.cfg.Now()
		c.expireLocked(now)
		if requireHolder && (c.holders[source] == nil || c.holders[source].fenced) ||
			!requireHolder && !externalLeaseSourceActive(externalTerminal) {
			c.releaseRecallReservationLocked(source, sequence, keys)
			c.mu.Unlock()
			return nil, ErrLeaseHolder
		}
		busy := false
		for _, key := range keys {
			if c.readers[key] != 0 {
				busy = true
				break
			}
		}
		if !busy {
			for id, holder := range c.holders {
				if id == source {
					continue
				}
				if holder.barrier != 0 && holderHasAnyLease(holder, keys) {
					busy = true
					break
				}
			}
		}
		if busy {
			changed := c.changed
			c.mu.Unlock()
			var waitErr error
			if requireHolder {
				select {
				case <-changed:
					continue
				case <-ctx.Done():
					waitErr = ctx.Err()
				}
			} else {
				select {
				case <-changed:
					continue
				case <-externalTerminal:
					waitErr = ErrLeaseHolder
				case <-ctx.Done():
					waitErr = ctx.Err()
				}
			}
			c.mu.Lock()
			c.releaseRecallReservationLocked(source, sequence, keys)
			c.mu.Unlock()
			return nil, waitErr
		}

		deliveries := make(map[SessionID]*leaseDelivery)
		var sourceKeys []string
		for id, holder := range c.holders {
			recalls := make([]LeaseRecall, 0, len(keys))
			for _, key := range keys {
				record := holder.leases[key]
				if record == nil || record.state != leaseGranted || !record.grant.ExpiresAt.After(now) {
					continue
				}
				if id == source {
					// The source's local reply discipline replaces remote recall. Keep
					// its old authority record until the operation proves whether state
					// changed; a definite no-op does not invalidate the source kernel.
					sourceKeys = append(sourceKeys, key)
					continue
				}
				record.state = leaseRevoking
				record.revokeEpoch = nextLeaseEpochLocked(holder)
				record.transaction = sequence
				recalls = append(recalls, LeaseRecall{
					Coordinate: cloneLeaseCoordinate(record.grant.Coordinate), Right: record.grant.Right,
					GrantEpoch: record.grant.Epoch, RevokeEpoch: record.revokeEpoch,
				})
			}
			if len(recalls) == 0 {
				continue
			}
			event := LeaseEvent{
				Cursor: LeaseEventCursor{Sequence: sequence, Phase: LeaseEventRevoke}, Initiator: source, Recalls: recalls,
			}
			delivery := &leaseDelivery{event: event, done: make(chan error, 1), deadline: now.Add(c.cfg.RecallBudget)}
			holder.barrier = sequence
			holder.pending = delivery
			holder.signalLocked()
			deliveries[id] = delivery
		}
		transaction := &LeaseRecallTransaction{
			coordinator: c, sequence: sequence, initiator: source, keys: keys, deliveries: deliveries,
			sourceKeys: sourceKeys, started: now,
		}
		c.mu.Unlock()
		// Once a REVOKE is visible on CONTROL, its matching COMPLETE is ordered
		// behind that acknowledgement. Caller cancellation cannot skip or replace
		// the first phase; fencing and grant expiry bound the terminal wait.
		if err := c.awaitLeaseDeliveries(context.Background(), deliveries); err != nil {
			transaction.Abort()
			return nil, err
		}
		if !requireHolder && !externalLeaseSourceActive(externalTerminal) {
			transaction.Abort()
			return nil, ErrLeaseHolder
		}
		return transaction, nil
	}
}

func (c *LeaseCoordinator) releaseBlockedLocked(sequence uint64, keys []string) {
	changed := false
	for _, key := range keys {
		if c.blocked[key] == sequence {
			delete(c.blocked, key)
			delete(c.blockedSource, key)
			changed = true
		}
	}
	if changed {
		c.signalLocked()
	}
}

func (c *LeaseCoordinator) releaseRecallReservationLocked(source SessionID, sequence uint64, keys []string) {
	_ = source
	c.releaseBlockedLocked(sequence, keys)
}

func holderHasAnyLease(holder *leaseHolder, keys []string) bool {
	for _, key := range keys {
		if holder.leases[key] != nil {
			return true
		}
	}
	return false
}

// CompletePeers publishes exact post-state and waits for every remote holder's
// discharge. A changed operation with source-side grants returns a source
// obligation and deliberately leaves its coordinates closed until the frontend
// proves required A/D/E caches were purged and the physical reply was written.
func (t *LeaseRecallTransaction) CompletePeers(ctx context.Context, postState []VisibilityObjectPostState, snapshotSequence uint64, changed bool) (*LeaseSourceDischarge, error) {
	if t == nil || t.coordinator == nil {
		return nil, ErrLeaseCursor
	}
	var result error
	var discharge *LeaseSourceDischarge
	didRun := false
	t.once.Do(func() {
		didRun = true
		discharge, result = t.complete(ctx, postState, snapshotSequence, changed)
	})
	if !didRun {
		return nil, ErrLeaseCursor
	}
	return discharge, result
}

func (t *LeaseRecallTransaction) complete(ctx context.Context, postState []VisibilityObjectPostState, snapshotSequence uint64, changed bool) (*LeaseSourceDischarge, error) {
	c := t.coordinator
	c.mu.Lock()
	deliveries := make(map[SessionID]*leaseDelivery, len(t.deliveries))
	now := c.cfg.Now()
	c.expireLocked(now)
	for id := range t.deliveries {
		holder := c.holders[id]
		if holder == nil {
			continue
		}
		recalls := recallsForTransaction(holder, t.sequence)
		if len(recalls) == 0 {
			continue
		}
		event := LeaseEvent{
			Cursor: LeaseEventCursor{Sequence: t.sequence, Phase: LeaseEventComplete}, Initiator: t.initiator,
			Recalls: recalls, PostState: cloneLeasePostState(postState), SnapshotSequence: snapshotSequence,
		}
		delivery := &leaseDelivery{event: event, done: make(chan error, 1), deadline: now.Add(c.cfg.RecallBudget)}
		holder.pending = delivery
		holder.signalLocked()
		deliveries[id] = delivery
	}
	c.mu.Unlock()
	// COMPLETE is a post-apply terminal obligation. Caller cancellation cannot
	// reopen cache-grant admission ahead of discharge; each delivery is already
	// bounded by recall fencing followed by the grant's authority expiry.
	_ = ctx
	err := c.awaitLeaseDeliveries(context.Background(), deliveries)
	c.mu.Lock()
	var sourceDischarge *LeaseSourceDischarge
	var obligation *sourceLeaseObligation
	if err == nil && changed {
		source := c.holders[t.initiator]
		if source != nil {
			now = c.cfg.Now()
			c.expireLocked(now)
			recalls := make([]LeaseRecall, 0, len(t.sourceKeys))
			latest := now
			for _, key := range t.sourceKeys {
				record := source.leases[key]
				if record == nil || record.state != leaseGranted || !record.grant.ExpiresAt.After(now) {
					continue
				}
				record.state = leaseRevoking
				record.revokeEpoch = nextLeaseEpochLocked(source)
				record.transaction = t.sequence
				recalls = append(recalls, LeaseRecall{
					Coordinate: cloneLeaseCoordinate(record.grant.Coordinate), Right: record.grant.Right,
					GrantEpoch: record.grant.Epoch, RevokeEpoch: record.revokeEpoch,
				})
				if record.grant.ExpiresAt.After(latest) {
					latest = record.grant.ExpiresAt
				}
			}
			sort.Slice(recalls, func(i, j int) bool { return recalls[i].Coordinate.key() < recalls[j].Coordinate.key() })
			if len(recalls) != 0 {
				discharge := LeaseSourceDischarge{Sequence: t.sequence, Recalls: recalls}
				obligation = &sourceLeaseObligation{
					discharge: discharge, keys: append([]string(nil), t.keys...), done: make(chan struct{}),
					deadline: now.Add(c.cfg.RecallBudget), expires: latest,
				}
				c.source[sourceLeaseKey{holder: t.initiator, sequence: t.sequence}] = obligation
				for _, key := range t.keys {
					if c.blocked[key] == t.sequence {
						c.blockedSource[key] = t.initiator
					}
				}
				if !source.fenced {
					sourceDischarge = cloneSourceDischarge(&discharge)
				}
			}
		}
	}
	if err == nil && obligation == nil {
		c.releaseRecallReservationLocked(t.initiator, t.sequence, t.keys)
	}
	c.mu.Unlock()
	if obligation != nil {
		go c.awaitSourceDischarge(t.initiator, obligation)
	}
	if c.cfg.OnRecall != nil {
		c.cfg.OnRecall(c.cfg.Now().Sub(t.started), len(deliveries))
	}
	return sourceDischarge, err
}

// GrantSourcePostState issues the mutating holder fresh cache authority over the
// coordinates its own applied post-state describes. It is legal only at this
// point in the transaction: every conflicting peer lease has been recalled to
// none, XFS has applied, and the grant covers exactly the state the reply is
// about to carry, so a successor here can never cover state whose freshness was
// not just established. The epoch is new, so the source's recalled epochs still
// owe their purge before the discharge receipt, and the coordinate stays closed
// to every other holder until that receipt arrives.
func (t *LeaseRecallTransaction) GrantSourcePostState(requests []LeaseGrantRequest) []LeaseGrant {
	if t == nil || t.coordinator == nil || len(requests) == 0 {
		return nil
	}
	c := t.coordinator
	c.mu.Lock()
	defer c.mu.Unlock()
	now := c.cfg.Now()
	c.expireLocked(now)
	grants := make([]LeaseGrant, 0, len(requests))
	for _, request := range requests {
		grant, err := c.grantLocked(t.initiator, request.Coordinate, request.Right, now, t.sequence, true)
		if err != nil {
			continue
		}
		grants = append(grants, grant)
	}
	return grants
}

// Abort is safe only before filesystem apply. It still completes the recall to
// none; reopening grants without an explicit successor would leave the daemon
// and authority disagreeing after the already-delivered REVOKE.
func (t *LeaseRecallTransaction) Abort() {
	if t == nil || t.coordinator == nil {
		return
	}
	t.once.Do(func() {
		ctx, cancel := context.WithTimeout(context.Background(), t.coordinator.cfg.TTL+t.coordinator.cfg.RecallBudget)
		defer cancel()
		_, _ = t.complete(ctx, nil, 0, false)
	})
}

func cloneSourceDischarge(discharge *LeaseSourceDischarge) *LeaseSourceDischarge {
	if discharge == nil {
		return nil
	}
	clone := &LeaseSourceDischarge{Sequence: discharge.Sequence, Recalls: append([]LeaseRecall(nil), discharge.Recalls...)}
	for index := range clone.Recalls {
		clone.Recalls[index].Coordinate = cloneLeaseCoordinate(clone.Recalls[index].Coordinate)
	}
	return clone
}

// DischargeSource is the authenticated post-reply receipt. The frontend calls
// it only after exact A/D/E invalidations named by the obligation completed
// before callback return and the subsequent /dev/fuse reply write completed.
func (c *LeaseCoordinator) DischargeSource(id SessionID, sequence uint64) error {
	if sequence == 0 {
		return ErrLeaseCursor
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	holder := c.holders[id]
	if holder == nil {
		return ErrLeaseHolder
	}
	key := sourceLeaseKey{holder: id, sequence: sequence}
	obligation := c.source[key]
	if obligation == nil {
		if sequence <= holder.sourceAck {
			return nil
		}
		return ErrLeaseCursor
	}
	c.finishSourceDischargeLocked(key, holder, obligation)
	return nil
}

func (c *LeaseCoordinator) finishSourceDischargeLocked(key sourceLeaseKey, holder *leaseHolder, obligation *sourceLeaseObligation) {
	obligation.once.Do(func() {
		for _, recall := range obligation.discharge.Recalls {
			coordinateKey := recall.Coordinate.key()
			record := holder.leases[coordinateKey]
			// A post-state successor may already have replaced the revoking
			// record for this coordinate. Its epoch is newer than the recalled
			// one, so the receipt discharges the old epoch and leaves the
			// successor -- and its lease-count entry -- alone.
			if record != nil && record.state == leaseRevoking && record.transaction == key.sequence && record.revokeEpoch == recall.RevokeEpoch {
				delete(holder.leases, coordinateKey)
				c.totalLeases--
			}
		}
		delete(c.source, key)
		if key.sequence > holder.sourceAck {
			holder.sourceAck = key.sequence
		}
		holder.signalLocked()
		c.releaseBlockedLocked(key.sequence, obligation.keys)
		close(obligation.done)
	})
}

func (c *LeaseCoordinator) awaitSourceDischarge(id SessionID, obligation *sourceLeaseObligation) {
	delay := obligation.deadline.Sub(c.cfg.Now())
	if delay < 0 {
		delay = 0
	}
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-obligation.done:
		return
	case <-timer.C:
	}
	c.FenceHolder(id)
	delay = obligation.expires.Sub(c.cfg.Now())
	if delay > 0 {
		timer.Reset(delay)
		select {
		case <-obligation.done:
			return
		case <-timer.C:
		}
	}
	c.mu.Lock()
	key := sourceLeaseKey{holder: id, sequence: obligation.discharge.Sequence}
	if holder := c.holders[id]; holder != nil && c.source[key] == obligation {
		c.finishSourceDischargeLocked(key, holder, obligation)
	}
	c.mu.Unlock()
}

func recallsForTransaction(holder *leaseHolder, sequence uint64) []LeaseRecall {
	recalls := make([]LeaseRecall, 0)
	for _, record := range holder.leases {
		if record.state != leaseRevoking || record.transaction != sequence {
			continue
		}
		recalls = append(recalls, LeaseRecall{
			Coordinate: cloneLeaseCoordinate(record.grant.Coordinate), Right: record.grant.Right,
			GrantEpoch: record.grant.Epoch, RevokeEpoch: record.revokeEpoch,
		})
	}
	sort.Slice(recalls, func(i, j int) bool { return recalls[i].Coordinate.key() < recalls[j].Coordinate.key() })
	return recalls
}

func cloneLeasePostState(states []VisibilityObjectPostState) []VisibilityObjectPostState {
	return append([]VisibilityObjectPostState(nil), states...)
}

func (c *LeaseCoordinator) Next(ctx context.Context, id SessionID, after LeaseEventCursor) (LeaseEvent, error) {
	for {
		c.mu.Lock()
		c.expireLocked(c.cfg.Now())
		holder := c.holders[id]
		if holder == nil {
			c.mu.Unlock()
			return LeaseEvent{}, ErrLeaseHolder
		}
		if holder.acked != after {
			c.mu.Unlock()
			c.FenceHolder(id)
			return LeaseEvent{}, ErrLeaseCursor
		}
		if holder.pending != nil {
			event := cloneLeaseEvent(holder.pending.event)
			c.mu.Unlock()
			return event, nil
		}
		changed := holder.changed
		terminal := holder.terminal
		c.mu.Unlock()
		select {
		case <-changed:
		case <-terminal:
			c.FenceHolder(id)
			return LeaseEvent{}, ErrLeaseHolder
		case <-ctx.Done():
			return LeaseEvent{}, ctx.Err()
		}
	}
}

func cloneLeaseEvent(event LeaseEvent) LeaseEvent {
	event.Recalls = append([]LeaseRecall(nil), event.Recalls...)
	for index := range event.Recalls {
		event.Recalls[index].Coordinate = cloneLeaseCoordinate(event.Recalls[index].Coordinate)
	}
	event.PostState = cloneLeasePostState(event.PostState)
	return event
}

// ExecuteRoutes commits a topology transition only at clean mount absence.
// LOCAL graft cache has no authority TTL, so neither a CONTROL acknowledgment
// nor fencing is evidence that an old-revision kernel stopped serving it. The
// caller holds topology exclusion, keeping this absence check stable.
func (c *LeaseCoordinator) ExecuteRoutes(ctx context.Context, next RoutesChange, commit func() (RoutesChange, error)) (int, error) {
	if ctx == nil || commit == nil || next.Revision == ([32]byte{}) {
		return 0, errors.New("volumeserver: routing change needs a context, revision, and durable commit")
	}
	c.mu.Lock()
	now := c.cfg.Now()
	if now.Before(c.startupUntil) {
		c.mu.Unlock()
		return 0, ErrLeaseStartup
	}
	if len(c.holders) != 0 {
		c.mu.Unlock()
		return 0, ErrLeaseRoutesLive
	}
	c.mu.Unlock()
	_, err := commit()
	return 0, err
}

// HolderCount includes fenced holders until a clean absence proof removes
// them. LOCAL route state has no lease TTL, so a hot topology change cannot
// treat fencing as proof that the old mount stopped serving it.
func (c *LeaseCoordinator) HolderCount() int {
	if c == nil {
		return 0
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	return len(c.holders)
}

// AcknowledgeRevoke is the PREPARE-equivalent receipt: it proves the daemon's
// installing admission is closed before XFS apply begins.
func (c *LeaseCoordinator) AcknowledgeRevoke(id SessionID, cursor LeaseEventCursor) error {
	if cursor.Sequence == 0 || cursor.Phase != LeaseEventRevoke {
		return ErrLeaseCursor
	}
	c.mu.Lock()
	holder := c.holders[id]
	if holder == nil {
		c.mu.Unlock()
		return ErrLeaseHolder
	}
	if holder.acked == cursor {
		c.mu.Unlock()
		return nil
	}
	if holder.pending == nil || holder.pending.event.Cursor != cursor {
		c.mu.Unlock()
		c.FenceHolder(id)
		return ErrLeaseCursor
	}
	delivery := holder.pending
	holder.pending = nil
	holder.acked = cursor
	holder.signalLocked()
	c.signalLocked()
	c.mu.Unlock()
	delivery.finish(nil)
	return nil
}

// Discharge completes one exact COMPLETE. Every recalled lease must be named
// once. Protocol 6 v1 accepts only recall-to-none because its D coordinate is
// whole-file and cannot represent a retained-range successor safely.
func (c *LeaseCoordinator) Discharge(id SessionID, cursor LeaseEventCursor, discharges []LeaseDischarge) error {
	if cursor.Sequence == 0 || cursor.Phase != LeaseEventComplete {
		return ErrLeaseCursor
	}
	c.mu.Lock()
	holder := c.holders[id]
	if holder == nil {
		c.mu.Unlock()
		return ErrLeaseHolder
	}
	if holder.acked == cursor {
		c.mu.Unlock()
		return nil
	}
	if holder.pending == nil || holder.pending.event.Cursor != cursor {
		c.mu.Unlock()
		c.FenceHolder(id)
		return ErrLeaseCursor
	}
	recalls := holder.pending.event.Recalls
	if len(discharges) != len(recalls) {
		c.mu.Unlock()
		return ErrLeaseDischarge
	}
	seen := make(map[string]struct{}, len(discharges))
	for _, discharge := range discharges {
		if err := discharge.Coordinate.validate(); err != nil || discharge.Mode != LeaseDischargeToNone || discharge.SuccessorRight != 0 {
			c.mu.Unlock()
			return ErrLeaseDischarge
		}
		key := discharge.Coordinate.key()
		if _, duplicate := seen[key]; duplicate {
			c.mu.Unlock()
			return ErrLeaseDischarge
		}
		seen[key] = struct{}{}
		record := holder.leases[key]
		if record == nil || record.state != leaseRevoking || record.transaction != cursor.Sequence || record.revokeEpoch != discharge.RevokeEpoch {
			c.mu.Unlock()
			return ErrLeaseEpoch
		}
	}
	delivery := holder.pending
	for key := range seen {
		delete(holder.leases, key)
		c.totalLeases--
	}
	holder.pending = nil
	holder.barrier = 0
	holder.acked = cursor
	holder.signalLocked()
	c.signalLocked()
	c.mu.Unlock()
	delivery.finish(nil)
	return nil
}

func (c *LeaseCoordinator) awaitLeaseDeliveries(ctx context.Context, deliveries map[SessionID]*leaseDelivery) error {
	if len(deliveries) == 0 {
		return nil
	}
	type result struct {
		id  SessionID
		err error
	}
	results := make(chan result, len(deliveries))
	for id, delivery := range deliveries {
		go func() { results <- result{id: id, err: c.awaitLeaseDelivery(ctx, id, delivery)} }()
	}
	var first error
	for range deliveries {
		result := <-results
		if result.err != nil && first == nil {
			first = result.err
		}
	}
	return first
}

func (c *LeaseCoordinator) awaitLeaseDelivery(ctx context.Context, id SessionID, delivery *leaseDelivery) error {
	delay := delivery.deadline.Sub(c.cfg.Now())
	if delay < 0 {
		delay = 0
	}
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case err := <-delivery.done:
		return err
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
	}
	c.FenceHolder(id)

	// A fenced daemon may still have live kernel cache. Wait for the latest
	// recalled grant's authority expiry, then expire it as an implicit discharge.
	// Wire durations are anchored at client request-start, so the client expiry
	// is conservatively no later than this boundary without comparing clocks.
	c.mu.Lock()
	holder := c.holders[id]
	latest := c.cfg.Now()
	if holder != nil {
		for _, recall := range delivery.event.Recalls {
			if record := holder.leases[recall.Coordinate.key()]; record != nil && record.grant.ExpiresAt.After(latest) {
				latest = record.grant.ExpiresAt
			}
		}
	}
	c.mu.Unlock()
	delay = latest.Sub(c.cfg.Now())
	if delay > 0 {
		timer.Reset(delay)
		select {
		case err := <-delivery.done:
			return err
		case <-ctx.Done():
			return ctx.Err()
		case <-timer.C:
		}
	}
	c.mu.Lock()
	holder = c.holders[id]
	if holder != nil && holder.pending == delivery {
		for _, recall := range delivery.event.Recalls {
			if _, exists := holder.leases[recall.Coordinate.key()]; exists {
				delete(holder.leases, recall.Coordinate.key())
				c.totalLeases--
			}
		}
		holder.pending = nil
		holder.barrier = 0
		holder.acked = delivery.event.Cursor
		holder.signalLocked()
		c.signalLocked()
	}
	c.mu.Unlock()
	delivery.finish(nil)
	return nil
}

func (c *LeaseCoordinator) expireLocked(now time.Time) {
	changed := false
	for _, holder := range c.holders {
		for key, record := range holder.leases {
			if record.state == leaseGranted && !record.grant.ExpiresAt.After(now) {
				delete(holder.leases, key)
				c.totalLeases--
				changed = true
			}
		}
	}
	if changed {
		c.signalLocked()
	}
}

// Held returns a stable snapshot for tests and metrics.
func (c *LeaseCoordinator) Held(id SessionID) []LeaseGrant {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.expireLocked(c.cfg.Now())
	holder := c.holders[id]
	if holder == nil {
		return nil
	}
	grants := make([]LeaseGrant, 0, len(holder.leases))
	for _, record := range holder.leases {
		if record.state == leaseGranted {
			grants = append(grants, cloneLeaseGrant(record.grant))
		}
	}
	sort.Slice(grants, func(i, j int) bool { return grants[i].Coordinate.key() < grants[j].Coordinate.key() })
	return grants
}

func (c LeaseCoordinate) String() string {
	if c.Family == LeaseFamilyName {
		return fmt.Sprintf("N(%x,%x)", c.ParentIdentity, c.Name)
	}
	return fmt.Sprintf("%d(%x)", c.Family, c.Identity)
}
