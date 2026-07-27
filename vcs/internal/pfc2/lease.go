package pfc2

import "time"

// Lease-time integration surface.
//
// Durable truth for every session deadline is EXACT DATABASE TIME, observed
// through short-lived capability-bound ADMISSION FACTS minted by the fenced
// SQL database — never by a client or authority host wall clock. This package
// never calls time.Now.
//
// The production wiring is a two-step protocol against the same database that
// journals the records:
//
//  1. ISSUE: before building a record, the authority asks the database for an
//     admission fact, bound to its exact coordinates — tenant, volume,
//     branch, journal generation/epoch, manager runtime binding, authority
//     capability, subject session, and the issuer's view of the durable
//     control floor. The database answers with a fresh fact id, the exact
//     database time, and a short fact TTL (FactIssuer).
//  2. FREEZE: the issued values (source, fact id, database time) are frozen
//     verbatim into the PFC2 record bytes exactly once (the builders below).
//     Those bytes are the retry unit: an unknown outcome retries the
//     IDENTICAL bytes, never a re-mint.
//  3. APPEND REVALIDATION: the journal append transaction — the same fenced
//     SQL transaction that commits the PFJ3 row — revalidates each referenced
//     fact: it exists, is unconsumed, is unexpired against a fresh
//     clock_timestamp, was issued for exactly this generation's coordinates,
//     its frozen database time is not behind the generation's committed
//     db-time floor and not ahead of the fresh clock (reverse-issued facts
//     fail), and the HA/fence facts still hold. It then consumes the fact.
//     A receipt-replayed identical append succeeds WITHOUT the fact rows
//     (receipts are checked first), so retries survive fact expiry; an
//     unused expired fact can never append.
//  4. PROJECT: serving layers convert deadlines to LOCAL monotonic waits with
//     RemainingLease; when a timer fires the sweeper obtains a FRESH fact and
//     asks ExpiryDue — the elapsed timer itself authorizes nothing, so host
//     wall-clock skew can only re-check early or late, never expire a live
//     lease or resurrect a fenced one.
//
// There are deliberately no periodic per-inode leases anywhere: session
// renewal owns the liveness of every pin, lock, and checkout the session
// holds.

// FactPurpose is the frozen operation-purpose byte an admission fact is
// minted for. The issuing SQL records it and the append transaction rejects a
// consume under any other purpose; the PFJ3 manifest restates it verbatim.
type FactPurpose uint8

const (
	FactPurposeSessionOpen   FactPurpose = 1
	FactPurposeSessionRenew  FactPurpose = 2
	FactPurposeSessionExpiry FactPurpose = 3
)

// Valid reports whether p is a known purpose.
func (p FactPurpose) Valid() bool {
	return p >= FactPurposeSessionOpen && p <= FactPurposeSessionExpiry
}

// FactScope names the exact coordinates one admission fact binds. Every field
// is part of the issuance predicate; the append transaction re-derives the
// same scope from its own generation row and rejects a fact issued for any
// other scope.
type FactScope struct {
	TenantID     string
	VolumeID     string
	Branch       string
	GenerationID string
	Epoch        uint64
	// Purpose is the exact operation kind this fact may authorize.
	Purpose FactPurpose
	// Session is the subject session generation (the session being opened,
	// renewed, or expired).
	Session SessionRef
	// PriorDbTimeFloorMs is the issuer's view of the durable database-time
	// floor when it asked. Issuance requires it to EQUAL the committed floor
	// exactly; anything else fails closed (stale or speculative view).
	PriorDbTimeFloorMs int64
}

// IssuedFact is one short-lived admission fact: the frozen TimeFact plus the
// fact row's own expiry (database time). The TTL bounds how long the caller
// may sit between issuance and append; it is NOT a lease deadline.
type IssuedFact struct {
	Fact TimeFact
	// FactExpiresDbMs is the database time after which an UNUSED fact can no
	// longer append. Receipt-replayed identical retries are exempt: their
	// append already consumed the fact.
	FactExpiresDbMs int64
}

// FactIssuer mints admission facts. The production implementation is the
// remote journal client: one capability-bound SQL call inside the same fenced
// database that will later validate and consume the fact at append.
// Implementations MUST NOT substitute host wall clocks.
type FactIssuer interface {
	IssueAdmissionFact(scope FactScope) (IssuedFact, error)
}

// leaseDeadline computes fact.DbMs+ttl with bounds: ttl must be positive, at
// most MaxSessionLeaseMs, and the deadline must remain plausible.
func leaseDeadline(fact TimeFact, ttl time.Duration) (int64, error) {
	if err := fact.Validate(); err != nil {
		return 0, err
	}
	ttlMs := ttl.Milliseconds()
	if ttlMs <= 0 || ttlMs > MaxSessionLeaseMs {
		return 0, malformedf("lease ttl %v is outside (0, %dms]", ttl, int64(MaxSessionLeaseMs))
	}
	expires := fact.DbMs + ttlMs // cannot overflow: both bounded far below MaxInt64
	if !validDbTimeMs(expires) {
		return 0, malformedf("lease deadline %d is implausible", expires)
	}
	return expires, nil
}

// NewSessionOpenRecord freezes an issued admission fact and bounded TTL into
// a canonical SessionOpen record.
func NewSessionOpenRecord(session SessionRef, owner string, tokenHash [TokenHashBytes]byte, slots uint32, fact TimeFact, ttl time.Duration) (*Record, error) {
	expires, err := leaseDeadline(fact, ttl)
	if err != nil {
		return nil, err
	}
	r := &Record{Kind: KindSessionOpen, SessionOpen: &SessionOpen{
		Session: session, Owner: owner, TokenHash: tokenHash, Slots: slots,
		Fact: fact, ExpiresDbMs: expires,
	}}
	if err := r.Validate(); err != nil {
		return nil, err
	}
	return r, nil
}

// NewSessionRenewRecord freezes an issued admission fact and bounded TTL into
// a canonical SessionRenew record.
func NewSessionRenewRecord(session SessionRef, tokenHash [TokenHashBytes]byte, fact TimeFact, ttl time.Duration) (*Record, error) {
	expires, err := leaseDeadline(fact, ttl)
	if err != nil {
		return nil, err
	}
	r := &Record{Kind: KindSessionRenew, SessionRenew: &SessionRenew{
		Session: session, TokenHash: tokenHash, Fact: fact, ExpiresDbMs: expires,
	}}
	if err := r.Validate(); err != nil {
		return nil, err
	}
	return r, nil
}

// NewSessionExpiryRecord freezes the observed durable deadline and the FRESH
// decision fact into a conditional SessionTerminal expiry record. It refuses
// a decision fact that has not actually reached the deadline: a local timer
// firing early (or a skewed host clock) can never mint an expiry.
func NewSessionExpiryRecord(session SessionRef, observedDeadlineDbMs int64, decision TimeFact) (*Record, error) {
	due, err := ExpiryDue(decision, observedDeadlineDbMs)
	if err != nil {
		return nil, err
	}
	if !due {
		return nil, malformedf("expiry decision at %d precedes the observed deadline %d; database time has not expired this lease",
			decision.DbMs, observedDeadlineDbMs)
	}
	r := &Record{Kind: KindSessionTerminal, SessionTerminal: &SessionTerminal{
		Session: session, Reason: TerminalExpire,
		ObservedDeadlineDbMs: observedDeadlineDbMs, DecisionFact: decision,
	}}
	if err := r.Validate(); err != nil {
		return nil, err
	}
	return r, nil
}

// RemainingLease projects a durable database-time deadline onto a LOCAL
// monotonic wait: the remaining duration as measured in database time,
// clamped at zero. The caller schedules a monotonic timer with it and, when
// the timer fires, must obtain a fresh admission fact and consult ExpiryDue —
// the elapsed local timer itself authorizes nothing.
func RemainingLease(now TimeFact, expiresDbMs int64) (time.Duration, error) {
	if err := now.Validate(); err != nil {
		return 0, err
	}
	if !validDbTimeMs(expiresDbMs) {
		return 0, malformedf("lease deadline %d is implausible", expiresDbMs)
	}
	if expiresDbMs <= now.DbMs {
		return 0, nil
	}
	return time.Duration(expiresDbMs-now.DbMs) * time.Millisecond, nil
}

// ExpiryDue reports whether database time has reached a durable deadline.
func ExpiryDue(now TimeFact, deadlineDbMs int64) (bool, error) {
	if err := now.Validate(); err != nil {
		return false, err
	}
	if !validDbTimeMs(deadlineDbMs) {
		return false, malformedf("lease deadline %d is implausible", deadlineDbMs)
	}
	return now.DbMs >= deadlineDbMs, nil
}

// FactIDs collects the admission-fact identities frozen in one record, in
// canonical field order. The journal append passes exactly these (with their
// frozen times) for revalidation and consumption inside the same transaction
// that commits the bytes.
func (r *Record) FactIDs() []TimeFact {
	switch r.Kind {
	case KindSessionOpen:
		return []TimeFact{r.SessionOpen.Fact}
	case KindSessionRenew:
		return []TimeFact{r.SessionRenew.Fact}
	case KindSessionTerminal:
		if r.SessionTerminal.Reason == TerminalExpire {
			return []TimeFact{r.SessionTerminal.DecisionFact}
		}
	}
	return nil
}
