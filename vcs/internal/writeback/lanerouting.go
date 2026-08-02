package writeback

// Lane routing, counted.
//
// Round 18f's premise was that the write path "systematically escapes its own
// backpressure onto an uncharged lane". That is a claim about PROPORTIONS, and
// no proportion was measurable: the engine recorded which lane a write took
// nowhere at all, so every statement about the routing had to be inferred from
// the shape of the code. Inference is how the unwind door got blamed for the
// whole of a loss that, measured, it does not dominate.
//
// This file installs the missing counters. There are exactly FIVE doors onto
// the authority lane and they are not interchangeable — two are structural and
// correct, one is a policy decision, and two are the same saturation escape
// seen from either side of the frontend's locks:
//
//	DoorIdentity    an orphan, a hard link, a pathless detached handle. The
//	                overlay is path-keyed and cannot represent these AT ALL, so
//	                the authority lane is not an escape, it is the only lane
//	                that exists. (clientcore.authorityOnlyByIdentity)
//	DoorUncovered   no delegation covers the path. Write-through consumes no
//	                stream budget and has no grant to release. Also structural,
//	                and the reason a mount with no delegation at all is not
//	                throttled by a WAL it never writes to.
//	DoorBudget      the credit budget expired: 40s of delegated starvation with
//	                a live uplink. A POLICY divert. (divertAfterCreditBudget)
//	DoorLaneChanged the engine refused a resolved delegated write inside the
//	                locks because the gate was full, which unwinds the frontend.
//	DoorForced      the unwind's second pass, which resolves the authority lane
//	                UNCONDITIONALLY so the operation terminates.
//
// DoorLaneChanged and DoorForced are one event counted at both ends: every
// unwind that reaches the second pass should produce one of each. Counting
// them separately is what makes an unwind that does NOT terminate visible as a
// divergence between the two, rather than as a hang with no evidence.
//
// The counters are plain atomics on a cache line nothing else touches, read
// only by Status and by tests. The hot path pays one atomic add on a decision
// it was already making.

import "sync/atomic"

// LaneDoor identifies which admission decision put a write on the authority
// lane. Doors are counted, never inferred.
type LaneDoor int

const (
	// DoorIdentity: authority-only by construction (orphan, hard link,
	// pathless detached handle). Not an escape; the only lane that exists.
	DoorIdentity LaneDoor = iota
	// DoorUncovered: no delegation covers the path, so there is no stream
	// budget to consume and no grant to release.
	DoorUncovered
	// DoorBudget: creditAdmissionBudget expired with a live uplink and the
	// frontend diverted rather than failing the application.
	DoorBudget
	// DoorLaneChanged: the engine refused a resolved delegated write inside
	// the frontend's locks; the frontend unwinds.
	DoorLaneChanged
	// DoorForced: the unwind's terminating second pass.
	DoorForced
	numLaneDoors
)

var laneDoorNames = [numLaneDoors]string{
	DoorIdentity:    "identity",
	DoorUncovered:   "uncovered",
	DoorBudget:      "credit-budget-divert",
	DoorLaneChanged: "lane-changed",
	DoorForced:      "forced-authority",
}

func (d LaneDoor) String() string {
	if d < 0 || d >= numLaneDoors {
		return "unknown"
	}
	return laneDoorNames[d]
}

// laneCounters is the engine's routing tally. Each door carries both an
// operation count and a byte count, because the two answer different questions:
// operations say how OFTEN a door is taken, bytes say how much of a flood
// escapes through it, and a door taken rarely for huge writes is invisible in
// the first and dominant in the second.
type laneCounters struct {
	ops   [numLaneDoors]atomic.Int64
	bytes [numLaneDoors]atomic.Int64

	// delegatedOps/delegatedBytes are the denominator. Without them a door
	// count is a number with no scale.
	delegatedOps   atomic.Int64
	delegatedBytes atomic.Int64
}

// note records one door CHOICE together with the bytes it admitted. It is for
// the engine-internal doors, where the choice and the admission are the same
// event.
func (c *laneCounters) note(d LaneDoor, n int64) {
	if d < 0 || d >= numLaneDoors {
		return
	}
	c.ops[d].Add(1)
	if n > 0 {
		c.bytes[d].Add(n)
	}
}

// noteChoice records that a write CHOSE this door, without yet claiming any
// byte went through it.
//
// The split exists because a door choice and a door admission are not the same
// event once the lane is gated: a write can pick the uncovered door and then be
// refused by the gate behind it. Counting the request's bytes at the choice
// would put bytes in the tally that were never admitted anywhere, and the first
// run of TestUncoveredWriteThroughIsBounded caught exactly that — 6553600
// tallied against 6291456 admitted, the difference being one refused request.
//
// So ops answer "how often was this door taken" and bytes answer "how much
// actually went through it", and the two are recorded at the two different
// moments where each is true.
func (c *laneCounters) noteChoice(d LaneDoor) {
	if d < 0 || d >= numLaneDoors {
		return
	}
	c.ops[d].Add(1)
}

// noteAdmitted records bytes that really were admitted through d.
func (c *laneCounters) noteAdmitted(d LaneDoor, n int64) {
	if d < 0 || d >= numLaneDoors || n <= 0 {
		return
	}
	c.bytes[d].Add(n)
}

func (c *laneCounters) noteDelegated(n int64) {
	c.delegatedOps.Add(1)
	if n > 0 {
		c.delegatedBytes.Add(n)
	}
}

func (c *laneCounters) snapshot() LaneRouting {
	var r LaneRouting
	for d := LaneDoor(0); d < numLaneDoors; d++ {
		r.Ops[d] = c.ops[d].Load()
		r.Bytes[d] = c.bytes[d].Load()
	}
	r.DelegatedOps = c.delegatedOps.Load()
	r.DelegatedBytes = c.delegatedBytes.Load()
	return r
}

// LaneRouting is one immutable reading of the routing tally.
type LaneRouting struct {
	Ops            [numLaneDoors]int64
	Bytes          [numLaneDoors]int64
	DelegatedOps   int64
	DelegatedBytes int64
}

// AuthorityBytes is every byte that reached the authority lane, through any
// door.
func (r LaneRouting) AuthorityBytes() int64 {
	var total int64
	for d := LaneDoor(0); d < numLaneDoors; d++ {
		if d == DoorLaneChanged {
			// DoorLaneChanged is the unwind's FIRST half: the same bytes are
			// counted again at DoorForced when the second pass admits them.
			// Summing both would double-count every unwound write.
			continue
		}
		total += r.Bytes[d]
	}
	return total
}

// EscapedBytes is the share of the authority lane that is a saturation ESCAPE
// rather than a structural necessity: the two doors a flood can drive.
func (r LaneRouting) EscapedBytes() int64 {
	return r.Bytes[DoorBudget] + r.Bytes[DoorForced]
}

// AuthorityShare is the fraction of admitted bytes that took the authority
// lane, in [0,1]. Zero when nothing has been admitted at all.
func (r LaneRouting) AuthorityShare() float64 {
	auth := r.AuthorityBytes()
	total := auth + r.DelegatedBytes
	if total <= 0 {
		return 0
	}
	return float64(auth) / float64(total)
}

// NoteLaneDoor records one authority-lane admission. It is exported because
// two of the five doors are decided in clientcore's pre-lock classifier, which
// is a different package and must not have to keep a second tally that could
// disagree with this one.
func (e *Engine) NoteLaneDoor(d LaneDoor, n int64) {
	if e == nil {
		return
	}
	e.lanes.note(d, n)
}

// NoteLaneDoorChoice records that a write chose door d. The bytes it actually
// admits are reported separately with NoteLaneDoorAdmitted, once the lane's
// gate has said how many there are.
func (e *Engine) NoteLaneDoorChoice(d LaneDoor) {
	if e == nil {
		return
	}
	e.lanes.noteChoice(d)
}

// NoteLaneDoorAdmitted records bytes admitted through door d.
func (e *Engine) NoteLaneDoorAdmitted(d LaneDoor, n int64) {
	if e == nil {
		return
	}
	e.lanes.noteAdmitted(d, n)
}

// NoteDelegatedAdmission records one delegated-lane admission: the denominator
// every door count is read against.
func (e *Engine) NoteDelegatedAdmission(n int64) {
	if e == nil {
		return
	}
	e.lanes.noteDelegated(n)
}

// LaneRouting reports the routing tally since the engine opened.
func (e *Engine) LaneRouting() LaneRouting {
	if e == nil {
		return LaneRouting{}
	}
	return e.lanes.snapshot()
}
