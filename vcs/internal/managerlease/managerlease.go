// Package managerlease implements the managed child's side of the two
// inherited manager pipes:
//
//   - LEASE FRAMES (manager → child, VCS_HEARTBEAT_FD): bounded (≤ 4 KiB)
//     newline-delimited JSON v1 frames carrying the manager's exact identity,
//     this child's exact runtime binding, a strictly monotonic per-child
//     sequence, and the manager claim's DATABASE-TIME facts (dbTimeMs and
//     leaseRemainingMs — both sides of one database response, so their sum is
//     an ABSOLUTE database-clock expiry). The child fences its ENTIRE data
//     plane on the first malformed, oversized, foreign, duplicate-keyed,
//     non-monotonic, or stale frame, on pipe EOF/error, and when the armed
//     deadline passes — always BEFORE the manager's database lease can
//     expire.
//
//   - BOOTSTRAP (child → manager, VCS_BOOTSTRAP_FD): exactly one bounded
//     JSON v1 frame reporting the child's exact identity, its self-bound
//     listener addresses, the claimed journal generation, the protocol
//     version, and the HA policy hash; the descriptor is closed immediately
//     after. The manager consumes it with a timeout and never adopts a
//     listener it did not receive through this frame.
//
// DEADLINE SOUNDNESS. A frame can sit in a pipe arbitrarily long, AND a
// manager claim can be superseded BEFORE its previously reported expiry — so
// neither "arrival time + remaining" nor "old frame expiry + fresh database
// now" is a correctness proof. Every deadline extension is therefore
// grounded in the CAPABILITY/RUNTIME-BOUND lease-facts read
// (pfj.authority_lease_facts through the already-open fenced journal
// connection; LeaseFactsProber):
//
//  1. a valid, sequence-monotonic frame is only the TRIGGER (its own
//     dbTimeMs/leaseRemainingMs are strictly validated wire metadata, never
//     an extension source);
//  2. on each valid frame the guard captures the CHILD-LOCAL MONOTONIC
//     instant BEFORE the bounded lease-facts query; the database verifies the
//     exact manager epoch + runtime binding + raw capability and answers
//     {current, dbTimeMs, expiresAtDbMs} from the LIVE claim row. The guard
//     arms deadline = capturedLocal + (expiresAtDbMs − dbTimeMs) − guard —
//     database time minus database time, anchored at a local instant that
//     provably precedes the database read. Process clocks are never
//     compared and no wall time is trusted.
//  3. a query error, timeout, ambiguous response, current=false (superseded
//     or expired claim), or binding-echo mismatch NEVER extends the armed
//     deadline — the old deadline continues and expires on schedule, which
//     is the fail-closed direction. Pipe EOF/malformed/foreign/backpressure
//     still fence immediately.
//
// Serving readiness gates on the FIRST GROUNDED arming (FirstFrame): before
// the journal seam exists, valid frames are parsed and the LATEST one is
// queued (bounded to one) so it grounds the moment the prober is installed —
// but no fallback or provisional path may close FirstFrame or authorize
// serving. Pre-seam frames arm only a provisional FENCING deadline.
//
// TIMER CORRECTNESS. One reusable timer guards the deadline. Its callback
// re-validates under the lock against the CURRENT deadline and generation:
// a callback that raced an extension (it was already firing while a fresh
// frame re-armed the deadline) observes now < deadlineAt, re-arms itself for
// the remainder, and never fences on stale state.
package managerlease

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"regexp"
	"sync"
	"time"
)

// MaxFrameBytes bounds one pipe frame (either direction), newline included.
const MaxFrameBytes = 4096

// FrameVersion is the only supported pipe frame version.
const FrameVersion = 1

// DefaultGuard is subtracted from every grounded remaining window when
// arming the local deadline. It must cover the probe's local-clock cost and
// scheduling jitter; the manager renews at a third of its claim TTL, so 2s
// of guard on a ≥ 15s lease leaves several renewal opportunities before any
// fence.
const DefaultGuard = 2 * time.Second

// probeTimeout bounds one lease-facts query. A query slower than this is
// ambiguous and extends nothing.
const probeTimeout = 5 * time.Second

// maxLeaseRemainingMs bounds a frame's claimed remaining lease. The manager
// claim TTL is bounded to one hour in SQL (pfm.manager_claim); anything
// larger is a malformed or forged frame.
const maxLeaseRemainingMs = int64(2 * time.Hour / time.Millisecond)

// maxSafeMs bounds every millisecond fact to JavaScript-safe integers: the
// frames are produced by the TypeScript manager, so anything above 2^53-1
// cannot be an honest value.
const maxSafeMs = int64(1)<<53 - 1

// maxIDBytes bounds every identifier field.
const maxIDBytes = 256

var canonicalDecimalPattern = regexp.MustCompile(`^[1-9][0-9]{0,18}$`)

// LeaseFacts is the capability/runtime-bound manager-claim truth returned by
// pfj.authority_lease_facts through the already-open journal connection: the
// LIVE claim's database clock and expiry, plus the exact binding echo the
// guard re-validates. Current=false means the database proved the binding is
// no longer the live one (superseded, expired, or revoked) — never an
// extension, though fencing is left to the armed deadline.
type LeaseFacts struct {
	Current             bool
	DBTimeMs            int64
	ExpiresAtDbMs       int64
	ManagerEpoch        string
	AuthorityRuntimeSeq string
	AuthorityRuntimeID  string
}

// LeaseFactsProber performs the bounded capability/runtime-bound lease-facts
// query (remotejournal.Log.AuthorityLeaseFacts). Implementations must never
// fabricate facts on error and must report a superseded/fenced binding as
// Current=false with a nil error.
type LeaseFactsProber interface {
	ProbeLeaseFacts(ctx context.Context) (LeaseFacts, error)
}

// Identity is the exact binding this child was launched under. Every lease
// frame must name it verbatim; counters stay canonical decimal strings.
type Identity struct {
	ManagerEpoch        string
	ManagerRuntimeID    string
	AuthorityInstanceID string
	AuthorityRuntimeSeq string
	AuthorityRuntimeID  string
}

// Frame is one manager lease frame (wire format v1). Seq is the manager's
// per-child MONOTONIC frame sequence: the manager delivers frames latest-
// value/coalesced (at most one in flight, superseded frames discarded), so a
// non-increasing sequence proves reordered, duplicated, or replayed frames —
// a stale lease view — and fences the child.
type Frame struct {
	V                   int    `json:"v"`
	Seq                 int64  `json:"seq"`
	ManagerEpoch        string `json:"managerEpoch"`
	ManagerRuntimeID    string `json:"managerRuntimeId"`
	AuthorityInstanceID string `json:"authorityInstanceId"`
	AuthorityRuntimeSeq string `json:"authorityRuntimeSeq"`
	AuthorityRuntimeID  string `json:"authorityRuntimeId"`
	DBTimeMs            int64  `json:"dbTimeMs"`
	LeaseRemainingMs    int64  `json:"leaseRemainingMs"`
}

// ParseFrame decodes and STRICTLY validates one lease-frame line (without
// the trailing newline): exactly one JSON object, no unknown/duplicate keys,
// no trailing data, canonical positive decimal counters, bounded nonempty
// ids, positive JavaScript-safe database times, and a bounded TTL/sequence.
// Identity and sequence-monotonicity checks live in the Guard.
func ParseFrame(line []byte) (Frame, error) {
	if err := requireStrictJSONObject(line); err != nil {
		return Frame{}, fmt.Errorf("managerlease: malformed lease frame: %w", err)
	}
	var frame Frame
	decoder := json.NewDecoder(bytes.NewReader(line))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&frame); err != nil {
		return Frame{}, fmt.Errorf("managerlease: malformed lease frame: %w", err)
	}
	if err := ensureDecoderExhausted(decoder); err != nil {
		return Frame{}, fmt.Errorf("managerlease: malformed lease frame: %w", err)
	}
	if frame.V != FrameVersion {
		return Frame{}, fmt.Errorf("managerlease: unsupported lease frame version %d", frame.V)
	}
	if frame.Seq < 1 || frame.Seq > maxSafeMs {
		return Frame{}, fmt.Errorf("managerlease: lease frame sequence %d is outside 1..2^53-1", frame.Seq)
	}
	for name, value := range map[string]string{
		"managerEpoch":        frame.ManagerEpoch,
		"authorityRuntimeSeq": frame.AuthorityRuntimeSeq,
	} {
		if !canonicalDecimalPattern.MatchString(value) {
			return Frame{}, fmt.Errorf("managerlease: lease frame %s %q is not a canonical positive decimal", name, value)
		}
	}
	for name, value := range map[string]string{
		"managerRuntimeId":    frame.ManagerRuntimeID,
		"authorityInstanceId": frame.AuthorityInstanceID,
		"authorityRuntimeId":  frame.AuthorityRuntimeID,
	} {
		if value == "" || len(value) > maxIDBytes {
			return Frame{}, fmt.Errorf("managerlease: lease frame %s is empty or exceeds %d bytes", name, maxIDBytes)
		}
	}
	if frame.DBTimeMs < 1 || frame.DBTimeMs > maxSafeMs {
		return Frame{}, fmt.Errorf("managerlease: lease frame dbTimeMs %d is outside 1..2^53-1", frame.DBTimeMs)
	}
	if frame.LeaseRemainingMs < 1 || frame.LeaseRemainingMs > maxLeaseRemainingMs {
		return Frame{}, fmt.Errorf("managerlease: lease frame leaseRemainingMs %d is outside 1..%d", frame.LeaseRemainingMs, maxLeaseRemainingMs)
	}
	return frame, nil
}

// Guard consumes lease frames and fences exactly once.
type Guard struct {
	identity Identity
	guard    time.Duration
	// now is the CHILD-LOCAL monotonic clock (time.Now; injectable in tests).
	// Go's time.Now carries a monotonic reading, so Sub/Add arithmetic on it
	// is immune to wall-clock steps.
	now func() time.Time

	mu     sync.Mutex
	prober LeaseFactsProber
	// pendingFrame holds the LATEST valid frame observed before the journal
	// seam existed (bounded to exactly one): it grounds immediately when
	// SetProber installs the seam. It never authorizes serving by itself.
	pendingFrame *Frame
	// One reusable timer; its callback re-validates deadlineAt/deadlineGen
	// under mu, so a callback racing a Reset can never fence on stale state.
	timer       *time.Timer
	deadlineAt  time.Time
	deadlineGen uint64
	lastSeq     int64
	grounded    bool
	probeFails  int
	notCurrent  int
	fenced      bool
	cause       error

	// groundedGen counts COMPLETED groundings; groundedCh is closed and
	// replaced after each one, so a caller can await settlement without
	// polling.
	groundedGen uint64
	groundedCh  chan struct{}

	fencedCh chan struct{}
	firstCh  chan struct{}
	firstOne sync.Once

	// groundReq is the LATEST-VALUE trigger that hands the database probe to
	// the grounder goroutine. Capacity one: a frame arriving while a
	// grounding is already queued rides on it, because grounding reads the
	// CURRENT database facts — a queued request can never be stale.
	groundReq  chan struct{}
	grounderOn sync.Once
}

// NewGuard builds a Guard for the exact identity. guard ≤ 0 uses DefaultGuard.
func NewGuard(identity Identity, guard time.Duration) *Guard {
	if guard <= 0 {
		guard = DefaultGuard
	}
	return &Guard{
		identity:   identity,
		guard:      guard,
		now:        time.Now,
		fencedCh:   make(chan struct{}),
		firstCh:    make(chan struct{}),
		groundedCh: make(chan struct{}),
		groundReq:  make(chan struct{}, 1),
	}
}

// requestGrounding hands ONE grounding to the grounder goroutine without ever
// blocking the caller.
//
// The frame reader's only job is to keep the lease pipe drained. Running the
// database probe inline made the reader's progress a function of database
// latency, and the manager reads a stalled pipe as a dead child: a child that
// is merely waiting on Postgres looks identical to one that has stopped
// consuming its fencing clock. Handing the probe off makes the two states
// structurally distinguishable — the pipe drains at pipe speed, the deadline
// advances at database speed, and neither can be mistaken for the other.
func (g *Guard) requestGrounding() {
	g.grounderOn.Do(func() { go g.groundLoop() })
	select {
	case g.groundReq <- struct{}{}:
	default:
		// A grounding is already queued; it will read facts at least as fresh
		// as this frame's.
	}
}

// groundLoop runs groundings one at a time, off the frame reader, until the
// guard fences. At most one probe is ever in flight.
func (g *Guard) groundLoop() {
	for {
		select {
		case <-g.fencedCh:
			return
		case <-g.groundReq:
			g.groundDeadline()
			g.mu.Lock()
			g.groundedGen++
			settled := g.groundedCh
			g.groundedCh = make(chan struct{})
			g.mu.Unlock()
			close(settled)
		}
	}
}

// groundingSettled reports the completed-grounding count and a channel closed
// when the NEXT grounding completes. Taken before an action, awaited after it,
// this observes the asynchronous grounder without polling.
func (g *Guard) groundingSettled() (uint64, <-chan struct{}) {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.groundedGen, g.groundedCh
}

// SetProber installs the capability-bound lease-facts seam once the fenced
// journal connection exists. Frames observed before this armed only a
// provisional FENCING deadline and never released FirstFrame; the latest
// queued frame grounds immediately.
func (g *Guard) SetProber(prober LeaseFactsProber) {
	g.mu.Lock()
	g.prober = prober
	pending := g.pendingFrame
	g.pendingFrame = nil
	g.mu.Unlock()
	if pending != nil {
		g.requestGrounding()
	}
}

// ProbeNotCurrent reports how many lease-facts queries proved the binding no
// longer current (observability; they never extend).
func (g *Guard) ProbeNotCurrent() int {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.notCurrent
}

// Fenced is closed the moment the guard fences the data plane.
func (g *Guard) Fenced() <-chan struct{} { return g.fencedCh }

// FirstFrame is closed after the first valid frame whose deadline was
// GROUNDED in database time. Serving must not begin before it.
func (g *Guard) FirstFrame() <-chan struct{} { return g.firstCh }

// Cause reports why the guard fenced (nil while unfenced).
func (g *Guard) Cause() error {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.cause
}

// ProbeFailures reports how many database-time probes failed (observability;
// failures never extend and never fence by themselves).
func (g *Guard) ProbeFailures() int {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.probeFails
}

// Fence fences explicitly (idempotent). Used by Run and by tests.
func (g *Guard) Fence(cause error) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.fenceLocked(cause)
}

func (g *Guard) fenceLocked(cause error) {
	if g.fenced {
		return
	}
	g.fenced = true
	g.cause = cause
	if g.timer != nil {
		g.timer.Stop()
	}
	close(g.fencedCh)
}

// armLocked installs a new deadline and bumps the generation; the reusable
// timer is (re)armed for the remainder. Only a GROUNDED arming whose
// deadline is genuinely in the future releases FirstFrame — a provisional
// or already-expired arming can fence but never authorize serving.
func (g *Guard) armLocked(deadline time.Time, grounded bool) {
	g.deadlineAt = deadline
	g.deadlineGen++
	remaining := deadline.Sub(g.now())
	if g.timer == nil {
		g.timer = time.AfterFunc(remaining, g.onDeadlineTimer)
	} else {
		g.timer.Reset(remaining)
	}
	if grounded && remaining > 0 {
		g.grounded = true
		g.firstOne.Do(func() { close(g.firstCh) })
	}
}

// onDeadlineTimer is the single timer callback. It fences ONLY when the
// currently armed deadline (whatever generation is live by the time it holds
// the lock) has truly passed; a callback that raced a re-arm observes the
// fresh deadline, re-arms itself for the remainder, and returns.
func (g *Guard) onDeadlineTimer() {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.deadlineCheckLocked()
}

// deadlineCheckLocked evaluates the CURRENT deadline/generation under mu.
// Split from the timer callback so tests can drive the exact interleavings
// (a stale callback firing after a valid frame re-armed the deadline).
func (g *Guard) deadlineCheckLocked() {
	if g.fenced || g.deadlineAt.IsZero() {
		return
	}
	if remaining := g.deadlineAt.Sub(g.now()); remaining > 0 {
		// A stale wakeup (this callback was scheduled for an older, already
		// superseded generation). Re-arm for the live deadline's remainder.
		if g.timer != nil {
			g.timer.Reset(remaining)
		}
		return
	}
	g.fenceLocked(fmt.Errorf("managerlease: manager lease deadline passed without a fresh grounded frame (generation %d)", g.deadlineGen))
}

// observe validates one parsed frame against the identity and sequence,
// then triggers a capability-bound lease-facts grounding. It returns the
// fence cause for an invalid frame.
func (g *Guard) observe(frame Frame) error {
	id := g.identity
	if frame.ManagerEpoch != id.ManagerEpoch ||
		frame.ManagerRuntimeID != id.ManagerRuntimeID ||
		frame.AuthorityInstanceID != id.AuthorityInstanceID ||
		frame.AuthorityRuntimeSeq != id.AuthorityRuntimeSeq ||
		frame.AuthorityRuntimeID != id.AuthorityRuntimeID {
		return fmt.Errorf("managerlease: lease frame names a foreign manager/runtime binding (epoch %q runtime %q instance %q seq %q id %q)",
			frame.ManagerEpoch, frame.ManagerRuntimeID, frame.AuthorityInstanceID, frame.AuthorityRuntimeSeq, frame.AuthorityRuntimeID)
	}

	g.mu.Lock()
	if frame.Seq <= g.lastSeq {
		g.mu.Unlock()
		// The manager sends a strictly increasing sequence with latest-value
		// coalescing; anything else is a reordered/duplicated/replayed frame
		// and must never refresh the lease view.
		return fmt.Errorf("managerlease: non-increasing lease frame sequence %d (last %d)", frame.Seq, g.lastSeq)
	}
	g.lastSeq = frame.Seq

	if g.prober == nil {
		// The journal seam does not exist yet. Queue the LATEST frame
		// (bounded to one — it grounds the moment the seam is installed) and
		// arm only a PROVISIONAL FENCING deadline from the frame's own
		// manager-computed remaining window: it may only fence a dead
		// manager early, never authorize serving (FirstFrame stays closed;
		// a superseded manager or buffered frame could overstate it).
		copied := frame
		g.pendingFrame = &copied
		if !g.fenced {
			provisional := g.now().Add(time.Duration(frame.LeaseRemainingMs)*time.Millisecond - g.guard)
			g.armLocked(provisional, false)
		}
		g.mu.Unlock()
		return nil
	}
	g.mu.Unlock()

	g.requestGrounding()
	return nil
}

// groundDeadline runs ONE bounded capability/runtime-bound lease-facts query
// and arms the deadline from its exact facts:
//
//	deadline = capturedLocal(BEFORE the query) + (expiresAtDbMs − dbTimeMs) − guard
//
// Anything short of a fully valid current=true answer with the exact binding
// echo NEVER extends: the previously armed deadline continues and expires on
// schedule. This is what makes a takeover sound — a manager superseded
// BEFORE its previously reported expiry stops producing extensions the
// moment the database says so, no matter how fresh its buffered frames look.
func (g *Guard) groundDeadline() {
	g.mu.Lock()
	prober := g.prober
	g.mu.Unlock()
	if prober == nil {
		return
	}

	capturedLocal := g.now()
	probeCtx, cancel := context.WithTimeout(context.Background(), probeTimeout)
	facts, err := prober.ProbeLeaseFacts(probeCtx)
	cancel()

	g.mu.Lock()
	defer g.mu.Unlock()
	if err != nil {
		// Ambiguous (error/timeout/ACL/revoked read): never extends, never
		// fences by itself.
		g.probeFails++
		return
	}
	if !facts.Current {
		// The database PROVED the binding is no longer the live one. Never
		// an extension; the armed deadline keeps counting down and expires.
		g.notCurrent++
		return
	}
	id := g.identity
	if facts.ManagerEpoch != id.ManagerEpoch ||
		facts.AuthorityRuntimeSeq != id.AuthorityRuntimeSeq ||
		facts.AuthorityRuntimeID != id.AuthorityRuntimeID {
		// A binding echo naming anything but OUR exact identity extends
		// nothing (a compromised or confused read path must fail closed).
		g.probeFails++
		return
	}
	if facts.DBTimeMs < 1 || facts.DBTimeMs > maxSafeMs ||
		facts.ExpiresAtDbMs < 1 || facts.ExpiresAtDbMs > maxSafeMs ||
		facts.ExpiresAtDbMs <= facts.DBTimeMs {
		g.probeFails++
		return
	}
	if g.fenced {
		return
	}
	remaining := time.Duration(facts.ExpiresAtDbMs-facts.DBTimeMs) * time.Millisecond
	g.armLocked(capturedLocal.Add(remaining-g.guard), true)
	return
}

// Run reads lease frames until the pipe ends or the guard fences. It ALWAYS
// fences on return: a healthy managed child never outlives its lease pipe.
// Run blocks; callers run it in a goroutine.
func (g *Guard) Run(r io.Reader) {
	reader := bufio.NewReaderSize(r, MaxFrameBytes)
	for {
		line, err := readBoundedLine(reader)
		if err != nil {
			g.Fence(fmt.Errorf("managerlease: lease pipe ended: %w", err))
			return
		}
		frame, err := ParseFrame(line)
		if err != nil {
			g.Fence(err)
			return
		}
		if err := g.observe(frame); err != nil {
			g.Fence(err)
			return
		}
		select {
		case <-g.fencedCh:
			return
		default:
		}
	}
}

// requireStrictJSONObject scans one JSON document and rejects duplicate
// member names anywhere, non-object top levels, and trailing data.
// DisallowUnknownFields on the typed decode remains authoritative for
// unknown names.
func requireStrictJSONObject(raw []byte) error {
	decoder := json.NewDecoder(bytes.NewReader(raw))
	decoder.UseNumber()
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	if token != json.Delim('{') {
		return fmt.Errorf("top-level value must be an object")
	}
	if err := scanObjectForDuplicates(decoder); err != nil {
		return err
	}
	if _, err := decoder.Token(); err != io.EOF {
		if err == nil {
			return fmt.Errorf("trailing data after the JSON object")
		}
		return err
	}
	return nil
}

func scanObjectForDuplicates(decoder *json.Decoder) error {
	seen := map[string]struct{}{}
	for decoder.More() {
		nameToken, err := decoder.Token()
		if err != nil {
			return err
		}
		name, ok := nameToken.(string)
		if !ok {
			return fmt.Errorf("object member name is not a string")
		}
		if _, duplicate := seen[name]; duplicate {
			return fmt.Errorf("duplicate field %q", name)
		}
		seen[name] = struct{}{}
		if err := skipValueChecked(decoder); err != nil {
			return err
		}
	}
	closeToken, err := decoder.Token()
	if err != nil || closeToken != json.Delim('}') {
		return fmt.Errorf("invalid object close: %v", err)
	}
	return nil
}

// skipValueChecked consumes one JSON value, recursing into nested objects so
// their duplicate names are rejected too.
func skipValueChecked(decoder *json.Decoder) error {
	token, err := decoder.Token()
	if err != nil {
		return err
	}
	switch token {
	case json.Delim('{'):
		return scanObjectForDuplicates(decoder)
	case json.Delim('['):
		for decoder.More() {
			if err := skipValueChecked(decoder); err != nil {
				return err
			}
		}
		closeToken, err := decoder.Token()
		if err != nil || closeToken != json.Delim(']') {
			return fmt.Errorf("invalid array close: %v", err)
		}
		return nil
	default:
		return nil
	}
}

// ensureDecoderExhausted requires the SECOND Decode to report io.EOF: one
// document, nothing trailing.
func ensureDecoderExhausted(decoder *json.Decoder) error {
	var trailing any
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		if err == nil {
			return fmt.Errorf("trailing JSON after the frame")
		}
		return err
	}
	return nil
}

// readBoundedLine reads one newline-terminated line of at most MaxFrameBytes
// (newline included). An oversized line is an error, never truncated input.
func readBoundedLine(reader *bufio.Reader) ([]byte, error) {
	var line []byte
	for {
		chunk, err := reader.ReadSlice('\n')
		line = append(line, chunk...)
		if len(line) > MaxFrameBytes {
			return nil, fmt.Errorf("frame exceeds %d bytes", MaxFrameBytes)
		}
		if err == nil {
			return line[:len(line)-1], nil
		}
		if err == bufio.ErrBufferFull {
			continue
		}
		if err == io.EOF && len(line) > 0 {
			return nil, fmt.Errorf("truncated frame before EOF")
		}
		return nil, err
	}
}

// Bootstrap is the one-shot child → manager report (wire format v1). Counter
// fields are canonical decimal strings; addresses are the EXACT self-bound
// listener addresses (loopback in managed production).
type Bootstrap struct {
	V                   int    `json:"v"`
	AuthorityInstanceID string `json:"authorityInstanceId"`
	VolumeID            string `json:"volumeId"`
	Branch              string `json:"branch"`
	ManagerEpoch        string `json:"managerEpoch"`
	AuthorityRuntimeSeq string `json:"authorityRuntimeSeq"`
	AuthorityRuntimeID  string `json:"authorityRuntimeId"`
	FSAddr              string `json:"fsAddr"`
	MetricsAddr         string `json:"metricsAddr"`
	JournalGenerationID string `json:"journalGenerationId"`
	ProtocolVersion     int    `json:"protocolVersion"`
	HAPolicyHash        string `json:"haPolicyHash"`
}

// EmitBootstrap writes exactly one bounded bootstrap frame, tolerating short
// writes (a pipe may accept fewer bytes per write than offered). The caller
// closes the descriptor afterwards; the manager reads exactly one line.
func EmitBootstrap(w io.Writer, frame Bootstrap) error {
	frame.V = FrameVersion
	encoded, err := json.Marshal(frame)
	if err != nil {
		return fmt.Errorf("managerlease: encode bootstrap frame: %w", err)
	}
	if len(encoded)+1 > MaxFrameBytes {
		return fmt.Errorf("managerlease: bootstrap frame exceeds %d bytes", MaxFrameBytes)
	}
	buf := append(encoded, '\n')
	for len(buf) > 0 {
		n, err := w.Write(buf)
		if err != nil {
			return fmt.Errorf("managerlease: write bootstrap frame: %w", err)
		}
		if n <= 0 {
			return fmt.Errorf("managerlease: bootstrap pipe accepted no bytes")
		}
		buf = buf[n:]
	}
	return nil
}
