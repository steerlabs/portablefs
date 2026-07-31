// Package fusefrontend contains the small amount of coordination shared by
// PortableFS's in-process FUSE frontends.
package fusefrontend

import (
	"context"
	"strings"
	"sync"

	"github.com/hanwen/go-fuse/v2/fuse"
)

// ReplyGate prevents a delegation handoff from being followed by an older
// content reply for the released subtree. Its zero value is ready for use.
//
// Read admission is path-scoped. Closing "a/b" waits for reads of "a/b" and
// descendants while reads in "a/c" continue. A closed scope remains closed
// until EndHandoff, so the exact cache flush and authority Checkin execute
// without a newer overlapping reply entering the old view.
//
// A drain must never wait on a request that cannot finish. A request that
// blocks on the authority — a foreign delegation recall, this mount's own
// release, exact-mutation serialization, a blocking advisory-lock acquire —
// suspends its admitted replies for the duration of that wait (Operation and
// SuspendOperation), so the two directions of a delegation handoff cannot wait
// on each other. Suspension is only ever safe because the reply is sampled
// after the wait: resume re-enters admission, and blocks while an overlapping
// scope is closed rather than publishing across the handoff it just enabled.
type ReplyGate struct {
	mu sync.Mutex

	active  map[string]int
	closing map[string]int
	changed chan struct{}
}

// ReadAdmission owns one admitted content reply. On success, Wrap transfers
// the admission to go-fuse and keeps it live through ReadResult.Done. Abort
// releases an operation that will not return a ReadResult.
type ReadAdmission struct {
	fuse.ReadResult

	gate *ReplyGate
	path string

	// op is the kernel request this reply belongs to (nil when the caller
	// never bound one). It is the handle SuspendOperation uses to find this
	// reply, and it is cleared under gate.mu when the reply is released.
	//
	// op, counted and revoked are guarded by gate.mu, not by mu: they are
	// the gate's view of this reply, and a concurrent handoff reads them
	// while deciding whether its subtree has drained. mu guards only the
	// wrapped result and its publication state machine.
	op      *operation
	counted bool
	revoked bool

	mu    sync.Mutex
	state readAdmissionState
}

// operationKey addresses one kernel request's publication record in a context.
type operationKey struct{}

// operation is a kernel request's publication identity inside the gate: the
// content replies it has admitted, and how deep it currently sits inside
// authority-bound waits. Every field is guarded by gate.mu.
type operation struct {
	gate       *ReplyGate
	admissions []*ReadAdmission
	depth      int
}

// Operation binds ctx to this gate's per-request publication record, so an
// authority-bound wait deeper in the stack can suspend whatever the request
// has already admitted. A frontend must install it before handing ctx to the
// client core; a context without one leaves suspension inert, which is exactly
// the behavior of a frontend that does not publish through the gate.
//
// Rebinding an already-bound context is a no-op: one kernel request is one
// publication identity no matter how many layers ask for it.
func (g *ReplyGate) Operation(ctx context.Context) context.Context {
	if g.operationFrom(ctx) != nil {
		return ctx
	}
	return context.WithValue(ctx, operationKey{}, &operation{gate: g})
}

// SuspendOperation implements the client core's operation-wait hook: it takes
// every content reply the request has admitted out of the handoff drain set
// for the duration of an authority-bound wait, and returns the resume that
// puts them back.
//
// The rule it enforces is the reason a handoff can drain at all: a request
// blocked on the authority cannot finish, so leaving it inside admission lets
// a foreign delegation recall and this mount's own release wait on each other
// forever. Suspending it is safe because the reply it eventually publishes is
// sampled AFTER the wait, so it belongs to the post-handoff view.
//
// Waits nest (a mutation that releases a delegation and then makes its own
// authority call): only the outermost resume re-enters admission. Every
// returned resume is idempotent. A request that holds no admission — every
// non-read FUSE op — suspends and resumes without touching gate state.
func (g *ReplyGate) SuspendOperation(ctx context.Context) func() {
	op := g.operationFrom(ctx)
	if op == nil {
		return nil
	}

	g.mu.Lock()
	op.depth++
	if op.depth == 1 {
		dropped := false
		for _, a := range op.admissions {
			if !a.counted {
				continue
			}
			a.counted = false
			g.dropActiveLocked(a.path)
			dropped = true
		}
		if dropped {
			g.signalLocked()
		}
	}
	g.mu.Unlock()

	resumed := false
	return func() {
		g.mu.Lock()
		defer g.mu.Unlock()
		if resumed {
			return
		}
		resumed = true
		op.depth--
		if op.depth > 0 {
			return
		}
		g.readmitLocked(ctx, op)
	}
}

// readmitLocked re-enters admission for every reply the operation still owns,
// blocking while any of those paths sits inside a closing handoff scope. That
// wait is the second half of the invariant: a reply must not reach the kernel
// after the handoff that superseded its view.
//
// A canceled kernel request stops waiting and stays OUT of admission, with its
// replies revoked. Re-entering unconditionally would re-block the drain, and
// publishing from outside admission would put an unaccounted reply on the
// wire; revoking lets the frontend answer EINTR for a request the kernel has
// already abandoned. It is called with g.mu held and returns with it held.
func (g *ReplyGate) readmitLocked(ctx context.Context, op *operation) {
	for {
		blocked := false
		for _, a := range op.admissions {
			if a.counted || a.revoked {
				continue
			}
			if g.blockedLocked(a.path) {
				blocked = true
				continue
			}
			if g.active == nil {
				g.active = make(map[string]int)
			}
			g.active[a.path]++
			a.counted = true
		}
		if !blocked {
			return
		}
		if ctx.Err() != nil {
			for _, a := range op.admissions {
				if !a.counted {
					a.revoked = true
				}
			}
			return
		}
		changed := g.changedLocked()
		g.mu.Unlock()
		select {
		case <-changed:
		case <-ctx.Done():
		}
		g.mu.Lock()
	}
}

// Revoked reports that this reply lost its place in the publication order: its
// request was canceled while suspended for an authority wait, and the gate can
// no longer prove the reply is not a pre-handoff view. The caller must abort it
// instead of publishing.
func (a *ReadAdmission) Revoked() bool {
	if a == nil {
		return false
	}
	a.gate.mu.Lock()
	defer a.gate.mu.Unlock()
	return a.revoked
}

func (g *ReplyGate) operationFrom(ctx context.Context) *operation {
	op, ok := ctx.Value(operationKey{}).(*operation)
	if !ok || op == nil || op.gate != g {
		return nil
	}
	return op
}

func (op *operation) forgetLocked(a *ReadAdmission) {
	for i, held := range op.admissions {
		if held != a {
			continue
		}
		last := len(op.admissions) - 1
		op.admissions[i] = op.admissions[last]
		op.admissions[last] = nil
		op.admissions = op.admissions[:last]
		return
	}
}

type readAdmissionState uint8

const (
	readAdmissionOpen readAdmissionState = iota
	readAdmissionWrapped
	readAdmissionFinished
)

// BeginRead enters content-reply admission for path. It waits only for a
// handoff whose scope contains path and returns the context error if the kernel
// request is canceled before admission.
//
// When ctx carries an Operation, the admission joins it and follows that
// request's suspensions. Admitting inside an already-suspended request yields
// an already-suspended reply, so "counted iff the owning request is running"
// holds for every admission the gate ever hands out.
func (g *ReplyGate) BeginRead(ctx context.Context, path string) (*ReadAdmission, error) {
	op := g.operationFrom(ctx)
	for {
		if err := ctx.Err(); err != nil {
			return nil, err
		}

		g.mu.Lock()
		if !g.blockedLocked(path) {
			admission := &ReadAdmission{gate: g, path: path, op: op}
			if op == nil || op.depth == 0 {
				if g.active == nil {
					g.active = make(map[string]int)
				}
				g.active[path]++
				admission.counted = true
			}
			if op != nil {
				op.admissions = append(op.admissions, admission)
			}
			g.mu.Unlock()
			return admission, nil
		}
		changed := g.changedLocked()
		g.mu.Unlock()

		select {
		case <-changed:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
}

// BeginHandoff closes reply admission for scope and waits for every admitted
// content reply in that subtree to reach ReadResult.Done. If ctx is canceled,
// the provisional close is removed before the error is returned.
//
// Replies suspended for an authority wait are not admitted and are not waited
// for: they cannot publish while the scope stays closed, and waiting for a
// request that is itself waiting on the authority is how a handoff deadlocks.
func (g *ReplyGate) BeginHandoff(ctx context.Context, scope string) error {
	if err := ctx.Err(); err != nil {
		return err
	}

	g.mu.Lock()
	if g.closing == nil {
		g.closing = make(map[string]int)
	}
	g.closing[scope]++

	for g.activeUnderLocked(scope) != 0 {
		changed := g.changedLocked()
		g.mu.Unlock()

		select {
		case <-changed:
		case <-ctx.Done():
			g.mu.Lock()
			g.removeClosingLocked(scope)
			g.signalLocked()
			g.mu.Unlock()
			return ctx.Err()
		}

		if err := ctx.Err(); err != nil {
			g.mu.Lock()
			g.removeClosingLocked(scope)
			g.signalLocked()
			g.mu.Unlock()
			return err
		}
		g.mu.Lock()
	}
	g.mu.Unlock()
	return nil
}

// EndHandoff reopens one successfully closed scope. An unmatched call is a
// programming error: silently reopening a different boundary would violate
// the handoff proof.
func (g *ReplyGate) EndHandoff(scope string) {
	g.mu.Lock()
	defer g.mu.Unlock()
	g.removeClosingLocked(scope)
	g.signalLocked()
}

// Wrap transfers this admission to result. go-fuse calls Done after publishing
// the read to the kernel; the gate is released only after the wrapped Done
// completes. Wrap must be called exactly once.
func (a *ReadAdmission) Wrap(result fuse.ReadResult) fuse.ReadResult {
	if result == nil {
		panic("fusefrontend: cannot wrap a nil read result")
	}
	a.mu.Lock()
	defer a.mu.Unlock()
	if a.state != readAdmissionOpen {
		panic("fusefrontend: read admission already wrapped")
	}
	a.ReadResult = result
	a.state = readAdmissionWrapped
	return a
}

// Abort releases an admission whose operation will not publish a ReadResult.
// It is safe to call more than once.
func (a *ReadAdmission) Abort() {
	if a == nil {
		return
	}
	a.mu.Lock()
	switch a.state {
	case readAdmissionOpen:
		a.state = readAdmissionFinished
		a.mu.Unlock()
		a.release()
	case readAdmissionFinished:
		a.mu.Unlock()
	case readAdmissionWrapped:
		a.mu.Unlock()
		panic("fusefrontend: cannot abort a published read result")
	default:
		a.mu.Unlock()
		panic("fusefrontend: invalid read admission state")
	}
}

// Done implements fuse.ReadResult. The deferred release preserves the gate
// invariant even if a custom wrapped ReadResult panics during cleanup.
func (a *ReadAdmission) Done() {
	a.mu.Lock()
	switch a.state {
	case readAdmissionWrapped:
		result := a.ReadResult
		a.state = readAdmissionFinished
		a.mu.Unlock()
		defer a.release()
		result.Done()
	case readAdmissionFinished:
		a.mu.Unlock()
	case readAdmissionOpen:
		a.mu.Unlock()
		panic("fusefrontend: unwrapped read admission completed")
	default:
		a.mu.Unlock()
		panic("fusefrontend: invalid read admission state")
	}
}

func (a *ReadAdmission) release() {
	g := a.gate
	g.mu.Lock()
	if a.op != nil {
		a.op.forgetLocked(a)
		a.op = nil
	}
	if a.counted {
		a.counted = false
		g.dropActiveLocked(a.path)
	}
	g.signalLocked()
	g.mu.Unlock()
}

// dropActiveLocked removes one counted admission for path. It releases the
// mutex before the underflow panic so a recovering process does not inherit a
// wedged gate; callers must therefore not hold a deferred unlock.
func (g *ReplyGate) dropActiveLocked(path string) {
	count := g.active[path]
	if count <= 0 {
		g.mu.Unlock()
		panic("fusefrontend: read admission underflow")
	}
	if count == 1 {
		delete(g.active, path)
	} else {
		g.active[path] = count - 1
	}
}

func (g *ReplyGate) blockedLocked(path string) bool {
	for scope := range g.closing {
		if pathWithinScope(path, scope) {
			return true
		}
	}
	return false
}

func (g *ReplyGate) activeUnderLocked(scope string) int {
	total := 0
	for path, count := range g.active {
		if pathWithinScope(path, scope) {
			total += count
		}
	}
	return total
}

func (g *ReplyGate) removeClosingLocked(scope string) {
	count := g.closing[scope]
	if count <= 0 {
		panic("fusefrontend: unmatched handoff end")
	}
	if count == 1 {
		delete(g.closing, scope)
	} else {
		g.closing[scope] = count - 1
	}
}

func (g *ReplyGate) changedLocked() <-chan struct{} {
	if g.changed == nil {
		g.changed = make(chan struct{})
	}
	return g.changed
}

func (g *ReplyGate) signalLocked() {
	if g.changed != nil {
		close(g.changed)
		g.changed = nil
	}
}

func pathWithinScope(path, scope string) bool {
	return scope == "" || path == scope || strings.HasPrefix(path, scope+"/")
}
