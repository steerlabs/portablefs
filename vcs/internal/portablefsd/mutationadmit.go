package portablefsd

// The daemon's pre-lock mutation admission point.
//
// Every path-bearing NAMESPACE mutation resolves its lane, its metadata-lane
// backpressure and its delegation transition HERE — at the single request
// dispatch site, before any handler touches a.nsMu, a name stripe or a handle
// gate. The data plane has done this since the credit controller landed
// (attach.admitWrite); this is the other half, and together they establish ONE
// global lock order for the whole daemon:
//
//	delegation transition claim → a.nsMu → name stripes / handle gates → a.mu
//
// Why it must be global rather than per-lane. As long as metadata mutations
// took a.nsMu and THEN the transition claim, a write could not safely hold its
// claim across a.nsMu — the two orders closed a cycle — so the write's
// authority lane had to release its grant and then let go of the exclusion,
// which left a window in which a concurrent acquisition installed a fresh grant
// and the write, already inside a.nsMu.RLock and its handle lock, waited for
// that acquisition's claim and then DRAINED its grant. Go's RWMutex is
// writer-preferring, so the next rename, remove or reclaim parked behind that
// wait and every lookup, getattr and read behind it: one slow uplink became a
// namespace-wide stall on paths with nothing to do with the backlog.
//
// With the order global, nothing that holds a.nsMu ever waits for a claim, the
// claim can be held across the locks, and the locked region becomes what it
// must be: a pure CHECK. clientcore.beginAuthorityMutation verifies the token
// covers the operands the handler actually reached and answers ErrLaneChanged
// otherwise, which unwinds to here with every lock released.
//
// The operand paths are resolved from the item registry (a.mu only, never
// blocking). A rename can move them between this resolution and the handler's
// own resolution under a.nsMu; the handler then reaches an operand the token
// does not cover, unwinds, and re-admits against the moved path. That is the
// same two-pass shape the write path already uses, and its second pass is the
// terminator: it resolves the authority lane unconditionally, which is not a
// claim about a grant and has nothing left for a recall to invalidate.

import (
	"context"

	"github.com/steerlabs/portablefs/vcs/internal/clientcore"
	"github.com/steerlabs/portablefs/vcs/internal/pfslocal"
)

// admitMutation is the pre-lock classifier for one namespace-mutating request.
//
// It returns the operation context, a settle that hands back everything the
// classification took (always non-nil, must be called on every exit path), an
// errno for a definite refusal, and whether the request was classified at all.
//
// classified is what makes the dispatcher's unwind loop safe: only a classified
// request can produce errnoLaneChanged, so an unclassified handler's result is
// final on the first pass and can never spin.
//
// Requests that cannot reach the write-back WAL are passed through
// unclassified, so the handler produces its own exact errno instead of
// inheriting one from admission: a non-mutating request, an operand that does
// not resolve, an operand owned by a local-directory graft (machine-local, no
// delegation, no stream bytes), and a detached or volume-less attach.

// admitRequest is the daemon's ONE pre-lock admission point, for the data lane
// and the namespace lane alike.
//
// Having two — the dispatcher's for metadata and attach.write's own for data —
// was not a duplication but an ORDER INVERSION. lockFrontendRequest marks a
// write as name-mutating, so a write held a frontend name-stripe mirror while
// its admission waited for a transition claim, while a namespace mutation held a
// conflicting claim (taken in phase 1) and waited for that same stripe. The two
// deadlocked until the operation deadline expired and both were answered EINTR.
//
// One point, one phase, one order: every claim in the daemon is taken before
// every frontend lock.
//
// It is also where a SIZE mutation takes the item-scoped token that orders it
// against a pinned kernel refresh (refreshpin.go). The token is taken here, and
// only here, for the same reason everything else unbounded is: a waiter must
// hold no frontend lock, because the thing it waits for is a syscall whose own
// upcall needs those locks to complete. It is taken AFTER the lane admission
// rather than around it — an admission park is unbounded, and a token held
// across one would refuse every refresh on the item for the length of a
// backlog it has nothing to do with.
func (a *attach) admitRequest(
	ctx context.Context,
	body any,
	forceAuthority bool,
) (context.Context, func(), int32, bool) {
	opCtx, settle, eno, classified := a.admitLane(ctx, body, forceAuthority)
	if eno != 0 {
		return opCtx, settle, eno, classified
	}
	release, reserveEno := a.reserveSizeMutationForRequest(opCtx, body)
	if reserveEno != 0 {
		settle()
		return opCtx, func() {}, reserveEno, classified
	}
	if release != nil {
		lane := settle
		settle = func() {
			// Order mirrors acquisition: the token was taken after the lane and
			// is given back before it, so nothing can observe a request holding
			// the lane's claim without its size token.
			release()
			lane()
		}
	}
	return opCtx, settle, 0, classified
}

// admitLane resolves one request's LANE — the data-plane credit grant or the
// namespace-plane transition claim. It is the half of admission that can block
// on the uplink, and it is separated from the size token above it so the token
// is never held across that park.
func (a *attach) admitLane(
	ctx context.Context,
	body any,
	forceAuthority bool,
) (context.Context, func(), int32, bool) {
	if req, ok := body.(*pfslocal.WriteRequest); ok {
		if barrier := a.testMutationAdmissionBarrier; barrier != nil {
			barrier(ctx)
		}
		return a.admitWrite(ctx, req, forceAuthority)
	}
	return a.admitMutation(ctx, body, forceAuthority)
}

func (a *attach) admitMutation(
	ctx context.Context,
	body any,
	forceAuthority bool,
) (context.Context, func(), int32, bool) {
	noop := func() {}
	if barrier := a.testMutationAdmissionBarrier; barrier != nil {
		// Stands in for the one thing this step can do that no frontend lock may
		// span: a metadata- or credit-lane park. Tests hold it to prove that
		// nothing else is held while admission waits.
		barrier(ctx)
	}
	// PROVENANCE IS DECIDED HERE, ONCE, AND THEN CARRIED.
	//
	// The verdict is frozen into the operation context for EVERY size-bearing
	// setattr — including the ones this classifier hands on to ordinary
	// admission. Freezing only the internal ones would leave the handler free to
	// re-derive an answer for the rest, and the direction that must be
	// impossible is the one that turns the daemon's own refresh into an
	// authority mutation: a request that was waved past admission because it
	// would never reach the authority must not be able to reach it later. See
	// refreshVerdictKey.
	if verdict, isSizeSet := a.classifyRefreshRequest(body); isSizeSet {
		ctx = withRefreshVerdict(ctx, verdict)
		if verdict.class != refreshClassApplication {
			// DAEMON-ORIGINATED, not application-originated. This is the setattr
			// upcall of a kernel-state refresh this daemon is issuing through its own
			// mount (coherence_refresh.go): the handler consumes it, it never reaches
			// the authority, and it appends nothing to the write-back stream.
			//
			// It must bypass admission for two independent reasons, and the second is
			// a correctness one. Pacing it is MEANINGLESS — it publishes state the
			// authority has already applied, so it neither caused the metadata backlog
			// nor can help drain it, exactly like an authority-lane mutation. And
			// pacing it is UNSAFE — an admission park is unbounded relative to the
			// syscall that produced the upcall, and the longer the handler is held
			// away from its marker the longer the window in which some other rule
			// could decide this is an application truncate. Provenance is settled
			// here, once, before anything can wait.
			return ctx, noop, 0, false
		}
	}
	vol, eno := a.volOrErr()
	if eno != 0 {
		// The handler answers a detached/failing attach on its own terms.
		return ctx, noop, 0, false
	}
	paths, nodes, ok := a.mutationOperands(body)
	if !ok || len(paths) == 0 {
		return ctx, noop, 0, false
	}
	for _, p := range paths {
		if a.localDirFor(p) != "" {
			// A graft operand is served by the host filesystem: no delegation
			// can cover it and it consumes no stream budget, so classifying it
			// would make a machine-local operation wait on a remote uplink.
			return ctx, noop, 0, false
		}
	}
	opCtx, settle, err := vol.AdmitMutation(
		ctx, a.mutationIntent(body), nodes, forceAuthority, paths...,
	)
	if err != nil {
		settle()
		return ctx, noop, mutationAdmissionErrno(err), true
	}
	return opCtx, settle, 0, true
}

// mutationAdmissionErrno maps a refused pre-lock mutation admission to the
// errno the daemon replies. It is deliberately the SAME mapping the data lane
// uses (creditErrno): ENOSPC only for an operation this store can never fit, a
// far end that stopped answering is EIO, a cancelled request is EINTR. The two
// lanes must not disagree about what backpressure looks like to an application.
func mutationAdmissionErrno(err error) int32 { return creditErrno(err) }

// mutationIntent names what a request IS, so the classifier can force the
// authority lane for the mutations whose diversion is SEMANTIC rather than
// path-shaped (clientcore.MutationIntent). Without it a link, an
// unlink-while-open, a rename over an open destination or a setattr on a
// hard-linked inode classifies from path coverage, resolves LaneDelegated, and
// the handler then discovers the diversion inside a.nsMu and the name stripes —
// where the release it implies is the drain this whole admission point exists to
// hoist out.
//
// A directory remove is deliberately MutationOther: rmdir has no orphan
// protocol and no alias fan-out, so nothing about it diverts.
//
// The roles are resolved from the item registry under a.mu only, never blocking.
// A node the registry does not hold yet is nil, which is the honest answer — the
// classifier then relies on path coverage and, if the handler discovers the
// diversion anyway, the operation unwinds and re-admits.
func (a *attach) mutationIntent(body any) clientcore.MutationIntent {
	child := func(dir pfslocal.Item, name []byte) *clientcore.NodeState {
		rec, eno := a.item(dir)
		if eno != 0 {
			return nil
		}
		p, eno := cleanChild(rec.path, name)
		if eno != 0 {
			return nil
		}
		return a.nodeAt(p)
	}
	switch req := body.(type) {
	case *pfslocal.HardLinkRequest:
		return clientcore.MutationIntent{Kind: clientcore.MutationLink}
	case *pfslocal.RemoveRequest:
		if req.Directory {
			return clientcore.MutationIntent{Kind: clientcore.MutationOther}
		}
		return clientcore.MutationIntent{
			Kind:   clientcore.MutationUnlink,
			Target: child(req.Dir, req.Name),
		}
	case *pfslocal.RenameRequest:
		return clientcore.MutationIntent{
			Kind:   clientcore.MutationRename,
			Source: child(req.FromDir, req.FromName),
			Target: child(req.ToDir, req.ToName),
		}
	case *pfslocal.SetAttrRequest:
		var target *clientcore.NodeState
		if rec, eno := a.item(req.Item); eno == 0 {
			target = rec.state
		}
		return clientcore.MutationIntent{
			Kind:   clientcore.MutationSetattr,
			Target: target,
		}
	}
	return clientcore.MutationIntent{Kind: clientcore.MutationOther}
}

// mutationOperands resolves — without any namespace lock — the operand paths
// and node identities one request will mutate.
//
// The second return is the node set whose hard-link aliases must join the
// transition claim: a request addressed to an Item carries an inode whose other
// spellings are just as exclusive as the one named here.
//
// ok is false for every request that is not a path-bearing namespace mutation,
// and for one whose operands cannot be resolved right now — the handler answers
// that on its own terms under the locks.
func (a *attach) mutationOperands(body any) ([]string, []*clientcore.NodeState, bool) {
	switch req := body.(type) {
	case *pfslocal.CreateRequest:
		return a.childOperand(req.Dir, req.Name)
	case *pfslocal.MkdirRequest:
		return a.childOperand(req.Dir, req.Name)
	case *pfslocal.SymlinkRequest:
		return a.childOperand(req.Dir, req.Name)
	case *pfslocal.RemoveRequest:
		return a.childOperand(req.Dir, req.Name)
	case *pfslocal.RenameRequest:
		from, fromNodes, ok := a.childOperand(req.FromDir, req.FromName)
		if !ok {
			return nil, nil, false
		}
		to, toNodes, ok := a.childOperand(req.ToDir, req.ToName)
		if !ok {
			return nil, nil, false
		}
		// Source first: its governing scope decides the lane, and a
		// destination-only grant is just as exclusive, so both are claimed and
		// both leave delegated mode together.
		return append(from, to...), append(fromNodes, toNodes...), true
	case *pfslocal.HardLinkRequest:
		target, nodes, ok := a.itemOperand(req.Item)
		if !ok {
			return nil, nil, false
		}
		link, linkNodes, ok := a.childOperand(req.Dir, req.Name)
		if !ok {
			return nil, nil, false
		}
		return append(target, link...), append(nodes, linkNodes...), true
	case *pfslocal.SetAttrRequest:
		return a.itemOperand(req.Item)
	case *pfslocal.XattrSetRequest:
		return a.itemOperand(req.Item)
	case *pfslocal.XattrRemoveRequest:
		return a.itemOperand(req.Item)
	}
	return nil, nil, false
}

// childOperand resolves dir/name to one operand path, together with the node
// already registered for that name when there is one.
//
// Supplying the node matters: hardlinkMutationTargets expands an inode's OTHER
// spellings, so a classifier that omits the node claims a narrower path set
// than the operation will reach under the locks, and the coverage check then
// unwinds every time instead of never.
func (a *attach) childOperand(
	dir pfslocal.Item,
	name []byte,
) ([]string, []*clientcore.NodeState, bool) {
	rec, eno := a.item(dir)
	if eno != 0 {
		return nil, nil, false
	}
	p, eno := cleanChild(rec.path, name)
	if eno != 0 {
		return nil, nil, false
	}
	var nodes []*clientcore.NodeState
	if n := a.nodeAt(p); n != nil {
		nodes = []*clientcore.NodeState{n}
	}
	return []string{p}, nodes, true
}

// nodeAt returns the node currently bound to p, if the registry holds one.
func (a *attach) nodeAt(p string) *clientcore.NodeState {
	a.mu.RLock()
	defer a.mu.RUnlock()
	if rec := a.paths[p]; rec != nil {
		return rec.state
	}
	return nil
}

// itemOperand resolves an Item-addressed request to its path and node.
func (a *attach) itemOperand(item pfslocal.Item) ([]string, []*clientcore.NodeState, bool) {
	rec, eno := a.item(item)
	if eno != 0 {
		return nil, nil, false
	}
	if rec.path == "" {
		return nil, nil, false
	}
	var nodes []*clientcore.NodeState
	if rec.state != nil {
		nodes = []*clientcore.NodeState{rec.state}
	}
	return []string{rec.path}, nodes, true
}
