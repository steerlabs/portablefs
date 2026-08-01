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
func (a *attach) admitMutation(
	ctx context.Context,
	body any,
	forceAuthority bool,
) (context.Context, func(), int32, bool) {
	noop := func() {}
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
	opCtx, settle, err := vol.AdmitMutation(ctx, nodes, forceAuthority, paths...)
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
