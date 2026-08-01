package workfs

// Managed write-back delegations: the authority-side grant decision, the
// peer-visible scope state, and the recovery transitions (rebind/discard).
// A delegation is a CheckoutChange grant bound to a mount write-back stream
// (WritebackID). It differs from a plain coordination checkout exactly
// where the write-back contract requires it to:
//
//   - holder death flips it to recovery-required instead of releasing it
//     (the holder may have unshipped acknowledged state);
//   - it is never force-transferred;
//   - the stream's flush watermark + digest survive session-generation
//     changes and rebind to the recovering mount.

import (
	"errors"
	"sort"
	"strings"

	"github.com/steerlabs/portablefs/vcs/internal/errnos"
	"github.com/steerlabs/portablefs/vcs/internal/pfc2"
	"github.com/steerlabs/portablefs/vcs/internal/wal"
)

var (
	ErrDelegationPrepareNotHeld = errors.New("vcs: delegation prepare does not name the caller's live grant")
	errPreparedPinsAlreadyHeld  = errors.New("vcs: prepared open pins already held")
)

const maxDelegationPreparePaths = 127 // one pin per path within PFJ3's 128-control row ceiling

// ManagedPrepareDelegationPins resolves and durably pins an ordered path
// batch while the caller's exact write-back delegation remains held. The
// grant freezes peer namespace changes and the client handoff barrier freezes
// its own opens/renames, so a lost reply may safely rerun this idempotent
// decision and reconstruct the same aligned inode vector.
func (fs *FS) ManagedPrepareDelegationPins(
	ref pfc2.SessionRef,
	scope string,
	epoch string,
	paths []string,
) ([]uint64, error) {
	if fs.managed == nil {
		return nil, ErrNotManaged
	}
	if err := pfc2.ValidateCanonicalPath(scope); err != nil {
		return nil, invalidMutation("delegation prepare scope: %v", err)
	}
	if err := pfc2.Epoch(epoch).Validate(); err != nil {
		return nil, invalidMutation("delegation prepare epoch: %v", err)
	}
	if len(paths) == 0 || len(paths) > maxDelegationPreparePaths {
		return nil, invalidMutation("invalid delegation prepare shape")
	}
	canonicalScope := scope
	// Authenticate ownership before any lazy-base hydration. The final
	// reserved-state check inside commitEntryDynamic remains authoritative
	// against a concurrent release/fence; this applied-state check prevents
	// a merely attached non-holder from driving path hydration work.
	appliedGrant, held := fs.managed.applied.CheckoutAt(canonicalScope)
	if !held || appliedGrant.Holder != ref || string(appliedGrant.Epoch) != epoch ||
		appliedGrant.WritebackID == "" || appliedGrant.Recovery {
		return nil, ErrDelegationPrepareNotHeld
	}
	canonicalPaths := make([]string, len(paths))
	for i, candidate := range paths {
		if err := pfc2.ValidateCanonicalPath(candidate); err != nil {
			return nil, invalidMutation("delegation prepare open path: %v", err)
		}
		canonical := candidate
		if !pathWithin(canonical, canonicalScope) {
			return nil, invalidMutation("open path %q is outside delegation %q", candidate, canonicalScope)
		}
		canonicalPaths[i] = canonical
		// Hydrate every lazy-base binding outside fs.mu. The held grant makes
		// the later locked re-resolution stable against peer namespace work.
		if err := fs.withReadPath(canonical, func(*inode) error { return nil }); err != nil {
			return nil, err
		}
	}

	inos := make([]uint64, len(canonicalPaths))
	build := func() ([]pfc2.Record, error) {
		grant, held := fs.managed.reserved.CheckoutAt(canonicalScope)
		if !held || grant.Holder != ref || string(grant.Epoch) != epoch ||
			grant.WritebackID == "" || grant.Recovery {
			return nil, ErrDelegationPrepareNotHeld
		}

		uniqueNew := make(map[uint64]struct{}, len(canonicalPaths))
		for i, openPath := range canonicalPaths {
			node := fs.resolve(openPath)
			if node == nil || node.ino == 0 || fs.pendingReaps[node.ino] != 0 {
				return nil, ErrPinTargetGone
			}
			inos[i] = node.ino
			if !fs.managed.reserved.HasPin(ref, node.ino) {
				uniqueNew[node.ino] = struct{}{}
			}
		}
		if len(uniqueNew) == 0 {
			return nil, errPreparedPinsAlreadyHeld
		}
		ordered := make([]uint64, 0, len(uniqueNew))
		for ino := range uniqueNew {
			ordered = append(ordered, ino)
		}
		sort.Slice(ordered, func(i, j int) bool { return ordered[i] < ordered[j] })
		records := make([]pfc2.Record, 0, len(ordered))
		for _, ino := range ordered {
			records = append(records, pfc2.Record{
				Kind: pfc2.KindOpenPinChange,
				OpenPinChange: &pfc2.OpenPinChange{
					Session: ref,
					Ino:     ino,
				},
			})
		}
		return records, nil
	}
	if _, err := fs.commitEntryDynamic(build, ""); err != nil {
		if errors.Is(err, errPreparedPinsAlreadyHeld) {
			return append([]uint64(nil), inos...), nil
		}
		return nil, classifyCoordinationCommit(err)
	}
	return append([]uint64(nil), inos...), nil
}

func pathWithin(candidate, scope string) bool {
	return candidate == scope || strings.HasPrefix(candidate, scope+"/")
}

// ManagedDelegationDecide observes the staged checkout table under the ONE
// fs.mu reservation and journals either the granted delegation (a
// CheckoutChange grant carrying the stream binding) or the control-only
// EBUSY rejection row. The volatile adaptive-policy inputs (recent peer
// activity, contention windows, snapshot bounds) are the protocol layer's
// decision BEFORE this call; this is the durable overlap decision.
func (fs *FS) ManagedDelegationDecide(env *wal.Envelope, path, writebackID string) (CoordinationDecision, error) {
	if fs.managed == nil {
		return CoordinationDecision{}, ErrNotManaged
	}
	ref, err := managedSessionRef(env)
	if err != nil {
		return CoordinationDecision{}, err
	}
	canonical := cleanPath(path)
	if canonical == "" {
		return CoordinationDecision{}, invalidMutation("delegation path is empty/root")
	}
	key := pfc2.ExactKey{Session: ref, Slot: env.Slot, SlotSeq: env.SlotSeq}
	probe := &pfc2.CheckoutChange{Key: key, Op: pfc2.CheckoutGrant, Path: canonical, Epoch: pfc2.FirstEpoch, WritebackID: writebackID}
	key.RequestHash = probe.RequestHash()
	if err := envHashMatches(env, key.RequestHash); err != nil {
		return CoordinationDecision{}, err
	}
	decision := CoordinationDecision{}
	build := func() ([]pfc2.Record, error) {
		if overlaps := fs.managed.reserved.OverlappingCheckouts(canonical); len(overlaps) != 0 {
			decision.Status = errnos.EBUSY
			return decideRejection(key, errnos.EBUSY), nil
		}
		epoch := fs.managed.reserved.NextCheckoutEpoch()
		rec := &pfc2.CheckoutChange{Key: key, Op: pfc2.CheckoutGrant, Path: canonical, Epoch: epoch, WritebackID: writebackID}
		rec.Key.RequestHash = rec.RequestHash()
		decision.Epoch = string(epoch)
		return []pfc2.Record{{Kind: pfc2.KindCheckoutChange, CheckoutChange: rec}}, nil
	}
	if _, err := fs.commitEntryDynamic(build, ""); err != nil {
		return CoordinationDecision{}, classifyCoordinationCommit(err)
	}
	return decision, nil
}

// DelegationRequestHash is the canonical fingerprint of a delegation-acquire
// request (the grant fingerprint with the stream binding folded in).
func DelegationRequestHash(env *wal.Envelope, path, writebackID string) ([]byte, error) {
	ref, err := managedSessionRef(env)
	if err != nil {
		return nil, err
	}
	rec := &pfc2.CheckoutChange{
		Key: pfc2.ExactKey{Session: ref, Slot: env.Slot, SlotSeq: env.SlotSeq},
		Op:  pfc2.CheckoutGrant, Path: cleanPath(path), Epoch: pfc2.FirstEpoch, WritebackID: writebackID,
	}
	h := rec.RequestHash()
	return h[:], nil
}

// WritebackScope names one delegation a recovering stream claims.
type WritebackScope struct {
	Path  string
	Epoch string
}

// WritebackConflict is one typed recovery conflict.
type WritebackConflict struct {
	Path  string
	Epoch string
	Kind  string // SCOPE_MISSING, HOLDER_CHANGED, DIGEST_MISMATCH
}

// WritebackMark is a recovering stream's claimed durable position: the legacy
// single-stream pair plus each lane's independent one. Every field must match
// the authority's ledger exactly or the rebind is DIGEST_MISMATCH — verifying
// only the legacy pair would leave a stream born after the lane boundary
// (legacy watermark permanently 0) effectively unverified.
type WritebackMark struct {
	Through     uint64
	Digest      [32]byte
	NSThrough   uint64
	NSDigest    [32]byte
	DataThrough uint64
	DataDigest  [32]byte
}

// normalized is the mark's CANONICAL form: a lane that has applied nothing
// carries no digest.
//
// It exists because "the chain digest at watermark zero" is a constant
// (digestZero), not an absence, and both sides may legitimately spell it either
// way — the client rebuilding a lane's digest from an empty WAL prefix produces
// the constant, while a ledger that has never seen the lane produces the zero
// value. Comparing the raw structs would call those two spellings of "nothing
// applied" a divergence, which is exactly the false DIGEST_MISMATCH a rebind
// must never invent.
func (m WritebackMark) normalized() WritebackMark {
	if m.Through == 0 {
		m.Digest = [32]byte{}
	}
	if m.NSThrough == 0 {
		m.NSDigest = [32]byte{}
	}
	if m.DataThrough == 0 {
		m.DataDigest = [32]byte{}
	}
	return m
}

// ClaimsNothing reports a mark that names no durable position in any lane.
func (m WritebackMark) ClaimsNothing() bool {
	return m.Through == 0 && m.NSThrough == 0 && m.DataThrough == 0
}

func evaluateWritebackRebind(
	state *pfc2.State,
	writebackID string,
	scopes []WritebackScope,
	mark WritebackMark,
) ([]WritebackConflict, map[pfc2.SessionRef]bool) {
	paths := make([]string, len(scopes))
	for i, scope := range scopes {
		paths[i] = cleanPath(scope.Path)
	}
	view := state.WritebackRebindSnapshot(writebackID, paths)
	conflicts := make([]WritebackConflict, 0, len(scopes)+1)
	if view.StreamExists {
		durable := WritebackMark{
			Through: view.Stream.Through, Digest: view.Stream.Digest,
			NSThrough: view.Stream.NSThrough, NSDigest: view.Stream.NSDigest,
			DataThrough: view.Stream.DataThrough, DataDigest: view.Stream.DataDigest,
		}
		if durable.normalized() != mark.normalized() {
			conflicts = append(conflicts, WritebackConflict{Kind: "DIGEST_MISMATCH"})
		}
	} else if !mark.ClaimsNothing() {
		conflicts = append(conflicts, WritebackConflict{Kind: "DIGEST_MISMATCH"})
	}
	holders := make(map[pfc2.SessionRef]bool)
	for i, scope := range scopes {
		canonical := paths[i]
		grant, ok := view.Scopes[i], view.ScopeExists[i]
		switch {
		case !ok:
			conflicts = append(conflicts, WritebackConflict{
				Path: canonical, Epoch: scope.Epoch, Kind: "SCOPE_MISSING",
			})
		case string(grant.Epoch) != scope.Epoch || grant.WritebackID != writebackID:
			conflicts = append(conflicts, WritebackConflict{
				Path: canonical, Epoch: scope.Epoch, Kind: "HOLDER_CHANGED",
			})
		default:
			holders[grant.Holder] = true
		}
	}
	return conflicts, holders
}

// ManagedWritebackConflicts revalidates a rejected rebind against one coherent
// snapshot of the durable applied state. It is read-only: duplicate exact
// replies use it solely to restore typed proof omitted from PFC2's deliberately
// compact frozen Outcome. A stream watermark only advances, so a stale
// watermark/digest rejection remains DIGEST_MISMATCH after a lost reply.
func (fs *FS) ManagedWritebackConflicts(
	writebackID string,
	scopes []WritebackScope,
	mark WritebackMark,
) ([]WritebackConflict, error) {
	if fs.managed == nil {
		return nil, ErrNotManaged
	}
	conflicts, _ := evaluateWritebackRebind(fs.managed.applied, writebackID, scopes, mark)
	return conflicts, nil
}

// reservedDelegationBlocks reports whether the reservation-order projection
// contains a write-back delegation overlapping any path. The caller MUST hold
// fs.mu: this helper is used only inside commitEntryDynamic* decision
// callbacks, so the observation and the row chosen from it are one atomic
// journal reservation.
//
// self is non-nil for read-like acquisitions such as POSIX locks: that
// session's own live grant may serve the operation. Exact tree mutations pass
// nil because write-through must never run under even the caller's own grant.
func (fs *FS) reservedDelegationBlocks(self *pfc2.SessionRef, paths ...string) bool {
	for _, candidate := range paths {
		if candidate == "" {
			continue
		}
		for _, grant := range fs.managed.reserved.OverlappingCheckouts(cleanPath(candidate)) {
			if grant.WritebackID == "" {
				continue
			}
			if self != nil && grant.Holder == *self && !grant.Recovery {
				continue
			}
			return true
		}
	}
	return false
}

// ManagedWritebackRebind atomically claims a parked stream for the caller's
// session: it verifies the stream's durable watermark + digest against the
// client's claim, fences the dead holder generation when it is still live
// (the claim itself proves the mount identity moved on), and rebinds every
// recovery scope to the caller — all in ONE journal row group. Conflicts are
// returned typed; nothing partial commits.
func (fs *FS) ManagedWritebackRebind(env *wal.Envelope, envHash []byte, writebackID string, scopes []WritebackScope, mark WritebackMark) ([]WritebackConflict, error) {
	if fs.managed == nil {
		return nil, ErrNotManaged
	}
	ref, err := managedSessionRef(env)
	if err != nil {
		return nil, err
	}
	if err := envHashExact(env, envHash); err != nil {
		return nil, err
	}
	key := pfc2.ExactKey{Session: ref, Slot: env.Slot, SlotSeq: env.SlotSeq}
	copy(key.RequestHash[:], envHash)
	var conflicts []WritebackConflict
	build := func() ([]pfc2.Record, error) {
		var holders map[pfc2.SessionRef]bool
		conflicts, holders = evaluateWritebackRebind(
			fs.managed.reserved, writebackID, scopes, mark,
		)
		for holder := range holders {
			if holder == ref {
				delete(holders, holder)
			}
		}
		if len(conflicts) > 0 {
			// The identity is consumed durably with the definite rejection;
			// the client surfaces the typed conflicts and never re-guesses.
			return decideRejection(key, errnos.EIO), nil
		}
		records := []pfc2.Record{{Kind: pfc2.KindExactOutcome, ExactOutcome: &pfc2.ExactOutcome{
			Key: key, Outcome: pfc2.Outcome{},
		}}}
		// Fence still-live dead-holder generations first: the rebind claim
		// proves the mount identity restarted, and a zombie holder must not
		// flush after its scopes move.
		refs := make([]pfc2.SessionRef, 0, len(holders))
		for h := range holders {
			refs = append(refs, h)
		}
		sort.Slice(refs, func(i, j int) bool {
			if refs[i].SessionID != refs[j].SessionID {
				return refs[i].SessionID < refs[j].SessionID
			}
			return refs[i].Generation < refs[j].Generation
		})
		for _, h := range refs {
			if info, ok := fs.managed.reserved.Session(h.SessionID); ok && !info.Terminal && info.Ref == h {
				records = append(records, pfc2.Record{Kind: pfc2.KindSessionTerminal, SessionTerminal: &pfc2.SessionTerminal{
					Session: h, Reason: pfc2.TerminalAdminFence,
				}})
			}
		}
		for _, sc := range scopes {
			records = append(records, pfc2.Record{Kind: pfc2.KindCheckoutChange, CheckoutChange: &pfc2.CheckoutChange{
				Op: pfc2.CheckoutRebind, Path: cleanPath(sc.Path), Epoch: pfc2.Epoch(sc.Epoch),
				WritebackID: writebackID, NewHolder: ref,
			}})
		}
		return records, nil
	}
	if _, err := fs.commitEntryDynamic(build, ""); err != nil {
		return nil, classifyCoordinationCommit(err)
	}
	return conflicts, nil
}

// ManagedWritebackDiscard releases a parked stream's recovery scopes as an
// audited data-loss decision: one journal row carrying the identity outcome
// plus a CheckoutDiscard per scope. An EMPTY scope list means "every grant
// bound to writebackID": the recovering mount proved no unshipped mutation
// depends on any remaining authority grant. That includes both an acquire
// orphaned before its DELEGATION frame and a fully-drained grant whose local
// RELEASE frame was synced before Checkin; either remainder is released
// losslessly. A still-live zombie holder generation is fenced in the same
// journal group first (only the mount owning the store flock can compute this
// writebackID, so the claim proves the mount identity moved on).
func (fs *FS) ManagedWritebackDiscard(env *wal.Envelope, envHash []byte, writebackID string, scopes []WritebackScope) error {
	if fs.managed == nil {
		return ErrNotManaged
	}
	ref, err := managedSessionRef(env)
	if err != nil {
		return err
	}
	if err := envHashExact(env, envHash); err != nil {
		return err
	}
	key := pfc2.ExactKey{Session: ref, Slot: env.Slot, SlotSeq: env.SlotSeq}
	copy(key.RequestHash[:], envHash)
	build := func() ([]pfc2.Record, error) {
		targets := scopes
		if len(targets) == 0 {
			for _, v := range fs.managed.reserved.StreamCheckouts(writebackID) {
				targets = append(targets, WritebackScope{Path: v.Path, Epoch: string(v.Epoch)})
			}
		}
		holders := map[pfc2.SessionRef]bool{}
		var discards []pfc2.Record
		for _, sc := range targets {
			canonical := cleanPath(sc.Path)
			g, ok := fs.managed.reserved.CheckoutAt(canonical)
			if !ok {
				continue // already resolved; discard stays idempotent
			}
			if string(g.Epoch) != sc.Epoch || g.WritebackID != writebackID {
				return nil, errors.New("vcs: discard names a scope that is not this stream's state")
			}
			if !g.Recovery && len(scopes) > 0 {
				return nil, errors.New("vcs: discard names a scope that is not this stream's recovery state")
			}
			if !g.Recovery && g.Holder != ref {
				holders[g.Holder] = true
			}
			discards = append(discards, pfc2.Record{Kind: pfc2.KindCheckoutChange, CheckoutChange: &pfc2.CheckoutChange{
				Op: pfc2.CheckoutDiscard, Path: canonical, Epoch: pfc2.Epoch(sc.Epoch), WritebackID: writebackID,
			}})
		}
		refs := make([]pfc2.SessionRef, 0, len(holders))
		for h := range holders {
			refs = append(refs, h)
		}
		sort.Slice(refs, func(i, j int) bool {
			if refs[i].SessionID != refs[j].SessionID {
				return refs[i].SessionID < refs[j].SessionID
			}
			return refs[i].Generation < refs[j].Generation
		})
		records := []pfc2.Record{{Kind: pfc2.KindExactOutcome, ExactOutcome: &pfc2.ExactOutcome{
			Key: key, Outcome: pfc2.Outcome{},
		}}}
		// Fences apply before the discards: terminalization flips a live
		// zombie holder's grants to recovery-required, which
		// CheckoutDiscard requires.
		for _, h := range refs {
			if info, ok := fs.managed.reserved.Session(h.SessionID); ok && !info.Terminal && info.Ref == h {
				records = append(records, pfc2.Record{Kind: pfc2.KindSessionTerminal, SessionTerminal: &pfc2.SessionTerminal{
					Session: h, Reason: pfc2.TerminalAdminFence,
				}})
			}
		}
		return append(records, discards...), nil
	}
	if _, err := fs.commitEntryDynamic(build, ""); err != nil {
		return classifyCoordinationCommit(err)
	}
	return nil
}

// ManagedDelegationsOverlapping reports the delegation grants (stream-bound
// checkouts) whose subtree overlaps path — the peer gate's decision input.
func (fs *FS) ManagedDelegationsOverlapping(path string) []pfc2.CheckoutView {
	if fs.managed == nil {
		return nil
	}
	overlaps := fs.managed.applied.OverlappingCheckouts(cleanPath(path))
	out := overlaps[:0]
	for _, v := range overlaps {
		if v.WritebackID != "" {
			out = append(out, v)
		}
	}
	return out
}
