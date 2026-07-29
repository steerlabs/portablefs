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

	"github.com/steerlabs/portablefs/vcs/internal/errnos"
	"github.com/steerlabs/portablefs/vcs/internal/pfc2"
	"github.com/steerlabs/portablefs/vcs/internal/wal"
)

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

// ManagedWritebackRebind atomically claims a parked stream for the caller's
// session: it verifies the stream's durable watermark + digest against the
// client's claim, fences the dead holder generation when it is still live
// (the claim itself proves the mount identity moved on), and rebinds every
// recovery scope to the caller — all in ONE journal row group. Conflicts are
// returned typed; nothing partial commits.
func (fs *FS) ManagedWritebackRebind(env *wal.Envelope, envHash []byte, writebackID string, scopes []WritebackScope, through uint64, digest [32]byte) ([]WritebackConflict, error) {
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
		conflicts = conflicts[:0]
		if view, ok := fs.managed.reserved.StreamState(writebackID); ok {
			if view.Through != through || view.Digest != digest {
				conflicts = append(conflicts, WritebackConflict{Kind: "DIGEST_MISMATCH"})
			}
		} else if through != 0 {
			conflicts = append(conflicts, WritebackConflict{Kind: "DIGEST_MISMATCH"})
		}
		holders := map[pfc2.SessionRef]bool{}
		for _, sc := range scopes {
			canonical := cleanPath(sc.Path)
			g, ok := fs.managed.reserved.CheckoutAt(canonical)
			switch {
			case !ok:
				conflicts = append(conflicts, WritebackConflict{Path: canonical, Epoch: sc.Epoch, Kind: "SCOPE_MISSING"})
			case string(g.Epoch) != sc.Epoch || g.WritebackID != writebackID:
				conflicts = append(conflicts, WritebackConflict{Path: canonical, Epoch: sc.Epoch, Kind: "HOLDER_CHANGED"})
			default:
				if g.Holder != ref {
					holders[g.Holder] = true
				}
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
// bound to writebackID": the recovering mount proved its stream is empty (a
// valid header with zero frames — no mutation was ever acknowledged, because
// frames append before any ack), so the grants a crash orphaned between the
// authority's journal row and the client's DELEGATION frame are released
// losslessly. A still-live zombie holder generation is fenced in the same
// journal group first (only the mount owning the store flock can compute
// this writebackID, so the claim proves the mount identity moved on).
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
