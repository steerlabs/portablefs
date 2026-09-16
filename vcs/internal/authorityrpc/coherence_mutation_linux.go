//go:build linux

package authorityrpc

import (
	"context"
	"errors"
	"math"
	"syscall"

	"github.com/steerlabs/portablefs/vcs/internal/authoritypb"
	"github.com/steerlabs/portablefs/vcs/internal/volumeserver"
	"github.com/steerlabs/portablefs/vcs/internal/xfsstore"
)

type coherenceOperationKey struct{}
type coherenceOperation struct {
	beforeAdmission func() error

	reservation *volumeserver.DelegationReservation
	delegation  volumeserver.Delegation
}

func (h *VolumeHandler) initCoherence() {
	h.coherenceOnce.Do(func() {
		if h.Coherence == nil {
			h.Coherence = volumeserver.NewCoherenceCoordinator(volumeserver.CoherenceConfig{})
		}
		h.coherenceStorage = volumeserver.NewStorageSequencer()
		h.coherenceVersion = 1

	})
}
func (h *VolumeHandler) coherenceVersionNow() uint64 {
	h.initCoherence()
	h.coherenceCommitMu.Lock()
	defer h.coherenceCommitMu.Unlock()
	return h.coherenceVersion
}
func (h *VolumeHandler) SweepCoherence() {
	if h.Coherence == nil {
		return
	}
	h.Coherence.Sweep()
	h.coherenceRetiredMu.Lock()
	defer h.coherenceRetiredMu.Unlock()
	for id := range h.coherenceRetired {
		if h.forgetCoherenceSession(id) == nil {
			delete(h.coherenceRetired, id)
		}
	}
}

func coherenceGateTargets(gate volumeserver.SourcePublicationGate) []volumeserver.VisibilityTarget {
	targets := make([]volumeserver.VisibilityTarget, 0, len(gate.Targets))
	for _, t := range gate.Targets {
		if len(t.Name) != 0 {
			targets = append(targets, volumeserver.VisibilityTarget{Scope: volumeserver.VisibilityNamespace, ParentIdentity: t.ParentIdentity, Name: t.Name, RelatedIdentities: t.BoundIdentities})
		} else {
			targets = append(targets, volumeserver.VisibilityTarget{Scope: volumeserver.VisibilityAttributes, Identity: t.Identity})
		}
	}
	return targets
}

// Resolve without retaining a storage stripe. Delegation cuts may cause the
// holder to flush through exactly those stripes and must run before acquiring
// the complete storage dependency footprint.
func (h *VolumeHandler) coherencePreflight(ctx context.Context, req *authoritypb.Request, id volumeserver.SessionID, gate volumeserver.SourcePublicationGate) (*volumeserver.DelegationFlush, [16]byte, error) {
	token, err := h.coherenceToken(id)
	if err != nil {
		return nil, [16]byte{}, err
	}
	var identity [16]byte
	var reference *authoritypb.DelegationRef
	intent := false
	resolver := newOperationResolutionContext(h, id)
	resolveOpen := func(raw []byte) error { r, e := resolver.open(raw); identity = r.identity; return e }
	switch b := req.GetBody().(type) {
	case *authoritypb.Request_Write:
		err = resolveOpen(b.Write.GetHandle())
		reference = b.Write.GetDelegation()
	case *authoritypb.Request_SetAttr:
		if len(b.SetAttr.GetHandle()) != 0 {
			err = resolveOpen(b.SetAttr.GetHandle())
		} else {
			r, e := resolver.item(b.SetAttr.GetItem())
			identity, err = r.identity, e
		}
		reference = b.SetAttr.GetDelegation()
	case *authoritypb.Request_Fallocate:
		err = resolveOpen(b.Fallocate.GetHandle())
		reference = b.Fallocate.GetDelegation()
	case *authoritypb.Request_CopyFileRange:
		source, e := resolver.open(b.CopyFileRange.GetInputHandle())
		if e != nil {
			return nil, identity, e
		}
		guard, e := h.Coherence.DataConsumed(ctx, token, source.identity)
		if e != nil {
			return nil, identity, e
		}
		guard.Release()
		err = resolveOpen(b.CopyFileRange.GetOutputHandle())
	case *authoritypb.Request_Open:
		r, e := resolver.item(b.Open.GetItem())
		identity, err = r.identity, e
		intent = b.Open.GetWriteIntent()
		if intent && !b.Open.GetFlags().GetWrite() {
			return nil, identity, syscall.EINVAL
		}
	case *authoritypb.Request_Create:
		intent = b.Create.GetWriteIntent()
		if intent && !b.Create.GetFlags().GetWrite() {
			return nil, identity, syscall.EINVAL
		}
		for _, t := range gate.Targets {
			if len(t.Name) != 0 && len(t.BoundIdentities) != 0 {
				identity = t.BoundIdentities[0]
			}
		}
		if !intent && !b.Create.GetFlags().GetTruncate() {
			identity = [16]byte{}
		}
	}
	if err != nil {
		return nil, identity, err
	}
	if identity == ([16]byte{}) {
		// Namespace clients flush their own named identities before dispatch. Peer
		// cuts are still necessary for attribute-bearing mutation post-state.
		for _, t := range gate.Targets {
			ids := t.BoundIdentities
			if t.Identity != ([16]byte{}) {
				ids = append(append([][16]byte(nil), ids...), t.Identity)
			}
			for _, i := range ids {
				g, e := h.Coherence.DataConsumed(ctx, token, i)
				if e != nil {
					return nil, identity, e
				}
				g.Release()
			}
		}
		return nil, identity, nil
	}
	if reference == nil {
		pin, e := h.Coherence.BeginSynchronousMutation(ctx, token, identity)
		return pin, identity, e
	}
	n, err := parseCoherenceDelegationID(reference.GetId())
	if err != nil {
		return nil, identity, volumeserver.ErrDelegationStale
	}
	pin, err := h.Coherence.BeginFlush(token, identity, n, reference.GetGeneration())
	return pin, identity, err
}

func (h *VolumeHandler) mutateCoherenceVisibleSequenceResolved(ctx context.Context, req *authoritypb.Request, cred volumeserver.SessionCredential, prepare func(*operationResolutionContext) ([]volumeserver.VisibilityTarget, error), apply func(uint64) (*authoritypb.Response, []volumeserver.VisibilityTarget), releases ...*func()) *authoritypb.Response {
	h.initCoherence()
	profile, _ := h.sessionFrontendProfile(cred.ID)
	if profile == authoritypb.FrontendProfile_FRONTEND_PROFILE_FSKIT_SYNC_REPAIR {
		return h.mutateFskitCoherence(ctx, req, cred, prepare, apply, releases...)
	}
	if coherenceFlushReference(req) == nil {
		h.coherenceProfileAdmission.RLock()
		defer h.coherenceProfileAdmission.RUnlock()
		if err := h.Visibility.CheckCompatibilityWriter(cred.ID); err != nil {
			return h.coherenceError(req.GetRequestId(), err)
		}
	}
	// Mac activation holds exclusive profile admission while recalling old
	// delegations. Their exact-generation flushes must still pass so recall can
	// drain. BeginFlush rejects stale references; activation publishes the Mac
	// participant only after every recalled generation and active pin retires.
	if ctx.Value(coherenceOperationKey{}) == nil {
		ctx = context.WithValue(ctx, coherenceOperationKey{}, &coherenceOperation{})
	}
	releaseStorage := func() {
		for _, p := range releases {
			if p != nil && *p != nil {
				(*p)()
				*p = nil
			}
		}
	}
	return h.mutateOperation(ctx, req, cred, func(mid volumeserver.MutationID) *authoritypb.Response {
		defer releaseStorage()
		if op, _ := ctx.Value(coherenceOperationKey{}).(*coherenceOperation); op != nil && op.beforeAdmission != nil {
			admit := op.beforeAdmission
			op.beforeAdmission = nil // Detached withdrawal must not retain the bulk carrier.
			if err := admit(); err != nil {
				return h.coherenceError(0, err)
			}
		}
		for attempt := 0; attempt < maxStabilizeAttempts; attempt++ {
			resolver := newOperationResolutionContext(h, cred.ID)
			gate, err := resolver.deriveCoherenceGate(req)
			if err != nil {
				return h.coherenceError(0, err)
			}
			pin, identity, err := h.coherencePreflight(ctx, req, cred.ID, gate)
			if err != nil {
				return h.coherenceError(0, err)
			}
			finishPin := func(ticket uint64) {
				if pin != nil {
					pin.End(ticket)
					pin = nil
				}
			}
			dependencies := volumeserver.MutationDependenciesForTargets(coherenceGateTargets(gate))
			releaseTurn, err := h.coherenceStorage.Acquire(ctx, dependencies)
			if err != nil {
				finishPin(0)
				return h.coherenceError(0, err)
			}
			current := newOperationResolutionContext(h, cred.ID)
			checked, err := current.deriveCoherenceGate(req)
			if err != nil || !sourcePublicationGatesEqual(&gate, &checked) {
				releaseTurn()
				finishPin(0)
				if err != nil {
					return h.coherenceError(0, err)
				}
				continue
			}
			token, err := h.coherenceToken(cred.ID)
			if err == nil {
				err = h.Coherence.CheckSession(token)
			}
			if err != nil {
				releaseTurn()
				finishPin(0)
				return h.coherenceError(0, err)
			}
			prepared, err := prepare(current)
			if err != nil {
				releaseStorage()
				releaseTurn()
				finishPin(0)
				if errors.Is(err, volumeserver.ErrVisibilityDependencyRefresh) {
					continue
				}
				return h.coherenceError(0, err)
			}
			provisional := h.coherenceOperationSequence.Add(1)
			// Reserve zero as the baseline and use a separate provisional domain.
			provisional |= uint64(1) << 63
			var response *authoritypb.Response
			var changes []volumeserver.VisibilityTarget
			var position uint64
			var retainedGrantErr error
			terminal, _ := h.Runtime.SessionTerminal(cred.ID)
			applied := false
			err = h.Visibility.ExecuteFromExternalSource(ctx, cred.ID, terminal, mid, dependencies, func() ([]volumeserver.VisibilityTarget, error) { return prepared, nil }, func() ([]volumeserver.VisibilityTarget, bool) {
				response, changes = apply(provisional)
				applied = true
				if response == nil {
					response = h.errorResponse(0, errInternal, true)
				}
				if pin != nil && response.GetErrno() == 0 && (req.GetCreate().GetWriteIntent() || req.GetOpen().GetWriteIntent()) {
					op := ctx.Value(coherenceOperationKey{}).(*coherenceOperation)
					op.reservation, op.delegation, retainedGrantErr = pin.RetainDelegation()
				}
				position = h.publishCoherenceCommit(req, cred.ID, identity, provisional, response, changes)
				stampVisibilityTargets(changes, response.GetPostState())
				releaseStorage()
				releaseTurn()
				finishPin(response.GetAppliedSequence())
				return changes, changes != nil
			})
			if !applied {
				releaseStorage()
				releaseTurn()
				finishPin(0)
				return h.coherenceError(0, err)
			}
			if response == nil {
				response = h.errorResponse(0, errInternal, true)
			}
			releaseStorage()
			releaseTurn()
			finishPin(response.GetAppliedSequence())
			if retainedGrantErr != nil {
				h.discardCoherenceOpenReply(cred.ID, response)
				response = h.coherenceError(0, retainedGrantErr)
			}
			if err != nil {
				return h.errorResponse(0, err, changes != nil)
			}
			op, _ := ctx.Value(coherenceOperationKey{}).(*coherenceOperation)
			if position != 0 {
				wait := func() { _ = h.Coherence.WaitWithdrawn(context.WithoutCancel(ctx), position, cred.ID) }
				if response.GetAppliedSequence() != 0 && (coherenceFlushReference(req) != nil || op != nil && op.delegation.ID != 0) {
					// The response is an application receipt. Holder cut acknowledgments must
					// be able to pass a withdrawal of the holder's pending read publication.
					go wait()
				} else {
					wait()
				}
			}
			if op != nil && op.reservation != nil {
				if response.GetErrno() != 0 {
					op.reservation.Abort()
					op.reservation = nil
				}
				var grant volumeserver.Delegation
				var grantErr error
				if op.reservation != nil {
					grant, grantErr = op.reservation.Grant(context.WithoutCancel(ctx))
					if grantErr == nil {
						grantErr = h.rememberCoherenceDelegation(grant)
					}
				}
				op.reservation = nil
				if grantErr != nil {
					h.discardCoherenceOpenReply(cred.ID, response)
					response = h.coherenceError(0, grantErr)
				} else {
					op.delegation = grant
				}
			}
			if op != nil && response.GetErrno() == 0 {
				if c := response.GetCreate(); c != nil && req.GetCreate().GetWriteIntent() {
					c.Delegation = coherenceDelegationProto(op.delegation)
				}
				if o := response.GetOpen(); o != nil && req.GetOpen().GetWriteIntent() {
					o.Delegation = coherenceDelegationProto(op.delegation)
				}
			}
			return response
		}
		return h.coherenceError(0, syscall.EAGAIN)
	}, nil)
}

func (r *operationResolutionContext) deriveCoherenceGate(req *authoritypb.Request) (volumeserver.SourcePublicationGate, error) {
	if w := req.GetWrite(); w != nil {
		resolved, err := r.open(w.GetHandle())
		if err != nil {
			return volumeserver.SourcePublicationGate{}, err
		}
		return volumeserver.SourcePublicationGate{Targets: []volumeserver.SourcePublicationTarget{{Identity: resolved.identity, Attributes: true, Data: true}}}, nil
	}
	return r.deriveSourcePublicationGate(req, true)
}
func coherenceFlushReference(req *authoritypb.Request) *authoritypb.DelegationRef {
	if w := req.GetWrite(); w != nil {
		return w.GetDelegation()
	}
	if s := req.GetSetAttr(); s != nil {
		return s.GetDelegation()
	}
	if f := req.GetFallocate(); f != nil {
		return f.GetDelegation()
	}
	return nil
}
func coherenceDelegationProto(d volumeserver.Delegation) *authoritypb.Delegation {
	if d.ID == 0 {
		return nil
	}
	return &authoritypb.Delegation{Id: coherenceDelegationID(d.ID), Generation: d.Generation, Mode: authoritypb.DelegationMode(d.Mode)}
}

func (h *VolumeHandler) publishCoherenceCommit(req *authoritypb.Request, id volumeserver.SessionID, identity [16]byte, provisional uint64, resp *authoritypb.Response, targets []volumeserver.VisibilityTarget) uint64 {
	h.coherenceCommitMu.Lock()
	defer h.coherenceCommitMu.Unlock()
	changed := targets != nil
	if changed {
		if h.coherenceVersion == math.MaxUint64 {
			panic("authorityrpc: coherence version exhausted")
		}
		h.coherenceVersion++
	}
	seq := h.coherenceVersion
	versions := h.finalizeMutationPostState(provisional, seq, resp.GetPostState())
	rewriteMutationReplyMetadata(resp.ProtoReflect(), seq, versions)
	resp.VolumeVersion = seq
	if w := resp.GetWrite(); w != nil {
		_, w.DurableSequence = h.latestCoherenceDurability(id)
	}
	if !changed {
		return 0
	}
	entries := coherenceChanges(req, resp, targets, seq)
	position := h.Coherence.OnCommitFrom(entries, id)
	if identity != ([16]byte{}) && (req.GetWrite() != nil || req.GetSetAttr() != nil || req.GetFallocate() != nil) {
		resp.AppliedSequence = h.coherenceDurability.recordApplied(id, identity, seq)
	}
	return position
}
func coherenceChanges(req *authoritypb.Request, resp *authoritypb.Response, targets []volumeserver.VisibilityTarget, version uint64) []volumeserver.ChangeEntry {
	entries := make([]volumeserver.ChangeEntry, 0, len(targets)*2+len(resp.GetPostState().GetObjects()))
	type coordinate struct {
		kind             volumeserver.ChangeKind
		identity, parent [16]byte
		name             string
	}
	seen := make(map[coordinate]bool)
	add := func(e volumeserver.ChangeEntry) {
		e.VolumeVersion = version
		key := coordinate{e.Kind, e.Identity, e.ParentIdentity, e.Name}
		if !seen[key] {
			seen[key] = true
			entries = append(entries, e)
		}
	}
	for _, t := range targets {
		switch t.Scope {
		case volumeserver.VisibilityNamespace:
			add(volumeserver.ChangeEntry{Kind: volumeserver.NamespaceChanged, ParentIdentity: t.ParentIdentity, Name: string(t.Name)})
			add(volumeserver.ChangeEntry{Kind: volumeserver.DirectoryChanged, Identity: t.ParentIdentity})
		case volumeserver.VisibilityAttributes:
			add(volumeserver.ChangeEntry{Kind: volumeserver.AttributesChanged, Identity: t.Identity})
		case volumeserver.VisibilityData:
			e := volumeserver.ChangeEntry{Kind: volumeserver.DataChanged, Identity: t.Identity}
			if w := resp.GetWrite(); w != nil && w.GetCommittedSize() != 0 {
				e.HasRange = true
				e.Offset = w.GetAssignedOffset()
				e.Length = w.GetCommittedSize()
			}
			if c := resp.GetCopyFileRange(); c != nil && c.GetResultSize() != 0 {
				e.HasRange = true
				e.Offset = req.GetCopyFileRange().GetOutputOffset()
				e.Length = c.GetResultSize()
			}
			if f := req.GetFallocate(); f != nil && f.GetMode()&0x28 == 0 {
				e.HasRange = true
				e.Offset = f.GetOffset()
				e.Length = f.GetLength()
			}
			add(e)
		}
	}
	for _, o := range resp.GetPostState().GetObjects() {
		if o.GetObjectVersion() == version && len(o.GetStableIdentity()) == 16 {
			var i [16]byte
			copy(i[:], o.GetStableIdentity())
			add(volumeserver.ChangeEntry{Kind: volumeserver.AttributesChanged, Identity: i})
		}
	}
	return entries
}

// A committed namespace mutation can outlive its subscription while Grant
// waits. Retire reply-only capabilities if the client cannot receive them.
func (h *VolumeHandler) discardCoherenceOpenReply(id volumeserver.SessionID, response *authoritypb.Response) {
	var rawHandle, rawItem []byte
	if c := response.GetCreate(); c != nil {
		rawHandle = c.GetHandle()
		rawItem = c.GetItem().GetToken()
	}
	if o := response.GetOpen(); o != nil {
		rawHandle = o.GetHandle()
	}
	if len(rawHandle) == 16 {
		var handle xfsstore.Capability
		copy(handle[:], rawHandle)
		h.untrackOpen(id, handle)
		h.closeOpen(handle)
	}
	if len(rawItem) == 16 {
		var item xfsstore.Capability
		copy(item[:], rawItem)
		h.untrackItem(id, item)
		h.forgetItem(item)
	}
}
