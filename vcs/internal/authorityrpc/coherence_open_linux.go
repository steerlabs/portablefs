//go:build linux

package authorityrpc

import (
	"context"
	"syscall"

	"github.com/steerlabs/portablefs/vcs/internal/authoritypb"
	"github.com/steerlabs/portablefs/vcs/internal/volumeserver"
	"github.com/steerlabs/portablefs/vcs/internal/xfsstore"
)

// Accounting belongs to the server description, not the RPC delivery. These
// helpers run inside exact replay and cleanup removes the record atomically.
func (h *VolumeHandler) coherenceAdmitOpen(id volumeserver.SessionID, handle xfsstore.Capability, identity [16]byte, requested, writeIntent bool) (bool, error) {
	if !requested || writeIntent {
		return false, nil
	}
	token, err := h.coherenceToken(id)
	if err != nil {
		return false, err
	}
	admitted, err := h.Coherence.OpenCacheCapable(token, identity)
	if err != nil || !admitted {
		return admitted, err
	}
	h.resourcesMu.Lock()
	resources := h.resources[id]
	if resources == nil || resources.ended {
		h.resourcesMu.Unlock()
		_ = h.Coherence.CloseCacheCapable(token, identity)
		return false, volumeserver.ErrSessionExpired
	}
	if resources.cacheOpens == nil {
		resources.cacheOpens = make(map[xfsstore.Capability][16]byte)
	}
	resources.cacheOpens[handle] = identity
	h.resourcesMu.Unlock()
	return true, nil
}
func (h *VolumeHandler) coherenceCloseAccounting(id volumeserver.SessionID, handle xfsstore.Capability) {
	h.resourcesMu.Lock()
	var identity [16]byte
	if resources := h.resources[id]; resources != nil {
		identity = resources.cacheOpens[handle]
		delete(resources.cacheOpens, handle)
	}
	h.resourcesMu.Unlock()
	if identity != ([16]byte{}) {
		if token, err := h.coherenceToken(id); err == nil {
			_ = h.Coherence.CloseCacheCapable(token, identity)
		}
	}
}

func (h *VolumeHandler) coherenceReserveCreated(ctx context.Context, id volumeserver.SessionID, item xfsstore.Capability, request *authoritypb.CreateRequest, existed bool) error {
	if !request.GetWriteIntent() {
		return nil
	}
	profile, _ := h.sessionFrontendProfile(id)
	if profile != authoritypb.FrontendProfile_FRONTEND_PROFILE_LINUX_LEASES {
		return syscall.EINVAL
	}
	if !request.GetFlags().GetWrite() {
		return syscall.EINVAL
	}
	if existed {
		return nil
	}
	identity, err := h.Store.Identity(item)
	if err != nil {
		return err
	}
	token, err := h.coherenceToken(id)
	if err != nil {
		return err
	}
	reservation, err := h.Coherence.ReserveNew(token, identity)
	if err == nil {
		ctx.Value(coherenceOperationKey{}).(*coherenceOperation).reservation = reservation
	}
	return err
}

func (h *VolumeHandler) coherenceOpen(ctx context.Context, req *authoritypb.Request, cred volumeserver.SessionCredential) *authoritypb.Response {
	profile, err := h.sessionFrontendProfile(cred.ID)
	if err != nil {
		return h.coherenceError(req.GetRequestId(), err)
	}
	cacheless := profile == authoritypb.FrontendProfile_FRONTEND_PROFILE_CACHELESS_READER
	if cacheless && (requestRequiresWrite(req) || req.GetOpen().GetWriteIntent() || req.GetOpen().GetCacheCapable()) {
		return h.coherenceError(req.GetRequestId(), syscall.EPERM)
	}
	if req.GetOpen().GetWriteIntent() || req.GetOpen().GetFlags().GetWrite() {
		h.coherenceProfileAdmission.RLock()
		defer h.coherenceProfileAdmission.RUnlock()
		if err := h.Visibility.CheckCompatibilityWriter(cred.ID); err != nil {
			return h.coherenceError(req.GetRequestId(), err)
		}
	}
	return h.mutate(ctx, req, cred, func() *authoritypb.Response {
		body := req.GetOpen()
		if body.GetWriteIntent() && !body.GetFlags().GetWrite() {
			return h.coherenceError(0, syscall.EINVAL)
		}
		item, err := h.item(cred.ID, body.GetItem())
		if err != nil {
			return h.coherenceError(0, err)
		}
		identity, err := h.Store.Identity(item)
		if err != nil {
			return h.coherenceError(0, err)
		}
		var token volumeserver.SubscriptionToken
		if !cacheless {
			token, err = h.coherenceToken(cred.ID)
			if err != nil {
				return h.coherenceError(0, err)
			}
		}
		var delegationReservation *volumeserver.DelegationReservation
		if body.GetWriteIntent() {
			reservation, e := h.Coherence.Reserve(ctx, token, identity)
			if e != nil {
				return h.coherenceError(0, e)
			}
			defer reservation.Abort()
			delegationReservation = reservation
		}
		guard, err := h.coherenceReadAdmission(ctx, cred.ID, identity)
		if err != nil {
			return h.coherenceError(0, err)
		}
		guardHeld := true
		defer func() {
			if guardHeld {
				guard.Release()
			}
		}()
		release, err := h.coherenceStorage.Acquire(ctx, volumeserver.MutationDependenciesForTargets([]volumeserver.VisibilityTarget{{Scope: volumeserver.VisibilityAttributes, Identity: identity}}))
		if err != nil {
			return h.coherenceError(0, err)
		}
		storageHeld := true
		defer func() {
			if storageHeld {
				release()
			}
		}()
		reservation, err := h.reserveCapabilities(cred.ID, 0, 1)
		if err != nil {
			return h.coherenceError(0, err)
		}
		defer reservation.release()
		handle, err := h.Store.OpenFile(item, openFlags(body.GetFlags()))
		if err != nil {
			return h.coherenceError(0, err)
		}
		if err = reservation.commit(nil, []trackedCapability{{value: handle, protected: h.protectedCapability(cred.ID, item)}}); err != nil {
			h.closeOpen(handle)
			return h.coherenceError(0, err)
		}
		cache, err := h.coherenceAdmitOpen(cred.ID, handle, identity, body.GetCacheCapable(), body.GetWriteIntent())
		if err != nil {
			h.untrackOpen(cred.ID, handle)
			h.closeOpen(handle)
			return h.coherenceError(0, err)
		}
		// Grant can wait for every peer to withdraw cached data. The open handle
		// is already durable server state, so retire both storage exclusions
		// before entering that protocol wait and unwind it if the grant fails.
		release()
		storageHeld = false
		guard.Release()
		guardHeld = false
		var grant volumeserver.Delegation
		if delegationReservation != nil {
			grant, err = delegationReservation.Grant(ctx)
			if err == nil {
				err = h.rememberCoherenceDelegation(grant)
			}
			if err != nil {
				if grant.ID != 0 {
					_, _ = h.Coherence.ReleaseBatch(token, []volumeserver.Delegation{grant})
				}
				h.untrackOpen(cred.ID, handle)
				h.closeOpen(handle)
				return h.coherenceError(0, err)
			}
		}
		resp := h.success(0)
		resp.VolumeVersion = h.coherenceVersionNow()
		resp.Body = &authoritypb.Response_Open{Open: &authoritypb.OpenReply{Handle: handle[:], Delegation: coherenceDelegationProto(grant), CacheCapable: cache}}
		return resp
	})
}
