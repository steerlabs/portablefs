//go:build linux

package authorityrpc

import (
	"context"
	"errors"
	"io"
	"syscall"

	"github.com/steerlabs/portablefs/vcs/internal/authoritypb"
	"github.com/steerlabs/portablefs/vcs/internal/volumeserver"
	"github.com/steerlabs/portablefs/vcs/internal/xfsstore"
)

// coherenceRead owns the protocol-7 Linux cache-installing read paths. The
// caller has already authenticated the runtime session and checked the current
// subscription incarnation. FSKit remains on its existing repair path.
func (h *VolumeHandler) coherenceRead(ctx context.Context, req *authoritypb.Request, cred volumeserver.SessionCredential) (*authoritypb.Response, bool) {
	if req == nil {
		return nil, false
	}
	profile, err := h.sessionFrontendProfile(cred.ID)
	if err != nil || profile != authoritypb.FrontendProfile_FRONTEND_PROFILE_LINUX_LEASES && profile != authoritypb.FrontendProfile_FRONTEND_PROFILE_CACHELESS_READER {
		return nil, false
	}
	switch body := req.GetBody().(type) {
	case *authoritypb.Request_Read:
		return h.coherenceReadData(ctx, req.GetRequestId(), cred.ID, body.Read), true
	case *authoritypb.Request_GetAttr:
		return h.coherenceGetAttr(ctx, req.GetRequestId(), cred.ID, body.GetAttr), true
	case *authoritypb.Request_Lookup:
		return h.coherenceLookup(ctx, req, cred, body.Lookup), true
	case *authoritypb.Request_ReadDir:
		return h.coherenceReadDir(ctx, req, cred, body.ReadDir), true
	case *authoritypb.Request_Fsync:
		return h.coherenceFsync(ctx, req.GetRequestId(), cred.ID, body.Fsync), true
	default:
		return nil, false
	}
}

func (h *VolumeHandler) coherenceFsync(ctx context.Context, requestID uint64, session volumeserver.SessionID, request *authoritypb.FsyncRequest) *authoritypb.Response {
	if request == nil {
		return h.errorResponse(requestID, syscall.EINVAL, false)
	}
	handle, err := h.open(session, request.GetHandle())
	if err != nil {
		return h.errorResponse(requestID, err, false)
	}
	identity, err := h.Store.IdentityOpen(handle)
	if err != nil {
		return h.errorResponse(requestID, err, false)
	}
	guard, err := h.coherenceReadAdmission(ctx, session, identity)
	if err != nil {
		return h.coherenceError(requestID, err)
	}
	defer guard.Release()
	release, err := h.coherenceStorage.AcquireRead(ctx, coherenceInodeDependencies(identity))
	if err != nil {
		return h.errorResponse(requestID, err, false)
	}
	defer release()
	group := 0
	if store, ok := h.Store.(coalescingFsyncStore); ok {
		group, err = store.FsyncCoalesced(handle, request.GetDataOnly())
	} else {
		err = h.Store.Fsync(handle, request.GetDataOnly())
	}
	if group != 0 && h.Metrics != nil {
		h.Metrics.ObserveFsyncBatch(group)
	}
	if err != nil {
		return h.errorResponse(requestID, err, true)
	}
	version := h.coherenceVersionNow()
	_, durable := h.latestCoherenceDurability(session)
	response := h.success(requestID)
	response.VolumeVersion = version
	response.Body = &authoritypb.Response_Fsync{Fsync: &authoritypb.FsyncReply{DurableSequence: durable}}
	return response
}

func coherenceInodeDependencies(identity [16]byte) volumeserver.MutationDependencies {
	return volumeserver.MutationDependenciesForTargets([]volumeserver.VisibilityTarget{{
		Scope: volumeserver.VisibilityAttributes, Identity: identity,
	}})
}

func coherenceBindingDependencies(parent [16]byte, name []byte, identity [16]byte) volumeserver.MutationDependencies {
	target := volumeserver.VisibilityTarget{
		Scope: volumeserver.VisibilityNamespace, ParentIdentity: parent, Name: name,
	}
	if identity != ([16]byte{}) {
		target.RelatedIdentities = [][16]byte{identity}
	}
	return volumeserver.MutationDependenciesForTargets([]volumeserver.VisibilityTarget{target})
}

func (h *VolumeHandler) coherenceReadAdmission(ctx context.Context, session volumeserver.SessionID, identity [16]byte) (*volumeserver.DataGuard, error) {
	if h.Coherence == nil || h.coherenceStorage == nil {
		return nil, errInternal
	}
	profile, err := h.sessionFrontendProfile(session)
	if err != nil {
		return nil, err
	}
	if profile == authoritypb.FrontendProfile_FRONTEND_PROFILE_CACHELESS_READER {
		return h.Coherence.BreakForReadSet(ctx, [][16]byte{identity})
	}
	token, err := h.coherenceToken(session)
	if err != nil {
		return nil, err
	}
	return h.Coherence.DataConsumed(ctx, token, identity)
}

func (h *VolumeHandler) coherenceReadSetAdmission(ctx context.Context, session volumeserver.SessionID, identities [][16]byte) (*volumeserver.DataGuard, error) {
	if h.Coherence == nil || h.coherenceStorage == nil {
		return nil, errInternal
	}
	profile, err := h.sessionFrontendProfile(session)
	if err != nil {
		return nil, err
	}
	if profile == authoritypb.FrontendProfile_FRONTEND_PROFILE_CACHELESS_READER {
		return h.Coherence.BreakForReadSet(ctx, identities)
	}
	token, err := h.coherenceToken(session)
	if err != nil {
		return nil, err
	}
	return h.Coherence.DataConsumedSet(ctx, token, identities)
}

func (h *VolumeHandler) coherenceTryReadAdmission(ctx context.Context, session volumeserver.SessionID, identity [16]byte) (*volumeserver.DataGuard, bool, error) {
	profile, err := h.sessionFrontendProfile(session)
	if err != nil {
		return nil, false, err
	}
	if profile == authoritypb.FrontendProfile_FRONTEND_PROFILE_CACHELESS_READER {
		return nil, false, nil
	}
	token, err := h.coherenceToken(session)
	if err != nil {
		return nil, false, err
	}
	return h.Coherence.TryDataConsumed(ctx, token, identity)
}

func (h *VolumeHandler) coherenceReadData(ctx context.Context, requestID uint64, session volumeserver.SessionID, request *authoritypb.ReadRequest) *authoritypb.Response {
	if request == nil || request.GetLength() > h.MaxRead {
		return h.errorResponse(requestID, syscall.EINVAL, false)
	}
	handle, err := h.open(session, request.GetHandle())
	if err != nil {
		return h.errorResponse(requestID, err, false)
	}
	identity, err := h.Store.IdentityOpen(handle)
	if err != nil {
		return h.errorResponse(requestID, err, false)
	}
	cacheToken, err := h.coherenceCacheToken(session)
	if err != nil {
		return h.coherenceError(requestID, err)
	}
	guard, err := h.coherenceReadAdmission(ctx, session, identity)
	if err != nil {
		return h.coherenceError(requestID, err)
	}
	defer guard.Release()
	release, err := h.coherenceStorage.AcquireRead(ctx, coherenceInodeDependencies(identity))
	if err != nil {
		return h.errorResponse(requestID, err, false)
	}
	defer release()
	if h.Restore != nil && h.Restore.Active() {
		if err := h.Restore.EnsureHydrated(ctx, identity, request.GetOffset(), uint64(request.GetLength())); err != nil {
			return h.errorResponse(requestID, err, false)
		}
	}
	buf := make([]byte, request.GetLength())
	n, err := h.Store.ReadAt(handle, buf, int64(request.GetOffset()))
	if err != nil && !errors.Is(err, io.EOF) {
		return h.errorResponse(requestID, err, false)
	}
	if err := h.admitCoherenceCache(cacheToken, volumeserver.CacheAdmission{Data: [][16]byte{identity}}); err != nil {
		return h.coherenceError(requestID, err)
	}
	version := h.coherenceVersionNow()
	response := h.success(requestID)
	response.VolumeVersion = version
	response.Body = &authoritypb.Response_Read{Read: &authoritypb.ReadReply{
		Data: buf[:n], VolumeVersion: version,
	}}
	return response
}

func (h *VolumeHandler) coherenceGetAttr(ctx context.Context, requestID uint64, session volumeserver.SessionID, request *authoritypb.GetAttrRequest) *authoritypb.Response {
	if request == nil || len(request.GetItem()) == 0 && len(request.GetHandle()) == 0 ||
		len(request.GetItem()) != 0 && len(request.GetHandle()) != 0 {
		return h.errorResponse(requestID, syscall.EINVAL, false)
	}
	var item, handle xfsstore.Capability
	var identity [16]byte
	var err error
	if len(request.GetHandle()) != 0 {
		handle, err = h.open(session, request.GetHandle())
		if err == nil {
			identity, err = h.Store.IdentityOpen(handle)
		}
	} else {
		item, err = h.item(session, request.GetItem())
		if err == nil {
			identity, err = h.Store.Identity(item)
		}
	}
	if err != nil {
		return h.errorResponse(requestID, err, false)
	}
	cacheToken, err := h.coherenceCacheToken(session)
	if err != nil {
		return h.coherenceError(requestID, err)
	}
	guard, err := h.coherenceReadAdmission(ctx, session, identity)
	if err != nil {
		return h.coherenceError(requestID, err)
	}
	defer guard.Release()
	release, err := h.coherenceStorage.AcquireRead(ctx, coherenceInodeDependencies(identity))
	if err != nil {
		return h.errorResponse(requestID, err, false)
	}
	defer release()
	var attr xfsstore.Attr
	if handle != (xfsstore.Capability{}) {
		attr, err = h.getattrOpenRestored(identity, handle)
	} else {
		attr, err = h.getattrItemRestored(identity, item)
	}
	if err != nil {
		return h.errorResponse(requestID, err, false)
	}
	if err := h.admitCoherenceCache(cacheToken, volumeserver.CacheAdmission{Attributes: [][16]byte{identity}}); err != nil {
		return h.coherenceError(requestID, err)
	}
	version := h.coherenceVersionNow()
	response := h.success(requestID)
	response.VolumeVersion = version
	response.Body = &authoritypb.Response_GetAttr{GetAttr: &authoritypb.GetAttrReply{
		Attr: attrProto(attr), ObjectVersion: h.sampledObjectVersion(identity, version), SnapshotSequence: version,
	}}
	return response
}

func (h *VolumeHandler) coherenceLookup(ctx context.Context, req *authoritypb.Request, cred volumeserver.SessionCredential, request *authoritypb.LookupRequest) *authoritypb.Response {
	return h.mutate(ctx, req, cred, func() *authoritypb.Response {
		if request == nil || namespaceName(request.GetName()) != nil {
			return h.errorResponse(0, syscall.EINVAL, false)
		}
		parent, err := h.item(cred.ID, request.GetParent())
		if err != nil {
			return h.errorResponse(0, err, false)
		}
		parentIdentity, err := h.Store.Identity(parent)
		if err != nil {
			return h.errorResponse(0, err, false)
		}
		cacheToken, err := h.coherenceCacheToken(cred.ID)
		if err != nil {
			return h.coherenceError(0, err)
		}
		for attempt := 0; attempt < maxStabilizeAttempts; attempt++ {
			binding := coherenceBindingDependencies(parentIdentity, request.GetName(), [16]byte{})
			probeTurn, err := h.coherenceStorage.AcquireReadTurn(ctx, binding)
			if err != nil {
				return h.errorResponse(0, err, false)
			}
			probeRelease := probeTurn.Release
			// Only the stable capability is retained from this probe. Its
			// attributes cannot be published before the child delegation break.
			item, _, lookupErr := h.Store.Lookup(parent, string(request.GetName()))
			if errors.Is(lookupErr, syscall.ENOENT) {
				release := probeRelease
				if err := h.admitCoherenceCache(cacheToken, volumeserver.CacheAdmission{Directories: [][16]byte{parentIdentity}}); err != nil {
					release()
					return h.coherenceError(0, err)
				}
				version := h.coherenceVersionNow()
				release()
				response := h.success(0)
				response.VolumeVersion = version
				response.Body = &authoritypb.Response_Lookup{Lookup: &authoritypb.LookupReply{NegativeSnapshotSequence: version}}
				return response
			}
			if lookupErr != nil {
				probeRelease()
				return h.errorResponse(0, lookupErr, false)
			}
			identity, err := h.Store.Identity(item)
			if err != nil {
				probeRelease()
				h.forgetItem(item)
				return h.errorResponse(0, err, false)
			}
			dependencies := coherenceBindingDependencies(parentIdentity, request.GetName(), identity)
			guard, immediate, err := h.coherenceTryReadAdmission(ctx, cred.ID, identity)
			if err != nil {
				probeRelease()
				h.forgetItem(item)
				return h.coherenceError(0, err)
			}
			completeRelease := probeRelease
			if !immediate || !probeTurn.TryExpand(dependencies) {
				declaration := h.coherenceStorage.Declare(binding)
				probeRelease()
				if !immediate {
					guard, err = h.coherenceReadAdmission(ctx, cred.ID, identity)
					if err != nil {
						declaration.Release()
						h.forgetItem(item)
						return h.coherenceError(0, err)
					}
				}
				var unchanged bool
				completeRelease, unchanged, err = h.coherenceStorage.AcquireDeclared(ctx, dependencies, declaration)
				if err != nil {
					guard.Release()
					h.forgetItem(item)
					return h.errorResponse(0, err, false)
				}
				if !unchanged {
					completeRelease()
					guard.Release()
					h.forgetItem(item)
					continue
				}
			}
			attr, err := h.getattrItemRestored(identity, item)
			if err != nil {
				completeRelease()
				guard.Release()
				h.forgetItem(item)
				return h.errorResponse(0, err, false)
			}
			if err := h.admitCoherenceCache(cacheToken, volumeserver.CacheAdmission{Directories: [][16]byte{parentIdentity}, Attributes: [][16]byte{identity}}); err != nil {
				h.forgetItem(item)
				completeRelease()
				guard.Release()
				return h.coherenceError(0, err)
			}
			version := h.coherenceVersionNow()
			if err := h.trackItem(cred.ID, item, h.protectedChild(cred.ID, parent, request.GetName())); err != nil {
				completeRelease()
				guard.Release()
				return h.errorResponse(0, err, false)
			}
			objectVersion := h.sampledObjectVersion(identity, version)
			completeRelease()
			guard.Release()
			itemReply := itemProto(item, attr, identity)
			itemReply.ObjectVersion = objectVersion
			itemReply.SnapshotSequence = version
			response := h.success(0)
			response.VolumeVersion = version
			response.Body = &authoritypb.Response_Lookup{Lookup: &authoritypb.LookupReply{Item: itemReply}}
			return response
		}
		return h.errorResponse(0, syscall.EAGAIN, false)
	})
}

func (h *VolumeHandler) coherenceReadDir(ctx context.Context, req *authoritypb.Request, cred volumeserver.SessionCredential, request *authoritypb.ReadDirRequest) *authoritypb.Response {
	return h.mutate(ctx, req, cred, func() *authoritypb.Response {
		if request == nil || request.GetMaxEntries() == 0 || request.GetMaxEntries() > 4096 {
			return h.errorResponse(0, syscall.EINVAL, false)
		}
		heldIdentities, err := heldDirectoryIdentities(request)
		if err != nil {
			return h.errorResponse(0, err, false)
		}
		handle, err := h.open(cred.ID, request.GetHandle())
		if err != nil {
			return h.errorResponse(0, err, false)
		}
		directoryIdentity, err := h.Store.IdentityOpen(handle)
		if err != nil {
			return h.errorResponse(0, err, false)
		}
		cookie, err := decodeCookie(request.GetCookie())
		if err != nil {
			return h.errorResponse(0, err, false)
		}
		// The frozen wire field remains shape-checked. Continuation uses only
		// the issued cookie; the current page stamp comes from storage.
		if len(request.GetVerifier()) != 0 && len(request.GetVerifier()) != 16 {
			return h.errorResponse(0, syscall.EINVAL, false)
		}
		budget := h.readDirEntryBudget(request.GetMaxEntries())
		cacheToken, err := h.coherenceCacheToken(cred.ID)
		if err != nil {
			return h.coherenceError(0, err)
		}
		for {
			if err := ctx.Err(); err != nil {
				return h.errorResponse(0, err, false)
			}
			directoryGuard, guardErr := h.coherenceReadAdmission(ctx, cred.ID, directoryIdentity)
			if guardErr != nil {
				return h.coherenceError(0, guardErr)
			}
			entries, _, current, eof, directory, readErr := h.coherenceReadDirPage(handle, cookie, int(request.GetMaxEntries()))
			if readErr != nil {
				directoryGuard.Release()
				if errors.Is(readErr, syscall.EAGAIN) {
					continue
				}
				return h.errorResponse(0, readErr, false)
			}
			candidates, budgetExhausted, conflict, buildErr := h.constructDirectoryPage(handle, entries, cookie, request.GetWantItems(), heldIdentities, budget)
			if buildErr != nil {
				directoryGuard.Release()
				if errors.Is(buildErr, syscall.EAGAIN) {
					continue
				}
				return h.errorResponse(0, buildErr, false)
			}
			if conflict {
				directoryGuard.Release()
				continue
			}

			identities := make([][16]byte, 1, len(candidates)+1)
			identities[0] = directoryIdentity
			seen := map[[16]byte]struct{}{directoryIdentity: {}}
			for _, candidate := range candidates {
				if candidate.identity == ([16]byte{}) {
					continue
				}
				if _, ok := seen[candidate.identity]; ok {
					continue
				}
				seen[candidate.identity] = struct{}{}
				identities = append(identities, candidate.identity)
			}
			pageGuard := directoryGuard
			if len(identities) > 1 {
				// Never nest identity guards: opposite-order pages must acquire
				// one complete footprint. Empty pages retain their first cut.
				directoryGuard.Release()
				pageGuard, guardErr = h.coherenceReadSetAdmission(ctx, cred.ID, identities)
				if guardErr != nil {
					h.forgetDirectoryCandidates(candidates)
					return h.coherenceError(0, guardErr)
				}
			}

			dependencies := h.coherenceDirectoryDependencies(directoryIdentity, candidates)
			release, acquireErr := h.coherenceStorage.AcquireRead(ctx, dependencies)
			if acquireErr != nil {
				pageGuard.Release()
				h.forgetDirectoryCandidates(candidates)
				return h.errorResponse(0, acquireErr, false)
			}
			valid, revalidated, verifyErr := h.coherenceRevalidateDirectoryPage(handle, directory, cookie, int(request.GetMaxEntries()), entries, eof, candidates)
			if verifyErr != nil || !valid {
				release()
				pageGuard.Release()
				h.forgetDirectoryCandidates(candidates)
				if verifyErr != nil {
					if errors.Is(verifyErr, syscall.EAGAIN) {
						continue
					}
					return h.errorResponse(0, verifyErr, false)
				}
				continue
			}
			current = revalidated
			admission := volumeserver.CacheAdmission{Directories: [][16]byte{directoryIdentity}}
			for _, candidate := range candidates {
				if candidate.identity != ([16]byte{}) {
					admission.Attributes = append(admission.Attributes, candidate.identity)
				}
			}
			if err := h.admitCoherenceCache(cacheToken, admission); err != nil {
				release()
				pageGuard.Release()
				h.forgetDirectoryCandidates(candidates)
				return h.coherenceError(0, err)
			}
			version := h.coherenceVersionNow()
			// The object stamp belongs to the same storage cut as its attributes.
			// Sampling after release could observe a peer version beyond this snapshot.
			for _, candidate := range candidates {
				candidate.dirent.ObjectVersion = h.sampledObjectVersion(candidate.identity, version)
			}
			release()
			pageGuard.Release()

			result := &authoritypb.ReadDirReply{Verifier: current[:], Eof: eof && !budgetExhausted}
			issued := make([]directoryPageCandidate, 0, len(candidates))
			for _, candidate := range candidates {
				candidate.dirent.SnapshotSequence = version
				if candidate.dirent.GetItem() != nil {
					candidate.dirent.Item.ObjectVersion = candidate.dirent.ObjectVersion
					candidate.dirent.Item.SnapshotSequence = version
					issued = append(issued, candidate)
				} else if candidate.item != (xfsstore.Capability{}) {
					h.forgetItem(candidate.item)
				}
				result.Entries = append(result.Entries, candidate.dirent)
			}
			if budgetExhausted && len(result.Entries) == 0 {
				return h.errorResponse(0, syscall.EOVERFLOW, false)
			}
			for index, candidate := range issued {
				if err := h.trackItem(cred.ID, candidate.item, h.protectedChild(cred.ID, directory, candidate.dirent.GetName())); err != nil {
					for _, prior := range issued[:index] {
						h.untrackItem(cred.ID, prior.item)
						h.forgetItem(prior.item)
					}
					for _, remaining := range issued[index+1:] {
						h.forgetItem(remaining.item)
					}
					return h.errorResponse(0, err, false)
				}
			}
			response := h.success(0)
			response.VolumeVersion = version
			response.Body = &authoritypb.Response_ReadDir{ReadDir: result}
			return response
		}
	})
}

func (h *VolumeHandler) coherenceDirectoryDependencies(directory [16]byte, candidates []directoryPageCandidate) volumeserver.MutationDependencies {
	targets := make([]volumeserver.VisibilityTarget, 0, len(candidates)*2+1)
	targets = append(targets, volumeserver.VisibilityTarget{Scope: volumeserver.VisibilityAttributes, Identity: directory})
	for _, candidate := range candidates {
		namespace := volumeserver.VisibilityTarget{
			Scope: volumeserver.VisibilityNamespace, ParentIdentity: directory, Name: candidate.dirent.GetName(),
		}
		if candidate.identity != ([16]byte{}) {
			namespace.RelatedIdentities = [][16]byte{candidate.identity}
			targets = append(targets, volumeserver.VisibilityTarget{Scope: volumeserver.VisibilityAttributes, Identity: candidate.identity})
		}
		targets = append(targets, namespace)
	}
	return volumeserver.MutationDependenciesForTargets(targets)
}

func (h *VolumeHandler) coherenceRevalidateDirectoryPage(
	handle, directory xfsstore.Capability,
	cookie uint64,
	maxEntries int,
	entries []xfsstore.Dirent,
	eof bool,
	candidates []directoryPageCandidate,
) (bool, [16]byte, error) {
	checkEntries, _, checkVerifier, checkEOF, checkDirectory, err := h.coherenceReadDirPage(handle, cookie, maxEntries)
	if err != nil {
		return false, [16]byte{}, err
	}
	if checkDirectory != directory || checkEOF != eof || !sameDirectoryEnumeration(checkEntries, entries) {
		return false, checkVerifier, nil
	}
	for _, candidate := range candidates {
		if candidate.item == (xfsstore.Capability{}) {
			continue
		}
		item, attr, lookupErr := h.Store.LookupOpen(handle, candidate.enumerated.Name)
		if errors.Is(lookupErr, syscall.ENOENT) || errors.Is(lookupErr, xfsstore.ErrStaleObject) ||
			errors.Is(lookupErr, xfsstore.ErrForbiddenType) || errors.Is(lookupErr, xfsstore.ErrProjectIsolation) {
			return false, checkVerifier, nil
		}
		if errors.Is(lookupErr, syscall.EAGAIN) {
			return false, checkVerifier, nil
		}
		if lookupErr != nil {
			return false, checkVerifier, lookupErr
		}
		identity, identityErr := h.Store.Identity(item)
		forgetErr := h.Store.Forget(item)
		if identityErr != nil || forgetErr != nil {
			return false, checkVerifier, errors.Join(identityErr, forgetErr)
		}
		if identity != candidate.identity || attr != candidate.attr {
			return false, checkVerifier, nil
		}
	}
	return true, checkVerifier, nil
}

// coherenceReadDirPage uses the store's stable XFS continuation offsets.
func (h *VolumeHandler) coherenceReadDirPage(handle xfsstore.Capability, cookie uint64, maxEntries int) ([]xfsstore.Dirent, uint64, [16]byte, bool, xfsstore.Capability, error) {
	return h.Store.ReadDirOpen(handle, cookie, maxEntries)
}
