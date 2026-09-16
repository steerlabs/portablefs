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
	release, err := h.coherenceStorage.Acquire(ctx, coherenceInodeDependencies(identity))
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
		return nil, h.Coherence.BreakForRead(ctx, identity)
	}
	token, err := h.coherenceToken(session)
	if err != nil {
		return nil, err
	}
	return h.Coherence.DataConsumed(ctx, token, identity)
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
	guard, err := h.coherenceReadAdmission(ctx, session, identity)
	if err != nil {
		return h.coherenceError(requestID, err)
	}
	defer guard.Release()
	release, err := h.coherenceStorage.Acquire(ctx, coherenceInodeDependencies(identity))
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
	guard, err := h.coherenceReadAdmission(ctx, session, identity)
	if err != nil {
		return h.coherenceError(requestID, err)
	}
	defer guard.Release()
	release, err := h.coherenceStorage.Acquire(ctx, coherenceInodeDependencies(identity))
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
		for attempt := 0; attempt < maxStabilizeAttempts; attempt++ {
			probeRelease, acquireErr := h.coherenceStorage.Acquire(ctx, coherenceBindingDependencies(parentIdentity, request.GetName(), [16]byte{}))
			if acquireErr != nil {
				return h.errorResponse(0, acquireErr, false)
			}
			probe, _, lookupErr := h.Store.Lookup(parent, string(request.GetName()))
			if errors.Is(lookupErr, syscall.ENOENT) {
				version := h.coherenceVersionNow()
				probeRelease()
				response := h.success(0)
				response.VolumeVersion = version
				response.Body = &authoritypb.Response_Lookup{Lookup: &authoritypb.LookupReply{NegativeSnapshotSequence: version}}
				return response
			}
			if lookupErr != nil {
				probeRelease()
				return h.errorResponse(0, lookupErr, false)
			}
			identity, identityErr := h.Store.Identity(probe)
			forgetErr := h.Store.Forget(probe)
			probeRelease()
			if identityErr != nil || forgetErr != nil {
				return h.errorResponse(0, errors.Join(identityErr, forgetErr), false)
			}

			guard, guardErr := h.coherenceReadAdmission(ctx, cred.ID, identity)
			if guardErr != nil {
				return h.coherenceError(0, guardErr)
			}
			completeRelease, acquireErr := h.coherenceStorage.Acquire(ctx, coherenceBindingDependencies(parentIdentity, request.GetName(), identity))
			if acquireErr != nil {
				guard.Release()
				return h.errorResponse(0, acquireErr, false)
			}
			item, attr, lookupErr := h.Store.Lookup(parent, string(request.GetName()))
			if lookupErr == nil {
				current, currentErr := h.Store.Identity(item)
				if currentErr != nil {
					h.forgetItem(item)
					completeRelease()
					guard.Release()
					return h.errorResponse(0, currentErr, false)
				}
				if current != identity {
					h.forgetItem(item)
					completeRelease()
					guard.Release()
					continue
				}
				attr, lookupErr = h.getattrItemRestored(identity, item)
			}
			if lookupErr != nil {
				if item != (xfsstore.Capability{}) {
					h.forgetItem(item)
				}
				completeRelease()
				guard.Release()
				if errors.Is(lookupErr, syscall.ENOENT) {
					continue
				}
				return h.errorResponse(0, lookupErr, false)
			}
			version := h.coherenceVersionNow()
			if err := h.trackItem(cred.ID, item, h.protectedChild(cred.ID, parent, request.GetName())); err != nil {
				completeRelease()
				guard.Release()
				return h.errorResponse(0, err, false)
			}
			completeRelease()
			guard.Release()
			itemReply := itemProto(item, attr, identity)
			itemReply.ObjectVersion = h.sampledObjectVersion(identity, version)
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
		var verifier [16]byte
		if len(request.GetVerifier()) != 0 {
			if len(request.GetVerifier()) != len(verifier) {
				return h.errorResponse(0, syscall.EINVAL, false)
			}
			copy(verifier[:], request.GetVerifier())
		}
		budget := h.readDirEntryBudget(request.GetMaxEntries())
		for attempt := 0; attempt < maxStabilizeAttempts; attempt++ {
			entries, _, current, eof, directory, readErr := h.coherenceReadDirPage(handle, cookie, verifier, int(request.GetMaxEntries()))
			if readErr != nil {
				return h.errorResponse(0, readErr, false)
			}
			candidates, budgetExhausted, conflict, buildErr := h.constructDirectoryPage(handle, entries, cookie, request.GetWantItems(), budget)
			if buildErr != nil {
				return h.errorResponse(0, buildErr, false)
			}
			if conflict {
				continue
			}

			identities := make([][16]byte, 0, len(candidates)+1)
			identities = append(identities, directoryIdentity)
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
			for _, identity := range identities {
				guard, guardErr := h.coherenceReadAdmission(ctx, cred.ID, identity)
				if guardErr != nil {
					h.forgetDirectoryCandidates(candidates)
					return h.coherenceError(0, guardErr)
				}
				guard.Release()
			}

			dependencies := h.coherenceDirectoryDependencies(directoryIdentity, candidates)
			release, acquireErr := h.coherenceStorage.Acquire(ctx, dependencies)
			if acquireErr != nil {
				h.forgetDirectoryCandidates(candidates)
				return h.errorResponse(0, acquireErr, false)
			}
			valid, verifyErr := h.coherenceRevalidateDirectoryPage(handle, directory, cookie, current, int(request.GetMaxEntries()), entries, eof, candidates)
			if verifyErr != nil || !valid {
				release()
				h.forgetDirectoryCandidates(candidates)
				if verifyErr != nil {
					return h.errorResponse(0, verifyErr, false)
				}
				continue
			}
			version := h.coherenceVersionNow()
			release()

			result := &authoritypb.ReadDirReply{Verifier: current[:], Eof: eof && !budgetExhausted}
			issued := make([]directoryPageCandidate, 0, len(candidates))
			for _, candidate := range candidates {
				candidate.dirent.ObjectVersion = h.sampledObjectVersion(candidate.identity, version)
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
		return h.errorResponse(0, syscall.EAGAIN, false)
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
	verifier [16]byte,
	maxEntries int,
	entries []xfsstore.Dirent,
	eof bool,
	candidates []directoryPageCandidate,
) (bool, error) {
	checkEntries, _, checkVerifier, checkEOF, checkDirectory, err := h.coherenceReadDirPage(handle, cookie, verifier, maxEntries)
	if err != nil {
		return false, err
	}
	if checkDirectory != directory || checkVerifier != verifier || checkEOF != eof || !sameDirectoryEnumeration(checkEntries, entries) {
		return false, nil
	}
	for _, candidate := range candidates {
		if candidate.item == (xfsstore.Capability{}) {
			continue
		}
		item, attr, lookupErr := h.Store.LookupOpen(handle, candidate.enumerated.Name)
		if errors.Is(lookupErr, syscall.ENOENT) || errors.Is(lookupErr, xfsstore.ErrStaleObject) ||
			errors.Is(lookupErr, xfsstore.ErrForbiddenType) || errors.Is(lookupErr, xfsstore.ErrProjectIsolation) {
			return false, nil
		}
		if lookupErr != nil {
			return false, lookupErr
		}
		identity, identityErr := h.Store.Identity(item)
		forgetErr := h.Store.Forget(item)
		if identityErr != nil || forgetErr != nil {
			return false, errors.Join(identityErr, forgetErr)
		}
		if identity != candidate.identity || attr != candidate.attr {
			return false, nil
		}
	}
	return true, nil
}

// coherenceReadDirPage uses the store's stable XFS continuation offsets.
func (h *VolumeHandler) coherenceReadDirPage(handle xfsstore.Capability, cookie uint64, verifier [16]byte, maxEntries int) ([]xfsstore.Dirent, uint64, [16]byte, bool, xfsstore.Capability, error) {
	return h.Store.ReadDirOpen(handle, cookie, verifier, maxEntries)
}
