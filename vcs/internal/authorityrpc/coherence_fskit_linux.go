//go:build linux

package authorityrpc

import (
	"context"
	"errors"
	"syscall"

	"github.com/steerlabs/portablefs/vcs/internal/authoritypb"
	"github.com/steerlabs/portablefs/vcs/internal/volumeserver"
)

// mutateFskitCoherence retains FSKit's source-publication and fragmented-write
// contracts while publishing the same protocol-7 change log Linux consumes.
// Storage locks and the cross-profile storage turn are released in the apply
// callback, after OnCommit and before post-apply peer repair or withdrawal.
func (h *VolumeHandler) mutateFskitCoherence(
	ctx context.Context,
	req *authoritypb.Request,
	cred volumeserver.SessionCredential,
	prepare func(*operationResolutionContext) ([]volumeserver.VisibilityTarget, error),
	apply func(uint64) (*authoritypb.Response, []volumeserver.VisibilityTarget),
	releases ...*func(),
) *authoritypb.Response {
	releaseStorage := func() {
		for _, release := range releases {
			if release != nil && *release != nil {
				(*release)()
				*release = nil
			}
		}
	}

	executed := false
	response := h.mutateOperation(ctx, req, cred, func(mutationID volumeserver.MutationID) *authoritypb.Response {
		writeCommit := req.GetFskitWrite()
		if writeCommit != nil && writeCommit.GetPhase() != authoritypb.FskitWritePhase_FSKIT_WRITE_PHASE_COMMIT {
			writeCommit = nil
		}
		var writeCommitOwner *fskitWriteCommitOwner
		defer func() {
			releaseStorage()
			if writeCommit != nil {
				h.finishFskitWriteCommit(cred.ID, writeCommit, writeCommitOwner)
			}
		}()
		definiteRejection := func(err error) *authoritypb.Response {
			if writeCommit != nil && writeCommitOwner != nil {
				if rejected := h.rejectPendingFskitWrite(cred.ID, writeCommit, err); rejected != nil {
					return rejected
				}
			}
			return h.errorResponse(0, err, false)
		}

		if h.Visibility == nil || h.coherenceStorage == nil {
			return definiteRejection(errInternal)
		}
		if writeCommit != nil {
			if terminal, found, err := h.rejectedFskitWriteTerminal(req, cred.ID, writeCommit); err != nil {
				return definiteRejection(err)
			} else if found {
				return terminal
			}
		}
		if !validFskitSourcePublicationPresence(req) {
			return definiteRejection(syscall.EINVAL)
		}
		declared, err := decodeFskitSourcePublication(req)
		if err != nil || declared == nil {
			return definiteRejection(syscall.EINVAL)
		}
		declaration := h.Visibility.DeclareSourceGate(*declared)
		declarationOwned := true
		releaseDeclaration := func() {
			if declarationOwned {
				declaration.Release()
				declarationOwned = false
			}
		}
		defer releaseDeclaration()

		resolution := newOperationResolutionContext(h, cred.ID)
		expected, gateErr := resolution.deriveSourcePublicationGate(req, true)
		if gateErr != nil || !sourcePublicationGatesEqual(declared, &expected) {
			if gateErr == nil {
				gateErr = volumeserver.ErrSourcePublicationGate
			}
			return definiteRejection(gateErr)
		}
		activeGate := expected

		if writeCommit != nil {
			writeCommitOwner, err = h.markFskitWriteCommitting(cred.ID, req, writeCommit)
			if err != nil {
				return definiteRejection(err)
			}
		}

		var releaseTurn func()
		releaseAll := func() {
			releaseStorage()
			if releaseTurn != nil {
				releaseTurn()
				releaseTurn = nil
			}
		}
		defer releaseAll()

		refresh := func() (volumeserver.SourcePublicationGate, error) {
			refreshedResolution := newOperationResolutionContext(h, cred.ID)
			refreshed, err := refreshedResolution.deriveSourcePublicationGate(req, true)
			if err == nil {
				activeGate = refreshed
				resolution = refreshedResolution
			}
			return refreshed, err
		}
		prepareForVisibility := func() ([]volumeserver.VisibilityTarget, error) {
			releaseAll()
			dependencies := volumeserver.MutationDependenciesForTargets(coherenceGateTargets(activeGate))
			var err error
			releaseTurn, err = h.coherenceStorage.Acquire(ctx, dependencies)
			if err != nil {
				return nil, err
			}
			prepared, err := prepare(resolution)
			if err != nil {
				releaseAll()
				return nil, err
			}
			prepared, err = normalizeMutationVisibilityTargets(prepared)
			if err != nil {
				releaseAll()
				return nil, err
			}
			return prepared, nil
		}

		var (
			result     *authoritypb.Response
			changes    []volumeserver.VisibilityTarget
			position   uint64
			applied    bool
			publishErr error
		)
		published := func() ([]volumeserver.VisibilityResolution, error) {
			return sourcePublicationResolutions(req, result)
		}
		declarationOwned = false // Execute owns the declaration on every return path.
		_, visibilityErr := h.Visibility.ExecuteWithSourceGateSequence(
			ctx, cred.ID, mutationID, declaration, activeGate, refresh, prepareForVisibility,
			func(sequence uint64) ([]volumeserver.VisibilityTarget, bool) {
				applied = true
				result, changes = apply(sequence)
				if result == nil {
					publishErr = errInternal
					releaseAll()
					return nil, true
				}
				position = h.publishCoherenceCommit(req, cred.ID, [16]byte{}, sequence, result, changes)
				stampVisibilityTargets(changes, result.GetPostState())
				if changes != nil && !validMutationPostStateRoles(req, result.GetPostState()) {
					publishErr = errInternal
				}
				releaseAll()
				return changes, changes != nil
			},
			published,
		)
		releaseAll()

		if !applied {
			if visibilityErr == nil {
				visibilityErr = errInternal
			}
			return definiteRejection(visibilityErr)
		}
		if result == nil {
			return h.errorResponse(0, errInternal, true)
		}
		if publishErr != nil {
			visibilityErr = errors.Join(visibilityErr, publishErr)
		}
		if position != 0 {
			if err := h.Coherence.WaitWithdrawn(context.WithoutCancel(ctx), position, cred.ID); err != nil {
				visibilityErr = errors.Join(visibilityErr, err)
			}
		}
		if visibilityErr != nil {
			barrier := &volumeserver.VisibilityBarrierError{Applied: changes != nil, Err: visibilityErr}
			if changes != nil && markFskitWritePostApplyFailure(result, barrier) {
				h.deferCoherenceFailure(result, barrier)
				return result
			}
			return h.errorResponse(0, barrier, changes != nil)
		}
		return result
	}, &executed)
	if writeCommit := req.GetFskitWrite(); writeCommit != nil &&
		writeCommit.GetPhase() == authoritypb.FskitWritePhase_FSKIT_WRITE_PHASE_COMMIT &&
		!executed && response.GetMutation() == nil && response.GetErrno() == int32(syscall.ENOMEM) {
		return h.rejectUnadmittedFskitWrite(req, cred.ID, writeCommit)
	}
	return response
}
