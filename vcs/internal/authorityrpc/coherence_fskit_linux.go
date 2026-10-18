//go:build linux

package authorityrpc

import (
	"context"
	"errors"
	"syscall"

	"github.com/steerlabs/portablefs/vcs/internal/authoritypb"
	"github.com/steerlabs/portablefs/vcs/internal/volumeserver"
)

// FSKit shares storage scheduling and Linux withdrawal with ordinary mutations.
// Its runtime use pins the exact admitted writer through durability and replay;
// no profile read lock or peer-actuation owner participates in this path.
func (h *VolumeHandler) mutateFskitCoherence(ctx context.Context, req *authoritypb.Request, cred volumeserver.SessionCredential,
	prepare func(*operationResolutionContext) ([]volumeserver.MutationTarget, error),
	apply func(uint64, *mutationChanges) (*authoritypb.Response, []volumeserver.MutationTarget),
	syncMutation func() error, releases ...*func()) *authoritypb.Response {
	releaseStorage := func() {
		for _, p := range releases {
			if p != nil && *p != nil {
				(*p)()
				*p = nil
			}
		}
	}
	return h.mutateOperation(ctx, req, cred, func(volumeserver.MutationID) *authoritypb.Response {
		defer releaseStorage()
		if w := req.GetWrite(); w != nil && (w.GetAppend() || w.GetSync() || w.GetDataSync() || w.GetDelegation() != nil || w.GetFlushSequence() != 0 || w.GetWriteFlags()&writeLockOwner != 0 || w.GetLockOwner() != 0) {
			return h.errorResponse(0, syscall.EINVAL, false)
		}
		if op, _ := ctx.Value(coherenceOperationKey{}).(*coherenceOperation); op != nil && op.beforeAdmission != nil {
			admit := op.beforeAdmission
			op.beforeAdmission = nil
			if err := admit(); err != nil {
				return h.errorResponse(0, err, false)
			}
		}
		for attempt := 0; attempt < maxResolutionAttempts; attempt++ {
			resolver := newOperationResolutionContext(h, cred.ID)
			footprint, err := resolver.deriveCoherenceGate(req)
			if err != nil {
				return h.errorResponse(0, err, false)
			}
			deps := volumeserver.MutationDependenciesForFootprint(footprint)
			release, err := h.coherenceStorage.Acquire(ctx, deps)
			if err != nil {
				return h.errorResponse(0, err, false)
			}
			current := newOperationResolutionContext(h, cred.ID)
			checked, err := current.deriveCoherenceGate(req)
			if err != nil || !mutationFootprintsEqual(&footprint, &checked) {
				release()
				if err != nil {
					return h.errorResponse(0, err, false)
				}
				continue
			}
			prepared, err := prepare(current)
			if err == nil {
				err = deps.ValidateTargets(prepared)
			}
			if err != nil {
				releaseStorage()
				release()
				if errors.Is(err, volumeserver.ErrMutationDependencyRefresh) {
					continue
				}
				return h.errorResponse(0, err, false)
			}
			if err = ctx.Err(); err != nil {
				releaseStorage()
				release()
				return h.errorResponse(0, err, false)
			}
			use, err := h.Runtime.Begin(cred)
			if err == nil {
				err = h.Writers.CheckOwner(cred.ID)
			}
			if err != nil {
				if use != nil {
					use.End()
				}
				releaseStorage()
				release()
				return h.errorResponse(0, err, false)
			}
			// Fence racing this cut either denies admission above or retains this pin.
			changed := new(mutationChanges)
			response, targets := apply(1, changed)
			if response == nil {
				response = h.errorResponse(0, errInternal, true)
			}
			position := h.publishCoherenceCommit(req, cred.ID, [16]byte{}, response, targets, changed)
			stampMutationTargets(targets, response.GetPostState())
			if targets != nil {
				err = volumeserver.ValidateMutationCompletion(targets, prepared)
				if err == nil && !validMutationPostStateRoles(req, response.GetPostState()) {
					err = errInternal
				}
			}
			releaseStorage()
			release()
			if position != 0 {
				err = errors.Join(err, h.Coherence.WaitWithdrawn(context.WithoutCancel(ctx), position, cred.ID))
			}
			// A post-apply error never erases the persistence obligation.
			if targets != nil {
				if syncErr := h.syncFskitMutation(syncMutation); syncErr != nil {
					use.End()
					if response.GetUncertain() && response.GetFailure() == authoritypb.FailureClass_FAILURE_CLASS_STORAGE {
						h.deferStorageFailure(nil, syncErr)
						return response
					}
					if markFskitMutationPostApplyFailure(response, syncErr) {
						response.Failure = authoritypb.FailureClass_FAILURE_CLASS_STORAGE
						h.deferStorageFailure(response, syncErr)
						return response
					}
					return h.errorResponse(0, syncErr, true)
				}
			}
			use.End()
			if err != nil {
				return h.errorResponse(0, errors.Join(volumeserver.ErrMutationPoisoned, err), targets != nil)
			}
			return response
		}
		return h.errorResponse(0, syscall.EAGAIN, false)
	}, nil)
}
