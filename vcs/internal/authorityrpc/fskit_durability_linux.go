//go:build linux

package authorityrpc

import (
	"syscall"
	"time"

	"github.com/steerlabs/portablefs/vcs/internal/authoritypb"
	"github.com/steerlabs/portablefs/vcs/internal/xfsstore"
)

// retainFskitMutationHandle takes a reference to an already-open description.
// Call it while applying the mutation, before its storage turn is released.
func (h *VolumeHandler) retainFskitMutationHandle(profile authoritypb.FrontendProfile, handle xfsstore.Capability) (xfsstore.SyncTarget, error) {
	if profile != authoritypb.FrontendProfile_FRONTEND_PROFILE_FSKIT_EXCLUSIVE {
		return nil, nil
	}
	return h.Store.PinSyncHandle(handle)
}

func syncFskitHandle(target xfsstore.SyncTarget) error {
	if target == nil {
		return &xfsstore.DurabilityError{Cause: syscall.ESTALE}
	}
	return target.Sync()
}

// The caller declares its descriptor barrier at the mutation's apply site.
// Handleless mutations use syncfs directly. No request context may cancel the
// storage obligation after apply, and no acquisition failure changes the rule.
func (h *VolumeHandler) syncFskitMutation(syncHandle func() error) error {
	kind := "syncfs"
	sync := h.Store.SyncFS
	if syncHandle != nil {
		kind, sync = "handle", syncHandle
	}
	started := time.Now()
	err := sync()
	h.Metrics.ObserveFskitDurability(kind, time.Since(started))
	if err != nil {
		return &xfsstore.DurabilityError{Cause: err}
	}
	return nil
}

func markFskitMutationPostApplyFailure(response *authoritypb.Response, cause error) bool {
	return markWritePostApplyFailure(response, cause)
}
