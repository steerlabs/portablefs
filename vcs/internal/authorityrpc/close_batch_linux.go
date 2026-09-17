//go:build linux

package authorityrpc

import (
	"context"
	"errors"
	"syscall"

	"github.com/steerlabs/portablefs/vcs/internal/authoritypb"
	"github.com/steerlabs/portablefs/vcs/internal/volumeserver"
	"github.com/steerlabs/portablefs/vcs/internal/xfsstore"
)

func (h *VolumeHandler) handleCloseBatch(ctx context.Context, request *authoritypb.Request, cred volumeserver.SessionCredential) *authoritypb.Response {
	closes := request.GetCloseBatch().GetCloses()
	if len(closes) == 0 || len(closes) > MaxCloseBatch {
		return h.errorResponse(request.GetRequestId(), syscall.EINVAL, false)
	}
	seen := make(map[string]struct{}, len(closes))
	for _, close := range closes {
		if close == nil || len(close.GetHandle()) != 16 {
			return h.errorResponse(request.GetRequestId(), syscall.EINVAL, false)
		}
		key := string(close.GetHandle())
		if _, duplicate := seen[key]; duplicate {
			return h.errorResponse(request.GetRequestId(), syscall.EINVAL, false)
		}
		seen[key] = struct{}{}
	}
	// Closing descriptors cannot be atomic. Retain every ordered outcome in one
	// replay slot so retries neither close twice nor lose partial cleanup progress.
	return h.mutate(ctx, request, cred, func() *authoritypb.Response {
		results := make([]*authoritypb.CloseBatchResult, len(closes))
		for i, close := range closes {
			results[i] = h.closeBatchEntry(cred, close)
		}
		response := h.success(0)
		response.Body = &authoritypb.Response_CloseBatch{CloseBatch: &authoritypb.CloseBatchReply{Results: results}}
		return response
	})
}

func (h *VolumeHandler) closeForSession(cred volumeserver.SessionCredential, close *authoritypb.CloseRequest) *authoritypb.Response {
	handle, err := h.open(cred.ID, close.GetHandle())
	if err != nil {
		return h.errorResponse(0, err, false)
	}
	if close.GetFlockUnlock() {
		if err := h.unlockOpenOwner(cred, handle, close.GetLockOwner(), true); err != nil {
			return h.errorResponse(0, err, false)
		}
	}
	if err := h.Store.CloseOpen(handle); err != nil {
		return h.errorResponse(0, err, false)
	}
	h.untrackOpen(cred.ID, handle)
	return h.success(0)
}

// A close error reports descriptor cleanup, not ownership of a retryable open.
// CloseOpen consumes the store capability before releasing its last reference.
func (h *VolumeHandler) closeBatchEntry(cred volumeserver.SessionCredential, close *authoritypb.CloseRequest) *authoritypb.CloseBatchResult {
	handle, err := h.open(cred.ID, close.Handle)
	if err != nil {
		response := h.errorResponse(0, err, false)
		return &authoritypb.CloseBatchResult{Errno: response.Errno, Failure: response.Failure, Retired: errors.Is(err, xfsstore.ErrStaleOpen)}
	}
	var firstErr error
	if close.FlockUnlock {
		firstErr = h.unlockOpenOwner(cred, handle, close.LockOwner, true)
	}
	if err := h.Store.CloseOpen(handle); firstErr == nil {
		firstErr = err
	}
	h.untrackOpen(cred.ID, handle)
	result := &authoritypb.CloseBatchResult{Retired: true}
	if firstErr != nil {
		response := h.errorResponse(0, firstErr, false)
		result.Errno, result.Failure = response.Errno, response.Failure
	}
	return result
}
