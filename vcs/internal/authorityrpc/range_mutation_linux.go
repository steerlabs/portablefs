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
	"golang.org/x/sys/unix"
)

const (
	rangeReplyApplied        uint32 = 1 << 0
	rangeReplyRejected       uint32 = 1 << 1
	rangeReplyPostApply      uint32 = 1 << 2
	rangeReplyRejectedRLimit uint32 = 1 << 3
	rangeReplyNoop           uint32 = 1 << 4
)

type rangeMutationStore interface {
	Fallocate(xfsstore.Capability, xfsstore.FallocateSpec) (xfsstore.Attr, error)
	CopyFileRange(xfsstore.Capability, xfsstore.Capability, xfsstore.CopyFileRangeSpec) (uint64, xfsstore.Attr, error)
}

func validRangeWriteFlags(flags uint32) bool {
	return flags == 0 || flags == writeTransactionKillSUIDGID
}

func validFallocateRequest(body *authoritypb.FallocateRequest) bool {
	if body == nil || len(body.GetHandle()) != 16 || body.GetLength() == 0 ||
		body.GetOffset() > math.MaxInt64 || body.GetLength() > math.MaxInt64-body.GetOffset() ||
		body.GetFileMaxSize() == 0 || body.GetFileMaxSize() > math.MaxInt64 || !validRangeWriteFlags(body.GetWriteFlags()) {
		return false
	}
	switch body.GetMode() {
	case 0,
		uint32(unix.FALLOC_FL_KEEP_SIZE),
		uint32(unix.FALLOC_FL_PUNCH_HOLE | unix.FALLOC_FL_KEEP_SIZE),
		uint32(unix.FALLOC_FL_ZERO_RANGE),
		uint32(unix.FALLOC_FL_ZERO_RANGE | unix.FALLOC_FL_KEEP_SIZE),
		uint32(unix.FALLOC_FL_COLLAPSE_RANGE),
		uint32(unix.FALLOC_FL_INSERT_RANGE),
		uint32(unix.FALLOC_FL_UNSHARE_RANGE),
		uint32(unix.FALLOC_FL_UNSHARE_RANGE | unix.FALLOC_FL_KEEP_SIZE):
		return true
	default:
		return false
	}
}

func validCopyFileRangeRequest(body *authoritypb.CopyFileRangeRequest) bool {
	return body != nil && len(body.GetInputHandle()) == 16 && len(body.GetOutputHandle()) == 16 && body.GetLength() != 0 &&
		body.GetInputOffset() <= math.MaxInt64 && body.GetLength() <= math.MaxInt64-body.GetInputOffset() &&
		body.GetOutputOffset() <= math.MaxInt64 && body.GetLength() <= math.MaxInt64-body.GetOutputOffset() &&
		body.GetFileMaxSize() != 0 && body.GetFileMaxSize() <= math.MaxInt64 &&
		validRangeWriteFlags(body.GetWriteFlags()) && body.GetFlags() == 0
}

func rangeCoordinate(coordinate xfsstore.ObjectCoordinate) visibilityCoordinate {
	return visibilityCoordinate{
		identity: coordinate.Stable,
		ino:      coordinate.Ino,
		device:   uint64(coordinate.DeviceMajor)<<32 | uint64(coordinate.DeviceMinor),
	}
}

func rangeResultError(err error) int32 {
	errno := wireErrno(err)
	if errno <= 0 {
		errno = int32(syscall.EIO)
	}
	return -errno
}

func fallocateRejected(h *VolumeHandler, before xfsstore.Attr, err error) *authoritypb.Response {
	flags := rangeReplyRejected
	preSize := uint64(0)
	var limit *xfsstore.WriteLimitError
	if errors.As(err, &limit) && limit.RLimit {
		flags = rangeReplyRejectedRLimit
		preSize = uint64(before.Size)
	}
	resp := h.success(0)
	resp.Body = &authoritypb.Response_Fallocate{Fallocate: &authoritypb.FallocateReply{
		PostSize: preSize, Flags: flags, Error: rangeResultError(err),
	}}
	return resp
}

func copyFileRangeRejected(h *VolumeHandler, err error) *authoritypb.Response {
	flags := rangeReplyRejected
	var limit *xfsstore.WriteLimitError
	if errors.As(err, &limit) && limit.RLimit {
		flags = rangeReplyRejectedRLimit
	}
	resp := h.success(0)
	resp.Body = &authoritypb.Response_CopyFileRange{CopyFileRange: &authoritypb.CopyFileRangeReply{
		Flags: flags, Error: rangeResultError(err),
	}}
	return resp
}

func (h *VolumeHandler) handleFallocate(ctx context.Context, req *authoritypb.Request, credential volumeserver.SessionCredential, body *authoritypb.FallocateRequest) *authoritypb.Response {
	store, ok := h.Store.(rangeMutationStore)
	if !ok {
		return h.errorResponse(req.GetRequestId(), errInternal, false)
	}
	var handle xfsstore.Capability
	var coordinate visibilityCoordinate
	var releaseMutation func()
	prepare := func() ([]volumeserver.VisibilityTarget, error) {
		if !validFallocateRequest(body) {
			return nil, syscall.EINVAL
		}
		var err error
		handle, err = h.open(credential.ID, body.GetHandle())
		if err != nil {
			return nil, err
		}
		resolved, err := h.Store.CoordinateOpen(handle)
		if err != nil {
			return nil, err
		}
		coordinate = rangeCoordinate(resolved)
		releaseMutation, err = lockMutationStore(h.Store, coordinate.identity)
		if err != nil {
			return nil, err
		}
		return []volumeserver.VisibilityTarget{
			inodeTarget(volumeserver.VisibilityData, coordinate, 0),
			inodeTarget(volumeserver.VisibilityAttributes, coordinate, 0),
		}, nil
	}
	response := h.mutateVisibleSequence(ctx, req, credential, prepare, func(sequence uint64) (*authoritypb.Response, []volumeserver.VisibilityTarget) {
		post, applyErr := store.Fallocate(handle, xfsstore.FallocateSpec{
			Offset: body.GetOffset(), Length: body.GetLength(), RLimitSize: body.GetRlimitFsize(),
			FileMaxSize: body.GetFileMaxSize(), Mode: body.GetMode(),
			KillPrivileges: body.GetWriteFlags()&writeTransactionKillSUIDGID != 0,
		})
		if applyErr != nil && !errors.Is(applyErr, xfsstore.ErrWritePostApply) {
			if errors.Is(applyErr, xfsstore.ErrOutcomeUncertain) {
				return h.errorResponse(0, applyErr, true), []volumeserver.VisibilityTarget{}
			}
			var limit *xfsstore.WriteLimitError
			if errors.As(applyErr, &limit) && limit.RLimit &&
				(post.Kind != xfsstore.KindRegular || post.Size < 0) {
				return h.errorResponse(0, syscall.EIO, true), []volumeserver.VisibilityTarget{}
			}
			response := fallocateRejected(h, post, applyErr)
			h.deferStorageFailure(nil, applyErr)
			return response, nil
		}
		if post.Kind != xfsstore.KindRegular || post.Size < 0 || sequence == 0 {
			return h.errorResponse(0, syscall.EIO, true), []volumeserver.VisibilityTarget{}
		}
		flags, resultErr := rangeReplyApplied, int32(0)
		if applyErr != nil {
			flags |= rangeReplyPostApply
			resultErr = rangeResultError(applyErr)
		}
		resp := h.success(0)
		resp.PostState = h.mutationPostState(sequence, postStateSnapshot{identity: coordinate.identity, attr: post, roles: postStateRoleTarget, changed: true})
		resp.Body = &authoritypb.Response_Fallocate{Fallocate: &authoritypb.FallocateReply{
			PostSize: uint64(post.Size), VisibilitySequence: sequence, Flags: flags, Error: resultErr,
		}}
		if applyErr != nil {
			h.deferStorageFailure(resp, applyErr)
		}
		return resp, []volumeserver.VisibilityTarget{
			inodeTarget(volumeserver.VisibilityData, coordinate, post.Size),
			inodeTarget(volumeserver.VisibilityAttributes, coordinate, 0),
		}
	})
	if releaseMutation != nil {
		releaseMutation()
	}
	return response
}

func (h *VolumeHandler) handleCopyFileRange(ctx context.Context, req *authoritypb.Request, credential volumeserver.SessionCredential, body *authoritypb.CopyFileRangeRequest) *authoritypb.Response {
	store, ok := h.Store.(rangeMutationStore)
	if !ok {
		return h.errorResponse(req.GetRequestId(), errInternal, false)
	}
	var input, output xfsstore.Capability
	var sourceCoordinate, destinationCoordinate visibilityCoordinate
	var releaseMutation func()
	prepare := func() ([]volumeserver.VisibilityTarget, error) {
		if !validCopyFileRangeRequest(body) {
			return nil, syscall.EINVAL
		}
		var err error
		input, err = h.open(credential.ID, body.GetInputHandle())
		if err == nil {
			output, err = h.open(credential.ID, body.GetOutputHandle())
		}
		if err != nil {
			return nil, err
		}
		source, err := h.Store.CoordinateOpen(input)
		if err == nil {
			var destination xfsstore.ObjectCoordinate
			destination, err = h.Store.CoordinateOpen(output)
			if err == nil {
				sourceCoordinate = rangeCoordinate(source)
				destinationCoordinate = rangeCoordinate(destination)
			}
		}
		if err != nil {
			return nil, err
		}
		releaseMutation, err = lockMutationStore(h.Store, sourceCoordinate.identity, destinationCoordinate.identity)
		if err != nil {
			return nil, err
		}
		return []volumeserver.VisibilityTarget{
			inodeTarget(volumeserver.VisibilityData, sourceCoordinate, 0),
			inodeTarget(volumeserver.VisibilityAttributes, sourceCoordinate, 0),
			inodeTarget(volumeserver.VisibilityData, destinationCoordinate, 0),
			inodeTarget(volumeserver.VisibilityAttributes, destinationCoordinate, 0),
		}, nil
	}
	response := h.mutateVisibleSequence(ctx, req, credential, prepare, func(sequence uint64) (*authoritypb.Response, []volumeserver.VisibilityTarget) {
		copied, post, applyErr := store.CopyFileRange(input, output, xfsstore.CopyFileRangeSpec{
			InputOffset: body.GetInputOffset(), OutputOffset: body.GetOutputOffset(), Length: body.GetLength(),
			RLimitSize: body.GetRlimitFsize(), FileMaxSize: body.GetFileMaxSize(),
			KillPrivileges: body.GetWriteFlags()&writeTransactionKillSUIDGID != 0,
		})
		zeroPostApply := copied == 0 && errors.Is(applyErr, xfsstore.ErrWritePostApply) &&
			!errors.Is(applyErr, xfsstore.ErrOutcomeUncertain)
		if copied == 0 && !zeroPostApply {
			if applyErr == nil {
				resp := h.success(0)
				resp.Body = &authoritypb.Response_CopyFileRange{CopyFileRange: &authoritypb.CopyFileRangeReply{Flags: rangeReplyNoop}}
				return resp, nil
			}
			if errors.Is(applyErr, xfsstore.ErrOutcomeUncertain) || errors.Is(applyErr, xfsstore.ErrWritePostApply) {
				return h.errorResponse(0, applyErr, true), []volumeserver.VisibilityTarget{}
			}
			response := copyFileRangeRejected(h, applyErr)
			h.deferStorageFailure(nil, applyErr)
			return response, nil
		}
		if copied > body.GetLength() || post.Kind != xfsstore.KindRegular || post.Size < 0 || sequence == 0 ||
			errors.Is(applyErr, xfsstore.ErrOutcomeUncertain) {
			return h.errorResponse(0, syscall.EIO, true), []volumeserver.VisibilityTarget{}
		}
		if copied != 0 && (body.GetOutputOffset() > math.MaxInt64-copied || uint64(post.Size) < body.GetOutputOffset()+copied) {
			return h.errorResponse(0, syscall.EIO, true), []volumeserver.VisibilityTarget{}
		}
		flags, resultErr := rangeReplyApplied, int32(0)
		if errors.Is(applyErr, xfsstore.ErrWritePostApply) {
			flags |= rangeReplyPostApply
			resultErr = rangeResultError(applyErr)
		}
		sourcePost, sourceErr := h.Store.GetattrOpen(input)
		if sourceErr != nil {
			return h.errorResponse(0, sourceErr, true), []volumeserver.VisibilityTarget{}
		}
		resp := h.success(0)
		resp.PostState = h.mutationPostState(sequence,
			postStateSnapshot{identity: sourceCoordinate.identity, attr: sourcePost, roles: postStateRoleSource, changed: true},
			postStateSnapshot{identity: destinationCoordinate.identity, attr: post, roles: postStateRoleDestination, changed: true},
		)
		resp.Body = &authoritypb.Response_CopyFileRange{CopyFileRange: &authoritypb.CopyFileRangeReply{
			ResultSize: copied, PostSize: uint64(post.Size), VisibilitySequence: sequence, Flags: flags, Error: resultErr,
		}}
		if applyErr != nil {
			h.deferStorageFailure(resp, applyErr)
		}
		return resp, []volumeserver.VisibilityTarget{
			inodeTarget(volumeserver.VisibilityAttributes, sourceCoordinate, 0),
			inodeTarget(volumeserver.VisibilityData, destinationCoordinate, post.Size),
			inodeTarget(volumeserver.VisibilityAttributes, destinationCoordinate, 0),
		}
	})
	if releaseMutation != nil {
		releaseMutation()
	}
	return response
}

// markRangePostApplyFailure preserves the exact range result after XFS changed
// but peer completion failed. The patched kernel must publish that known local
// state before surfacing the embedded errno; an outer uncertain response would
// discard the only truthful size and invite a retry.
func markRangePostApplyFailure(response *authoritypb.Response, cause error) bool {
	if response == nil || cause == nil {
		return false
	}
	if reply := response.GetFallocate(); reply != nil && reply.GetFlags()&rangeReplyApplied != 0 {
		reply.Flags |= rangeReplyPostApply
		reply.Error = rangeResultError(cause)
		return true
	}
	if reply := response.GetCopyFileRange(); reply != nil && reply.GetFlags()&rangeReplyApplied != 0 {
		reply.Flags |= rangeReplyPostApply
		reply.Error = rangeResultError(cause)
		return true
	}
	return false
}
