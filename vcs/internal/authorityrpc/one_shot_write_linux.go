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

func oneShotWriteMetadata(body *authoritypb.OneShotWriteRequest, maxWrite uint32) (writeTransactionMetadata, error) {
	if body == nil || body.GetSize() == 0 || body.GetSize() > maxWrite || uint32(len(body.GetData())) != body.GetSize() {
		return writeTransactionMetadata{}, syscall.EINVAL
	}
	return writeMetadataFromGeometry(body.GetHandle(), uint64(body.GetSize()), body.GetPosition(), body.GetRlimitFsize(),
		body.GetFileMaxSize(), body.GetLockOwner(), body.GetWriteFlags(), body.GetFlags())
}

func oneShotWriteRejection(cause error, rlimit bool) *authoritypb.Response {
	errno := wireErrno(cause)
	if errno <= 0 || errno > 4095 {
		errno = int32(syscall.EIO)
	}
	flags := writeTransactionReplyRejected
	if rlimit {
		flags = writeTransactionReplyRLimit
	}
	return &authoritypb.Response{Body: &authoritypb.Response_OneShotWrite{OneShotWrite: &authoritypb.OneShotWriteReply{
		Flags: flags, Error: -errno,
	}}}
}

func oneShotWriteCommitReply(committed, assigned, post, sequence uint64, postAttr xfsstore.Attr, err error) *authoritypb.Response {
	flags := writeTransactionReplyCommitted
	wireError := int32(0)
	if err != nil && errors.Is(err, xfsstore.ErrWritePostApply) {
		flags |= writeTransactionReplyPostApply
		wireError = -wireErrno(err)
		if wireError >= 0 {
			wireError = -int32(syscall.EIO)
		}
	}
	return &authoritypb.Response{
		PostAttr: attrProto(postAttr),
		Body: &authoritypb.Response_OneShotWrite{OneShotWrite: &authoritypb.OneShotWriteReply{
			CommittedSize: committed, AssignedOffset: assigned, PostSize: post,
			VisibilitySequence: sequence, Flags: flags, Error: wireError,
		}},
	}
}

func markOneShotWritePostApplyFailure(response *authoritypb.Response, cause error) bool {
	if response == nil || cause == nil {
		return false
	}
	reply := response.GetOneShotWrite()
	if reply == nil || reply.GetFlags()&writeTransactionReplyCommitted == 0 {
		return false
	}
	reply.Flags |= writeTransactionReplyPostApply
	reply.Error = -wireErrno(cause)
	if reply.Error >= 0 {
		reply.Error = -int32(syscall.EIO)
	}
	response.Errno = 0
	response.Uncertain = false
	return true
}

// handleOneShotWrite executes a complete one-frame write as one ordinary
// replay-slot mutation. Capacity is charged to the same FIFO byte/count
// budgets as staged transactions, but the retained frame payload is written
// directly and no staging object or transaction ID exists.
func (h *VolumeHandler) handleOneShotWrite(ctx context.Context, request *authoritypb.Request, credential volumeserver.SessionCredential, body *authoritypb.OneShotWriteRequest) *authoritypb.Response {
	metadata, metadataErr := oneShotWriteMetadata(body, h.MaxWrite)
	var resources *sessionResources
	var target xfsstore.WriteTarget
	var coordinate visibilityCoordinate
	reserved := false
	defer func() {
		if target != nil {
			_ = target.Close()
		}
		if reserved {
			h.releaseWriteTransactionCapacity(resources, metadata.requestedSize)
		}
	}()

	prepare := func() ([]volumeserver.VisibilityTarget, error) {
		if metadataErr != nil {
			return nil, metadataErr
		}
		var err error
		resources, err = h.writeTransactionResources(credential.ID)
		if err != nil {
			return nil, err
		}
		terminal, err := h.Runtime.SessionTerminal(credential.ID)
		if err != nil {
			return nil, err
		}
		if err := h.reserveWriteTransactionCapacity(ctx, terminal, resources, metadata.requestedSize); err != nil {
			return nil, err
		}
		reserved = true
		store, ok := h.Store.(writeTransactionStore)
		if !ok {
			return nil, syscall.EOPNOTSUPP
		}
		target, err = store.PinWriteTarget(metadata.handle)
		if err != nil {
			return nil, err
		}
		object := target.Coordinate()
		if object.Stable == ([16]byte{}) || object.Ino == 0 {
			return nil, syscall.EIO
		}
		coordinate = visibilityCoordinate{
			identity: object.Stable, ino: object.Ino,
			device: uint64(object.DeviceMajor)<<32 | uint64(object.DeviceMinor),
		}
		return []volumeserver.VisibilityTarget{
			inodeTarget(volumeserver.VisibilityData, coordinate, 0),
			inodeTarget(volumeserver.VisibilityAttributes, coordinate, 0),
		}, nil
	}

	return h.mutateVisibleSequence(ctx, request, credential, prepare, func(sequence uint64) (*authoritypb.Response, []volumeserver.VisibilityTarget) {
		if target == nil {
			return h.errorResponse(0, syscall.EIO, false), nil
		}
		committed, assigned, post, applyErr := target.CommitWriteData(body.GetData(), xfsstore.WriteCommit{
			RequestedSize: metadata.requestedSize, Position: metadata.position,
			RLimitSize: metadata.rlimitSize, FileMaxSize: metadata.fileMaxSize, Mode: metadata.mode,
			DataSync: metadata.dataSync, Sync: metadata.sync,
			KillPrivileges: metadata.writeFlags&writeTransactionKillSUIDGID != 0,
		})
		zeroPostApply := committed == 0 && errors.Is(applyErr, xfsstore.ErrWritePostApply) &&
			!errors.Is(applyErr, xfsstore.ErrOutcomeUncertain)
		if committed == 0 && !zeroPostApply {
			if applyErr == nil {
				return h.errorResponse(0, syscall.EIO, true), []volumeserver.VisibilityTarget{}
			}
			if errors.Is(applyErr, xfsstore.ErrOutcomeUncertain) || errors.Is(applyErr, xfsstore.ErrWritePostApply) {
				return h.errorResponse(0, applyErr, true), []volumeserver.VisibilityTarget{}
			}
			var limit *xfsstore.WriteLimitError
			response := oneShotWriteRejection(applyErr, errors.As(applyErr, &limit) && limit.RLimit)
			h.deferStorageFailure(nil, applyErr)
			return response, nil
		}
		if zeroPostApply {
			if post.Kind != xfsstore.KindRegular || post.Size < 0 || sequence == 0 {
				return h.errorResponse(0, syscall.EIO, true), []volumeserver.VisibilityTarget{}
			}
			response := oneShotWriteCommitReply(0, 0, uint64(post.Size), sequence, post, applyErr)
			h.deferStorageFailure(response, applyErr)
			return response, []volumeserver.VisibilityTarget{
				inodeTarget(volumeserver.VisibilityData, coordinate, post.Size),
				inodeTarget(volumeserver.VisibilityAttributes, coordinate, 0),
			}
		}
		if committed > metadata.requestedSize || assigned > math.MaxInt64 || committed > math.MaxInt64-assigned {
			return h.errorResponse(0, syscall.EIO, true), []volumeserver.VisibilityTarget{}
		}
		end := assigned + committed
		if post.Kind != xfsstore.KindRegular || post.Size < 0 || uint64(post.Size) < end || sequence == 0 {
			return h.errorResponse(0, syscall.EIO, true), []volumeserver.VisibilityTarget{}
		}
		if metadata.mode == xfsstore.WriteAppend && uint64(post.Size) != end ||
			metadata.mode == xfsstore.WritePositioned && assigned != metadata.position {
			return h.errorResponse(0, syscall.EIO, true), []volumeserver.VisibilityTarget{}
		}
		if errors.Is(applyErr, xfsstore.ErrOutcomeUncertain) {
			return h.errorResponse(0, applyErr, true), []volumeserver.VisibilityTarget{}
		}
		if applyErr != nil && !errors.Is(applyErr, xfsstore.ErrWritePostApply) {
			applyErr = nil
		}
		response := oneShotWriteCommitReply(committed, assigned, uint64(post.Size), sequence, post, applyErr)
		if applyErr != nil {
			h.deferStorageFailure(response, applyErr)
		}
		return response, []volumeserver.VisibilityTarget{
			inodeTarget(volumeserver.VisibilityData, coordinate, post.Size),
			inodeTarget(volumeserver.VisibilityAttributes, coordinate, 0),
		}
	})
}
