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

type writeMetadata struct {
	handle        xfsstore.Capability
	requestedSize uint64
	position      uint64
	lockOwner     uint64
	writeFlags    uint32
	mode          xfsstore.WriteMode
	sync          bool
	dataSync      bool
}

func stockWriteMetadata(body *authoritypb.WriteRequest, maxWrite uint32) (writeMetadata, error) {
	var metadata writeMetadata
	if body == nil || body.GetSize() == 0 || body.GetSize() > maxWrite || uint32(len(body.GetData())) != body.GetSize() {
		return metadata, syscall.EINVAL
	}
	if len(body.GetHandle()) != len(metadata.handle) || body.GetPosition() > math.MaxInt64 ||
		body.GetWriteFlags()&^(writeLockOwner|writeKillSUIDGID) != 0 ||
		body.GetWriteFlags()&writeLockOwner == 0 && body.GetLockOwner() != 0 ||
		body.GetSync() && body.GetDataSync() {
		return metadata, syscall.EINVAL
	}
	// An append carries no position: the authority assigns one under the writer
	// stripe.
	if body.GetAppend() && body.GetPosition() != 0 {
		return metadata, syscall.EINVAL
	}
	copy(metadata.handle[:], body.GetHandle())
	if metadata.handle == (xfsstore.Capability{}) {
		return writeMetadata{}, syscall.EINVAL
	}
	metadata.requestedSize = uint64(body.GetSize())
	metadata.position = body.GetPosition()
	metadata.lockOwner = body.GetLockOwner()
	metadata.writeFlags = body.GetWriteFlags()
	metadata.mode = xfsstore.WritePositioned
	if body.GetAppend() {
		metadata.mode = xfsstore.WriteAppend
	}
	metadata.sync, metadata.dataSync = body.GetSync(), body.GetDataSync()
	return metadata, nil
}

func stockWriteRejection(cause error, _ bool) *authoritypb.Response {
	errno := wireErrno(cause)
	if errno <= 0 || errno > 4095 {
		errno = int32(syscall.EIO)
	}
	return &authoritypb.Response{Body: &authoritypb.Response_Write{Write: &authoritypb.WriteReply{
		Error: -errno,
	}}}
}

func stockWriteResponseWithEnvelope(h *VolumeHandler, requestID uint64, response *authoritypb.Response) *authoritypb.Response {
	if response == nil {
		return h.errorResponse(requestID, syscall.EIO, true)
	}
	response.RequestId = requestID
	response.Epoch = h.Epoch()
	return response
}

func stockWriteCommitReply(committed, assigned, post, sequence uint64, postAttr xfsstore.Attr, err error) *authoritypb.Response {
	wireError := int32(0)
	if err != nil && errors.Is(err, xfsstore.ErrWritePostApply) {
		wireError = -wireErrno(err)
		if wireError >= 0 {
			wireError = -int32(syscall.EIO)
		}
	}
	return &authoritypb.Response{
		Body: &authoritypb.Response_Write{Write: &authoritypb.WriteReply{
			CommittedSize: committed, AssignedOffset: assigned, PostAttr: attrProto(postAttr), Error: wireError,
		}},
	}
}

func markWritePostApplyFailure(response *authoritypb.Response, cause error) bool {
	if response == nil || cause == nil {
		return false
	}
	reply := response.GetWrite()
	if reply == nil || reply.GetPostAttr() == nil {
		return false
	}
	reply.Error = -wireErrno(cause)
	if reply.Error >= 0 {
		reply.Error = -int32(syscall.EIO)
	}
	response.Errno = 0
	response.Uncertain = false
	return true
}

// handleWrite executes a complete one-frame write as one ordinary
// replay-slot mutation. Capacity is charged to the same FIFO byte/count
// budgets as staged transactions, but the retained frame payload is written
// directly and no staging object or transaction ID exists.
func (h *VolumeHandler) handleWrite(ctx context.Context, request *authoritypb.Request, credential volumeserver.SessionCredential, body *authoritypb.WriteRequest) *authoritypb.Response {
	if h.WriteAbsoluteTimeout > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(ctx, h.WriteAbsoluteTimeout)
		defer cancel()
	}
	metadata, metadataErr := stockWriteMetadata(body, h.MaxWrite)
	var resources *sessionResources
	var target xfsstore.WriteTarget
	var coordinate visibilityCoordinate
	var releaseMutation func()
	reserved := false
	defer func() {
		if target != nil {
			_ = target.Close()
		}
		if reserved {
			h.releaseWriteAdmission(resources, metadata.requestedSize)
		}
	}()

	prepare := func() ([]volumeserver.VisibilityTarget, error) {
		if metadataErr != nil {
			return nil, metadataErr
		}
		var err error
		resources, err = h.sessionResources(credential.ID)
		if err != nil {
			return nil, err
		}
		terminal, err := h.Runtime.SessionTerminal(credential.ID)
		if err != nil {
			return nil, err
		}
		if err := h.reserveWriteAdmission(ctx, terminal, resources, metadata.requestedSize); err != nil {
			return nil, err
		}
		reserved = true
		store, ok := h.Store.(writeStore)
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
		releaseMutation, err = lockMutationStore(h.Store, coordinate.identity)
		if err != nil {
			return nil, err
		}
		return []volumeserver.VisibilityTarget{
			inodeTarget(volumeserver.VisibilityData, coordinate, 0),
			inodeTarget(volumeserver.VisibilityAttributes, coordinate, 0),
		}, nil
	}

	response := h.mutateVisibleSequence(ctx, request, credential, prepare, func(sequence uint64) (*authoritypb.Response, []volumeserver.VisibilityTarget) {
		if target == nil {
			return h.errorResponse(0, syscall.EIO, false), nil
		}
		committed, assigned, post, applyErr := target.CommitWriteData(body.GetData(), xfsstore.WriteCommit{
			RequestedSize: metadata.requestedSize, Position: metadata.position,
			RLimitSize: math.MaxUint64, FileMaxSize: math.MaxInt64, Mode: metadata.mode,
			DataSync: metadata.dataSync, Sync: metadata.sync,
			KillPrivileges: metadata.writeFlags&writeKillSUIDGID != 0,
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
			response := stockWriteRejection(applyErr, errors.As(applyErr, &limit) && limit.RLimit)
			h.deferStorageFailure(nil, applyErr)
			return response, nil
		}
		if zeroPostApply {
			if post.Kind != xfsstore.KindRegular || post.Size < 0 || sequence == 0 {
				return h.errorResponse(0, syscall.EIO, true), []volumeserver.VisibilityTarget{}
			}
			response := stockWriteCommitReply(0, 0, uint64(post.Size), sequence, post, applyErr)
			response.PostState = h.mutationPostState(sequence, postStateSnapshot{identity: coordinate.identity, attr: post, roles: postStateRoleTarget, changed: true})
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
		// An append is exact only if the object ends exactly where the committed
		// bytes end: any other post size means another writer interleaved inside
		// the writer stripe, which cannot happen.
		if metadata.mode == xfsstore.WriteAppend && uint64(post.Size) != end {
			return h.errorResponse(0, syscall.EIO, true), []volumeserver.VisibilityTarget{}
		}
		if metadata.mode == xfsstore.WritePositioned && assigned != metadata.position {
			return h.errorResponse(0, syscall.EIO, true), []volumeserver.VisibilityTarget{}
		}
		if errors.Is(applyErr, xfsstore.ErrOutcomeUncertain) {
			return h.errorResponse(0, applyErr, true), []volumeserver.VisibilityTarget{}
		}
		if applyErr != nil && !errors.Is(applyErr, xfsstore.ErrWritePostApply) {
			applyErr = nil
		}
		response := stockWriteCommitReply(committed, assigned, uint64(post.Size), sequence, post, applyErr)
		response.PostState = h.mutationPostState(sequence, postStateSnapshot{identity: coordinate.identity, attr: post, roles: postStateRoleTarget, changed: true})
		if applyErr != nil {
			h.deferStorageFailure(response, applyErr)
		}
		return response, []volumeserver.VisibilityTarget{
			inodeTarget(volumeserver.VisibilityData, coordinate, post.Size),
			inodeTarget(volumeserver.VisibilityAttributes, coordinate, 0),
		}
	})
	if errors.Is(ctx.Err(), context.DeadlineExceeded) && response != nil && response.GetErrno() == 0 && response.GetWrite() == nil {
		return h.errorResponse(request.GetRequestId(), syscall.ETIMEDOUT, false)
	}
	if releaseMutation != nil {
		releaseMutation()
	}
	return response
}
