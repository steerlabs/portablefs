//go:build linux

package fusev3

import (
	"errors"
	"fmt"
	"math"
	"syscall"

	"github.com/hanwen/go-fuse/v2/fuse"
	"github.com/steerlabs/portablefs/vcs/internal/authoritypb"
	"golang.org/x/sys/unix"
)

const (
	rangeResultApplied   = uint32(1 << 0)
	rangeResultRejected  = uint32(1 << 1)
	rangeResultPostApply = uint32(1 << 2)
	rangeResultNoop      = uint32(1 << 4)
)

func validSignedRange(offset, length uint64) bool {
	return length != 0 && offset <= math.MaxInt64 && length <= math.MaxInt64 && offset <= math.MaxInt64-length
}

func (r *rawFileSystem) Fallocate(_ <-chan struct{}, input *fuse.FallocateIn) fuse.Status {
	if input == nil || !validSignedRange(input.Offset, input.Length) {
		return fuse.EINVAL
	}
	if held, handle := r.acquireGraftFileHandle(input.Fh); handle != nil {
		defer r.releaseHandleOperation(held)
		if held.inode == nil || held.inode.id != input.NodeId {
			return fuse.EBADF
		}
		return fuse.Status(errnoOfError(unix.Fallocate(handle.fd, input.Mode, int64(input.Offset), int64(input.Length))))
	}
	if held, handle := r.acquireFileHandle(input.Fh); handle != nil {
		defer r.releaseHandleOperation(held)
		if held.inode == nil || held.inode.id != input.NodeId || handle.node != held.inode.node {
			return fuse.EBADF
		}
		ctx, finish, lifecycle := r.mutationContext(input.Unique)
		if !lifecycle.Ok() {
			return lifecycle
		}
		defer finish()
		gate, err := itemSourceGate(handle.node.item, true)
		if err != nil {
			return fuse.EIO
		}
		response, errno := handle.node.mutateWithSource(ctx, &authoritypb.Request{
			Body: &authoritypb.Request_Fallocate{Fallocate: &authoritypb.FallocateRequest{
				Handle: cloneBytes(handle.token), Offset: input.Offset, Length: input.Length, Mode: input.Mode,
			}},
		}, gate)
		if errno != 0 {
			return fuse.Status(errno)
		}
		reply := response.GetFallocate()
		if reply == nil || response.GetUncertain() {
			r.mount.revoke(errors.New("fusev3: stock fallocate returned no definite result"))
			return fuse.Status(syscall.ENOTCONN)
		}
		if reply.GetFlags() == rangeResultRejected && reply.GetResultSize() == 0 && reply.GetPostSize() == 0 && reply.GetVisibilitySequence() == 0 && reply.GetError() < 0 {
			if err := completeDefiniteNoChangePublication(ctx); err != nil {
				r.mount.revoke(err)
				return fuse.Status(syscall.ENOTCONN)
			}
			return fuse.Status(-reply.GetError())
		}
		if reply.GetFlags() != rangeResultApplied && reply.GetFlags() != rangeResultApplied|rangeResultPostApply ||
			reply.GetResultSize() != 0 || reply.GetVisibilitySequence() == 0 || reply.GetPostSize() > math.MaxInt64 {
			r.mount.revoke(errors.New("fusev3: stock fallocate returned malformed applied state"))
			return fuse.Status(syscall.ENOTCONN)
		}
		if err := expectPostStateRecord(ctx, held.inode, postStateRoleTarget); err != nil {
			r.mount.revoke(err)
			return fuse.Status(syscall.ENOTCONN)
		}
		if err := completeSourcePublication(ctx); err != nil {
			r.mount.revoke(fmt.Errorf("fusev3: complete fallocate publication: %w", err))
			return fuse.Status(syscall.ENOTCONN)
		}
		if reply.GetFlags()&rangeResultPostApply != 0 && reply.GetError() < 0 {
			return fuse.Status(-reply.GetError())
		}
		if reply.GetError() != 0 {
			r.mount.revoke(errors.New("fusev3: stock fallocate applied result carried an invalid error"))
			return fuse.Status(syscall.ENOTCONN)
		}
		return fuse.OK
	}
	return fuse.EBADF
}

// CopyFileRange never bridges local and authority domains. The kernel performs
// generic write-limit checks before issuing the stock FUSE request.
func (r *rawFileSystem) CopyFileRange(_ <-chan struct{}, input *fuse.CopyFileRangeIn) (uint32, fuse.Status) {
	if input == nil || input.Flags != 0 || input.Len == 0 || input.Len > math.MaxUint32 ||
		!validSignedRange(input.OffIn, input.Len) || !validSignedRange(input.OffOut, input.Len) {
		return 0, fuse.EINVAL
	}
	sourceRecord, sourceLocal := r.acquireGraftFileHandle(input.FhIn)
	if sourceRecord != nil {
		defer r.releaseHandleOperation(sourceRecord)
	}
	var sourceSharedRecord *handleRecord
	var sourceShared *fileHandle
	if sourceLocal == nil {
		sourceSharedRecord, sourceShared = r.acquireFileHandle(input.FhIn)
		if sourceSharedRecord != nil {
			defer r.releaseHandleOperation(sourceSharedRecord)
		}
	}
	destinationRecord, destinationLocal := r.acquireGraftFileHandle(input.FhOut)
	if destinationRecord != nil {
		defer r.releaseHandleOperation(destinationRecord)
	}
	var destinationSharedRecord *handleRecord
	var destinationShared *fileHandle
	if destinationLocal == nil {
		destinationSharedRecord, destinationShared = r.acquireFileHandle(input.FhOut)
		if destinationSharedRecord != nil {
			defer r.releaseHandleOperation(destinationSharedRecord)
		}
	}
	if sourceLocal == nil && sourceShared == nil || destinationLocal == nil && destinationShared == nil {
		return 0, fuse.EBADF
	}
	sourceInode := sourceRecord
	if sourceInode == nil {
		sourceInode = sourceSharedRecord
	}
	destinationInode := destinationRecord
	if destinationInode == nil {
		destinationInode = destinationSharedRecord
	}
	if sourceInode.inode == nil || destinationInode.inode == nil || sourceInode.inode.id != input.NodeId || destinationInode.inode.id != input.NodeIdOut {
		return 0, fuse.EBADF
	}
	if sourceLocal != nil && destinationLocal != nil {
		offIn, offOut := int64(input.OffIn), int64(input.OffOut)
		copied, err := unix.CopyFileRange(sourceLocal.fd, &offIn, destinationLocal.fd, &offOut, int(input.Len), 0)
		if err != nil {
			return 0, fuse.Status(errnoOfError(err))
		}
		if copied < 0 || uint64(copied) > input.Len {
			return 0, fuse.EIO
		}
		return uint32(copied), fuse.OK
	}
	if sourceLocal != nil || destinationLocal != nil {
		return 0, fuse.Status(syscall.EXDEV)
	}
	ctx, finish, lifecycle := r.mutationContext(input.Unique)
	if !lifecycle.Ok() {
		return 0, lifecycle
	}
	defer finish()
	sourceSpec, err := sourceItem(sourceShared.node.item, true, false)
	if err != nil {
		return 0, fuse.EIO
	}
	destinationSpec, err := sourceItem(destinationShared.node.item, true, true)
	if err != nil {
		return 0, fuse.EIO
	}
	gate, err := exactSourceGate([]sourceItemSpec{sourceSpec, destinationSpec}, nil)
	if err != nil {
		return 0, fuse.EIO
	}
	response, errno := destinationShared.node.mutateWithSource(ctx, &authoritypb.Request{
		Body: &authoritypb.Request_CopyFileRange{CopyFileRange: &authoritypb.CopyFileRangeRequest{
			InputHandle: cloneBytes(sourceShared.token), InputOffset: input.OffIn,
			OutputHandle: cloneBytes(destinationShared.token), OutputOffset: input.OffOut,
			Length: input.Len, Flags: uint32(input.Flags),
		}},
	}, gate)
	if errno != 0 {
		return 0, fuse.Status(errno)
	}
	reply := response.GetCopyFileRange()
	if reply == nil || response.GetUncertain() {
		r.mount.revoke(errors.New("fusev3: stock copy_file_range returned no definite result"))
		return 0, fuse.Status(syscall.ENOTCONN)
	}
	if reply.GetFlags() == rangeResultNoop && reply.GetResultSize() == 0 && reply.GetPostSize() == 0 && reply.GetVisibilitySequence() == 0 && reply.GetError() == 0 {
		if err := completeDefiniteNoChangePublication(ctx); err != nil {
			r.mount.revoke(err)
			return 0, fuse.Status(syscall.ENOTCONN)
		}
		return 0, fuse.OK
	}
	if reply.GetFlags() == rangeResultRejected && reply.GetResultSize() == 0 && reply.GetPostSize() == 0 && reply.GetVisibilitySequence() == 0 && reply.GetError() < 0 {
		if err := completeDefiniteNoChangePublication(ctx); err != nil {
			r.mount.revoke(err)
			return 0, fuse.Status(syscall.ENOTCONN)
		}
		return 0, fuse.Status(-reply.GetError())
	}
	if reply.GetFlags() != rangeResultApplied && reply.GetFlags() != rangeResultApplied|rangeResultPostApply ||
		reply.GetResultSize() == 0 || reply.GetResultSize() > input.Len || reply.GetResultSize() > math.MaxUint32 ||
		reply.GetVisibilitySequence() == 0 || reply.GetPostSize() > math.MaxInt64 {
		r.mount.revoke(errors.New("fusev3: stock copy_file_range returned malformed applied state"))
		return 0, fuse.Status(syscall.ENOTCONN)
	}
	if err := expectPostStateRecord(ctx, sourceSharedRecord.inode, postStateRoleSource); err != nil {
		r.mount.revoke(err)
		return 0, fuse.Status(syscall.ENOTCONN)
	}
	if err := expectPostStateRecord(ctx, destinationSharedRecord.inode, postStateRoleDestination); err != nil {
		r.mount.revoke(err)
		return 0, fuse.Status(syscall.ENOTCONN)
	}
	if err := completeSourcePublication(ctx); err != nil {
		r.mount.revoke(fmt.Errorf("fusev3: complete copy_file_range publication: %w", err))
		return 0, fuse.Status(syscall.ENOTCONN)
	}
	if reply.GetFlags()&rangeResultPostApply != 0 && reply.GetError() < 0 {
		return 0, fuse.Status(-reply.GetError())
	}
	if reply.GetError() != 0 {
		r.mount.revoke(errors.New("fusev3: stock copy_file_range applied result carried an invalid error"))
		return 0, fuse.Status(syscall.ENOTCONN)
	}
	return uint32(reply.GetResultSize()), fuse.OK
}
