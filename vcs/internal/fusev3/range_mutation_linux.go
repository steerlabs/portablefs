//go:build linux

package fusev3

import (
	"context"
	"errors"
	"math"
	"syscall"

	"github.com/hanwen/go-fuse/v2/fuse"
	"github.com/steerlabs/portablefs/vcs/internal/authoritypb"
	"golang.org/x/sys/unix"
)

var rangeMutationProtocolError = fuse.Status(syscall.EPROTO)

func validPrivateRequestIdentity(header *fuse.InHeader) bool {
	return header != nil && header.Unique != 0 && header.Unique < fuse.PFS_UNIQUE_PUBLISH && header.Unique&1 == 0 && header.NodeId != 0
}

func validRangeWriteFlags(flags uint32) bool {
	return flags&^uint32(fuse.WRITE_KILL_SUIDGID) == 0
}

func validSignedRange(offset, length uint64) bool {
	return length != 0 && offset <= math.MaxInt64 && length <= math.MaxInt64 && offset <= math.MaxInt64-length
}

func validPFSFallocateInput(input *fuse.PFSFallocateIn) bool {
	if input == nil || !validPrivateRequestIdentity(&input.InHeader) || input.Fh == 0 ||
		input.FileMaxSize == 0 || input.FileMaxSize > math.MaxInt64 ||
		!validSignedRange(input.Offset, input.Length) || input.Offset+input.Length > input.FileMaxSize ||
		!validRangeWriteFlags(input.WriteFlags) {
		return false
	}
	switch input.Mode {
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

func validFallocateRlimitRejection(input *fuse.PFSFallocateIn, preSize uint64) bool {
	if input.RlimitFsize == math.MaxUint64 || preSize > input.FileMaxSize {
		return false
	}
	end := input.Offset + input.Length
	switch input.Mode {
	case 0, uint32(unix.FALLOC_FL_ZERO_RANGE), uint32(unix.FALLOC_FL_UNSHARE_RANGE):
		return preSize < end && end > input.RlimitFsize
	case uint32(unix.FALLOC_FL_INSERT_RANGE):
		if input.Offset >= preSize || preSize > math.MaxUint64-input.Length {
			return false
		}
		postSize := preSize + input.Length
		return postSize <= input.FileMaxSize && postSize > input.RlimitFsize
	default:
		return false
	}
}

func validFallocateNoChange(input *fuse.PFSFallocateIn, resultSize, postSize, sequence uint64, flags uint32, errno int32) bool {
	if flags == fuse.PFS_RANGE_OUT_REJECTED_RLIMIT {
		return resultSize == 0 && sequence == 0 && errno == -int32(syscall.EFBIG) &&
			validFallocateRlimitRejection(input, postSize)
	}
	return validStructuredRangeNoChange(resultSize, postSize, sequence, flags, errno, false)
}

func validFallocateAppliedPost(input *fuse.PFSFallocateIn, postSize uint64, flags uint32) bool {
	if postSize > input.FileMaxSize {
		return false
	}
	// Once XFS is dispatched, an error can follow a partial extent or size
	// mutation. Its exact post-state is authoritative but cannot be constrained
	// by the successful-mode formula.
	if flags == fuse.PFS_RANGE_OUT_APPLIED|fuse.PFS_RANGE_OUT_POSTAPPLY_ERROR {
		return true
	}
	end := input.Offset + input.Length
	switch input.Mode {
	case 0, uint32(unix.FALLOC_FL_ZERO_RANGE), uint32(unix.FALLOC_FL_UNSHARE_RANGE):
		return postSize >= end
	case uint32(unix.FALLOC_FL_INSERT_RANGE):
		return postSize > end &&
			(input.RlimitFsize == math.MaxUint64 || postSize <= input.RlimitFsize)
	case uint32(unix.FALLOC_FL_COLLAPSE_RANGE):
		// Clean COLLAPSE returns S-length for an authoritative pre-size S
		// bounded by file_max_size. Both bounds are independently useful: the
		// lower one proves the collapsed range ended before EOF, while the upper
		// one prevents a daemon from publishing an impossible pre-EOF result.
		return postSize > input.Offset && postSize <= input.FileMaxSize-input.Length
	default:
		// KEEP_SIZE, PUNCH_HOLE|KEEP_SIZE, ZERO_RANGE|KEEP_SIZE, and
		// UNSHARE_RANGE|KEEP_SIZE preserve an authoritative size that is
		// intentionally absent from the request.
		return true
	}
}

func validPFSCopyFileRangeInput(input *fuse.PFSCopyFileRangeIn) bool {
	return input != nil && validPrivateRequestIdentity(&input.InHeader) && input.FhIn != 0 &&
		input.NodeIdOut != 0 && input.FhOut != 0 && input.Flags == 0 &&
		input.FileMaxSize != 0 && input.FileMaxSize <= math.MaxInt64 &&
		validSignedRange(input.OffIn, input.Len) && validSignedRange(input.OffOut, input.Len) &&
		validRangeWriteFlags(input.WriteFlags)
}

// Fallocate is exclusively the LOCAL graft path in the strict profile.
// Receiving it for a SHARED handle proves the negotiated kernel bypassed the
// private authority-serialized operation, so that mount is no longer trustworthy.
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
		r.releaseHandleOperation(held)
		r.mount.revoke(errors.New("fusev3: kernel sent stock FUSE_FALLOCATE for a SHARED handle under strict coherence"))
		return fuse.Status(syscall.ENOTCONN)
	}
	return fuse.EBADF
}

// CopyFileRange is exclusively LOCAL-to-LOCAL. It never copies through a
// userspace buffer and never bridges LOCAL and SHARED domains.
func (r *rawFileSystem) CopyFileRange(_ <-chan struct{}, input *fuse.CopyFileRangeIn) (uint32, fuse.Status) {
	if input == nil || input.Flags != 0 || input.Len == 0 || input.Len > math.MaxUint32 ||
		!validSignedRange(input.OffIn, input.Len) || !validSignedRange(input.OffOut, input.Len) {
		return 0, fuse.EINVAL
	}
	sourceLocalRecord, sourceLocal := r.acquireGraftFileHandle(input.FhIn)
	if sourceLocalRecord != nil {
		defer r.releaseHandleOperation(sourceLocalRecord)
	}
	var sourceSharedRecord *handleRecord
	var sourceShared *fileHandle
	if sourceLocal == nil {
		sourceSharedRecord, sourceShared = r.acquireFileHandle(input.FhIn)
		if sourceSharedRecord != nil {
			defer r.releaseHandleOperation(sourceSharedRecord)
		}
	}
	destinationLocalRecord, destinationLocal := r.acquireGraftFileHandle(input.FhOut)
	if destinationLocalRecord != nil {
		defer r.releaseHandleOperation(destinationLocalRecord)
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
	sourceRecord := sourceLocalRecord
	if sourceRecord == nil {
		sourceRecord = sourceSharedRecord
	}
	destinationRecord := destinationLocalRecord
	if destinationRecord == nil {
		destinationRecord = destinationSharedRecord
	}
	if sourceRecord.inode == nil || destinationRecord.inode == nil ||
		sourceRecord.inode.id != input.NodeId || destinationRecord.inode.id != input.NodeIdOut {
		return 0, fuse.EBADF
	}
	if sourceLocal != nil && destinationLocal != nil {
		offIn, offOut := int64(input.OffIn), int64(input.OffOut)
		copied, err := unix.CopyFileRange(sourceLocal.fd, &offIn, destinationLocal.fd, &offOut, int(input.Len), 0)
		if err != nil {
			return 0, fuse.Status(errnoOfError(err))
		}
		if copied < 0 || uint64(copied) > input.Len || uint64(copied) > math.MaxUint32 {
			return 0, fuse.EIO
		}
		return uint32(copied), fuse.OK
	}
	if sourceLocal != nil || destinationLocal != nil {
		return 0, fuse.Status(syscall.EXDEV)
	}
	r.mount.revoke(errors.New("fusev3: kernel sent stock FUSE_COPY_FILE_RANGE for SHARED handles under strict coherence"))
	return 0, fuse.Status(syscall.ENOTCONN)
}

func fillRangeOut(out *fuse.PFSRangeOut, resultSize, postSize, sequence uint64, flags uint32, errno int32) {
	*out = fuse.PFSRangeOut{ResultSize: resultSize, PostSize: postSize, Sequence: sequence, Flags: flags, Error: errno}
}

func validStructuredRangeNoChange(resultSize, postSize, sequence uint64, flags uint32, errno int32, allowNoop bool) bool {
	if resultSize != 0 || postSize != 0 || sequence != 0 {
		return false
	}
	switch flags {
	case fuse.PFS_RANGE_OUT_REJECTED:
		return errno <= -1 && errno >= -4095
	case fuse.PFS_RANGE_OUT_REJECTED_RLIMIT:
		return errno == -int32(syscall.EFBIG)
	case fuse.PFS_RANGE_OUT_NOOP:
		return allowNoop && errno == 0
	default:
		return false
	}
}

func validAppliedRange(resultSize, postSize, sequence uint64, flags uint32, errno int32, fallocate bool, limit uint64) bool {
	if sequence == 0 || sequence > math.MaxInt64 {
		return false
	}
	if fallocate {
		if resultSize != 0 {
			return false
		}
	} else if resultSize > limit {
		return false
	}
	switch flags {
	case fuse.PFS_RANGE_OUT_APPLIED:
		return errno == 0 && (fallocate || resultSize != 0)
	case fuse.PFS_RANGE_OUT_APPLIED | fuse.PFS_RANGE_OUT_POSTAPPLY_ERROR:
		return errno <= -1 && errno >= -4095
	default:
		return false
	}
}

func validateRangePostAttr(response *authoritypb.Response, inode, postSize uint64, role uint32) bool {
	attr := responsePostAttr(response, role)
	return attr != nil && attr.GetKind() == authoritypb.Attr_REGULAR && attr.GetInode() == inode &&
		attr.GetSize() >= 0 && uint64(attr.GetSize()) == postSize
}

func (r *rawFileSystem) completeRangeNoChange(ctx context.Context, out *fuse.PFSRangeOut, resultSize, postSize, sequence uint64, flags uint32, errno int32) fuse.Status {
	if err := completeDefiniteNoChangePublication(ctx); err != nil {
		r.mount.revoke(err)
		return fuse.Status(syscall.ENOTCONN)
	}
	fillRangeOut(out, resultSize, postSize, sequence, flags, errno)
	return fuse.OK
}

func (r *rawFileSystem) completeAppliedRange(ctx context.Context, out *fuse.PFSRangeOut, resultSize, postSize, sequence uint64, flags uint32, errno int32) fuse.Status {
	if err := completeSourcePublication(ctx); err != nil {
		r.mount.revoke(err)
		return fuse.Status(syscall.ENOTCONN)
	}
	fillRangeOut(out, resultSize, postSize, sequence, flags, errno)
	return fuse.OK
}

func (r *rawFileSystem) rangeMutationFailure(message string) fuse.Status {
	r.mount.revoke(errors.New(message))
	return fuse.Status(syscall.ENOTCONN)
}

// PFSFallocate is the sole strict SHARED fallocate path. The authority runs one
// range mutation under the DATA+ATTR source gate. Linux fallocate may expose a
// changed extent map before returning an error, so APPLIED|POSTAPPLY_ERROR is a
// first-class exact-state result; stock FUSE_FALLOCATE remains exclusively for
// LOCAL graft handles.
func (r *rawFileSystem) PFSFallocate(_ <-chan struct{}, input *fuse.PFSFallocateIn, out *fuse.PFSRangeOut) fuse.Status {
	if out == nil || !validPFSFallocateInput(input) {
		return rangeMutationProtocolError
	}
	*out = fuse.PFSRangeOut{}
	handleRecord, handle := r.acquireFileHandle(input.Fh)
	if handle == nil {
		return fuse.EBADF
	}
	defer r.releaseHandleOperation(handleRecord)
	if handleRecord.inode == nil || handleRecord.inode.id != input.NodeId ||
		handleRecord.inode.key.kind != authoritypb.Attr_REGULAR || handle.node != handleRecord.inode.node {
		return fuse.EBADF
	}
	ctx, finish, lifecycle := r.mutationContext(input.Unique)
	if !lifecycle.Ok() {
		return lifecycle
	}
	defer finish()
	gate, err := itemSourceGate(handle.node.item, true)
	if err != nil {
		return r.rangeMutationFailure("fusev3: PFS_FALLOCATE could not construct its exact source gate")
	}
	request := &authoritypb.Request{
		SourcePublicationGate: gate,
		Body: &authoritypb.Request_Fallocate{Fallocate: &authoritypb.FallocateRequest{
			Handle: cloneBytes(handle.token), Offset: input.Offset, Length: input.Length,
			RlimitFsize: input.RlimitFsize, FileMaxSize: input.FileMaxSize,
			Mode: input.Mode, WriteFlags: input.WriteFlags,
		}},
	}
	response, errno := handle.node.mutate(ctx, request)
	if errno != 0 {
		return fuse.Status(errno)
	}
	reply := response.GetFallocate()
	if reply == nil {
		return r.rangeMutationFailure("fusev3: PFS_FALLOCATE omitted its exact result")
	}
	resultSize, postSize, sequence, flags, replyErrno := reply.GetResultSize(), reply.GetPostSize(), reply.GetVisibilitySequence(), reply.GetFlags(), reply.GetError()
	if validFallocateNoChange(input, resultSize, postSize, sequence, flags, replyErrno) {
		if response.GetPostState() != nil {
			return r.rangeMutationFailure("fusev3: rejected PFS_FALLOCATE carried post-mutation attributes")
		}
		return r.completeRangeNoChange(ctx, out, resultSize, postSize, sequence, flags, replyErrno)
	}
	if !validAppliedRange(resultSize, postSize, sequence, flags, replyErrno, true, 0) ||
		!validFallocateAppliedPost(input, postSize, flags) ||
		!validateRangePostAttr(response, handleRecord.inode.key.inode, postSize, postStateRoleTarget) {
		return r.rangeMutationFailure("fusev3: PFS_FALLOCATE returned a malformed applied result")
	}
	if err := expectPostStateRecord(ctx, handleRecord.inode, postStateRoleTarget); err != nil {
		return r.rangeMutationFailure(err.Error())
	}
	return r.completeAppliedRange(ctx, out, resultSize, postSize, sequence, flags, replyErrno)
}

// PFSCopyFileRange performs one server-side SHARED-to-SHARED copy. Both source
// and destination are DATA+ATTR ordering dependencies; mixed-domain copies are
// rejected by the kernel and LOCAL-to-LOCAL remains the stock direct path.
func (r *rawFileSystem) PFSCopyFileRange(_ <-chan struct{}, input *fuse.PFSCopyFileRangeIn, out *fuse.PFSRangeOut) fuse.Status {
	if out == nil || !validPFSCopyFileRangeInput(input) {
		return rangeMutationProtocolError
	}
	*out = fuse.PFSRangeOut{}
	sourceRecord, source := r.acquireFileHandle(input.FhIn)
	if source == nil {
		return fuse.EBADF
	}
	defer r.releaseHandleOperation(sourceRecord)
	destinationRecord, destination := r.acquireFileHandle(input.FhOut)
	if destination == nil {
		return fuse.EBADF
	}
	defer r.releaseHandleOperation(destinationRecord)
	if sourceRecord.inode == nil || destinationRecord.inode == nil ||
		sourceRecord.inode.id != input.NodeId || destinationRecord.inode.id != input.NodeIdOut ||
		sourceRecord.inode.key.kind != authoritypb.Attr_REGULAR || destinationRecord.inode.key.kind != authoritypb.Attr_REGULAR ||
		source.node != sourceRecord.inode.node || destination.node != destinationRecord.inode.node {
		return fuse.EBADF
	}
	ctx, finish, lifecycle := r.mutationContext(input.Unique)
	if !lifecycle.Ok() {
		return lifecycle
	}
	defer finish()
	sourceTarget, err := sourceItem(source.node.item, true, true)
	if err != nil {
		return r.rangeMutationFailure("fusev3: PFS_COPY_FILE_RANGE has an invalid source identity")
	}
	destinationTarget, err := sourceItem(destination.node.item, true, true)
	if err != nil {
		return r.rangeMutationFailure("fusev3: PFS_COPY_FILE_RANGE has an invalid destination identity")
	}
	gate, err := exactSourceGate([]sourceItemSpec{sourceTarget, destinationTarget}, nil)
	if err != nil {
		return r.rangeMutationFailure("fusev3: PFS_COPY_FILE_RANGE could not construct its exact source gate")
	}
	request := &authoritypb.Request{
		SourcePublicationGate: gate,
		Body: &authoritypb.Request_CopyFileRange{CopyFileRange: &authoritypb.CopyFileRangeRequest{
			InputHandle: cloneBytes(source.token), InputOffset: input.OffIn,
			OutputHandle: cloneBytes(destination.token), OutputOffset: input.OffOut,
			Length: input.Len, RlimitFsize: input.RlimitFsize, FileMaxSize: input.FileMaxSize,
			WriteFlags: input.WriteFlags, Flags: input.Flags,
		}},
	}
	response, errno := source.node.mutate(ctx, request)
	if errno != 0 {
		return fuse.Status(errno)
	}
	reply := response.GetCopyFileRange()
	if reply == nil {
		return r.rangeMutationFailure("fusev3: PFS_COPY_FILE_RANGE omitted its exact result")
	}
	resultSize, postSize, sequence, flags, replyErrno := reply.GetResultSize(), reply.GetPostSize(), reply.GetVisibilitySequence(), reply.GetFlags(), reply.GetError()
	if validStructuredRangeNoChange(resultSize, postSize, sequence, flags, replyErrno, true) {
		if response.GetPostState() != nil {
			return r.rangeMutationFailure("fusev3: no-change PFS_COPY_FILE_RANGE carried post-mutation attributes")
		}
		// Linux checks the destination position against both absolute ceilings
		// after clipping the source at EOF but before a clipped-zero copy becomes
		// a successful no-op. Only the authority knows the clipped count; once it
		// says NOOP, the frontend can and must still prove that precedence.
		if flags == fuse.PFS_RANGE_OUT_NOOP && (input.OffOut >= input.FileMaxSize || input.OffOut >= input.RlimitFsize) {
			return r.rangeMutationFailure("fusev3: PFS_COPY_FILE_RANGE returned NOOP above a destination ceiling")
		}
		return r.completeRangeNoChange(ctx, out, resultSize, postSize, sequence, flags, replyErrno)
	}
	attrOnlyPostapply := resultSize == 0 && flags == fuse.PFS_RANGE_OUT_APPLIED|fuse.PFS_RANGE_OUT_POSTAPPLY_ERROR
	invalidRange := false
	if !attrOnlyPostapply {
		end := input.OffOut + resultSize
		ceiling := input.FileMaxSize
		if input.RlimitFsize < ceiling {
			ceiling = input.RlimitFsize
		}
		invalidRange = end > ceiling || postSize < end
	}
	if !validAppliedRange(resultSize, postSize, sequence, flags, replyErrno, false, input.Len) ||
		invalidRange || postSize > input.FileMaxSize || !validateRangePostAttr(response, destinationRecord.inode.key.inode, postSize, postStateRoleDestination) {
		return r.rangeMutationFailure("fusev3: PFS_COPY_FILE_RANGE returned a malformed applied result")
	}
	sourceObject, sourceErr := expectedPostStateRecord(sourceRecord.inode, postStateRoleSource)
	destinationObject, destinationErr := expectedPostStateRecord(destinationRecord.inode, postStateRoleDestination)
	if sourceErr != nil || destinationErr != nil || expectPostState(ctx, sourceObject, destinationObject) != nil {
		return r.rangeMutationFailure("fusev3: PFS_COPY_FILE_RANGE post-state identities do not match its handles")
	}
	return r.completeAppliedRange(ctx, out, resultSize, postSize, sequence, flags, replyErrno)
}
