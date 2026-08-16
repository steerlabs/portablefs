//go:build linux

package fusev3

import (
	"context"
	"errors"
	"fmt"
	"math"
	"syscall"

	"github.com/hanwen/go-fuse/v2/fuse"
	"github.com/steerlabs/portablefs/vcs/internal/authoritypb"
	"golang.org/x/sys/unix"
)

const writeTransactionReplyFlags = fuse.PFS_WRITE_OUT_BEGUN | fuse.PFS_WRITE_OUT_STAGED |
	fuse.PFS_WRITE_OUT_COMMITTED | fuse.PFS_WRITE_OUT_ABORTED |
	fuse.PFS_WRITE_OUT_REJECTED | fuse.PFS_WRITE_OUT_POSTAPPLY_ERROR |
	fuse.PFS_WRITE_OUT_REJECTED_RLIMIT

var (
	writeTransactionProtocolError = fuse.Status(syscall.EPROTO)
	writeTransactionOverflowError = fuse.Status(syscall.EOVERFLOW)
)

func writeTransactionMetadataMatches(tx *writeTransaction, input *fuse.PFSWriteIn) bool {
	return tx != nil && input != nil && tx.kernelTxid == input.Txid && tx.nodeID == input.NodeId && tx.handleID == input.Fh &&
		tx.requestedSize == input.RequestedSize && tx.position == input.Position && tx.rlimitFsize == input.RlimitFsize &&
		tx.fileMaxSize == input.FileMaxSize &&
		tx.lockOwner == input.LockOwner && tx.writeFlags == input.WriteFlags && tx.flags == input.Flags
}

func validWriteTransactionMetadata(input *fuse.PFSWriteIn, maxTransaction uint64) bool {
	if input == nil || input.Unique == 0 || input.Unique >= fuse.PFS_UNIQUE_PUBLISH || input.Unique&1 != 0 || input.NodeId == 0 || input.Fh == 0 ||
		input.Txid == 0 || input.Txid > math.MaxInt64 || input.RequestedSize == 0 ||
		input.FileMaxSize == 0 || input.RequestedSize > maxTransaction {
		return false
	}
	allowedFlags := uint32(syscall.O_APPEND | syscall.O_SYNC)
	if input.Flags&^allowedFlags != 0 {
		return false
	}
	// Linux O_SYNC is the composite __O_SYNC|O_DSYNC value. Accept O_DSYNC
	// alone or the complete O_SYNC value, never the internal __O_SYNC bit alone.
	internalSync := uint32(syscall.O_SYNC) &^ uint32(unix.O_DSYNC)
	if input.Flags&internalSync != 0 && input.Flags&uint32(unix.O_DSYNC) == 0 {
		return false
	}
	allowedWriteFlags := uint32(fuse.WRITE_LOCKOWNER | fuse.WRITE_KILL_SUIDGID)
	if input.WriteFlags&^allowedWriteFlags != 0 || input.WriteFlags&fuse.WRITE_LOCKOWNER == 0 && input.LockOwner != 0 {
		return false
	}
	if input.Flags&uint32(syscall.O_APPEND) != 0 {
		return input.Position == 0
	}
	return input.Position <= math.MaxInt64 && input.Position < input.RlimitFsize && input.Position < input.FileMaxSize
}

func writeTransactionPhase(phase uint32) authoritypb.WriteTransactionPhase {
	switch phase {
	case fuse.PFS_WRITE_BEGIN:
		return authoritypb.WriteTransactionPhase_WRITE_TRANSACTION_PHASE_BEGIN
	case fuse.PFS_WRITE_DATA:
		return authoritypb.WriteTransactionPhase_WRITE_TRANSACTION_PHASE_DATA
	case fuse.PFS_WRITE_COMMIT:
		return authoritypb.WriteTransactionPhase_WRITE_TRANSACTION_PHASE_COMMIT
	case fuse.PFS_WRITE_ABORT:
		return authoritypb.WriteTransactionPhase_WRITE_TRANSACTION_PHASE_ABORT
	default:
		return authoritypb.WriteTransactionPhase_WRITE_TRANSACTION_PHASE_UNSPECIFIED
	}
}

func writeTransactionAuthorityRequest(tx *writeTransaction, input *fuse.PFSWriteIn, data []byte) *authoritypb.Request {
	return &authoritypb.Request{Body: &authoritypb.Request_WriteTransaction{WriteTransaction: &authoritypb.WriteTransactionRequest{
		TransactionId:  tx.authorityTxid,
		Handle:         cloneBytes(tx.handle.token),
		RequestedSize:  tx.requestedSize,
		FragmentOffset: input.FragmentOffset,
		Position:       tx.position,
		RlimitFsize:    tx.rlimitFsize,
		FileMaxSize:    tx.fileMaxSize,
		LockOwner:      tx.lockOwner,
		Size:           input.Size,
		WriteFlags:     tx.writeFlags,
		Flags:          tx.flags,
		Phase:          writeTransactionPhase(input.Phase),
		Data:           data,
	}}}
}

func (r *rawFileSystem) writeTransactionCall(ctx context.Context, request *authoritypb.Request, commit bool) (*authoritypb.Response, error) {
	if errno := r.mount.acquireBulk(ctx); errno != 0 {
		return nil, errno
	}
	defer r.mount.releaseBulk()
	if commit {
		return r.mount.callMutation(ctx, request)
	}
	response, consumption, err := r.mount.rpc.CallIdempotentOwnedRetained(
		ctx, request, r.mount.forceTerminalResponseRevocation,
	)
	if consumption != nil {
		if retainErr := retainAuthorityResponse(ctx, consumption); retainErr != nil {
			r.mount.revoke(retainErr)
			consumption.Consume()
			return response, retainErr
		}
	}
	return response, err
}

func validWriteTransactionReply(reply *authoritypb.WriteTransactionReply, authorityTxid uint64, want uint32) bool {
	if reply == nil || reply.GetTransactionId() != authorityTxid || reply.GetFlags()&^writeTransactionReplyFlags != 0 {
		return false
	}
	if reply.GetFlags() == fuse.PFS_WRITE_OUT_REJECTED {
		return want == fuse.PFS_WRITE_OUT_COMMITTED && reply.GetError() <= -1 && reply.GetError() >= -4095 &&
			reply.GetCommittedSize() == 0 && reply.GetAssignedOffset() == 0 && reply.GetPostSize() == 0 && reply.GetVisibilitySequence() == 0
	}
	if reply.GetFlags() == fuse.PFS_WRITE_OUT_REJECTED_RLIMIT {
		return want == fuse.PFS_WRITE_OUT_COMMITTED && reply.GetError() == -int32(syscall.EFBIG) &&
			reply.GetCommittedSize() == 0 && reply.GetAssignedOffset() == 0 && reply.GetPostSize() == 0 && reply.GetVisibilitySequence() == 0
	}
	if reply.GetFlags() == fuse.PFS_WRITE_OUT_COMMITTED|fuse.PFS_WRITE_OUT_POSTAPPLY_ERROR {
		return want == fuse.PFS_WRITE_OUT_COMMITTED && reply.GetError() <= -1 && reply.GetError() >= -4095 &&
			reply.GetVisibilitySequence() != 0 && reply.GetVisibilitySequence() <= math.MaxInt64 &&
			(reply.GetCommittedSize() != 0 || reply.GetAssignedOffset() == 0)
	}
	if reply.GetFlags() != want || reply.GetError() != 0 {
		return false
	}
	if want != fuse.PFS_WRITE_OUT_COMMITTED {
		return reply.GetCommittedSize() == 0 && reply.GetAssignedOffset() == 0 && reply.GetPostSize() == 0 && reply.GetVisibilitySequence() == 0
	}
	return reply.GetCommittedSize() != 0 && reply.GetVisibilitySequence() != 0 && reply.GetVisibilitySequence() <= math.MaxInt64
}

func fillWriteTransactionOut(out *fuse.PFSWriteOut, kernelTxid uint64, reply *authoritypb.WriteTransactionReply) {
	*out = fuse.PFSWriteOut{
		Txid:           kernelTxid,
		CommittedSize:  reply.GetCommittedSize(),
		AssignedOffset: reply.GetAssignedOffset(),
		PostSize:       reply.GetPostSize(),
		Sequence:       reply.GetVisibilitySequence(),
		Flags:          reply.GetFlags(),
		Error:          reply.GetError(),
	}
}

// PFSWrite implements PortableFS's negotiated multi-frame transaction for
// every SHARED write. BEGIN/DATA/ABORT are inert idempotent session staging;
// COMMIT alone acquires the source gate and a retained replay identity.
func (r *rawFileSystem) PFSWrite(_ <-chan struct{}, input *fuse.PFSWriteIn, data []byte, out *fuse.PFSWriteOut) fuse.Status {
	if out == nil || !validWriteTransactionMetadata(input, r.mount.rpc.MaxWriteTransactionBytes()) {
		return writeTransactionProtocolError
	}
	*out = fuse.PFSWriteOut{}
	switch input.Phase {
	case fuse.PFS_WRITE_BEGIN:
		return r.writeTransactionBegin(input, out)
	case fuse.PFS_WRITE_DATA:
		return r.writeTransactionData(input, data, out)
	case fuse.PFS_WRITE_COMMIT:
		return r.writeTransactionCommit(input, out)
	case fuse.PFS_WRITE_ABORT:
		return r.writeTransactionAbort(input, out)
	default:
		return writeTransactionProtocolError
	}
}

func (r *rawFileSystem) writeTransactionBegin(input *fuse.PFSWriteIn, out *fuse.PFSWriteOut) fuse.Status {
	if input.FragmentOffset != 0 || input.Size != 0 {
		return writeTransactionProtocolError
	}
	handleRecord, handle := r.acquireFileHandle(input.Fh)
	if handle == nil {
		return fuse.EBADF
	}
	transferred := false
	defer func() {
		if !transferred {
			r.releaseHandleOperation(handleRecord)
		}
	}()
	if handleRecord.inode == nil || input.NodeId != handleRecord.inode.id || handleRecord.inode.key.kind != authoritypb.Attr_REGULAR || handle.node != handleRecord.inode.node {
		return fuse.EBADF
	}

	r.writeBeginMu.Lock()
	defer r.writeBeginMu.Unlock()
	r.writeMu.Lock()
	if existing := r.writeTx[input.Txid]; existing != nil {
		matches := writeTransactionMetadataMatches(existing, input) && existing.stagedSize == 0 && existing.committedSize == 0
		if !matches {
			r.writeMu.Unlock()
			return writeTransactionProtocolError
		}
		if existing.begun {
			r.writeMu.Unlock()
			out.Txid, out.Flags = input.Txid, fuse.PFS_WRITE_OUT_BEGUN
			return fuse.OK
		}
		tx := existing
		r.writeMu.Unlock()
		return r.dispatchWriteTransactionBegin(input, tx, out)
	}
	authorityTxid := r.nextWriteTx
	if authorityTxid == 0 {
		r.writeMu.Unlock()
		return writeTransactionOverflowError
	}
	tx := &writeTransaction{
		kernelTxid: input.Txid, authorityTxid: authorityTxid, nodeID: input.NodeId, handleID: input.Fh, handleRecord: handleRecord, handle: handle,
		requestedSize: input.RequestedSize, position: input.Position, rlimitFsize: input.RlimitFsize, fileMaxSize: input.FileMaxSize,
		lockOwner:  input.LockOwner,
		writeFlags: input.WriteFlags, flags: input.Flags,
	}
	r.writeTx[input.Txid] = tx
	r.nextWriteTx++
	transferred = true
	r.writeMu.Unlock()
	return r.dispatchWriteTransactionBegin(input, tx, out)
}

func (r *rawFileSystem) dispatchWriteTransactionBegin(input *fuse.PFSWriteIn, tx *writeTransaction, out *fuse.PFSWriteOut) fuse.Status {
	request := writeTransactionAuthorityRequest(tx, input, nil)
	callbackCtx, finish, lifecycle := r.mutationContext(input.Unique)
	if !lifecycle.Ok() {
		return lifecycle
	}
	defer finish()
	ctx, cancel := context.WithTimeout(callbackCtx, r.requestTimeout)
	defer cancel()
	response, err := r.writeTransactionCall(ctx, request, false)
	if err != nil {
		return fuse.Status(rpcErrno(response, err))
	}
	if errno := responseErrno(response); errno != 0 {
		if response == nil || response.GetUncertain() || errno > 4095 {
			return writeTransactionProtocolError
		}
		return fuse.Status(errno)
	}
	if !validWriteTransactionReply(response.GetWriteTransaction(), tx.authorityTxid, fuse.PFS_WRITE_OUT_BEGUN) {
		return writeTransactionProtocolError
	}
	r.writeMu.Lock()
	if r.writeTx[input.Txid] != tx || tx.begun {
		r.writeMu.Unlock()
		return writeTransactionProtocolError
	}
	tx.begun = true
	r.writeMu.Unlock()
	out.Txid, out.Flags = input.Txid, fuse.PFS_WRITE_OUT_BEGUN
	return fuse.OK
}

func writeTransactionStageStatus(response *authoritypb.Response, err error) fuse.Status {
	if err != nil {
		return fuse.Status(rpcErrno(response, err))
	}
	if errno := responseErrno(response); errno != 0 {
		if response == nil || response.GetUncertain() || errno > 4095 {
			return writeTransactionProtocolError
		}
		return fuse.Status(errno)
	}
	return writeTransactionProtocolError
}

func (r *rawFileSystem) writeTransactionData(input *fuse.PFSWriteIn, data []byte, out *fuse.PFSWriteOut) fuse.Status {
	if input.Size == 0 || input.Size > r.maxWrite || uint64(input.Size) != uint64(len(data)) {
		return writeTransactionProtocolError
	}
	r.writeMu.Lock()
	tx := r.writeTx[input.Txid]
	if !writeTransactionMetadataMatches(tx, input) || !tx.begun || tx.committedSize != 0 || tx.stagedSize > tx.requestedSize ||
		input.FragmentOffset != tx.stagedSize || uint64(input.Size) > tx.requestedSize-tx.stagedSize {
		r.writeMu.Unlock()
		return writeTransactionProtocolError
	}
	r.writeMu.Unlock()
	callbackCtx, finish, lifecycle := r.mutationContext(input.Unique)
	if !lifecycle.Ok() {
		return lifecycle
	}
	defer finish()
	ctx, cancel := context.WithTimeout(callbackCtx, r.requestTimeout)
	defer cancel()
	response, err := r.writeTransactionCall(ctx, writeTransactionAuthorityRequest(tx, input, data), false)
	if err != nil || responseErrno(response) != 0 || !validWriteTransactionReply(response.GetWriteTransaction(), tx.authorityTxid, fuse.PFS_WRITE_OUT_STAGED) {
		return writeTransactionStageStatus(response, err)
	}
	r.writeMu.Lock()
	if r.writeTx[input.Txid] != tx || tx.stagedSize != input.FragmentOffset {
		r.writeMu.Unlock()
		return writeTransactionProtocolError
	}
	tx.stagedSize += uint64(input.Size)
	r.writeMu.Unlock()
	out.Txid, out.Flags = input.Txid, fuse.PFS_WRITE_OUT_STAGED
	return fuse.OK
}

func (r *rawFileSystem) writeTransactionAbort(input *fuse.PFSWriteIn, out *fuse.PFSWriteOut) fuse.Status {
	if input.FragmentOffset != 0 || input.Size != 0 {
		return writeTransactionProtocolError
	}
	r.writeMu.Lock()
	tx := r.writeTx[input.Txid]
	if tx == nil {
		r.writeMu.Unlock()
		out.Txid, out.Flags = input.Txid, fuse.PFS_WRITE_OUT_ABORTED
		return fuse.OK
	}
	if !writeTransactionMetadataMatches(tx, input) || tx.committedSize != 0 || tx.lease != nil {
		r.writeMu.Unlock()
		return writeTransactionProtocolError
	}
	r.writeMu.Unlock()
	callbackCtx, finish, lifecycle := r.mutationContext(input.Unique)
	if !lifecycle.Ok() {
		return lifecycle
	}
	defer finish()
	ctx, cancel := context.WithTimeout(callbackCtx, r.requestTimeout)
	defer cancel()
	response, err := r.writeTransactionCall(ctx, writeTransactionAuthorityRequest(tx, input, nil), false)
	if err != nil || responseErrno(response) != 0 || !validWriteTransactionReply(response.GetWriteTransaction(), tx.authorityTxid, fuse.PFS_WRITE_OUT_ABORTED) {
		return writeTransactionStageStatus(response, err)
	}
	r.writeMu.Lock()
	if r.writeTx[input.Txid] != tx {
		r.writeMu.Unlock()
		return writeTransactionProtocolError
	}
	delete(r.writeTx, input.Txid)
	r.writeMu.Unlock()
	r.releaseHandleOperation(tx.handleRecord)
	out.Txid, out.Flags = input.Txid, fuse.PFS_WRITE_OUT_ABORTED
	return fuse.OK
}

func (r *rawFileSystem) writeTransactionCommit(input *fuse.PFSWriteIn, out *fuse.PFSWriteOut) fuse.Status {
	if input.Size != 0 {
		return writeTransactionProtocolError
	}
	r.writeMu.Lock()
	tx := r.writeTx[input.Txid]
	if !writeTransactionMetadataMatches(tx, input) || !tx.begun || tx.commitResolved || tx.lease != nil || input.FragmentOffset == 0 || input.FragmentOffset != tx.stagedSize {
		r.writeMu.Unlock()
		return writeTransactionProtocolError
	}
	r.writeMu.Unlock()
	ctx, finish, lifecycle := r.mutationContext(input.Unique)
	if !lifecycle.Ok() {
		return lifecycle
	}
	defer finish()
	gate, err := itemSourceGate(tx.handle.node.item, true)
	if err != nil {
		return fuse.EIO
	}
	request := writeTransactionAuthorityRequest(tx, input, nil)
	request.SourcePublicationGate = gate
	response, callErr := r.writeTransactionCall(ctx, request, true)
	if callErr != nil || response == nil || response.GetUncertain() || responseErrno(response) != 0 {
		responseNil, uncertain, errno, failure := response == nil, false, syscall.Errno(0), authoritypb.FailureClass_FAILURE_CLASS_UNSPECIFIED
		if response != nil {
			uncertain, errno, failure = response.GetUncertain(), responseErrno(response), response.GetFailure()
		}
		r.mount.revoke(fmt.Errorf("fusev3: write COMMIT outcome is ambiguous: call=%v response_nil=%t uncertain=%t errno=%d failure=%s",
			callErr, responseNil, uncertain, errno, failure))
		return fuse.Status(syscall.ENOTCONN)
	}
	reply := response.GetWriteTransaction()
	if !validWriteTransactionReply(reply, tx.authorityTxid, fuse.PFS_WRITE_OUT_COMMITTED) {
		r.mount.revoke(errors.New("fusev3: write COMMIT returned a malformed result"))
		return fuse.Status(syscall.ENOTCONN)
	}
	lease := sourceLeaseFromContext(ctx)
	publication := replyPublicationFromContext(ctx)
	if lease == nil || publication == nil {
		r.mount.revoke(errors.New("fusev3: write COMMIT escaped source publication ownership"))
		return fuse.Status(syscall.ENOTCONN)
	}
	if reply.GetFlags() == fuse.PFS_WRITE_OUT_REJECTED || reply.GetFlags() == fuse.PFS_WRITE_OUT_REJECTED_RLIMIT {
		r.writeMu.Lock()
		if r.writeTx[input.Txid] != tx {
			r.writeMu.Unlock()
			r.mount.revoke(errors.New("fusev3: rejected write COMMIT lost local transaction ownership"))
			return fuse.Status(syscall.ENOTCONN)
		}
		tx.lease, tx.commitResolved = lease, true
		publication.writeKernelTx = input.Txid
		r.writeMu.Unlock()
		if err := completeDefiniteNoChangePublication(ctx); err != nil {
			r.mount.revoke(err)
			return fuse.Status(syscall.ENOTCONN)
		}
		fillWriteTransactionOut(out, input.Txid, reply)
		return fuse.OK
	}
	postAttr := response.GetPostAttr()
	if postAttr == nil || postAttr.GetKind() != authoritypb.Attr_REGULAR ||
		postAttr.GetInode() != tx.handleRecord.inode.key.inode || postAttr.GetSize() < 0 ||
		uint64(postAttr.GetSize()) != reply.GetPostSize() || reply.GetPostSize() > tx.fileMaxSize {
		r.mount.revoke(errors.New("fusev3: write COMMIT result omitted its exact regular-file post attributes"))
		return fuse.Status(syscall.ENOTCONN)
	}
	attrOnlyPostapply := reply.GetCommittedSize() == 0 &&
		reply.GetFlags() == fuse.PFS_WRITE_OUT_COMMITTED|fuse.PFS_WRITE_OUT_POSTAPPLY_ERROR
	if attrOnlyPostapply && reply.GetAssignedOffset() != 0 {
		r.mount.revoke(errors.New("fusev3: zero-byte post-apply write carried data-position or invalid size state"))
		return fuse.Status(syscall.ENOTCONN)
	}
	appendMode := tx.flags&uint32(syscall.O_APPEND) != 0
	ceiling := tx.fileMaxSize
	if tx.rlimitFsize < ceiling {
		ceiling = tx.rlimitFsize
	}
	invalidResult := reply.GetCommittedSize() > tx.stagedSize || !attrOnlyPostapply &&
		(reply.GetAssignedOffset() > ceiling || reply.GetCommittedSize() > ceiling-reply.GetAssignedOffset())
	if invalidResult {
		r.mount.revoke(errors.New("fusev3: write COMMIT result exceeded its staged or maximum range"))
		return fuse.Status(syscall.ENOTCONN)
	}
	end := reply.GetAssignedOffset() + reply.GetCommittedSize()
	if attrOnlyPostapply {
		invalidResult = false
	} else if appendMode {
		invalidResult = reply.GetPostSize() != end
	} else {
		invalidResult = reply.GetAssignedOffset() != tx.position || reply.GetPostSize() < end
	}
	if invalidResult {
		r.mount.revoke(errors.New("fusev3: write COMMIT result violated its staged position or maximum range"))
		return fuse.Status(syscall.ENOTCONN)
	}
	r.writeMu.Lock()
	if r.writeTx[input.Txid] != tx {
		r.writeMu.Unlock()
		r.mount.revoke(errors.New("fusev3: write COMMIT lost local transaction ownership"))
		return fuse.Status(syscall.ENOTCONN)
	}
	tx.committedSize, tx.assignedOffset, tx.postSize, tx.sequence = reply.GetCommittedSize(), reply.GetAssignedOffset(), reply.GetPostSize(), reply.GetVisibilitySequence()
	tx.lease, tx.commitResolved = lease, true
	publication.writeKernelTx = input.Txid
	r.writeMu.Unlock()
	if err := completeSourcePublication(ctx); err != nil {
		r.mount.revoke(err)
		return fuse.Status(syscall.ENOTCONN)
	}
	fillWriteTransactionOut(out, input.Txid, reply)
	return fuse.OK
}
