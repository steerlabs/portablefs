package portablefsd

import (
	"context"
	"errors"
	"fmt"
	"math"
	"syscall"

	"github.com/steerlabs/portablefs/vcs/internal/authoritypb"
)

const (
	v3WriteReplyBegun uint32 = 1 << iota
	v3WriteReplyStaged
	v3WriteReplyCommitted
	v3WriteReplyAborted
	v3WriteReplyRejected
	v3WriteReplyPostApply
	v3WriteReplyRejectedRLimit

	// Qualification FSKit does not expose the kernel's per-call killpriv
	// decision. Every non-empty content mutation therefore requests the safe
	// HANDLE_KILLPRIV_V2 behavior explicitly. Shipping macOS Attach is refused.
	v3WriteFlagKillSUIDGID uint32 = 1 << 2
)

type v3WriteTransaction struct {
	id            uint64
	handle        []byte
	requestedSize uint64
	position      uint64
	rlimitFsize   uint64
	fileMaxSize   uint64
	lockOwner     uint64
	writeFlags    uint32
	flags         uint32
}

func (tx v3WriteTransaction) request(phase authoritypb.WriteTransactionPhase, fragmentOffset uint64, data []byte) *authoritypb.Request {
	size := uint32(0)
	if phase == authoritypb.WriteTransactionPhase_WRITE_TRANSACTION_PHASE_DATA {
		size = uint32(len(data))
	}
	return &authoritypb.Request{Body: &authoritypb.Request_WriteTransaction{WriteTransaction: &authoritypb.WriteTransactionRequest{
		TransactionId: tx.id, Handle: cloneBytesV3(tx.handle), RequestedSize: tx.requestedSize,
		FragmentOffset: fragmentOffset, Position: tx.position, RlimitFsize: tx.rlimitFsize,
		FileMaxSize: tx.fileMaxSize, LockOwner: tx.lockOwner, WriteFlags: tx.writeFlags,
		Flags: tx.flags, Phase: phase, Size: size, Data: data,
	}}}
}

func validV3WritePhaseReply(response *authoritypb.Response, transactionID uint64, want uint32) bool {
	if response == nil || response.GetMutation() != nil || response.GetPostAttr() != nil {
		return false
	}
	reply := response.GetWriteTransaction()
	return reply != nil && reply.GetTransactionId() == transactionID && reply.GetFlags() == want && reply.GetError() == 0 &&
		reply.GetCommittedSize() == 0 && reply.GetAssignedOffset() == 0 && reply.GetPostSize() == 0 && reply.GetVisibilitySequence() == 0
}

func exactV3WriteRejection(request *authoritypb.Request, response *authoritypb.Response) (int32, bool) {
	body := request.GetWriteTransaction()
	reply := response.GetWriteTransaction()
	if body == nil || body.GetPhase() != authoritypb.WriteTransactionPhase_WRITE_TRANSACTION_PHASE_COMMIT || reply == nil ||
		reply.GetTransactionId() != body.GetTransactionId() || response.GetPostAttr() != nil ||
		reply.GetCommittedSize() != 0 || reply.GetAssignedOffset() != 0 || reply.GetPostSize() != 0 || reply.GetVisibilitySequence() != 0 ||
		reply.GetError() > -1 || reply.GetError() < -4095 {
		return 0, false
	}
	switch reply.GetFlags() {
	case v3WriteReplyRejected:
		return -reply.GetError(), true
	case v3WriteReplyRejectedRLimit:
		if reply.GetError() == -int32(syscall.EFBIG) {
			return int32(syscall.EFBIG), true
		}
	}
	return 0, false
}

func validV3WriteCommit(tx v3WriteTransaction, response *authoritypb.Response) error {
	if response == nil {
		return errors.New("write transaction omitted its commit reply")
	}
	if errno, rejected := exactV3WriteRejection(tx.request(authoritypb.WriteTransactionPhase_WRITE_TRANSACTION_PHASE_COMMIT, tx.requestedSize, nil), response); rejected {
		return fmt.Errorf("write transaction returned an unhandled definite rejection errno %d", errno)
	}
	reply := response.GetWriteTransaction()
	if reply == nil || reply.GetTransactionId() != tx.id || reply.GetCommittedSize() == 0 ||
		reply.GetCommittedSize() > tx.requestedSize || reply.GetCommittedSize() > math.MaxUint32 ||
		reply.GetAssignedOffset() != tx.position ||
		reply.GetVisibilitySequence() == 0 || response.GetPostAttr() == nil {
		return errors.New("write transaction omitted its exact committed result")
	}
	if reply.GetAssignedOffset() > tx.fileMaxSize || reply.GetCommittedSize() > tx.fileMaxSize-reply.GetAssignedOffset() {
		return errors.New("write transaction exceeded its frozen file-size ceiling")
	}
	end := reply.GetAssignedOffset() + reply.GetCommittedSize()
	postAttr := response.GetPostAttr()
	if reply.GetPostSize() < end || postAttr.GetKind() != authoritypb.Attr_REGULAR || postAttr.GetSize() < 0 || uint64(postAttr.GetSize()) != reply.GetPostSize() {
		return errors.New("write transaction returned contradictory post-write size")
	}
	switch reply.GetFlags() {
	case v3WriteReplyCommitted:
		if reply.GetError() != 0 {
			return errors.New("successful write transaction carried an errno")
		}
	case v3WriteReplyCommitted | v3WriteReplyPostApply:
		if reply.GetError() > -1 || reply.GetError() < -4095 {
			return errors.New("post-apply write transaction omitted its exact errno")
		}
	default:
		return errors.New("write transaction returned an unknown commit flag set")
	}
	return nil
}

func (d *v3DataPlane) callWriteInert(ctx context.Context, operationID uint64, request *authoritypb.Request, want uint32) (*authoritypb.Response, int32) {
	response, consumption, callErr := d.client.CallIdempotentOwnedRetained(ctx, request, func(cause error) {
		d.revokeRetainedResponse(ctx, errors.Join(
			errors.New("portablefsd: retained authority write phase crossed its frontend delivery bound"),
			cause,
		))
	})
	retained := false
	defer func() {
		if consumption != nil && !retained {
			consumption.Consume()
		}
	}()
	if consumption == nil {
		if callErr == nil && response != nil {
			d.revokeRetainedResponse(ctx, errors.New("portablefsd: parsed write phase omitted its response consumption"))
			return nil, darwinEIO
		}
	} else {
		if cause := retainedV3ResponseTerminalCause(response, callErr); cause != nil {
			d.revokeRetainedResponse(ctx, cause)
			return nil, darwinEIO
		}
		if err := d.bridge.sourcePublication.retainFrontendResponseConsumption(operationID, consumption); err != nil {
			d.revokeRetainedResponse(ctx, err)
			return nil, darwinEIO
		}
		retained = true
	}
	classified, errno := d.classify(response, callErr, false)
	if errno != 0 {
		return classified, errno
	}
	transactionID := request.GetWriteTransaction().GetTransactionId()
	if !validV3WritePhaseReply(classified, transactionID, want) {
		_ = d.fail(fmt.Errorf("portablefsd: write transaction %d returned a malformed inert-phase reply", transactionID))
		return nil, darwinEIO
	}
	return classified, 0
}

func (d *v3DataPlane) abortWriteTransaction(operationID uint64, tx v3WriteTransaction) {
	if d.ctx.Err() != nil {
		return
	}
	// BEGIN/DATA may observe their callback cancellation after the authority
	// accepted inert staging. Cleanup therefore belongs to the live mount
	// session, not to the expired callback. The authority's bounded expiry is
	// still the final owner if this best-effort idempotent ABORT cannot return.
	abortCtx, cancel := context.WithTimeout(d.ctx, operationAdmissionBudgetValue())
	defer cancel()
	_, errno := d.callWriteInert(abortCtx, operationID, tx.request(authoritypb.WriteTransactionPhase_WRITE_TRANSACTION_PHASE_ABORT, 0, nil), v3WriteReplyAborted)
	if errno != 0 && d.terminalError() == nil {
		_ = d.fail(fmt.Errorf("portablefsd: write transaction %d ABORT failed with errno %d", tx.id, errno))
	}
}

func (d *v3DataPlane) executeWriteTransaction(ctx context.Context, operationID uint64, tx *v3WriteTransaction, data []byte, gate *authoritypb.SourcePublicationGate) (*authoritypb.Response, int32) {
	if tx == nil || tx.id != 0 || tx.requestedSize == 0 || tx.requestedSize != uint64(len(data)) ||
		tx.requestedSize > d.maxWriteTransaction || tx.position > math.MaxInt64 || tx.fileMaxSize == 0 {
		return nil, darwinEINVAL
	}

	// The authority accepts BEGIN identities in exact session order. Hold the
	// tiny allocator/dispatch mutex through the first reply so concurrent FSKit
	// callbacks cannot put transaction N+1 on the wire before N.
	d.writeBeginMu.Lock()
	tx.id = d.nextWriteTransaction
	if tx.id == 0 {
		d.writeBeginMu.Unlock()
		_ = d.fail(errors.New("portablefsd: authority write-transaction identity space exhausted"))
		return nil, darwinEOVERFLOW
	}
	d.nextWriteTransaction++
	_, errno := d.callWriteInert(ctx, operationID, tx.request(authoritypb.WriteTransactionPhase_WRITE_TRANSACTION_PHASE_BEGIN, 0, nil), v3WriteReplyBegun)
	if errno != 0 {
		d.abortWriteTransaction(operationID, *tx)
		d.writeBeginMu.Unlock()
		return nil, errno
	}
	d.writeBeginMu.Unlock()

	fragmentOffset := uint64(0)
	for fragmentOffset < tx.requestedSize {
		fragmentSize := min(uint64(d.maxWrite), tx.requestedSize-fragmentOffset)
		fragment := data[int(fragmentOffset):int(fragmentOffset+fragmentSize)]
		_, errno = d.callWriteInert(ctx, operationID, tx.request(authoritypb.WriteTransactionPhase_WRITE_TRANSACTION_PHASE_DATA, fragmentOffset, fragment), v3WriteReplyStaged)
		if errno != 0 {
			d.abortWriteTransaction(operationID, *tx)
			return nil, errno
		}
		fragmentOffset += fragmentSize
	}

	commit := tx.request(authoritypb.WriteTransactionPhase_WRITE_TRANSACTION_PHASE_COMMIT, fragmentOffset, nil)
	response, errno := d.callMutation(ctx, operationID, commit, gate)
	if errno != 0 {
		if d.terminalError() == nil {
			d.abortWriteTransaction(operationID, *tx)
		}
		return response, errno
	}
	if rejectedErrno, rejected := exactV3WriteRejection(commit, response); rejected {
		d.abortWriteTransaction(operationID, *tx)
		if d.terminalError() != nil {
			return nil, darwinEIO
		}
		return response, linuxToDarwin(rejectedErrno)
	}
	return response, 0
}
