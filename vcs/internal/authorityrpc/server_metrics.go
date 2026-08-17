package authorityrpc

import (
	"context"
	"log"
	"time"

	"github.com/steerlabs/portablefs/vcs/internal/authoritymetrics"
	"github.com/steerlabs/portablefs/vcs/internal/authoritypb"
	"github.com/steerlabs/portablefs/vcs/internal/errnos"
)

// Authority responses always carry Linux-numbered errnos, including on a
// non-Linux build used by protocol clients and transport tests. These values
// are not part of the smaller common errnos package because no filesystem
// operation currently emits them through its ordinary mapping.
const (
	linuxEDEADLK         int32 = 35
	linuxEPROTO          int32 = 71
	linuxEBADMSG         int32 = 74
	linuxESHUTDOWN       int32 = 108
	linuxEUCLEAN         int32 = 117
	linuxECANCELED       int32 = 125
	linuxENOTRECOVERABLE int32 = 131
)

// dispatchRequest is the one handler invocation point for accepted transport
// requests. A nil Metrics keeps tests and embedders at the old direct-call
// cost; production receives precomputed atomic handles and a monotonic latency
// sample without building labels or consulting a map.
func (s *Server) dispatchRequest(ctx context.Context, request *authoritypb.Request) *authoritypb.Response {
	if s.Metrics == nil {
		return handleTransportRequest(s.Handler, ctx, request)
	}
	started := time.Now()
	response := handleTransportRequest(s.Handler, ctx, request)
	elapsed := time.Since(started)
	operation := requestOperation(request)
	outcome := responseOutcome(response)
	s.Metrics.ObserveRPC(operation, outcome, elapsed)
	s.logRPC(request, response, operation, outcome, elapsed)
	return response
}

func requestOperation(request *authoritypb.Request) authoritymetrics.Operation {
	if request == nil {
		return authoritymetrics.OperationUnknown
	}
	switch body := request.GetBody().(type) {
	case *authoritypb.Request_Hello:
		return authoritymetrics.OperationHello
	case *authoritypb.Request_Attach:
		return authoritymetrics.OperationAttach
	case *authoritypb.Request_Resume:
		return authoritymetrics.OperationResume
	case *authoritypb.Request_Activate:
		return authoritymetrics.OperationActivate
	case *authoritypb.Request_AbortAttach:
		return authoritymetrics.OperationAbortAttach
	case *authoritypb.Request_KeepAlive:
		return authoritymetrics.OperationKeepAlive
	case *authoritypb.Request_Reauthorize:
		return authoritymetrics.OperationReauthorize
	case *authoritypb.Request_Detach:
		return authoritymetrics.OperationDetach
	case *authoritypb.Request_Cancel:
		return authoritymetrics.OperationCancel
	case *authoritypb.Request_TerminalDeliveryReceipt:
		return authoritymetrics.OperationTerminalDeliveryReceipt
	case *authoritypb.Request_NextVisibility:
		return authoritymetrics.OperationNextVisibility
	case *authoritypb.Request_AckVisibility:
		return authoritymetrics.OperationAckVisibility
	case *authoritypb.Request_ApplyRoutes:
		return authoritymetrics.OperationApplyRoutes
	case *authoritypb.Request_Lookup:
		return authoritymetrics.OperationLookup
	case *authoritypb.Request_GetAttr:
		return authoritymetrics.OperationGetAttr
	case *authoritypb.Request_SetAttr:
		return authoritymetrics.OperationSetAttr
	case *authoritypb.Request_Create:
		return authoritymetrics.OperationCreate
	case *authoritypb.Request_Mkdir:
		return authoritymetrics.OperationMkdir
	case *authoritypb.Request_Unlink:
		return authoritymetrics.OperationUnlink
	case *authoritypb.Request_Rename:
		return authoritymetrics.OperationRename
	case *authoritypb.Request_Link:
		return authoritymetrics.OperationLink
	case *authoritypb.Request_Symlink:
		return authoritymetrics.OperationSymlink
	case *authoritypb.Request_Readlink:
		return authoritymetrics.OperationReadlink
	case *authoritypb.Request_Open:
		return authoritymetrics.OperationOpen
	case *authoritypb.Request_Close:
		return authoritymetrics.OperationClose
	case *authoritypb.Request_Read:
		return authoritymetrics.OperationRead
	case *authoritypb.Request_OneShotWrite:
		return authoritymetrics.OperationOneShotWrite
	case *authoritypb.Request_WriteTransaction:
		switch body.WriteTransaction.GetPhase() {
		case authoritypb.WriteTransactionPhase_WRITE_TRANSACTION_PHASE_BEGIN:
			return authoritymetrics.OperationWriteTransactionBegin
		case authoritypb.WriteTransactionPhase_WRITE_TRANSACTION_PHASE_DATA:
			return authoritymetrics.OperationWriteTransactionData
		case authoritypb.WriteTransactionPhase_WRITE_TRANSACTION_PHASE_COMMIT:
			return authoritymetrics.OperationWriteTransactionCommit
		case authoritypb.WriteTransactionPhase_WRITE_TRANSACTION_PHASE_ABORT:
			return authoritymetrics.OperationWriteTransactionAbort
		default:
			return authoritymetrics.OperationUnknown
		}
	case *authoritypb.Request_Fallocate:
		return authoritymetrics.OperationFallocate
	case *authoritypb.Request_CopyFileRange:
		return authoritymetrics.OperationCopyFileRange
	case *authoritypb.Request_Tmpfile:
		return authoritymetrics.OperationTmpfile
	case *authoritypb.Request_Fsync:
		return authoritymetrics.OperationFsync
	case *authoritypb.Request_ReadDir:
		return authoritymetrics.OperationReadDir
	case *authoritypb.Request_Reclaim:
		return authoritymetrics.OperationReclaim
	case *authoritypb.Request_Flush:
		return authoritymetrics.OperationFlush
	case *authoritypb.Request_GetXattr:
		return authoritymetrics.OperationGetXattr
	case *authoritypb.Request_SetXattr:
		return authoritymetrics.OperationSetXattr
	case *authoritypb.Request_ListXattr:
		return authoritymetrics.OperationListXattr
	case *authoritypb.Request_RemoveXattr:
		return authoritymetrics.OperationRemoveXattr
	case *authoritypb.Request_StatFs:
		return authoritymetrics.OperationStatFS
	case *authoritypb.Request_SyncFs:
		return authoritymetrics.OperationSyncFS
	case *authoritypb.Request_GetLock:
		return authoritymetrics.OperationGetLock
	case *authoritypb.Request_SetLock:
		return authoritymetrics.OperationSetLock
	default:
		return authoritymetrics.OperationUnknown
	}
}

func responseOutcome(response *authoritypb.Response) authoritymetrics.Outcome {
	if response == nil {
		return authoritymetrics.OutcomeInternal
	}
	if response.GetErrno() == 0 {
		return authoritymetrics.OutcomeSuccess
	}
	switch response.GetFailure() {
	case authoritypb.FailureClass_FAILURE_CLASS_STORAGE:
		return authoritymetrics.OutcomeStorage
	case authoritypb.FailureClass_FAILURE_CLASS_INTERNAL:
		return authoritymetrics.OutcomeInternal
	case authoritypb.FailureClass_FAILURE_CLASS_COHERENCE:
		return authoritymetrics.OutcomeCoherence
	case authoritypb.FailureClass_FAILURE_CLASS_ROUTES:
		return authoritymetrics.OutcomeRoutes
	case authoritypb.FailureClass_FAILURE_CLASS_VISIBILITY_INTERRUPTED:
		return authoritymetrics.OutcomeVisibilityInterrupted
	case authoritypb.FailureClass_FAILURE_CLASS_VISIBILITY_RETRY:
		return authoritymetrics.OutcomeVisibilityRetry
	}
	errno := response.GetErrno()
	switch {
	case errno == errnos.ENOENT:
		return authoritymetrics.OutcomeNotFound
	case errno == errnos.EPERM || errno == errnos.EACCES:
		return authoritymetrics.OutcomePermission
	case errno == errnos.ESTALE:
		return authoritymetrics.OutcomeStale
	case errno == errnos.EINVAL || errno == linuxEPROTO || errno == linuxEBADMSG:
		return authoritymetrics.OutcomeInvalid
	case errno == errnos.EAGAIN || errno == errnos.ENOMEM || errno == errnos.ENFILE || errno == errnos.EMFILE ||
		errno == errnos.ENOSPC || errno == errnos.EDQUOT:
		return authoritymetrics.OutcomeSaturation
	case errno == errnos.ENOSYS || errno == errnos.EOPNOTSUPP:
		return authoritymetrics.OutcomeUnsupported
	case errno == errnos.EEXIST || errno == errnos.ENOTEMPTY || errno == errnos.EBUSY || errno == errnos.EXDEV || errno == linuxEDEADLK:
		return authoritymetrics.OutcomeConflict
	case errno == errnos.EINTR || errno == errnos.ETIMEDOUT || errno == linuxECANCELED:
		return authoritymetrics.OutcomeCanceled
	case errno == errnos.EIO || errno == linuxESHUTDOWN || errno == linuxEUCLEAN || errno == linuxENOTRECOVERABLE:
		return authoritymetrics.OutcomeIO
	default:
		return authoritymetrics.OutcomeOther
	}
}

func (s *Server) logRPC(request *authoritypb.Request, response *authoritypb.Response, operation authoritymetrics.Operation, outcome authoritymetrics.Outcome, elapsed time.Duration) {
	if !loggableRPC(operation, outcome, response) {
		return
	}
	requestID := uint64(0)
	var session []byte
	if request != nil {
		requestID = request.GetRequestId()
		if proof := request.GetSession(); proof != nil {
			session = proof.GetId()
		}
	}
	if len(session) == 0 && response != nil && response.GetAttach() != nil {
		session = response.GetAttach().GetSessionId()
	}
	errno := int32(0)
	if response != nil {
		errno = response.GetErrno()
	}
	log.Printf("portablefs-authority: rpc volume=%q request_id=%d session=%x opcode=%s outcome=%s errno=%d duration_us=%d",
		s.Metrics.Volume(), requestID, session, operation, outcome, errno, elapsed.Microseconds())
}

func loggableRPC(operation authoritymetrics.Operation, outcome authoritymetrics.Outcome, response *authoritypb.Response) bool {
	if response == nil || response.GetFailure() != authoritypb.FailureClass_FAILURE_CLASS_UNSPECIFIED {
		return true
	}
	if outcome == authoritymetrics.OutcomeInvalid {
		return true
	}
	switch operation {
	case authoritymetrics.OperationHello, authoritymetrics.OperationAttach, authoritymetrics.OperationResume,
		authoritymetrics.OperationActivate, authoritymetrics.OperationAbortAttach,
		authoritymetrics.OperationDetach, authoritymetrics.OperationReauthorize:
		return true
	case authoritymetrics.OperationNextVisibility, authoritymetrics.OperationAckVisibility:
		return response.GetErrno() != 0
	default:
		return false
	}
}
