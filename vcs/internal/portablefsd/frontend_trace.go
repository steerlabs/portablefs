package portablefsd

import (
	"context"
	"strconv"
	"time"

	"github.com/steerlabs/portablefs/vcs/bench/lantrace"
	"github.com/steerlabs/portablefs/vcs/internal/pfslocal"
)

// A request keeps its original binding through reply, disposition and cleanup.
// The recorder is opt-in and caller-owned; no filesystem lifetime closes it.
// Origin is a daemon-local witness, never a cross-process join key.
type v3RequestTrace struct {
	FrontendPID int
	AttachRef   string
	ConnRole    string
	RequestID   uint64
	OperationID uint64
	Origin      uint64
	localOp     lantrace.LocalOp
	recorder    *lantrace.Recorder
}

type v3RequestTraceContextKey struct{}

func (c *frontendConn) requestTrace(requestID, operationID uint64, body any) v3RequestTrace {
	t := v3RequestTrace{FrontendPID: c.frontendPID, ConnRole: c.helloClientName,
		RequestID: requestID, OperationID: operationID, localOp: v3TraceLocalOp(body)}
	c.attachMu.RLock()
	t.Origin = c.origin
	if c.attach != nil {
		t.AttachRef = c.attach.ref
	}
	c.attachMu.RUnlock()
	if c.srv != nil {
		t.recorder = c.srv.cfg.Trace
	}
	return t
}

func (t v3RequestTrace) emit(e lantrace.Event) {
	if t.recorder == nil {
		return
	}
	e.FrontendPID = uint32(t.FrontendPID)
	e.AttachRef, e.ConnRole = lantrace.TraceID(t.AttachRef), lantrace.TraceID(t.ConnRole)
	if t.Origin != 0 {
		e.Conn = lantrace.TraceID(strconv.FormatUint(t.Origin, 10))
	}
	e.RequestID, e.Operation = t.RequestID, t.OperationID
	// Invalid exact identities are counted as lost by the shared recorder.
	// Never normalize or hash Hello/Resolve values to manufacture a join.
	_ = t.recorder.Emit(e)
}

func (t v3RequestTrace) local(phase lantrace.Phase, errno int32) {
	e := lantrace.Event{Kind: lantrace.KindLocal, Phase: phase, LocalOp: t.localOp}
	if errno != 0 {
		e.Outcome, e.Errno = lantrace.OutcomeError, lantrace.Errno(errno)
	}
	t.emit(e)
}

func (t v3RequestTrace) wait(kind lantrace.WaitKind, elapsed time.Duration) {
	if t.recorder != nil && elapsed > 0 {
		// P9's wait grammar is an aggregate duration and has no local opcode.
		// Keep these stream-level samples separate from request lifecycle
		// records, whose complete identity always includes local_op.
		_ = t.recorder.Emit(lantrace.Event{Kind: lantrace.KindWait, Wait: kind, Duration: lantrace.Nanos(elapsed)})
	}
}

func (t v3RequestTrace) pending(count, limit int) {
	if t.recorder != nil {
		_ = t.recorder.Emit(lantrace.Event{Kind: lantrace.KindOccupancy, Phase: lantrace.PhaseSample,
			Resource: lantrace.ResourcePendingReservations, Count: uint32(count), Limit: uint32(limit)})
	}
}

func traceV3Request(ctx context.Context, phase lantrace.Phase, errno int32) {
	t, _ := ctx.Value(v3RequestTraceContextKey{}).(v3RequestTrace)
	t.local(phase, errno)
}

func v3TraceLocalOp(body any) lantrace.LocalOp {
	switch body.(type) {
	case *pfslocal.Hello:
		return lantrace.LocalHello
	case *pfslocal.ResolveRequest:
		return lantrace.LocalResolve
	case *pfslocal.LookupRequest:
		return lantrace.LocalLookup
	case *pfslocal.GetAttrRequest:
		return lantrace.LocalGetAttr
	case *pfslocal.SetAttrRequest:
		return lantrace.LocalSetAttr
	case *pfslocal.OpenRequest:
		return lantrace.LocalOpen
	case *pfslocal.CloseRequest:
		return lantrace.LocalClose
	case *pfslocal.ReadRequest:
		return lantrace.LocalRead
	case *pfslocal.WriteRequest:
		return lantrace.LocalWrite
	case *pfslocal.CreateRequest:
		return lantrace.LocalCreate
	case *pfslocal.MkdirRequest:
		return lantrace.LocalMkdir
	case *pfslocal.RemoveRequest:
		return lantrace.LocalRemove
	case *pfslocal.RenameRequest:
		return lantrace.LocalRename
	case *pfslocal.SymlinkRequest:
		return lantrace.LocalSymlink
	case *pfslocal.ReadlinkRequest:
		return lantrace.LocalReadlink
	case *pfslocal.XattrGetRequest:
		return lantrace.LocalXattrGet
	case *pfslocal.XattrListRequest:
		return lantrace.LocalXattrList
	case *pfslocal.XattrRemoveRequest:
		return lantrace.LocalXattrRemove
	case *pfslocal.StatfsRequest:
		return lantrace.LocalStatfs
	case *pfslocal.ReclaimRequest:
		return lantrace.LocalReclaim
	case *pfslocal.SubscribeEventsRequest:
		return lantrace.LocalSubscribeEvents
	case *pfslocal.HardLinkRequest:
		return lantrace.LocalHardLink
	case *pfslocal.SyncVolumeRequest:
		return lantrace.LocalSyncVolume
	case *pfslocal.EnumerateEntriesRequest:
		return lantrace.LocalEnumerateEntries
	default:
		return ""
	}
}
