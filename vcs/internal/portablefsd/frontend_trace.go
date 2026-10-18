package portablefsd

import (
	"context"
	"encoding/json"
	"log"
	"sync"
	"time"

	"github.com/steerlabs/portablefs/vcs/internal/authorityrpc"
)

// These are trace-only join keys shared with Swift and the LAN recorder.
// origin disambiguates daemon-local incarnations and is never a wire key.
type v3RequestTrace struct {
	FrontendPID int    `json:"frontend_pid"`
	AttachRef   string `json:"attach_ref"`
	ConnRole    string `json:"conn_role"`
	RequestID   uint64 `json:"request_id"`
	OperationID uint64 `json:"operation_id"`
	Origin      uint64 `json:"origin"`
	valid       bool
}

type v3RequestTraceContextKey struct{}

func (c *frontendConn) requestTrace(requestID, operationID uint64) v3RequestTrace {
	return v3RequestTrace{FrontendPID: c.frontendPID, AttachRef: c.currentAttachRef(), ConnRole: c.helloClientName,
		RequestID: requestID, OperationID: operationID, Origin: c.origin, valid: true}
}

func (t v3RequestTrace) emit(event string, errno int32, elapsed time.Duration) {
	if !t.valid {
		return
	}
	// Use the daemon's existing log sink until the coordinator integrates
	// vcs/bench/lantrace. No socket protocol field or independent recorder owner.
	entry := struct {
		v3RequestTrace
		Event     string `json:"event"`
		Errno     int32  `json:"errno"`
		ElapsedNS int64  `json:"elapsed_ns"`
	}{t, event, errno, int64(elapsed)}
	encoded, err := json.Marshal(entry)
	if err == nil {
		log.Printf("portablefsd_trace %s", encoded)
	}
}

func traceV3Request(ctx context.Context, event string, errno int32) {
	t, _ := ctx.Value(v3RequestTraceContextKey{}).(v3RequestTrace)
	t.emit(event, errno, 0)
}

// Follow the existing receipt through callback retirement without changing its
// owner. The wrapper carries the original request key even for multi-request
// callbacks, whose final PublicationAck has wire request_id zero.
type v3TracedConsumption struct {
	inner authorityrpc.ResponseConsumption
	trace v3RequestTrace
	once  sync.Once
}

func traceV3Consumption(ctx context.Context, inner authorityrpc.ResponseConsumption) authorityrpc.ResponseConsumption {
	trace, _ := ctx.Value(v3RequestTraceContextKey{}).(v3RequestTrace)
	if inner == nil || !trace.valid {
		return inner
	}
	trace.emit("response_received", 0, 0)
	return &v3TracedConsumption{inner: inner, trace: trace}
}

func (c *v3TracedConsumption) Consume() {
	c.once.Do(func() {
		c.inner.Consume()
		c.trace.emit("response_retired", 0, 0)
	})
}

func v3TraceErrno(err error) int32 {
	if err == nil {
		return 0
	}
	return v3LocalErrno(err)
}
