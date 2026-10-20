package authorityrpc

import (
	"bytes"
	"context"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/steerlabs/portablefs/vcs/internal/authoritymetrics"
	"github.com/steerlabs/portablefs/vcs/internal/authoritypb"
	"github.com/steerlabs/portablefs/vcs/internal/volumeserver"
)

type benchmarkDispatchHandler struct {
	response *authoritypb.Response
}

func (h *benchmarkDispatchHandler) Epoch() []byte { return nil }
func (h *benchmarkDispatchHandler) Bounds() TransportBounds {
	return TransportBounds{MaxFrame: 1, MaxRequestFrame: 1, MaxInFlight: 2}
}
func (h *benchmarkDispatchHandler) SessionStateForTransport(volumeserver.SessionID) (volumeserver.SessionState, bool) {
	return volumeserver.SessionStateActive, true
}
func (h *benchmarkDispatchHandler) SessionTerminalForTransport(volumeserver.SessionID) (<-chan struct{}, bool) {
	return make(chan struct{}), true
}
func (h *benchmarkDispatchHandler) Handle(context.Context, *authoritypb.Request) *authoritypb.Response {
	return h.response
}

func BenchmarkDispatchInstrumentation(b *testing.B) {
	request := &authoritypb.Request{
		RequestId: 1,
		Body:      &authoritypb.Request_KeepAlive{KeepAlive: &authoritypb.KeepAliveRequest{}},
	}
	handler := &benchmarkDispatchHandler{response: &authoritypb.Response{RequestId: 1}}
	metrics, err := authoritymetrics.New("benchmark")
	if err != nil {
		b.Fatal(err)
	}
	for _, benchmark := range []struct {
		name    string
		metrics *authoritymetrics.Metrics
	}{
		{name: "without_instrumentation"},
		{name: "with_instrumentation", metrics: metrics},
	} {
		b.Run(benchmark.name, func(b *testing.B) {
			server := &Server{Handler: handler, Metrics: benchmark.metrics}
			b.ReportAllocs()
			for b.Loop() {
				if response := server.dispatchRequest(context.Background(), request); response != handler.response {
					b.Fatal("dispatch replaced the handler response")
				}
			}
		})
	}
}

type countingDispatchHandler struct {
	benchmarkDispatchHandler
	calls int
}

func (h *countingDispatchHandler) Handle(ctx context.Context, request *authoritypb.Request) *authoritypb.Response {
	h.calls++
	return h.benchmarkDispatchHandler.Handle(ctx, request)
}

func TestDispatchRecordsCompletedHandlerOnce(t *testing.T) {
	for _, tc := range []struct {
		name     string
		response *authoritypb.Response
		outcome  string
	}{
		{"positive", &authoritypb.Response{Body: &authoritypb.Response_Lookup{Lookup: &authoritypb.LookupReply{Item: &authoritypb.Item{}}}}, "success"},
		{"stamped-negative", &authoritypb.Response{Body: &authoritypb.Response_Lookup{Lookup: &authoritypb.LookupReply{NegativeSnapshotSequence: 7}}}, "success"},
		{"permission", &authoritypb.Response{Errno: 13}, "permission"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			metrics, err := authoritymetrics.New("dispatch-test")
			if err != nil {
				t.Fatal(err)
			}
			handler := &countingDispatchHandler{benchmarkDispatchHandler: benchmarkDispatchHandler{response: tc.response}}
			server := &Server{Handler: handler, Metrics: metrics}
			request := &authoritypb.Request{Body: &authoritypb.Request_Lookup{Lookup: &authoritypb.LookupRequest{}}}
			if response := server.dispatchRequest(t.Context(), request); response != handler.response {
				t.Fatal("dispatch replaced the handler reply")
			}
			if handler.calls != 1 {
				t.Fatalf("handler invocations=%d, want 1", handler.calls)
			}
			var rendered bytes.Buffer
			if err := metrics.Registry().WritePrometheus(&rendered); err != nil {
				t.Fatal(err)
			}
			for _, sample := range []string{
				`portablefs_authority_rpc_requests_total{volume="dispatch-test",opcode="lookup",outcome="` + tc.outcome + `"} 1`,
				`portablefs_authority_rpc_duration_seconds_count{volume="dispatch-test",opcode="lookup"} 1`,
			} {
				if !strings.Contains(rendered.String(), sample+"\n") {
					t.Errorf("missing completed invocation: %s", sample)
				}
			}
		})
	}
}

func TestRequestOperationAndResponseOutcome(t *testing.T) {
	request := &authoritypb.Request{Body: &authoritypb.Request_Write{Write: &authoritypb.WriteRequest{}}}
	if got := requestOperation(request); got != authoritymetrics.OperationWrite {
		t.Fatalf("operation = %s, want positioned_write", got)
	}
	response := &authoritypb.Response{Errno: 5, Failure: authoritypb.FailureClass_FAILURE_CLASS_STORAGE}
	if got := responseOutcome(response); got != authoritymetrics.OutcomeStorage {
		t.Fatalf("outcome = %s, want storage", got)
	}
	response = &authoritypb.Response{Errno: 28}
	if got := responseOutcome(response); got != authoritymetrics.OutcomeSaturation {
		t.Fatalf("outcome = %s, want saturation", got)
	}
}

func TestServerServingObserverTracksTLSAcceptLoop(t *testing.T) {
	serverTLS, _ := testTLSConfigs(t)
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	states := make(chan bool, 2)
	server := &Server{
		Handler:  &benchmarkDispatchHandler{response: &authoritypb.Response{}},
		MaxFrame: 1, MaxInFlight: 2, MaxConnections: 2, MaxFrameBytesInFlight: MinimumFrameBytesInFlight(1),
		HandshakeTimeout: time.Second, IdleTimeout: time.Second, WriteTimeout: time.Second,
		OnServing: func(up bool) { states <- up },
	}
	done := make(chan error, 1)
	go func() { done <- server.Serve(ctx, listener, serverTLS) }()
	select {
	case up := <-states:
		if !up {
			t.Fatal("first serving transition was down")
		}
	case <-time.After(time.Second):
		t.Fatal("TLS accept loop did not publish readiness")
	}
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(time.Second):
		t.Fatal("TLS accept loop did not stop")
	}
	select {
	case up := <-states:
		if up {
			t.Fatal("final serving transition was up")
		}
	case <-time.After(time.Second):
		t.Fatal("TLS accept loop did not clear readiness")
	}
}

func TestLinuxCoherenceOperationMetrics(t *testing.T) {
	for _, tc := range []struct {
		request *authoritypb.Request
		want    authoritymetrics.Operation
	}{
		{&authoritypb.Request{Body: &authoritypb.Request_Subscribe{}}, authoritymetrics.OperationSubscribe},
		{&authoritypb.Request{Body: &authoritypb.Request_RenewSubscription{}}, authoritymetrics.OperationRenewSubscription},
		{&authoritypb.Request{Body: &authoritypb.Request_NextControlEvent{}}, authoritymetrics.OperationNextControlEvent},
		{&authoritypb.Request{Body: &authoritypb.Request_ChangeAck{}}, authoritymetrics.OperationChangeAck},
		{&authoritypb.Request{Body: &authoritypb.Request_DelegationRecallAck{}}, authoritymetrics.OperationDelegationRecallAck},
		{&authoritypb.Request{Body: &authoritypb.Request_DelegationBreakAck{}}, authoritymetrics.OperationDelegationBreakAck},
		{&authoritypb.Request{Body: &authoritypb.Request_DelegationModeChangeAck{}}, authoritymetrics.OperationDelegationModeChangeAck},
		{&authoritypb.Request{Body: &authoritypb.Request_DelegationRelease{}}, authoritymetrics.OperationDelegationRelease},
		{&authoritypb.Request{Body: &authoritypb.Request_Barrier{}}, authoritymetrics.OperationBarrier},
		{&authoritypb.Request{Body: &authoritypb.Request_WaitVisibility{}}, authoritymetrics.OperationWaitVisibility},
	} {
		if got := requestOperation(tc.request); got != tc.want || got.String() == "unknown" {
			t.Errorf("%T mapped to %v, want %v", tc.request.Body, got, tc.want)
		}
	}
}
