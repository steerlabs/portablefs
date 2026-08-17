package authorityrpc

import (
	"context"
	"net"
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

func TestRequestOperationAndResponseOutcome(t *testing.T) {
	request := &authoritypb.Request{Body: &authoritypb.Request_WriteTransaction{WriteTransaction: &authoritypb.WriteTransactionRequest{
		Phase: authoritypb.WriteTransactionPhase_WRITE_TRANSACTION_PHASE_COMMIT,
	}}}
	if got := requestOperation(request); got != authoritymetrics.OperationWriteTransactionCommit {
		t.Fatalf("operation = %s, want write_transaction_commit", got)
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
		MaxFrame: 1, MaxInFlight: 2, MaxConnections: 2, MaxFrameBytesInFlight: 1,
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
