package histworker

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"net/http"
	"time"
)

// ServeHealth runs the health/metrics listener until ctx cancels. There is
// deliberately NO data-plane surface here: /healthz (liveness), /readyz
// (readiness: database migration/capability, policy admission, every
// configured store domain), and /metrics (low-cardinality Prometheus text).
// Returns the bound address on startup through addrCh when non-nil.
func (w *Worker) ServeHealth(ctx context.Context, addr string, addrCh chan<- string) error {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", func(rw http.ResponseWriter, _ *http.Request) {
		rw.WriteHeader(http.StatusOK)
		rw.Write([]byte("ok\n"))
	})
	mux.HandleFunc("/readyz", func(rw http.ResponseWriter, _ *http.Request) {
		ready, detail := w.Readiness()
		rw.Header().Set("Content-Type", "application/json")
		if !ready {
			rw.WriteHeader(http.StatusServiceUnavailable)
		}
		json.NewEncoder(rw).Encode(map[string]any{"ready": ready, "checks": detail})
	})
	mux.HandleFunc("/metrics", func(rw http.ResponseWriter, _ *http.Request) {
		rw.Header().Set("Content-Type", "text/plain; version=0.0.4")
		rw.Write([]byte(w.metrics.Prometheus()))
	})

	listener, err := net.Listen("tcp", addr)
	if err != nil {
		return err
	}
	if addrCh != nil {
		addrCh <- listener.Addr().String()
	}
	server := &http.Server{Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	done := make(chan error, 1)
	go func() { done <- server.Serve(listener) }()
	select {
	case <-ctx.Done():
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
		defer cancel()
		_ = server.Shutdown(shutdownCtx)
		return ctx.Err()
	case err := <-done:
		if errors.Is(err, http.ErrServerClosed) {
			return nil
		}
		return err
	}
}
