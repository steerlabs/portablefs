package authoritymetrics

import (
	"context"
	"net/http"
	"sync/atomic"
)

// Readiness combines explicit lifecycle state with a live storage-root check.
// The callback must inspect the already-open root descriptor rather than
// resolving a deployment path again.
type Readiness struct {
	listenerUp atomic.Bool
	volumeOpen atomic.Bool
	rootCheck  func(context.Context) error
}

func NewReadiness(rootCheck func(context.Context) error) *Readiness {
	return &Readiness{rootCheck: rootCheck}
}

func (r *Readiness) SetListenerUp(up bool) {
	if r != nil {
		r.listenerUp.Store(up)
	}
}

func (r *Readiness) SetVolumeOpen(open bool) {
	if r != nil {
		r.volumeOpen.Store(open)
	}
}

func (r *Readiness) Check(ctx context.Context) error {
	if r == nil || !r.listenerUp.Load() || !r.volumeOpen.Load() || r.rootCheck == nil {
		return context.Canceled
	}
	return r.rootCheck(ctx)
}

func AdminHandler(registry *Registry, readiness *Readiness) http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/metrics", func(w http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodGet {
			w.Header().Set("Allow", http.MethodGet)
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "text/plain; version=0.0.4; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		if registry == nil {
			http.Error(w, "metrics unavailable", http.StatusServiceUnavailable)
			return
		}
		if err := registry.WritePrometheus(w); err != nil {
			return
		}
	})
	mux.HandleFunc("/healthz", func(w http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodGet {
			w.Header().Set("Allow", http.MethodGet)
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ok\n"))
	})
	mux.HandleFunc("/readyz", func(w http.ResponseWriter, request *http.Request) {
		if request.Method != http.MethodGet {
			w.Header().Set("Allow", http.MethodGet)
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		w.Header().Set("Cache-Control", "no-store")
		if readiness == nil || readiness.Check(request.Context()) != nil {
			http.Error(w, "not ready", http.StatusServiceUnavailable)
			return
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write([]byte("ready\n"))
	})
	return mux
}
