package authoritymetrics

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
)

func TestAdminHandlersAndReadinessTransitions(t *testing.T) {
	registry := NewRegistry()
	counter, err := registry.RegisterCounter("portablefs_test_ready_total", "Ready test.")
	if err != nil {
		t.Fatal(err)
	}
	counter.Inc()
	var rootHealthy atomic.Bool
	readiness := NewReadiness(func(context.Context) error {
		if !rootHealthy.Load() {
			return errors.New("root unhealthy")
		}
		return nil
	})
	handler := AdminHandler(registry, readiness)

	request := func(path string) *httptest.ResponseRecorder {
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodGet, path, nil))
		return recorder
	}
	if response := request("/healthz"); response.Code != http.StatusOK || response.Body.String() != "ok\n" {
		t.Fatalf("healthz = %d %q", response.Code, response.Body.String())
	}
	if response := request("/readyz"); response.Code != http.StatusServiceUnavailable {
		t.Fatalf("initial readyz = %d, want 503", response.Code)
	}
	readiness.SetVolumeOpen(true)
	readiness.SetListenerUp(true)
	if response := request("/readyz"); response.Code != http.StatusServiceUnavailable {
		t.Fatalf("unhealthy-root readyz = %d, want 503", response.Code)
	}
	rootHealthy.Store(true)
	if response := request("/readyz"); response.Code != http.StatusOK || response.Body.String() != "ready\n" {
		t.Fatalf("ready readyz = %d %q", response.Code, response.Body.String())
	}
	readiness.SetListenerUp(false)
	if response := request("/readyz"); response.Code != http.StatusServiceUnavailable {
		t.Fatalf("listener-down readyz = %d, want 503", response.Code)
	}
	if response := request("/metrics"); response.Code != http.StatusOK ||
		!strings.Contains(response.Body.String(), "portablefs_test_ready_total 1\n") ||
		response.Header().Get("Content-Type") != "text/plain; version=0.0.4; charset=utf-8" {
		t.Fatalf("metrics = %d %q headers=%v", response.Code, response.Body.String(), response.Header())
	}

	recorder := httptest.NewRecorder()
	handler.ServeHTTP(recorder, httptest.NewRequest(http.MethodPost, "/metrics", nil))
	if recorder.Code != http.StatusMethodNotAllowed || recorder.Header().Get("Allow") != http.MethodGet {
		t.Fatalf("POST metrics = %d allow=%q", recorder.Code, recorder.Header().Get("Allow"))
	}
}
