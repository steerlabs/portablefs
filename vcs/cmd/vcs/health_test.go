package main

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestReadinessProbe: /readyz is 503 until the node is serving, then 200 with the
// role — the signal an orchestrator uses to route traffic only to a live primary.
func TestReadinessProbe(t *testing.T) {
	setReady(false)
	setRole("standby")

	rec := httptest.NewRecorder()
	readinessHandler(rec, httptest.NewRequest(http.MethodGet, "/readyz", nil))
	if rec.Code != http.StatusServiceUnavailable {
		t.Fatalf("not-ready /readyz = %d, want 503", rec.Code)
	}
	var body struct {
		Ready bool   `json:"ready"`
		Role  string `json:"role"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &body); err != nil {
		t.Fatalf("decode body: %v", err)
	}
	if body.Ready || body.Role != "standby" {
		t.Fatalf("not-ready body = %+v, want {false standby}", body)
	}

	// Promote + serve.
	setRole("primary")
	setReady(true)
	if readyGauge.Value() != 1 {
		t.Fatalf("vcs_ready gauge = %d, want 1 once serving", readyGauge.Value())
	}

	rec = httptest.NewRecorder()
	readinessHandler(rec, httptest.NewRequest(http.MethodGet, "/readyz", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("ready /readyz = %d, want 200", rec.Code)
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &body)
	if !body.Ready || body.Role != "primary" {
		t.Fatalf("ready body = %+v, want {true primary}", body)
	}
}

// TestLivenessAlwaysOK: /healthz is 200 regardless of readiness (the process is up).
func TestLivenessAlwaysOK(t *testing.T) {
	setReady(false)
	rec := httptest.NewRecorder()
	livenessHandler(rec, httptest.NewRequest(http.MethodGet, "/healthz", nil))
	if rec.Code != http.StatusOK {
		t.Fatalf("/healthz = %d, want 200 even when not ready", rec.Code)
	}
}

// TestRoleDefaultsToStarting: before any role is set, currentRole reports "starting".
func TestRoleDefaultsToStarting(t *testing.T) {
	if healthRole.Load() == nil && currentRole() != "starting" {
		t.Fatalf("default role = %q, want starting", currentRole())
	}
}
