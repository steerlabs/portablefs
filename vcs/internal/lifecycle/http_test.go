package lifecycle

import (
	"bytes"
	"encoding/json"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"testing"

	"github.com/trendup-ai/portablefs/vcs/internal/opstate"
	"github.com/trendup-ai/portablefs/vcs/internal/secure"
)

func postOp(t *testing.T, url, token string, body map[string]any) (int, map[string]any) {
	t.Helper()
	raw, err := json.Marshal(body)
	if err != nil {
		t.Fatal(err)
	}
	req, err := http.NewRequest(http.MethodPost, url, bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	if token != "" {
		req.Header.Set("Authorization", "Bearer "+token)
	}
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var decoded map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&decoded); err != nil {
		t.Fatalf("decode response: %v", err)
	}
	return resp.StatusCode, decoded
}

func opBody(id string) map[string]any {
	return map[string]any{
		"operationId":         id,
		"volumeId":            "vol_1",
		"branch":              "main",
		"authorityInstanceId": "pfvcs_1",
	}
}

// TestHTTPEvictReturnsExactDurableRevision drives the journal-only ordinary
// stop endpoint. Its receipt is fenced/idempotent, contains decimal strings so
// uint64 identity survives JSON, and never runs a checkpoint or claims a head.
func TestHTTPEvictReturnsExactDurableRevision(t *testing.T) {
	h := newManagedHarness(t)
	h.write(t, "live.txt", "journal only")
	wantEpoch := h.w.Epoch()
	// The harness stands the file WAL in for the remote journal, so the
	// drained revision cursor is the WAL append watermark.
	wantLSN := h.w.Watermark()
	holder := &Holder{}
	holder.Set(h.controller)
	srv := httptest.NewServer(Handler(holder, "admin-token"))
	defer srv.Close()

	status, first := postOp(t, srv.URL+EvictPath, "admin-token", opBody("op-evict"))
	if status != http.StatusOK {
		t.Fatalf("evict status = %d body=%v", status, first)
	}
	if first["kind"] != opstate.KindEvict || first["state"] != string(StateEvicted) {
		t.Fatalf("evict identity/state = %v", first)
	}
	if first["walEpoch"] != strconv.FormatUint(wantEpoch, 10) || first["appliedLsn"] != strconv.FormatUint(wantLSN, 10) {
		t.Fatalf("evict revision = %v, want epoch=%d lsn=%d", first, wantEpoch, wantLSN)
	}
	if _, present := first["headCommitId"]; present {
		t.Fatalf("ordinary evict claimed a checkpoint head: %v", first)
	}
	// The exact receipted journal suspension travels as verbatim decimal
	// strings (never JS-rounded numbers).
	if first["journalSuspended"] != true || first["journalNextSeq"] != "42" {
		t.Fatalf("evict receipt lacks the exact journal suspension: %v", first)
	}

	// Lost-response replay is byte-stable in all exact proof fields and does
	// not repeat teardown work.
	status, replay := postOp(t, srv.URL+EvictPath, "admin-token", opBody("op-evict"))
	if status != http.StatusOK {
		t.Fatalf("evict replay status = %d body=%v", status, replay)
	}
	for _, field := range []string{"operationId", "kind", "volumeId", "branch", "authorityInstanceId", "state", "walEpoch", "appliedLsn", "coherenceGeneration", "walPoisoned", "reconciliationRequired", "journalSuspended", "journalNextSeq", "journalTipDigest", "completedAtMs"} {
		if first[field] != replay[field] {
			t.Fatalf("evict replay diverged on %s: %v vs %v", field, first[field], replay[field])
		}
	}
	if h.stops.Load() != 1 {
		t.Fatalf("duplicate evict repeated data-plane stop: %d", h.stops.Load())
	}
	if h.journal.callCount() != 1 {
		t.Fatalf("duplicate evict repeated the journal step-down: %d", h.journal.callCount())
	}
	if first["coherenceGeneration"] == "" || first["reconciliationRequired"] != false {
		t.Fatalf("evict response lacks complete healthy revision semantics: %v", first)
	}

	changed := opBody("op-evict")
	changed["branch"] = "other"
	status, conflict := postOp(t, srv.URL+EvictPath, "admin-token", changed)
	if status != http.StatusConflict {
		t.Fatalf("changed retry status = %d body=%v", status, conflict)
	}
}

func TestHTTPEvictPoisonRequiresReconciliation(t *testing.T) {
	h := newManagedHarness(t)
	h.write(t, "durable-before-poison.txt", "acknowledged")
	h.w.Poison()
	holder := &Holder{}
	holder.Set(h.controller)
	srv := httptest.NewServer(Handler(holder, "admin-token"))
	defer srv.Close()

	status, body := postOp(t, srv.URL+EvictPath, "admin-token", opBody("op-poisoned-evict"))
	if status != http.StatusOK || body["walPoisoned"] != true || body["reconciliationRequired"] != true {
		t.Fatalf("poisoned evict did not explicitly require reconciliation: status=%d body=%v", status, body)
	}
	if body["state"] != string(StateEvicted) || body["walEpoch"] == "" || body["coherenceGeneration"] == "" {
		t.Fatalf("poisoned evict lost its acknowledged-prefix proof: %v", body)
	}
}

func TestHTTPStrictBodyMethodNoStoreAndExplicitDevAuth(t *testing.T) {
	h := newManagedHarness(t)
	holder := &Holder{}
	holder.Set(h.controller)

	// Empty-token Handler is locked by default; unauthenticated control requires
	// the explicit development option used only by main's loopback branch.
	locked := httptest.NewServer(Handler(holder, ""))
	defer locked.Close()
	status, body := postOp(t, locked.URL+CheckpointPath, "", opBody("op-locked"))
	if status != http.StatusForbidden {
		t.Fatalf("empty-token handler failed open: status=%d body=%v", status, body)
	}
	// The dev opt-in admits the request past authentication; a managed
	// controller then answers the explicit history-cut refusal.
	dev := httptest.NewServer(HandlerWithOptions(holder, "", HandlerOptions{AllowUnauthenticatedDevelopment: true}))
	defer dev.Close()
	status, body = postOp(t, dev.URL+CheckpointPath, "", opBody("op-dev"))
	if status != http.StatusNotImplemented || body["error"].(map[string]any)["code"] != CodeHistoryCutUnavailable {
		t.Fatalf("explicit dev handler did not opt in: status=%d body=%v", status, body)
	}

	strict := httptest.NewServer(Handler(holder, "admin-token"))
	defer strict.Close()
	unknown := opBody("op-unknown-field")
	unknown["surprise"] = true
	status, body = postOp(t, strict.URL+CheckpointPath, "admin-token", unknown)
	if status != http.StatusBadRequest || body["error"].(map[string]any)["code"] != CodeInvalidRequest {
		t.Fatalf("unknown JSON field was accepted: status=%d body=%v", status, body)
	}
	duplicateRaw := `{"operationId":"op-duplicate","operationId":"op-shadow","volumeId":"vol_1","branch":"main","authorityInstanceId":"pfvcs_1"}`
	duplicateReq, err := http.NewRequest(http.MethodPost, strict.URL+CheckpointPath, bytes.NewBufferString(duplicateRaw))
	if err != nil {
		t.Fatal(err)
	}
	duplicateReq.Header.Set("Authorization", "Bearer admin-token")
	duplicateResp, err := http.DefaultClient.Do(duplicateReq)
	if err != nil {
		t.Fatal(err)
	}
	var duplicateBody map[string]any
	if err := json.NewDecoder(duplicateResp.Body).Decode(&duplicateBody); err != nil {
		_ = duplicateResp.Body.Close()
		t.Fatal(err)
	}
	_ = duplicateResp.Body.Close()
	if duplicateResp.StatusCode != http.StatusBadRequest || duplicateBody["error"].(map[string]any)["code"] != CodeInvalidRequest {
		t.Fatalf("duplicate JSON field was accepted: status=%d body=%v", duplicateResp.StatusCode, duplicateBody)
	}

	req, err := http.NewRequest(http.MethodGet, strict.URL+EvictPath, nil)
	if err != nil {
		t.Fatal(err)
	}
	req.Header.Set("Authorization", "Bearer admin-token")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusMethodNotAllowed || resp.Header.Get("Allow") != http.MethodPost {
		t.Fatalf("method response = %d Allow=%q", resp.StatusCode, resp.Header.Get("Allow"))
	}
	if resp.Header.Get("Cache-Control") != "no-store" {
		t.Fatalf("lifecycle response is cacheable: %q", resp.Header.Get("Cache-Control"))
	}
	var methodBody map[string]any
	if err := json.NewDecoder(resp.Body).Decode(&methodBody); err != nil {
		t.Fatal(err)
	}
	if methodBody["error"].(map[string]any)["code"] != CodeMethodNotAllowed {
		t.Fatalf("wrong method error: %v", methodBody)
	}
}

// TestHTTPManagedRefusalsAndFencing drives the managed admin surface over
// real HTTP: not-primary, auth, fencing, and the typed history-cut refusal on
// every history-materialization route.
func TestHTTPManagedRefusalsAndFencing(t *testing.T) {
	holder := &Holder{}
	srv := httptest.NewServer(Handler(holder, "admin-token"))
	defer srv.Close()

	// No controller published yet: 503 VCS_NOT_PRIMARY.
	status, body := postOp(t, srv.URL+CheckpointPath, "admin-token", opBody("op-1"))
	if status != http.StatusServiceUnavailable {
		t.Fatalf("no-controller status = %d body=%v", status, body)
	}

	h := newManagedHarness(t)
	holder.Set(h.controller)

	// Missing/wrong token: 401 before any work.
	if status, _ := postOp(t, srv.URL+CheckpointPath, "", opBody("op-1")); status != http.StatusUnauthorized {
		t.Fatalf("unauthenticated status = %d", status)
	}
	if status, _ := postOp(t, srv.URL+CheckpointPath, "wrong", opBody("op-1")); status != http.StatusUnauthorized {
		t.Fatalf("wrong-token status = %d", status)
	}

	// Fence mismatch: machine-readable code.
	wrong := opBody("op-1")
	wrong["authorityInstanceId"] = "pfvcs_STALE"
	status, body = postOp(t, srv.URL+CheckpointPath, "admin-token", wrong)
	if status != http.StatusConflict {
		t.Fatalf("fence status = %d body=%v", status, body)
	}
	if errObj, _ := body["error"].(map[string]any); errObj == nil || errObj["code"] != CodeFenceMismatch {
		t.Fatalf("fence error body = %v", body)
	}

	// Every history-materialization route answers the explicit typed refusal.
	for name, path := range map[string]string{
		"checkpoint":    CheckpointPath,
		"quiesce":       QuiescePath,
		"release-lease": ReleaseLeasePath,
	} {
		status, refused := postOp(t, srv.URL+path, "admin-token", opBody("op-"+name))
		if status != http.StatusNotImplemented {
			t.Fatalf("%s status = %d body=%v", name, status, refused)
		}
		if errObj, _ := refused["error"].(map[string]any); errObj == nil || errObj["code"] != CodeHistoryCutUnavailable {
			t.Fatalf("%s error body = %v", name, refused)
		}
	}
	if h.controller.State() != StateServing {
		t.Fatalf("refusals changed lifecycle state to %s", h.controller.State())
	}
}

// TestCrossTokenAuthorizationFails proves the credential separation both ways:
// the DATA-PLANE token never authorizes a lifecycle operation on the admin API,
// and the ADMIN token never authenticates the data-plane handshake. A leaked
// mount credential cannot evict the volume; a control-plane credential cannot
// read or write file data.
func TestCrossTokenAuthorizationFails(t *testing.T) {
	const (
		adminToken = "admin-secret"
		dataToken  = "data-plane-secret"
	)
	h := newManagedHarness(t)
	holder := &Holder{}
	holder.Set(h.controller)
	srv := httptest.NewServer(Handler(holder, adminToken))
	defer srv.Close()

	// Data-plane bearer on the admin API: rejected before any work.
	status, body := postOp(t, srv.URL+CheckpointPath, dataToken, opBody("op-cross"))
	if status != http.StatusUnauthorized {
		t.Fatalf("data-plane token on admin API: status = %d body=%v", status, body)
	}
	// The admin bearer reaches the controller (control positive: the managed
	// answer is the typed refusal, not 401).
	if status, _ := postOp(t, srv.URL+CheckpointPath, adminToken, opBody("op-cross")); status != http.StatusNotImplemented {
		t.Fatalf("admin token on admin API: status = %d", status)
	}

	// Admin token on the data-plane handshake: rejected; the data token accepted.
	left, right := net.Pipe()
	defer left.Close()
	serverErr := make(chan error, 1)
	go func() { serverErr <- secure.ServerHandshake(right, dataToken) }()
	if err := secure.ClientHandshake(left, adminToken); err == nil {
		t.Fatal("admin token must not authenticate the data-plane handshake")
	}
	if err := <-serverErr; err == nil {
		t.Fatal("server must reject the admin token on the data plane")
	}

	left2, right2 := net.Pipe()
	defer left2.Close()
	go func() { serverErr <- secure.ServerHandshake(right2, dataToken) }()
	if err := secure.ClientHandshake(left2, dataToken); err != nil {
		t.Fatalf("data token must authenticate the data plane: %v", err)
	}
	if err := <-serverErr; err != nil {
		t.Fatalf("server handshake with the data token: %v", err)
	}
}
