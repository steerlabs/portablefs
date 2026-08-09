package cellagent

import (
	"context"
	"crypto/ed25519"
	"encoding/json"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/steerlabs/portablefs/vcs/internal/cellplan"
	"github.com/steerlabs/portablefs/vcs/internal/controlplane"
)

type roundTripFunc func(*http.Request) (*http.Response, error)

func (function roundTripFunc) RoundTrip(request *http.Request) (*http.Response, error) {
	return function(request)
}

func TestRunOnceVerifiesReconcilesAndReportsExactReleases(t *testing.T) {
	publicKey, privateKey, _ := ed25519.GenerateKey(nil)
	now := time.Unix(1_900_000_000, 0)
	cellID := "11111111-1111-4111-8111-111111111111"
	plan := testPlan(now, cellID)
	envelope, err := cellplan.Sign(privateKey, plan)
	if err != nil {
		t.Fatal(err)
	}
	var reported controlplane.CellObservation
	managerCalls := 0
	heartbeats := 0
	observations := 0
	managerClient := &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		managerCalls++
		switch request.Method {
		case http.MethodGet:
			return jsonResponse(t, envelope), nil
		case http.MethodPost:
			if strings.HasSuffix(request.URL.Path, "/heartbeat") {
				heartbeats++
				return jsonResponse(t, map[string]string{"ok": "true"}), nil
			}
			observations++
			if !strings.HasPrefix(request.Header.Get("Idempotency-Key"), "cell-observation-") {
				t.Fatal("observation did not carry deterministic idempotency key")
			}
			if err := json.NewDecoder(request.Body).Decode(&reported); err != nil {
				t.Fatal(err)
			}
			return jsonResponse(t, map[string]string{"ok": "true"}), nil
		default:
			t.Fatalf("unexpected manager method %s", request.Method)
			return nil, nil
		}
	})}
	helperCalls := 0
	helperClient := &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		helperCalls++
		if request.URL.String() != "http://unix/v1/reconcile" {
			t.Fatalf("helper URL = %s", request.URL)
		}
		var received cellplan.Envelope
		if err := json.NewDecoder(request.Body).Decode(&received); err != nil || received.Token != envelope.Token {
			t.Fatalf("helper received altered signed envelope: %v", err)
		}
		return jsonResponse(t, controlplane.CellObservation{
			CellID: cellID, PlanGeneration: plan.Generation, ManagerReleaseID: plan.ReleaseID,
			HelperReleaseID: "helper-r1", ObservedUnix: now.Unix(),
		}), nil
	})}
	agent, err := New(Config{
		CellID: cellID, ManagerURL: "https://manager.example", PlanPublicKey: publicKey,
		PlanLifetime: 5 * time.Minute, ClockSkew: time.Second, PollInterval: time.Second,
		ReleaseID: "agent-r2", ManagerClient: managerClient, HelperClient: helperClient, Now: func() time.Time { return now },
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := agent.RunOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := agent.RunOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	if managerCalls != 4 || helperCalls != 2 || observations != 1 || heartbeats != 1 {
		t.Fatalf("manager calls=%d helper calls=%d", managerCalls, helperCalls)
	}
	if reported.AgentReleaseID != "agent-r2" || reported.HelperReleaseID != "helper-r1" || reported.ManagerReleaseID != "manager-r3" {
		t.Fatalf("reported releases = %+v", reported)
	}
}

func TestRunOnceRejectsUnverifiedPlanBeforePrivilegeBoundary(t *testing.T) {
	publicKey, _, _ := ed25519.GenerateKey(nil)
	_, wrongPrivateKey, _ := ed25519.GenerateKey(nil)
	now := time.Unix(1_900_000_000, 0)
	cellID := "11111111-1111-4111-8111-111111111111"
	envelope, err := cellplan.Sign(wrongPrivateKey, testPlan(now, cellID))
	if err != nil {
		t.Fatal(err)
	}
	helperCalled := false
	agent, err := New(Config{
		CellID: cellID, ManagerURL: "https://manager.example", PlanPublicKey: publicKey,
		PlanLifetime: 5 * time.Minute, ClockSkew: time.Second, PollInterval: time.Second, ReleaseID: "agent-r2",
		ManagerClient: &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
			return jsonResponse(t, envelope), nil
		})},
		HelperClient: &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
			helperCalled = true
			return nil, nil
		})},
		Now: func() time.Time { return now },
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := agent.RunOnce(context.Background()); err == nil {
		t.Fatal("unverified plan was accepted")
	}
	if helperCalled {
		t.Fatal("unverified plan crossed the local privilege boundary")
	}
}

func TestObservationMustContainEveryExactSignedAssignment(t *testing.T) {
	planned := []cellplan.VolumePlan{{
		VolumeID: "22222222-2222-4222-8222-222222222222", AuthorityGeneration: 3,
		ProjectID: 71, ServiceUID: 10_071, ServiceGID: 10_071, ListenPort: 20_071,
	}}
	exact := controlplane.VolumeObservation{
		VolumeID: planned[0].VolumeID, AuthorityGeneration: 3,
		ProjectID: 71, ServiceUID: 10_071, ServiceGID: 10_071, ListenPort: 20_071,
	}
	if !observationMatchesPlan([]controlplane.VolumeObservation{exact}, planned) {
		t.Fatal("exact helper observation did not match the signed plan")
	}
	if observationMatchesPlan(nil, planned) {
		t.Fatal("helper was allowed to omit a signed volume")
	}
	if observationMatchesPlan([]controlplane.VolumeObservation{exact, exact}, planned) {
		t.Fatal("helper was allowed to duplicate a signed volume")
	}
	changed := exact
	changed.ProjectID++
	if observationMatchesPlan([]controlplane.VolumeObservation{changed}, planned) {
		t.Fatal("helper was allowed to change a signed isolation identifier")
	}
}

func TestDecodeStrictRejectsBytesBeyondTheHardLimit(t *testing.T) {
	var target struct{}
	if err := decodeStrict(strings.NewReader(`{} `), 2, &target); err == nil {
		t.Fatal("decoder accepted a valid JSON prefix followed by bytes beyond its limit")
	}
}

func testPlan(now time.Time, cellID string) cellplan.Plan {
	return cellplan.Plan{
		Version: cellplan.Version, CellID: cellID, Generation: 7, IssuedAt: now.Unix(),
		ExpiresAt: now.Add(time.Minute).Unix(), ReleaseID: "manager-r3",
	}
}

func jsonResponse(t *testing.T, value any) *http.Response {
	t.Helper()
	payload, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return &http.Response{
		StatusCode: http.StatusOK, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(string(payload))),
	}
}
