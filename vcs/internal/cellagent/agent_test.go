package cellagent

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"errors"
	"io"
	"math/big"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/steerlabs/portablefs/vcs/internal/cellhelper"
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
			ArchiveConfigured: true,
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
	if !reported.ArchiveConfigured {
		t.Fatalf("agent dropped the helper archive capability = %+v", reported)
	}
}

type convergenceHost struct {
	mu       sync.Mutex
	applied  []string
	observed []string
}

func (host *convergenceHost) Apply(_ context.Context, plan cellplan.VolumePlan, _ cellhelper.Assignment) (controlplane.VolumeObservation, cellhelper.HostUpdate) {
	host.mu.Lock()
	defer host.mu.Unlock()
	host.applied = append(host.applied, plan.VolumeID)
	return controlplane.VolumeObservation{Provisioned: true, AuthorityAbsent: true}, cellhelper.HostUpdate{}
}

func (host *convergenceHost) Observe(_ context.Context, plan cellplan.VolumePlan, _ cellhelper.Assignment) (controlplane.VolumeObservation, cellhelper.HostUpdate) {
	host.mu.Lock()
	defer host.mu.Unlock()
	host.observed = append(host.observed, plan.VolumeID)
	return controlplane.VolumeObservation{Provisioned: true, AuthorityAbsent: true}, cellhelper.HostUpdate{}
}

func (*convergenceHost) ArchiveConfigured() bool { return true }

func TestManagerAgentHelperAppliesCompletePlanAfterSkippingGenerations(t *testing.T) {
	now := time.Unix(1_900_000_000, 0).UTC()
	planPublic, planPrivate, _ := ed25519.GenerateKey(rand.Reader)
	_, capabilityPrivate, _ := ed25519.GenerateKey(rand.Reader)
	productPublic, _, _ := ed25519.GenerateKey(rand.Reader)
	ca := agentTestCA(t, now)
	store, err := controlplane.OpenStore(filepath.Join(t.TempDir(), "manager.state"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	manager, err := controlplane.NewManager(controlplane.ManagerConfig{
		Store: store, PlanPrivateKey: planPrivate, CapabilityPrivateKey: capabilityPrivate,
		ProductIssuers: map[string]ed25519.PublicKey{"opensteer": productPublic},
		AuthorityCA:    ca, ClientCA: ca, EnrollmentCA: ca, Now: func() time.Time { return now }, ReleaseID: "manager-r3",
		PlanLifetime: 10 * time.Minute, GrantLifetime: 10 * time.Minute, EnrollmentLease: 30 * time.Minute,
		ProductMaxLifetime: 15 * time.Minute, ClientCertLifetime: time.Hour, AuthorityCertLifetime: time.Hour,
		ObservedStaleAfter: 2 * time.Minute, ClockSkew: time.Second, WakeBurstBytes: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	cellID := "11111111-1111-4111-8111-111111111111"
	cell, err := manager.RegisterCell("generation-skip-cell", controlplane.RegisterCellRequest{
		ID: cellID, AvailabilityZone: "zone-a", AuthorityHost: "cell.test", AuthorityDNSZone: "cell.test",
		CapacityBytes: 20 << 30, CapacityInodes: 2_000_000, Pool: controlplane.PoolProduct,
	})
	if err != nil {
		t.Fatal(err)
	}
	managerObservations, managerHeartbeats := 0, 0
	managerClient := &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		switch {
		case request.Method == http.MethodGet && strings.HasSuffix(request.URL.Path, "/plan"):
			envelope, planErr := manager.CellPlan(cellID)
			if planErr != nil {
				t.Fatal(planErr)
			}
			return jsonResponse(t, envelope), nil
		case request.Method == http.MethodPost && strings.HasSuffix(request.URL.Path, "/observations"):
			managerObservations++
			var observation controlplane.CellObservation
			if decodeErr := json.NewDecoder(request.Body).Decode(&observation); decodeErr != nil {
				t.Fatal(decodeErr)
			}
			observed, observeErr := manager.ObserveCell(request.Header.Get("Idempotency-Key"), observation)
			if observeErr != nil {
				t.Fatal(observeErr)
			}
			return jsonResponse(t, observed), nil
		case request.Method == http.MethodPost && strings.HasSuffix(request.URL.Path, "/heartbeat"):
			managerHeartbeats++
			var heartbeat controlplane.CellHeartbeat
			if decodeErr := json.NewDecoder(request.Body).Decode(&heartbeat); decodeErr != nil {
				t.Fatal(decodeErr)
			}
			if heartbeatErr := manager.HeartbeatCell(heartbeat); heartbeatErr != nil {
				t.Fatal(heartbeatErr)
			}
			return jsonResponse(t, map[string]string{"status": "ok"}), nil
		default:
			t.Fatalf("unexpected Manager request %s %s", request.Method, request.URL.Path)
			return nil, nil
		}
	})}
	host := &convergenceHost{}
	helperStatePath := filepath.Join(t.TempDir(), "helper.state")
	helperFails := false
	reconciler := &cellhelper.Reconciler{
		CellID: cellID, PlanPublicKey: planPublic, ClockSkew: time.Second, PlanLifetime: 10 * time.Minute,
		ReleaseID: "helper-r1", Now: func() time.Time { return now }, StatePath: helperStatePath, Host: host,
	}
	helperClient := &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		if request.Method != http.MethodPost || request.URL.String() != "http://unix/v1/reconcile" {
			t.Fatalf("unexpected Helper request %s %s", request.Method, request.URL)
		}
		if helperFails {
			return &http.Response{StatusCode: http.StatusInternalServerError, Header: make(http.Header),
				Body: io.NopCloser(strings.NewReader(`{"error":"reconciliation failed"}`))}, nil
		}
		var envelope cellplan.Envelope
		if decodeErr := json.NewDecoder(request.Body).Decode(&envelope); decodeErr != nil {
			t.Fatal(decodeErr)
		}
		observation, reconcileErr := reconciler.Reconcile(request.Context(), envelope)
		if reconcileErr != nil {
			t.Fatal(reconcileErr)
		}
		return jsonResponse(t, observation), nil
	})}
	agent, err := New(Config{
		CellID: cellID, ManagerURL: "https://manager.example", PlanPublicKey: planPublic,
		PlanLifetime: 10 * time.Minute, ClockSkew: time.Second, PollInterval: time.Second, ReleaseID: "agent-r2",
		ManagerClient: managerClient, HelperClient: helperClient, Now: func() time.Time { return now },
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := agent.RunOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	initialState := readHelperState(t, helperStatePath)
	if initialState.PlanGeneration != cell.PlanGeneration || len(initialState.Assignments) != 0 {
		t.Fatalf("initial helper state = %+v", initialState)
	}
	for index := range 3 {
		if _, err := manager.CreateVolume("generation-skip-volume-"+string(rune('a'+index)), controlplane.CreateVolumeRequest{
			AuthorizationDomain: "org", Owner: "owner", ProductIssuer: "opensteer",
			QuotaBytes: 1 << 30, QuotaInodes: 100_000, Pool: controlplane.PoolProduct,
		}); err != nil {
			t.Fatal(err)
		}
	}
	latestEnvelope, err := manager.CellPlan(cellID)
	if err != nil {
		t.Fatal(err)
	}
	latestPlan, _, err := cellplan.Verify(planPublic, latestEnvelope, cellID, now, time.Second, 10*time.Minute)
	if err != nil || latestPlan.Generation != cell.PlanGeneration+3 || len(latestPlan.Volumes) != 3 {
		t.Fatalf("latest complete Manager plan = %+v, %v", latestPlan, err)
	}
	if err := agent.RunOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	convergedState := readHelperState(t, helperStatePath)
	if convergedState.PlanGeneration != latestPlan.Generation || len(convergedState.Assignments) != 3 || len(host.applied) != 3 {
		t.Fatalf("generation-skipping reconcile: helper=%+v applies=%v", convergedState, host.applied)
	}
	if err := agent.RunOnce(context.Background()); err != nil {
		t.Fatal(err)
	}
	if managerObservations != 2 || managerHeartbeats != 1 || len(host.observed) != 3 {
		t.Fatalf("level-triggered calls: observations=%d heartbeats=%d applies=%d observes=%d",
			managerObservations, managerHeartbeats, len(host.applied), len(host.observed))
	}
	failedPlacement, err := manager.CreateVolume("generation-skip-unreconciled", controlplane.CreateVolumeRequest{
		AuthorizationDomain: "org", Owner: "unreconciled", ProductIssuer: "opensteer",
		QuotaBytes: 1 << 30, QuotaInodes: 100_000, Pool: controlplane.PoolProduct,
	})
	if err != nil {
		t.Fatal(err)
	}
	helperFails = true
	if err := agent.RunOnce(context.Background()); err == nil {
		t.Fatal("failed helper reconciliation was reported as successful")
	}
	now = now.Add(3 * time.Minute)
	if _, err := manager.CreateVolume("generation-skip-after-failure", controlplane.CreateVolumeRequest{
		AuthorizationDomain: "org", Owner: "after-failure", ProductIssuer: "opensteer",
		QuotaBytes: 1 << 30, QuotaInodes: 100_000, Pool: controlplane.PoolProduct,
	}); !errors.Is(err, controlplane.ErrCellUnavailable) {
		t.Fatalf("placement after reconciliation liveness aged = %v", err)
	}
	volumes, err := manager.ListVolumes()
	if err != nil {
		t.Fatal(err)
	}
	retained := false
	for _, volume := range volumes.Volumes {
		if volume.ID == failedPlacement.ID {
			retained = volume.Placement != nil && volume.Placement.PendingBytes == failedPlacement.Placement.PendingBytes &&
				volume.Placement.PendingInodes == failedPlacement.Placement.PendingInodes && volume.Placement.PendingBytes > 0
		}
	}
	report, reportErr := manager.Capacity()
	if !retained || reportErr != nil || report.Pools[0].CreateStatus != controlplane.AdmissionCellUnavailable {
		t.Fatalf("failed reconcile reservation/report: retained=%v report=%+v err=%v", retained, report, reportErr)
	}
}

func agentTestCA(t *testing.T, now time.Time) *controlplane.CertificateAuthority {
	t.Helper()
	public, private, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	template := &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "agent-test-ca"},
		NotBefore: now.Add(-time.Hour), NotAfter: now.Add(48 * time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true, IsCA: true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, public, private)
	if err != nil {
		t.Fatal(err)
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(private)
	if err != nil {
		t.Fatal(err)
	}
	ca, err := controlplane.ParseCertificateAuthority(
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
		pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}),
	)
	if err != nil {
		t.Fatal(err)
	}
	return ca
}

func readHelperState(t *testing.T, path string) cellhelper.State {
	t.Helper()
	payload, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var state cellhelper.State
	if err := json.Unmarshal(payload, &state); err != nil {
		t.Fatal(err)
	}
	return state
}

func TestRunOnceRefreshesUnchangedObservationAtPlanInterval(t *testing.T) {
	publicKey, privateKey, _ := ed25519.GenerateKey(nil)
	now := time.Unix(1_900_000_000, 0)
	cellID := "11111111-1111-4111-8111-111111111111"
	plan := testPlan(now, cellID)
	plan.UsageRefreshSeconds = 90
	envelope, err := cellplan.Sign(privateKey, plan)
	if err != nil {
		t.Fatal(err)
	}
	var observationKeys []string
	heartbeats := 0
	managerClient := &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		if request.Method == http.MethodGet {
			return jsonResponse(t, envelope), nil
		}
		if strings.HasSuffix(request.URL.Path, "/heartbeat") {
			heartbeats++
		} else {
			observationKeys = append(observationKeys, request.Header.Get("Idempotency-Key"))
		}
		return jsonResponse(t, map[string]string{"ok": "true"}), nil
	})}
	helperClient := &http.Client{Transport: roundTripFunc(func(*http.Request) (*http.Response, error) {
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
	for _, advance := range []time.Duration{0, 29 * time.Second, time.Second} {
		now = now.Add(advance)
		if err := agent.RunOnce(context.Background()); err != nil {
			t.Fatal(err)
		}
	}
	if len(observationKeys) != 2 || heartbeats != 1 {
		t.Fatalf("observations=%d heartbeats=%d, want 2 and 1", len(observationKeys), heartbeats)
	}
	if observationKeys[0] == observationKeys[1] {
		t.Fatal("timed observations reused an idempotency key")
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

func TestObservationMatchesReleaseOnlyWithExactReleasedIdentity(t *testing.T) {
	planned := []cellplan.VolumePlan{{VolumeID: "22222222-2222-4222-8222-222222222222", Phase: cellplan.PhaseRelease,
		AuthorityGeneration: 3, ProjectID: 71, ServiceUID: 10_071, ServiceGID: 10_071, ListenPort: 20_071}}
	observed := controlplane.VolumeObservation{VolumeID: planned[0].VolumeID, Released: true, AuthorityGeneration: 3,
		ProjectID: 71, ServiceUID: 10_071, ServiceGID: 10_071, ListenPort: 20_071}
	if !observationMatchesPlan([]controlplane.VolumeObservation{observed}, planned) {
		t.Fatal("exact released observation was rejected")
	}
	observed.Released = false
	if observationMatchesPlan([]controlplane.VolumeObservation{observed}, planned) {
		t.Fatal("release phase was accepted without the helper's released signal")
	}
}

func TestRunOnceRelaysV2EnvelopeAndHelperCapabilities(t *testing.T) {
	publicKey, privateKey, _ := ed25519.GenerateKey(nil)
	now := time.Unix(1_900_000_000, 0)
	cellID := "11111111-1111-4111-8111-111111111111"
	plan := testPlan(now, cellID)
	plan.Version = cellplan.Version
	plan.AuthorityCAPEM, plan.ClientCAPEM, plan.CapabilityPublicKey = "authority-ca", "client-ca", "cap-key"
	envelope, err := cellplan.Sign(privateKey, plan)
	if err != nil {
		t.Fatal(err)
	}
	var reported controlplane.CellObservation
	managerClient := &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		if request.Method == http.MethodGet {
			return jsonResponse(t, envelope), nil
		}
		if err := json.NewDecoder(request.Body).Decode(&reported); err != nil {
			t.Fatal(err)
		}
		return jsonResponse(t, map[string]string{"ok": "true"}), nil
	})}
	helperClient := &http.Client{Transport: roundTripFunc(func(request *http.Request) (*http.Response, error) {
		var received cellplan.Envelope
		if err := json.NewDecoder(request.Body).Decode(&received); err != nil || received.Token != envelope.Token {
			t.Fatalf("v2 envelope changed across the agent: %v", err)
		}
		return jsonResponse(t, controlplane.CellObservation{CellID: cellID, PlanGeneration: plan.Generation,
			ManagerReleaseID: plan.ReleaseID, HelperReleaseID: "helper-v2", ObservedUnix: now.Unix()}), nil
	})}
	agent, err := New(Config{CellID: cellID, ManagerURL: "https://manager.example", PlanPublicKey: publicKey,
		PlanLifetime: 5 * time.Minute, ClockSkew: time.Second, PollInterval: time.Second, ReleaseID: "agent-v2",
		ManagerClient: managerClient, HelperClient: helperClient, Now: func() time.Time { return now }})
	if err != nil {
		t.Fatal(err)
	}
	if err := agent.RunOnce(context.Background()); err != nil {
		t.Fatal(err)
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
		UsageRefreshSeconds: 300,
		AuthorityCAPEM:      "authority-ca", ClientCAPEM: "client-ca", CapabilityPublicKey: "cap-key",
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
