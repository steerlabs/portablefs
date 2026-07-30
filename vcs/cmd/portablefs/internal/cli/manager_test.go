package cli

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestResolveAccessNeverFallsBack pins the v2 contract: the access-lease
// route is the ONLY endpoint resolution transport. A manager without it
// (404) is a hard, actionable error — the client must not probe the retired
// mount-session/authority-session routes.
func TestResolveAccessNeverFallsBack(t *testing.T) {
	f := newFakeServer(t) // /v1/access-leases/create unset => 404
	m := newManagerClient(f.srv.URL, "mgr_tok")
	_, err := m.resolveAccess(context.Background(), "vol_1", "main", "")
	if err == nil || !strings.Contains(err.Error(), "vol_1@main") {
		t.Fatalf("a manager without the access-lease route must fail by name: %v", err)
	}
	var paths []string
	for _, r := range f.recorded() {
		paths = append(paths, r.Path)
	}
	if strings.Join(paths, ",") != "/v1/access-leases/create" {
		t.Fatalf("resolution must touch ONLY the access-lease route: %v", paths)
	}
}

func TestIntentLeaseTransactionReplaysExactCreateThenRelease(t *testing.T) {
	f := newFakeServer(t)
	const (
		createOp  = "11111111-2222-4333-8444-555555555555"
		releaseOp = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"
		consumer  = "cli:durable-host"
	)
	var createBodies, releaseBodies []map[string]any
	f.on("POST", "/v1/access-leases/create", func(body map[string]any) (int, string) {
		createBodies = append(createBodies, body)
		return 200, leaseCreateOK
	})
	f.on("POST", "/v1/access-leases/release", func(body map[string]any) (int, string) {
		releaseBodies = append(releaseBodies, body)
		return 200, `{"lease":{"accessLeaseId":"pfal_1","controlSeq":"8","expiresAt":1700000600000,"state":"released"}}`
	})
	e, _, _ := testEnv(t)
	baseGetenv := e.getenv
	e.getenv = func(name string) string {
		switch name {
		case "PORTABLEFS_API_URL", "PORTABLEFS_MANAGER_URL":
			return f.srv.URL
		case "PORTABLEFS_MANAGER_TOKEN":
			return "mgr_tok"
		default:
			return baseGetenv(name)
		}
	}
	intent := &mountIntent{
		SchemaVersion:           2,
		Phase:                   "starting",
		MountPath:               filepath.Join(t.TempDir(), "mount"),
		VolumeID:                "vol_1",
		Branch:                  "main",
		Strategy:                "fuse",
		ManagerURL:              f.srv.URL,
		LeaseCreateOperationID:  createOp,
		LeaseReleaseOperationID: releaseOp,
		LeaseConsumerID:         consumer,
		OperationOwnerPID:       os.Getpid(),
		UpdatedAtMs:             time.Now().UnixMilli(),
	}
	identity, err := processStartIdentity(os.Getpid())
	if err != nil {
		t.Fatal(err)
	}
	intent.OperationOwnerStartIdentity = identity
	if err := e.releaseIntentAccessLease(intent); err != nil {
		t.Fatal(err)
	}
	if len(createBodies) != 1 || createBodies[0]["operationId"] != createOp ||
		createBodies[0]["consumerId"] != consumer {
		t.Fatalf("exact replay create body = %+v", createBodies)
	}
	if len(releaseBodies) != 1 || releaseBodies[0]["operationId"] != releaseOp ||
		releaseBodies[0]["accessLeaseId"] != "pfal_1" {
		t.Fatalf("exact replay release body = %+v", releaseBodies)
	}
}

func TestInjectedPreMountFailureReleasesExactLease(t *testing.T) {
	f := newFakeServer(t)
	const releaseOp = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"
	var operations []string
	f.on("POST", "/v1/access-leases/release", func(body map[string]any) (int, string) {
		operations = append(operations, body["operationId"].(string))
		return 200, `{"lease":{"accessLeaseId":"pfal_1","controlSeq":"8","expiresAt":1700000600000,"state":"released"}}`
	})
	keeper := newLeaseKeeper(newManagerClient(f.srv.URL, "mgr_tok"), nil, leaseState{
		AccessLeaseID: "pfal_1",
		AccessToken:   "lease_tok_1",
		ExpiresAtMs:   1700000600000,
		ControlSeq:    "7",
	}, nil)
	if err := releaseStartupAccessLease(keeper, releaseOp); err != nil {
		t.Fatal(err)
	}
	if len(operations) != 1 || operations[0] != releaseOp {
		t.Fatalf("pre-mount cleanup operations = %v", operations)
	}
}

func TestReleasedLeaseFactUsesLatestStateTokenAndNeedsNoManagerReplay(t *testing.T) {
	e, _, _ := testEnv(t)
	stateDir := filepath.Join(t.TempDir(), "mounts")
	mountPath := filepath.Join(t.TempDir(), "mount")
	operation, err := acquireMountOperation(stateDir, mountPath, "vol_1", "main", "fuse")
	if err != nil {
		t.Fatal(err)
	}
	defer operation.close(false)
	operation.mountInstanceID = "mnt_AAAAAAAAAAAAAAAAAAAAAA"
	operation.mountMechanism = "direct"
	operation.managerURL = "https://manager.example"
	operation.leaseReleaseOp = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"
	st := validFuseMountState(t, mountPath)
	st.MountInstanceID = operation.mountInstanceID
	st.ManagerURL = operation.managerURL
	st.AccessLeaseReleaseOperationID = operation.leaseReleaseOp
	st.AccessLease = &leaseState{
		AccessLeaseID: "pfal_1",
		AccessToken:   "rotated_latest_token",
		ExpiresAtMs:   1700000600000,
		ControlSeq:    "9",
	}
	if err := writeMountState(stateDir, st); err != nil {
		t.Fatal(err)
	}
	if err := publishReleasedLeaseIntent(operation, stateDir, mountPath); err != nil {
		t.Fatal(err)
	}
	intent, err := readMountIntent(operation.intentPath, mountPath)
	if err != nil {
		t.Fatal(err)
	}
	if intent.Phase != "lease-released" || intent.AccessLease == nil ||
		intent.AccessLease.AccessToken != "rotated_latest_token" {
		t.Fatalf("released fact = %+v", intent)
	}
	if _, err := e.reconcileMountIntent(intent, false); err != nil {
		t.Fatalf("released fact must finalize without manager replay: %v", err)
	}
}

func TestUmountFinalizesCoexistingReleasedIntentAndState(t *testing.T) {
	e, _, stderr := testEnv(t)
	stateDir, err := e.mountStateDir()
	if err != nil {
		t.Fatal(err)
	}
	mountPath := t.TempDir()
	operation, err := acquireMountOperation(stateDir, mountPath, "vol_1", "main", "fuse")
	if err != nil {
		t.Fatal(err)
	}
	operation.mountInstanceID = "mnt_AAAAAAAAAAAAAAAAAAAAAA"
	operation.mountMechanism = "direct"
	operation.managerURL = "https://manager.example"
	operation.leaseReleaseOp = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"
	lease := &leaseState{
		AccessLeaseID: "pfal_1",
		AccessToken:   "rotated_latest_token",
		ExpiresAtMs:   1700000600000,
		ControlSeq:    "9",
	}
	st := validFuseMountState(t, mountPath)
	st.MountInstanceID = operation.mountInstanceID
	st.ManagerURL = operation.managerURL
	st.AccessLeaseReleaseOperationID = operation.leaseReleaseOp
	st.AccessLease = lease
	if err := writeMountState(stateDir, st); err != nil {
		t.Fatal(err)
	}
	if err := publishReleasedLeaseIntent(operation, stateDir, mountPath); err != nil {
		t.Fatal(err)
	}
	if err := operation.close(false); err != nil {
		t.Fatal(err)
	}
	if rc := e.run([]string{"umount", mountPath}); rc != 0 {
		t.Fatalf("rc = %d, stderr = %q", rc, stderr.String())
	}
	if state, err := readMountState(stateDir, mountPath); err != nil || state != nil {
		t.Fatalf("state after finalization = %+v, %v", state, err)
	}
	_, intentPath := mountOperationPaths(stateDir, mountPath)
	if _, err := os.Stat(intentPath); !os.IsNotExist(err) {
		t.Fatalf("intent remains after finalization: %v", err)
	}
}

func TestPreparedCleanupIdentityAllowsSameLeaseRotation(t *testing.T) {
	mountPath := t.TempDir()
	state := validFuseMountState(t, mountPath)
	state.ManagerURL = "https://manager.example"
	state.AccessLeaseReleaseOperationID = "aaaaaaaa-bbbb-4ccc-8ddd-eeeeeeeeeeee"
	state.AccessLease = &leaseState{
		AccessLeaseID: "pfal_same_lease",
		AccessToken:   "token-before",
		ExpiresAtMs:   1700000600000,
		ControlSeq:    "8",
	}
	op := &mountOperation{mountPath: mountPath}
	hydrateMountOperationFromState(op, &state)
	identity, err := processStartIdentity(os.Getpid())
	if err != nil {
		t.Fatal(err)
	}
	intent := &mountIntent{
		SchemaVersion:               2,
		Phase:                       "drain-prepared",
		MountPath:                   op.mountPath,
		VolumeID:                    op.volumeID,
		Branch:                      op.branch,
		Strategy:                    op.strategy,
		FSType:                      op.fsType,
		AttachRef:                   op.attachRef,
		MountInstanceID:             op.mountInstanceID,
		KernelMountID:               op.kernelMountID,
		MountTargetDevice:           op.mountTarget.device,
		MountTargetInode:            op.mountTarget.inode,
		ManagerURL:                  op.managerURL,
		LeaseReleaseOperationID:     op.leaseReleaseOp,
		AccessLease:                 op.accessLease,
		MountMechanism:              op.mountMechanism,
		FUSEHelperPath:              op.fuseHelperPath,
		StartedAtMs:                 op.startedAtMs,
		AuthorityURL:                op.authorityURL,
		DataPlaneTransport:          op.transportMode,
		DataPlaneServerName:         op.transportServer,
		DataPlaneCAPath:             op.dataPlaneCAPath,
		DataPlaneCASHA256:           op.dataPlaneCAHash,
		MountOwnerPID:               state.PID,
		MountOwnerStartIdentity:     state.ProcessStartIdentity,
		OperationOwnerPID:           os.Getpid(),
		OperationOwnerStartIdentity: identity,
		UpdatedAtMs:                 1,
	}
	state.AccessLease = &leaseState{
		AccessLeaseID: "pfal_same_lease",
		AccessToken:   "token-after",
		ExpiresAtMs:   1700000900000,
		ControlSeq:    "9",
	}
	if err := verifyCleanupIntentMatchesState(intent, &state); err != nil {
		t.Fatalf("same lease rotation wedged prepared recovery: %v", err)
	}
	intent.Phase = "resources-cleaned"
	if err := verifyCleanupIntentMatchesState(intent, &state); err == nil {
		t.Fatal("terminal cleanup accepted a stale mutable lease frame")
	}
}

func TestResolveAccessErrorsAreActionable(t *testing.T) {
	f := newFakeServer(t)
	f.on("POST", "/v1/access-leases/create", func(map[string]any) (int, string) {
		return 401, `{"error":"Unauthorized."}`
	})
	m := newManagerClient(f.srv.URL, "wrong")
	_, err := m.resolveAccess(context.Background(), "vol_1", "main", "")
	if err == nil || !strings.Contains(err.Error(), "vol_1@main") {
		t.Fatalf("error must identify the volume@branch: %v", err)
	}
}

const leaseCreateOK = `{
  "authority": {"authorityUrl":"vcs.example.com:2050","host":"vcs.example.com","port":2050,"authorityInstanceId":"pfai_9","dataPlaneTransport":{"mode":"plaintext"}},
  "lease": {"accessLeaseId":"pfal_1","controlSeq":"7","expiresAt":1700000600000,"state":"active"},
  "accessToken": "lease_tok_1",
  "serverTimeMs": 1700000000000
}`

func TestResolveAccessRequiresExplicitTransport(t *testing.T) {
	f := newFakeServer(t)
	f.on("POST", "/v1/access-leases/create", func(map[string]any) (int, string) {
		return 200, `{
		  "authority":{"authorityUrl":"router.example:2050"},
		  "lease":{"accessLeaseId":"pfal_1","controlSeq":"1","expiresAt":1700000600000,"state":"active"},
		  "accessToken":"lease_tok"
		}`
	})
	_, err := newManagerClient(f.srv.URL, "mgr_tok").resolveAccess(context.Background(), "vol_1", "main", "")
	if err == nil || !strings.Contains(err.Error(), "upgrade the authority manager") {
		t.Fatalf("missing transport must fail with upgrade guidance: %v", err)
	}
}

func TestResolveAccessCarriesPrivateCATransport(t *testing.T) {
	ca := testCertificatePEM(t, 77)
	sum := sha256.Sum256([]byte(ca))
	digest := hex.EncodeToString(sum[:])
	response, err := json.Marshal(map[string]any{
		"authority": map[string]any{
			"authorityUrl": "router.example:2050",
			"dataPlaneTransport": map[string]any{
				"mode":       "tls-private-ca",
				"serverName": "router.example",
				"caPem":      ca,
				"caSha256":   digest,
			},
		},
		"lease": map[string]any{
			"accessLeaseId": "pfal_1",
			"controlSeq":    "1",
			"expiresAt":     int64(1700000600000),
			"state":         "active",
		},
		"accessToken": "lease_tok",
	})
	if err != nil {
		t.Fatal(err)
	}
	f := newFakeServer(t)
	f.on("POST", "/v1/access-leases/create", func(map[string]any) (int, string) {
		return 200, string(response)
	})
	session, err := newManagerClient(f.srv.URL, "mgr_tok").resolveAccess(context.Background(), "vol_1", "main", "")
	if err != nil {
		t.Fatal(err)
	}
	if session.DataPlaneTransport.Mode != dataPlaneTransportTLSPrivateCA ||
		session.DataPlaneTransport.ServerName != "router.example" ||
		session.DataPlaneTransport.CASHA256 != digest ||
		session.DataPlaneTransport.CAPEM != ca {
		t.Fatalf("private CA transport = %+v", session.DataPlaneTransport)
	}
}

// TestResolveAccessLeaseRoute pins the canonical transport: a manager
// serving POST /v1/access-leases/create resolves in ONE request, the access
// token is the data-plane credential, and the lease slice (id, token, expiry,
// controlSeq) is carried for the renewal loop.
func TestResolveAccessLeaseRoute(t *testing.T) {
	f := newFakeServer(t)
	f.on("POST", "/v1/access-leases/create", func(body map[string]any) (int, string) {
		if body["volumeId"] != "vol_1" || body["branch"] != "main" {
			return 400, `{"error":{"code":"ACCESS_LEASE_INVALID_REQUEST","message":"volumeId and branch are required."}}`
		}
		op, _ := body["operationId"].(string)
		if op == "" {
			return 400, `{"error":{"code":"ACCESS_LEASE_INVALID_REQUEST","message":"operationId is required."}}`
		}
		consumer, _ := body["consumerId"].(string)
		if !strings.HasPrefix(consumer, "cli:") {
			return 400, `{"error":{"code":"ACCESS_LEASE_INVALID_REQUEST","message":"consumerId must identify the CLI."}}`
		}
		return 200, leaseCreateOK
	})
	m := newManagerClient(f.srv.URL, "mgr_tok")
	got, err := m.resolveAccess(context.Background(), "vol_1", "main", "")
	if err != nil {
		t.Fatalf("resolveAccess: %v", err)
	}
	if got.AuthorityURL != "vcs.example.com:2050" || got.Token != "lease_tok_1" || got.AuthorityInstanceID != "pfai_9" {
		t.Fatalf("session = %+v", got)
	}
	if got.ExpiresAtMs != 1700000600000 {
		t.Fatalf("expiry must come from the lease: %+v", got)
	}
	if got.Lease == nil || got.Lease.AccessLeaseID != "pfal_1" || got.Lease.AccessToken != "lease_tok_1" || got.Lease.ControlSeq != "7" || got.Lease.ExpiresAtMs != 1700000600000 {
		t.Fatalf("lease slice = %+v", got.Lease)
	}
	if len(f.recorded()) != 1 {
		t.Fatalf("the lease route must resolve in one request: %+v", f.recorded())
	}
}

// TestResolveAccessForwardsTeamID pins the tenant namespace: when the CLI
// knows the volume's tenant id it rides as teamId on the lease route
// (journal-native production managers require it; environment managers
// ignore it).
func TestResolveAccessForwardsTeamID(t *testing.T) {
	f := newFakeServer(t)
	f.on("POST", "/v1/access-leases/create", func(body map[string]any) (int, string) {
		if body["teamId"] != "team_9" {
			return 400, `{"error":{"code":"ACCESS_LEASE_INVALID_REQUEST","message":"teamId is required by this manager."}}`
		}
		return 200, leaseCreateOK
	})
	m := newManagerClient(f.srv.URL, "mgr_tok")
	got, err := m.resolveAccess(context.Background(), "vol_1", "main", "team_9")
	if err != nil {
		t.Fatalf("resolveAccess with teamId: %v", err)
	}
	if got.Lease == nil || got.Lease.AccessLeaseID != "pfal_1" {
		t.Fatalf("lease slice = %+v", got.Lease)
	}

	// Without a resolved tenant the requests stay teamId-free (byte-identical
	// to the pre-teamId wire shape).
	f3 := newFakeServer(t)
	f3.on("POST", "/v1/access-leases/create", func(body map[string]any) (int, string) {
		if _, present := body["teamId"]; present {
			return 400, `{"error":{"code":"ACCESS_LEASE_INVALID_REQUEST","message":"unexpected teamId"}}`
		}
		return 200, leaseCreateOK
	})
	m3 := newManagerClient(f3.srv.URL, "mgr_tok")
	if _, err := m3.resolveAccess(context.Background(), "vol_1", "main", ""); err != nil {
		t.Fatalf("resolveAccess without teamId: %v", err)
	}
}

// TestAccessLeaseCreateRetriesSameOperationID pins the replay contract: an
// AMBIGUOUS create failure (5xx/transport) retries with the SAME operationId
// so the manager's receipts can dedupe, while success (or a definitive 4xx)
// ends the logical attempt and the next one mints a fresh id.
func TestAccessLeaseCreateRetriesSameOperationID(t *testing.T) {
	f := newFakeServer(t)
	calls := 0
	var opIDs []string
	f.on("POST", "/v1/access-leases/create", func(body map[string]any) (int, string) {
		calls++
		op, _ := body["operationId"].(string)
		opIDs = append(opIDs, op)
		if calls == 1 {
			return 503, `{"error":"store unavailable"}`
		}
		return 200, leaseCreateOK
	})
	m := newManagerClient(f.srv.URL, "mgr_tok")

	if _, err := m.resolveAccess(context.Background(), "vol_1", "main", ""); err == nil {
		t.Fatal("first attempt must surface the 503")
	}
	got, err := m.resolveAccess(context.Background(), "vol_1", "main", "")
	if err != nil || got.Lease == nil {
		t.Fatalf("retry: %v %+v", err, got)
	}
	if len(opIDs) != 2 || opIDs[0] == "" || opIDs[0] != opIDs[1] {
		t.Fatalf("ambiguous failure must retry the SAME operationId: %v", opIDs)
	}

	// After success the logical attempt is complete: a new mount attempt
	// must mint a fresh operationId.
	if _, err := m.resolveAccess(context.Background(), "vol_1", "main", ""); err != nil {
		t.Fatalf("third attempt: %v", err)
	}
	if len(opIDs) != 3 || opIDs[2] == opIDs[1] {
		t.Fatalf("a completed attempt must not reuse its operationId: %v", opIDs)
	}
}

// TestAccessLeaseRenewAndRelease pins the renew wire shape (fresh operationId
// per renewal, expectedControlSeq = last observed controlSeq, token rotation
// adopted) and the release call.
func TestAccessLeaseRenewAndRelease(t *testing.T) {
	f := newFakeServer(t)
	var renewBodies []map[string]any
	f.on("POST", "/v1/access-leases/renew", func(body map[string]any) (int, string) {
		renewBodies = append(renewBodies, body)
		return 200, `{
		  "lease": {"accessLeaseId":"pfal_1","controlSeq":"8","expiresAt":1700001200000,"state":"active"},
		  "accessToken": "lease_tok_rotated",
		  "serverTimeMs": 1700000600000
		}`
	})
	released := 0
	f.on("POST", "/v1/access-leases/release", func(body map[string]any) (int, string) {
		released++
		if body["accessLeaseId"] != "pfal_1" || body["accessToken"] != "lease_tok_rotated" || body["operationId"] == "" {
			return 400, `{"error":"bad release"}`
		}
		return 200, `{"lease":{"accessLeaseId":"pfal_1","controlSeq":"9","expiresAt":1700001200000,"state":"released"},"receipt":{"operationId":"x","kind":"release","fingerprint":"f","accessLeaseId":"pfal_1","controlSeq":"9","tokenGeneration":"1","completedAtMs":1},"serverTimeMs":1}`
	})

	m := newManagerClient(f.srv.URL, "mgr_tok")
	tokens := &sessionTokenSource{}
	var persisted []leaseState
	k := newLeaseKeeper(m, tokens, leaseState{
		AccessLeaseID: "pfal_1", AccessToken: "lease_tok_1", ExpiresAtMs: 1700000600000, ControlSeq: "7",
	}, func(l leaseState) { persisted = append(persisted, l) })

	k.renewOnce(context.Background())
	if len(renewBodies) != 1 {
		t.Fatalf("renew calls = %d", len(renewBodies))
	}
	body := renewBodies[0]
	if body["accessLeaseId"] != "pfal_1" || body["accessToken"] != "lease_tok_1" || body["expectedControlSeq"] != "7" {
		t.Fatalf("renew body = %+v", body)
	}
	if body["operationId"] == "" {
		t.Fatal("renew must carry an operationId")
	}
	cur := k.snapshot()
	if cur.ControlSeq != "8" || cur.AccessToken != "lease_tok_rotated" || cur.ExpiresAtMs != 1700001200000 {
		t.Fatalf("renewed lease = %+v", cur)
	}
	if tokens.get() != "lease_tok_rotated" {
		t.Fatalf("rotated token must reach the token source: %q", tokens.get())
	}
	if len(persisted) != 1 || persisted[0].ControlSeq != "8" {
		t.Fatalf("renewal must persist the new lease slice: %+v", persisted)
	}

	// A second renewal is a NEW logical operation: fresh operationId, CAS on
	// the controlSeq observed from the first renewal.
	k.renewOnce(context.Background())
	if len(renewBodies) != 2 {
		t.Fatalf("renew calls = %d", len(renewBodies))
	}
	if renewBodies[1]["operationId"] == renewBodies[0]["operationId"] {
		t.Fatal("each renewal mints a fresh operationId")
	}
	if renewBodies[1]["expectedControlSeq"] != "8" {
		t.Fatalf("second renew must CAS on the last controlSeq: %+v", renewBodies[1])
	}

	releaseCtx, cancelRelease := context.WithCancel(context.Background())
	defer cancelRelease()
	if err := k.release(releaseCtx); err != nil {
		t.Fatalf("release: %v", err)
	}
	if released != 1 {
		t.Fatalf("release calls = %d", released)
	}
}

// TestAccessLeaseReleaseRetriesSameOperationID pins clean-unmount cleanup:
// an ambiguous response replays the exact release operation. It never mints
// a second logical release or creates a replacement lease.
func TestAccessLeaseReleaseRetriesSameOperationID(t *testing.T) {
	f := newFakeServer(t)
	var releaseOps []string
	f.on("POST", "/v1/access-leases/release", func(body map[string]any) (int, string) {
		op, _ := body["operationId"].(string)
		releaseOps = append(releaseOps, op)
		if len(releaseOps) == 1 {
			return 503, `{"error":{"code":"ACCESS_LEASE_STORE_UNAVAILABLE","message":"receipt outcome unknown"}}`
		}
		return 200, `{"lease":{"accessLeaseId":"pfal_1","controlSeq":"9","expiresAt":1700001200000,"state":"released"}}`
	})
	m := newManagerClient(f.srv.URL, "mgr_tok")
	k := newLeaseKeeper(m, nil, leaseState{
		AccessLeaseID: "pfal_1", AccessToken: "lease_tok_1", ExpiresAtMs: 1700000600000, ControlSeq: "8",
	}, nil)

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := k.release(ctx); err != nil {
		t.Fatalf("release: %v", err)
	}
	if len(releaseOps) != 2 || releaseOps[0] == "" || releaseOps[0] != releaseOps[1] {
		t.Fatalf("ambiguous release must replay the SAME operationId: %v", releaseOps)
	}
}

func TestAccessLeaseReleasePersistedOperationConvergesTerminalState(t *testing.T) {
	f := newFakeServer(t)
	var operationIDs []string
	f.on("POST", "/v1/access-leases/release", func(body map[string]any) (int, string) {
		operationIDs = append(operationIDs, body["operationId"].(string))
		return 409, `{"error":{"code":"ACCESS_LEASE_RELEASED","message":"already released"}}`
	})
	k := newLeaseKeeper(newManagerClient(f.srv.URL, "mgr_tok"), nil, leaseState{
		AccessLeaseID: "pfal_done", AccessToken: "tok_done", ExpiresAtMs: 1, ControlSeq: "9",
	}, nil)
	const persistedOperationID = "11111111-2222-4333-8444-555555555555"
	if err := k.releaseWithOperation(context.Background(), persistedOperationID); err != nil {
		t.Fatalf("terminal released state must converge cleanup: %v", err)
	}
	if len(operationIDs) != 1 || operationIDs[0] != persistedOperationID {
		t.Fatalf("release operations = %v", operationIDs)
	}
}

// TestLeaseKeeperFailsClosedOnEpochSuperseded pins the manager-restart path:
// ACCESS_LEASE_EPOCH_SUPERSEDED ships as a 503, which the ambiguity rule
// alone would classify as "retry the same renew" — but the typed code means
// this lease can NEVER renew again (its epoch is gone), so the keeper stops
// without creating a replacement.
func TestLeaseKeeperFailsClosedOnEpochSuperseded(t *testing.T) {
	f := newFakeServer(t)
	renews := 0
	f.on("POST", "/v1/access-leases/renew", func(map[string]any) (int, string) {
		renews++
		return 503, `{"error":{"code":"ACCESS_LEASE_EPOCH_SUPERSEDED","message":"Manager epoch 4 has been superseded; reacquire against the new manager."}}`
	})
	m := newManagerClient(f.srv.URL, "mgr_tok")
	tokens := &sessionTokenSource{}
	k := newLeaseKeeper(m, tokens, leaseState{
		AccessLeaseID: "pfal_epoch4", AccessToken: "tok_epoch4", ExpiresAtMs: 1700000600000, ControlSeq: "7",
	}, nil)

	k.renewOnce(context.Background())
	cur := k.snapshot()
	if cur.AccessLeaseID != "pfal_epoch4" || cur.AccessToken != "tok_epoch4" {
		t.Fatalf("terminal refusal must preserve the original lease, got %+v", cur)
	}
	if renews != 1 {
		t.Fatalf("renew calls = %d — the dead lease must not be blindly re-renewed", renews)
	}
	if tokens.get() != "" {
		t.Fatalf("terminal refusal must not install a replacement token: %q", tokens.get())
	}
	if k.pendingRenew != "" {
		t.Fatal("a definitive refusal must clear the retained renew operationId")
	}
	if !k.terminal {
		t.Fatal("a definitive refusal must stop the keeper")
	}
	k.renewOnce(context.Background())
	if renews != 1 {
		t.Fatalf("terminal keeper retried after stop: %d renewals", renews)
	}
}

// TestLeaseKeeperUnknownLeaseIsTerminal: after a restart the new epoch has
// never projected the old lease, so renew answers 404 ACCESS_LEASE_NOT_FOUND
// — terminal, never a create or blind renew retry.
func TestLeaseKeeperUnknownLeaseIsTerminal(t *testing.T) {
	f := newFakeServer(t)
	f.on("POST", "/v1/access-leases/renew", func(map[string]any) (int, string) {
		return 404, `{"error":{"code":"ACCESS_LEASE_NOT_FOUND","message":"Unknown access lease pfal_old (production lease state is scoped to the current manager epoch)."}}`
	})
	m := newManagerClient(f.srv.URL, "mgr_tok")
	k := newLeaseKeeper(m, nil, leaseState{
		AccessLeaseID: "pfal_old", AccessToken: "tok_old", ExpiresAtMs: 1, ControlSeq: "3",
	}, nil)
	k.renewOnce(context.Background())
	if cur := k.snapshot(); cur.AccessLeaseID != "pfal_old" || !k.terminal {
		t.Fatalf("unknown-lease refusal must stop original lease: %+v terminal=%v", cur, k.terminal)
	}
}

// TestLeaseKeeperPlain503StaysAmbiguous pins the counterpart: a 503 WITHOUT a
// typed terminal code (a store hiccup) really is ambiguous — the keeper keeps
// the lease, retains the operationId, and does NOT mint a replacement lease.
func TestLeaseKeeperPlain503StaysAmbiguous(t *testing.T) {
	f := newFakeServer(t)
	var renewOps []string
	f.on("POST", "/v1/access-leases/renew", func(body map[string]any) (int, string) {
		op, _ := body["operationId"].(string)
		renewOps = append(renewOps, op)
		return 503, `{"error":{"code":"ACCESS_LEASE_STORE_UNAVAILABLE","message":"the control store refused the durable transition"}}`
	})
	created := 0
	f.on("POST", "/v1/access-leases/create", func(map[string]any) (int, string) {
		created++
		return 200, leaseCreateOK
	})
	m := newManagerClient(f.srv.URL, "mgr_tok")
	k := newLeaseKeeper(m, nil, leaseState{
		AccessLeaseID: "pfal_keep", AccessToken: "tok_keep", ExpiresAtMs: 1700000600000, ControlSeq: "7",
	}, nil)

	k.renewOnce(context.Background())
	k.renewOnce(context.Background())
	if created != 0 {
		t.Fatalf("an ambiguous failure must not mint a replacement lease (created %d)", created)
	}
	if cur := k.snapshot(); cur.AccessLeaseID != "pfal_keep" {
		t.Fatalf("lease must be retained across ambiguous failures: %+v", cur)
	}
	if len(renewOps) != 2 || renewOps[0] == "" || renewOps[0] != renewOps[1] {
		t.Fatalf("ambiguous renew failures must replay the SAME operationId: %v", renewOps)
	}
}

// TestAccessLeaseRenewFailureStopsOriginalLease pins fail-closed behavior: a
// definitive expiry never creates or adopts a replacement lease.
func TestAccessLeaseRenewFailureStopsOriginalLease(t *testing.T) {
	f := newFakeServer(t)
	f.on("POST", "/v1/access-leases/renew", func(map[string]any) (int, string) {
		return 410, `{"error":{"code":"ACCESS_LEASE_EXPIRED","message":"lease expired"}}`
	})
	m := newManagerClient(f.srv.URL, "mgr_tok")
	tokens := &sessionTokenSource{}
	k := newLeaseKeeper(m, tokens, leaseState{
		AccessLeaseID: "pfal_1", AccessToken: "dead_tok", ExpiresAtMs: 1, ControlSeq: "7",
	}, nil)

	k.renewOnce(context.Background())
	cur := k.snapshot()
	if cur.AccessLeaseID != "pfal_1" || cur.AccessToken != "dead_tok" || !k.terminal {
		t.Fatalf("keeper must stop the original lease: %+v terminal=%v", cur, k.terminal)
	}
	if tokens.get() != "" {
		t.Fatalf("replacement token must never be installed: %q", tokens.get())
	}
}
