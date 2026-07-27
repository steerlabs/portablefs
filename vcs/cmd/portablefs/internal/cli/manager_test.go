package cli

import (
	"context"
	"strings"
	"testing"
)

func TestMountSessionCanonicalVolumeScopedRoute(t *testing.T) {
	f := newFakeServer(t) // /v1/access-leases/create unset => 404 => legacy ladder
	f.on("POST", "/v1/volumes/vol_1/mount-sessions", func(body map[string]any) (int, string) {
		if body["volumeId"] != "vol_1" || body["branch"] != "main" {
			return 400, `{"error":"volumeId and branch are required."}`
		}
		return 200, `{"mountSession":{"endpoint":{"authorityUrl":"vcs.example.com:2050","host":"vcs.example.com","port":2050,"nfsPort":2049},"token":"sess_tok","expiresAtMs":1700000000000,"authorityInstanceId":"pfai_1"}}`
	})
	m := newManagerClient(f.srv.URL, "mgr_tok")
	got, err := m.mountSession(context.Background(), "vol_1", "main", "")
	if err != nil {
		t.Fatalf("mountSession: %v", err)
	}
	if got.AuthorityURL != "vcs.example.com:2050" || got.Token != "sess_tok" || got.Port != 2050 || got.NFSPort != 2049 {
		t.Fatalf("session = %+v", got)
	}
	if got.ExpiresAtMs != 1700000000000 || got.AuthorityInstanceID != "pfai_1" {
		t.Fatalf("session metadata = %+v", got)
	}
	if got.Lease != nil {
		t.Fatalf("a non-lease route must not fabricate a lease: %+v", got.Lease)
	}
	var paths []string
	for _, r := range f.recorded() {
		paths = append(paths, r.Path)
	}
	want := "/v1/access-leases/create,/v1/volumes/vol_1/mount-sessions"
	if strings.Join(paths, ",") != want {
		t.Fatalf("the volume-scoped route must not fall further when it succeeds: %v", paths)
	}
}

// TestMountSessionFlatAliasRoute pins the middle rung of the ladder: a manager
// that serves only the flat /v1/mount-sessions alias (404 on the volume-scoped
// form) still resolves in two requests without touching the legacy pair.
func TestMountSessionFlatAliasRoute(t *testing.T) {
	f := newFakeServer(t)
	f.on("POST", "/v1/mount-sessions", func(body map[string]any) (int, string) {
		if body["volumeId"] != "vol_1" || body["branch"] != "main" {
			return 400, `{"error":"volumeId and branch are required."}`
		}
		return 200, `{"mountSession":{"endpoint":{"authorityUrl":"vcs.example.com:2050","host":"vcs.example.com","port":2050},"token":"sess_tok"}}`
	})
	m := newManagerClient(f.srv.URL, "mgr_tok")
	got, err := m.mountSession(context.Background(), "vol_1", "main", "")
	if err != nil {
		t.Fatalf("mountSession: %v", err)
	}
	if got.AuthorityURL != "vcs.example.com:2050" || got.Token != "sess_tok" {
		t.Fatalf("session = %+v", got)
	}
	var paths []string
	for _, r := range f.recorded() {
		paths = append(paths, r.Path)
	}
	want := "/v1/access-leases/create,/v1/volumes/vol_1/mount-sessions,/v1/mount-sessions"
	if strings.Join(paths, ",") != want {
		t.Fatalf("call sequence = %v", paths)
	}
}

// TestMountSessionFallsBackToEnsureSession pins the compatibility path: a
// manager without /v1/mount-sessions (404) is driven through
// /v1/authorities/ensure + /v1/authorities/session and yields the same info.
func TestMountSessionFallsBackToEnsureSession(t *testing.T) {
	f := newFakeServer(t) // /v1/mount-sessions unset => 404
	f.on("POST", "/v1/authorities/ensure", func(body map[string]any) (int, string) {
		if body["volumeId"] != "vol_1" || body["branch"] != "dev" {
			return 400, `{"error":"volumeId and branch are required."}`
		}
		return 200, `{"authority":{"provider":"portablefs-managed","authorityUrl":"router.example.com:2050","host":"router.example.com","port":2050,"authorityInstanceId":"pfai_7"}}`
	})
	f.on("POST", "/v1/authorities/session", func(map[string]any) (int, string) {
		return 200, `{"authority":{"provider":"portablefs-managed","authorityUrl":"router.example.com:2050","host":"router.example.com","port":2050,"authorityInstanceId":"pfai_7","authorityAuthToken":"data_tok","authorityExpiresAt":1700000000000}}`
	})
	m := newManagerClient(f.srv.URL, "mgr_tok")
	got, err := m.mountSession(context.Background(), "vol_1", "dev", "")
	if err != nil {
		t.Fatalf("mountSession fallback: %v", err)
	}
	if got.AuthorityURL != "router.example.com:2050" || got.Token != "data_tok" || got.AuthorityInstanceID != "pfai_7" {
		t.Fatalf("fallback session = %+v", got)
	}
	var paths []string
	for _, r := range f.recorded() {
		paths = append(paths, r.Path)
	}
	want := "/v1/access-leases/create,/v1/volumes/vol_1/mount-sessions,/v1/mount-sessions,/v1/authorities/ensure,/v1/authorities/session"
	if strings.Join(paths, ",") != want {
		t.Fatalf("call sequence = %v", paths)
	}
}

func TestMountSessionErrorsAreActionable(t *testing.T) {
	f := newFakeServer(t)
	f.on("POST", "/v1/mount-sessions", func(map[string]any) (int, string) {
		return 401, `{"error":"Unauthorized."}`
	})
	m := newManagerClient(f.srv.URL, "wrong")
	_, err := m.mountSession(context.Background(), "vol_1", "main", "")
	if err == nil || !strings.Contains(err.Error(), "vol_1@main") {
		t.Fatalf("error must identify the volume@branch: %v", err)
	}
}

const leaseCreateOK = `{
  "authority": {"authorityUrl":"vcs.example.com:2050","host":"vcs.example.com","port":2050,"nfsPort":2049,"authorityInstanceId":"pfai_9"},
  "lease": {"accessLeaseId":"pfal_1","controlSeq":"7","expiresAt":1700000600000,"state":"active"},
  "accessToken": "lease_tok_1",
  "serverTimeMs": 1700000000000
}`

// TestMountSessionPrefersAccessLeases pins the canonical transport: a manager
// serving POST /v1/access-leases/create resolves in ONE request, the access
// token is the data-plane credential, and the lease slice (id, token, expiry,
// controlSeq) is carried for the renewal loop.
func TestMountSessionPrefersAccessLeases(t *testing.T) {
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
	got, err := m.mountSession(context.Background(), "vol_1", "main", "")
	if err != nil {
		t.Fatalf("mountSession: %v", err)
	}
	if got.AuthorityURL != "vcs.example.com:2050" || got.Token != "lease_tok_1" || got.NFSPort != 2049 || got.AuthorityInstanceID != "pfai_9" {
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

// TestMountSessionForwardsTeamID pins the tenant namespace: when the CLI
// knows the volume's tenant id it rides as teamId on the lease route AND on
// the mount-session fallback rungs (journal-native production managers
// require it; environment managers ignore it).
func TestMountSessionForwardsTeamID(t *testing.T) {
	f := newFakeServer(t)
	f.on("POST", "/v1/access-leases/create", func(body map[string]any) (int, string) {
		if body["teamId"] != "team_9" {
			return 400, `{"error":{"code":"ACCESS_LEASE_INVALID_REQUEST","message":"teamId is required by this manager."}}`
		}
		return 200, leaseCreateOK
	})
	m := newManagerClient(f.srv.URL, "mgr_tok")
	got, err := m.mountSession(context.Background(), "vol_1", "main", "team_9")
	if err != nil {
		t.Fatalf("mountSession with teamId: %v", err)
	}
	if got.Lease == nil || got.Lease.AccessLeaseID != "pfal_1" {
		t.Fatalf("lease slice = %+v", got.Lease)
	}

	// The fallback rungs carry the same teamId.
	f2 := newFakeServer(t) // lease route unset => 404 => mount-session ladder
	f2.on("POST", "/v1/volumes/vol_1/mount-sessions", func(body map[string]any) (int, string) {
		if body["teamId"] != "team_9" {
			return 400, `{"error":"teamId missing on the mount-session rung"}`
		}
		return 200, `{"mountSession":{"endpoint":{"authorityUrl":"vcs.example.com:2050","host":"vcs.example.com","port":2050},"token":"sess_tok"}}`
	})
	m2 := newManagerClient(f2.srv.URL, "mgr_tok")
	if _, err := m2.mountSession(context.Background(), "vol_1", "main", "team_9"); err != nil {
		t.Fatalf("mount-session rung with teamId: %v", err)
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
	if _, err := m3.mountSession(context.Background(), "vol_1", "main", ""); err != nil {
		t.Fatalf("mountSession without teamId: %v", err)
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

	if _, err := m.mountSession(context.Background(), "vol_1", "main", ""); err == nil {
		t.Fatal("first attempt must surface the 503")
	}
	got, err := m.mountSession(context.Background(), "vol_1", "main", "")
	if err != nil || got.Lease == nil {
		t.Fatalf("retry: %v %+v", err, got)
	}
	if len(opIDs) != 2 || opIDs[0] == "" || opIDs[0] != opIDs[1] {
		t.Fatalf("ambiguous failure must retry the SAME operationId: %v", opIDs)
	}

	// After success the logical attempt is complete: a new mount attempt
	// must mint a fresh operationId.
	if _, err := m.mountSession(context.Background(), "vol_1", "main", ""); err != nil {
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
	k := newLeaseKeeper(m, "vol_1", "main", "", tokens, leaseState{
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

	k.release()
	if released != 1 {
		t.Fatalf("release calls = %d", released)
	}
}

// TestLeaseKeeperReacquiresOnEpochSuperseded pins the manager-restart path:
// ACCESS_LEASE_EPOCH_SUPERSEDED ships as a 503, which the ambiguity rule
// alone would classify as "retry the same renew" — but the typed code means
// this lease can NEVER renew again (its epoch is gone), so the keeper must
// re-acquire a fresh lease through the mountSession ladder instead of
// renewing a dead one forever.
func TestLeaseKeeperReacquiresOnEpochSuperseded(t *testing.T) {
	f := newFakeServer(t)
	renews := 0
	f.on("POST", "/v1/access-leases/renew", func(map[string]any) (int, string) {
		renews++
		return 503, `{"error":{"code":"ACCESS_LEASE_EPOCH_SUPERSEDED","message":"Manager epoch 4 has been superseded; reacquire against the new manager."}}`
	})
	f.on("POST", "/v1/access-leases/create", func(map[string]any) (int, string) {
		return 200, `{
		  "authority": {"authorityUrl":"vcs.example.com:2050","host":"vcs.example.com","port":2050},
		  "lease": {"accessLeaseId":"pfal_epoch5","controlSeq":"1","expiresAt":1700009999000,"state":"active"},
		  "accessToken": "lease_tok_epoch5",
		  "serverTimeMs": 1700000000000
		}`
	})
	m := newManagerClient(f.srv.URL, "mgr_tok")
	tokens := &sessionTokenSource{}
	k := newLeaseKeeper(m, "vol_1", "main", "", tokens, leaseState{
		AccessLeaseID: "pfal_epoch4", AccessToken: "tok_epoch4", ExpiresAtMs: 1700000600000, ControlSeq: "7",
	}, nil)

	k.renewOnce(context.Background())
	cur := k.snapshot()
	if cur.AccessLeaseID != "pfal_epoch5" || cur.AccessToken != "lease_tok_epoch5" {
		t.Fatalf("keeper must re-acquire on a typed epoch refusal, got %+v", cur)
	}
	if renews != 1 {
		t.Fatalf("renew calls = %d — the dead lease must not be blindly re-renewed", renews)
	}
	if tokens.get() != "lease_tok_epoch5" {
		t.Fatalf("re-acquired token must reach the token source: %q", tokens.get())
	}
	if k.pendingRenew != "" {
		t.Fatal("a definitive refusal must clear the retained renew operationId")
	}
}

// TestLeaseKeeperUnknownLeaseReacquires: after a restart the new epoch has
// never projected the old lease, so renew answers 404 ACCESS_LEASE_NOT_FOUND
// — also a re-acquire, never a blind renew retry.
func TestLeaseKeeperUnknownLeaseReacquires(t *testing.T) {
	f := newFakeServer(t)
	f.on("POST", "/v1/access-leases/renew", func(map[string]any) (int, string) {
		return 404, `{"error":{"code":"ACCESS_LEASE_NOT_FOUND","message":"Unknown access lease pfal_old (production lease state is scoped to the current manager epoch)."}}`
	})
	f.on("POST", "/v1/access-leases/create", func(map[string]any) (int, string) {
		return 200, leaseCreateOK
	})
	m := newManagerClient(f.srv.URL, "mgr_tok")
	k := newLeaseKeeper(m, "vol_1", "main", "", nil, leaseState{
		AccessLeaseID: "pfal_old", AccessToken: "tok_old", ExpiresAtMs: 1, ControlSeq: "3",
	}, nil)
	k.renewOnce(context.Background())
	if cur := k.snapshot(); cur.AccessLeaseID != "pfal_1" {
		t.Fatalf("unknown-lease refusal must re-acquire: %+v", cur)
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
	k := newLeaseKeeper(m, "vol_1", "main", "", nil, leaseState{
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

// TestAccessLeaseRenewFailureMintsFreshLease pins recovery: a definitive
// renew refusal (the lease expired server-side) falls back to creating a
// fresh lease through the mountSession ladder, and the mount keeps running.
func TestAccessLeaseRenewFailureMintsFreshLease(t *testing.T) {
	f := newFakeServer(t)
	f.on("POST", "/v1/access-leases/renew", func(map[string]any) (int, string) {
		return 410, `{"error":{"code":"ACCESS_LEASE_EXPIRED","message":"lease expired"}}`
	})
	f.on("POST", "/v1/access-leases/create", func(map[string]any) (int, string) {
		return 200, `{
		  "authority": {"authorityUrl":"vcs.example.com:2050","host":"vcs.example.com","port":2050},
		  "lease": {"accessLeaseId":"pfal_2","controlSeq":"1","expiresAt":1700009999000,"state":"active"},
		  "accessToken": "lease_tok_2",
		  "serverTimeMs": 1700000000000
		}`
	})
	m := newManagerClient(f.srv.URL, "mgr_tok")
	tokens := &sessionTokenSource{}
	k := newLeaseKeeper(m, "vol_1", "main", "", tokens, leaseState{
		AccessLeaseID: "pfal_1", AccessToken: "dead_tok", ExpiresAtMs: 1, ControlSeq: "7",
	}, nil)

	k.renewOnce(context.Background())
	cur := k.snapshot()
	if cur.AccessLeaseID != "pfal_2" || cur.AccessToken != "lease_tok_2" {
		t.Fatalf("keeper must adopt the replacement lease: %+v", cur)
	}
	if tokens.get() != "lease_tok_2" {
		t.Fatalf("replacement token must reach the token source: %q", tokens.get())
	}
}
