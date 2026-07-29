package histworker

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/steerlabs/portablefs/vcs/internal/histstore"
)

func envLookup(values map[string]string) func(string) (string, bool) {
	return func(name string) (string, bool) {
		value, ok := values[name]
		return value, ok
	}
}

func TestFromEnvBuildsValidatedRedactedConfig(t *testing.T) {
	root := t.TempDir()
	stores, err := json.Marshal([]StoreConfig{{
		FailureDomain: "dom-a", Kind: "fs", RootDir: root,
	}})
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := FromEnv(envLookup(map[string]string{
		"PFH_WORKER_DATABASE_URL":             "postgres://worker:super-secret@db.internal/pfs",
		"PFH_WORKER_ID":                       "history-01",
		"PFH_WORKER_POLICY_EPOCH":             "7",
		"PFH_WORKER_STORES_JSON":              string(stores),
		"PFH_WORKER_MIN_FAILURE_DOMAINS":      "1",
		"PFH_WORKER_DB_MAX_CONNS":             "12",
		"PFH_WORKER_LEASE_TTL_MS":             "90000",
		"PFH_WORKER_HEARTBEAT_MS":             "20000",
		"PFH_WORKER_MAX_CUT_ATTEMPTS":         "20",
		"PFH_WORKER_TEMP_SWEEP_AGE_MS":        "7200000",
		"PFH_WORKER_LISTEN_ADDR":              "127.0.0.1:0",
		"PFH_WORKER_MAX_CACHE_BYTES":          "16777216",
		"PFH_WORKER_MAX_PENDING_UPLOAD_BYTES": "16777216",
	}))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.ExpectedPolicyEpoch != 7 || cfg.DatabaseMaxConns != 12 || cfg.LeaseTTL != 90*time.Second {
		t.Fatalf("unexpected config: %+v", cfg)
	}
	if cfg.MaxCutAttempts != 20 {
		t.Fatalf("max cut attempts: %+v", cfg.MaxCutAttempts)
	}
	if cfg.MinFailureDomains != 1 || cfg.Production {
		t.Fatalf("replication floor: %+v", cfg)
	}
	raw, err := json.Marshal(cfg.Redacted())
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(raw), "super-secret") || strings.Contains(string(raw), cfg.DSN) {
		t.Fatalf("redacted config leaked the DSN: %s", raw)
	}
}

func TestFromEnvFailsClosedBeforeConnections(t *testing.T) {
	base := map[string]string{
		"PFH_WORKER_DATABASE_URL":        "postgres://worker:secret@localhost/pfs",
		"PFH_WORKER_ID":                  "history-01",
		"PFH_WORKER_POLICY_EPOCH":        "1",
		"PFH_WORKER_STORES_JSON":         `[{"failureDomain":"dom-a","kind":"fs","rootDir":"/tmp"}]`,
		"PFH_WORKER_MIN_FAILURE_DOMAINS": "1",
	}
	for name, value := range map[string]string{
		"PFH_WORKER_POLICY_EPOCH":        "1.5",
		"PFH_WORKER_DB_MAX_CONNS":        "65",
		"PFH_WORKER_HEARTBEAT_MS":        "60000",
		"PFH_WORKER_LISTEN_ADDR":         "not-an-address",
		"PFH_WORKER_TEMP_SWEEP_AGE_MS":   "1000",
		"PFH_WORKER_MIN_FAILURE_DOMAINS": "9",
		"PFH_WORKER_MAX_CUT_ATTEMPTS":    "2",
	} {
		t.Run(name, func(t *testing.T) {
			values := make(map[string]string, len(base)+1)
			for key, item := range base {
				values[key] = item
			}
			values[name] = value
			if _, err := FromEnv(envLookup(values)); err == nil {
				t.Fatalf("%s=%q was accepted", name, value)
			}
		})
	}
}

func TestFromEnvDerivesHeartbeatFromConfiguredLease(t *testing.T) {
	cfg, err := FromEnv(envLookup(map[string]string{
		"PFH_WORKER_DATABASE_URL":        "postgres://worker:secret@localhost/pfs",
		"PFH_WORKER_ID":                  "history-01",
		"PFH_WORKER_POLICY_EPOCH":        "1",
		"PFH_WORKER_STORES_JSON":         `[{"failureDomain":"dom-a","kind":"fs","rootDir":"/tmp"}]`,
		"PFH_WORKER_MIN_FAILURE_DOMAINS": "1",
		"PFH_WORKER_LEASE_TTL_MS":        "5000",
	}))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.HeartbeatInterval != 1250*time.Millisecond {
		t.Fatalf("heartbeat=%v, want lease/4", cfg.HeartbeatInterval)
	}
}

// TestReplicationFloor covers the domain-count knob: the default floor of 2
// keeps requiring two independent failure domains, an explicit floor of 1
// admits single-domain self-host deployments, and production mode
// (VCS_PRODUCTION=1 semantics) refuses any floor below 2.
func TestReplicationFloor(t *testing.T) {
	makeConfig := func(domains int, floor int, production bool) Config {
		var stores []StoreConfig
		for i := 0; i < domains; i++ {
			stores = append(stores, StoreConfig{
				FailureDomain: "dom-" + strconv.Itoa(i), Kind: "fs",
				RootDir: "/tmp/history-" + strconv.Itoa(i),
			})
		}
		return Config{
			DSN: "postgres://worker:secret@localhost/pfs", WorkerID: "worker",
			ExpectedPolicyEpoch: 1, Stores: stores,
			MinFailureDomains: floor, Production: production,
		}.withDefaults()
	}
	cases := []struct {
		name    string
		domains int
		floor   int // 0 = defaulted
		prod    bool
		wantErr string
	}{
		{"default floor requires two domains", 1, 0, false, "below the replication floor"},
		{"default floor satisfied by two domains", 2, 0, false, ""},
		{"explicit floor of one admits single-domain", 1, 1, false, ""},
		{"production refuses a floor below two", 2, 1, true, "production requires a replication floor"},
		{"production with the default floor", 2, 0, true, ""},
		{"floor above the policy bound", 9, 9, false, "outside 1..8"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := makeConfig(tc.domains, tc.floor, tc.prod).Validate()
			if tc.wantErr == "" {
				if err != nil {
					t.Fatalf("unexpected: %v", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.wantErr) {
				t.Fatalf("got %v, want %q", err, tc.wantErr)
			}
		})
	}

	// The same floor gates policy admission: a policy naming one domain is
	// refused (typed operator work) by a floor-2 deployment and admitted by
	// an explicit floor-1 deployment.
	stores, err := NewDomainStores(staticStore{domain: "dom-0"})
	if err != nil {
		t.Fatal(err)
	}
	policy := ReplicationPolicy{Version: "1", PolicyEpoch: "1", RequiredFailureDomains: []string{"dom-0"}}
	if err := stores.RequireAll(policy, 1, 2); !errors.Is(err, ErrPolicyMismatch) {
		t.Fatalf("floor-2 admission of a one-domain policy: %v", err)
	}
	if err := stores.RequireAll(policy, 1, 1); err != nil {
		t.Fatalf("floor-1 admission of a one-domain policy: %v", err)
	}
}

// staticStore is a minimal histstore.Store for admission tests (never used
// for I/O here).
type staticStore struct{ domain string }

func (s staticStore) Domain() string { return s.domain }
func (s staticStore) ExactKey(id histstore.ObjectID) (string, error) {
	return id.Key()
}
func (s staticStore) Put(context.Context, string, int64, string, io.Reader) error { return nil }
func (s staticStore) Get(context.Context, string) (io.ReadCloser, int64, error) {
	return nil, 0, histstore.ErrNotFound
}
func (s staticStore) Head(context.Context, string) (int64, error) { return 0, histstore.ErrNotFound }
func (s staticStore) Delete(context.Context, string) error        { return nil }

func TestDefaultsUseFullBoundedUploadConcurrency(t *testing.T) {
	cfg := Config{}.withDefaults()
	if cfg.UploadConcurrency != 32 {
		t.Fatalf("upload concurrency = %d, want the validated maximum 32", cfg.UploadConcurrency)
	}
}

func TestStoreConfigRejectsAliasesAndUnknownFields(t *testing.T) {
	base := Config{
		DSN: "postgres://worker:secret@localhost/pfs", WorkerID: "worker",
		ExpectedPolicyEpoch: 1,
		Stores: []StoreConfig{
			{FailureDomain: "a", Kind: "fs", RootDir: "/tmp/history"},
			{FailureDomain: "b", Kind: "fs", RootDir: "/tmp/history/../history"},
		},
	}.withDefaults()
	if err := base.Validate(); err == nil || !strings.Contains(err.Error(), "same filesystem target") {
		t.Fatalf("duplicate physical target: %v", err)
	}
	if _, err := ParseStoresJSON(
		`[{"failureDomain":"a","kind":"fs","rootDir":"/tmp","typo":true}]`,
	); err == nil {
		t.Fatal("unknown store field was accepted")
	}
	if _, err := ParseLegacyStoreJSON(
		`{"kind":"fs","rootDir":"/tmp"} {"kind":"fs","rootDir":"/other"}`,
	); err == nil {
		t.Fatal("multiple legacy-store JSON values were accepted")
	}
}
