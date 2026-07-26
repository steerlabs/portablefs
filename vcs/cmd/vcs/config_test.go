package main

import (
	"strings"
	"testing"
)

const testHAPolicyJSON = `{"v":1,"expectedSystemIdentifier":"7300000000000000001","expectedDatabase":"portablefs","minSynchronousCommit":"on","minSyncStandbys":1,"standbyFailureDomains":{"standby_a":"zone-a","standby_b":"zone-b"},"minDistinctFailureDomains":1}`

// baseProductionConfig is a valid MANAGED production config: remote journal
// only, no local WAL/opstate/cache, exact manager/runtime binding, both
// manager pipes, structured HA policy, and NO operator listener addresses
// (the child binds 127.0.0.1:0 itself and reports through the bootstrap
// pipe). Tests must pair it with setManagedProductionEnv.
func baseProductionConfig() config {
	return config{
		apiURL:                     "https://volume-api.example",
		volumeID:                   "vol_test",
		branch:                     "main",
		production:                 true,
		writable:                   true,
		journalDSN:                 "postgres://authority@db.internal/portablefs",
		tenantID:                   "tenant_test",
		authorityInstanceID:        "authority-instance-1",
		managerEpoch:               "7",
		managerRuntimeID:           "pfmgr_test",
		authorityRuntimeSeq:        "3",
		authorityRuntimeID:         "pfrt_test",
		authorityRuntimeCapability: "pfrtcap_test",
		heartbeatFD:                3,
		bootstrapFD:                4,
		journalHAPolicyJSON:        testHAPolicyJSON,
		walPath:                    "/tmp/implicit.wal", // implicit default, not explicit
	}
}

// setManagedProductionEnv installs the credential env managed production
// requires: the fsproto data plane and lifecycle control are authenticated
// even on loopback.
func setManagedProductionEnv(t *testing.T) {
	t.Helper()
	t.Setenv("VCS_AUTH_TOKEN", "data-plane-token")
	t.Setenv("VCS_ADMIN_TOKEN", "admin-token")
}

func TestValidateConfigDevAllowsSingleNodeWritable(t *testing.T) {
	cfg := config{
		apiURL:   "http://localhost:8787",
		volumeID: "vol_dev",
		writable: true,
	}
	if err := validateConfig(cfg); err != nil {
		t.Fatalf("dev single-node writable should be allowed: %v", err)
	}
}

// TestValidateConfigRefusesRemovedPairedEnvs: the process-pair standby mode
// was removed pre-launch. A deployment still exporting one of its settings
// must stop loudly — never silently serve a different role than the operator
// configured.
func TestValidateConfigRefusesRemovedPairedEnvs(t *testing.T) {
	for _, name := range removedPairedEnvs {
		t.Run(name, func(t *testing.T) {
			t.Setenv(name, "1")
			cfg := config{apiURL: "http://localhost:8787", volumeID: "vol_dev", writable: true}
			err := validateConfig(cfg)
			if err == nil || !strings.Contains(err.Error(), name) || !strings.Contains(err.Error(), "removed") {
				t.Fatalf("removed env %s must refuse startup by name, got %v", name, err)
			}
		})
	}
}

func TestValidateConfigProductionRequiresRemoteJournal(t *testing.T) {
	setManagedProductionEnv(t)
	cfg := baseProductionConfig()
	cfg.journalDSN = ""
	cfg.tenantID = ""
	if err := validateConfig(cfg); err == nil || !strings.Contains(err.Error(), "VCS_JOURNAL_DSN") {
		t.Fatalf("managed production without the remote journal should fail, got %v", err)
	}
	if err := validateConfig(baseProductionConfig()); err != nil {
		t.Fatalf("managed production remote config should pass: %v", err)
	}
}

func TestValidateConfigRemoteJournalRequiresTenant(t *testing.T) {
	setManagedProductionEnv(t)
	cfg := baseProductionConfig()
	cfg.tenantID = ""
	if err := validateConfig(cfg); err == nil || !strings.Contains(err.Error(), "VCS_TENANT_ID") {
		t.Fatalf("remote journal without tenant should fail, got %v", err)
	}
}

func TestValidateConfigRemoteJournalRejectsLocalDurability(t *testing.T) {
	setManagedProductionEnv(t)
	cfg := baseProductionConfig()
	cfg.walPathExplicit = true
	if err := validateConfig(cfg); err == nil || !strings.Contains(err.Error(), "VCS_WAL") {
		t.Fatalf("remote journal with a local WAL should fail, got %v", err)
	}

	cfg = baseProductionConfig()
	cfg.cacheDir = "/var/cache/portablefs"
	if err := validateConfig(cfg); err == nil || !strings.Contains(err.Error(), "VCS_CACHE_DIR") {
		t.Fatalf("remote journal with a persistent local cache dir should fail, got %v", err)
	}

	// There is deliberately no codec knob: the pair is a provisioning
	// decision (pfj.branch_provisioning), never configuration.
	t.Setenv("VCS_JOURNAL_CODEC", "pfj3")
	if err := validateConfig(baseProductionConfig()); err == nil || !strings.Contains(err.Error(), "VCS_JOURNAL_CODEC") {
		t.Fatalf("remote journal with a codec knob should fail, got %v", err)
	}
}

func TestValidateConfigRemoteJournalRejectsNFSAndReadOnly(t *testing.T) {
	setManagedProductionEnv(t)
	// The remote-journal authority serves authenticated fsproto ONLY: an
	// explicit NFS address is a config error, not a silently ignored setting.
	cfg := baseProductionConfig()
	cfg.addrExplicit = true
	cfg.addr = "127.0.0.1:2049"
	if err := validateConfig(cfg); err == nil || !strings.Contains(err.Error(), "VCS_ADDR") {
		t.Fatalf("remote journal with an NFS listener should fail, got %v", err)
	}

	// Managed read-only serving does not exist: a journal DSN without a
	// writable primary is an error, never a silent branch-head fallback.
	cfg = baseProductionConfig()
	cfg.production = false
	cfg.writable = false
	if err := validateConfig(cfg); err == nil || !strings.Contains(err.Error(), "writable fenced primary only") {
		t.Fatalf("remote journal without writable should fail, got %v", err)
	}
}

func TestValidateConfigRemoteJournalRequiresManagerBinding(t *testing.T) {
	setManagedProductionEnv(t)
	cfg := baseProductionConfig()
	cfg.managerEpoch = ""
	if err := validateConfig(cfg); err == nil || !strings.Contains(err.Error(), "VCS_MANAGER_EPOCH") {
		t.Fatalf("remote journal without the manager epoch should fail, got %v", err)
	}

	cfg = baseProductionConfig()
	cfg.authorityRuntimeSeq = ""
	if err := validateConfig(cfg); err == nil || !strings.Contains(err.Error(), "VCS_AUTHORITY_RUNTIME_SEQ") {
		t.Fatalf("remote journal without the runtime sequence should fail, got %v", err)
	}

	cfg = baseProductionConfig()
	cfg.authorityRuntimeCapability = ""
	if err := validateConfig(cfg); err == nil || !strings.Contains(err.Error(), "VCS_AUTHORITY_RUNTIME_CAPABILITY") {
		t.Fatalf("remote journal without the runtime capability should fail, got %v", err)
	}
}

func TestValidateConfigRemoteJournalDevModeAllowed(t *testing.T) {
	// A non-production run against a local test database is allowed (that is
	// how integration tests run) but still requires the exact manager binding
	// (every journal transaction is fenced by it in SQL) and still refuses
	// mixed local durability.
	cfg := config{
		apiURL:                     "http://localhost:8787",
		volumeID:                   "vol_dev",
		writable:                   true,
		journalDSN:                 "postgres://authority@127.0.0.1:15432/portablefs",
		tenantID:                   "tenant_dev",
		managerEpoch:               "1",
		managerRuntimeID:           "pfmgr_dev",
		authorityRuntimeSeq:        "1",
		authorityRuntimeID:         "pfrt_dev",
		authorityRuntimeCapability: "pfrtcap_dev",
	}
	if err := validateConfig(cfg); err != nil {
		t.Fatalf("dev remote-journal run should be allowed: %v", err)
	}
	cfg.walPathExplicit = true
	if err := validateConfig(cfg); err == nil || !strings.Contains(err.Error(), "VCS_WAL") {
		t.Fatalf("dev remote-journal run with a local WAL should fail, got %v", err)
	}
}

func TestValidateConfigProductionRejectsOperatorListenerAddresses(t *testing.T) {
	setManagedProductionEnv(t)
	// The managed child binds 127.0.0.1:0 itself and reports the exact
	// addresses on the bootstrap pipe; operator addresses would reintroduce
	// the pre-allocation TOCTOU race the manager used to have.
	cfg := baseProductionConfig()
	cfg.fsAddr = "127.0.0.1:2050"
	if err := validateConfig(cfg); err == nil || !strings.Contains(err.Error(), "VCS_FS_ADDR") {
		t.Fatalf("production with an operator fsproto address should fail, got %v", err)
	}

	cfg = baseProductionConfig()
	cfg.metricsAddr = "127.0.0.1:9100"
	if err := validateConfig(cfg); err == nil || !strings.Contains(err.Error(), "VCS_METRICS_ADDR") {
		t.Fatalf("production with an operator metrics address should fail, got %v", err)
	}
}

func TestValidateConfigProductionRequiresAuthorityInstance(t *testing.T) {
	setManagedProductionEnv(t)
	cfg := baseProductionConfig()
	cfg.authorityInstanceID = ""
	if err := validateConfig(cfg); err == nil || !strings.Contains(err.Error(), "VCS_AUTHORITY_INSTANCE_ID") {
		t.Fatalf("production primary without an authority instance id should fail, got %v", err)
	}
}

func TestValidateConfigProductionRequiresManagerPipes(t *testing.T) {
	setManagedProductionEnv(t)
	cfg := baseProductionConfig()
	cfg.heartbeatFD = 0
	if err := validateConfig(cfg); err == nil || !strings.Contains(err.Error(), "VCS_HEARTBEAT_FD") {
		t.Fatalf("production without the manager lease pipe should fail, got %v", err)
	}

	cfg = baseProductionConfig()
	cfg.bootstrapFD = 0
	if err := validateConfig(cfg); err == nil || !strings.Contains(err.Error(), "VCS_BOOTSTRAP_FD") {
		t.Fatalf("production without the bootstrap pipe should fail, got %v", err)
	}

	cfg = baseProductionConfig()
	cfg.bootstrapFD = cfg.heartbeatFD
	if err := validateConfig(cfg); err == nil || !strings.Contains(err.Error(), "VCS_BOOTSTRAP_FD") {
		t.Fatalf("production with colliding pipe descriptors should fail, got %v", err)
	}
}

func TestValidateConfigProductionRequiresStructuredHAPolicy(t *testing.T) {
	setManagedProductionEnv(t)
	cfg := baseProductionConfig()
	cfg.journalHAPolicyJSON = ""
	if err := validateConfig(cfg); err == nil || !strings.Contains(err.Error(), "VCS_JOURNAL_HA_POLICY_JSON") {
		t.Fatalf("production without a structured HA policy should fail, got %v", err)
	}

	cfg = baseProductionConfig()
	cfg.journalHAPolicyJSON = `{"v":1,"minSynchronousCommit":"eventually","minSyncStandbys":1}`
	if err := validateConfig(cfg); err == nil || !strings.Contains(err.Error(), "VCS_JOURNAL_HA_POLICY_JSON") {
		t.Fatalf("production with an invalid HA policy should fail, got %v", err)
	}

	// The policy must pin identity and attest failure domains; the pin-less
	// shape is rejected by name.
	cfg = baseProductionConfig()
	cfg.journalHAPolicyJSON = `{"v":1,"expectedSystemIdentifier":"7300000000000000001","expectedDatabase":"portablefs","minSynchronousCommit":"on","minSyncStandbys":1}`
	if err := validateConfig(cfg); err == nil || !strings.Contains(err.Error(), "standbyFailureDomains") {
		t.Fatalf("production without attested failure domains should fail, got %v", err)
	}
}

func TestValidateConfigProductionRejectsLegacyWrites(t *testing.T) {
	setManagedProductionEnv(t)
	t.Setenv("VCS_ALLOW_LEGACY_WRITES", "1")
	if err := validateConfig(baseProductionConfig()); err == nil || !strings.Contains(err.Error(), "VCS_ALLOW_LEGACY_WRITES") {
		t.Fatalf("production with legacy (non-exact) writes enabled should fail, got %v", err)
	}
}

func TestValidateConfigProductionRequiresAuthenticationEvenOnLoopback(t *testing.T) {
	t.Setenv("VCS_AUTH_TOKEN", "")
	t.Setenv("VCS_ADMIN_TOKEN", "admin-token")
	if err := validateConfig(baseProductionConfig()); err == nil || !strings.Contains(err.Error(), "VCS_AUTH_TOKEN") {
		t.Fatalf("production without a data-plane token should fail even on loopback, got %v", err)
	}

	t.Setenv("VCS_AUTH_TOKEN", "data-plane-token")
	t.Setenv("VCS_ADMIN_TOKEN", "")
	if err := validateConfig(baseProductionConfig()); err == nil || !strings.Contains(err.Error(), "VCS_ADMIN_TOKEN") {
		t.Fatalf("production without an admin token should fail, got %v", err)
	}
}

// TestDirtyRSSMaxConfig: the dirty-block memory bound defaults to 2 GiB,
// honors an explicit override, and refuses zero/negative/garbage at startup —
// a silent fallback would either disable the OOM guard or wedge every write.
func TestDirtyRSSMaxConfig(t *testing.T) {
	cfg := config{apiURL: "http://localhost:8787", volumeID: "vol_dev", writable: true}
	if err := validateConfig(cfg); err != nil {
		t.Fatalf("unset VCS_DIRTY_RSS_MAX_MB must apply the default: %v", err)
	}
	if got, err := cfg.dirtyRSSMaxBytes(); err != nil || got != int64(defaultDirtyRSSMaxMB)<<20 {
		t.Fatalf("default bound = %d, %v; want %d", got, err, int64(defaultDirtyRSSMaxMB)<<20)
	}

	t.Setenv("VOLUME_API_URL", "http://localhost:8787")
	t.Setenv("VCS_VOLUME_ID", "vol_dev")
	t.Setenv("VCS_DIRTY_RSS_MAX_MB", "512")
	loaded := loadConfig()
	if got, err := loaded.dirtyRSSMaxBytes(); err != nil || got != 512<<20 {
		t.Fatalf("explicit bound = %d, %v; want %d", got, err, int64(512)<<20)
	}

	for _, bad := range []string{"0", "-1", "abc", "2.5"} {
		cfg.dirtyRSSMaxMB = bad
		err := validateConfig(cfg)
		if err == nil || !strings.Contains(err.Error(), "VCS_DIRTY_RSS_MAX_MB") {
			t.Fatalf("VCS_DIRTY_RSS_MAX_MB=%q must refuse startup by name, got %v", bad, err)
		}
	}
}

func TestValidateConfigProductionBoundsSuspendDeadline(t *testing.T) {
	setManagedProductionEnv(t)
	cfg := baseProductionConfig()
	cfg.suspendDeadlineMs = 500
	if err := validateConfig(cfg); err == nil || !strings.Contains(err.Error(), "VCS_SUSPEND_DEADLINE_MS") {
		t.Fatalf("an out-of-bounds suspend deadline should fail, got %v", err)
	}
	cfg.suspendDeadlineMs = 30_000
	if err := validateConfig(cfg); err != nil {
		t.Fatalf("the default suspend deadline should pass: %v", err)
	}
}
