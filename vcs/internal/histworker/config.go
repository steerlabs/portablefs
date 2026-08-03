package histworker

import (
	"encoding/json"
	"fmt"
	"io"
	"net"
	"path"
	"strconv"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"
	"github.com/steerlabs/portablefs/vcs/internal/histstore"
)

// Config is the complete typed configuration of one history worker. Every
// field is bounded and Validate proves DSN shape, worker identity,
// concurrency, lease/heartbeat relations, store definitions, TLS/S3
// endpoint shapes, and failure-domain uniqueness BEFORE anything connects.
// Secrets (DSN, S3 credentials) are never logged; Redacted() is the only
// loggable projection.
type Config struct {
	// DSN is the restricted history-worker PostgreSQL connection string.
	DSN string
	// WorkerID identifies this worker in claims and heartbeats (1..128).
	WorkerID string
	// ExpectedPolicyEpoch is the replication policy epoch this deployment
	// was rolled out for; a cut carrying a different epoch is refused
	// (retried later) instead of being written under the wrong policy.
	ExpectedPolicyEpoch int64
	// DatabaseMaxConns bounds the worker's one pgx pool (1..64).
	DatabaseMaxConns int32
	// Stores declares one exact-key store per failure domain (>= the
	// MinFailureDomains floor, domains unique).
	Stores []StoreConfig
	// MinFailureDomains is the deployment's replication floor: the minimum
	// number of distinct failure domains that must be configured here AND
	// named by the installed replication policy before this worker writes
	// history. Default 2 (every object holds two independently verified
	// copies). A single-domain deployment is a legitimate self-host
	// posture: set the floor to 1 explicitly (PFH_WORKER_MIN_FAILURE_DOMAINS=1)
	// outside production mode. Production keeps requiring 2.
	MinFailureDomains int
	// Production carries VCS_PRODUCTION=1 semantics: fail-closed
	// production validation. A production worker refuses a replication
	// floor below 2.
	Production bool
	// LegacyStore optionally binds a legacy digest-addressed blob store
	// used ONLY as conversion input (recorded keys, never derived).
	LegacyStore *LegacyStoreConfig

	// MaterializeConcurrency bounds cuts materializing in parallel (1..8).
	MaterializeConcurrency int
	// MaxCutAttempts terminal-fails (FailCut) a cut whose claim attempt
	// number has reached this bound instead of settling another retry
	// (3..50, default 12). The database independently dead-letters at 16
	// attempts on claim — the backstop for attempts that die without ever
	// reaching a worker-side settlement.
	MaxCutAttempts int
	// UploadConcurrency bounds parallel object uploads per flush (1..256).
	// Each in-flight upload holds one already-materialized object (bounded in
	// aggregate by MaxPendingUploadBytes) and streams its read-after-write
	// proof, so raising this costs store round trips in flight, not memory.
	// It is the knob that decides whether a cut's upload plane can outrun a
	// sustained writer: one 1 GiB cut publishes ~19k objects, and every one
	// costs a PUT plus a verification per required failure domain.
	UploadConcurrency int
	// ScrubBatch / ScrubConcurrency bound one scrub pass (1..512 / 1..32).
	ScrubBatch       int
	ScrubConcurrency int
	// RepairBatch / RepairConcurrency bound one repair pass (1..128 / 1..16).
	RepairBatch       int
	RepairConcurrency int
	// LeaseTTL is the DB-time claim lease (5s..300s, DB-enforced bounds).
	LeaseTTL time.Duration
	// HeartbeatInterval renews cut leases (must be < LeaseTTL/2).
	HeartbeatInterval time.Duration
	// PollInterval is the idle wait between claim attempts (>= 100ms).
	PollInterval time.Duration
	// OperationTimeout bounds one claim-loop iteration end to end. A timed
	// out materialization settles loudly: the attempt is retried with the
	// timeout recorded (or terminal-failed at MaxCutAttempts), never left
	// to die silently on lease expiry.
	OperationTimeout time.Duration
	// SweepMinAge is the minimum unreferenced age before GC claims an
	// object (DB clamps to [1m..30d]).
	SweepMinAge time.Duration
	// FreshenAge triggers re-verification receipts for closure copies whose
	// last verification is older (keep well under the policy freshness).
	FreshenAge time.Duration
	// ShutdownGrace bounds in-flight work after a stop signal.
	ShutdownGrace time.Duration
	// TempSweepAge is the minimum age of crash-orphaned filesystem-store
	// temporary files eligible for startup cleanup. It must comfortably
	// exceed the longest object-store operation.
	TempSweepAge time.Duration

	// MaxCacheBytes bounds the disposable object LRU (>= 8 MiB).
	MaxCacheBytes int64
	// MaxPendingUploadBytes bounds reducer output buffered before a flush
	// (>= 8 MiB).
	MaxPendingUploadBytes int64
	// MaxLegacyBlobBytes bounds one legacy blob (stored or decompressed).
	MaxLegacyBlobBytes int64

	// ListenAddr serves /healthz, /readyz, /metrics ("" disables).
	ListenAddr string
}

// StoreConfig declares one failure domain's store.
type StoreConfig struct {
	FailureDomain string `json:"failureDomain"`
	Kind          string `json:"kind"` // "fs" | "s3"

	// fs
	RootDir string `json:"rootDir,omitempty"`

	// s3
	Endpoint        string `json:"endpoint,omitempty"`
	Region          string `json:"region,omitempty"`
	Bucket          string `json:"bucket,omitempty"`
	PathStyle       bool   `json:"pathStyle,omitempty"`
	AccessKeyID     string `json:"accessKeyId,omitempty"`
	SecretAccessKey string `json:"secretAccessKey,omitempty"`

	// shared
	Prefix             string `json:"prefix,omitempty"`
	OperationTimeoutMs int64  `json:"operationTimeoutMs,omitempty"`
}

// LegacyStoreConfig binds the legacy digest-addressed blob store.
type LegacyStoreConfig struct {
	Kind string `json:"kind"` // "fs" | "s3"

	// fs: recorded file:// keys must resolve under this root.
	RootDir string `json:"rootDir,omitempty"`

	// s3: recorded relative keys are used verbatim in this bucket.
	Endpoint        string `json:"endpoint,omitempty"`
	Region          string `json:"region,omitempty"`
	Bucket          string `json:"bucket,omitempty"`
	PathStyle       bool   `json:"pathStyle,omitempty"`
	AccessKeyID     string `json:"accessKeyId,omitempty"`
	SecretAccessKey string `json:"secretAccessKey,omitempty"`
}

// withDefaults fills unset optional fields with production defaults.
func (c Config) withDefaults() Config {
	def := func(v *int, d int) {
		if *v == 0 {
			*v = d
		}
	}
	def(&c.MaterializeConcurrency, 1)
	def(&c.MaxCutAttempts, 12)
	def(&c.MinFailureDomains, 2)
	def(&c.UploadConcurrency, 64)
	def(&c.ScrubBatch, 64)
	def(&c.ScrubConcurrency, 8)
	def(&c.RepairBatch, 16)
	def(&c.RepairConcurrency, 4)
	if c.DatabaseMaxConns == 0 {
		c.DatabaseMaxConns = 8
	}
	if c.LeaseTTL == 0 {
		c.LeaseTTL = 60 * time.Second
	}
	if c.HeartbeatInterval == 0 {
		c.HeartbeatInterval = c.LeaseTTL / 4
	}
	if c.PollInterval == 0 {
		c.PollInterval = 5 * time.Second
	}
	if c.OperationTimeout == 0 {
		c.OperationTimeout = 5 * time.Minute
	}
	if c.SweepMinAge == 0 {
		c.SweepMinAge = time.Hour
	}
	if c.FreshenAge == 0 {
		c.FreshenAge = 6 * time.Hour
	}
	if c.ShutdownGrace == 0 {
		c.ShutdownGrace = 20 * time.Second
	}
	if c.TempSweepAge == 0 {
		c.TempSweepAge = 24 * time.Hour
	}
	if c.MaxCacheBytes == 0 {
		c.MaxCacheBytes = 128 << 20
	}
	if c.MaxPendingUploadBytes == 0 {
		c.MaxPendingUploadBytes = 64 << 20
	}
	if c.MaxLegacyBlobBytes == 0 {
		c.MaxLegacyBlobBytes = 128 << 20
	}
	return c
}

// Validate proves the full configuration without connecting anywhere.
func (c Config) Validate() error {
	if strings.TrimSpace(c.DSN) == "" {
		return fmt.Errorf("histworker: DSN is required")
	}
	if _, err := pgxpool.ParseConfig(c.DSN); err != nil {
		return fmt.Errorf("histworker: DSN does not parse (value withheld): %w", redactDSNError(err))
	}
	if n := len(c.WorkerID); n < 1 || n > 128 {
		return fmt.Errorf("histworker: worker id must be 1..128 chars")
	}
	if c.ExpectedPolicyEpoch < 1 {
		return fmt.Errorf("histworker: expected policy epoch must be >= 1")
	}
	if c.DatabaseMaxConns < 1 || c.DatabaseMaxConns > 64 {
		return fmt.Errorf("histworker: database max conns %d outside 1..64", c.DatabaseMaxConns)
	}
	// The floor bound's ceiling (8) matches the pfh policy shape check:
	// a policy names 1..8 distinct failure domains.
	if c.MinFailureDomains < 1 || c.MinFailureDomains > 8 {
		return fmt.Errorf("histworker: min failure domains %d outside 1..8", c.MinFailureDomains)
	}
	if c.Production && c.MinFailureDomains < 2 {
		return fmt.Errorf("histworker: production requires a replication floor of at least 2 failure domains (configured %d)",
			c.MinFailureDomains)
	}
	if len(c.Stores) < c.MinFailureDomains {
		return fmt.Errorf("histworker: %d store failure domains configured, below the replication floor of %d",
			len(c.Stores), c.MinFailureDomains)
	}
	seen := map[string]bool{}
	targets := map[string]string{}
	for i, s := range c.Stores {
		domain := strings.TrimSpace(s.FailureDomain)
		if domain == "" || len(domain) > 128 {
			return fmt.Errorf("histworker: store %d failure domain must be 1..128 chars", i)
		}
		if seen[domain] {
			return fmt.Errorf("histworker: failure domain %q is declared twice", domain)
		}
		seen[domain] = true
		switch s.Kind {
		case "fs":
			if !strings.HasPrefix(s.RootDir, "/") {
				return fmt.Errorf("histworker: store %q rootDir must be absolute", domain)
			}
			target := "fs:" + path.Clean(s.RootDir)
			if prior, exists := targets[target]; exists {
				return fmt.Errorf("histworker: stores %q and %q name the same filesystem target", prior, domain)
			}
			targets[target] = domain
		case "s3":
			if _, err := histstore.NewS3Store(histstore.S3Config{
				Domain: domain, Endpoint: s.Endpoint, Region: s.Region,
				Bucket: s.Bucket, Prefix: s.Prefix, PathStyle: s.PathStyle,
				AccessKeyID: s.AccessKeyID, SecretAccessKey: s.SecretAccessKey,
			}); err != nil {
				return fmt.Errorf("histworker: store %q: %w", domain, err)
			}
			target := "s3:" + strings.TrimRight(s.Endpoint, "/") + "/" + s.Bucket
			if prior, exists := targets[target]; exists {
				return fmt.Errorf("histworker: stores %q and %q name the same S3 bucket", prior, domain)
			}
			targets[target] = domain
		default:
			return fmt.Errorf("histworker: store %q kind %q is unknown", domain, s.Kind)
		}
		if s.Prefix != "" {
			if err := histstore.ValidateKey(s.Prefix); err != nil {
				return fmt.Errorf("histworker: store %q prefix: %w", domain, err)
			}
		}
	}
	if c.LegacyStore != nil {
		switch c.LegacyStore.Kind {
		case "fs":
			if !strings.HasPrefix(c.LegacyStore.RootDir, "/") {
				return fmt.Errorf("histworker: legacy store rootDir must be absolute")
			}
		case "s3":
			if _, err := histstore.NewS3Store(histstore.S3Config{
				Domain: "legacy", Endpoint: c.LegacyStore.Endpoint,
				Region: c.LegacyStore.Region, Bucket: c.LegacyStore.Bucket,
				PathStyle:   c.LegacyStore.PathStyle,
				AccessKeyID: c.LegacyStore.AccessKeyID, SecretAccessKey: c.LegacyStore.SecretAccessKey,
			}); err != nil {
				return fmt.Errorf("histworker: legacy store: %w", err)
			}
		default:
			return fmt.Errorf("histworker: legacy store kind %q is unknown", c.LegacyStore.Kind)
		}
	}

	bounds := []struct {
		name     string
		value    int
		min, max int
	}{
		{"materialize concurrency", c.MaterializeConcurrency, 1, 8},
		{"max cut attempts", c.MaxCutAttempts, 3, 50},
		{"upload concurrency", c.UploadConcurrency, 1, 256},
		{"scrub batch", c.ScrubBatch, 1, 512},
		{"scrub concurrency", c.ScrubConcurrency, 1, 32},
		{"repair batch", c.RepairBatch, 1, 128},
		{"repair concurrency", c.RepairConcurrency, 1, 16},
	}
	for _, b := range bounds {
		if b.value < b.min || b.value > b.max {
			return fmt.Errorf("histworker: %s %d outside %d..%d", b.name, b.value, b.min, b.max)
		}
	}
	if c.LeaseTTL < 5*time.Second || c.LeaseTTL > 300*time.Second {
		return fmt.Errorf("histworker: lease TTL %v outside 5s..300s", c.LeaseTTL)
	}
	if c.HeartbeatInterval <= 0 || c.HeartbeatInterval > c.LeaseTTL/2 {
		return fmt.Errorf("histworker: heartbeat interval %v must be within (0, leaseTTL/2]", c.HeartbeatInterval)
	}
	if c.PollInterval < 100*time.Millisecond {
		return fmt.Errorf("histworker: poll interval %v is below 100ms", c.PollInterval)
	}
	if c.OperationTimeout < time.Second || c.OperationTimeout > 30*time.Minute {
		return fmt.Errorf("histworker: operation timeout %v outside 1s..30m", c.OperationTimeout)
	}
	if c.SweepMinAge < time.Minute || c.SweepMinAge > 30*24*time.Hour {
		return fmt.Errorf("histworker: sweep min age %v outside 1m..720h", c.SweepMinAge)
	}
	if c.FreshenAge < time.Minute || c.FreshenAge > 30*24*time.Hour {
		return fmt.Errorf("histworker: freshen age %v outside 1m..720h", c.FreshenAge)
	}
	if c.ShutdownGrace < time.Second || c.ShutdownGrace > 5*time.Minute {
		return fmt.Errorf("histworker: shutdown grace %v outside 1s..5m", c.ShutdownGrace)
	}
	if c.TempSweepAge < time.Hour || c.TempSweepAge > 30*24*time.Hour {
		return fmt.Errorf("histworker: temp sweep age %v outside 1h..720h", c.TempSweepAge)
	}
	if c.ListenAddr != "" {
		if _, _, err := net.SplitHostPort(c.ListenAddr); err != nil {
			return fmt.Errorf("histworker: listen address %q: %w", c.ListenAddr, err)
		}
	}
	if c.MaxCacheBytes < 8<<20 || c.MaxPendingUploadBytes < 8<<20 {
		return fmt.Errorf("histworker: cache and pending-upload bounds must be >= 8 MiB")
	}
	if c.MaxLegacyBlobBytes < 1<<20 || c.MaxLegacyBlobBytes > 512<<20 {
		return fmt.Errorf("histworker: legacy blob bound must be within 1..512 MiB")
	}
	perCut := c.MaxCacheBytes + c.MaxPendingUploadBytes + c.MaxLegacyBlobBytes
	if perCut < 0 || perCut > (2<<30)/int64(c.MaterializeConcurrency) {
		return fmt.Errorf("histworker: aggregate materialization memory bound exceeds 2 GiB")
	}
	return nil
}

// Redacted is the only loggable projection: identity, bounds, and store
// shapes with every secret withheld.
func (c Config) Redacted() map[string]any {
	stores := make([]map[string]any, 0, len(c.Stores))
	for _, s := range c.Stores {
		entry := map[string]any{
			"failureDomain": s.FailureDomain,
			"kind":          s.Kind,
		}
		if s.Kind == "fs" {
			entry["rootDir"] = s.RootDir
		} else {
			entry["endpoint"] = s.Endpoint
			entry["bucket"] = s.Bucket
			entry["region"] = s.Region
			entry["pathStyle"] = s.PathStyle
		}
		if s.Prefix != "" {
			entry["prefix"] = s.Prefix
		}
		stores = append(stores, entry)
	}
	out := map[string]any{
		"workerId":               c.WorkerID,
		"expectedPolicyEpoch":    c.ExpectedPolicyEpoch,
		"databaseMaxConns":       c.DatabaseMaxConns,
		"stores":                 stores,
		"minFailureDomains":      c.MinFailureDomains,
		"production":             c.Production,
		"materializeConcurrency": c.MaterializeConcurrency,
		"maxCutAttempts":         c.MaxCutAttempts,
		"leaseTtlMs":             c.LeaseTTL.Milliseconds(),
		"heartbeatMs":            c.HeartbeatInterval.Milliseconds(),
		"listenAddr":             c.ListenAddr,
	}
	if c.LegacyStore != nil {
		legacy := map[string]any{"kind": c.LegacyStore.Kind}
		if c.LegacyStore.Kind == "fs" {
			legacy["rootDir"] = c.LegacyStore.RootDir
		} else {
			legacy["endpoint"] = c.LegacyStore.Endpoint
			legacy["bucket"] = c.LegacyStore.Bucket
		}
		out["legacyStore"] = legacy
	}
	return out
}

// FromEnv constructs and validates the complete production configuration.
// Secrets are accepted only through the supplied lookup and are never
// included in validation errors or Redacted(). Stores use JSON so S3
// credentials and future additive fields do not require a parallel env-var
// grammar.
func FromEnv(lookup func(string) (string, bool)) (Config, error) {
	cfg := Config{}.withDefaults()
	get := func(name string) string {
		value, _ := lookup(name)
		return strings.TrimSpace(value)
	}
	cfg.DSN = get("PFH_WORKER_DATABASE_URL")
	cfg.WorkerID = get("PFH_WORKER_ID")
	cfg.ListenAddr = get("PFH_WORKER_LISTEN_ADDR")
	// The production switch is deployment-wide: the same VCS_PRODUCTION=1
	// the rest of the stack validates against.
	cfg.Production = get("VCS_PRODUCTION") == "1"

	if raw := get("PFH_WORKER_STORES_JSON"); raw != "" {
		stores, err := ParseStoresJSON(raw)
		if err != nil {
			return cfg, err
		}
		cfg.Stores = stores
	}
	if raw := get("PFH_WORKER_LEGACY_STORE_JSON"); raw != "" {
		legacy, err := ParseLegacyStoreJSON(raw)
		if err != nil {
			return cfg, err
		}
		cfg.LegacyStore = legacy
	}

	parseInt := func(name string, apply func(int64)) error {
		raw := get(name)
		if raw == "" {
			return nil
		}
		value, err := strconv.ParseInt(raw, 10, 64)
		if err != nil {
			return fmt.Errorf("histworker: %s must be a decimal integer", name)
		}
		apply(value)
		return nil
	}
	values := []struct {
		name  string
		apply func(int64)
	}{
		{"PFH_WORKER_POLICY_EPOCH", func(v int64) { cfg.ExpectedPolicyEpoch = v }},
		{"PFH_WORKER_MIN_FAILURE_DOMAINS", func(v int64) { cfg.MinFailureDomains = int(v) }},
		{"PFH_WORKER_DB_MAX_CONNS", func(v int64) { cfg.DatabaseMaxConns = int32(v) }},
		{"PFH_WORKER_MATERIALIZE_CONCURRENCY", func(v int64) { cfg.MaterializeConcurrency = int(v) }},
		{"PFH_WORKER_MAX_CUT_ATTEMPTS", func(v int64) { cfg.MaxCutAttempts = int(v) }},
		{"PFH_WORKER_UPLOAD_CONCURRENCY", func(v int64) { cfg.UploadConcurrency = int(v) }},
		{"PFH_WORKER_SCRUB_BATCH", func(v int64) { cfg.ScrubBatch = int(v) }},
		{"PFH_WORKER_SCRUB_CONCURRENCY", func(v int64) { cfg.ScrubConcurrency = int(v) }},
		{"PFH_WORKER_REPAIR_BATCH", func(v int64) { cfg.RepairBatch = int(v) }},
		{"PFH_WORKER_REPAIR_CONCURRENCY", func(v int64) { cfg.RepairConcurrency = int(v) }},
		{"PFH_WORKER_LEASE_TTL_MS", func(v int64) { cfg.LeaseTTL = time.Duration(v) * time.Millisecond }},
		{"PFH_WORKER_HEARTBEAT_MS", func(v int64) { cfg.HeartbeatInterval = time.Duration(v) * time.Millisecond }},
		{"PFH_WORKER_POLL_MS", func(v int64) { cfg.PollInterval = time.Duration(v) * time.Millisecond }},
		{"PFH_WORKER_OPERATION_TIMEOUT_MS", func(v int64) { cfg.OperationTimeout = time.Duration(v) * time.Millisecond }},
		{"PFH_WORKER_SWEEP_MIN_AGE_MS", func(v int64) { cfg.SweepMinAge = time.Duration(v) * time.Millisecond }},
		{"PFH_WORKER_FRESHEN_AGE_MS", func(v int64) { cfg.FreshenAge = time.Duration(v) * time.Millisecond }},
		{"PFH_WORKER_SHUTDOWN_GRACE_MS", func(v int64) { cfg.ShutdownGrace = time.Duration(v) * time.Millisecond }},
		{"PFH_WORKER_TEMP_SWEEP_AGE_MS", func(v int64) { cfg.TempSweepAge = time.Duration(v) * time.Millisecond }},
		{"PFH_WORKER_MAX_CACHE_BYTES", func(v int64) { cfg.MaxCacheBytes = v }},
		{"PFH_WORKER_MAX_PENDING_UPLOAD_BYTES", func(v int64) { cfg.MaxPendingUploadBytes = v }},
		{"PFH_WORKER_MAX_LEGACY_BLOB_BYTES", func(v int64) { cfg.MaxLegacyBlobBytes = v }},
	}
	leaseConfigured := get("PFH_WORKER_LEASE_TTL_MS") != ""
	heartbeatConfigured := get("PFH_WORKER_HEARTBEAT_MS") != ""
	for _, value := range values {
		if err := parseInt(value.name, value.apply); err != nil {
			return cfg, err
		}
	}
	if leaseConfigured && !heartbeatConfigured {
		cfg.HeartbeatInterval = cfg.LeaseTTL / 4
	}
	return cfg, cfg.Validate()
}

// redactDSNError strips anything resembling the DSN value from a parse
// error so secrets cannot leak through error text.
func redactDSNError(err error) error {
	msg := err.Error()
	if i := strings.Index(msg, ":"); i > 0 {
		return fmt.Errorf("%s: <redacted>", msg[:i])
	}
	return fmt.Errorf("invalid DSN")
}

// ParseStoresJSON decodes the store list from its JSON environment form.
func ParseStoresJSON(raw string) ([]StoreConfig, error) {
	var out []StoreConfig
	decoder := json.NewDecoder(strings.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&out); err != nil {
		return nil, fmt.Errorf("histworker: stores JSON: %w", err)
	}
	if err := requireJSONEOF(decoder); err != nil {
		return nil, fmt.Errorf("histworker: stores JSON: %w", err)
	}
	return out, nil
}

// ParseLegacyStoreJSON decodes the optional legacy store binding.
func ParseLegacyStoreJSON(raw string) (*LegacyStoreConfig, error) {
	var out LegacyStoreConfig
	decoder := json.NewDecoder(strings.NewReader(raw))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&out); err != nil {
		return nil, fmt.Errorf("histworker: legacy store JSON: %w", err)
	}
	if err := requireJSONEOF(decoder); err != nil {
		return nil, fmt.Errorf("histworker: legacy store JSON: %w", err)
	}
	return &out, nil
}

func requireJSONEOF(decoder *json.Decoder) error {
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		if err == nil {
			return fmt.Errorf("multiple JSON values are not allowed")
		}
		return err
	}
	return nil
}
