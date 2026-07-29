// Command vcs serves one volume branch as the MANAGED authority child: one
// disposable fenced process per active branch, cold-replaying the
// synchronously durable remote PostgreSQL journal (VCS_JOURNAL_DSN) — the only
// write truth — and serving the authenticated fsproto data plane.
//
// MANAGED PRODUCTION:
//
//	VCS_PRODUCTION=1 VCS_WRITABLE=1 VCS_JOURNAL_DSN=postgres://... \
//	VCS_TENANT_ID=... VCS_AUTHORITY_INSTANCE_ID=... \
//	VCS_JOURNAL_HA_POLICY_JSON="..." vcs
//
// The managed child is spawned by the authority manager with two inherited
// pipes (VCS_HEARTBEAT_FD, VCS_BOOTSTRAP_FD), binds its own loopback
// listeners, and reports the exact addresses back on the bootstrap pipe.
// VCS_PRODUCTION=1 rejects VCS_WAL and VCS_CACHE_DIR: durability lives in the
// fenced PostgreSQL journal, and the authority starts in an empty read-only
// working directory.
//
// A development run against a local test database drops VCS_PRODUCTION and the
// pipes but keeps the same remote-journal serving path (it may pin VCS_FS_ADDR
// and VCS_METRICS_ADDR). There is no other serving mode: no local file-WAL
// authority, no read-only branch-head serving, no NFS.
package main

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"fmt"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"strconv"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"github.com/go-git/go-billy/v5"

	"github.com/steerlabs/portablefs/vcs/internal/backend"
	"github.com/steerlabs/portablefs/vcs/internal/content"
	"github.com/steerlabs/portablefs/vcs/internal/fsproto"
	"github.com/steerlabs/portablefs/vcs/internal/hapolicy"
	"github.com/steerlabs/portablefs/vcs/internal/lifecycle"
	"github.com/steerlabs/portablefs/vcs/internal/metrics"
	"github.com/steerlabs/portablefs/vcs/internal/secure"
)

// Readiness / liveness state for orchestration probes. Liveness (/healthz) means
// the process is up; readiness (/readyz) means this node is actually serving the
// volume. An orchestrator routes traffic on readiness and only restarts on
// liveness.
var (
	healthReady atomic.Bool
	healthRole  atomic.Pointer[string]
	readyGauge  = metrics.Default.Gauge("vcs_ready")
	// adminLifecycle publishes the writable serving path's lifecycle controller to
	// the admin endpoints on the metrics listener (nil until a managed primary is
	// serving).
	adminLifecycle lifecycle.Holder
)

func setRole(r string) { healthRole.Store(&r) }

func currentRole() string {
	if p := healthRole.Load(); p != nil {
		return *p
	}
	return "starting"
}

// setReady flips the readiness signal (and the vcs_ready gauge) atomically.
func setReady(ready bool) {
	healthReady.Store(ready)
	if ready {
		readyGauge.Set(1)
	} else {
		readyGauge.Set(0)
	}
}

// livenessHandler answers /healthz: the process is up. Always 200 — an orchestrator
// restarts the node only if this stops answering.
func livenessHandler(w http.ResponseWriter, _ *http.Request) { _, _ = w.Write([]byte("ok\n")) }

// readinessIdentity is the exact identity a MANAGED child publishes on
// /readyz so the manager can validate the process answering the probe is the
// process it spawned — instance, scope, runtime binding, journal identity,
// protocol version, and the HA policy hash it verified. Never a raw secret.
type readinessIdentity struct {
	AuthorityInstanceID string `json:"authorityInstanceId"`
	VolumeID            string `json:"volumeId"`
	Branch              string `json:"branch"`
	Journal             string `json:"journal"`
	ManagerEpoch        string `json:"managerEpoch"`
	AuthorityRuntimeSeq string `json:"authorityRuntimeSeq"`
	AuthorityRuntimeID  string `json:"authorityRuntimeId"`
	JournalGenerationID string `json:"journalGenerationId"`
	ProtocolVersion     int    `json:"protocolVersion"`
	HAPolicyHash        string `json:"haPolicyHash"`
	// The ACTUAL bound listener addresses (self-bound 127.0.0.1:0): readiness
	// describes the exact process that is serving, not a configured intent.
	FSAddr      string `json:"fsAddr"`
	MetricsAddr string `json:"metricsAddr"`
}

var readyIdentity atomic.Pointer[readinessIdentity]

// readinessHandler answers /readyz: this node is serving the volume. 503 until it
// is, so a load balancer routes only to a live primary. A managed child
// additionally reports its exact identity.
func readinessHandler(w http.ResponseWriter, _ *http.Request) {
	ready := healthReady.Load()
	w.Header().Set("content-type", "application/json")
	if !ready {
		w.WriteHeader(http.StatusServiceUnavailable)
	}
	payload := map[string]any{"ready": ready, "role": currentRole()}
	if identity := readyIdentity.Load(); identity != nil {
		payload["authorityInstanceId"] = identity.AuthorityInstanceID
		payload["volumeId"] = identity.VolumeID
		payload["branch"] = identity.Branch
		payload["journal"] = identity.Journal
		payload["managerEpoch"] = identity.ManagerEpoch
		payload["authorityRuntimeSeq"] = identity.AuthorityRuntimeSeq
		payload["authorityRuntimeId"] = identity.AuthorityRuntimeID
		payload["journalGenerationId"] = identity.JournalGenerationID
		payload["protocolVersion"] = identity.ProtocolVersion
		payload["haPolicyHash"] = identity.HAPolicyHash
		payload["fsAddr"] = identity.FSAddr
		payload["metricsAddr"] = identity.MetricsAddr
	}
	_ = json.NewEncoder(w).Encode(payload)
}

// serveMetrics exposes the metrics registry over HTTP (opt-in via VCS_METRICS_ADDR):
// /stats (JSON), /metrics (Prometheus text), /healthz (liveness), /readyz (readiness),
// plus the fenced lifecycle admin API (/v1/ops/checkpoint, /v1/ops/evict,
// /v1/ops/quiesce, /v1/ops/release-lease). The lifecycle routes require the VCS_ADMIN_TOKEN
// bearer — a control-plane credential distinct from the data-plane
// VCS_AUTH_TOKEN, rotated per authority instance by the manager — when one is
// configured; the scrape endpoints stay unauthenticated as before.
func serveMetrics(ctx context.Context, addr string) {
	host, _, err := net.SplitHostPort(addr)
	if err != nil {
		host = addr
	}
	srv := &http.Server{Addr: addr, Handler: metricsMux(host), ReadHeaderTimeout: 5 * time.Second}
	go func() { <-ctx.Done(); _ = srv.Close() }()
	log.Printf("vcs metrics: http://%s/stats (+ /metrics, /healthz, /readyz, /v1/ops)", addr)
	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Printf("metrics server: %v", err)
	}
}

// serveMetricsOn serves the same metrics/admin surface on an already-bound
// listener (the MANAGED child binds 127.0.0.1:0 itself and reports the exact
// address through the bootstrap pipe).
func serveMetricsOn(ctx context.Context, ln net.Listener) {
	host, _, err := net.SplitHostPort(ln.Addr().String())
	if err != nil {
		host = ln.Addr().String()
	}
	srv := &http.Server{Handler: metricsMux(host), ReadHeaderTimeout: 5 * time.Second}
	go func() { <-ctx.Done(); _ = srv.Close() }()
	log.Printf("vcs metrics: http://%s/stats (+ /metrics, /healthz, /readyz, /v1/ops)", ln.Addr())
	if err := srv.Serve(ln); err != nil && err != http.ErrServerClosed {
		log.Printf("metrics server: %v", err)
	}
}

func metricsMux(host string) *http.ServeMux {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", livenessHandler)
	mux.HandleFunc("/readyz", readinessHandler)
	mux.HandleFunc("/stats", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("content-type", "application/json")
		_ = json.NewEncoder(w).Encode(metrics.Default.Snapshot())
	})
	mux.HandleFunc("/metrics", func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write([]byte(metrics.Default.Prometheus()))
	})
	// Fail closed: lifecycle operations (evict / checkpoint refusals) are only
	// served without a bearer token on a loopback bind. A network-reachable
	// metrics listener without VCS_ADMIN_TOKEN keeps its scrape endpoints but
	// refuses lifecycle control, so an open port can never evict the volume.
	// The data-plane VCS_AUTH_TOKEN deliberately does NOT unlock these routes:
	// mount credentials must not carry lifecycle authority.
	if secure.AdminToken() == "" && !secure.IsLoopbackBind(host) {
		mux.HandleFunc("/v1/ops/", func(w http.ResponseWriter, _ *http.Request) {
			w.Header().Set("content-type", "application/json")
			w.Header().Set("cache-control", "no-store")
			w.WriteHeader(http.StatusForbidden)
			_, _ = w.Write([]byte(`{"error":{"code":"VCS_OPS_LOCKED","message":"lifecycle operations require VCS_ADMIN_TOKEN on a network-reachable metrics listener"}}`))
		})
	} else {
		mux.Handle("/v1/ops/", lifecycle.HandlerWithOptions(&adminLifecycle, secure.AdminToken(), lifecycle.HandlerOptions{
			// Loopback without a token is an explicit local-development mode. The
			// lifecycle package itself remains fail closed by default.
			AllowUnauthenticatedDevelopment: secure.AdminToken() == "" && secure.IsLoopbackBind(host),
		}))
	}
	return mux
}

// maybeTLS wraps a listener in TLS when VCS_TLS_CERT/KEY are configured; otherwise
// it serves plaintext (a trusted LAN or behind WireGuard).
func maybeTLS(ln net.Listener, what string) net.Listener {
	cfg, err := secure.ServerTLS()
	if err != nil {
		log.Fatalf("%s TLS config: %v", what, err)
	}
	if cfg == nil {
		return ln
	}
	log.Printf("%s: TLS enabled", what)
	return tls.NewListener(ln, cfg)
}

func env(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

type config struct {
	apiURL        string
	token         string
	volumeID      string
	branch        string
	production    bool
	writable      bool
	fsAddr        string // custom FS protocol listen addr (dev runs); production rejects it
	failoverPoll  time.Duration
	leaseTTLms    int64 // write-lease lifetime; a successor waits up to this after a crash
	cacheRAMBytes int64
	// dirtyRSSMaxMB (VCS_DIRTY_RSS_MAX_MB, default 2048) bounds the working
	// tree's resident dirty-block bytes. Dirty blocks materialise at 4 MiB
	// granularity and — on a managed child, which never checkpoints
	// in-process — live for the whole generation, so one byte written into
	// each 4 MiB region of a large file costs 4 MiB of RSS per ~40 journal
	// bytes. Unbounded, that amplification lets a single tenant OOM the
	// shared manager host within kilobytes of journal quota. Writes past the
	// bound refuse with ENOSPC; releases (truncate/remove) always proceed.
	// Kept as the raw string so validation can reject 0/negative/garbage
	// loudly instead of silently substituting the default.
	dirtyRSSMaxMB string
	metricsAddr   string // VCS_METRICS_ADDR — serve /stats, /metrics, /healthz; "" disables
	// authorityInstanceID is the opaque manager-assigned identity of this authority
	// instance (VCS_AUTHORITY_INSTANCE_ID). Lifecycle operations are fenced by it.
	authorityInstanceID string
	// journalDSN (VCS_JOURNAL_DSN) names the remote journal: durability lives
	// in PostgreSQL behind SECURITY DEFINER functions, reached with the
	// restricted authority login. It is REQUIRED — the remote journal is the
	// only durability truth this binary serves.
	journalDSN string
	// journalPoolerMode (VCS_JOURNAL_POOLER_MODE) is empty for a direct
	// database connection or exactly "transaction" when the journal DSN
	// reaches a transaction-mode pooler: connection startup then omits the
	// session timeout GUCs a pooler cannot preserve (migration
	// 016_pooler_timeouts installs the equivalent database defaults).
	journalPoolerMode string
	// tenantID (VCS_TENANT_ID) scopes every journal claim/read in SQL.
	tenantID string
	// The exact manager/runtime binding this child was launched under
	// (VCS_MANAGER_EPOCH, VCS_MANAGER_RUNTIME_ID, VCS_AUTHORITY_RUNTIME_SEQ,
	// VCS_AUTHORITY_RUNTIME_ID, VCS_AUTHORITY_RUNTIME_CAPABILITY). Counters
	// stay canonical decimal strings; the raw capability is manager-issued,
	// presented on every journal call, and NEVER logged.
	managerEpoch               string
	managerRuntimeID           string
	authorityRuntimeSeq        string
	authorityRuntimeID         string
	authorityRuntimeCapability string
	// Inherited manager pipes (0 = absent): heartbeatFD carries bounded
	// manager→child lease frames; bootstrapFD carries the child's one-shot
	// listener/identity report back to the manager.
	heartbeatFD int
	bootstrapFD int
	// journalHAPolicyJSON (VCS_JOURNAL_HA_POLICY_JSON) is the operator's
	// versioned structured HA policy for the journal database. The child
	// verifies pfj.durability_facts() against it before readiness; prose
	// attestations are not a durability gate.
	journalHAPolicyJSON string
	// suspendDeadlineMs (VCS_SUSPEND_DEADLINE_MS) bounds the exact journal
	// suspension inside one eviction/SIGTERM teardown attempt. An unresolved
	// suspension at the bound exits non-zero with admission sealed and the
	// writer lease UNRELEASED (database-time expiry fences it); the immutable
	// suspend operation replays its receipt on the next attempt or restart.
	suspendDeadlineMs int64
}

func (c config) suspendDeadline() time.Duration {
	if c.suspendDeadlineMs <= 0 {
		return 30 * time.Second
	}
	return time.Duration(c.suspendDeadlineMs) * time.Millisecond
}

// identity is the fence for lifecycle operations against this process.
func (c config) identity() lifecycle.Identity {
	return lifecycle.Identity{VolumeID: c.volumeID, Branch: c.branch, InstanceID: c.authorityInstanceID}
}

// managed reports the MANAGED-production child mode: one disposable fenced
// process per active branch under the authority manager, remote journal only.
func (c config) managed() bool {
	return c.production && c.writable && c.journalDSN != ""
}

func loadConfig() config {
	return config{
		apiURL:        os.Getenv("VOLUME_API_URL"),
		token:         os.Getenv("VOLUME_API_TOKEN"),
		volumeID:      os.Getenv("VCS_VOLUME_ID"),
		branch:        env("VCS_BRANCH", "main"),
		production:    os.Getenv("VCS_PRODUCTION") == "1",
		writable:      os.Getenv("VCS_WRITABLE") == "1",
		fsAddr:        os.Getenv("VCS_FS_ADDR"),
		failoverPoll:  time.Duration(mustInt(env("VCS_FAILOVER_POLL", "2"))) * time.Second,
		leaseTTLms:    int64(mustInt(env("VCS_LEASE_TTL", "30"))) * 1000,
		cacheRAMBytes: int64(envInt("VCS_CACHE_RAM_MB", 256)) << 20,
		dirtyRSSMaxMB: os.Getenv("VCS_DIRTY_RSS_MAX_MB"),
		metricsAddr:   os.Getenv("VCS_METRICS_ADDR"),

		authorityInstanceID: os.Getenv("VCS_AUTHORITY_INSTANCE_ID"),
		journalDSN:          os.Getenv("VCS_JOURNAL_DSN"),
		journalPoolerMode:   os.Getenv("VCS_JOURNAL_POOLER_MODE"),
		tenantID:            os.Getenv("VCS_TENANT_ID"),

		managerEpoch:               os.Getenv("VCS_MANAGER_EPOCH"),
		managerRuntimeID:           os.Getenv("VCS_MANAGER_RUNTIME_ID"),
		authorityRuntimeSeq:        os.Getenv("VCS_AUTHORITY_RUNTIME_SEQ"),
		authorityRuntimeID:         os.Getenv("VCS_AUTHORITY_RUNTIME_ID"),
		authorityRuntimeCapability: os.Getenv("VCS_AUTHORITY_RUNTIME_CAPABILITY"),
		heartbeatFD:                envInt("VCS_HEARTBEAT_FD", 0),
		bootstrapFD:                envInt("VCS_BOOTSTRAP_FD", 0),
		journalHAPolicyJSON:        os.Getenv("VCS_JOURNAL_HA_POLICY_JSON"),
		suspendDeadlineMs:          int64(envInt("VCS_SUSPEND_DEADLINE_MS", 30_000)),
	}
}

// defaultDirtyRSSMaxMB is the default dirty-block memory bound (2 GiB).
const defaultDirtyRSSMaxMB = 2048

// dirtyRSSMaxBytes resolves VCS_DIRTY_RSS_MAX_MB: unset applies the default;
// anything that is not a positive integer is a startup error — a zero or
// negative bound would either disable the OOM guard silently or wedge every
// write, and neither is a state an operator should reach by typo.
func (c config) dirtyRSSMaxBytes() (int64, error) {
	if c.dirtyRSSMaxMB == "" {
		return defaultDirtyRSSMaxMB << 20, nil
	}
	n, err := strconv.Atoi(c.dirtyRSSMaxMB)
	if err != nil || n <= 0 {
		return 0, fmt.Errorf("VCS_DIRTY_RSS_MAX_MB must be a positive integer count of MiB (default %d): it bounds resident dirty-block memory, the authority's dominant RAM cost; got %q", defaultDirtyRSSMaxMB, c.dirtyRSSMaxMB)
	}
	return int64(n) << 20, nil
}

func validateConfig(cfg config) error {
	if cfg.apiURL == "" || cfg.volumeID == "" {
		return fmt.Errorf("VOLUME_API_URL and VCS_VOLUME_ID are required")
	}
	if _, err := cfg.dirtyRSSMaxBytes(); err != nil {
		return err
	}
	// The remote journal is the ONLY serving mode: cmd/vcs is the managed
	// authority child. Self-hosting runs the manager + Postgres (quickstart);
	// the bench/torture harness hosts its own in-process authority.
	if cfg.journalDSN == "" {
		return fmt.Errorf("VCS_JOURNAL_DSN is required: cmd/vcs serves the fenced remote PostgreSQL journal only (there is no file-WAL or read-only serving mode)")
	}
	if !cfg.writable {
		return fmt.Errorf("VCS_WRITABLE=1 is required: the remote journal serves a writable fenced primary only")
	}
	if cfg.journalPoolerMode != "" && cfg.journalPoolerMode != "transaction" {
		return fmt.Errorf("VCS_JOURNAL_POOLER_MODE must be empty (direct connection) or transaction")
	}
	if cfg.tenantID == "" {
		return fmt.Errorf("VCS_JOURNAL_DSN requires VCS_TENANT_ID (journal claims are tenant-scoped in SQL)")
	}
	// There is deliberately NO codec selection knob: the immutable pair
	// comes from the authoritative provisioning/claim result alone
	// (pfj.branch_provisioning), so no configuration typo can pick or
	// downgrade a data plane.
	if os.Getenv("VCS_JOURNAL_CODEC") != "" {
		return fmt.Errorf("VCS_JOURNAL_CODEC is not a setting: the journal codec pair is decided by authoritative provisioning (pfj.branch_provisioning), never by configuration")
	}
	// The remote journal is the only durability truth. Every local-durability
	// setting is rejected — there is no mixing and no silent fallback.
	if _, set := os.LookupEnv("VCS_WAL"); set {
		return fmt.Errorf("VCS_WAL was removed: the remote journal is the only durability authority (no local WAL)")
	}
	if os.Getenv("VCS_CACHE_DIR") != "" {
		return fmt.Errorf("VCS_CACHE_DIR was removed: the authority keeps no persistent local directories (RAM cache only)")
	}
	// Every journal transaction (claim, append, read, suspend) presents the
	// exact manager/runtime binding; the child fails fast instead of
	// failing its first SQL call.
	if cfg.managerEpoch == "" || cfg.managerRuntimeID == "" {
		return fmt.Errorf("VCS_JOURNAL_DSN requires VCS_MANAGER_EPOCH and VCS_MANAGER_RUNTIME_ID (every journal transaction is fenced by the live manager claim)")
	}
	if cfg.authorityRuntimeSeq == "" || cfg.authorityRuntimeID == "" {
		return fmt.Errorf("VCS_JOURNAL_DSN requires VCS_AUTHORITY_RUNTIME_SEQ and VCS_AUTHORITY_RUNTIME_ID (every journal transaction is fenced by the live pfm runtime row)")
	}
	if cfg.authorityRuntimeCapability == "" {
		return fmt.Errorf("VCS_JOURNAL_DSN requires VCS_AUTHORITY_RUNTIME_CAPABILITY (the manager-issued runtime capability; the database stores only its hash)")
	}
	if cfg.journalHAPolicyJSON != "" {
		if _, err := hapolicy.ParsePolicy(cfg.journalHAPolicyJSON); err != nil {
			return fmt.Errorf("VCS_JOURNAL_HA_POLICY_JSON is invalid: %w", err)
		}
	}
	if !cfg.production {
		return nil
	}
	// VCS_PRODUCTION=1 is MANAGED production under the authority manager.
	if cfg.authorityInstanceID == "" {
		return fmt.Errorf("VCS_PRODUCTION=1: writable primary requires VCS_AUTHORITY_INSTANCE_ID (lifecycle operations are fenced by it)")
	}
	// The managed child binds its own loopback-ephemeral listeners and
	// reports the exact addresses through the bootstrap pipe; operator
	// addresses would reintroduce the port-allocation race and a
	// network-reachable bind.
	if cfg.fsAddr != "" {
		return fmt.Errorf("VCS_PRODUCTION=1 rejects VCS_FS_ADDR: the managed child binds fsproto on 127.0.0.1:0 itself and reports the exact address on the bootstrap pipe")
	}
	if cfg.metricsAddr != "" {
		return fmt.Errorf("VCS_PRODUCTION=1 rejects VCS_METRICS_ADDR: the managed child binds metrics on 127.0.0.1:0 itself and reports the exact address on the bootstrap pipe")
	}
	if cfg.heartbeatFD < 3 {
		return fmt.Errorf("VCS_PRODUCTION=1: writable primary requires VCS_HEARTBEAT_FD (>= 3): the manager lease pipe is the child's self-fencing clock")
	}
	if cfg.bootstrapFD < 3 || cfg.bootstrapFD == cfg.heartbeatFD {
		return fmt.Errorf("VCS_PRODUCTION=1: writable primary requires a distinct VCS_BOOTSTRAP_FD (>= 3): the child reports its exact self-bound listener addresses on it")
	}
	if cfg.journalHAPolicyJSON == "" {
		return fmt.Errorf("VCS_PRODUCTION=1 requires VCS_JOURNAL_HA_POLICY_JSON: the structured HA policy the child verifies against pfj.durability_facts() (a DSN or prose attestation alone is never a durability gate)")
	}
	if os.Getenv("VCS_AUTH_TOKEN") == "" {
		return fmt.Errorf("VCS_PRODUCTION=1 requires VCS_AUTH_TOKEN: the managed fsproto data plane is authenticated even on loopback")
	}
	if secure.AdminToken() == "" {
		return fmt.Errorf("VCS_PRODUCTION=1 requires VCS_ADMIN_TOKEN: lifecycle control is authenticated even on loopback")
	}
	// Zero means "use the 30s default" (config built programmatically);
	// an explicit value needs a real bound that still fits teardown.
	if cfg.suspendDeadlineMs != 0 && (cfg.suspendDeadlineMs < 1_000 || cfg.suspendDeadlineMs > 600_000) {
		return fmt.Errorf("VCS_SUSPEND_DEADLINE_MS must be within [1000, 600000]: the exact journal suspension needs a real bound that still fits inside ordinary teardown")
	}
	return nil
}

// envInt reads a non-negative integer env var (0 allowed), falling back to def.
func envInt(key string, def int) int {
	if v := os.Getenv(key); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n >= 0 {
			return n
		}
	}
	return def
}

// atRest builds the at-rest encryption cipher from VCS_ENCRYPTION_KEY (nil when
// unset — encryption is opt-in and changes nothing when off).
func atRest() *secure.AtRest {
	enc, err := secure.NewAtRest()
	if err != nil {
		log.Fatalf("encryption key: %v", err)
	}
	return enc
}

// buildCache builds the RAM read cache. The managed child keeps no persistent
// local directories, so there is no disk tier.
func buildCache(cfg config) content.Cache {
	cache, err := content.NewTieredCache(cfg.cacheRAMBytes, "", 0, atRest())
	if err != nil {
		log.Fatalf("build cache: %v", err)
	}
	return cache
}

// renewEvery renews the lease comfortably within its lifetime (one third of TTL).
func (c config) renewEvery() time.Duration {
	return time.Duration(c.leaseTTLms/3) * time.Millisecond
}

// leaseTTL is the write-lease lifetime as a duration; a primary that cannot renew
// within it must self-fence before a successor can claim.
func (c config) leaseTTL() time.Duration {
	return time.Duration(c.leaseTTLms) * time.Millisecond
}

func main() {
	cfg := loadConfig()
	if err := validateConfig(cfg); err != nil {
		log.Fatal(err)
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	if !cfg.managed() {
		// SIGUSR1 -> dump the lock-free handoff trace (VCS_TRACE=1) for
		// post-mortem. A MANAGED child never creates local files — not even
		// diagnostics; its truth is remote and its process is disposable.
		go func() {
			ch := make(chan os.Signal, 1)
			signal.Notify(ch, syscall.SIGUSR1)
			for range ch {
				_ = os.WriteFile("/trace.log", []byte(fsproto.DumpTrace()), 0o644)
			}
		}()
	}
	// VOLUME_API_TOKEN_FILE (manager-managed) carries the rotating
	// short-lived runtime read credential; the static token remains for
	// unmanaged development runs.
	client := backend.NewClientWithTokenFile(cfg.apiURL, cfg.token,
		os.Getenv("VOLUME_API_TOKEN_FILE"))

	if cfg.metricsAddr != "" {
		go serveMetrics(ctx, cfg.metricsAddr)
	}

	runErr := runRemotePrimary(ctx, client, cfg)
	log.Print("vcs stopped")
	if runErr != nil {
		// The graceful eviction drain did not complete: some ADMITTED —
		// never acknowledged — operation could not finish its durability
		// boundary in time, or the exact journal suspension is unresolved.
		// Every acknowledged write was durable before it was acknowledged and
		// remains recoverable from the journal; exit non-zero so a supervisor
		// or manager can see the stop was not a clean drain.
		log.Printf("vcs stopped WITHOUT a completed eviction drain: %v", runErr)
		stop()
		os.Exit(3)
	}
}

// serveFSProtoOn serves fsproto on an already-bound listener (the managed
// child binds 127.0.0.1:0 itself; secure exposure was validated by the
// caller/binder). Blocks until ctx ends.
func serveFSProtoOn(ctx context.Context, ln net.Listener, fsys billy.Filesystem) {
	ln = maybeTLS(ln, "fsproto")
	log.Printf("vcs serving custom FS protocol (FUSE/FSKit clients) on %s", ln.Addr())
	var notifier fsproto.Notifier
	if n, ok := fsys.(fsproto.Notifier); ok {
		notifier = n // writable working tree pushes cache invalidations
	}
	if err := fsproto.NewServer(fsys, notifier).Serve(ctx, ln); err != nil {
		log.Printf("fsproto serve: %v", err)
	}
}

// leaseRenewer is the writer lease's renewal surface (*authority.Authority
// satisfies it); an interface so lease-keeping is testable without a backend.
type leaseRenewer interface {
	Renew(ctx context.Context) error
}

// renewLoop keeps the write lease alive and self-fences the data plane if it
// cannot. On a definitive lease-lost error it fences immediately; otherwise a
// watchdog fences when (TTL − one renew interval) elapses with no successful renew —
// stopping the node before its lease expires and a successor can claim. fence()
// cancels the serving context.
//
// Three properties make the self-fence sound even under a hung backend:
//   - Each renew runs under its own timeout (a fraction of the deadline), so a stalled
//     backend call returns in time to be retried instead of blocking past the lease.
//   - The watchdog (time.AfterFunc) fires independently of the renew call, so even if a
//     renew is wedged the node still fences before the lease can expire. The backend's
//     HTTP timeout (60s) exceeds the lease TTL (default 30s), so without these the loop
//     could block inside Renew while the lease expired and a successor claimed.
//   - The watchdog resets from the PRE-CALL monotonic instant of the successful renew,
//     never the response time: the backend granted the TTL at some point after the call
//     started, so start + deadline never projects past the true expiry — anchoring at
//     the response would extend the fence by exactly the response delay.
func renewLoop(ctx context.Context, auth leaseRenewer, every, ttl time.Duration, fence func()) {
	// Self-fence one renew interval before the lease would actually expire, to cover
	// renew round-trip latency and clock skew vs the backend's expiry clock.
	deadline := ttl - every
	if deadline <= 0 {
		deadline = ttl
	}
	// Bound a single renew so a hung backend call cannot outlive the lease; floor at 1s.
	renewTimeout := deadline / 2
	if renewTimeout < time.Second {
		renewTimeout = time.Second
	}

	fenced := make(chan struct{})
	var fenceOnce sync.Once
	selfFence := func(reason string, err error) {
		fenceOnce.Do(func() {
			log.Printf("%s: fencing data plane and stepping down: %v", reason, err)
			fence()
			close(fenced)
		})
	}
	// Watchdog: fence if `deadline` passes without a successful renew, regardless of
	// whether a renew call is currently blocked. Reset on every successful renew.
	watchdog := time.AfterFunc(deadline, func() {
		selfFence(fmt.Sprintf("lease not renewed within %s", deadline), nil)
	})
	defer watchdog.Stop()

	ticker := time.NewTicker(every)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-fenced:
			return // the watchdog stepped us down
		case <-ticker.C:
			start := time.Now()
			renewCtx, cancel := context.WithTimeout(ctx, renewTimeout)
			err := auth.Renew(renewCtx)
			cancel()
			if err == nil {
				// Pre-call anchor: the remaining window is deadline minus the
				// time already burned by this round trip.
				remaining := deadline - time.Since(start)
				if remaining <= 0 {
					selfFence(fmt.Sprintf("lease renewal round trip consumed the whole %s window", deadline), nil)
					return
				}
				watchdog.Reset(remaining)
				continue
			}
			if backend.IsLeaseLost(err) {
				selfFence("lease lost (superseded or expired)", err)
				return
			}
			log.Printf("lease renew failed (retrying; self-fence watchdog armed for %s): %v", deadline, err)
		}
	}
}

func holderID() string { return "vcs-" + strconv.FormatInt(time.Now().UnixNano(), 36) }

func mustInt(s string) int {
	n, err := strconv.Atoi(s)
	if err != nil || n <= 0 {
		return 5
	}
	return n
}
