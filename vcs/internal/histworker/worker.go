package histworker

import (
	"context"
	"errors"
	"fmt"
	"io"
	"sync"
	"sync/atomic"
	"time"

	"github.com/steerlabs/portablefs/vcs/internal/histstore"
	"github.com/steerlabs/portablefs/vcs/internal/metrics"
)

// Worker is one long-running history worker process: the materialize,
// scrub, repair, and GC loops over ONE repository and ONE store set. All
// coordination state lives in the database; the worker holds only
// disposable memory and can be SIGKILLed at any instant — DB-time leases
// reclaim everything it held.
type Worker struct {
	cfg     Config
	repo    Repository
	stores  *DomainStores
	log     *Logger
	metrics *metrics.Registry

	ready readiness

	// wake lets tests trigger an immediate claim poll.
	wake chan struct{}
}

// New assembles a worker from validated parts (production wiring lives in
// cmd/history-worker; tests inject fakes).
func New(cfg Config, repo Repository, stores *DomainStores, logOut io.Writer) (*Worker, error) {
	cfg = cfg.withDefaults()
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	if repo == nil || stores == nil || logOut == nil {
		return nil, fmt.Errorf("histworker: repository, stores, and log output are required")
	}
	configured := make(map[string]bool, len(cfg.Stores))
	for _, store := range cfg.Stores {
		configured[store.FailureDomain] = true
	}
	for _, domain := range stores.Domains() {
		if !configured[domain] {
			return nil, fmt.Errorf("histworker: runtime store %q is absent from validated config", domain)
		}
		delete(configured, domain)
	}
	if len(configured) != 0 {
		return nil, fmt.Errorf("histworker: validated config has stores absent from runtime")
	}
	return &Worker{
		cfg:     cfg,
		repo:    repo,
		stores:  stores,
		log:     NewLogger(logOut).With(map[string]any{"workerId": cfg.WorkerID}),
		metrics: metrics.NewRegistry(),
		wake:    make(chan struct{}, 1),
	}, nil
}

// Metrics exposes the worker's registry (health listener, tests).
func (w *Worker) Metrics() *metrics.Registry { return w.metrics }

// Wake triggers an immediate poll of every loop (tests).
func (w *Worker) Wake() {
	select {
	case w.wake <- struct{}{}:
	default:
	}
}

// Run executes every loop until ctx is cancelled, then drains bounded
// in-flight work and returns. Nothing is released by local assertion on
// the way out: claims expire on database time.
func (w *Worker) Run(ctx context.Context) error {
	w.log.Info("worker_start", map[string]any{"config": w.cfg.Redacted()})
	if removed, err := w.stores.SweepTemps(ctx, w.cfg.TempSweepAge); err != nil {
		w.log.Error("temp_sweep_incomplete", err, map[string]any{"removed": removed})
	} else if removed > 0 {
		w.log.Info("temp_sweep_complete", map[string]any{"removed": removed})
	}

	// One initial beat proves DB reachability + migration + capability
	// before any loop claims work.
	if _, err := w.repo.WorkerBeat(ctx, w.cfg.WorkerID,
		[]string{"materializer", "scrub", "repair", "gc"}, nil); err != nil {
		w.ready.setDB(err)
		if ctx.Err() != nil {
			return ctx.Err()
		}
		w.log.Error("worker_initial_beat_failed", err, nil)
	} else {
		w.ready.setDB(nil)
	}
	w.probeStores(ctx)

	// In-flight work continues past cancellation on a grace-bounded
	// context so DB/object I/O finishes or is cancelled cleanly.
	workCtx, stopWork := graceContext(ctx, w.cfg.ShutdownGrace)
	defer stopWork()

	var wg sync.WaitGroup
	loop := func(name string, body func(context.Context) (bool, error), idle time.Duration) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				if ctx.Err() != nil {
					return
				}
				iterationCtx, cancelIteration := context.WithTimeout(workCtx, w.cfg.OperationTimeout)
				busy, err := body(iterationCtx)
				cancelIteration()
				if err != nil && ctx.Err() == nil && !errors.Is(err, context.Canceled) {
					w.metrics.Counter("pfh_worker_loop_errors_total").Inc()
					w.log.Error(name+"_loop_error", err, nil)
				}
				if busy && ctx.Err() == nil {
					continue
				}
				select {
				case <-ctx.Done():
					return
				case <-w.wake:
				case <-time.After(idle):
				}
			}
		}()
	}

	loop("materialize", func(c context.Context) (bool, error) {
		return w.materializePass(ctx, c)
	}, w.cfg.PollInterval)
	loop("scrub", func(c context.Context) (bool, error) {
		n, err := w.scrubPass(c)
		return n > 0, err
	}, w.cfg.PollInterval)
	loop("repair", func(c context.Context) (bool, error) {
		n, err := w.repairPass(c)
		return n > 0, err
	}, w.cfg.PollInterval)
	loop("gc", func(c context.Context) (bool, error) {
		return w.gcPass(c)
	}, w.cfg.PollInterval)
	loop("retention", func(c context.Context) (bool, error) {
		return w.retentionPass(c)
	}, w.cfg.PollInterval)
	loop("rehome", func(c context.Context) (bool, error) {
		return w.rehomePass(c)
	}, w.cfg.PollInterval)
	loop("readiness", func(c context.Context) (bool, error) {
		if _, err := w.repo.WorkerBeat(c, w.cfg.WorkerID,
			[]string{"materializer", "scrub", "repair", "gc"}, nil); err != nil {
			w.ready.setDB(err)
		} else {
			w.ready.setDB(nil)
		}
		w.probeStores(c)
		return false, nil
	}, 15*time.Second)

	<-ctx.Done()
	w.log.Info("worker_stopping", nil)
	wg.Wait()
	stopWork()
	w.log.Info("worker_stopped", nil)
	return ctx.Err()
}

// materializePass claims up to the concurrency budget and materializes the
// claims in parallel. claimCtx stops NEW claims at shutdown; workCtx lets
// in-flight cuts finish within the grace bound. Both flow into each claim:
// claimCtx so the attempt can tell shutdown from its own deadline, workCtx
// as the attempt bound.
func (w *Worker) materializePass(claimCtx, workCtx context.Context) (bool, error) {
	if claimCtx.Err() != nil {
		return false, nil
	}
	claims, err := w.repo.ClaimCuts(claimCtx, w.cfg.WorkerID,
		w.cfg.MaterializeConcurrency, w.cfg.LeaseTTL.Milliseconds())
	if err != nil {
		if errors.Is(err, ErrPolicyMissing) {
			w.ready.setPolicy(err)
		}
		return false, err
	}
	if len(claims) == 0 {
		return false, nil
	}
	w.metrics.Counter("pfh_worker_cuts_claimed_total").Add(int64(len(claims)))
	var wg sync.WaitGroup
	for _, claim := range claims {
		wg.Add(1)
		go func(claim CutClaim) {
			defer wg.Done()
			started := time.Now()
			w.materializeClaim(claimCtx, workCtx, claim)
			w.metrics.Histogram("pfh_worker_materialize_seconds").Observe(time.Since(started))
		}(claim)
	}
	wg.Wait()
	return true, nil
}

// probeStores proves each configured failure domain reachable and
// authenticated: a Head of a never-written probe key must return a typed
// not-found (anything else — auth failure, transport failure — is not
// ready).
func (w *Worker) probeStores(ctx context.Context) {
	for _, domain := range w.stores.Domains() {
		store, _ := w.stores.Get(domain)
		_, err := store.Head(ctx, "readiness/probe")
		if errors.Is(err, histstore.ErrNotFound) || err == nil {
			w.ready.setStore(domain, nil)
			continue
		}
		w.ready.setStore(domain, err)
	}
}

func (w *Worker) setPolicyProof(ok bool) {
	if ok {
		w.ready.setPolicy(nil)
	}
}

func (w *Worker) setPolicyAdmission(err error) {
	if err == nil || errors.Is(err, ErrPolicyMismatch) {
		w.ready.setPolicy(err)
	}
}

// Readiness reports the current readiness verdict and its reasons.
func (w *Worker) Readiness() (bool, map[string]string) {
	return w.ready.report(w.stores.Domains())
}

// readiness aggregates the three proofs: database migration/capability
// (worker_beat), policy admission (policy installed AND servable by this
// deployment), and per-domain store reachability.
type readiness struct {
	mu       sync.Mutex
	dbErr    error
	dbProven bool

	policyErr    error
	policyProven bool

	storeErr map[string]error

	generation atomic.Int64
}

func (r *readiness) setDB(err error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.dbErr = err
	r.dbProven = true
	r.generation.Add(1)
}

func (r *readiness) setPolicy(err error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.policyErr = err
	r.policyProven = true
	r.generation.Add(1)
}

func (r *readiness) setStore(domain string, err error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.storeErr == nil {
		r.storeErr = map[string]error{}
	}
	r.storeErr[domain] = err
	r.generation.Add(1)
}

func (r *readiness) report(domains []string) (bool, map[string]string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	out := map[string]string{}
	ready := true
	switch {
	case !r.dbProven:
		out["database"] = "unproven"
		ready = false
	case r.dbErr != nil:
		out["database"] = r.dbErr.Error()
		ready = false
	default:
		out["database"] = "ok"
	}
	switch {
	case !r.policyProven:
		out["policy"] = "unproven"
		ready = false
	case r.policyErr != nil:
		out["policy"] = r.policyErr.Error()
		ready = false
	default:
		out["policy"] = "ok"
	}
	for _, domain := range domains {
		err, probed := r.storeErr[domain]
		key := "store:" + domain
		switch {
		case !probed:
			out[key] = "unproven"
			ready = false
		case err != nil:
			out[key] = err.Error()
			ready = false
		default:
			out[key] = "ok"
		}
	}
	return ready, out
}

// graceContext returns a context that stays live while root is live, and
// after root cancels remains live for the grace window so in-flight
// DB/object I/O can finish or observe its own deadline. The returned stop
// releases resources.
func graceContext(root context.Context, grace time.Duration) (context.Context, context.CancelFunc) {
	ctx, cancel := context.WithCancel(context.WithoutCancel(root))
	stopAfter := context.AfterFunc(root, func() {
		timer := time.AfterFunc(grace, cancel)
		// The timer is intentionally left running: cancelling an already
		// finished context is a no-op.
		_ = timer
	})
	return ctx, func() {
		stopAfter()
		cancel()
	}
}

// String renders one bounded diagnostic line (used in tests).
func (w *Worker) String() string {
	ready, _ := w.Readiness()
	return fmt.Sprintf("histworker{%s ready=%v}", w.cfg.WorkerID, ready)
}
