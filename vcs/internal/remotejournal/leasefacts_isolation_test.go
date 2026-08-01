package remotejournal

import (
	"context"
	"encoding/json"
	"errors"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
)

// boundedPoolDB models a pgxpool of a fixed connection count: a query that
// arrives when every connection is busy WAITS for one, exactly like
// pgxpool.Pool.Acquire, and fails with the context error if its bounded
// deadline arrives first. This is the property the live incident turned on —
// the lease-facts probe never failed on its own merits, it failed because it
// could not get a connection while bulk apply traffic held them all.
type boundedPoolDB struct {
	slots    chan struct{}
	response []byte

	mu       sync.Mutex
	acquires int
}

func newBoundedPoolDB(conns int, response []byte) *boundedPoolDB {
	db := &boundedPoolDB{slots: make(chan struct{}, conns), response: response}
	for i := 0; i < conns; i++ {
		db.slots <- struct{}{}
	}
	return db
}

// hold occupies n connections until the returned release func runs. It stands
// in for sustained write load: long apply/flush transactions pinning the pool.
func (db *boundedPoolDB) hold(t *testing.T, n int) func() {
	t.Helper()
	for i := 0; i < n; i++ {
		select {
		case <-db.slots:
		case <-time.After(time.Second):
			t.Fatalf("could not occupy connection %d", i)
		}
	}
	var once sync.Once
	return func() {
		once.Do(func() {
			for i := 0; i < n; i++ {
				db.slots <- struct{}{}
			}
		})
	}
}

func (db *boundedPoolDB) QueryRow(ctx context.Context, _ string, _ ...any) pgx.Row {
	select {
	case <-db.slots:
	case <-ctx.Done():
		return fakeJournalRow{err: ctx.Err()}
	}
	defer func() { db.slots <- struct{}{} }()
	db.mu.Lock()
	db.acquires++
	db.mu.Unlock()
	return fakeJournalRow{response: db.response}
}

func (db *boundedPoolDB) Query(context.Context, string, ...any) (pgx.Rows, error) {
	return nil, errors.New("unused")
}

func (db *boundedPoolDB) Close() {}

func (db *boundedPoolDB) acquireCount() int {
	db.mu.Lock()
	defer db.mu.Unlock()
	return db.acquires
}

func leaseFactsResponse(t *testing.T) []byte {
	t.Helper()
	now := time.Now().UnixMilli()
	raw, err := json.Marshal(map[string]any{
		"managed":             true,
		"current":             true,
		"tenantKey":           "tenant",
		"managerEpoch":        "7",
		"managerRuntimeId":    "mr-1",
		"authorityRuntimeSeq": "3",
		"authorityRuntimeId":  "ar-1",
		"authorityInstanceId": "ai-1",
		"dbTimeMs":            strconv.FormatInt(now, 10),
		"expiresAtDbMs":       strconv.FormatInt(now+15_000, 10),
	})
	if err != nil {
		t.Fatal(err)
	}
	return raw
}

func isolationTestLog(t *testing.T, data, liveness journalDB) *Log {
	t.Helper()
	return &Log{
		pool:         data,
		livenessPool: liveness,
		life:         context.Background(),
		cfg: Config{
			TenantID: "tenant", VolumeID: "vol", Branch: "main",
			AuthorityRuntimeID: "ar-1", CallTimeout: 30 * time.Second,
		},
		capability:   "cap",
		managerEpoch: 7,
		runtimeSeq:   3,
	}
}

// The root-fix regression test. Before the fix the fencing probe shared the
// data-plane pool, so saturating apply traffic starved it: the probe returned
// a context error, which NEVER extends the guard's deadline, and the child
// fenced itself under load. With the reserved liveness connection the answer
// arrives at full speed no matter how busy the journal is.
func TestSaturatedApplyTrafficCannotStarveTheFencingProbe(t *testing.T) {
	response := leaseFactsResponse(t)
	data := newBoundedPoolDB(defaultMaxConns, response)
	liveness := newBoundedPoolDB(1, response)
	log := isolationTestLog(t, data, liveness)

	// Sustained write load: every data-plane connection is pinned.
	release := data.hold(t, defaultMaxConns)
	defer release()

	// The guard bounds one probe; a probe that cannot answer inside it is
	// ambiguous and extends nothing.
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()

	start := time.Now()
	facts, err := log.AuthorityLeaseFacts(ctx)
	elapsed := time.Since(start)

	if err != nil {
		t.Fatalf("lease-facts probe failed under saturated apply traffic: %v", err)
	}
	if !facts.Current {
		t.Fatalf("lease-facts probe answered current=false under load")
	}
	if elapsed > time.Second {
		t.Fatalf("lease-facts probe queued behind the data plane (%v)", elapsed)
	}
	if data.acquireCount() != 0 {
		t.Fatalf("the fencing probe took %d data-plane connections; it must take none", data.acquireCount())
	}
	if liveness.acquireCount() != 1 {
		t.Fatalf("the fencing probe used the reserved connection %d times, want 1", liveness.acquireCount())
	}
}

// The same run WITHOUT the isolation, pinned so the regression can never be
// silently reintroduced: sharing the seam reproduces the incident exactly.
func TestSharedPoolReproducesTheStarvedFencingProbe(t *testing.T) {
	response := leaseFactsResponse(t)
	shared := newBoundedPoolDB(defaultMaxConns, response)
	log := isolationTestLog(t, shared, shared)

	release := shared.hold(t, defaultMaxConns)
	defer release()

	ctx, cancel := context.WithTimeout(context.Background(), 200*time.Millisecond)
	defer cancel()

	if _, err := log.AuthorityLeaseFacts(ctx); err == nil {
		t.Fatal("expected the shared-seam probe to starve under saturated apply traffic")
	} else if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("expected a deadline (starvation) failure, got %v", err)
	}
}

// livenessDB must resolve to the reserved connection whenever a production
// open path installed one, and to the single seam a directly constructed Log
// was handed otherwise. There is no per-call choice and no fallback once the
// reserved connection exists.
func TestLivenessSeamSelection(t *testing.T) {
	data := newBoundedPoolDB(1, nil)
	liveness := newBoundedPoolDB(1, nil)

	isolated := isolationTestLog(t, data, liveness)
	if isolated.livenessDB() != journalDB(liveness) {
		t.Fatal("an isolated Log must probe through the reserved connection")
	}

	direct := isolationTestLog(t, data, nil)
	if direct.livenessDB() != journalDB(data) {
		t.Fatal("a directly constructed Log must probe through its only seam")
	}
}

// The reserved connection is configured as exactly one warm connection, and
// tags itself distinctly in pg_stat_activity so operators can see that the
// fencing clock is not sharing the data plane.
func TestLivenessPoolConfigReservesOneWarmConnection(t *testing.T) {
	pc, err := livenessPoolConfig(Config{
		DSN:             "postgres://user:pw@127.0.0.1:5432/db",
		ApplicationName: "portablefs-authority",
		MaxConns:        16,
	})
	if err != nil {
		t.Fatal(err)
	}
	if pc.MaxConns != 1 {
		t.Fatalf("liveness MaxConns = %d, want 1", pc.MaxConns)
	}
	if pc.MinConns != 1 {
		t.Fatalf("liveness MinConns = %d, want 1 (the connection must stay warm)", pc.MinConns)
	}
	if got := pc.ConnConfig.RuntimeParams["application_name"]; got != "portablefs-authority-liveness" {
		t.Fatalf("liveness application_name = %q", got)
	}
}
