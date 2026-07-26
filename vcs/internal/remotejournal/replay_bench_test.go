package remotejournal

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"

	"github.com/trendup-ai/portablefs/vcs/internal/wal"
)

// journalFixture is a pre-encoded durable journal suffix: canonical PFR1
// payloads with their stored hash and chain digests, exactly as
// pfj.journal_read_page would serve them.
type journalFixture struct {
	rows       []pageRow
	tip        [32]byte
	totalBytes int64
}

func buildJournalFixture(tb testing.TB, records int, dataBytes int) journalFixture {
	tb.Helper()
	fixture := journalFixture{rows: make([]pageRow, records)}
	data := make([]byte, dataBytes)
	for i := range data {
		data[i] = byte(i)
	}
	chain := [32]byte{}
	for i := 0; i < records; i++ {
		record := wal.Record{
			Seq:    uint64(i),
			Op:     wal.OpWrite,
			Path:   "bench/file",
			Offset: int64(i) * int64(dataBytes),
			Data:   data,
		}
		payload, err := wal.EncodePFR1(&record)
		if err != nil {
			tb.Fatalf("encode fixture record %d: %v", i, err)
		}
		hash := wal.ChainDigestBytes([32]byte{}, payload)
		chain = wal.ChainDigestBytes(chain, payload)
		fixture.rows[i] = pageRow{
			seq:         uint64(i),
			payload:     payload,
			recordHash:  hex.EncodeToString(hash[:]),
			chainDigest: hex.EncodeToString(chain[:]),
		}
		fixture.totalBytes += int64(len(payload))
	}
	fixture.tip = chain
	return fixture
}

// pageServingDB is a fake journalDB that answers pfj.journal_read_page with
// bounded pages from a journalFixture at a configurable per-fetch latency
// (simulated network RTT), and pfj.journal_bound_head with a canned head
// snapshot. It honors context cancellation exactly like a live pgx query.
type pageServingDB struct {
	fixture      journalFixture
	fetchLatency time.Duration
	headJSON     []byte
	fetches      atomic.Int64

	// fetchGate, when non-nil, blocks every page fetch until the gate closes
	// (or the query context ends). Used by cancellation tests.
	fetchGate chan struct{}
	// fetchStarted, when non-nil, receives one signal per page fetch.
	fetchStarted chan struct{}
	// failFrom injects a deterministic per-position fetch failure.
	failFrom map[int64]error
}

func (db *pageServingDB) Query(ctx context.Context, _ string, args ...any) (pgx.Rows, error) {
	db.fetches.Add(1)
	if db.fetchStarted != nil {
		select {
		case db.fetchStarted <- struct{}{}:
		default:
		}
	}
	if db.fetchGate != nil {
		select {
		case <-db.fetchGate:
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	if db.fetchLatency > 0 {
		select {
		case <-time.After(db.fetchLatency):
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	from := args[8].(int64)
	maxRecords := args[9].(int)
	maxBytes := args[10].(int64)
	if err := db.failFrom[from]; err != nil {
		return nil, err
	}
	rows := &fixtureRows{}
	var pageBytes int64
	for i := from; i < int64(len(db.fixture.rows)) && len(rows.rows) < maxRecords; i++ {
		row := db.fixture.rows[i]
		pageBytes += int64(len(row.payload))
		if pageBytes > maxBytes && len(rows.rows) > 0 {
			break
		}
		rows.rows = append(rows.rows, row)
	}
	return rows, nil
}

func (db *pageServingDB) QueryRow(context.Context, string, ...any) pgx.Row {
	return fakeJournalRow{response: db.headJSON}
}

func (db *pageServingDB) Close() {}

// fixtureRows implements the minimal pgx.Rows surface queryPage consumes.
type fixtureRows struct {
	rows []pageRow
	idx  int
}

func (r *fixtureRows) Next() bool { r.idx++; return r.idx <= len(r.rows) }

func (r *fixtureRows) Scan(dest ...any) error {
	if len(dest) != 4 {
		return fmt.Errorf("fixture rows: got %d scan destinations", len(dest))
	}
	row := r.rows[r.idx-1]
	*(dest[0].(*int64)) = int64(row.seq)
	*(dest[1].(*[]byte)) = row.payload
	*(dest[2].(*string)) = row.recordHash
	*(dest[3].(*string)) = row.chainDigest
	return nil
}

func (r *fixtureRows) Close()                                       {}
func (r *fixtureRows) Err() error                                   { return nil }
func (r *fixtureRows) CommandTag() pgconn.CommandTag                { return pgconn.CommandTag{} }
func (r *fixtureRows) FieldDescriptions() []pgconn.FieldDescription { return nil }
func (r *fixtureRows) Values() ([]any, error)                       { return nil, nil }
func (r *fixtureRows) RawValues() [][]byte                          { return nil }
func (r *fixtureRows) Conn() *pgx.Conn                              { return nil }

// replayHeadJSON is the exact post-replay head snapshot a read-only replica
// verifies: unchanged base, the fixture's durable head, live status.
func replayHeadJSON(fixture journalFixture) []byte {
	return []byte(fmt.Sprintf(`{
		"generationId":"jgen-bench","tenantId":"tenant-b","volumeId":"volume-b",
		"branchId":"branch-b","branchName":"main","epoch":"1",
		"recordCodec":"pfr1","controlCodec":"pfc1","baseCommitId":"commit-base",
		"baseSeq":"0","baseDigest":"%s","nextSeq":"%d","tipDigest":"%s",
		"physicalTrimmedSeq":"0","status":"active",
		"backlogBytes":"%d","backlogRecords":"%d",
		"quotaBacklogBytes":"17179869184","quotaBacklogRecords":"1048576",
		"claimedAt":"1","updatedAt":"1",
		"dbTimeMs":"1","requestAuthorityRuntimeSeq":"4"
	}`, strings.Repeat("0", 64), len(fixture.rows), hex.EncodeToString(fixture.tip[:]),
		fixture.totalBytes, len(fixture.rows)))
}

// replayLog builds a read-only Log positioned to replay the whole fixture
// (base 0 .. durable head) from the given fake database.
func replayLog(db journalDB, fixture journalFixture) *Log {
	return &Log{
		pool: db, life: context.Background(), readOnly: true,
		cfg: Config{
			TenantID: "tenant-b", VolumeID: "volume-b", Branch: "main",
			AuthorityRuntimeID: "runtime-1", CallTimeout: 30 * time.Second,
		},
		generationID: "jgen-bench", branchID: "branch-b", epoch: 1,
		capability: "authority-capability-1", managerEpoch: 2, runtimeSeq: 4,
		durableSeq: uint64(len(fixture.rows)), durableTip: fixture.tip,
		poisonedCh: make(chan struct{}),
	}
}

// BenchmarkReplayIntoColdStart measures a full cold replay (verification and
// apply included) against a page source with a simulated per-fetch RTT. The
// fixture is 32 pages x 256 records x 4 KiB writes (~33 MiB), so page apply
// cost (two SHA-256 passes + strict decode) is comparable to a small RTT —
// the regime where overlapping fetch with apply pays the most.
func BenchmarkReplayIntoColdStart(b *testing.B) {
	fixture := buildJournalFixture(b, 32*256, 4096)
	head := replayHeadJSON(fixture)
	for _, rtt := range []time.Duration{0, time.Millisecond, 2 * time.Millisecond, 10 * time.Millisecond} {
		b.Run(fmt.Sprintf("fetchRTT=%s", rtt), func(b *testing.B) {
			db := &pageServingDB{fixture: fixture, fetchLatency: rtt, headJSON: head}
			l := replayLog(db, fixture)
			b.SetBytes(fixture.totalBytes)
			b.ResetTimer()
			for i := 0; i < b.N; i++ {
				applied := 0
				if err := l.ReplayInto(func(wal.Record) error {
					applied++
					return nil
				}); err != nil {
					b.Fatalf("replay: %v", err)
				}
				if applied != len(fixture.rows) {
					b.Fatalf("applied %d records, want %d", applied, len(fixture.rows))
				}
			}
		})
	}
}

// commitSinkDB is a fake journalDB that acknowledges pfj.journal_append with
// an exact, accounting-consistent response after a configurable
// per-transaction latency (simulated commit RTT: network + synchronous_commit
// flush). It counts transactions so benchmarks can report commits per flush.
type commitSinkDB struct {
	commitLatency  time.Duration
	commits        atomic.Int64
	backlogBytes   int64
	backlogRecords int64
}

func (db *commitSinkDB) QueryRow(ctx context.Context, _ string, args ...any) pgx.Row {
	db.commits.Add(1)
	if db.commitLatency > 0 {
		select {
		case <-time.After(db.commitLatency):
		case <-ctx.Done():
			return fakeJournalRow{err: ctx.Err()}
		}
	}
	firstSeq := args[10].(int64)
	payloads := args[11].([][]byte)
	endTip := args[13].(string)
	for _, p := range payloads {
		db.backlogBytes += int64(len(p))
	}
	db.backlogRecords += int64(len(payloads))
	body := fmt.Sprintf(`{
		"generationId":"jgen-bench","epoch":"1","nextSeq":"%d","tipDigest":"%s",
		"appended":"%d","duplicated":"0","replayed":false,
		"currentBaseCommitId":"commit-base","currentBaseSeq":"0","currentBaseDigest":"%s",
		"currentPhysicalTrimmedSeq":"0","currentBacklogBytes":"%d","currentBacklogRecords":"%d",
		"currentQuotaBacklogBytes":"4611686018427387904","currentQuotaBacklogRecords":"4611686018427387904",
		"currentCut":null
	}`, firstSeq+int64(len(payloads)), endTip, len(payloads),
		strings.Repeat("0", 64), db.backlogBytes, db.backlogRecords)
	return fakeJournalRow{response: []byte(body)}
}

func (db *commitSinkDB) Query(context.Context, string, ...any) (pgx.Rows, error) {
	return nil, errors.New("commit sink: unexpected Query")
}

func (db *commitSinkDB) Close() {}

// commitLog builds a writable Log whose commits land in the given sink.
func commitLog(db journalDB) *Log {
	return &Log{
		pool: db, life: context.Background(),
		cfg: Config{
			TenantID: "tenant-b", VolumeID: "volume-b", Branch: "main",
			LeaseID: "lease-1", FencingToken: 3, AuthorityRuntimeID: "runtime-1",
			CallTimeout: 30 * time.Second, MaxStagedBytes: defaultMaxStagedBytes,
		},
		generationID: "jgen-bench", branchID: "branch-b", epoch: 1,
		capability: "authority-capability-1", managerEpoch: 2, runtimeSeq: 4,
		baseCommitID: "commit-base",
		quotaBytes:   1 << 62, quotaRecords: 1 << 62,
		poisonedCh: make(chan struct{}),
	}
}

// BenchmarkFlushCommitGroups measures one write-back flush batch (records
// staged, then CommitThrough) against a commit sink with a per-transaction
// latency. A flush larger than the journal's group record cap pays one full
// commit round trip per group; the commits/flush metric makes the RTT
// amplification explicit.
func BenchmarkFlushCommitGroups(b *testing.B) {
	data := make([]byte, 1024)
	for _, flushRecords := range []int{128, 512} {
		for _, rtt := range []time.Duration{0, 2 * time.Millisecond, 10 * time.Millisecond} {
			b.Run(fmt.Sprintf("records=%d/commitRTT=%s", flushRecords, rtt), func(b *testing.B) {
				db := &commitSinkDB{commitLatency: rtt}
				l := commitLog(db)
				b.ResetTimer()
				for i := 0; i < b.N; i++ {
					records := make([]wal.Record, flushRecords)
					for j := range records {
						records[j] = wal.Record{
							Op:     wal.OpWrite,
							Path:   "bench/file",
							Offset: int64(j) * int64(len(data)),
							Data:   data,
						}
					}
					_, end, err := l.AppendBatchBuffered(records)
					if err != nil {
						b.Fatalf("stage flush: %v", err)
					}
					if err := l.CommitThrough(end - 1); err != nil {
						b.Fatalf("commit flush: %v", err)
					}
				}
				b.StopTimer()
				b.ReportMetric(float64(db.commits.Load())/float64(b.N), "commits/flush")
			})
		}
	}
}
