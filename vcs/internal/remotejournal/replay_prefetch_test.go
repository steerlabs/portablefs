package remotejournal

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgconn"

	"github.com/trendup-ai/portablefs/vcs/internal/pfj3"
	"github.com/trendup-ai/portablefs/vcs/internal/wal"
)

const testPageRecords = 256 // wal.ProductionLogBounds().MaxReplayPageRecords

// TestReplayPrefetchAppliesAllRecordsInLSNOrder proves the pipelined replay
// is observably identical to the sequential one on the happy path: every
// record arrives exactly once, in LSN order, the chain reaches the tip, and
// the post-replay head verification still runs.
func TestReplayPrefetchAppliesAllRecordsInLSNOrder(t *testing.T) {
	fixture := buildJournalFixture(t, 3*testPageRecords, 16)
	db := &pageServingDB{fixture: fixture, headJSON: replayHeadJSON(fixture)}
	l := replayLog(db, fixture)

	next := uint64(0)
	if err := l.ReplayInto(func(r wal.Record) error {
		if r.Seq != next {
			t.Fatalf("record %d arrived when %d was expected", r.Seq, next)
		}
		next++
		return nil
	}); err != nil {
		t.Fatalf("replay: %v", err)
	}
	if next != uint64(len(fixture.rows)) {
		t.Fatalf("applied %d records, want %d", next, len(fixture.rows))
	}
	if got := db.fetches.Load(); got != 3 {
		t.Fatalf("replay fetched %d pages, want 3", got)
	}
}

// TestReplayPrefetchFetchesNextPageWhileApplying proves the overlap the
// pipeline exists for, without timing assertions: while the first record of
// page one is still blocked in the apply callback, the fetch of page two must
// already have started.
func TestReplayPrefetchFetchesNextPageWhileApplying(t *testing.T) {
	fixture := buildJournalFixture(t, 2*testPageRecords, 16)
	started := make(chan struct{}, 8)
	db := &pageServingDB{fixture: fixture, headJSON: replayHeadJSON(fixture), fetchStarted: started}
	l := replayLog(db, fixture)

	release := make(chan struct{})
	done := make(chan error, 1)
	go func() {
		blocked := false
		done <- l.ReplayInto(func(r wal.Record) error {
			if !blocked {
				blocked = true
				<-release
			}
			return nil
		})
	}()

	// Signal one: the fetch of page one. Signal two must arrive while the
	// apply callback is still blocked on the first record of page one.
	for i := 0; i < 2; i++ {
		select {
		case <-started:
		case <-time.After(5 * time.Second):
			t.Fatalf("fetch %d did not start while page one was applying", i+1)
		}
	}
	close(release)
	if err := <-done; err != nil {
		t.Fatalf("replay: %v", err)
	}
}

// TestReplayPrefetchCorruptChainFailsMidPageIdentically corrupts the digest
// chain of the first record of page two. The prefetched fetch must not change
// what gets applied: page one applies completely, the corrupt record is never
// delivered, and the failure is the same typed divergence error the
// sequential code produced.
func TestReplayPrefetchCorruptChainFailsMidPageIdentically(t *testing.T) {
	fixture := buildJournalFixture(t, 2*testPageRecords, 16)
	corrupted := journalFixture{
		rows:       append([]pageRow(nil), fixture.rows...),
		tip:        fixture.tip,
		totalBytes: fixture.totalBytes,
	}
	corrupted.rows[testPageRecords].chainDigest = strings.Repeat("f", 64)
	db := &pageServingDB{fixture: corrupted, headJSON: replayHeadJSON(fixture)}
	l := replayLog(db, fixture)

	applied := uint64(0)
	err := l.ReplayInto(func(r wal.Record) error {
		applied++
		return nil
	})
	if !errors.Is(err, wal.ErrJournalDiverged) || !strings.Contains(err.Error(), "breaks the digest chain") {
		t.Fatalf("corrupt chain error = %v, want ErrJournalDiverged (digest chain)", err)
	}
	if applied != testPageRecords {
		t.Fatalf("applied %d records, want exactly page one (%d)", applied, testPageRecords)
	}
}

// TestReplayPrefetchErrorSurfacesAfterCurrentPageApplies injects a
// deterministic, non-retryable failure into the fetch of page two. Every
// record of page one must still apply (the prefetch failure may not corrupt
// or truncate the page currently applying), and the error surfaces afterwards
// exactly as the sequential fetch would have reported it.
func TestReplayPrefetchErrorSurfacesAfterCurrentPageApplies(t *testing.T) {
	fixture := buildJournalFixture(t, 2*testPageRecords, 16)
	db := &pageServingDB{
		fixture:  fixture,
		headJSON: replayHeadJSON(fixture),
		failFrom: map[int64]error{testPageRecords: &pgconn.PgError{Code: "42883", Message: "undefined function"}},
	}
	l := replayLog(db, fixture)

	applied := uint64(0)
	err := l.ReplayInto(func(r wal.Record) error {
		applied++
		return nil
	})
	if err == nil || !strings.Contains(err.Error(), "read page from 256") {
		t.Fatalf("prefetch failure error = %v, want read-page failure at 256", err)
	}
	var pgErr *pgconn.PgError
	if !errors.As(err, &pgErr) || pgErr.Code != "42883" {
		t.Fatalf("prefetch failure lost the SQL cause: %v", err)
	}
	if applied != testPageRecords {
		t.Fatalf("applied %d records, want all of page one (%d)", applied, testPageRecords)
	}
}

// TestReplayPrefetchCancellationDoesNotLeak aborts a replay whose page fetch
// is parked in the database call and proves both that ReplayInto returns
// promptly with the unresolved-outcome error and that the prefetch goroutine
// exits (no goroutine survives the abandoned stream).
func TestReplayPrefetchCancellationDoesNotLeak(t *testing.T) {
	fixture := buildJournalFixture(t, 2*testPageRecords, 16)
	gate := make(chan struct{})
	started := make(chan struct{}, 8)
	db := &pageServingDB{
		fixture: fixture, headJSON: replayHeadJSON(fixture),
		fetchGate: gate, fetchStarted: started,
	}
	l := replayLog(db, fixture)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	l.life = ctx

	baseline := runtime.NumGoroutine()
	done := make(chan error, 1)
	go func() {
		done <- l.ReplayInto(func(wal.Record) error { return nil })
	}()
	select {
	case <-started:
	case <-time.After(5 * time.Second):
		t.Fatal("first page fetch never started")
	}
	cancel()
	select {
	case err := <-done:
		if !errors.Is(err, ErrUnknownOutcome) {
			t.Fatalf("aborted replay error = %v, want ErrUnknownOutcome", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("aborted replay did not return")
	}
	deadline := time.Now().Add(5 * time.Second)
	for runtime.NumGoroutine() > baseline {
		if time.Now().After(deadline) {
			t.Fatalf("prefetch goroutine leaked: %d goroutines, baseline %d", runtime.NumGoroutine(), baseline)
		}
		time.Sleep(5 * time.Millisecond)
	}
}

// TestRecordsBelowIntoBoundaryIgnoresPageTailWithoutOverfetch replays a
// prefix that ends inside page two: the page tail past the boundary is
// ignored and the stream never fetches a page the sequential code would not
// have fetched.
func TestRecordsBelowIntoBoundaryIgnoresPageTailWithoutOverfetch(t *testing.T) {
	fixture := buildJournalFixture(t, 3*testPageRecords, 16)
	db := &pageServingDB{fixture: fixture, headJSON: replayHeadJSON(fixture)}
	l := replayLog(db, fixture)

	const boundary = testPageRecords + 44
	next := uint64(0)
	if err := l.RecordsBelowInto(boundary, func(r wal.Record) error {
		if r.Seq != next {
			t.Fatalf("record %d arrived when %d was expected", r.Seq, next)
		}
		next++
		return nil
	}); err != nil {
		t.Fatalf("records below: %v", err)
	}
	if next != boundary {
		t.Fatalf("applied %d records, want %d", next, boundary)
	}
	if got := db.fetches.Load(); got != 2 {
		t.Fatalf("boundary replay fetched %d pages, want 2", got)
	}
}

// TestReplayEntriesPrefetchAppliesAllEntriesInLSNOrder covers the PFJ3 entry
// stream over the same prefetched page pipeline: every entry arrives exactly
// once, in LSN order, through the identical verification.
func TestReplayEntriesPrefetchAppliesAllEntriesInLSNOrder(t *testing.T) {
	const entries = 2*testPageRecords + 32
	fixture := journalFixture{rows: make([]pageRow, entries)}
	chain := [32]byte{}
	for i := 0; i < entries; i++ {
		entry := pfj3.JournalEntry{
			LSN:  uint64(i),
			Tree: &wal.Record{Seq: uint64(i), Op: wal.OpCreate, Path: fmt.Sprintf("e%04d", i), Mode: 0o644},
		}
		payload, err := pfj3.Encode(&entry)
		if err != nil {
			t.Fatalf("encode entry %d: %v", i, err)
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

	head := []byte(strings.NewReplacer(
		`"recordCodec":"pfr1"`, `"recordCodec":"pfj3"`,
		`"controlCodec":"pfc1"`, `"controlCodec":"pfc2"`,
	).Replace(string(replayHeadJSON(fixture))))
	db := &pageServingDB{fixture: fixture, headJSON: head}
	l := replayLog(db, fixture)
	l.recordCodec, l.controlCodec = pfj3RecordCodec, pfc2ControlCodec

	next := uint64(0)
	if err := l.ReplayEntriesInto(func(e pfj3.JournalEntry) error {
		if e.LSN != next || e.Tree == nil || e.Tree.Seq != next {
			t.Fatalf("entry %d (tree %+v) arrived when %d was expected", e.LSN, e.Tree, next)
		}
		next++
		return nil
	}); err != nil {
		t.Fatalf("replay entries: %v", err)
	}
	if next != entries {
		t.Fatalf("applied %d entries, want %d", next, entries)
	}
	if got := db.fetches.Load(); got != 3 {
		t.Fatalf("entry replay fetched %d pages, want 3", got)
	}
}

// TestReplayPrefetchEmptyPageDiverges keeps the fail-closed divergence error
// when the journal serves no rows inside the durable range.
func TestReplayPrefetchEmptyPageDiverges(t *testing.T) {
	fixture := buildJournalFixture(t, testPageRecords, 16)
	short := journalFixture{
		rows: fixture.rows[:testPageRecords-1],
		tip:  fixture.tip, totalBytes: fixture.totalBytes,
	}
	db := &pageServingDB{fixture: short, headJSON: replayHeadJSON(fixture)}
	l := replayLog(db, fixture)

	err := l.ReplayInto(func(wal.Record) error { return nil })
	if !errors.Is(err, wal.ErrJournalDiverged) || !strings.Contains(err.Error(), "no rows at LSN 255") {
		t.Fatalf("empty page error = %v, want ErrJournalDiverged (no rows at LSN 255)", err)
	}
}
