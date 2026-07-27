package remotejournal

import (
	"context"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/steerlabs/portablefs/vcs/internal/wal"
)

// pageRow is one row of pfj.journal_read_page.
type pageRow struct {
	seq         uint64
	payload     []byte
	recordHash  string
	chainDigest string
}

// readPage fetches one bounded replay page ([from, …) capped at 256 records /
// 16 MiB), retrying transient failures (reads are idempotent). ctx bounds the
// retry loop and every SQL call: it is the page stream's context (a child of
// the lifecycle context), so an abandoned stream stops fetching promptly.
func (l *Log) readPage(ctx context.Context, from uint64) ([]pageRow, error) {
	bounds := wal.ProductionLogBounds()
	backoff := retryBackoffFloor
	for {
		rows, err := l.queryPage(ctx, from, bounds.MaxReplayPageRecords, bounds.MaxReplayPageBytes)
		if err == nil {
			return rows, nil
		}
		if typed := typedError(err); typed != nil {
			return nil, typed
		}
		if !retryableSQLFailure(err) {
			return nil, fmt.Errorf("remotejournal: read page from %d: %w", from, err)
		}
		select {
		case <-ctx.Done():
			return nil, fmt.Errorf("%w: read page from %d: %v (last attempt: %v)", ErrUnknownOutcome, from, ctx.Err(), err)
		case <-time.After(backoff):
		}
		if backoff *= 2; backoff > retryBackoffCeil {
			backoff = retryBackoffCeil
		}
	}
}

func (l *Log) queryPage(ctx context.Context, from uint64, maxRecords int, maxBytes int64) ([]pageRow, error) {
	fromSQL, err := checkedSQLBigint("read page sequence", from)
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(ctx, l.cfg.CallTimeout)
	defer cancel()
	rows, err := l.pool.Query(ctx,
		`SELECT seq, payload, record_hash, chain_digest FROM pfj.journal_read_page($1,$2,$3,$4,$5,$6,$7,$8,$9,$10,$11)`,
		l.generationID, int64(l.epoch), l.capability, l.cfg.LeaseID, l.cfg.FencingToken,
		l.managerEpoch, l.runtimeSeq, l.cfg.AuthorityRuntimeID,
		fromSQL, maxRecords, maxBytes,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []pageRow
	for rows.Next() {
		var r pageRow
		var seq int64
		if err := rows.Scan(&seq, &r.payload, &r.recordHash, &r.chainDigest); err != nil {
			return nil, err
		}
		r.seq = uint64(seq)
		out = append(out, r)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	return out, nil
}

// fetchedPage is one prefetched replay page, or the fetch failure that ended
// the page stream.
type fetchedPage struct {
	rows []pageRow
	err  error
}

// pageStream serves the bounded replay pages covering [from, to) from one
// producer goroutine, exactly ONE page ahead of its consumer. Roughly half of
// a cold replay is idle network wait, so overlapping the fetch of page N+1
// with the verify+apply of page N nearly halves wall time in the balanced
// regime — while the unbuffered channel keeps the memory bound at one extra
// page (the producer cannot start page N+2 until page N+1 is handed over).
//
// The producer performs ONLY idempotent reads; every verification (hash,
// digest chain, strict decode, LSN continuity) stays on the consuming
// goroutine, exactly as strict and in the same order as the sequential code,
// so a bad page fails replay with the identical typed error. A fetch failure
// for page N+1 is parked in the channel and surfaces only after the consumer
// finishes page N. The producer advances by whole served pages; if the
// journal serves diverging rows the consumer fails and abandons the stream,
// so the producer's optimistic position never becomes an applied fact.
type pageStream struct {
	pages  <-chan fetchedPage
	cancel context.CancelFunc
}

func (l *Log) startPageStream(from, to uint64) *pageStream {
	ctx, cancel := context.WithCancel(l.life)
	pages := make(chan fetchedPage)
	go func() {
		defer close(pages)
		for next := from; next < to; {
			rows, err := l.readPage(ctx, next)
			// Deliver unconditionally: the consumer either receives in
			// next() or drains in stop(), so this send never blocks forever,
			// and a terminal fetch error (a canceled lifecycle included) is
			// never swallowed by a racing close.
			pages <- fetchedPage{rows: rows, err: err}
			if err != nil || len(rows) == 0 {
				return // the consumer turns these into the replay failure
			}
			next += uint64(len(rows))
		}
	}()
	return &pageStream{pages: pages, cancel: cancel}
}

// next blocks for the next prefetched page. ok is false once the producer has
// served the whole range.
func (s *pageStream) next() (fetchedPage, bool) {
	fetched, ok := <-s.pages
	return fetched, ok
}

// stop cancels the producer and joins it (the channel close), so an abandoned
// or failed replay never leaks the prefetch goroutine or an in-flight query.
func (s *pageStream) stop() {
	s.cancel()
	for range s.pages {
	}
}

// streamRange streams the durable records [from, to) in LSN order with
// bounded memory (one page applying + one page prefetched), verifying for
// every record: LSN contiguity, the record hash over the exact stored bytes,
// the digest chain recomputed from chainStart, strict PFR1 decode, and the
// embedded LSN. It returns the chain digest at the exclusive end boundary.
func (l *Log) streamRange(from, to uint64, chainStart [32]byte, fn func(wal.Record) error) ([32]byte, error) {
	chain := chainStart
	stream := l.startPageStream(from, to)
	defer stream.stop()
	for next := from; next < to; {
		fetched, ok := stream.next()
		if !ok {
			// Unreachable while rows verify: the producer serves at least the
			// consumer's position. Fail closed rather than spin.
			return chain, fmt.Errorf("%w: page stream ended before LSN %d (head %d)", wal.ErrJournalDiverged, next, to)
		}
		if fetched.err != nil {
			return chain, fetched.err
		}
		page := fetched.rows
		if len(page) == 0 {
			return chain, fmt.Errorf("%w: journal returned no rows at LSN %d (head %d)", wal.ErrJournalDiverged, next, to)
		}
		for _, row := range page {
			if next >= to {
				break // page may extend past the requested range; ignore the tail
			}
			if row.seq != next {
				return chain, fmt.Errorf("%w: journal rows are not contiguous (want LSN %d, got %d)", wal.ErrJournalDiverged, next, row.seq)
			}
			hash := wal.ChainDigestBytes([32]byte{}, row.payload)
			if hex.EncodeToString(hash[:]) != row.recordHash {
				return chain, fmt.Errorf("%w: record %d payload does not match its stored hash", wal.ErrJournalDiverged, row.seq)
			}
			chain = wal.ChainDigestBytes(chain, row.payload)
			if hex.EncodeToString(chain[:]) != row.chainDigest {
				return chain, fmt.Errorf("%w: record %d breaks the digest chain", wal.ErrJournalDiverged, row.seq)
			}
			rec, derr := wal.DecodePFR1(row.payload)
			if derr != nil {
				return chain, fmt.Errorf("%w: record %d is not canonical PFR1: %v", wal.ErrJournalDiverged, row.seq, derr)
			}
			if rec.Seq != row.seq {
				return chain, fmt.Errorf("%w: record payload carries LSN %d, row says %d", wal.ErrJournalDiverged, rec.Seq, row.seq)
			}
			if err := fn(rec); err != nil {
				return chain, err
			}
			next++
		}
	}
	return chain, nil
}

// ReplayInto streams the retained durable suffix [base, durableHead) in LSN
// order with bounded page memory, verifying hashes, the digest chain from the
// base anchor to the tip, canonical PFR1 decode, and LSN continuity. After
// the stream it re-reads the head identity and fails unless it is unchanged
// and current — the caller publishes readiness only on nil.
func (l *Log) ReplayInto(fn func(wal.Record) error) error {
	if err := l.requireRecordLog("ReplayInto"); err != nil {
		return err
	}
	l.mu.Lock()
	from, to := l.baseSeq, l.durableSeq
	chainStart, wantTip := l.baseDigest, l.durableTip
	l.mu.Unlock()

	chain, err := l.streamRange(from, to, chainStart, fn)
	if err != nil {
		return err
	}
	if chain != wantTip {
		return fmt.Errorf("%w: replayed chain does not end at the journal tip", wal.ErrJournalDiverged)
	}
	return l.verifyHeadAfterReplay(from, to, wantTip)
}

// verifyHeadAfterReplay re-reads the head identity after a full replay and
// fails closed unless the generation is unchanged and (for a writer) still
// bound to this exact fence with a database-time-live lease.
func (l *Log) verifyHeadAfterReplay(from, to uint64, tip [32]byte) error {
	head, err := l.fetchHead()
	if err != nil {
		return err
	}
	if head == nil {
		return fmt.Errorf("%w: journal generation disappeared during replay", wal.ErrJournalDiverged)
	}
	validated, err := l.validateGenerationSnapshot(head, !l.readOnly)
	if err != nil {
		return fmt.Errorf("%w: invalid post-replay generation snapshot: %v", wal.ErrJournalDiverged, err)
	}
	if validated.baseSeq != from {
		return fmt.Errorf("%w: journal base moved from %d to %d during replay", wal.ErrJournalDiverged, from, validated.baseSeq)
	}
	if l.readOnly {
		// A live writer may append while a read-only replica replays; the
		// replica serves the verified snapshot. Its own range is proven by the
		// per-record chain; only identity/retention movement fails the replay.
		return nil
	}
	if validated.nextSeq != to || validated.tipDigest != tip {
		return fmt.Errorf("%w: journal head advanced during replay (another writer?)", wal.ErrJournalDiverged)
	}
	if head.WriterLeaseLive == nil || !*head.WriterLeaseLive {
		return fmt.Errorf("%w: writer lease is not live at database time after replay", ErrFenced)
	}
	return nil
}

// RecordsBelowInto streams every durable record with Seq < seq in LSN order.
// The range is verified record by record against the stored hash/chain (the
// chain anchor is the journal base, so callers always receive an exact,
// proven prefix).
func (l *Log) RecordsBelowInto(seq uint64, fn func(wal.Record) error) error {
	if err := l.requireRecordLog("RecordsBelowInto"); err != nil {
		return err
	}
	l.mu.Lock()
	from := l.baseSeq
	to := l.durableSeq
	chainStart := l.baseDigest
	l.mu.Unlock()
	if seq < to {
		to = seq
	}
	if from > to {
		return fmt.Errorf("remotejournal: records below %d are compacted (base %d)", seq, from)
	}
	_, err := l.streamRange(from, to, chainStart, fn)
	return err
}
