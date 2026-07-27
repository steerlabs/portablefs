package historycut

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5"
	"github.com/jackc/pgx/v5/pgconn"
	"github.com/jackc/pgx/v5/pgxpool"
)

// DBSource reaches the claim-fenced pfh worker functions over the restricted
// portablefs_history_worker role (pgx). It implements JournalSource and
// LegacySource for one claimed cut: every call presents the cut id and claim
// epoch, so a fenced-out worker fails typed (PF001) instead of reading.
type DBSource struct {
	pool       *pgxpool.Pool
	cutID      string
	claimEpoch int64
}

// OpenDBSource connects with the worker DSN.
func OpenDBSource(ctx context.Context, dsn, cutID string, claimEpoch int64) (*DBSource, error) {
	cfg, err := pgxpool.ParseConfig(dsn)
	if err != nil {
		return nil, err
	}
	cfg.MaxConns = 2
	pool, err := pgxpool.NewWithConfig(ctx, cfg)
	if err != nil {
		return nil, err
	}
	return &DBSource{pool: pool, cutID: cutID, claimEpoch: claimEpoch}, nil
}

// Close releases the pool.
func (s *DBSource) Close() { s.pool.Close() }

// ErrFenced reports a lost claim (stale epoch / expired lease): the worker
// must stop immediately; another claimer owns the cut.
var ErrFenced = errors.New("historycut: claim fenced")

func mapPgError(err error) error {
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) {
		switch pgErr.Code {
		case "PF001":
			return fmt.Errorf("%w: %s", ErrFenced, pgErr.Message)
		case "PF002", "PF005", "PF009", "PF010":
			return fmt.Errorf("%w: %s", ErrCorrupt, pgErr.Message)
		}
	}
	return err
}

// ReadPage implements JournalSource via pfh.cut_read_page.
func (s *DBSource) ReadPage(ctx context.Context, fromSeq uint64, maxRecords int, maxBytes int64) ([]PageRecord, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT seq, payload, record_hash, chain_digest
		 FROM pfh.cut_read_page($1, $2, $3, $4, $5)`,
		s.cutID, s.claimEpoch, int64(fromSeq), maxRecords, maxBytes)
	if err != nil {
		return nil, mapPgError(err)
	}
	defer rows.Close()
	var out []PageRecord
	for rows.Next() {
		var rec PageRecord
		var seq int64
		if err := rows.Scan(&seq, &rec.Payload, &rec.RecordHash, &rec.ChainDigest); err != nil {
			return nil, err
		}
		rec.Seq = uint64(seq)
		out = append(out, rec)
	}
	return out, mapPgError(rows.Err())
}

// EntriesPage implements LegacySource via pfh.legacy_entries_page.
func (s *DBSource) EntriesPage(ctx context.Context, afterOrd int64, limit int) ([]LegacyEntry, error) {
	rows, err := s.pool.Query(ctx,
		`SELECT ord, path, kind, mode, uid, gid, size, mtime_ms, ctime_ms,
		        atime_ms, executable, assigned_ino, nlink, link_target,
		        blob_digest, blob_size, compression, packed, chunks,
		        comparable_key
		 FROM pfh.legacy_entries_page($1, $2, $3, $4)`,
		s.cutID, s.claimEpoch, afterOrd, limit)
	if err != nil {
		return nil, mapPgError(err)
	}
	defer rows.Close()
	var out []LegacyEntry
	for rows.Next() {
		var (
			e           LegacyEntry
			mode        int64
			uid, gid    int64
			size        int64
			assignedIno *int64
			linkTarget  *string
			blobDigest  *string
			blobSize    *int64
			chunks      []byte
			comparable  string
		)
		if err := rows.Scan(&e.Ord, &e.Path, &e.Kind, &mode, &uid, &gid, &size,
			&e.MtimeMs, &e.CtimeMs, &e.AtimeMs, &e.Executable, &assignedIno,
			&e.Nlink, &linkTarget, &blobDigest, &blobSize, &e.Compression,
			&e.Packed, &chunks, &comparable); err != nil {
			return nil, err
		}
		e.Mode = uint32(mode)
		e.UID = uint32(uid)
		e.GID = uint32(gid)
		e.Size = uint64(size)
		if assignedIno != nil {
			e.AssignedIno = uint64(*assignedIno)
		}
		if linkTarget != nil {
			e.LinkTarget = *linkTarget
		}
		if blobDigest != nil {
			e.BlobDigest = *blobDigest
		}
		if blobSize != nil {
			e.BlobSize = *blobSize
		}
		e.ChunksJSON = chunks
		e.Synthetic = comparable == "synthetic-parent"
		out = append(out, e)
	}
	return out, mapPgError(rows.Err())
}

// ImportCursor implements LegacySource via pfh.legacy_import_cursor_get.
func (s *DBSource) ImportCursor(ctx context.Context) (json.RawMessage, error) {
	var cursor []byte
	err := s.pool.QueryRow(ctx,
		`SELECT pfh.legacy_import_cursor_get($1, $2)`, s.cutID, s.claimEpoch,
	).Scan(&cursor)
	if errors.Is(err, pgx.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, mapPgError(err)
	}
	return cursor, nil
}

// PutImportCursor implements LegacySource via pfh.legacy_import_cursor_put.
func (s *DBSource) PutImportCursor(ctx context.Context, cursor json.RawMessage) error {
	_, err := s.pool.Exec(ctx,
		`SELECT pfh.legacy_import_cursor_put($1, $2, $3::jsonb)`,
		s.cutID, s.claimEpoch, string(cursor))
	return mapPgError(err)
}

// VerifyTreeHash implements LegacySource via pfh.legacy_tree_hash_verify.
func (s *DBSource) VerifyTreeHash(ctx context.Context, treeHash string) error {
	_, err := s.pool.Exec(ctx,
		`SELECT pfh.legacy_tree_hash_verify($1, $2, $3)`,
		s.cutID, s.claimEpoch, treeHash)
	return mapPgError(err)
}

// Heartbeat renews the claim lease and stores bounded progress.
func (s *DBSource) Heartbeat(ctx context.Context, workerID string, ttlMs int64, progress any) error {
	raw, err := json.Marshal(progress)
	if err != nil {
		return err
	}
	_, err = s.pool.Exec(ctx,
		`SELECT pfh.cut_heartbeat($1, $2, $3, $4, $5::jsonb)`,
		s.cutID, s.claimEpoch, workerID, ttlMs, string(raw))
	return mapPgError(err)
}
