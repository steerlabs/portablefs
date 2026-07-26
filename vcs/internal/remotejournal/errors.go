package remotejournal

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"time"

	"github.com/jackc/pgx/v5/pgconn"

	"github.com/trendup-ai/portablefs/vcs/internal/wal"
)

// Typed outcomes raised by the pfj SQL layer (SQLSTATEs frozen in migration
// 009_remote_journal). Non-PF failures are retried only when the explicit
// transport/transient-SQLSTATE allowlist below says the result may be
// transient or ambiguous. Deterministic auth/signature/configuration errors
// return immediately.
var (
	ErrFenced   = errors.New("remotejournal: writer is stale or fenced (database-time lease/fence/capability check failed)")
	ErrConflict = errors.New("remotejournal: conflict with durable journal state (exact bytes/identity mismatch)")
	// ErrQuota chains to wal.ErrJournalQuota: quota exhaustion is a DEFINITE
	// pre-reservation rejection the protocol layer maps to EDQUOT without
	// consuming an exact identity (nothing durable exists or ever will for
	// the rejected intent).
	ErrQuota                 = fmt.Errorf("remotejournal: journal backlog quota exceeded: %w", wal.ErrJournalQuota)
	ErrBounds                = errors.New("remotejournal: request exceeds the frozen production bounds")
	ErrCodec                 = errors.New("remotejournal: journal generation codec mismatch")
	ErrGap                   = errors.New("remotejournal: append does not extend the journal head contiguously")
	ErrNotFound              = errors.New("remotejournal: journal generation not found")
	ErrInvalid               = errors.New("remotejournal: invalid request shape")
	ErrOpReplay              = errors.New("remotejournal: operation id replayed with different content")
	ErrAccounting            = errors.New("remotejournal: journal accounting failed closed")
	ErrProofMissing          = errors.New("remotejournal: destructive advance refused without landed checkpoint cut proof")
	ErrReceiptEvicted        = errors.New("remotejournal: exact operation receipt was evicted; the operation must not be re-executed")
	ErrDurabilityUnavailable = errors.New("remotejournal: durable-primary evidence is temporarily unavailable")
	ErrProtocolIntegrity     = errors.New("remotejournal: repeated invalid success responses violated the exact protocol")
	// ErrDurability is kept as a source-compatible alias for early callers.
	// New code should use ErrDurabilityUnavailable to make the retryable
	// availability semantics explicit.
	ErrDurability     = ErrDurabilityUnavailable
	ErrUnknownOutcome = errors.New("remotejournal: commit outcome unknown (unresolved when the request context ended)")
	errReadOnly       = errors.New("remotejournal: log is read-only (no writer claim)")
)

const maxInvalidSuccessBodies = 3

var typedByState = map[string]error{
	"PF001": ErrFenced,
	"PF002": ErrConflict,
	"PF003": ErrQuota,
	"PF004": ErrBounds,
	"PF005": ErrCodec,
	"PF006": ErrGap,
	"PF007": ErrNotFound,
	"PF008": ErrInvalid,
	"PF009": ErrOpReplay,
	"PF010": ErrAccounting,
	"PF011": ErrProofMissing,
	"PF014": ErrReceiptEvicted,
	"PF015": ErrDurabilityUnavailable,
}

// typedError maps a pfj SQLSTATE to its typed error. A non-PF error is not
// automatically transient; retryableSQLFailure applies the explicit
// transport/SQLSTATE allowlist below.
func typedError(err error) error {
	var pg *pgconn.PgError
	if !errors.As(err, &pg) {
		return nil
	}
	typed, ok := typedByState[pg.Code]
	if !ok {
		return nil
	}
	if pg.Detail != "" {
		return fmt.Errorf("%w: %s (detail: %s)", typed, pg.Message, pg.Detail)
	}
	return fmt.Errorf("%w: %s", typed, pg.Message)
}

// retryableSQLFailure is intentionally allowlisted. Exact idempotency makes
// retries safe when a response is lost, but it does not make deterministic
// signature, privilege, authentication, data, or configuration errors
// transient. Those must surface on the first attempt instead of looping until
// the process lifecycle ends.
func retryableSQLFailure(err error) bool {
	if err == nil {
		return false
	}
	var pg *pgconn.PgError
	if errors.As(err, &pg) {
		if strings.HasPrefix(pg.Code, "08") { // connection exception class
			return true
		}
		switch pg.Code {
		case "40001", // serialization_failure
			"40P01", // deadlock_detected
			"55P03", // lock_not_available
			"57014", // query_canceled / statement timeout (rolled back)
			"57P01", // admin_shutdown
			"57P02", // crash_shutdown
			"57P03", // cannot_connect_now
			"53300": // too_many_connections
			return true
		default:
			return false
		}
	}
	if errors.Is(err, context.DeadlineExceeded) || errors.Is(err, context.Canceled) ||
		errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) ||
		pgconn.Timeout(err) || pgconn.SafeToRetry(err) {
		return true
	}
	var network net.Error
	return errors.As(err, &network)
}

// callJSONB runs one SQL function call returning JSONB, bounded by the
// per-call timeout and fenced by the lifecycle context.
func (l *Log) callJSONB(parent context.Context, sql string, args ...any) ([]byte, error) {
	if parent == nil {
		parent = l.life
	}
	ctx, cancel := context.WithTimeout(parent, l.cfg.CallTimeout)
	defer cancel()
	var raw []byte
	if err := l.pool.QueryRow(ctx, sql, args...).Scan(&raw); err != nil {
		return nil, err
	}
	return raw, nil
}

// callIdempotent retries an idempotent JSONB call only on allowlisted lost
// responses, timeouts, and transient server errors until it resolves or the
// lifecycle context ends. Typed/deterministic outcomes return immediately.
func (l *Log) callIdempotent(sql string, args ...any) ([]byte, error) {
	backoff := retryBackoffFloor
	for {
		raw, err := l.callJSONB(l.life, sql, args...)
		if err == nil {
			return raw, nil
		}
		if typed := typedError(err); typed != nil {
			return nil, typed
		}
		if !retryableSQLFailure(err) {
			return nil, err
		}
		select {
		case <-l.life.Done():
			return nil, fmt.Errorf("%w: %v (last attempt: %v)", ErrUnknownOutcome, l.life.Err(), err)
		case <-time.After(backoff):
		}
		if backoff *= 2; backoff > retryBackoffCeil {
			backoff = retryBackoffCeil
		}
	}
}
