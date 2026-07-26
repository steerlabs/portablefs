// Package histworker is the long-running history worker: it claims
// HistoryCuts, drives the deterministic historycut reducer directly over
// pgx and exact-key object stores, uploads and read-back-verifies every
// emitted object per failure domain, records fenced receipts, publishes
// readiness atomically, and runs the scrub / repair / GC loops under
// DB-time fenced claims. PostgreSQL functions are the only claims, leases,
// fences, receipts, and state; object bytes are immutable; all local memory
// and caches are disposable.
package histworker

import (
	"errors"
	"fmt"

	"github.com/jackc/pgx/v5/pgconn"
	"github.com/trendup-ai/portablefs/vcs/internal/historycut"
)

var (
	// ErrFenced reports a lost claim (stale epoch, expired DB-time lease,
	// superseded incarnation): the holder must stop; another claimer owns
	// the work. It can never publish.
	ErrFenced = errors.New("histworker: claim fenced")
	// ErrPolicyMissing reports that the history policy row is not
	// installed; the worker is not ready and must not fabricate one.
	ErrPolicyMissing = errors.New("histworker: history policy is not installed")
	// ErrPolicyMismatch reports a policy the configuration refuses: wrong
	// expected epoch, duplicate failure domains, or required domains this
	// deployment has no store for.
	ErrPolicyMismatch = errors.New("histworker: replication policy mismatch")
	// ErrCapabilityMissing reports a database that does not install the
	// called surface (undefined function / missing grant): the deployment
	// predates the capability's migration. Optional loops treat it as "no
	// such work exists" so mixed-version rollouts stay healthy.
	ErrCapabilityMissing = errors.New("histworker: database capability missing")
)

// mapPgError classifies the pfh error taxonomy onto worker sentinels:
// PF001 is a fence; PF002/PF004/PF005/PF007/PF008/PF009/PF010/PF011 are
// definite source/contract failures on the restricted worker surface (they
// flow as historycut.ErrCorrupt so materialization fails instead of burning
// sixteen identical retries); PF015 is the missing-policy readiness gate.
// Everything else stays a transient repository error.
func mapPgError(err error) error {
	if err == nil {
		return nil
	}
	var pgErr *pgconn.PgError
	if errors.As(err, &pgErr) {
		switch pgErr.Code {
		case "PF001":
			return fmt.Errorf("%w: %s", ErrFenced, pgErr.Message)
		case "PF002", "PF004", "PF005", "PF007", "PF008", "PF009", "PF010", "PF011":
			return fmt.Errorf("%w: %s", historycut.ErrCorrupt, pgErr.Message)
		case "PF015":
			return fmt.Errorf("%w: %s", ErrPolicyMissing, pgErr.Message)
		case "42883", "42501":
			// undefined_function / insufficient_privilege: the database
			// does not install this capability (pre-migration or narrower
			// role) — typed so optional loops can idle instead of erroring.
			return fmt.Errorf("%w: %s", ErrCapabilityMissing, pgErr.Message)
		}
	}
	return err
}
