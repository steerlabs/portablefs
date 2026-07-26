-- 016_pooler_timeouts: database-owned safety deadlines for transaction-pooled
-- PostgreSQL clients.
--
-- Transaction-mode poolers (PgBouncer/pgcat in transaction mode) loan an
-- arbitrary server connection to each transaction. Arbitrary startup/session
-- GUCs sent by a client therefore do not reliably govern the server
-- connection that executes a later query. The Go remote journal's explicit
-- transaction-pooler mode (VCS_JOURNAL_POOLER_MODE=transaction) omits those
-- startup parameters, and these DATABASE defaults preserve the historical
-- deadlines: statement_timeout=30s, lock_timeout=5s, and
-- idle_in_transaction_session_timeout=60s.
--
-- ALTER DATABASE affects NEW server sessions only. Operators must apply this
-- migration and recycle existing direct/pooler server connections before
-- enabling pooled journal children. Direct journal connections continue to
-- pin the same three values at startup, so their behavior is byte-for-byte
-- unchanged.
--
-- The TypeScript migration runner is the exceptional long-running maintenance
-- session: it explicitly sets all three timeouts to 0 on its dedicated
-- advisory-locked connection (preserving the pre-016 DDL/backfill budgets)
-- and DISCARDS that connection when done. Ordinary application, manager,
-- journal, and history sessions inherit a real server-side ceiling.

DO $preflight$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM public.portablefs_migrations WHERE id='015_runtime_credentials'
  ) THEN
    RAISE EXCEPTION '016 preflight: 015_runtime_credentials receipt is missing';
  END IF;
  IF EXISTS (
    SELECT 1 FROM public.portablefs_migrations WHERE id LIKE '017%'
  ) THEN
    RAISE EXCEPTION '016 preflight: a later migration receipt exists';
  END IF;
END;
$preflight$;

DO $database_defaults$
DECLARE
  v_database TEXT := current_database();
BEGIN
  EXECUTE format(
    'ALTER DATABASE %I SET statement_timeout TO %L',
    v_database,
    '30000ms'
  );
  EXECUTE format(
    'ALTER DATABASE %I SET lock_timeout TO %L',
    v_database,
    '5000ms'
  );
  EXECUTE format(
    'ALTER DATABASE %I SET idle_in_transaction_session_timeout TO %L',
    v_database,
    '60000ms'
  );
END;
$database_defaults$;
