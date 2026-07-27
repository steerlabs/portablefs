#!/usr/bin/env bash
# provision-production-roles.sh — production LOGIN role provisioning.
#
# The quickstart (scripts/quickstart.sh) provisions its login roles as
# SUPERUSER with the portablefs.test_allow_unsafe_durability bypass — the
# explicit single-node DEVELOPMENT posture. This script is the production
# replacement: it creates (or converges) the three LOGIN roles the runtime
# connects with, WITHOUT superuser and WITHOUT the durability bypass, and
# GRANTs each one its NOLOGIN capability role created by the migrations:
#
#   portablefs_authority_login  <- portablefs_authority      (migration 009)
#   portablefs_manager_login    <- portablefs_manager        (migration 010)
#   portablefs_history_login    <- portablefs_history_worker (migration 013)
#
# Run AFTER the migration gate (scripts/run-migration-gate.mjs): the
# capability roles are created by the migrations, and this script fails
# closed with a preflight error when they are missing.
#
# Idempotent: re-running re-applies each password (ALTER ROLE when the role
# exists, CREATE ROLE otherwise — the quickstart's shape, minus SUPERUSER),
# re-GRANTs are no-ops, and the convergence is deliberately corrective: a
# role previously provisioned by the quickstart is downgraded to NOSUPERUSER
# and its durability-bypass GUC is RESET.
#
# Required environment:
#   PORTABLEFS_ADMIN_DATABASE_URL        admin/owner DSN (CREATE ROLE +
#                                        ADMIN/ownership of the capability
#                                        roles). DIRECT connection; do not
#                                        point this at a transaction pooler.
#   PORTABLEFS_AUTHORITY_LOGIN_PASSWORD  password for portablefs_authority_login
#   PORTABLEFS_MANAGER_LOGIN_PASSWORD    password for portablefs_manager_login
#   PORTABLEFS_HISTORY_LOGIN_PASSWORD    password for portablefs_history_login

set -euo pipefail

die() {
  echo "provision-production-roles: ERROR: $*" >&2
  exit 1
}

command -v psql >/dev/null 2>&1 || die "psql is required on PATH."

[ -n "${PORTABLEFS_ADMIN_DATABASE_URL:-}" ] \
  || die "PORTABLEFS_ADMIN_DATABASE_URL is required (admin/owner DSN; refusing to guess a connection)."
[ -n "${PORTABLEFS_AUTHORITY_LOGIN_PASSWORD:-}" ] \
  || die "PORTABLEFS_AUTHORITY_LOGIN_PASSWORD is required and must be non-empty."
[ -n "${PORTABLEFS_MANAGER_LOGIN_PASSWORD:-}" ] \
  || die "PORTABLEFS_MANAGER_LOGIN_PASSWORD is required and must be non-empty."
[ -n "${PORTABLEFS_HISTORY_LOGIN_PASSWORD:-}" ] \
  || die "PORTABLEFS_HISTORY_LOGIN_PASSWORD is required and must be non-empty."

# Passwords travel as psql variables and are embedded with format(%L) —
# never by shell interpolation into SQL text — so any password byte-sequence
# quotes safely.
psql "$PORTABLEFS_ADMIN_DATABASE_URL" \
  --no-psqlrc \
  --set=ON_ERROR_STOP=1 \
  -v authority_password="$PORTABLEFS_AUTHORITY_LOGIN_PASSWORD" \
  -v manager_password="$PORTABLEFS_MANAGER_LOGIN_PASSWORD" \
  -v history_password="$PORTABLEFS_HISTORY_LOGIN_PASSWORD" \
  <<'SQL'
-- Preflight: the NOLOGIN capability roles come from the migrations
-- (009_remote_journal, 010_manager_control, 013_managed_history). Missing
-- capability roles mean the migration gate has not run against this
-- database yet — fail with the actionable order instead of a bare GRANT
-- error.
DO $$
DECLARE
  v_missing TEXT;
BEGIN
  SELECT string_agg(expected.rolname, ', ')
    INTO v_missing
    FROM (VALUES
      ('portablefs_authority'),
      ('portablefs_manager'),
      ('portablefs_history_worker')
    ) AS expected(rolname)
    WHERE NOT EXISTS (
      SELECT 1 FROM pg_roles r WHERE r.rolname = expected.rolname
    );
  IF v_missing IS NOT NULL THEN
    RAISE EXCEPTION 'capability role(s) missing: %. Run the migration gate first (scripts/run-migration-gate.mjs) — migrations 009/010/013 create the capability roles this script GRANTs.', v_missing;
  END IF;
END
$$;

-- CREATE-or-ALTER per role, quickstart's idempotent shape WITHOUT
-- SUPERUSER. NOSUPERUSER is stated explicitly in the ALTER branch too so a
-- rerun converges a role that was previously provisioned as superuser by
-- the quickstart. INHERIT is stated because the capability role's grants
-- must reach the login's sessions.
SELECT CASE WHEN EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'portablefs_authority_login')
  THEN format('ALTER ROLE portablefs_authority_login WITH LOGIN INHERIT NOSUPERUSER PASSWORD %L', :'authority_password')
  ELSE format('CREATE ROLE portablefs_authority_login WITH LOGIN INHERIT NOSUPERUSER PASSWORD %L', :'authority_password')
END \gexec

SELECT CASE WHEN EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'portablefs_manager_login')
  THEN format('ALTER ROLE portablefs_manager_login WITH LOGIN INHERIT NOSUPERUSER PASSWORD %L', :'manager_password')
  ELSE format('CREATE ROLE portablefs_manager_login WITH LOGIN INHERIT NOSUPERUSER PASSWORD %L', :'manager_password')
END \gexec

SELECT CASE WHEN EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'portablefs_history_login')
  THEN format('ALTER ROLE portablefs_history_login WITH LOGIN INHERIT NOSUPERUSER PASSWORD %L', :'history_password')
  ELSE format('CREATE ROLE portablefs_history_login WITH LOGIN INHERIT NOSUPERUSER PASSWORD %L', :'history_password')
END \gexec

GRANT portablefs_authority TO portablefs_authority_login;
GRANT portablefs_manager TO portablefs_manager_login;
GRANT portablefs_history_worker TO portablefs_history_login;

-- Deliberately NOT set here: portablefs.test_allow_unsafe_durability.
-- That GUC is the quickstart's superuser-only development bypass — it lets
-- the journal accept commits WITHOUT the durable-replication evidence the
-- HA policy verdict requires. Production durability must come from the real
-- verdict (pfj.ha_policy_verdict over live synchronous-replication
-- evidence), never from the bypass. The RESETs converge a database that was
-- previously provisioned by the quickstart: RESET of an unset GUC is a
-- no-op, so reruns stay idempotent.
ALTER ROLE portablefs_authority_login RESET portablefs.test_allow_unsafe_durability;
ALTER ROLE portablefs_manager_login RESET portablefs.test_allow_unsafe_durability;
ALTER ROLE portablefs_history_login RESET portablefs.test_allow_unsafe_durability;
SQL

cat <<'GUIDANCE'
provision-production-roles: ok — LOGIN roles provisioned (NOSUPERUSER, no
durability bypass):
  portablefs_authority_login  (GRANTed portablefs_authority)  -> journal DSN
  portablefs_manager_login    (GRANTed portablefs_manager)    -> manager control DSN
  portablefs_history_login    (GRANTed portablefs_history_worker) -> history worker DSN

Next steps:
  1. If you have not already: run the migration gate
     (PORTABLEFS_MIGRATION_DATABASE_URL=... node scripts/run-migration-gate.mjs).
     This script's preflight requires the capability roles the migrations
     create, so a green run here means the gate has already passed at least
     once.
  2. Install the journal HA policy as the database owner/admin:
       SELECT pfj.install_ha_policy('<canonical policy JSON>');
     The policy JSON must match the deployment's ACTUAL synchronous-standby
     topology — schema (7 keys, validated by pfj.ha_policy_shape_check in
     packages/metadata-db/migrations/012_pfj3_pfc2.sql):
       {"v":1,"expectedSystemIdentifier":"<pg_control_system()>",
        "expectedDatabase":"<db>","minSynchronousCommit":"on|remote_apply",
        "minSyncStandbys":N,"standbyFailureDomains":{"<application_name>":"<domain>"},
        "minDistinctFailureDomains":N}
     The quickstart's single-node loopback policy is dev-only: it relies on
     the superuser durability bypass this script refuses to configure. The
     journal children verify live durability evidence against the installed
     policy and refuse to serve when the evidence is weaker.
  3. Point the service DSNs at these logins (direct vs pooled routing:
     docs/railway-deployment.md).
GUIDANCE
