#!/usr/bin/env bash
# Boots the full local PortableFS stack (docker-compose.quickstart.yml), provisions
# the journal roles + tenant, and prints the CLI commands to start working.
#
# The stack is journal-native: ONE Postgres container hosts the metadata database
# AND the pfj/pfm/pfh journal schemas (volume-api applies the migrations at
# startup), the authority manager runs in production mode (one disposable journal
# child per active branch behind the data-plane router), and the history worker
# materializes checkpoint cuts into the same filesystem blob store volume-api
# serves history from.
#
# Default (loopback) mode: localhost binds, plaintext data plane — local
# development only. All tokens and secrets (API/manager/tenant tokens, the
# Postgres superuser + journal-role passwords, the access-token root secret)
# are generated per install, persisted to .env.quickstart (0600), and reused
# on rerun in both modes.
#
# --tailnet / --lan mode: binds 0.0.0.0, generates strong per-install tokens,
# persists all settings to .env.quickstart, and advertises a routable address so
# other machines on your tailnet or private LAN can log in and mount. The data
# plane stays plaintext TCP with bearer tokens: serve a tailnet or trusted
# private LAN only, never the public internet.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
cd "$ROOT"

COMPOSE_FILE=docker-compose.quickstart.yml
ENV_FILE=.env.quickstart

die() {
  echo "quickstart: error: $*" >&2
  exit 1
}

usage() {
  cat <<EOF
usage: ./scripts/quickstart.sh [--tailnet|--lan] [--advertise-host HOST]

Default: loopback-only development stack with generated per-install tokens.

  --tailnet, --lan       serve other machines: bind 0.0.0.0, generate strong
                         tokens, persist settings to $ENV_FILE (0600)
  --advertise-host HOST  the address other machines reach this host on
                         (default: Tailscale IPv4, then first non-loopback IPv4)

Tailnet mode is also implied when QUICKSTART_BIND_HOST is set to a
non-loopback address.
EOF
}

MODE=loopback
ADVERTISE_ARG=""
while [ $# -gt 0 ]; do
  case "$1" in
    --tailnet | --lan)
      MODE=tailnet
      ;;
    --advertise-host)
      shift
      [ $# -gt 0 ] || die "--advertise-host requires a value"
      ADVERTISE_ARG=$1
      MODE=tailnet
      ;;
    --advertise-host=*)
      ADVERTISE_ARG=${1#*=}
      MODE=tailnet
      ;;
    -h | --help)
      usage
      exit 0
      ;;
    *)
      usage >&2
      die "unknown argument: $1"
      ;;
  esac
  shift
done

# Caller-environment overrides, captured before .env.quickstart can shadow them.
ENV_BIND_HOST="${QUICKSTART_BIND_HOST:-}"
ENV_ADVERTISE_HOST="${QUICKSTART_ADVERTISE_HOST:-}"
ENV_ADMIN_TOKEN="${QUICKSTART_ADMIN_TOKEN:-}"
ENV_MANAGER_TOKEN="${QUICKSTART_MANAGER_TOKEN:-}"
ENV_TENANT_TOKEN="${PORTABLEFS_QUICKSTART_TENANT_TOKEN:-}"
ENV_API_PORT="${QUICKSTART_API_PORT:-}"
ENV_MANAGER_PORT="${QUICKSTART_MANAGER_PORT:-}"
ENV_ROUTER_PORT="${QUICKSTART_ROUTER_PORT:-}"
ENV_POSTGRES_PORT="${QUICKSTART_POSTGRES_PORT:-}"

# A non-loopback bind host implies tailnet mode.
if [ "$MODE" = loopback ] && [ -n "$ENV_BIND_HOST" ]; then
  case "$ENV_BIND_HOST" in
    127.* | localhost | ::1) ;;
    *) MODE=tailnet ;;
  esac
fi

command -v docker >/dev/null 2>&1 || die "docker is required"
docker compose version >/dev/null 2>&1 || die "docker compose v2 is required"
command -v curl >/dev/null 2>&1 || die "curl is required"

# A host port that is already taken by an unrelated process makes the stack
# half-work in the worst way: compose publishes the port, but 127.0.0.1
# traffic keeps hitting the older listener (commonly a portablefs dev stack),
# which then rejects this script's tokens. Detect that before starting.
port_in_use() {
  (exec 3<>"/dev/tcp/127.0.0.1/$1") 2>/dev/null || return 1
  exec 3>&- 3<&-
  return 0
}

require_port_free_or_ours() {
  local port=$1 service=$2
  port_in_use "$port" || return 0
  # A running container of our own compose project also holds the port; that
  # is the rerun case and is fine.
  if [ -n "$(docker compose -f "$COMPOSE_FILE" ps --status running -q "$service" 2>/dev/null)" ]; then
    return 0
  fi
  die "port $port is already in use by another process (not this quickstart stack).
If that is a portablefs dev stack or another service, either stop it or run this
script on different ports, e.g.:
  QUICKSTART_API_PORT=18787 QUICKSTART_MANAGER_PORT=18788 \\
  QUICKSTART_ROUTER_PORT=12050 QUICKSTART_POSTGRES_PORT=15433 ./scripts/quickstart.sh"
}

wait_for_http() {
  local url=$1 name=$2 attempts=${3:-90}
  for _ in $(seq 1 "$attempts"); do
    if curl -fsS --max-time 2 "$url" >/dev/null 2>&1; then
      return 0
    fi
    sleep 1
  done
  die "$name did not answer at $url after ${attempts}s"
}

gen_token() {
  if command -v openssl >/dev/null 2>&1; then
    openssl rand -hex 24
  else
    od -An -tx1 -N24 /dev/urandom | tr -d ' \n'
  fi
}

gen_secret_hex32() {
  if command -v openssl >/dev/null 2>&1; then
    openssl rand -hex 32
  else
    od -An -tx1 -N32 /dev/urandom | tr -d ' \n'
  fi
}

# psql runs one SQL script (stdin) inside the postgres container, failing the
# quickstart on the first SQL error.
psql_script() {
  docker compose -f "$COMPOSE_FILE" exec -T postgres \
    psql -U postgres -d portablefs -v ON_ERROR_STOP=1 -q
}

# psql_value evaluates one scalar SQL expression and prints the bare value.
psql_value() {
  docker compose -f "$COMPOSE_FILE" exec -T postgres \
    psql -U postgres -d portablefs -v ON_ERROR_STOP=1 -tA -c "$1" | tr -d '[:space:]'
}

resolve_advertise_host() {
  local ip=""
  if [ -n "$ADVERTISE_ARG" ]; then
    echo "$ADVERTISE_ARG"
    return 0
  fi
  if [ -n "$ENV_ADVERTISE_HOST" ]; then
    echo "$ENV_ADVERTISE_HOST"
    return 0
  fi
  if [ -n "${QUICKSTART_ADVERTISE_HOST:-}" ]; then # persisted in $ENV_FILE
    echo "$QUICKSTART_ADVERTISE_HOST"
    return 0
  fi
  if command -v tailscale >/dev/null 2>&1; then
    ip=$(tailscale ip -4 2>/dev/null | head -n 1) || ip=""
  fi
  if [ -z "$ip" ]; then
    case "$(uname -s)" in
      Darwin)
        ip=$(ipconfig getifaddr en0 2>/dev/null || ipconfig getifaddr en1 2>/dev/null) || ip=""
        ;;
      Linux)
        ip=$(hostname -I 2>/dev/null | awk '{print $1}') || ip=""
        ;;
    esac
  fi
  [ -n "$ip" ] || die "could not detect this machine's address; pass --advertise-host <ip-or-hostname>"
  echo "$ip"
}

TENANT_ID="local"

if [ "$MODE" = tailnet ]; then
  # Reuse persisted tailnet settings so reruns are idempotent. A loopback-era
  # $ENV_FILE (no QUICKSTART_MODE marker) holds loopback secrets only; ignore
  # it and generate real settings.
  if [ -f "$ENV_FILE" ] && grep -q '^QUICKSTART_MODE=tailnet$' "$ENV_FILE"; then
    set -a
    # shellcheck source=/dev/null
    . "$ROOT/$ENV_FILE"
    set +a
  fi

  BIND_HOST=${ENV_BIND_HOST:-${QUICKSTART_BIND_HOST:-0.0.0.0}}
  API_PORT=${ENV_API_PORT:-${QUICKSTART_API_PORT:-8787}}
  MANAGER_PORT=${ENV_MANAGER_PORT:-${QUICKSTART_MANAGER_PORT:-8788}}
  ROUTER_PORT=${ENV_ROUTER_PORT:-${QUICKSTART_ROUTER_PORT:-2050}}
  POSTGRES_PORT=${ENV_POSTGRES_PORT:-${QUICKSTART_POSTGRES_PORT:-5433}}
  ADMIN_TOKEN=${ENV_ADMIN_TOKEN:-${QUICKSTART_ADMIN_TOKEN:-$(gen_token)}}
  MANAGER_TOKEN=${ENV_MANAGER_TOKEN:-${QUICKSTART_MANAGER_TOKEN:-$(gen_token)}}
  TENANT_TOKEN=${ENV_TENANT_TOKEN:-${PORTABLEFS_QUICKSTART_TENANT_TOKEN:-$(gen_token)}}
  ADVERTISE_HOST=$(resolve_advertise_host)
  case "$ADVERTISE_HOST" in
    127.* | localhost | ::1)
      die "advertise host $ADVERTISE_HOST is loopback; other machines cannot reach it (pass --advertise-host)"
      ;;
  esac

  # The script runs on the server itself, so probe over loopback; other
  # machines use the advertised address.
  API_URL="http://127.0.0.1:$API_PORT"
  MANAGER_URL="http://127.0.0.1:$MANAGER_PORT"
else
  if [ -f "$ENV_FILE" ] && grep -q '^QUICKSTART_MODE=tailnet$' "$ENV_FILE"; then
    die "this stack was configured with --tailnet ($ENV_FILE exists).
Rerun ./scripts/quickstart.sh --tailnet to keep it, or delete $ENV_FILE and rerun
this script to reset to loopback mode (remote machines will lose access)."
  fi
  # Reuse the persisted loopback secrets (role passwords, root secret, tenant
  # token) so reruns keep every issued credential valid.
  if [ -f "$ENV_FILE" ]; then
    set -a
    # shellcheck source=/dev/null
    . "$ROOT/$ENV_FILE"
    set +a
  fi
  # Effective ports: caller env wins, then the persisted file, then defaults.
  # Named like the tailnet branch so the shared env-file writer below can
  # persist them for bare reruns.
  API_PORT=${ENV_API_PORT:-${QUICKSTART_API_PORT:-8787}}
  MANAGER_PORT=${ENV_MANAGER_PORT:-${QUICKSTART_MANAGER_PORT:-8788}}
  ROUTER_PORT=${ENV_ROUTER_PORT:-${QUICKSTART_ROUTER_PORT:-2050}}
  POSTGRES_PORT=${ENV_POSTGRES_PORT:-${QUICKSTART_POSTGRES_PORT:-5433}}
  API_URL="http://127.0.0.1:$API_PORT"
  MANAGER_URL="http://127.0.0.1:$MANAGER_PORT"
  ROUTER_ADDR="127.0.0.1:$ROUTER_PORT"
  # Even loopback tokens are generated per install and persisted: the source is
  # public, so a fixed "local-*" token is known to everyone and would grant
  # full access to any other local account, or the moment a port is
  # republished (docker -p, ssh -L, a reverse proxy). Reused on rerun.
  ADMIN_TOKEN=${ENV_ADMIN_TOKEN:-${QUICKSTART_ADMIN_TOKEN:-$(gen_token)}}
  MANAGER_TOKEN=${ENV_MANAGER_TOKEN:-${QUICKSTART_MANAGER_TOKEN:-$(gen_token)}}
  TENANT_TOKEN=${ENV_TENANT_TOKEN:-${PORTABLEFS_QUICKSTART_TENANT_TOKEN:-$(gen_token)}}
fi

# Per-install secrets shared by both modes: the Postgres superuser password,
# the journal login-role passwords, and the access-token root secret. Generated
# once, persisted in $ENV_FILE, reused on rerun. The superuser password is set
# by initdb on the FIRST container start and reused verbatim after; the login
# roles ALTER ROLE re-applies the same password.
PG_SUPERUSER_PASSWORD=${QUICKSTART_PG_SUPERUSER_PASSWORD:-$(gen_token)}
PG_AUTHORITY_PASSWORD=${QUICKSTART_PG_AUTHORITY_PASSWORD:-$(gen_token)}
PG_MANAGER_PASSWORD=${QUICKSTART_PG_MANAGER_PASSWORD:-$(gen_token)}
PG_HISTORY_PASSWORD=${QUICKSTART_PG_HISTORY_PASSWORD:-$(gen_token)}
ACCESS_TOKEN_ROOT_SECRET=${QUICKSTART_ACCESS_TOKEN_ROOT_SECRET:-$(gen_secret_hex32)}

echo "== writing $ENV_FILE (0600; reused on rerun; delete it and rerun to rotate) =="
(
  umask 077
  if [ "$MODE" = tailnet ]; then
    cat > "$ENV_FILE" <<EOF
# Generated by scripts/quickstart.sh --tailnet. Sourced and reused on rerun;
# delete this file and rerun the script to rotate every token and secret.
QUICKSTART_MODE=tailnet
QUICKSTART_BIND_HOST=$BIND_HOST
QUICKSTART_ADVERTISE_HOST=$ADVERTISE_HOST
QUICKSTART_API_PORT=$API_PORT
QUICKSTART_MANAGER_PORT=$MANAGER_PORT
QUICKSTART_ROUTER_PORT=$ROUTER_PORT
QUICKSTART_POSTGRES_PORT=$POSTGRES_PORT
QUICKSTART_ADMIN_TOKEN=$ADMIN_TOKEN
QUICKSTART_MANAGER_TOKEN=$MANAGER_TOKEN
PORTABLEFS_QUICKSTART_TENANT_TOKEN=$TENANT_TOKEN
QUICKSTART_ACCESS_TOKEN_ROOT_SECRET=$ACCESS_TOKEN_ROOT_SECRET
QUICKSTART_PG_SUPERUSER_PASSWORD=$PG_SUPERUSER_PASSWORD
QUICKSTART_PG_AUTHORITY_PASSWORD=$PG_AUTHORITY_PASSWORD
QUICKSTART_PG_MANAGER_PASSWORD=$PG_MANAGER_PASSWORD
QUICKSTART_PG_HISTORY_PASSWORD=$PG_HISTORY_PASSWORD
EOF
  else
    cat > "$ENV_FILE" <<EOF
# Generated by scripts/quickstart.sh (loopback mode). Sourced and reused on
# rerun; delete this file and rerun the script to rotate the secrets below.
QUICKSTART_ADMIN_TOKEN=$ADMIN_TOKEN
QUICKSTART_MANAGER_TOKEN=$MANAGER_TOKEN
PORTABLEFS_QUICKSTART_TENANT_TOKEN=$TENANT_TOKEN
QUICKSTART_ACCESS_TOKEN_ROOT_SECRET=$ACCESS_TOKEN_ROOT_SECRET
QUICKSTART_PG_SUPERUSER_PASSWORD=$PG_SUPERUSER_PASSWORD
QUICKSTART_PG_AUTHORITY_PASSWORD=$PG_AUTHORITY_PASSWORD
QUICKSTART_PG_MANAGER_PASSWORD=$PG_MANAGER_PASSWORD
QUICKSTART_PG_HISTORY_PASSWORD=$PG_HISTORY_PASSWORD
# Ports persist so bare reruns (and docker compose invocations that source
# this file) keep serving the addresses this stack was created on instead of
# silently falling back to the defaults.
QUICKSTART_API_PORT=$API_PORT
QUICKSTART_MANAGER_PORT=$MANAGER_PORT
QUICKSTART_ROUTER_PORT=$ROUTER_PORT
QUICKSTART_POSTGRES_PORT=$POSTGRES_PORT
${COMPOSE_PROJECT_NAME:+COMPOSE_PROJECT_NAME=$COMPOSE_PROJECT_NAME}
EOF
  fi
)
chmod 0600 "$ENV_FILE"

# Export everything docker-compose.quickstart.yml interpolates.
set -a
# shellcheck source=/dev/null
. "$ROOT/$ENV_FILE"
set +a

require_port_free_or_ours "${QUICKSTART_API_PORT:-8787}" volume-api
require_port_free_or_ours "${QUICKSTART_MANAGER_PORT:-8788}" authority-manager
require_port_free_or_ours "${QUICKSTART_ROUTER_PORT:-2050}" authority-manager

echo "== starting postgres + volume-api =="
docker compose --env-file "$ENV_FILE" -f "$COMPOSE_FILE" up -d --build --wait postgres volume-api

echo "== waiting for the volume API on $API_URL =="
wait_for_http "$API_URL/healthz" "volume-api"

# volume-api applied the migrations at startup, creating the pfj/pfm/pfh
# schemas and their NOLOGIN capability roles. Provision the LOGIN roles the
# runtime connects with (idempotent: ALTER ROLE re-applies the password on
# rerun):
#
#   portablefs_authority_login  journal DSN for the manager's VCS children
#   portablefs_manager_login    the manager's pfm control store
#   portablefs_history_login    the history worker's restricted pfh surface
#
# The authority and manager logins are SUPERUSER with the durability test
# bypass GUC: single-node Postgres has no synchronous standby, and the
# journal admits writes only with durable-replication evidence OR the
# superuser-only bypass (pfm.durability_bypass_active). That is the explicit
# single-node development posture — durability equals this one disk. A
# production deployment uses non-superuser logins against a synchronously
# replicated Postgres instead (docs/self-hosting.md).
echo "== provisioning journal login roles (idempotent) =="
psql_script <<EOF
DO \$\$
BEGIN
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'portablefs_authority_login') THEN
    ALTER ROLE portablefs_authority_login WITH LOGIN SUPERUSER PASSWORD '$PG_AUTHORITY_PASSWORD';
  ELSE
    CREATE ROLE portablefs_authority_login WITH LOGIN SUPERUSER PASSWORD '$PG_AUTHORITY_PASSWORD';
  END IF;
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'portablefs_manager_login') THEN
    ALTER ROLE portablefs_manager_login WITH LOGIN SUPERUSER PASSWORD '$PG_MANAGER_PASSWORD';
  ELSE
    CREATE ROLE portablefs_manager_login WITH LOGIN SUPERUSER PASSWORD '$PG_MANAGER_PASSWORD';
  END IF;
  IF EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'portablefs_history_login') THEN
    ALTER ROLE portablefs_history_login WITH LOGIN PASSWORD '$PG_HISTORY_PASSWORD';
  ELSE
    CREATE ROLE portablefs_history_login WITH LOGIN PASSWORD '$PG_HISTORY_PASSWORD';
  END IF;
END
\$\$;
GRANT portablefs_authority TO portablefs_authority_login;
GRANT portablefs_manager TO portablefs_manager_login;
GRANT portablefs_history_worker TO portablefs_history_login;
ALTER ROLE portablefs_authority_login SET portablefs.test_allow_unsafe_durability = 'on';
ALTER ROLE portablefs_manager_login SET portablefs.test_allow_unsafe_durability = 'on';
EOF

# Install the single-domain history replication policy (expected-epoch CAS;
# first install only — a policy someone upgraded by hand is left alone) and
# read back the installed epoch for the worker.
echo "== installing the single-domain history policy (idempotent) =="
psql_script <<'EOF'
DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pfh.history_policies WHERE singleton_key = 'history') THEN
    PERFORM pfh.install_history_policy(
      '{"v":1,"requiredFailureDomains":["local"],"maxLastVerifiedAgeMs":86400000,"maxWorkerHeartbeatAgeMs":60000}',
      0);
  END IF;
END
$$;
EOF
QUICKSTART_HISTORY_POLICY_EPOCH=$(psql_value "SELECT policy_epoch FROM pfh.history_policies WHERE singleton_key = 'history'")
[ -n "$QUICKSTART_HISTORY_POLICY_EPOCH" ] || die "could not read the installed history policy epoch"
export QUICKSTART_HISTORY_POLICY_EPOCH

# The single-node dev HA policy the manager hands every journal child
# (VCS_JOURNAL_HA_POLICY_JSON). It pins the exact cluster + database; the
# replication minimums (1 synchronous standby in 1 attested failure domain)
# are satisfied through the superuser-only durability test bypass configured
# above — the child verifies the identity pins either way. Derived fresh on
# every run because initdb mints a new system identifier with a new volume.
SYSTEM_IDENTIFIER=$(psql_value "SELECT system_identifier FROM pg_control_system()")
[ -n "$SYSTEM_IDENTIFIER" ] || die "could not read the Postgres system identifier"
QUICKSTART_JOURNAL_HA_POLICY_JSON=$(printf '{"v":1,"expectedSystemIdentifier":"%s","expectedDatabase":"portablefs","minSynchronousCommit":"on","minSyncStandbys":1,"standbyFailureDomains":{"quickstart-single-node":"local"},"minDistinctFailureDomains":1}' "$SYSTEM_IDENTIFIER")
export QUICKSTART_JOURNAL_HA_POLICY_JSON

# Install the SAME canonical policy bytes in the database: PFJ3 journal
# claims verify live durability evidence against the INSTALLED policy
# (pfj.evaluate_ha_policy raises PF015 without one) and pin the claimed
# generation to its hash. Idempotent byte-compare: identical bytes are left
# alone (the hash — what generations pin — only changes when the bytes do).
echo "== installing the journal HA policy (idempotent) =="
psql_script <<EOF
DO \$\$
DECLARE
  v_current TEXT;
BEGIN
  SELECT canonical_json INTO v_current
    FROM pfj.ha_policies
    WHERE database_name = current_database()
      AND system_identifier = (SELECT system_identifier::TEXT FROM pg_control_system());
  IF v_current IS NULL OR v_current <> '$QUICKSTART_JOURNAL_HA_POLICY_JSON' THEN
    PERFORM pfj.install_ha_policy('$QUICKSTART_JOURNAL_HA_POLICY_JSON');
  END IF;
END
\$\$;
EOF

echo "== provisioning tenant '$TENANT_ID' (idempotent) =="
body_file="$(mktemp)"
trap 'rm -f "$body_file"' EXIT
status=$(curl -sS -o "$body_file" -w '%{http_code}' --max-time 10 \
  --retry 5 --retry-delay 1 --retry-connrefused \
  -X POST "$API_URL/v1/admin/tenants" \
  -H "authorization: Bearer $ADMIN_TOKEN" \
  -H "content-type: application/json" \
  -d "{\"tenantId\":\"$TENANT_ID\",\"token\":\"$TENANT_TOKEN\",\"label\":\"quickstart\"}") || die "tenant provisioning request failed"
case "$status" in
  2??)
    echo "tenant '$TENANT_ID' is provisioned"
    ;;
  409)
    # Current releases upsert idempotently and return 201; tolerate a future
    # already-exists conflict as success.
    echo "tenant '$TENANT_ID' already exists; reusing it"
    ;;
  *)
    echo "quickstart: tenant provisioning returned HTTP $status:" >&2
    cat "$body_file" >&2 || true
    exit 1
    ;;
esac

echo "== starting the authority manager (production mode) + history worker =="
docker compose --env-file "$ENV_FILE" -f "$COMPOSE_FILE" up -d --build --wait authority-manager history-worker

echo "== waiting for the authority manager on $MANAGER_URL =="
wait_for_http "$MANAGER_URL/readyz" "authority-manager"

if [ "$MODE" = tailnet ]; then
  if ! curl -fsS --max-time 3 "http://$ADVERTISE_HOST:$API_PORT/healthz" >/dev/null 2>&1; then
    echo "quickstart: warning: http://$ADVERTISE_HOST:$API_PORT/healthz is not reachable from this machine." >&2
    echo "  Allow incoming connections if the OS firewall prompts (macOS: System Settings" >&2
    echo "  -> Network -> Firewall), then verify from another machine:" >&2
    echo "    nc -vz $ADVERTISE_HOST $API_PORT" >&2
  fi

  cat <<EOF

PortableFS quickstart stack is up (tailnet/LAN mode).

  volume API         http://$ADVERTISE_HOST:$API_PORT
  authority manager  http://$ADVERTISE_HOST:$MANAGER_PORT  (journal-backed, production mode)
  data-plane router  $ADVERTISE_HOST:$ROUTER_PORT
  history worker     internal (materializes checkpoint history cuts)
  settings + tokens  $ENV_FILE (0600; reused on rerun)

WARNING
  The data plane is plaintext TCP and every API uses static bearer tokens:
  anyone who can reach these ports can read and write every volume. Serve a
  Tailscale tailnet or trusted private LAN only — NEVER the public internet.
  To rotate all tokens: delete $ENV_FILE and rerun this script.

Set up another machine (laptop, desktop, second server):

  1. Install the CLI:

     curl -fsSL https://raw.githubusercontent.com/steerlabs/portablefs/main/scripts/install.sh | sh

  2. Log in to this server:

     portablefs login http://$ADVERTISE_HOST:$API_PORT --token $TENANT_TOKEN \\
       --manager-url http://$ADVERTISE_HOST:$MANAGER_PORT --manager-token $MANAGER_TOKEN

  3. Import a project and mount it live:

     portablefs adopt ~/code/myproject
     portablefs mount myproject ~/work

Stop the stack (volumes persist):

  docker compose -f $COMPOSE_FILE down

Delete everything, including stored data:

  docker compose -f $COMPOSE_FILE down -v
EOF
else
  cat <<EOF

PortableFS quickstart stack is up.

  volume API         $API_URL  (tenant token: $TENANT_TOKEN)
  authority manager  $MANAGER_URL  (manager token: $MANAGER_TOKEN; journal-backed, production mode)
  data-plane router  $ROUTER_ADDR
  history worker     internal (materializes checkpoint history cuts)

Get to work:

  portablefs login --url $API_URL --token $TENANT_TOKEN \\
    --manager-url $MANAGER_URL --manager-token $MANAGER_TOKEN

  portablefs create myagent
  portablefs mount myagent ~/work
  (cd ~/work && ls -la)
  portablefs history myagent
  portablefs fork myagent --name attempt-1

Stop the stack (volumes persist):

  docker compose -f $COMPOSE_FILE down

Delete everything, including stored data:

  docker compose -f $COMPOSE_FILE down -v
EOF
fi
