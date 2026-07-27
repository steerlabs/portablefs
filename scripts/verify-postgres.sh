#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

STARTED=0
if ! docker compose ps postgres 2>/dev/null | grep -qiE "healthy|up|running"; then
  docker compose up -d postgres
  STARTED=1
fi

cleanup() {
  if [ "$STARTED" = "1" ]; then
    docker compose down
  fi
}
trap cleanup EXIT

for _ in $(seq 1 30); do
  if docker compose exec -T postgres pg_isready -U postgres >/dev/null 2>&1; then
    break
  fi
  sleep 1
done

export VOLUME_DATABASE_URL="${VOLUME_DATABASE_URL:-postgres://postgres:postgres@localhost:5432/portablefs}"
export VOLUME_DATABASE_CONNECT_TIMEOUT_MS="${VOLUME_DATABASE_CONNECT_TIMEOUT_MS:-10000}"

pnpm test:postgres

echo "verify-postgres: ok"

