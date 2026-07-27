#!/usr/bin/env bash
set -euo pipefail

ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$ROOT"

echo "== frozen install =="
pnpm install --frozen-lockfile

echo "== full local suite =="
pnpm test

echo "== typecheck + go vet =="
pnpm typecheck

echo "== VCS race suite =="
pnpm vcs:test:race

echo "== manifest index benchmark =="
pnpm bench:manifest-index

echo "== stale architecture scan =="
# Guards against resurrecting the removed local-folder-sync architecture. The old
# bare "daemon/" and "cli/" path patterns are gone: legitimate current components
# (portablefsd, cmd/portablefs/internal/cli) collide with them in ordinary prose.
# The old journal.js/lock.js FILENAME patterns are likewise gone: the journal-era
# metadata-db module (src/journal.ts) is imported as "./journal.js" under ESM,
# which is unrelated to the dead sync-journal files. The identifier patterns
# below still catch the old architecture's actual API surface.
if rg -n "volume-daemon|volume-cli|daemon-sync|bench:local-cache|test:hosted|test:cross-machine|test:multi-sandbox|JournalRecord\\b|acquireLocalLock" \
  . -g '!node_modules' -g '!pnpm-lock.yaml' -g '!dist' -g '!scripts/verify-local.sh'
then
  echo "stale legacy references found"
  exit 1
fi

echo "verify-local: ok"
