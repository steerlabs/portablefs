# Railway config-as-code

Per-service Railway configuration for the three deployable PortableFS
services plus the one-shot migration gate. All share this single repository
root, so Railway's one-file-per-service pattern is used: each service in
the Railway dashboard is pointed at its own config file here (service
settings → Config-as-code → file path, in **absolute repository-path
form** with the leading slash, e.g. `/railway/volume-api.railway.json` —
Railway's config-as-code docs specify absolute paths). Railway reads the
file on each deploy; values set in a config file **override** the dashboard
for those keys, everything else stays dashboard-managed.

JSON does not allow comments, so the rationale lives here. The deployment
runbook that ties these files to environment variables, DSN routing, and
deploy order is [docs/railway-deployment.md](../docs/railway-deployment.md).

## Files

| File | Service | Dockerfile | Health check | Restart policy |
| --- | --- | --- | --- | --- |
| `volume-api.railway.json` | volume-api | `Dockerfile.volume-api` | `GET /readyz` (port 8787) | `ON_FAILURE`, 10 retries |
| `authority-manager.railway.json` | authority-manager | `Dockerfile.authority-manager` | `GET /readyz` (control port 8788) | `ON_FAILURE`, 10 retries |
| `history-worker.railway.json` | history-worker | `Dockerfile.history-worker` | `GET /readyz` (port 8790) | `ON_FAILURE`, 10 retries |
| `migration-gate.railway.json` | migration gate (pre-deploy job) | `Dockerfile.volume-api` | none — one-shot job, no listener | `NEVER` |

Why these values:

- **`builder: DOCKERFILE` + `dockerfilePath`** — pins every service to its
  reviewed root Dockerfile so a stray Nixpacks auto-detection can never
  build the monorepo differently per service.
- **`healthcheckPath: /readyz`** — Railway gates a deployment on the health
  check before switching traffic, so the *readiness* endpoint (not
  liveness `/healthz`) is the correct gate:
  - volume-api applies the metadata migrations at startup before serving,
    hence the generous 300s `healthcheckTimeout`. `/readyz` is control
    readiness — metadata connectivity plus applied migration lineage —
    which is exactly what must hold before traffic switches.
  - authority-manager serves `/healthz` and `/readyz` on its HTTP control
    port — 8788 by default, `PORT` when Railway injects it
    (`apps/authority-manager/src/main.ts`, `src/server.ts`
    `readHealthCheck`). `/readyz` fails closed until the manager lease,
    control plane, and router hold (`docs/authority-manager.md`).
  - history-worker serves `/healthz`, `/readyz`, and `/metrics` on
    `PFH_WORKER_LISTEN_ADDR` (`vcs/internal/histworker/http.go`).
    **REQUIRED port coupling** — the config file alone is not sufficient:
    Railway probes the health-check path on the port named by its injected
    `PORT` variable, but the worker reads only `PFH_WORKER_LISTEN_ADDR`
    (`vcs/internal/histworker/config.go`) and ignores `PORT` entirely.
    The image `EXPOSE`s 8790 (`Dockerfile.history-worker`) but bakes **no
    `PFH_WORKER_LISTEN_ADDR` default, and an unset value disables the
    listener completely** — so the service variables must BOTH create the
    listener and align the probe port. Set
    `PFH_WORKER_LISTEN_ADDR=0.0.0.0:${{PORT}}` (tracks whatever Railway
    injects), optionally pinning `PORT=8790` to match the image's
    documented port; or pin both `PORT=8790` and
    `PFH_WORKER_LISTEN_ADDR=0.0.0.0:8790`. Setting `PORT=8790` alone
    leaves nothing listening and the deployment never becomes healthy.
- **`restartPolicyType`** — `ON_FAILURE` for the three long-running
  services; `NEVER` for the migration gate below: a failed migration must
  surface as a failed one-shot deploy, never a crash loop retrying against
  a wedged advisory lock. (Blob GC and the integrity walk are volume-api
  admin endpoints, cron-driven — see
  [docs/railway-deployment.md](../docs/railway-deployment.md).)
- **`drainingSeconds`** — Railway's default drain is **0 seconds**: the old
  deploy gets SIGKILL immediately after SIGTERM, which would cut off
  in-flight requests and graceful teardown. 30s for volume-api and the
  history-worker (finish in-flight requests / release worker leases and
  flush uploads within their shutdown grace). 60s for the
  authority-manager: its SIGTERM handler (`apps/authority-manager/src/main.ts`)
  tears the spawned journal children down gracefully, and each child must
  reach a clean journal state before the manager exits; give the handover
  a real budget.
- **`numReplicas: 1` on the authority-manager** — the manager is a fenced
  singleton: it claims a `pfm` epoch and every peer instance self-fences
  (`docs/authority-manager.md`). Two replicas would just fight over the
  epoch claim, flapping children on every claim exchange. This is pinned
  in config-as-code — unlike the other capacity knobs, which stay
  dashboard-managed — because scaling the manager horizontally is never a
  valid operator action. Railway's health-gated rolling activation is also
  deliberately NOT the handoff mechanism: Railway waits for the successor's
  `/readyz` before signaling the predecessor, while the successor correctly
  refuses readiness until the predecessor releases its live database claim.
  Deploy this service with the stop-before-start procedure in
  `docs/railway-deployment.md`. Do not weaken readiness, force a live takeover,
  or "fix" a slow manager by raising the replica count.
- **`migration-gate.railway.json` reuses `Dockerfile.volume-api`** — the
  volume-api runtime image already contains the built
  `packages/metadata-db/dist`, its installed `pg` dependency, and the
  checked-in migrations (at both `packages/metadata-db/migrations` and
  `packages/migrations`), and it additionally carries
  `scripts/run-migration-gate.mjs` as an inert file (nothing in the image
  executes it by default). The config's `startCommand`
  (`node /app/scripts/run-migration-gate.mjs`) overrides the image `CMD`,
  so there is no separate gate image to drift. Required environment on the
  gate service: `PORTABLEFS_MIGRATION_DATABASE_URL` = the **direct owner
  DSN** — never a transaction-pooler URL: the migration runner serializes
  appliers with a SESSION advisory lock (`pg_advisory_lock`), and a
  transaction pooler may execute the unlock on a different server session,
  stranding the lock and blocking every future `applyMigrations()`
  fleet-wide. Optional: `PORTABLEFS_MIGRATION_APPLICATION_NAME`,
  `PORTABLEFS_MIGRATION_CONNECT_TIMEOUT_MS`, `PORTABLEFS_MIGRATION_SSL`,
  `PORTABLEFS_MIGRATION_DEADLINE_MS` (default 600000 — the whole-gate
  deadline that keeps a stranded advisory lock or hung migration from
  occupying a Railway deploy slot indefinitely; on expiry the gate prints
  the advisory-lock holder and exits nonzero),
  `PORTABLEFS_MIGRATION_JOURNAL_ROLES` (default `portablefs_authority` —
  role-level timeout overrides on these logins that differ from the
  016_pooler_timeouts targets FAIL the gate; other roles' overrides only
  warn). No health check (no listener); run at most one instance at a
  time; deploy order is in
  [docs/railway-deployment.md](../docs/railway-deployment.md).

## Release identity on Railway

The images read `PORTABLEFS_RELEASE_ID` and `PORTABLEFS_SOURCE_REVISION`
from the environment at runtime (declared as default-empty `ARG`/`ENV`
pairs — see the comment in `Dockerfile.volume-api` around the release
identity block). Unset, `/v1/release-identity` answers 404: the honest
"unpinned dev image" signal. On Railway, set them as **service variables**
derived from the deploy's git metadata, e.g.:

```text
PORTABLEFS_RELEASE_ID=railway-${{RAILWAY_GIT_COMMIT_SHA}}
PORTABLEFS_SOURCE_REVISION=${{RAILWAY_GIT_COMMIT_SHA}}
```

so deployment tooling can poll `/v1/release-identity` after promoting (and
after rolling back) instead of assuming the platform switched artifacts
(`docs/release-identity.md`).

## Deliberately dashboard-managed (not in these files)

Kept out of config-as-code on purpose — they are environment-shaped,
secret-bearing, or capacity decisions:

- **Environment variables and secrets** — all DSNs, tokens, PEMs, and
  policy JSON. In particular the DSN routing law (which single variable
  may point at PgBouncer, and why every other one must stay direct) is
  enforced by operators against
  [docs/railway-deployment.md](../docs/railway-deployment.md), never
  encoded here.
- **Volumes** — no service in this repo mounts a Railway volume in managed
  production; blobs live in the bucket and every durable fact in Postgres.
- **Replica counts** — a budgeted decision (volume-api replicas change the
  connection budget), with the one deliberate exception above: the
  authority-manager is pinned to 1 in its config file because a second
  replica is never correct, not merely never budgeted.
- **Per-replica CPU/RAM caps, regions, usage limits** — capacity decisions.
- **Public networking/domains and TCP proxying** — the authority-manager's
  data-plane router (port 2050) is exposed through a Railway TCP proxy;
  the proxy target port and the public domain are environment-specific.

These files are intentionally minimal: a key absent here is a key the
dashboard still owns.
