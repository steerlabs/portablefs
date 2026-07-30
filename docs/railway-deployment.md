# Railway Deployment

Deploying PortableFS to Railway from this repository's root Dockerfiles.
Per-service config-as-code lives in [`railway/`](../railway/README.md)
(builder, health checks, drain, restart policies — and why); this runbook
owns everything the dashboard manages: environment variables, DSN routing,
networking, storage, and deploy order. General production semantics
(token model, HA policy, upgrades) are in
[self-hosting.md](./self-hosting.md); this file is only the
Railway-specific wiring.

## Services

| Railway service | Source | Config file | Role |
| --- | --- | --- | --- |
| migration-gate | this repo, `Dockerfile.volume-api` | `/railway/migration-gate.railway.json` | one-shot pre-deploy job: applies migrations, verifies lineage + 016 timeout attestation |
| volume-api | this repo, `Dockerfile.volume-api` | `/railway/volume-api.railway.json` | control and history API (`/v1`), port 8787 |
| authority-manager | this repo, `Dockerfile.authority-manager` | `/railway/authority-manager.railway.json` | fenced singleton; spawns journal children behind the TCP router (2050) |
| history-worker | this repo, `Dockerfile.history-worker` | `/railway/history-worker.railway.json` | resident pfh worker: cuts, scrub, repair, GC |
| Postgres | Railway Postgres (16+) | — | metadata + journal (`pfj`/`pfm`/`pfh`) |
| bucket(s) | Railway Buckets | — | volume-api blobs + history stores |

## Deploy order

1. **Postgres + bucket(s) + TCP proxy** exist first (dashboard).
2. **migration-gate** — one instance, `restartPolicyType NEVER`. Green run
   = migrations applied, lineage receipts complete, 016 timeout defaults
   attested. A red gate stops the train before any service restarts.
3. **`scripts/provision-production-roles.sh`** (operator shell, not a
   Railway service) — creates the three LOGIN roles and GRANTs the
   capability roles the migrations created. Then, as the owner/admin:
   install the journal HA policy (`SELECT pfj.install_ha_policy('<json>')`)
   matching the actual synchronous-standby topology, and install the
   history replication policy (`SELECT pfh.install_history_policy('<json>', 0)`)
   naming the worker's failure domains — its `policy_epoch` is what
   `PFH_WORKER_POLICY_EPOCH` pins. The script prints the exact next steps.
4. **volume-api** — applies migrations again at startup (harmless; the
   gate already did the work) and serves `/readyz`.
5. **history-worker** — needs the policy epoch from step 3's
   `pfh.history_policies` install and the stores JSON below.
6. **authority-manager** — last, using the explicit stop-before-start
   singleton handoff below: its children need the volume API, the journal
   roles, and the installed HA policy to pass their own readiness.

### Authority-manager singleton handoff

Do not submit an ordinary health-gated rolling deploy for the
`authority-manager`. Railway keeps the previous deployment active until the
candidate passes `/readyz`, but a candidate manager correctly refuses readiness
while the previous manager holds the live `pfm` claim. Neither side should
weaken that fence.

For this one service, perform an explicit stop-before-start handoff with exact
project, environment, and service IDs:

1. Confirm the currently active deployment and that the service is pinned to
   one replica.
2. Run `railway down --yes` with all three exact selectors. Wait for the command
   to finish and verify the previous deployment is `REMOVED`. Its SIGTERM path
   drains children and releases the manager claim; the configured 60-second
   drain budget bounds that shutdown.
3. Run `railway up --ci` from the clean, verified release checkout with the same
   exact selectors.
4. Require a successful Railway deployment, `GET /readyz`, and authenticated
   `GET /v1/release-identity` readback before publishing the matching client
   release or declaring the rollout complete.

The bounded manager unavailability during this handoff is intentional. It is a
fail-closed singleton transition, not a fallback. Never bypass the claim,
disable readiness, run two replicas, or silently route around the manager.

## Environment matrix

Set variables per service in the dashboard. Sealed variables for every
secret (tokens, passwords, PEMs). Names below are code-verified.

### migration-gate

| Variable | Value |
| --- | --- |
| `PORTABLEFS_MIGRATION_DATABASE_URL` | **direct owner DSN** (the Postgres superuser/owner URL). NEVER a transaction-pooler URL: the migration runner holds a session advisory lock (`pg_advisory_lock`), and a pooler can strand it fleet-wide. |
| `PORTABLEFS_MIGRATION_SSL` | `require` (or `no-verify` while the Postgres cert chain is unverifiable) |
| optional | `PORTABLEFS_MIGRATION_APPLICATION_NAME`, `PORTABLEFS_MIGRATION_CONNECT_TIMEOUT_MS`, `PORTABLEFS_MIGRATION_DEADLINE_MS` (default 600000), `PORTABLEFS_MIGRATION_JOURNAL_ROLES` (default `portablefs_authority`) |

### volume-api

| Variable | Value |
| --- | --- |
| `VOLUME_DATABASE_URL` | **direct** Postgres URL (startup migrations take the session advisory lock; wait-head long-polling runs `LISTEN portablefs_head` — both are session identities a transaction pooler destroys) |
| `VOLUME_DATABASE_SSL` | `require` / `no-verify` |
| `VOLUME_API_TOKEN` | admin credential (tenant provisioning + GC only) |
| `VOLUME_BLOB_STORE` | `s3` (the default when unset; `railway-bucket` remains a compat alias for one release) |
| `AWS_ENDPOINT_URL` / `AWS_S3_BUCKET_NAME` / `AWS_DEFAULT_REGION` / `AWS_ACCESS_KEY_ID` / `AWS_SECRET_ACCESS_KEY` | reference the Railway bucket service's variables of the same names directly; `VOLUME_S3_PREFIX` is the optional key prefix. The retired `VOLUME_RAILWAY_BUCKET_*` spellings remain accepted as aliases (see [self-hosting.md](./self-hosting.md)) |
| `PORTABLEFS_RELEASE_ID` / `PORTABLEFS_SOURCE_REVISION` | from `RAILWAY_GIT_COMMIT_SHA` (see [release identity](#release-identity)) |

`PORT` is Railway-injected; the API listens on it (image default 8787) and
the `/readyz` health check probes it — no coupling needed here.

### authority-manager

`NODE_ENV=production`, `PORTABLEFS_AUTHORITY_MODE=production`, and
`PORTABLEFS_MANAGED_VCS_BIN=/usr/local/bin/vcs` are baked into the image.

| Variable | Value |
| --- | --- |
| `PORTABLEFS_AUTHORITY_MANAGER_TOKEN` | manager API bearer token (required in production) |
| `PORTABLEFS_MANAGER_CONTROL_DATABASE_URL` | **direct** URL as `portablefs_manager_login` (pfm control store) |
| `PORTABLEFS_MANAGED_VCS_JOURNAL_DSN` | URL as `portablefs_authority_login` — direct, **or** the PgBouncer URL together with the pooler-mode flag below |
| `PORTABLEFS_MANAGED_VCS_JOURNAL_POOLER_MODE` | `transaction` — set ONLY when the journal DSN points at a transaction-mode pooler (children then omit session timeout GUCs and rely on migration 016's database defaults); absent otherwise |
| `PORTABLEFS_MANAGED_VCS_JOURNAL_HA_POLICY_JSON` | the same canonical policy JSON installed via `pfj.install_ha_policy` (7-key schema; see [self-hosting.md](./self-hosting.md)) |
| `PORTABLEFS_ACCESS_TOKEN_ROOT_SECRET` | >= 32 bytes, hex or base64url (sealed) |
| `PORTABLEFS_AUTHORITY_ROUTER_LISTEN_ADDR` | `0.0.0.0:2050` |
| `PORTABLEFS_AUTHORITY_ROUTER_URL` | `${{RAILWAY_TCP_PROXY_DOMAIN}}:${{RAILWAY_TCP_PROXY_PORT}}` — the public address mount clients dial |
| `PORTABLEFS_AUTHORITY_ROUTER_TRANSPORT_MODE` | `tls-private-ca` |
| `PORTABLEFS_AUTHORITY_ROUTER_TLS_SERVER_NAME` | `${{RAILWAY_TCP_PROXY_DOMAIN}}` — exact SAN/verification name, without a port |
| `PORTABLEFS_AUTHORITY_ROUTER_TLS_CERT_PEM` / `PORTABLEFS_AUTHORITY_ROUTER_TLS_KEY_PEM` | router TLS as inline PEMs in sealed variables (the `*_PATH` file variants exist but Railway has no secret-file mount; PEM-in-env avoids a volume) |
| `PORTABLEFS_AUTHORITY_ROUTER_TLS_CA_PEM` | strict private CA certificate bundle that anchors the router certificate; its SHA-256 is lease-bound automatically |
| `PORTABLEFS_VOLUME_API_URL` | `http://volume-api.railway.internal:8787` (private network) |

Do NOT set `PORTABLEFS_VOLUME_API_TOKEN` / `VOLUME_API_TOKEN` here — a
static child credential on the manager is a startup error; children mint
rotating runtime credentials (migration 015).

The manager's control API listens on `PORT` (image default 8788) and
serves `/healthz` + `/readyz` there; keep it private-network only and
expose ONLY the router (2050) through the TCP proxy.

### history-worker

| Variable | Value |
| --- | --- |
| `PFH_WORKER_DATABASE_URL` | **direct** URL as `portablefs_history_login` (bounded at 8 connections; direct by policy — pooling it adds failure surface without connection relief) |
| `PFH_WORKER_ID` | stable worker identity, e.g. `railway-history-1` |
| `PFH_WORKER_POLICY_EPOCH` | the installed `pfh.history_policies` epoch this rollout targets |
| `PFH_WORKER_STORES_JSON` | one exact-key store per failure domain (`kind: "s3"` entries pointing at buckets; production refuses a floor below 2 distinct domains) |
| `PFH_WORKER_LEGACY_STORE_JSON` | the SAME store the volume API writes blobs to (`{"kind":"s3",...}`) — required for `portablefs adopt`/`activate` conversion |
| `VCS_PRODUCTION` | `1` (deployment-wide fail-closed switch) |
| `PORT` | `8790` |
| `PFH_WORKER_LISTEN_ADDR` | `0.0.0.0:${{PORT}}` — **required coupling.** Railway probes `/readyz` on its injected `PORT`, but the worker reads only `PFH_WORKER_LISTEN_ADDR` and ignores `PORT`; the image `EXPOSE`s 8790 but bakes no listen-addr default, and an unset value disables the listener entirely. Details: [railway/README.md](../railway/README.md). |

### Maintenance jobs (GC and integrity)

Blob GC and the integrity walk are volume-api admin endpoints
(`POST /v1/admin/gc`, `GET /v1/admin/integrity`), authenticated with the
admin token — there is no separate worker service. Schedule them with any
cron that can curl over the private network; see
[self-hosting.md](./self-hosting.md#maintenance-jobs-gc-and-integrity) for
example schedules. Never let two GC sweeps overlap.

## The DSN routing law

Exactly one variable may ever point at a transaction-mode pooler
(Railway's PgBouncer): `PORTABLEFS_MANAGED_VCS_JOURNAL_DSN`, and only with
`PORTABLEFS_MANAGED_VCS_JOURNAL_POOLER_MODE=transaction`. The journal is
purpose-built for it — pooler mode omits the session timeout startup GUCs
and relies on migration 016's `ALTER DATABASE` defaults (which the
migration gate attests on every deploy).

Everything else stays **direct**, each for a session-scoped reason:

| Variable | Why direct |
| --- | --- |
| `PORTABLEFS_MIGRATION_DATABASE_URL` (gate) | session advisory lock (`pg_advisory_lock`, classid `0x70667321` / objid `0x6d696772`); a pooler can unlock on the wrong server session and strand it fleet-wide |
| `VOLUME_DATABASE_URL` (api) | startup migrations take the same session lock; `LISTEN portablefs_head` long-polling pins a connection |
| `PORTABLEFS_MANAGER_CONTROL_DATABASE_URL` | pfm control pool with session-configured timeouts |
| `PORTABLEFS_MANAGED_VCS_JOURNAL_DSN` in direct mode | children pin session timeout GUCs at startup |
| `PFH_WORKER_DATABASE_URL` | already bounded at 8 connections; pooling adds failure surface without relief |

Use separate secret names for the pooled URL and every direct URL so a
direct consumer can never receive the pooled host by copy-paste.

## Router networking: TCP proxy + private CA

Mount clients dial the manager's data-plane router over raw TCP/TLS on
port 2050 — not HTTP — so it is exposed through a Railway **TCP proxy**
(service settings → networking), not a public HTTP domain. The proxy
passes bytes through; TLS terminates at the router itself using the
PEM variables above. Practical consequence: Railway's edge certificates
do not apply, so issue the router certificate from your own private CA
with the TCP proxy domain (`RAILWAY_TCP_PROXY_DOMAIN`) in the SAN, seal
the PEMs into `PORTABLEFS_AUTHORITY_ROUTER_TLS_CERT_PEM`/`_KEY_PEM`, and
seal the CA into `PORTABLEFS_AUTHORITY_ROUTER_TLS_CA_PEM`. The manager sends
the exact CA, fingerprint, and server name only inside the access lease; clients
never probe or reuse a profile cache. Startup proves the leaf/key/SAN,
intermediate chain, validity, TLS-server purpose, and an actual local TLS 1.3
handshake against that exact private CA before the public listener is
published. Plaintext is only possible with
`PORTABLEFS_AUTHORITY_ROUTER_TRANSPORT_MODE=plaintext` plus
`PORTABLEFS_AUTHORITY_ROUTER_ALLOW_PLAINTEXT_PRODUCTION=1`
behind an authenticated private tunnel — never across the public proxy.

Router addresses are strict `host:port`; bracket IPv6 as `[address]:port`.
Paths, userinfo, queries, unbracketed IPv6, ambiguous numeric IPv4, and
noncanonical ports fail startup. The recommended Railway value is already the
canonical scheme-free `${{RAILWAY_TCP_PROXY_DOMAIN}}:${{RAILWAY_TCP_PROXY_PORT}}`.

Everything else stays on the private network: volume-api is reachable at
`volume-api.railway.internal:8787` and needs no public domain unless CLIs
outside Railway must call `/v1` directly; the manager's control port 8788
should not be proxied publicly at all.

## Buckets

- **volume-api blobs** — one Railway bucket; let the service read the
  bucket's `AWS_*` reference variables directly (the retired
  `VOLUME_RAILWAY_BUCKET_*` spellings remain accepted as aliases).
  Content-addressed, safe to share with the history legacy store.
- **history stores** — `PFH_WORKER_STORES_JSON` needs one store per
  failure domain and production enforces >= 2 distinct domains: use two
  buckets in different regions, or one Railway bucket plus one external
  S3-compatible bucket, each tagged with its own `failureDomain`.
- **legacy store** — `PFH_WORKER_LEGACY_STORE_JSON` points at the SAME
  bucket+prefix volume-api writes, or adopted-volume activation fails
  typed at the conversion step.

## Backup posture

Production state lives in exactly two places
([self-hosting.md](./self-hosting.md#backup-and-restore)):

- **Postgres** — metadata AND the live journal. Enable Railway PITR /
  scheduled backups on the Postgres service's volume; run the database
  with the synchronous replication your HA policy attests. The PortableFS
  services themselves mount **no** Railway volumes — there is nothing
  service-local to back up, and a manager restart is an epoch handoff,
  not a recovery.
- **Bucket** — content-addressed blobs, consistent with Postgres by
  construction. After a Postgres point-in-time restore, pause GC until
  the fleet reconverges (never GC between the restore point and now).

## Release identity

The images read `PORTABLEFS_RELEASE_ID` + `PORTABLEFS_SOURCE_REVISION`
from the environment at runtime (default-empty in the Dockerfiles; unset
means `/v1/release-identity` answers 404). Set on volume-api and
authority-manager:

```text
PORTABLEFS_RELEASE_ID=railway-${{RAILWAY_GIT_COMMIT_SHA}}
PORTABLEFS_SOURCE_REVISION=${{RAILWAY_GIT_COMMIT_SHA}}
```

and have deploy tooling poll `/v1/release-identity` after promoting or
rolling back ([release-identity.md](./release-identity.md)).
