# Local Development

Run the normal local suite:

```bash
pnpm install
pnpm build
pnpm test
pnpm typecheck
pnpm verify
```

`pnpm verify` is the broad local gate: frozen install, TypeScript build/test/typecheck, Go VCS
tests, Go vet, VCS race tests, the manifest-index benchmark, and stale architecture reference scan.

Run only the VCS mount/runtime suite:

```bash
pnpm vcs:build
pnpm vcs:test
pnpm vcs:test:race
```

Run the TypeScript API packages against local Postgres:

```bash
docker compose up -d postgres
export VOLUME_DATABASE_URL=postgres://postgres:postgres@localhost:5432/portablefs
export VOLUME_DATABASE_CONNECT_TIMEOUT_MS=10000
pnpm test:postgres
```

Or let the repo start and clean up local Postgres for you:

```bash
pnpm verify:postgres
```

Run against a real Railway Bucket:

```bash
docker compose up -d postgres
export VOLUME_DATABASE_URL=postgres://postgres:postgres@localhost:5432/portablefs
export VOLUME_DATABASE_CONNECT_TIMEOUT_MS=10000
set -a
eval "$(railway bucket credentials --bucket portablefs-blobs)"
set +a
export VOLUME_S3_PREFIX=portablefs/dev
pnpm test:s3-bucket
```

See [railway-buckets.md](./railway-buckets.md) for the full bucket setup.

## Run The API Locally

Use filesystem blob storage for a fully local PortableFS stack:

```bash
docker compose up -d postgres
export VOLUME_DATABASE_URL=postgres://postgres:postgres@localhost:5432/portablefs
export VOLUME_API_TOKEN=local-admin-token
export VOLUME_BLOB_STORE=filesystem
export VOLUME_FILESYSTEM_BLOB_ROOT="$HOME/.local/share/portablefs/blobs"
pnpm --filter @portablefs/volume-api dev
```

Provision a local tenant token for agents or VCS:

```bash
curl -X POST http://localhost:8787/v1/admin/tenants \
  -H "authorization: Bearer local-admin-token" \
  -H "content-type: application/json" \
  -d '{"tenantId":"local","token":"local-tenant-token","label":"local-dev"}'
```

S3-compatible storage is the default blob backend when `VOLUME_BLOB_STORE` is
not set (`railway-bucket` keeps working as a compat alias for `s3`, and the
retired `VOLUME_RAILWAY_BUCKET_*` spellings alias onto the canonical
`AWS_*`/`VOLUME_S3_*` names; see [self-hosting.md](./self-hosting.md)):

```bash
export VOLUME_DATABASE_URL=postgres://postgres:postgres@localhost:5432/portablefs
set -a
eval "$(railway bucket credentials --bucket portablefs-blobs)"
set +a
export VOLUME_S3_PREFIX=portablefs/dev
pnpm --filter @portablefs/volume-api dev
```

## Run A Writable VCS

Build the server and CLI:

```bash
go build -C vcs -o ../vcs-bin ./cmd/vcs
go build -C vcs -o ../portablefs-bin ./cmd/portablefs
```

Start a writable authority:

```bash
VCS_WRITABLE=1 \
VOLUME_API_URL=http://localhost:8787 \
VOLUME_API_TOKEN=<token> \
VCS_VOLUME_ID=vol_... \
VCS_ADDR=127.0.0.1:2049 \
VCS_FS_ADDR=127.0.0.1:2050 \
./vcs-bin
```

Mount it through the custom protocol:

```bash
mkdir -p /mnt/vol
./portablefs-bin mount vol_... /mnt/vol --addr 127.0.0.1:2050 \
  --data-plane-transport plaintext --foreground
```

Run agents and tools inside `/mnt/vol`. That mounted filesystem is the live source of truth for
the active volume.

Production direct mounts also pass `--mount-token` and an explicit transport:
`tls-system-pki` plus `--data-plane-server-name`, or `tls-private-ca` plus the
exact server name and `--data-plane-ca <ca.pem>`. There is no TLS environment
fallback and an empty CA never selects plaintext.

For NFS mounting, the managed journal child, TLS/auth, metrics, and real-backend VCS tests, see
[../vcs/README.md](../vcs/README.md).
