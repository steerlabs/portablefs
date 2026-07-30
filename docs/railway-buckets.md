# Railway Buckets

PortableFS stores durable bytes in Railway Buckets and durable metadata in Postgres.
Railway Buckets expose an S3-compatible HTTP surface, but this repo uses a small first-party
signer instead of the AWS SDK so the hosted-byte path stays explicit and portable.

The live filesystem source of truth is the VCS authority. Railway Buckets are the durable object
store used when VCS checkpoints dirty content into immutable commits.

## Provision Dev Resources

Create or choose a Railway project with a Postgres database and an S3-compatible Railway Bucket.
The examples below use `portablefs-blobs` as the bucket name and `portablefs/dev` as the object
prefix, but any bucket and prefix work.

## Export Bucket Credentials

Do not commit bucket credentials. To populate your current shell without printing secrets:

```bash
set -a
eval "$(railway bucket credentials --bucket portablefs-blobs)"
set +a
export VOLUME_S3_PREFIX=portablefs/dev
```

The canonical configuration names are exactly the Railway CLI variable names,
so the eval above is all the credential setup the API needs:

```text
AWS_ENDPOINT_URL
AWS_ACCESS_KEY_ID
AWS_SECRET_ACCESS_KEY
AWS_S3_BUCKET_NAME
AWS_DEFAULT_REGION
```

plus the optional PortableFS extras `VOLUME_S3_PREFIX` (object key prefix,
default `portablefs`) and `VOLUME_S3_SSE`. The retired
`VOLUME_RAILWAY_BUCKET_*` spellings remain accepted as compat aliases for one
release; the mapping table is in [self-hosting.md](./self-hosting.md).

## Test Against Railway

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

`test:s3-bucket` uploads, downloads, dedupes, verifies, and deletes real objects through
the generic S3 SigV4 implementation in `packages/storage-s3`.

## Manual API And VCS Run

Start Postgres and the API:

```bash
docker compose up -d postgres
export VOLUME_DATABASE_URL=postgres://postgres:postgres@localhost:5432/portablefs
set -a
eval "$(railway bucket credentials --bucket portablefs-blobs)"
set +a
export VOLUME_S3_PREFIX=portablefs/dev
pnpm --filter @portablefs/volume-api dev
```

In another shell, run a writable VCS authority against that API:

```bash
go build -C vcs -o ../vcs-bin ./cmd/vcs
go build -C vcs -o ../portablefs-bin ./cmd/portablefs

VCS_WRITABLE=1 \
VOLUME_API_URL=http://localhost:8787 \
VOLUME_API_TOKEN=<token> \
VCS_VOLUME_ID=vol_... \
VCS_ADDR=127.0.0.1:2049 \
VCS_FS_ADDR=127.0.0.1:2050 \
./vcs-bin
```

Then mount the live filesystem:

```bash
mkdir -p /mnt/vol
./portablefs-bin mount vol_... /mnt/vol --addr 127.0.0.1:2050 \
  --data-plane-transport plaintext --foreground
```
