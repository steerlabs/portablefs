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
export VOLUME_RAILWAY_BUCKET_PREFIX=portablefs/dev
```

The storage package can read the Railway CLI variable names directly:

```text
AWS_ENDPOINT_URL
AWS_ACCESS_KEY_ID
AWS_SECRET_ACCESS_KEY
AWS_S3_BUCKET_NAME
AWS_DEFAULT_REGION
```

The API and worker can read the Railway CLI variables directly. They also accept explicit
PortableFS names when you want clearer production config:

```bash
export VOLUME_RAILWAY_BUCKET_ENDPOINT="$AWS_ENDPOINT_URL"
export VOLUME_RAILWAY_BUCKET_NAME="$AWS_S3_BUCKET_NAME"
export VOLUME_RAILWAY_BUCKET_REGION="$AWS_DEFAULT_REGION"
export VOLUME_RAILWAY_BUCKET_URL_STYLE=virtual-host
export VOLUME_RAILWAY_BUCKET_ACCESS_KEY_ID="$AWS_ACCESS_KEY_ID"
export VOLUME_RAILWAY_BUCKET_SECRET_ACCESS_KEY="$AWS_SECRET_ACCESS_KEY"
export VOLUME_RAILWAY_BUCKET_PREFIX=portablefs/dev
```

## Test Against Railway

```bash
docker compose up -d postgres
export VOLUME_DATABASE_URL=postgres://postgres:postgres@localhost:5432/portablefs
export VOLUME_DATABASE_CONNECT_TIMEOUT_MS=10000
set -a
eval "$(railway bucket credentials --bucket portablefs-blobs)"
set +a
export VOLUME_RAILWAY_BUCKET_PREFIX=portablefs/dev
pnpm test:railway-bucket
```

`test:railway-bucket` uploads, downloads, dedupes, verifies, and deletes real objects through
`packages/storage-railway`. The store itself is the generic S3 SigV4 implementation in
`packages/storage-s3`; the Railway-named exports are compatibility aliases for it.

## Manual API And VCS Run

Start Postgres and the API:

```bash
docker compose up -d postgres
export VOLUME_DATABASE_URL=postgres://postgres:postgres@localhost:5432/portablefs
set -a
eval "$(railway bucket credentials --bucket portablefs-blobs)"
set +a
export VOLUME_RAILWAY_BUCKET_PREFIX=portablefs/dev
pnpm --filter @portablefs/volume-api dev
```

In another shell, run a writable VCS authority against that API:

```bash
go build -C vcs -o ../vcs-bin ./cmd/vcs
go build -C vcs -o ../mount-bin ./cmd/mount

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
./mount-bin -addr 127.0.0.1:2050 -mount /mnt/vol
```
