# Working On PortableFS

Instructions for coding agents making changes to this repository. (If you are an
agent that *uses* PortableFS workspaces, read
[skills/portablefs/SKILL.md](./skills/portablefs/SKILL.md) instead.)

## Build And Test

```bash
pnpm install              # frozen lockfile; do not update pnpm-lock.yaml casually
pnpm build                # all TypeScript workspaces
pnpm test                 # TS suites + go -C vcs test ./...
pnpm typecheck            # tsc --noEmit + go -C vcs vet ./...
```

Go-only iteration is faster when you are inside `vcs/`:

```bash
go -C vcs test ./...
go -C vcs test -race ./...
go -C vcs vet ./...
```

Postgres integration suite (needs Docker): `pnpm verify:postgres`.

## Before You Finish

Run `pnpm verify` and make it pass. It is the local merge gate: frozen install,
full TS + Go suites, vet, the race suite, the manifest-index benchmark, and a stale
legacy reference scan. Do not report a change as complete with a failing or skipped
`pnpm verify`.

## Frozen Surfaces

Read [COMPATIBILITY.md](./COMPATIBILITY.md) before changing: environment variable
names (`VCS_*`, `VOLUME_*`, `PORTABLEFS_*`), `/v1` HTTP routes, the `fsproto` and
`pfslocal` wire protocols, persisted formats (WAL, migrations, manifests, tree hash,
digests), or the pinned repo layout (`vcs/cmd/*` binaries, `swift/PortableFSKit`,
root Dockerfiles). Those are frozen: evolve additively (new route, new env var, new
protocol version), never rename or repurpose. Postgres migrations are append-only —
never edit a released file under `packages/metadata-db/migrations`.

## Code Style

- Go: `gofmt`-clean; table-driven tests; wrap errors with context.
- TypeScript: two-space indentation; `zod` validation at API boundaries; no `any`
  casts; prefer clear names over comments.
- Comments explain intent, invariants, and trade-offs — not what the code does.
- No emojis in code, docs, or commit messages.
- Match the register of [docs/architecture.md](./docs/architecture.md) when writing
  docs: concise, technical, honest.

## Repo Shape

- `vcs/`: Go data plane (authority server, Linux FUSE mount client, the macOS
  `portablefsd` daemon behind the FSKit extension, NFS compat, WAL,
  replication, checkpoints). Internals live under `vcs/internal/`.
- `apps/volume-api`, `apps/authority-manager`, `apps/volume-worker`: TypeScript
  control plane.
- `packages/*`: shared TS libraries (protocol schemas, core tree/chunk/hash logic,
  metadata DB, blob stores, testkit).
- `docs/`: contracts and guides; `docs/architecture.md` is the root contract.
