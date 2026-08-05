# Working On PortableFS

Instructions for coding agents making changes to this repository. (If you are an
agent that *uses* PortableFS workspaces, read
[skills/portablefs/SKILL.md](./skills/portablefs/SKILL.md) instead.)

## Build And Test

There is no build system above the two languages and nothing to install:

```bash
go -C vcs build ./...      # Go data plane (add GOOS=darwin / GOOS=linux to cross-check)
go -C vcs test ./...
go -C vcs test -race ./...
go -C vcs vet ./...

swift test --package-path swift/PortableFSKit --parallel --num-workers 1
```

`--num-workers 1` on the Swift suite is required, not a tuning choice: several
tests bind fixed per-process resources and deadlock under multiple workers.

## Before You Finish

Run `bash scripts/verify-local.sh` and make it pass. It is the local merge gate:
darwin + linux builds and vet, the Go suite, the Go race suite, the Swift suite,
the release-trust policy checks, and a stale-architecture scan. Do not report a
change as complete with a failing or skipped `verify-local.sh`.

## Frozen Surfaces

Read [COMPATIBILITY.md](./COMPATIBILITY.md) before changing: environment variable
names (`VCS_*`, `VOLUME_*`, `PORTABLEFS_*`), `/v1` HTTP routes, the `pfslocal`
wire protocol, persisted formats (WAL, manifests, tree hash, digests), or the
pinned repo layout (`vcs/cmd/*` binaries, `swift/PortableFSKit`). Those are
frozen: evolve additively (new route, new env var, new protocol version), never
rename or repurpose.

## Code Style

- Go: `gofmt`-clean; table-driven tests; wrap errors with context.
- Swift: follow the existing package's conventions; no force-unwraps on I/O paths.
- Comments explain intent, invariants, and trade-offs — not what the code does.
- No emojis in code, docs, or commit messages.
- Match the register of [docs/architecture.md](./docs/architecture.md) when writing
  docs: concise, technical, honest.

## Repo Shape

- `vcs/`: Go data plane (authority server, Linux FUSE mount client, the macOS
  `portablefsd` daemon behind the FSKit extension, NFS compat, WAL,
  replication, checkpoints). Internals live under `vcs/internal/`.
- `swift/PortableFSKit`: the macOS FSKit extension, the app, and the installer core.
- `pfslocal/`, `proto/`: the wire protocol sources shared by the Go daemon and the
  Swift frontend, plus their golden frames.
- `scripts/`: the local gate, the privileged Linux batteries, release packaging,
  and the release-trust policy checkers.
- `docs/`: contracts and guides; `docs/architecture.md` is the root contract.
