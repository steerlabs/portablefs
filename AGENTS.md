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

swift test --package-path swift/PortableFSKit --no-parallel
```

`--no-parallel` on the Swift suite is required, not a tuning choice: Swift
Testing can otherwise run cases concurrently inside one worker, and several
tests share process resources or exercise hard protocol deadlines.

## Before You Finish

Run `bash scripts/verify-local.sh` and make it pass. It is the local merge gate:
darwin + linux builds and vet, the Go suite, the Go race suite, the Swift suite,
the release-trust policy checks, and a stale-architecture scan. Do not report a
change as complete with a failing or skipped `verify-local.sh`.

## Frozen Surfaces

Read [COMPATIBILITY.md](./COMPATIBILITY.md) before changing: the authority wire
(ALPN, protocol major, required feature strings, canonical encoding), the
declared macOS cache policy names, the `.portablefs/local-dirs` rule syntax and
its revision hash, the `pfslocal` protocol between the daemon and the FSKit
extension, `PORTABLEFS_*` environment variable names, the user-facing CLI
commands and their documented flags, and the release identity chain. Those are
frozen: evolve additively (new operation, new optional field, new env var), never
rename or repurpose. A wire-incompatible change gets a new exact protocol major
and refuses the old one at the handshake.

## Code Style

- Go: `gofmt`-clean; table-driven tests; wrap errors with context.
- Swift: follow the existing package's conventions; no force-unwraps on I/O paths.
- Comments explain intent, invariants, and trade-offs — not what the code does.
- No emojis in code, docs, or commit messages.
- Match the register of
  [docs/xfs-authority-architecture.md](./docs/xfs-authority-architecture.md) when
  writing docs: concise, technical, honest about what is unproven.

## Repo Shape

- `vcs/`: the Go data plane — the XFS authority, the Linux kernel-FUSE mount
  client, the macOS `portablefsd` v3 data plane behind the FSKit extension, and
  the CLI. Internals live under `vcs/internal/`; see [vcs/README.md](./vcs/README.md).
- `swift/`: the FSKit extension and its coherence stack (`PortableFSKit`), the
  shipping app (`PortableFSApp`), and a manual-registration dev host.
- `pfslocal/`, `proto/`: the wire protocol sources shared by the Go daemon and the
  Swift frontend, plus their golden frames.
- `scripts/`: the local gate, the privileged Linux batteries, the coherence
  matrices, release packaging, and the release-trust policy checkers.
- `docs/`: contracts and guides. `docs/architecture.md` states the product
  contract; `docs/xfs-authority-architecture.md` is the core design document.
