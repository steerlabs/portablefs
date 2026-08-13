# Working On PortableFS

Instructions for coding agents making changes to this repository. (If you are an
agent that *uses* PortableFS workspaces, read
[skills/portablefs/SKILL.md](./skills/portablefs/SKILL.md) instead.)

## Build And Test

There is no build system above the two languages and nothing to install:

```bash
CGO_ENABLED=1 GOOS=darwin go -C vcs build ./... # on macOS; Foundation resolver
CGO_ENABLED=0 GOOS=linux go -C vcs build ./...  # static Linux release
go -C vcs test ./...
go -C vcs test -race ./...
go -C vcs vet ./...

bash scripts/test-swift-xcode.sh # macOS: authoritative native Swift gate
```

The native gate runs one Xcode test process and proves exact equality between
the enumerated inventory and the all-passing xcresult. Socket-backed integration
tests declare their process-wide resource constraint with a serialized Swift
Testing suite; pure tests remain parallel.

## Before You Finish

Run `bash scripts/verify-local.sh` and make it pass. It is the local merge gate:
on macOS it builds and vets the real Foundation/cgo Darwin boundary plus static
Linux, while Linux compiles its native product plus Darwin's deliberate !cgo
refusal stub. CI always supplies the required native macOS Foundation lane. The
gate also runs the native Go and race suites, the Swift suite, the release-trust
policy checks, and a stale-architecture scan. Do not report a change as complete
with a failing `verify-local.sh`.

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
