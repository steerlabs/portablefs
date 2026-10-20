# Working On PortableFS

Instructions for coding agents making changes to this repository. (If you are an
agent that *uses* PortableFS workspaces, read
[skills/portablefs/SKILL.md](./skills/portablefs/SKILL.md) instead.)

## Build And Test

macOS builds require Xcode 27.1 (build 27A9275) and the macOS 27 SDK for FSKit
V3 APIs. Select it with `DEVELOPER_DIR` before running the gates. CI and release
use `xcode-27` with `/Applications/Xcode_27.1.app/Contents/Developer` and assert
the exact build and SDK 27.0. The app and extension still deploy to macOS 26,
using V2 there and V3 on macOS 27.

There is no build system above the two languages and nothing to install:

```bash
CGO_ENABLED=1 GOOS=darwin go -C vcs build ./... # on macOS; Foundation resolver
CGO_ENABLED=0 GOOS=linux go -C vcs build ./...  # static Linux release
go -C vcs test -count=1 ./internal/pfslocal -run '^TestLocalGrammarGeneratedFromCurrentSchema$'
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

Run `bash scripts/verify-local.sh` and make it pass. On macOS it builds and vets
the real Foundation/cgo Darwin boundary plus static Linux, while Linux compiles
its native product plus Darwin's deliberate !cgo refusal stub. CI always
supplies the required native macOS Foundation lane. The gate also runs uncached
`pfslocal` schema freshness, the native Go and race suites, the Swift suite, the
release-trust policy checks, and the current-architecture check
(`scripts/check-current-architecture.py`), which asserts the exact protocol
versions, profile set, schema shape, and production wiring positively rather
than scanning for retired names. Do not report a change as complete with a
failing `verify-local.sh`.

That default mode runs no real mount. It closes by naming every gate it did not
run, and it is not merge evidence for a change to the authority, a frontend, or
the coherence protocol. For those, run `bash scripts/verify-local.sh --full`,
which adds the two privileged Docker suites CI runs on its ubuntu-24.04 lanes
(`scripts/xfs-fuse-integration.sh` and `scripts/coherence-matrix-linux.sh`), and
say in the PR which mode you ran. The privileged suite enforces exact
required-test inventories, one list per owning package:
`scripts/xfs-required-authority-tests.txt`, `scripts/xfs-required-fuse-tests.txt`
and `scripts/xfs-required-tiered-tests.txt`. Rename or delete a required test and
its list entry in the same change.

## Frozen Surfaces

Read [COMPATIBILITY.md](./COMPATIBILITY.md) before changing: the authority wire
(ALPN, exact protocol major, grammar, canonical encoding, error and replay
semantics, frontend profile meanings), the exact paired `pfslocal` and daemon
control interfaces and the cross-release lifecycle v1 API, the
`.portablefs/local-dirs` rule syntax and its revision hash, documented
`PORTABLEFS_*` environment names, the user-facing CLI commands, flags, JSON
meanings and capability strings, the external hosted contracts, and the release
identity chain.

The authority wire has no feature negotiation and rejects unknown fields, so any
grammar or semantic change is a new exact protocol major and ALPN that the old
major refuses at the handshake. Do not add optional fields, aliases, or dual
decoders within a major. `pfslocal` and operational control change only with the
paired release under a new exact version. Public non-wire surfaces evolve
additively or are deprecated and removed at a product-major boundary. Private
persistent state carries one exact format marker and has no historical decoder.

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
- `swift/`: the FSKit extension and its exclusive-writer frontend
  (`PortableFSKit`), the shipping app (`PortableFSApp`), and a
  manual-registration dev host.
- `pfslocal/`, `proto/`: the wire protocol sources shared by the Go daemon and the
  Swift frontend, plus their golden frames.
- `scripts/`: the local gate and its current-architecture check, the privileged
  Linux batteries and their required-test inventories, the coherence matrices,
  the power-loss harness, release packaging, and the release-trust policy
  checkers.
- `docs/`: contracts and guides. `docs/architecture.md` states the product
  contract; `docs/xfs-authority-architecture.md` is the core design document;
  `docs/coherence-v2/wire.md` is the authority wire contract. History lives in
  git, not in the tree: do not add dated receipts or superseded designs.
