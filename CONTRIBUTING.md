# Contributing

Thanks for contributing to PortableFS. This document covers the development
setup, the verification gates, and the submission requirements.

## Development Setup

PortableFS is a two-language tree: the Go data plane under `vcs/` and the Swift
FSKit/app package under `swift/PortableFSKit`. There is no build system above
those two languages and nothing to install:

- **Go**, at the version pinned in [vcs/go.mod](./vcs/go.mod) (currently
  1.26.5). It builds every binary under `vcs/cmd/`: `portablefs`,
  `portablefs-authority`, `portablefs-mount-v3`, and `portablefsd`.
- **A Swift toolchain** for `swift/PortableFSKit`. The package declares
  `swift-tools-version: 6.2` and targets macOS 26, so the Swift suite runs on a
  Mac; a Linux host skips it and CI's macOS job covers it.
- **Docker**, only for the privileged Linux gates below. Nothing in the everyday
  loop needs it.

There is no Node project, no package manager, no lockfile, and no dependency
install step. The two release-trust checkers the local gate runs are
dependency-free single-file `.mjs` programs executed with `node`, and the
stale-architecture scan uses `rg`; both are host tools, not project
dependencies.

## Everyday Commands

```bash
go -C vcs build ./...
go -C vcs test ./...
go -C vcs test -race ./...
go -C vcs vet ./...

swift test --package-path swift/PortableFSKit --no-parallel
```

The daemon, the mount clients, and the frontend adapters carry per-`GOOS` files,
so building or vetting only the host platform hides breakage on the other one
until a release job runs. Prefix with `GOOS=darwin` or `GOOS=linux` to
cross-check both:

```bash
GOOS=darwin go -C vcs build ./...
GOOS=linux go -C vcs vet ./...
```

`--no-parallel` on the Swift suite is required, not a tuning choice: Swift
Testing can otherwise run cases concurrently inside one SwiftPM worker.
Several tests share process resources — sockets, mount points, the app-group
container — or exercise hard protocol deadlines, so they must run serially.

## The Local Gate

```bash
bash scripts/verify-local.sh
```

This is the repository's single pre-push gate. It runs from anywhere, operates
on the repository root, and is plain bash so that a developer Mac and a Linux CI
runner execute the same steps:

1. **Cross-OS build** — `GOOS=darwin` and `GOOS=linux` builds of `vcs/...`,
   before anything is executed, so a compile error surfaces in seconds.
2. **Cross-OS vet** — `go vet` for both targets.
3. **Native Go suite** — `go -C vcs test ./...`. The Go tests exercise real
   syscalls, sockets, and mounts, so they are only meaningful on the host
   platform.
4. **Native Go race suite** — `go -C vcs test -race ./...`.
5. **Swift suite** — `swift test --package-path swift/PortableFSKit
   --no-parallel`. Skipped loudly, with a printed `SKIP`, when the host has no
   Swift toolchain.
6. **Release-trust policy** — a `sh -n` syntax check of `scripts/install.sh`,
   the workflow action-pin checker, and the installer release-trust checker.
7. **Stale-architecture scan** — an `rg` pass that fails the gate if the deleted
   v2 journal-era architecture's API and package identifiers reappear anywhere
   outside `docs/`, `CHANGELOG.md`, and the two scripts that legitimately name
   them.

Do not report a change as complete with a failing or skipped `verify-local.sh`.
A skipped Swift suite means you ran the gate on a host that cannot prove the
Swift half; say so rather than treating the run as green.

## Deeper Gates

Changes to the authority's XFS interaction, the FUSE frontends, the coherence
protocol, or the mount lifecycle need more than the local gate:

```bash
bash scripts/xfs-fuse-integration.sh    # privileged Linux: real XFS + kernel FUSE
bash scripts/coherence-matrix-linux.sh  # 23-case two-mount black-box matrix
```

`xfs-fuse-integration.sh` needs Docker on the host and root inside a throwaway
privileged container. It provisions a real XFS filesystem with project quotas
and mounts real kernel FUSE, and it names 43 tests that must actually run and
pass — a renamed or deleted required test fails the job instead of quietly
shrinking privileged coverage. The same script is the CI entry point and the
local reproduction, so both execute byte-identical provisioning.

`coherence-matrix-linux.sh` starts the real `portablefs-authority` and two real
`portablefs-mount-v3` processes against a real XFS cell and drives both
mountpoints with ordinary syscalls from a separate black-box program. Nothing is
in-process and nothing is faked. It also runs falsifiability controls: a case
declared falsifiable must turn red under a control that corrupts what the mounts
see, and a case that neither passes nor matches a named expectation is a hard
failure. See
[docs/cross-mount-coherence-matrix.md](./docs/cross-mount-coherence-matrix.md)
for the case table and
[docs/xfs-authority-architecture.md](./docs/xfs-authority-architecture.md) for
what they are proving.

`scripts/audit-public-source.sh` scans a source tree, its ref names, and
optionally all Git objects for caller-supplied forbidden markers. It requires at
least one `--forbid` expression or `PORTABLEFS_PUBLIC_FORBIDDEN_REGEX`; it is a
release-hygiene tool, not part of the local gate.

## Sign Your Work (DCO)

We use the [Developer Certificate of Origin](https://developercertificate.org/)
instead of a CLA. There is no paperwork: you certify that you have the right to
submit your contribution by adding a `Signed-off-by` line to each commit:

```text
Signed-off-by: Your Name <you@example.com>
```

Git adds it for you:

```bash
git commit -s -m "vcs: fix rename over non-empty directory"
```

The name and email must match your commit author identity. PRs with unsigned commits
cannot be merged; fix up with `git commit --amend -s` or
`git rebase --signoff <base>`.

## Pull Request Guidelines

- **Tests are required.** Behavior changes come with tests that fail without the
  change. Bug fixes come with a regression test.
- **Check the stability contract.** [COMPATIBILITY.md](./COMPATIBILITY.md) is the
  v3 compatibility statement. If your change touches a surface it lists as
  frozen, say so explicitly in the PR description and explain the compatibility
  story. Silent changes to frozen surfaces are rejected.
- **Run `bash scripts/verify-local.sh` locally.** CI runs the same suites; a
  green local run saves a round trip. If your change reaches the authority's XFS
  path or a frontend's cache behavior, run the privileged gate too and say what
  you ran.
- **Match the codebase style.** Go is `gofmt`-clean, with table-driven tests and
  errors wrapped with the context the caller needs to act on them. Swift follows
  the existing package's conventions, with no force-unwraps on I/O paths.
  Comments explain intent, invariants, and trade-offs — not what the code
  already says. No emojis in code, docs, or commit messages.
- **Keep PRs focused.** One logical change per PR. Refactors travel separately
  from behavior changes.

## No CLA

There is no contributor license agreement. Contributions are accepted under the
repository license (Apache-2.0) with DCO sign-off, as described above.

## Code of Conduct

This project follows the [Contributor Covenant](./CODE_OF_CONDUCT.md). By
participating, you agree to uphold it. Report unacceptable behavior privately
per the contact in that document.
