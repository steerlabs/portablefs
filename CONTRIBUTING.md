# Contributing

Thanks for contributing to PortableFS. This document covers the development setup,
the verification gates, and the submission requirements.

## Development Setup

You need Node 22, pnpm 10 (via corepack), Go 1.26, and Docker (for the Postgres
integration suite).

```bash
pnpm install
pnpm build
pnpm test
pnpm typecheck
```

Go-only iteration:

```bash
go -C vcs test ./...
go -C vcs test -race ./...
go -C vcs vet ./...
```

The broad local gate — run it before pushing:

```bash
pnpm verify
```

It checks install/lockfile consistency, TypeScript builds/tests/typecheck, Go VCS
tests, Go vet, the VCS race suite, the manifest-index benchmark, and stale legacy
references. The Postgres integration gate (`pnpm verify:postgres`) starts a local
Postgres container and runs the metadata-db suite against it. See
[docs/local-dev.md](./docs/local-dev.md) for the credential-gated suites.

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
- **Check the stability contract.** If your change touches a surface listed as frozen
  in [COMPATIBILITY.md](./COMPATIBILITY.md) — env var names, `/v1` routes, wire
  protocols, persisted formats, the pinned repo layout — say so explicitly in the PR
  description and explain the compatibility story. Silent changes to frozen surfaces
  are rejected.
- **Keep migrations append-only.** Never edit a released file under
  `packages/metadata-db/migrations`; add a new one.
- **Run `pnpm verify` locally.** CI (when enabled on the repo) runs the same suites; a green local run saves a
  round trip.
- **Match the codebase style.** Go code is `gofmt`-clean. TypeScript uses two-space
  indentation, `zod` validation at API boundaries, and no `any` casts. Comments
  explain intent and invariants, not what the code already says.
- **Keep PRs focused.** One logical change per PR. Refactors travel separately from
  behavior changes.

## No CLA

There is no contributor license agreement. Contributions are accepted under the
repository license (Apache-2.0) with DCO sign-off, as described above.

## Code of Conduct

This project follows the [Contributor Covenant](./CODE_OF_CONDUCT.md). By
participating, you agree to uphold it. Report unacceptable behavior privately
per the contact in that document.
