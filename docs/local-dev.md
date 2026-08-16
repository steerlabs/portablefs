# Local Development

This is a two-language tree — the Go data plane under `vcs/` and the Swift
FSKit/app package under `swift/PortableFSKit` — with no build system above them
and no package manager to install.

## The merge gate

```bash
bash scripts/verify-local.sh
```

That script is the single local gate, and it is plain bash so a developer Mac
and a Linux CI runner execute the same steps:

1. cross-platform compile and vet: `GOOS=darwin` and `GOOS=linux`, both built
   before anything runs, because the daemon, mount clients, and frontend
   adapters all carry per-GOOS files;
2. the pinned `govulncheck` reachable-call scan, which also enforces the exact
   Go security patch level required by `vcs/go.mod`;
3. the native Go suite, then the native race suite — these tests exercise real
   syscalls, sockets, and mounts, so they are only meaningful on the host;
4. `bash scripts/test-swift-xcode.sh` on macOS. The gate asks Xcode to
   enumerate the complete package inventory, executes that already-built
   inventory once through Xcode's native serial test runner, and rejects the
   result unless the `.xcresult` contains the same unique all-passing set. This
   avoids SwiftPM's separate Darwin helper process while preserving exact
   coverage. Non-macOS hosts skip this macOS-only package loudly; the macOS CI
   job always runs it;
5. workflow semantics and release-trust policy: the pinned `actionlint`,
   `sh -n scripts/install.sh`, `scripts/check-workflow-pins.mjs`, and
   `scripts/check-install-release-trust.mjs` (the project checkers are
   dependency-free single-file node programs that read the installer, the
   workflows, and `.goreleaser.yaml` as text);
6. the stale-architecture scan, which fails the run if the deleted journal-era
   package and API surface reappears.

The raw commands, when you want one piece:

```bash
GOOS=darwin go -C vcs build ./...
GOOS=linux  go -C vcs vet ./...
go -C vcs test ./...
go -C vcs test -race ./...
bash scripts/test-swift-xcode.sh
```


## The privileged Linux gate

```bash
bash scripts/xfs-fuse-integration.sh          # host side; needs docker
bash scripts/xfs-fuse-integration.sh --in-container   # container side; needs root
```

Runs a throwaway privileged container against a real XFS loopback filesystem
with project quotas and real kernel FUSE mounts. Its host or VM must already be
booted into the exact patched Linux 6.12.100 profile in
`kernel/linux-6.12.100-portablefs-append/`; a stock Docker Desktop, GCP, or
distro kernel is expected to fail INIT and is never accepted as weaker
evidence. The same script is the CI entry point and local reproduction once the
runner has that kernel. It enumerates 44 required tests by name: a test that is
renamed, deleted, or skipped fails the job rather than quietly shrinking
privileged coverage.

## The cross-mount coherence matrix

```bash
bash scripts/coherence-matrix-linux.sh        # host side; needs docker
```

On a host or VM booted into the exact patched kernel, provisions a real XFS cell, starts a real authority and two real mount
processes, then drives both mountpoints with ordinary syscalls from a separate
black-box program — 23 named cases, nothing in-process and nothing faked. Every
mount uses protocol 5's strict source-publication and peer-visibility contract;
the harness has no weaker profile selector.

On macOS the same cases run against paths you have already mounted yourself; the
script never mounts, unmounts, or drives `portablefsd`:

```bash
scripts/coherence-matrix-macos.sh --mount-a /path/a --mount-b /path/b
scripts/coherence-matrix-macos.sh --mount-a /path/a \
  --remote user@host --remote-mount /path/b
```

Both scripts fail closed. A case that cannot be honestly asserted skips loudly
with a stated reason and a nonzero exit; a quiet pass is never an option. See
[cross-mount-coherence-matrix.md](./cross-mount-coherence-matrix.md).

## Running a real authority

Standing up an authoritative-XFS volume by hand — host and disk preparation, the
isolated volume worker, credentials, and connecting a Linux mount — is
[xfs-authority-deployment.md](./xfs-authority-deployment.md).

Production mounts pass `--mount-token` and an explicit transport: `tls-system-pki`
plus `--data-plane-server-name`, or `tls-private-ca` plus that exact server name
and `--data-plane-ca <ca.pem>`. There is no TLS environment fallback, an empty CA
never selects plaintext, and plaintext is refused outright — a v3 authority
session is mutually authenticated TLS 1.3.
