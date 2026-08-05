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
2. the native Go suite, then the native race suite — these tests exercise real
   syscalls, sockets, and mounts, so they are only meaningful on the host;
3. `swift test --package-path swift/PortableFSKit --parallel --num-workers 1`.
   The single worker is required, not a performance knob: several tests bind
   fixed per-process resources (sockets, mount points, the shared app-group
   container) and concurrent workers deadlock rather than fail. Skipped loudly
   on a host with no Swift toolchain; the macOS CI job always runs it;
4. release-trust policy: `sh -n scripts/install.sh`, `scripts/check-workflow-pins.mjs`,
   and `scripts/check-install-release-trust.mjs` (dependency-free single-file
   node programs that read the installer, the workflows, and `.goreleaser.yaml`
   as text);
5. the stale-architecture scan, which fails the run if the deleted journal-era
   package and API surface reappears.

The raw commands, when you want one piece:

```bash
GOOS=darwin go -C vcs build ./...
GOOS=linux  go -C vcs vet ./...
go -C vcs test ./...
go -C vcs test -race ./...
swift test --package-path swift/PortableFSKit --parallel --num-workers 1
```


## The privileged Linux gate

```bash
bash scripts/xfs-fuse-integration.sh          # host side; needs docker
bash scripts/xfs-fuse-integration.sh --in-container   # container side; needs root
```

Runs a throwaway privileged container against a real XFS loopback filesystem
with project quotas and real kernel FUSE mounts. The same script is the CI entry
point and the local reproduction, so a green CI run and a developer run execute
byte-identical provisioning. It enumerates 43 required tests by name: a test
that is renamed, deleted, or skipped fails the job rather than quietly shrinking
privileged coverage.

## The cross-mount coherence matrix

```bash
bash scripts/coherence-matrix-linux.sh        # host side; needs docker
PORTABLEFS_COHERENCE=uncached bash scripts/coherence-matrix-linux.sh
```

Provisions a real XFS cell, starts a real authority and two real mount
processes, then drives both mountpoints with ordinary syscalls from a separate
black-box program — 23 named cases, nothing in-process and nothing faked. It
defaults to the `strict` kernel-cache profile; `PORTABLEFS_COHERENCE=uncached`
measures the other supported profile with the same case list, and both must give
the same answers.

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
